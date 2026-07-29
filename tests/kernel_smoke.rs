//! Privileged end-to-end coverage for the loader's kernel UAPI boundary.

use std::env;
use std::ffi::CString;
use std::fs;
use std::io::{self, IoSlice, IoSliceMut};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::UnixDatagram;
use std::path::Path;
use std::process::{self, Command};
use std::ptr;
use std::time::Duration;

use ebeepf::{
    AttachType, BpfToken, Btf, BtfObject, BtfType, Error, HelperId, Instruction, LinkType, Map,
    MapCreateOptions, MapFlags, MapSpec, MapType, MappedDataSectionMut, Object, ProgramType,
    RingBuffer, SkeletonBuilder, TcAttachOptions, TcAttachPoint, TcHook, TestRunOptions, TypeId,
    UpdateMode, UsdtOptions, Xdp, XdpAttachOptions, XdpFlags,
};
use nix::errno::Errno;
use nix::fcntl::{fcntl, FcntlArg, FdFlag};
use nix::sys::socket::{recvmsg, sendmsg, ControlMessage, ControlMessageOwned, MsgFlags};
use object::write::{Object as WriteObject, Symbol, SymbolSection};
use object::{
    Architecture, BinaryFormat, Endianness, SectionKind, SymbolFlags, SymbolKind, SymbolScope,
};
use probe::probe;

fn instruction_bytes(instructions: &[Instruction]) -> Vec<u8> {
    instructions
        .iter()
        .flat_map(|instruction| instruction.to_bytes())
        .collect()
}

fn loadable_object() -> Vec<u8> {
    make_loadable_object(false)
}

fn loadable_object_with_btf() -> Vec<u8> {
    make_loadable_object(true)
}

fn make_loadable_object(include_btf: bool) -> Vec<u8> {
    let mut object = WriteObject::new(BinaryFormat::Elf, Architecture::Bpf, Endianness::Little);

    let program = object.add_section(Vec::new(), b"socket".to_vec(), SectionKind::Text);
    let instructions = [
        Instruction::new(0xb7, 0, 0, 0, 0),
        Instruction::new(0x95, 0, 0, 0, 0),
    ];
    object.append_section_data(program, &instruction_bytes(&instructions), 8);
    object.add_symbol(Symbol {
        name: b"drop_packet".to_vec(),
        value: 0,
        size: 16,
        kind: SymbolKind::Text,
        scope: SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(program),
        flags: SymbolFlags::None,
    });

    let tracepoint = object.add_section(
        Vec::new(),
        b"tracepoint/sched/sched_switch".to_vec(),
        SectionKind::Text,
    );
    object.append_section_data(tracepoint, &instruction_bytes(&instructions), 8);
    object.add_symbol(Symbol {
        name: b"track_switch".to_vec(),
        value: 0,
        size: 16,
        kind: SymbolKind::Text,
        scope: SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(tracepoint),
        flags: SymbolFlags::None,
    });

    let maps = object.add_section(Vec::new(), b".maps".to_vec(), SectionKind::Data);
    let mut definition = Vec::new();
    definition.extend(2_u32.to_le_bytes()); // BPF_MAP_TYPE_ARRAY
    definition.extend(4_u32.to_le_bytes());
    definition.extend(8_u32.to_le_bytes());
    definition.extend(4_u32.to_le_bytes());
    definition.extend(0_u32.to_le_bytes());
    object.append_section_data(maps, &definition, 8);
    object.add_symbol(Symbol {
        name: b"values".to_vec(),
        value: 0,
        size: definition.len() as u64,
        kind: SymbolKind::Data,
        scope: SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(maps),
        flags: SymbolFlags::None,
    });

    if include_btf {
        let btf = object.add_section(Vec::new(), b".BTF".to_vec(), SectionKind::Debug);
        object.append_section_data(btf, &minimal_btf(), 4);
    }

    let license = object.add_section(Vec::new(), b"license".to_vec(), SectionKind::Data);
    object.append_section_data(license, b"GPL\0", 1);
    object.write().unwrap()
}

fn networking_object() -> Vec<u8> {
    let mut object = WriteObject::new(BinaryFormat::Elf, Architecture::Bpf, Endianness::Little);
    for (section_name, program_name, return_value) in
        [("xdp", "pass_xdp", 2_i32), ("classifier", "pass_tc", 0_i32)]
    {
        let section = object.add_section(
            Vec::new(),
            section_name.as_bytes().to_vec(),
            SectionKind::Text,
        );
        let instructions = [
            Instruction::new(0xb7, 0, 0, 0, return_value),
            Instruction::new(0x95, 0, 0, 0, 0),
        ];
        object.append_section_data(section, &instruction_bytes(&instructions), 8);
        object.add_symbol(Symbol {
            name: program_name.as_bytes().to_vec(),
            value: 0,
            size: 16,
            kind: SymbolKind::Text,
            scope: SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Section(section),
            flags: SymbolFlags::None,
        });
    }
    let license = object.add_section(Vec::new(), b"license".to_vec(), SectionKind::Data);
    object.append_section_data(license, b"GPL\0", 1);
    object.write().unwrap()
}

struct TemporaryInterface {
    name: String,
}

impl TemporaryInterface {
    fn new() -> Self {
        let name = format!("ebpf{:x}", process::id());
        let status = Command::new("ip")
            .args(["link", "add", &name, "type", "dummy"])
            .status()
            .unwrap();
        assert!(
            status.success(),
            "failed to create temporary dummy interface"
        );
        let interface = Self { name };
        let status = Command::new("ip")
            .args(["link", "set", "dev", &interface.name, "up"])
            .status()
            .unwrap();
        assert!(status.success(), "failed to bring dummy interface up");
        interface
    }
}

impl Drop for TemporaryInterface {
    fn drop(&mut self) {
        drop(
            Command::new("ip")
                .args(["link", "delete", &self.name])
                .status(),
        );
    }
}

fn compile_bpf(source: &Path, output: &Path) {
    let status = Command::new("clang")
        .args(["-target", "bpfel", "-g", "-O2", "-c"])
        .arg(source)
        .arg("-o")
        .arg(output)
        .status()
        .unwrap();
    assert!(
        status.success(),
        "failed to compile BPF fixture `{}`",
        source.display()
    );
}

fn minimal_btf() -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend(0xeb9f_u16.to_le_bytes());
    bytes.extend([1, 0]); // version, flags
    bytes.extend(24_u32.to_le_bytes()); // header length
    bytes.extend(0_u32.to_le_bytes()); // type offset
    bytes.extend(16_u32.to_le_bytes()); // type length
    bytes.extend(16_u32.to_le_bytes()); // string offset
    bytes.extend(5_u32.to_le_bytes()); // string length
    bytes.extend(1_u32.to_le_bytes()); // type name offset
    bytes.extend((1_u32 << 24).to_le_bytes()); // BTF_KIND_INT
    bytes.extend(4_u32.to_le_bytes()); // byte size
    bytes.extend(32_u32.to_le_bytes()); // bit width
    bytes.extend(b"\0int\0");
    bytes
}

#[test]
#[ignore = "requires root or CAP_BPF and a loaded kernel module exposing BTF"]
fn opens_kernel_module_split_btf() {
    let module_name = fs::read_dir("/sys/kernel/btf")
        .unwrap()
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .find(|name| name != "vmlinux")
        .expect("the test kernel has no module BTF");
    let module = BtfObject::from_kernel_module(&module_name).unwrap();
    assert!(module.info().kernel);
    assert_eq!(module.info().name, module_name);
    assert!(module.btf().len() > Btf::from_vmlinux().unwrap().len());
}

#[test]
#[ignore = "requires root or CAP_BPF, clang with the BPF target, and the dummy module with BTF"]
fn loads_and_attaches_kernel_module_fentry() {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/bpf/module-fentry.bpf.c");
    let build = tempfile::tempdir().unwrap();
    let object = build.path().join("module-fentry.bpf.o");
    compile_bpf(&source, &object);

    let loaded = Object::open(&object).unwrap().load().unwrap();
    let program = loaded.program("observe_dummy_xmit").unwrap();
    let target = program.spec().attach_btf_object().unwrap();
    assert_eq!(target.info().name, "dummy");
    assert!(program.spec().attach_btf_id() as usize > target.btf().base_type_count());
    let link = program.attach().unwrap();
    assert_eq!(link.info().unwrap().link_type, LinkType::Tracing);
}

#[test]
#[ignore = "requires root or CAP_BPF, clang with the BPF target, and tracing-multi module support"]
fn loads_and_attaches_kernel_module_fentry_multi() {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/bpf/module-fentry-multi.bpf.c");
    let build = tempfile::tempdir().unwrap();
    let object = build.path().join("module-fentry-multi.bpf.o");
    compile_bpf(&source, &object);

    let loaded = match Object::open(&object).unwrap().load() {
        Ok(loaded) => loaded,
        Err(Error::Verifier { source, log, .. })
            if source.raw_os_error() == Some(libc::EINVAL) && log.is_empty() =>
        {
            // The library surface can be newer than the running kernel.
            return;
        }
        Err(error) => panic!("failed to load tracing-multi fixture: {error}"),
    };
    let program = loaded.program("observe_dummy_functions").unwrap();
    assert_eq!(
        program.spec().attach_btf_object().unwrap().info().name,
        "dummy"
    );
    let link = program.attach().unwrap();
    assert_eq!(link.info().unwrap().link_type, LinkType::TracingMulti);
}

#[test]
#[ignore = "requires root or CAP_BPF, clang with the BPF target, and nf_conntrack module kfuncs"]
fn loads_program_calling_kernel_module_kfuncs() {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/bpf/module-kfunc.bpf.c");
    let build = tempfile::tempdir().unwrap();
    let object = build.path().join("module-kfunc.bpf.o");
    compile_bpf(&source, &object);

    let loaded = Object::open(&object).unwrap().load().unwrap();
    let program = loaded.program("call_module_kfunc").unwrap();
    let dependencies = program.spec().kfunc_btf_objects().collect::<Vec<_>>();
    assert_eq!(dependencies.len(), 1);
    assert_eq!(dependencies[0].info().name, "nf_conntrack");
    let calls = program
        .spec()
        .instructions()
        .iter()
        .filter(|instruction| instruction.code == 0x85 && instruction.source() == 2)
        .collect::<Vec<_>>();
    assert_eq!(calls.len(), 2);
    assert!(calls.iter().all(|instruction| instruction.offset == 1));
}

#[test]
#[ignore = "requires root or CAP_BPF, clang with the BPF target, BTF ksyms, and visible kallsyms"]
fn relocates_typed_and_typeless_kernel_symbols() {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/bpf/ksyms.bpf.c");
    let build = tempfile::tempdir().unwrap();
    let object = build.path().join("ksyms.bpf.o");
    compile_bpf(&source, &object);

    let loaded = Object::open(&object).unwrap().load().unwrap();
    for name in [
        "read_typed_kernel_variable",
        "compare_typed_kernel_function",
        "compare_typed_module_function",
    ] {
        let program = loaded.program(name).unwrap();
        assert!(program
            .spec()
            .instructions()
            .iter()
            .any(|instruction| instruction.code == 0x18 && instruction.source() == 3));
    }
    let module = loaded.program("compare_typed_module_function").unwrap();
    assert_eq!(
        module
            .spec()
            .kernel_btf_objects()
            .next()
            .unwrap()
            .info()
            .name,
        "dummy"
    );
    let typeless = loaded.program("retain_typeless_kernel_symbol").unwrap();
    assert!(typeless.spec().instructions().iter().any(|instruction| {
        instruction.code == 0x18 && instruction.source() == 0 && instruction.immediate != 0
    }));
}

#[test]
#[ignore = "requires root or CAP_BPF, clang with the BPF target, and a visible kernel config"]
fn populates_real_and_virtual_kconfig_externs() {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/bpf/kconfig.bpf.c");
    let build = tempfile::tempdir().unwrap();
    let object_path = build.path().join("kconfig.bpf.o");
    compile_bpf(&source, &object_path);

    let object = Object::open(&object_path).unwrap();
    let btf = object.btf().unwrap();
    let map = object
        .maps()
        .find(|map| map.name().ends_with(".kconfig"))
        .unwrap();
    let initial = map.initial_value().unwrap();
    let value = |name: &str| -> (&[u8], TypeId) {
        let (_, BtfType::DataSection { variables, .. }) =
            btf.find(ebeepf::BtfKind::DataSection, ".kconfig").unwrap()
        else {
            unreachable!()
        };
        let variable = variables
            .iter()
            .find(|variable| {
                matches!(
                    btf.type_by_id(variable.ty),
                    Some(BtfType::Variable { name: candidate, .. }) if candidate == name
                )
            })
            .unwrap();
        let BtfType::Variable { ty, .. } = btf.type_by_id(variable.ty).unwrap() else {
            unreachable!()
        };
        let start = variable.offset as usize;
        (&initial[start..start + variable.size as usize], *ty)
    };
    assert_eq!(
        u32::from_ne_bytes(value("CONFIG_HZ").0.try_into().unwrap()),
        1000
    );
    assert_eq!(value("CONFIG_PREEMPT_DYNAMIC").0, [1]);
    assert_eq!(
        u32::from_ne_bytes(value("CONFIG_VFAT_FS").0.try_into().unwrap()),
        1
    );
    assert_eq!(value("CONFIG_LOCALVERSION").0[0], 0);
    assert_ne!(
        u32::from_ne_bytes(value("LINUX_KERNEL_VERSION").0.try_into().unwrap()),
        0
    );
    assert!(btf.resolve_type(value("CONFIG_HZ").1).unwrap().0 > 0);

    let loaded = object.load().unwrap();
    assert!(loaded.has_kernel_btf());
    assert!(loaded.program("consume_kernel_configuration").is_ok());
}

#[test]
#[ignore = "requires root and a kernel with BPF token delegation"]
fn creates_resources_with_a_delegated_bpf_token() {
    const TOKEN_SOCKET: &str = "EBEEPF_TEST_TOKEN_SOCKET";
    if let Ok(socket_fd) = env::var(TOKEN_SOCKET) {
        delegated_token_child(socket_fd.parse().unwrap());
        return;
    }

    let (parent_socket, child_socket) = UnixDatagram::pair().unwrap();
    parent_socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    fcntl(child_socket.as_raw_fd(), FcntlArg::F_SETFD(FdFlag::empty())).unwrap();
    let child_directory = tempfile::tempdir().unwrap();
    fs::set_permissions(child_directory.path(), fs::Permissions::from_mode(0o755)).unwrap();
    let child_executable = child_directory.path().join("kernel-smoke");
    fs::copy(env::current_exe().unwrap(), &child_executable).unwrap();
    fs::set_permissions(&child_executable, fs::Permissions::from_mode(0o755)).unwrap();
    let mut child = Command::new("unshare")
        .args(["--user", "--map-root-user", "--mount", "--fork", "--"])
        .arg(child_executable)
        .args([
            "--ignored",
            "--exact",
            "creates_resources_with_a_delegated_bpf_token",
            "--nocapture",
        ])
        .env(TOKEN_SOCKET, child_socket.as_raw_fd().to_string())
        .spawn()
        .unwrap();
    drop(child_socket);

    let fs_context = receive_fd(&parent_socket).unwrap();
    for (key, value) in [
        ("delegate_cmds", "any"),
        ("delegate_maps", "any"),
        ("delegate_progs", "any"),
        ("delegate_attachs", "any"),
    ] {
        configure_bpffs(&fs_context, key, value).unwrap();
    }
    create_bpffs(&fs_context).unwrap();
    parent_socket.send(&[1]).unwrap();

    let status = child.wait().unwrap();
    assert!(
        status.success(),
        "unprivileged delegated-token child failed"
    );
}

fn delegated_token_child(socket_fd: RawFd) {
    // SAFETY: the parent deliberately preserved this Unix datagram descriptor
    // across exec and transferred its sole ownership to this child process.
    let socket = unsafe { UnixDatagram::from_raw_fd(socket_fd) };
    let fs_context = fsopen_bpffs().unwrap();
    send_fd(&socket, fs_context.as_raw_fd()).unwrap();
    let mut ready = [0_u8; 1];
    socket.recv(&mut ready).unwrap();

    let mount = fsmount(&fs_context).unwrap();
    let dot = CString::new(".").unwrap();
    // SAFETY: `mount` is a live detached-mount descriptor and `dot` is a
    // terminated path. On success, openat returns a newly owned descriptor.
    let bpffs_fd = unsafe {
        libc::openat(
            mount.as_raw_fd(),
            dot.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };
    let bpffs = owned_syscall_fd(bpffs_fd.into()).unwrap();
    let token = BpfToken::create(&bpffs).unwrap();
    exercise_delegated_bpf_token(token);
}

fn exercise_delegated_bpf_token(token: BpfToken) {
    let info = token.info().unwrap();
    assert!(info.allows_map_type(MapType::Array));
    assert!(info.allows_program_type(ProgramType::SocketFilter));

    let map = Map::create_with_options(
        MapSpec::new("token_map", MapType::Array, 4, 8, 1),
        MapCreateOptions::default().token(&token),
    )
    .unwrap();
    assert_eq!(map.info().unwrap().map_type, MapType::Array);

    let btf = Btf::parse(&minimal_btf()).unwrap();
    let kernel_btf = btf.load_with_token(Some(&token)).unwrap();
    assert!(kernel_btf.info().id > 0);

    let mut object = Object::parse_named("token-smoke", &loadable_object_with_btf()).unwrap();
    object.set_token(&token);
    let loaded = object.load().unwrap();
    assert!(loaded.has_kernel_btf());
    assert!(loaded.token().is_some());
    assert!(loaded.program("drop_packet").unwrap().token().is_some());
    assert_eq!(
        loaded.program("drop_packet").unwrap().info().unwrap().name,
        "drop_packet"
    );
}

fn fsopen_bpffs() -> io::Result<OwnedFd> {
    let filesystem = CString::new("bpf").unwrap();
    // SAFETY: fsopen reads a terminated filesystem name and has no other
    // pointer arguments.
    let fd = unsafe { libc::syscall(libc::SYS_fsopen, filesystem.as_ptr(), 0) };
    owned_syscall_fd(fd)
}

fn configure_bpffs(fs_context: &OwnedFd, key: &str, value: &str) -> io::Result<()> {
    let key = CString::new(key).unwrap();
    let value = CString::new(value).unwrap();
    // SAFETY: both strings are terminated and remain live for the syscall.
    let result = unsafe {
        libc::syscall(
            libc::SYS_fsconfig,
            fs_context.as_raw_fd(),
            1, // FSCONFIG_SET_STRING
            key.as_ptr(),
            value.as_ptr(),
            0,
        )
    };
    syscall_unit(result)
}

fn create_bpffs(fs_context: &OwnedFd) -> io::Result<()> {
    // SAFETY: FSCONFIG_CMD_CREATE has no string arguments.
    let result = unsafe {
        libc::syscall(
            libc::SYS_fsconfig,
            fs_context.as_raw_fd(),
            6, // FSCONFIG_CMD_CREATE
            ptr::null::<libc::c_char>(),
            ptr::null::<libc::c_char>(),
            0,
        )
    };
    syscall_unit(result)
}

fn fsmount(fs_context: &OwnedFd) -> io::Result<OwnedFd> {
    // SAFETY: fsmount has only integer arguments.
    let fd = unsafe { libc::syscall(libc::SYS_fsmount, fs_context.as_raw_fd(), 0, 0) };
    owned_syscall_fd(fd)
}

fn owned_syscall_fd(fd: libc::c_long) -> io::Result<OwnedFd> {
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        let fd = i32::try_from(fd)
            .map_err(|_| io::Error::other("kernel returned a descriptor larger than i32"))?;
        // SAFETY: successful descriptor-returning syscalls transfer one live
        // descriptor to the caller.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

fn syscall_unit(result: libc::c_long) -> io::Result<()> {
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn send_fd(socket: &UnixDatagram, fd: RawFd) -> nix::Result<()> {
    let data = [0_u8];
    let io = [IoSlice::new(&data)];
    let descriptors = [fd];
    sendmsg::<()>(
        socket.as_raw_fd(),
        &io,
        &[ControlMessage::ScmRights(&descriptors)],
        MsgFlags::empty(),
        None,
    )
    .map(drop)
}

fn receive_fd(socket: &UnixDatagram) -> nix::Result<OwnedFd> {
    let mut data = [0_u8];
    let mut io = [IoSliceMut::new(&mut data)];
    let mut control = nix::cmsg_space!([RawFd; 1]);
    let message = recvmsg::<()>(
        socket.as_raw_fd(),
        &mut io,
        Some(&mut control),
        MsgFlags::empty(),
    )?;
    for control in message.cmsgs() {
        if let ControlMessageOwned::ScmRights(descriptors) = control {
            if let Some(fd) = descriptors.into_iter().next() {
                // SAFETY: SCM_RIGHTS creates a new descriptor owned by the
                // receiving process.
                return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
            }
        }
    }
    Err(Errno::EBADMSG)
}

#[test]
#[ignore = "requires root or CAP_BPF and a kernel with eBPF enabled"]
fn loads_program_and_exercises_map_crud() {
    for map_type in [
        MapType::Array,
        MapType::LpmTrie,
        MapType::ArrayOfMaps,
        MapType::SocketStorage,
        MapType::RingBuffer,
        MapType::StructOps,
        MapType::UserRingBuffer,
        MapType::Arena,
        MapType::InstructionArray,
    ] {
        let supported = map_type
            .is_supported()
            .unwrap_or_else(|error| panic!("{map_type:?} probe failed: {error}"));
        assert!(supported, "{map_type:?} was not detected");
    }
    assert!(!MapType::Other(u32::MAX).is_supported().unwrap());
    assert!(ProgramType::SocketFilter.is_supported().unwrap());
    assert!(ProgramType::SocketFilter
        .is_helper_supported(HelperId::MAP_LOOKUP_ELEMENT)
        .unwrap());

    let mut mmap_spec = MapSpec::new("mapped_values", MapType::Array, 4, 8, 2);
    mmap_spec.set_flags(MapFlags::MMAPABLE);
    let mmap_map = Map::create(mmap_spec).unwrap();
    let mut memory = mmap_map.mmap_mut().unwrap();
    assert!(mmap_map.mmap().is_err());
    {
        let mut data = MappedDataSectionMut::new(&mut memory);
        data.write(0, &0xfeed_face_cafe_beef_u64).unwrap();
        assert_eq!(data.read::<u64>(0).unwrap(), 0xfeed_face_cafe_beef);
    }
    assert_eq!(
        mmap_map.lookup(&0_u32.to_ne_bytes()).unwrap().as_deref(),
        Some(0xfeed_face_cafe_beef_u64.to_ne_bytes().as_slice())
    );
    drop(memory);
    assert_eq!(
        mmap_map.mmap().unwrap().read_vec(0, 8).unwrap(),
        0xfeed_face_cafe_beef_u64.to_ne_bytes()
    );

    let object = Object::parse_named("kernel-smoke", &loadable_object()).unwrap();
    let loaded = object.load().unwrap();
    let map = loaded.map("values").unwrap();

    let key = 2_u32.to_ne_bytes();
    let value = 0x1234_5678_9abc_def0_u64.to_ne_bytes();
    map.update(&key, &value, UpdateMode::Any).unwrap();
    assert_eq!(map.lookup(&key).unwrap().as_deref(), Some(value.as_slice()));
    assert_eq!(map.info().unwrap().value_size, 8);
    let drop_packet = loaded.program("drop_packet").unwrap();
    assert_eq!(drop_packet.info().unwrap().name, "drop_packet");
    drop_packet.bind_map(map, 0).unwrap();
    let link = loaded
        .program("track_switch")
        .unwrap()
        .attach_tracepoint_with_cookie("sched", "sched_switch", 0xfeed)
        .unwrap();
    drop(link);
}

#[test]
#[ignore = "requires root or CAP_BPF, BPF uprobe-multi, and an eBPF-enabled kernel"]
fn attaches_usdt_and_receives_cookie() {
    const COOKIE: i32 = 1337;

    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("../libbpf-rs/tests/bin/usdt.bpf.o");
    let executable = env::current_exe().unwrap();
    let loaded = Object::open(&fixture).unwrap().load().unwrap();
    let mut ring = RingBuffer::new(loaded.map("ringbuf").unwrap()).unwrap();
    let program = loaded.program("handle__usdt_with_cookie").unwrap();
    let program_info = program.info().unwrap();
    assert!(!program_info.map_ids.is_empty());
    assert_eq!(
        BtfObject::from_id(program_info.btf_id).unwrap().info().id,
        program_info.btf_id
    );
    let link = program
        .attach_usdt(
            UsdtOptions::new(&executable, "ebeepf_test", "cookie_probe")
                .pid(Some(process::id()))
                .cookie(COOKIE as u64),
        )
        .unwrap();
    assert_eq!(link.info().unwrap().link_type, LinkType::UprobeMulti);

    probe!(ebeepf_test, cookie_probe, 1_u64);

    let mut received = 0;
    let samples = ring
        .poll(Some(Duration::from_secs(1)), |sample| {
            if let Ok(bytes) = <[u8; 4]>::try_from(sample) {
                received = i32::from_ne_bytes(bytes);
            }
        })
        .unwrap();
    assert_eq!(samples, 1);
    assert_eq!(received, COOKIE);
}

#[test]
#[ignore = "requires root or CAP_NET_ADMIN, CAP_BPF, and an eBPF-enabled kernel"]
fn manages_legacy_xdp_and_tc_attachments() {
    let interface = TemporaryInterface::new();
    let loaded = Object::parse_named("network-smoke", &networking_object())
        .unwrap()
        .load()
        .unwrap();

    let xdp_program = loaded.program("pass_xdp").unwrap();
    let xdp = Xdp::from_name(&interface.name).unwrap();
    xdp.attach(
        xdp_program,
        XdpAttachOptions::new().with_flags(XdpFlags::GENERIC),
    )
    .unwrap();
    assert_eq!(
        xdp.program_id(XdpFlags::GENERIC).unwrap(),
        Some(xdp_program.info().unwrap().id)
    );
    xdp.detach(
        XdpAttachOptions::new()
            .with_flags(XdpFlags::GENERIC)
            .replacing(xdp_program),
    )
    .unwrap();

    let tc_program = loaded.program("pass_tc").unwrap();
    let hook = TcHook::new(xdp.interface_index(), TcAttachPoint::Ingress).unwrap();
    hook.create_clsact().unwrap();
    let filter = hook.attach(tc_program, TcAttachOptions::new()).unwrap();
    assert_eq!(
        hook.query(filter.info().identity).unwrap().program_id,
        tc_program.info().unwrap().id
    );
    filter.detach().unwrap();
    hook.destroy_clsact().unwrap();
}

#[test]
#[ignore = "requires root or CAP_BPF, clang with the BPF target, and an eBPF-enabled kernel"]
fn loads_and_attaches_freplace_program() {
    let source_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/bpf");
    let build = tempfile::tempdir().unwrap();
    let target_object = build.path().join("freplace-target.bpf.o");
    let extension_object = build.path().join("freplace-extension.bpf.o");
    compile_bpf(&source_root.join("freplace-target.bpf.c"), &target_object);
    compile_bpf(
        &source_root.join("freplace-extension.bpf.c"),
        &extension_object,
    );

    let target = Object::open(&target_object).unwrap().load().unwrap();
    let target_program = target.program("call_replaceable").unwrap();
    let packet = [0_u8; 64];
    assert_eq!(
        target_program
            .test_run(TestRunOptions::new(&packet))
            .unwrap()
            .return_value,
        2
    );

    let mut extension = Object::open(&extension_object).unwrap();
    extension
        .program_mut("replacement")
        .unwrap()
        .set_attach_target_by_name(target_program, "replaceable")
        .unwrap();
    let extension = extension.load().unwrap();
    let replacement = extension.program("replacement").unwrap();
    let link = replacement.attach_freplace().unwrap();
    assert_eq!(link.info().unwrap().link_type, LinkType::Tracing);
    assert_eq!(
        target_program
            .test_run(TestRunOptions::new(&packet))
            .unwrap()
            .return_value,
        3
    );
    drop(link);
    assert_eq!(
        target_program
            .test_run(TestRunOptions::new(&packet))
            .unwrap()
            .return_value,
        2
    );
}

#[test]
#[ignore = "requires root or CAP_BPF, clang with the BPF target, and socket-map bpf_link support"]
fn loads_and_attaches_sockmap_program() {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/bpf/sockmap.bpf.c");
    let build = tempfile::tempdir().unwrap();
    let object = build.path().join("sockmap.bpf.o");
    compile_bpf(&source, &object);

    let loaded = Object::open(&object).unwrap().load().unwrap();
    let map = loaded.map("sockets").unwrap();
    let program = loaded.program("parse_message").unwrap();
    let link = program
        .attach_sockmap(map, AttachType::StreamParser)
        .unwrap();
    let info = link.info().unwrap();
    assert_eq!(info.link_type, LinkType::SocketMap);
    assert_eq!(info.map_id, Some(map.info().unwrap().id));
}

#[test]
#[ignore = "requires root or CAP_BPF, clang with the BPF target, and struct_ops link support"]
fn loads_and_attaches_elf_struct_ops() {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/bpf/struct-ops.bpf.c");
    let build = tempfile::tempdir().unwrap();
    let object = build.path().join("struct-ops.bpf.o");
    compile_bpf(&source, &object);

    let mut generator = SkeletonBuilder::new();
    generator.object(&object).format(false);
    let skeleton = generator.render().unwrap();
    assert!(skeleton.contains("map.attach_struct_ops()?"));
    assert!(skeleton.contains("map.spec().auto_attach()"));
    assert!(skeleton.contains("pub fn ebeepf_ca(&self) -> Option<&::ebeepf::Link>"));

    let open = Object::open(&object).unwrap();
    let map = open.map("ebeepf_ca").unwrap();
    assert_eq!(map.map_type(), MapType::StructOps);
    assert!(map.flags().contains(MapFlags::LINK));
    assert_eq!(map.value_size(), 48);
    let legacy_map = open.map("ebeepf_legacy_ca").unwrap();
    assert!(!legacy_map.flags().contains(MapFlags::LINK));
    assert_eq!(
        open.program("ebeepf_ca_init").unwrap().program_type(),
        ProgramType::StructOps
    );

    let loaded = open.load().unwrap();
    let map = loaded.map("ebeepf_ca").unwrap();
    assert!(map.info().unwrap().value_size > 48);
    let callback = loaded.program("ebeepf_ca_init").unwrap();
    assert_ne!(callback.spec().attach_btf_id(), 0);
    let link = map.attach_struct_ops().unwrap();
    let info = link.info().unwrap();
    assert_eq!(info.link_type, LinkType::StructOps);
    assert_eq!(info.map_id, Some(map.info().unwrap().id));
    let legacy_link = loaded
        .map("ebeepf_legacy_ca")
        .unwrap()
        .attach_struct_ops()
        .unwrap();
    assert!(legacy_link.as_fd().is_none());
}
