//! Privileged end-to-end coverage for the loader's kernel UAPI boundary.

use std::env;
use std::path::Path;
use std::process::{self, Command};
use std::time::Duration;

use ebeepf::{
    BtfObject, Instruction, LinkType, Object, RingBuffer, TcAttachOptions, TcAttachPoint, TcHook,
    UpdateMode, UsdtOptions, Xdp, XdpAttachOptions, XdpFlags,
};
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

#[test]
#[ignore = "requires root or CAP_BPF and a kernel with eBPF enabled"]
fn loads_program_and_exercises_map_crud() {
    let object = Object::parse_named("kernel-smoke", &loadable_object()).unwrap();
    let loaded = object.load().unwrap();
    let map = loaded.map("values").unwrap();

    let key = 2_u32.to_ne_bytes();
    let value = 0x1234_5678_9abc_def0_u64.to_ne_bytes();
    map.update(&key, &value, UpdateMode::Any).unwrap();
    assert_eq!(map.lookup(&key).unwrap().as_deref(), Some(value.as_slice()));
    assert_eq!(map.info().unwrap().value_size, 8);
    assert_eq!(
        loaded.program("drop_packet").unwrap().info().unwrap().name,
        "drop_packet"
    );
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
