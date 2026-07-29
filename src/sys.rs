//! Minimal Linux UAPI boundary.
//!
//! Structures in this module intentionally mirror the relevant prefixes of
//! `union bpf_attr`. Keeping them private lets the rest of the crate stay safe
//! and independent of generated C bindings.

use std::ffi::{CString, OsStr};
use std::io;
use std::mem::{self, MaybeUninit};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;
use std::ptr;

use crate::instruction::Instruction;

pub(crate) const BPF_OBJ_NAME_LEN: usize = 16;

const BPF_MAP_CREATE: u32 = 0;
const BPF_MAP_LOOKUP_ELEM: u32 = 1;
const BPF_MAP_UPDATE_ELEM: u32 = 2;
const BPF_MAP_DELETE_ELEM: u32 = 3;
const BPF_MAP_GET_NEXT_KEY: u32 = 4;
const BPF_PROG_LOAD: u32 = 5;
const BPF_OBJ_PIN: u32 = 6;
const BPF_OBJ_GET: u32 = 7;
const BPF_PROG_TEST_RUN: u32 = 10;
const BPF_PROG_GET_NEXT_ID: u32 = 11;
const BPF_MAP_GET_NEXT_ID: u32 = 12;
const BPF_PROG_GET_FD_BY_ID: u32 = 13;
const BPF_MAP_GET_FD_BY_ID: u32 = 14;
const BPF_OBJ_GET_INFO_BY_FD: u32 = 15;
const BPF_RAW_TRACEPOINT_OPEN: u32 = 17;
const BPF_BTF_LOAD: u32 = 18;
const BPF_BTF_GET_FD_BY_ID: u32 = 19;
const BPF_MAP_LOOKUP_AND_DELETE_ELEM: u32 = 21;
const BPF_MAP_FREEZE: u32 = 22;
const BPF_BTF_GET_NEXT_ID: u32 = 23;
const BPF_MAP_LOOKUP_BATCH: u32 = 24;
const BPF_MAP_LOOKUP_AND_DELETE_BATCH: u32 = 25;
const BPF_MAP_UPDATE_BATCH: u32 = 26;
const BPF_MAP_DELETE_BATCH: u32 = 27;
const BPF_LINK_CREATE: u32 = 28;
const BPF_LINK_GET_FD_BY_ID: u32 = 30;
const BPF_LINK_GET_NEXT_ID: u32 = 31;
const BPF_LINK_DETACH: u32 = 34;

const PERF_TYPE_TRACEPOINT: u32 = 2;
const PERF_TYPE_SOFTWARE: u32 = 1;
const PERF_COUNT_SW_BPF_OUTPUT: u64 = 10;
const PERF_SAMPLE_RAW: u64 = 1 << 10;
const PERF_EVENT_IOC_ENABLE: libc::c_ulong = 0x2400;
const PERF_EVENT_IOC_SET_BPF: libc::c_ulong = 0x4004_2408;
const PERF_FLAG_FD_CLOEXEC: libc::c_ulong = 1 << 3;

#[derive(Debug)]
pub(crate) struct MapCreate<'a> {
    pub map_type: u32,
    pub name: &'a str,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub flags: u32,
    pub inner_map_fd: Option<RawFd>,
    pub numa_node: Option<u32>,
    pub btf_fd: Option<RawFd>,
    pub btf_key_type_id: u32,
    pub btf_value_type_id: u32,
    pub map_extra: u64,
}

#[derive(Debug)]
pub(crate) struct ProgramLoad<'a> {
    pub program_type: u32,
    pub expected_attach_type: u32,
    pub name: &'a str,
    pub instructions: &'a [Instruction],
    pub license: &'a [u8],
    pub kernel_version: u32,
    pub flags: u32,
    pub btf_fd: Option<RawFd>,
    pub func_info: &'a [u8],
    pub func_info_record_size: u32,
    pub line_info: &'a [u8],
    pub line_info_record_size: u32,
    pub attach_btf_id: u32,
    pub attach_program_fd: Option<RawFd>,
    pub log_level: u32,
    pub log_size: usize,
}

#[repr(C)]
#[derive(Default)]
struct MapCreateAttr {
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
    inner_map_fd: u32,
    numa_node: u32,
    map_name: [u8; BPF_OBJ_NAME_LEN],
    map_ifindex: u32,
    btf_fd: u32,
    btf_key_type_id: u32,
    btf_value_type_id: u32,
    btf_vmlinux_value_type_id: u32,
    map_extra: u64,
    value_type_btf_obj_fd: i32,
    map_token_fd: i32,
    excl_prog_hash: u64,
    excl_prog_hash_size: u32,
}

const MAP_CREATE_ATTR_SIZE: usize =
    mem::offset_of!(MapCreateAttr, excl_prog_hash_size) + mem::size_of::<u32>();

#[repr(C)]
#[derive(Default)]
struct MapElementAttr {
    map_fd: u32,
    _padding: u32,
    key: u64,
    value_or_next_key: u64,
    flags: u64,
}

#[repr(C)]
#[derive(Default)]
struct MapBatchAttr {
    in_batch: u64,
    out_batch: u64,
    keys: u64,
    values: u64,
    count: u32,
    map_fd: u32,
    element_flags: u64,
    flags: u64,
}

#[repr(C)]
#[derive(Default)]
struct ProgramLoadAttr {
    prog_type: u32,
    insn_cnt: u32,
    insns: u64,
    license: u64,
    log_level: u32,
    log_size: u32,
    log_buf: u64,
    kern_version: u32,
    prog_flags: u32,
    prog_name: [u8; BPF_OBJ_NAME_LEN],
    prog_ifindex: u32,
    expected_attach_type: u32,
    prog_btf_fd: u32,
    func_info_rec_size: u32,
    func_info: u64,
    func_info_cnt: u32,
    line_info_rec_size: u32,
    line_info: u64,
    line_info_cnt: u32,
    attach_btf_id: u32,
    attach_prog_fd: u32,
}

#[repr(C)]
#[derive(Default)]
struct ObjectPathAttr {
    pathname: u64,
    bpf_fd: u32,
    file_flags: u32,
    path_fd: i32,
    _padding: u32,
}

#[repr(C)]
#[derive(Default)]
struct ObjectInfoAttr {
    bpf_fd: u32,
    info_len: u32,
    info: u64,
}

#[repr(C)]
#[derive(Default)]
struct GetIdAttr {
    start_id: u32,
    next_id: u32,
    open_flags: u32,
}

#[repr(C)]
#[derive(Default)]
struct BtfLoadAttr {
    btf: u64,
    btf_log_buf: u64,
    btf_size: u32,
    btf_log_size: u32,
    btf_log_level: u32,
    btf_log_true_size: u32,
}

#[repr(C)]
#[derive(Default)]
struct LinkCreateAttr {
    prog_fd: u32,
    target_fd_or_ifindex: u32,
    attach_type: u32,
    flags: u32,
    target_btf_id: u32,
    _padding: u32,
    cookie: u64,
}

#[repr(C)]
#[derive(Default)]
struct NetfilterLinkCreateAttr {
    prog_fd: u32,
    target_fd: u32,
    attach_type: u32,
    link_flags: u32,
    protocol_family: u32,
    hook_number: u32,
    priority: i32,
    netfilter_flags: u32,
}

#[repr(C)]
#[derive(Default)]
struct RawTracepointAttr {
    name: u64,
    prog_fd: u32,
    _padding: u32,
    cookie: u64,
}

#[repr(C)]
#[derive(Default)]
struct ProgramTestRunAttr {
    prog_fd: u32,
    retval: u32,
    data_size_in: u32,
    data_size_out: u32,
    data_in: u64,
    data_out: u64,
    repeat: u32,
    duration: u32,
    ctx_size_in: u32,
    ctx_size_out: u32,
    ctx_in: u64,
    ctx_out: u64,
    flags: u32,
    cpu: u32,
    batch_size: u32,
    _padding: u32,
}

#[repr(C)]
#[derive(Default)]
struct PerfEventAttr {
    event_type: u32,
    size: u32,
    config: u64,
    sample_period: u64,
    sample_type: u64,
    read_format: u64,
    flags: u64,
    wakeup_events: u32,
    breakpoint_type: u32,
    config1: u64,
    config2: u64,
    branch_sample_type: u64,
    sample_regs_user: u64,
    sample_stack_user: u32,
    clock_id: i32,
    sample_regs_intr: u64,
    aux_watermark: u32,
    sample_max_stack: u16,
    _reserved_2: u16,
}

#[repr(C)]
#[derive(Default)]
pub(crate) struct MapInfoRaw {
    pub map_type: u32,
    pub id: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub map_flags: u32,
    pub name: [u8; BPF_OBJ_NAME_LEN],
    pub ifindex: u32,
    pub btf_vmlinux_value_type_id: u32,
    pub netns_dev: u64,
    pub netns_ino: u64,
    pub btf_id: u32,
    pub btf_key_type_id: u32,
    pub btf_value_type_id: u32,
    pub _padding: u32,
    pub map_extra: u64,
}

#[repr(C)]
#[derive(Default)]
pub(crate) struct ProgramInfoRaw {
    pub program_type: u32,
    pub id: u32,
    pub tag: [u8; 8],
    pub jited_program_len: u32,
    pub xlated_program_len: u32,
    pub jited_program_insns: u64,
    pub xlated_program_insns: u64,
    pub load_time: u64,
    pub created_by_uid: u32,
    pub nr_map_ids: u32,
    pub map_ids: u64,
    pub name: [u8; BPF_OBJ_NAME_LEN],
    pub ifindex: u32,
    pub gpl_compatible: u32,
}

pub(crate) fn map_create(options: &MapCreate<'_>) -> io::Result<OwnedFd> {
    let mut attr = MapCreateAttr {
        map_type: options.map_type,
        key_size: options.key_size,
        value_size: options.value_size,
        max_entries: options.max_entries,
        map_flags: options.flags,
        inner_map_fd: fd_u32(options.inner_map_fd)?,
        numa_node: options.numa_node.unwrap_or_default(),
        btf_fd: fd_u32(options.btf_fd)?,
        btf_key_type_id: options.btf_key_type_id,
        btf_value_type_id: options.btf_value_type_id,
        map_extra: options.map_extra,
        ..Default::default()
    };
    set_object_name(&mut attr.map_name, options.name);
    // The UAPI's map-create payload ends at `excl_prog_hash_size` (byte 92).
    // `repr(C)` rounds this Rust structure up to 96 bytes for its u64
    // alignment, but the four tail-padding bytes are not part of the ABI.
    command_fd_sized(BPF_MAP_CREATE, &attr, MAP_CREATE_ATTR_SIZE)
}

pub(crate) fn map_lookup(fd: RawFd, key: &[u8], value: &mut [u8], flags: u64) -> io::Result<bool> {
    let attr = MapElementAttr {
        map_fd: raw_fd_u32(fd)?,
        key: slice_pointer(key),
        value_or_next_key: mut_pointer(value.as_mut_ptr()),
        flags,
        ..Default::default()
    };
    match command(BPF_MAP_LOOKUP_ELEM, &attr) {
        Ok(_) => Ok(true),
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(false),
        Err(error) => Err(error),
    }
}

pub(crate) fn map_update(fd: RawFd, key: &[u8], value: &[u8], flags: u64) -> io::Result<()> {
    let attr = MapElementAttr {
        map_fd: raw_fd_u32(fd)?,
        key: slice_pointer(key),
        value_or_next_key: pointer(value.as_ptr()),
        flags,
        ..Default::default()
    };
    command(BPF_MAP_UPDATE_ELEM, &attr).map(drop)
}

pub(crate) fn map_delete(fd: RawFd, key: &[u8]) -> io::Result<bool> {
    let attr = MapElementAttr {
        map_fd: raw_fd_u32(fd)?,
        key: slice_pointer(key),
        ..Default::default()
    };
    match command(BPF_MAP_DELETE_ELEM, &attr) {
        Ok(_) => Ok(true),
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(false),
        Err(error) => Err(error),
    }
}

pub(crate) fn map_next_key(
    fd: RawFd,
    previous: Option<&[u8]>,
    next: &mut [u8],
) -> io::Result<bool> {
    let attr = MapElementAttr {
        map_fd: raw_fd_u32(fd)?,
        key: previous.map_or(0, |key| pointer(key.as_ptr())),
        value_or_next_key: mut_pointer(next.as_mut_ptr()),
        ..Default::default()
    };
    match command(BPF_MAP_GET_NEXT_KEY, &attr) {
        Ok(_) => Ok(true),
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(false),
        Err(error) => Err(error),
    }
}

pub(crate) fn map_lookup_and_delete(fd: RawFd, key: &[u8], value: &mut [u8]) -> io::Result<bool> {
    let attr = MapElementAttr {
        map_fd: raw_fd_u32(fd)?,
        key: slice_pointer(key),
        value_or_next_key: mut_pointer(value.as_mut_ptr()),
        ..Default::default()
    };
    match command(BPF_MAP_LOOKUP_AND_DELETE_ELEM, &attr) {
        Ok(_) => Ok(true),
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(false),
        Err(error) => Err(error),
    }
}

pub(crate) fn map_freeze(fd: RawFd) -> io::Result<()> {
    let attr = MapElementAttr {
        map_fd: raw_fd_u32(fd)?,
        ..Default::default()
    };
    command(BPF_MAP_FREEZE, &attr).map(drop)
}

pub(crate) struct BatchLookup<'a> {
    pub fd: RawFd,
    pub cursor: Option<&'a [u8]>,
    pub next_cursor: &'a mut [u8],
    pub keys: &'a mut [u8],
    pub values: &'a mut [u8],
    pub count: u32,
    pub delete: bool,
}

pub(crate) struct BatchLookupResult {
    pub count: u32,
    pub done: bool,
}

pub(crate) fn map_lookup_batch(options: &mut BatchLookup<'_>) -> io::Result<BatchLookupResult> {
    let mut attr = MapBatchAttr {
        in_batch: options.cursor.map_or(0, |cursor| pointer(cursor.as_ptr())),
        out_batch: mut_pointer(options.next_cursor.as_mut_ptr()),
        keys: mut_pointer(options.keys.as_mut_ptr()),
        values: mut_pointer(options.values.as_mut_ptr()),
        count: options.count,
        map_fd: raw_fd_u32(options.fd)?,
        ..Default::default()
    };
    let command_number = if options.delete {
        BPF_MAP_LOOKUP_AND_DELETE_BATCH
    } else {
        BPF_MAP_LOOKUP_BATCH
    };
    let done = match command_mut(command_number, &mut attr) {
        Ok(_) => false,
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => true,
        Err(error) => return Err(error),
    };
    Ok(BatchLookupResult {
        count: attr.count,
        done,
    })
}

pub(crate) fn map_update_batch(
    fd: RawFd,
    keys: &[u8],
    values: &[u8],
    count: u32,
    element_flags: u64,
) -> io::Result<u32> {
    let mut attr = MapBatchAttr {
        keys: pointer(keys.as_ptr()),
        values: pointer(values.as_ptr()),
        count,
        map_fd: raw_fd_u32(fd)?,
        element_flags,
        ..Default::default()
    };
    command_mut(BPF_MAP_UPDATE_BATCH, &mut attr)?;
    Ok(attr.count)
}

pub(crate) fn map_delete_batch(fd: RawFd, keys: &[u8], count: u32) -> io::Result<u32> {
    let mut attr = MapBatchAttr {
        keys: pointer(keys.as_ptr()),
        count,
        map_fd: raw_fd_u32(fd)?,
        ..Default::default()
    };
    command_mut(BPF_MAP_DELETE_BATCH, &mut attr)?;
    Ok(attr.count)
}

pub(crate) fn load_btf(bytes: &[u8], log_size: usize) -> Result<OwnedFd, (io::Error, String)> {
    let mut log = vec![0_u8; log_size];
    let attr = BtfLoadAttr {
        btf: pointer(bytes.as_ptr()),
        btf_log_buf: mut_pointer(log.as_mut_ptr()),
        btf_size: match u32::try_from(bytes.len()) {
            Ok(value) => value,
            Err(_) => {
                return Err((
                    io::Error::new(io::ErrorKind::InvalidInput, "BTF is larger than u32::MAX"),
                    String::new(),
                ));
            }
        },
        btf_log_size: u32::try_from(log.len()).unwrap_or(u32::MAX),
        btf_log_level: u32::from(!log.is_empty()),
        ..Default::default()
    };
    command_fd(BPF_BTF_LOAD, &attr).map_err(|error| (error, log_string(&log)))
}

pub(crate) fn program_load(options: &ProgramLoad<'_>) -> Result<OwnedFd, (io::Error, String)> {
    let mut log = vec![0_u8; options.log_size];
    let mut attr = ProgramLoadAttr {
        prog_type: options.program_type,
        insn_cnt: u32::try_from(options.instructions.len()).unwrap_or(u32::MAX),
        insns: pointer(options.instructions.as_ptr()),
        license: pointer(options.license.as_ptr()),
        log_level: options.log_level,
        log_size: u32::try_from(log.len()).unwrap_or(u32::MAX),
        log_buf: mut_pointer(log.as_mut_ptr()),
        kern_version: options.kernel_version,
        prog_flags: options.flags,
        expected_attach_type: options.expected_attach_type,
        prog_btf_fd: fd_u32(options.btf_fd).unwrap_or_default(),
        func_info_rec_size: options.func_info_record_size,
        func_info: pointer(options.func_info.as_ptr()),
        func_info_cnt: record_count(options.func_info, options.func_info_record_size),
        line_info_rec_size: options.line_info_record_size,
        line_info: pointer(options.line_info.as_ptr()),
        line_info_cnt: record_count(options.line_info, options.line_info_record_size),
        attach_btf_id: options.attach_btf_id,
        attach_prog_fd: fd_u32(options.attach_program_fd).unwrap_or_default(),
        ..Default::default()
    };
    set_object_name(&mut attr.prog_name, options.name);
    command_fd(BPF_PROG_LOAD, &attr).map_err(|error| (error, log_string(&log)))
}

pub(crate) fn object_pin(fd: RawFd, path: &Path) -> io::Result<()> {
    let path = path_cstring(path.as_os_str())?;
    let attr = ObjectPathAttr {
        pathname: pointer(path.as_ptr()),
        bpf_fd: raw_fd_u32(fd)?,
        ..Default::default()
    };
    command(BPF_OBJ_PIN, &attr).map(drop)
}

pub(crate) fn object_get(path: &Path) -> io::Result<OwnedFd> {
    let path = path_cstring(path.as_os_str())?;
    let attr = ObjectPathAttr {
        pathname: pointer(path.as_ptr()),
        ..Default::default()
    };
    command_fd(BPF_OBJ_GET, &attr)
}

pub(crate) fn map_info(fd: RawFd) -> io::Result<MapInfoRaw> {
    object_info(fd)
}

pub(crate) fn program_info(fd: RawFd) -> io::Result<ProgramInfoRaw> {
    object_info(fd)
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum ObjectKind {
    Map,
    Program,
    Link,
    Btf,
}

pub(crate) fn next_id(kind: ObjectKind, start: u32) -> io::Result<Option<u32>> {
    let command_number = match kind {
        ObjectKind::Map => BPF_MAP_GET_NEXT_ID,
        ObjectKind::Program => BPF_PROG_GET_NEXT_ID,
        ObjectKind::Link => BPF_LINK_GET_NEXT_ID,
        ObjectKind::Btf => BPF_BTF_GET_NEXT_ID,
    };
    let mut attr = GetIdAttr {
        start_id: start,
        ..Default::default()
    };
    match command_mut(command_number, &mut attr) {
        Ok(_) => Ok(Some(attr.next_id)),
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(None),
        Err(error) => Err(error),
    }
}

pub(crate) fn object_get_fd_by_id(kind: ObjectKind, id: u32) -> io::Result<OwnedFd> {
    let command_number = match kind {
        ObjectKind::Map => BPF_MAP_GET_FD_BY_ID,
        ObjectKind::Program => BPF_PROG_GET_FD_BY_ID,
        ObjectKind::Link => BPF_LINK_GET_FD_BY_ID,
        ObjectKind::Btf => BPF_BTF_GET_FD_BY_ID,
    };
    command_fd(
        command_number,
        &GetIdAttr {
            start_id: id,
            ..Default::default()
        },
    )
}

fn object_info<T>(fd: RawFd) -> io::Result<T> {
    let mut info = MaybeUninit::<T>::zeroed();
    let attr = ObjectInfoAttr {
        bpf_fd: raw_fd_u32(fd)?,
        info_len: u32::try_from(mem::size_of::<T>())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "info type is too large"))?,
        info: mut_pointer(info.as_mut_ptr()),
    };
    command(BPF_OBJ_GET_INFO_BY_FD, &attr)?;
    // SAFETY: The value was zero-initialized, and the kernel only writes bytes
    // within the advertised `T` allocation. All info structs contain integers.
    Ok(unsafe { info.assume_init() })
}

pub(crate) fn link_create(
    program_fd: RawFd,
    target_fd_or_ifindex: u32,
    attach_type: u32,
    flags: u32,
    target_btf_id: u32,
    cookie: u64,
) -> io::Result<OwnedFd> {
    let attr = LinkCreateAttr {
        prog_fd: raw_fd_u32(program_fd)?,
        target_fd_or_ifindex,
        attach_type,
        flags,
        target_btf_id,
        cookie,
        ..Default::default()
    };
    command_fd(BPF_LINK_CREATE, &attr)
}

pub(crate) struct NetfilterLink {
    pub program_fd: RawFd,
    pub protocol_family: u32,
    pub hook_number: u32,
    pub priority: i32,
    pub flags: u32,
}

pub(crate) fn netfilter_link_create(options: &NetfilterLink) -> io::Result<OwnedFd> {
    let attr = NetfilterLinkCreateAttr {
        prog_fd: raw_fd_u32(options.program_fd)?,
        attach_type: 45, // BPF_NETFILTER
        protocol_family: options.protocol_family,
        hook_number: options.hook_number,
        priority: options.priority,
        netfilter_flags: options.flags,
        ..Default::default()
    };
    command_fd(BPF_LINK_CREATE, &attr)
}

pub(crate) fn link_detach(fd: RawFd) -> io::Result<()> {
    #[repr(C)]
    struct Attr {
        link_fd: u32,
    }
    command(
        BPF_LINK_DETACH,
        &Attr {
            link_fd: raw_fd_u32(fd)?,
        },
    )
    .map(drop)
}

pub(crate) fn raw_tracepoint_open(
    name: &str,
    program_fd: RawFd,
    cookie: u64,
) -> io::Result<OwnedFd> {
    let name = CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "tracepoint name contains NUL"))?;
    let attr = RawTracepointAttr {
        name: pointer(name.as_ptr()),
        prog_fd: raw_fd_u32(program_fd)?,
        cookie,
        ..Default::default()
    };
    command_fd(BPF_RAW_TRACEPOINT_OPEN, &attr)
}

pub(crate) struct TestRun<'a> {
    pub program_fd: RawFd,
    pub data: &'a [u8],
    pub context: &'a [u8],
    pub data_output_size: usize,
    pub context_output_size: usize,
    pub repeat: u32,
    pub cpu: Option<u32>,
}

pub(crate) struct TestRunResult {
    pub return_value: u32,
    pub duration_nanoseconds: u32,
    pub data: Vec<u8>,
    pub context: Vec<u8>,
}

pub(crate) fn program_test_run(options: &TestRun<'_>) -> io::Result<TestRunResult> {
    let mut data_output = vec![0_u8; options.data_output_size];
    let mut context_output = vec![0_u8; options.context_output_size];
    let mut attr = ProgramTestRunAttr {
        prog_fd: raw_fd_u32(options.program_fd)?,
        data_size_in: u32_len(options.data.len(), "test input")?,
        data_size_out: u32_len(data_output.len(), "test output")?,
        data_in: pointer(options.data.as_ptr()),
        data_out: mut_pointer(data_output.as_mut_ptr()),
        repeat: options.repeat,
        ctx_size_in: u32_len(options.context.len(), "test context")?,
        ctx_size_out: u32_len(context_output.len(), "test context output")?,
        ctx_in: pointer(options.context.as_ptr()),
        ctx_out: mut_pointer(context_output.as_mut_ptr()),
        flags: u32::from(options.cpu.is_some()),
        cpu: options.cpu.unwrap_or_default(),
        ..Default::default()
    };
    command_mut(BPF_PROG_TEST_RUN, &mut attr)?;
    data_output.truncate(attr.data_size_out as usize);
    context_output.truncate(attr.ctx_size_out as usize);
    Ok(TestRunResult {
        return_value: attr.retval,
        duration_nanoseconds: attr.duration,
        data: data_output,
        context: context_output,
    })
}

pub(crate) fn tracepoint_perf_event(
    tracepoint_id: u64,
    cpu: i32,
    program_fd: RawFd,
) -> io::Result<OwnedFd> {
    let attr = PerfEventAttr {
        event_type: PERF_TYPE_TRACEPOINT,
        size: mem::size_of::<PerfEventAttr>() as u32,
        config: tracepoint_id,
        sample_period: 1,
        flags: 1, // disabled
        wakeup_events: 1,
        ..Default::default()
    };
    perf_event_attach(&attr, -1, cpu, program_fd)
}

pub(crate) fn kprobe_perf_event(
    pmu_type: u32,
    function: &str,
    offset: u64,
    return_probe: bool,
    cpu: i32,
    program_fd: RawFd,
) -> io::Result<OwnedFd> {
    let function = CString::new(function)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "function contains NUL"))?;
    let attr = PerfEventAttr {
        event_type: pmu_type,
        size: mem::size_of::<PerfEventAttr>() as u32,
        config: u64::from(return_probe),
        sample_period: 1,
        flags: 1,
        wakeup_events: 1,
        config1: pointer(function.as_ptr()),
        config2: offset,
        ..Default::default()
    };
    perf_event_attach(&attr, -1, cpu, program_fd)
}

pub(crate) struct UprobeTarget<'a> {
    pub pmu_type: u32,
    pub path: &'a Path,
    pub offset: u64,
    pub return_probe: bool,
    pub pid: Option<u32>,
    pub cpu: i32,
    pub program_fd: RawFd,
}

pub(crate) fn uprobe_perf_event(target: &UprobeTarget<'_>) -> io::Result<OwnedFd> {
    let path = path_cstring(target.path.as_os_str())?;
    let attr = PerfEventAttr {
        event_type: target.pmu_type,
        size: mem::size_of::<PerfEventAttr>() as u32,
        config: u64::from(target.return_probe),
        sample_period: 1,
        flags: 1,
        wakeup_events: 1,
        config1: pointer(path.as_ptr()),
        config2: target.offset,
        ..Default::default()
    };
    let pid = target
        .pid
        .map_or(-1, |pid| i32::try_from(pid).unwrap_or(i32::MAX));
    perf_event_attach(&attr, pid, target.cpu, target.program_fd)
}

pub(crate) fn perf_output_event(cpu: i32) -> io::Result<OwnedFd> {
    let attr = PerfEventAttr {
        event_type: PERF_TYPE_SOFTWARE,
        size: mem::size_of::<PerfEventAttr>() as u32,
        config: PERF_COUNT_SW_BPF_OUTPUT,
        sample_period: 1,
        sample_type: PERF_SAMPLE_RAW,
        flags: 1,
        wakeup_events: 1,
        ..Default::default()
    };
    perf_event_open(&attr, -1, cpu)
}

pub(crate) fn perf_event_enable(fd: RawFd) -> io::Result<()> {
    // SAFETY: PERF_EVENT_IOC_ENABLE takes an ignored integer argument and `fd`
    // is expected to be a perf-event descriptor.
    if unsafe { libc::ioctl(fd, PERF_EVENT_IOC_ENABLE, 0) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub(crate) fn socket_attach_bpf(socket_fd: RawFd, program_fd: RawFd) -> io::Result<()> {
    let program_fd = raw_fd_u32(program_fd)?;
    // SAFETY: The option value points to a live `u32` program descriptor and
    // the kernel validates both descriptors.
    let result = unsafe {
        libc::setsockopt(
            socket_fd,
            libc::SOL_SOCKET,
            libc::SO_ATTACH_BPF,
            ptr::from_ref(&program_fd).cast(),
            mem::size_of_val(&program_fd) as libc::socklen_t,
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub(crate) fn socket_detach_bpf(socket_fd: RawFd) -> io::Result<()> {
    let zero = 0_u32;
    // SAFETY: SO_DETACH_BPF ignores the option payload but Linux requires a
    // valid pointer and length on some versions.
    let result = unsafe {
        libc::setsockopt(
            socket_fd,
            libc::SOL_SOCKET,
            libc::SO_DETACH_BPF,
            ptr::from_ref(&zero).cast(),
            mem::size_of_val(&zero) as libc::socklen_t,
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn perf_event_attach(
    attr: &PerfEventAttr,
    pid: i32,
    cpu: i32,
    program_fd: RawFd,
) -> io::Result<OwnedFd> {
    let fd = perf_event_open(attr, pid, cpu)?;
    // SAFETY: This ioctl command takes an integer program descriptor and `fd`
    // is a perf-event descriptor.
    if unsafe { libc::ioctl(fd.as_raw_fd(), PERF_EVENT_IOC_SET_BPF, program_fd) } < 0 {
        return Err(io::Error::last_os_error());
    }
    perf_event_enable(fd.as_raw_fd())?;
    Ok(fd)
}

fn perf_event_open(attr: &PerfEventAttr, pid: i32, cpu: i32) -> io::Result<OwnedFd> {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: `attr` is an initialized perf_event_attr ABI prefix and all
        // pointed-to strings remain live for the duration of the call.
        let result = unsafe {
            libc::syscall(
                libc::SYS_perf_event_open,
                ptr::from_ref(attr),
                pid,
                cpu,
                -1,
                PERF_FLAG_FD_CLOEXEC,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        let raw_fd = RawFd::try_from(result)
            .map_err(|_| io::Error::other("perf_event_open returned an invalid descriptor"))?;
        // SAFETY: `perf_event_open` returned a new descriptor.
        Ok(unsafe { OwnedFd::from_raw_fd(raw_fd) })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (attr, pid, cpu);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "perf events are only supported on Linux",
        ))
    }
}

fn record_count(bytes: &[u8], record_size: u32) -> u32 {
    if record_size == 0 {
        0
    } else {
        u32::try_from(bytes.len() / record_size as usize).unwrap_or(u32::MAX)
    }
}

fn set_object_name(buffer: &mut [u8; BPF_OBJ_NAME_LEN], name: &str) {
    buffer.fill(0);
    let len = name.len().min(BPF_OBJ_NAME_LEN - 1);
    buffer[..len].copy_from_slice(&name.as_bytes()[..len]);
}

fn log_string(log: &[u8]) -> String {
    let end = log.iter().position(|byte| *byte == 0).unwrap_or(log.len());
    String::from_utf8_lossy(&log[..end]).into_owned()
}

fn path_cstring(path: &OsStr) -> io::Result<CString> {
    CString::new(path.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte"))
}

fn fd_u32(fd: Option<RawFd>) -> io::Result<u32> {
    fd.map_or(Ok(0), raw_fd_u32)
}

fn raw_fd_u32(fd: RawFd) -> io::Result<u32> {
    u32::try_from(fd)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "file descriptor is negative"))
}

fn u32_len(len: usize, what: &str) -> io::Result<u32> {
    u32::try_from(len)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, format!("{what} is too large")))
}

fn pointer<T>(pointer: *const T) -> u64 {
    pointer as usize as u64
}

fn slice_pointer(bytes: &[u8]) -> u64 {
    if bytes.is_empty() {
        0
    } else {
        pointer(bytes.as_ptr())
    }
}

fn mut_pointer<T>(pointer: *mut T) -> u64 {
    pointer as usize as u64
}

fn command_fd<T>(command_number: u32, attr: &T) -> io::Result<OwnedFd> {
    let fd = command(command_number, attr)?;
    // SAFETY: A successful fd-producing bpf command returns a new descriptor
    // owned by the caller.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn command_fd_sized<T>(command_number: u32, attr: &T, attr_size: usize) -> io::Result<OwnedFd> {
    if attr_size > mem::size_of::<T>() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "bpf attribute size exceeds its backing value",
        ));
    }
    let fd = command_sized(command_number, attr, attr_size)?;
    // SAFETY: A successful fd-producing bpf command returns a new descriptor
    // owned by the caller.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn command<T>(command_number: u32, attr: &T) -> io::Result<RawFd> {
    command_sized(command_number, attr, mem::size_of::<T>())
}

fn command_sized<T>(command_number: u32, attr: &T, attr_size: usize) -> io::Result<RawFd> {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: `attr` points to an initialized repr(C) UAPI prefix for this
        // command and remains alive for the duration of the syscall.
        let result = unsafe {
            libc::syscall(
                libc::SYS_bpf,
                libc::c_long::from(command_number),
                ptr::from_ref(attr),
                attr_size,
            )
        };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            RawFd::try_from(result)
                .map_err(|_| io::Error::other("bpf syscall returned an invalid descriptor"))
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (command_number, attr, attr_size);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "eBPF is only supported on Linux",
        ))
    }
}

fn command_mut<T>(command_number: u32, attr: &mut T) -> io::Result<RawFd> {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: `attr` is an initialized, writable repr(C) UAPI structure
        // and remains live for the duration of the syscall.
        let result = unsafe {
            libc::syscall(
                libc::SYS_bpf,
                libc::c_long::from(command_number),
                ptr::from_mut(attr),
                mem::size_of::<T>(),
            )
        };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            RawFd::try_from(result)
                .map_err(|_| io::Error::other("bpf syscall returned an invalid value"))
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (command_number, attr);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "eBPF is only supported on Linux",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_abi_layouts_match_linux_uapi() {
        assert_eq!(mem::size_of::<MapCreateAttr>(), 96);
        assert_eq!(MAP_CREATE_ATTR_SIZE, 92);
        assert_eq!(mem::size_of::<MapElementAttr>(), 32);
        assert_eq!(mem::size_of::<MapBatchAttr>(), 56);
        assert_eq!(mem::size_of::<ProgramLoadAttr>(), 120);
        assert_eq!(mem::size_of::<BtfLoadAttr>(), 32);
        assert_eq!(mem::size_of::<ObjectPathAttr>(), 24);
        assert_eq!(mem::size_of::<GetIdAttr>(), 12);
        assert_eq!(mem::size_of::<LinkCreateAttr>(), 32);
        assert_eq!(mem::size_of::<NetfilterLinkCreateAttr>(), 32);
        // PERF_ATTR_SIZE_VER5. Newer fields are optional ABI suffixes.
        assert_eq!(mem::size_of::<PerfEventAttr>(), 112);
        assert_eq!(mem::size_of::<ProgramTestRunAttr>(), 80);
    }

    #[test]
    fn object_names_are_truncated_and_terminated() {
        let mut name = [0xff; BPF_OBJ_NAME_LEN];
        set_object_name(&mut name, "a-name-that-is-far-too-long");
        assert_eq!(&name[..15], b"a-name-that-is-");
        assert_eq!(name[15], 0);
    }

    #[test]
    fn paths_with_nul_are_rejected() {
        let path = OsStr::from_bytes(b"bad\0path");
        assert_eq!(
            path_cstring(path).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn owned_fd_inputs_reject_negative_values() {
        assert_eq!(
            raw_fd_u32(-1).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }
}
