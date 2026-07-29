//! Minimal Linux UAPI boundary.
//!
//! Structures in this module intentionally mirror the relevant prefixes of
//! `union bpf_attr`. Keeping them private lets the rest of the crate stay safe
//! and independent of generated C bindings.

use std::ffi::{CString, OsStr};
use std::fs;
use std::io;
use std::mem::{self, MaybeUninit};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;
use std::ptr;
use std::sync::OnceLock;

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
const BPF_PROG_ATTACH: u32 = 8;
const BPF_PROG_DETACH: u32 = 9;
const BPF_PROG_TEST_RUN: u32 = 10;
const BPF_PROG_GET_NEXT_ID: u32 = 11;
const BPF_MAP_GET_NEXT_ID: u32 = 12;
const BPF_PROG_GET_FD_BY_ID: u32 = 13;
const BPF_MAP_GET_FD_BY_ID: u32 = 14;
const BPF_OBJ_GET_INFO_BY_FD: u32 = 15;
const BPF_PROG_QUERY: u32 = 16;
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
const BPF_LINK_UPDATE: u32 = 29;
const BPF_LINK_GET_FD_BY_ID: u32 = 30;
const BPF_LINK_GET_NEXT_ID: u32 = 31;
const BPF_ITER_CREATE: u32 = 33;
const BPF_LINK_DETACH: u32 = 34;
const BPF_PROG_BIND_MAP: u32 = 35;
const BPF_TOKEN_CREATE: u32 = 36;
const BPF_PROG_ASSOC_STRUCT_OPS: u32 = 38;
const BPF_F_TOKEN_FD: u32 = 1 << 16;

const PERF_TYPE_TRACEPOINT: u32 = 2;
const PERF_TYPE_SOFTWARE: u32 = 1;
const PERF_COUNT_SW_BPF_OUTPUT: u64 = 10;
const PERF_SAMPLE_RAW: u64 = 1 << 10;
const PERF_EVENT_IOC_ENABLE: libc::c_ulong = 0x2400;
const PERF_EVENT_IOC_DISABLE: libc::c_ulong = 0x2401;
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
    pub btf_vmlinux_value_type_id: u32,
    pub value_type_btf_obj_fd: Option<RawFd>,
    pub map_extra: u64,
    pub token_fd: Option<RawFd>,
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
    pub interface_index: u32,
    pub btf_fd: Option<RawFd>,
    pub func_info: &'a [u8],
    pub func_info_record_size: u32,
    pub line_info: &'a [u8],
    pub line_info_record_size: u32,
    pub attach_btf_id: u32,
    pub attach_program_fd: Option<RawFd>,
    pub attach_btf_object_fd: Option<RawFd>,
    pub fd_array: &'a [RawFd],
    pub log_level: u32,
    pub log_size: usize,
    pub token_fd: Option<RawFd>,
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
    core_relocation_count: u32,
    fd_array: u64,
    core_relocations: u64,
    core_relocation_record_size: u32,
    log_true_size: u32,
    program_token_fd: i32,
    fd_array_count: u32,
    signature: u64,
    signature_size: u32,
    keyring_id: i32,
}

#[repr(C)]
#[derive(Default)]
struct ProgramAttachAttr {
    target_fd: u32,
    program_fd: u32,
    attach_type: u32,
    attach_flags: u32,
    replace_program_fd: u32,
    relative_fd_or_id: u32,
    expected_revision: u64,
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
struct ProgramQueryAttr {
    target_fd_or_ifindex: u32,
    attach_type: u32,
    query_flags: u32,
    attach_flags: u32,
    program_ids: u64,
    count: u32,
    _padding: u32,
    program_attach_flags: u64,
    link_ids: u64,
    link_attach_flags: u64,
    revision: u64,
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
struct GetIdWithTokenAttr {
    start_id: u32,
    next_id: u32,
    open_flags: u32,
    token_fd: i32,
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
    btf_flags: u32,
    btf_token_fd: i32,
}

#[repr(C)]
#[derive(Default)]
struct TokenCreateAttr {
    flags: u32,
    bpffs_fd: u32,
}

#[repr(C)]
#[derive(Default)]
pub(crate) struct TokenInfoRaw {
    pub allowed_commands: u64,
    pub allowed_map_types: u64,
    pub allowed_program_types: u64,
    pub allowed_attach_types: u64,
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
struct PerfEventLinkCreateAttr {
    prog_fd: u32,
    target_fd: u32,
    attach_type: u32,
    flags: u32,
    cookie: u64,
}

#[repr(C)]
#[derive(Default)]
struct LinkUpdateAttr {
    link_fd: u32,
    new_prog_fd: u32,
    flags: u32,
    old_prog_fd: u32,
}

#[repr(C)]
#[derive(Default)]
struct ProgramMapAttr {
    first_fd: u32,
    second_fd: u32,
    flags: u32,
}

#[repr(C)]
#[derive(Default)]
struct KprobeMultiLinkCreateAttr {
    prog_fd: u32,
    target_fd: u32,
    attach_type: u32,
    link_flags: u32,
    multi_flags: u32,
    count: u32,
    symbols: u64,
    addresses: u64,
    cookies: u64,
}

#[repr(C)]
#[derive(Default)]
struct TracingMultiLinkCreateAttr {
    prog_fd: u32,
    target_fd: u32,
    attach_type: u32,
    link_flags: u32,
    ids: u64,
    cookies: u64,
    count: u32,
    _padding: u32,
}

#[repr(C)]
#[derive(Default)]
struct UprobeMultiLinkCreateAttr {
    prog_fd: u32,
    target_fd: u32,
    attach_type: u32,
    link_flags: u32,
    path: u64,
    offsets: u64,
    reference_counter_offsets: u64,
    cookies: u64,
    count: u32,
    multi_flags: u32,
    pid: u32,
    path_fd: i32,
}

#[repr(C)]
#[derive(Default)]
struct IteratorLinkCreateAttr {
    prog_fd: u32,
    target_fd: u32,
    attach_type: u32,
    link_flags: u32,
    iterator_info: u64,
    iterator_info_length: u32,
    _padding: u32,
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
    pub btf_vmlinux_id: u32,
    pub map_extra: u64,
    pub hash: u64,
    pub hash_size: u32,
    pub _padding: u32,
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
    pub netns_dev: u64,
    pub netns_ino: u64,
    pub nr_jited_symbols: u32,
    pub nr_jited_function_lengths: u32,
    pub jited_symbols: u64,
    pub jited_function_lengths: u64,
    pub btf_id: u32,
    pub function_info_record_size: u32,
    pub function_info: u64,
    pub function_info_count: u32,
    pub line_info_count: u32,
    pub line_info: u64,
    pub jited_line_info: u64,
    pub jited_line_info_count: u32,
    pub line_info_record_size: u32,
    pub jited_line_info_record_size: u32,
    pub program_tag_count: u32,
    pub program_tags: u64,
    pub run_time_nanoseconds: u64,
    pub run_count: u64,
    pub recursion_misses: u64,
    pub verified_instructions: u32,
    pub attach_btf_object_id: u32,
    pub attach_btf_id: u32,
    pub _padding: u32,
}

#[repr(C, align(8))]
pub(crate) struct LinkInfoRaw {
    pub link_type: u32,
    pub id: u32,
    pub program_id: u32,
    pub _padding: u32,
    pub details: [u8; 48],
}

impl Default for LinkInfoRaw {
    fn default() -> Self {
        Self {
            link_type: 0,
            id: 0,
            program_id: 0,
            _padding: 0,
            details: [0; 48],
        }
    }
}

#[repr(C)]
#[derive(Default)]
pub(crate) struct BtfInfoRaw {
    pub btf: u64,
    pub btf_size: u32,
    pub id: u32,
    pub name: u64,
    pub name_length: u32,
    pub kernel_btf: u32,
}

pub(crate) fn map_create(options: &MapCreate<'_>) -> io::Result<OwnedFd> {
    let token_flag = u32::from(options.token_fd.is_some()) * BPF_F_TOKEN_FD;
    let value_type_flag = u32::from(options.value_type_btf_obj_fd.is_some()) * (1_u32 << 15);
    let mut attr = MapCreateAttr {
        map_type: options.map_type,
        key_size: options.key_size,
        value_size: options.value_size,
        max_entries: options.max_entries,
        map_flags: (options.flags & !(BPF_F_TOKEN_FD | (1_u32 << 15)))
            | token_flag
            | value_type_flag,
        inner_map_fd: fd_u32(options.inner_map_fd)?,
        numa_node: options.numa_node.unwrap_or_default(),
        btf_fd: fd_u32(options.btf_fd)?,
        btf_key_type_id: options.btf_key_type_id,
        btf_value_type_id: options.btf_value_type_id,
        btf_vmlinux_value_type_id: options.btf_vmlinux_value_type_id,
        value_type_btf_obj_fd: options.value_type_btf_obj_fd.unwrap_or_default(),
        map_extra: options.map_extra,
        map_token_fd: options.token_fd.unwrap_or_default(),
        ..Default::default()
    };
    set_object_name(&mut attr.map_name, options.name);
    // The UAPI's map-create payload ends at `excl_prog_hash_size` (byte 92).
    // `repr(C)` rounds this Rust structure up to 96 bytes for its u64
    // alignment, but the four tail-padding bytes are not part of the ABI.
    command_fd_sized(BPF_MAP_CREATE, &attr, MAP_CREATE_ATTR_SIZE)
}

pub(crate) fn probe_map_type(map_type: u32) -> io::Result<bool> {
    let mut key_size = 4;
    let mut value_size = 4;
    let mut max_entries = 1;
    let mut map_flags = 0;
    let mut btf = None;
    let mut btf_key_type_id = 0;
    let mut btf_value_type_id = 0;
    let mut btf_vmlinux_value_type_id = 0;
    let mut value_type_btf_obj_fd = 0;

    match map_type {
        0 => return Ok(false),
        1..=6 | 8..=10 | 14..=18 | 20 | 25 => {}
        7 => value_size = 8,
        11 => {
            key_size = 8;
            value_size = 8;
            map_flags = 1; // BPF_F_NO_PREALLOC
        }
        12 | 13 => {}
        19 | 21 => {
            key_size = 16; // struct bpf_cgroup_storage_key
            value_size = 8;
            max_entries = 0;
        }
        22 | 23 => key_size = 0,
        24 | 28 | 29 | 32 => {
            let loaded = match load_local_storage_probe_btf() {
                Ok(loaded) => loaded,
                Err(_) => return Ok(false),
            };
            btf_key_type_id = 1;
            btf_value_type_id = 3;
            value_size = 8;
            max_entries = 0;
            map_flags = 1; // BPF_F_NO_PREALLOC
            btf = Some(loaded);
        }
        26 => {
            btf_vmlinux_value_type_id = 1;
            value_type_btf_obj_fd = -1;
        }
        27 | 31 => {
            key_size = 0;
            value_size = 0;
            // SAFETY: `sysconf` has no pointer arguments.
            let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
            max_entries = u32::try_from(page_size).unwrap_or(4096);
        }
        30 => {
            key_size = 0;
            max_entries = 1;
        }
        33 => {
            key_size = 0;
            value_size = 0;
            max_entries = 1;
            map_flags = 1 << 10; // BPF_F_MMAPABLE
        }
        34 => value_size = 16, // struct bpf_insn_array_value
        _ => return Ok(false),
    }

    let inner = if matches!(map_type, 12 | 13) {
        match map_create(&MapCreate {
            map_type: 1,
            name: "",
            key_size: 4,
            value_size: 4,
            max_entries: 1,
            flags: 0,
            inner_map_fd: None,
            numa_node: None,
            btf_fd: None,
            btf_key_type_id: 0,
            btf_value_type_id: 0,
            btf_vmlinux_value_type_id: 0,
            value_type_btf_obj_fd: None,
            map_extra: 0,
            token_fd: None,
        }) {
            Ok(inner) => Some(inner),
            Err(_) => return Ok(false),
        }
    } else {
        None
    };
    let attr = MapCreateAttr {
        map_type,
        key_size,
        value_size,
        max_entries,
        map_flags,
        inner_map_fd: inner
            .as_ref()
            .map_or(0, |fd| u32::try_from(fd.as_raw_fd()).unwrap_or_default()),
        btf_fd: btf
            .as_ref()
            .map_or(0, |fd| u32::try_from(fd.as_raw_fd()).unwrap_or_default()),
        btf_key_type_id,
        btf_value_type_id,
        btf_vmlinux_value_type_id,
        value_type_btf_obj_fd,
        ..Default::default()
    };
    match command_fd_sized(BPF_MAP_CREATE, &attr, MAP_CREATE_ATTR_SIZE) {
        Ok(_) => Ok(true),
        Err(error) if map_type == 26 && error.raw_os_error() == Some(524) => Ok(true),
        Err(_) => Ok(false),
    }
}

pub(crate) fn supports_full_range_map_value_offset(token_fd: Option<RawFd>) -> io::Result<bool> {
    let map = map_create(&MapCreate {
        map_type: 2, // BPF_MAP_TYPE_ARRAY
        name: "offset_probe",
        key_size: 4,
        value_size: 1,
        max_entries: 1,
        flags: 0,
        inner_map_fd: None,
        numa_node: None,
        btf_fd: None,
        btf_key_type_id: 0,
        btf_value_type_id: 0,
        btf_vmlinux_value_type_id: 0,
        value_type_btf_obj_fd: None,
        map_extra: 0,
        token_fd,
    })?;
    let instructions = [
        Instruction::new(
            0x18, // BPF_LD | BPF_DW | BPF_IMM
            1,
            2, // BPF_PSEUDO_MAP_VALUE
            0,
            map.as_raw_fd(),
        ),
        Instruction::new(0, 0, 0, 0, 1 << 30),
        Instruction::new(0x95, 0, 0, 0, 0),
    ];
    match program_load(&ProgramLoad {
        program_type: 1, // BPF_PROG_TYPE_SOCKET_FILTER
        expected_attach_type: 0,
        name: "offset_probe",
        instructions: &instructions,
        license: b"GPL\0",
        kernel_version: 0,
        flags: 0,
        interface_index: 0,
        btf_fd: None,
        func_info: &[],
        func_info_record_size: 0,
        line_info: &[],
        line_info_record_size: 0,
        attach_btf_id: 0,
        attach_program_fd: None,
        attach_btf_object_fd: None,
        fd_array: &[],
        log_level: 1,
        log_size: 4096,
        token_fd,
    }) {
        Err((_, log)) if log.contains("direct value offset of") => Ok(false),
        Err((_, log)) if log.contains("invalid access to map value pointer") => Ok(true),
        Err((source, _)) => Err(source),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "full-range map-offset probe unexpectedly loaded",
        )),
    }
}

fn load_local_storage_probe_btf() -> io::Result<OwnedFd> {
    const STRINGS: &[u8] = b"\0bpf_spin_lock\0val\0cnt\0l\0";
    const TYPES: &[u32] = &[
        // int
        0,
        1 << 24,
        4,
        (1 << 24) | 32,
        // struct bpf_spin_lock { int val; }
        1,
        (4 << 24) | 1,
        4,
        15,
        1,
        0,
        // struct val { int cnt; struct bpf_spin_lock l; }
        15,
        (4 << 24) | 2,
        8,
        19,
        1,
        0,
        23,
        2,
        32,
    ];
    let type_length = u32::try_from(mem::size_of_val(TYPES))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "probe BTF is too large"))?;
    let string_length = u32::try_from(STRINGS.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "probe BTF is too large"))?;
    let mut bytes = Vec::with_capacity(24 + type_length as usize + STRINGS.len());
    bytes.extend_from_slice(&0xeb9f_u16.to_ne_bytes());
    bytes.push(1);
    bytes.push(0);
    bytes.extend_from_slice(&24_u32.to_ne_bytes());
    bytes.extend_from_slice(&0_u32.to_ne_bytes());
    bytes.extend_from_slice(&type_length.to_ne_bytes());
    bytes.extend_from_slice(&type_length.to_ne_bytes());
    bytes.extend_from_slice(&string_length.to_ne_bytes());
    for word in TYPES {
        bytes.extend_from_slice(&word.to_ne_bytes());
    }
    bytes.extend_from_slice(STRINGS);
    load_btf(&bytes, 4096).map_err(|(error, log)| {
        io::Error::new(
            error.kind(),
            format!("failed to load probe BTF: {error}: {log}"),
        )
    })
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
    load_btf_with_token(bytes, log_size, None)
}

pub(crate) fn load_btf_with_token(
    bytes: &[u8],
    log_size: usize,
    token_fd: Option<RawFd>,
) -> Result<OwnedFd, (io::Error, String)> {
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
        btf_flags: u32::from(token_fd.is_some()) * BPF_F_TOKEN_FD,
        btf_token_fd: token_fd.unwrap_or_default(),
        ..Default::default()
    };
    command_fd(BPF_BTF_LOAD, &attr).map_err(|error| (error, log_string(&log)))
}

pub(crate) fn program_load(options: &ProgramLoad<'_>) -> Result<OwnedFd, (io::Error, String)> {
    if options.attach_program_fd.is_some() && options.attach_btf_object_fd.is_some() {
        return Err((
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "program and BTF attachment descriptors are mutually exclusive",
            ),
            String::new(),
        ));
    }
    if options.fd_array.iter().any(|fd| *fd < 0) {
        return Err((
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "program FD array contains a negative descriptor",
            ),
            String::new(),
        ));
    }
    let mut log = vec![0_u8; options.log_size];
    let mut attr = ProgramLoadAttr {
        prog_type: options.program_type,
        insn_cnt: u32::try_from(options.instructions.len()).unwrap_or(u32::MAX),
        insns: pointer(options.instructions.as_ptr()),
        license: pointer(options.license.as_ptr()),
        log_level: options.log_level,
        log_size: u32::try_from(log.len()).unwrap_or(u32::MAX),
        log_buf: mut_slice_pointer(&mut log),
        kern_version: options.kernel_version,
        prog_flags: (options.flags & !BPF_F_TOKEN_FD)
            | (u32::from(options.token_fd.is_some()) * BPF_F_TOKEN_FD),
        prog_ifindex: options.interface_index,
        expected_attach_type: options.expected_attach_type,
        prog_btf_fd: fd_u32(options.btf_fd).unwrap_or_default(),
        func_info_rec_size: options.func_info_record_size,
        func_info: slice_pointer(options.func_info),
        func_info_cnt: record_count(options.func_info, options.func_info_record_size),
        line_info_rec_size: options.line_info_record_size,
        line_info: slice_pointer(options.line_info),
        line_info_cnt: record_count(options.line_info, options.line_info_record_size),
        attach_btf_id: options.attach_btf_id,
        attach_prog_fd: fd_u32(options.attach_program_fd.or(options.attach_btf_object_fd))
            .unwrap_or_default(),
        fd_array: slice_pointer(options.fd_array),
        program_token_fd: options.token_fd.unwrap_or_default(),
        // The kfunc array is sparse because index zero denotes vmlinux and is
        // not a descriptor. A nonzero count asks the kernel to bind every
        // element and would therefore reject that reserved zero slot.
        fd_array_count: 0,
        ..Default::default()
    };
    set_object_name(&mut attr.prog_name, options.name);
    command_fd(BPF_PROG_LOAD, &attr).map_err(|error| (error, log_string(&log)))
}

pub(crate) fn probe_program_type(program_type: u32) -> io::Result<bool> {
    let Some(config) = probe_program_config(program_type) else {
        return Ok(false);
    };
    let instructions = [
        Instruction::new(0xb7, 0, 0, 0, 0),
        Instruction::new(0x95, 0, 0, 0, 0),
    ];
    let result = probe_program_load(program_type, &instructions, config, false);
    Ok(match (result, config.expected_failure) {
        (Ok(_), None) => true,
        (Ok(_), Some(_)) => false,
        (Err((error, log)), Some((expected_errno, expected_message))) => {
            error.raw_os_error() == Some(expected_errno)
                && expected_message.is_none_or(|message| log.contains(message))
        }
        (Err(_), None) => false,
    })
}

pub(crate) fn probe_program_helper(program_type: u32, helper_id: u32) -> io::Result<bool> {
    if matches!(program_type, 26..=29) {
        return Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP));
    }
    let Some(config) = probe_program_config(program_type) else {
        return Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP));
    };
    let instructions = [
        Instruction::new(0x85, 0, 0, 0, helper_id as i32),
        Instruction::new(0x95, 0, 0, 0, 0),
    ];
    match probe_program_load(program_type, &instructions, config, true) {
        Ok(_) => Ok(true),
        Err((_, log))
            if log.contains("invalid func ")
                || log.contains("unknown func ")
                || log.contains("program of this type cannot use helper ") =>
        {
            Ok(false)
        }
        Err(_) => Ok(true),
    }
}

#[derive(Clone, Copy)]
struct ProbeProgramConfig {
    expected_attach_type: u32,
    kernel_version: u32,
    flags: u32,
    attach_btf_id: u32,
    expected_failure: Option<(i32, Option<&'static str>)>,
}

fn probe_program_config(program_type: u32) -> Option<ProbeProgramConfig> {
    if program_type > 32 {
        return None;
    }
    let mut config = ProbeProgramConfig {
        expected_attach_type: 0,
        kernel_version: 0,
        flags: 0,
        attach_btf_id: 0,
        expected_failure: None,
    };
    match program_type {
        2 => config.kernel_version = running_kernel_version(),
        18 => config.expected_attach_type = 10, // BPF_CGROUP_INET4_CONNECT
        20 => config.expected_attach_type = 16, // BPF_LIRC_MODE2
        25 => config.expected_attach_type = 21, // BPF_CGROUP_GETSOCKOPT
        26 => {
            config.expected_attach_type = 24; // BPF_TRACE_FENTRY
            config.attach_btf_id = 1;
            config.expected_failure =
                Some((libc::EINVAL, Some("attach_btf_id 1 is not a function")));
        }
        27 => config.expected_failure = Some((524, None)), // ENOTSUPP
        28 => {
            config.attach_btf_id = 1;
            config.expected_failure = Some((libc::EINVAL, Some("Cannot replace kernel functions")));
        }
        29 => {
            config.expected_attach_type = 26; // BPF_MODIFY_RETURN
            config.attach_btf_id = 1;
            config.expected_failure =
                Some((libc::EINVAL, Some("attach_btf_id 1 is not a function")));
        }
        30 => config.expected_attach_type = 36, // BPF_SK_LOOKUP
        31 => config.flags = 1 << 4,            // BPF_F_SLEEPABLE
        32 => config.expected_attach_type = 45, // BPF_NETFILTER
        _ => {}
    }
    Some(config)
}

fn probe_program_load(
    program_type: u32,
    instructions: &[Instruction],
    config: ProbeProgramConfig,
    always_log: bool,
) -> Result<OwnedFd, (io::Error, String)> {
    let log = always_log || config.expected_failure.is_some();
    program_load(&ProgramLoad {
        program_type,
        expected_attach_type: config.expected_attach_type,
        name: "",
        instructions,
        license: b"GPL\0",
        kernel_version: config.kernel_version,
        flags: config.flags,
        interface_index: 0,
        btf_fd: None,
        func_info: &[],
        func_info_record_size: 0,
        line_info: &[],
        line_info_record_size: 0,
        attach_btf_id: config.attach_btf_id,
        attach_program_fd: None,
        attach_btf_object_fd: None,
        fd_array: &[],
        log_level: u32::from(log),
        log_size: if log { 4096 } else { 0 },
        token_fd: None,
    })
}

fn running_kernel_version() -> u32 {
    let Ok(release) = fs::read_to_string("/proc/sys/kernel/osrelease") else {
        return 0;
    };
    let mut components = release.trim().split('.');
    let Some(major) = components
        .next()
        .and_then(|value| value.parse::<u32>().ok())
    else {
        return 0;
    };
    let Some(minor) = components
        .next()
        .and_then(|value| value.parse::<u32>().ok())
    else {
        return 0;
    };
    let Some(patch) = components.next().and_then(|value| {
        value
            .chars()
            .take_while(char::is_ascii_digit)
            .collect::<String>()
            .parse::<u32>()
            .ok()
    }) else {
        return 0;
    };
    (major << 16) | (minor.min(255) << 8) | patch.min(255)
}

pub(crate) fn supports_bpf_cookie() -> bool {
    static SUPPORTED: OnceLock<bool> = OnceLock::new();

    *SUPPORTED.get_or_init(probe_bpf_cookie)
}

fn probe_bpf_cookie() -> bool {
    const BPF_FUNC_GET_ATTACH_COOKIE: i32 = 174;
    let instructions = [
        Instruction::new(0x85, 0, 0, 0, BPF_FUNC_GET_ATTACH_COOKIE),
        Instruction::new(0x95, 0, 0, 0, 0),
    ];
    program_load(&ProgramLoad {
        program_type: 5, // BPF_PROG_TYPE_TRACEPOINT
        expected_attach_type: 0,
        name: "",
        instructions: &instructions,
        license: b"GPL\0",
        kernel_version: 0,
        flags: 0,
        interface_index: 0,
        btf_fd: None,
        func_info: &[],
        func_info_record_size: 0,
        line_info: &[],
        line_info_record_size: 0,
        attach_btf_id: 0,
        attach_program_fd: None,
        attach_btf_object_fd: None,
        fd_array: &[],
        log_level: 0,
        log_size: 0,
        token_fd: None,
    })
    .is_ok()
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

pub(crate) fn token_info(fd: RawFd) -> io::Result<TokenInfoRaw> {
    object_info(fd)
}

pub(crate) fn program_info(fd: RawFd) -> io::Result<ProgramInfoRaw> {
    object_info(fd)
}

pub(crate) fn program_info_with_map_ids(fd: RawFd) -> io::Result<(ProgramInfoRaw, Vec<u32>)> {
    let initial = program_info(fd)?;
    let capacity = initial.nr_map_ids as usize;
    if capacity == 0 {
        return Ok((initial, Vec::new()));
    }
    let mut map_ids = vec![0_u32; capacity];
    let mut info = ProgramInfoRaw {
        map_ids: mut_slice_pointer(&mut map_ids),
        nr_map_ids: u32::try_from(map_ids.len()).unwrap_or(u32::MAX),
        ..Default::default()
    };
    object_info_into(fd, &mut info)?;
    map_ids.truncate((info.nr_map_ids as usize).min(capacity));
    info.map_ids = 0;
    Ok((info, map_ids))
}

pub(crate) fn link_info(fd: RawFd) -> io::Result<LinkInfoRaw> {
    object_info(fd)
}

pub(crate) fn btf_info(fd: RawFd) -> io::Result<(BtfInfoRaw, Vec<u8>, Vec<u8>)> {
    let mut info = object_info::<BtfInfoRaw>(fd)?;
    let btf_capacity = info.btf_size as usize;
    let name_capacity = (info.name_length as usize).max(256);
    let mut btf = vec![0_u8; btf_capacity];
    let mut name = vec![0_u8; name_capacity];
    info.btf = mut_slice_pointer(&mut btf);
    info.btf_size = u32::try_from(btf.len()).unwrap_or(u32::MAX);
    info.name = mut_slice_pointer(&mut name);
    info.name_length = u32::try_from(name.len()).unwrap_or(u32::MAX);
    object_info_into(fd, &mut info)?;
    btf.truncate((info.btf_size as usize).min(btf_capacity));
    name.truncate((info.name_length as usize).min(name_capacity));
    info.btf = 0;
    info.name = 0;
    Ok((info, btf, name))
}

pub(crate) fn btf_metadata(fd: RawFd) -> io::Result<(BtfInfoRaw, Vec<u8>)> {
    let mut info = object_info::<BtfInfoRaw>(fd)?;
    let btf_size = info.btf_size;
    let mut name = vec![0_u8; (info.name_length as usize).max(256)];
    info.btf = 0;
    info.btf_size = 0;
    info.name = mut_slice_pointer(&mut name);
    info.name_length = u32::try_from(name.len()).unwrap_or(u32::MAX);
    object_info_into(fd, &mut info)?;
    name.truncate((info.name_length as usize).min(name.len()));
    info.btf = 0;
    info.btf_size = btf_size;
    info.name = 0;
    Ok((info, name))
}

pub(crate) struct ProgramQueryResult {
    pub attach_flags: u32,
    pub revision: u64,
    pub program_ids: Vec<u32>,
    pub program_attach_flags: Vec<u32>,
    pub link_ids: Vec<u32>,
    pub link_attach_flags: Vec<u32>,
}

pub(crate) fn program_query(
    target_fd_or_ifindex: u32,
    attach_type: u32,
    query_flags: u32,
) -> io::Result<ProgramQueryResult> {
    let mut attr = ProgramQueryAttr {
        target_fd_or_ifindex,
        attach_type,
        query_flags,
        ..Default::default()
    };
    match command_mut(BPF_PROG_QUERY, &mut attr) {
        Ok(_) => {}
        Err(error) if error.raw_os_error() == Some(libc::ENOSPC) => {}
        Err(error) => return Err(error),
    }
    let capacity = attr.count as usize;
    if capacity == 0 {
        return Ok(ProgramQueryResult {
            attach_flags: attr.attach_flags,
            revision: attr.revision,
            program_ids: Vec::new(),
            program_attach_flags: Vec::new(),
            link_ids: Vec::new(),
            link_attach_flags: Vec::new(),
        });
    }
    let mut program_ids = vec![0_u32; capacity];
    let mut program_attach_flags = vec![0_u32; capacity];
    let mut link_ids = vec![0_u32; capacity];
    let mut link_attach_flags = vec![0_u32; capacity];
    attr.count = u32::try_from(capacity).unwrap_or(u32::MAX);
    attr.program_ids = mut_pointer(program_ids.as_mut_ptr());
    attr.program_attach_flags = mut_pointer(program_attach_flags.as_mut_ptr());
    attr.link_ids = mut_pointer(link_ids.as_mut_ptr());
    attr.link_attach_flags = mut_pointer(link_attach_flags.as_mut_ptr());
    command_mut(BPF_PROG_QUERY, &mut attr)?;
    let actual = (attr.count as usize).min(capacity);
    program_ids.truncate(actual);
    program_attach_flags.truncate(actual);
    link_ids.truncate(actual);
    link_attach_flags.truncate(actual);
    Ok(ProgramQueryResult {
        attach_flags: attr.attach_flags,
        revision: attr.revision,
        program_ids,
        program_attach_flags,
        link_ids,
        link_attach_flags,
    })
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

pub(crate) fn btf_get_fd_by_id_with_token(id: u32, token_fd: RawFd) -> io::Result<OwnedFd> {
    command_fd(
        BPF_BTF_GET_FD_BY_ID,
        &GetIdWithTokenAttr {
            start_id: id,
            token_fd,
            ..Default::default()
        },
    )
}

fn object_info<T>(fd: RawFd) -> io::Result<T> {
    let mut info = MaybeUninit::<T>::zeroed();
    let value = info.as_mut_ptr();
    let attr = ObjectInfoAttr {
        bpf_fd: raw_fd_u32(fd)?,
        info_len: u32::try_from(mem::size_of::<T>())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "info type is too large"))?,
        info: mut_pointer(value),
    };
    command(BPF_OBJ_GET_INFO_BY_FD, &attr)?;
    // SAFETY: The value was zero-initialized, and the kernel only writes bytes
    // within the advertised `T` allocation. All info structs contain integers.
    Ok(unsafe { info.assume_init() })
}

fn object_info_into<T>(fd: RawFd, info: &mut T) -> io::Result<()> {
    let attr = ObjectInfoAttr {
        bpf_fd: raw_fd_u32(fd)?,
        info_len: u32::try_from(mem::size_of::<T>())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "info type is too large"))?,
        info: mut_pointer(info),
    };
    command(BPF_OBJ_GET_INFO_BY_FD, &attr).map(drop)
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

pub(crate) fn perf_event_link_create(
    program_fd: RawFd,
    event_fd: RawFd,
    cookie: u64,
) -> io::Result<OwnedFd> {
    let attr = PerfEventLinkCreateAttr {
        prog_fd: raw_fd_u32(program_fd)?,
        target_fd: raw_fd_u32(event_fd)?,
        attach_type: 41, // BPF_PERF_EVENT
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

pub(crate) fn link_update(
    link_fd: RawFd,
    new_program_fd: RawFd,
    old_program_fd: Option<RawFd>,
) -> io::Result<()> {
    let attr = LinkUpdateAttr {
        link_fd: raw_fd_u32(link_fd)?,
        new_prog_fd: raw_fd_u32(new_program_fd)?,
        flags: u32::from(old_program_fd.is_some()),
        old_prog_fd: fd_u32(old_program_fd)?,
    };
    command(BPF_LINK_UPDATE, &attr).map(drop)
}

pub(crate) fn kprobe_multi_link_create(
    program_fd: RawFd,
    attach_type: u32,
    symbols: Option<&[&str]>,
    addresses: Option<&[u64]>,
    cookies: Option<&[u64]>,
    return_probe: bool,
) -> io::Result<OwnedFd> {
    if symbols.is_some() == addresses.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "exactly one of kprobe symbols or addresses is required",
        ));
    }
    let count = symbols.map_or_else(|| addresses.map_or(0, <[u64]>::len), <[&str]>::len);
    if count == 0 || cookies.is_some_and(|cookies| cookies.len() != count) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "kprobe target and cookie counts do not match",
        ));
    }
    let symbol_strings = symbols
        .unwrap_or_default()
        .iter()
        .map(|symbol| {
            CString::new(*symbol).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "kprobe symbol contains NUL")
            })
        })
        .collect::<io::Result<Vec<_>>>()?;
    let symbol_pointers = symbol_strings
        .iter()
        .map(|symbol| pointer(symbol.as_ptr()))
        .collect::<Vec<_>>();
    let attr = KprobeMultiLinkCreateAttr {
        prog_fd: raw_fd_u32(program_fd)?,
        attach_type,
        multi_flags: u32::from(return_probe),
        count: u32_len(count, "kprobe target count")?,
        symbols: slice_pointer(&symbol_pointers),
        addresses: addresses.map_or(0, slice_pointer),
        cookies: cookies.map_or(0, slice_pointer),
        ..Default::default()
    };
    command_fd(BPF_LINK_CREATE, &attr)
}

pub(crate) struct UprobeMultiTarget<'a> {
    pub program_fd: RawFd,
    pub attach_type: u32,
    pub path: &'a Path,
    pub offsets: &'a [u64],
    pub reference_counter_offsets: Option<&'a [u64]>,
    pub cookies: Option<&'a [u64]>,
    pub pid: Option<u32>,
    pub return_probe: bool,
}

pub(crate) fn uprobe_multi_link_create(target: &UprobeMultiTarget<'_>) -> io::Result<OwnedFd> {
    let count = target.offsets.len();
    if count == 0
        || target
            .reference_counter_offsets
            .is_some_and(|offsets| offsets.len() != count)
        || target.cookies.is_some_and(|cookies| cookies.len() != count)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "uprobe target and optional metadata counts do not match",
        ));
    }
    let path = path_cstring(target.path.as_os_str())?;
    let attr = UprobeMultiLinkCreateAttr {
        prog_fd: raw_fd_u32(target.program_fd)?,
        attach_type: target.attach_type,
        path: pointer(path.as_ptr()),
        offsets: slice_pointer(target.offsets),
        reference_counter_offsets: target.reference_counter_offsets.map_or(0, slice_pointer),
        cookies: target.cookies.map_or(0, slice_pointer),
        count: u32_len(count, "uprobe target count")?,
        multi_flags: u32::from(target.return_probe),
        pid: target.pid.unwrap_or_default(),
        ..Default::default()
    };
    command_fd(BPF_LINK_CREATE, &attr)
}

pub(crate) fn iterator_link_create(
    program_fd: RawFd,
    attach_type: u32,
    iterator_info: Option<&[u8; 16]>,
) -> io::Result<OwnedFd> {
    let attr = IteratorLinkCreateAttr {
        prog_fd: raw_fd_u32(program_fd)?,
        attach_type,
        iterator_info: iterator_info.map_or(0, |info| pointer(info.as_ptr())),
        iterator_info_length: if iterator_info.is_some() { 16 } else { 0 },
        ..Default::default()
    };
    command_fd(BPF_LINK_CREATE, &attr)
}

pub(crate) fn iterator_create(link_fd: RawFd) -> io::Result<OwnedFd> {
    #[repr(C)]
    struct Attr {
        link_fd: u32,
        flags: u32,
    }
    command_fd(
        BPF_ITER_CREATE,
        &Attr {
            link_fd: raw_fd_u32(link_fd)?,
            flags: 0,
        },
    )
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
        data_in: slice_pointer(options.data),
        data_out: mut_slice_pointer(&mut data_output),
        repeat: options.repeat,
        ctx_size_in: u32_len(options.context.len(), "test context")?,
        ctx_size_out: u32_len(context_output.len(), "test context output")?,
        ctx_in: slice_pointer(options.context),
        ctx_out: mut_slice_pointer(&mut context_output),
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

pub(crate) fn program_attach(
    program_fd: RawFd,
    target_fd: RawFd,
    attach_type: u32,
    flags: u32,
) -> io::Result<()> {
    let attr = ProgramAttachAttr {
        target_fd: raw_fd_u32(target_fd)?,
        program_fd: raw_fd_u32(program_fd)?,
        attach_type,
        attach_flags: flags,
        ..Default::default()
    };
    command(BPF_PROG_ATTACH, &attr).map(drop)
}

pub(crate) fn program_detach(
    program_fd: RawFd,
    target_fd: RawFd,
    attach_type: u32,
) -> io::Result<()> {
    let attr = ProgramAttachAttr {
        target_fd: raw_fd_u32(target_fd)?,
        program_fd: raw_fd_u32(program_fd)?,
        attach_type,
        ..Default::default()
    };
    command(BPF_PROG_DETACH, &attr).map(drop)
}

pub(crate) fn program_bind_map(program_fd: RawFd, map_fd: RawFd, flags: u32) -> io::Result<()> {
    let attr = ProgramMapAttr {
        first_fd: raw_fd_u32(program_fd)?,
        second_fd: raw_fd_u32(map_fd)?,
        flags,
    };
    command(BPF_PROG_BIND_MAP, &attr).map(drop)
}

pub(crate) fn program_associate_struct_ops(
    program_fd: RawFd,
    map_fd: RawFd,
    flags: u32,
) -> io::Result<()> {
    // BPF_PROG_ASSOC_STRUCT_OPS orders map_fd before prog_fd.
    let attr = ProgramMapAttr {
        first_fd: raw_fd_u32(map_fd)?,
        second_fd: raw_fd_u32(program_fd)?,
        flags,
    };
    command(BPF_PROG_ASSOC_STRUCT_OPS, &attr).map(drop)
}

pub(crate) fn token_create(bpffs_fd: RawFd, flags: u32) -> io::Result<OwnedFd> {
    let attr = TokenCreateAttr {
        flags,
        bpffs_fd: raw_fd_u32(bpffs_fd)?,
    };
    command_fd(BPF_TOKEN_CREATE, &attr)
}

pub(crate) fn struct_ops_link_create(map_fd: RawFd) -> io::Result<OwnedFd> {
    let attr = LinkCreateAttr {
        prog_fd: raw_fd_u32(map_fd)?,
        attach_type: 44,
        ..Default::default()
    };
    command_fd(BPF_LINK_CREATE, &attr)
}

pub(crate) fn tracing_multi_link_create(
    program_fd: RawFd,
    attach_type: u32,
    type_ids: &[u32],
    cookies: Option<&[u64]>,
) -> io::Result<OwnedFd> {
    if type_ids.is_empty() || cookies.is_some_and(|cookies| cookies.len() != type_ids.len()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "tracing-multi targets and cookies have incompatible lengths",
        ));
    }
    let attr = TracingMultiLinkCreateAttr {
        prog_fd: raw_fd_u32(program_fd)?,
        attach_type,
        ids: slice_pointer(type_ids),
        cookies: cookies.map_or(0, slice_pointer),
        count: u32::try_from(type_ids.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "too many BTF targets"))?,
        ..Default::default()
    };
    command_fd(BPF_LINK_CREATE, &attr)
}

pub(crate) fn tracepoint_event(tracepoint_id: u64, cpu: i32) -> io::Result<OwnedFd> {
    let attr = PerfEventAttr {
        event_type: PERF_TYPE_TRACEPOINT,
        size: mem::size_of::<PerfEventAttr>() as u32,
        config: tracepoint_id,
        sample_period: 1,
        flags: 1, // disabled
        wakeup_events: 1,
        ..Default::default()
    };
    perf_event_open(&attr, -1, cpu)
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

pub(crate) fn perf_event_disable(fd: RawFd) -> io::Result<()> {
    // SAFETY: PERF_EVENT_IOC_DISABLE takes an ignored integer argument and
    // `fd` is expected to be a perf-event descriptor.
    if unsafe { libc::ioctl(fd, PERF_EVENT_IOC_DISABLE, 0) } < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub(crate) fn perf_event_set_bpf(fd: RawFd, program_fd: RawFd) -> io::Result<()> {
    // SAFETY: This ioctl command takes an integer program descriptor and `fd`
    // is a perf-event descriptor.
    if unsafe { libc::ioctl(fd, PERF_EVENT_IOC_SET_BPF, program_fd) } < 0 {
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
    perf_event_set_bpf(fd.as_raw_fd(), program_fd)?;
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

fn slice_pointer<T>(slice: &[T]) -> u64 {
    if slice.is_empty() {
        0
    } else {
        pointer(slice.as_ptr())
    }
}

fn mut_pointer<T>(pointer: *mut T) -> u64 {
    pointer as usize as u64
}

fn mut_slice_pointer<T>(slice: &mut [T]) -> u64 {
    if slice.is_empty() {
        0
    } else {
        mut_pointer(slice.as_mut_ptr())
    }
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
        assert_eq!(mem::size_of::<ProgramLoadAttr>(), 168);
        assert_eq!(mem::size_of::<BtfLoadAttr>(), 40);
        assert_eq!(mem::size_of::<TokenCreateAttr>(), 8);
        assert_eq!(mem::size_of::<TokenInfoRaw>(), 32);
        assert_eq!(mem::size_of::<ObjectPathAttr>(), 24);
        assert_eq!(mem::size_of::<GetIdAttr>(), 12);
        assert_eq!(mem::size_of::<GetIdWithTokenAttr>(), 16);
        assert_eq!(mem::size_of::<ProgramAttachAttr>(), 32);
        assert_eq!(mem::size_of::<ProgramQueryAttr>(), 64);
        assert_eq!(mem::size_of::<LinkCreateAttr>(), 32);
        assert_eq!(mem::offset_of!(LinkCreateAttr, cookie), 24);
        assert_eq!(mem::size_of::<PerfEventLinkCreateAttr>(), 24);
        assert_eq!(mem::offset_of!(PerfEventLinkCreateAttr, cookie), 16);
        assert_eq!(mem::size_of::<LinkUpdateAttr>(), 16);
        assert_eq!(mem::size_of::<ProgramMapAttr>(), 12);
        assert_eq!(mem::size_of::<KprobeMultiLinkCreateAttr>(), 48);
        assert_eq!(mem::size_of::<TracingMultiLinkCreateAttr>(), 40);
        assert_eq!(mem::size_of::<UprobeMultiLinkCreateAttr>(), 64);
        assert_eq!(mem::size_of::<IteratorLinkCreateAttr>(), 32);
        assert_eq!(mem::size_of::<NetfilterLinkCreateAttr>(), 32);
        assert_eq!(mem::size_of::<MapInfoRaw>(), 104);
        assert_eq!(mem::size_of::<ProgramInfoRaw>(), 232);
        assert_eq!(mem::size_of::<LinkInfoRaw>(), 64);
        assert_eq!(mem::size_of::<BtfInfoRaw>(), 32);
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
