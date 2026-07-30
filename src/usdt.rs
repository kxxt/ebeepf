//! `SystemTap` USDT note discovery and attachment support.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::str;
use std::sync::{Arc, Mutex};

use goblin::elf::header::ET_DYN;
use goblin::elf::program_header::{PF_X, PT_LOAD};
use goblin::elf::section_header::SHT_NOTE;
use goblin::elf::{Elf, ProgramHeader};

use crate::sys;
use crate::{
    Btf, BtfKind, BtfMember, BtfType, Error, Link, Map, Program, Result, TypeId, UpdateMode,
    UprobeMultiOptions,
};

const NOTE_TYPE: u32 = 3;
const NOTE_NAME: &[u8] = b"stapsdt";
const SPEC_MAP: &str = "__bpf_usdt_specs";
const IP_MAP: &str = "__bpf_usdt_ip_to_spec_id";

/// A USDT probe discovered in a userspace ELF file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UsdtProbe {
    /// Provider name.
    pub provider: String,
    /// Probe name.
    pub name: String,
    /// Raw `SystemTap` argument-location specification.
    pub arguments: String,
    /// Uprobe file offset.
    pub offset: u64,
    /// Optional semaphore reference-counter file offset.
    pub semaphore_offset: Option<u64>,
}

/// Options for attaching a program to every matching USDT call site.
#[derive(Clone, Debug)]
pub struct UsdtOptions {
    path: PathBuf,
    provider: String,
    name: String,
    pid: Option<u32>,
    cookie: u64,
}

impl UsdtOptions {
    /// Selects a provider and probe in an executable or shared object.
    pub fn new(
        path: impl Into<PathBuf>,
        provider: impl Into<String>,
        name: impl Into<String>,
    ) -> Self {
        Self {
            path: path.into(),
            provider: provider.into(),
            name: name.into(),
            pid: None,
            cookie: 0,
        }
    }

    /// Limits the attachment to one process. `None` means system-wide.
    pub const fn pid(mut self, pid: Option<u32>) -> Self {
        self.pid = pid;
        self
    }

    /// Sets the value returned by BPF-side `bpf_usdt_cookie`.
    pub const fn cookie(mut self, cookie: u64) -> Self {
        self.cookie = cookie;
        self
    }
}

/// Discovers all USDT probes described by `.note.stapsdt`.
pub fn discover_usdt_probes(path: impl AsRef<Path>) -> Result<Vec<UsdtProbe>> {
    Ok(parse_targets(path.as_ref())?
        .into_iter()
        .map(|target| target.probe)
        .collect())
}

#[derive(Debug)]
struct UsdtTarget {
    probe: UsdtProbe,
    absolute_address: u64,
    dynamic: bool,
}

#[derive(Debug)]
pub(crate) struct UsdtManager {
    specs: Map,
    ip_to_spec: Map,
    btf: Btf,
    has_bpf_cookie: bool,
    state: Mutex<UsdtState>,
}

#[derive(Debug, Default)]
struct UsdtState {
    next_id: u32,
    free_ids: Vec<u32>,
}

impl UsdtManager {
    pub(crate) fn from_maps(
        maps: &BTreeMap<String, Map>,
        btf: Option<&Btf>,
    ) -> Result<Option<Arc<Self>>> {
        let specs = maps.get(SPEC_MAP);
        let ip_to_spec = maps.get(IP_MAP);
        match (specs, ip_to_spec) {
            (None, None) => Ok(None),
            (Some(specs), Some(ip_to_spec)) => {
                let btf = btf.ok_or_else(|| {
                    Error::InvalidObject("USDT support maps require object BTF".into())
                })?;
                Ok(Some(Arc::new(Self {
                    specs: specs.clone(),
                    ip_to_spec: ip_to_spec.clone(),
                    btf: btf.clone(),
                    has_bpf_cookie: sys::supports_bpf_cookie(),
                    state: Mutex::new(UsdtState::default()),
                })))
            }
            _ => Err(Error::InvalidObject(format!(
                "USDT support requires both `{SPEC_MAP}` and `{IP_MAP}` maps"
            ))),
        }
    }

    pub(crate) fn attach(
        self: &Arc<Self>,
        program: &Program,
        options: UsdtOptions,
    ) -> Result<Link> {
        let targets = parse_targets(&options.path)?
            .into_iter()
            .filter(|target| {
                target.probe.provider == options.provider && target.probe.name == options.name
            })
            .collect::<Vec<_>>();
        if targets.is_empty() {
            return Err(Error::InvalidObject(format!(
                "USDT probe `{}:{}` was not found in `{}`",
                options.provider,
                options.name,
                options.path.display()
            )));
        }
        let layout = UsdtLayout::from_btf(&self.btf, self.specs.spec().value_size())?;
        let ids = self.allocate_ids(targets.len())?;
        let mut initialized = Vec::new();
        let mut ip_keys = Vec::new();
        let setup = (|| {
            for (target, id) in targets.iter().zip(&ids) {
                let value = layout.encode(&self.btf, &target.probe.arguments, options.cookie)?;
                self.specs
                    .update(&id.to_ne_bytes(), &value, UpdateMode::Any)?;
                initialized.push(*id);
                if !self.has_bpf_cookie {
                    let address =
                        runtime_address(target, &options.path, options.pid)?.ok_or_else(|| {
                            Error::Unsupported(
                                "system-wide PIE USDT needs kernel BPF-cookie support".into(),
                            )
                        })?;
                    let key = address.to_ne_bytes();
                    self.ip_to_spec
                        .update(&key, &id.to_ne_bytes(), UpdateMode::NoExist)?;
                    ip_keys.push(key);
                }
            }
            Ok::<_, Error>(())
        })();
        if let Err(error) = setup {
            self.release(&initialized, &ip_keys);
            self.return_ids(ids);
            return Err(error);
        }

        let offsets = targets
            .iter()
            .map(|target| target.probe.offset)
            .collect::<Vec<_>>();
        let semaphore_offsets = targets
            .iter()
            .map(|target| target.probe.semaphore_offset.unwrap_or_default())
            .collect::<Vec<_>>();
        let cookies = ids.iter().map(|id| u64::from(*id)).collect::<Vec<_>>();
        let attach = program.attach_uprobe_multi(
            UprobeMultiOptions::offsets(&options.path, &offsets)
                .reference_counter_offsets(&semaphore_offsets)
                .cookies(&cookies)
                .pid(options.pid),
        );
        let link = match attach {
            Ok(link) => link,
            Err(error) => {
                self.release(&initialized, &ip_keys);
                self.return_ids(ids);
                return Err(error);
            }
        };
        let manager = Arc::clone(self);
        Ok(link.with_cleanup(move || {
            manager.release(&initialized, &ip_keys);
            manager.return_ids(ids);
        }))
    }

    fn allocate_ids(&self, count: usize) -> Result<Vec<u32>> {
        let maximum = self.specs.spec().max_entries();
        let mut state = self
            .state
            .lock()
            .map_err(|_| Error::InvalidObject("USDT allocator lock was poisoned".into()))?;
        let mut ids = Vec::with_capacity(count);
        while ids.len() < count {
            if let Some(id) = state.free_ids.pop() {
                ids.push(id);
            } else if state.next_id < maximum {
                ids.push(state.next_id);
                state.next_id += 1;
            } else {
                state.free_ids.extend(ids);
                return Err(Error::InvalidObject(format!(
                    "USDT spec map is full after {maximum} unique call sites"
                )));
            }
        }
        Ok(ids)
    }

    fn return_ids(&self, ids: Vec<u32>) {
        if let Ok(mut state) = self.state.lock() {
            state.free_ids.extend(ids);
        }
    }

    fn release(&self, ids: &[u32], ip_keys: &[[u8; 8]]) {
        let zero = vec![0_u8; self.specs.spec().value_size() as usize];
        for id in ids {
            drop(self.specs.update(&id.to_ne_bytes(), &zero, UpdateMode::Any));
        }
        for key in ip_keys {
            drop(self.ip_to_spec.delete(key));
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Field {
    bit_offset: u32,
    bit_size: Option<u8>,
    size: usize,
}

#[derive(Debug)]
struct UsdtLayout {
    spec_size: usize,
    arguments_offset: usize,
    argument_size: usize,
    maximum_arguments: usize,
    cookie: Field,
    argument_count: Field,
    value_offset: Field,
    argument_type: Field,
    index_register_offset: Option<Field>,
    scale_shift: Option<Field>,
    register_offset: Field,
    signed: Field,
    bit_shift: Field,
}

impl UsdtLayout {
    fn from_btf(btf: &Btf, map_value_size: u32) -> Result<Self> {
        let (spec_id, BtfType::Struct { size, members, .. }) = btf
            .find(BtfKind::Struct, "__bpf_usdt_spec")
            .ok_or_else(|| Error::InvalidObject("USDT BTF spec type is absent".into()))?
        else {
            unreachable!("kind-filtered BTF lookup")
        };
        if *size != map_value_size {
            return Err(Error::InvalidObject(format!(
                "USDT spec BTF size {size} differs from map value size {map_value_size}"
            )));
        }
        let arguments = member(btf, members, "args")?;
        let array_id = btf.resolve_type(arguments.0.ty)?;
        let BtfType::Array {
            element_type,
            count,
            ..
        } = btf.type_by_id(array_id).ok_or_else(|| {
            Error::Btf(format!("USDT argument array type {} is absent", array_id.0))
        })?
        else {
            return Err(Error::InvalidObject(
                "USDT spec `args` member is not an array".into(),
            ));
        };
        let argument_id = btf.resolve_type(*element_type)?;
        let BtfType::Struct {
            size: argument_size,
            members: argument_members,
            ..
        } = btf
            .type_by_id(argument_id)
            .ok_or_else(|| Error::Btf(format!("USDT argument type {} is absent", argument_id.0)))?
        else {
            return Err(Error::InvalidObject(
                "USDT argument element is not a structure".into(),
            ));
        };
        let optional = |name| {
            argument_members
                .iter()
                .find(|candidate| candidate.name == name)
                .map(|member| field(btf, member))
                .transpose()
        };
        let layout = Self {
            spec_size: *size as usize,
            arguments_offset: (arguments.0.bit_offset / 8) as usize,
            argument_size: *argument_size as usize,
            maximum_arguments: *count as usize,
            cookie: field(btf, member(btf, members, "usdt_cookie")?.0)?,
            argument_count: field(btf, member(btf, members, "arg_cnt")?.0)?,
            value_offset: field(btf, member(btf, argument_members, "val_off")?.0)?,
            argument_type: field(btf, member(btf, argument_members, "arg_type")?.0)?,
            index_register_offset: optional("idx_reg_off")?,
            scale_shift: optional("scale_bitshift")?,
            register_offset: field(btf, member(btf, argument_members, "reg_off")?.0)?,
            signed: field(btf, member(btf, argument_members, "arg_signed")?.0)?,
            bit_shift: field(btf, member(btf, argument_members, "arg_bitshift")?.0)?,
        };
        let _ = spec_id;
        Ok(layout)
    }

    fn encode(&self, btf: &Btf, arguments: &str, cookie: u64) -> Result<Vec<u8>> {
        let parsed = parse_arguments(btf, arguments)?;
        if parsed.len() > self.maximum_arguments {
            return Err(Error::InvalidObject(format!(
                "USDT has {} arguments, maximum is {}",
                parsed.len(),
                self.maximum_arguments
            )));
        }
        let mut bytes = vec![0_u8; self.spec_size];
        write_field(&mut bytes, 0, self.cookie, cookie)?;
        write_field(&mut bytes, 0, self.argument_count, parsed.len() as u64)?;
        for (index, argument) in parsed.iter().enumerate() {
            let base = self
                .arguments_offset
                .checked_add(index.saturating_mul(self.argument_size))
                .ok_or_else(|| Error::InvalidObject("USDT argument offset overflow".into()))?;
            write_field(&mut bytes, base, self.value_offset, argument.value as u64)?;
            write_field(
                &mut bytes,
                base,
                self.argument_type,
                u64::from(argument.kind),
            )?;
            if let Some(field) = self.index_register_offset {
                write_field(
                    &mut bytes,
                    base,
                    field,
                    u64::from(argument.index_register_offset),
                )?;
            }
            if let Some(field) = self.scale_shift {
                write_field(&mut bytes, base, field, u64::from(argument.scale_shift))?;
            }
            write_field(
                &mut bytes,
                base,
                self.register_offset,
                argument.register_offset as u16 as u64,
            )?;
            write_field(&mut bytes, base, self.signed, u64::from(argument.signed))?;
            write_field(
                &mut bytes,
                base,
                self.bit_shift,
                u64::from(argument.bit_shift),
            )?;
        }
        Ok(bytes)
    }
}

fn member<'a>(btf: &Btf, members: &'a [BtfMember], name: &str) -> Result<(&'a BtfMember, TypeId)> {
    let member = members
        .iter()
        .find(|member| member.name == name)
        .ok_or_else(|| Error::InvalidObject(format!("USDT BTF member `{name}` is absent")))?;
    Ok((member, btf.resolve_type(member.ty)?))
}

fn field(btf: &Btf, member: &BtfMember) -> Result<Field> {
    Ok(Field {
        bit_offset: member.bit_offset,
        bit_size: member.bitfield_size,
        size: btf.size_of(member.ty)?,
    })
}

fn write_field(bytes: &mut [u8], base: usize, field: Field, value: u64) -> Result<()> {
    if cfg!(target_endian = "big") {
        return Err(Error::Unsupported(
            "USDT BTF bitfield encoding on big-endian hosts is not implemented".into(),
        ));
    }
    let bit_offset = base
        .checked_mul(8)
        .and_then(|base| base.checked_add(field.bit_offset as usize))
        .ok_or_else(|| Error::InvalidObject("USDT field offset overflow".into()))?;
    let bit_size = field
        .bit_size
        .map_or(field.size.saturating_mul(8), usize::from);
    if bit_size > 64 {
        return Err(Error::InvalidObject(
            "USDT scalar BTF field is wider than 64 bits".into(),
        ));
    }
    for bit in 0..bit_size {
        let target = bit_offset + bit;
        let byte = bytes
            .get_mut(target / 8)
            .ok_or_else(|| Error::InvalidObject("USDT BTF field lies outside map value".into()))?;
        let mask = 1_u8 << (target % 8);
        if value & (1_u64 << bit) == 0 {
            *byte &= !mask;
        } else {
            *byte |= mask;
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct Argument {
    value: i64,
    kind: u8,
    register_offset: i16,
    index_register_offset: u16,
    scale_shift: u8,
    signed: bool,
    bit_shift: u8,
}

fn parse_arguments(btf: &Btf, specification: &str) -> Result<Vec<Argument>> {
    if specification.trim().is_empty() {
        return Ok(Vec::new());
    }
    if !cfg!(any(target_arch = "x86", target_arch = "x86_64")) {
        return Err(Error::Unsupported(
            "non-empty USDT argument specifications are currently supported on x86 only".into(),
        ));
    }
    specification
        .split_ascii_whitespace()
        .map(|argument| parse_x86_argument(btf, argument))
        .collect()
}

fn parse_x86_argument(btf: &Btf, specification: &str) -> Result<Argument> {
    let (size, location) = specification
        .split_once('@')
        .ok_or_else(|| Error::InvalidObject(format!("invalid USDT argument `{specification}`")))?;
    let signed_size = size.parse::<i32>().map_err(|_| {
        Error::InvalidObject(format!("invalid USDT argument size in `{specification}`"))
    })?;
    let width = signed_size.unsigned_abs();
    if !matches!(width, 1 | 2 | 4 | 8) {
        return Err(Error::InvalidObject(format!(
            "USDT argument `{specification}` has unsupported size {width}"
        )));
    }
    let mut argument = Argument {
        value: 0,
        kind: 0,
        register_offset: 0,
        index_register_offset: 0,
        scale_shift: 0,
        signed: signed_size < 0,
        bit_shift: (64 - width * 8) as u8,
    };
    if let Some(value) = location.strip_prefix('$') {
        argument.value = value.parse().map_err(|_| {
            Error::InvalidObject(format!("invalid USDT constant in `{specification}`"))
        })?;
    } else if let Some(register) = location.strip_prefix('%') {
        argument.kind = 1;
        argument.register_offset = register_offset(btf, register)?;
    } else if let Some(open) = location.find('(') {
        let close = location.strip_suffix(')').ok_or_else(|| {
            Error::InvalidObject(format!("invalid USDT dereference `{specification}`"))
        })?;
        let offset = &location[..open];
        argument.value = if offset.is_empty() {
            0
        } else {
            offset.parse().map_err(|_| {
                Error::InvalidObject(format!("invalid USDT offset in `{specification}`"))
            })?
        };
        let registers = close[open + 1..]
            .split(',')
            .map(|register| register.trim_start_matches('%'))
            .collect::<Vec<_>>();
        let base_register = registers
            .first()
            .filter(|register| !register.is_empty())
            .ok_or_else(|| {
                Error::InvalidObject(format!(
                    "USDT address in `{specification}` has no base register"
                ))
            })?;
        argument.register_offset = register_offset(btf, base_register)?;
        if registers.len() == 1 {
            argument.kind = 2;
        } else if registers.len() <= 3 && !registers[1].is_empty() {
            argument.kind = 3;
            argument.index_register_offset = register_offset(btf, registers[1])? as u16;
            let scale = registers
                .get(2)
                .map_or(Ok(1_u8), |scale| scale.parse())
                .map_err(|_| {
                    Error::InvalidObject(format!("invalid USDT scale in `{specification}`"))
                })?;
            argument.scale_shift = match scale {
                1 => 0,
                2 => 1,
                4 => 2,
                8 => 3,
                _ => {
                    return Err(Error::InvalidObject(format!(
                        "invalid USDT scale {scale} in `{specification}`"
                    )));
                }
            };
        } else {
            return Err(Error::InvalidObject(format!(
                "invalid USDT address in `{specification}`"
            )));
        }
    } else {
        return Err(Error::InvalidObject(format!(
            "unsupported USDT argument `{specification}`"
        )));
    }
    Ok(argument)
}

fn register_offset(btf: &Btf, register: &str) -> Result<i16> {
    let member_name = match register {
        "rip" | "eip" => "ip",
        "rax" | "eax" | "ax" | "al" => "ax",
        "rbx" | "ebx" | "bx" | "bl" => "bx",
        "rcx" | "ecx" | "cx" | "cl" => "cx",
        "rdx" | "edx" | "dx" | "dl" => "dx",
        "rsi" | "esi" | "si" | "sil" => "si",
        "rdi" | "edi" | "di" | "dil" => "di",
        "rbp" | "ebp" | "bp" | "bpl" => "bp",
        "rsp" | "esp" | "sp" | "spl" => "sp",
        "r8" | "r8d" | "r8w" | "r8b" => "r8",
        "r9" | "r9d" | "r9w" | "r9b" => "r9",
        "r10" | "r10d" | "r10w" | "r10b" => "r10",
        "r11" | "r11d" | "r11w" | "r11b" => "r11",
        "r12" | "r12d" | "r12w" | "r12b" => "r12",
        "r13" | "r13d" | "r13w" | "r13b" => "r13",
        "r14" | "r14d" | "r14w" | "r14b" => "r14",
        "r15" | "r15d" | "r15w" | "r15b" => "r15",
        _ => {
            return Err(Error::InvalidObject(format!(
                "unrecognized x86 USDT register `%{register}`"
            )));
        }
    };
    let (_, BtfType::Struct { members, .. }) = btf
        .find(BtfKind::Struct, "pt_regs")
        .ok_or_else(|| Error::InvalidObject("object BTF has no `pt_regs` structure".into()))?
    else {
        unreachable!("kind-filtered BTF lookup")
    };
    let member = members
        .iter()
        .find(|member| member.name == member_name)
        .ok_or_else(|| {
            Error::InvalidObject(format!("object `pt_regs` has no member for `%{register}`"))
        })?;
    i16::try_from(member.bit_offset / 8)
        .map_err(|_| Error::InvalidObject("pt_regs member offset does not fit i16".into()))
}

fn parse_targets(path: &Path) -> Result<Vec<UsdtTarget>> {
    let bytes = fs::read(path).map_err(|source| Error::File {
        operation: "read USDT ELF",
        path: path.into(),
        source,
    })?;
    let elf = Elf::parse(&bytes)
        .map_err(|error| Error::InvalidObject(format!("invalid USDT ELF: {error}")))?;
    let section = elf
        .section_headers
        .iter()
        .find(|section| {
            section.sh_type == SHT_NOTE
                && elf.shdr_strtab.get_at(section.sh_name) == Some(".note.stapsdt")
        })
        .ok_or_else(|| {
            Error::InvalidObject(format!(
                "`{}` has no `.note.stapsdt` section",
                path.display()
            ))
        })?;
    let start = usize::try_from(section.sh_offset)
        .map_err(|_| Error::InvalidObject("USDT note offset does not fit usize".into()))?;
    let size = usize::try_from(section.sh_size)
        .map_err(|_| Error::InvalidObject("USDT note size does not fit usize".into()))?;
    let end = start
        .checked_add(size)
        .ok_or_else(|| Error::InvalidObject("USDT note section range overflow".into()))?;
    let notes = bytes
        .get(start..end)
        .ok_or_else(|| Error::InvalidObject("USDT note section lies outside ELF".into()))?;
    let base_address = elf
        .section_headers
        .iter()
        .find(|section| elf.shdr_strtab.get_at(section.sh_name) == Some(".stapsdt.base"))
        .map(|section| section.sh_addr);
    let mut targets = Vec::new();
    let mut offset = 0;
    while offset < notes.len() {
        let header = notes
            .get(offset..offset.saturating_add(12))
            .ok_or_else(|| Error::InvalidObject("truncated USDT note header".into()))?;
        let namesz = target_u32(&header[..4], elf.little_endian)? as usize;
        let descsz = target_u32(&header[4..8], elf.little_endian)? as usize;
        let note_type = target_u32(&header[8..12], elf.little_endian)?;
        let name_start = offset
            .checked_add(12)
            .ok_or_else(|| Error::InvalidObject("USDT note name offset overflow".into()))?;
        let name_end = name_start
            .checked_add(namesz)
            .ok_or_else(|| Error::InvalidObject("USDT note name overflow".into()))?;
        let description_start = align4(name_end)?;
        let description_end = description_start
            .checked_add(descsz)
            .ok_or_else(|| Error::InvalidObject("USDT note description overflow".into()))?;
        let next = align4(description_end)?;
        let name = notes
            .get(name_start..name_end)
            .ok_or_else(|| Error::InvalidObject("USDT note name lies outside section".into()))?;
        let description = notes
            .get(description_start..description_end)
            .ok_or_else(|| {
                Error::InvalidObject("USDT note description lies outside section".into())
            })?;
        offset = next;
        if note_type != NOTE_TYPE || name.strip_suffix(&[0]).unwrap_or(name) != NOTE_NAME {
            continue;
        }
        let address_size = if elf.is_64 { 8 } else { 4 };
        if description.len() < address_size * 3 + 3 {
            return Err(Error::InvalidObject(
                "USDT note description is too short".into(),
            ));
        }
        let location = target_address(&description[..address_size], elf.little_endian)?;
        let recorded_base = target_address(
            &description[address_size..address_size * 2],
            elf.little_endian,
        )?;
        let semaphore = target_address(
            &description[address_size * 2..address_size * 3],
            elf.little_endian,
        )?;
        let strings = &description[address_size * 3..];
        let (provider, strings) = take_c_string(strings, "USDT provider")?;
        let (probe_name, strings) = take_c_string(strings, "USDT name")?;
        let (arguments, _) = take_c_string(strings, "USDT arguments")?;
        if probe_name.is_empty() {
            return Err(Error::InvalidObject("USDT probe name is empty".into()));
        }
        let adjustment = match (base_address, recorded_base) {
            (Some(base), recorded) if recorded != 0 => i128::from(base) - i128::from(recorded),
            _ => 0,
        };
        let absolute_address = adjusted_address(location, adjustment)?;
        let adjusted_semaphore = (semaphore != 0)
            .then(|| adjusted_address(semaphore, adjustment))
            .transpose()?;
        let executable = load_segment(&elf, absolute_address).ok_or_else(|| {
            Error::InvalidObject(format!(
                "USDT location 0x{absolute_address:x} is outside a loadable segment"
            ))
        })?;
        if executable.p_flags & PF_X == 0 {
            return Err(Error::InvalidObject(format!(
                "USDT location 0x{absolute_address:x} is not executable"
            )));
        }
        let file_offset = absolute_address
            .checked_sub(executable.p_vaddr)
            .and_then(|offset| offset.checked_add(executable.p_offset))
            .ok_or_else(|| Error::InvalidObject("USDT probe file offset overflow".into()))?;
        let semaphore_offset = adjusted_semaphore
            .map(|address| {
                let segment = load_segment(&elf, address).ok_or_else(|| {
                    Error::InvalidObject(format!(
                        "USDT semaphore 0x{address:x} is outside a loadable segment"
                    ))
                })?;
                address
                    .checked_sub(segment.p_vaddr)
                    .and_then(|offset| offset.checked_add(segment.p_offset))
                    .ok_or_else(|| Error::InvalidObject("USDT semaphore offset overflow".into()))
            })
            .transpose()?;
        targets.push(UsdtTarget {
            probe: UsdtProbe {
                provider: provider.into(),
                name: probe_name.into(),
                arguments: arguments.trim_start_matches(':').into(),
                offset: file_offset,
                semaphore_offset,
            },
            absolute_address,
            dynamic: elf.header.e_type == ET_DYN,
        });
    }
    Ok(targets)
}

fn load_segment<'elf>(elf: &'elf Elf<'_>, address: u64) -> Option<&'elf ProgramHeader> {
    elf.program_headers.iter().find(|segment| {
        segment.p_type == PT_LOAD
            && address >= segment.p_vaddr
            && address < segment.p_vaddr.saturating_add(segment.p_memsz)
    })
}

fn runtime_address(target: &UsdtTarget, path: &Path, pid: Option<u32>) -> Result<Option<u64>> {
    if !target.dynamic {
        return Ok(Some(target.absolute_address));
    }
    let Some(pid) = pid else {
        return Ok(None);
    };
    let maps_path = PathBuf::from(format!("/proc/{pid}/maps"));
    let maps = fs::read_to_string(&maps_path).map_err(|source| Error::File {
        operation: "read process mappings for USDT",
        path: maps_path,
        source,
    })?;
    let canonical = path.canonicalize().map_err(|source| Error::File {
        operation: "canonicalize USDT ELF",
        path: path.into(),
        source,
    })?;
    for line in maps.lines() {
        let mut fields = line.split_whitespace();
        let range = fields.next().unwrap_or("");
        let _permissions = fields.next();
        let file_offset = fields
            .next()
            .and_then(|offset| u64::from_str_radix(offset, 16).ok());
        let _device = fields.next();
        let _inode = fields.next();
        let mapped_path = fields.next().map(decode_proc_maps_path).transpose()?;
        let Some((start, end)) = range.split_once('-').and_then(|(start, end)| {
            Some((
                u64::from_str_radix(start, 16).ok()?,
                u64::from_str_radix(end, 16).ok()?,
            ))
        }) else {
            continue;
        };
        let Some(file_offset) = file_offset else {
            continue;
        };
        if mapped_path.as_deref().map(Path::new) != Some(canonical.as_path())
            || target.probe.offset < file_offset
            || target.probe.offset - file_offset >= end - start
        {
            continue;
        }
        return Ok(Some(start + target.probe.offset - file_offset));
    }
    Err(Error::InvalidObject(format!(
        "`{}` is not mapped in process {pid} at USDT offset 0x{:x}",
        path.display(),
        target.probe.offset
    )))
}

fn decode_proc_maps_path(path: &str) -> Result<String> {
    let bytes = path.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut offset = 0;
    while offset < bytes.len() {
        if bytes[offset] == b'\\' && offset + 3 < bytes.len() {
            let octal = &bytes[offset + 1..offset + 4];
            if octal.iter().all(|byte| matches!(byte, b'0'..=b'7')) {
                let value = u16::from(octal[0] - b'0') * 64
                    + u16::from(octal[1] - b'0') * 8
                    + u16::from(octal[2] - b'0');
                if let Ok(value) = u8::try_from(value) {
                    decoded.push(value);
                    offset += 4;
                    continue;
                }
            }
        }
        decoded.push(bytes[offset]);
        offset += 1;
    }
    String::from_utf8(decoded)
        .map_err(|error| Error::InvalidObject(format!("invalid path in process maps: {error}")))
}

fn target_u32(bytes: &[u8], little_endian: bool) -> Result<u32> {
    let bytes: [u8; 4] = bytes
        .try_into()
        .map_err(|_| Error::InvalidObject("truncated target integer".into()))?;
    Ok(if little_endian {
        u32::from_le_bytes(bytes)
    } else {
        u32::from_be_bytes(bytes)
    })
}

fn target_address(bytes: &[u8], little_endian: bool) -> Result<u64> {
    match bytes.len() {
        4 => target_u32(bytes, little_endian).map(u64::from),
        8 => {
            let bytes: [u8; 8] = bytes
                .try_into()
                .map_err(|_| Error::InvalidObject("truncated target address".into()))?;
            Ok(if little_endian {
                u64::from_le_bytes(bytes)
            } else {
                u64::from_be_bytes(bytes)
            })
        }
        _ => Err(Error::InvalidObject(
            "unsupported target address width".into(),
        )),
    }
}

fn take_c_string<'a>(bytes: &'a [u8], what: &str) -> Result<(&'a str, &'a [u8])> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| Error::InvalidObject(format!("{what} is not NUL-terminated")))?;
    let value = str::from_utf8(&bytes[..end])
        .map_err(|error| Error::InvalidObject(format!("{what} is not UTF-8: {error}")))?;
    Ok((value, &bytes[end + 1..]))
}

fn adjusted_address(address: u64, adjustment: i128) -> Result<u64> {
    u64::try_from(i128::from(address) + adjustment)
        .map_err(|_| Error::InvalidObject("prelinked USDT address adjustment overflow".into()))
}

fn align4(value: usize) -> Result<usize> {
    value
        .checked_add(3)
        .map(|value| value & !3)
        .ok_or_else(|| Error::InvalidObject("USDT note alignment overflow".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn note_helpers_decode_endianness_and_strings() {
        assert_eq!(target_u32(&[1, 2, 3, 4], true).unwrap(), 0x0403_0201);
        assert_eq!(target_u32(&[1, 2, 3, 4], false).unwrap(), 0x0102_0304);
        assert_eq!(
            take_c_string(b"provider\0remaining", "test").unwrap(),
            ("provider", b"remaining".as_slice())
        );
        assert!(take_c_string(b"unterminated", "test").is_err());
        assert_eq!(
            decode_proc_maps_path("/tmp/a\\040b\\134c").unwrap(),
            "/tmp/a b\\c"
        );
    }

    #[test]
    fn discovers_repository_usdt_fixture_when_available() {
        let fixture = crate::test_bpf::compile_fixture("usdt");
        // The BPF object itself has no SystemTap notes; this verifies the
        // structured error path against a real ELF.
        assert!(discover_usdt_probes(fixture.path()).is_err());
    }

    #[test]
    fn encodes_repository_usdt_layout_from_btf_when_available() {
        let fixture = crate::test_bpf::compile_fixture("usdt");
        let object = crate::Object::open(fixture.path()).unwrap();
        let btf = object.btf().unwrap();
        let value_size = object.map(SPEC_MAP).unwrap().value_size();
        let layout = UsdtLayout::from_btf(btf, value_size).unwrap();
        let encoded = layout.encode(btf, "-8@%rax", 1337).unwrap();

        assert_eq!(encoded.len(), value_size as usize);
        let cookie_offset = (layout.cookie.bit_offset / 8) as usize;
        assert_eq!(
            &encoded[cookie_offset..cookie_offset + layout.cookie.size],
            &1337_u64.to_ne_bytes()
        );
        let argument_count_offset = (layout.argument_count.bit_offset / 8) as usize;
        assert_eq!(
            &encoded[argument_count_offset..argument_count_offset + layout.argument_count.size],
            &1_u16.to_ne_bytes()
        );
        assert!(layout.encode(btf, "-8@()", 0).is_err());
    }
}
