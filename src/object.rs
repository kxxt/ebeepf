use std::collections::hash_map::Entry as HashMapEntry;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::fs::File;
use std::io::{ErrorKind, Read};
use std::mem::size_of;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::str;

use flate2::read::GzDecoder;
use goblin::elf::header::{EI_CLASS, ELFCLASS64, EM_BPF, ET_REL};
use goblin::elf::section_header::{SHF_EXECINSTR, SHT_NOBITS};
use goblin::elf::sym::{STB_GLOBAL, STB_WEAK, STT_FUNC, STT_OBJECT, STV_HIDDEN};
use goblin::elf::{Elf, SectionHeader, Sym};

use crate::btf::{BtfType, Endian};
use crate::map::{possible_cpu_count, MapFlags, Pinning};
use crate::program::{
    kind_supports_auto_attach, program_flags_from_section, ProgramKind, VerifierLog,
};
use crate::sys::{self, MapCreate};
use crate::usdt::UsdtManager;
use crate::{
    BpfToken, Btf, BtfObject, Error, Instruction, Map, MapSpec, MapType, Program, ProgramSpec,
    ProgramType, Result, TypeId,
};

const R_BPF_64_64: u32 = 1;
const R_BPF_64_ABS64: u32 = 2;
const R_BPF_64_32: u32 = 10;
const R_BPF_64_ABS32: u32 = 3;
const R_BPF_64_NODYLD32: u32 = 4;
const BPF_LD_IMM_DW: u8 = 0x18;
const BPF_PSEUDO_MAP_FD: u8 = 1;
const BPF_PSEUDO_MAP_VALUE: u8 = 2;
const BPF_PSEUDO_BTF_ID: u8 = 3;
const BPF_PSEUDO_CALL: u8 = 1;
const BPF_PSEUDO_KFUNC_CALL: u8 = 2;
const BPF_PSEUDO_FUNC: u8 = 4;

#[derive(Clone, Debug, Eq, PartialEq)]
struct MapRelocation {
    program: String,
    instruction_index: usize,
    map: String,
    value_offset: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CoreRelocation {
    program: String,
    instruction_index: usize,
    type_id: TypeId,
    access: String,
    kind: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct KfuncRelocation {
    program: String,
    instruction_index: usize,
    name: String,
    weak: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KsymKind {
    Variable,
    Function,
    Untyped,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct KsymRelocation {
    program: String,
    instruction_index: usize,
    name: String,
    kind: KsymKind,
    weak: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct KconfigEntry {
    variable_id: TypeId,
    name: String,
    offset: u32,
    size: u32,
    value_type: TypeId,
    weak: bool,
    alignment: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StructOpsCallback {
    member_index: usize,
    program: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PreparedStructOps {
    kernel_value_type: TypeId,
    value: Vec<u8>,
    callbacks: Vec<(String, usize)>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StructOpsDefinition {
    source_type: TypeId,
    callbacks: Vec<StructOpsCallback>,
    prepared: Option<PreparedStructOps>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Placement {
    source_start: usize,
    destination_start: usize,
    instruction_count: usize,
}

type Placements = HashMap<usize, Vec<Placement>>;

fn translate_placement(
    placements: &Placements,
    section_index: usize,
    source_index: usize,
) -> Option<usize> {
    placements
        .get(&section_index)?
        .iter()
        .find_map(|placement| placement.translate(source_index))
}

impl Placement {
    fn translate(self, source_index: usize) -> Option<usize> {
        let local = source_index.checked_sub(self.source_start)?;
        (local < self.instruction_count)
            .then(|| self.destination_start.checked_add(local))
            .flatten()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct EntryPoint {
    section_index: usize,
    name: String,
    byte_offset: usize,
    byte_size: usize,
}

/// A parsed, configurable eBPF object that has not created kernel resources.
#[derive(Clone, Debug)]
pub struct Object {
    name: String,
    license: Vec<u8>,
    btf: Option<Btf>,
    maps: BTreeMap<String, MapSpec>,
    programs: BTreeMap<String, ProgramSpec>,
    map_relocations: Vec<MapRelocation>,
    core_relocations: Vec<CoreRelocation>,
    kfunc_relocations: Vec<KfuncRelocation>,
    ksym_relocations: Vec<KsymRelocation>,
    struct_ops: BTreeMap<String, StructOpsDefinition>,
    pin_root: PathBuf,
    reused_maps: BTreeMap<String, Map>,
    token: Option<BpfToken>,
}

impl Object {
    /// Reads and parses an eBPF ELF object.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let bytes = fs::read(path).map_err(|source| Error::File {
            operation: "read eBPF object",
            path: path.into(),
            source,
        })?;
        let name = path
            .file_stem()
            .and_then(|name| name.to_str())
            .unwrap_or("bpf");
        Self::parse_named(name, &bytes)
    }

    /// Parses an in-memory eBPF ELF object using `"bpf"` as its object name.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        Self::parse_named("bpf", bytes)
    }

    /// Parses an in-memory eBPF ELF object with an explicit object name.
    pub fn parse_named(name: impl Into<String>, bytes: &[u8]) -> Result<Self> {
        let name = name.into();
        let elf = Elf::parse(bytes).map_err(|error| Error::Elf(error.to_string()))?;
        validate_elf(&elf)?;

        let sections = Sections::new(&elf, bytes)?;
        let mut btf = parse_btf(&elf, &sections)?;
        if let Some(btf) = btf.as_mut() {
            mark_hidden_subprograms_static(&elf, &sections, btf)?;
        }
        let btf_ext = match (btf.as_ref(), sections.by_name(".BTF.ext")) {
            (Some(btf), Some((index, _))) => {
                let data = relocated_metadata_section(&elf, &sections, index)?;
                Some(BtfExt::parse(&data, btf)?)
            }
            (None, Some(_)) => {
                return Err(Error::InvalidObject(
                    "object has .BTF.ext but no .BTF section".into(),
                ));
            }
            (_, None) => None,
        };

        let license = sections
            .by_name("license")
            .map(|(_, data)| nul_terminated(data))
            .unwrap_or_else(|| b"GPL\0".to_vec());
        let kernel_version = sections
            .by_name("version")
            .map(|(_, data)| read_u32(data, 0, elf.little_endian, "kernel version"))
            .transpose()?
            .unwrap_or_else(running_kernel_version);

        let mut maps = parse_maps(&elf, &sections, btf.as_ref())?;
        let data_sections = add_data_maps(&name, &elf, &sections, btf.as_ref(), &mut maps)?;
        let ksym_kinds = collect_ksym_kinds(btf.as_ref())?;
        let extern_data = add_kconfig_map(&name, &elf, btf.as_mut(), &mut maps)?;
        let mut struct_ops = add_struct_ops_maps(&elf, &sections, btf.as_ref(), &mut maps)?;
        resolve_inner_maps(&elf, &sections, &mut maps)?;

        let mut programs = BTreeMap::new();
        let mut map_relocations = Vec::new();
        let mut core_relocations = Vec::new();
        let mut kfunc_relocations = Vec::new();
        let mut ksym_relocations = Vec::new();
        for entry in executable_entries(&elf, &sections)? {
            let entry_index = entry.section_index;
            let entry_name = sections.name(entry_index)?;
            let entry_data = sections.data(entry_index)?;
            let entry_end = entry
                .byte_offset
                .checked_add(entry.byte_size)
                .ok_or_else(|| Error::InvalidObject("program range overflow".into()))?;
            let entry_bytes = entry_data
                .get(entry.byte_offset..entry_end)
                .ok_or_else(|| Error::InvalidObject("program lies outside its section".into()))?;
            let mut instructions = Instruction::decode(entry_bytes)?;
            let entry_instruction_count = instructions.len();
            let mut placements = HashMap::from([(
                entry_index,
                vec![Placement {
                    source_start: entry.byte_offset / Instruction::SIZE,
                    destination_start: 0,
                    instruction_count: entry_instruction_count,
                }],
            )]);

            for linked in linked_subprograms(&elf, &sections, &entry)? {
                let section_data = sections.data(linked.section_index)?;
                let end = linked
                    .byte_offset
                    .checked_add(linked.byte_size)
                    .ok_or_else(|| Error::InvalidObject("subprogram range overflow".into()))?;
                let bytes = section_data.get(linked.byte_offset..end).ok_or_else(|| {
                    Error::InvalidObject("subprogram lies outside section".into())
                })?;
                let subprogram_instructions = Instruction::decode(bytes)?;
                placements
                    .entry(linked.section_index)
                    .or_default()
                    .push(Placement {
                        source_start: linked.byte_offset / Instruction::SIZE,
                        destination_start: instructions.len(),
                        instruction_count: subprogram_instructions.len(),
                    });
                instructions.extend(subprogram_instructions);
            }

            let program_name = entry.name;
            let kind = ProgramKind::from_section(entry_name).unwrap_or(ProgramKind::Other {
                program_type: ProgramType::Unspecified,
                attach_type: None,
            });
            let auto_attach = kind_supports_auto_attach(&kind);
            let mut spec = ProgramSpec {
                name: program_name.clone(),
                section: entry_name.into(),
                kind,
                instructions,
                autoload: true,
                auto_attach,
                flags: program_flags_from_section(entry_name),
                kernel_version,
                interface_index: 0,
                attach_btf_id: 0,
                attach_program: None,
                attach_btf_object: None,
                kernel_btf_objects: Vec::new(),
                func_info: Vec::new(),
                func_info_record_size: 0,
                line_info: Vec::new(),
                line_info_record_size: 0,
                verifier_log: VerifierLog::default(),
                section_index: entry_index,
                section_offset: entry.byte_offset as u64,
            };

            apply_program_relocations(
                &elf,
                &placements,
                &data_sections,
                &extern_data,
                &maps,
                &program_name,
                &mut spec.instructions,
                &mut map_relocations,
                &mut kfunc_relocations,
                &mut ksym_relocations,
                &ksym_kinds,
            )?;

            if let Some(ext) = &btf_ext {
                append_ext_info(
                    &mut spec.func_info,
                    &mut spec.func_info_record_size,
                    &ext.function_info,
                    &placements,
                    &sections,
                    btf.as_ref().expect("BTF.ext requires BTF").endian(),
                )?;
                append_ext_info(
                    &mut spec.line_info,
                    &mut spec.line_info_record_size,
                    &ext.line_info,
                    &placements,
                    &sections,
                    btf.as_ref().expect("BTF.ext requires BTF").endian(),
                )?;
                append_core_relocations(
                    &program_name,
                    &ext.core_relocations,
                    &placements,
                    &mut core_relocations,
                    btf.as_ref().expect("BTF.ext requires BTF"),
                    &sections,
                )?;
            }

            // The entry section is always first; this field is useful to
            // consumers inspecting the unrelocated ELF relationship.
            debug_assert_eq!(entry_instruction_count, entry.byte_size / Instruction::SIZE);
            if programs.insert(program_name.clone(), spec).is_some() {
                return Err(Error::InvalidObject(format!(
                    "duplicate program name `{program_name}`"
                )));
            }
        }
        collect_struct_ops_relocations(&elf, btf.as_ref(), &maps, &programs, &mut struct_ops)?;

        Ok(Self {
            name,
            license,
            btf,
            maps,
            programs,
            map_relocations,
            core_relocations,
            kfunc_relocations,
            ksym_relocations,
            struct_ops,
            pin_root: "/sys/fs/bpf".into(),
            reused_maps: BTreeMap::new(),
            token: None,
        })
    }

    /// Object name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// License text without its trailing NUL byte.
    pub fn license(&self) -> &str {
        let end = self
            .license
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(self.license.len());
        str::from_utf8(&self.license[..end]).unwrap_or("")
    }

    /// Parsed BTF, when the object contains it.
    pub fn btf(&self) -> Option<&Btf> {
        self.btf.as_ref()
    }

    /// Iterates over map definitions in deterministic name order.
    pub fn maps(&self) -> impl ExactSizeIterator<Item = &MapSpec> {
        self.maps.values()
    }

    /// Iterates mutably over map definitions.
    pub fn maps_mut(&mut self) -> impl ExactSizeIterator<Item = &mut MapSpec> {
        self.maps.values_mut()
    }

    /// Gets a map definition.
    pub fn map(&self, name: &str) -> Result<&MapSpec> {
        self.maps
            .get(name)
            .ok_or_else(|| Error::MapNotFound(name.into()))
    }

    /// Gets a mutable map definition for pre-load configuration.
    pub fn map_mut(&mut self, name: &str) -> Result<&mut MapSpec> {
        self.maps
            .get_mut(name)
            .ok_or_else(|| Error::MapNotFound(name.into()))
    }

    /// Iterates over program definitions in deterministic name order.
    pub fn programs(&self) -> impl ExactSizeIterator<Item = &ProgramSpec> {
        self.programs.values()
    }

    /// Iterates mutably over program definitions.
    pub fn programs_mut(&mut self) -> impl ExactSizeIterator<Item = &mut ProgramSpec> {
        self.programs.values_mut()
    }

    /// Gets a program definition.
    pub fn program(&self, name: &str) -> Result<&ProgramSpec> {
        self.programs
            .get(name)
            .ok_or_else(|| Error::ProgramNotFound(name.into()))
    }

    /// Gets a mutable program definition for pre-load configuration.
    pub fn program_mut(&mut self, name: &str) -> Result<&mut ProgramSpec> {
        self.programs
            .get_mut(name)
            .ok_or_else(|| Error::ProgramNotFound(name.into()))
    }

    /// Sets the root used by maps whose BTF definition requests pin-by-name.
    pub fn set_pin_root(&mut self, path: impl Into<PathBuf>) -> &mut Self {
        self.pin_root = path.into();
        self
    }

    /// Uses a delegated BPF token for kernel resource creation during load.
    pub fn set_token(&mut self, token: &BpfToken) -> &mut Self {
        self.token = Some(token.clone());
        self
    }

    /// Removes the delegated BPF token configured for loading.
    pub fn clear_token(&mut self) -> &mut Self {
        self.token = None;
        self
    }

    /// Token configured for loading, when present.
    pub fn token(&self) -> Option<&BpfToken> {
        self.token.as_ref()
    }

    /// Reuses an already loaded kernel map for a named object definition.
    ///
    /// Compatibility is checked transactionally during [`Self::load`].
    pub fn reuse_map(&mut self, name: &str, map: &Map) -> Result<&mut Self> {
        if !self.maps.contains_key(name) {
            return Err(Error::MapNotFound(name.into()));
        }
        self.reused_maps.insert(name.into(), map.clone());
        Ok(self)
    }

    /// Applies pending CO-RE relocations against an explicit target BTF.
    ///
    /// This is useful for inspecting or preparing an object for a kernel other
    /// than the running one. [`Self::load`] performs this automatically against
    /// `/sys/kernel/btf/vmlinux` when relocations remain.
    pub fn relocate_for(&mut self, target_btf: &Btf) -> Result<&mut Self> {
        if self.core_relocations.is_empty() {
            return Ok(self);
        }
        apply_core_relocations(
            self.btf
                .as_ref()
                .ok_or_else(|| Error::InvalidObject("CO-RE records require BTF".into()))?,
            target_btf,
            &mut self.programs,
            &self.core_relocations,
        )?;
        self.core_relocations.clear();
        Ok(self)
    }

    /// Applies pending CO-RE relocations for the running kernel.
    pub fn relocate_for_running_kernel(&mut self) -> Result<&mut Self> {
        if self.core_relocations.is_empty() {
            return Ok(self);
        }
        let kernel_bytes = fs::read("/sys/kernel/btf/vmlinux").map_err(|source| Error::File {
            operation: "read kernel BTF for CO-RE",
            path: "/sys/kernel/btf/vmlinux".into(),
            source,
        })?;
        let target_btf = Btf::parse(&kernel_bytes)?;
        apply_core_relocations_for_running_kernel(
            self.btf
                .as_ref()
                .ok_or_else(|| Error::InvalidObject("CO-RE records require BTF".into()))?,
            &target_btf,
            &mut self.programs,
            &self.core_relocations,
        )?;
        self.core_relocations.clear();
        Ok(self)
    }

    /// Creates maps, applies relocations, and loads programs into the kernel.
    ///
    /// Loading is transactional with respect to process-owned resources: on
    /// error, all descriptors created so far are closed. Maps pinned by policy
    /// remain pinned, as requested by their definitions.
    pub fn load(mut self) -> Result<LoadedObject> {
        let token = self.token.clone();
        let token_fd = token.as_ref().map(|token| token.as_fd().as_raw_fd());
        for map in self.maps.values_mut() {
            if map.map_type == MapType::PerfEventArray && map.max_entries == 0 {
                map.max_entries = u32::try_from(possible_cpu_count()?).map_err(|_| {
                    Error::InvalidObject("possible CPU count does not fit u32".into())
                })?;
            }
        }
        for map in self.maps.values() {
            map.validate()?;
        }
        for program in self.programs.values().filter(|program| program.autoload) {
            program.validate()?;
        }

        if !self.core_relocations.is_empty() {
            self.relocate_for_running_kernel()?;
        }
        prepare_struct_ops(
            self.btf.as_ref(),
            &mut self.maps,
            &mut self.programs,
            &mut self.struct_ops,
        )?;
        resolve_kfunc_relocations(&mut self.programs, &self.kfunc_relocations, token.as_ref())?;
        resolve_ksym_relocations(&mut self.programs, &self.ksym_relocations, token.as_ref())?;
        resolve_attach_btf_ids(&mut self.programs, token.as_ref())?;

        let kernel_btf = self
            .btf
            .as_ref()
            .map(|btf| {
                let mut btf = btf.clone();
                btf.sanitize_extern_linkage_for_kernel()?;
                Ok::<_, Error>(btf)
            })
            .transpose()?;
        let btf_fd = match kernel_btf.as_ref() {
            Some(btf) => match sys::load_btf_with_token(btf.as_bytes(), 256 * 1024, token_fd) {
                Ok(fd) => Some(fd),
                Err(_)
                    if !self.kfunc_relocations.is_empty() || !self.ksym_relocations.is_empty() =>
                {
                    None
                }
                Err((source, log)) => {
                    return Err(Error::InvalidObject(format!(
                        "kernel rejected object BTF: {source}\n{log}"
                    )));
                }
            },
            None => None,
        };

        let mut maps = load_maps(
            &self.maps,
            &self.reused_maps,
            btf_fd.as_ref(),
            &self.pin_root,
            token_fd,
            &self.struct_ops,
        )?;
        relocate_maps(&mut self.programs, &self.map_relocations, &maps)?;
        let usdt_manager = UsdtManager::from_maps(&maps, self.btf.as_ref())?;

        let mut programs = BTreeMap::new();
        for (name, spec) in self.programs {
            if !spec.autoload {
                continue;
            }
            let mut program = Program::load(
                spec,
                &self.license,
                btf_fd.as_ref().map(OwnedFd::as_fd),
                token.as_ref(),
            )?;
            program.set_usdt_manager(usdt_manager.clone());
            programs.insert(name, program);
        }
        finalize_struct_ops_values(&mut maps, &programs, &self.struct_ops)?;

        Ok(LoadedObject {
            name: self.name,
            btf: self.btf,
            btf_fd,
            maps,
            programs,
            token,
        })
    }
}

/// An eBPF object whose selected maps and programs are loaded in the kernel.
#[derive(Debug)]
pub struct LoadedObject {
    name: String,
    btf: Option<Btf>,
    // Kept alive because maps and programs reference this kernel BTF object.
    btf_fd: Option<OwnedFd>,
    maps: BTreeMap<String, Map>,
    programs: BTreeMap<String, Program>,
    token: Option<BpfToken>,
}

impl LoadedObject {
    /// Object name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Parsed object BTF.
    pub fn btf(&self) -> Option<&Btf> {
        self.btf.as_ref()
    }

    /// Whether object BTF was loaded in the kernel.
    pub fn has_kernel_btf(&self) -> bool {
        self.btf_fd.is_some()
    }

    /// Token retained from this object's delegated load, when present.
    pub fn token(&self) -> Option<&BpfToken> {
        self.token.as_ref()
    }

    /// Iterates over loaded maps.
    pub fn maps(&self) -> impl ExactSizeIterator<Item = &Map> {
        self.maps.values()
    }

    /// Gets a loaded map.
    pub fn map(&self, name: &str) -> Result<&Map> {
        self.maps
            .get(name)
            .ok_or_else(|| Error::MapNotFound(name.into()))
    }

    /// Removes a map handle from the object.
    pub fn take_map(&mut self, name: &str) -> Result<Map> {
        self.maps
            .remove(name)
            .ok_or_else(|| Error::MapNotFound(name.into()))
    }

    /// Iterates over loaded programs.
    pub fn programs(&self) -> impl ExactSizeIterator<Item = &Program> {
        self.programs.values()
    }

    /// Gets a loaded program.
    pub fn program(&self, name: &str) -> Result<&Program> {
        self.programs
            .get(name)
            .ok_or_else(|| Error::ProgramNotFound(name.into()))
    }

    /// Removes a program handle from the object.
    pub fn take_program(&mut self, name: &str) -> Result<Program> {
        self.programs
            .remove(name)
            .ok_or_else(|| Error::ProgramNotFound(name.into()))
    }
}

fn validate_elf(elf: &Elf<'_>) -> Result<()> {
    if elf.header.e_ident[EI_CLASS] != ELFCLASS64 || !elf.is_64 {
        return Err(Error::Elf(
            "only 64-bit eBPF ELF objects are supported".into(),
        ));
    }
    if elf.header.e_machine != EM_BPF {
        return Err(Error::Elf(format!(
            "ELF machine {} is not EM_BPF ({EM_BPF})",
            elf.header.e_machine
        )));
    }
    if elf.header.e_type != ET_REL {
        return Err(Error::Elf("eBPF input must be a relocatable object".into()));
    }
    if elf.little_endian != cfg!(target_endian = "little") {
        return Err(Error::Unsupported(
            "loading an eBPF object with endianness different from the host".into(),
        ));
    }
    Ok(())
}

struct Sections<'a> {
    elf: &'a Elf<'a>,
    bytes: &'a [u8],
    names: Vec<&'a str>,
}

impl<'a> Sections<'a> {
    fn new(elf: &'a Elf<'a>, bytes: &'a [u8]) -> Result<Self> {
        let names = elf
            .section_headers
            .iter()
            .map(|header| {
                elf.shdr_strtab
                    .get_at(header.sh_name)
                    .ok_or_else(|| Error::Elf("section has an invalid name offset".into()))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { elf, bytes, names })
    }

    fn name(&self, index: usize) -> Result<&'a str> {
        self.names
            .get(index)
            .copied()
            .ok_or_else(|| Error::Elf(format!("section index {index} is out of bounds")))
    }

    fn data(&self, index: usize) -> Result<&'a [u8]> {
        let header = self
            .elf
            .section_headers
            .get(index)
            .ok_or_else(|| Error::Elf(format!("section index {index} is out of bounds")))?;
        if header.sh_type == SHT_NOBITS {
            return Ok(&[]);
        }
        let offset = usize::try_from(header.sh_offset)
            .map_err(|_| Error::Elf("section offset does not fit usize".into()))?;
        let size = usize::try_from(header.sh_size)
            .map_err(|_| Error::Elf("section size does not fit usize".into()))?;
        let name = self.name(index)?;
        self.bytes
            .get(offset..offset.saturating_add(size))
            .ok_or_else(|| Error::Elf(format!("section `{name}` lies outside the file")))
    }

    fn owned_data(&self, index: usize) -> Result<Vec<u8>> {
        let header = &self.elf.section_headers[index];
        if header.sh_type == SHT_NOBITS {
            let size = usize::try_from(header.sh_size)
                .map_err(|_| Error::Elf("BSS section size does not fit usize".into()))?;
            Ok(vec![0; size])
        } else {
            Ok(self.data(index)?.to_vec())
        }
    }

    fn by_name(&self, name: &str) -> Option<(usize, &'a [u8])> {
        self.names
            .iter()
            .position(|candidate| *candidate == name)
            .and_then(|index| self.data(index).ok().map(|data| (index, data)))
    }
}

fn parse_btf(elf: &Elf<'_>, sections: &Sections<'_>) -> Result<Option<Btf>> {
    let Some((index, _)) = sections.by_name(".BTF") else {
        return Ok(None);
    };
    let data = relocated_metadata_section(elf, sections, index)?;
    let mut btf = Btf::parse(&data)?;
    for (section_index, header) in elf.section_headers.iter().enumerate() {
        let name = sections.name(section_index)?;
        let size = u32::try_from(header.sh_size).map_err(|_| {
            Error::InvalidObject(format!(
                "ELF section `{name}` is too large for a BTF data section"
            ))
        })?;
        btf.set_data_section_size(name, size)?;
    }
    Ok(Some(btf))
}

fn relocated_metadata_section(
    elf: &Elf<'_>,
    sections: &Sections<'_>,
    target_index: usize,
) -> Result<Vec<u8>> {
    let mut data = sections.owned_data(target_index)?;
    for (relocation_index, relocations) in &elf.shdr_relocs {
        let header = &elf.section_headers[*relocation_index];
        if header.sh_info as usize != target_index {
            continue;
        }
        for relocation in relocations {
            if !matches!(relocation.r_type, R_BPF_64_ABS32 | R_BPF_64_NODYLD32) {
                return Err(Error::Unsupported(format!(
                    "metadata section `{}` uses relocation type {}",
                    sections.name(target_index)?,
                    relocation.r_type
                )));
            }
            let symbol = elf.syms.get(relocation.r_sym).ok_or_else(|| {
                Error::Elf(format!(
                    "relocation references missing symbol {}",
                    relocation.r_sym
                ))
            })?;
            let offset = usize::try_from(relocation.r_offset)
                .map_err(|_| Error::Elf("metadata relocation offset is too large".into()))?;
            let original = read_u32(
                &data,
                offset,
                elf.little_endian,
                "metadata relocation target",
            )?;
            let value = i128::from(original)
                + i128::from(symbol.st_value)
                + i128::from(relocation.r_addend.unwrap_or_default());
            let value = u32::try_from(value).map_err(|_| {
                Error::InvalidObject("metadata relocation result does not fit u32".into())
            })?;
            write_u32(&mut data, offset, value, elf.little_endian)?;
        }
    }
    Ok(data)
}

fn parse_maps(
    elf: &Elf<'_>,
    sections: &Sections<'_>,
    btf: Option<&Btf>,
) -> Result<BTreeMap<String, MapSpec>> {
    let Some((map_section_index, map_data)) = sections.by_name(".maps") else {
        return Ok(BTreeMap::new());
    };
    if let Some(btf) = btf {
        if let Some((_, BtfType::DataSection { variables, .. })) =
            btf.find(crate::BtfKind::DataSection, ".maps")
        {
            let mut definitions = BTreeMap::new();
            let mut struct_names = HashMap::new();
            for variable in variables {
                let (name, struct_id, _) = map_variable(btf, variable.ty)?;
                struct_names.insert(struct_id, name.to_owned());
            }
            for variable in variables {
                let (name, struct_id, members) = map_variable(btf, variable.ty)?;
                let mut values = HashMap::new();
                for member in members {
                    values.insert(member.name.as_str(), member.ty);
                }
                let map_type = btf_uint(btf, required_member(&values, "type", name)?)?;
                let key_type = values
                    .get("key")
                    .copied()
                    .map(|id| btf_pointee(btf, id))
                    .transpose()?;
                let value_type = values
                    .get("value")
                    .copied()
                    .map(|id| btf_pointee(btf, id))
                    .transpose()?;
                let key_size = match values.get("key_size") {
                    Some(id) => btf_uint(btf, *id)?,
                    None => key_type.map(|id| btf.size_of(id)).transpose()?.unwrap_or(0) as u32,
                };
                let value_size = match values.get("value_size") {
                    Some(id) => btf_uint(btf, *id)?,
                    None => value_type
                        .map(|id| btf.size_of(id))
                        .transpose()?
                        .unwrap_or(0) as u32,
                };
                let max_entries = values
                    .get("max_entries")
                    .map(|id| btf_uint(btf, *id))
                    .transpose()?
                    .unwrap_or_default();
                let mut spec = MapSpec::new(
                    name,
                    MapType::from_raw(map_type),
                    key_size,
                    value_size,
                    max_entries,
                );
                spec.flags = MapFlags::from_bits_retain(
                    values
                        .get("map_flags")
                        .map(|id| btf_uint(btf, *id))
                        .transpose()?
                        .unwrap_or_default(),
                );
                spec.numa_node = values
                    .get("numa_node")
                    .map(|id| btf_uint(btf, *id))
                    .transpose()?;
                spec.map_extra = u64::from(
                    values
                        .get("map_extra")
                        .map(|id| btf_uint(btf, *id))
                        .transpose()?
                        .unwrap_or_default(),
                );
                spec.pinning = match values
                    .get("pinning")
                    .map(|id| btf_uint(btf, *id))
                    .transpose()?
                    .unwrap_or_default()
                {
                    0 => Pinning::None,
                    1 => Pinning::ByName,
                    value => {
                        return Err(Error::InvalidObject(format!(
                            "map `{name}` has unknown pinning value {value}"
                        )));
                    }
                };
                spec.btf_key_type = key_type.unwrap_or(TypeId::VOID);
                spec.btf_value_type = value_type.unwrap_or(TypeId::VOID);
                spec.section_index = Some(map_section_index);
                spec.section_offset = u64::from(variable.offset);
                if let Some(values_type) = values.get("values") {
                    let id = btf.resolve_type(*values_type)?;
                    let BtfType::Array { element_type, .. } =
                        btf.type_by_id(id).ok_or_else(|| {
                            Error::Btf(format!("map `{name}` values type does not exist"))
                        })?
                    else {
                        return Err(Error::InvalidObject(format!(
                            "map `{name}` values member is not an array"
                        )));
                    };
                    let inner_struct = btf.resolve_type(btf_pointee(btf, *element_type)?)?;
                    spec.inner_map = struct_names.get(&inner_struct).cloned();
                }
                // `struct_id` is intentionally retained in `struct_names`; it
                // also detects BTF emitters that reuse a map-definition type.
                let _ = struct_id;
                if definitions.insert(name.into(), spec).is_some() {
                    return Err(Error::InvalidObject(format!(
                        "duplicate map definition `{name}`"
                    )));
                }
            }
            return Ok(definitions);
        }
    }

    parse_legacy_maps(elf, map_section_index, map_data)
}

fn map_variable(btf: &Btf, variable_id: TypeId) -> Result<(&str, TypeId, &[crate::BtfMember])> {
    let BtfType::Variable { name, ty, .. } = btf.type_by_id(variable_id).ok_or_else(|| {
        Error::Btf(format!(
            ".maps references missing variable type {}",
            variable_id.0
        ))
    })?
    else {
        return Err(Error::Btf(format!(
            ".maps type {} is not a variable",
            variable_id.0
        )));
    };
    let struct_id = btf.resolve_type(*ty)?;
    let BtfType::Struct { members, .. } = btf
        .type_by_id(struct_id)
        .ok_or_else(|| Error::Btf(format!("map `{name}` structure type is missing")))?
    else {
        return Err(Error::InvalidObject(format!(
            "map `{name}` definition is not a struct"
        )));
    };
    Ok((name, struct_id, members))
}

fn required_member(members: &HashMap<&str, TypeId>, field: &str, map: &str) -> Result<TypeId> {
    members.get(field).copied().ok_or_else(|| {
        Error::InvalidObject(format!("map `{map}` definition has no `{field}` member"))
    })
}

fn btf_uint(btf: &Btf, id: TypeId) -> Result<u32> {
    let id = btf.resolve_type(id)?;
    let BtfType::Pointer { ty } = btf
        .type_by_id(id)
        .ok_or_else(|| Error::Btf(format!("type ID {} is missing", id.0)))?
    else {
        return Err(Error::InvalidObject(format!(
            "map integer encoding type {} is not a pointer",
            id.0
        )));
    };
    let array_id = btf.resolve_type(*ty)?;
    let BtfType::Array { count, .. } = btf
        .type_by_id(array_id)
        .ok_or_else(|| Error::Btf(format!("type ID {} is missing", array_id.0)))?
    else {
        return Err(Error::InvalidObject(format!(
            "map integer encoding type {} does not point to an array",
            id.0
        )));
    };
    Ok(*count)
}

fn btf_pointee(btf: &Btf, id: TypeId) -> Result<TypeId> {
    let id = btf.resolve_type(id)?;
    let BtfType::Pointer { ty } = btf
        .type_by_id(id)
        .ok_or_else(|| Error::Btf(format!("type ID {} is missing", id.0)))?
    else {
        return Err(Error::InvalidObject(format!(
            "map key/value encoding type {} is not a pointer",
            id.0
        )));
    };
    Ok(*ty)
}

fn parse_legacy_maps(
    elf: &Elf<'_>,
    section_index: usize,
    data: &[u8],
) -> Result<BTreeMap<String, MapSpec>> {
    let mut maps = BTreeMap::new();
    for symbol in elf
        .syms
        .iter()
        .filter(|symbol| symbol.st_shndx == section_index && symbol.st_type() == STT_OBJECT)
    {
        let name = symbol_name(elf, &symbol)?.to_owned();
        let offset = usize::try_from(symbol.st_value)
            .map_err(|_| Error::Elf("legacy map offset does not fit usize".into()))?;
        let size = usize::try_from(symbol.st_size)
            .map_err(|_| Error::Elf("legacy map size does not fit usize".into()))?;
        let definition = data
            .get(offset..offset.saturating_add(size))
            .ok_or_else(|| {
                Error::InvalidObject(format!("legacy map `{name}` lies outside .maps"))
            })?;
        if definition.len() < 20 {
            return Err(Error::InvalidObject(format!(
                "legacy map `{name}` is shorter than 20 bytes"
            )));
        }
        let mut spec = MapSpec::new(
            &name,
            MapType::from_raw(read_u32(definition, 0, elf.little_endian, "map type")?),
            read_u32(definition, 4, elf.little_endian, "map key size")?,
            read_u32(definition, 8, elf.little_endian, "map value size")?,
            read_u32(definition, 12, elf.little_endian, "map maximum entries")?,
        );
        spec.flags =
            MapFlags::from_bits_retain(read_u32(definition, 16, elf.little_endian, "map flags")?);
        spec.section_index = Some(section_index);
        spec.section_offset = symbol.st_value;
        maps.insert(name, spec);
    }
    Ok(maps)
}

fn add_data_maps(
    object_name: &str,
    elf: &Elf<'_>,
    sections: &Sections<'_>,
    btf: Option<&Btf>,
    maps: &mut BTreeMap<String, MapSpec>,
) -> Result<HashMap<usize, String>> {
    let mut result = HashMap::new();
    for (index, header) in elf.section_headers.iter().enumerate() {
        let section_name = sections.name(index)?;
        if !is_data_section(section_name, header) {
            continue;
        }
        let data = sections.owned_data(index)?;
        if data.is_empty() {
            continue;
        }
        let suffix = section_name.trim_start_matches('.');
        let name = format!("{}.{suffix}", sanitize_kernel_name(object_name));
        let mut spec = MapSpec::new(&name, MapType::Array, 4, data.len() as u32, 1);
        spec.flags = MapFlags::MMAPABLE;
        if section_name.starts_with(".rodata") || section_name == ".kconfig" {
            spec.flags |= MapFlags::PROGRAM_READ_ONLY;
            spec.freeze_after_init = true;
        }
        spec.initial_value = Some(data);
        spec.section_index = Some(index);
        if let Some(btf) = btf {
            if let Some((id, _)) = btf.find(crate::BtfKind::DataSection, section_name) {
                spec.btf_value_type = id;
            }
        }
        if maps.insert(name.clone(), spec).is_some() {
            return Err(Error::InvalidObject(format!(
                "data map name `{name}` conflicts with a declared map"
            )));
        }
        result.insert(index, name);
    }
    Ok(result)
}

fn add_struct_ops_maps(
    elf: &Elf<'_>,
    sections: &Sections<'_>,
    btf: Option<&Btf>,
    maps: &mut BTreeMap<String, MapSpec>,
) -> Result<BTreeMap<String, StructOpsDefinition>> {
    let mut definitions = BTreeMap::new();
    for (section_index, _) in elf.section_headers.iter().enumerate() {
        let section_name = sections.name(section_index)?;
        let normalized = section_name.strip_prefix('?').unwrap_or(section_name);
        if !matches!(normalized, ".struct_ops" | ".struct_ops.link") {
            continue;
        }
        let btf = btf.ok_or_else(|| {
            Error::InvalidObject(format!(
                "`{section_name}` requires an object BTF data-section definition"
            ))
        })?;
        let (_, BtfType::DataSection { variables, .. }) = btf
            .find(crate::BtfKind::DataSection, section_name)
            .or_else(|| btf.find(crate::BtfKind::DataSection, normalized))
            .ok_or_else(|| {
                Error::InvalidObject(format!("`{section_name}` is absent from the object BTF"))
            })?
        else {
            unreachable!("BTF lookup was constrained to data sections");
        };
        let data = sections.owned_data(section_index)?;
        for variable in variables {
            let BtfType::Variable {
                name: variable_name,
                ty,
                ..
            } = btf.type_by_id(variable.ty).ok_or_else(|| {
                Error::Btf(format!(
                    "`{section_name}` references missing variable type {}",
                    variable.ty.0
                ))
            })?
            else {
                return Err(Error::Btf(format!(
                    "`{section_name}` type {} is not a variable",
                    variable.ty.0
                )));
            };
            let source_type = btf.resolve_type(*ty)?;
            let BtfType::Struct {
                name: type_name,
                size,
                ..
            } = btf.type_by_id(source_type).ok_or_else(|| {
                Error::Btf(format!(
                    "struct_ops variable `{variable_name}` has a missing type"
                ))
            })?
            else {
                return Err(Error::InvalidObject(format!(
                    "struct_ops variable `{variable_name}` is not a structure"
                )));
            };
            if type_name.is_empty() {
                return Err(Error::Unsupported(format!(
                    "struct_ops variable `{variable_name}` has an anonymous structure type"
                )));
            }
            let offset = usize::try_from(variable.offset).map_err(|_| {
                Error::InvalidObject(format!(
                    "struct_ops variable `{variable_name}` offset is too large"
                ))
            })?;
            let size = usize::try_from(*size).map_err(|_| {
                Error::InvalidObject(format!(
                    "struct_ops variable `{variable_name}` is too large"
                ))
            })?;
            let end = offset.checked_add(size).ok_or_else(|| {
                Error::InvalidObject(format!(
                    "struct_ops variable `{variable_name}` range overflows"
                ))
            })?;
            let initial = data.get(offset..end).ok_or_else(|| {
                Error::InvalidObject(format!(
                    "struct_ops variable `{variable_name}` lies outside `{section_name}`"
                ))
            })?;

            let value_size = u32::try_from(size).map_err(|_| {
                Error::InvalidObject(format!(
                    "struct_ops variable `{variable_name}` is too large"
                ))
            })?;
            let mut spec = MapSpec::new(variable_name, MapType::StructOps, 4, value_size, 1);
            spec.flags
                .set(MapFlags::LINK, normalized == ".struct_ops.link");
            spec.autocreate = !section_name.starts_with('?');
            spec.auto_attach = true;
            spec.btf_value_type = source_type;
            spec.initial_value = Some(initial.to_vec());
            spec.section_index = Some(section_index);
            spec.section_offset = u64::from(variable.offset);
            if maps.insert(variable_name.clone(), spec).is_some()
                || definitions
                    .insert(
                        variable_name.clone(),
                        StructOpsDefinition {
                            source_type,
                            callbacks: Vec::new(),
                            prepared: None,
                        },
                    )
                    .is_some()
            {
                return Err(Error::InvalidObject(format!(
                    "duplicate map definition `{variable_name}`"
                )));
            }
        }
    }
    Ok(definitions)
}

fn collect_struct_ops_relocations(
    elf: &Elf<'_>,
    btf: Option<&Btf>,
    maps: &BTreeMap<String, MapSpec>,
    programs: &BTreeMap<String, ProgramSpec>,
    definitions: &mut BTreeMap<String, StructOpsDefinition>,
) -> Result<()> {
    if definitions.is_empty() {
        return Ok(());
    }
    let btf = btf.ok_or_else(|| Error::InvalidObject("struct_ops requires object BTF".into()))?;
    for (relocation_index, relocations) in &elf.shdr_relocs {
        let target_section = elf.section_headers[*relocation_index].sh_info as usize;
        for relocation in relocations {
            let Some((map_name, map)) = maps.iter().find(|(name, map)| {
                definitions.contains_key(*name)
                    && map.section_index == Some(target_section)
                    && map.section_offset <= relocation.r_offset
                    && relocation.r_offset
                        < map.section_offset.saturating_add(u64::from(map.value_size))
            }) else {
                continue;
            };
            if !matches!(relocation.r_type, R_BPF_64_64 | R_BPF_64_ABS64) {
                return Err(Error::Unsupported(format!(
                    "struct_ops map `{map_name}` uses relocation type {}",
                    relocation.r_type
                )));
            }
            let relative_offset = relocation
                .r_offset
                .checked_sub(map.section_offset)
                .ok_or_else(|| {
                    Error::InvalidObject(format!(
                        "struct_ops relocation for `{map_name}` precedes its value"
                    ))
                })?;
            let definition = definitions
                .get_mut(map_name)
                .expect("map was selected through the definitions table");
            let BtfType::Struct { members, .. } =
                btf.type_by_id(definition.source_type).ok_or_else(|| {
                    Error::Btf(format!("struct_ops map `{map_name}` type is missing"))
                })?
            else {
                return Err(Error::InvalidObject(format!(
                    "struct_ops map `{map_name}` value is not a structure"
                )));
            };
            let bit_offset = u32::try_from(relative_offset)
                .ok()
                .and_then(|offset| offset.checked_mul(8))
                .ok_or_else(|| {
                    Error::InvalidObject(format!(
                        "struct_ops relocation offset for `{map_name}` is too large"
                    ))
                })?;
            let (member_index, member) = members
                .iter()
                .enumerate()
                .find(|(_, member)| {
                    member.bit_offset == bit_offset && member.bitfield_size.is_none()
                })
                .ok_or_else(|| {
                    Error::InvalidObject(format!(
                        "struct_ops relocation at byte {relative_offset} in `{map_name}` does not target a member"
                    ))
                })?;
            let member_type = btf.resolve_type(member.ty)?;
            let BtfType::Pointer { ty } = btf
                .type_by_id(member_type)
                .ok_or_else(|| Error::Btf(format!("member `{}` type is missing", member.name)))?
            else {
                return Err(Error::InvalidObject(format!(
                    "struct_ops relocation targets non-function-pointer member `{}`",
                    member.name
                )));
            };
            let prototype = btf.resolve_type(*ty)?;
            if !matches!(
                btf.type_by_id(prototype),
                Some(BtfType::FunctionPrototype { .. })
            ) {
                return Err(Error::InvalidObject(format!(
                    "struct_ops relocation member `{}` is not a function pointer",
                    member.name
                )));
            }

            let symbol = elf.syms.get(relocation.r_sym).ok_or_else(|| {
                Error::Elf(format!(
                    "struct_ops relocation references missing symbol {}",
                    relocation.r_sym
                ))
            })?;
            let target_offset =
                i128::from(symbol.st_value) + i128::from(relocation.r_addend.unwrap_or_default());
            let program = programs
                .values()
                .find(|program| {
                    program.section_index == symbol.st_shndx
                        && i128::from(program.section_offset) == target_offset
                })
                .ok_or_else(|| {
                    Error::InvalidObject(format!(
                        "struct_ops callback `{}` in `{map_name}` does not resolve to a program",
                        symbol_name(elf, &symbol).unwrap_or("<invalid>")
                    ))
                })?;
            if program.program_type() != ProgramType::StructOps {
                return Err(Error::InvalidObject(format!(
                    "struct_ops member `{}` references non-struct_ops program `{}`",
                    member.name, program.name
                )));
            }
            if definition
                .callbacks
                .iter()
                .any(|callback| callback.member_index == member_index)
            {
                return Err(Error::InvalidObject(format!(
                    "struct_ops member `{}` in `{map_name}` has multiple relocations",
                    member.name
                )));
            }
            definition.callbacks.push(StructOpsCallback {
                member_index,
                program: program.name.clone(),
            });
        }
    }
    Ok(())
}

fn add_kconfig_map(
    object_name: &str,
    elf: &Elf<'_>,
    btf: Option<&mut Btf>,
    maps: &mut BTreeMap<String, MapSpec>,
) -> Result<HashMap<String, (String, u32)>> {
    let Some(btf) = btf else {
        return Ok(HashMap::new());
    };
    let Some((data_section_id, BtfType::DataSection { variables, .. })) =
        btf.find(crate::BtfKind::DataSection, ".kconfig")
    else {
        return Ok(HashMap::new());
    };
    let variables = variables.clone();
    let name = format!("{}.kconfig", sanitize_kernel_name(object_name));
    let mut entries = Vec::with_capacity(variables.len());
    for variable in &variables {
        let BtfType::Variable {
            name: variable_name,
            ty,
            ..
        } = btf.type_by_id(variable.ty).ok_or_else(|| {
            Error::Btf(format!(
                ".kconfig references missing variable type {}",
                variable.ty.0
            ))
        })?
        else {
            return Err(Error::Btf(format!(
                ".kconfig type {} is not a variable",
                variable.ty.0
            )));
        };
        entries.push(KconfigEntry {
            variable_id: variable.ty,
            name: variable_name.clone(),
            offset: 0,
            size: variable.size,
            value_type: *ty,
            weak: extern_symbol_is_weak(elf, variable_name)?,
            alignment: kconfig_alignment(btf, *ty)?,
        });
    }

    let mut size = 0_u32;
    for entry in &mut entries {
        size = round_up_u32(size, entry.alignment)?;
        entry.offset = size;
        size = size
            .checked_add(entry.size)
            .ok_or_else(|| Error::InvalidObject(".kconfig data size overflow".into()))?;
    }
    if size == 0 {
        return Ok(HashMap::new());
    }
    let layout = entries
        .iter()
        .map(|entry| (entry.variable_id, entry.offset))
        .collect::<HashMap<_, _>>();
    btf.set_data_section_layout(".kconfig", size, &layout)?;

    let mut symbols = HashMap::new();
    for entry in &entries {
        symbols.insert(entry.name.clone(), (name.clone(), entry.offset));
    }
    let mut initial_value = vec![0; size as usize];
    let needs_kernel_config = entries
        .iter()
        .any(|entry| entry.name.starts_with("CONFIG_"));
    let kernel_config = needs_kernel_config
        .then(read_kernel_config)
        .transpose()?
        .flatten();

    for entry in entries {
        if let Some(value) = match entry.name.as_str() {
            "LINUX_KERNEL_VERSION" => Some(u64::from(running_kernel_version())),
            "LINUX_HAS_BPF_COOKIE" => Some(u64::from(sys::supports_bpf_cookie())),
            "LINUX_HAS_SYSCALL_WRAPPER" => Some(u64::from(kernel_has_syscall_wrapper()?)),
            _ => None,
        } {
            write_kconfig_numeric(
                &mut initial_value,
                entry.offset,
                entry.size,
                entry.value_type,
                value,
                btf,
            )?;
            continue;
        }
        if entry.name.starts_with("LINUX_") {
            if entry.weak {
                continue;
            }
            return Err(Error::Unsupported(format!(
                "unrecognized virtual kconfig extern `{}`",
                entry.name
            )));
        }
        if !entry.name.starts_with("CONFIG_") {
            return Err(Error::Unsupported(format!(
                "kconfig extern `{}` has no CONFIG_ or LINUX_ prefix",
                entry.name
            )));
        }
        let value = kernel_config
            .as_ref()
            .and_then(|config| config.get(&entry.name));
        match value {
            Some(value) => write_kconfig_value(
                &mut initial_value,
                entry.offset,
                entry.size,
                entry.value_type,
                value,
                btf,
            )?,
            None if entry.weak => {}
            None => {
                return Err(Error::InvalidObject(format!(
                    "strong kconfig extern `{}` is absent from the running kernel configuration",
                    entry.name
                )));
            }
        }
    }

    let mut spec = MapSpec::new(&name, MapType::Array, 4, size, 1);
    spec.flags = MapFlags::MMAPABLE | MapFlags::PROGRAM_READ_ONLY;
    spec.initial_value = Some(initial_value);
    spec.freeze_after_init = true;
    spec.btf_value_type = data_section_id;
    if maps.insert(name.clone(), spec).is_some() {
        return Err(Error::InvalidObject(format!(
            "kconfig map name `{name}` conflicts with a declared map"
        )));
    }
    Ok(symbols)
}

fn collect_ksym_kinds(btf: Option<&Btf>) -> Result<HashMap<String, KsymKind>> {
    let Some(btf) = btf else {
        return Ok(HashMap::new());
    };
    let Some((_, BtfType::DataSection { variables, .. })) =
        btf.find(crate::BtfKind::DataSection, ".ksyms")
    else {
        return Ok(HashMap::new());
    };
    let mut symbols = HashMap::new();
    for entry in variables {
        let ty = btf
            .type_by_id(entry.ty)
            .ok_or_else(|| Error::Btf(format!(".ksyms references missing type {}", entry.ty.0)))?;
        let (name, kind) = match ty {
            BtfType::Variable { name, ty, .. } => (
                name,
                if btf.resolve_type(*ty)? == TypeId::VOID {
                    KsymKind::Untyped
                } else {
                    KsymKind::Variable
                },
            ),
            BtfType::Function { name, .. } => (name, KsymKind::Function),
            _ => {
                return Err(Error::Btf(format!(
                    ".ksyms type {} is neither a variable nor function",
                    entry.ty.0
                )));
            }
        };
        if let Some(previous) = symbols.insert(name.clone(), kind) {
            if previous != kind {
                return Err(Error::InvalidObject(format!(
                    "kernel symbol `{name}` has conflicting BTF declarations"
                )));
            }
        }
    }
    Ok(symbols)
}

fn kconfig_alignment(btf: &Btf, type_id: TypeId) -> Result<u32> {
    let resolved = btf.resolve_type(type_id)?;
    match btf.type_by_id(resolved).ok_or_else(|| {
        Error::Btf(format!(
            "kconfig extern references missing type {}",
            resolved.0
        ))
    })? {
        BtfType::Integer { size, .. }
        | BtfType::Enum { size, .. }
        | BtfType::Enum64 { size, .. } => match *size {
            1 | 2 | 4 | 8 => Ok(*size),
            size => Err(Error::Unsupported(format!(
                "kconfig scalar has unsupported alignment {size}"
            ))),
        },
        BtfType::Array { element_type, .. } => kconfig_alignment(btf, *element_type),
        _ => Err(Error::Unsupported(
            "kconfig extern is not an integer, tristate, or character array".into(),
        )),
    }
}

fn round_up_u32(value: u32, alignment: u32) -> Result<u32> {
    let mask = alignment
        .checked_sub(1)
        .ok_or_else(|| Error::InvalidObject("zero .kconfig alignment".into()))?;
    value
        .checked_add(mask)
        .map(|value| value & !mask)
        .ok_or_else(|| Error::InvalidObject(".kconfig alignment overflow".into()))
}

fn extern_symbol_is_weak(elf: &Elf<'_>, name: &str) -> Result<bool> {
    for symbol in elf.syms.iter().filter(|symbol| symbol.st_shndx == 0) {
        if symbol_name(elf, &symbol)? == name {
            return Ok(symbol.st_bind() == STB_WEAK);
        }
    }
    Err(Error::InvalidObject(format!(
        "BTF extern `{name}` has no undefined ELF symbol"
    )))
}

fn read_kernel_config() -> Result<Option<HashMap<String, String>>> {
    let release =
        fs::read_to_string("/proc/sys/kernel/osrelease").map_err(|source| Error::File {
            operation: "read kernel release",
            path: "/proc/sys/kernel/osrelease".into(),
            source,
        })?;
    let release = release.trim();
    let paths = [
        PathBuf::from(format!("/boot/config-{release}")),
        PathBuf::from(format!("/lib/modules/{release}/config")),
    ];
    for path in paths {
        match fs::read_to_string(&path) {
            Ok(contents) => return Ok(Some(parse_kernel_config(&contents))),
            Err(source) if source.kind() == ErrorKind::NotFound => {}
            Err(source) => {
                return Err(Error::File {
                    operation: "read kernel configuration",
                    path,
                    source,
                });
            }
        }
    }

    let path = Path::new("/proc/config.gz");
    let file = match File::open(path) {
        Ok(file) => file,
        Err(source) if source.kind() == ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(Error::File {
                operation: "open compressed kernel configuration",
                path: path.into(),
                source,
            });
        }
    };
    let mut contents = String::new();
    GzDecoder::new(file)
        .read_to_string(&mut contents)
        .map_err(|source| Error::File {
            operation: "decompress kernel configuration",
            path: path.into(),
            source,
        })?;
    Ok(Some(parse_kernel_config(&contents)))
}

fn parse_kernel_config(contents: &str) -> HashMap<String, String> {
    let mut config = HashMap::new();
    for line in contents.lines() {
        if let Some((name, value)) = line
            .strip_prefix("CONFIG_")
            .and_then(|line| line.split_once('='))
        {
            config.insert(format!("CONFIG_{name}"), value.trim().into());
            continue;
        }
        if let Some(name) = line
            .strip_prefix("# CONFIG_")
            .and_then(|line| line.strip_suffix(" is not set"))
        {
            config.insert(format!("CONFIG_{name}"), "n".into());
        }
    }
    config
}

fn kernel_has_syscall_wrapper() -> Result<bool> {
    let btf = Btf::from_vmlinux()?;
    let supported = btf.types().any(|(_, ty)| {
        ty.kind() == crate::BtfKind::Function
            && ty
                .name()
                .is_some_and(|name| name.starts_with("__") && name.ends_with("_sys_bpf"))
    });
    Ok(supported)
}

fn write_kconfig_value(
    bytes: &mut [u8],
    offset: u32,
    size: u32,
    type_id: TypeId,
    value: &str,
    btf: &Btf,
) -> Result<()> {
    let resolved = btf.resolve_type(type_id)?;
    let ty = btf.type_by_id(resolved).ok_or_else(|| {
        Error::Btf(format!(
            "kconfig extern references missing type {}",
            resolved.0
        ))
    })?;
    if matches!(value, "y" | "m" | "n") {
        let encoded = match ty {
            BtfType::Integer {
                size: 1, encoding, ..
            } if encoding.boolean => match value {
                "y" => 1,
                "n" => 0,
                "m" => {
                    return Err(Error::InvalidObject(
                        "module kconfig value cannot initialize a boolean extern".into(),
                    ));
                }
                _ => unreachable!(),
            },
            BtfType::Integer { size: 1, .. } => u64::from(value.as_bytes()[0]),
            BtfType::Enum {
                name,
                values,
                size: enum_size,
                ..
            }
            | BtfType::Enum64 {
                name,
                values,
                size: enum_size,
                ..
            } if name == "libbpf_tristate" => {
                let expected = match value {
                    "n" => "TRI_NO",
                    "m" => "TRI_MODULE",
                    "y" => "TRI_YES",
                    _ => unreachable!(),
                };
                let fallback = match value {
                    "n" => 0,
                    "m" => 1,
                    "y" => 2,
                    _ => unreachable!(),
                };
                if *enum_size != size {
                    return Err(Error::InvalidObject(
                        "tristate kconfig extern has inconsistent size".into(),
                    ));
                }
                values
                    .iter()
                    .find(|candidate| candidate.name == expected)
                    .map_or(fallback, |candidate| candidate.value as u64)
            }
            _ => {
                return Err(Error::InvalidObject(format!(
                    "kconfig value `{value}` is incompatible with its extern type"
                )));
            }
        };
        return write_kconfig_integer(bytes, offset, size, encoded, btf.endian());
    }

    if value.starts_with('"') {
        let BtfType::Array {
            element_type,
            count,
            ..
        } = ty
        else {
            return Err(Error::InvalidObject(
                "string kconfig value requires a character-array extern".into(),
            ));
        };
        let element = btf.resolve_type(*element_type)?;
        let Some(BtfType::Integer { size: 1, .. }) = btf.type_by_id(element) else {
            return Err(Error::InvalidObject(
                "string kconfig extern does not contain characters".into(),
            ));
        };
        let Some(contents) = value
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
        else {
            return Err(Error::InvalidObject(format!(
                "unterminated string kconfig value `{value}`"
            )));
        };
        let capacity = usize::try_from(size.min(*count))
            .map_err(|_| Error::InvalidObject("kconfig string size is too large".into()))?;
        if capacity == 0 {
            return Err(Error::InvalidObject(
                "kconfig string extern has zero capacity".into(),
            ));
        }
        let offset = usize::try_from(offset)
            .map_err(|_| Error::InvalidObject("kconfig offset does not fit usize".into()))?;
        let target = bytes
            .get_mut(offset..offset.saturating_add(capacity))
            .ok_or_else(|| Error::InvalidObject("kconfig string lies outside its map".into()))?;
        let length = contents.len().min(capacity - 1);
        target[..length].copy_from_slice(&contents.as_bytes()[..length]);
        target[length] = 0;
        return Ok(());
    }

    let numeric = parse_kconfig_integer(value)?;
    write_kconfig_numeric(bytes, offset, size, type_id, numeric, btf)
}

fn write_kconfig_numeric(
    bytes: &mut [u8],
    offset: u32,
    size: u32,
    type_id: TypeId,
    value: u64,
    btf: &Btf,
) -> Result<()> {
    let resolved = btf.resolve_type(type_id)?;
    let ty = btf.type_by_id(resolved).ok_or_else(|| {
        Error::Btf(format!(
            "kconfig extern references missing type {}",
            resolved.0
        ))
    })?;
    let (type_size, signed, boolean) = match ty {
        BtfType::Integer { size, encoding, .. } => (*size, encoding.signed, encoding.boolean),
        _ => {
            return Err(Error::InvalidObject(
                "numeric kconfig value requires an integer extern".into(),
            ));
        }
    };
    if type_size != size {
        return Err(Error::InvalidObject(
            "numeric kconfig extern has inconsistent size".into(),
        ));
    }
    if boolean && value > 1 {
        return Err(Error::InvalidObject(format!(
            "kconfig value {value} is not boolean"
        )));
    }
    let bits = size
        .checked_mul(8)
        .ok_or_else(|| Error::InvalidObject("kconfig integer width overflows".into()))?;
    if !matches!(bits, 8 | 16 | 32 | 64) {
        return Err(Error::InvalidObject(format!(
            "kconfig integer has unsupported width {bits}"
        )));
    }
    let fits = if bits == 64 {
        true
    } else if signed {
        let sign = 1_u64 << (bits - 1);
        value.wrapping_add(sign) < (1_u64 << bits)
    } else {
        value >> bits == 0
    };
    if !fits {
        return Err(Error::InvalidObject(format!(
            "kconfig value {value} does not fit in {bits} bits"
        )));
    }
    write_kconfig_integer(bytes, offset, size, value, btf.endian())
}

fn parse_kconfig_integer(value: &str) -> Result<u64> {
    let (negative, magnitude) = value
        .strip_prefix('-')
        .map_or((false, value), |value| (true, value));
    let (radix, digits) = magnitude
        .strip_prefix("0x")
        .or_else(|| magnitude.strip_prefix("0X"))
        .map_or_else(
            || {
                if magnitude.len() > 1 && magnitude.starts_with('0') {
                    (8, &magnitude[1..])
                } else {
                    (10, magnitude)
                }
            },
            |digits| (16, digits),
        );
    let magnitude = u64::from_str_radix(digits, radix)
        .map_err(|_| Error::InvalidObject(format!("invalid integer kconfig value `{value}`")))?;
    Ok(if negative {
        0_u64.wrapping_sub(magnitude)
    } else {
        magnitude
    })
}

fn mark_hidden_subprograms_static(
    elf: &Elf<'_>,
    sections: &Sections<'_>,
    btf: &mut Btf,
) -> Result<()> {
    for symbol in elf.syms.iter().filter(|symbol| {
        symbol.st_type() == STT_FUNC && symbol.st_visibility() == STV_HIDDEN && symbol.st_shndx != 0
    }) {
        if !sections.name(symbol.st_shndx)?.starts_with(".text") {
            continue;
        }
        let name = symbol_name(elf, &symbol)?;
        btf.set_function_linkage(name, 0)?;
    }
    Ok(())
}

fn write_kconfig_integer(
    bytes: &mut [u8],
    offset: u32,
    size: u32,
    value: u64,
    endian: Endian,
) -> Result<()> {
    let offset = usize::try_from(offset)
        .map_err(|_| Error::InvalidObject(".kconfig offset does not fit usize".into()))?;
    let size = usize::try_from(size)
        .map_err(|_| Error::InvalidObject(".kconfig value size does not fit usize".into()))?;
    if !matches!(size, 1 | 2 | 4 | 8) {
        return Err(Error::InvalidObject(format!(
            "virtual .kconfig value has unsupported size {size}"
        )));
    }
    let target = bytes
        .get_mut(offset..offset.saturating_add(size))
        .ok_or_else(|| Error::InvalidObject(".kconfig value lies outside its data map".into()))?;
    let encoded = match endian {
        Endian::Little => value.to_le_bytes(),
        Endian::Big => value.to_be_bytes(),
    };
    match endian {
        Endian::Little => target.copy_from_slice(&encoded[..size]),
        Endian::Big => target.copy_from_slice(&encoded[encoded.len() - size..]),
    }
    Ok(())
}

fn is_data_section(name: &str, header: &SectionHeader) -> bool {
    let conventional = name == ".data"
        || name.starts_with(".data.")
        || name == ".rodata"
        || name.starts_with(".rodata.")
        || name == ".bss"
        || name.starts_with(".bss.")
        || name == ".kconfig";
    conventional && header.sh_size > 0
}

fn resolve_inner_maps(
    elf: &Elf<'_>,
    sections: &Sections<'_>,
    maps: &mut BTreeMap<String, MapSpec>,
) -> Result<()> {
    let Some((maps_index, _)) = sections.by_name(".maps") else {
        return Ok(());
    };
    for (relocation_index, relocations) in &elf.shdr_relocs {
        if elf.section_headers[*relocation_index].sh_info as usize != maps_index {
            continue;
        }
        for relocation in relocations {
            if relocation.r_type != R_BPF_64_64 {
                continue;
            }
            let Some(symbol) = elf.syms.get(relocation.r_sym) else {
                continue;
            };
            let target_name = symbol_name(elf, &symbol)?;
            if !maps.contains_key(target_name) {
                continue;
            }
            let offset = relocation.r_offset;
            if let Some(outer) = maps.values_mut().find(|map| {
                map.section_offset <= offset
                    && offset
                        < map
                            .section_offset
                            .saturating_add(u64::from(map.value_size.max(1)))
            }) {
                if outer.map_type.is_map_of_maps() {
                    outer.inner_map = Some(target_name.into());
                }
            }
        }
    }
    Ok(())
}

fn executable_entries(elf: &Elf<'_>, sections: &Sections<'_>) -> Result<Vec<EntryPoint>> {
    let mut entries = Vec::new();
    for (section_index, header) in
        elf.section_headers
            .iter()
            .enumerate()
            .filter(|(index, header)| {
                header.sh_flags & u64::from(SHF_EXECINSTR) != 0
                    && header.sh_size > 0
                    && !sections.names[*index].starts_with(".text")
            })
    {
        let section_size = usize::try_from(header.sh_size)
            .map_err(|_| Error::InvalidObject("executable section is too large".into()))?;
        let mut symbols = elf
            .syms
            .iter()
            .filter(|symbol| {
                symbol.st_shndx == section_index
                    && symbol.st_type() == STT_FUNC
                    && symbol.st_bind() == STB_GLOBAL
            })
            .map(|symbol| {
                Ok((
                    usize::try_from(symbol.st_value).map_err(|_| {
                        Error::InvalidObject("program symbol offset is too large".into())
                    })?,
                    usize::try_from(symbol.st_size).map_err(|_| {
                        Error::InvalidObject("program symbol size is too large".into())
                    })?,
                    symbol_name(elf, &symbol)?.to_owned(),
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        symbols.sort_by_key(|(offset, _, _)| *offset);

        if symbols.is_empty() {
            entries.push(EntryPoint {
                section_index,
                name: sanitize_name(sections.name(section_index)?),
                byte_offset: 0,
                byte_size: section_size,
            });
            continue;
        }

        for (position, (offset, declared_size, name)) in symbols.iter().enumerate() {
            let next_offset = symbols
                .get(position + 1)
                .map_or(section_size, |(offset, _, _)| *offset);
            let size = if *declared_size == 0 {
                next_offset.checked_sub(*offset).ok_or_else(|| {
                    Error::InvalidObject(format!("program `{name}` symbols overlap"))
                })?
            } else {
                *declared_size
            };
            let end = offset
                .checked_add(size)
                .ok_or_else(|| Error::InvalidObject(format!("program `{name}` range overflow")))?;
            if *offset % Instruction::SIZE != 0
                || size == 0
                || size % Instruction::SIZE != 0
                || end > section_size
                || end > next_offset
            {
                return Err(Error::InvalidObject(format!(
                    "program `{name}` has invalid section range {offset}..{end}"
                )));
            }
            entries.push(EntryPoint {
                section_index,
                name: name.clone(),
                byte_offset: *offset,
                byte_size: size,
            });
        }
    }
    Ok(entries)
}

fn linked_subprograms(
    elf: &Elf<'_>,
    sections: &Sections<'_>,
    entry: &EntryPoint,
) -> Result<Vec<EntryPoint>> {
    let mut linked = Vec::new();
    let mut seen = HashSet::new();
    let mut queue = vec![entry.clone()];
    let mut position = 0;
    while let Some(source) = queue.get(position).cloned() {
        position += 1;
        let source_end = source
            .byte_offset
            .checked_add(source.byte_size)
            .ok_or_else(|| Error::InvalidObject("subprogram range overflow".into()))?;
        for (relocation_index, relocations) in &elf.shdr_relocs {
            if elf.section_headers[*relocation_index].sh_info as usize != source.section_index {
                continue;
            }
            for relocation in relocations {
                let offset = usize::try_from(relocation.r_offset).map_err(|_| {
                    Error::InvalidObject("subprogram relocation offset is too large".into())
                })?;
                if offset < source.byte_offset
                    || offset >= source_end
                    || !matches!(relocation.r_type, R_BPF_64_32 | R_BPF_64_64)
                {
                    continue;
                }
                let symbol = elf.syms.get(relocation.r_sym).ok_or_else(|| {
                    Error::Elf(format!(
                        "subprogram relocation references missing symbol {}",
                        relocation.r_sym
                    ))
                })?;
                let target_section = symbol.st_shndx;
                if target_section == 0 || !sections.name(target_section)?.starts_with(".text") {
                    continue;
                }
                let target_symbol = if symbol.st_type() == STT_FUNC {
                    symbol
                } else {
                    let target_offset =
                        i128::from(symbol.st_value) + i128::from(relocation.r_addend.unwrap_or(0));
                    elf.syms
                        .iter()
                        .find(|candidate| {
                            candidate.st_shndx == target_section
                                && candidate.st_type() == STT_FUNC
                                && i128::from(candidate.st_value) == target_offset
                        })
                        .ok_or_else(|| {
                            Error::Unsupported(format!(
                                "function-address relocation in `{}` has no target symbol",
                                source.name
                            ))
                        })?
                };
                let target = function_entry(elf, target_section, &target_symbol)?;
                if seen.insert((target.section_index, target.byte_offset)) {
                    queue.push(target.clone());
                    linked.push(target);
                }
            }
        }
    }
    Ok(linked)
}

fn function_entry(elf: &Elf<'_>, section_index: usize, symbol: &Sym) -> Result<EntryPoint> {
    let section_size = usize::try_from(elf.section_headers[section_index].sh_size)
        .map_err(|_| Error::InvalidObject("function section is too large".into()))?;
    let byte_offset = usize::try_from(symbol.st_value)
        .map_err(|_| Error::InvalidObject("function offset is too large".into()))?;
    let next_offset = elf
        .syms
        .iter()
        .filter(|candidate| {
            candidate.st_shndx == section_index
                && candidate.st_type() == STT_FUNC
                && candidate.st_value > symbol.st_value
        })
        .filter_map(|candidate| usize::try_from(candidate.st_value).ok())
        .min()
        .unwrap_or(section_size);
    let declared_size = usize::try_from(symbol.st_size)
        .map_err(|_| Error::InvalidObject("function size is too large".into()))?;
    let byte_size = if declared_size == 0 {
        next_offset
            .checked_sub(byte_offset)
            .ok_or_else(|| Error::InvalidObject("function symbols overlap".into()))?
    } else {
        declared_size
    };
    let end = byte_offset
        .checked_add(byte_size)
        .ok_or_else(|| Error::InvalidObject("function range overflow".into()))?;
    let name = symbol_name(elf, symbol)?.to_owned();
    if byte_offset % Instruction::SIZE != 0
        || byte_size == 0
        || byte_size % Instruction::SIZE != 0
        || end > section_size
        || end > next_offset
    {
        return Err(Error::InvalidObject(format!(
            "function `{name}` has invalid section range {byte_offset}..{end}"
        )));
    }
    Ok(EntryPoint {
        section_index,
        name,
        byte_offset,
        byte_size,
    })
}

#[allow(clippy::too_many_arguments)]
fn apply_program_relocations(
    elf: &Elf<'_>,
    placements: &Placements,
    data_sections: &HashMap<usize, String>,
    extern_data: &HashMap<String, (String, u32)>,
    maps: &BTreeMap<String, MapSpec>,
    program_name: &str,
    instructions: &mut [Instruction],
    map_relocations: &mut Vec<MapRelocation>,
    kfunc_relocations: &mut Vec<KfuncRelocation>,
    ksym_relocations: &mut Vec<KsymRelocation>,
    ksym_kinds: &HashMap<String, KsymKind>,
) -> Result<()> {
    for (relocation_index, relocations) in &elf.shdr_relocs {
        let source_section = elf.section_headers[*relocation_index].sh_info as usize;
        if !placements.contains_key(&source_section) {
            continue;
        }
        for relocation in relocations {
            if relocation.r_offset % Instruction::SIZE as u64 != 0 {
                return Err(Error::InvalidObject(format!(
                    "program relocation offset {} is not instruction-aligned",
                    relocation.r_offset
                )));
            }
            let local_index = usize::try_from(relocation.r_offset / Instruction::SIZE as u64)
                .map_err(|_| Error::InvalidObject("relocation offset is too large".into()))?;
            let Some(instruction_index) =
                translate_placement(placements, source_section, local_index)
            else {
                continue;
            };
            let symbol = elf.syms.get(relocation.r_sym).ok_or_else(|| {
                Error::Elf(format!(
                    "program relocation references missing symbol {}",
                    relocation.r_sym
                ))
            })?;
            let target_section = symbol.st_shndx;

            match relocation.r_type {
                R_BPF_64_32 => {
                    if target_section == 0 {
                        let name = symbol_name(elf, &symbol)?.to_owned();
                        let instruction =
                            instructions.get_mut(instruction_index).ok_or_else(|| {
                                Error::InvalidObject("kfunc relocation is outside program".into())
                            })?;
                        instruction.set_source(BPF_PSEUDO_KFUNC_CALL)?;
                        instruction.immediate = 0;
                        kfunc_relocations.push(KfuncRelocation {
                            program: program_name.into(),
                            instruction_index,
                            name,
                            weak: symbol.st_bind() == STB_WEAK,
                        });
                        continue;
                    }
                    if !placements.contains_key(&target_section) {
                        return Err(Error::Unsupported(format!(
                            "program `{program_name}` calls `{}` in a section that is not linked",
                            symbol_name(elf, &symbol).unwrap_or("<unnamed>")
                        )));
                    }
                    let target_local = usize::try_from(symbol.st_value / Instruction::SIZE as u64)
                        .map_err(|_| Error::InvalidObject("call target is too large".into()))?;
                    let target = translate_placement(placements, target_section, target_local)
                        .ok_or_else(|| {
                            Error::Unsupported(format!(
                                "program `{program_name}` calls `{}` outside its linked instruction set",
                                symbol_name(elf, &symbol).unwrap_or("<unnamed>")
                            ))
                        })?;
                    let delta = i64::try_from(target)
                        .and_then(|target| {
                            i64::try_from(instruction_index).map(|source| target - source - 1)
                        })
                        .map_err(|_| {
                            Error::InvalidObject("call relocation does not fit i64".into())
                        })?;
                    let instruction = instructions.get_mut(instruction_index).ok_or_else(|| {
                        Error::InvalidObject("call relocation is outside program".into())
                    })?;
                    instruction.set_source(BPF_PSEUDO_CALL)?;
                    instruction.immediate = i32::try_from(delta).map_err(|_| {
                        Error::InvalidObject("call relocation does not fit i32".into())
                    })?;
                }
                R_BPF_64_64 => {
                    if placements.contains_key(&target_section) {
                        let target_local = usize::try_from(
                            symbol.st_value / Instruction::SIZE as u64,
                        )
                        .map_err(|_| Error::InvalidObject("function target too large".into()))?;
                        let target =
                            translate_placement(placements, target_section, target_local)
                                .ok_or_else(|| {
                                    Error::Unsupported(format!(
                                        "program `{program_name}` references function `{}` outside its linked instruction set",
                                        symbol_name(elf, &symbol).unwrap_or("<unnamed>")
                                    ))
                                })?;
                        let delta = i64::try_from(target)
                            .and_then(|target| {
                                i64::try_from(instruction_index).map(|source| target - source - 1)
                            })
                            .map_err(|_| {
                                Error::InvalidObject("function relocation too large".into())
                            })?;
                        let instruction =
                            instructions.get_mut(instruction_index).ok_or_else(|| {
                                Error::InvalidObject(
                                    "function relocation is outside program".into(),
                                )
                            })?;
                        instruction.set_source(BPF_PSEUDO_FUNC)?;
                        instruction.immediate = i32::try_from(delta).map_err(|_| {
                            Error::InvalidObject("function relocation does not fit i32".into())
                        })?;
                        continue;
                    }

                    if target_section == 0 {
                        let name = symbol_name(elf, &symbol)?;
                        if !extern_data.contains_key(name) && !maps.contains_key(name) {
                            if relocation.r_addend.unwrap_or_default() != 0 {
                                return Err(Error::Unsupported(format!(
                                    "kernel symbol `{name}` uses a nonzero relocation addend"
                                )));
                            }
                            let end = instruction_index.checked_add(2).ok_or_else(|| {
                                Error::InvalidObject(
                                    "kernel-symbol relocation range overflows".into(),
                                )
                            })?;
                            let Some([instruction, second]) =
                                instructions.get_mut(instruction_index..end)
                            else {
                                return Err(Error::InvalidObject(
                                    "kernel-symbol relocation is truncated".into(),
                                ));
                            };
                            if instruction.code != BPF_LD_IMM_DW {
                                return Err(Error::InvalidObject(format!(
                                    "kernel-symbol relocation in `{program_name}` does not target ldimm64"
                                )));
                            }
                            instruction.set_source(0)?;
                            instruction.immediate = 0;
                            second.immediate = 0;
                            ksym_relocations.push(KsymRelocation {
                                program: program_name.into(),
                                instruction_index,
                                name: name.into(),
                                kind: ksym_kinds.get(name).copied().unwrap_or(KsymKind::Untyped),
                                weak: symbol.st_bind() == STB_WEAK,
                            });
                            continue;
                        }
                    }

                    let (map, value_offset) = if let Some(map) = data_sections.get(&target_section)
                    {
                        let addend = relocation.r_addend.unwrap_or_default();
                        let embedded = instructions
                            .get(instruction_index + 1)
                            .map(|instruction| i64::from(instruction.immediate))
                            .unwrap_or_default();
                        let offset =
                            i128::from(symbol.st_value) + i128::from(addend) + i128::from(embedded);
                        let offset = u32::try_from(offset).map_err(|_| {
                            Error::InvalidObject("data relocation offset does not fit u32".into())
                        })?;
                        (map.clone(), Some(offset))
                    } else {
                        let name = symbol_name(elf, &symbol)?;
                        if let Some((map, base_offset)) = extern_data.get(name) {
                            let addend = relocation.r_addend.unwrap_or_default();
                            let embedded = instructions
                                .get(instruction_index + 1)
                                .map(|instruction| i64::from(instruction.immediate))
                                .unwrap_or_default();
                            let offset = i128::from(*base_offset)
                                + i128::from(addend)
                                + i128::from(embedded);
                            let offset = u32::try_from(offset).map_err(|_| {
                                Error::InvalidObject(
                                    "extern data relocation offset does not fit u32".into(),
                                )
                            })?;
                            (map.clone(), Some(offset))
                        } else if maps.contains_key(name) {
                            (name.into(), None)
                        } else {
                            let absolute = symbol.st_value.saturating_add(
                                relocation.r_addend.unwrap_or_default().max(0) as u64,
                            );
                            let map = maps
                                .values()
                                .find(|map| {
                                    map.section_index == Some(target_section)
                                        && map.section_offset == absolute
                                })
                                .map(|map| map.name.clone())
                                .ok_or_else(|| {
                                    Error::Unsupported(format!(
                                        "relocation references unresolved symbol `{name}`"
                                    ))
                                })?;
                            (map, None)
                        }
                    };
                    let instruction = instructions.get(instruction_index).ok_or_else(|| {
                        Error::InvalidObject("map relocation is outside program".into())
                    })?;
                    if instruction.code != BPF_LD_IMM_DW
                        || instructions.get(instruction_index + 1).is_none()
                    {
                        return Err(Error::InvalidObject(format!(
                            "map relocation in `{program_name}` does not target ldimm64"
                        )));
                    }
                    map_relocations.push(MapRelocation {
                        program: program_name.into(),
                        instruction_index,
                        map,
                        value_offset,
                    });
                }
                0 => {}
                kind => {
                    return Err(Error::Unsupported(format!(
                        "program `{program_name}` uses ELF relocation type {kind}"
                    )));
                }
            }
        }
    }
    Ok(())
}

fn relocate_maps(
    programs: &mut BTreeMap<String, ProgramSpec>,
    relocations: &[MapRelocation],
    maps: &BTreeMap<String, Map>,
) -> Result<()> {
    for relocation in relocations {
        let program = programs.get_mut(&relocation.program).ok_or_else(|| {
            Error::InvalidObject(format!(
                "relocation references missing program `{}`",
                relocation.program
            ))
        })?;
        let map = maps.get(&relocation.map).ok_or_else(|| {
            Error::InvalidObject(format!(
                "relocation references missing map `{}`",
                relocation.map
            ))
        })?;
        let fd = map.fd.as_raw_fd();
        let instruction = program
            .instructions
            .get_mut(relocation.instruction_index)
            .ok_or_else(|| Error::InvalidObject("map relocation is outside program".into()))?;
        instruction.set_source(if relocation.value_offset.is_some() {
            BPF_PSEUDO_MAP_VALUE
        } else {
            BPF_PSEUDO_MAP_FD
        })?;
        instruction.immediate = fd;
        let second = program
            .instructions
            .get_mut(relocation.instruction_index + 1)
            .ok_or_else(|| Error::InvalidObject("map ldimm64 has no second instruction".into()))?;
        second.immediate = relocation.value_offset.unwrap_or_default() as i32;
    }
    Ok(())
}

fn prepare_struct_ops(
    object_btf: Option<&Btf>,
    maps: &mut BTreeMap<String, MapSpec>,
    programs: &mut BTreeMap<String, ProgramSpec>,
    definitions: &mut BTreeMap<String, StructOpsDefinition>,
) -> Result<()> {
    if definitions.is_empty() {
        return Ok(());
    }
    let object_btf =
        object_btf.ok_or_else(|| Error::InvalidObject("struct_ops requires object BTF".into()))?;
    let mut callback_loading = HashMap::<&str, bool>::new();
    for (map_name, definition) in definitions.iter() {
        let map_is_created = maps.get(map_name).is_some_and(|map| map.autocreate);
        for callback in &definition.callbacks {
            callback_loading
                .entry(&callback.program)
                .and_modify(|autoload| *autoload |= map_is_created)
                .or_insert(map_is_created);
        }
    }
    for (program_name, autoload) in callback_loading {
        programs
            .get_mut(program_name)
            .ok_or_else(|| Error::ProgramNotFound(program_name.into()))?
            .autoload = autoload;
    }
    if !definitions
        .keys()
        .any(|name| maps.get(name).is_some_and(|map| map.autocreate))
    {
        return Ok(());
    }
    let kernel_bytes = fs::read("/sys/kernel/btf/vmlinux").map_err(|source| Error::File {
        operation: "read kernel BTF for struct_ops",
        path: "/sys/kernel/btf/vmlinux".into(),
        source,
    })?;
    let kernel_btf = Btf::parse(&kernel_bytes)?;

    for (map_name, definition) in definitions.iter_mut() {
        if !maps.get(map_name).is_some_and(|map| map.autocreate) {
            continue;
        }
        let BtfType::Struct {
            name: source_name,
            members: source_members,
            ..
        } = object_btf
            .type_by_id(definition.source_type)
            .ok_or_else(|| Error::Btf(format!("struct_ops map `{map_name}` type is missing")))?
        else {
            return Err(Error::InvalidObject(format!(
                "struct_ops map `{map_name}` value is not a structure"
            )));
        };
        let source_name = essential_name(source_name);
        let (kernel_type_id, kernel_members) = kernel_btf
            .types()
            .find_map(|(id, ty)| match ty {
                BtfType::Struct { name, members, .. } if essential_name(name) == source_name => {
                    Some((id, members))
                }
                _ => None,
            })
            .ok_or_else(|| {
                Error::Unsupported(format!(
                    "kernel BTF has no struct `{source_name}` required by `{map_name}`"
                ))
            })?;
        let wrapper_name = format!("bpf_struct_ops_{source_name}");
        let (kernel_value_type, wrapper_size, data_offset) = kernel_btf
            .types()
            .find_map(|(id, ty)| {
                let BtfType::Struct {
                    name,
                    size,
                    members,
                } = ty
                else {
                    return None;
                };
                if name != &wrapper_name {
                    return None;
                }
                members.iter().find_map(|member| {
                    (member.bitfield_size.is_none()
                        && member.bit_offset % 8 == 0
                        && kernel_btf.resolve_type(member.ty).ok() == Some(kernel_type_id))
                    .then_some((id, *size, member.bit_offset as usize / 8))
                })
            })
            .ok_or_else(|| {
                Error::Unsupported(format!(
                    "kernel BTF has no `{wrapper_name}` value wrapper for `{map_name}`"
                ))
            })?;
        let map = maps
            .get_mut(map_name)
            .ok_or_else(|| Error::MapNotFound(map_name.clone()))?;
        let source_value = map.initial_value.as_deref().ok_or_else(|| {
            Error::InvalidObject(format!(
                "struct_ops map `{map_name}` has no initial implementation value"
            ))
        })?;
        let mut value = vec![
            0;
            usize::try_from(wrapper_size).map_err(|_| {
                Error::InvalidObject(format!("struct_ops map `{map_name}` value is too large"))
            })?
        ];
        let callbacks_by_member = definition
            .callbacks
            .iter()
            .map(|callback| (callback.member_index, callback.program.as_str()))
            .collect::<HashMap<_, _>>();
        let mut prepared_callbacks = Vec::new();

        for (member_index, source_member) in source_members.iter().enumerate() {
            if source_member.bitfield_size.is_some() || source_member.bit_offset % 8 != 0 {
                return Err(Error::Unsupported(format!(
                    "struct_ops member `{}` in `{map_name}` is a bit field",
                    source_member.name
                )));
            }
            let source_offset = source_member.bit_offset as usize / 8;
            let source_size = object_btf.size_of(source_member.ty)?;
            let source_end = source_offset.checked_add(source_size).ok_or_else(|| {
                Error::InvalidObject(format!(
                    "struct_ops member `{}` range overflows",
                    source_member.name
                ))
            })?;
            let source_bytes = source_value.get(source_offset..source_end).ok_or_else(|| {
                Error::InvalidObject(format!(
                    "struct_ops member `{}` lies outside `{map_name}`",
                    source_member.name
                ))
            })?;
            let Some((kernel_member_index, kernel_member)) =
                kernel_members.iter().enumerate().find(|(_, member)| {
                    essential_name(&member.name) == essential_name(&source_member.name)
                })
            else {
                if source_bytes.iter().any(|byte| *byte != 0)
                    || callbacks_by_member.contains_key(&member_index)
                {
                    return Err(Error::Unsupported(format!(
                        "kernel struct `{source_name}` has no configured member `{}`",
                        source_member.name
                    )));
                }
                continue;
            };
            if kernel_member.bitfield_size.is_some() || kernel_member.bit_offset % 8 != 0 {
                return Err(Error::Unsupported(format!(
                    "kernel struct_ops member `{}` is a bit field",
                    kernel_member.name
                )));
            }
            let source_type = object_btf.resolve_type(source_member.ty)?;
            let kernel_type = kernel_btf.resolve_type(kernel_member.ty)?;
            let source_kind = object_btf
                .type_by_id(source_type)
                .ok_or_else(|| Error::Btf(format!("source type {} is missing", source_type.0)))?
                .kind();
            let kernel_kind = kernel_btf
                .type_by_id(kernel_type)
                .ok_or_else(|| Error::Btf(format!("kernel type {} is missing", kernel_type.0)))?
                .kind();
            if source_kind != kernel_kind {
                return Err(Error::Unsupported(format!(
                    "struct_ops member `{}` has incompatible object and kernel BTF kinds",
                    source_member.name
                )));
            }
            let kernel_offset = data_offset
                .checked_add(kernel_member.bit_offset as usize / 8)
                .ok_or_else(|| {
                    Error::InvalidObject(format!(
                        "kernel offset for struct_ops member `{}` overflows",
                        source_member.name
                    ))
                })?;

            if let BtfType::Pointer { ty: kernel_pointee } = kernel_btf
                .type_by_id(kernel_type)
                .ok_or_else(|| Error::Btf(format!("kernel type {} is missing", kernel_type.0)))?
            {
                let Some(program_name) = callbacks_by_member.get(&member_index).copied() else {
                    if source_bytes.iter().any(|byte| *byte != 0) {
                        return Err(Error::InvalidObject(format!(
                            "struct_ops pointer member `{}` has no program relocation",
                            source_member.name
                        )));
                    }
                    continue;
                };
                let kernel_prototype = kernel_btf.resolve_type(*kernel_pointee)?;
                if !matches!(
                    kernel_btf.type_by_id(kernel_prototype),
                    Some(BtfType::FunctionPrototype { .. })
                ) {
                    return Err(Error::Unsupported(format!(
                        "kernel struct_ops member `{}` is not a function pointer",
                        source_member.name
                    )));
                }
                let program = programs
                    .get_mut(program_name)
                    .ok_or_else(|| Error::ProgramNotFound(program_name.to_owned()))?;
                if program.attach_btf_id != 0 && program.attach_btf_id != kernel_type_id.0 {
                    return Err(Error::InvalidObject(format!(
                        "struct_ops program `{program_name}` is reused for incompatible structures"
                    )));
                }
                let expected_attach_type =
                    crate::AttachType::Other(u32::try_from(kernel_member_index).map_err(|_| {
                        Error::InvalidObject("struct_ops member index does not fit u32".into())
                    })?);
                let ProgramKind::Other {
                    program_type: ProgramType::StructOps,
                    attach_type,
                } = &mut program.kind
                else {
                    return Err(Error::InvalidObject(format!(
                        "callback `{program_name}` is not a struct_ops program"
                    )));
                };
                if attach_type.is_some_and(|attach| attach != expected_attach_type) {
                    return Err(Error::InvalidObject(format!(
                        "struct_ops program `{program_name}` is reused for incompatible members"
                    )));
                }
                *attach_type = Some(expected_attach_type);
                program.attach_btf_id = kernel_type_id.0;
                prepared_callbacks.push((program_name.to_owned(), kernel_offset));
                continue;
            }

            let kernel_size = kernel_btf.size_of(kernel_member.ty)?;
            if source_size != kernel_size {
                return Err(Error::Unsupported(format!(
                    "struct_ops member `{}` has size {source_size}, kernel expects {kernel_size}",
                    source_member.name
                )));
            }
            let kernel_end = kernel_offset.checked_add(kernel_size).ok_or_else(|| {
                Error::InvalidObject(format!(
                    "kernel range for struct_ops member `{}` overflows",
                    source_member.name
                ))
            })?;
            let destination = value.get_mut(kernel_offset..kernel_end).ok_or_else(|| {
                Error::InvalidObject(format!(
                    "kernel struct_ops member `{}` lies outside its value wrapper",
                    source_member.name
                ))
            })?;
            destination.copy_from_slice(source_bytes);
        }

        map.value_size = wrapper_size;
        map.initial_value = Some(value.clone());
        definition.prepared = Some(PreparedStructOps {
            kernel_value_type,
            value,
            callbacks: prepared_callbacks,
        });
    }
    Ok(())
}

fn finalize_struct_ops_values(
    maps: &mut BTreeMap<String, Map>,
    programs: &BTreeMap<String, Program>,
    definitions: &BTreeMap<String, StructOpsDefinition>,
) -> Result<()> {
    for (map_name, definition) in definitions {
        if !maps.contains_key(map_name) {
            continue;
        }
        let prepared = definition.prepared.as_ref().ok_or_else(|| {
            Error::InvalidObject(format!("struct_ops map `{map_name}` was not prepared"))
        })?;
        let mut value = prepared.value.clone();
        for (program_name, offset) in &prepared.callbacks {
            let program = programs
                .get(program_name)
                .ok_or_else(|| Error::ProgramNotFound(program_name.clone()))?;
            let fd = u64::try_from(program.fd.as_raw_fd()).map_err(|_| {
                Error::InvalidObject(format!(
                    "struct_ops callback `{program_name}` has an invalid descriptor"
                ))
            })?;
            let end = offset.checked_add(size_of::<u64>()).ok_or_else(|| {
                Error::InvalidObject("struct_ops callback offset overflows".into())
            })?;
            let slot = value.get_mut(*offset..end).ok_or_else(|| {
                Error::InvalidObject(format!(
                    "struct_ops callback `{program_name}` lies outside the kernel value"
                ))
            })?;
            slot.copy_from_slice(&fd.to_ne_bytes());
        }
        maps.get_mut(map_name)
            .ok_or_else(|| Error::MapNotFound(map_name.clone()))?
            .set_struct_ops_value(value)?;
    }
    Ok(())
}

fn load_maps(
    specs: &BTreeMap<String, MapSpec>,
    reused: &BTreeMap<String, Map>,
    btf_fd: Option<&OwnedFd>,
    pin_root: &Path,
    token_fd: Option<i32>,
    struct_ops: &BTreeMap<String, StructOpsDefinition>,
) -> Result<BTreeMap<String, Map>> {
    let mut loaded = BTreeMap::new();
    let mut pending = specs
        .iter()
        .filter(|(_, spec)| spec.autocreate)
        .map(|(name, _)| name.clone())
        .collect::<HashSet<_>>();
    while !pending.is_empty() {
        let mut progress = false;
        let names = pending.iter().cloned().collect::<Vec<_>>();
        for name in names {
            let spec = &specs[&name];
            if spec
                .inner_map
                .as_ref()
                .is_some_and(|inner| !loaded.contains_key(inner))
            {
                continue;
            }
            let pin_path = (spec.pinning == Pinning::ByName).then(|| pin_root.join(&name));
            let explicit = reused.get(&name).cloned();
            let pinned = pin_path
                .as_ref()
                .filter(|path| path.exists())
                .map(Map::open_pinned)
                .transpose()?;
            let map = if let Some(map) = explicit {
                ensure_map_compatible(spec, &map)?;
                if let Some(pinned) = pinned {
                    if pinned.info()?.id != map.info()?.id {
                        return Err(Error::InvalidObject(format!(
                            "reused map `{name}` differs from existing pin `{}`",
                            pin_path.as_ref().expect("pinned path exists").display()
                        )));
                    }
                } else if let Some(path) = &pin_path {
                    map.pin(path)?;
                }
                map
            } else if let Some(map) = pinned {
                ensure_map_compatible(spec, &map)?;
                map
            } else {
                let inner_fd = spec
                    .inner_map
                    .as_ref()
                    .and_then(|inner| loaded.get(inner))
                    .map(|map: &Map| map.fd.as_raw_fd());
                let accepts_btf = spec.map_type.accepts_btf_types();
                let struct_ops_definition = struct_ops.get(&name);
                let create = |with_btf: bool| {
                    sys::map_create(&MapCreate {
                        map_type: spec.map_type.as_raw(),
                        name: &spec.name,
                        key_size: spec.key_size,
                        value_size: spec.value_size,
                        max_entries: spec.max_entries,
                        flags: spec.flags.bits(),
                        inner_map_fd: inner_fd,
                        numa_node: spec.numa_node,
                        btf_fd: with_btf.then_some(btf_fd).flatten().map(AsRawFd::as_raw_fd),
                        btf_key_type_id: if with_btf { spec.btf_key_type.0 } else { 0 },
                        btf_value_type_id: if with_btf && spec.map_type != MapType::StructOps {
                            spec.btf_value_type.0
                        } else {
                            0
                        },
                        btf_vmlinux_value_type_id: struct_ops_definition
                            .and_then(|definition| definition.prepared.as_ref())
                            .map_or(0, |prepared| prepared.kernel_value_type.0),
                        value_type_btf_obj_fd: None,
                        map_extra: spec.map_extra,
                        token_fd,
                    })
                };
                let with_btf = accepts_btf
                    && btf_fd.is_some()
                    && (spec.btf_key_type != TypeId::VOID || spec.btf_value_type != TypeId::VOID);
                let fd = match create(with_btf) {
                    Ok(fd) => fd,
                    Err(_) if with_btf => create(false).map_err(|source| Error::MapCreate {
                        map: name.clone(),
                        source,
                    })?,
                    Err(source) => {
                        return Err(Error::MapCreate {
                            map: name.clone(),
                            source,
                        });
                    }
                };
                let map = Map::from_fd(fd, spec.clone());
                if spec.map_type != MapType::StructOps {
                    if let Some(initial) = &spec.initial_value {
                        sys::map_update(map.fd.as_raw_fd(), &0_u32.to_ne_bytes(), initial, 0)
                            .map_err(|source| Error::system("initialize data map", source))?;
                    }
                }
                if spec.freeze_after_init {
                    map.freeze()?;
                }
                if let Some(path) = &pin_path {
                    map.pin(path)?;
                }
                map
            };
            loaded.insert(name.clone(), map);
            pending.remove(&name);
            progress = true;
        }
        if !progress {
            return Err(Error::InvalidObject(format!(
                "map dependency cycle among: {}",
                pending.into_iter().collect::<Vec<_>>().join(", ")
            )));
        }
    }
    Ok(loaded)
}

fn ensure_map_compatible(spec: &MapSpec, map: &Map) -> Result<()> {
    let info = map.info()?;
    if info.map_type != spec.map_type
        || info.key_size != spec.key_size
        || info.value_size != spec.value_size
        || info.max_entries != spec.max_entries
        || info.flags != spec.flags
    {
        return Err(Error::InvalidObject(format!(
            "pinned map `{}` is incompatible with the object definition",
            spec.name
        )));
    }
    Ok(())
}

fn running_kernel_version() -> u32 {
    fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .and_then(|release| parse_kernel_version(&release))
        .unwrap_or_default()
}

fn parse_kernel_version(release: &str) -> Option<u32> {
    let mut components = release.trim().split('.');
    let major = components.next()?.parse::<u32>().ok()?;
    let minor = components.next()?.parse::<u32>().ok()?;
    let patch = components
        .next()?
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>()
        .parse::<u32>()
        .ok()?;
    (major <= u32::from(u16::MAX) && minor <= u32::from(u8::MAX))
        .then(|| (major << 16) | (minor << 8) | patch.min(u32::from(u8::MAX)))
}

fn resolve_attach_btf_ids(
    programs: &mut BTreeMap<String, ProgramSpec>,
    token: Option<&BpfToken>,
) -> Result<()> {
    let needs_resolution = programs.values().any(|program| {
        matches!(
            program.kind(),
            ProgramKind::Tracing {
                attach_type,
                target,
            } if !target.is_empty()
                && (program.attach_btf_id == 0
                    || (matches!(
                        attach_type,
                        crate::AttachType::TraceFunctionEntryMulti
                            | crate::AttachType::TraceFunctionExitMulti
                            | crate::AttachType::TraceFunctionSessionMulti
                    ) && target.contains(':')
                        && program.attach_btf_object.is_none()))
        )
    });
    if !needs_resolution {
        return Ok(());
    }
    let bytes = fs::read("/sys/kernel/btf/vmlinux").map_err(|source| Error::File {
        operation: "read kernel BTF for program attachment",
        path: "/sys/kernel/btf/vmlinux".into(),
        source,
    })?;
    let kernel_btf = Btf::parse(&bytes)?;
    for program in programs.values_mut() {
        let (attach_type, target) = match program.kind() {
            ProgramKind::Tracing {
                attach_type,
                target,
            } => (*attach_type, target.clone()),
            _ => continue,
        };
        if target.is_empty() {
            continue;
        }
        let tracing_multi = matches!(
            attach_type,
            crate::AttachType::TraceFunctionEntryMulti
                | crate::AttachType::TraceFunctionExitMulti
                | crate::AttachType::TraceFunctionSessionMulti
        );
        let (module_name, target_name) = match target.split_once(':') {
            Some(("vmlinux", target)) => (None, target),
            Some((module, target)) if !module.is_empty() && !target.is_empty() => {
                (Some(module), target)
            }
            Some(_) => {
                return Err(Error::InvalidObject(format!(
                    "invalid module BTF attachment target `{target}`"
                )));
            }
            None => (None, target.as_str()),
        };
        if tracing_multi {
            if let Some(module_name) = module_name {
                let module = match token {
                    Some(token) => {
                        crate::BtfObject::from_kernel_module_with_token(module_name, token)?
                    }
                    None => crate::BtfObject::from_kernel_module(module_name)?,
                };
                program.attach_btf_object = Some(module);
            }
            continue;
        }
        if program.attach_btf_id != 0 {
            continue;
        }
        let module = match module_name {
            Some(module_name) => Some(match token {
                Some(token) => crate::BtfObject::from_kernel_module_with_token(module_name, token)?,
                None => crate::BtfObject::from_kernel_module(module_name)?,
            }),
            None => None,
        };
        let target_btf = module.as_ref().map_or(&kernel_btf, crate::BtfObject::btf);
        let (prefix, kind) = match attach_type {
            crate::AttachType::TraceRawTracepoint => ("btf_trace_", crate::BtfKind::Typedef),
            crate::AttachType::LsmMac | crate::AttachType::LsmCgroup => {
                ("bpf_lsm_", crate::BtfKind::Function)
            }
            crate::AttachType::TraceIterator => ("bpf_iter_", crate::BtfKind::Function),
            _ => ("", crate::BtfKind::Function),
        };
        let name = format!("{prefix}{target_name}");
        let (id, _) = if module.is_some() {
            target_btf.find_local(kind, &name)
        } else {
            target_btf.find(kind, &name)
        }
        .ok_or_else(|| {
            Error::InvalidObject(format!(
                "attachment target `{name}` for program `{}` is absent from {} BTF",
                program.name,
                module_name.unwrap_or("kernel")
            ))
        })?;
        program.attach_btf_id = id.0;
        program.attach_btf_object = module;
    }
    Ok(())
}

fn resolve_kfunc_relocations(
    programs: &mut BTreeMap<String, ProgramSpec>,
    relocations: &[KfuncRelocation],
    token: Option<&BpfToken>,
) -> Result<()> {
    if relocations.is_empty() {
        return Ok(());
    }
    let bytes = fs::read("/sys/kernel/btf/vmlinux").map_err(|source| Error::File {
        operation: "read kernel BTF for kfunc relocation",
        path: "/sys/kernel/btf/vmlinux".into(),
        source,
    })?;
    let kernel_btf = Btf::parse(&bytes)?;
    let mut module_btfs: Option<Vec<BtfObject>> = None;
    for (index, relocation) in relocations.iter().enumerate() {
        let target = match find_kfunc(&kernel_btf, false, &relocation.name) {
            Some(type_id) => Some((type_id, None)),
            None => {
                if module_btfs.is_none() {
                    module_btfs = Some(match token {
                        Some(token) => crate::BtfObject::kernel_modules_with_token(token)?,
                        None => crate::BtfObject::kernel_modules()?,
                    });
                }
                module_btfs.as_ref().and_then(|modules| {
                    modules.iter().find_map(|module| {
                        find_kfunc(module.btf(), true, &relocation.name)
                            .map(|type_id| (type_id, Some(module.clone())))
                    })
                })
            }
        };
        let program = programs.get_mut(&relocation.program).ok_or_else(|| {
            Error::InvalidObject(format!(
                "kfunc relocation references missing program `{}`",
                relocation.program
            ))
        })?;
        if relocation.instruction_index >= program.instructions.len() {
            return Err(Error::InvalidObject(
                "kfunc relocation is outside program".into(),
            ));
        }
        if let Some((type_id, module)) = target {
            let btf_fd_index = match module {
                Some(module) => retain_kernel_btf_object(program, module)?,
                None => 0,
            };
            let instruction = &mut program.instructions[relocation.instruction_index];
            instruction.set_source(BPF_PSEUDO_KFUNC_CALL)?;
            instruction.offset = btf_fd_index;
            instruction.immediate = i32::try_from(type_id.0)
                .map_err(|_| Error::Btf("kfunc BTF ID does not fit i32".into()))?;
        } else if relocation.weak {
            let instruction = &mut program.instructions[relocation.instruction_index];
            instruction.set_source(0)?;
            instruction.offset = 0;
            instruction.immediate = 2_002_000_000_i32
                .checked_add(i32::try_from(index).unwrap_or(i32::MAX))
                .unwrap_or(i32::MAX);
        } else {
            return Err(Error::Unsupported(format!(
                "kernel BTF does not define kfunc `{}`",
                relocation.name
            )));
        }
    }
    Ok(())
}

fn resolve_ksym_relocations(
    programs: &mut BTreeMap<String, ProgramSpec>,
    relocations: &[KsymRelocation],
    token: Option<&BpfToken>,
) -> Result<()> {
    if relocations.is_empty() {
        return Ok(());
    }
    let bytes = fs::read("/sys/kernel/btf/vmlinux").map_err(|source| Error::File {
        operation: "read kernel BTF for kernel-symbol relocation",
        path: "/sys/kernel/btf/vmlinux".into(),
        source,
    })?;
    let kernel_btf = Btf::parse(&bytes)?;
    let mut module_btfs = programs
        .values()
        .flat_map(|program| program.kernel_btf_objects.iter().cloned())
        .fold(Vec::<BtfObject>::new(), |mut modules, module| {
            if !modules
                .iter()
                .any(|candidate| candidate.info().id == module.info().id)
            {
                modules.push(module);
            }
            modules
        });
    let mut enumerated_modules = false;
    let mut kallsyms = None;

    for relocation in relocations {
        let typed_target = if relocation.kind == KsymKind::Untyped {
            None
        } else {
            let target = find_ksym(&kernel_btf, false, relocation.kind, &relocation.name)
                .map(|type_id| (type_id, None))
                .or_else(|| {
                    module_btfs.iter().find_map(|module| {
                        find_ksym(module.btf(), true, relocation.kind, &relocation.name)
                            .map(|type_id| (type_id, Some(module.clone())))
                    })
                });
            if target.is_some() {
                target
            } else {
                if !enumerated_modules {
                    let discovered = match token {
                        Some(token) => BtfObject::kernel_modules_with_token(token)?,
                        None => BtfObject::kernel_modules()?,
                    };
                    for module in discovered {
                        if !module_btfs
                            .iter()
                            .any(|candidate| candidate.info().id == module.info().id)
                        {
                            module_btfs.push(module);
                        }
                    }
                    enumerated_modules = true;
                }
                module_btfs.iter().find_map(|module| {
                    find_ksym(module.btf(), true, relocation.kind, &relocation.name)
                        .map(|type_id| (type_id, Some(module.clone())))
                })
            }
        };

        let program = programs.get_mut(&relocation.program).ok_or_else(|| {
            Error::InvalidObject(format!(
                "kernel-symbol relocation references missing program `{}`",
                relocation.program
            ))
        })?;
        let end = relocation
            .instruction_index
            .checked_add(2)
            .ok_or_else(|| Error::InvalidObject("kernel-symbol relocation overflows".into()))?;
        if end > program.instructions.len() {
            return Err(Error::InvalidObject(
                "kernel-symbol relocation is outside program".into(),
            ));
        }

        if let Some((type_id, module)) = typed_target {
            let btf_fd = match module {
                Some(module) => {
                    let fd = module.as_fd().as_raw_fd();
                    retain_kernel_btf_object(program, module)?;
                    fd
                }
                None => 0,
            };
            let [instruction, second] =
                &mut program.instructions[relocation.instruction_index..end]
            else {
                unreachable!("the kernel-symbol instruction range has length two");
            };
            instruction.set_source(BPF_PSEUDO_BTF_ID)?;
            instruction.immediate = i32::try_from(type_id.0)
                .map_err(|_| Error::Btf("kernel-symbol BTF ID does not fit i32".into()))?;
            second.immediate = btf_fd;
            continue;
        }

        if relocation.kind != KsymKind::Untyped {
            if relocation.weak {
                clear_ksym_instruction(program, relocation.instruction_index)?;
                continue;
            }
            return Err(Error::Unsupported(format!(
                "kernel BTF does not define {:?} symbol `{}`",
                relocation.kind, relocation.name
            )));
        }

        let symbols = match kallsyms.as_ref() {
            Some(symbols) => symbols,
            None => {
                kallsyms = Some(read_kallsyms()?);
                kallsyms.as_ref().expect("kallsyms was initialized")
            }
        };
        let address = match symbols.get(&relocation.name) {
            Some(Some(address)) => Some(*address),
            Some(None) => {
                return Err(Error::InvalidObject(format!(
                    "kernel symbol `{}` resolves to multiple addresses",
                    relocation.name
                )));
            }
            None => None,
        };
        match address {
            Some(address) => {
                let [instruction, second] =
                    &mut program.instructions[relocation.instruction_index..end]
                else {
                    unreachable!("the kernel-symbol instruction range has length two");
                };
                instruction.set_source(0)?;
                instruction.immediate = address as u32 as i32;
                second.immediate = (address >> 32) as u32 as i32;
            }
            None if relocation.weak => {
                clear_ksym_instruction(program, relocation.instruction_index)?;
            }
            None => {
                return Err(Error::Unsupported(format!(
                    "kernel symbol `{}` is absent or its address is hidden",
                    relocation.name
                )));
            }
        }
    }
    Ok(())
}

fn retain_kernel_btf_object(program: &mut ProgramSpec, module: BtfObject) -> Result<i16> {
    let index = match program
        .kernel_btf_objects
        .iter()
        .position(|candidate| candidate.info().id == module.info().id)
    {
        Some(index) => index + 1,
        None => {
            program.kernel_btf_objects.push(module);
            program.kernel_btf_objects.len()
        }
    };
    i16::try_from(index).map_err(|_| {
        Error::InvalidObject(format!(
            "program `{}` references too many module BTF objects",
            program.name
        ))
    })
}

fn clear_ksym_instruction(program: &mut ProgramSpec, index: usize) -> Result<()> {
    let end = index
        .checked_add(2)
        .ok_or_else(|| Error::InvalidObject("kernel-symbol relocation overflows".into()))?;
    let Some([instruction, second]) = program.instructions.get_mut(index..end) else {
        return Err(Error::InvalidObject(
            "kernel-symbol relocation is outside program".into(),
        ));
    };
    instruction.set_source(0)?;
    instruction.immediate = 0;
    second.immediate = 0;
    Ok(())
}

fn find_kfunc(btf: &Btf, local_only: bool, name: &str) -> Option<TypeId> {
    let find = |name| {
        if local_only {
            btf.find_local(crate::BtfKind::Function, name)
        } else {
            btf.find(crate::BtfKind::Function, name)
        }
        .map(|(id, _)| id)
    };
    find(name).or_else(|| name.split_once("___").and_then(|(name, _)| find(name)))
}

fn find_ksym(btf: &Btf, local_only: bool, kind: KsymKind, name: &str) -> Option<TypeId> {
    let btf_kind = match kind {
        KsymKind::Variable => crate::BtfKind::Variable,
        KsymKind::Function => crate::BtfKind::Function,
        KsymKind::Untyped => return None,
    };
    let find = |name| {
        if local_only {
            btf.find_local(btf_kind, name)
        } else {
            btf.find(btf_kind, name)
        }
        .map(|(id, _)| id)
    };
    find(name).or_else(|| name.split_once("___").and_then(|(name, _)| find(name)))
}

fn read_kallsyms() -> Result<HashMap<String, Option<u64>>> {
    let contents = fs::read_to_string("/proc/kallsyms").map_err(|source| Error::File {
        operation: "read kernel symbols",
        path: "/proc/kallsyms".into(),
        source,
    })?;
    Ok(parse_kallsyms(&contents))
}

fn parse_kallsyms(contents: &str) -> HashMap<String, Option<u64>> {
    let mut symbols = HashMap::new();
    for line in contents.lines() {
        let mut fields = line.split_whitespace();
        let Some(address) = fields
            .next()
            .and_then(|address| u64::from_str_radix(address, 16).ok())
        else {
            continue;
        };
        let Some(_symbol_type) = fields.next() else {
            continue;
        };
        let Some(name) = fields.next() else {
            continue;
        };
        if address == 0 {
            continue;
        }
        match symbols.entry(name.into()) {
            HashMapEntry::Vacant(entry) => {
                entry.insert(Some(address));
            }
            HashMapEntry::Occupied(mut entry)
                if entry.get().is_some_and(|previous| previous != address) =>
            {
                entry.insert(None);
            }
            _ => {}
        }
    }
    symbols
}

fn symbol_name<'a>(elf: &'a Elf<'_>, symbol: &Sym) -> Result<&'a str> {
    elf.strtab
        .get_at(symbol.st_name)
        .ok_or_else(|| Error::Elf(format!("symbol has invalid name offset {}", symbol.st_name)))
}

fn sanitize_name(section: &str) -> String {
    section
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '_' {
                character
            } else {
                '_'
            }
        })
        .collect()
}

fn sanitize_kernel_name(name: &str) -> String {
    name.chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '_' | '.') {
                character
            } else {
                '_'
            }
        })
        .collect()
}

fn nul_terminated(bytes: &[u8]) -> Vec<u8> {
    let mut bytes = bytes.to_vec();
    if bytes.last() != Some(&0) {
        bytes.push(0);
    }
    bytes
}

fn read_u32(bytes: &[u8], offset: usize, little_endian: bool, what: &str) -> Result<u32> {
    let bytes: [u8; 4] = bytes
        .get(offset..offset.saturating_add(4))
        .ok_or_else(|| Error::InvalidObject(format!("{what} lies outside its section")))?
        .try_into()
        .expect("four-byte slice");
    Ok(if little_endian {
        u32::from_le_bytes(bytes)
    } else {
        u32::from_be_bytes(bytes)
    })
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32, little_endian: bool) -> Result<()> {
    let target = bytes
        .get_mut(offset..offset.saturating_add(4))
        .ok_or_else(|| Error::InvalidObject("relocation target is outside its section".into()))?;
    let value = if little_endian {
        value.to_le_bytes()
    } else {
        value.to_be_bytes()
    };
    target.copy_from_slice(&value);
    Ok(())
}

#[derive(Clone, Debug, Default)]
struct ExtSegment {
    record_size: u32,
    sections: HashMap<String, Vec<Vec<u8>>>,
}

#[derive(Clone, Debug, Default)]
struct BtfExt {
    function_info: ExtSegment,
    line_info: ExtSegment,
    core_relocations: ExtSegment,
}

impl BtfExt {
    fn parse(bytes: &[u8], btf: &Btf) -> Result<Self> {
        let endian = btf.endian();
        if bytes.len() < 32 {
            return Err(Error::Btf(".BTF.ext header is truncated".into()));
        }
        let magic = read_ext_u16(bytes, 0, endian)?;
        if magic != 0xeb9f || bytes[2] != 1 {
            return Err(Error::Btf("invalid .BTF.ext header".into()));
        }
        let header_len = read_ext_u32(bytes, 4, endian)? as usize;
        if header_len < 24 || header_len > bytes.len() {
            return Err(Error::Btf(format!(
                "invalid .BTF.ext header length {header_len}"
            )));
        }
        let func_offset = read_ext_u32(bytes, 8, endian)? as usize;
        let func_len = read_ext_u32(bytes, 12, endian)? as usize;
        let line_offset = read_ext_u32(bytes, 16, endian)? as usize;
        let line_len = read_ext_u32(bytes, 20, endian)? as usize;
        let (core_offset, core_len) = if header_len >= 32 {
            (
                read_ext_u32(bytes, 24, endian)? as usize,
                read_ext_u32(bytes, 28, endian)? as usize,
            )
        } else {
            (0, 0)
        };
        Ok(Self {
            function_info: parse_ext_segment(
                ext_slice(bytes, header_len, func_offset, func_len)?,
                btf,
                endian,
            )?,
            line_info: parse_ext_segment(
                ext_slice(bytes, header_len, line_offset, line_len)?,
                btf,
                endian,
            )?,
            core_relocations: parse_ext_segment(
                ext_slice(bytes, header_len, core_offset, core_len)?,
                btf,
                endian,
            )?,
        })
    }
}

fn ext_slice(bytes: &[u8], header_len: usize, offset: usize, len: usize) -> Result<&[u8]> {
    let start = header_len
        .checked_add(offset)
        .ok_or_else(|| Error::Btf(".BTF.ext section offset overflow".into()))?;
    let end = start
        .checked_add(len)
        .ok_or_else(|| Error::Btf(".BTF.ext section length overflow".into()))?;
    bytes
        .get(start..end)
        .ok_or_else(|| Error::Btf(".BTF.ext subsection is out of bounds".into()))
}

fn parse_ext_segment(bytes: &[u8], btf: &Btf, endian: Endian) -> Result<ExtSegment> {
    if bytes.is_empty() {
        return Ok(ExtSegment::default());
    }
    let record_size = read_ext_u32(bytes, 0, endian)?;
    if record_size < 4 {
        return Err(Error::Btf(format!(
            ".BTF.ext record size {record_size} is too small"
        )));
    }
    let record_size_usize = record_size as usize;
    let mut offset = 4;
    let mut sections = HashMap::new();
    while offset < bytes.len() {
        let name_offset = read_ext_u32(bytes, offset, endian)?;
        let count = read_ext_u32(bytes, offset + 4, endian)? as usize;
        offset += 8;
        let name = btf.string_at(name_offset)?.to_owned();
        let byte_count = count
            .checked_mul(record_size_usize)
            .ok_or_else(|| Error::Btf(".BTF.ext record count overflow".into()))?;
        let records = bytes
            .get(offset..offset.saturating_add(byte_count))
            .ok_or_else(|| Error::Btf(".BTF.ext records are truncated".into()))?
            .chunks_exact(record_size_usize)
            .map(<[u8]>::to_vec)
            .collect();
        offset += byte_count;
        sections.insert(name, records);
    }
    Ok(ExtSegment {
        record_size,
        sections,
    })
}

fn append_ext_info(
    output: &mut Vec<u8>,
    output_record_size: &mut u32,
    segment: &ExtSegment,
    placements: &Placements,
    sections: &Sections<'_>,
    endian: Endian,
) -> Result<()> {
    if segment.record_size == 0 {
        return Ok(());
    }
    let mut ordered = placements
        .iter()
        .flat_map(|(section_index, placements)| {
            placements
                .iter()
                .map(move |placement| (section_index, placement))
        })
        .collect::<Vec<_>>();
    ordered.sort_by_key(|(_, placement)| placement.destination_start);
    for (section_index, placement) in ordered {
        let section_name = sections.name(*section_index)?;
        let Some(records) = segment.sections.get(section_name) else {
            continue;
        };
        for record in records {
            let mut record = record.clone();
            let byte_offset = read_ext_u32(&record, 0, endian)?;
            if byte_offset % Instruction::SIZE as u32 != 0 {
                return Err(Error::Btf(format!(
                    ".BTF.ext record for `{section_name}` is not instruction-aligned"
                )));
            }
            let source_index = usize::try_from(byte_offset / Instruction::SIZE as u32)
                .map_err(|_| Error::Btf(".BTF.ext instruction offset is too large".into()))?;
            let Some(destination_index) = placement.translate(source_index) else {
                continue;
            };
            let instruction_offset = u32::try_from(destination_index)
                .map_err(|_| Error::Btf(".BTF.ext instruction offset overflow".into()))?;
            write_ext_u32(&mut record, 0, instruction_offset, endian)?;
            output.extend(record);
        }
    }
    if !output.is_empty() {
        *output_record_size = segment.record_size;
    }
    Ok(())
}

fn append_core_relocations(
    program_name: &str,
    segment: &ExtSegment,
    placements: &Placements,
    output: &mut Vec<CoreRelocation>,
    btf: &Btf,
    sections: &Sections<'_>,
) -> Result<()> {
    if segment.record_size == 0 {
        return Ok(());
    }
    if segment.record_size < 16 {
        return Err(Error::Btf(format!(
            "CO-RE record size {} is smaller than 16",
            segment.record_size
        )));
    }
    for (section_index, section_placements) in placements {
        for placement in section_placements {
            let section_name = sections.name(*section_index)?;
            let Some(records) = segment.sections.get(section_name) else {
                continue;
            };
            for record in records {
                let byte_offset = read_ext_u32(record, 0, btf.endian())?;
                if byte_offset % Instruction::SIZE as u32 != 0 {
                    return Err(Error::Btf(format!(
                        "CO-RE relocation for `{section_name}` is not instruction-aligned"
                    )));
                }
                let local_index = usize::try_from(byte_offset / Instruction::SIZE as u32)
                    .map_err(|_| Error::Btf("CO-RE instruction offset is too large".into()))?;
                let Some(instruction_index) = placement.translate(local_index) else {
                    continue;
                };
                let type_id = TypeId(read_ext_u32(record, 4, btf.endian())?);
                let access_offset = read_ext_u32(record, 8, btf.endian())?;
                let access = btf.string_at(access_offset)?.to_owned();
                let kind = read_ext_u32(record, 12, btf.endian())?;
                output.push(CoreRelocation {
                    program: program_name.into(),
                    instruction_index,
                    type_id,
                    access,
                    kind,
                });
            }
        }
    }
    Ok(())
}

fn apply_core_relocations(
    local_btf: &Btf,
    target_btf: &Btf,
    programs: &mut BTreeMap<String, ProgramSpec>,
    relocations: &[CoreRelocation],
) -> Result<()> {
    if relocations.is_empty() {
        return Ok(());
    }
    for relocation in relocations {
        let value = evaluate_core_relocation(local_btf, target_btf, relocation)?;
        apply_core_value(programs, relocation, value)?;
    }
    Ok(())
}

fn apply_core_relocations_for_running_kernel(
    local_btf: &Btf,
    vmlinux_btf: &Btf,
    programs: &mut BTreeMap<String, ProgramSpec>,
    relocations: &[CoreRelocation],
) -> Result<()> {
    let mut pending = Vec::new();
    for relocation in relocations {
        if relocation.kind == 6 || core_target_exists(local_btf, vmlinux_btf, relocation)? {
            let value = evaluate_core_relocation(local_btf, vmlinux_btf, relocation)?;
            apply_core_value(programs, relocation, value)?;
        } else {
            pending.push(relocation);
        }
    }
    if pending.is_empty() {
        return Ok(());
    }

    let directory = match fs::read_dir("/sys/kernel/btf") {
        Ok(directory) => directory,
        Err(source) if source.kind() == ErrorKind::NotFound => {
            for relocation in pending {
                let value = evaluate_core_relocation(local_btf, vmlinux_btf, relocation)?;
                apply_core_value(programs, relocation, value)?;
            }
            return Ok(());
        }
        Err(source) => {
            return Err(Error::File {
                operation: "enumerate kernel module BTF",
                path: "/sys/kernel/btf".into(),
                source,
            });
        }
    };
    let mut paths = directory
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(|source| Error::File {
            operation: "enumerate kernel module BTF",
            path: "/sys/kernel/btf".into(),
            source,
        })?;
    paths.retain(|path| path.file_name().is_some_and(|name| name != "vmlinux"));
    paths.sort();
    for path in paths {
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(source) if source.kind() == ErrorKind::NotFound => continue,
            Err(source) => {
                return Err(Error::File {
                    operation: "read kernel module BTF for CO-RE",
                    path,
                    source,
                });
            }
        };
        let module_btf = Btf::parse_split(&bytes, vmlinux_btf)?;
        let mut unresolved = Vec::new();
        for relocation in pending {
            if core_target_exists(local_btf, &module_btf, relocation)? {
                let value = evaluate_core_relocation(local_btf, &module_btf, relocation)?;
                apply_core_value(programs, relocation, value)?;
            } else {
                unresolved.push(relocation);
            }
        }
        pending = unresolved;
        if pending.is_empty() {
            return Ok(());
        }
    }
    for relocation in pending {
        let value = evaluate_core_relocation(local_btf, vmlinux_btf, relocation)?;
        apply_core_value(programs, relocation, value)?;
    }
    Ok(())
}

fn core_target_exists(
    local_btf: &Btf,
    target_btf: &Btf,
    relocation: &CoreRelocation,
) -> Result<bool> {
    let local_root = local_btf.resolve_type(relocation.type_id)?;
    Ok(!target_type_candidates(local_btf, target_btf, local_root)?.is_empty())
}

fn apply_core_value(
    programs: &mut BTreeMap<String, ProgramSpec>,
    relocation: &CoreRelocation,
    value: CoreValue,
) -> Result<()> {
    let program = programs.get_mut(&relocation.program).ok_or_else(|| {
        Error::InvalidObject(format!(
            "CO-RE relocation references missing program `{}`",
            relocation.program
        ))
    })?;
    patch_core_instruction(
        &mut program.instructions,
        relocation.instruction_index,
        value,
    )
}

#[derive(Clone, Copy, Debug)]
struct CoreValue {
    value: u64,
    local_size: Option<usize>,
    target_size: Option<usize>,
    poison: bool,
}

impl CoreValue {
    const fn plain(value: u64) -> Self {
        Self {
            value,
            local_size: None,
            target_size: None,
            poison: false,
        }
    }

    const fn poison() -> Self {
        Self {
            value: 0,
            local_size: None,
            target_size: None,
            poison: true,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct FieldDescriptor {
    ty: TypeId,
    bit_offset: u64,
    bitfield_size: Option<u8>,
}

fn evaluate_core_relocation(
    local: &Btf,
    target: &Btf,
    relocation: &CoreRelocation,
) -> Result<CoreValue> {
    let local_root = local.resolve_type(relocation.type_id)?;
    match relocation.kind {
        0..=5 => evaluate_field_relocation(local, target, local_root, relocation),
        6 => Ok(CoreValue::plain(u64::from(relocation.type_id.0))),
        7..=9 | 12 => evaluate_type_relocation(local, target, local_root, relocation.kind),
        10 | 11 => evaluate_enum_relocation(local, target, local_root, relocation),
        kind => Err(Error::Unsupported(format!(
            "unknown CO-RE relocation kind {kind}"
        ))),
    }
}

fn evaluate_field_relocation(
    local: &Btf,
    target: &Btf,
    local_root: TypeId,
    relocation: &CoreRelocation,
) -> Result<CoreValue> {
    let accessors = parse_accessors(&relocation.access)?;
    let local_field = resolve_local_field(local, local_root, &accessors)?;
    let candidates = target_type_candidates(local, target, local_root)?;
    let target_field = candidates.into_iter().find_map(|target_root| {
        resolve_target_field(local, target, local_root, target_root, &accessors).ok()
    });
    if relocation.kind == 2 {
        return Ok(CoreValue::plain(u64::from(target_field.is_some())));
    }
    let Some(target_field) = target_field else {
        return Ok(CoreValue::poison());
    };
    let local_layout = field_layout(local, local_field)?;
    let target_layout = field_layout(target, target_field)?;
    let value = match relocation.kind {
        0 => target_layout.byte_offset,
        1 => target_layout.byte_size as u64,
        3 => u64::from(type_is_signed(target, target_field.ty)?),
        4 => target_layout.left_shift,
        5 => 64 - u64::from(target_layout.bit_size),
        _ => unreachable!(),
    };
    Ok(CoreValue {
        value,
        local_size: (relocation.kind == 0).then_some(local_layout.byte_size),
        target_size: (relocation.kind == 0).then_some(target_layout.byte_size),
        poison: false,
    })
}

fn evaluate_type_relocation(
    local: &Btf,
    target: &Btf,
    local_root: TypeId,
    kind: u32,
) -> Result<CoreValue> {
    let candidate = target_type_candidates(local, target, local_root)?
        .into_iter()
        .next();
    let value = match kind {
        7 => candidate.map_or(0, |id| u64::from(id.0)),
        8 | 12 => u64::from(candidate.is_some()),
        9 => candidate
            .map(|id| target.size_of(id).map(|size| size as u64))
            .transpose()?
            .unwrap_or(0),
        _ => unreachable!(),
    };
    Ok(CoreValue::plain(value))
}

fn evaluate_enum_relocation(
    local: &Btf,
    target: &Btf,
    local_root: TypeId,
    relocation: &CoreRelocation,
) -> Result<CoreValue> {
    let index = relocation.access.parse::<usize>().map_err(|_| {
        Error::Btf(format!(
            "invalid enum CO-RE accessor `{}`",
            relocation.access
        ))
    })?;
    let local_name = enum_value(local, local_root, index)?.0;
    let target_value = target_type_candidates(local, target, local_root)?
        .into_iter()
        .find_map(|id| enum_value_by_name(target, id, local_name));
    match relocation.kind {
        10 => Ok(CoreValue::plain(u64::from(target_value.is_some()))),
        11 => {
            Ok(target_value.map_or_else(CoreValue::poison, |value| CoreValue::plain(value as u64)))
        }
        _ => unreachable!(),
    }
}

fn target_type_candidates(local: &Btf, target: &Btf, local_id: TypeId) -> Result<Vec<TypeId>> {
    let local_ty = local
        .type_by_id(local_id)
        .ok_or_else(|| Error::Btf(format!("local type ID {} does not exist", local_id.0)))?;
    let local_name = local_ty.name().unwrap_or("");
    let essential = essential_name(local_name);
    if essential.is_empty() {
        return Ok(Vec::new());
    }
    Ok(target
        .types()
        .filter(|(_, candidate)| {
            core_kinds_compatible(local_ty, candidate)
                && candidate
                    .name()
                    .is_some_and(|name| essential_name(name) == essential)
        })
        .map(|(id, _)| id)
        .collect())
}

fn core_kinds_compatible(left: &BtfType, right: &BtfType) -> bool {
    matches!(
        (left, right),
        (BtfType::Struct { .. }, BtfType::Struct { .. })
            | (BtfType::Union { .. }, BtfType::Union { .. })
            | (BtfType::Enum { .. }, BtfType::Enum { .. })
            | (BtfType::Enum { .. }, BtfType::Enum64 { .. })
            | (BtfType::Enum64 { .. }, BtfType::Enum { .. })
            | (BtfType::Enum64 { .. }, BtfType::Enum64 { .. })
            | (BtfType::Integer { .. }, BtfType::Integer { .. })
            | (BtfType::Float { .. }, BtfType::Float { .. })
    )
}

fn essential_name(name: &str) -> &str {
    name.split_once("___").map_or(name, |(name, _)| name)
}

fn parse_accessors(access: &str) -> Result<Vec<usize>> {
    let accessors = access
        .split(':')
        .map(|accessor| {
            accessor
                .parse::<usize>()
                .map_err(|_| Error::Btf(format!("invalid CO-RE field accessor `{accessor}`")))
        })
        .collect::<Result<Vec<_>>>()?;
    if accessors.is_empty() {
        Err(Error::Btf("CO-RE field accessor is empty".into()))
    } else {
        Ok(accessors)
    }
}

fn resolve_local_field(btf: &Btf, root: TypeId, accessors: &[usize]) -> Result<FieldDescriptor> {
    let mut descriptor = FieldDescriptor {
        ty: root,
        bit_offset: 0,
        bitfield_size: None,
    };
    for (position, accessor) in accessors.iter().copied().enumerate() {
        if position == 0 && accessor == 0 {
            continue;
        }
        descriptor = step_local_field(btf, descriptor, accessor)?;
    }
    Ok(descriptor)
}

fn step_local_field(
    btf: &Btf,
    mut descriptor: FieldDescriptor,
    accessor: usize,
) -> Result<FieldDescriptor> {
    descriptor.ty = btf.resolve_type(descriptor.ty)?;
    let ty = btf
        .type_by_id(descriptor.ty)
        .ok_or_else(|| Error::Btf(format!("type ID {} does not exist", descriptor.ty.0)))?;
    match ty {
        BtfType::Pointer { ty } => {
            let stride = btf.size_of(*ty)? as u64;
            descriptor.ty = *ty;
            descriptor.bit_offset += accessor as u64 * stride * 8;
            descriptor.bitfield_size = None;
            Ok(descriptor)
        }
        BtfType::Array { element_type, .. } => {
            let stride = btf.size_of(*element_type)? as u64;
            descriptor.ty = *element_type;
            descriptor.bit_offset += accessor as u64 * stride * 8;
            descriptor.bitfield_size = None;
            Ok(descriptor)
        }
        BtfType::Struct { members, .. } | BtfType::Union { members, .. } => {
            let member = members.get(accessor).ok_or_else(|| {
                Error::Btf(format!(
                    "CO-RE member index {accessor} is outside type {}",
                    descriptor.ty.0
                ))
            })?;
            descriptor.ty = member.ty;
            descriptor.bit_offset += u64::from(member.bit_offset);
            descriptor.bitfield_size = member.bitfield_size.filter(|size| *size != 0);
            Ok(descriptor)
        }
        _ => Err(Error::Btf(format!(
            "CO-RE accessor indexes non-composite type {}",
            descriptor.ty.0
        ))),
    }
}

fn resolve_target_field(
    local: &Btf,
    target: &Btf,
    local_root: TypeId,
    target_root: TypeId,
    accessors: &[usize],
) -> Result<FieldDescriptor> {
    let mut local_descriptor = FieldDescriptor {
        ty: local_root,
        bit_offset: 0,
        bitfield_size: None,
    };
    let mut target_descriptor = FieldDescriptor {
        ty: target_root,
        bit_offset: 0,
        bitfield_size: None,
    };
    for (position, accessor) in accessors.iter().copied().enumerate() {
        if position == 0 && accessor == 0 {
            continue;
        }
        local_descriptor.ty = local.resolve_type(local_descriptor.ty)?;
        target_descriptor.ty = target.resolve_type(target_descriptor.ty)?;
        let local_ty = local
            .type_by_id(local_descriptor.ty)
            .ok_or_else(|| Error::Btf("local CO-RE type is missing".into()))?;
        let target_ty = target
            .type_by_id(target_descriptor.ty)
            .ok_or_else(|| Error::Btf("target CO-RE type is missing".into()))?;
        match (local_ty, target_ty) {
            (
                BtfType::Struct {
                    members: local_members,
                    ..
                }
                | BtfType::Union {
                    members: local_members,
                    ..
                },
                BtfType::Struct {
                    members: target_members,
                    ..
                }
                | BtfType::Union {
                    members: target_members,
                    ..
                },
            ) => {
                let local_member = local_members
                    .get(accessor)
                    .ok_or_else(|| Error::Btf("local CO-RE member index is out of range".into()))?;
                let target_member = target_members
                    .iter()
                    .find(|member| {
                        !local_member.name.is_empty()
                            && essential_name(&member.name) == essential_name(&local_member.name)
                    })
                    .or_else(|| {
                        local_member
                            .name
                            .is_empty()
                            .then(|| target_members.get(accessor))
                            .flatten()
                    })
                    .ok_or_else(|| {
                        Error::Btf(format!("target type has no member `{}`", local_member.name))
                    })?;
                local_descriptor.ty = local_member.ty;
                local_descriptor.bit_offset += u64::from(local_member.bit_offset);
                local_descriptor.bitfield_size =
                    local_member.bitfield_size.filter(|size| *size != 0);
                target_descriptor.ty = target_member.ty;
                target_descriptor.bit_offset += u64::from(target_member.bit_offset);
                target_descriptor.bitfield_size =
                    target_member.bitfield_size.filter(|size| *size != 0);
            }
            (
                BtfType::Array {
                    element_type: local_element,
                    ..
                },
                BtfType::Array {
                    element_type: target_element,
                    ..
                },
            ) => {
                local_descriptor.bit_offset +=
                    accessor as u64 * local.size_of(*local_element)? as u64 * 8;
                target_descriptor.bit_offset +=
                    accessor as u64 * target.size_of(*target_element)? as u64 * 8;
                local_descriptor.ty = *local_element;
                target_descriptor.ty = *target_element;
            }
            (BtfType::Pointer { ty: local_type }, BtfType::Pointer { ty: target_type }) => {
                local_descriptor.bit_offset +=
                    accessor as u64 * local.size_of(*local_type)? as u64 * 8;
                target_descriptor.bit_offset +=
                    accessor as u64 * target.size_of(*target_type)? as u64 * 8;
                local_descriptor.ty = *local_type;
                target_descriptor.ty = *target_type;
            }
            _ => {
                return Err(Error::Btf(
                    "local and target CO-RE access paths have incompatible kinds".into(),
                ));
            }
        }
    }
    Ok(target_descriptor)
}

#[derive(Clone, Copy, Debug)]
struct FieldLayout {
    byte_offset: u64,
    byte_size: usize,
    bit_size: u8,
    left_shift: u64,
}

fn field_layout(btf: &Btf, field: FieldDescriptor) -> Result<FieldLayout> {
    let type_size = btf.size_of(field.ty)?;
    if let Some(bit_size) = field.bitfield_size {
        let mut byte_size = type_size;
        if byte_size == 0 || byte_size > 8 {
            return Err(Error::Btf("CO-RE bitfield has invalid storage size".into()));
        }
        let mut byte_offset = field.bit_offset / 8 / byte_size as u64 * byte_size as u64;
        while field.bit_offset + u64::from(bit_size) > (byte_offset + byte_size as u64) * 8 {
            byte_size = byte_size
                .checked_mul(2)
                .ok_or_else(|| Error::Btf("CO-RE bitfield storage overflow".into()))?;
            if byte_size > 8 {
                return Err(Error::Btf(
                    "CO-RE bitfield cannot be read in 64 bits".into(),
                ));
            }
            byte_offset = field.bit_offset / 8 / byte_size as u64 * byte_size as u64;
        }
        let left_shift = if cfg!(target_endian = "little") {
            64 - (field.bit_offset + u64::from(bit_size) - byte_offset * 8)
        } else {
            (8 - byte_size as u64) * 8 + (field.bit_offset - byte_offset * 8)
        };
        Ok(FieldLayout {
            byte_offset,
            byte_size,
            bit_size,
            left_shift,
        })
    } else {
        let bit_size = u8::try_from(type_size.saturating_mul(8)).unwrap_or(64);
        Ok(FieldLayout {
            byte_offset: field.bit_offset / 8,
            byte_size: type_size,
            bit_size,
            left_shift: 0,
        })
    }
}

fn type_is_signed(btf: &Btf, id: TypeId) -> Result<bool> {
    let id = btf.resolve_type(id)?;
    match btf
        .type_by_id(id)
        .ok_or_else(|| Error::Btf(format!("type ID {} does not exist", id.0)))?
    {
        BtfType::Integer { encoding, .. } => Ok(encoding.signed),
        BtfType::Enum { signed, .. } | BtfType::Enum64 { signed, .. } => Ok(*signed),
        _ => Ok(false),
    }
}

fn enum_value(btf: &Btf, id: TypeId, index: usize) -> Result<(&str, i64)> {
    match btf
        .type_by_id(id)
        .ok_or_else(|| Error::Btf(format!("enum type ID {} does not exist", id.0)))?
    {
        BtfType::Enum { values, .. } | BtfType::Enum64 { values, .. } => values
            .get(index)
            .map(|value| (value.name.as_str(), value.value))
            .ok_or_else(|| Error::Btf(format!("enum value index {index} is out of range"))),
        _ => Err(Error::Btf(format!("type ID {} is not an enum", id.0))),
    }
}

fn enum_value_by_name(btf: &Btf, id: TypeId, name: &str) -> Option<i64> {
    match btf.type_by_id(id)? {
        BtfType::Enum { values, .. } | BtfType::Enum64 { values, .. } => values
            .iter()
            .find(|value| essential_name(&value.name) == essential_name(name))
            .map(|value| value.value),
        _ => None,
    }
}

fn patch_core_instruction(
    instructions: &mut [Instruction],
    index: usize,
    value: CoreValue,
) -> Result<()> {
    let instruction = instructions
        .get_mut(index)
        .ok_or_else(|| Error::InvalidObject("CO-RE relocation is outside program".into()))?;
    if value.poison {
        let is_ldimm64 = instruction.code == BPF_LD_IMM_DW;
        *instruction = Instruction::new(0x85, 0, 0, 0, 195_896_080);
        if is_ldimm64 {
            if let Some(second) = instructions.get_mut(index + 1) {
                *second = Instruction::new(0x85, 0, 0, 0, 195_896_080);
            }
        }
        return Ok(());
    }
    let class = instruction.code & 0x07;
    match class {
        0 if instruction.code == BPF_LD_IMM_DW => {
            instruction.immediate = value.value as u32 as i32;
            let second = instructions
                .get_mut(index + 1)
                .ok_or_else(|| Error::InvalidObject("CO-RE ldimm64 is truncated".into()))?;
            second.immediate = (value.value >> 32) as u32 as i32;
        }
        1..=3 => {
            instruction.offset = i16::try_from(value.value)
                .map_err(|_| Error::InvalidObject("CO-RE memory offset does not fit i16".into()))?;
            if let (Some(local_size), Some(target_size)) = (value.local_size, value.target_size) {
                if local_size != target_size {
                    let size_bits = match target_size {
                        1 => 0x10,
                        2 => 0x08,
                        4 => 0x00,
                        8 => 0x18,
                        _ => {
                            return Err(Error::Unsupported(format!(
                                "CO-RE cannot encode a {target_size}-byte memory access"
                            )));
                        }
                    };
                    instruction.code = (instruction.code & !0x18) | size_bits;
                }
            }
        }
        4 | 7 => {
            instruction.immediate = value.value as u32 as i32;
        }
        _ => {
            return Err(Error::InvalidObject(format!(
                "CO-RE relocation targets unsupported opcode 0x{:02x}",
                instruction.code
            )));
        }
    }
    Ok(())
}

fn read_ext_u16(bytes: &[u8], offset: usize, endian: Endian) -> Result<u16> {
    let value: [u8; 2] = bytes
        .get(offset..offset.saturating_add(2))
        .ok_or_else(|| Error::Btf(".BTF.ext is truncated".into()))?
        .try_into()
        .expect("two-byte slice");
    Ok(match endian {
        Endian::Little => u16::from_le_bytes(value),
        Endian::Big => u16::from_be_bytes(value),
    })
}

fn read_ext_u32(bytes: &[u8], offset: usize, endian: Endian) -> Result<u32> {
    let value: [u8; 4] = bytes
        .get(offset..offset.saturating_add(4))
        .ok_or_else(|| Error::Btf(".BTF.ext is truncated".into()))?
        .try_into()
        .expect("four-byte slice");
    Ok(match endian {
        Endian::Little => u32::from_le_bytes(value),
        Endian::Big => u32::from_be_bytes(value),
    })
}

fn write_ext_u32(bytes: &mut [u8], offset: usize, value: u32, endian: Endian) -> Result<()> {
    let target = bytes
        .get_mut(offset..offset.saturating_add(4))
        .ok_or_else(|| Error::Btf(".BTF.ext record is truncated".into()))?;
    let encoded = match endian {
        Endian::Little => value.to_le_bytes(),
        Endian::Big => value.to_be_bytes(),
    };
    target.copy_from_slice(&encoded);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use object::write::{
        Object as WriteObject, Relocation, StandardSection, Symbol, SymbolSection,
    };
    use object::{
        Architecture, BinaryFormat, Endianness, RelocationFlags, SectionKind, SymbolFlags,
        SymbolKind, SymbolScope,
    };

    fn instruction_bytes(instructions: &[Instruction]) -> Vec<u8> {
        instructions
            .iter()
            .flat_map(|instruction| {
                [
                    instruction.code,
                    instruction.destination() | (instruction.source() << 4),
                    instruction.offset.to_ne_bytes()[0],
                    instruction.offset.to_ne_bytes()[1],
                    instruction.immediate.to_ne_bytes()[0],
                    instruction.immediate.to_ne_bytes()[1],
                    instruction.immediate.to_ne_bytes()[2],
                    instruction.immediate.to_ne_bytes()[3],
                ]
            })
            .collect()
    }

    fn legacy_object_fixture(with_subprogram: bool) -> Vec<u8> {
        let mut object = WriteObject::new(BinaryFormat::Elf, Architecture::Bpf, Endianness::Little);
        let program_section = object.add_section(
            Vec::new(),
            b"raw_tracepoint/sys_enter".to_vec(),
            SectionKind::Text,
        );
        let mut program = vec![
            Instruction::new(BPF_LD_IMM_DW, 1, 0, 0, 0),
            Instruction::default(),
            Instruction::new(0x95, 0, 0, 0, 0),
        ];
        if with_subprogram {
            program = vec![
                Instruction::new(0x85, 0, 0, 0, 0),
                Instruction::new(0x95, 0, 0, 0, 0),
            ];
        }
        object.append_section_data(program_section, &instruction_bytes(&program), 8);
        object.add_symbol(Symbol {
            name: b"entry".to_vec(),
            value: 0,
            size: (program.len() * Instruction::SIZE) as u64,
            kind: SymbolKind::Text,
            scope: SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Section(program_section),
            flags: SymbolFlags::None,
        });

        let maps = object.add_section(Vec::new(), b".maps".to_vec(), SectionKind::Data);
        let mut definition = Vec::new();
        definition.extend(1_u32.to_le_bytes()); // hash
        definition.extend(4_u32.to_le_bytes());
        definition.extend(8_u32.to_le_bytes());
        definition.extend(16_u32.to_le_bytes());
        definition.extend(0_u32.to_le_bytes());
        object.append_section_data(maps, &definition, 8);
        let map_symbol = object.add_symbol(Symbol {
            name: b"counts".to_vec(),
            value: 0,
            size: definition.len() as u64,
            kind: SymbolKind::Data,
            scope: SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Section(maps),
            flags: SymbolFlags::None,
        });

        if with_subprogram {
            let text = object.section_id(StandardSection::Text);
            object.append_section_data(
                text,
                &instruction_bytes(&[
                    Instruction::new(0xb7, 0, 0, 0, 7),
                    Instruction::new(0x95, 0, 0, 0, 0),
                ]),
                8,
            );
            let subprogram = object.add_symbol(Symbol {
                name: b"subprogram".to_vec(),
                value: 0,
                size: 16,
                kind: SymbolKind::Text,
                scope: SymbolScope::Compilation,
                weak: false,
                section: SymbolSection::Section(text),
                flags: SymbolFlags::None,
            });
            object
                .add_relocation(
                    program_section,
                    Relocation {
                        offset: 0,
                        symbol: subprogram,
                        addend: 0,
                        flags: RelocationFlags::Elf {
                            r_type: R_BPF_64_32,
                        },
                    },
                )
                .unwrap();
        } else {
            object
                .add_relocation(
                    program_section,
                    Relocation {
                        offset: 0,
                        symbol: map_symbol,
                        addend: 0,
                        flags: RelocationFlags::Elf {
                            r_type: R_BPF_64_64,
                        },
                    },
                )
                .unwrap();
        }

        let license = object.add_section(Vec::new(), b"license".to_vec(), SectionKind::Data);
        object.append_section_data(license, b"Dual BSD/GPL\0", 1);
        object.write().unwrap()
    }

    fn shared_program_section_fixture() -> Vec<u8> {
        let mut object = WriteObject::new(BinaryFormat::Elf, Architecture::Bpf, Endianness::Little);
        let section = object.add_section(
            Vec::new(),
            b"raw_tracepoint/sys_enter".to_vec(),
            SectionKind::Text,
        );
        object.append_section_data(
            section,
            &instruction_bytes(&[
                Instruction::new(0xb7, 0, 0, 0, 1),
                Instruction::new(0x95, 0, 0, 0, 0),
                Instruction::new(0xb7, 0, 0, 0, 2),
                Instruction::new(0x95, 0, 0, 0, 0),
            ]),
            8,
        );
        for (name, value) in [(b"first".as_slice(), 0), (b"second".as_slice(), 16)] {
            object.add_symbol(Symbol {
                name: name.to_vec(),
                value,
                size: 16,
                kind: SymbolKind::Text,
                scope: SymbolScope::Linkage,
                weak: false,
                section: SymbolSection::Section(section),
                flags: SymbolFlags::None,
            });
        }
        object.write().unwrap()
    }

    fn selective_subprogram_fixture() -> Vec<u8> {
        let mut object = WriteObject::new(BinaryFormat::Elf, Architecture::Bpf, Endianness::Little);
        let entry = object.add_section(
            Vec::new(),
            b"raw_tracepoint/sys_enter".to_vec(),
            SectionKind::Text,
        );
        object.append_section_data(
            entry,
            &instruction_bytes(&[
                Instruction::new(0x85, 0, 0, 0, 0),
                Instruction::new(0x95, 0, 0, 0, 0),
            ]),
            8,
        );
        object.add_symbol(Symbol {
            name: b"entry".to_vec(),
            value: 0,
            size: 16,
            kind: SymbolKind::Text,
            scope: SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Section(entry),
            flags: SymbolFlags::None,
        });

        let text = object.section_id(StandardSection::Text);
        object.append_section_data(
            text,
            &instruction_bytes(&[
                Instruction::new(0xb7, 0, 0, 0, 1),
                Instruction::new(0x95, 0, 0, 0, 0),
                Instruction::new(0xb7, 0, 0, 0, 2),
                Instruction::new(0x95, 0, 0, 0, 0),
            ]),
            8,
        );
        object.add_symbol(Symbol {
            name: b"unused".to_vec(),
            value: 0,
            size: 16,
            kind: SymbolKind::Text,
            scope: SymbolScope::Compilation,
            weak: false,
            section: SymbolSection::Section(text),
            flags: SymbolFlags::None,
        });
        let used = object.add_symbol(Symbol {
            name: b"used".to_vec(),
            value: 16,
            size: 16,
            kind: SymbolKind::Text,
            scope: SymbolScope::Compilation,
            weak: false,
            section: SymbolSection::Section(text),
            flags: SymbolFlags::None,
        });
        object
            .add_relocation(
                entry,
                Relocation {
                    offset: 0,
                    symbol: used,
                    addend: 0,
                    flags: RelocationFlags::Elf {
                        r_type: R_BPF_64_32,
                    },
                },
            )
            .unwrap();
        object.write().unwrap()
    }

    fn map_only_fixture() -> Vec<u8> {
        let mut object = WriteObject::new(BinaryFormat::Elf, Architecture::Bpf, Endianness::Little);
        let maps = object.add_section(Vec::new(), b".maps".to_vec(), SectionKind::Data);
        let mut definition = Vec::new();
        definition.extend(2_u32.to_le_bytes());
        definition.extend(4_u32.to_le_bytes());
        definition.extend(8_u32.to_le_bytes());
        definition.extend(1_u32.to_le_bytes());
        definition.extend(0_u32.to_le_bytes());
        object.append_section_data(maps, &definition, 8);
        object.add_symbol(Symbol {
            name: b"only_map".to_vec(),
            value: 0,
            size: definition.len() as u64,
            kind: SymbolKind::Data,
            scope: SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Section(maps),
            flags: SymbolFlags::None,
        });
        object.write().unwrap()
    }

    fn push_u32(bytes: &mut Vec<u8>, value: u32) {
        bytes.extend(value.to_le_bytes());
    }

    fn btf_object_fixture() -> Vec<u8> {
        let mut strings = vec![0];
        let mut add_string = |value: &str| {
            let offset = strings.len() as u32;
            strings.extend(value.as_bytes());
            strings.push(0);
            offset
        };
        let u32_name = add_string("u32");
        let u64_name = add_string("u64");
        let map_definition_name = add_string("map_definition");
        let type_name = add_string("type");
        let max_entries_name = add_string("max_entries");
        let key_name = add_string("key");
        let value_name = add_string("value");
        let counts_name = add_string("counts");
        let maps_name = add_string(".maps");
        let context_name = add_string("ctx");
        let entry_name = add_string("entry");
        let section_name = add_string("raw_tracepoint/sys_enter");

        let mut types = Vec::new();
        // 1: u32
        push_u32(&mut types, u32_name);
        push_u32(&mut types, 1 << 24);
        push_u32(&mut types, 4);
        push_u32(&mut types, 32);
        // 2: [u32; 1], 3: pointer (map type = HASH)
        push_u32(&mut types, 0);
        push_u32(&mut types, 3 << 24);
        push_u32(&mut types, 0);
        push_u32(&mut types, 1);
        push_u32(&mut types, 1);
        push_u32(&mut types, 1);
        push_u32(&mut types, 0);
        push_u32(&mut types, 2 << 24);
        push_u32(&mut types, 2);
        // 4: [u32; 16], 5: pointer (max entries)
        push_u32(&mut types, 0);
        push_u32(&mut types, 3 << 24);
        push_u32(&mut types, 0);
        push_u32(&mut types, 1);
        push_u32(&mut types, 1);
        push_u32(&mut types, 16);
        push_u32(&mut types, 0);
        push_u32(&mut types, 2 << 24);
        push_u32(&mut types, 4);
        // 6: *u32 (key)
        push_u32(&mut types, 0);
        push_u32(&mut types, 2 << 24);
        push_u32(&mut types, 1);
        // 7: u64, 8: *u64 (value)
        push_u32(&mut types, u64_name);
        push_u32(&mut types, 1 << 24);
        push_u32(&mut types, 8);
        push_u32(&mut types, 64);
        push_u32(&mut types, 0);
        push_u32(&mut types, 2 << 24);
        push_u32(&mut types, 7);
        // 9: named map definition struct.
        push_u32(&mut types, map_definition_name);
        push_u32(&mut types, (4 << 24) | 4);
        push_u32(&mut types, 32);
        for (name, ty, offset) in [
            (type_name, 3, 0),
            (max_entries_name, 5, 64),
            (key_name, 6, 128),
            (value_name, 8, 192),
        ] {
            push_u32(&mut types, name);
            push_u32(&mut types, ty);
            push_u32(&mut types, offset);
        }
        // 10: counts variable, 11: .maps data section.
        push_u32(&mut types, counts_name);
        push_u32(&mut types, 14 << 24);
        push_u32(&mut types, 9);
        push_u32(&mut types, 1);
        push_u32(&mut types, maps_name);
        push_u32(&mut types, (15 << 24) | 1);
        push_u32(&mut types, 32);
        push_u32(&mut types, 10);
        push_u32(&mut types, 0);
        push_u32(&mut types, 32);
        // 12: void pointer, 13: int (void *) prototype, 14: entry function.
        push_u32(&mut types, 0);
        push_u32(&mut types, 2 << 24);
        push_u32(&mut types, 0);
        push_u32(&mut types, 0);
        push_u32(&mut types, (13 << 24) | 1);
        push_u32(&mut types, 1);
        push_u32(&mut types, context_name);
        push_u32(&mut types, 12);
        push_u32(&mut types, entry_name);
        push_u32(&mut types, (12 << 24) | 1);
        push_u32(&mut types, 13);

        let mut btf = Vec::new();
        btf.extend(0xeb9f_u16.to_le_bytes());
        btf.extend([1, 0]);
        push_u32(&mut btf, 24);
        push_u32(&mut btf, 0);
        push_u32(&mut btf, types.len() as u32);
        push_u32(&mut btf, types.len() as u32);
        push_u32(&mut btf, strings.len() as u32);
        btf.extend(types);
        btf.extend(strings);

        let mut btf_ext = Vec::new();
        btf_ext.extend(0xeb9f_u16.to_le_bytes());
        btf_ext.extend([1, 0]);
        push_u32(&mut btf_ext, 32);
        push_u32(&mut btf_ext, 0);
        push_u32(&mut btf_ext, 20);
        push_u32(&mut btf_ext, 20);
        push_u32(&mut btf_ext, 0);
        push_u32(&mut btf_ext, 20);
        push_u32(&mut btf_ext, 0);
        push_u32(&mut btf_ext, 8);
        push_u32(&mut btf_ext, section_name);
        push_u32(&mut btf_ext, 1);
        push_u32(&mut btf_ext, 0);
        push_u32(&mut btf_ext, 14);

        let mut object = WriteObject::new(BinaryFormat::Elf, Architecture::Bpf, Endianness::Little);
        let program = object.add_section(
            Vec::new(),
            b"raw_tracepoint/sys_enter".to_vec(),
            SectionKind::Text,
        );
        object.append_section_data(
            program,
            &instruction_bytes(&[Instruction::new(0x95, 0, 0, 0, 0)]),
            8,
        );
        object.add_symbol(Symbol {
            name: b"entry".to_vec(),
            value: 0,
            size: 8,
            kind: SymbolKind::Text,
            scope: SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Section(program),
            flags: SymbolFlags::None,
        });
        let maps = object.add_section(Vec::new(), b".maps".to_vec(), SectionKind::Data);
        object.append_section_data(maps, &[0; 32], 8);
        object.add_symbol(Symbol {
            name: b"counts".to_vec(),
            value: 0,
            size: 32,
            kind: SymbolKind::Data,
            scope: SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Section(maps),
            flags: SymbolFlags::None,
        });
        let btf_section =
            object.add_section(Vec::new(), b".BTF".to_vec(), SectionKind::ReadOnlyData);
        object.append_section_data(btf_section, &btf, 4);
        let ext_section =
            object.add_section(Vec::new(), b".BTF.ext".to_vec(), SectionKind::ReadOnlyData);
        object.append_section_data(ext_section, &btf_ext, 4);
        object.write().unwrap()
    }

    #[test]
    fn sanitizes_section_names_for_fallback_program_names() {
        assert_eq!(
            sanitize_name("tracepoint/syscalls/open"),
            "tracepoint_syscalls_open"
        );
    }

    #[test]
    fn sanitizes_object_names_used_by_kernel_data_maps() {
        assert_eq!(sanitize_kernel_name("my-probe"), "my_probe");
        assert_eq!(sanitize_kernel_name("already.valid_1"), "already.valid_1");
    }

    #[test]
    fn nul_termination_is_idempotent() {
        assert_eq!(nul_terminated(b"GPL"), b"GPL\0");
        assert_eq!(nul_terminated(b"GPL\0"), b"GPL\0");
    }

    #[test]
    fn rejects_non_elf_input() {
        assert!(Object::parse(b"not an ELF").is_err());
    }

    #[test]
    fn parses_legacy_map_and_records_map_relocation() {
        let object = Object::parse_named("fixture", &legacy_object_fixture(false)).unwrap();
        let map = object.map("counts").unwrap();
        assert_eq!(map.map_type(), MapType::Hash);
        assert_eq!(map.key_size(), 4);
        assert_eq!(map.value_size(), 8);
        assert_eq!(map.max_entries(), 16);
        assert_eq!(object.license(), "Dual BSD/GPL");
        assert_eq!(object.map_relocations.len(), 1);
        assert_eq!(object.map_relocations[0].map, "counts");
        assert_eq!(object.program("entry").unwrap().instructions().len(), 3);
    }

    #[test]
    fn links_text_subprogram_and_patches_relative_call() {
        let object = Object::parse(&legacy_object_fixture(true)).unwrap();
        let instructions = object.program("entry").unwrap().instructions();
        assert_eq!(instructions.len(), 4);
        assert_eq!(instructions[0].source(), BPF_PSEUDO_CALL);
        assert_eq!(instructions[0].immediate, 1);
        assert_eq!(instructions[2].immediate, 7);
    }

    #[test]
    fn splits_multiple_entry_programs_sharing_one_section() {
        let object = Object::parse(&shared_program_section_fixture()).unwrap();
        assert_eq!(object.programs().len(), 2);
        let first = object.program("first").unwrap();
        let second = object.program("second").unwrap();
        assert_eq!(first.instructions().len(), 2);
        assert_eq!(second.instructions().len(), 2);
        assert_eq!(first.instructions()[0].immediate, 1);
        assert_eq!(second.instructions()[0].immediate, 2);
        assert_eq!(first.section_offset, 0);
        assert_eq!(second.section_offset, 16);
    }

    #[test]
    fn links_only_reachable_subprogram_functions() {
        let object = Object::parse(&selective_subprogram_fixture()).unwrap();
        let instructions = object.program("entry").unwrap().instructions();
        assert_eq!(instructions.len(), 4);
        assert_eq!(instructions[0].source(), BPF_PSEUDO_CALL);
        assert_eq!(instructions[0].immediate, 1);
        assert_eq!(instructions[2].immediate, 2);
    }

    #[test]
    fn accepts_objects_containing_only_maps() {
        let object = Object::parse(&map_only_fixture()).unwrap();
        assert_eq!(object.maps().len(), 1);
        assert_eq!(object.programs().len(), 0);
        assert_eq!(object.map("only_map").unwrap().map_type(), MapType::Array);
    }

    #[test]
    fn parses_kernel_release_for_program_loads() {
        assert_eq!(
            parse_kernel_version("6.19.14-200.fc43\n"),
            Some(0x0006_130e)
        );
        assert_eq!(parse_kernel_version("4.19.260"), Some(0x0004_13ff));
        assert_eq!(parse_kernel_version("not-a-release"), None);
    }

    #[test]
    fn relocates_repository_usdt_btf_information_when_available() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../libbpf-rs/tests/bin/usdt.bpf.o");
        if !path.exists() {
            return;
        }
        let object = Object::open(path).unwrap();
        let (_, BtfType::Function { linkage, .. }) = object
            .btf()
            .unwrap()
            .find(crate::BtfKind::Function, "bpf_usdt_cookie")
            .unwrap()
        else {
            unreachable!()
        };
        assert_eq!(*linkage, 0);
        assert_eq!(
            object.program("handle__usdt").unwrap().func_info,
            [0_u32.to_le_bytes(), 59_u32.to_le_bytes()].concat()
        );
        assert_eq!(
            object
                .program("handle__usdt_with_cookie")
                .unwrap()
                .func_info,
            [
                0_u32.to_le_bytes(),
                61_u32.to_le_bytes(),
                27_u32.to_le_bytes(),
                56_u32.to_le_bytes()
            ]
            .concat()
        );
    }

    #[test]
    fn parses_btf_map_definitions_and_function_info() {
        let object = Object::parse(&btf_object_fixture()).unwrap();
        assert_eq!(object.btf().unwrap().len(), 14);
        let map = object.map("counts").unwrap();
        assert_eq!(map.map_type(), MapType::Hash);
        assert_eq!(map.max_entries(), 16);
        assert_eq!(map.btf_key_type(), TypeId(1));
        assert_eq!(map.btf_value_type(), TypeId(7));

        let program = object.program("entry").unwrap();
        assert_eq!(program.func_info_record_size, 8);
        assert_eq!(program.func_info.len(), 8);
        assert_eq!(
            u32::from_le_bytes(program.func_info[4..8].try_into().unwrap()),
            14
        );
    }

    #[test]
    fn evaluates_field_core_relocations_by_member_name() {
        let object = Object::parse(&btf_object_fixture()).unwrap();
        let btf = object.btf().unwrap();
        let relocation = |kind| CoreRelocation {
            program: "entry".into(),
            instruction_index: 0,
            type_id: TypeId(9),
            access: "0:2".into(),
            kind,
        };
        assert_eq!(
            evaluate_core_relocation(btf, btf, &relocation(0))
                .unwrap()
                .value,
            16
        );
        assert_eq!(
            evaluate_core_relocation(btf, btf, &relocation(1))
                .unwrap()
                .value,
            8
        );
        assert_eq!(
            evaluate_core_relocation(btf, btf, &relocation(2))
                .unwrap()
                .value,
            1
        );
    }

    #[test]
    fn patches_core_memory_offsets_and_widths() {
        let mut instructions = [Instruction::new(0x79, 0, 1, 0, 0)];
        patch_core_instruction(
            &mut instructions,
            0,
            CoreValue {
                value: 24,
                local_size: Some(8),
                target_size: Some(4),
                poison: false,
            },
        )
        .unwrap();
        assert_eq!(instructions[0].offset, 24);
        assert_eq!(instructions[0].code, 0x61);
    }

    #[test]
    fn kfunc_lookup_accepts_btf_flavored_extern_names() {
        let strings = b"\0target\0";
        let mut types = Vec::new();
        types.extend(0_u32.to_le_bytes());
        types.extend((13_u32 << 24).to_le_bytes());
        types.extend(0_u32.to_le_bytes());
        types.extend(1_u32.to_le_bytes());
        types.extend(((12_u32 << 24) | 1).to_le_bytes());
        types.extend(1_u32.to_le_bytes());

        let mut bytes = Vec::new();
        bytes.extend(0xeb9f_u16.to_le_bytes());
        bytes.extend([1, 0]);
        bytes.extend(24_u32.to_le_bytes());
        bytes.extend(0_u32.to_le_bytes());
        bytes.extend((types.len() as u32).to_le_bytes());
        bytes.extend((types.len() as u32).to_le_bytes());
        bytes.extend((strings.len() as u32).to_le_bytes());
        bytes.extend(types);
        bytes.extend(strings);

        let btf = Btf::parse(&bytes).unwrap();
        assert_eq!(find_kfunc(&btf, false, "target"), Some(TypeId(2)));
        assert_eq!(
            find_kfunc(&btf, false, "target___versioned"),
            Some(TypeId(2))
        );
    }

    #[test]
    fn kallsyms_parser_ignores_masked_addresses_and_marks_ambiguity() {
        let symbols = parse_kallsyms(
            "0000000000000000 T hidden\n\
             0000000000000010 T unique\n\
             0000000000000020 T duplicate\n\
             0000000000000030 T duplicate [module]\n",
        );
        assert!(!symbols.contains_key("hidden"));
        assert_eq!(symbols.get("unique"), Some(&Some(0x10)));
        assert_eq!(symbols.get("duplicate"), Some(&None));
    }

    #[test]
    fn kernel_config_parser_handles_values_disabled_options_and_c_integers() {
        let config = parse_kernel_config(
            "CONFIG_ENABLED=y\n\
             # CONFIG_DISABLED is not set\n\
             CONFIG_TEXT=\"hello=world\"\n",
        );
        assert_eq!(config.get("CONFIG_ENABLED").map(String::as_str), Some("y"));
        assert_eq!(config.get("CONFIG_DISABLED").map(String::as_str), Some("n"));
        assert_eq!(
            config.get("CONFIG_TEXT").map(String::as_str),
            Some("\"hello=world\"")
        );
        assert_eq!(parse_kconfig_integer("42").unwrap(), 42);
        assert_eq!(parse_kconfig_integer("077").unwrap(), 0o77);
        assert_eq!(parse_kconfig_integer("0x2a").unwrap(), 42);
        assert_eq!(parse_kconfig_integer("-1").unwrap(), u64::MAX);
        assert!(parse_kconfig_integer("12oops").is_err());
    }
}
