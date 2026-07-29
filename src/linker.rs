//! Pure Rust static linking for relocatable eBPF objects.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::path::Path;

use goblin::elf::header::{EI_CLASS, ELFCLASS64, EM_BPF, ET_REL};
use goblin::elf::section_header::{
    SHF_EXECINSTR, SHF_TLS, SHF_WRITE, SHN_ABS, SHN_COMMON, SHN_LORESERVE, SHT_NOBITS,
    SHT_PROGBITS, SHT_REL, SHT_RELA, SHT_STRTAB, SHT_SYMTAB,
};
use goblin::elf::sym::{
    STB_GLOBAL, STB_LOCAL, STB_WEAK, STT_FILE, STT_FUNC, STT_NOTYPE, STT_OBJECT, STT_SECTION,
    STT_TLS,
};
use goblin::elf::{Elf, Sym};
use object::write::{
    Object as WriteObject, Relocation, SectionId, Symbol, SymbolId, SymbolSection,
};
use object::{
    Architecture, BinaryFormat, Endianness, RelocationFlags, SectionFlags, SectionKind,
    SymbolFlags, SymbolKind, SymbolScope,
};

use crate::btf::{BtfMember, BtfParameter, BtfType, Endian};
use crate::{Btf, Error, Object, Result, TypeId};

const R_BPF_64_ABS32: u32 = 3;
const R_BPF_64_NODYLD32: u32 = 4;
const BTF_HEADER_LEN: u32 = 24;
const BTF_EXT_HEADER_LEN: u32 = 32;

/// A pure Rust builder for combining relocatable eBPF ELF objects.
///
/// Sections with the same name are concatenated with their required
/// alignment. ELF symbols and relocations, BTF type IDs and strings,
/// data-section layouts, and BTF.ext instruction offsets are rewritten to
/// describe the combined object.
#[derive(Clone, Debug, Default)]
pub struct ObjectLinker {
    inputs: Vec<LinkInput>,
}

#[derive(Clone, Debug)]
struct LinkInput {
    name: String,
    bytes: Vec<u8>,
}

/// An owned, linked eBPF ELF object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinkedObject {
    bytes: Vec<u8>,
}

impl ObjectLinker {
    /// Creates an empty linker.
    pub const fn new() -> Self {
        Self { inputs: Vec::new() }
    }

    /// Reads and adds a relocatable eBPF object.
    pub fn add_file(&mut self, path: impl AsRef<Path>) -> Result<&mut Self> {
        let path = path.as_ref();
        let bytes = fs::read(path).map_err(|source| Error::File {
            operation: "read linker input",
            path: path.into(),
            source,
        })?;
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("input.bpf.o");
        self.add_bytes(name, &bytes)
    }

    /// Adds an in-memory relocatable eBPF object.
    pub fn add_bytes(&mut self, name: impl Into<String>, bytes: &[u8]) -> Result<&mut Self> {
        let name = name.into();
        validate_input(&name, bytes)?;
        self.inputs.push(LinkInput {
            name,
            bytes: bytes.to_vec(),
        });
        Ok(self)
    }

    /// Number of objects currently in the link.
    pub fn len(&self) -> usize {
        self.inputs.len()
    }

    /// Whether no objects have been added.
    pub fn is_empty(&self) -> bool {
        self.inputs.is_empty()
    }

    /// Links all added objects into one owned ELF image.
    pub fn link(&self) -> Result<LinkedObject> {
        if self.inputs.is_empty() {
            return Err(Error::InvalidObject(
                "cannot link an empty eBPF object set".into(),
            ));
        }
        Ok(LinkedObject {
            bytes: link_inputs(&self.inputs)?,
        })
    }
}

impl LinkedObject {
    /// Borrows the linked ELF bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consumes the wrapper and returns the linked ELF bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Writes the linked ELF object to a path.
    pub fn write(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        fs::write(path, &self.bytes).map_err(|source| Error::File {
            operation: "write linked eBPF object",
            path: path.into(),
            source,
        })
    }

    /// Opens the linked bytes through the pure Rust loader.
    pub fn open(&self) -> Result<Object> {
        Object::parse_named("linked", &self.bytes)
    }
}

struct InputView<'a> {
    name: &'a str,
    bytes: &'a [u8],
    elf: Elf<'a>,
    section_names: Vec<&'a str>,
    btf: Option<Btf>,
    btf_ext: Option<InputBtfExt>,
}

#[derive(Clone, Copy, Debug)]
struct SectionPlacement {
    output: SectionId,
    offset: u64,
    deduplicated: bool,
}

#[derive(Debug)]
struct OutputSection {
    id: SectionId,
    size: u64,
    section_type: u32,
    flags: u64,
    entry_size: u64,
    contents: Vec<u8>,
}

#[derive(Clone, Debug, Default)]
struct InputExtSegment {
    record_size: u32,
    sections: Vec<(String, Vec<Vec<u8>>)>,
}

#[derive(Clone, Debug, Default)]
struct InputBtfExt {
    function_info: InputExtSegment,
    line_info: InputExtSegment,
    core_relocations: InputExtSegment,
}

#[derive(Clone, Copy)]
enum ExtKind {
    Function,
    Line,
    Core,
}

#[derive(Debug)]
struct GlobalSymbol {
    id: SymbolId,
    defined: bool,
    weak: bool,
    symbol_type: u8,
}

fn validate_input(name: &str, bytes: &[u8]) -> Result<()> {
    let elf = Elf::parse(bytes).map_err(|error| Error::Elf(format!("{name}: {error}")))?;
    if elf.header.e_ident[EI_CLASS] != ELFCLASS64 || !elf.is_64 {
        return Err(Error::Elf(format!("{name}: expected a 64-bit ELF object")));
    }
    if elf.header.e_machine != EM_BPF || elf.header.e_type != ET_REL {
        return Err(Error::Elf(format!(
            "{name}: expected an EM_BPF relocatable object"
        )));
    }
    Ok(())
}

fn link_inputs(inputs: &[LinkInput]) -> Result<Vec<u8>> {
    let mut views = inputs
        .iter()
        .map(InputView::parse)
        .collect::<Result<Vec<_>>>()?;
    let little_endian = views[0].elf.little_endian;
    if views
        .iter()
        .any(|input| input.elf.little_endian != little_endian)
    {
        return Err(Error::InvalidObject(
            "linker inputs use different byte orders".into(),
        ));
    }
    let endian = if little_endian {
        Endianness::Little
    } else {
        Endianness::Big
    };
    let btf_endian = if little_endian {
        Endian::Little
    } else {
        Endian::Big
    };
    let mut output = WriteObject::new(BinaryFormat::Elf, Architecture::Bpf, endian);
    let mut output_sections = HashMap::<String, OutputSection>::new();
    let mut placements = views
        .iter()
        .map(|view| vec![None; view.elf.section_headers.len()])
        .collect::<Vec<_>>();

    for (input_index, input) in views.iter().enumerate() {
        for (section_index, (header, placement_slot)) in input
            .elf
            .section_headers
            .iter()
            .zip(placements[input_index].iter_mut())
            .enumerate()
            .skip(1)
        {
            let name = input.section_names[section_index];
            if skip_section(name, header.sh_type) {
                continue;
            }
            if !matches!(header.sh_type, SHT_PROGBITS | SHT_NOBITS) {
                continue;
            }
            let align = header.sh_addralign.max(1);
            if !align.is_power_of_two() {
                return Err(Error::InvalidObject(format!(
                    "{}: section `{name}` has invalid alignment {align}",
                    input.name
                )));
            }
            let initialized = header.sh_type != SHT_NOBITS;
            let data = if initialized {
                section_data(input, section_index)?.to_vec()
            } else {
                Vec::new()
            };

            if let Some(existing) = output_sections.get_mut(name) {
                if existing.section_type != header.sh_type
                    || existing.flags != header.sh_flags
                    || existing.entry_size != header.sh_entsize
                {
                    return Err(Error::InvalidObject(format!(
                        "{}: incompatible definitions of ELF section `{name}`",
                        input.name
                    )));
                }
                if matches!(name, "license" | "version") {
                    if !initialized || existing.contents != data {
                        return Err(Error::InvalidObject(format!(
                            "{}: linked `{name}` sections have different contents",
                            input.name
                        )));
                    }
                    *placement_slot = Some(SectionPlacement {
                        output: existing.id,
                        offset: 0,
                        deduplicated: true,
                    });
                    continue;
                }
                let offset = align_up(existing.size, align, "linked section offset")?;
                if initialized {
                    let written = output.append_section_data(existing.id, &data, align);
                    debug_assert_eq!(written, offset);
                    let offset_usize = usize::try_from(offset).map_err(|_| {
                        Error::InvalidObject("linked section offset does not fit usize".into())
                    })?;
                    existing.contents.resize(offset_usize, 0);
                    existing.contents.extend_from_slice(&data);
                } else {
                    let written = output.append_section_bss(existing.id, header.sh_size, align);
                    debug_assert_eq!(written, offset);
                }
                existing.size = offset
                    .checked_add(header.sh_size)
                    .ok_or_else(|| Error::InvalidObject("linked section size overflows".into()))?;
                *placement_slot = Some(SectionPlacement {
                    output: existing.id,
                    offset,
                    deduplicated: false,
                });
                continue;
            }

            let kind = section_kind(name, header.sh_type, header.sh_flags);
            let id = output.add_section(Vec::new(), name.as_bytes().to_vec(), kind);
            output.section_mut(id).flags = SectionFlags::Elf {
                sh_flags: header.sh_flags,
            };
            if initialized {
                output.append_section_data(id, &data, align);
            } else {
                output.append_section_bss(id, header.sh_size, align);
            }
            output_sections.insert(
                name.into(),
                OutputSection {
                    id,
                    size: header.sh_size,
                    section_type: header.sh_type,
                    flags: header.sh_flags,
                    entry_size: header.sh_entsize,
                    contents: data,
                },
            );
            *placement_slot = Some(SectionPlacement {
                output: id,
                offset: 0,
                deduplicated: false,
            });
        }
    }

    let (btf, btf_ext) = merge_btf(&views, &placements, &output_sections, btf_endian)?;
    if let Some(btf) = btf {
        let id = output.add_section(Vec::new(), b".BTF".to_vec(), SectionKind::ReadOnlyData);
        output.append_section_data(id, &btf, 4);
    }
    if let Some(btf_ext) = btf_ext {
        let id = output.add_section(Vec::new(), b".BTF.ext".to_vec(), SectionKind::ReadOnlyData);
        output.append_section_data(id, &btf_ext, 4);
    }

    let mut symbol_maps = views
        .iter()
        .map(|view| vec![None; view.elf.syms.len()])
        .collect::<Vec<_>>();
    let mut globals = HashMap::<String, GlobalSymbol>::new();
    for (input_index, input) in views.iter().enumerate() {
        for (symbol_index, symbol) in input.elf.syms.iter().enumerate() {
            let name = symbol_name(input, &symbol)?;
            if symbol.st_type() == STT_SECTION {
                if let Some(placement) = placements[input_index]
                    .get(symbol.st_shndx)
                    .copied()
                    .flatten()
                {
                    symbol_maps[input_index][symbol_index] =
                        Some(output.section_symbol(placement.output));
                }
                continue;
            }
            if symbol.st_type() == STT_FILE {
                symbol_maps[input_index][symbol_index] = Some(output.add_symbol(Symbol {
                    name: name.as_bytes().to_vec(),
                    value: 0,
                    size: 0,
                    kind: SymbolKind::File,
                    scope: SymbolScope::Compilation,
                    weak: false,
                    section: SymbolSection::None,
                    flags: SymbolFlags::Elf {
                        st_info: symbol.st_info,
                        st_other: symbol.st_other,
                    },
                }));
                continue;
            }
            let Some(mut converted) =
                convert_symbol(input, input_index, &symbol, name, &placements)?
            else {
                continue;
            };
            let global = symbol.st_bind() != STB_LOCAL && !name.is_empty();
            if !global {
                symbol_maps[input_index][symbol_index] = Some(output.add_symbol(converted));
                continue;
            }
            let defined = symbol.st_shndx != 0;
            let weak = symbol.st_bind() == STB_WEAK;
            let deduplicated = placements[input_index]
                .get(symbol.st_shndx)
                .copied()
                .flatten()
                .is_some_and(|placement| placement.deduplicated);
            if let Some(existing) = globals.get_mut(name) {
                symbol_maps[input_index][symbol_index] = Some(existing.id);
                if deduplicated {
                    continue;
                }
                if existing.defined && defined && !existing.weak && !weak {
                    return Err(Error::InvalidObject(format!(
                        "{}: conflicting strong symbol `{name}`",
                        input.name
                    )));
                }
                if existing.symbol_type != STT_NOTYPE
                    && symbol.st_type() != STT_NOTYPE
                    && existing.symbol_type != symbol.st_type()
                {
                    return Err(Error::InvalidObject(format!(
                        "{}: incompatible symbol kinds for `{name}`",
                        input.name
                    )));
                }
                let replace = defined && (!existing.defined || (existing.weak && !weak));
                let visibility = symbol_visibility(output.symbol(existing.id))
                    .max(symbol_visibility(&converted));
                if replace {
                    converted.weak = existing.weak && weak;
                    if !converted.weak {
                        set_symbol_binding(&mut converted, STB_GLOBAL);
                    }
                    *output.symbol_mut(existing.id) = converted;
                    existing.defined = true;
                    existing.weak &= weak;
                    existing.symbol_type = symbol.st_type();
                } else if symbol.st_bind() == STB_GLOBAL {
                    let target = output.symbol_mut(existing.id);
                    target.weak = false;
                    set_symbol_binding(target, STB_GLOBAL);
                    existing.weak = false;
                }
                set_symbol_visibility(output.symbol_mut(existing.id), visibility);
                continue;
            }
            let id = output.add_symbol(converted);
            globals.insert(
                name.into(),
                GlobalSymbol {
                    id,
                    defined,
                    weak,
                    symbol_type: symbol.st_type(),
                },
            );
            symbol_maps[input_index][symbol_index] = Some(id);
        }
    }

    for (input_index, input) in views.iter().enumerate() {
        for (relocation_section, relocations) in &input.elf.shdr_relocs {
            let source_index = input.elf.section_headers[*relocation_section].sh_info as usize;
            let Some(source) = placements[input_index].get(source_index).copied().flatten() else {
                continue;
            };
            if source.deduplicated {
                continue;
            }
            for relocation in relocations {
                let symbol = symbol_maps[input_index]
                    .get(relocation.r_sym)
                    .copied()
                    .flatten()
                    .ok_or_else(|| {
                        Error::InvalidObject(format!(
                            "{}: relocation references an omitted symbol {}",
                            input.name, relocation.r_sym
                        ))
                    })?;
                output
                    .add_relocation(
                        source.output,
                        Relocation {
                            offset: source.offset.checked_add(relocation.r_offset).ok_or_else(
                                || {
                                    Error::InvalidObject(
                                        "linked relocation offset overflows".into(),
                                    )
                                },
                            )?,
                            symbol,
                            addend: relocation.r_addend.unwrap_or_default(),
                            flags: RelocationFlags::Elf {
                                r_type: relocation.r_type,
                            },
                        },
                    )
                    .map_err(|error| {
                        Error::InvalidObject(format!(
                            "{}: could not emit relocation: {error}",
                            input.name
                        ))
                    })?;
            }
        }
    }

    // Parsed metadata is no longer needed and dropping it before serialization
    // keeps peak memory bounded for large multi-object links.
    views.clear();
    output
        .write()
        .map_err(|error| Error::InvalidObject(format!("could not encode linked ELF: {error}")))
}

impl<'a> InputView<'a> {
    fn parse(input: &'a LinkInput) -> Result<Self> {
        let elf = Elf::parse(&input.bytes)
            .map_err(|error| Error::Elf(format!("{}: {error}", input.name)))?;
        let section_names = elf
            .section_headers
            .iter()
            .map(|header| {
                elf.shdr_strtab
                    .get_at(header.sh_name)
                    .ok_or_else(|| Error::Elf(format!("{}: invalid section name", input.name)))
            })
            .collect::<Result<Vec<_>>>()?;
        let btf_index = section_names.iter().position(|name| *name == ".BTF");
        let btf = btf_index
            .map(|index| relocated_metadata(&elf, &input.bytes, &section_names, index))
            .transpose()?
            .map(|bytes| Btf::parse(&bytes))
            .transpose()?;
        let btf_ext = match (
            btf.as_ref(),
            section_names.iter().position(|name| *name == ".BTF.ext"),
        ) {
            (Some(btf), Some(index)) => {
                let bytes = relocated_metadata(&elf, &input.bytes, &section_names, index)?;
                Some(parse_btf_ext(&bytes, btf)?)
            }
            (None, Some(_)) => {
                return Err(Error::InvalidObject(format!(
                    "{}: .BTF.ext exists without .BTF",
                    input.name
                )));
            }
            _ => None,
        };
        Ok(Self {
            name: &input.name,
            bytes: &input.bytes,
            elf,
            section_names,
            btf,
            btf_ext,
        })
    }
}

fn skip_section(name: &str, section_type: u32) -> bool {
    name.is_empty()
        || matches!(
            name,
            ".BTF" | ".BTF.ext" | ".symtab" | ".strtab" | ".shstrtab"
        )
        || name.starts_with(".debug")
        || name.starts_with(".rel.debug")
        || name.starts_with(".rela.debug")
        || name == ".llvm_addrsig"
        || matches!(section_type, SHT_REL | SHT_RELA | SHT_SYMTAB | SHT_STRTAB)
}

fn section_kind(name: &str, section_type: u32, flags: u64) -> SectionKind {
    if section_type == SHT_NOBITS {
        if flags & u64::from(SHF_TLS) != 0 {
            SectionKind::UninitializedTls
        } else {
            SectionKind::UninitializedData
        }
    } else if flags & u64::from(SHF_EXECINSTR) != 0 {
        SectionKind::Text
    } else if flags & u64::from(SHF_TLS) != 0 {
        SectionKind::Tls
    } else if name.starts_with(".debug") {
        SectionKind::Debug
    } else if flags & u64::from(SHF_WRITE) != 0 {
        SectionKind::Data
    } else {
        SectionKind::ReadOnlyData
    }
}

fn section_data<'a>(input: &'a InputView<'_>, index: usize) -> Result<&'a [u8]> {
    let header = &input.elf.section_headers[index];
    let start = usize::try_from(header.sh_offset)
        .map_err(|_| Error::Elf(format!("{}: section offset is too large", input.name)))?;
    let size = usize::try_from(header.sh_size)
        .map_err(|_| Error::Elf(format!("{}: section size is too large", input.name)))?;
    input
        .bytes
        .get(start..start.saturating_add(size))
        .ok_or_else(|| Error::Elf(format!("{}: section lies outside the file", input.name)))
}

fn symbol_name<'a>(input: &'a InputView<'_>, symbol: &Sym) -> Result<&'a str> {
    input
        .elf
        .strtab
        .get_at(symbol.st_name)
        .ok_or_else(|| Error::Elf(format!("{}: symbol has an invalid name", input.name)))
}

fn convert_symbol(
    input: &InputView<'_>,
    input_index: usize,
    symbol: &Sym,
    name: &str,
    placements: &[Vec<Option<SectionPlacement>>],
) -> Result<Option<Symbol>> {
    let (section, base) = if symbol.st_shndx == 0 {
        (SymbolSection::Undefined, 0)
    } else if symbol.st_shndx >= SHN_LORESERVE as usize {
        match symbol.st_shndx as u32 {
            SHN_ABS => (SymbolSection::Absolute, 0),
            SHN_COMMON => (SymbolSection::Common, 0),
            _ => {
                return Err(Error::Unsupported(format!(
                    "{}: symbol `{name}` uses special section index {}",
                    input.name, symbol.st_shndx
                )));
            }
        }
    } else {
        let Some(placement) = placements[input_index]
            .get(symbol.st_shndx)
            .copied()
            .flatten()
        else {
            return Ok(None);
        };
        (SymbolSection::Section(placement.output), placement.offset)
    };
    let value = if symbol.st_type() == STT_SECTION {
        0
    } else {
        base.checked_add(symbol.st_value)
            .ok_or_else(|| Error::InvalidObject("linked symbol offset overflows".into()))?
    };
    let kind = match symbol.st_type() {
        STT_FUNC => SymbolKind::Text,
        STT_OBJECT => SymbolKind::Data,
        STT_TLS => SymbolKind::Tls,
        STT_NOTYPE => SymbolKind::Label,
        _ => SymbolKind::Unknown,
    };
    let scope = match symbol.st_bind() {
        STB_LOCAL => SymbolScope::Compilation,
        STB_GLOBAL | STB_WEAK => SymbolScope::Linkage,
        binding => {
            return Err(Error::Unsupported(format!(
                "{}: symbol `{name}` uses binding {binding}",
                input.name
            )));
        }
    };
    Ok(Some(Symbol {
        name: name.as_bytes().to_vec(),
        value,
        size: symbol.st_size,
        kind,
        scope,
        weak: symbol.st_bind() == STB_WEAK,
        section,
        flags: SymbolFlags::Elf {
            st_info: symbol.st_info,
            st_other: symbol.st_other,
        },
    }))
}

fn set_symbol_binding(symbol: &mut Symbol, binding: u8) {
    if let SymbolFlags::Elf { st_info, .. } = &mut symbol.flags {
        *st_info = (*st_info & 0x0f) | (binding << 4);
    }
}

fn symbol_visibility(symbol: &Symbol) -> u8 {
    match symbol.flags {
        SymbolFlags::Elf { st_other, .. } => st_other & 0x03,
        _ => 0,
    }
}

fn set_symbol_visibility(symbol: &mut Symbol, visibility: u8) {
    if let SymbolFlags::Elf { st_other, .. } = &mut symbol.flags {
        *st_other = (*st_other & !0x03) | visibility;
    }
}

fn align_up(value: u64, align: u64, what: &str) -> Result<u64> {
    value
        .checked_add(align - 1)
        .map(|value| value & !(align - 1))
        .ok_or_else(|| Error::InvalidObject(format!("{what} overflows")))
}

fn relocated_metadata(
    elf: &Elf<'_>,
    bytes: &[u8],
    names: &[&str],
    target_index: usize,
) -> Result<Vec<u8>> {
    let header = &elf.section_headers[target_index];
    let start = usize::try_from(header.sh_offset)
        .map_err(|_| Error::Elf("metadata section offset is too large".into()))?;
    let size = usize::try_from(header.sh_size)
        .map_err(|_| Error::Elf("metadata section size is too large".into()))?;
    let mut data = bytes
        .get(start..start.saturating_add(size))
        .ok_or_else(|| Error::Elf("metadata section lies outside the file".into()))?
        .to_vec();
    for (relocation_section, relocations) in &elf.shdr_relocs {
        if elf.section_headers[*relocation_section].sh_info as usize != target_index {
            continue;
        }
        for relocation in relocations {
            if !matches!(relocation.r_type, R_BPF_64_ABS32 | R_BPF_64_NODYLD32) {
                return Err(Error::Unsupported(format!(
                    "metadata section `{}` uses relocation type {}",
                    names[target_index], relocation.r_type
                )));
            }
            let symbol = elf.syms.get(relocation.r_sym).ok_or_else(|| {
                Error::Elf(format!(
                    "metadata relocation references missing symbol {}",
                    relocation.r_sym
                ))
            })?;
            let offset = usize::try_from(relocation.r_offset)
                .map_err(|_| Error::Elf("metadata relocation offset is too large".into()))?;
            let original = read_u32(&data, offset, elf.little_endian)?;
            let value = i128::from(original)
                + i128::from(symbol.st_value)
                + i128::from(relocation.r_addend.unwrap_or_default());
            write_u32(
                &mut data,
                offset,
                u32::try_from(value).map_err(|_| {
                    Error::InvalidObject("metadata relocation does not fit u32".into())
                })?,
                if elf.little_endian {
                    Endian::Little
                } else {
                    Endian::Big
                },
            )?;
        }
    }
    Ok(data)
}

fn parse_btf_ext(bytes: &[u8], btf: &Btf) -> Result<InputBtfExt> {
    let endian = btf.endian();
    if bytes.len() < BTF_EXT_HEADER_LEN as usize
        || read_u16(bytes, 0, endian)? != 0xeb9f
        || bytes.get(2) != Some(&1)
    {
        return Err(Error::Btf("invalid .BTF.ext header".into()));
    }
    let header_len = read_u32_endian(bytes, 4, endian)? as usize;
    if !(24..=bytes.len()).contains(&header_len) {
        return Err(Error::Btf("invalid .BTF.ext header length".into()));
    }
    let segment = |offset_field, length_field| -> Result<InputExtSegment> {
        let offset = read_u32_endian(bytes, offset_field, endian)? as usize;
        let length = read_u32_endian(bytes, length_field, endian)? as usize;
        let start = header_len
            .checked_add(offset)
            .ok_or_else(|| Error::Btf(".BTF.ext offset overflows".into()))?;
        let data = bytes
            .get(start..start.saturating_add(length))
            .ok_or_else(|| Error::Btf(".BTF.ext segment is truncated".into()))?;
        parse_ext_segment(data, btf)
    };
    Ok(InputBtfExt {
        function_info: segment(8, 12)?,
        line_info: segment(16, 20)?,
        core_relocations: if header_len >= 32 {
            segment(24, 28)?
        } else {
            InputExtSegment::default()
        },
    })
}

fn parse_ext_segment(bytes: &[u8], btf: &Btf) -> Result<InputExtSegment> {
    if bytes.is_empty() {
        return Ok(InputExtSegment::default());
    }
    let endian = btf.endian();
    let record_size = read_u32_endian(bytes, 0, endian)?;
    if record_size < 4 {
        return Err(Error::Btf(".BTF.ext record is too small".into()));
    }
    let record_size_usize = record_size as usize;
    let mut offset = 4;
    let mut sections = Vec::new();
    while offset < bytes.len() {
        let name_offset = read_u32_endian(bytes, offset, endian)?;
        let count = read_u32_endian(bytes, offset + 4, endian)? as usize;
        offset += 8;
        let size = count
            .checked_mul(record_size_usize)
            .ok_or_else(|| Error::Btf(".BTF.ext record count overflows".into()))?;
        let records = bytes
            .get(offset..offset.saturating_add(size))
            .ok_or_else(|| Error::Btf(".BTF.ext records are truncated".into()))?
            .chunks_exact(record_size_usize)
            .map(<[u8]>::to_vec)
            .collect();
        sections.push((btf.string_at(name_offset)?.into(), records));
        offset += size;
    }
    Ok(InputExtSegment {
        record_size,
        sections,
    })
}

// BTF merging and encoding are kept below the ELF linker so all cross-format
// offset rewriting is performed in one place.

#[derive(Default)]
struct BtfStrings {
    bytes: Vec<u8>,
    offsets: HashMap<String, u32>,
}

impl BtfStrings {
    fn new() -> Self {
        Self {
            bytes: vec![0],
            offsets: HashMap::new(),
        }
    }

    fn add(&mut self, value: &str) -> Result<u32> {
        if value.is_empty() {
            return Ok(0);
        }
        if value.as_bytes().contains(&0) {
            return Err(Error::Btf("BTF string contains NUL".into()));
        }
        if let Some(offset) = self.offsets.get(value) {
            return Ok(*offset);
        }
        let offset = u32::try_from(self.bytes.len())
            .map_err(|_| Error::Btf("BTF string table is too large".into()))?;
        self.bytes.extend_from_slice(value.as_bytes());
        self.bytes.push(0);
        self.offsets.insert(value.into(), offset);
        Ok(offset)
    }
}

#[derive(Default)]
struct MergedDataSection {
    variables: BTreeMap<TypeId, (u32, u32, bool)>,
    fallback_size: u32,
}

#[derive(Clone, Debug)]
struct GlobalBtfRecord {
    output: TypeId,
    input_index: usize,
    input_type: TypeId,
    defined: bool,
}

fn global_btf_symbol(ty: &BtfType) -> Option<(u8, &str, bool)> {
    match ty {
        BtfType::Function { name, linkage, .. } if *linkage != 0 && !name.is_empty() => {
            Some((12, name, *linkage != 2))
        }
        BtfType::Variable { name, linkage, .. } if *linkage != 0 && !name.is_empty() => {
            Some((14, name, *linkage != 2))
        }
        _ => None,
    }
}

fn btf_types_compatible(
    left: &Btf,
    left_id: TypeId,
    right: &Btf,
    right_id: TypeId,
    seen: &mut BTreeSet<(TypeId, TypeId)>,
) -> Result<bool> {
    if left_id == TypeId::VOID || right_id == TypeId::VOID {
        return Ok(left_id == right_id);
    }
    let left_id = left.resolve_type(left_id)?;
    let right_id = right.resolve_type(right_id)?;
    if !seen.insert((left_id, right_id)) {
        return Ok(true);
    }
    let left_type = left
        .type_by_id(left_id)
        .ok_or_else(|| Error::Btf(format!("missing BTF type {}", left_id.0)))?;
    let right_type = right
        .type_by_id(right_id)
        .ok_or_else(|| Error::Btf(format!("missing BTF type {}", right_id.0)))?;
    let compatible = match (left_type, right_type) {
        (
            BtfType::Integer {
                size: left_size,
                encoding: left_encoding,
                ..
            },
            BtfType::Integer {
                size: right_size,
                encoding: right_encoding,
                ..
            },
        ) => left_size == right_size && left_encoding == right_encoding,
        (BtfType::Pointer { ty: left_ty }, BtfType::Pointer { ty: right_ty }) => {
            btf_types_compatible(left, *left_ty, right, *right_ty, seen)?
        }
        (
            BtfType::Array {
                element_type: left_element,
                index_type: left_index,
                count: left_count,
            },
            BtfType::Array {
                element_type: right_element,
                index_type: right_index,
                count: right_count,
            },
        ) => {
            left_count == right_count
                && btf_types_compatible(left, *left_element, right, *right_element, seen)?
                && btf_types_compatible(left, *left_index, right, *right_index, seen)?
        }
        (
            BtfType::Struct {
                name: left_name,
                size: left_size,
                members: left_members,
            },
            BtfType::Struct {
                name: right_name,
                size: right_size,
                members: right_members,
            },
        )
        | (
            BtfType::Union {
                name: left_name,
                size: left_size,
                members: left_members,
            },
            BtfType::Union {
                name: right_name,
                size: right_size,
                members: right_members,
            },
        ) => {
            essential_btf_name(left_name) == essential_btf_name(right_name)
                && left_size == right_size
                && left_members.len() == right_members.len()
                && btf_members_compatible(left, left_members, right, right_members, seen)?
        }
        (
            BtfType::Enum {
                name: left_name,
                size: left_size,
                signed: left_signed,
                values: left_values,
            },
            BtfType::Enum {
                name: right_name,
                size: right_size,
                signed: right_signed,
                values: right_values,
            },
        )
        | (
            BtfType::Enum64 {
                name: left_name,
                size: left_size,
                signed: left_signed,
                values: left_values,
            },
            BtfType::Enum64 {
                name: right_name,
                size: right_size,
                signed: right_signed,
                values: right_values,
            },
        ) => {
            essential_btf_name(left_name) == essential_btf_name(right_name)
                && left_size == right_size
                && left_signed == right_signed
                && left_values == right_values
        }
        (
            BtfType::Forward {
                name: left_name,
                union: left_union,
            },
            BtfType::Forward {
                name: right_name,
                union: right_union,
            },
        ) => {
            essential_btf_name(left_name) == essential_btf_name(right_name)
                && left_union == right_union
        }
        (
            BtfType::Function {
                prototype: left_prototype,
                ..
            },
            BtfType::Function {
                prototype: right_prototype,
                ..
            },
        ) => btf_types_compatible(left, *left_prototype, right, *right_prototype, seen)?,
        (
            BtfType::FunctionPrototype {
                return_type: left_return,
                parameters: left_parameters,
            },
            BtfType::FunctionPrototype {
                return_type: right_return,
                parameters: right_parameters,
            },
        ) => {
            left_parameters.len() == right_parameters.len()
                && btf_types_compatible(left, *left_return, right, *right_return, seen)?
                && btf_parameters_compatible(left, left_parameters, right, right_parameters, seen)?
        }
        (BtfType::Variable { ty: left_ty, .. }, BtfType::Variable { ty: right_ty, .. }) => {
            btf_types_compatible(left, *left_ty, right, *right_ty, seen)?
        }
        (
            BtfType::Float {
                name: left_name,
                size: left_size,
            },
            BtfType::Float {
                name: right_name,
                size: right_size,
            },
        ) => left_name == right_name && left_size == right_size,
        (
            BtfType::DeclarationTag {
                name: left_name,
                ty: left_ty,
                component_index: left_index,
            },
            BtfType::DeclarationTag {
                name: right_name,
                ty: right_ty,
                component_index: right_index,
            },
        ) => {
            left_name == right_name
                && left_index == right_index
                && btf_types_compatible(left, *left_ty, right, *right_ty, seen)?
        }
        _ => false,
    };
    seen.remove(&(left_id, right_id));
    Ok(compatible)
}

fn btf_members_compatible(
    left: &Btf,
    left_members: &[BtfMember],
    right: &Btf,
    right_members: &[BtfMember],
    seen: &mut BTreeSet<(TypeId, TypeId)>,
) -> Result<bool> {
    for (left_member, right_member) in left_members.iter().zip(right_members) {
        if left_member.name != right_member.name
            || left_member.bit_offset != right_member.bit_offset
            || left_member.bitfield_size != right_member.bitfield_size
            || !btf_types_compatible(left, left_member.ty, right, right_member.ty, seen)?
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn btf_parameters_compatible(
    left: &Btf,
    left_parameters: &[BtfParameter],
    right: &Btf,
    right_parameters: &[BtfParameter],
    seen: &mut BTreeSet<(TypeId, TypeId)>,
) -> Result<bool> {
    for (left_parameter, right_parameter) in left_parameters.iter().zip(right_parameters) {
        if !btf_types_compatible(left, left_parameter.ty, right, right_parameter.ty, seen)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn essential_btf_name(name: &str) -> &str {
    name.split_once("___").map_or(name, |(name, _)| name)
}

fn merge_btf(
    inputs: &[InputView<'_>],
    placements: &[Vec<Option<SectionPlacement>>],
    output_sections: &HashMap<String, OutputSection>,
    endian: Endian,
) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>)> {
    let btf_inputs = inputs
        .iter()
        .enumerate()
        .filter_map(|(index, input)| input.btf.as_ref().map(|btf| (index, btf)))
        .collect::<Vec<_>>();
    if btf_inputs.is_empty() {
        if inputs.iter().any(|input| input.btf_ext.is_some()) {
            return Err(Error::InvalidObject(".BTF.ext requires linked BTF".into()));
        }
        return Ok((None, None));
    }
    if btf_inputs.iter().any(|(_, btf)| btf.endian() != endian) {
        return Err(Error::InvalidObject(
            "linked BTF tables use different byte orders".into(),
        ));
    }

    let mut type_maps = inputs
        .iter()
        .map(|input| {
            input.btf.as_ref().map_or_else(
                || vec![TypeId::VOID],
                |btf| vec![TypeId::VOID; btf.len() + 1],
            )
        })
        .collect::<Vec<_>>();
    let mut data_names = BTreeSet::new();
    let mut next_id = 1_u32;
    let mut record_sources = BTreeMap::<u32, (usize, TypeId)>::new();
    let mut global_records = HashMap::<(u8, String), GlobalBtfRecord>::new();
    for (input_index, btf) in &btf_inputs {
        for (id, ty) in btf.types() {
            if let BtfType::DataSection { name, .. } = ty {
                data_names.insert(name.clone());
                continue;
            }
            if let Some((kind, name, defined)) = global_btf_symbol(ty) {
                let key = (kind, name.into());
                if let Some(existing) = global_records.get_mut(&key) {
                    let existing_btf = inputs[existing.input_index]
                        .btf
                        .as_ref()
                        .expect("global BTF records come from BTF inputs");
                    if !btf_types_compatible(
                        existing_btf,
                        existing.input_type,
                        btf,
                        id,
                        &mut BTreeSet::new(),
                    )? {
                        return Err(Error::Btf(format!(
                            "linked global BTF symbol `{name}` has incompatible types"
                        )));
                    }
                    type_maps[*input_index][id.0 as usize] = existing.output;
                    if defined && !existing.defined {
                        existing.input_index = *input_index;
                        existing.input_type = id;
                        existing.defined = true;
                        record_sources.insert(existing.output.0, (*input_index, id));
                    }
                    continue;
                }
                let output = TypeId(next_id);
                type_maps[*input_index][id.0 as usize] = output;
                record_sources.insert(output.0, (*input_index, id));
                global_records.insert(
                    key,
                    GlobalBtfRecord {
                        output,
                        input_index: *input_index,
                        input_type: id,
                        defined,
                    },
                );
            } else {
                let output = TypeId(next_id);
                type_maps[*input_index][id.0 as usize] = output;
                record_sources.insert(output.0, (*input_index, id));
            }
            next_id = next_id
                .checked_add(1)
                .ok_or_else(|| Error::Btf("too many linked BTF types".into()))?;
        }
    }
    let mut data_ids = BTreeMap::new();
    for name in &data_names {
        data_ids.insert(name.clone(), TypeId(next_id));
        next_id = next_id
            .checked_add(1)
            .ok_or_else(|| Error::Btf("too many linked BTF types".into()))?;
    }
    for (input_index, btf) in &btf_inputs {
        for (id, ty) in btf.types() {
            if let BtfType::DataSection { name, .. } = ty {
                type_maps[*input_index][id.0 as usize] = data_ids[name];
            }
        }
    }

    let mut strings = BtfStrings::new();
    let mut type_bytes = Vec::new();
    for (_output_id, (input_index, input_id)) in record_sources {
        let btf = inputs[input_index]
            .btf
            .as_ref()
            .expect("BTF record sources have parsed BTF");
        let ty = btf
            .type_by_id(input_id)
            .ok_or_else(|| Error::Btf(format!("missing linked BTF type {}", input_id.0)))?;
        encode_btf_type(
            ty,
            &type_maps[input_index],
            &mut strings,
            endian,
            &mut type_bytes,
        )?;
    }

    let mut data_sections = BTreeMap::<String, MergedDataSection>::new();
    for (input_index, btf) in &btf_inputs {
        for (_, ty) in btf.types() {
            let BtfType::DataSection {
                name,
                size,
                variables,
            } = ty
            else {
                continue;
            };
            let merged = data_sections.entry(name.clone()).or_default();
            let placement = inputs[*input_index]
                .section_names
                .iter()
                .position(|candidate| *candidate == name)
                .and_then(|index| placements[*input_index][index]);
            if placement.is_some_and(|placement| placement.deduplicated) {
                continue;
            }
            let base = placement
                .map(|placement| placement.offset)
                .unwrap_or(u64::from(merged.fallback_size));
            for variable in variables {
                let offset = base
                    .checked_add(u64::from(variable.offset))
                    .ok_or_else(|| {
                        Error::Btf(format!("linked BTF data section `{name}` offset overflows"))
                    })?;
                let ty = remap_type(variable.ty, &type_maps[*input_index])?;
                let offset = u32::try_from(offset).map_err(|_| {
                    Error::Btf(format!(
                        "linked BTF data section `{name}` offset is too large"
                    ))
                })?;
                let physical = placement.is_some();
                match merged.variables.entry(ty) {
                    Entry::Vacant(entry) => {
                        entry.insert((offset, variable.size, physical));
                    }
                    Entry::Occupied(mut entry) if physical && !entry.get().2 => {
                        entry.insert((offset, variable.size, true));
                    }
                    Entry::Occupied(entry) if entry.get().1 != variable.size => {
                        return Err(Error::Btf(format!(
                            "linked BTF variable type {} has inconsistent sizes",
                            ty.0
                        )));
                    }
                    _ => {}
                }
            }
            if placement.is_none() {
                merged.fallback_size = merged
                    .fallback_size
                    .checked_add(*size)
                    .ok_or_else(|| Error::Btf("linked BTF data section is too large".into()))?;
            }
        }
    }
    for (name, merged) in &data_sections {
        let size = output_sections
            .get(name)
            .map(|section| {
                u32::try_from(section.size)
                    .map_err(|_| Error::Btf(format!("linked section `{name}` is too large")))
            })
            .transpose()?
            .unwrap_or(merged.fallback_size);
        encode_data_section(
            name,
            size,
            merged
                .variables
                .iter()
                .map(|(ty, (offset, size, _))| (*ty, *offset, *size)),
            &mut strings,
            endian,
            &mut type_bytes,
        )?;
    }

    let ext = merge_btf_ext(inputs, placements, &type_maps, &mut strings, endian)?;
    let btf = encode_btf(type_bytes, strings.bytes, endian)?;
    Ok((Some(btf), ext))
}

fn remap_type(id: TypeId, mapping: &[TypeId]) -> Result<TypeId> {
    if id == TypeId::VOID {
        return Ok(id);
    }
    mapping
        .get(id.0 as usize)
        .copied()
        .filter(|mapped| *mapped != TypeId::VOID)
        .ok_or_else(|| Error::Btf(format!("missing linked mapping for BTF type {}", id.0)))
}

fn encode_btf_type(
    ty: &BtfType,
    mapping: &[TypeId],
    strings: &mut BtfStrings,
    endian: Endian,
    output: &mut Vec<u8>,
) -> Result<()> {
    let mut common = |name: &str, kind: u32, vlen: usize, kind_flag: bool, size_or_type: u32| {
        let name = strings.add(name)?;
        push_u32(output, name, endian);
        let vlen =
            u32::try_from(vlen).map_err(|_| Error::Btf("BTF type has too many entries".into()))?;
        if vlen > 0xffff {
            return Err(Error::Btf("BTF type has more than 65535 entries".into()));
        }
        push_u32(
            output,
            (u32::from(kind_flag) << 31) | (kind << 24) | vlen,
            endian,
        );
        push_u32(output, size_or_type, endian);
        Ok::<_, Error>(())
    };
    match ty {
        BtfType::Integer {
            name,
            size,
            encoding,
        } => {
            common(name, 1, 0, false, *size)?;
            let flags = u32::from(encoding.signed)
                | (u32::from(encoding.character) << 1)
                | (u32::from(encoding.boolean) << 2);
            push_u32(
                output,
                (flags << 24) | (u32::from(encoding.offset) << 16) | u32::from(encoding.bits),
                endian,
            );
        }
        BtfType::Pointer { ty } => common("", 2, 0, false, remap_type(*ty, mapping)?.0)?,
        BtfType::Array {
            element_type,
            index_type,
            count,
        } => {
            common("", 3, 0, false, 0)?;
            push_u32(output, remap_type(*element_type, mapping)?.0, endian);
            push_u32(output, remap_type(*index_type, mapping)?.0, endian);
            push_u32(output, *count, endian);
        }
        BtfType::Struct {
            name,
            size,
            members,
        }
        | BtfType::Union {
            name,
            size,
            members,
        } => {
            let kind = if matches!(ty, BtfType::Struct { .. }) {
                4
            } else {
                5
            };
            let kind_flag = members.iter().any(|member| member.bitfield_size.is_some());
            common(name, kind, members.len(), kind_flag, *size)?;
            for member in members {
                push_u32(output, strings.add(&member.name)?, endian);
                push_u32(output, remap_type(member.ty, mapping)?.0, endian);
                let offset = if kind_flag {
                    member.bit_offset | (u32::from(member.bitfield_size.unwrap_or_default()) << 24)
                } else {
                    member.bit_offset
                };
                push_u32(output, offset, endian);
            }
        }
        BtfType::Enum {
            name,
            size,
            signed,
            values,
        } => {
            common(name, 6, values.len(), *signed, *size)?;
            for value in values {
                push_u32(output, strings.add(&value.name)?, endian);
                push_u32(output, value.value as i32 as u32, endian);
            }
        }
        BtfType::Forward { name, union } => common(name, 7, 0, *union, 0)?,
        BtfType::Typedef { name, ty } => common(name, 8, 0, false, remap_type(*ty, mapping)?.0)?,
        BtfType::Volatile { ty } => common("", 9, 0, false, remap_type(*ty, mapping)?.0)?,
        BtfType::Const { ty } => common("", 10, 0, false, remap_type(*ty, mapping)?.0)?,
        BtfType::Restrict { ty } => common("", 11, 0, false, remap_type(*ty, mapping)?.0)?,
        BtfType::Function {
            name,
            prototype,
            linkage,
        } => common(
            name,
            12,
            usize::from(*linkage),
            false,
            remap_type(*prototype, mapping)?.0,
        )?,
        BtfType::FunctionPrototype {
            return_type,
            parameters,
        } => {
            common(
                "",
                13,
                parameters.len(),
                false,
                remap_type(*return_type, mapping)?.0,
            )?;
            for parameter in parameters {
                push_u32(output, strings.add(&parameter.name)?, endian);
                push_u32(output, remap_type(parameter.ty, mapping)?.0, endian);
            }
        }
        BtfType::Variable { name, ty, linkage } => {
            common(name, 14, 0, false, remap_type(*ty, mapping)?.0)?;
            push_u32(output, *linkage, endian);
        }
        BtfType::DataSection { .. } => unreachable!(),
        BtfType::Float { name, size } => common(name, 16, 0, false, *size)?,
        BtfType::DeclarationTag {
            name,
            ty,
            component_index,
        } => {
            common(name, 17, 0, false, remap_type(*ty, mapping)?.0)?;
            push_u32(output, *component_index as u32, endian);
        }
        BtfType::TypeTag { name, ty } => common(name, 18, 0, false, remap_type(*ty, mapping)?.0)?,
        BtfType::Enum64 {
            name,
            size,
            signed,
            values,
        } => {
            common(name, 19, values.len(), *signed, *size)?;
            for value in values {
                push_u32(output, strings.add(&value.name)?, endian);
                push_u32(output, value.value as u64 as u32, endian);
                push_u32(output, ((value.value as u64) >> 32) as u32, endian);
            }
        }
    }
    Ok(())
}

fn encode_data_section(
    name: &str,
    size: u32,
    variables: impl IntoIterator<Item = (TypeId, u32, u32)>,
    strings: &mut BtfStrings,
    endian: Endian,
    output: &mut Vec<u8>,
) -> Result<()> {
    let mut variables = variables.into_iter().collect::<Vec<_>>();
    variables.sort_by_key(|(_, offset, _)| *offset);
    let count = u32::try_from(variables.len())
        .map_err(|_| Error::Btf("BTF data section has too many variables".into()))?;
    if count > 0xffff {
        return Err(Error::Btf(
            "BTF data section has more than 65535 variables".into(),
        ));
    }
    let name = strings.add(name)?;
    push_u32(output, name, endian);
    push_u32(output, (15 << 24) | count, endian);
    push_u32(output, size, endian);
    for (ty, offset, variable_size) in variables {
        push_u32(output, ty.0, endian);
        push_u32(output, offset, endian);
        push_u32(output, variable_size, endian);
    }
    Ok(())
}

fn encode_btf(types: Vec<u8>, strings: Vec<u8>, endian: Endian) -> Result<Vec<u8>> {
    let type_len =
        u32::try_from(types.len()).map_err(|_| Error::Btf("BTF type data is too large".into()))?;
    let string_len = u32::try_from(strings.len())
        .map_err(|_| Error::Btf("BTF string data is too large".into()))?;
    let mut output = Vec::with_capacity(BTF_HEADER_LEN as usize + types.len() + strings.len());
    push_u16(&mut output, 0xeb9f, endian);
    output.extend([1, 0]);
    push_u32(&mut output, BTF_HEADER_LEN, endian);
    push_u32(&mut output, 0, endian);
    push_u32(&mut output, type_len, endian);
    push_u32(&mut output, type_len, endian);
    push_u32(&mut output, string_len, endian);
    output.extend(types);
    output.extend(strings);
    Ok(output)
}

fn merge_btf_ext(
    inputs: &[InputView<'_>],
    placements: &[Vec<Option<SectionPlacement>>],
    type_maps: &[Vec<TypeId>],
    strings: &mut BtfStrings,
    endian: Endian,
) -> Result<Option<Vec<u8>>> {
    let function = merge_ext_segment(
        ExtKind::Function,
        inputs,
        placements,
        type_maps,
        strings,
        endian,
    )?;
    let line = merge_ext_segment(
        ExtKind::Line,
        inputs,
        placements,
        type_maps,
        strings,
        endian,
    )?;
    let core = merge_ext_segment(
        ExtKind::Core,
        inputs,
        placements,
        type_maps,
        strings,
        endian,
    )?;
    if function.is_empty() && line.is_empty() && core.is_empty() {
        return Ok(None);
    }
    let function_len = u32::try_from(function.len())
        .map_err(|_| Error::Btf("linked BTF.ext function info is too large".into()))?;
    let line_len = u32::try_from(line.len())
        .map_err(|_| Error::Btf("linked BTF.ext line info is too large".into()))?;
    let core_len = u32::try_from(core.len())
        .map_err(|_| Error::Btf("linked BTF.ext CO-RE info is too large".into()))?;
    let mut output = Vec::new();
    push_u16(&mut output, 0xeb9f, endian);
    output.extend([1, 0]);
    push_u32(&mut output, BTF_EXT_HEADER_LEN, endian);
    push_u32(&mut output, 0, endian);
    push_u32(&mut output, function_len, endian);
    push_u32(&mut output, function_len, endian);
    push_u32(&mut output, line_len, endian);
    push_u32(
        &mut output,
        function_len
            .checked_add(line_len)
            .ok_or_else(|| Error::Btf("linked BTF.ext offsets overflow".into()))?,
        endian,
    );
    push_u32(&mut output, core_len, endian);
    output.extend(function);
    output.extend(line);
    output.extend(core);
    Ok(Some(output))
}

fn merge_ext_segment(
    kind: ExtKind,
    inputs: &[InputView<'_>],
    placements: &[Vec<Option<SectionPlacement>>],
    type_maps: &[Vec<TypeId>],
    strings: &mut BtfStrings,
    endian: Endian,
) -> Result<Vec<u8>> {
    let mut record_size = None;
    let mut sections = BTreeMap::<String, Vec<Vec<u8>>>::new();
    for (input_index, input) in inputs.iter().enumerate() {
        let Some(ext) = input.btf_ext.as_ref() else {
            continue;
        };
        let segment = match kind {
            ExtKind::Function => &ext.function_info,
            ExtKind::Line => &ext.line_info,
            ExtKind::Core => &ext.core_relocations,
        };
        if segment.record_size == 0 {
            continue;
        }
        if record_size
            .replace(segment.record_size)
            .is_some_and(|existing| existing != segment.record_size)
        {
            return Err(Error::Btf(
                "linked BTF.ext segments use different record sizes".into(),
            ));
        }
        let btf = input
            .btf
            .as_ref()
            .ok_or_else(|| Error::Btf(".BTF.ext input has no BTF".into()))?;
        for (section_name, records) in &segment.sections {
            let section_index = input
                .section_names
                .iter()
                .position(|name| *name == section_name)
                .ok_or_else(|| {
                    Error::Btf(format!(
                        "{}: BTF.ext references missing section `{section_name}`",
                        input.name
                    ))
                })?;
            let placement = placements[input_index][section_index].ok_or_else(|| {
                Error::Btf(format!(
                    "{}: BTF.ext references omitted section `{section_name}`",
                    input.name
                ))
            })?;
            let output_records = sections.entry(section_name.clone()).or_default();
            for record in records {
                let mut record = record.clone();
                let instruction_offset = u64::from(read_u32_endian(&record, 0, endian)?)
                    .checked_add(placement.offset)
                    .ok_or_else(|| Error::Btf("BTF.ext instruction offset overflows".into()))?;
                write_u32(
                    &mut record,
                    0,
                    u32::try_from(instruction_offset).map_err(|_| {
                        Error::Btf("BTF.ext instruction offset is too large".into())
                    })?,
                    endian,
                )?;
                match kind {
                    ExtKind::Function => {
                        remap_record_type(&mut record, 4, &type_maps[input_index], endian)?;
                    }
                    ExtKind::Line => {
                        remap_record_string(&mut record, 4, btf, strings, endian)?;
                        remap_record_string(&mut record, 8, btf, strings, endian)?;
                    }
                    ExtKind::Core => {
                        remap_record_type(&mut record, 4, &type_maps[input_index], endian)?;
                        remap_record_string(&mut record, 8, btf, strings, endian)?;
                    }
                }
                output_records.push(record);
            }
        }
    }
    let Some(record_size) = record_size else {
        return Ok(Vec::new());
    };
    let mut output = Vec::new();
    push_u32(&mut output, record_size, endian);
    for (section_name, records) in sections {
        push_u32(&mut output, strings.add(&section_name)?, endian);
        push_u32(
            &mut output,
            u32::try_from(records.len())
                .map_err(|_| Error::Btf("too many linked BTF.ext records".into()))?,
            endian,
        );
        for record in records {
            output.extend(record);
        }
    }
    Ok(output)
}

fn remap_record_type(
    record: &mut [u8],
    offset: usize,
    mapping: &[TypeId],
    endian: Endian,
) -> Result<()> {
    let old = TypeId(read_u32_endian(record, offset, endian)?);
    write_u32(record, offset, remap_type(old, mapping)?.0, endian)
}

fn remap_record_string(
    record: &mut [u8],
    offset: usize,
    btf: &Btf,
    strings: &mut BtfStrings,
    endian: Endian,
) -> Result<()> {
    let old = read_u32_endian(record, offset, endian)?;
    write_u32(record, offset, strings.add(btf.string_at(old)?)?, endian)
}

fn read_u16(bytes: &[u8], offset: usize, endian: Endian) -> Result<u16> {
    let value: [u8; 2] = bytes
        .get(offset..offset.saturating_add(2))
        .ok_or_else(|| Error::Btf("encoded integer is truncated".into()))?
        .try_into()
        .expect("two-byte slice");
    Ok(match endian {
        Endian::Little => u16::from_le_bytes(value),
        Endian::Big => u16::from_be_bytes(value),
    })
}

fn read_u32(bytes: &[u8], offset: usize, little_endian: bool) -> Result<u32> {
    read_u32_endian(
        bytes,
        offset,
        if little_endian {
            Endian::Little
        } else {
            Endian::Big
        },
    )
}

fn read_u32_endian(bytes: &[u8], offset: usize, endian: Endian) -> Result<u32> {
    let value: [u8; 4] = bytes
        .get(offset..offset.saturating_add(4))
        .ok_or_else(|| Error::Btf("encoded integer is truncated".into()))?
        .try_into()
        .expect("four-byte slice");
    Ok(match endian {
        Endian::Little => u32::from_le_bytes(value),
        Endian::Big => u32::from_be_bytes(value),
    })
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32, endian: Endian) -> Result<()> {
    let target = bytes
        .get_mut(offset..offset.saturating_add(4))
        .ok_or_else(|| Error::Btf("encoded integer is truncated".into()))?;
    let encoded = match endian {
        Endian::Little => value.to_le_bytes(),
        Endian::Big => value.to_be_bytes(),
    };
    target.copy_from_slice(&encoded);
    Ok(())
}

fn push_u16(output: &mut Vec<u8>, value: u16, endian: Endian) {
    output.extend(match endian {
        Endian::Little => value.to_le_bytes(),
        Endian::Big => value.to_be_bytes(),
    });
}

fn push_u32(output: &mut Vec<u8>, value: u32, endian: Endian) {
    output.extend(match endian {
        Endian::Little => value.to_le_bytes(),
        Endian::Big => value.to_be_bytes(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Instruction;
    use object::write::{Relocation, Symbol};
    use object::{RelocationFlags, SymbolFlags};

    fn instruction_bytes(instructions: &[Instruction]) -> Vec<u8> {
        instructions
            .iter()
            .flat_map(|instruction| instruction.to_bytes())
            .collect()
    }

    fn fixture(section_name: &str, program_name: &str, map_name: &str, value: i32) -> Vec<u8> {
        let mut object = WriteObject::new(BinaryFormat::Elf, Architecture::Bpf, Endianness::Little);
        let section = object.add_section(
            Vec::new(),
            section_name.as_bytes().to_vec(),
            SectionKind::Text,
        );
        object.append_section_data(
            section,
            &instruction_bytes(&[
                Instruction::new(0x18, 1, 0, 0, 0),
                Instruction::default(),
                Instruction::new(0xb7, 0, 0, 0, value),
                Instruction::new(0x95, 0, 0, 0, 0),
            ]),
            8,
        );
        object.add_symbol(Symbol {
            name: program_name.as_bytes().to_vec(),
            value: 0,
            size: 32,
            kind: SymbolKind::Text,
            scope: SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Section(section),
            flags: SymbolFlags::None,
        });

        let maps = object.add_section(Vec::new(), b".maps".to_vec(), SectionKind::Data);
        let mut definition = Vec::new();
        definition.extend(2_u32.to_le_bytes());
        definition.extend(4_u32.to_le_bytes());
        definition.extend(8_u32.to_le_bytes());
        definition.extend(1_u32.to_le_bytes());
        definition.extend(0_u32.to_le_bytes());
        object.append_section_data(maps, &definition, 8);
        let map = object.add_symbol(Symbol {
            name: map_name.as_bytes().to_vec(),
            value: 0,
            size: definition.len() as u64,
            kind: SymbolKind::Data,
            scope: SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Section(maps),
            flags: SymbolFlags::None,
        });
        object
            .add_relocation(
                section,
                Relocation {
                    offset: 0,
                    symbol: map,
                    addend: 0,
                    flags: RelocationFlags::Elf { r_type: 1 },
                },
            )
            .unwrap();
        let license = object.add_section(Vec::new(), b"license".to_vec(), SectionKind::Data);
        object.append_section_data(license, b"GPL\0", 1);
        object.add_symbol(Symbol {
            name: b"LICENSE".to_vec(),
            value: 0,
            size: 4,
            kind: SymbolKind::Data,
            scope: SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Section(license),
            flags: SymbolFlags::None,
        });
        object.write().unwrap()
    }

    #[test]
    fn links_sections_symbols_and_relocations() {
        let first = fixture("socket/first", "first", "first_map", 11);
        let second = fixture("socket/second", "second", "second_map", 22);
        let mut linker = ObjectLinker::new();
        linker
            .add_bytes("first.bpf.o", &first)
            .unwrap()
            .add_bytes("second.bpf.o", &second)
            .unwrap();
        let linked = linker.link().unwrap();
        let object = linked.open().unwrap();
        assert!(object.program("first").is_ok());
        assert!(object.program("second").is_ok());
        assert!(object.map("first_map").is_ok());
        assert!(object.map("second_map").is_ok());
        assert_eq!(object.license(), "GPL");

        let elf = Elf::parse(linked.as_bytes()).unwrap();
        let license = elf
            .section_headers
            .iter()
            .find(|header| elf.shdr_strtab.get_at(header.sh_name) == Some("license"))
            .unwrap();
        assert_eq!(license.sh_size, 4);
    }

    #[test]
    fn links_repository_objects_with_btf_and_ext_info() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../libbpf-rs/tests/bin");
        let usdt = root.join("usdt.bpf.o");
        let ringbuf = root.join("ringbuf.bpf.o");
        if !usdt.exists() || !ringbuf.exists() {
            return;
        }
        let mut linker = ObjectLinker::new();
        linker.add_file(usdt).unwrap().add_file(ringbuf).unwrap();
        let linked = linker.link().unwrap();
        let object = linked.open().unwrap();
        assert!(object.btf().is_some());
        assert!(object.program("handle__usdt").is_ok());
        assert!(object.program("handle__sys_enter_getpid").is_ok());
        assert!(object.map("ringbuf").is_ok());
        assert!(object.map("ringbuf1").is_ok());
    }

    #[test]
    fn rejects_empty_and_non_elf_links() {
        assert!(ObjectLinker::new().link().is_err());
        assert!(ObjectLinker::new()
            .add_bytes("bad", b"not an object")
            .is_err());
    }
}
