use std::collections::HashSet;
use std::str;

use crate::{Error, Result};

const BTF_MAGIC: u16 = 0xeb9f;
const BTF_VERSION: u8 = 1;
const BTF_HEADER_LEN: usize = 24;

/// An ID in a BTF type table. ID zero denotes `void`.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TypeId(pub u32);

impl TypeId {
    /// The special `void` type ID.
    pub const VOID: Self = Self(0);
}

/// The kind of a BTF type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum BtfKind {
    /// Integer.
    Integer,
    /// Pointer.
    Pointer,
    /// Array.
    Array,
    /// Structure.
    Struct,
    /// Union.
    Union,
    /// Enumeration.
    Enum,
    /// Forward declaration.
    Forward,
    /// Type alias.
    Typedef,
    /// `volatile` modifier.
    Volatile,
    /// `const` modifier.
    Const,
    /// `restrict` modifier.
    Restrict,
    /// Function.
    Function,
    /// Function prototype.
    FunctionPrototype,
    /// Variable.
    Variable,
    /// ELF data section.
    DataSection,
    /// Floating-point value.
    Float,
    /// Declaration tag.
    DeclarationTag,
    /// Type tag.
    TypeTag,
    /// 64-bit enumeration.
    Enum64,
}

/// Integer encoding attributes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IntegerEncoding {
    /// Whether the integer is signed.
    pub signed: bool,
    /// Whether the integer represents a character.
    pub character: bool,
    /// Whether the integer is a boolean.
    pub boolean: bool,
    /// Bit offset within the storage unit.
    pub offset: u8,
    /// Number of meaningful bits.
    pub bits: u8,
}

/// A member of a BTF struct or union.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BtfMember {
    /// Member name.
    pub name: String,
    /// Member type.
    pub ty: TypeId,
    /// Offset from the containing type in bits.
    pub bit_offset: u32,
    /// Bit-field width, when this is a bit-field.
    pub bitfield_size: Option<u8>,
}

/// A BTF enumeration value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BtfEnumValue {
    /// Enumerator name.
    pub name: String,
    /// Enumerator value.
    pub value: i64,
}

/// A parameter in a BTF function prototype.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BtfParameter {
    /// Parameter name. An empty name is valid.
    pub name: String,
    /// Parameter type.
    pub ty: TypeId,
}

/// A variable entry in a BTF data section.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BtfVariable {
    /// ID of a [`BtfType::Variable`].
    pub ty: TypeId,
    /// Byte offset within the ELF section.
    pub offset: u32,
    /// Byte size within the ELF section.
    pub size: u32,
}

/// A parsed BTF type.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum BtfType {
    /// An integer storage unit.
    Integer {
        /// Type name.
        name: String,
        /// Storage size in bytes.
        size: u32,
        /// Encoding attributes.
        encoding: IntegerEncoding,
    },
    /// A pointer to another type.
    Pointer {
        /// Pointed-to type.
        ty: TypeId,
    },
    /// A fixed-size array.
    Array {
        /// Element type.
        element_type: TypeId,
        /// Index type.
        index_type: TypeId,
        /// Number of elements.
        count: u32,
    },
    /// A structure.
    Struct {
        /// Type name.
        name: String,
        /// Size in bytes.
        size: u32,
        /// Members in declaration order.
        members: Vec<BtfMember>,
    },
    /// A union.
    Union {
        /// Type name.
        name: String,
        /// Size in bytes.
        size: u32,
        /// Members in declaration order.
        members: Vec<BtfMember>,
    },
    /// An enumeration with 32-bit values.
    Enum {
        /// Type name.
        name: String,
        /// Storage size in bytes.
        size: u32,
        /// Whether values are signed.
        signed: bool,
        /// Values.
        values: Vec<BtfEnumValue>,
    },
    /// A forward declaration.
    Forward {
        /// Type name.
        name: String,
        /// Whether this declares a union rather than a struct.
        union: bool,
    },
    /// A named alias.
    Typedef {
        /// Alias name.
        name: String,
        /// Aliased type.
        ty: TypeId,
    },
    /// A `volatile` qualified type.
    Volatile {
        /// Qualified type.
        ty: TypeId,
    },
    /// A `const` qualified type.
    Const {
        /// Qualified type.
        ty: TypeId,
    },
    /// A `restrict` qualified type.
    Restrict {
        /// Qualified type.
        ty: TypeId,
    },
    /// A function declaration.
    Function {
        /// Function name.
        name: String,
        /// Prototype type.
        prototype: TypeId,
        /// Linkage value from the BTF ABI.
        linkage: u16,
    },
    /// A function prototype.
    FunctionPrototype {
        /// Return type.
        return_type: TypeId,
        /// Parameters.
        parameters: Vec<BtfParameter>,
    },
    /// A variable declaration.
    Variable {
        /// Variable name.
        name: String,
        /// Variable type.
        ty: TypeId,
        /// Linkage value from the BTF ABI.
        linkage: u32,
    },
    /// Description of an ELF data section.
    DataSection {
        /// Section name.
        name: String,
        /// Section size in bytes.
        size: u32,
        /// Variables stored in the section.
        variables: Vec<BtfVariable>,
    },
    /// A floating-point value.
    Float {
        /// Type name.
        name: String,
        /// Storage size in bytes.
        size: u32,
    },
    /// A tag attached to a declaration.
    DeclarationTag {
        /// Tag text.
        name: String,
        /// Tagged type.
        ty: TypeId,
        /// Member or parameter index, or `-1` for the declaration itself.
        component_index: i32,
    },
    /// A tag attached to a type.
    TypeTag {
        /// Tag text.
        name: String,
        /// Tagged type.
        ty: TypeId,
    },
    /// An enumeration with 64-bit values.
    Enum64 {
        /// Type name.
        name: String,
        /// Storage size in bytes.
        size: u32,
        /// Whether values are signed.
        signed: bool,
        /// Values.
        values: Vec<BtfEnumValue>,
    },
}

impl BtfType {
    /// Returns this type's kind.
    pub const fn kind(&self) -> BtfKind {
        match self {
            Self::Integer { .. } => BtfKind::Integer,
            Self::Pointer { .. } => BtfKind::Pointer,
            Self::Array { .. } => BtfKind::Array,
            Self::Struct { .. } => BtfKind::Struct,
            Self::Union { .. } => BtfKind::Union,
            Self::Enum { .. } => BtfKind::Enum,
            Self::Forward { .. } => BtfKind::Forward,
            Self::Typedef { .. } => BtfKind::Typedef,
            Self::Volatile { .. } => BtfKind::Volatile,
            Self::Const { .. } => BtfKind::Const,
            Self::Restrict { .. } => BtfKind::Restrict,
            Self::Function { .. } => BtfKind::Function,
            Self::FunctionPrototype { .. } => BtfKind::FunctionPrototype,
            Self::Variable { .. } => BtfKind::Variable,
            Self::DataSection { .. } => BtfKind::DataSection,
            Self::Float { .. } => BtfKind::Float,
            Self::DeclarationTag { .. } => BtfKind::DeclarationTag,
            Self::TypeTag { .. } => BtfKind::TypeTag,
            Self::Enum64 { .. } => BtfKind::Enum64,
        }
    }

    /// Returns the type's name, if the kind has one.
    pub fn name(&self) -> Option<&str> {
        match self {
            Self::Integer { name, .. }
            | Self::Struct { name, .. }
            | Self::Union { name, .. }
            | Self::Enum { name, .. }
            | Self::Forward { name, .. }
            | Self::Typedef { name, .. }
            | Self::Function { name, .. }
            | Self::Variable { name, .. }
            | Self::DataSection { name, .. }
            | Self::Float { name, .. }
            | Self::DeclarationTag { name, .. }
            | Self::TypeTag { name, .. }
            | Self::Enum64 { name, .. } => Some(name),
            _ => None,
        }
    }

    /// Returns a directly referenced type, for modifier and pointer-like kinds.
    pub const fn referenced_type(&self) -> Option<TypeId> {
        match self {
            Self::Pointer { ty }
            | Self::Typedef { ty, .. }
            | Self::Volatile { ty }
            | Self::Const { ty }
            | Self::Restrict { ty }
            | Self::Variable { ty, .. }
            | Self::DeclarationTag { ty, .. }
            | Self::TypeTag { ty, .. } => Some(*ty),
            Self::Function { prototype, .. } => Some(*prototype),
            _ => None,
        }
    }
}

/// An owned BPF Type Format table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Btf {
    raw: Vec<u8>,
    types: Vec<BtfType>,
    type_offsets: Vec<usize>,
    type_section_offset: usize,
    strings: Vec<u8>,
    endian: Endian,
}

impl Btf {
    /// Parses a `.BTF` section.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let endian = Endian::detect(bytes)?;
        let mut header = Reader::new(bytes, endian);
        let magic = header.u16()?;
        debug_assert_eq!(magic, BTF_MAGIC);
        let version = header.u8()?;
        if version != BTF_VERSION {
            return Err(Error::Btf(format!(
                "unsupported version {version}; expected {BTF_VERSION}"
            )));
        }
        let _flags = header.u8()?;
        let header_len = usize_from(header.u32()?, "header length")?;
        let type_offset = usize_from(header.u32()?, "type offset")?;
        let type_len = usize_from(header.u32()?, "type length")?;
        let string_offset = usize_from(header.u32()?, "string offset")?;
        let string_len = usize_from(header.u32()?, "string length")?;

        if header_len < BTF_HEADER_LEN || header_len > bytes.len() {
            return Err(Error::Btf(format!("invalid header length {header_len}")));
        }

        let type_start = checked_add(header_len, type_offset, "type section offset")?;
        let type_end = checked_add(type_start, type_len, "type section length")?;
        let string_start = checked_add(header_len, string_offset, "string section offset")?;
        let string_end = checked_add(string_start, string_len, "string section length")?;
        let type_bytes = bytes
            .get(type_start..type_end)
            .ok_or_else(|| Error::Btf("type section lies outside input".into()))?;
        let strings = bytes
            .get(string_start..string_end)
            .ok_or_else(|| Error::Btf("string section lies outside input".into()))?;
        if strings.first() != Some(&0) {
            return Err(Error::Btf(
                "string table does not start with a NUL byte".into(),
            ));
        }

        let mut reader = Reader::new(type_bytes, endian);
        let mut types = Vec::new();
        let mut type_offsets = Vec::new();
        while !reader.is_empty() {
            type_offsets.push(reader.position());
            types.push(parse_type(&mut reader, strings)?);
        }

        let btf = Self {
            raw: bytes.to_vec(),
            types,
            type_offsets,
            type_section_offset: type_start,
            strings: strings.to_vec(),
            endian,
        };
        btf.validate_references()?;
        Ok(btf)
    }

    /// Returns the original encoded BTF bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.raw
    }

    /// Returns the number of types, excluding `void`.
    pub fn len(&self) -> usize {
        self.types.len()
    }

    /// Returns whether there are no types.
    pub fn is_empty(&self) -> bool {
        self.types.is_empty()
    }

    /// Gets a type by ID. Type ID zero (`void`) returns `None`.
    pub fn type_by_id(&self, id: TypeId) -> Option<&BtfType> {
        id.0.checked_sub(1)
            .and_then(|index| self.types.get(index as usize))
    }

    /// Iterates over all non-void types and their IDs.
    pub fn types(&self) -> impl ExactSizeIterator<Item = (TypeId, &BtfType)> {
        self.types
            .iter()
            .enumerate()
            .map(|(index, ty)| (TypeId(index as u32 + 1), ty))
    }

    /// Finds the first type with the given kind and name.
    pub fn find(&self, kind: BtfKind, name: &str) -> Option<(TypeId, &BtfType)> {
        self.types()
            .find(|(_, ty)| ty.kind() == kind && ty.name() == Some(name))
    }

    /// Removes typedef and CVR/type-tag wrappers from an ID.
    pub fn resolve_type(&self, mut id: TypeId) -> Result<TypeId> {
        let mut seen = HashSet::new();
        loop {
            if id == TypeId::VOID {
                return Ok(id);
            }
            if !seen.insert(id) {
                return Err(Error::Btf(format!(
                    "type qualifier cycle at type ID {}",
                    id.0
                )));
            }
            match self.type_by_id(id) {
                Some(
                    BtfType::Typedef { ty, .. }
                    | BtfType::Volatile { ty }
                    | BtfType::Const { ty }
                    | BtfType::Restrict { ty }
                    | BtfType::TypeTag { ty, .. },
                ) => id = *ty,
                Some(_) => return Ok(id),
                None => return Err(Error::Btf(format!("type ID {} does not exist", id.0))),
            }
        }
    }

    /// Computes the byte size of a type.
    ///
    /// Pointers use the eBPF 64-bit address size. Function and forward
    /// declaration types do not have a size.
    pub fn size_of(&self, id: TypeId) -> Result<usize> {
        self.size_of_inner(id, &mut HashSet::new())
    }

    fn size_of_inner(&self, id: TypeId, seen: &mut HashSet<TypeId>) -> Result<usize> {
        if id == TypeId::VOID {
            return Ok(0);
        }
        if !seen.insert(id) {
            return Err(Error::Btf(format!("type size cycle at type ID {}", id.0)));
        }
        let ty = self
            .type_by_id(id)
            .ok_or_else(|| Error::Btf(format!("type ID {} does not exist", id.0)))?;
        let size = match ty {
            BtfType::Integer { size, .. }
            | BtfType::Struct { size, .. }
            | BtfType::Union { size, .. }
            | BtfType::Enum { size, .. }
            | BtfType::Float { size, .. }
            | BtfType::Enum64 { size, .. }
            | BtfType::DataSection { size, .. } => usize_from(*size, "type size")?,
            BtfType::Pointer { .. } => 8,
            BtfType::Array {
                element_type,
                count,
                ..
            } => self
                .size_of_inner(*element_type, seen)?
                .checked_mul(usize_from(*count, "array element count")?)
                .ok_or_else(|| Error::Btf("array size overflows usize".into()))?,
            BtfType::Typedef { ty, .. }
            | BtfType::Volatile { ty }
            | BtfType::Const { ty }
            | BtfType::Restrict { ty }
            | BtfType::Variable { ty, .. }
            | BtfType::DeclarationTag { ty, .. }
            | BtfType::TypeTag { ty, .. } => self.size_of_inner(*ty, seen)?,
            BtfType::Forward { .. }
            | BtfType::Function { .. }
            | BtfType::FunctionPrototype { .. } => {
                return Err(Error::Btf(format!(
                    "{:?} type ID {} has no size",
                    ty.kind(),
                    id.0
                )));
            }
        };
        seen.remove(&id);
        Ok(size)
    }

    fn validate_references(&self) -> Result<()> {
        let max =
            u32::try_from(self.types.len()).map_err(|_| Error::Btf("too many BTF types".into()))?;
        for (id, ty) in self.types() {
            let mut references = Vec::new();
            match ty {
                BtfType::Pointer { ty }
                | BtfType::Typedef { ty, .. }
                | BtfType::Volatile { ty }
                | BtfType::Const { ty }
                | BtfType::Restrict { ty }
                | BtfType::Variable { ty, .. }
                | BtfType::DeclarationTag { ty, .. }
                | BtfType::TypeTag { ty, .. } => references.push(*ty),
                BtfType::Array {
                    element_type,
                    index_type,
                    ..
                } => references.extend([*element_type, *index_type]),
                BtfType::Struct { members, .. } | BtfType::Union { members, .. } => {
                    references.extend(members.iter().map(|member| member.ty));
                }
                BtfType::Function { prototype, .. } => references.push(*prototype),
                BtfType::FunctionPrototype {
                    return_type,
                    parameters,
                } => {
                    references.push(*return_type);
                    references.extend(parameters.iter().map(|parameter| parameter.ty));
                }
                BtfType::DataSection { variables, .. } => {
                    references.extend(variables.iter().map(|variable| variable.ty));
                }
                _ => {}
            }
            if let Some(reference) = references.iter().find(|reference| reference.0 > max) {
                return Err(Error::Btf(format!(
                    "type ID {} references nonexistent type ID {}",
                    id.0, reference.0
                )));
            }
        }
        Ok(())
    }

    pub(crate) fn string_at(&self, offset: u32) -> Result<&str> {
        string(&self.strings, offset)
    }

    pub(crate) const fn endian(&self) -> Endian {
        self.endian
    }

    pub(crate) fn set_data_section_size(&mut self, name: &str, size: u32) -> Result<bool> {
        let Some(index) = self.types.iter().position(
            |ty| matches!(ty, BtfType::DataSection { name: candidate, .. } if candidate == name),
        ) else {
            return Ok(false);
        };
        let BtfType::DataSection {
            size: current_size, ..
        } = &mut self.types[index]
        else {
            unreachable!();
        };
        *current_size = size;
        let offset = self
            .type_section_offset
            .checked_add(self.type_offsets[index])
            .and_then(|offset| offset.checked_add(8))
            .ok_or_else(|| Error::Btf("data-section size offset overflow".into()))?;
        let target = self
            .raw
            .get_mut(offset..offset.saturating_add(4))
            .ok_or_else(|| Error::Btf("data-section size lies outside raw BTF".into()))?;
        let encoded = match self.endian {
            Endian::Little => size.to_le_bytes(),
            Endian::Big => size.to_be_bytes(),
        };
        target.copy_from_slice(&encoded);
        Ok(true)
    }

    pub(crate) fn sanitize_extern_linkage_for_kernel(&mut self) -> Result<()> {
        for (index, ty) in self.types.iter_mut().enumerate() {
            let record_offset = self
                .type_section_offset
                .checked_add(self.type_offsets[index])
                .ok_or_else(|| Error::Btf("type record offset overflow".into()))?;
            match ty {
                BtfType::Function { linkage, .. } if *linkage == 2 => {
                    *linkage = 1;
                    let info_offset = record_offset
                        .checked_add(4)
                        .ok_or_else(|| Error::Btf("function info offset overflow".into()))?;
                    let target = self
                        .raw
                        .get_mut(info_offset..info_offset.saturating_add(4))
                        .ok_or_else(|| Error::Btf("function info lies outside raw BTF".into()))?;
                    let mut info = match self.endian {
                        Endian::Little => u32::from_le_bytes(target.try_into().unwrap()),
                        Endian::Big => u32::from_be_bytes(target.try_into().unwrap()),
                    };
                    info = (info & !0xffff) | 1;
                    let encoded = match self.endian {
                        Endian::Little => info.to_le_bytes(),
                        Endian::Big => info.to_be_bytes(),
                    };
                    target.copy_from_slice(&encoded);
                }
                BtfType::Variable { linkage, .. } if *linkage == 2 => {
                    *linkage = 1;
                    let linkage_offset = record_offset
                        .checked_add(12)
                        .ok_or_else(|| Error::Btf("variable linkage offset overflow".into()))?;
                    let target = self
                        .raw
                        .get_mut(linkage_offset..linkage_offset.saturating_add(4))
                        .ok_or_else(|| {
                            Error::Btf("variable linkage lies outside raw BTF".into())
                        })?;
                    let encoded = match self.endian {
                        Endian::Little => 1_u32.to_le_bytes(),
                        Endian::Big => 1_u32.to_be_bytes(),
                    };
                    target.copy_from_slice(&encoded);
                }
                _ => {}
            }
        }
        Ok(())
    }
}

fn parse_type(reader: &mut Reader<'_>, strings: &[u8]) -> Result<BtfType> {
    let name_offset = reader.u32()?;
    let info = reader.u32()?;
    let size_or_type = reader.u32()?;
    let vlen = (info & 0xffff) as usize;
    let kind = ((info >> 24) & 0x1f) as u8;
    let kind_flag = info >> 31 != 0;
    let name = || string(strings, name_offset);

    let ty = match kind {
        1 => {
            let data = reader.u32()?;
            let flags = (data >> 24) as u8;
            BtfType::Integer {
                name: name()?.into(),
                size: size_or_type,
                encoding: IntegerEncoding {
                    signed: flags & 1 != 0,
                    character: flags & 2 != 0,
                    boolean: flags & 4 != 0,
                    offset: ((data >> 16) & 0xff) as u8,
                    bits: (data & 0xff) as u8,
                },
            }
        }
        2 => BtfType::Pointer {
            ty: TypeId(size_or_type),
        },
        3 => BtfType::Array {
            element_type: TypeId(reader.u32()?),
            index_type: TypeId(reader.u32()?),
            count: reader.u32()?,
        },
        4 | 5 => {
            let mut members = Vec::with_capacity(vlen);
            for _ in 0..vlen {
                let member_name = string(strings, reader.u32()?)?.into();
                let member_type = TypeId(reader.u32()?);
                let offset = reader.u32()?;
                let (bit_offset, bitfield_size) = if kind_flag {
                    (offset & 0x00ff_ffff, Some((offset >> 24) as u8))
                } else {
                    (offset, None)
                };
                members.push(BtfMember {
                    name: member_name,
                    ty: member_type,
                    bit_offset,
                    bitfield_size,
                });
            }
            if kind == 4 {
                BtfType::Struct {
                    name: name()?.into(),
                    size: size_or_type,
                    members,
                }
            } else {
                BtfType::Union {
                    name: name()?.into(),
                    size: size_or_type,
                    members,
                }
            }
        }
        6 => {
            let mut values = Vec::with_capacity(vlen);
            for _ in 0..vlen {
                values.push(BtfEnumValue {
                    name: string(strings, reader.u32()?)?.into(),
                    value: i64::from(reader.i32()?),
                });
            }
            BtfType::Enum {
                name: name()?.into(),
                size: size_or_type,
                signed: kind_flag,
                values,
            }
        }
        7 => BtfType::Forward {
            name: name()?.into(),
            union: kind_flag,
        },
        8 => BtfType::Typedef {
            name: name()?.into(),
            ty: TypeId(size_or_type),
        },
        9 => BtfType::Volatile {
            ty: TypeId(size_or_type),
        },
        10 => BtfType::Const {
            ty: TypeId(size_or_type),
        },
        11 => BtfType::Restrict {
            ty: TypeId(size_or_type),
        },
        12 => BtfType::Function {
            name: name()?.into(),
            prototype: TypeId(size_or_type),
            linkage: vlen as u16,
        },
        13 => {
            let mut parameters = Vec::with_capacity(vlen);
            for _ in 0..vlen {
                parameters.push(BtfParameter {
                    name: string(strings, reader.u32()?)?.into(),
                    ty: TypeId(reader.u32()?),
                });
            }
            BtfType::FunctionPrototype {
                return_type: TypeId(size_or_type),
                parameters,
            }
        }
        14 => BtfType::Variable {
            name: name()?.into(),
            ty: TypeId(size_or_type),
            linkage: reader.u32()?,
        },
        15 => {
            let mut variables = Vec::with_capacity(vlen);
            for _ in 0..vlen {
                variables.push(BtfVariable {
                    ty: TypeId(reader.u32()?),
                    offset: reader.u32()?,
                    size: reader.u32()?,
                });
            }
            BtfType::DataSection {
                name: name()?.into(),
                size: size_or_type,
                variables,
            }
        }
        16 => BtfType::Float {
            name: name()?.into(),
            size: size_or_type,
        },
        17 => BtfType::DeclarationTag {
            name: name()?.into(),
            ty: TypeId(size_or_type),
            component_index: reader.i32()?,
        },
        18 => BtfType::TypeTag {
            name: name()?.into(),
            ty: TypeId(size_or_type),
        },
        19 => {
            let mut values = Vec::with_capacity(vlen);
            for _ in 0..vlen {
                let value_name = string(strings, reader.u32()?)?.into();
                let low = u64::from(reader.u32()?);
                let high = u64::from(reader.u32()?);
                values.push(BtfEnumValue {
                    name: value_name,
                    value: ((high << 32) | low) as i64,
                });
            }
            BtfType::Enum64 {
                name: name()?.into(),
                size: size_or_type,
                signed: kind_flag,
                values,
            }
        }
        0 => return Err(Error::Btf("type table contains reserved kind zero".into())),
        _ => return Err(Error::Btf(format!("unsupported BTF kind {kind}"))),
    };
    Ok(ty)
}

fn string(strings: &[u8], offset: u32) -> Result<&str> {
    let offset = usize_from(offset, "string offset")?;
    let tail = strings
        .get(offset..)
        .ok_or_else(|| Error::Btf(format!("string offset {offset} is out of bounds")))?;
    let len = tail
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| Error::Btf(format!("string at offset {offset} is not NUL-terminated")))?;
    str::from_utf8(&tail[..len])
        .map_err(|error| Error::Btf(format!("string at offset {offset} is not UTF-8: {error}")))
}

fn checked_add(left: usize, right: usize, what: &str) -> Result<usize> {
    left.checked_add(right)
        .ok_or_else(|| Error::Btf(format!("{what} overflows usize")))
}

fn usize_from(value: u32, what: &str) -> Result<usize> {
    usize::try_from(value).map_err(|_| Error::Btf(format!("{what} does not fit usize")))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Endian {
    Little,
    Big,
}

impl Endian {
    fn detect(bytes: &[u8]) -> Result<Self> {
        let magic = bytes
            .get(..2)
            .ok_or_else(|| Error::Btf("input is shorter than the header".into()))?;
        if magic == BTF_MAGIC.to_le_bytes() {
            Ok(Self::Little)
        } else if magic == BTF_MAGIC.to_be_bytes() {
            Ok(Self::Big)
        } else {
            Err(Error::Btf(format!(
                "bad magic 0x{:02x}{:02x}",
                magic[0], magic[1]
            )))
        }
    }
}

#[derive(Debug)]
struct Reader<'a> {
    remaining: &'a [u8],
    original_len: usize,
    endian: Endian,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8], endian: Endian) -> Self {
        Self {
            remaining: bytes,
            original_len: bytes.len(),
            endian,
        }
    }

    fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }

    fn position(&self) -> usize {
        self.original_len - self.remaining.len()
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let (value, remaining) = self
            .remaining
            .split_at_checked(len)
            .ok_or_else(|| Error::Btf("unexpected end of data".into()))?;
        self.remaining = remaining;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        let value = self.take(2)?;
        let bytes = [value[0], value[1]];
        Ok(match self.endian {
            Endian::Little => u16::from_le_bytes(bytes),
            Endian::Big => u16::from_be_bytes(bytes),
        })
    }

    fn u32(&mut self) -> Result<u32> {
        let value = self.take(4)?;
        let bytes = [value[0], value[1], value[2], value[3]];
        Ok(match self.endian {
            Endian::Little => u32::from_le_bytes(bytes),
            Endian::Big => u32::from_be_bytes(bytes),
        })
    }

    fn i32(&mut self) -> Result<i32> {
        self.u32().map(|value| value as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u32_bytes(value: u32) -> [u8; 4] {
        value.to_le_bytes()
    }

    fn sample_btf() -> Vec<u8> {
        // IDs: 1 = int, 2 = ptr(int), 3 = array, 4 = struct pair.
        let strings = b"\0u32\0pair\0first\0second\0";
        let mut types = Vec::new();
        types.extend(u32_bytes(1)); // "u32"
        types.extend(u32_bytes(1 << 24)); // INT, vlen 0
        types.extend(u32_bytes(4));
        types.extend(u32_bytes(32));

        types.extend(u32_bytes(0));
        types.extend(u32_bytes(2 << 24)); // PTR
        types.extend(u32_bytes(1));

        types.extend(u32_bytes(0));
        types.extend(u32_bytes(3 << 24)); // ARRAY
        types.extend(u32_bytes(0));
        types.extend(u32_bytes(1));
        types.extend(u32_bytes(1));
        types.extend(u32_bytes(3));

        types.extend(u32_bytes(5)); // "pair"
        types.extend(u32_bytes((4 << 24) | 2)); // STRUCT, vlen 2
        types.extend(u32_bytes(16));
        types.extend(u32_bytes(10)); // "first"
        types.extend(u32_bytes(1));
        types.extend(u32_bytes(0));
        types.extend(u32_bytes(16)); // "second"
        types.extend(u32_bytes(3));
        types.extend(u32_bytes(32));

        let mut bytes = Vec::new();
        bytes.extend(BTF_MAGIC.to_le_bytes());
        bytes.push(BTF_VERSION);
        bytes.push(0);
        bytes.extend(u32_bytes(BTF_HEADER_LEN as u32));
        bytes.extend(u32_bytes(0));
        bytes.extend(u32_bytes(types.len() as u32));
        bytes.extend(u32_bytes(types.len() as u32));
        bytes.extend(u32_bytes(strings.len() as u32));
        bytes.extend(types);
        bytes.extend(strings);
        bytes
    }

    #[test]
    fn parses_and_resolves_types() {
        let btf = Btf::parse(&sample_btf()).unwrap();
        assert_eq!(btf.len(), 4);
        assert_eq!(btf.size_of(TypeId(1)).unwrap(), 4);
        assert_eq!(btf.size_of(TypeId(2)).unwrap(), 8);
        assert_eq!(btf.size_of(TypeId(3)).unwrap(), 12);
        assert_eq!(btf.size_of(TypeId(4)).unwrap(), 16);
        assert_eq!(btf.find(BtfKind::Struct, "pair").unwrap().0, TypeId(4));

        let BtfType::Struct { members, .. } = btf.type_by_id(TypeId(4)).unwrap() else {
            panic!("expected struct");
        };
        assert_eq!(members[1].name, "second");
        assert_eq!(members[1].bit_offset, 32);
    }

    #[test]
    fn rejects_out_of_range_reference() {
        let mut bytes = sample_btf();
        // Pointer target type is at header + first int record + 8.
        let offset = BTF_HEADER_LEN + 16 + 8;
        bytes[offset..offset + 4].copy_from_slice(&99_u32.to_le_bytes());
        assert!(Btf::parse(&bytes)
            .unwrap_err()
            .to_string()
            .contains("nonexistent type ID 99"));
    }

    #[test]
    fn accepts_big_endian_btf() {
        let strings = b"\0u8\0";
        let mut bytes = Vec::new();
        bytes.extend(BTF_MAGIC.to_be_bytes());
        bytes.push(BTF_VERSION);
        bytes.push(0);
        bytes.extend((BTF_HEADER_LEN as u32).to_be_bytes());
        bytes.extend(0_u32.to_be_bytes());
        bytes.extend(16_u32.to_be_bytes());
        bytes.extend(16_u32.to_be_bytes());
        bytes.extend((strings.len() as u32).to_be_bytes());
        bytes.extend(1_u32.to_be_bytes());
        bytes.extend((1_u32 << 24).to_be_bytes());
        bytes.extend(1_u32.to_be_bytes());
        bytes.extend(8_u32.to_be_bytes());
        bytes.extend(strings);

        let btf = Btf::parse(&bytes).unwrap();
        assert_eq!(btf.size_of(TypeId(1)).unwrap(), 1);
    }

    #[test]
    fn patches_data_section_size_in_model_and_kernel_bytes() {
        let strings = b"\0.rodata\0";
        let mut bytes = Vec::new();
        bytes.extend(BTF_MAGIC.to_le_bytes());
        bytes.push(BTF_VERSION);
        bytes.push(0);
        bytes.extend(u32_bytes(BTF_HEADER_LEN as u32));
        bytes.extend(u32_bytes(0));
        bytes.extend(u32_bytes(12));
        bytes.extend(u32_bytes(12));
        bytes.extend(u32_bytes(strings.len() as u32));
        bytes.extend(u32_bytes(1));
        bytes.extend(u32_bytes(15 << 24));
        bytes.extend(u32_bytes(0));
        bytes.extend(strings);

        let mut btf = Btf::parse(&bytes).unwrap();
        assert!(btf.set_data_section_size(".rodata", 64).unwrap());
        assert!(!btf.set_data_section_size(".missing", 1).unwrap());
        assert!(matches!(
            btf.type_by_id(TypeId(1)),
            Some(BtfType::DataSection { size: 64, .. })
        ));
        assert_eq!(
            &btf.as_bytes()[BTF_HEADER_LEN + 8..BTF_HEADER_LEN + 12],
            &64_u32.to_le_bytes()
        );
    }

    #[test]
    fn sanitizes_extern_function_linkage_for_kernel_loading() {
        let strings = b"\0external\0";
        let mut types = Vec::new();
        types.extend(u32_bytes(0));
        types.extend(u32_bytes(13 << 24));
        types.extend(u32_bytes(0));
        types.extend(u32_bytes(1));
        types.extend(u32_bytes((12 << 24) | 2));
        types.extend(u32_bytes(1));

        let mut bytes = Vec::new();
        bytes.extend(BTF_MAGIC.to_le_bytes());
        bytes.push(BTF_VERSION);
        bytes.push(0);
        bytes.extend(u32_bytes(BTF_HEADER_LEN as u32));
        bytes.extend(u32_bytes(0));
        bytes.extend(u32_bytes(types.len() as u32));
        bytes.extend(u32_bytes(types.len() as u32));
        bytes.extend(u32_bytes(strings.len() as u32));
        bytes.extend(types);
        bytes.extend(strings);

        let mut btf = Btf::parse(&bytes).unwrap();
        btf.sanitize_extern_linkage_for_kernel().unwrap();
        assert!(matches!(
            btf.type_by_id(TypeId(2)),
            Some(BtfType::Function { linkage: 1, .. })
        ));
        let info = u32::from_le_bytes(
            btf.as_bytes()[BTF_HEADER_LEN + 12 + 4..BTF_HEADER_LEN + 12 + 8]
                .try_into()
                .unwrap(),
        );
        assert_eq!(info & 0xffff, 1);
    }
}
