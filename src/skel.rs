//! Rust-native skeleton generation for eBPF objects.
//!
//! A generated skeleton embeds an eBPF ELF object and exposes its maps and
//! programs through named, safe Rust methods. Unlike a C libbpf skeleton, it
//! owns each lifecycle stage: a builder opens the bytes, an open skeleton
//! permits configuration, and loading returns a loaded skeleton that owns both
//! the kernel object and its attached links.

use std::collections::{HashMap, HashSet};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::{
    btf::{BtfEnumValue, BtfVariable},
    Btf, BtfType, Error, LoadedObject, MapFlags, MapMemory, MapMemoryMut, Object, Result, TypeId,
};

/// A value that can be decoded from and encoded into an eBPF data section.
///
/// Implementations use native byte order because eBPF objects loaded by this
/// crate must have the host's endianness. Generated structures implement this
/// trait field-by-field and do not rely on layout casts or `unsafe` code.
pub trait DataValue: Sized {
    /// Encoded value size in bytes.
    const SIZE: usize;

    /// Decodes a value from exactly [`Self::SIZE`] bytes.
    fn decode(bytes: &[u8]) -> Result<Self>;

    /// Encodes a value into exactly [`Self::SIZE`] bytes.
    fn encode(&self, bytes: &mut [u8]) -> Result<()>;
}

/// Safe, immutable access to bytes in an eBPF global data section.
#[derive(Clone, Copy, Debug)]
pub struct DataSection<'data> {
    bytes: &'data [u8],
}

impl<'data> DataSection<'data> {
    /// Wraps an encoded data section.
    pub const fn new(bytes: &'data [u8]) -> Self {
        Self { bytes }
    }

    /// Returns the entire encoded section.
    pub const fn as_bytes(self) -> &'data [u8] {
        self.bytes
    }

    /// Decodes a value starting at `offset`.
    pub fn read<T: DataValue>(self, offset: usize) -> Result<T> {
        T::decode(section_range(self.bytes, offset, T::SIZE)?)
    }

    /// Borrows an exact byte range.
    pub fn bytes(self, offset: usize, length: usize) -> Result<&'data [u8]> {
        section_range(self.bytes, offset, length)
    }
}

/// Safe, mutable access to bytes in an eBPF global data section.
#[derive(Debug)]
pub struct DataSectionMut<'data> {
    bytes: &'data mut [u8],
}

impl<'data> DataSectionMut<'data> {
    /// Wraps an encoded mutable data section.
    pub fn new(bytes: &'data mut [u8]) -> Self {
        Self { bytes }
    }

    /// Returns the entire encoded section.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes
    }

    /// Returns the entire mutable encoded section.
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        self.bytes
    }

    /// Decodes a value starting at `offset`.
    pub fn read<T: DataValue>(&self, offset: usize) -> Result<T> {
        T::decode(section_range(self.bytes, offset, T::SIZE)?)
    }

    /// Encodes a value starting at `offset`.
    pub fn write<T: DataValue>(&mut self, offset: usize, value: &T) -> Result<()> {
        value.encode(section_range_mut(self.bytes, offset, T::SIZE)?)
    }

    /// Borrows an exact byte range.
    pub fn bytes(&self, offset: usize, length: usize) -> Result<&[u8]> {
        section_range(self.bytes, offset, length)
    }

    /// Mutably borrows an exact byte range.
    pub fn bytes_mut(&mut self, offset: usize, length: usize) -> Result<&mut [u8]> {
        section_range_mut(self.bytes, offset, length)
    }
}

/// Safe typed snapshot access to a live mmapable global-data map.
#[derive(Debug)]
pub struct MappedDataSection<'data> {
    memory: MappedMemory<'data>,
    base_offset: usize,
}

#[derive(Debug)]
enum MappedMemory<'data> {
    ReadOnly(&'data MapMemory),
    Mutable(&'data MapMemoryMut),
}

impl<'data> MappedDataSection<'data> {
    /// Wraps an immutable map memory view.
    pub const fn new(memory: &'data MapMemory) -> Self {
        Self {
            memory: MappedMemory::ReadOnly(memory),
            base_offset: 0,
        }
    }

    /// Wraps an immutable map memory view whose section starts at `offset`.
    pub const fn new_at(memory: &'data MapMemory, offset: usize) -> Self {
        Self {
            memory: MappedMemory::ReadOnly(memory),
            base_offset: offset,
        }
    }

    /// Wraps the shared side of a mutable map memory view.
    pub const fn from_mutable(memory: &'data MapMemoryMut) -> Self {
        Self {
            memory: MappedMemory::Mutable(memory),
            base_offset: 0,
        }
    }

    /// Wraps a mutable map memory view whose shared section starts at
    /// `offset`.
    pub const fn from_mutable_at(memory: &'data MapMemoryMut, offset: usize) -> Self {
        Self {
            memory: MappedMemory::Mutable(memory),
            base_offset: offset,
        }
    }

    /// Decodes a copied value starting at `offset`.
    pub fn read<T: DataValue>(&self, offset: usize) -> Result<T> {
        T::decode(&self.read_vec(offset, T::SIZE)?)
    }

    /// Copies a byte range from live map memory.
    pub fn bytes(&self, offset: usize, length: usize) -> Result<Vec<u8>> {
        self.read_vec(offset, length)
    }

    fn read_vec(&self, offset: usize, length: usize) -> Result<Vec<u8>> {
        let offset = self
            .base_offset
            .checked_add(offset)
            .ok_or_else(|| Error::InvalidObject("mapped data-section offset overflow".into()))?;
        match self.memory {
            MappedMemory::ReadOnly(memory) => memory.read_vec(offset, length),
            MappedMemory::Mutable(memory) => memory.read_vec(offset, length),
        }
    }
}

/// Safe typed read-write access to a live mmapable global-data map.
#[derive(Debug)]
pub struct MappedDataSectionMut<'data> {
    memory: &'data mut MapMemoryMut,
    base_offset: usize,
}

impl<'data> MappedDataSectionMut<'data> {
    /// Wraps a mutable map memory view.
    pub fn new(memory: &'data mut MapMemoryMut) -> Self {
        Self {
            memory,
            base_offset: 0,
        }
    }

    /// Wraps a mutable map memory view whose section starts at `offset`.
    pub fn new_at(memory: &'data mut MapMemoryMut, offset: usize) -> Self {
        Self {
            memory,
            base_offset: offset,
        }
    }

    /// Decodes a copied value starting at `offset`.
    pub fn read<T: DataValue>(&self, offset: usize) -> Result<T> {
        let offset = self.absolute_offset(offset)?;
        T::decode(&self.memory.read_vec(offset, T::SIZE)?)
    }

    /// Copies a byte range from live map memory.
    pub fn bytes(&self, offset: usize, length: usize) -> Result<Vec<u8>> {
        self.memory.read_vec(self.absolute_offset(offset)?, length)
    }

    /// Encodes a value into live map memory at `offset`.
    pub fn write<T: DataValue>(&mut self, offset: usize, value: &T) -> Result<()> {
        let mut bytes = vec![0; T::SIZE];
        value.encode(&mut bytes)?;
        let offset = self.absolute_offset(offset)?;
        self.memory.write(offset, &bytes)
    }

    /// Copies bytes into live map memory at `offset`.
    pub fn write_bytes(&mut self, offset: usize, bytes: &[u8]) -> Result<()> {
        let offset = self.absolute_offset(offset)?;
        self.memory.write(offset, bytes)
    }

    fn absolute_offset(&self, offset: usize) -> Result<usize> {
        self.base_offset
            .checked_add(offset)
            .ok_or_else(|| Error::InvalidObject("mapped data-section offset overflow".into()))
    }
}

fn section_range(bytes: &[u8], offset: usize, length: usize) -> Result<&[u8]> {
    let end = offset
        .checked_add(length)
        .ok_or_else(|| Error::InvalidObject("data-section range overflow".into()))?;
    bytes.get(offset..end).ok_or(Error::SizeMismatch {
        what: "data section",
        expected: end,
        actual: bytes.len(),
    })
}

fn section_range_mut(bytes: &mut [u8], offset: usize, length: usize) -> Result<&mut [u8]> {
    let actual = bytes.len();
    let end = offset
        .checked_add(length)
        .ok_or_else(|| Error::InvalidObject("data-section range overflow".into()))?;
    bytes.get_mut(offset..end).ok_or(Error::SizeMismatch {
        what: "data section",
        expected: end,
        actual,
    })
}

macro_rules! primitive_data_value {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl DataValue for $ty {
                const SIZE: usize = std::mem::size_of::<Self>();

                fn decode(bytes: &[u8]) -> Result<Self> {
                    let bytes: [u8; Self::SIZE] =
                        bytes.try_into().map_err(|_| Error::SizeMismatch {
                            what: "encoded data value",
                            expected: Self::SIZE,
                            actual: bytes.len(),
                        })?;
                    Ok(Self::from_ne_bytes(bytes))
                }

                fn encode(&self, bytes: &mut [u8]) -> Result<()> {
                    if bytes.len() != Self::SIZE {
                        return Err(Error::SizeMismatch {
                            what: "encoded data value",
                            expected: Self::SIZE,
                            actual: bytes.len(),
                        });
                    }
                    bytes.copy_from_slice(&self.to_ne_bytes());
                    Ok(())
                }
            }
        )+
    };
}

primitive_data_value!(u8, i8, u16, i16, u32, i32, u64, i64, u128, i128, f32, f64);

impl DataValue for bool {
    const SIZE: usize = 1;

    fn decode(bytes: &[u8]) -> Result<Self> {
        match bytes {
            [0] => Ok(false),
            [1] => Ok(true),
            [value] => Err(Error::InvalidObject(format!(
                "encoded boolean has non-canonical value {value}"
            ))),
            _ => Err(Error::SizeMismatch {
                what: "encoded boolean",
                expected: Self::SIZE,
                actual: bytes.len(),
            }),
        }
    }

    fn encode(&self, bytes: &mut [u8]) -> Result<()> {
        match bytes {
            [value] => {
                *value = u8::from(*self);
                Ok(())
            }
            _ => Err(Error::SizeMismatch {
                what: "encoded boolean",
                expected: Self::SIZE,
                actual: bytes.len(),
            }),
        }
    }
}

impl<T: DataValue, const N: usize> DataValue for [T; N] {
    const SIZE: usize = T::SIZE * N;

    fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != Self::SIZE {
            return Err(Error::SizeMismatch {
                what: "encoded data array",
                expected: Self::SIZE,
                actual: bytes.len(),
            });
        }
        let mut values = Vec::with_capacity(N);
        if T::SIZE == 0 {
            for _ in 0..N {
                values.push(T::decode(&[])?);
            }
        } else {
            for chunk in bytes.chunks_exact(T::SIZE) {
                values.push(T::decode(chunk)?);
            }
        }
        values.try_into().map_err(|values: Vec<T>| {
            Error::InvalidObject(format!(
                "decoded data array has {} elements, expected {N}",
                values.len()
            ))
        })
    }

    fn encode(&self, bytes: &mut [u8]) -> Result<()> {
        if bytes.len() != Self::SIZE {
            return Err(Error::SizeMismatch {
                what: "encoded data array",
                expected: Self::SIZE,
                actual: bytes.len(),
            });
        }
        if T::SIZE == 0 {
            for value in self {
                value.encode(&mut [])?;
            }
        } else {
            for (value, chunk) in self.iter().zip(bytes.chunks_exact_mut(T::SIZE)) {
                value.encode(chunk)?;
            }
        }
        Ok(())
    }
}

/// Common behavior of a generated, configurable skeleton.
///
/// Generated skeletons also provide named map and program accessors as
/// inherent methods.
pub trait OpenSkeleton: Sized {
    /// Loaded skeleton produced by [`Self::load`].
    type Loaded: Skeleton;

    /// Borrows the parsed object.
    fn object(&self) -> &Object;

    /// Mutably borrows the parsed object for pre-load configuration.
    fn object_mut(&mut self) -> &mut Object;

    /// Loads maps and programs into the kernel.
    fn load(self) -> Result<Self::Loaded>;
}

/// Common behavior of a generated, loaded skeleton.
///
/// Generated skeletons retain their automatic links until detached or
/// dropped.
pub trait Skeleton {
    /// Borrows the loaded object.
    fn object(&self) -> &LoadedObject;

    /// Mutably borrows the loaded object.
    fn object_mut(&mut self) -> &mut LoadedObject;

    /// Attaches every program whose target is fully described by its ELF
    /// section and retains the resulting links.
    fn attach(&mut self) -> Result<&mut Self>;

    /// Drops all links retained by the skeleton.
    fn detach(&mut self);
}

/// Builds eBPF C sources and generates safe, Rust-native skeleton modules.
///
/// This type is intended for `build.rs`, but the object-only generation path
/// is also useful to checked-in code generators and command-line tools.
///
/// # Example
///
/// ```no_run
/// use ebeepf::SkeletonBuilder;
///
/// SkeletonBuilder::new()
///     .source("src/bpf/monitor.bpf.c")
///     .build_and_generate("src/monitor.skel.rs")?;
/// # Ok::<(), ebeepf::Error>(())
/// ```
#[derive(Clone, Debug)]
pub struct SkeletonBuilder {
    source: Option<PathBuf>,
    object: Option<PathBuf>,
    clang: PathBuf,
    clang_args: Vec<OsString>,
    rustfmt: Option<PathBuf>,
    reference_object: bool,
    name: Option<String>,
    crate_path: String,
    type_allowlist: Option<Vec<String>>,
}

impl Default for SkeletonBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl SkeletonBuilder {
    /// Creates a skeleton builder with `clang` and `rustfmt` from `PATH`.
    pub fn new() -> Self {
        Self {
            source: None,
            object: None,
            clang: "clang".into(),
            clang_args: Vec::new(),
            rustfmt: Some("rustfmt".into()),
            reference_object: false,
            name: None,
            crate_path: "::ebeepf".into(),
            type_allowlist: None,
        }
    }

    /// Selects a `.bpf.c` source file to compile.
    pub fn source(&mut self, source: impl AsRef<Path>) -> &mut Self {
        self.source = Some(source.as_ref().into());
        self
    }

    /// Selects the `.bpf.o` object to generate from or to write while building.
    pub fn object(&mut self, object: impl AsRef<Path>) -> &mut Self {
        self.object = Some(object.as_ref().into());
        self
    }

    /// Alias for [`Self::object`], matching common eBPF build-script usage.
    pub fn obj(&mut self, object: impl AsRef<Path>) -> &mut Self {
        self.object(object)
    }

    /// Selects the Clang executable used by [`Self::build`].
    pub fn clang(&mut self, clang: impl AsRef<Path>) -> &mut Self {
        self.clang = clang.as_ref().into();
        self
    }

    /// Replaces additional arguments passed to Clang.
    pub fn clang_args<I, S>(&mut self, arguments: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.clang_args = arguments
            .into_iter()
            .map(|argument| argument.as_ref().to_owned())
            .collect();
        self
    }

    /// Selects the Rustfmt executable used after generation.
    pub fn rustfmt(&mut self, rustfmt: impl AsRef<Path>) -> &mut Self {
        self.rustfmt = Some(rustfmt.as_ref().into());
        self
    }

    /// Enables or disables formatting generated Rust.
    pub fn format(&mut self, enabled: bool) -> &mut Self {
        self.rustfmt = enabled.then(|| PathBuf::from("rustfmt"));
        self
    }

    /// Uses `include_bytes!` instead of embedding the object as a byte array.
    ///
    /// Referencing greatly reduces generated source size, but the object must
    /// remain at the same canonical path when the generated code is compiled.
    pub fn reference_object(&mut self, reference: bool) -> &mut Self {
        self.reference_object = reference;
        self
    }

    /// Alias for [`Self::reference_object`].
    pub fn reference_obj(&mut self, reference: bool) -> &mut Self {
        self.reference_object(reference)
    }

    /// Overrides the object and generated Rust type name.
    pub fn name(&mut self, name: impl Into<String>) -> &mut Self {
        self.name = Some(name.into());
        self
    }

    /// Overrides the path used to refer to this crate in generated source.
    ///
    /// For example, an application that renames its dependency can use
    /// `"::bpf_runtime"`.
    pub fn crate_path(&mut self, path: impl Into<String>) -> &mut Self {
        self.crate_path = path.into();
        self
    }

    /// Restricts generated BTF-derived C types to these names and their dependencies.
    ///
    /// Names are matched against BTF names and generated Rust type names. Data
    /// sections may be listed either as their BTF section name, such as
    /// `.rodata`, or as the generated Rust name, such as `rodata`.
    ///
    /// When this is not configured, all BTF-derived C types are generated.
    pub fn type_allowlist<I, S>(&mut self, types: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.type_allowlist = Some(types.into_iter().map(Into::into).collect());
        self
    }

    /// Adds one name to the BTF-derived C type generation allowlist.
    pub fn allow_type(&mut self, ty: impl Into<String>) -> &mut Self {
        self.type_allowlist
            .get_or_insert_with(Vec::new)
            .push(ty.into());
        self
    }

    /// Clears the BTF-derived C type generation allowlist.
    pub fn clear_type_allowlist(&mut self) -> &mut Self {
        self.type_allowlist = None;
        self
    }

    /// Compiles the configured source to an eBPF ELF object.
    ///
    /// If no object path was selected, the output is placed in `OUT_DIR`
    /// when available and next to the source otherwise.
    pub fn build(&mut self) -> Result<&mut Self> {
        let source = self
            .source
            .as_ref()
            .ok_or_else(|| Error::Build("no eBPF C source was configured".into()))?;
        let filename = source
            .file_name()
            .and_then(OsStr::to_str)
            .ok_or_else(|| Error::Build("the eBPF source has no UTF-8 file name".into()))?;
        let stem = filename.strip_suffix(".bpf.c").ok_or_else(|| {
            Error::Build(format!(
                "eBPF source `{}` must end in `.bpf.c`",
                source.display()
            ))
        })?;

        if self.object.is_none() {
            let directory = env::var_os("OUT_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| source.parent().unwrap_or_else(|| Path::new(".")).into());
            self.object = Some(directory.join(format!("{stem}.bpf.o")));
        }
        let object = self.object.as_ref().expect("object path initialized");
        if let Some(parent) = object.parent() {
            fs::create_dir_all(parent).map_err(|source| Error::File {
                operation: "create eBPF object output directory",
                path: parent.into(),
                source,
            })?;
        }

        let mut command = Command::new(&self.clang);
        command
            .arg("-g")
            .arg("-O2")
            .arg("-target")
            .arg("bpf")
            .arg(format!("-D__TARGET_ARCH_{}", target_arch()?))
            .args(&self.clang_args)
            .arg("-c")
            .arg(source)
            .arg("-o")
            .arg(object);
        let output = command.output().map_err(|source| Error::File {
            operation: "execute Clang",
            path: self.clang.clone(),
            source,
        })?;
        if !output.status.success() {
            return Err(Error::Build(format!(
                "Clang exited with {} while compiling `{}`:\n{}",
                output.status,
                source.display(),
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        Ok(self)
    }

    /// Renders a skeleton for the configured object without writing it.
    pub fn render(&self) -> Result<String> {
        let path = self
            .object
            .as_ref()
            .ok_or_else(|| Error::Build("no eBPF object was configured".into()))?;
        let bytes = fs::read(path).map_err(|source| Error::File {
            operation: "read eBPF object for skeleton generation",
            path: path.clone(),
            source,
        })?;
        let default_name = object_stem(path)?;
        let name = self.name.as_deref().unwrap_or(&default_name);
        let object = Object::parse_named(name, &bytes)?;
        render_skeleton(
            &object,
            &bytes,
            path,
            name,
            &self.crate_path,
            self.reference_object,
            self.type_allowlist.as_deref(),
        )
    }

    /// Generates a Rust skeleton at `output`.
    pub fn generate(&self, output: impl AsRef<Path>) -> Result<()> {
        let output = output.as_ref();
        let source = self.render()?;
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent).map_err(|source| Error::File {
                operation: "create skeleton output directory",
                path: parent.into(),
                source,
            })?;
        }
        fs::write(output, source).map_err(|source| Error::File {
            operation: "write generated Rust skeleton",
            path: output.into(),
            source,
        })?;
        if let Some(rustfmt) = &self.rustfmt {
            let result = Command::new(rustfmt)
                .arg("--edition")
                .arg("2021")
                .arg(output)
                .output()
                .map_err(|source| Error::File {
                    operation: "execute Rustfmt",
                    path: rustfmt.clone(),
                    source,
                })?;
            if !result.status.success() {
                return Err(Error::Build(format!(
                    "Rustfmt exited with {} for `{}`:\n{}",
                    result.status,
                    output.display(),
                    String::from_utf8_lossy(&result.stderr)
                )));
            }
        }
        Ok(())
    }

    /// Compiles the configured source and generates a Rust skeleton.
    pub fn build_and_generate(&mut self, output: impl AsRef<Path>) -> Result<()> {
        self.build()?;
        self.generate(output)
    }

    /// Returns the selected or inferred object path after [`Self::build`].
    pub fn object_path(&self) -> Option<&Path> {
        self.object.as_deref()
    }
}

fn target_arch() -> Result<&'static str> {
    let architecture =
        env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_else(|_| env::consts::ARCH.into());
    match architecture.as_str() {
        "x86" | "x86_64" => Ok("x86"),
        "arm" => Ok("arm"),
        "aarch64" => Ok("arm64"),
        "riscv64" => Ok("riscv"),
        "powerpc64" => Ok("powerpc"),
        "s390x" => Ok("s390"),
        value => Err(Error::Build(format!(
            "target architecture `{value}` has no __TARGET_ARCH mapping"
        ))),
    }
}

fn object_stem(path: &Path) -> Result<String> {
    let filename = path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| Error::Build("the eBPF object has no UTF-8 file name".into()))?;
    Ok(filename
        .strip_suffix(".bpf.o")
        .or_else(|| filename.strip_suffix(".o"))
        .unwrap_or(filename)
        .to_owned())
}

#[derive(Debug)]
struct NamedItem {
    source: String,
    method: String,
}

#[derive(Debug)]
struct DataVariable {
    source: String,
    method: String,
    offset: usize,
    rust_type: String,
}

#[derive(Debug)]
struct DataSectionItem {
    source: String,
    map: String,
    method: String,
    shared_type: String,
    mutable_type: String,
    loaded_shared_type: String,
    loaded_mutable_type: String,
    read_only: bool,
    variables: Vec<DataVariable>,
}

fn render_skeleton(
    object: &Object,
    bytes: &[u8],
    object_path: &Path,
    name: &str,
    crate_path: &str,
    reference_object: bool,
    type_allowlist: Option<&[String]>,
) -> Result<String> {
    validate_crate_path(crate_path)?;
    let doc_name = doc_text(name);
    let type_name = pascal_identifier(name);
    let builder_name = format!("{type_name}SkelBuilder");
    let open_name = format!("Open{type_name}Skel");
    let loaded_name = format!("{type_name}Skel");
    let open_maps_name = format!("Open{type_name}Maps");
    let open_maps_mut_name = format!("Open{type_name}MapsMut");
    let maps_name = format!("{type_name}Maps");
    let open_programs_name = format!("Open{type_name}Programs");
    let open_programs_mut_name = format!("Open{type_name}ProgramsMut");
    let programs_name = format!("{type_name}Programs");
    let links_name = format!("{type_name}Links");
    let mut map_names = HashSet::new();
    let maps = object
        .maps()
        .map(|map| NamedItem {
            source: map.name().to_owned(),
            method: unique_identifier(snake_identifier(map.name()), &mut map_names),
        })
        .collect::<Vec<_>>();
    let mut program_names = HashSet::new();
    let programs = object
        .programs()
        .map(|program| NamedItem {
            source: program.name().to_owned(),
            method: unique_identifier(snake_identifier(program.name()), &mut program_names),
        })
        .collect::<Vec<_>>();
    let mut link_names = programs
        .iter()
        .map(|program| program.method.clone())
        .collect::<HashSet<_>>();
    let struct_ops_links = object
        .maps()
        .filter(|map| map.map_type() == crate::MapType::StructOps)
        .map(|map| NamedItem {
            source: map.name().to_owned(),
            method: unique_identifier(snake_identifier(map.name()), &mut link_names),
        })
        .collect::<Vec<_>>();
    let btf_types = render_btf_type_module(object, type_allowlist)?;
    let (data_sections, data_types) = collect_data_sections(object, &type_name, crate_path)?;
    let mut loaded_data_fields = String::new();
    let mut loaded_data_setup = String::new();
    let mut loaded_data_initializers = String::new();
    for section in &data_sections {
        let memory_type = if section.read_only {
            "MapMemory"
        } else {
            "MapMemoryMut"
        };
        let mapping_method = if section.read_only {
            "mmap"
        } else {
            "mmap_mut"
        };
        writeln!(
            loaded_data_fields,
            "    {}_memory: {crate_path}::{memory_type},",
            section.method
        )
        .expect("String write");
        writeln!(
            loaded_data_setup,
            "        let {}_memory = object.map({:?})?.{}()?;",
            section.method, section.map, mapping_method
        )
        .expect("String write");
        writeln!(
            loaded_data_initializers,
            "            {}_memory,",
            section.method
        )
        .expect("String write");
    }

    let mut output = String::new();
    writeln!(
        output,
        "// @generated by ebeepf. Changes to this file will be overwritten."
    )
    .expect("writing to String cannot fail");
    writeln!(output, "#[allow(clippy::needless_lifetimes)]")
        .expect("writing to String cannot fail");
    if reference_object {
        let canonical = fs::canonicalize(object_path).map_err(|source| Error::File {
            operation: "canonicalize referenced eBPF object",
            path: object_path.into(),
            source,
        })?;
        writeln!(
            output,
            "const OBJECT_BYTES: &[u8] = include_bytes!({:?});",
            canonical.to_string_lossy()
        )
        .expect("writing to String cannot fail");
    } else {
        writeln!(output, "const OBJECT_BYTES: &[u8] = &[").expect("String write");
        for chunk in bytes.chunks(16) {
            output.push_str("    ");
            for byte in chunk {
                write!(output, "0x{byte:02x}, ").expect("String write");
            }
            output.push('\n');
        }
        writeln!(output, "];").expect("String write");
    }
    output.push('\n');
    output.push_str(&btf_types);
    output.push_str(&data_types);

    writeln!(
        output,
        "/// Builder for the generated `{doc_name}` eBPF skeleton.\n\
         #[derive(Clone, Debug, Default)]\n\
         pub struct {builder_name} {{\n\
             pin_root: Option<std::path::PathBuf>,\n\
             token: Option<{crate_path}::BpfToken>,\n\
         }}\n\
         \n\
         impl {builder_name} {{\n\
             /// Creates a skeleton builder.\n\
             pub fn new() -> Self {{ Self::default() }}\n\
             \n\
             /// Sets the root used by maps configured for pin-by-name.\n\
             pub fn pin_root(mut self, path: impl Into<std::path::PathBuf>) -> Self {{\n\
                 self.pin_root = Some(path.into());\n\
                 self\n\
             }}\n\
             \n\
             /// Uses a delegated BPF token while loading the skeleton.\n\
             pub fn token(mut self, token: &{crate_path}::BpfToken) -> Self {{\n\
                 self.token = Some(token.clone());\n\
                 self\n\
             }}\n\
             \n\
             /// Parses the embedded object and enters the configurable stage.\n\
             pub fn open(self) -> {crate_path}::Result<{open_name}> {{\n\
                 let mut object = {crate_path}::Object::parse_named({name:?}, OBJECT_BYTES)?;\n\
                 if let Some(pin_root) = self.pin_root {{\n\
                     object.set_pin_root(pin_root);\n\
                 }}\n\
                 if let Some(token) = self.token.as_ref() {{\n\
                     object.set_token(token);\n\
                 }}\n\
                 Ok({open_name} {{ object }})\n\
             }}\n\
         }}\n"
    )
    .expect("String write");

    writeln!(
        output,
        "/// Parsed, configurable `{doc_name}` eBPF skeleton.\n\
         #[derive(Clone, Debug)]\n\
         pub struct {open_name} {{\n\
             object: {crate_path}::Object,\n\
         }}\n\
         \n\
         impl {open_name} {{\n\
             /// Borrows all open map specifications through named accessors.\n\
             pub fn maps(&self) -> {open_maps_name}<'_> {{ {open_maps_name} {{ object: &self.object }} }}\n\
             \n\
             /// Mutably borrows all open map specifications through named accessors.\n\
             pub fn maps_mut(&mut self) -> {open_maps_mut_name}<'_> {{ {open_maps_mut_name} {{ object: &mut self.object }} }}\n\
             \n\
             /// Borrows all open program specifications through named accessors.\n\
             pub fn programs(&self) -> {open_programs_name}<'_> {{ {open_programs_name} {{ object: &self.object }} }}\n\
             \n\
             /// Mutably borrows all open program specifications through named accessors.\n\
             pub fn programs_mut(&mut self) -> {open_programs_mut_name}<'_> {{ {open_programs_mut_name} {{ object: &mut self.object }} }}\n\
             \n\
             /// Borrows the underlying parsed object.\n\
             pub fn object(&self) -> &{crate_path}::Object {{ &self.object }}\n\
             \n\
             /// Mutably borrows the underlying parsed object.\n\
             pub fn object_mut(&mut self) -> &mut {crate_path}::Object {{ &mut self.object }}\n\
             \n\
             /// Loads all enabled maps and programs into the kernel.\n\
             pub fn load(self) -> {crate_path}::Result<{loaded_name}> {{\n\
                 let object = self.object.load()?;\n\
{loaded_data_setup}                 Ok({loaded_name} {{\n\
                     object,\n\
                     links: {links_name}::default(),\n\
{loaded_data_initializers}                 }})\n\
             }}\n\
         }}\n\
         \n\
         impl {crate_path}::OpenSkeleton for {open_name} {{\n\
             type Loaded = {loaded_name};\n\
             fn object(&self) -> &{crate_path}::Object {{ &self.object }}\n\
             fn object_mut(&mut self) -> &mut {crate_path}::Object {{ &mut self.object }}\n\
             fn load(self) -> {crate_path}::Result<Self::Loaded> {{ Self::load(self) }}\n\
         }}\n"
    )
    .expect("String write");

    render_open_map_accessors(
        &mut output,
        &maps,
        &open_maps_name,
        &open_maps_mut_name,
        crate_path,
    );
    render_open_program_accessors(
        &mut output,
        &programs,
        &open_programs_name,
        &open_programs_mut_name,
        crate_path,
    );
    render_data_accessors(&mut output, &data_sections, &open_name, crate_path);
    render_loaded_accessors(
        &mut output,
        &maps,
        &programs,
        &maps_name,
        &programs_name,
        crate_path,
    );
    render_links(
        &mut output,
        &programs,
        &struct_ops_links,
        &links_name,
        crate_path,
    );

    writeln!(
        output,
        "/// Loaded `{doc_name}` eBPF skeleton and its retained links.\n\
         #[derive(Debug)]\n\
         pub struct {loaded_name} {{\n\
             object: {crate_path}::LoadedObject,\n\
             links: {links_name},\n\
{loaded_data_fields}\
         }}\n\
         \n\
         impl {loaded_name} {{\n\
             /// Borrows all loaded maps through named accessors.\n\
             pub fn maps(&self) -> {maps_name}<'_> {{ {maps_name} {{ object: &self.object }} }}\n\
             \n\
             /// Borrows all loaded programs through named accessors.\n\
             pub fn programs(&self) -> {programs_name}<'_> {{ {programs_name} {{ object: &self.object }} }}\n\
             \n\
             /// Borrows retained links.\n\
             pub fn links(&self) -> &{links_name} {{ &self.links }}\n\
             \n\
             /// Mutably borrows retained links, including slots for manual attachments.\n\
             pub fn links_mut(&mut self) -> &mut {links_name} {{ &mut self.links }}\n\
             \n\
             /// Borrows the underlying loaded object.\n\
             pub fn object(&self) -> &{crate_path}::LoadedObject {{ &self.object }}\n\
             \n\
             /// Mutably borrows the underlying loaded object.\n\
             pub fn object_mut(&mut self) -> &mut {crate_path}::LoadedObject {{ &mut self.object }}\n\
             \n\
             /// Attaches enabled programs which require no additional runtime arguments.\n\
             ///\n\
             /// Attachment is transactional: existing retained links are replaced only\n\
             /// after every new automatic attachment succeeds.\n\
             pub fn attach(&mut self) -> {crate_path}::Result<&mut Self> {{\n\
                 {} links = {links_name}::default();",
        if programs.is_empty() && struct_ops_links.is_empty() {
            "let"
        } else {
            "let mut"
        }
    )
    .expect("String write");
    for program in &programs {
        writeln!(
            output,
            "        if let Some(program) = self.object.programs().find(|program| program.name() == {:?} && program.spec().auto_attach()) {{\n\
                 links.{} = Some(program.attach()?);\n\
             }}",
            program.source, program.method
        )
        .expect("String write");
    }
    for map in &struct_ops_links {
        writeln!(
            output,
            "        if let Some(map) = self.object.maps().find(|map| map.name() == {:?} && map.spec().auto_attach()) {{\n\
                 links.{} = Some(map.attach_struct_ops()?);\n\
             }}",
            map.source, map.method
        )
        .expect("String write");
    }
    writeln!(
        output,
        "        self.links = links;\n\
                 Ok(self)\n\
             }}\n\
             \n\
             /// Detaches all links currently retained by this skeleton.\n\
             pub fn detach(&mut self) {{ self.links = {links_name}::default(); }}\n\
         }}\n\
         \n\
         impl {crate_path}::Skeleton for {loaded_name} {{\n\
             fn object(&self) -> &{crate_path}::LoadedObject {{ &self.object }}\n\
             fn object_mut(&mut self) -> &mut {crate_path}::LoadedObject {{ &mut self.object }}\n\
             fn attach(&mut self) -> {crate_path}::Result<&mut Self> {{ Self::attach(self) }}\n\
             fn detach(&mut self) {{ Self::detach(self); }}\n\
         }}\n"
    )
    .expect("String write");
    render_loaded_data_accessors(&mut output, &data_sections, &loaded_name, crate_path);
    let output = output
        .replace(
            "const OBJECT_BYTES:",
            "#[allow(dead_code)]\nconst OBJECT_BYTES:",
        )
        .replace("\npub struct ", "\n#[allow(dead_code)]\npub struct ")
        .replace("\nimpl ", "\n#[allow(dead_code)]\nimpl ")
        .replace("\nimpl<", "\n#[allow(dead_code)]\nimpl<");
    Ok(output)
}

#[derive(Debug, Default)]
struct BtfTypeNames {
    names: HashMap<TypeId, String>,
    aliases: HashMap<String, Vec<TypeId>>,
}

impl BtfTypeNames {
    fn new(btf: &Btf) -> Self {
        let mut names = HashMap::new();
        let mut aliases = HashMap::<String, Vec<TypeId>>::new();
        let mut used = HashMap::<String, usize>::new();
        let mut next_anonymous = 1_usize;
        for (id, ty) in btf.types() {
            if !is_renderable_c_type(ty) {
                continue;
            }
            let Some(base) = c_type_base_name(ty, next_anonymous) else {
                continue;
            };
            if ty.name().is_some_and(str::is_empty) {
                next_anonymous += 1;
            }
            let name = unique_type_identifier(base, &mut used);
            insert_type_alias(&mut aliases, &name, id);
            if let Some(alias) = ty.name().filter(|name| !name.is_empty()) {
                insert_type_alias(&mut aliases, alias, id);
            }
            if let BtfType::DataSection { name, .. } = ty {
                insert_type_alias(&mut aliases, &data_section_type_name(name), id);
            }
            names.insert(id, name);
        }
        Self { names, aliases }
    }

    fn name(&self, id: TypeId) -> Result<&str> {
        self.names
            .get(&id)
            .map(String::as_str)
            .ok_or_else(|| Error::Btf(format!("BTF type ID {} has no generated Rust name", id.0)))
    }

    fn name_for_type(&self, btf: &Btf, id: TypeId) -> Result<&str> {
        let id = btf.resolve_type(id)?;
        self.name(id)
    }

    fn ids_for_allowlist_name(&self, name: &str) -> Option<&[TypeId]> {
        self.aliases
            .get(name)
            .or_else(|| self.aliases.get(&c_identifier(name, "type")))
            .map(Vec::as_slice)
    }
}

fn render_btf_type_module(object: &Object, allowlist: Option<&[String]>) -> Result<String> {
    let Some(btf) = object.btf() else {
        return Ok(String::new());
    };
    let names = BtfTypeNames::new(btf);
    let generated_types = c_type_generation_set(btf, &names, allowlist)?;
    let mut definitions = String::new();
    for (id, ty) in btf.types() {
        if !generated_types.contains(&id) {
            continue;
        }
        match ty {
            BtfType::Struct { size, members, .. } => {
                render_c_struct_type(&mut definitions, btf, &names, id, *size, members)?;
            }
            BtfType::Union { size, members, .. } => {
                render_c_union_type(&mut definitions, btf, &names, id, *size, members)?;
            }
            BtfType::Enum {
                size,
                signed,
                values,
                ..
            }
            | BtfType::Enum64 {
                size,
                signed,
                values,
                ..
            } => render_c_enum_type(&mut definitions, &names, id, *size, *signed, values)?,
            BtfType::DataSection {
                name,
                size,
                variables,
            } if data_section_type_name(name) != "ksyms" => {
                render_c_data_section_type(&mut definitions, btf, &names, id, *size, variables)?;
            }
            _ => {}
        }
    }
    if definitions.is_empty() {
        return Ok(String::new());
    }

    let mut output = String::new();
    writeln!(
        output,
        "pub mod types {{\n\
             #![allow(dead_code, non_camel_case_types, non_snake_case, non_upper_case_globals)]\n\
             #[allow(unused_imports)]\n\
             use super::*;"
    )
    .expect("String write");
    output.push_str(&definitions);
    writeln!(output, "}}\n").expect("String write");
    Ok(output)
}

fn c_type_generation_set(
    btf: &Btf,
    names: &BtfTypeNames,
    allowlist: Option<&[String]>,
) -> Result<HashSet<TypeId>> {
    let Some(allowlist) = allowlist else {
        return Ok(btf
            .types()
            .filter_map(|(id, ty)| is_renderable_c_type(ty).then_some(id))
            .collect());
    };

    let mut pending = Vec::new();
    let mut missing = Vec::new();
    for name in allowlist {
        if let Some(ids) = names.ids_for_allowlist_name(name) {
            pending.extend_from_slice(ids);
        } else {
            missing.push(name.clone());
        }
    }
    if !missing.is_empty() {
        return Err(Error::Btf(format!(
            "BTF type allowlist entries were not found: {}",
            missing.join(", ")
        )));
    }

    let mut generated = HashSet::new();
    let mut visited = HashSet::new();
    while let Some(id) = pending.pop() {
        add_c_type_closure(btf, id, &mut generated, &mut visited, &mut pending)?;
    }
    Ok(generated)
}

fn add_c_type_closure(
    btf: &Btf,
    id: TypeId,
    generated: &mut HashSet<TypeId>,
    visited: &mut HashSet<TypeId>,
    pending: &mut Vec<TypeId>,
) -> Result<()> {
    if id == TypeId::VOID {
        return Ok(());
    }
    let id = btf.resolve_type(id)?;
    if id == TypeId::VOID || !visited.insert(id) {
        return Ok(());
    }
    let ty = btf
        .type_by_id(id)
        .ok_or_else(|| Error::Btf(format!("type ID {} does not exist", id.0)))?;
    match ty {
        BtfType::Struct { members, .. } | BtfType::Union { members, .. } => {
            if is_renderable_c_type(ty) {
                generated.insert(id);
            }
            pending.extend(members.iter().map(|member| member.ty));
        }
        BtfType::Enum { .. } | BtfType::Enum64 { .. } => {
            if is_renderable_c_type(ty) {
                generated.insert(id);
            }
        }
        BtfType::DataSection { variables, .. } => {
            if is_renderable_c_type(ty) {
                generated.insert(id);
            }
            pending.extend(variables.iter().map(|variable| variable.ty));
        }
        BtfType::Pointer { ty }
        | BtfType::Variable { ty, .. }
        | BtfType::DeclarationTag { ty, .. }
        | BtfType::TypeTag { ty, .. } => {
            pending.push(*ty);
        }
        BtfType::Array { element_type, .. } => {
            pending.push(*element_type);
        }
        BtfType::Typedef { .. }
        | BtfType::Volatile { .. }
        | BtfType::Const { .. }
        | BtfType::Restrict { .. } => unreachable!("resolve_type strips BTF modifiers"),
        BtfType::Integer { .. }
        | BtfType::Float { .. }
        | BtfType::Forward { .. }
        | BtfType::Function { .. }
        | BtfType::FunctionPrototype { .. } => {}
    }
    Ok(())
}

fn render_c_struct_type(
    output: &mut String,
    btf: &Btf,
    names: &BtfTypeNames,
    id: TypeId,
    size: u32,
    members: &[crate::BtfMember],
) -> Result<()> {
    let name = names.name(id)?;
    let size = usize_from_btf(size, "structure size")?;
    let packed = c_struct_is_packed(btf, id, size, members)?;
    let mut fields = Vec::new();
    let mut defaults = Vec::new();
    let mut field_names = HashSet::new();
    let mut manual_default = false;
    let mut force_tail_padding = false;
    let mut offset = 0_usize;

    for (index, member) in members.iter().enumerate() {
        if member.bitfield_size.is_some() || member.bit_offset % 8 != 0 {
            force_tail_padding = true;
            continue;
        }
        force_tail_padding = false;
        let member_offset = usize_from_btf(member.bit_offset / 8, "structure member offset")?;
        let padding = required_c_padding(btf, offset, member_offset, member.ty, packed, false)?;
        push_c_padding_field(
            &mut fields,
            &mut defaults,
            &mut field_names,
            &mut manual_default,
            offset,
            padding,
        );

        let field_name = c_member_field_name(btf, names, member, index, &mut field_names)?;
        let field_type = render_c_field_type(btf, names, member.ty)?;
        let field_default = render_c_field_default(btf, names, member.ty)?;
        if c_type_needs_manual_default(btf, member.ty)? {
            manual_default = true;
        }
        fields.push(format!("    pub {field_name}: {field_type},"));
        defaults.push(format!("            {field_name}: {field_default}"));

        let field_size = btf.size_of(member.ty)?;
        offset = member_offset
            .checked_add(field_size)
            .ok_or_else(|| Error::Btf("structure member offset overflows usize".into()))?;
    }

    let padding = required_c_padding(btf, offset, size, id, packed, force_tail_padding)?;
    push_c_padding_field(
        &mut fields,
        &mut defaults,
        &mut field_names,
        &mut manual_default,
        offset,
        padding,
    );

    if manual_default {
        writeln!(output, "    #[derive(Debug, Copy, Clone)]").expect("String write");
    } else {
        writeln!(output, "    #[derive(Debug, Default, Copy, Clone)]").expect("String write");
    }
    let packed_repr = if packed { ", packed" } else { "" };
    writeln!(output, "    #[repr(C{packed_repr})]").expect("String write");
    writeln!(output, "    pub struct {name} {{").expect("String write");
    for field in fields {
        writeln!(output, "{field}").expect("String write");
    }
    writeln!(output, "    }}").expect("String write");

    if manual_default {
        writeln!(output, "    impl Default for {name} {{").expect("String write");
        writeln!(output, "        fn default() -> Self {{").expect("String write");
        writeln!(output, "            Self {{").expect("String write");
        for default in defaults {
            writeln!(output, "{default},").expect("String write");
        }
        writeln!(output, "            }}").expect("String write");
        writeln!(output, "        }}").expect("String write");
        writeln!(output, "    }}").expect("String write");
    }
    Ok(())
}

fn render_c_union_type(
    output: &mut String,
    btf: &Btf,
    names: &BtfTypeNames,
    id: TypeId,
    size: u32,
    members: &[crate::BtfMember],
) -> Result<()> {
    let name = names.name(id)?;
    let size = usize_from_btf(size, "union size")?;
    let mut fields = Vec::new();
    let mut defaults = Vec::new();
    let mut field_names = HashSet::new();
    let mut maximum_field_size = 0_usize;

    for (index, member) in members.iter().enumerate() {
        if member.bitfield_size.is_some() {
            continue;
        }
        let field_name = c_member_field_name(btf, names, member, index, &mut field_names)?;
        let field_type = render_c_field_type(btf, names, member.ty)?;
        let field_default = render_c_field_default(btf, names, member.ty)?;
        maximum_field_size = maximum_field_size.max(btf.size_of(member.ty)?);
        fields.push(format!("    pub {field_name}: {field_type},"));
        defaults.push(format!("            {field_name}: {field_default}"));
    }

    if fields.is_empty() {
        return render_c_opaque_struct(output, name, size);
    }
    if maximum_field_size < size {
        let field_name = unique_identifier("__data".into(), &mut field_names);
        fields.push(format!("    pub {field_name}: [u8; {size}],"));
    }

    writeln!(output, "    #[derive(Copy, Clone)]").expect("String write");
    writeln!(output, "    #[repr(C)]").expect("String write");
    writeln!(output, "    pub union {name} {{").expect("String write");
    for field in fields {
        writeln!(output, "{field}").expect("String write");
    }
    writeln!(output, "    }}").expect("String write");
    writeln!(output, "    impl std::fmt::Debug for {name} {{").expect("String write");
    writeln!(
        output,
        "        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {{"
    )
    .expect("String write");
    writeln!(output, "            write!(f, \"(???)\")").expect("String write");
    writeln!(output, "        }}").expect("String write");
    writeln!(output, "    }}").expect("String write");
    writeln!(output, "    impl Default for {name} {{").expect("String write");
    writeln!(output, "        fn default() -> Self {{").expect("String write");
    writeln!(output, "            Self {{").expect("String write");
    writeln!(output, "{},", defaults[0]).expect("String write");
    writeln!(output, "            }}").expect("String write");
    writeln!(output, "        }}").expect("String write");
    writeln!(output, "    }}").expect("String write");
    Ok(())
}

fn render_c_enum_type(
    output: &mut String,
    names: &BtfTypeNames,
    id: TypeId,
    size: u32,
    signed: bool,
    values: &[BtfEnumValue],
) -> Result<()> {
    let name = names.name(id)?;
    let bits = match size {
        1 | 2 | 4 | 8 | 16 => size * 8,
        _ => return Err(Error::Btf(format!("unsupported enum size {size}"))),
    };
    let prefix = if signed { 'i' } else { 'u' };
    let mut variant_names = HashSet::new();
    let mut first_variant = None;

    writeln!(output, "    #[derive(Debug, Copy, Clone, Eq, PartialEq)]").expect("String write");
    writeln!(output, "    #[repr(transparent)]").expect("String write");
    writeln!(output, "    pub struct {name}(pub {prefix}{bits});").expect("String write");
    writeln!(output, "    #[allow(non_upper_case_globals)]").expect("String write");
    writeln!(output, "    impl {name} {{").expect("String write");
    for (index, value) in values.iter().enumerate() {
        let base_name = if value.name.is_empty() {
            format!("value_{index}")
        } else {
            value.name.clone()
        };
        let variant = unique_identifier(c_identifier(&base_name, "value"), &mut variant_names);
        first_variant.get_or_insert_with(|| variant.clone());
        let literal = c_enum_literal(value.value, signed, bits);
        writeln!(
            output,
            "        pub const {variant}: Self = Self({literal});"
        )
        .expect("String write");
    }
    writeln!(output, "    }}").expect("String write");
    writeln!(output, "    impl Default for {name} {{").expect("String write");
    if let Some(first_variant) = first_variant {
        writeln!(
            output,
            "        fn default() -> Self {{ Self::{first_variant} }}"
        )
        .expect("String write");
    } else {
        writeln!(output, "        fn default() -> Self {{ Self(0) }}").expect("String write");
    }
    writeln!(output, "    }}").expect("String write");
    Ok(())
}

fn render_c_data_section_type(
    output: &mut String,
    btf: &Btf,
    names: &BtfTypeNames,
    id: TypeId,
    size: u32,
    variables: &[BtfVariable],
) -> Result<()> {
    let name = names.name(id)?;
    let size = usize_from_btf(size, "data section size")?;
    let mut fields = Vec::new();
    let mut defaults = Vec::new();
    let mut field_names = HashSet::new();
    let mut manual_default = false;
    let mut offset = 0_usize;

    for (index, data_variable) in variables.iter().enumerate() {
        let variable = btf.type_by_id(data_variable.ty).ok_or_else(|| {
            Error::Btf(format!(
                "data section type {} references missing variable type {}",
                id.0, data_variable.ty.0
            ))
        })?;
        let BtfType::Variable {
            name: variable_name,
            ty,
            linkage,
        } = variable
        else {
            return Err(Error::Btf(format!(
                "data section type {} entry {} is not a variable",
                id.0, data_variable.ty.0
            )));
        };
        if *linkage == 0 {
            continue;
        }
        let variable_offset = usize_from_btf(data_variable.offset, "data section variable offset")?;
        let padding =
            required_c_padding(btf, offset, variable_offset, data_variable.ty, false, false)?;
        push_c_padding_field(
            &mut fields,
            &mut defaults,
            &mut field_names,
            &mut manual_default,
            offset,
            padding,
        );

        let base_name = if variable_name.is_empty() {
            format!("variable_{index}")
        } else {
            variable_name.clone()
        };
        let field_name = unique_identifier(c_identifier(&base_name, "variable"), &mut field_names);
        let field_type = render_c_field_type(btf, names, *ty)?;
        let field_default = render_c_field_default(btf, names, *ty)?;
        if c_type_needs_manual_default(btf, *ty)? {
            manual_default = true;
        }
        fields.push(format!("    pub {field_name}: {field_type},"));
        defaults.push(format!("            {field_name}: {field_default}"));
        offset = variable_offset
            .checked_add(usize_from_btf(
                data_variable.size,
                "data section variable size",
            )?)
            .ok_or_else(|| Error::Btf("data section variable offset overflows usize".into()))?;
    }

    if fields.is_empty() && size != 0 {
        fields.push(format!("    pub __data: [u8; {size}],"));
        defaults.push(format!("            __data: [u8::default(); {size}]"));
        if size > 32 {
            manual_default = true;
        }
    } else if offset < size {
        push_c_padding_field(
            &mut fields,
            &mut defaults,
            &mut field_names,
            &mut manual_default,
            offset,
            size - offset,
        );
    }

    if manual_default {
        writeln!(output, "    #[derive(Debug, Copy, Clone)]").expect("String write");
    } else {
        writeln!(output, "    #[derive(Debug, Default, Copy, Clone)]").expect("String write");
    }
    writeln!(output, "    #[repr(C)]").expect("String write");
    writeln!(output, "    pub struct {name} {{").expect("String write");
    for field in fields {
        writeln!(output, "{field}").expect("String write");
    }
    writeln!(output, "    }}").expect("String write");
    if manual_default {
        writeln!(output, "    impl Default for {name} {{").expect("String write");
        writeln!(output, "        fn default() -> Self {{").expect("String write");
        writeln!(output, "            Self {{").expect("String write");
        for default in defaults {
            writeln!(output, "{default},").expect("String write");
        }
        writeln!(output, "            }}").expect("String write");
        writeln!(output, "        }}").expect("String write");
        writeln!(output, "    }}").expect("String write");
    }
    Ok(())
}

fn render_c_opaque_struct(output: &mut String, name: &str, size: usize) -> Result<()> {
    if size > 32 {
        writeln!(output, "    #[derive(Debug, Copy, Clone)]").expect("String write");
    } else {
        writeln!(output, "    #[derive(Debug, Default, Copy, Clone)]").expect("String write");
    }
    writeln!(output, "    #[repr(C)]").expect("String write");
    writeln!(output, "    pub struct {name} {{").expect("String write");
    writeln!(output, "        pub __data: [u8; {size}],").expect("String write");
    writeln!(output, "    }}").expect("String write");
    if size > 32 {
        writeln!(output, "    impl Default for {name} {{").expect("String write");
        writeln!(output, "        fn default() -> Self {{").expect("String write");
        writeln!(output, "            Self {{").expect("String write");
        writeln!(output, "                __data: [u8::default(); {size}],").expect("String write");
        writeln!(output, "            }}").expect("String write");
        writeln!(output, "        }}").expect("String write");
        writeln!(output, "    }}").expect("String write");
    }
    Ok(())
}

fn c_member_field_name(
    btf: &Btf,
    names: &BtfTypeNames,
    member: &crate::BtfMember,
    index: usize,
    field_names: &mut HashSet<String>,
) -> Result<String> {
    let base = if member.name.is_empty() {
        names
            .name_for_type(btf, member.ty)
            .map(ToOwned::to_owned)
            .unwrap_or_else(|_| format!("field_{index}"))
    } else {
        c_identifier(&member.name, "field")
    };
    Ok(unique_identifier(base, field_names))
}

fn render_c_field_type(btf: &Btf, names: &BtfTypeNames, id: TypeId) -> Result<String> {
    let rust_type = render_c_type_ref(btf, names, id)?;
    if c_type_is_unsafe(btf, id)? {
        Ok(format!("std::mem::MaybeUninit<{rust_type}>"))
    } else {
        Ok(rust_type)
    }
}

fn render_c_field_default(btf: &Btf, names: &BtfTypeNames, id: TypeId) -> Result<String> {
    let default = render_c_default_expr(btf, names, id)?;
    if c_type_is_unsafe(btf, id)? {
        Ok(format!("std::mem::MaybeUninit::new({default})"))
    } else {
        Ok(default)
    }
}

fn render_c_type_ref(btf: &Btf, names: &BtfTypeNames, id: TypeId) -> Result<String> {
    if id == TypeId::VOID {
        return Ok("std::ffi::c_void".into());
    }
    let id = btf.resolve_type(id)?;
    if id == TypeId::VOID {
        return Ok("std::ffi::c_void".into());
    }
    let ty = btf
        .type_by_id(id)
        .ok_or_else(|| Error::Btf(format!("type ID {} does not exist", id.0)))?;
    match ty {
        BtfType::Integer { size, encoding, .. } => {
            render_c_integer_type(*size, encoding.signed, encoding.boolean, encoding.bits)
        }
        BtfType::Pointer { ty } => {
            let pointee = render_c_type_ref(btf, names, *ty)?;
            Ok(format!("*mut {pointee}"))
        }
        BtfType::Array {
            element_type,
            count,
            ..
        } => {
            let element = render_c_type_ref(btf, names, *element_type)?;
            Ok(format!("[{element}; {count}]"))
        }
        BtfType::Struct { .. }
        | BtfType::Union { .. }
        | BtfType::Enum { .. }
        | BtfType::Enum64 { .. }
        | BtfType::DataSection { .. } => Ok(names.name(id)?.to_owned()),
        BtfType::Float { size, .. } => match size {
            4 => Ok("f32".into()),
            8 => Ok("f64".into()),
            _ => Err(Error::Btf(format!("unsupported float size {size}"))),
        },
        BtfType::Forward { .. } | BtfType::Function { .. } | BtfType::FunctionPrototype { .. } => {
            Ok("std::ffi::c_void".into())
        }
        BtfType::Variable { ty, .. }
        | BtfType::DeclarationTag { ty, .. }
        | BtfType::TypeTag { ty, .. } => render_c_type_ref(btf, names, *ty),
        BtfType::Typedef { .. }
        | BtfType::Volatile { .. }
        | BtfType::Const { .. }
        | BtfType::Restrict { .. } => unreachable!("resolve_type strips BTF modifiers"),
    }
}

fn render_c_default_expr(btf: &Btf, names: &BtfTypeNames, id: TypeId) -> Result<String> {
    if id == TypeId::VOID {
        return Err(Error::Btf("void has no default value".into()));
    }
    let id = btf.resolve_type(id)?;
    if id == TypeId::VOID {
        return Err(Error::Btf("void has no default value".into()));
    }
    let ty = btf
        .type_by_id(id)
        .ok_or_else(|| Error::Btf(format!("type ID {} does not exist", id.0)))?;
    match ty {
        BtfType::Integer { .. } | BtfType::Float { .. } => {
            Ok(format!("{}::default()", render_c_type_ref(btf, names, id)?))
        }
        BtfType::Pointer { .. } => Ok("std::ptr::null_mut()".into()),
        BtfType::Array {
            element_type,
            count,
            ..
        } => {
            let element = render_c_default_expr(btf, names, *element_type)?;
            Ok(format!("[{element}; {count}]"))
        }
        BtfType::Struct { .. }
        | BtfType::Union { .. }
        | BtfType::Enum { .. }
        | BtfType::Enum64 { .. }
        | BtfType::DataSection { .. } => Ok(format!("{}::default()", names.name(id)?)),
        BtfType::Variable { ty, .. }
        | BtfType::DeclarationTag { ty, .. }
        | BtfType::TypeTag { ty, .. } => render_c_default_expr(btf, names, *ty),
        BtfType::Forward { .. } | BtfType::Function { .. } | BtfType::FunctionPrototype { .. } => {
            Err(Error::Btf(format!(
                "{:?} type ID {} has no default value",
                ty.kind(),
                id.0
            )))
        }
        BtfType::Typedef { .. }
        | BtfType::Volatile { .. }
        | BtfType::Const { .. }
        | BtfType::Restrict { .. } => unreachable!("resolve_type strips BTF modifiers"),
    }
}

fn c_type_is_unsafe(btf: &Btf, id: TypeId) -> Result<bool> {
    if id == TypeId::VOID {
        return Ok(false);
    }
    let id = btf.resolve_type(id)?;
    if id == TypeId::VOID {
        return Ok(false);
    }
    let ty = btf
        .type_by_id(id)
        .ok_or_else(|| Error::Btf(format!("type ID {} does not exist", id.0)))?;
    match ty {
        BtfType::Integer { encoding, .. } => Ok(encoding.boolean),
        BtfType::Variable { ty, .. }
        | BtfType::DeclarationTag { ty, .. }
        | BtfType::TypeTag { ty, .. } => c_type_is_unsafe(btf, *ty),
        _ => Ok(false),
    }
}

fn c_type_needs_manual_default(btf: &Btf, id: TypeId) -> Result<bool> {
    if id == TypeId::VOID {
        return Ok(false);
    }
    let id = btf.resolve_type(id)?;
    if id == TypeId::VOID {
        return Ok(false);
    }
    let ty = btf
        .type_by_id(id)
        .ok_or_else(|| Error::Btf(format!("type ID {} does not exist", id.0)))?;
    match ty {
        BtfType::Integer { encoding, .. } => Ok(encoding.boolean),
        BtfType::Pointer { .. } => Ok(true),
        BtfType::Array {
            element_type,
            count,
            ..
        } => Ok(*count > 32 || c_type_needs_manual_default(btf, *element_type)?),
        BtfType::Variable { ty, .. }
        | BtfType::DeclarationTag { ty, .. }
        | BtfType::TypeTag { ty, .. } => c_type_needs_manual_default(btf, *ty),
        _ => Ok(false),
    }
}

fn c_struct_is_packed(
    btf: &Btf,
    id: TypeId,
    size: usize,
    members: &[crate::BtfMember],
) -> Result<bool> {
    let align = btf.alignment_of(id)?;
    if align > 1 && size % align != 0 {
        return Ok(true);
    }
    for member in members {
        if member.bitfield_size.is_some() {
            continue;
        }
        let member_alignment = btf.alignment_of(member.ty)?;
        if member_alignment > 1 && u64::from(member.bit_offset) % (8 * member_alignment as u64) != 0
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn required_c_padding(
    btf: &Btf,
    current_offset: usize,
    required_offset: usize,
    id: TypeId,
    packed: bool,
    force: bool,
) -> Result<usize> {
    if current_offset > required_offset {
        return Err(Error::Btf(format!(
            "current offset ({current_offset}) is ahead of required offset ({required_offset})"
        )));
    }
    let alignment = if packed {
        1
    } else {
        btf.alignment_of(id)?.clamp(1, 4)
    };
    let aligned = current_offset
        .checked_add(alignment - 1)
        .ok_or_else(|| Error::Btf("offset alignment overflows usize".into()))?
        / alignment
        * alignment;
    if !force && aligned == required_offset {
        Ok(0)
    } else {
        Ok(required_offset - current_offset)
    }
}

fn push_c_padding_field(
    fields: &mut Vec<String>,
    defaults: &mut Vec<String>,
    field_names: &mut HashSet<String>,
    manual_default: &mut bool,
    offset: usize,
    padding: usize,
) {
    if padding == 0 {
        return;
    }
    let field_name = unique_identifier(format!("__pad_{offset}"), field_names);
    fields.push(format!("    pub {field_name}: [u8; {padding}],"));
    defaults.push(format!(
        "            {field_name}: [u8::default(); {padding}]"
    ));
    if padding > 32 {
        *manual_default = true;
    }
}

fn render_c_integer_type(size: u32, signed: bool, boolean: bool, bits: u8) -> Result<String> {
    let bits = if bits == 0 {
        size.checked_mul(8)
            .ok_or_else(|| Error::Btf("integer bit width overflows u32".into()))?
    } else {
        u32::from(bits)
    };
    let bytes = bits.div_ceil(8);
    let width = match bytes {
        1 | 2 | 4 | 8 | 16 => bytes * 8,
        _ => return Err(Error::Btf(format!("unsupported integer bit width {bits}"))),
    };
    if boolean {
        Ok("bool".into())
    } else if signed {
        Ok(format!("i{width}"))
    } else {
        Ok(format!("u{width}"))
    }
}

fn c_type_base_name(ty: &BtfType, anonymous_index: usize) -> Option<String> {
    match ty {
        BtfType::Struct { name, .. }
        | BtfType::Union { name, .. }
        | BtfType::Enum { name, .. }
        | BtfType::Enum64 { name, .. } => {
            if name.is_empty() {
                Some(format!("__anon_{anonymous_index}"))
            } else {
                Some(c_identifier(name, "type"))
            }
        }
        BtfType::DataSection { name, .. } => {
            Some(c_identifier(&data_section_type_name(name), "data"))
        }
        _ => None,
    }
}

fn is_renderable_c_type(ty: &BtfType) -> bool {
    match ty {
        BtfType::Struct { .. }
        | BtfType::Union { .. }
        | BtfType::Enum { .. }
        | BtfType::Enum64 { .. } => true,
        BtfType::DataSection { name, .. } => data_section_type_name(name) != "ksyms",
        _ => false,
    }
}

fn insert_type_alias(aliases: &mut HashMap<String, Vec<TypeId>>, alias: &str, id: TypeId) {
    aliases.entry(alias.into()).or_default().push(id);
}

fn data_section_type_name(name: &str) -> String {
    name.trim_start_matches('.').replace('.', "_")
}

fn unique_type_identifier(base: String, used: &mut HashMap<String, usize>) -> String {
    let count = used
        .entry(base.clone())
        .and_modify(|count| *count += 1)
        .or_insert(1);
    if *count == 1 {
        base
    } else if let Some(raw) = base.strip_prefix("r#") {
        format!("{raw}_{count}")
    } else {
        format!("{base}_{count}")
    }
}

fn c_identifier(name: &str, fallback: &str) -> String {
    let mut output = String::new();
    let mut previous_was_separator = false;
    for character in name.chars() {
        if character == '_' || character.is_ascii_alphanumeric() {
            if output.is_empty() && character.is_ascii_digit() {
                output.push('_');
            }
            output.push(character);
            previous_was_separator = false;
        } else if !previous_was_separator {
            if !output.is_empty() {
                output.push('_');
            }
            previous_was_separator = true;
        }
    }
    while output.ends_with('_') && output.len() > 1 {
        output.pop();
    }
    if output.is_empty() || output == "_" {
        output = fallback.into();
    }
    if output.as_bytes()[0].is_ascii_digit() {
        output.insert(0, '_');
    }
    if rust_keyword(&output) {
        match output.as_str() {
            "Self" | "crate" | "self" | "super" => output.push('_'),
            _ => output = format!("r#{output}"),
        }
    }
    output
}

fn c_enum_literal(value: i64, signed: bool, bits: u32) -> String {
    if signed || value >= 0 {
        value.to_string()
    } else {
        format!("({value}i64 as u{bits})")
    }
}

fn usize_from_btf(value: u32, context: &str) -> Result<usize> {
    usize::try_from(value).map_err(|_| Error::Btf(format!("{context} does not fit usize")))
}

fn collect_data_sections(
    object: &Object,
    skeleton_type: &str,
    crate_path: &str,
) -> Result<(Vec<DataSectionItem>, String)> {
    let Some(btf) = object.btf() else {
        return Ok((Vec::new(), String::new()));
    };
    let mut sections = Vec::new();
    let mut section_methods = HashSet::new();
    let mut definitions = String::new();
    for (id, ty) in btf.types() {
        let BtfType::DataSection {
            name, variables, ..
        } = ty
        else {
            continue;
        };
        let Some(map) = object
            .maps()
            .find(|map| map.btf_value_type() == id && map.initial_value().is_some())
        else {
            continue;
        };
        let base_method = snake_identifier(name.trim_start_matches('.'));
        let method = unique_identifier(base_method, &mut section_methods);
        let section_type = format!("{skeleton_type}{}", pascal_identifier(&method));
        let mut variable_methods = HashSet::new();
        let mut data_variables = Vec::new();
        for variable in variables {
            let BtfType::Variable {
                name: variable_name,
                ty,
                linkage,
            } = btf.type_by_id(variable.ty).ok_or_else(|| {
                Error::Btf(format!(
                    "data section `{name}` references missing variable type {}",
                    variable.ty.0
                ))
            })?
            else {
                return Err(Error::Btf(format!(
                    "data section `{name}` type {} is not a variable",
                    variable.ty.0
                )));
            };
            if *linkage == 0 {
                continue;
            }
            let method = unique_identifier(
                snake_identifier(if variable_name.is_empty() {
                    "variable"
                } else {
                    variable_name
                }),
                &mut variable_methods,
            );
            let suggested = format!("{section_type}{}", pascal_identifier(&method));
            let expected_size = usize::try_from(variable.size)
                .map_err(|_| Error::Btf("data variable size does not fit usize".into()))?;
            let rendered = render_data_value_type(
                btf,
                *ty,
                &suggested,
                crate_path,
                &mut definitions,
                &mut HashSet::new(),
            )?;
            let rust_type = match rendered {
                Some((rust_type, size)) if size == expected_size => rust_type,
                _ => format!("[u8; {expected_size}]"),
            };
            data_variables.push(DataVariable {
                source: variable_name.clone(),
                method,
                offset: usize::try_from(variable.offset)
                    .map_err(|_| Error::Btf("data variable offset does not fit usize".into()))?,
                rust_type,
            });
        }
        sections.push(DataSectionItem {
            source: name.clone(),
            map: map.name().to_owned(),
            method,
            shared_type: format!("Open{section_type}"),
            mutable_type: format!("Open{section_type}Mut"),
            loaded_shared_type: format!("Loaded{section_type}"),
            loaded_mutable_type: format!("Loaded{section_type}Mut"),
            read_only: map.flags().contains(MapFlags::PROGRAM_READ_ONLY),
            variables: data_variables,
        });
    }
    Ok((sections, definitions))
}

fn render_data_value_type(
    btf: &Btf,
    id: TypeId,
    suggested: &str,
    crate_path: &str,
    definitions: &mut String,
    stack: &mut HashSet<TypeId>,
) -> Result<Option<(String, usize)>> {
    let id = btf.resolve_type(id)?;
    let Some(ty) = btf.type_by_id(id) else {
        return Ok(None);
    };
    let scalar = |signed: bool, size: u32| {
        let prefix = if signed { 'i' } else { 'u' };
        match size {
            1 | 2 | 4 | 8 | 16 => Some((format!("{prefix}{}", size * 8), size as usize)),
            _ => None,
        }
    };
    match ty {
        BtfType::Integer { size, encoding, .. } => {
            if encoding.offset != 0 || u32::from(encoding.bits) > size.saturating_mul(8) {
                return Ok(None);
            }
            if encoding.boolean && *size == 1 {
                Ok(Some(("bool".into(), 1)))
            } else {
                Ok(scalar(encoding.signed, *size))
            }
        }
        BtfType::Enum { size, signed, .. } | BtfType::Enum64 { size, signed, .. } => {
            Ok(scalar(*signed, *size))
        }
        BtfType::Float { size, .. } => Ok(match size {
            4 => Some(("f32".into(), 4)),
            8 => Some(("f64".into(), 8)),
            _ => None,
        }),
        BtfType::Pointer { .. } => Ok(Some(("u64".into(), 8))),
        BtfType::Array {
            element_type,
            count,
            ..
        } => {
            let nested_name = format!("{suggested}Element");
            let Some((element, element_size)) = render_data_value_type(
                btf,
                *element_type,
                &nested_name,
                crate_path,
                definitions,
                stack,
            )?
            else {
                return Ok(None);
            };
            let count = usize::try_from(*count)
                .map_err(|_| Error::Btf("array element count does not fit usize".into()))?;
            let size = element_size
                .checked_mul(count)
                .ok_or_else(|| Error::Btf("generated data array size overflow".into()))?;
            Ok(Some((format!("[{element}; {count}]"), size)))
        }
        BtfType::Struct { size, members, .. } => {
            if !stack.insert(id) {
                return Ok(None);
            }
            let result = render_data_struct(
                btf,
                *size,
                members,
                suggested,
                crate_path,
                definitions,
                stack,
            );
            stack.remove(&id);
            result
        }
        BtfType::Variable { ty, .. } | BtfType::DeclarationTag { ty, .. } => {
            render_data_value_type(btf, *ty, suggested, crate_path, definitions, stack)
        }
        BtfType::Union { size, .. } => {
            let size = usize::try_from(*size)
                .map_err(|_| Error::Btf("union size does not fit usize".into()))?;
            Ok(Some((format!("[u8; {size}]"), size)))
        }
        _ => Ok(None),
    }
}

fn render_data_struct(
    btf: &Btf,
    size: u32,
    members: &[crate::BtfMember],
    suggested: &str,
    crate_path: &str,
    definitions: &mut String,
    stack: &mut HashSet<TypeId>,
) -> Result<Option<(String, usize)>> {
    let size = usize::try_from(size)
        .map_err(|_| Error::Btf("structure size does not fit usize".into()))?;
    let name = pascal_identifier(suggested);
    let mut fields = Vec::new();
    let mut field_names = HashSet::new();
    for (index, member) in members.iter().enumerate() {
        if member.bitfield_size.is_some() || member.bit_offset % 8 != 0 {
            return Ok(None);
        }
        let source = if member.name.is_empty() {
            format!("field_{index}")
        } else {
            member.name.clone()
        };
        let field = unique_identifier(snake_identifier(&source), &mut field_names);
        let nested_name = format!("{name}{}", pascal_identifier(&field));
        let Some((rust_type, field_size)) =
            render_data_value_type(btf, member.ty, &nested_name, crate_path, definitions, stack)?
        else {
            return Ok(None);
        };
        let offset = usize::try_from(member.bit_offset / 8)
            .map_err(|_| Error::Btf("structure member offset does not fit usize".into()))?;
        if offset.checked_add(field_size).is_none_or(|end| end > size) {
            return Ok(None);
        }
        fields.push((source, field, rust_type, offset));
    }

    writeln!(
        definitions,
        "/// Owned, layout-independent value decoded from BTF type `{}`.\n\
         #[derive(Clone, Debug, PartialEq)]\n\
         #[allow(clippy::derive_partial_eq_without_eq)]\n\
         pub struct {name} {{",
        doc_text(suggested)
    )
    .expect("String write");
    for (source, field, rust_type, _) in &fields {
        writeln!(
            definitions,
            "    /// Value of BTF member `{}`.\n    pub {field}: {rust_type},",
            doc_text(source)
        )
        .expect("String write");
    }
    writeln!(
        definitions,
        "}}\n\
         \n\
         impl {crate_path}::DataValue for {name} {{\n\
             const SIZE: usize = {size};\n\
             \n\
             fn decode(bytes: &[u8]) -> {crate_path}::Result<Self> {{\n\
                 let section = {crate_path}::DataSection::new(bytes);\n\
                 Ok(Self {{"
    )
    .expect("String write");
    for (_, field, rust_type, offset) in &fields {
        writeln!(
            definitions,
            "            {field}: section.read::<{rust_type}>({offset})?,"
        )
        .expect("String write");
    }
    writeln!(
        definitions,
        "        }})\n\
             }}\n\
             \n\
             fn encode(&self, bytes: &mut [u8]) -> {crate_path}::Result<()> {{\n\
                 let mut section = {crate_path}::DataSectionMut::new(bytes);"
    )
    .expect("String write");
    for (_, field, _, offset) in &fields {
        writeln!(
            definitions,
            "        section.write({offset}, &self.{field})?;"
        )
        .expect("String write");
    }
    writeln!(definitions, "        Ok(())\n    }}\n}}\n").expect("String write");
    Ok(Some((name, size)))
}

fn render_data_accessors(
    output: &mut String,
    sections: &[DataSectionItem],
    open_skeleton: &str,
    crate_path: &str,
) {
    if sections.is_empty() {
        return;
    }
    writeln!(output, "impl {open_skeleton} {{").expect("String write");
    for section in sections {
        writeln!(
            output,
            "    /// Borrows typed values in the `{}` data section.\n\
             pub fn {}(&self) -> {crate_path}::Result<{}<'_>> {{\n\
                 let bytes = self.object.map({:?})?.initial_value().ok_or_else(|| {{\n\
                     {crate_path}::Error::InvalidObject({:?}.into())\n\
                 }})?;\n\
                 Ok({} {{ data: {crate_path}::DataSection::new(bytes) }})\n\
             }}\n\
             \n\
             /// Mutably borrows typed values in the `{}` data section.\n\
             pub fn {}_mut(&mut self) -> {crate_path}::Result<{}<'_>> {{\n\
                 let bytes = self.object.map_mut({:?})?.initial_value_mut().ok_or_else(|| {{\n\
                     {crate_path}::Error::InvalidObject({:?}.into())\n\
                 }})?;\n\
                 Ok({} {{ data: {crate_path}::DataSectionMut::new(bytes) }})\n\
             }}",
            doc_text(&section.source),
            section.method,
            section.shared_type,
            section.map,
            format!("map `{}` has no initial data", section.map),
            section.shared_type,
            doc_text(&section.source),
            section.method,
            section.mutable_type,
            section.map,
            format!("map `{}` has no initial data", section.map),
            section.mutable_type,
        )
        .expect("String write");
    }
    writeln!(output, "}}\n").expect("String write");

    for section in sections {
        writeln!(
            output,
            "/// Typed immutable view of the `{}` global data section.\n\
             #[derive(Clone, Copy, Debug)]\n\
             pub struct {}<'data> {{ data: {crate_path}::DataSection<'data> }}\n\
             \n\
             impl<'data> {}<'data> {{",
            doc_text(&section.source),
            section.shared_type,
            section.shared_type
        )
        .expect("String write");
        for variable in &section.variables {
            writeln!(
                output,
                "    /// Decodes global `{}`.\n\
                 pub fn {}(&self) -> {crate_path}::Result<{}> {{\n\
                     self.data.read::<{}>({})\n\
                 }}",
                doc_text(&variable.source),
                variable.method,
                variable.rust_type,
                variable.rust_type,
                variable.offset
            )
            .expect("String write");
        }
        writeln!(output, "}}\n").expect("String write");

        writeln!(
            output,
            "/// Typed mutable view of the `{}` global data section.\n\
             #[derive(Debug)]\n\
             pub struct {}<'data> {{ data: {crate_path}::DataSectionMut<'data> }}\n\
             \n\
             impl<'data> {}<'data> {{",
            doc_text(&section.source),
            section.mutable_type,
            section.mutable_type
        )
        .expect("String write");
        for variable in &section.variables {
            writeln!(
                output,
                "    /// Decodes global `{}`.\n\
                 pub fn {}(&self) -> {crate_path}::Result<{}> {{\n\
                     self.data.read::<{}>({})\n\
                 }}\n\
                 \n\
                 /// Encodes global `{}` for use when the object is loaded.\n\
                 pub fn set_{}(&mut self, value: &{}) -> {crate_path}::Result<&mut Self> {{\n\
                     self.data.write({}, value)?;\n\
                     Ok(self)\n\
                 }}",
                doc_text(&variable.source),
                variable.method,
                variable.rust_type,
                variable.rust_type,
                variable.offset,
                doc_text(&variable.source),
                variable.method,
                variable.rust_type,
                variable.offset
            )
            .expect("String write");
        }
        writeln!(output, "}}\n").expect("String write");
    }
}

fn render_loaded_data_accessors(
    output: &mut String,
    sections: &[DataSectionItem],
    loaded_skeleton: &str,
    crate_path: &str,
) {
    if sections.is_empty() {
        return;
    }
    writeln!(output, "impl {loaded_skeleton} {{").expect("String write");
    for section in sections {
        let constructor = if section.read_only {
            "new_at"
        } else {
            "from_mutable_at"
        };
        writeln!(
            output,
            "    /// Borrows live typed values in the `{}` data section.\n\
             pub fn {}(&self) -> {crate_path}::Result<{}<'_>> {{\n\
                 let offset = self.object.map({:?})?.spec().initial_value_offset() as usize;\n\
                 Ok({} {{\n\
                     data: {crate_path}::MappedDataSection::{}(&self.{}_memory, offset),\n\
                 }})\n\
             }}",
            doc_text(&section.source),
            section.method,
            section.loaded_shared_type,
            section.map,
            section.loaded_shared_type,
            constructor,
            section.method,
        )
        .expect("String write");
        if !section.read_only {
            writeln!(
                output,
                "\n\
                 /// Mutably borrows live typed values in the `{}` data section.\n\
                 pub fn {}_mut(&mut self) -> {crate_path}::Result<{}<'_>> {{\n\
                     let offset = self.object.map({:?})?.spec().initial_value_offset() as usize;\n\
                     Ok({} {{\n\
                         data: {crate_path}::MappedDataSectionMut::new_at(&mut self.{}_memory, offset),\n\
                     }})\n\
                 }}",
                doc_text(&section.source),
                section.method,
                section.loaded_mutable_type,
                section.map,
                section.loaded_mutable_type,
                section.method,
            )
            .expect("String write");
        }
    }
    writeln!(output, "}}\n").expect("String write");

    for section in sections {
        writeln!(
            output,
            "/// Typed live view of the `{}` global data section.\n\
             #[derive(Debug)]\n\
             pub struct {}<'data> {{ data: {crate_path}::MappedDataSection<'data> }}\n\
             \n\
             impl<'data> {}<'data> {{",
            doc_text(&section.source),
            section.loaded_shared_type,
            section.loaded_shared_type,
        )
        .expect("String write");
        for variable in &section.variables {
            writeln!(
                output,
                "    /// Decodes a snapshot of global `{}`.\n\
                 pub fn {}(&self) -> {crate_path}::Result<{}> {{\n\
                     self.data.read::<{}>({})\n\
                 }}",
                doc_text(&variable.source),
                variable.method,
                variable.rust_type,
                variable.rust_type,
                variable.offset,
            )
            .expect("String write");
        }
        writeln!(output, "}}\n").expect("String write");

        if !section.read_only {
            writeln!(
                output,
                "/// Typed mutable live view of the `{}` global data section.\n\
                 #[derive(Debug)]\n\
                 pub struct {}<'data> {{ data: {crate_path}::MappedDataSectionMut<'data> }}\n\
                 \n\
                 impl<'data> {}<'data> {{",
                doc_text(&section.source),
                section.loaded_mutable_type,
                section.loaded_mutable_type,
            )
            .expect("String write");
            for variable in &section.variables {
                writeln!(
                    output,
                    "    /// Decodes a snapshot of global `{}`.\n\
                     pub fn {}(&self) -> {crate_path}::Result<{}> {{\n\
                         self.data.read::<{}>({})\n\
                     }}\n\
                     \n\
                     /// Encodes global `{}` into live map memory.\n\
                     pub fn set_{}(&mut self, value: &{}) -> {crate_path}::Result<&mut Self> {{\n\
                         self.data.write({}, value)?;\n\
                         Ok(self)\n\
                     }}",
                    doc_text(&variable.source),
                    variable.method,
                    variable.rust_type,
                    variable.rust_type,
                    variable.offset,
                    doc_text(&variable.source),
                    variable.method,
                    variable.rust_type,
                    variable.offset,
                )
                .expect("String write");
            }
            writeln!(output, "}}\n").expect("String write");
        }
    }
}

fn render_open_map_accessors(
    output: &mut String,
    maps: &[NamedItem],
    shared: &str,
    mutable: &str,
    crate_path: &str,
) {
    writeln!(
        output,
        "/// Named immutable access to open map specifications.\n\
         #[derive(Clone, Copy, Debug)]\n\
         pub struct {shared}<'object> {{ object: &'object {crate_path}::Object }}\n\
         \n\
         impl<'object> {shared}<'object> {{"
    )
    .expect("String write");
    for map in maps {
        writeln!(
            output,
            "    /// Borrows the `{}` map specification.\n\
             pub fn {}(&self) -> {crate_path}::Result<&'object {crate_path}::MapSpec> {{\n\
                 self.object.map({:?})\n\
             }}",
            doc_text(&map.source),
            map.method,
            map.source
        )
        .expect("String write");
    }
    writeln!(output, "}}\n").expect("String write");

    writeln!(
        output,
        "/// Named mutable access to open map specifications.\n\
         #[derive(Debug)]\n\
         pub struct {mutable}<'object> {{ object: &'object mut {crate_path}::Object }}\n\
         \n\
         impl<'object> {mutable}<'object> {{"
    )
    .expect("String write");
    for map in maps {
        writeln!(
            output,
            "    /// Mutably borrows the `{}` map specification.\n\
             pub fn {}(&mut self) -> {crate_path}::Result<&mut {crate_path}::MapSpec> {{\n\
                 self.object.map_mut({:?})\n\
             }}\n\
             \n\
             /// Reuses an already loaded map for `{}`.\n\
             pub fn reuse_{}(&mut self, map: &{crate_path}::Map) -> {crate_path}::Result<&mut Self> {{\n\
                 self.object.reuse_map({:?}, map)?;\n\
                 Ok(self)\n\
             }}",
            doc_text(&map.source),
            map.method,
            map.source,
            doc_text(&map.source),
            map.method,
            map.source,
        )
        .expect("String write");
    }
    writeln!(output, "}}\n").expect("String write");
}

fn render_open_program_accessors(
    output: &mut String,
    programs: &[NamedItem],
    shared: &str,
    mutable: &str,
    crate_path: &str,
) {
    writeln!(
        output,
        "/// Named immutable access to open program specifications.\n\
         #[derive(Clone, Copy, Debug)]\n\
         pub struct {shared}<'object> {{ object: &'object {crate_path}::Object }}\n\
         \n\
         impl<'object> {shared}<'object> {{"
    )
    .expect("String write");
    for program in programs {
        writeln!(
            output,
            "    /// Borrows the `{}` program specification.\n\
             pub fn {}(&self) -> {crate_path}::Result<&'object {crate_path}::ProgramSpec> {{\n\
                 self.object.program({:?})\n\
             }}",
            doc_text(&program.source),
            program.method,
            program.source
        )
        .expect("String write");
    }
    writeln!(output, "}}\n").expect("String write");

    writeln!(
        output,
        "/// Named mutable access to open program specifications.\n\
         #[derive(Debug)]\n\
         pub struct {mutable}<'object> {{ object: &'object mut {crate_path}::Object }}\n\
         \n\
         impl<'object> {mutable}<'object> {{"
    )
    .expect("String write");
    for program in programs {
        writeln!(
            output,
            "    /// Mutably borrows the `{}` program specification.\n\
             pub fn {}(&mut self) -> {crate_path}::Result<&mut {crate_path}::ProgramSpec> {{\n\
                 self.object.program_mut({:?})\n\
             }}",
            doc_text(&program.source),
            program.method,
            program.source
        )
        .expect("String write");
    }
    writeln!(output, "}}\n").expect("String write");
}

fn render_loaded_accessors(
    output: &mut String,
    maps: &[NamedItem],
    programs: &[NamedItem],
    map_type: &str,
    program_type: &str,
    crate_path: &str,
) {
    writeln!(
        output,
        "/// Named access to loaded maps.\n\
         #[derive(Clone, Copy, Debug)]\n\
         pub struct {map_type}<'object> {{ object: &'object {crate_path}::LoadedObject }}\n\
         \n\
         impl<'object> {map_type}<'object> {{"
    )
    .expect("String write");
    for map in maps {
        writeln!(
            output,
            "    /// Borrows the loaded `{}` map.\n\
             pub fn {}(&self) -> {crate_path}::Result<&'object {crate_path}::Map> {{\n\
                 self.object.map({:?})\n\
             }}",
            doc_text(&map.source),
            map.method,
            map.source
        )
        .expect("String write");
    }
    writeln!(output, "}}\n").expect("String write");

    writeln!(
        output,
        "/// Named access to loaded programs.\n\
         #[derive(Clone, Copy, Debug)]\n\
         pub struct {program_type}<'object> {{ object: &'object {crate_path}::LoadedObject }}\n\
         \n\
         impl<'object> {program_type}<'object> {{"
    )
    .expect("String write");
    for program in programs {
        writeln!(
            output,
            "    /// Borrows the loaded `{}` program.\n\
             pub fn {}(&self) -> {crate_path}::Result<&'object {crate_path}::Program> {{\n\
                 self.object.program({:?})\n\
             }}",
            doc_text(&program.source),
            program.method,
            program.source
        )
        .expect("String write");
    }
    writeln!(output, "}}\n").expect("String write");
}

fn render_links(
    output: &mut String,
    programs: &[NamedItem],
    struct_ops_maps: &[NamedItem],
    links: &str,
    crate_path: &str,
) {
    writeln!(
        output,
        "/// Link slots for every program in the object.\n\
         ///\n\
         /// Programs needing runtime arguments can store manually created links here.\n\
         #[derive(Debug, Default)]\n\
         pub struct {links} {{"
    )
    .expect("String write");
    for program in programs {
        writeln!(
            output,
            "    {}: Option<{crate_path}::Link>,",
            program.method
        )
        .expect("String write");
    }
    for map in struct_ops_maps {
        writeln!(output, "    {}: Option<{crate_path}::Link>,", map.method).expect("String write");
    }
    writeln!(output, "}}\n\nimpl {links} {{").expect("String write");
    for program in programs {
        writeln!(
            output,
            "    /// Borrows the retained link for `{}` when attached.\n\
             pub fn {}(&self) -> Option<&{crate_path}::Link> {{ self.{}.as_ref() }}\n\
             \n\
             /// Replaces the retained link for `{}`.\n\
             pub fn set_{}(&mut self, link: {crate_path}::Link) -> Option<{crate_path}::Link> {{\n\
                 self.{}.replace(link)\n\
             }}\n\
             \n\
             /// Removes and returns the retained link for `{}`.\n\
             pub fn take_{}(&mut self) -> Option<{crate_path}::Link> {{ self.{}.take() }}",
            doc_text(&program.source),
            program.method,
            program.method,
            doc_text(&program.source),
            program.method,
            program.method,
            doc_text(&program.source),
            program.method,
            program.method
        )
        .expect("String write");
    }
    for map in struct_ops_maps {
        writeln!(
            output,
            "    /// Borrows the retained struct_ops link for `{}` when attached.\n\
             pub fn {}(&self) -> Option<&{crate_path}::Link> {{ self.{}.as_ref() }}\n\
             \n\
             /// Replaces the retained struct_ops link for `{}`.\n\
             pub fn set_{}(&mut self, link: {crate_path}::Link) -> Option<{crate_path}::Link> {{\n\
                 self.{}.replace(link)\n\
             }}\n\
             \n\
             /// Removes and returns the retained struct_ops link for `{}`.\n\
             pub fn take_{}(&mut self) -> Option<{crate_path}::Link> {{ self.{}.take() }}",
            doc_text(&map.source),
            map.method,
            map.method,
            doc_text(&map.source),
            map.method,
            map.method,
            doc_text(&map.source),
            map.method,
            map.method
        )
        .expect("String write");
    }
    writeln!(output, "}}\n").expect("String write");
}

fn validate_crate_path(path: &str) -> Result<()> {
    if path.is_empty()
        || path
            .split("::")
            .filter(|component| !component.is_empty())
            .any(|component| {
                !component.chars().enumerate().all(|(index, character)| {
                    character == '_'
                        || character.is_ascii_alphanumeric()
                            && (index != 0 || !character.is_ascii_digit())
                })
            })
    {
        return Err(Error::Build(format!(
            "`{path}` is not a simple absolute or relative Rust crate path"
        )));
    }
    Ok(())
}

fn doc_text(value: &str) -> String {
    value
        .chars()
        .map(|character| match character {
            '\r' | '\n' => ' ',
            character => character,
        })
        .collect()
}

fn unique_identifier(mut identifier: String, used: &mut HashSet<String>) -> String {
    if used.insert(identifier.clone()) {
        return identifier;
    }
    let base = identifier.clone();
    let mut suffix = 2;
    loop {
        identifier = format!("{base}_{suffix}");
        if used.insert(identifier.clone()) {
            return identifier;
        }
        suffix += 1;
    }
}

fn snake_identifier(name: &str) -> String {
    let characters = name.chars().collect::<Vec<_>>();
    let mut output = String::new();
    let mut separator = false;
    let mut previous = None;
    for (index, character) in characters.iter().copied().enumerate() {
        if character.is_ascii_alphanumeric() {
            let next = characters
                .get(index + 1)
                .copied()
                .filter(char::is_ascii_alphanumeric);
            let case_boundary = previous.is_some_and(|previous: char| {
                character.is_ascii_uppercase()
                    && (previous.is_ascii_lowercase()
                        || previous.is_ascii_digit()
                        || previous.is_ascii_uppercase()
                            && next.is_some_and(|next| next.is_ascii_lowercase()))
            });
            if (separator || case_boundary) && !output.is_empty() && !output.ends_with('_') {
                output.push('_');
            }
            output.push(character.to_ascii_lowercase());
            previous = Some(character);
            separator = false;
        } else {
            separator = true;
            previous = None;
        }
    }
    if output.is_empty() {
        output.push_str("item");
    }
    if output.as_bytes()[0].is_ascii_digit() {
        output.insert(0, '_');
    }
    if rust_keyword(&output) {
        output.push('_');
    }
    output
}

fn pascal_identifier(name: &str) -> String {
    let snake = snake_identifier(name);
    let mut output = String::new();
    for component in snake.trim_start_matches('_').split('_') {
        let mut characters = component.chars();
        if let Some(first) = characters.next() {
            output.push(first.to_ascii_uppercase());
            output.extend(characters);
        }
    }
    if output.is_empty() {
        output.push_str("Bpf");
    }
    if output.as_bytes()[0].is_ascii_digit() {
        output.insert_str(0, "Bpf");
    }
    output
}

fn rust_keyword(value: &str) -> bool {
    matches!(
        value,
        "as" | "break"
            | "const"
            | "continue"
            | "crate"
            | "else"
            | "enum"
            | "extern"
            | "false"
            | "fn"
            | "for"
            | "if"
            | "impl"
            | "in"
            | "let"
            | "loop"
            | "match"
            | "mod"
            | "move"
            | "mut"
            | "pub"
            | "ref"
            | "return"
            | "self"
            | "Self"
            | "static"
            | "struct"
            | "super"
            | "trait"
            | "true"
            | "type"
            | "unsafe"
            | "use"
            | "where"
            | "while"
            | "async"
            | "await"
            | "dyn"
            | "abstract"
            | "become"
            | "box"
            | "do"
            | "final"
            | "macro"
            | "override"
            | "priv"
            | "typeof"
            | "unsized"
            | "virtual"
            | "yield"
            | "try"
    )
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::fs;
    use std::process::Command;

    use object::write::{Object as WriteObject, Symbol, SymbolSection};
    use object::{
        Architecture, BinaryFormat, Endianness, SectionKind, SymbolFlags, SymbolKind, SymbolScope,
    };
    use tempfile::tempdir;

    use super::{
        pascal_identifier, snake_identifier, DataSection, DataSectionMut, SkeletonBuilder,
    };
    use crate::Instruction;

    fn fixture() -> Vec<u8> {
        let mut object = WriteObject::new(BinaryFormat::Elf, Architecture::Bpf, Endianness::Little);
        let program = object.add_section(
            Vec::new(),
            b"kprobe/do_sys_open".to_vec(),
            SectionKind::Text,
        );
        let instructions = [
            Instruction::new(0xb7, 0, 0, 0, 0),
            Instruction::new(0x95, 0, 0, 0, 0),
        ];
        let bytes = instructions
            .iter()
            .flat_map(|instruction| instruction.to_bytes())
            .collect::<Vec<_>>();
        object.append_section_data(program, &bytes, 8);
        object.add_symbol(Symbol {
            name: b"type".to_vec(),
            value: 0,
            size: bytes.len() as u64,
            kind: SymbolKind::Text,
            scope: SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Section(program),
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
        object.add_symbol(Symbol {
            name: b"event-counts".to_vec(),
            value: 0,
            size: definition.len() as u64,
            kind: SymbolKind::Data,
            scope: SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Section(maps),
            flags: SymbolFlags::None,
        });

        let rodata = object.add_section(Vec::new(), b".rodata".to_vec(), SectionKind::ReadOnlyData);
        let mut rodata_initial = Vec::new();
        rodata_initial.extend(7_u32.to_le_bytes());
        rodata_initial.extend(0_u32.to_le_bytes());
        object.append_section_data(rodata, &rodata_initial, 4);
        let data = object.add_section(Vec::new(), b".data".to_vec(), SectionKind::Data);
        object.append_section_data(data, &9_u32.to_le_bytes(), 4);
        let btf = object.add_section(Vec::new(), b".BTF".to_vec(), SectionKind::ReadOnlyData);
        object.append_section_data(btf, &data_btf(), 4);

        let license = object.add_section(Vec::new(), b"license".to_vec(), SectionKind::Data);
        object.append_section_data(license, b"GPL\0", 1);
        object.write().expect("write fixture")
    }

    fn data_btf() -> Vec<u8> {
        fn string(strings: &mut Vec<u8>, value: &str) -> u32 {
            let offset = strings.len() as u32;
            strings.extend(value.as_bytes());
            strings.push(0);
            offset
        }

        let mut strings = vec![0];
        let u32_name = string(&mut strings, "u32");
        let setting_name = string(&mut strings, "setting");
        let fmt_name = string(&mut strings, "should_trace.____fmt");
        let rodata_name = string(&mut strings, ".rodata");
        let counter_name = string(&mut strings, "counter");
        let data_name = string(&mut strings, ".data");
        let event_type_name = string(&mut strings, "event_type");
        let sysenter_event_name = string(&mut strings, "SYSENTER_EVENT");
        let sysexit_event_name = string(&mut strings, "SYSEXIT_EVENT");
        let header_type_name = string(&mut strings, "tracexec_event_header");
        let pid_name = string(&mut strings, "pid");
        let type_name = string(&mut strings, "type");
        let exec_event_name = string(&mut strings, "exec_event");
        let header_name = string(&mut strings, "header");
        let count_name = string(&mut strings, "count");
        let unused_event_name = string(&mut strings, "unused_event");
        let mut types = Vec::new();
        // Type 1: u32.
        types.extend(u32_name.to_le_bytes());
        types.extend((1_u32 << 24).to_le_bytes());
        types.extend(4_u32.to_le_bytes());
        types.extend(32_u32.to_le_bytes());

        // Type 2: setting variable.
        types.extend(setting_name.to_le_bytes());
        types.extend((14_u32 << 24).to_le_bytes());
        types.extend(1_u32.to_le_bytes());
        types.extend(1_u32.to_le_bytes());

        // Type 3: .rodata data section.
        types.extend(rodata_name.to_le_bytes());
        types.extend(((15_u32 << 24) | 2).to_le_bytes());
        types.extend(8_u32.to_le_bytes());
        types.extend(2_u32.to_le_bytes());
        types.extend(0_u32.to_le_bytes());
        types.extend(4_u32.to_le_bytes());
        types.extend(10_u32.to_le_bytes());
        types.extend(4_u32.to_le_bytes());
        types.extend(4_u32.to_le_bytes());

        // Type 4: counter variable.
        types.extend(counter_name.to_le_bytes());
        types.extend((14_u32 << 24).to_le_bytes());
        types.extend(1_u32.to_le_bytes());
        types.extend(1_u32.to_le_bytes());

        // Type 5: .data data section.
        types.extend(data_name.to_le_bytes());
        types.extend(((15_u32 << 24) | 1).to_le_bytes());
        types.extend(4_u32.to_le_bytes());
        types.extend(4_u32.to_le_bytes());
        types.extend(0_u32.to_le_bytes());
        types.extend(4_u32.to_le_bytes());

        // Type 6: event_type enum.
        types.extend(event_type_name.to_le_bytes());
        types.extend(((6_u32 << 24) | 2).to_le_bytes());
        types.extend(4_u32.to_le_bytes());
        types.extend(sysenter_event_name.to_le_bytes());
        types.extend(0_i32.to_le_bytes());
        types.extend(sysexit_event_name.to_le_bytes());
        types.extend(1_i32.to_le_bytes());

        // Type 7: tracexec_event_header struct.
        types.extend(header_type_name.to_le_bytes());
        types.extend(((4_u32 << 24) | 2).to_le_bytes());
        types.extend(8_u32.to_le_bytes());
        types.extend(pid_name.to_le_bytes());
        types.extend(1_u32.to_le_bytes());
        types.extend(0_u32.to_le_bytes());
        types.extend(type_name.to_le_bytes());
        types.extend(6_u32.to_le_bytes());
        types.extend(32_u32.to_le_bytes());

        // Type 8: exec_event struct.
        types.extend(exec_event_name.to_le_bytes());
        types.extend(((4_u32 << 24) | 2).to_le_bytes());
        types.extend(12_u32.to_le_bytes());
        types.extend(header_name.to_le_bytes());
        types.extend(7_u32.to_le_bytes());
        types.extend(0_u32.to_le_bytes());
        types.extend(count_name.to_le_bytes());
        types.extend(1_u32.to_le_bytes());
        types.extend(64_u32.to_le_bytes());

        // Type 9: unused_event struct.
        types.extend(unused_event_name.to_le_bytes());
        types.extend(((4_u32 << 24) | 1).to_le_bytes());
        types.extend(4_u32.to_le_bytes());
        types.extend(count_name.to_le_bytes());
        types.extend(1_u32.to_le_bytes());
        types.extend(0_u32.to_le_bytes());

        // Type 10: static format-string variable that should not get an accessor.
        types.extend(fmt_name.to_le_bytes());
        types.extend((14_u32 << 24).to_le_bytes());
        types.extend(1_u32.to_le_bytes());
        types.extend(0_u32.to_le_bytes());

        let mut bytes = Vec::new();
        bytes.extend(0xeb9f_u16.to_le_bytes());
        bytes.push(1);
        bytes.push(0);
        bytes.extend(24_u32.to_le_bytes());
        bytes.extend(0_u32.to_le_bytes());
        bytes.extend((types.len() as u32).to_le_bytes());
        bytes.extend((types.len() as u32).to_le_bytes());
        bytes.extend((strings.len() as u32).to_le_bytes());
        bytes.extend(types);
        bytes.extend(&strings);
        bytes
    }

    #[test]
    fn data_sections_decode_and_encode_without_layout_casts() {
        let mut bytes = [0_u8; 12];
        {
            let mut data = DataSectionMut::new(&mut bytes);
            data.write(0, &0x1234_5678_u32).unwrap();
            data.write(4, &[1_i16, -2, 3, -4]).unwrap();
        }
        let data = DataSection::new(&bytes);
        assert_eq!(data.read::<u32>(0).unwrap(), 0x1234_5678);
        assert_eq!(data.read::<[i16; 4]>(4).unwrap(), [1, -2, 3, -4]);
        assert!(data.read::<u64>(8).is_err());
    }

    #[test]
    fn identifiers_are_valid_and_idiomatic() {
        assert_eq!(snake_identifier("event-counts"), "event_counts");
        assert_eq!(snake_identifier("HTTPEvents"), "http_events");
        assert_eq!(
            snake_identifier("BPF_BITS_ITER_MAX_BYTES"),
            "bpf_bits_iter_max_bytes"
        );
        assert_eq!(snake_identifier("type"), "type_");
        assert_eq!(snake_identifier("42-map"), "_42_map");
        assert_eq!(pascal_identifier("network-events"), "NetworkEvents");
    }

    #[test]
    fn renders_staged_named_skeleton() {
        let directory = tempdir().unwrap();
        let object = directory.path().join("network-events.bpf.o");
        fs::write(&object, fixture()).unwrap();
        let mut builder = SkeletonBuilder::new();
        builder.object(&object).format(false);
        let source = builder.render().unwrap();
        assert!(source.contains("pub struct NetworkEventsSkelBuilder"));
        assert!(source.contains("pub struct OpenNetworkEventsSkel"));
        assert!(source.contains("pub struct NetworkEventsSkel"));
        assert!(source.contains("pub fn event_counts(&self)"));
        assert!(source.contains("pub fn type_(&self)"));
        assert!(source.contains("program.attach()?"));
        assert!(source.contains("program.spec().auto_attach()"));
        assert!(source.contains("impl ::ebeepf::OpenSkeleton"));
        assert!(source.contains("pub fn rodata(&self)"));
        assert!(source.contains("rodata_memory: ::ebeepf::MapMemory"));
        assert!(source.contains("data_memory: ::ebeepf::MapMemoryMut"));
        assert!(source.contains("object.map(\"network_events.rodata\")?.mmap()?"));
        assert!(source.contains("object.map(\"network_events.data\")?.mmap_mut()?"));
        assert!(source.contains("pub fn token(mut self, token: &::ebeepf::BpfToken)"));
        assert!(source.contains("pub fn setting(&self) -> ::ebeepf::Result<u32>"));
        assert!(source.contains("pub fn set_setting(&mut self, value: &u32)"));
        assert!(!source.contains("should_trace.____fmt"));
        assert!(!source.contains("should_trace_fmt"));
        assert!(source.contains("pub mod types"));
        assert!(source.contains("pub struct rodata"));
        assert!(source.contains("pub setting: u32"));
        assert!(source.contains("pub struct data"));
        assert!(source.contains("pub counter: u32"));
        assert!(source.contains("const OBJECT_BYTES: &[u8] = &["));
    }

    #[test]
    fn type_allowlist_generates_only_dependency_closure() {
        let directory = tempdir().unwrap();
        let object = directory.path().join("network-events.bpf.o");
        fs::write(&object, fixture()).unwrap();
        let mut builder = SkeletonBuilder::new();
        builder
            .object(&object)
            .type_allowlist(["exec_event"])
            .format(false);
        let source = builder.render().unwrap();
        assert!(source.contains("pub struct exec_event"));
        assert!(source.contains("pub struct tracexec_event_header"));
        assert!(source.contains("pub struct event_type"));
        assert!(source.contains("pub r#type: event_type"));
        assert!(!source.contains("pub struct unused_event"));
        assert!(!source.contains("pub struct rodata"));
        assert!(!source.contains("pub struct data"));
    }

    #[test]
    fn type_allowlist_rejects_missing_types() {
        let directory = tempdir().unwrap();
        let object = directory.path().join("network-events.bpf.o");
        fs::write(&object, fixture()).unwrap();
        let mut builder = SkeletonBuilder::new();
        builder
            .object(&object)
            .type_allowlist(["missing_event"])
            .format(false);
        let error = builder.render().unwrap_err();
        assert!(
            error.to_string().contains("missing_event"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn referenced_skeleton_uses_canonical_include() {
        let directory = tempdir().unwrap();
        let object = directory.path().join("probe.bpf.o");
        fs::write(&object, fixture()).unwrap();
        let mut builder = SkeletonBuilder::new();
        builder.object(&object).reference_object(true).format(false);
        let source = builder.render().unwrap();
        assert!(source.contains("include_bytes!("));
        assert!(source.contains(object.canonicalize().unwrap().to_str().unwrap()));
        assert!(!source.contains("0x7f, 0x45, 0x4c, 0x46"));
    }

    #[test]
    fn writes_rustfmt_parseable_source() {
        let directory = tempdir().unwrap();
        let object = directory.path().join("probe.bpf.o");
        let skeleton = directory.path().join("probe.skel.rs");
        fs::write(&object, fixture()).unwrap();
        let mut builder = SkeletonBuilder::new();
        builder.object(&object);
        builder.generate(&skeleton).unwrap();
        let source = fs::read_to_string(skeleton).unwrap();
        assert!(source.starts_with("// @generated by ebeepf"));
    }

    #[test]
    fn generated_skeleton_type_checks_in_a_consumer_crate() {
        let directory = tempdir().unwrap();
        let object = directory.path().join("network-events.bpf.o");
        let source_directory = directory.path().join("src");
        let skeleton = source_directory.join("network_events.skel.rs");
        fs::create_dir(&source_directory).unwrap();
        fs::write(&object, fixture()).unwrap();
        let mut builder = SkeletonBuilder::new();
        builder.object(&object);
        builder.generate(&skeleton).unwrap();

        let manifest_directory = env!("CARGO_MANIFEST_DIR");
        fs::write(
            directory.path().join("Cargo.toml"),
            format!(
                "[package]\nname = \"generated-skel-check\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n[dependencies]\nebeepf = {{ path = {manifest_directory:?} }}\n"
            ),
        )
        .unwrap();
        fs::write(
            source_directory.join("lib.rs"),
            r#"
mod generated {
    include!("network_events.skel.rs");
}

pub fn configure() -> ebeepf::Result<()> {
    let mut open = generated::NetworkEventsSkelBuilder::new().open()?;
    let _ = generated::types::rodata::default();
    let _ = generated::types::data::default();
    open.rodata_mut()?.set_setting(&42)?;
    let _ = open.maps().event_counts()?;
    let _ = open.programs().type_()?;
    Ok(())
}

pub fn read_loaded(skeleton: &mut generated::NetworkEventsSkel) -> ebeepf::Result<u32> {
    skeleton.rodata()?.setting()
}

pub fn modify_loaded(skeleton: &mut generated::NetworkEventsSkel) -> ebeepf::Result<()> {
    skeleton.data_mut()?.set_counter(&9)?;
    Ok(())
}
"#,
        )
        .unwrap();
        let result = Command::new(env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
            .arg("check")
            .arg("--quiet")
            .arg("--offline")
            .current_dir(directory.path())
            .env("CARGO_TARGET_DIR", directory.path().join("target"))
            .env("RUSTFLAGS", "-Dwarnings")
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "generated consumer failed to compile:\n{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
}
