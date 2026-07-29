use std::fmt;
use std::fs;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::path::Path;
use std::sync::Arc;

use bitflags::bitflags;

use crate::sys;
use crate::{Error, Link, Result, TypeId};

bitflags! {
    /// Flags controlling map creation and access.
    #[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
    pub struct MapFlags: u32 {
        /// Do not preallocate hash-map entries.
        const NO_PREALLOC = 1 << 0;
        /// Use a per-CPU LRU list.
        const NO_COMMON_LRU = 1 << 1;
        /// Create the map on a specific NUMA node.
        const NUMA_NODE = 1 << 2;
        /// User space may only read the map.
        const READ_ONLY = 1 << 3;
        /// User space may only write the map.
        const WRITE_ONLY = 1 << 4;
        /// Stack-trace values contain build IDs.
        const STACK_BUILD_ID = 1 << 5;
        /// Use a deterministic hash seed.
        const ZERO_SEED = 1 << 6;
        /// eBPF programs may only read the map.
        const PROGRAM_READ_ONLY = 1 << 7;
        /// eBPF programs may only write the map.
        const PROGRAM_WRITE_ONLY = 1 << 8;
        /// Clone socket map entries from a listener.
        const CLONE = 1 << 9;
        /// Allow `mmap(2)` access.
        const MMAPABLE = 1 << 10;
        /// Preserve perf-event entries across program ownership changes.
        const PRESERVE_ELEMENTS = 1 << 11;
        /// This map is an inner-map template with dynamic capacity.
        const INNER_MAP = 1 << 12;
        /// Register or unregister the map through a backing BPF link.
        const LINK = 1 << 13;
        /// Interpret pin/get paths relative to a supplied directory descriptor.
        const PATH_FD = 1 << 14;
        /// A value-type BTF object descriptor is present.
        const VALUE_TYPE_BTF_OBJECT_FD = 1 << 15;
        /// A BPF token descriptor is present.
        const TOKEN_FD = 1 << 16;
        /// Deliver `SIGSEGV` instead of faulting new arena pages in.
        const SEGMENTATION_FAULT_ON_ARENA_PAGE_FAULT = 1 << 17;
        /// Do not translate kernel arena pointers to userspace pointers.
        const NO_ARENA_USER_POINTER_CONVERSION = 1 << 18;
        /// Allow ring-buffer overwrite mode.
        const RING_BUFFER_OVERWRITE = 1 << 19;
    }
}

/// A kernel eBPF map type.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum MapType {
    /// Unspecified map type.
    Unspecified,
    /// Hash table.
    Hash,
    /// Fixed-size array.
    Array,
    /// Program tail-call array.
    ProgramArray,
    /// Perf-event descriptor array.
    PerfEventArray,
    /// Per-CPU hash table.
    PerCpuHash,
    /// Per-CPU array.
    PerCpuArray,
    /// Stack trace storage.
    StackTrace,
    /// Cgroup array.
    CgroupArray,
    /// LRU hash table.
    LruHash,
    /// Per-CPU LRU hash table.
    LruPerCpuHash,
    /// Longest-prefix-match trie.
    LpmTrie,
    /// Array of maps.
    ArrayOfMaps,
    /// Hash table of maps.
    HashOfMaps,
    /// Device map.
    DeviceMap,
    /// Socket map.
    SocketMap,
    /// CPU redirect map.
    CpuMap,
    /// `AF_XDP` socket map.
    XskMap,
    /// Socket hash table.
    SocketHash,
    /// Cgroup storage.
    CgroupStorage,
    /// Reuseport socket array.
    ReuseportSocketArray,
    /// Per-CPU cgroup storage.
    PerCpuCgroupStorage,
    /// Queue.
    Queue,
    /// Stack.
    Stack,
    /// Socket-local storage.
    SocketStorage,
    /// Hashed device map.
    DeviceMapHash,
    /// `struct_ops` implementation map.
    StructOps,
    /// Kernel-to-user ring buffer.
    RingBuffer,
    /// Inode-local storage.
    InodeStorage,
    /// Task-local storage.
    TaskStorage,
    /// Bloom filter.
    BloomFilter,
    /// User-to-kernel ring buffer.
    UserRingBuffer,
    /// Modern cgroup storage.
    CgroupLocalStorage,
    /// Arena map.
    Arena,
    /// Instruction array.
    InstructionArray,
    /// A map type introduced after this crate version.
    Other(u32),
}

impl MapType {
    /// Converts a raw Linux UAPI value to a map type.
    pub const fn from_raw(value: u32) -> Self {
        match value {
            0 => Self::Unspecified,
            1 => Self::Hash,
            2 => Self::Array,
            3 => Self::ProgramArray,
            4 => Self::PerfEventArray,
            5 => Self::PerCpuHash,
            6 => Self::PerCpuArray,
            7 => Self::StackTrace,
            8 => Self::CgroupArray,
            9 => Self::LruHash,
            10 => Self::LruPerCpuHash,
            11 => Self::LpmTrie,
            12 => Self::ArrayOfMaps,
            13 => Self::HashOfMaps,
            14 => Self::DeviceMap,
            15 => Self::SocketMap,
            16 => Self::CpuMap,
            17 => Self::XskMap,
            18 => Self::SocketHash,
            19 => Self::CgroupStorage,
            20 => Self::ReuseportSocketArray,
            21 => Self::PerCpuCgroupStorage,
            22 => Self::Queue,
            23 => Self::Stack,
            24 => Self::SocketStorage,
            25 => Self::DeviceMapHash,
            26 => Self::StructOps,
            27 => Self::RingBuffer,
            28 => Self::InodeStorage,
            29 => Self::TaskStorage,
            30 => Self::BloomFilter,
            31 => Self::UserRingBuffer,
            32 => Self::CgroupLocalStorage,
            33 => Self::Arena,
            34 => Self::InstructionArray,
            value => Self::Other(value),
        }
    }

    /// Returns the Linux UAPI value.
    pub const fn as_raw(self) -> u32 {
        match self {
            Self::Unspecified => 0,
            Self::Hash => 1,
            Self::Array => 2,
            Self::ProgramArray => 3,
            Self::PerfEventArray => 4,
            Self::PerCpuHash => 5,
            Self::PerCpuArray => 6,
            Self::StackTrace => 7,
            Self::CgroupArray => 8,
            Self::LruHash => 9,
            Self::LruPerCpuHash => 10,
            Self::LpmTrie => 11,
            Self::ArrayOfMaps => 12,
            Self::HashOfMaps => 13,
            Self::DeviceMap => 14,
            Self::SocketMap => 15,
            Self::CpuMap => 16,
            Self::XskMap => 17,
            Self::SocketHash => 18,
            Self::CgroupStorage => 19,
            Self::ReuseportSocketArray => 20,
            Self::PerCpuCgroupStorage => 21,
            Self::Queue => 22,
            Self::Stack => 23,
            Self::SocketStorage => 24,
            Self::DeviceMapHash => 25,
            Self::StructOps => 26,
            Self::RingBuffer => 27,
            Self::InodeStorage => 28,
            Self::TaskStorage => 29,
            Self::BloomFilter => 30,
            Self::UserRingBuffer => 31,
            Self::CgroupLocalStorage => 32,
            Self::Arena => 33,
            Self::InstructionArray => 34,
            Self::Other(value) => value,
        }
    }

    /// Whether one logical value has a separate slot for every possible CPU.
    pub const fn is_per_cpu(self) -> bool {
        matches!(
            self,
            Self::PerCpuHash | Self::PerCpuArray | Self::LruPerCpuHash | Self::PerCpuCgroupStorage
        )
    }

    /// Whether map values are file descriptors for other maps.
    pub const fn is_map_of_maps(self) -> bool {
        matches!(self, Self::ArrayOfMaps | Self::HashOfMaps)
    }

    /// Probes whether the running kernel can create this map type.
    ///
    /// The probe supplies type-specific sizes, flags, inner maps, and BTF
    /// metadata so that an `EINVAL` result is not confused with an invalid
    /// generic map definition.
    pub fn is_supported(self) -> Result<bool> {
        sys::probe_map_type(self.as_raw())
            .map_err(|source| Error::system("probe eBPF map type", source))
    }

    pub(crate) const fn accepts_btf_types(self) -> bool {
        !matches!(
            self,
            Self::PerfEventArray
                | Self::CgroupArray
                | Self::StackTrace
                | Self::ArrayOfMaps
                | Self::HashOfMaps
                | Self::DeviceMap
                | Self::DeviceMapHash
                | Self::CpuMap
                | Self::XskMap
                | Self::SocketMap
                | Self::SocketHash
                | Self::Queue
                | Self::Stack
                | Self::Arena
        )
    }
}

/// Pinning policy encoded in a BTF map definition.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Pinning {
    /// Do not automatically pin this map.
    #[default]
    None,
    /// Pin the map using its name below the object's pin root.
    ByName,
}

/// A map's parsed and configurable definition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MapSpec {
    pub(crate) name: String,
    pub(crate) map_type: MapType,
    pub(crate) key_size: u32,
    pub(crate) value_size: u32,
    pub(crate) max_entries: u32,
    pub(crate) flags: MapFlags,
    pub(crate) pinning: Pinning,
    pub(crate) numa_node: Option<u32>,
    pub(crate) map_extra: u64,
    pub(crate) btf_key_type: TypeId,
    pub(crate) btf_value_type: TypeId,
    pub(crate) inner_map: Option<String>,
    pub(crate) initial_value: Option<Vec<u8>>,
    pub(crate) freeze_after_init: bool,
    pub(crate) section_index: Option<usize>,
    pub(crate) section_offset: u64,
}

impl MapSpec {
    /// Creates a map definition.
    pub fn new(
        name: impl Into<String>,
        map_type: MapType,
        key_size: u32,
        value_size: u32,
        max_entries: u32,
    ) -> Self {
        Self {
            name: name.into(),
            map_type,
            key_size,
            value_size,
            max_entries,
            flags: MapFlags::empty(),
            pinning: Pinning::None,
            numa_node: None,
            map_extra: 0,
            btf_key_type: TypeId::VOID,
            btf_value_type: TypeId::VOID,
            inner_map: None,
            initial_value: None,
            freeze_after_init: false,
            section_index: None,
            section_offset: 0,
        }
    }

    /// Map name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Kernel map type.
    pub const fn map_type(&self) -> MapType {
        self.map_type
    }

    /// Key size in bytes.
    pub const fn key_size(&self) -> u32 {
        self.key_size
    }

    /// Logical value size in bytes.
    pub const fn value_size(&self) -> u32 {
        self.value_size
    }

    /// Maximum number of entries.
    pub const fn max_entries(&self) -> u32 {
        self.max_entries
    }

    /// Map flags.
    pub const fn flags(&self) -> MapFlags {
        self.flags
    }

    /// BTF key type ID, or zero when absent.
    pub const fn btf_key_type(&self) -> TypeId {
        self.btf_key_type
    }

    /// BTF value type ID, or zero when absent.
    pub const fn btf_value_type(&self) -> TypeId {
        self.btf_value_type
    }

    /// Pinning policy.
    pub const fn pinning(&self) -> Pinning {
        self.pinning
    }

    /// NUMA node selected for map allocation.
    pub const fn numa_node(&self) -> Option<u32> {
        self.numa_node
    }

    /// Type-specific map creation value.
    pub const fn map_extra(&self) -> u64 {
        self.map_extra
    }

    /// Name of the inner-map template used by map-in-map definitions.
    pub fn inner_map(&self) -> Option<&str> {
        self.inner_map.as_deref()
    }

    /// Initial value written to key zero while loading, when configured.
    ///
    /// ELF global-data and kconfig maps have an initial value by default.
    pub fn initial_value(&self) -> Option<&[u8]> {
        self.initial_value.as_deref()
    }

    /// Mutably borrows the value written to key zero while loading.
    ///
    /// This is primarily useful to configure fields in global data sections
    /// without copying the entire section.
    pub fn initial_value_mut(&mut self) -> Option<&mut [u8]> {
        self.initial_value.as_deref_mut()
    }

    /// Changes the kernel map type before loading.
    pub fn set_map_type(&mut self, map_type: MapType) -> &mut Self {
        self.map_type = map_type;
        self
    }

    /// Changes the key size before loading.
    pub fn set_key_size(&mut self, key_size: u32) -> &mut Self {
        self.key_size = key_size;
        self
    }

    /// Changes the logical value size before loading.
    pub fn set_value_size(&mut self, value_size: u32) -> &mut Self {
        self.value_size = value_size;
        self
    }

    /// Changes the maximum number of entries before loading.
    pub fn set_max_entries(&mut self, max_entries: u32) -> &mut Self {
        self.max_entries = max_entries;
        self
    }

    /// Changes map flags before loading.
    pub fn set_flags(&mut self, flags: MapFlags) -> &mut Self {
        self.flags = flags;
        self
    }

    /// Changes the NUMA placement. This also enables [`MapFlags::NUMA_NODE`].
    pub fn set_numa_node(&mut self, node: Option<u32>) -> &mut Self {
        self.numa_node = node;
        self.flags.set(MapFlags::NUMA_NODE, node.is_some());
        self
    }

    /// Changes the automatic pinning policy.
    pub fn set_pinning(&mut self, pinning: Pinning) -> &mut Self {
        self.pinning = pinning;
        self
    }

    /// Names the map whose descriptor should be used as the inner-map template.
    pub fn set_inner_map(&mut self, name: Option<impl Into<String>>) -> &mut Self {
        self.inner_map = name.map(Into::into);
        self
    }

    /// Changes the type-specific extra map creation value.
    pub fn set_map_extra(&mut self, map_extra: u64) -> &mut Self {
        self.map_extra = map_extra;
        self
    }

    /// Changes the BTF key and value type IDs.
    ///
    /// Standalone map creation cannot use nonzero IDs because the IDs belong
    /// to a particular loaded BTF object. Object loading supplies that BTF
    /// descriptor automatically.
    pub fn set_btf_types(&mut self, key: TypeId, value: TypeId) -> &mut Self {
        self.btf_key_type = key;
        self.btf_value_type = value;
        self
    }

    /// Replaces the value written to key zero while loading.
    ///
    /// This is useful for configuring `.data`, `.rodata`, `.bss`, and
    /// `.kconfig` maps before [`crate::Object::load`].
    pub fn set_initial_value(&mut self, value: impl Into<Vec<u8>>) -> Result<&mut Self> {
        let value = value.into();
        validate_size("initial map value", self.value_size, value.len())?;
        self.initial_value = Some(value);
        Ok(self)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.name.is_empty() {
            return Err(Error::InvalidObject("map name cannot be empty".into()));
        }
        if self.max_entries == 0
            && !matches!(
                self.map_type,
                MapType::CgroupStorage
                    | MapType::PerCpuCgroupStorage
                    | MapType::SocketStorage
                    | MapType::StructOps
                    | MapType::InodeStorage
                    | MapType::TaskStorage
                    | MapType::CgroupLocalStorage
            )
        {
            return Err(Error::InvalidObject(format!(
                "map `{}` has zero maximum entries",
                self.name
            )));
        }
        if self.map_type.is_map_of_maps() && self.inner_map.is_none() {
            return Err(Error::InvalidObject(format!(
                "map-of-maps `{}` has no inner-map template",
                self.name
            )));
        }
        if !self.map_type.is_map_of_maps() && self.inner_map.is_some() {
            return Err(Error::InvalidObject(format!(
                "map `{}` is not a map-in-map but has an inner-map template",
                self.name
            )));
        }
        if let Some(value) = &self.initial_value {
            validate_size("initial map value", self.value_size, value.len())?;
        }
        Ok(())
    }
}

/// Semantics for a map update operation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum UpdateMode {
    /// Insert a new element or replace an existing one.
    #[default]
    Any,
    /// Fail when the key already exists.
    NoExist,
    /// Fail when the key does not exist.
    Exist,
}

impl UpdateMode {
    const fn as_raw(self) -> u64 {
        match self {
            Self::Any => 0,
            Self::NoExist => 1,
            Self::Exist => 2,
        }
    }
}

/// Kernel metadata for a loaded map.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MapInfo {
    /// Kernel-assigned ID.
    pub id: u32,
    /// Kernel map type.
    pub map_type: MapType,
    /// Kernel object name.
    pub name: String,
    /// Key size in bytes.
    pub key_size: u32,
    /// Value size in bytes.
    pub value_size: u32,
    /// Maximum entries.
    pub max_entries: u32,
    /// Map flags.
    pub flags: MapFlags,
    /// BTF object ID.
    pub btf_id: u32,
    /// BTF key type ID.
    pub btf_key_type: TypeId,
    /// BTF value type ID.
    pub btf_value_type: TypeId,
    /// Type-specific extra value.
    pub map_extra: u64,
    /// Network interface index for device-bound maps.
    pub interface_index: u32,
    /// Network namespace device containing the map.
    pub network_namespace_device: u64,
    /// Network namespace inode containing the map.
    pub network_namespace_inode: u64,
    /// Kernel BTF ID used for values whose layout comes from vmlinux.
    pub btf_vmlinux_id: u32,
    /// Vmlinux value type ID.
    pub btf_vmlinux_value_type: TypeId,
}

/// Opaque continuation state for map batch lookup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchCursor(Vec<u8>);

/// A page returned by a map batch lookup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MapBatch {
    entries: Vec<(Vec<u8>, Vec<u8>)>,
    cursor: Option<BatchCursor>,
}

impl MapBatch {
    /// Key/value pairs returned by the kernel.
    pub fn entries(&self) -> &[(Vec<u8>, Vec<u8>)] {
        &self.entries
    }

    /// Consumes the page and returns its entries.
    pub fn into_entries(self) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.entries
    }

    /// Cursor for the next page, or `None` when iteration is complete.
    pub fn cursor(&self) -> Option<&BatchCursor> {
        self.cursor.as_ref()
    }

    /// Whether this is the last page.
    pub fn is_last(&self) -> bool {
        self.cursor.is_none()
    }
}

/// An owned reference to a map loaded in the kernel.
#[derive(Clone)]
pub struct Map {
    pub(crate) fd: Arc<OwnedFd>,
    spec: MapSpec,
}

impl fmt::Debug for Map {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Map")
            .field("fd", &self.fd.as_raw_fd())
            .field("spec", &self.spec)
            .finish()
    }
}

impl Map {
    pub(crate) fn from_fd(fd: OwnedFd, spec: MapSpec) -> Self {
        Self {
            fd: Arc::new(fd),
            spec,
        }
    }

    /// Creates a standalone kernel map from an owned definition.
    ///
    /// Map-in-map definitions must use [`Self::create_with_inner`].
    pub fn create(spec: MapSpec) -> Result<Self> {
        Self::create_impl(spec, None)
    }

    /// Creates a standalone map-in-map using `inner` as its template.
    pub fn create_with_inner(mut spec: MapSpec, inner: &Self) -> Result<Self> {
        if spec.inner_map.is_none() {
            spec.inner_map = Some(inner.name().into());
        }
        Self::create_impl(spec, Some(inner))
    }

    fn create_impl(mut spec: MapSpec, inner: Option<&Self>) -> Result<Self> {
        if spec.map_type.is_map_of_maps() != inner.is_some() {
            return Err(Error::InvalidObject(format!(
                "map `{}` {} an inner-map template",
                spec.name,
                if spec.map_type.is_map_of_maps() {
                    "requires"
                } else {
                    "does not accept"
                }
            )));
        }
        if spec.btf_key_type != TypeId::VOID || spec.btf_value_type != TypeId::VOID {
            return Err(Error::Unsupported(
                "standalone maps with BTF type IDs require an owning BTF object".into(),
            ));
        }
        if spec.map_type == MapType::PerfEventArray && spec.max_entries == 0 {
            spec.max_entries = u32::try_from(possible_cpu_count()?)
                .map_err(|_| Error::InvalidObject("possible CPU count does not fit u32".into()))?;
        }
        spec.validate()?;
        let fd = sys::map_create(&sys::MapCreate {
            map_type: spec.map_type.as_raw(),
            name: &spec.name,
            key_size: spec.key_size,
            value_size: spec.value_size,
            max_entries: spec.max_entries,
            flags: spec.flags.bits(),
            inner_map_fd: inner.map(|map| map.fd.as_raw_fd()),
            numa_node: spec.numa_node,
            btf_fd: None,
            btf_key_type_id: 0,
            btf_value_type_id: 0,
            map_extra: spec.map_extra,
        })
        .map_err(|source| Error::MapCreate {
            map: spec.name.clone(),
            source,
        })?;
        let map = Self::from_fd(fd, spec);
        if let Some(initial) = &map.spec.initial_value {
            sys::map_update(map.fd.as_raw_fd(), &0_u32.to_ne_bytes(), initial, 0)
                .map_err(|source| Error::system("initialize standalone map", source))?;
        }
        if map.spec.freeze_after_init {
            map.freeze()?;
        }
        Ok(map)
    }

    /// Opens a map pinned in bpffs.
    pub fn open_pinned(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let fd = sys::object_get(path).map_err(|source| Error::File {
            operation: "open pinned map",
            path: path.into(),
            source,
        })?;
        Self::from_kernel_fd(fd)
    }

    /// Opens a map by its kernel ID.
    pub fn from_id(id: u32) -> Result<Self> {
        let fd = sys::object_get_fd_by_id(sys::ObjectKind::Map, id)
            .map_err(|source| Error::system("open map by ID", source))?;
        Self::from_kernel_fd(fd)
    }

    fn from_kernel_fd(fd: OwnedFd) -> Result<Self> {
        let raw = sys::map_info(fd.as_raw_fd())
            .map_err(|source| Error::system("read map metadata", source))?;
        let name = kernel_name(&raw.name);
        let mut spec = MapSpec::new(
            name,
            MapType::from_raw(raw.map_type),
            raw.key_size,
            raw.value_size,
            raw.max_entries,
        );
        spec.flags = MapFlags::from_bits_retain(raw.map_flags);
        spec.btf_key_type = TypeId(raw.btf_key_type_id);
        spec.btf_value_type = TypeId(raw.btf_value_type_id);
        spec.map_extra = raw.map_extra;
        Ok(Self::from_fd(fd, spec))
    }

    /// Parsed map definition.
    pub fn spec(&self) -> &MapSpec {
        &self.spec
    }

    /// Name from the object definition.
    pub fn name(&self) -> &str {
        self.spec.name()
    }

    /// Borrows the kernel file descriptor.
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// Looks up a key, returning `None` when it is absent.
    pub fn lookup(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.validate_key(key)?;
        let mut value = vec![0; self.storage_value_size()?];
        let found = sys::map_lookup(self.fd.as_raw_fd(), key, &mut value, 0)
            .map_err(|source| Error::system("look up map element", source))?;
        Ok(found.then_some(value))
    }

    /// Inserts or updates a key/value pair.
    pub fn update(&self, key: &[u8], value: &[u8], mode: UpdateMode) -> Result<()> {
        self.validate_key(key)?;
        self.validate_value(value)?;
        sys::map_update(self.fd.as_raw_fd(), key, value, mode.as_raw())
            .map_err(|source| Error::system("update map element", source))
    }

    /// Stores a file descriptor in a program, perf-event, cgroup, or map array.
    pub fn update_fd(&self, key: &[u8], value: impl AsFd, mode: UpdateMode) -> Result<()> {
        let descriptor = value.as_fd().as_raw_fd().to_ne_bytes();
        self.update(key, &descriptor, mode)
    }

    /// Deletes a key. Returns whether it existed.
    pub fn delete(&self, key: &[u8]) -> Result<bool> {
        self.validate_key(key)?;
        sys::map_delete(self.fd.as_raw_fd(), key)
            .map_err(|source| Error::system("delete map element", source))
    }

    /// Looks up and atomically deletes a key.
    pub fn lookup_and_delete(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.validate_key(key)?;
        let mut value = vec![0; self.storage_value_size()?];
        let found = sys::map_lookup_and_delete(self.fd.as_raw_fd(), key, &mut value)
            .map_err(|source| Error::system("look up and delete map element", source))?;
        Ok(found.then_some(value))
    }

    /// Pushes a value onto a queue or stack map.
    pub fn push(&self, value: &[u8], mode: UpdateMode) -> Result<()> {
        if !matches!(self.spec.map_type, MapType::Queue | MapType::Stack) {
            return Err(Error::Unsupported(format!(
                "map `{}` is not a queue or stack",
                self.name()
            )));
        }
        self.update(&[], value, mode)
    }

    /// Reads the next queue/stack value without removing it.
    pub fn peek(&self) -> Result<Option<Vec<u8>>> {
        if !matches!(self.spec.map_type, MapType::Queue | MapType::Stack) {
            return Err(Error::Unsupported(format!(
                "map `{}` is not a queue or stack",
                self.name()
            )));
        }
        self.lookup(&[])
    }

    /// Removes and returns the next queue/stack value.
    pub fn pop(&self) -> Result<Option<Vec<u8>>> {
        if !matches!(self.spec.map_type, MapType::Queue | MapType::Stack) {
            return Err(Error::Unsupported(format!(
                "map `{}` is not a queue or stack",
                self.name()
            )));
        }
        self.lookup_and_delete(&[])
    }

    /// Prevents further updates to this map.
    pub fn freeze(&self) -> Result<()> {
        sys::map_freeze(self.fd.as_raw_fd()).map_err(|source| Error::system("freeze map", source))
    }

    /// Registers a loaded `struct_ops` map and returns its kernel link.
    pub fn attach_struct_ops(&self) -> Result<Link> {
        if self.spec.map_type != MapType::StructOps {
            return Err(Error::InvalidObject(format!(
                "map `{}` is not a struct_ops map",
                self.name()
            )));
        }
        let fd = sys::struct_ops_link_create(self.fd.as_raw_fd())
            .map_err(|source| Error::system("attach struct_ops map", source))?;
        Ok(Link::bpf(fd))
    }

    /// Pins the map at a bpffs path.
    pub fn pin(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        sys::object_pin(self.fd.as_raw_fd(), path).map_err(|source| Error::File {
            operation: "pin map",
            path: path.into(),
            source,
        })
    }

    /// Removes a bpffs pin without closing this map handle.
    pub fn unpin(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        fs::remove_file(path).map_err(|source| Error::File {
            operation: "unpin map",
            path: path.into(),
            source,
        })
    }

    /// Reads current metadata from the kernel.
    pub fn info(&self) -> Result<MapInfo> {
        let raw = sys::map_info(self.fd.as_raw_fd())
            .map_err(|source| Error::system("read map metadata", source))?;
        Ok(MapInfo {
            id: raw.id,
            map_type: MapType::from_raw(raw.map_type),
            name: kernel_name(&raw.name),
            key_size: raw.key_size,
            value_size: raw.value_size,
            max_entries: raw.max_entries,
            flags: MapFlags::from_bits_retain(raw.map_flags),
            btf_id: raw.btf_id,
            btf_key_type: TypeId(raw.btf_key_type_id),
            btf_value_type: TypeId(raw.btf_value_type_id),
            map_extra: raw.map_extra,
            interface_index: raw.ifindex,
            network_namespace_device: raw.netns_dev,
            network_namespace_inode: raw.netns_ino,
            btf_vmlinux_id: raw.btf_vmlinux_id,
            btf_vmlinux_value_type: TypeId(raw.btf_vmlinux_value_type_id),
        })
    }

    /// Iterates over a snapshot-like sequence of keys.
    ///
    /// Concurrent updates may make keys appear, disappear, or be visited more
    /// than once, matching `BPF_MAP_GET_NEXT_KEY` semantics.
    pub fn keys(&self) -> KeyIterator<'_> {
        KeyIterator {
            map: self,
            previous: None,
            finished: false,
        }
    }

    /// Looks up up to `maximum_count` entries in one syscall.
    pub fn lookup_batch(
        &self,
        cursor: Option<&BatchCursor>,
        maximum_count: u32,
    ) -> Result<MapBatch> {
        self.lookup_batch_impl(cursor, maximum_count, false)
    }

    /// Looks up and atomically deletes up to `maximum_count` entries.
    pub fn lookup_and_delete_batch(
        &self,
        cursor: Option<&BatchCursor>,
        maximum_count: u32,
    ) -> Result<MapBatch> {
        self.lookup_batch_impl(cursor, maximum_count, true)
    }

    /// Updates a group of entries in one syscall.
    ///
    /// Returns the number of entries processed by the kernel.
    pub fn update_batch(&self, entries: &[(&[u8], &[u8])], mode: UpdateMode) -> Result<u32> {
        let count = u32::try_from(entries.len()).map_err(|_| {
            Error::InvalidObject("batch contains more than u32::MAX entries".into())
        })?;
        if entries.is_empty() {
            return Ok(0);
        }
        let key_size = usize::try_from(self.spec.key_size)
            .map_err(|_| Error::InvalidObject("map key size does not fit usize".into()))?;
        if key_size == 0 {
            return Err(Error::Unsupported(
                "batch update is not defined for keyless maps".into(),
            ));
        }
        let value_size = self.storage_value_size()?;
        let mut keys = Vec::with_capacity(
            key_size
                .checked_mul(entries.len())
                .ok_or_else(|| Error::InvalidObject("batch key size overflow".into()))?,
        );
        let mut values = Vec::with_capacity(
            value_size
                .checked_mul(entries.len())
                .ok_or_else(|| Error::InvalidObject("batch value size overflow".into()))?,
        );
        for (key, value) in entries {
            self.validate_key(key)?;
            self.validate_value(value)?;
            keys.extend_from_slice(key);
            values.extend_from_slice(value);
        }
        sys::map_update_batch(self.fd.as_raw_fd(), &keys, &values, count, mode.as_raw())
            .map_err(|source| Error::system("batch-update map elements", source))
    }

    /// Deletes a group of keys in one syscall.
    ///
    /// Returns the number of keys processed by the kernel.
    pub fn delete_batch(&self, keys: &[&[u8]]) -> Result<u32> {
        let count = u32::try_from(keys.len())
            .map_err(|_| Error::InvalidObject("batch contains more than u32::MAX keys".into()))?;
        if keys.is_empty() {
            return Ok(0);
        }
        let key_size = usize::try_from(self.spec.key_size)
            .map_err(|_| Error::InvalidObject("map key size does not fit usize".into()))?;
        if key_size == 0 {
            return Err(Error::Unsupported(
                "batch delete is not defined for keyless maps".into(),
            ));
        }
        let mut flattened = Vec::with_capacity(
            key_size
                .checked_mul(keys.len())
                .ok_or_else(|| Error::InvalidObject("batch key size overflow".into()))?,
        );
        for key in keys {
            self.validate_key(key)?;
            flattened.extend_from_slice(key);
        }
        sys::map_delete_batch(self.fd.as_raw_fd(), &flattened, count)
            .map_err(|source| Error::system("batch-delete map elements", source))
    }

    fn lookup_batch_impl(
        &self,
        cursor: Option<&BatchCursor>,
        maximum_count: u32,
        delete: bool,
    ) -> Result<MapBatch> {
        if maximum_count == 0 {
            return Err(Error::InvalidObject(
                "batch lookup count cannot be zero".into(),
            ));
        }
        let count = maximum_count as usize;
        let key_size = usize::try_from(self.spec.key_size)
            .map_err(|_| Error::InvalidObject("map key size does not fit usize".into()))?;
        if key_size == 0 {
            return Err(Error::Unsupported(
                "batch lookup is not defined for keyless maps".into(),
            ));
        }
        if let Some(cursor) = cursor {
            if cursor.0.len() != key_size {
                return Err(Error::SizeMismatch {
                    what: "batch cursor",
                    expected: key_size,
                    actual: cursor.0.len(),
                });
            }
        }
        let value_size = self.storage_value_size()?;
        let mut next_cursor = vec![0; key_size];
        let mut keys =
            vec![
                0;
                key_size
                    .checked_mul(count)
                    .ok_or_else(|| Error::InvalidObject("batch key allocation overflow".into()))?
            ];
        let mut values = vec![
            0;
            value_size.checked_mul(count).ok_or_else(|| {
                Error::InvalidObject("batch value allocation overflow".into())
            })?
        ];
        let result = sys::map_lookup_batch(&mut sys::BatchLookup {
            fd: self.fd.as_raw_fd(),
            cursor: cursor.map(|cursor| cursor.0.as_slice()),
            next_cursor: &mut next_cursor,
            keys: &mut keys,
            values: &mut values,
            count: maximum_count,
            delete,
        })
        .map_err(|source| Error::system("batch-lookup map elements", source))?;
        let actual = result.count as usize;
        keys.truncate(key_size * actual);
        values.truncate(value_size * actual);
        let entries = keys
            .chunks_exact(key_size)
            .zip(values.chunks_exact(value_size))
            .map(|(key, value)| (key.to_vec(), value.to_vec()))
            .collect();
        Ok(MapBatch {
            entries,
            cursor: (!result.done).then_some(BatchCursor(next_cursor)),
        })
    }

    fn validate_key(&self, key: &[u8]) -> Result<()> {
        validate_size("map key", self.spec.key_size, key.len())
    }

    fn validate_value(&self, value: &[u8]) -> Result<()> {
        let expected = self.storage_value_size()?;
        if value.len() != expected {
            Err(Error::SizeMismatch {
                what: "map value",
                expected,
                actual: value.len(),
            })
        } else {
            Ok(())
        }
    }

    fn storage_value_size(&self) -> Result<usize> {
        let logical = usize::try_from(self.spec.value_size)
            .map_err(|_| Error::InvalidObject("map value size does not fit usize".into()))?;
        if self.spec.map_type.is_per_cpu() {
            let stride = logical
                .checked_add(7)
                .map(|value| value & !7)
                .ok_or_else(|| Error::InvalidObject("per-CPU value size overflow".into()))?;
            stride
                .checked_mul(possible_cpu_count()?)
                .ok_or_else(|| Error::InvalidObject("per-CPU map allocation overflow".into()))
        } else {
            Ok(logical)
        }
    }
}

/// Iterator returned by [`Map::keys`].
#[derive(Debug)]
pub struct KeyIterator<'map> {
    map: &'map Map,
    previous: Option<Vec<u8>>,
    finished: bool,
}

impl Iterator for KeyIterator<'_> {
    type Item = Result<Vec<u8>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        let key_size = match usize::try_from(self.map.spec.key_size) {
            Ok(size) => size,
            Err(_) => {
                self.finished = true;
                return Some(Err(Error::InvalidObject(
                    "map key size does not fit usize".into(),
                )));
            }
        };
        let mut next = vec![0; key_size];
        match sys::map_next_key(self.map.fd.as_raw_fd(), self.previous.as_deref(), &mut next) {
            Ok(true) => {
                self.previous = Some(next.clone());
                Some(Ok(next))
            }
            Ok(false) => {
                self.finished = true;
                None
            }
            Err(source) => {
                self.finished = true;
                Some(Err(Error::system("iterate map keys", source)))
            }
        }
    }
}

pub(crate) fn possible_cpu_count() -> Result<usize> {
    let text = fs::read_to_string("/sys/devices/system/cpu/possible")
        .map_err(|source| Error::system("read possible CPU list", source))?;
    parse_cpu_list(text.trim())
}

fn parse_cpu_list(list: &str) -> Result<usize> {
    if list.is_empty() {
        return Err(Error::InvalidObject("possible CPU list is empty".into()));
    }
    let mut count = 0_usize;
    for range in list.split(',') {
        let (start, end) = match range.split_once('-') {
            Some((start, end)) => (parse_cpu(start)?, parse_cpu(end)?),
            None => {
                let cpu = parse_cpu(range)?;
                (cpu, cpu)
            }
        };
        if end < start {
            return Err(Error::InvalidObject(format!(
                "invalid descending CPU range `{range}`"
            )));
        }
        count = count
            .checked_add(end - start + 1)
            .ok_or_else(|| Error::InvalidObject("possible CPU count overflows usize".into()))?;
    }
    Ok(count)
}

fn parse_cpu(cpu: &str) -> Result<usize> {
    cpu.parse()
        .map_err(|_| Error::InvalidObject(format!("invalid CPU number `{cpu}`")))
}

fn validate_size(what: &'static str, expected: u32, actual: usize) -> Result<()> {
    let expected = usize::try_from(expected)
        .map_err(|_| Error::InvalidObject(format!("{what} size does not fit usize")))?;
    if actual == expected {
        Ok(())
    } else {
        Err(Error::SizeMismatch {
            what,
            expected,
            actual,
        })
    }
}

pub(crate) fn kernel_name(bytes: &[u8; sys::BPF_OBJ_NAME_LEN]) -> String {
    let len = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..len]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_types_round_trip_even_when_unknown() {
        for raw in 0..=40 {
            assert_eq!(MapType::from_raw(raw).as_raw(), raw);
        }
    }

    #[test]
    fn cpu_list_parser_supports_ranges_and_gaps() {
        assert_eq!(parse_cpu_list("0").unwrap(), 1);
        assert_eq!(parse_cpu_list("0-3").unwrap(), 4);
        assert_eq!(parse_cpu_list("0-3,8,10-11").unwrap(), 7);
        assert!(parse_cpu_list("3-1").is_err());
        assert!(parse_cpu_list("0-nope").is_err());
    }

    #[test]
    fn map_spec_enforces_inner_template() {
        let spec = MapSpec::new("outer", MapType::HashOfMaps, 4, 4, 8);
        assert!(spec
            .validate()
            .unwrap_err()
            .to_string()
            .contains("template"));
        assert!(MapSpec::new("events", MapType::RingBuffer, 0, 0, 0)
            .validate()
            .is_err());
        assert!(MapSpec::new("storage", MapType::TaskStorage, 4, 8, 0)
            .validate()
            .is_ok());
    }

    #[test]
    fn setters_preserve_invariants() {
        let mut spec = MapSpec::new("counts", MapType::Hash, 4, 8, 1);
        spec.set_numa_node(Some(2))
            .set_max_entries(1024)
            .set_pinning(Pinning::ByName);
        spec.set_initial_value(7_u64.to_ne_bytes()).unwrap();
        assert_eq!(spec.max_entries(), 1024);
        assert!(spec.flags().contains(MapFlags::NUMA_NODE));
        assert_eq!(spec.pinning(), Pinning::ByName);
        assert_eq!(spec.initial_value(), Some(7_u64.to_ne_bytes().as_slice()));
        assert!(spec.set_initial_value([0; 4]).is_err());
    }

    #[test]
    fn map_batch_exposes_entries_and_completion() {
        let batch = MapBatch {
            entries: vec![(vec![1], vec![2])],
            cursor: None,
        };
        assert!(batch.is_last());
        assert_eq!(batch.entries(), [(vec![1], vec![2])]);
    }
}
