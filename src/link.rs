use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::mem;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::sys;
use crate::{Error, Map, MapType, ObjectPathOptions, Program, Result, UpdateMode};

/// A Linux eBPF attachment type.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum AttachType {
    /// Cgroup IPv4/IPv6 ingress.
    CgroupInetIngress,
    /// Cgroup IPv4/IPv6 egress.
    CgroupInetEgress,
    /// Cgroup socket creation.
    CgroupInetSocketCreate,
    /// Cgroup socket operations.
    CgroupSocketOps,
    /// Stream parser.
    StreamParser,
    /// Stream verdict.
    StreamVerdict,
    /// Cgroup device access.
    CgroupDevice,
    /// Socket-message verdict.
    SocketMessageVerdict,
    /// IPv4 bind.
    CgroupInet4Bind,
    /// IPv6 bind.
    CgroupInet6Bind,
    /// IPv4 connect.
    CgroupInet4Connect,
    /// IPv6 connect.
    CgroupInet6Connect,
    /// IPv4 post-bind.
    CgroupInet4PostBind,
    /// IPv6 post-bind.
    CgroupInet6PostBind,
    /// IPv4 UDP send.
    CgroupUdp4SendMessage,
    /// IPv6 UDP send.
    CgroupUdp6SendMessage,
    /// Infrared input.
    LircMode2,
    /// Flow dissector.
    FlowDissector,
    /// Cgroup sysctl.
    CgroupSysctl,
    /// IPv4 UDP receive.
    CgroupUdp4ReceiveMessage,
    /// IPv6 UDP receive.
    CgroupUdp6ReceiveMessage,
    /// Cgroup getsockopt.
    CgroupGetSocketOption,
    /// Cgroup setsockopt.
    CgroupSetSocketOption,
    /// Raw tracepoint.
    TraceRawTracepoint,
    /// Function entry tracing.
    TraceFunctionEntry,
    /// Function exit tracing.
    TraceFunctionExit,
    /// Function return-value modification.
    ModifyReturn,
    /// LSM hook.
    LsmMac,
    /// BPF iterator.
    TraceIterator,
    /// IPv4 peer-name lookup.
    CgroupInet4GetPeerName,
    /// IPv6 peer-name lookup.
    CgroupInet6GetPeerName,
    /// IPv4 local-name lookup.
    CgroupInet4GetSocketName,
    /// IPv6 local-name lookup.
    CgroupInet6GetSocketName,
    /// XDP device-map program.
    XdpDeviceMap,
    /// Cgroup socket release.
    CgroupInetSocketRelease,
    /// XDP CPU-map program.
    XdpCpuMap,
    /// Socket lookup.
    SocketLookup,
    /// XDP network-device link.
    Xdp,
    /// Socket verdict.
    SocketVerdict,
    /// Reuseport selection.
    ReuseportSelect,
    /// Reuseport selection or migration.
    ReuseportSelectOrMigrate,
    /// Perf event.
    PerfEvent,
    /// Multi-kprobe.
    TraceKprobeMulti,
    /// Cgroup LSM hook.
    LsmCgroup,
    /// Struct operations.
    StructOps,
    /// Netfilter hook.
    Netfilter,
    /// TC ingress link.
    TcxIngress,
    /// TC egress link.
    TcxEgress,
    /// Multi-uprobe.
    TraceUprobeMulti,
    /// Unix-domain connect.
    CgroupUnixConnect,
    /// Unix-domain send.
    CgroupUnixSendMessage,
    /// Unix-domain receive.
    CgroupUnixReceiveMessage,
    /// Unix-domain peer-name lookup.
    CgroupUnixGetPeerName,
    /// Unix-domain local-name lookup.
    CgroupUnixGetSocketName,
    /// Primary netkit device.
    NetkitPrimary,
    /// Peer netkit device.
    NetkitPeer,
    /// Kprobe session.
    TraceKprobeSession,
    /// Uprobe session.
    TraceUprobeSession,
    /// Function tracing session.
    TraceFunctionSession,
    /// Multi-function entry tracing.
    TraceFunctionEntryMulti,
    /// Multi-function exit tracing.
    TraceFunctionExitMulti,
    /// Multi-function tracing session.
    TraceFunctionSessionMulti,
    /// A type introduced after this crate version.
    Other(u32),
}

impl AttachType {
    /// Converts a Linux UAPI value.
    pub const fn from_raw(value: u32) -> Self {
        match value {
            0 => Self::CgroupInetIngress,
            1 => Self::CgroupInetEgress,
            2 => Self::CgroupInetSocketCreate,
            3 => Self::CgroupSocketOps,
            4 => Self::StreamParser,
            5 => Self::StreamVerdict,
            6 => Self::CgroupDevice,
            7 => Self::SocketMessageVerdict,
            8 => Self::CgroupInet4Bind,
            9 => Self::CgroupInet6Bind,
            10 => Self::CgroupInet4Connect,
            11 => Self::CgroupInet6Connect,
            12 => Self::CgroupInet4PostBind,
            13 => Self::CgroupInet6PostBind,
            14 => Self::CgroupUdp4SendMessage,
            15 => Self::CgroupUdp6SendMessage,
            16 => Self::LircMode2,
            17 => Self::FlowDissector,
            18 => Self::CgroupSysctl,
            19 => Self::CgroupUdp4ReceiveMessage,
            20 => Self::CgroupUdp6ReceiveMessage,
            21 => Self::CgroupGetSocketOption,
            22 => Self::CgroupSetSocketOption,
            23 => Self::TraceRawTracepoint,
            24 => Self::TraceFunctionEntry,
            25 => Self::TraceFunctionExit,
            26 => Self::ModifyReturn,
            27 => Self::LsmMac,
            28 => Self::TraceIterator,
            29 => Self::CgroupInet4GetPeerName,
            30 => Self::CgroupInet6GetPeerName,
            31 => Self::CgroupInet4GetSocketName,
            32 => Self::CgroupInet6GetSocketName,
            33 => Self::XdpDeviceMap,
            34 => Self::CgroupInetSocketRelease,
            35 => Self::XdpCpuMap,
            36 => Self::SocketLookup,
            37 => Self::Xdp,
            38 => Self::SocketVerdict,
            39 => Self::ReuseportSelect,
            40 => Self::ReuseportSelectOrMigrate,
            41 => Self::PerfEvent,
            42 => Self::TraceKprobeMulti,
            43 => Self::LsmCgroup,
            44 => Self::StructOps,
            45 => Self::Netfilter,
            46 => Self::TcxIngress,
            47 => Self::TcxEgress,
            48 => Self::TraceUprobeMulti,
            49 => Self::CgroupUnixConnect,
            50 => Self::CgroupUnixSendMessage,
            51 => Self::CgroupUnixReceiveMessage,
            52 => Self::CgroupUnixGetPeerName,
            53 => Self::CgroupUnixGetSocketName,
            54 => Self::NetkitPrimary,
            55 => Self::NetkitPeer,
            56 => Self::TraceKprobeSession,
            57 => Self::TraceUprobeSession,
            58 => Self::TraceFunctionSession,
            59 => Self::TraceFunctionEntryMulti,
            60 => Self::TraceFunctionExitMulti,
            61 => Self::TraceFunctionSessionMulti,
            value => Self::Other(value),
        }
    }

    /// Returns the Linux UAPI value.
    pub const fn as_raw(self) -> u32 {
        match self {
            Self::CgroupInetIngress => 0,
            Self::CgroupInetEgress => 1,
            Self::CgroupInetSocketCreate => 2,
            Self::CgroupSocketOps => 3,
            Self::StreamParser => 4,
            Self::StreamVerdict => 5,
            Self::CgroupDevice => 6,
            Self::SocketMessageVerdict => 7,
            Self::CgroupInet4Bind => 8,
            Self::CgroupInet6Bind => 9,
            Self::CgroupInet4Connect => 10,
            Self::CgroupInet6Connect => 11,
            Self::CgroupInet4PostBind => 12,
            Self::CgroupInet6PostBind => 13,
            Self::CgroupUdp4SendMessage => 14,
            Self::CgroupUdp6SendMessage => 15,
            Self::LircMode2 => 16,
            Self::FlowDissector => 17,
            Self::CgroupSysctl => 18,
            Self::CgroupUdp4ReceiveMessage => 19,
            Self::CgroupUdp6ReceiveMessage => 20,
            Self::CgroupGetSocketOption => 21,
            Self::CgroupSetSocketOption => 22,
            Self::TraceRawTracepoint => 23,
            Self::TraceFunctionEntry => 24,
            Self::TraceFunctionExit => 25,
            Self::ModifyReturn => 26,
            Self::LsmMac => 27,
            Self::TraceIterator => 28,
            Self::CgroupInet4GetPeerName => 29,
            Self::CgroupInet6GetPeerName => 30,
            Self::CgroupInet4GetSocketName => 31,
            Self::CgroupInet6GetSocketName => 32,
            Self::XdpDeviceMap => 33,
            Self::CgroupInetSocketRelease => 34,
            Self::XdpCpuMap => 35,
            Self::SocketLookup => 36,
            Self::Xdp => 37,
            Self::SocketVerdict => 38,
            Self::ReuseportSelect => 39,
            Self::ReuseportSelectOrMigrate => 40,
            Self::PerfEvent => 41,
            Self::TraceKprobeMulti => 42,
            Self::LsmCgroup => 43,
            Self::StructOps => 44,
            Self::Netfilter => 45,
            Self::TcxIngress => 46,
            Self::TcxEgress => 47,
            Self::TraceUprobeMulti => 48,
            Self::CgroupUnixConnect => 49,
            Self::CgroupUnixSendMessage => 50,
            Self::CgroupUnixReceiveMessage => 51,
            Self::CgroupUnixGetPeerName => 52,
            Self::CgroupUnixGetSocketName => 53,
            Self::NetkitPrimary => 54,
            Self::NetkitPeer => 55,
            Self::TraceKprobeSession => 56,
            Self::TraceUprobeSession => 57,
            Self::TraceFunctionSession => 58,
            Self::TraceFunctionEntryMulti => 59,
            Self::TraceFunctionExitMulti => 60,
            Self::TraceFunctionSessionMulti => 61,
            Self::Other(value) => value,
        }
    }
}

/// Kernel type of a `bpf_link` object.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum LinkType {
    /// Unspecified.
    Unspecified,
    /// Raw tracepoint.
    RawTracepoint,
    /// BTF tracing, LSM, or extension.
    Tracing,
    /// Cgroup.
    Cgroup,
    /// BPF iterator.
    Iterator,
    /// Network namespace.
    NetworkNamespace,
    /// XDP.
    Xdp,
    /// Perf event.
    PerfEvent,
    /// Multi-kprobe or kprobe session.
    KprobeMulti,
    /// `struct_ops`.
    StructOps,
    /// Netfilter.
    Netfilter,
    /// TCX.
    Tcx,
    /// Multi-uprobe or uprobe session.
    UprobeMulti,
    /// Netkit.
    Netkit,
    /// Socket map.
    SocketMap,
    /// Multi-function BTF tracing.
    TracingMulti,
    /// A type introduced after this crate version.
    Other(u32),
}

impl LinkType {
    /// Converts a Linux UAPI value.
    pub const fn from_raw(value: u32) -> Self {
        match value {
            0 => Self::Unspecified,
            1 => Self::RawTracepoint,
            2 => Self::Tracing,
            3 => Self::Cgroup,
            4 => Self::Iterator,
            5 => Self::NetworkNamespace,
            6 => Self::Xdp,
            7 => Self::PerfEvent,
            8 => Self::KprobeMulti,
            9 => Self::StructOps,
            10 => Self::Netfilter,
            11 => Self::Tcx,
            12 => Self::UprobeMulti,
            13 => Self::Netkit,
            14 => Self::SocketMap,
            15 => Self::TracingMulti,
            value => Self::Other(value),
        }
    }

    /// Returns the Linux UAPI value.
    pub const fn as_raw(self) -> u32 {
        match self {
            Self::Unspecified => 0,
            Self::RawTracepoint => 1,
            Self::Tracing => 2,
            Self::Cgroup => 3,
            Self::Iterator => 4,
            Self::NetworkNamespace => 5,
            Self::Xdp => 6,
            Self::PerfEvent => 7,
            Self::KprobeMulti => 8,
            Self::StructOps => 9,
            Self::Netfilter => 10,
            Self::Tcx => 11,
            Self::UprobeMulti => 12,
            Self::Netkit => 13,
            Self::SocketMap => 14,
            Self::TracingMulti => 15,
            Self::Other(value) => value,
        }
    }
}

/// Target-specific metadata for a BPF iterator link.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum IteratorLinkTarget {
    /// Iterator over entries of one map.
    Map {
        /// Kernel ID of the selected map.
        map_id: u32,
    },
    /// Iterator over a cgroup hierarchy.
    Cgroup {
        /// Kernel ID of the starting cgroup.
        cgroup_id: u64,
        /// Hierarchy traversal order.
        order: CgroupLinkOrder,
    },
    /// Iterator over a task, task files, or task VMAs.
    Task {
        /// Selected thread ID, or zero for all threads.
        thread_id: u32,
        /// Selected process ID, or zero for all processes.
        process_id: u32,
    },
    /// Target not decoded by this crate version.
    Other,
}

/// Traversal order used by a cgroup iterator.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum CgroupLinkOrder {
    /// Kernel-selected default traversal.
    Unspecified,
    /// Visit only the selected cgroup.
    SelfOnly,
    /// Visit descendants in pre-order.
    DescendantsPre,
    /// Visit descendants in post-order.
    DescendantsPost,
    /// Walk from the selected cgroup toward its ancestors.
    AncestorsUp,
    /// Visit direct children.
    Children,
    /// Value introduced after this crate version.
    Other(u32),
}

impl CgroupLinkOrder {
    const fn from_raw(value: u32) -> Self {
        match value {
            0 => Self::Unspecified,
            1 => Self::SelfOnly,
            2 => Self::DescendantsPre,
            3 => Self::DescendantsPost,
            4 => Self::AncestorsUp,
            5 => Self::Children,
            value => Self::Other(value),
        }
    }
}

/// Decoded metadata for a perf-event BPF link.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PerfEventLinkDetails {
    /// Userspace probe or return probe.
    Uprobe {
        /// Probed executable path, when disclosed by the kernel.
        path: Option<PathBuf>,
        /// Whether this is a return probe.
        return_probe: bool,
        /// File offset of the probe.
        offset: u32,
        /// Caller-supplied attachment cookie.
        cookie: u64,
        /// File offset of the USDT reference counter.
        reference_counter_offset: u64,
    },
    /// Kernel probe or return probe.
    Kprobe {
        /// Probed kernel function, when disclosed by the kernel.
        function: Option<String>,
        /// Whether this is a return probe.
        return_probe: bool,
        /// Offset from the function entry.
        offset: u32,
        /// Resolved kernel address.
        address: u64,
        /// Number of missed probe hits.
        missed: u64,
        /// Caller-supplied attachment cookie.
        cookie: u64,
    },
    /// Tracepoint event.
    Tracepoint {
        /// Tracepoint name, when disclosed by the kernel.
        name: Option<String>,
        /// Caller-supplied attachment cookie.
        cookie: u64,
    },
    /// Generic perf event.
    Event {
        /// Perf-event configuration value.
        config: u64,
        /// Perf-event type.
        event_type: u32,
        /// Caller-supplied attachment cookie.
        cookie: u64,
    },
    /// Perf-event subtype not decoded by this crate version.
    Other(u32),
}

/// Type-specific metadata from the `bpf_link_info` union.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum LinkDetails {
    /// No type-specific metadata.
    Unspecified,
    /// Raw tracepoint target.
    RawTracepoint {
        /// Tracepoint name.
        name: String,
        /// Caller-supplied attachment cookie.
        cookie: u64,
    },
    /// BTF tracing, LSM, or extension target.
    Tracing {
        /// Hook attachment type.
        attach_type: AttachType,
        /// Kernel ID of the target program or BTF object.
        target_btf_object_id: u32,
        /// Type ID within the target BTF object.
        target_btf_id: u32,
        /// Caller-supplied attachment cookie.
        cookie: u64,
    },
    /// Cgroup target.
    Cgroup {
        /// Kernel ID of the target cgroup.
        cgroup_id: u64,
        /// Hook attachment type.
        attach_type: AttachType,
    },
    /// Iterator target and decoded iterator-specific selector.
    Iterator {
        /// Kernel iterator target name.
        target_name: String,
        /// Target-specific selector.
        target: IteratorLinkTarget,
    },
    /// Network-namespace target.
    NetworkNamespace {
        /// Network namespace inode.
        inode: u32,
        /// Hook attachment type.
        attach_type: AttachType,
    },
    /// XDP network-device target.
    Xdp {
        /// Target network interface index.
        interface_index: u32,
    },
    /// Perf-event target.
    PerfEvent(PerfEventLinkDetails),
    /// Multiple kernel-probe targets.
    KprobeMulti {
        /// Kernel attachment flags.
        flags: u32,
        /// Number of missed probe hits.
        missed: u64,
        /// Resolved target addresses.
        addresses: Vec<u64>,
        /// Attachment cookies corresponding to the addresses.
        cookies: Vec<u64>,
    },
    /// Map backing a `struct_ops` link.
    StructOps {
        /// Kernel ID of the backing map.
        map_id: u32,
    },
    /// Netfilter hook target.
    Netfilter {
        /// Network protocol family.
        protocol_family: u32,
        /// Netfilter hook number.
        hook_number: u32,
        /// Hook priority.
        priority: i32,
        /// Kernel attachment flags.
        flags: u32,
    },
    /// TCX network-device target.
    Tcx {
        /// Target network interface index.
        interface_index: u32,
        /// Hook attachment type.
        attach_type: AttachType,
    },
    /// Multiple userspace-probe targets.
    UprobeMulti {
        /// Probed executable path, when disclosed by the kernel.
        path: Option<PathBuf>,
        /// Kernel attachment flags.
        flags: u32,
        /// Target process ID, or zero for all processes.
        process_id: u32,
        /// File offsets of the probes.
        offsets: Vec<u64>,
        /// USDT reference-counter offsets corresponding to the probes.
        reference_counter_offsets: Vec<u64>,
        /// Attachment cookies corresponding to the probes.
        cookies: Vec<u64>,
    },
    /// Netkit network-device target.
    Netkit {
        /// Target network interface index.
        interface_index: u32,
        /// Hook attachment type.
        attach_type: AttachType,
    },
    /// Socket-map target.
    SocketMap {
        /// Kernel ID of the target socket map.
        map_id: u32,
        /// Hook attachment type.
        attach_type: AttachType,
    },
    /// Multiple BTF tracing targets.
    TracingMulti {
        /// Hook attachment type.
        attach_type: AttachType,
        /// Kernel ID of the target BTF object.
        btf_object_id: u32,
        /// Target type IDs.
        type_ids: Vec<u32>,
        /// Resolved target addresses.
        addresses: Vec<u64>,
        /// Attachment cookies corresponding to the targets.
        cookies: Vec<u64>,
    },
    /// Type introduced after this crate version.
    Other([u8; 48]),
}

/// Metadata common to a kernel `bpf_link`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinkInfo {
    /// Kernel-assigned link ID.
    pub id: u32,
    /// Link type.
    pub link_type: LinkType,
    /// Attached program ID.
    pub program_id: u32,
    /// Hook attachment type when exposed by this link kind.
    pub attach_type: Option<AttachType>,
    /// Network interface index for device links.
    pub interface_index: Option<u32>,
    /// Map ID for map-backed links.
    pub map_id: Option<u32>,
    /// BTF object ID for tracing links.
    pub target_btf_object_id: Option<u32>,
    /// BTF type ID for tracing links.
    pub target_btf_id: Option<u32>,
    /// Cgroup kernel ID for cgroup links.
    pub cgroup_id: Option<u64>,
    /// Fully decoded type-specific metadata.
    pub details: LinkDetails,
}

enum LinkFd {
    Bpf(OwnedFd),
    BpfPerfEvent {
        link: OwnedFd,
        event: OwnedFd,
    },
    PerfEvents(Vec<OwnedFd>),
    Socket(OwnedFd),
    Legacy {
        target: OwnedFd,
        program: OwnedFd,
        attach_type: AttachType,
    },
    StructOpsLegacy(Arc<OwnedFd>),
    Detached,
}

/// An owned eBPF attachment.
///
/// Dropping a link closes its file descriptor(s), atomically detaching the
/// program unless the link was pinned.
pub struct Link {
    fd: LinkFd,
    cleanup: Option<Box<dyn FnOnce() + Send>>,
}

impl fmt::Debug for Link {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.fd {
            LinkFd::Bpf(fd) => formatter
                .debug_struct("Link")
                .field("bpf_fd", &fd.as_raw_fd())
                .finish(),
            LinkFd::BpfPerfEvent { link, event } => formatter
                .debug_struct("Link")
                .field("bpf_fd", &link.as_raw_fd())
                .field("perf_event_fd", &event.as_raw_fd())
                .finish(),
            LinkFd::PerfEvents(fds) => formatter
                .debug_struct("Link")
                .field(
                    "perf_event_fds",
                    &fds.iter().map(AsRawFd::as_raw_fd).collect::<Vec<_>>(),
                )
                .finish(),
            LinkFd::Socket(fd) => formatter
                .debug_struct("Link")
                .field("socket_fd", &fd.as_raw_fd())
                .finish(),
            LinkFd::Legacy {
                target,
                program,
                attach_type,
            } => formatter
                .debug_struct("Link")
                .field("legacy_target_fd", &target.as_raw_fd())
                .field("program_fd", &program.as_raw_fd())
                .field("attach_type", attach_type)
                .finish(),
            LinkFd::StructOpsLegacy(fd) => formatter
                .debug_struct("Link")
                .field("legacy_struct_ops_map_fd", &fd.as_raw_fd())
                .finish(),
            LinkFd::Detached => formatter.write_str("Link { detached: true }"),
        }
    }
}

impl Link {
    pub(crate) fn bpf(fd: OwnedFd) -> Self {
        Self {
            fd: LinkFd::Bpf(fd),
            cleanup: None,
        }
    }

    pub(crate) fn perf_events(fds: Vec<OwnedFd>) -> Self {
        Self {
            fd: LinkFd::PerfEvents(fds),
            cleanup: None,
        }
    }

    pub(crate) fn bpf_perf_event(link: OwnedFd, event: OwnedFd) -> Self {
        Self {
            fd: LinkFd::BpfPerfEvent { link, event },
            cleanup: None,
        }
    }

    pub(crate) fn socket(fd: OwnedFd) -> Self {
        Self {
            fd: LinkFd::Socket(fd),
            cleanup: None,
        }
    }

    pub(crate) fn legacy(target: OwnedFd, program: OwnedFd, attach_type: AttachType) -> Self {
        Self {
            fd: LinkFd::Legacy {
                target,
                program,
                attach_type,
            },
            cleanup: None,
        }
    }

    pub(crate) fn struct_ops_legacy(map: Arc<OwnedFd>) -> Self {
        Self {
            fd: LinkFd::StructOpsLegacy(map),
            cleanup: None,
        }
    }

    pub(crate) fn with_cleanup(mut self, cleanup: impl FnOnce() + Send + 'static) -> Self {
        self.cleanup = Some(Box::new(cleanup));
        self
    }

    /// Opens a link pinned in bpffs.
    pub fn open_pinned(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_pinned_with(path, ObjectPathOptions::new())
    }

    /// Opens a pinned link with access flags or directory-relative resolution.
    pub fn open_pinned_with(
        path: impl AsRef<Path>,
        options: ObjectPathOptions<'_>,
    ) -> Result<Self> {
        let path = path.as_ref();
        let (flags, directory) = options.raw_for_open();
        let fd = sys::object_get_with(path, flags, directory).map_err(|source| Error::File {
            operation: "open pinned link",
            path: path.into(),
            source,
        })?;
        Ok(Self::bpf(fd))
    }

    /// Opens a link by its kernel ID.
    pub fn from_id(id: u32) -> Result<Self> {
        let fd = sys::object_get_fd_by_id(sys::ObjectKind::Link, id)
            .map_err(|source| Error::system("open link by ID", source))?;
        Ok(Self::bpf(fd))
    }

    /// Borrows the link FD when this is a kernel `bpf_link`.
    ///
    /// Perf-event based attachments consist of multiple descriptors and return
    /// `None`.
    pub fn as_fd(&self) -> Option<BorrowedFd<'_>> {
        match &self.fd {
            LinkFd::Bpf(fd) => Some(fd.as_fd()),
            LinkFd::BpfPerfEvent { link, .. } => Some(link.as_fd()),
            LinkFd::PerfEvents(_)
            | LinkFd::Socket(_)
            | LinkFd::Legacy { .. }
            | LinkFd::StructOpsLegacy(_)
            | LinkFd::Detached => None,
        }
    }

    /// Pins a kernel link in bpffs so it outlives this process.
    pub fn pin(&self, path: impl AsRef<Path>) -> Result<()> {
        self.pin_with(path, ObjectPathOptions::new())
    }

    /// Pins this link with optional directory-relative resolution.
    pub fn pin_with(&self, path: impl AsRef<Path>, options: ObjectPathOptions<'_>) -> Result<()> {
        let path = path.as_ref();
        let fd = match &self.fd {
            LinkFd::Bpf(fd) => fd,
            LinkFd::BpfPerfEvent { link, .. } => link,
            _ => {
                return Err(Error::Unsupported(
                    "this attachment is not represented by one pinnable bpf_link".into(),
                ));
            }
        };
        let directory = options.raw_for_pin()?;
        sys::object_pin_with(fd.as_raw_fd(), path, 0, directory).map_err(|source| Error::File {
            operation: "pin link",
            path: path.into(),
            source,
        })
    }

    /// Removes a bpffs pin without detaching this live link handle.
    pub fn unpin(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        fs::remove_file(path).map_err(|source| Error::File {
            operation: "unpin link",
            path: path.into(),
            source,
        })
    }

    /// Atomically changes a kernel link to run `program`.
    pub fn update(&self, program: &Program) -> Result<()> {
        self.update_if(program, None)
    }

    /// Atomically changes a kernel link only if it still runs `expected`.
    pub fn update_if(&self, program: &Program, expected: Option<&Program>) -> Result<()> {
        let fd = match &self.fd {
            LinkFd::Bpf(fd) => fd,
            LinkFd::BpfPerfEvent { link, .. } => link,
            _ => {
                return Err(Error::Unsupported(
                    "only individual kernel bpf_link attachments support program updates".into(),
                ));
            }
        };
        sys::link_update(
            fd.as_raw_fd(),
            program.as_fd().as_raw_fd(),
            expected.map(|program| program.as_fd().as_raw_fd()),
        )
        .map_err(|source| Error::system("update eBPF link program", source))
    }

    /// Replaces the struct-ops map backing this kernel link.
    pub fn update_struct_ops(&self, map: &Map) -> Result<()> {
        if map.spec().map_type() != MapType::StructOps {
            return Err(Error::InvalidObject(format!(
                "map `{}` is not a struct_ops map",
                map.name()
            )));
        }
        let fd = match &self.fd {
            LinkFd::Bpf(fd) => fd,
            _ => {
                return Err(Error::Unsupported(
                    "only a kernel struct_ops link can swap its backing map".into(),
                ));
            }
        };
        if self.info()?.link_type != LinkType::StructOps {
            return Err(Error::InvalidObject("link is not a struct_ops link".into()));
        }
        let value = map.spec().initial_value().ok_or_else(|| {
            Error::InvalidObject(format!(
                "struct_ops map `{}` has no prepared implementation value",
                map.name()
            ))
        })?;
        match map.update(&0_u32.to_ne_bytes(), value, UpdateMode::Any) {
            Ok(()) => {}
            Err(Error::System { source, .. }) if source.raw_os_error() == Some(libc::EBUSY) => {}
            Err(error) => return Err(error),
        }
        sys::link_update_map(fd.as_raw_fd(), map.as_fd().as_raw_fd())
            .map_err(|source| Error::system("update struct_ops link map", source))
    }

    /// Reads current metadata for a kernel `bpf_link`.
    pub fn info(&self) -> Result<LinkInfo> {
        let fd = match &self.fd {
            LinkFd::Bpf(fd) => fd,
            LinkFd::BpfPerfEvent { link, .. } => link,
            _ => {
                return Err(Error::Unsupported(
                    "this attachment is not represented by one kernel bpf_link".into(),
                ));
            }
        };
        let mut raw = sys::link_info(fd.as_raw_fd())
            .map_err(|source| Error::system("read eBPF link metadata", source))?;
        let link_type = LinkType::from_raw(raw.link_type);
        let details = decode_link_details(fd.as_raw_fd(), &mut raw, link_type)?;
        let attach_type = match link_type {
            LinkType::Tracing => Some(AttachType::from_raw(detail_u32(&raw.details, 0))),
            LinkType::Cgroup => Some(AttachType::from_raw(detail_u32(&raw.details, 8))),
            LinkType::Tcx | LinkType::Netkit | LinkType::SocketMap => {
                Some(AttachType::from_raw(detail_u32(&raw.details, 4)))
            }
            _ => None,
        };
        Ok(LinkInfo {
            id: raw.id,
            link_type,
            program_id: raw.program_id,
            attach_type,
            interface_index: matches!(link_type, LinkType::Xdp | LinkType::Tcx | LinkType::Netkit)
                .then(|| detail_u32(&raw.details, 0)),
            map_id: matches!(link_type, LinkType::StructOps | LinkType::SocketMap)
                .then(|| detail_u32(&raw.details, 0)),
            target_btf_object_id: (link_type == LinkType::Tracing)
                .then(|| detail_u32(&raw.details, 4)),
            target_btf_id: (link_type == LinkType::Tracing).then(|| detail_u32(&raw.details, 8)),
            cgroup_id: (link_type == LinkType::Cgroup).then(|| detail_u64(&raw.details, 0)),
            details,
        })
    }

    /// Explicitly detaches the link.
    ///
    /// Dropping an unpinned link also detaches it. Explicit detach is useful
    /// for a pinned link because it marks the kernel link inactive.
    pub fn detach(mut self) -> Result<()> {
        let fd = mem::replace(&mut self.fd, LinkFd::Detached);
        match fd {
            LinkFd::Bpf(fd) => sys::link_detach(fd.as_raw_fd())
                .map_err(|source| Error::system("detach eBPF link", source)),
            LinkFd::BpfPerfEvent { link, event } => {
                sys::perf_event_disable(event.as_raw_fd())
                    .map_err(|source| Error::system("disable perf event", source))?;
                sys::link_detach(link.as_raw_fd())
                    .map_err(|source| Error::system("detach eBPF link", source))
            }
            LinkFd::Socket(fd) => sys::socket_detach_bpf(fd.as_raw_fd())
                .map_err(|source| Error::system("detach socket filter", source)),
            LinkFd::Legacy {
                target,
                program,
                attach_type,
            } => sys::program_detach(
                program.as_raw_fd(),
                target.as_raw_fd(),
                attach_type.as_raw(),
            )
            .map_err(|source| Error::system("detach legacy eBPF program", source)),
            LinkFd::StructOpsLegacy(map) => {
                sys::map_delete(map.as_raw_fd(), &0_u32.to_ne_bytes(), 0)
                    .map(drop)
                    .map_err(|source| Error::system("detach legacy struct_ops map", source))
            }
            LinkFd::PerfEvents(_) | LinkFd::Detached => Ok(()),
        }
    }
}

const MAX_LINK_INFO_ITEMS: usize = 1 << 20;
const MAX_LINK_INFO_STRING: usize = 1 << 20;
const DEFAULT_LINK_INFO_STRING: usize = 4096;

fn detail_u32(details: &[u8; 48], offset: usize) -> u32 {
    u32::from_ne_bytes(
        details[offset..offset + 4]
            .try_into()
            .expect("fixed link-info u32 range"),
    )
}

fn detail_i32(details: &[u8; 48], offset: usize) -> i32 {
    i32::from_ne_bytes(
        details[offset..offset + 4]
            .try_into()
            .expect("fixed link-info i32 range"),
    )
}

fn detail_u64(details: &[u8; 48], offset: usize) -> u64 {
    u64::from_ne_bytes(
        details[offset..offset + 8]
            .try_into()
            .expect("fixed link-info u64 range"),
    )
}

fn set_detail_u32(details: &mut [u8; 48], offset: usize, value: u32) {
    details[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
}

fn set_detail_u64(details: &mut [u8; 48], offset: usize, value: u64) {
    details[offset..offset + 8].copy_from_slice(&value.to_ne_bytes());
}

fn link_info_string_buffer(reported: u32) -> Result<Vec<u8>> {
    let capacity = (reported as usize).max(DEFAULT_LINK_INFO_STRING);
    if capacity > MAX_LINK_INFO_STRING {
        return Err(Error::InvalidObject(format!(
            "kernel link-info string length {capacity} is unreasonable"
        )));
    }
    Ok(vec![0; capacity])
}

fn link_info_u64_buffer(count: u32) -> Result<Vec<u64>> {
    let count = count as usize;
    if count > MAX_LINK_INFO_ITEMS {
        return Err(Error::InvalidObject(format!(
            "kernel link-info item count {count} is unreasonable"
        )));
    }
    Ok(vec![0; count])
}

fn link_info_u32_buffer(count: u32) -> Result<Vec<u32>> {
    let count = count as usize;
    if count > MAX_LINK_INFO_ITEMS {
        return Err(Error::InvalidObject(format!(
            "kernel link-info item count {count} is unreasonable"
        )));
    }
    Ok(vec![0; count])
}

fn buffer_bytes(buffer: &[u8], reported: u32) -> &[u8] {
    let end = (reported as usize).min(buffer.len());
    let bytes = &buffer[..end];
    let nul = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    &bytes[..nul]
}

fn buffer_string(buffer: &[u8], reported: u32) -> String {
    String::from_utf8_lossy(buffer_bytes(buffer, reported)).into_owned()
}

fn buffer_path(buffer: &[u8], reported: u32) -> Option<PathBuf> {
    (reported != 0)
        .then(|| PathBuf::from(OsString::from_vec(buffer_bytes(buffer, reported).into())))
}

fn refresh_link_info(fd: i32, raw: &mut sys::LinkInfoRaw) -> Result<()> {
    sys::link_info_into(fd, raw)
        .map_err(|source| Error::system("read detailed eBPF link metadata", source))
}

fn decode_link_details(
    fd: i32,
    raw: &mut sys::LinkInfoRaw,
    link_type: LinkType,
) -> Result<LinkDetails> {
    match link_type {
        LinkType::Unspecified => Ok(LinkDetails::Unspecified),
        LinkType::RawTracepoint => {
            let mut name = link_info_string_buffer(detail_u32(&raw.details, 8))?;
            set_detail_u64(&mut raw.details, 0, name.as_mut_ptr() as usize as u64);
            set_detail_u32(
                &mut raw.details,
                8,
                u32::try_from(name.len()).unwrap_or(u32::MAX),
            );
            refresh_link_info(fd, raw)?;
            Ok(LinkDetails::RawTracepoint {
                name: buffer_string(&name, detail_u32(&raw.details, 8)),
                cookie: detail_u64(&raw.details, 16),
            })
        }
        LinkType::Tracing => Ok(LinkDetails::Tracing {
            attach_type: AttachType::from_raw(detail_u32(&raw.details, 0)),
            target_btf_object_id: detail_u32(&raw.details, 4),
            target_btf_id: detail_u32(&raw.details, 8),
            cookie: detail_u64(&raw.details, 16),
        }),
        LinkType::Cgroup => Ok(LinkDetails::Cgroup {
            cgroup_id: detail_u64(&raw.details, 0),
            attach_type: AttachType::from_raw(detail_u32(&raw.details, 8)),
        }),
        LinkType::Iterator => {
            let mut name = link_info_string_buffer(detail_u32(&raw.details, 8))?;
            set_detail_u64(&mut raw.details, 0, name.as_mut_ptr() as usize as u64);
            set_detail_u32(
                &mut raw.details,
                8,
                u32::try_from(name.len()).unwrap_or(u32::MAX),
            );
            refresh_link_info(fd, raw)?;
            let target_name = buffer_string(&name, detail_u32(&raw.details, 8));
            let target = match target_name.as_str() {
                "bpf_map_elem" | "bpf_sk_storage_map" => IteratorLinkTarget::Map {
                    map_id: detail_u32(&raw.details, 12),
                },
                "cgroup" => IteratorLinkTarget::Cgroup {
                    cgroup_id: detail_u64(&raw.details, 16),
                    order: CgroupLinkOrder::from_raw(detail_u32(&raw.details, 24)),
                },
                "task" | "task_file" | "task_vma" => IteratorLinkTarget::Task {
                    thread_id: detail_u32(&raw.details, 16),
                    process_id: detail_u32(&raw.details, 20),
                },
                _ => IteratorLinkTarget::Other,
            };
            Ok(LinkDetails::Iterator {
                target_name,
                target,
            })
        }
        LinkType::NetworkNamespace => Ok(LinkDetails::NetworkNamespace {
            inode: detail_u32(&raw.details, 0),
            attach_type: AttachType::from_raw(detail_u32(&raw.details, 4)),
        }),
        LinkType::Xdp => Ok(LinkDetails::Xdp {
            interface_index: detail_u32(&raw.details, 0),
        }),
        LinkType::PerfEvent => decode_perf_event_details(fd, raw),
        LinkType::KprobeMulti => {
            let capacity = detail_u32(&raw.details, 8);
            let mut addresses = link_info_u64_buffer(capacity)?;
            let mut cookies = link_info_u64_buffer(capacity)?;
            set_detail_u64(&mut raw.details, 0, addresses.as_mut_ptr() as usize as u64);
            set_detail_u64(&mut raw.details, 24, cookies.as_mut_ptr() as usize as u64);
            refresh_link_info(fd, raw)?;
            let count = (detail_u32(&raw.details, 8) as usize).min(addresses.len());
            addresses.truncate(count);
            cookies.truncate(count);
            Ok(LinkDetails::KprobeMulti {
                flags: detail_u32(&raw.details, 12),
                missed: detail_u64(&raw.details, 16),
                addresses,
                cookies,
            })
        }
        LinkType::StructOps => Ok(LinkDetails::StructOps {
            map_id: detail_u32(&raw.details, 0),
        }),
        LinkType::Netfilter => Ok(LinkDetails::Netfilter {
            protocol_family: detail_u32(&raw.details, 0),
            hook_number: detail_u32(&raw.details, 4),
            priority: detail_i32(&raw.details, 8),
            flags: detail_u32(&raw.details, 12),
        }),
        LinkType::Tcx => Ok(LinkDetails::Tcx {
            interface_index: detail_u32(&raw.details, 0),
            attach_type: AttachType::from_raw(detail_u32(&raw.details, 4)),
        }),
        LinkType::UprobeMulti => {
            let path_capacity = detail_u32(&raw.details, 32);
            let item_capacity = detail_u32(&raw.details, 36);
            let mut path = link_info_string_buffer(path_capacity)?;
            let mut offsets = link_info_u64_buffer(item_capacity)?;
            let mut reference_counter_offsets = link_info_u64_buffer(item_capacity)?;
            let mut cookies = link_info_u64_buffer(item_capacity)?;
            set_detail_u64(&mut raw.details, 0, path.as_mut_ptr() as usize as u64);
            set_detail_u64(&mut raw.details, 8, offsets.as_mut_ptr() as usize as u64);
            set_detail_u64(
                &mut raw.details,
                16,
                reference_counter_offsets.as_mut_ptr() as usize as u64,
            );
            set_detail_u64(&mut raw.details, 24, cookies.as_mut_ptr() as usize as u64);
            set_detail_u32(
                &mut raw.details,
                32,
                u32::try_from(path.len()).unwrap_or(u32::MAX),
            );
            refresh_link_info(fd, raw)?;
            let count = (detail_u32(&raw.details, 36) as usize).min(offsets.len());
            offsets.truncate(count);
            reference_counter_offsets.truncate(count);
            cookies.truncate(count);
            Ok(LinkDetails::UprobeMulti {
                path: buffer_path(&path, detail_u32(&raw.details, 32)),
                flags: detail_u32(&raw.details, 40),
                process_id: detail_u32(&raw.details, 44),
                offsets,
                reference_counter_offsets,
                cookies,
            })
        }
        LinkType::Netkit => Ok(LinkDetails::Netkit {
            interface_index: detail_u32(&raw.details, 0),
            attach_type: AttachType::from_raw(detail_u32(&raw.details, 4)),
        }),
        LinkType::SocketMap => Ok(LinkDetails::SocketMap {
            map_id: detail_u32(&raw.details, 0),
            attach_type: AttachType::from_raw(detail_u32(&raw.details, 4)),
        }),
        LinkType::TracingMulti => {
            let capacity = detail_u32(&raw.details, 4);
            let mut type_ids = link_info_u32_buffer(capacity)?;
            let mut addresses = link_info_u64_buffer(capacity)?;
            let mut cookies = link_info_u64_buffer(capacity)?;
            set_detail_u64(&mut raw.details, 16, type_ids.as_mut_ptr() as usize as u64);
            set_detail_u64(&mut raw.details, 24, addresses.as_mut_ptr() as usize as u64);
            set_detail_u64(&mut raw.details, 32, cookies.as_mut_ptr() as usize as u64);
            refresh_link_info(fd, raw)?;
            let count = (detail_u32(&raw.details, 4) as usize).min(type_ids.len());
            type_ids.truncate(count);
            addresses.truncate(count);
            cookies.truncate(count);
            Ok(LinkDetails::TracingMulti {
                attach_type: AttachType::from_raw(detail_u32(&raw.details, 0)),
                btf_object_id: detail_u32(&raw.details, 8),
                type_ids,
                addresses,
                cookies,
            })
        }
        LinkType::Other(_) => Ok(LinkDetails::Other(raw.details)),
    }
}

fn decode_perf_event_details(fd: i32, raw: &mut sys::LinkInfoRaw) -> Result<LinkDetails> {
    let event_kind = detail_u32(&raw.details, 0);
    let details = match event_kind {
        1 | 2 => {
            let mut name = link_info_string_buffer(detail_u32(&raw.details, 16))?;
            set_detail_u64(&mut raw.details, 8, name.as_mut_ptr() as usize as u64);
            set_detail_u32(
                &mut raw.details,
                16,
                u32::try_from(name.len()).unwrap_or(u32::MAX),
            );
            refresh_link_info(fd, raw)?;
            PerfEventLinkDetails::Uprobe {
                path: buffer_path(&name, detail_u32(&raw.details, 16)),
                return_probe: event_kind == 2,
                offset: detail_u32(&raw.details, 20),
                cookie: detail_u64(&raw.details, 24),
                reference_counter_offset: detail_u64(&raw.details, 32),
            }
        }
        3 | 4 => {
            let mut name = link_info_string_buffer(detail_u32(&raw.details, 16))?;
            set_detail_u64(&mut raw.details, 8, name.as_mut_ptr() as usize as u64);
            set_detail_u32(
                &mut raw.details,
                16,
                u32::try_from(name.len()).unwrap_or(u32::MAX),
            );
            refresh_link_info(fd, raw)?;
            let reported = detail_u32(&raw.details, 16);
            PerfEventLinkDetails::Kprobe {
                function: (reported != 0).then(|| buffer_string(&name, reported)),
                return_probe: event_kind == 4,
                offset: detail_u32(&raw.details, 20),
                address: detail_u64(&raw.details, 24),
                missed: detail_u64(&raw.details, 32),
                cookie: detail_u64(&raw.details, 40),
            }
        }
        5 => {
            let mut name = link_info_string_buffer(detail_u32(&raw.details, 16))?;
            set_detail_u64(&mut raw.details, 8, name.as_mut_ptr() as usize as u64);
            set_detail_u32(
                &mut raw.details,
                16,
                u32::try_from(name.len()).unwrap_or(u32::MAX),
            );
            refresh_link_info(fd, raw)?;
            let reported = detail_u32(&raw.details, 16);
            PerfEventLinkDetails::Tracepoint {
                name: (reported != 0).then(|| buffer_string(&name, reported)),
                cookie: detail_u64(&raw.details, 24),
            }
        }
        6 => PerfEventLinkDetails::Event {
            config: detail_u64(&raw.details, 8),
            event_type: detail_u32(&raw.details, 16),
            cookie: detail_u64(&raw.details, 24),
        },
        value => PerfEventLinkDetails::Other(value),
    };
    Ok(LinkDetails::PerfEvent(details))
}

impl Drop for Link {
    fn drop(&mut self) {
        let fd = mem::replace(&mut self.fd, LinkFd::Detached);
        match &fd {
            LinkFd::Socket(socket) => drop(sys::socket_detach_bpf(socket.as_raw_fd())),
            LinkFd::Legacy {
                target,
                program,
                attach_type,
            } => drop(sys::program_detach(
                program.as_raw_fd(),
                target.as_raw_fd(),
                attach_type.as_raw(),
            )),
            LinkFd::BpfPerfEvent { event, .. } => {
                drop(sys::perf_event_disable(event.as_raw_fd()));
            }
            LinkFd::StructOpsLegacy(map) => {
                drop(sys::map_delete(map.as_raw_fd(), &0_u32.to_ne_bytes(), 0));
            }
            LinkFd::Bpf(_) | LinkFd::PerfEvents(_) | LinkFd::Detached => {}
        }
        // Close attachment descriptors before releasing any auxiliary state
        // that a concurrently running program may still access.
        drop(fd);
        if let Some(cleanup) = self.cleanup.take() {
            cleanup();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attach_types_round_trip_known_and_unknown_values() {
        for raw in 0..60 {
            assert_eq!(AttachType::from_raw(raw).as_raw(), raw);
        }
    }

    #[test]
    fn decodes_static_link_union_variants() {
        let mut tracing = sys::LinkInfoRaw::default();
        set_detail_u32(
            &mut tracing.details,
            0,
            AttachType::TraceFunctionEntry.as_raw(),
        );
        set_detail_u32(&mut tracing.details, 4, 17);
        set_detail_u32(&mut tracing.details, 8, 23);
        set_detail_u64(&mut tracing.details, 16, 0xfeed);
        assert_eq!(
            decode_link_details(-1, &mut tracing, LinkType::Tracing).unwrap(),
            LinkDetails::Tracing {
                attach_type: AttachType::TraceFunctionEntry,
                target_btf_object_id: 17,
                target_btf_id: 23,
                cookie: 0xfeed,
            }
        );

        let mut perf = sys::LinkInfoRaw::default();
        set_detail_u32(&mut perf.details, 0, 6);
        set_detail_u64(&mut perf.details, 8, 91);
        set_detail_u32(&mut perf.details, 16, 7);
        set_detail_u64(&mut perf.details, 24, 42);
        assert_eq!(
            decode_link_details(-1, &mut perf, LinkType::PerfEvent).unwrap(),
            LinkDetails::PerfEvent(PerfEventLinkDetails::Event {
                config: 91,
                event_type: 7,
                cookie: 42,
            })
        );
    }

    #[test]
    fn link_info_allocations_are_bounded() {
        assert!(link_info_u64_buffer((MAX_LINK_INFO_ITEMS + 1) as u32).is_err());
        assert!(link_info_string_buffer((MAX_LINK_INFO_STRING + 1) as u32).is_err());
        assert_eq!(mem::size_of::<sys::LinkInfoRaw>(), 64);
    }
}
