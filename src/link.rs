use std::fmt;
use std::fs;
use std::mem;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::path::Path;

use crate::sys;
use crate::{Error, Program, Result};

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
            Self::Other(value) => value,
        }
    }
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
}

enum LinkFd {
    Bpf(OwnedFd),
    PerfEvents(Vec<OwnedFd>),
    Socket(OwnedFd),
    Legacy {
        target: OwnedFd,
        program: OwnedFd,
        attach_type: AttachType,
    },
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

    pub(crate) fn with_cleanup(mut self, cleanup: impl FnOnce() + Send + 'static) -> Self {
        self.cleanup = Some(Box::new(cleanup));
        self
    }

    /// Opens a link pinned in bpffs.
    pub fn open_pinned(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let fd = sys::object_get(path).map_err(|source| Error::File {
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
            LinkFd::PerfEvents(_)
            | LinkFd::Socket(_)
            | LinkFd::Legacy { .. }
            | LinkFd::Detached => None,
        }
    }

    /// Pins a kernel link in bpffs so it outlives this process.
    pub fn pin(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        let LinkFd::Bpf(fd) = &self.fd else {
            return Err(Error::Unsupported(
                "this attachment is not represented by a pinnable bpf_link".into(),
            ));
        };
        sys::object_pin(fd.as_raw_fd(), path).map_err(|source| Error::File {
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
        let LinkFd::Bpf(fd) = &self.fd else {
            return Err(Error::Unsupported(
                "only kernel bpf_link attachments support program updates".into(),
            ));
        };
        sys::link_update(
            fd.as_raw_fd(),
            program.as_fd().as_raw_fd(),
            expected.map(|program| program.as_fd().as_raw_fd()),
        )
        .map_err(|source| Error::system("update eBPF link program", source))
    }

    /// Reads current metadata for a kernel `bpf_link`.
    pub fn info(&self) -> Result<LinkInfo> {
        let LinkFd::Bpf(fd) = &self.fd else {
            return Err(Error::Unsupported(
                "this attachment is not represented by a kernel bpf_link".into(),
            ));
        };
        let raw = sys::link_info(fd.as_raw_fd())
            .map_err(|source| Error::system("read eBPF link metadata", source))?;
        let link_type = LinkType::from_raw(raw.link_type);
        let detail_u32 = |offset: usize| {
            u32::from_ne_bytes(
                raw.details[offset..offset + 4]
                    .try_into()
                    .expect("fixed link-info range"),
            )
        };
        let detail_u64 = |offset: usize| {
            u64::from_ne_bytes(
                raw.details[offset..offset + 8]
                    .try_into()
                    .expect("fixed link-info range"),
            )
        };
        let attach_type = match link_type {
            LinkType::Tracing => Some(AttachType::from_raw(detail_u32(0))),
            LinkType::Cgroup => Some(AttachType::from_raw(detail_u32(8))),
            LinkType::Tcx | LinkType::Netkit | LinkType::SocketMap => {
                Some(AttachType::from_raw(detail_u32(4)))
            }
            _ => None,
        };
        Ok(LinkInfo {
            id: raw.id,
            link_type,
            program_id: raw.program_id,
            attach_type,
            interface_index: matches!(link_type, LinkType::Xdp | LinkType::Tcx | LinkType::Netkit)
                .then(|| detail_u32(0)),
            map_id: matches!(link_type, LinkType::StructOps | LinkType::SocketMap)
                .then(|| detail_u32(0)),
            target_btf_object_id: (link_type == LinkType::Tracing).then(|| detail_u32(4)),
            target_btf_id: (link_type == LinkType::Tracing).then(|| detail_u32(8)),
            cgroup_id: (link_type == LinkType::Cgroup).then(|| detail_u64(0)),
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
            LinkFd::PerfEvents(_) | LinkFd::Detached => Ok(()),
        }
    }
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
}
