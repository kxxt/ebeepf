use std::fmt;
use std::mem;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::path::Path;

use crate::sys;
use crate::{Error, Result};

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
            Self::Other(value) => value,
        }
    }
}

enum LinkFd {
    Bpf(OwnedFd),
    PerfEvents(Vec<OwnedFd>),
    Detached,
}

/// An owned eBPF attachment.
///
/// Dropping a link closes its file descriptor(s), atomically detaching the
/// program unless the link was pinned.
pub struct Link {
    fd: LinkFd,
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
            LinkFd::Detached => formatter.write_str("Link { detached: true }"),
        }
    }
}

impl Link {
    pub(crate) fn bpf(fd: OwnedFd) -> Self {
        Self {
            fd: LinkFd::Bpf(fd),
        }
    }

    pub(crate) fn perf_events(fds: Vec<OwnedFd>) -> Self {
        Self {
            fd: LinkFd::PerfEvents(fds),
        }
    }

    /// Borrows the link FD when this is a kernel `bpf_link`.
    ///
    /// Perf-event based attachments consist of multiple descriptors and return
    /// `None`.
    pub fn as_fd(&self) -> Option<BorrowedFd<'_>> {
        match &self.fd {
            LinkFd::Bpf(fd) => Some(fd.as_fd()),
            LinkFd::PerfEvents(_) | LinkFd::Detached => None,
        }
    }

    /// Pins a kernel link in bpffs so it outlives this process.
    pub fn pin(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        let LinkFd::Bpf(fd) = &self.fd else {
            return Err(Error::Unsupported(
                "perf-event links cannot be pinned as bpf_link objects".into(),
            ));
        };
        sys::object_pin(fd.as_raw_fd(), path).map_err(|source| Error::File {
            operation: "pin link",
            path: path.into(),
            source,
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
            LinkFd::PerfEvents(_) | LinkFd::Detached => Ok(()),
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
