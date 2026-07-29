use std::fmt;
use std::fs;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::result::Result as StdResult;
use std::sync::Arc;

use goblin::elf::sym::STT_FUNC;
use goblin::elf::Elf;

use crate::link::{AttachType, Link};
use crate::map::{kernel_name, Map};
use crate::sys::{self, ProgramLoad};
use crate::usdt::{UsdtManager, UsdtOptions};
use crate::{BpfToken, BtfKind, BtfObject, Error, Instruction, Result, TypeId};

/// A kernel eBPF program type.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ProgramType {
    /// Unspecified type.
    Unspecified,
    /// Socket filter.
    SocketFilter,
    /// Kprobe or uprobe.
    Kprobe,
    /// Traffic-control classifier.
    SchedulerClassifier,
    /// Traffic-control action.
    SchedulerAction,
    /// Tracepoint.
    Tracepoint,
    /// Express Data Path.
    Xdp,
    /// Perf event.
    PerfEvent,
    /// Cgroup socket-buffer filter.
    CgroupSocketBuffer,
    /// Cgroup socket hook.
    CgroupSocket,
    /// Lightweight tunnel input.
    LightweightTunnelInput,
    /// Lightweight tunnel output.
    LightweightTunnelOutput,
    /// Lightweight tunnel transmit.
    LightweightTunnelTransmit,
    /// Socket operations.
    SocketOps,
    /// Socket-buffer stream parser/verdict.
    SocketBuffer,
    /// Cgroup device filter.
    CgroupDevice,
    /// Socket message.
    SocketMessage,
    /// Raw tracepoint.
    RawTracepoint,
    /// Cgroup socket-address hook.
    CgroupSocketAddress,
    /// IPv6 segment-routing local hook.
    LightweightTunnelSeg6Local,
    /// Infrared input decoder.
    LircMode2,
    /// Socket reuseport selector.
    SocketReuseport,
    /// Flow dissector.
    FlowDissector,
    /// Cgroup sysctl hook.
    CgroupSysctl,
    /// Writable raw tracepoint.
    RawTracepointWritable,
    /// Cgroup socket-option hook.
    CgroupSocketOption,
    /// BTF-based tracing program.
    Tracing,
    /// `struct_ops` program.
    StructOps,
    /// Program extension.
    Extension,
    /// Linux Security Module hook.
    Lsm,
    /// Socket lookup.
    SocketLookup,
    /// Program allowed to issue BPF syscalls.
    Syscall,
    /// Netfilter program.
    Netfilter,
    /// A type introduced after this crate version.
    Other(u32),
}

impl ProgramType {
    /// Converts a Linux UAPI value.
    pub const fn from_raw(value: u32) -> Self {
        match value {
            0 => Self::Unspecified,
            1 => Self::SocketFilter,
            2 => Self::Kprobe,
            3 => Self::SchedulerClassifier,
            4 => Self::SchedulerAction,
            5 => Self::Tracepoint,
            6 => Self::Xdp,
            7 => Self::PerfEvent,
            8 => Self::CgroupSocketBuffer,
            9 => Self::CgroupSocket,
            10 => Self::LightweightTunnelInput,
            11 => Self::LightweightTunnelOutput,
            12 => Self::LightweightTunnelTransmit,
            13 => Self::SocketOps,
            14 => Self::SocketBuffer,
            15 => Self::CgroupDevice,
            16 => Self::SocketMessage,
            17 => Self::RawTracepoint,
            18 => Self::CgroupSocketAddress,
            19 => Self::LightweightTunnelSeg6Local,
            20 => Self::LircMode2,
            21 => Self::SocketReuseport,
            22 => Self::FlowDissector,
            23 => Self::CgroupSysctl,
            24 => Self::RawTracepointWritable,
            25 => Self::CgroupSocketOption,
            26 => Self::Tracing,
            27 => Self::StructOps,
            28 => Self::Extension,
            29 => Self::Lsm,
            30 => Self::SocketLookup,
            31 => Self::Syscall,
            32 => Self::Netfilter,
            value => Self::Other(value),
        }
    }

    /// Returns the Linux UAPI value.
    pub const fn as_raw(self) -> u32 {
        match self {
            Self::Unspecified => 0,
            Self::SocketFilter => 1,
            Self::Kprobe => 2,
            Self::SchedulerClassifier => 3,
            Self::SchedulerAction => 4,
            Self::Tracepoint => 5,
            Self::Xdp => 6,
            Self::PerfEvent => 7,
            Self::CgroupSocketBuffer => 8,
            Self::CgroupSocket => 9,
            Self::LightweightTunnelInput => 10,
            Self::LightweightTunnelOutput => 11,
            Self::LightweightTunnelTransmit => 12,
            Self::SocketOps => 13,
            Self::SocketBuffer => 14,
            Self::CgroupDevice => 15,
            Self::SocketMessage => 16,
            Self::RawTracepoint => 17,
            Self::CgroupSocketAddress => 18,
            Self::LightweightTunnelSeg6Local => 19,
            Self::LircMode2 => 20,
            Self::SocketReuseport => 21,
            Self::FlowDissector => 22,
            Self::CgroupSysctl => 23,
            Self::RawTracepointWritable => 24,
            Self::CgroupSocketOption => 25,
            Self::Tracing => 26,
            Self::StructOps => 27,
            Self::Extension => 28,
            Self::Lsm => 29,
            Self::SocketLookup => 30,
            Self::Syscall => 31,
            Self::Netfilter => 32,
            Self::Other(value) => value,
        }
    }

    /// Probes whether the running kernel can load this program type.
    ///
    /// A `false` result also covers kernels on which eBPF loading is disabled
    /// for the current process, matching the kernel's observable behavior.
    pub fn is_supported(self) -> Result<bool> {
        sys::probe_program_type(self.as_raw())
            .map_err(|source| Error::system("probe eBPF program type", source))
    }

    /// Probes whether one helper is recognized for this program type.
    ///
    /// Tracing, extension, LSM, and `struct_ops` programs cannot be probed
    /// reliably without a real BTF attachment target and return
    /// [`Error::Unsupported`].
    pub fn is_helper_supported(self, helper: HelperId) -> Result<bool> {
        sys::probe_program_helper(self.as_raw(), helper.as_raw()).map_err(|source| {
            if source.raw_os_error() == Some(libc::EOPNOTSUPP) {
                Error::Unsupported(format!(
                    "helper probing is not reliable for {self:?} programs"
                ))
            } else {
                Error::system("probe eBPF helper", source)
            }
        })
    }
}

/// A future-proof kernel eBPF helper function ID.
///
/// Associated constants cover common helpers; [`Self::from_raw`] allows
/// probing helpers introduced by newer kernels without waiting for a crate
/// release.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct HelperId(u32);

impl HelperId {
    /// No helper.
    pub const UNSPECIFIED: Self = Self(0);
    /// `bpf_map_lookup_elem`.
    pub const MAP_LOOKUP_ELEMENT: Self = Self(1);
    /// `bpf_map_update_elem`.
    pub const MAP_UPDATE_ELEMENT: Self = Self(2);
    /// `bpf_map_delete_elem`.
    pub const MAP_DELETE_ELEMENT: Self = Self(3);
    /// `bpf_probe_read`.
    pub const PROBE_READ: Self = Self(4);
    /// `bpf_ktime_get_ns`.
    pub const KERNEL_TIME_NANOSECONDS: Self = Self(5);
    /// `bpf_trace_printk`.
    pub const TRACE_PRINTK: Self = Self(6);
    /// `bpf_get_prandom_u32`.
    pub const RANDOM_U32: Self = Self(7);
    /// `bpf_get_smp_processor_id`.
    pub const PROCESSOR_ID: Self = Self(8);
    /// `bpf_tail_call`.
    pub const TAIL_CALL: Self = Self(12);
    /// `bpf_perf_event_output`.
    pub const PERF_EVENT_OUTPUT: Self = Self(25);
    /// `bpf_ringbuf_output`.
    pub const RING_BUFFER_OUTPUT: Self = Self(130);
    /// `bpf_ringbuf_reserve`.
    pub const RING_BUFFER_RESERVE: Self = Self(131);
    /// `bpf_ringbuf_submit`.
    pub const RING_BUFFER_SUBMIT: Self = Self(132);
    /// `bpf_ringbuf_discard`.
    pub const RING_BUFFER_DISCARD: Self = Self(133);
    /// `bpf_get_attach_cookie`.
    pub const ATTACH_COOKIE: Self = Self(174);

    /// Wraps a Linux UAPI helper ID.
    pub const fn from_raw(value: u32) -> Self {
        Self(value)
    }

    /// Returns the Linux UAPI helper ID.
    pub const fn as_raw(self) -> u32 {
        self.0
    }
}

impl From<u32> for HelperId {
    fn from(value: u32) -> Self {
        Self::from_raw(value)
    }
}

/// Attachment information inferred from an ELF section name.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProgramKind {
    /// A socket filter.
    SocketFilter,
    /// A kernel probe.
    Kprobe {
        /// Kernel function name.
        function: String,
        /// Whether this is a return probe.
        return_probe: bool,
    },
    /// A userspace probe.
    Uprobe {
        /// Optional target text encoded after the section prefix.
        target: String,
        /// Whether this is a return probe.
        return_probe: bool,
    },
    /// A tracepoint.
    Tracepoint {
        /// Tracepoint category.
        category: String,
        /// Event name.
        event: String,
    },
    /// A raw tracepoint.
    RawTracepoint {
        /// Tracepoint name.
        name: String,
        /// Whether the tracepoint context is writable.
        writable: bool,
    },
    /// Express Data Path.
    Xdp,
    /// A cgroup hook.
    Cgroup {
        /// Expected hook type.
        attach_type: AttachType,
    },
    /// BTF-based kernel tracing.
    Tracing {
        /// Expected hook type.
        attach_type: AttachType,
        /// Target function or hook name.
        target: String,
    },
    /// A perf-event program.
    PerfEvent,
    /// A program whose section is understood only as a raw program type.
    Other {
        /// Program type.
        program_type: ProgramType,
        /// Expected attach type, when known.
        attach_type: Option<AttachType>,
    },
}

impl ProgramKind {
    /// Infers program and attachment types from a conventional ELF section.
    pub fn from_section(section: &str) -> Result<Self> {
        let (prefix, target) = section.split_once('/').unwrap_or((section, ""));
        let kind = match prefix {
            "socket" | "sk_filter" => Self::SocketFilter,
            "kprobe" | "ksyscall" => Self::Kprobe {
                function: target.into(),
                return_probe: false,
            },
            "kretprobe" | "kretsyscall" => Self::Kprobe {
                function: target.into(),
                return_probe: true,
            },
            "uprobe" | "uprobe.s" => Self::Uprobe {
                target: target.into(),
                return_probe: false,
            },
            // BPF-side USDT helpers inspect the uprobe-multi attachment
            // context, so the expected attach type must be present when the
            // program is verified (not merely when its link is created).
            "usdt" | "usdt.s" => Self::Other {
                program_type: ProgramType::Kprobe,
                attach_type: Some(AttachType::TraceUprobeMulti),
            },
            "uretprobe" | "uretprobe.s" => Self::Uprobe {
                target: target.into(),
                return_probe: true,
            },
            "kprobe.multi" | "kretprobe.multi" => Self::Other {
                program_type: ProgramType::Kprobe,
                attach_type: Some(AttachType::TraceKprobeMulti),
            },
            "kprobe.session" => Self::Other {
                program_type: ProgramType::Kprobe,
                attach_type: Some(AttachType::TraceKprobeSession),
            },
            "uprobe.multi" | "uprobe.multi.s" | "uretprobe.multi" | "uretprobe.multi.s" => {
                Self::Other {
                    program_type: ProgramType::Kprobe,
                    attach_type: Some(AttachType::TraceUprobeMulti),
                }
            }
            "uprobe.session" | "uprobe.session.s" => Self::Other {
                program_type: ProgramType::Kprobe,
                attach_type: Some(AttachType::TraceUprobeSession),
            },
            "tracepoint" | "tp" | "tracepoint.s" | "tp.s" => {
                let (category, event) = target.split_once('/').ok_or_else(|| {
                    Error::InvalidObject(format!(
                        "tracepoint section `{section}` must name category/event"
                    ))
                })?;
                Self::Tracepoint {
                    category: category.into(),
                    event: event.into(),
                }
            }
            "raw_tracepoint" | "raw_tp" | "raw_tracepoint.s" | "raw_tp.s" => Self::RawTracepoint {
                name: target.into(),
                writable: false,
            },
            "raw_tracepoint.w" | "raw_tp.w" => Self::RawTracepoint {
                name: target.into(),
                writable: true,
            },
            "xdp" | "xdp.frags" if target == "devmap" => Self::Other {
                program_type: ProgramType::Xdp,
                attach_type: Some(AttachType::XdpDeviceMap),
            },
            "xdp" | "xdp.frags" if target == "cpumap" => Self::Other {
                program_type: ProgramType::Xdp,
                attach_type: Some(AttachType::XdpCpuMap),
            },
            "xdp" | "xdp.frags" => Self::Xdp,
            "perf_event" => Self::PerfEvent,
            "sk_reuseport" if target == "migrate" => Self::Other {
                program_type: ProgramType::SocketReuseport,
                attach_type: Some(AttachType::ReuseportSelectOrMigrate),
            },
            "sk_reuseport" => Self::Other {
                program_type: ProgramType::SocketReuseport,
                attach_type: Some(AttachType::ReuseportSelect),
            },
            "cgroup_skb" if target == "ingress" => Self::Cgroup {
                attach_type: AttachType::CgroupInetIngress,
            },
            "cgroup_skb" if target == "egress" => Self::Cgroup {
                attach_type: AttachType::CgroupInetEgress,
            },
            "cgroup" if target == "dev" => Self::Cgroup {
                attach_type: AttachType::CgroupDevice,
            },
            "cgroup" if target == "sysctl" => Self::Cgroup {
                attach_type: AttachType::CgroupSysctl,
            },
            "cgroup" if target == "sock_create" || target == "sock" => Self::Cgroup {
                attach_type: AttachType::CgroupInetSocketCreate,
            },
            "cgroup" if target == "sock_release" => Self::Cgroup {
                attach_type: AttachType::CgroupInetSocketRelease,
            },
            "cgroup" if target == "post_bind4" => Self::Cgroup {
                attach_type: AttachType::CgroupInet4PostBind,
            },
            "cgroup" if target == "post_bind6" => Self::Cgroup {
                attach_type: AttachType::CgroupInet6PostBind,
            },
            "cgroup" if target == "getsockopt" => Self::Other {
                program_type: ProgramType::CgroupSocketOption,
                attach_type: Some(AttachType::CgroupGetSocketOption),
            },
            "cgroup" if target == "setsockopt" => Self::Other {
                program_type: ProgramType::CgroupSocketOption,
                attach_type: Some(AttachType::CgroupSetSocketOption),
            },
            "cgroup" => {
                let attach_type = match target {
                    "bind4" => AttachType::CgroupInet4Bind,
                    "bind6" => AttachType::CgroupInet6Bind,
                    "connect4" => AttachType::CgroupInet4Connect,
                    "connect6" => AttachType::CgroupInet6Connect,
                    "connect_unix" => AttachType::CgroupUnixConnect,
                    "sendmsg4" => AttachType::CgroupUdp4SendMessage,
                    "sendmsg6" => AttachType::CgroupUdp6SendMessage,
                    "sendmsg_unix" => AttachType::CgroupUnixSendMessage,
                    "recvmsg4" => AttachType::CgroupUdp4ReceiveMessage,
                    "recvmsg6" => AttachType::CgroupUdp6ReceiveMessage,
                    "recvmsg_unix" => AttachType::CgroupUnixReceiveMessage,
                    "getpeername4" => AttachType::CgroupInet4GetPeerName,
                    "getpeername6" => AttachType::CgroupInet6GetPeerName,
                    "getpeername_unix" => AttachType::CgroupUnixGetPeerName,
                    "getsockname4" => AttachType::CgroupInet4GetSocketName,
                    "getsockname6" => AttachType::CgroupInet6GetSocketName,
                    "getsockname_unix" => AttachType::CgroupUnixGetSocketName,
                    _ => {
                        return Err(Error::Unsupported(format!(
                            "cannot infer cgroup program type from ELF section `{section}`"
                        )));
                    }
                };
                Self::Other {
                    program_type: ProgramType::CgroupSocketAddress,
                    attach_type: Some(attach_type),
                }
            }
            "fentry" | "fentry.s" => Self::Tracing {
                attach_type: AttachType::TraceFunctionEntry,
                target: target.into(),
            },
            "fexit" | "fexit.s" => Self::Tracing {
                attach_type: AttachType::TraceFunctionExit,
                target: target.into(),
            },
            "fmod_ret" | "fmod_ret.s" => Self::Tracing {
                attach_type: AttachType::ModifyReturn,
                target: target.into(),
            },
            "iter" | "iter.s" => Self::Tracing {
                attach_type: AttachType::TraceIterator,
                target: target.into(),
            },
            "lsm" | "lsm.s" => Self::Tracing {
                attach_type: AttachType::LsmMac,
                target: target.into(),
            },
            "tp_btf" | "tp_btf.s" => Self::Tracing {
                attach_type: AttachType::TraceRawTracepoint,
                target: target.into(),
            },
            "fsession" | "fsession.s" => Self::Tracing {
                attach_type: AttachType::TraceFunctionSession,
                target: target.into(),
            },
            "fentry.multi" | "fentry.multi.s" => Self::Tracing {
                attach_type: AttachType::TraceFunctionEntryMulti,
                target: target.into(),
            },
            "fexit.multi" | "fexit.multi.s" => Self::Tracing {
                attach_type: AttachType::TraceFunctionExitMulti,
                target: target.into(),
            },
            "fsession.multi" | "fsession.multi.s" => Self::Tracing {
                attach_type: AttachType::TraceFunctionSessionMulti,
                target: target.into(),
            },
            "lsm_cgroup" => Self::Tracing {
                attach_type: AttachType::LsmCgroup,
                target: target.into(),
            },
            "classifier" | "tc" | "sched_cls" => Self::Other {
                program_type: ProgramType::SchedulerClassifier,
                attach_type: match target {
                    "ingress" => Some(AttachType::TcxIngress),
                    "egress" => Some(AttachType::TcxEgress),
                    _ => None,
                },
            },
            "tcx" => Self::Other {
                program_type: ProgramType::SchedulerClassifier,
                attach_type: match target {
                    "ingress" => Some(AttachType::TcxIngress),
                    "egress" => Some(AttachType::TcxEgress),
                    _ => None,
                },
            },
            "netkit" => Self::Other {
                program_type: ProgramType::SchedulerClassifier,
                attach_type: match target {
                    "primary" => Some(AttachType::NetkitPrimary),
                    "peer" => Some(AttachType::NetkitPeer),
                    _ => None,
                },
            },
            "action" | "sched_act" => Self::Other {
                program_type: ProgramType::SchedulerAction,
                attach_type: None,
            },
            "lwt_in" => Self::Other {
                program_type: ProgramType::LightweightTunnelInput,
                attach_type: None,
            },
            "lwt_out" => Self::Other {
                program_type: ProgramType::LightweightTunnelOutput,
                attach_type: None,
            },
            "lwt_xmit" => Self::Other {
                program_type: ProgramType::LightweightTunnelTransmit,
                attach_type: None,
            },
            "lwt_seg6local" => Self::Other {
                program_type: ProgramType::LightweightTunnelSeg6Local,
                attach_type: None,
            },
            "sockops" => Self::Other {
                program_type: ProgramType::SocketOps,
                attach_type: Some(AttachType::CgroupSocketOps),
            },
            "sk_skb" => Self::Other {
                program_type: ProgramType::SocketBuffer,
                attach_type: match target {
                    "stream_parser" => Some(AttachType::StreamParser),
                    "stream_verdict" => Some(AttachType::StreamVerdict),
                    "verdict" => Some(AttachType::SocketVerdict),
                    _ => None,
                },
            },
            "sk_msg" => Self::Other {
                program_type: ProgramType::SocketMessage,
                attach_type: Some(AttachType::SocketMessageVerdict),
            },
            "lirc_mode2" => Self::Other {
                program_type: ProgramType::LircMode2,
                attach_type: Some(AttachType::LircMode2),
            },
            "flow_dissector" => Self::Other {
                program_type: ProgramType::FlowDissector,
                attach_type: Some(AttachType::FlowDissector),
            },
            "sk_lookup" => Self::Other {
                program_type: ProgramType::SocketLookup,
                attach_type: Some(AttachType::SocketLookup),
            },
            "syscall" => Self::Other {
                program_type: ProgramType::Syscall,
                attach_type: None,
            },
            "netfilter" => Self::Other {
                program_type: ProgramType::Netfilter,
                attach_type: Some(AttachType::Netfilter),
            },
            "struct_ops" | "struct_ops.s" => Self::Other {
                program_type: ProgramType::StructOps,
                attach_type: None,
            },
            "freplace" => Self::Other {
                program_type: ProgramType::Extension,
                attach_type: None,
            },
            _ => {
                return Err(Error::Unsupported(format!(
                    "cannot infer program type from ELF section `{section}`"
                )));
            }
        };
        Ok(kind)
    }

    /// Returns the program type implied by this kind.
    pub const fn program_type(&self) -> ProgramType {
        match self {
            Self::SocketFilter => ProgramType::SocketFilter,
            Self::Kprobe { .. } | Self::Uprobe { .. } => ProgramType::Kprobe,
            Self::Tracepoint { .. } => ProgramType::Tracepoint,
            Self::RawTracepoint {
                writable: false, ..
            } => ProgramType::RawTracepoint,
            Self::RawTracepoint { writable: true, .. } => ProgramType::RawTracepointWritable,
            Self::Xdp => ProgramType::Xdp,
            Self::Cgroup { attach_type } => match attach_type {
                AttachType::CgroupInetIngress | AttachType::CgroupInetEgress => {
                    ProgramType::CgroupSocketBuffer
                }
                AttachType::CgroupDevice => ProgramType::CgroupDevice,
                AttachType::CgroupSysctl => ProgramType::CgroupSysctl,
                _ => ProgramType::CgroupSocket,
            },
            Self::Tracing { attach_type, .. } => match attach_type {
                AttachType::LsmMac | AttachType::LsmCgroup => ProgramType::Lsm,
                _ => ProgramType::Tracing,
            },
            Self::PerfEvent => ProgramType::PerfEvent,
            Self::Other { program_type, .. } => *program_type,
        }
    }

    /// Returns the expected attach type when the verifier needs one.
    pub const fn attach_type(&self) -> Option<AttachType> {
        match self {
            Self::Cgroup { attach_type } | Self::Tracing { attach_type, .. } => Some(*attach_type),
            Self::Xdp => Some(AttachType::Xdp),
            Self::Other { attach_type, .. } => *attach_type,
            _ => None,
        }
    }
}

/// Verifier logging configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifierLog {
    /// Kernel verbosity level.
    pub level: u32,
    /// Log buffer size.
    pub capacity: usize,
}

impl Default for VerifierLog {
    fn default() -> Self {
        Self {
            level: 1,
            capacity: 256 * 1024,
        }
    }
}

/// Common options for descriptor-targeted `bpf_link` attachments.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LinkOptions {
    /// Kernel attachment flags.
    pub flags: u32,
    /// Optional target BTF type ID.
    pub target_btf_id: u32,
}

impl LinkOptions {
    /// Creates zeroed link options.
    pub const fn new() -> Self {
        Self {
            flags: 0,
            target_btf_id: 0,
        }
    }

    /// Sets kernel attachment flags.
    pub const fn with_flags(mut self, flags: u32) -> Self {
        self.flags = flags;
        self
    }

    /// Selects a target BTF type.
    pub const fn with_target_btf(mut self, target: TypeId) -> Self {
        self.target_btf_id = target.0;
        self
    }
}

pub(crate) fn kind_supports_auto_attach(kind: &ProgramKind) -> bool {
    match kind {
        ProgramKind::Kprobe { .. }
        | ProgramKind::Tracepoint { .. }
        | ProgramKind::RawTracepoint { .. } => true,
        ProgramKind::Tracing { target, .. } => !target.is_empty(),
        _ => false,
    }
}

#[derive(Clone)]
pub(crate) struct AttachProgram {
    fd: Arc<OwnedFd>,
}

impl fmt::Debug for AttachProgram {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AttachProgram")
            .field("fd", &self.fd.as_raw_fd())
            .finish()
    }
}

impl PartialEq for AttachProgram {
    fn eq(&self, other: &Self) -> bool {
        self.fd.as_raw_fd() == other.fd.as_raw_fd()
    }
}

impl Eq for AttachProgram {}

/// A program's parsed and configurable definition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProgramSpec {
    pub(crate) name: String,
    pub(crate) section: String,
    pub(crate) kind: ProgramKind,
    pub(crate) instructions: Vec<Instruction>,
    pub(crate) autoload: bool,
    pub(crate) auto_attach: bool,
    pub(crate) flags: u32,
    pub(crate) kernel_version: u32,
    pub(crate) interface_index: u32,
    pub(crate) attach_btf_id: u32,
    pub(crate) attach_program: Option<AttachProgram>,
    pub(crate) attach_btf_object: Option<BtfObject>,
    pub(crate) kernel_btf_objects: Vec<BtfObject>,
    pub(crate) func_info: Vec<u8>,
    pub(crate) func_info_record_size: u32,
    pub(crate) line_info: Vec<u8>,
    pub(crate) line_info_record_size: u32,
    pub(crate) verifier_log: VerifierLog,
    pub(crate) section_index: usize,
    pub(crate) section_offset: u64,
}

impl ProgramSpec {
    /// Creates a definition from instructions and a conventional section name.
    pub fn new(
        name: impl Into<String>,
        section: impl Into<String>,
        instructions: Vec<Instruction>,
    ) -> Result<Self> {
        let section = section.into();
        let kind = ProgramKind::from_section(&section)?;
        let auto_attach = kind_supports_auto_attach(&kind);
        let flags = program_flags_from_section(&section);
        Ok(Self {
            name: name.into(),
            section,
            kind,
            instructions,
            autoload: true,
            auto_attach,
            flags,
            kernel_version: 0,
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
            section_index: 0,
            section_offset: 0,
        })
    }

    /// Program name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Source ELF section name.
    pub fn section(&self) -> &str {
        &self.section
    }

    /// Inferred attachment kind.
    pub fn kind(&self) -> &ProgramKind {
        &self.kind
    }

    /// Program type passed to the verifier.
    pub const fn program_type(&self) -> ProgramType {
        self.kind.program_type()
    }

    /// Program instructions, after ELF relocation.
    pub fn instructions(&self) -> &[Instruction] {
        &self.instructions
    }

    /// Whether [`crate::Object::load`] loads this program.
    pub const fn autoload(&self) -> bool {
        self.autoload
    }

    /// Whether generated skeletons should automatically attach this program.
    pub const fn auto_attach(&self) -> bool {
        self.auto_attach
    }

    /// BTF ID of the resolved attachment target.
    ///
    /// This is populated while loading for BTF tracing, LSM, and iterator
    /// programs. It is zero before resolution or when the attachment kind does
    /// not use a single BTF target.
    pub const fn attach_btf_id(&self) -> u32 {
        self.attach_btf_id
    }

    /// Network interface selected for hardware-offloaded loading, or zero.
    pub const fn interface_index(&self) -> u32 {
        self.interface_index
    }

    /// Borrows the target program descriptor used for extension or tracing.
    pub fn attach_program(&self) -> Option<BorrowedFd<'_>> {
        self.attach_program.as_ref().map(|target| target.fd.as_fd())
    }

    /// Borrows the kernel or module BTF object selected as an attachment target.
    pub fn attach_btf_object(&self) -> Option<&BtfObject> {
        self.attach_btf_object.as_ref()
    }

    /// Module BTF objects referenced by relocated kfunc calls or typed ksyms.
    ///
    /// These objects are retained through program verification and correspond
    /// to positive BTF FD-array indexes or typed-symbol descriptor operands.
    pub fn kernel_btf_objects(&self) -> impl ExactSizeIterator<Item = &BtfObject> {
        self.kernel_btf_objects.iter()
    }

    /// Module BTF objects referenced specifically by relocated kfunc calls.
    ///
    /// This compatibility alias returns all retained module BTF dependencies;
    /// use [`Self::kernel_btf_objects`] for code that also handles ksyms.
    pub fn kfunc_btf_objects(&self) -> impl ExactSizeIterator<Item = &BtfObject> {
        self.kernel_btf_objects()
    }

    /// Whether [`Program::attach`] can attach this program without additional
    /// runtime arguments.
    pub fn auto_attachable(&self) -> bool {
        self.auto_attach && kind_supports_auto_attach(&self.kind)
    }

    /// Enables or disables automatic loading.
    pub fn set_autoload(&mut self, autoload: bool) -> &mut Self {
        self.autoload = autoload;
        self
    }

    /// Enables or disables skeleton automatic attachment.
    pub fn set_auto_attach(&mut self, auto_attach: bool) -> &mut Self {
        self.auto_attach = auto_attach;
        self
    }

    /// Overrides the inferred program and attachment kind.
    pub fn set_kind(&mut self, kind: ProgramKind) -> &mut Self {
        self.kind = kind;
        self
    }

    /// Changes program load flags.
    pub fn set_flags(&mut self, flags: u32) -> &mut Self {
        self.flags = flags;
        self
    }

    /// Selects a network interface for hardware-offloaded program loading.
    ///
    /// Zero restores normal host-kernel loading.
    pub fn set_interface_index(&mut self, interface_index: u32) -> &mut Self {
        self.interface_index = interface_index;
        self
    }

    /// Targets a function type in an already loaded eBPF program.
    ///
    /// This supports `freplace` as well as BTF tracing of another eBPF
    /// program. The target descriptor is owned by this definition, so it
    /// remains valid through object loading.
    pub fn set_attach_target(&mut self, program: &Program, function: TypeId) -> &mut Self {
        self.attach_program = Some(AttachProgram {
            fd: Arc::clone(&program.fd),
        });
        self.attach_btf_object = None;
        self.attach_btf_id = function.0;
        self
    }

    /// Targets a type in a kernel or module BTF object.
    ///
    /// This is the explicit form used for module `fentry`, `fexit`, LSM, and
    /// other BTF-based programs. Section targets such as
    /// `"fentry/module:function"` are resolved automatically during object
    /// loading.
    pub fn set_kernel_attach_target(&mut self, btf: &BtfObject, target: TypeId) -> &mut Self {
        self.attach_program = None;
        self.attach_btf_object = Some(btf.clone());
        self.attach_btf_id = target.0;
        self
    }

    /// Resolves and targets a named BTF function in a loaded eBPF program.
    pub fn set_attach_target_by_name(
        &mut self,
        program: &Program,
        function: &str,
    ) -> Result<&mut Self> {
        let btf_id = program.info()?.btf_id;
        if btf_id == 0 {
            return Err(Error::InvalidObject(format!(
                "target program `{}` has no BTF",
                program.name()
            )));
        }
        let btf = match program.token.as_ref() {
            Some(token) => BtfObject::from_id_with_token(btf_id, token)?,
            None => BtfObject::from_id(btf_id)?,
        };
        let (function_id, _) = btf.btf().find(BtfKind::Function, function).ok_or_else(|| {
            Error::InvalidObject(format!(
                "target program `{}` has no BTF function `{function}`",
                program.name()
            ))
        })?;
        Ok(self.set_attach_target(program, function_id))
    }

    /// Clears a previously configured loaded-program attachment target.
    pub fn clear_attach_target(&mut self) -> &mut Self {
        self.attach_program = None;
        self.attach_btf_object = None;
        self.attach_btf_id = 0;
        self
    }

    /// Changes verifier log settings.
    pub fn set_verifier_log(&mut self, log: VerifierLog) -> &mut Self {
        self.verifier_log = log;
        self
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.name.is_empty() {
            return Err(Error::InvalidObject("program name cannot be empty".into()));
        }
        if self.instructions.is_empty() {
            return Err(Error::InvalidObject(format!(
                "program `{}` contains no instructions",
                self.name
            )));
        }
        if self.attach_program.is_some() && self.attach_btf_id == 0 {
            return Err(Error::InvalidObject(format!(
                "program `{}` has an attachment program but no target BTF ID",
                self.name
            )));
        }
        let tracing_multi = matches!(
            self.kind.attach_type(),
            Some(
                AttachType::TraceFunctionEntryMulti
                    | AttachType::TraceFunctionExitMulti
                    | AttachType::TraceFunctionSessionMulti
            )
        );
        if self.attach_btf_object.is_some() && self.attach_btf_id == 0 && !tracing_multi {
            return Err(Error::InvalidObject(format!(
                "program `{}` has an attachment BTF object but no target type ID",
                self.name
            )));
        }
        if self.attach_program.is_some() && self.attach_btf_object.is_some() {
            return Err(Error::InvalidObject(format!(
                "program `{}` has both program and kernel-BTF attachment targets",
                self.name
            )));
        }
        Ok(())
    }
}

/// Kernel metadata for a loaded program.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProgramInfo {
    /// Kernel-assigned ID.
    pub id: u32,
    /// Program type.
    pub program_type: ProgramType,
    /// Kernel object name.
    pub name: String,
    /// Kernel-generated program tag.
    pub tag: [u8; 8],
    /// Translated instruction length.
    pub translated_size: u32,
    /// JIT-compiled instruction length.
    pub jited_size: u32,
    /// Time the program was loaded, in nanoseconds since boot.
    pub load_time: u64,
    /// UID that loaded the program.
    pub created_by_uid: u32,
    /// Whether the program may call GPL-only helpers.
    pub gpl_compatible: bool,
    /// IDs of maps referenced by the program.
    pub map_ids: Vec<u32>,
    /// Network interface index for device-bound programs.
    pub interface_index: u32,
    /// Network namespace device containing the program.
    pub network_namespace_device: u64,
    /// Network namespace inode containing the program.
    pub network_namespace_inode: u64,
    /// BTF object ID describing the program.
    pub btf_id: u32,
    /// Accumulated runtime in nanoseconds when statistics are enabled.
    pub run_time_nanoseconds: u64,
    /// Number of executions when statistics are enabled.
    pub run_count: u64,
    /// Number of missed recursive executions.
    pub recursion_misses: u64,
    /// Number of verifier-processed instructions.
    pub verified_instructions: u32,
    /// BTF object containing the attachment target.
    pub attach_btf_object_id: u32,
    /// BTF type ID of the attachment target.
    pub attach_btf_id: u32,
}

/// Kernel targets used by a multi-kprobe attachment.
#[derive(Clone, Copy, Debug)]
pub enum KprobeMultiTargets<'target> {
    /// Kernel function names.
    Symbols(&'target [&'target str]),
    /// Kernel function addresses.
    Addresses(&'target [u64]),
}

/// Options for attaching one program to multiple kernel probes.
#[derive(Clone, Copy, Debug)]
pub struct KprobeMultiOptions<'target> {
    targets: KprobeMultiTargets<'target>,
    cookies: Option<&'target [u64]>,
    return_probe: bool,
    session: bool,
}

impl<'target> KprobeMultiOptions<'target> {
    /// Creates options targeting kernel function names.
    pub const fn symbols(symbols: &'target [&'target str]) -> Self {
        Self {
            targets: KprobeMultiTargets::Symbols(symbols),
            cookies: None,
            return_probe: false,
            session: false,
        }
    }

    /// Creates options targeting kernel function addresses.
    pub const fn addresses(addresses: &'target [u64]) -> Self {
        Self {
            targets: KprobeMultiTargets::Addresses(addresses),
            cookies: None,
            return_probe: false,
            session: false,
        }
    }

    /// Supplies one attachment cookie per target.
    pub const fn cookies(mut self, cookies: &'target [u64]) -> Self {
        self.cookies = Some(cookies);
        self
    }

    /// Selects return probes instead of entry probes.
    pub const fn return_probe(mut self, enabled: bool) -> Self {
        self.return_probe = enabled;
        self
    }

    /// Selects a kprobe session link.
    pub const fn session(mut self, enabled: bool) -> Self {
        self.session = enabled;
        self
    }
}

/// Kernel BTF targets used by a tracing-multi attachment.
#[derive(Clone, Copy, Debug)]
pub enum TracingMultiTargets<'target> {
    /// Explicit kernel BTF function type IDs.
    TypeIds(&'target [TypeId]),
    /// A glob pattern matched against traceable kernel BTF function names.
    Pattern(&'target str),
}

/// Options for `fentry.multi`, `fexit.multi`, and `fsession.multi` links.
#[derive(Clone, Copy, Debug)]
pub struct TracingMultiOptions<'target> {
    targets: TracingMultiTargets<'target>,
    cookies: Option<&'target [u64]>,
}

impl<'target> TracingMultiOptions<'target> {
    /// Creates options targeting explicit BTF function IDs.
    pub const fn type_ids(ids: &'target [TypeId]) -> Self {
        Self {
            targets: TracingMultiTargets::TypeIds(ids),
            cookies: None,
        }
    }

    /// Creates options selecting function names with `*` and `?` wildcards.
    pub const fn pattern(pattern: &'target str) -> Self {
        Self {
            targets: TracingMultiTargets::Pattern(pattern),
            cookies: None,
        }
    }

    /// Supplies one attachment cookie per selected function.
    pub const fn cookies(mut self, cookies: &'target [u64]) -> Self {
        self.cookies = Some(cookies);
        self
    }
}

/// Userspace targets used by a multi-uprobe attachment.
#[derive(Clone, Copy, Debug)]
pub enum UprobeMultiTargets<'target> {
    /// File offsets into the executable or shared object.
    Offsets(&'target [u64]),
    /// Exact ELF function symbols resolved by this crate.
    Symbols(&'target [&'target str]),
}

/// Options for attaching one program to multiple userspace probes.
#[derive(Clone, Debug)]
pub struct UprobeMultiOptions<'target> {
    path: PathBuf,
    targets: UprobeMultiTargets<'target>,
    reference_counter_offsets: Option<&'target [u64]>,
    cookies: Option<&'target [u64]>,
    pid: Option<u32>,
    return_probe: bool,
    session: bool,
}

/// Order used when a BPF iterator walks cgroups.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum CgroupIteratorOrder {
    /// Kernel default.
    #[default]
    Default,
    /// Only the selected cgroup.
    SelfOnly,
    /// Descendants in pre-order.
    DescendantsPre,
    /// Descendants in post-order.
    DescendantsPost,
    /// Ancestors upward.
    AncestorsUp,
}

impl CgroupIteratorOrder {
    const fn as_raw(self) -> u32 {
        match self {
            Self::Default => 0,
            Self::SelfOnly => 1,
            Self::DescendantsPre => 2,
            Self::DescendantsPost => 3,
            Self::AncestorsUp => 4,
        }
    }
}

/// Optional target information for a BPF iterator link.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum IteratorOptions<'target> {
    /// No target-specific information.
    None,
    /// Iterate over the contents of a map.
    Map(&'target Map),
    /// Walk cgroups starting at an open cgroup descriptor.
    Cgroup {
        /// Open cgroup directory.
        cgroup: BorrowedFd<'target>,
        /// Traversal order.
        order: CgroupIteratorOrder,
    },
    /// Walk cgroups starting at a kernel cgroup ID.
    CgroupId {
        /// Kernel cgroup ID.
        id: u64,
        /// Traversal order.
        order: CgroupIteratorOrder,
    },
    /// Iterate tasks, optionally filtering by thread and process IDs.
    Task {
        /// Thread ID, or zero for all threads.
        thread_id: u32,
        /// Process ID, or zero for all processes.
        process_id: u32,
        /// Optional pidfd used by newer kernels.
        process_fd: Option<BorrowedFd<'target>>,
    },
}

impl<'target> UprobeMultiOptions<'target> {
    /// Creates options targeting exact file offsets.
    pub fn offsets(path: impl Into<PathBuf>, offsets: &'target [u64]) -> Self {
        Self {
            path: path.into(),
            targets: UprobeMultiTargets::Offsets(offsets),
            reference_counter_offsets: None,
            cookies: None,
            pid: None,
            return_probe: false,
            session: false,
        }
    }

    /// Creates options targeting exact ELF function symbols.
    pub fn symbols(path: impl Into<PathBuf>, symbols: &'target [&'target str]) -> Self {
        Self {
            path: path.into(),
            targets: UprobeMultiTargets::Symbols(symbols),
            reference_counter_offsets: None,
            cookies: None,
            pid: None,
            return_probe: false,
            session: false,
        }
    }

    /// Supplies one reference-counter file offset per target.
    pub const fn reference_counter_offsets(mut self, offsets: &'target [u64]) -> Self {
        self.reference_counter_offsets = Some(offsets);
        self
    }

    /// Supplies one attachment cookie per target.
    pub const fn cookies(mut self, cookies: &'target [u64]) -> Self {
        self.cookies = Some(cookies);
        self
    }

    /// Limits probes to a process. `None` means system-wide.
    pub const fn pid(mut self, pid: Option<u32>) -> Self {
        self.pid = pid;
        self
    }

    /// Selects return probes instead of entry probes.
    pub const fn return_probe(mut self, enabled: bool) -> Self {
        self.return_probe = enabled;
        self
    }

    /// Selects an uprobe session link.
    pub const fn session(mut self, enabled: bool) -> Self {
        self.session = enabled;
        self
    }
}

/// Inputs and execution controls for [`Program::test_run`].
#[derive(Clone, Copy, Debug)]
pub struct TestRunOptions<'data> {
    data: &'data [u8],
    context: &'data [u8],
    data_output_size: usize,
    context_output_size: usize,
    repeat: u32,
    cpu: Option<u32>,
}

impl<'data> TestRunOptions<'data> {
    /// Creates options with the supplied packet/input data.
    ///
    /// The default output capacity is the input length, and the program runs
    /// once on an arbitrary CPU.
    pub fn new(data: &'data [u8]) -> Self {
        Self {
            data,
            context: &[],
            data_output_size: data.len(),
            context_output_size: 0,
            repeat: 1,
            cpu: None,
        }
    }

    /// Supplies program-type-specific context bytes and output capacity.
    pub fn with_context(mut self, context: &'data [u8], output_size: usize) -> Self {
        self.context = context;
        self.context_output_size = output_size;
        self
    }

    /// Changes packet/input output capacity.
    pub fn with_output_size(mut self, size: usize) -> Self {
        self.data_output_size = size;
        self
    }

    /// Runs the program repeatedly; the kernel reports average duration.
    pub fn repeat(mut self, repeat: u32) -> Self {
        self.repeat = repeat.max(1);
        self
    }

    /// Requests execution on a specific CPU.
    pub fn on_cpu(mut self, cpu: u32) -> Self {
        self.cpu = Some(cpu);
        self
    }
}

/// Output from an in-kernel test execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TestRunOutput {
    /// Program return value.
    pub return_value: u32,
    /// Kernel-reported execution duration in nanoseconds.
    pub duration_nanoseconds: u32,
    /// Program output data.
    pub data: Vec<u8>,
    /// Program-specific output context.
    pub context: Vec<u8>,
}

/// An owned reference to a program loaded in the kernel.
#[derive(Clone)]
pub struct Program {
    pub(crate) fd: Arc<OwnedFd>,
    spec: ProgramSpec,
    usdt_manager: Option<Arc<UsdtManager>>,
    token: Option<BpfToken>,
}

impl fmt::Debug for Program {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Program")
            .field("fd", &self.fd.as_raw_fd())
            .field("spec", &self.spec)
            .field("has_usdt_manager", &self.usdt_manager.is_some())
            .field("has_token", &self.token.is_some())
            .finish()
    }
}

impl AsFd for Program {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl Program {
    pub(crate) fn load(
        spec: ProgramSpec,
        license: &[u8],
        btf_fd: Option<BorrowedFd<'_>>,
        token: Option<&BpfToken>,
    ) -> Result<Self> {
        spec.validate()?;
        let btf_fd = btf_fd.map(|fd| fd.as_raw_fd());
        let token_fd = token.map(|token| token.as_fd().as_raw_fd());
        let attach_program_fd = spec
            .attach_program
            .as_ref()
            .map(|target| target.fd.as_raw_fd());
        let attach_btf_object_fd = spec
            .attach_btf_object
            .as_ref()
            .map(|target| target.as_fd().as_raw_fd());
        let mut fd_array = Vec::new();
        if !spec.kernel_btf_objects.is_empty() {
            // Kfunc instruction offset zero denotes vmlinux. Module BTF
            // descriptors therefore start at index one.
            fd_array.reserve(spec.kernel_btf_objects.len() + 1);
            fd_array.push(0);
            fd_array.extend(
                spec.kernel_btf_objects
                    .iter()
                    .map(|btf| btf.as_fd().as_raw_fd()),
            );
        }
        let (func_info, func_info_record_size, line_info, line_info_record_size) =
            if btf_fd.is_some() {
                (
                    spec.func_info.as_slice(),
                    spec.func_info_record_size,
                    spec.line_info.as_slice(),
                    spec.line_info_record_size,
                )
            } else {
                (&[][..], 0, &[][..], 0)
            };
        let options = ProgramLoad {
            program_type: spec.program_type().as_raw(),
            expected_attach_type: spec.kind.attach_type().map_or(0, AttachType::as_raw),
            name: &spec.name,
            instructions: &spec.instructions,
            license,
            kernel_version: spec.kernel_version,
            flags: spec.flags,
            interface_index: spec.interface_index,
            btf_fd,
            func_info,
            func_info_record_size,
            line_info,
            line_info_record_size,
            attach_btf_id: spec.attach_btf_id,
            attach_program_fd,
            attach_btf_object_fd,
            fd_array: &fd_array,
            log_level: spec.verifier_log.level,
            log_size: spec.verifier_log.capacity,
            token_fd,
        };
        let fd = sys::program_load(&options).map_err(|(source, log)| Error::Verifier {
            program: spec.name.clone(),
            source,
            log,
        })?;
        Ok(Self {
            fd: Arc::new(fd),
            spec,
            usdt_manager: None,
            token: token.cloned(),
        })
    }

    /// Opens a program pinned in bpffs.
    pub fn open_pinned(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let fd = sys::object_get(path).map_err(|source| Error::File {
            operation: "open pinned program",
            path: path.into(),
            source,
        })?;
        Self::from_kernel_fd(fd)
    }

    /// Opens a program by its kernel ID.
    pub fn from_id(id: u32) -> Result<Self> {
        let fd = sys::object_get_fd_by_id(sys::ObjectKind::Program, id)
            .map_err(|source| Error::system("open program by ID", source))?;
        Self::from_kernel_fd(fd)
    }

    fn from_kernel_fd(fd: OwnedFd) -> Result<Self> {
        let raw = sys::program_info(fd.as_raw_fd())
            .map_err(|source| Error::system("read program metadata", source))?;
        let program_type = ProgramType::from_raw(raw.program_type);
        let spec = ProgramSpec {
            name: kernel_name(&raw.name),
            section: String::new(),
            kind: ProgramKind::Other {
                program_type,
                attach_type: None,
            },
            instructions: Vec::new(),
            autoload: false,
            auto_attach: false,
            flags: 0,
            kernel_version: 0,
            interface_index: raw.ifindex,
            attach_btf_id: 0,
            attach_program: None,
            attach_btf_object: None,
            kernel_btf_objects: Vec::new(),
            func_info: Vec::new(),
            func_info_record_size: 0,
            line_info: Vec::new(),
            line_info_record_size: 0,
            verifier_log: VerifierLog::default(),
            section_index: 0,
            section_offset: 0,
        };
        Ok(Self {
            fd: Arc::new(fd),
            spec,
            usdt_manager: None,
            token: None,
        })
    }

    pub(crate) fn set_usdt_manager(&mut self, manager: Option<Arc<UsdtManager>>) {
        self.usdt_manager = manager;
    }

    /// Parsed program definition.
    pub fn spec(&self) -> &ProgramSpec {
        &self.spec
    }

    /// Program name.
    pub fn name(&self) -> &str {
        self.spec.name()
    }

    /// Borrows the kernel file descriptor.
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }

    /// Token retained from this program's delegated load, when present.
    pub fn token(&self) -> Option<&BpfToken> {
        self.token.as_ref()
    }

    /// Reads current metadata from the kernel.
    pub fn info(&self) -> Result<ProgramInfo> {
        let (raw, map_ids) = sys::program_info_with_map_ids(self.fd.as_raw_fd())
            .map_err(|source| Error::system("read program metadata", source))?;
        Ok(ProgramInfo {
            id: raw.id,
            program_type: ProgramType::from_raw(raw.program_type),
            name: kernel_name(&raw.name),
            tag: raw.tag,
            translated_size: raw.xlated_program_len,
            jited_size: raw.jited_program_len,
            load_time: raw.load_time,
            created_by_uid: raw.created_by_uid,
            gpl_compatible: raw.gpl_compatible != 0,
            map_ids,
            interface_index: raw.ifindex,
            network_namespace_device: raw.netns_dev,
            network_namespace_inode: raw.netns_ino,
            btf_id: raw.btf_id,
            run_time_nanoseconds: raw.run_time_nanoseconds,
            run_count: raw.run_count,
            recursion_misses: raw.recursion_misses,
            verified_instructions: raw.verified_instructions,
            attach_btf_object_id: raw.attach_btf_object_id,
            attach_btf_id: raw.attach_btf_id,
        })
    }

    /// Pins the program in bpffs.
    pub fn pin(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        sys::object_pin(self.fd.as_raw_fd(), path).map_err(|source| Error::File {
            operation: "pin program",
            path: path.into(),
            source,
        })
    }

    /// Removes a bpffs pin without closing this program handle.
    pub fn unpin(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        fs::remove_file(path).map_err(|source| Error::File {
            operation: "unpin program",
            path: path.into(),
            source,
        })
    }

    /// Binds a map to this program so the kernel retains the map lifetime.
    pub fn bind_map(&self, map: &Map, flags: u32) -> Result<()> {
        sys::program_bind_map(self.fd.as_raw_fd(), map.as_fd().as_raw_fd(), flags)
            .map_err(|source| Error::system("bind map to eBPF program", source))
    }

    /// Associates a non-`struct_ops` program with a `struct_ops` map.
    ///
    /// This is used by programs which call struct-ops kfuncs without being a
    /// callback stored directly in that map.
    pub fn associate_struct_ops(&self, map: &Map, flags: u32) -> Result<()> {
        if self.spec.program_type() == ProgramType::StructOps {
            return Err(Error::InvalidObject(
                "a struct_ops callback program cannot be separately associated".into(),
            ));
        }
        if map.info()?.map_type != crate::MapType::StructOps {
            return Err(Error::InvalidObject(format!(
                "map `{}` is not a struct_ops map",
                map.name()
            )));
        }
        sys::program_associate_struct_ops(self.fd.as_raw_fd(), map.as_fd().as_raw_fd(), flags)
            .map_err(|source| Error::system("associate program with struct_ops map", source))
    }

    /// Executes the program in the kernel without attaching it.
    pub fn test_run(&self, options: TestRunOptions<'_>) -> Result<TestRunOutput> {
        let output = sys::program_test_run(&sys::TestRun {
            program_fd: self.fd.as_raw_fd(),
            data: options.data,
            context: options.context,
            data_output_size: options.data_output_size,
            context_output_size: options.context_output_size,
            repeat: options.repeat,
            cpu: options.cpu,
        })
        .map_err(|source| Error::system("test-run eBPF program", source))?;
        Ok(TestRunOutput {
            return_value: output.return_value,
            duration_nanoseconds: output.duration_nanoseconds,
            data: output.data,
            context: output.context,
        })
    }

    /// Attaches to a raw tracepoint.
    pub fn attach_raw_tracepoint(&self, name: &str) -> Result<Link> {
        self.attach_raw_tracepoint_with_cookie(name, 0)
    }

    /// Attaches to a raw tracepoint with an attachment cookie.
    pub fn attach_raw_tracepoint_with_cookie(&self, name: &str, cookie: u64) -> Result<Link> {
        let fd = sys::raw_tracepoint_open(name, self.fd.as_raw_fd(), cookie)
            .map_err(|source| Error::system("attach raw tracepoint", source))?;
        Ok(Link::bpf(fd))
    }

    /// Attaches this program as a classic socket filter.
    ///
    /// The returned link owns a duplicate socket descriptor and detaches the
    /// filter when dropped.
    pub fn attach_socket(&self, socket: impl AsFd) -> Result<Link> {
        let socket = socket
            .as_fd()
            .try_clone_to_owned()
            .map_err(|source| Error::system("duplicate socket descriptor", source))?;
        sys::socket_attach_bpf(socket.as_raw_fd(), self.fd.as_raw_fd())
            .map_err(|source| Error::system("attach socket filter", source))?;
        Ok(Link::socket(socket))
    }

    /// Attaches to a tracepoint.
    pub fn attach_tracepoint(&self, category: &str, event: &str) -> Result<Link> {
        self.attach_tracepoint_with_cookie(category, event, 0)
    }

    /// Attaches to a tracepoint with an attachment cookie.
    pub fn attach_tracepoint_with_cookie(
        &self,
        category: &str,
        event: &str,
        cookie: u64,
    ) -> Result<Link> {
        let id = tracepoint_id(category, event)?;
        let event = sys::tracepoint_event(id, 0)
            .map_err(|source| Error::system("open tracepoint perf event", source))?;
        self.attach_owned_perf_event(event, cookie)
    }

    /// Attaches to a kernel function on every online CPU.
    pub fn attach_kprobe(&self, function: &str, offset: u64, return_probe: bool) -> Result<Link> {
        let pmu_type = read_u32(
            "/sys/bus/event_source/devices/kprobe/type",
            "kprobe PMU type",
        )?;
        let fds = online_cpus()?
            .into_iter()
            .map(|cpu| {
                sys::kprobe_perf_event(
                    pmu_type,
                    function,
                    offset,
                    return_probe,
                    cpu,
                    self.fd.as_raw_fd(),
                )
            })
            .collect::<StdResult<Vec<_>, _>>()
            .map_err(|source| Error::system("attach kprobe perf event", source))?;
        Ok(Link::perf_events(fds))
    }

    /// Attaches to many kernel functions with one kernel link.
    pub fn attach_kprobe_multi(&self, options: KprobeMultiOptions<'_>) -> Result<Link> {
        if options.return_probe && options.session {
            return Err(Error::InvalidObject(
                "kprobe sessions cannot be return probes".into(),
            ));
        }
        let (symbols, addresses) = match options.targets {
            KprobeMultiTargets::Symbols(symbols) => (Some(symbols), None),
            KprobeMultiTargets::Addresses(addresses) => (None, Some(addresses)),
        };
        let attach_type = if options.session {
            AttachType::TraceKprobeSession
        } else {
            AttachType::TraceKprobeMulti
        };
        let fd = sys::kprobe_multi_link_create(
            self.fd.as_raw_fd(),
            attach_type.as_raw(),
            symbols,
            addresses,
            options.cookies,
            options.return_probe,
        )
        .map_err(|source| Error::system("attach multi-kprobe program", source))?;
        Ok(Link::bpf(fd))
    }

    /// Attaches a tracing program to multiple kernel BTF functions.
    pub fn attach_tracing_multi(&self, options: TracingMultiOptions<'_>) -> Result<Link> {
        let attach_type = self.spec.kind.attach_type().ok_or_else(|| {
            Error::InvalidObject(format!(
                "program `{}` has no tracing-multi attachment type",
                self.name()
            ))
        })?;
        if !matches!(
            attach_type,
            AttachType::TraceFunctionEntryMulti
                | AttachType::TraceFunctionExitMulti
                | AttachType::TraceFunctionSessionMulti
        ) {
            return Err(Error::InvalidObject(format!(
                "program `{}` is not a tracing-multi program",
                self.name()
            )));
        }
        let ids = match options.targets {
            TracingMultiTargets::TypeIds(ids) => ids.iter().map(|id| id.0).collect::<Vec<_>>(),
            TracingMultiTargets::Pattern(pattern) => {
                if pattern.is_empty() {
                    return Err(Error::InvalidObject(
                        "tracing-multi pattern cannot be empty".into(),
                    ));
                }
                let (module_name, pattern) = match pattern.split_once(':') {
                    Some((module, pattern)) if !module.is_empty() && !pattern.is_empty() => {
                        (Some(module), pattern)
                    }
                    Some(_) => {
                        return Err(Error::InvalidObject(format!(
                            "invalid tracing-multi module pattern `{pattern}`"
                        )));
                    }
                    None => (None, pattern),
                };
                let owned_btf = (module_name.is_none() && self.spec.attach_btf_object.is_none())
                    .then(crate::Btf::from_vmlinux)
                    .transpose()?;
                let btf = match (module_name, self.spec.attach_btf_object.as_ref()) {
                    (Some(module), Some(btf)) if btf.info().name == module => btf.btf(),
                    (Some(module), Some(btf)) => {
                        return Err(Error::InvalidObject(format!(
                            "program `{}` was verified for module `{}`, not `{module}`",
                            self.name(),
                            btf.info().name
                        )));
                    }
                    (Some(module), None) => {
                        return Err(Error::InvalidObject(format!(
                            "program `{}` was not loaded for module `{module}`",
                            self.name()
                        )));
                    }
                    (None, Some(btf)) => btf.btf(),
                    (None, None) => owned_btf
                        .as_ref()
                        .expect("vmlinux BTF is loaded for an unqualified pattern"),
                };
                let local_only = self.spec.attach_btf_object.is_some();
                btf.types()
                    .filter(|(id, ty)| {
                        (!local_only || id.0 as usize > btf.base_type_count())
                            && ty.kind() == BtfKind::Function
                            && ty.name().is_some_and(|name| glob_matches(pattern, name))
                    })
                    .map(|(id, _)| id.0)
                    .collect::<Vec<_>>()
            }
        };
        if ids.is_empty() {
            return Err(Error::InvalidObject(format!(
                "program `{}` has no tracing-multi targets",
                self.name()
            )));
        }
        let fd = sys::tracing_multi_link_create(
            self.fd.as_raw_fd(),
            attach_type.as_raw(),
            &ids,
            options.cookies,
        )
        .map_err(|source| Error::system("attach tracing-multi program", source))?;
        Ok(Link::bpf(fd))
    }

    /// Attaches to an offset in a userspace executable or shared object.
    ///
    /// With `pid = None`, the probe is system-wide. With a process ID, only
    /// that process is observed.
    pub fn attach_uprobe(
        &self,
        path: impl AsRef<Path>,
        offset: u64,
        pid: Option<u32>,
        return_probe: bool,
    ) -> Result<Link> {
        let pmu_type = read_u32(
            "/sys/bus/event_source/devices/uprobe/type",
            "uprobe PMU type",
        )?;
        let path = path.as_ref();
        let cpus = if pid.is_some() {
            vec![-1]
        } else {
            online_cpus()?
        };
        let fds = cpus
            .into_iter()
            .map(|cpu| {
                sys::uprobe_perf_event(&sys::UprobeTarget {
                    pmu_type,
                    path,
                    offset,
                    return_probe,
                    pid,
                    cpu,
                    program_fd: self.fd.as_raw_fd(),
                })
            })
            .collect::<StdResult<Vec<_>, _>>()
            .map_err(|source| Error::system("attach uprobe perf event", source))?;
        Ok(Link::perf_events(fds))
    }

    /// Attaches to many locations in one executable with one kernel link.
    pub fn attach_uprobe_multi(&self, options: UprobeMultiOptions<'_>) -> Result<Link> {
        if options.return_probe && options.session {
            return Err(Error::InvalidObject(
                "uprobe sessions cannot be return probes".into(),
            ));
        }
        let resolved;
        let offsets = match options.targets {
            UprobeMultiTargets::Offsets(offsets) => offsets,
            UprobeMultiTargets::Symbols(symbols) => {
                resolved = resolve_elf_symbols(&options.path, symbols)?;
                &resolved
            }
        };
        let attach_type = if options.session {
            AttachType::TraceUprobeSession
        } else {
            AttachType::TraceUprobeMulti
        };
        let fd = sys::uprobe_multi_link_create(&sys::UprobeMultiTarget {
            program_fd: self.fd.as_raw_fd(),
            attach_type: attach_type.as_raw(),
            path: &options.path,
            offsets,
            reference_counter_offsets: options.reference_counter_offsets,
            cookies: options.cookies,
            pid: options.pid,
            return_probe: options.return_probe,
        })
        .map_err(|source| Error::system("attach multi-uprobe program", source))?;
        Ok(Link::bpf(fd))
    }

    /// Attaches to every call site for one `SystemTap` USDT probe.
    ///
    /// The owning object must contain the support maps emitted by
    /// `bpf/usdt.bpf.h`. Spec IDs, argument layouts, cookies, semaphore
    /// offsets, and cleanup are managed automatically.
    pub fn attach_usdt(&self, options: UsdtOptions) -> Result<Link> {
        let manager = self.usdt_manager.as_ref().ok_or_else(|| {
            Error::InvalidObject(format!(
                "program `{}` has no USDT support maps in its loaded object",
                self.name()
            ))
        })?;
        manager.attach(self, options)
    }

    /// Creates a cgroup link.
    pub fn attach_cgroup(&self, cgroup: impl AsFd, attach_type: AttachType) -> Result<Link> {
        self.attach_link(cgroup, attach_type, LinkOptions::default())
    }

    /// Creates a descriptor-targeted kernel link.
    ///
    /// This is the common safe primitive for cgroup, network-namespace,
    /// socket-map, and other FD-targeted hooks.
    pub fn attach_link(
        &self,
        target: impl AsFd,
        attach_type: AttachType,
        options: LinkOptions,
    ) -> Result<Link> {
        let target = u32::try_from(target.as_fd().as_raw_fd())
            .map_err(|_| Error::InvalidObject("attachment descriptor is negative".into()))?;
        let fd = sys::link_create(
            self.fd.as_raw_fd(),
            target,
            attach_type.as_raw(),
            options.flags,
            options.target_btf_id,
            0,
        )
        .map_err(|source| Error::system("create descriptor-targeted eBPF link", source))?;
        Ok(Link::bpf(fd))
    }

    /// Attaches to a network namespace using the program's inferred hook type.
    pub fn attach_netns(&self, namespace: impl AsFd) -> Result<Link> {
        let attach_type = self.spec.kind.attach_type().ok_or_else(|| {
            Error::InvalidObject(format!(
                "program `{}` has no inferred network-namespace attachment type",
                self.name()
            ))
        })?;
        self.attach_link(namespace, attach_type, LinkOptions::default())
    }

    /// Attaches a parser or verdict program to a socket map with a kernel link.
    pub fn attach_sockmap(&self, map: &Map, attach_type: AttachType) -> Result<Link> {
        if !matches!(
            attach_type,
            AttachType::StreamParser
                | AttachType::StreamVerdict
                | AttachType::SocketVerdict
                | AttachType::SocketMessageVerdict
        ) {
            return Err(Error::InvalidObject(format!(
                "{attach_type:?} is not a socket-map attachment type"
            )));
        }
        self.attach_link(map, attach_type, LinkOptions::default())
    }

    /// Attaches through the generic `BPF_PROG_ATTACH` API.
    ///
    /// This covers hooks such as socket-map verdicts and flow dissectors that
    /// do not necessarily expose a `bpf_link` on all supported kernels. The
    /// returned RAII link owns duplicate descriptors and detaches on drop.
    pub fn attach_legacy(
        &self,
        target: impl AsFd,
        attach_type: AttachType,
        flags: u32,
    ) -> Result<Link> {
        let target = target
            .as_fd()
            .try_clone_to_owned()
            .map_err(|source| Error::system("duplicate attachment target descriptor", source))?;
        let program = self
            .fd
            .try_clone()
            .map_err(|source| Error::system("duplicate eBPF program descriptor", source))?;
        sys::program_attach(
            program.as_raw_fd(),
            target.as_raw_fd(),
            attach_type.as_raw(),
            flags,
        )
        .map_err(|source| Error::system("attach legacy eBPF program", source))?;
        Ok(Link::legacy(target, program, attach_type))
    }

    /// Creates an XDP link on a network interface.
    pub fn attach_xdp(&self, interface_index: u32, flags: u32) -> Result<Link> {
        let fd = sys::link_create(
            self.fd.as_raw_fd(),
            interface_index,
            AttachType::Xdp.as_raw(),
            flags,
            0,
            0,
        )
        .map_err(|source| Error::system("attach XDP program", source))?;
        Ok(Link::bpf(fd))
    }

    /// Creates a TCX ingress or egress link on a network interface.
    pub fn attach_tcx(
        &self,
        interface_index: u32,
        attach_type: AttachType,
        flags: u32,
    ) -> Result<Link> {
        if !matches!(attach_type, AttachType::TcxIngress | AttachType::TcxEgress) {
            return Err(Error::InvalidObject(format!(
                "{attach_type:?} is not a TCX attachment type"
            )));
        }
        let fd = sys::link_create(
            self.fd.as_raw_fd(),
            interface_index,
            attach_type.as_raw(),
            flags,
            0,
            0,
        )
        .map_err(|source| Error::system("attach TCX program", source))?;
        Ok(Link::bpf(fd))
    }

    /// Creates a netfilter link.
    pub fn attach_netfilter(
        &self,
        protocol_family: u32,
        hook_number: u32,
        priority: i32,
        flags: u32,
    ) -> Result<Link> {
        let fd = sys::netfilter_link_create(&sys::NetfilterLink {
            program_fd: self.fd.as_raw_fd(),
            protocol_family,
            hook_number,
            priority,
            flags,
        })
        .map_err(|source| Error::system("attach netfilter program", source))?;
        Ok(Link::bpf(fd))
    }

    /// Links the program to an already-open perf event.
    pub fn attach_perf_event(&self, event: impl AsFd, cookie: u64) -> Result<Link> {
        let event = event
            .as_fd()
            .try_clone_to_owned()
            .map_err(|source| Error::system("duplicate perf-event descriptor", source))?;
        self.attach_owned_perf_event(event, cookie)
    }

    /// Creates a BTF tracing, LSM, or iterator link.
    pub fn attach_btf(&self, attach_type: AttachType, target_btf_id: u32) -> Result<Link> {
        if target_btf_id != 0
            && self.spec.attach_btf_id != 0
            && target_btf_id != self.spec.attach_btf_id
        {
            return Err(Error::InvalidObject(format!(
                "program `{}` was verified for BTF type {}, not {target_btf_id}",
                self.name(),
                self.spec.attach_btf_id
            )));
        }
        let fd = sys::link_create(self.fd.as_raw_fd(), 0, attach_type.as_raw(), 0, 0, 0)
            .map_err(|source| Error::system("attach BTF tracing program", source))?;
        Ok(Link::bpf(fd))
    }

    /// Attaches an extension program to its configured loaded-program target.
    pub fn attach_freplace(&self) -> Result<Link> {
        if self.spec.program_type() != ProgramType::Extension {
            return Err(Error::InvalidObject(format!(
                "program `{}` is not an extension program",
                self.name()
            )));
        }
        let target = self.spec.attach_program.as_ref().ok_or_else(|| {
            Error::InvalidObject(format!(
                "extension program `{}` has no configured target program",
                self.name()
            ))
        })?;
        let target_fd = u32::try_from(target.fd.as_raw_fd())
            .map_err(|_| Error::InvalidObject("target program descriptor is negative".into()))?;
        let fd = sys::link_create(
            self.fd.as_raw_fd(),
            target_fd,
            0,
            0,
            self.spec.attach_btf_id,
            0,
        )
        .map_err(|source| Error::system("attach extension program", source))?;
        Ok(Link::bpf(fd))
    }

    fn attach_owned_perf_event(&self, event: OwnedFd, cookie: u64) -> Result<Link> {
        match sys::perf_event_link_create(self.fd.as_raw_fd(), event.as_raw_fd(), cookie) {
            Ok(link) => {
                sys::perf_event_enable(event.as_raw_fd())
                    .map_err(|source| Error::system("enable perf event", source))?;
                Ok(Link::bpf_perf_event(link, event))
            }
            Err(error)
                if cookie == 0
                    && matches!(
                        error.raw_os_error(),
                        Some(code)
                            if code == libc::EINVAL
                                || code == libc::EOPNOTSUPP
                                || code == libc::ENOSYS
                    ) =>
            {
                sys::perf_event_set_bpf(event.as_raw_fd(), self.fd.as_raw_fd()).map_err(
                    |source| Error::system("attach program through perf-event ioctl", source),
                )?;
                sys::perf_event_enable(event.as_raw_fd())
                    .map_err(|source| Error::system("enable perf event", source))?;
                Ok(Link::perf_events(vec![event]))
            }
            Err(source) => Err(Error::system("attach program to perf event", source)),
        }
    }

    /// Creates a BPF iterator link with optional map, cgroup, or task scope.
    pub fn attach_iterator(&self, options: IteratorOptions<'_>) -> Result<Link> {
        if !matches!(
            self.spec.kind(),
            ProgramKind::Tracing {
                attach_type: AttachType::TraceIterator,
                ..
            }
        ) {
            return Err(Error::InvalidObject(format!(
                "program `{}` is not a BPF iterator",
                self.name()
            )));
        }
        let info = match options {
            IteratorOptions::None => None,
            IteratorOptions::Map(map) => {
                let mut info = [0_u8; 16];
                let fd = u32::try_from(map.as_fd().as_raw_fd())
                    .map_err(|_| Error::InvalidObject("map descriptor is negative".into()))?;
                info[..4].copy_from_slice(&fd.to_ne_bytes());
                Some(info)
            }
            IteratorOptions::Cgroup { cgroup, order } => {
                let mut info = [0_u8; 16];
                let fd = u32::try_from(cgroup.as_raw_fd())
                    .map_err(|_| Error::InvalidObject("cgroup descriptor is negative".into()))?;
                info[..4].copy_from_slice(&order.as_raw().to_ne_bytes());
                info[4..8].copy_from_slice(&fd.to_ne_bytes());
                Some(info)
            }
            IteratorOptions::CgroupId { id, order } => {
                let mut info = [0_u8; 16];
                info[..4].copy_from_slice(&order.as_raw().to_ne_bytes());
                info[8..16].copy_from_slice(&id.to_ne_bytes());
                Some(info)
            }
            IteratorOptions::Task {
                thread_id,
                process_id,
                process_fd,
            } => {
                let mut info = [0_u8; 16];
                let process_fd = process_fd
                    .map(|fd| {
                        u32::try_from(fd.as_raw_fd()).map_err(|_| {
                            Error::InvalidObject("process descriptor is negative".into())
                        })
                    })
                    .transpose()?
                    .unwrap_or_default();
                info[..4].copy_from_slice(&thread_id.to_ne_bytes());
                info[4..8].copy_from_slice(&process_id.to_ne_bytes());
                info[8..12].copy_from_slice(&process_fd.to_ne_bytes());
                Some(info)
            }
        };
        let fd = sys::iterator_link_create(
            self.fd.as_raw_fd(),
            AttachType::TraceIterator.as_raw(),
            info.as_ref(),
        )
        .map_err(|source| Error::system("attach BPF iterator program", source))?;
        Ok(Link::bpf(fd))
    }

    /// Attaches using the target encoded in the program section when no extra
    /// runtime argument is required.
    pub fn attach(&self) -> Result<Link> {
        match self.spec.kind() {
            ProgramKind::Kprobe {
                function,
                return_probe,
            } => self.attach_kprobe(function, 0, *return_probe),
            ProgramKind::Tracepoint { category, event } => self.attach_tracepoint(category, event),
            ProgramKind::RawTracepoint { name, .. } => self.attach_raw_tracepoint(name),
            ProgramKind::Tracing {
                attach_type: AttachType::TraceIterator,
                ..
            } if self.spec.auto_attachable() => self.attach_iterator(IteratorOptions::None),
            ProgramKind::Tracing {
                attach_type:
                    AttachType::TraceFunctionEntryMulti
                    | AttachType::TraceFunctionExitMulti
                    | AttachType::TraceFunctionSessionMulti,
                target,
            } if self.spec.auto_attachable() => {
                self.attach_tracing_multi(TracingMultiOptions::pattern(target))
            }
            ProgramKind::Tracing { attach_type, .. } if self.spec.auto_attachable() => {
                if self.spec.attach_btf_id == 0 {
                    return Err(Error::InvalidObject(format!(
                        "program `{}` has no resolved BTF attachment target",
                        self.spec.name
                    )));
                }
                self.attach_btf(*attach_type, self.spec.attach_btf_id)
            }
            ProgramKind::Other {
                program_type: ProgramType::Extension,
                ..
            } if self.spec.auto_attach() => self.attach_freplace(),
            _ => Err(Error::Unsupported(format!(
                "program section `{}` needs attachment arguments",
                self.spec.section
            ))),
        }
    }
}

fn glob_matches(pattern: &str, value: &str) -> bool {
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let (mut pattern_index, mut value_index) = (0, 0);
    let (mut star, mut retry_value) = (None, 0);
    while value_index < value.len() {
        if pattern
            .get(pattern_index)
            .is_some_and(|byte| *byte == b'?' || Some(byte) == value.get(value_index))
        {
            pattern_index += 1;
            value_index += 1;
        } else if pattern.get(pattern_index) == Some(&b'*') {
            star = Some(pattern_index);
            pattern_index += 1;
            retry_value = value_index;
        } else if let Some(star_index) = star {
            pattern_index = star_index + 1;
            retry_value += 1;
            value_index = retry_value;
        } else {
            return false;
        }
    }
    pattern[pattern_index..].iter().all(|byte| *byte == b'*')
}

fn resolve_elf_symbols(path: &Path, symbols: &[&str]) -> Result<Vec<u64>> {
    if symbols.is_empty() {
        return Err(Error::InvalidObject(
            "multi-uprobe symbol list cannot be empty".into(),
        ));
    }
    let bytes = fs::read(path).map_err(|source| Error::File {
        operation: "read userspace probe ELF",
        path: path.into(),
        source,
    })?;
    let elf = Elf::parse(&bytes)
        .map_err(|error| Error::InvalidObject(format!("invalid userspace probe ELF: {error}")))?;
    symbols
        .iter()
        .map(|requested| {
            elf.syms
                .iter()
                .filter(|symbol| symbol.st_type() == STT_FUNC && symbol.st_shndx != 0)
                .find(|symbol| elf.strtab.get_at(symbol.st_name) == Some(*requested))
                .or_else(|| {
                    elf.dynsyms
                        .iter()
                        .filter(|symbol| symbol.st_type() == STT_FUNC && symbol.st_shndx != 0)
                        .find(|symbol| elf.dynstrtab.get_at(symbol.st_name) == Some(*requested))
                })
                .ok_or_else(|| {
                    Error::InvalidObject(format!(
                        "ELF symbol `{requested}` was not found in `{}`",
                        path.display()
                    ))
                })
                .and_then(|symbol| {
                    let section = elf.section_headers.get(symbol.st_shndx).ok_or_else(|| {
                        Error::InvalidObject(format!(
                            "ELF symbol `{requested}` has invalid section {}",
                            symbol.st_shndx
                        ))
                    })?;
                    symbol
                        .st_value
                        .checked_sub(section.sh_addr)
                        .and_then(|offset| offset.checked_add(section.sh_offset))
                        .ok_or_else(|| {
                            Error::InvalidObject(format!(
                                "ELF symbol `{requested}` file offset overflows"
                            ))
                        })
                })
        })
        .collect()
}

fn tracepoint_id(category: &str, event: &str) -> Result<u64> {
    for root in ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"] {
        let path = PathBuf::from(root)
            .join("events")
            .join(category)
            .join(event)
            .join("id");
        match fs::read_to_string(&path) {
            Ok(value) => {
                return value.trim().parse().map_err(|_| {
                    Error::InvalidObject(format!(
                        "tracepoint ID in `{}` is not an integer",
                        path.display()
                    ))
                });
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(Error::File {
                    operation: "read tracepoint ID",
                    path,
                    source,
                });
            }
        }
    }
    Err(Error::InvalidObject(format!(
        "tracepoint `{category}/{event}` does not exist"
    )))
}

pub(crate) fn online_cpus() -> Result<Vec<i32>> {
    let text = fs::read_to_string("/sys/devices/system/cpu/online")
        .map_err(|source| Error::system("read online CPU list", source))?;
    parse_cpu_set(text.trim())
}

fn parse_cpu_set(list: &str) -> Result<Vec<i32>> {
    let mut cpus = Vec::new();
    for range in list.split(',').filter(|range| !range.is_empty()) {
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
        cpus.extend(start..=end);
    }
    if cpus.is_empty() {
        Err(Error::InvalidObject("online CPU list is empty".into()))
    } else {
        Ok(cpus)
    }
}

fn parse_cpu(cpu: &str) -> Result<i32> {
    cpu.parse()
        .map_err(|_| Error::InvalidObject(format!("invalid CPU number `{cpu}`")))
}

fn read_u32(path: &str, what: &'static str) -> Result<u32> {
    let value = fs::read_to_string(path).map_err(|source| Error::File {
        operation: "read perf PMU type",
        path: path.into(),
        source,
    })?;
    value
        .trim()
        .parse()
        .map_err(|_| Error::InvalidObject(format!("{what} is not an integer")))
}

pub(crate) fn program_flags_from_section(section: &str) -> u32 {
    const BPF_F_SLEEPABLE: u32 = 1 << 4;
    const BPF_F_XDP_HAS_FRAGS: u32 = 1 << 5;

    let prefix = section
        .split_once('/')
        .map_or(section, |(prefix, _)| prefix);
    let mut flags = 0;
    if prefix.ends_with(".s") || prefix == "syscall" {
        flags |= BPF_F_SLEEPABLE;
    }
    if prefix == "xdp.frags" {
        flags |= BPF_F_XDP_HAS_FRAGS;
    }
    flags
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn program_types_round_trip() {
        for raw in 0..40 {
            assert_eq!(ProgramType::from_raw(raw).as_raw(), raw);
        }
    }

    #[test]
    fn helper_ids_are_future_proof() {
        assert_eq!(HelperId::MAP_LOOKUP_ELEMENT.as_raw(), 1);
        assert_eq!(HelperId::from_raw(u32::MAX).as_raw(), u32::MAX);
        assert_eq!(HelperId::from(174), HelperId::ATTACH_COOKIE);
    }

    #[test]
    fn conventional_sections_are_inferred() {
        assert_eq!(
            ProgramKind::from_section("tracepoint/sched/sched_switch").unwrap(),
            ProgramKind::Tracepoint {
                category: "sched".into(),
                event: "sched_switch".into()
            }
        );
        assert_eq!(
            ProgramKind::from_section("fentry/do_unlinkat")
                .unwrap()
                .program_type(),
            ProgramType::Tracing
        );
        assert_eq!(
            ProgramKind::from_section("usdt").unwrap().attach_type(),
            Some(AttachType::TraceUprobeMulti)
        );
        assert!(ProgramKind::from_section("made_up/foo").is_err());
    }

    #[test]
    fn auto_attachment_requires_no_runtime_target() {
        let instructions = vec![Instruction::new(0x95, 0, 0, 0, 0)];
        assert!(
            ProgramSpec::new("entry", "fentry/do_unlinkat", instructions.clone())
                .unwrap()
                .auto_attachable()
        );
        assert!(ProgramSpec::new(
            "entry",
            "tracepoint/sched/sched_switch",
            instructions.clone()
        )
        .unwrap()
        .auto_attachable());
        assert!(
            ProgramSpec::new("entry", "fentry.multi/do_*", instructions.clone())
                .unwrap()
                .auto_attachable()
        );
        assert!(!ProgramSpec::new("entry", "xdp", instructions)
            .unwrap()
            .auto_attachable());
    }

    #[test]
    fn parses_sparse_cpu_sets() {
        assert_eq!(parse_cpu_set("0-2,5").unwrap(), [0, 1, 2, 5]);
        assert!(parse_cpu_set("").is_err());
        assert!(parse_cpu_set("2-1").is_err());
    }

    #[test]
    fn tracing_multi_globs_match_kernel_symbol_names() {
        assert!(glob_matches("tcp_*", "tcp_v4_connect"));
        assert!(glob_matches("dummy_?mit", "dummy_xmit"));
        assert!(glob_matches("*", "anything"));
        assert!(!glob_matches("tcp_?", "tcp_v4_connect"));
        assert!(!glob_matches("dummy_*", "net_dummy_xmit"));
    }

    #[test]
    fn program_spec_configuration_is_owned() {
        let mut spec = ProgramSpec::new(
            "on_exec",
            "raw_tracepoint/sys_enter",
            vec![Instruction::new(0x95, 0, 0, 0, 0)],
        )
        .unwrap();
        spec.set_autoload(false).set_auto_attach(false).set_flags(4);
        assert!(!spec.autoload());
        assert!(!spec.auto_attach());
        assert!(!spec.auto_attachable());
        assert_eq!(spec.program_type(), ProgramType::RawTracepoint);
    }

    #[test]
    fn test_run_options_are_fluent_and_never_repeat_zero_times() {
        let context = [1, 2, 3, 4];
        let options = TestRunOptions::new(&[5, 6])
            .with_output_size(32)
            .with_context(&context, 16)
            .repeat(0)
            .on_cpu(3);
        assert_eq!(options.data_output_size, 32);
        assert_eq!(options.context_output_size, 16);
        assert_eq!(options.repeat, 1);
        assert_eq!(options.cpu, Some(3));
    }

    #[test]
    fn section_suffixes_enable_kernel_program_flags() {
        assert_eq!(program_flags_from_section("fentry.s/do_open"), 1 << 4);
        assert_eq!(program_flags_from_section("syscall"), 1 << 4);
        assert_eq!(program_flags_from_section("xdp.frags/devmap"), 1 << 5);
        assert_eq!(program_flags_from_section("xdp"), 0);
    }
}
