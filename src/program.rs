use std::fmt;
use std::fs;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::result::Result as StdResult;
use std::sync::Arc;

use crate::link::{AttachType, Link};
use crate::map::kernel_name;
use crate::sys::{self, ProgramLoad};
use crate::{Error, Instruction, Result};

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
            "uprobe" | "uprobe.s" | "usdt" | "usdt.s" => Self::Uprobe {
                target: target.into(),
                return_probe: false,
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

/// A program's parsed and configurable definition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProgramSpec {
    pub(crate) name: String,
    pub(crate) section: String,
    pub(crate) kind: ProgramKind,
    pub(crate) instructions: Vec<Instruction>,
    pub(crate) autoload: bool,
    pub(crate) flags: u32,
    pub(crate) kernel_version: u32,
    pub(crate) attach_btf_id: u32,
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
        let flags = program_flags_from_section(&section);
        Ok(Self {
            name: name.into(),
            section,
            kind,
            instructions,
            autoload: true,
            flags,
            kernel_version: 0,
            attach_btf_id: 0,
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

    /// Enables or disables automatic loading.
    pub fn set_autoload(&mut self, autoload: bool) -> &mut Self {
        self.autoload = autoload;
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
}

impl fmt::Debug for Program {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Program")
            .field("fd", &self.fd.as_raw_fd())
            .field("spec", &self.spec)
            .finish()
    }
}

impl Program {
    pub(crate) fn load(
        spec: ProgramSpec,
        license: &[u8],
        btf_fd: Option<BorrowedFd<'_>>,
    ) -> Result<Self> {
        spec.validate()?;
        let btf_fd = btf_fd.map(|fd| fd.as_raw_fd());
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
            btf_fd,
            func_info,
            func_info_record_size,
            line_info,
            line_info_record_size,
            attach_btf_id: spec.attach_btf_id,
            attach_program_fd: None,
            log_level: spec.verifier_log.level,
            log_size: spec.verifier_log.capacity,
        };
        let fd = sys::program_load(&options).map_err(|(source, log)| Error::Verifier {
            program: spec.name.clone(),
            source,
            log,
        })?;
        Ok(Self {
            fd: Arc::new(fd),
            spec,
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
            flags: 0,
            kernel_version: 0,
            attach_btf_id: 0,
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
        })
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

    /// Reads current metadata from the kernel.
    pub fn info(&self) -> Result<ProgramInfo> {
        let raw = sys::program_info(self.fd.as_raw_fd())
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

    /// Attaches to a tracepoint on every online CPU.
    pub fn attach_tracepoint(&self, category: &str, event: &str) -> Result<Link> {
        let id = tracepoint_id(category, event)?;
        let fds = online_cpus()?
            .into_iter()
            .map(|cpu| sys::tracepoint_perf_event(id, cpu, self.fd.as_raw_fd()))
            .collect::<StdResult<Vec<_>, _>>()
            .map_err(|source| Error::system("attach tracepoint perf event", source))?;
        Ok(Link::perf_events(fds))
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

    /// Creates a cgroup link.
    pub fn attach_cgroup(&self, cgroup: impl AsFd, attach_type: AttachType) -> Result<Link> {
        let target = u32::try_from(cgroup.as_fd().as_raw_fd())
            .map_err(|_| Error::InvalidObject("cgroup descriptor is negative".into()))?;
        let fd = sys::link_create(self.fd.as_raw_fd(), target, attach_type.as_raw(), 0, 0, 0)
            .map_err(|source| Error::system("attach cgroup program", source))?;
        Ok(Link::bpf(fd))
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
        let target = u32::try_from(event.as_fd().as_raw_fd())
            .map_err(|_| Error::InvalidObject("perf-event descriptor is negative".into()))?;
        let fd = sys::link_create(
            self.fd.as_raw_fd(),
            target,
            AttachType::PerfEvent.as_raw(),
            0,
            0,
            cookie,
        )
        .map_err(|source| Error::system("attach program to perf event", source))?;
        Ok(Link::bpf(fd))
    }

    /// Creates a BTF tracing, LSM, or iterator link.
    pub fn attach_btf(&self, attach_type: AttachType, target_btf_id: u32) -> Result<Link> {
        let fd = sys::link_create(
            self.fd.as_raw_fd(),
            0,
            attach_type.as_raw(),
            0,
            target_btf_id,
            0,
        )
        .map_err(|source| Error::system("attach BTF tracing program", source))?;
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
            _ => Err(Error::Unsupported(format!(
                "program section `{}` needs attachment arguments",
                self.spec.section
            ))),
        }
    }
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
        assert!(ProgramKind::from_section("made_up/foo").is_err());
    }

    #[test]
    fn parses_sparse_cpu_sets() {
        assert_eq!(parse_cpu_set("0-2,5").unwrap(), [0, 1, 2, 5]);
        assert!(parse_cpu_set("").is_err());
        assert!(parse_cpu_set("2-1").is_err());
    }

    #[test]
    fn program_spec_configuration_is_owned() {
        let mut spec = ProgramSpec::new(
            "on_exec",
            "raw_tracepoint/sys_enter",
            vec![Instruction::new(0x95, 0, 0, 0, 0)],
        )
        .unwrap();
        spec.set_autoload(false).set_flags(4);
        assert!(!spec.autoload());
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
