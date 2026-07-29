//! A pure Rust eBPF loader and runtime for Linux.
//!
//! `ebeepf` parses ELF and BTF without libbpf and confines the small amount of
//! unsafe code needed for Linux system calls to a private backend. Public
//! operations use owned file descriptors and Rust lifetimes.
//!
//! The usual lifecycle is [`Object::open`], optional inspection or
//! configuration, and [`Object::load`].

#![cfg_attr(not(target_os = "linux"), allow(unused))]

mod btf;
mod error;
mod instruction;
mod iter;
mod link;
mod map;
mod netlink;
mod object;
mod perfbuf;
mod program;
pub mod query;
mod ringbuf;
pub mod skel;
mod sys;
mod tc;
mod token;
mod usdt;
mod user_ringbuf;
mod xdp;

pub use crate::btf::{Btf, BtfInfo, BtfKind, BtfMember, BtfObject, BtfType, TypeId};
pub use crate::error::{Error, Result};
pub use crate::instruction::Instruction;
pub use crate::iter::BpfIterator;
pub use crate::link::{AttachType, Link, LinkInfo, LinkType};
pub use crate::map::{
    BatchCursor, KeyIterator, Map, MapBatch, MapCreateOptions, MapFlags, MapInfo, MapMemory,
    MapMemoryMut, MapSpec, MapType, Pinning, UpdateMode,
};
pub use crate::object::{LoadedObject, Object};
pub use crate::perfbuf::{PerfBuffer, PerfBufferBuilder, PerfEvent};
pub use crate::program::{
    CgroupIteratorOrder, HelperId, IteratorOptions, KprobeMultiOptions, KprobeMultiTargets,
    LinkOptions, Program, ProgramInfo, ProgramKind, ProgramSpec, ProgramStream, ProgramType,
    TestRunOptions, TestRunOutput, TracingMultiOptions, TracingMultiTargets, UprobeMultiOptions,
    UprobeMultiTargets, VerifierLog,
};
pub use crate::ringbuf::{RingBuffer, RingBufferBuilder};
pub use crate::skel::{
    DataSection, DataSectionMut, DataValue, MappedDataSection, MappedDataSectionMut, OpenSkeleton,
    Skeleton, SkeletonBuilder,
};
pub use crate::tc::{TcAttachOptions, TcAttachPoint, TcFilter, TcFilterId, TcFilterInfo, TcHook};
pub use crate::token::{BpfToken, BpfTokenInfo};
pub use crate::usdt::{discover_usdt_probes, UsdtOptions, UsdtProbe};
pub use crate::user_ringbuf::{UserRingBuffer, UserRingReservation};
pub use crate::xdp::{Xdp, XdpAttachMode, XdpAttachOptions, XdpFeatures, XdpFlags, XdpInfo};
