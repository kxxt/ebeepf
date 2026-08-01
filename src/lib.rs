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
#[cfg(feature = "coverage")]
pub mod coverage;
mod error;
mod features;
mod instruction;
mod iter;
mod link;
mod linker;
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
#[cfg(test)]
mod test_bpf;
mod token;
mod usdt;
mod user_ringbuf;
mod xdp;

pub use crate::btf::{Btf, BtfEndianness, BtfInfo, BtfKind, BtfMember, BtfObject, BtfType, TypeId};
pub use crate::error::{Error, Result};
pub use crate::features::{possible_cpu_count, KernelFeatures};
pub use crate::instruction::Instruction;
pub use crate::iter::BpfIterator;
pub use crate::link::{
    AttachType, CgroupLinkOrder, IteratorLinkTarget, Link, LinkDetails, LinkInfo, LinkType,
    PerfEventLinkDetails,
};
pub use crate::linker::{LinkedObject, ObjectLinker};
pub use crate::map::{
    BatchCursor, KeyIterator, Map, MapBatch, MapBatchOptions, MapCreateOptions, MapElementFlags,
    MapFlags, MapInfo, MapMemory, MapMemoryMut, MapSpec, MapType, ObjectAccess, ObjectPathOptions,
    Pinning, UpdateMode,
};
pub use crate::object::{LoadedObject, Object};
pub use crate::perfbuf::{PerfBuffer, PerfBufferBuilder, PerfEvent};
pub use crate::program::{
    AttachAnchor, AttachOrder, CgroupIteratorOrder, HelperId, IteratorOptions, KprobeMultiOptions,
    KprobeMultiTargets, LinkOptions, OrderedLinkOptions, Program, ProgramInfo, ProgramInfoOptions,
    ProgramInfoRecords, ProgramInfoRecordsRef, ProgramKind, ProgramSpec, ProgramStatistics,
    ProgramStream, ProgramType, TestRunOptions, TestRunOutput, TracingMultiOptions,
    TracingMultiTargets, UprobeMultiOptions, UprobeMultiTargets, VerifierLog,
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
