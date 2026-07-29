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
mod link;
mod map;
mod object;
mod perfbuf;
mod program;
pub mod query;
mod ringbuf;
mod sys;
mod user_ringbuf;

pub use crate::btf::{Btf, BtfKind, BtfMember, BtfType, TypeId};
pub use crate::error::{Error, Result};
pub use crate::instruction::Instruction;
pub use crate::link::{AttachType, Link};
pub use crate::map::{
    BatchCursor, KeyIterator, Map, MapBatch, MapFlags, MapInfo, MapSpec, MapType, Pinning,
    UpdateMode,
};
pub use crate::object::{LoadedObject, Object};
pub use crate::perfbuf::{PerfBuffer, PerfBufferBuilder, PerfEvent};
pub use crate::program::{
    Program, ProgramInfo, ProgramKind, ProgramSpec, ProgramType, TestRunOptions, TestRunOutput,
    VerifierLog,
};
pub use crate::ringbuf::{RingBuffer, RingBufferBuilder};
pub use crate::user_ringbuf::{UserRingBuffer, UserRingReservation};
