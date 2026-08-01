//! `bpfcov` — source-based code coverage for eBPF programs.
//!
//! This crate provides three layers:
//!
//! 1. **Build-time instrumentation** ([`instrument`]) — drives `clang`, `opt`
//!    (with the bpfcov LLVM pass), and `llc` to produce both an instrumented BPF
//!    object (for loading into the kernel) and a coverage-only object (for
//!    `llvm-cov`).
//!
//! 2. **Runtime collection** (`collect`, requires the `libbpf` feature) — reads
//!    the profiling-data BPF maps from a loaded `libbpf-rs` object and assembles
//!    [`CoverageData`].
//!
//! 3. **Report generation** ([`report`]) — wraps `llvm-profdata merge` and
//!    `llvm-cov show` / `export` to turn the raw data into human-readable
//!    coverage reports.
//!
//! The core profraw serialization lives in [`profraw`] and has no external
//! dependencies.

#[cfg(feature = "libbpf")]
pub mod collect;
pub mod instrument;
pub mod profraw;
pub mod report;

#[cfg(feature = "libbpf")]
pub use collect::{collect_coverage_data, has_coverage_maps, CollectError};
pub use instrument::{InstrumentedBuild, Pipeline};
pub use profraw::CoverageData;
