//! Source-based coverage support for eBPF programs.
//!
//! Enable the `coverage` feature to instrument eBPF C sources with bpfcov,
//! collect their profiling maps from a loaded [`LoadedObject`], and generate
//! reports with the LLVM coverage tools.

use std::{
    fs::File,
    io::{self, Write},
    path::{Path, PathBuf},
};

use thiserror::Error as ThisError;

use crate::{Error, LoadedObject, Map};

pub use bpfcov::{instrument, profraw, report, CoverageData, InstrumentedBuild, Pipeline};

/// Suffix of the writable map containing the coverage counters.
pub const COUNTERS_MAP_SUFFIX: &str = ".data.profc";
/// Suffix of the read-only map containing profiling data records.
pub const DATA_RECORDS_MAP_SUFFIX: &str = ".rodata.profd";
/// Suffix of the read-only map containing compressed function names.
pub const NAMES_MAP_SUFFIX: &str = ".rodata.profn";

/// An error encountered while collecting bpfcov data from an eBPF object.
#[derive(Debug, ThisError)]
#[non_exhaustive]
pub enum CollectError {
    /// A required profiling map is absent.
    #[error("bpfcov map ending in `{0}` was not found")]
    MapNotFound(&'static str),
    /// Looking up the profiling map value failed.
    #[error("failed to read bpfcov map `{map}`: {source}")]
    Lookup {
        /// Name of the map being read.
        map: String,
        /// Error returned by the eBPF map lookup.
        #[source]
        source: Error,
    },
    /// A required profiling map had no value at key zero.
    #[error("bpfcov map ending in `{0}` was empty")]
    EmptyMap(&'static str),
}

/// An error encountered while writing a bpfcov `.profraw` file.
#[derive(Debug, ThisError)]
#[non_exhaustive]
pub enum WriteError {
    /// Collecting the coverage maps failed.
    #[error(transparent)]
    Collect(#[from] CollectError),
    /// Creating the output file failed.
    #[error("failed to create coverage output `{path}`: {source}")]
    Create {
        /// Output path.
        path: PathBuf,
        /// File-system error.
        #[source]
        source: io::Error,
    },
    /// Serializing the LLVM profile failed.
    #[error("failed to write LLVM coverage profile: {0}")]
    Write(#[source] io::Error),
}

/// Extracts bpfcov profiling data from the maps of a loaded eBPF object.
pub fn collect_coverage_data(object: &LoadedObject) -> Result<CoverageData, CollectError> {
    Ok(CoverageData {
        counters: read_map(object, COUNTERS_MAP_SUFFIX)?,
        data_records: read_map(object, DATA_RECORDS_MAP_SUFFIX)?,
        names: read_map(object, NAMES_MAP_SUFFIX)?,
    })
}

/// Returns whether all maps required for bpfcov collection are present.
pub fn has_coverage_maps(object: &LoadedObject) -> bool {
    let mut counters = false;
    let mut data_records = false;
    let mut names = false;

    for map in object.maps() {
        counters |= map.name().ends_with(COUNTERS_MAP_SUFFIX);
        data_records |= map.name().ends_with(DATA_RECORDS_MAP_SUFFIX);
        names |= map.name().ends_with(NAMES_MAP_SUFFIX);
        if counters && data_records && names {
            return true;
        }
    }
    false
}

/// Collects coverage from `object` and serializes it as LLVM profraw data.
pub fn write_profraw(object: &LoadedObject, writer: &mut impl Write) -> Result<(), WriteError> {
    collect_coverage_data(object)?
        .write_profraw(writer)
        .map_err(WriteError::Write)
}

/// Collects coverage from `object` and writes an LLVM `.profraw` file.
pub fn write_profraw_file(
    object: &LoadedObject,
    output: impl AsRef<Path>,
) -> Result<(), WriteError> {
    let output = output.as_ref();
    let mut file = File::create(output).map_err(|source| WriteError::Create {
        path: output.into(),
        source,
    })?;
    write_profraw(object, &mut file)
}

fn read_map(object: &LoadedObject, suffix: &'static str) -> Result<Vec<u8>, CollectError> {
    let map = find_map(object, suffix).ok_or(CollectError::MapNotFound(suffix))?;
    map.lookup(&0_u32.to_ne_bytes())
        .map_err(|source| CollectError::Lookup {
            map: map.name().into(),
            source,
        })?
        .ok_or(CollectError::EmptyMap(suffix))
}

fn find_map<'object>(object: &'object LoadedObject, suffix: &str) -> Option<&'object Map> {
    object.maps().find(|map| map.name().ends_with(suffix))
}
