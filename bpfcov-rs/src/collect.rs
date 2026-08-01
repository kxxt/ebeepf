//! Collect coverage data from BPF maps via libbpf-rs.
//!
//! After loading an instrumented BPF object, the bpfcov LLVM pass creates
//! three global-data maps whose names end in `.data.profc`, `.rodata.profd`,
//! and `.rodata.profn`.  This module finds those maps on a loaded
//! [`Object`](libbpf_rs::Object) and extracts the raw bytes into a
//! [`CoverageData`] ready for profraw serialization.

use libbpf_rs::{MapCore, MapFlags, Object};

use crate::profraw::CoverageData;

/// Map name suffixes produced by the bpfcov LLVM pass.
const PROFC_SUFFIX: &str = ".data.profc";
const PROFD_SUFFIX: &str = ".rodata.profd";
const PROFN_SUFFIX: &str = ".rodata.profn";

/// Errors that can occur when collecting coverage data.
#[derive(Debug)]
pub enum CollectError {
    /// A required BPF map was not found on the loaded object.
    MapNotFound(&'static str),
    /// A BPF map lookup failed.
    Lookup(libbpf_rs::Error),
    /// A BPF map returned no data for the expected key.
    EmptyMap(&'static str),
}

impl std::fmt::Display for CollectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MapNotFound(suffix) => write!(f, "bpfcov map ending in '{suffix}' not found"),
            Self::Lookup(e) => write!(f, "BPF map lookup failed: {e}"),
            Self::EmptyMap(suffix) => write!(f, "bpfcov map ending in '{suffix}' returned no data"),
        }
    }
}

impl std::error::Error for CollectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Lookup(e) => Some(e),
            _ => None,
        }
    }
}

/// Extract [`CoverageData`] from a loaded BPF [`Object`].
///
/// This iterates all maps on the object looking for the three bpfcov maps
/// (matched by their name suffix), reads their single-entry value, and
/// returns the assembled `CoverageData`.
pub fn collect_coverage_data(obj: &Object) -> Result<CoverageData, CollectError> {
    let mut profc: Option<Vec<u8>> = None;
    let mut profd: Option<Vec<u8>> = None;
    let mut profn: Option<Vec<u8>> = None;

    for map in obj.maps() {
        let name = map.name().to_string_lossy();
        if name.ends_with(PROFC_SUFFIX) {
            profc = Some(read_global_map(&map, PROFC_SUFFIX)?);
        } else if name.ends_with(PROFD_SUFFIX) {
            profd = Some(read_global_map(&map, PROFD_SUFFIX)?);
        } else if name.ends_with(PROFN_SUFFIX) {
            profn = Some(read_global_map(&map, PROFN_SUFFIX)?);
        }
    }

    Ok(CoverageData {
        counters: profc.ok_or(CollectError::MapNotFound(PROFC_SUFFIX))?,
        data_records: profd.ok_or(CollectError::MapNotFound(PROFD_SUFFIX))?,
        names: profn.ok_or(CollectError::MapNotFound(PROFN_SUFFIX))?,
    })
}

/// Read the single entry of a global-data BPF map (key = 0u32).
fn read_global_map(map: &impl MapCore, suffix: &'static str) -> Result<Vec<u8>, CollectError> {
    let key = 0u32.to_ne_bytes();
    map.lookup(&key, MapFlags::ANY)
        .map_err(CollectError::Lookup)?
        .ok_or(CollectError::EmptyMap(suffix))
}

/// Check whether a loaded [`Object`] contains bpfcov instrumentation maps.
pub fn has_coverage_maps(obj: &Object) -> bool {
    let (mut has_profc, mut has_profd, mut has_profn) = (false, false, false);
    for map in obj.maps() {
        let name = map.name().to_string_lossy();
        if name.ends_with(PROFC_SUFFIX) {
            has_profc = true;
        }
        if name.ends_with(PROFD_SUFFIX) {
            has_profd = true;
        }
        if name.ends_with(PROFN_SUFFIX) {
            has_profn = true;
        }
        if has_profc && has_profd && has_profn {
            break;
        }
    }
    has_profc && has_profd && has_profn
}
