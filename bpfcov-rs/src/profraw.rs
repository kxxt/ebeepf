//! Profraw v10 format writer.
//!
//! Converts BPF map data (as produced by the bpfcov LLVM pass) into the LLVM
//! profraw format version 10, suitable for consumption by `llvm-profdata` and
//! `llvm-cov`.
//!
//! The bpfcov LLVM pass stores profiling data in BPF map sections:
//! - `.data.profc`    — counter array (writable, one `i64` per counter)
//! - `.rodata.profd`  — data records (read-only, 48 bytes per function)
//! - `.rodata.profn`  — compressed function names (read-only)

use std::io::{self, Write};

/// Size of a single BPF‐side profiling data record.
///
/// Layout (48 bytes total):
/// - `NameRef`      (8 bytes, i64)
/// - `FuncHash`     (8 bytes, i64)
/// - `CounterOff`   (8 bytes, i64)
/// - `FuncPtr`      (8 bytes, i64)
/// - `Values`       (8 bytes, i64)
/// - `NumCounters`  (4 bytes, i32)
/// - `ValueSites`   (4 bytes, i32)
const BPF_DATA_RECORD_SIZE: usize = 48;

/// Size of one profraw v10 data record written to disk.
const PROFRAW_V10_RECORD_SIZE: i64 = 64;

/// Little-endian magic identifying a profraw file.
const PROFRAW_MAGIC: u64 = u64::from_le_bytes([0x81, 0x72, 0x66, 0x6F, 0x72, 0x70, 0x6C, 0xFF]);

/// Profraw format version emitted by this crate (LLVM 18+).
const PROFRAW_VERSION: u64 = 10;

/// IPVK_VTableTarget value for LLVM 18+.
const VALUE_KIND_LAST: u64 = 2;

/// Raw coverage data extracted from the three BPF maps that the bpfcov
/// LLVM pass creates.
#[derive(Debug, Clone)]
pub struct CoverageData {
    /// Counter blob from the `.data.profc` map (array of little-endian `i64`).
    pub counters: Vec<u8>,
    /// Data‐record blob from the `.rodata.profd` map (48 bytes per function).
    pub data_records: Vec<u8>,
    /// Compressed function-name blob from the `.rodata.profn` map.
    pub names: Vec<u8>,
}

impl CoverageData {
    /// Number of profiled functions, derived from the data-record blob size.
    pub fn num_functions(&self) -> u64 {
        (self.data_records.len() / BPF_DATA_RECORD_SIZE) as u64
    }

    /// Number of individual counters, derived from the counter blob size.
    pub fn num_counters(&self) -> u64 {
        (self.counters.len() / 8) as u64
    }

    /// Serialize into profraw v10 format, writing to `w`.
    pub fn write_profraw(&self, w: &mut impl Write) -> io::Result<()> {
        self.validate()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let func_num = self.num_functions();
        let counters_num = self.num_counters();
        let names_size = self.names.len() as u64;

        // --- Header (16 × u64 = 128 bytes) ---
        write_u64(w, PROFRAW_MAGIC)?;
        write_u64(w, PROFRAW_VERSION)?;
        write_u64(w, 0)?; // BinaryIdsSize
        write_u64(w, func_num)?;
        write_u64(w, 0)?; // PaddingBytesBeforeCounters
        write_u64(w, counters_num)?;
        write_u64(w, 0)?; // PaddingBytesAfterCounters
        write_u64(w, 0)?; // NumBitmapBytes
        write_u64(w, 0)?; // PaddingBytesAfterBitmapBytes
        write_u64(w, names_size)?;
        write_u64(w, 0)?; // CountersDelta
        write_u64(w, 0)?; // BitmapDelta
        write_u64(w, 0)?; // NamesDelta
        write_u64(w, 0)?; // NumVTables
        write_u64(w, 0)?; // VNamesSize
        write_u64(w, VALUE_KIND_LAST)?;

        // --- Data records (convert 48-byte BPF records → 64-byte v10 records) ---
        for i in 0..func_num {
            let off = (i as usize) * BPF_DATA_RECORD_SIZE;
            let rec = &self.data_records[off..off + BPF_DATA_RECORD_SIZE];

            // NameRef (8 bytes)
            w.write_all(&rec[0..8])?;
            // FuncHash (8 bytes)
            w.write_all(&rec[8..16])?;
            // CounterPtr (8 bytes) — compensate for advanceData() subtracting sizeof(Data)
            let counter_off = i64::from_le_bytes(rec[16..24].try_into().unwrap());
            let adjusted = counter_off - (i as i64) * PROFRAW_V10_RECORD_SIZE;
            w.write_all(&adjusted.to_le_bytes())?;
            // BitmapPtr (8 bytes, zero)
            w.write_all(&0u64.to_le_bytes())?;
            // FunctionPointer (8 bytes)
            w.write_all(&rec[24..32])?;
            // Values (8 bytes)
            w.write_all(&rec[32..40])?;
            // NumCounters (4 bytes)
            w.write_all(&rec[40..44])?;
            // NumValueSites[3] (3 × u16 = 6 bytes, all zero)
            w.write_all(&[0u8; 6])?;
            // NumBitmapBytes (4 bytes, zero)
            w.write_all(&[0u8; 4])?;
            // Padding to reach 64 bytes (2 bytes)
            w.write_all(&[0u8; 2])?;
        }

        // --- Counters ---
        w.write_all(&self.counters)?;

        // --- Names ---
        w.write_all(&self.names)?;

        // --- Align names to 8-byte boundary ---
        let remainder = self.names.len() % 8;
        if remainder != 0 {
            let padding = 8 - remainder;
            w.write_all(&[0u8; 8][..padding])?;
        }

        Ok(())
    }

    /// Basic sanity checks on the input data.
    fn validate(&self) -> Result<(), String> {
        if self.data_records.len() % BPF_DATA_RECORD_SIZE != 0 {
            return Err(format!(
                "data_records length {} is not a multiple of {}",
                self.data_records.len(),
                BPF_DATA_RECORD_SIZE
            ));
        }
        if self.counters.len() % 8 != 0 {
            return Err(format!(
                "counters length {} is not a multiple of 8",
                self.counters.len()
            ));
        }
        Ok(())
    }
}

fn write_u64(w: &mut impl Write, value: u64) -> io::Result<()> {
    w.write_all(&value.to_le_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_size_is_128_bytes() {
        let data = CoverageData {
            counters: vec![],
            data_records: vec![],
            names: vec![],
        };
        let mut buf = Vec::new();
        data.write_profraw(&mut buf).unwrap();
        // Header only (no data records, no counters, no names)
        assert_eq!(buf.len(), 128);
    }

    #[test]
    fn magic_and_version() {
        let data = CoverageData {
            counters: vec![],
            data_records: vec![],
            names: vec![],
        };
        let mut buf = Vec::new();
        data.write_profraw(&mut buf).unwrap();
        let magic = u64::from_le_bytes(buf[0..8].try_into().unwrap());
        let version = u64::from_le_bytes(buf[8..16].try_into().unwrap());
        assert_eq!(magic, PROFRAW_MAGIC);
        assert_eq!(version, 10);
    }

    #[test]
    fn rejects_malformed_data_records() {
        let data = CoverageData {
            counters: vec![],
            data_records: vec![0u8; 47], // not multiple of 48
            names: vec![],
        };
        let mut buf = Vec::new();
        assert!(data.write_profraw(&mut buf).is_err());
    }

    #[test]
    fn rejects_malformed_counters() {
        let data = CoverageData {
            counters: vec![0u8; 7], // not multiple of 8
            data_records: vec![],
            names: vec![],
        };
        let mut buf = Vec::new();
        assert!(data.write_profraw(&mut buf).is_err());
    }

    #[test]
    fn one_function_round_trip() {
        // One function with one counter
        let mut data_rec = vec![0u8; BPF_DATA_RECORD_SIZE];
        // NameRef = 0x42
        data_rec[0] = 0x42;
        // FuncHash = 0xAB
        data_rec[8] = 0xAB;
        // CounterOff = 0
        // FuncPtr = 0
        // Values = 0
        // NumCounters = 1
        data_rec[40] = 1;

        let counters = vec![0u8; 8]; // one counter, value 0
        let names = b"hello".to_vec();

        let data = CoverageData {
            counters,
            data_records: data_rec,
            names,
        };

        let mut buf = Vec::new();
        data.write_profraw(&mut buf).unwrap();

        // Header = 128, one v10 record = 64, counters = 8, names = 5, padding = 3
        assert_eq!(buf.len(), 128 + 64 + 8 + 5 + 3);

        // Verify header fields
        let num_data = u64::from_le_bytes(buf[24..32].try_into().unwrap());
        assert_eq!(num_data, 1);
        let num_counters = u64::from_le_bytes(buf[40..48].try_into().unwrap());
        assert_eq!(num_counters, 1);
        let names_size = u64::from_le_bytes(buf[72..80].try_into().unwrap());
        assert_eq!(names_size, 5);

        // Verify the v10 record starts at offset 128
        let name_ref = buf[128];
        assert_eq!(name_ref, 0x42);
        let func_hash = buf[128 + 8];
        assert_eq!(func_hash, 0xAB);
    }

    #[test]
    fn names_padding_aligns_to_8() {
        for names_len in 0..16 {
            let data = CoverageData {
                counters: vec![],
                data_records: vec![],
                names: vec![0xAA; names_len],
            };
            let mut buf = Vec::new();
            data.write_profraw(&mut buf).unwrap();
            assert_eq!(
                buf.len() % 8,
                0,
                "output not 8-byte aligned for names_len={names_len}"
            );
        }
    }
}
