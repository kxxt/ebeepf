use std::io;
use std::mem;
use std::num::NonZeroUsize;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::ptr::{self, NonNull};
use std::slice;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::program::online_cpus;
use crate::sys;
use crate::{Error, Map, MapType, Result, UpdateMode};

const PERF_RECORD_LOST: u32 = 2;
const PERF_RECORD_SAMPLE: u32 = 9;
const DATA_HEAD_OFFSET: usize = 1024;
const DATA_TAIL_OFFSET: usize = 1032;
const PERF_HEADER_SIZE: usize = 8;

/// One event read from a perf-event array.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PerfEvent<'sample> {
    /// Bytes emitted by `bpf_perf_event_output`.
    Sample {
        /// CPU on which the sample was emitted.
        cpu: u32,
        /// Raw payload.
        data: &'sample [u8],
    },
    /// Samples overwritten before user space consumed them.
    Lost {
        /// CPU whose ring overflowed.
        cpu: u32,
        /// Number of lost samples.
        count: u64,
    },
}

/// Configures perf-event rings for a `BPF_MAP_TYPE_PERF_EVENT_ARRAY` map.
#[derive(Clone, Debug)]
pub struct PerfBufferBuilder {
    map: Map,
    page_count: usize,
}

impl PerfBufferBuilder {
    /// Creates a builder with 64 data pages per CPU.
    pub fn new(map: &Map) -> Result<Self> {
        if map.spec().map_type() != MapType::PerfEventArray {
            return Err(Error::InvalidObject(format!(
                "map `{}` is {:?}, not a perf-event array",
                map.name(),
                map.spec().map_type()
            )));
        }
        Ok(Self {
            map: map.clone(),
            page_count: 64,
        })
    }

    /// Sets the number of mmap data pages per CPU.
    ///
    /// The kernel requires a power of two.
    pub fn page_count(&mut self, count: usize) -> Result<&mut Self> {
        if !count.is_power_of_two() {
            return Err(Error::InvalidObject(format!(
                "perf-buffer page count {count} is not a power of two"
            )));
        }
        self.page_count = count;
        Ok(self)
    }

    /// Opens, maps, registers, and enables one perf event per online CPU.
    pub fn build(self) -> Result<PerfBuffer> {
        let page_size = page_size()?;
        let mut buffers = Vec::new();
        for cpu in online_cpus()? {
            let cpu_key = u32::try_from(cpu)
                .map_err(|_| Error::InvalidObject("CPU number is negative".into()))?;
            if cpu_key >= self.map.spec().max_entries() {
                return Err(Error::InvalidObject(format!(
                    "perf-event map `{}` has {} entries but CPU {cpu_key} is online",
                    self.map.name(),
                    self.map.spec().max_entries()
                )));
            }
            let buffer = CpuBuffer::new(cpu_key, self.page_count, page_size)?;
            let fd_value = buffer.fd.as_raw_fd().to_ne_bytes();
            self.map
                .update(&cpu_key.to_ne_bytes(), &fd_value, UpdateMode::Any)?;
            sys::perf_event_enable(buffer.fd.as_raw_fd())
                .map_err(|source| Error::system("enable BPF perf event", source))?;
            buffers.push(buffer);
        }
        Ok(PerfBuffer {
            _map: self.map,
            buffers,
        })
    }
}

/// A per-CPU perf-event buffer consumer.
#[derive(Debug)]
pub struct PerfBuffer {
    // Keeps perf_event_array references and the map descriptor alive.
    _map: Map,
    buffers: Vec<CpuBuffer>,
}

impl PerfBuffer {
    /// Creates a perf buffer using default settings.
    pub fn new(map: &Map) -> Result<Self> {
        PerfBufferBuilder::new(map)?.build()
    }

    /// Consumes all records currently available without waiting.
    pub fn consume(&mut self, mut callback: impl FnMut(PerfEvent<'_>)) -> Result<usize> {
        let mut count = 0;
        for buffer in &mut self.buffers {
            count += buffer.consume(&mut callback)?;
        }
        Ok(count)
    }

    /// Consumes records currently available for one CPU.
    pub fn consume_cpu(
        &mut self,
        cpu: u32,
        mut callback: impl FnMut(PerfEvent<'_>),
    ) -> Result<usize> {
        let buffer = self
            .buffers
            .iter_mut()
            .find(|buffer| buffer.cpu == cpu)
            .ok_or_else(|| {
                Error::InvalidObject(format!("perf buffer has no event for CPU {cpu}"))
            })?;
        buffer.consume(&mut callback)
    }

    /// Number of per-CPU perf-event rings.
    pub fn len(&self) -> usize {
        self.buffers.len()
    }

    /// Whether no per-CPU rings are configured.
    pub fn is_empty(&self) -> bool {
        self.buffers.is_empty()
    }

    /// Iterates over CPUs with an active perf-event ring.
    pub fn cpus(&self) -> impl ExactSizeIterator<Item = u32> + '_ {
        self.buffers.iter().map(|buffer| buffer.cpu)
    }

    /// Borrows the perf-event descriptor for one CPU.
    pub fn event_fd(&self, cpu: u32) -> Option<BorrowedFd<'_>> {
        self.buffers
            .iter()
            .find(|buffer| buffer.cpu == cpu)
            .map(|buffer| buffer.fd.as_fd())
    }

    /// Waits for records and consumes all currently available data.
    pub fn poll(
        &mut self,
        timeout: Option<Duration>,
        callback: impl FnMut(PerfEvent<'_>),
    ) -> Result<usize> {
        let mut descriptors = self
            .buffers
            .iter()
            .map(|buffer| libc::pollfd {
                fd: buffer.fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            })
            .collect::<Vec<_>>();
        let timeout = timeout_to_milliseconds(timeout);
        loop {
            // SAFETY: `descriptors` is a live writable array and its exact
            // length is provided to `poll`.
            let ready = unsafe {
                libc::poll(
                    descriptors.as_mut_ptr(),
                    descriptors.len() as libc::nfds_t,
                    timeout,
                )
            };
            if ready >= 0 {
                break;
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(Error::system("poll perf buffer", error));
            }
        }
        self.consume(callback)
    }
}

#[derive(Debug)]
struct CpuBuffer {
    cpu: u32,
    fd: OwnedFd,
    mapping: Mapping,
    page_size: usize,
    data_size: usize,
    scratch: Vec<u8>,
}

impl CpuBuffer {
    fn new(cpu: u32, page_count: usize, page_size: usize) -> Result<Self> {
        let fd = sys::perf_output_event(cpu as i32)
            .map_err(|source| Error::system("open BPF perf event", source))?;
        let data_size = page_count
            .checked_mul(page_size)
            .ok_or_else(|| Error::InvalidObject("perf-buffer data size overflow".into()))?;
        let mapping_size = data_size
            .checked_add(page_size)
            .ok_or_else(|| Error::InvalidObject("perf-buffer mapping size overflow".into()))?;
        let mapping = Mapping::shared(fd.as_raw_fd(), mapping_size)?;
        Ok(Self {
            cpu,
            fd,
            mapping,
            page_size,
            data_size,
            scratch: Vec::new(),
        })
    }

    fn consume(&mut self, callback: &mut impl FnMut(PerfEvent<'_>)) -> Result<usize> {
        let head = self
            .mapping
            .atomic_u64(DATA_HEAD_OFFSET)?
            .load(Ordering::Acquire);
        let mut tail = self
            .mapping
            .atomic_u64(DATA_TAIL_OFFSET)?
            .load(Ordering::Relaxed);
        let mut count = 0;
        let cpu = self.cpu;
        while tail < head {
            let mut header = [0; PERF_HEADER_SIZE];
            copy_ring_into(
                &self.mapping,
                self.page_size,
                self.data_size,
                tail,
                &mut header,
            )?;
            let size = u16::from_ne_bytes(header[6..8].try_into().expect("u16 header")) as usize;
            if size < PERF_HEADER_SIZE || size > self.data_size {
                return Err(Error::InvalidObject(format!(
                    "CPU {} perf ring contains invalid record size {size}",
                    self.cpu
                )));
            }
            self.scratch.resize(size, 0);
            copy_ring_into(
                &self.mapping,
                self.page_size,
                self.data_size,
                tail,
                &mut self.scratch,
            )?;
            count += decode_record(cpu, &self.scratch, callback)?;
            tail = tail
                .checked_add(size as u64)
                .ok_or_else(|| Error::InvalidObject("perf-buffer tail overflow".into()))?;
            self.mapping
                .atomic_u64(DATA_TAIL_OFFSET)?
                .store(tail, Ordering::Release);
        }
        Ok(count)
    }
}

fn copy_ring_into(
    mapping: &Mapping,
    page_size: usize,
    data_size: usize,
    position: u64,
    output: &mut [u8],
) -> Result<()> {
    let offset = usize::try_from(position & (data_size as u64 - 1))
        .map_err(|_| Error::InvalidObject("perf-buffer position is too large".into()))?;
    let start = page_size + offset;
    if offset + output.len() <= data_size {
        output.copy_from_slice(mapping.bytes(start, output.len())?);
        return Ok(());
    }
    let first = data_size - offset;
    let remaining = output.len() - first;
    output[..first].copy_from_slice(mapping.bytes(start, first)?);
    output[first..].copy_from_slice(mapping.bytes(page_size, remaining)?);
    Ok(())
}

fn decode_record(
    cpu: u32,
    record: &[u8],
    callback: &mut impl FnMut(PerfEvent<'_>),
) -> Result<usize> {
    let record_type = u32::from_ne_bytes(
        record
            .get(0..4)
            .ok_or_else(|| Error::InvalidObject("perf record is truncated".into()))?
            .try_into()
            .expect("four-byte slice"),
    );
    match record_type {
        PERF_RECORD_SAMPLE => {
            let raw_size = u32::from_ne_bytes(
                record
                    .get(8..12)
                    .ok_or_else(|| Error::InvalidObject("perf sample is truncated".into()))?
                    .try_into()
                    .expect("four-byte slice"),
            ) as usize;
            let data = record
                .get(12..12_usize.saturating_add(raw_size))
                .ok_or_else(|| Error::InvalidObject("perf sample payload is truncated".into()))?;
            callback(PerfEvent::Sample { cpu, data });
            Ok(1)
        }
        PERF_RECORD_LOST => {
            let count = u64::from_ne_bytes(
                record
                    .get(16..24)
                    .ok_or_else(|| Error::InvalidObject("lost-event record is truncated".into()))?
                    .try_into()
                    .expect("eight-byte slice"),
            );
            callback(PerfEvent::Lost { cpu, count });
            Ok(1)
        }
        _ => Ok(0),
    }
}

#[derive(Debug)]
struct Mapping {
    address: NonNull<u8>,
    len: NonZeroUsize,
}

impl Mapping {
    fn shared(fd: libc::c_int, len: usize) -> Result<Self> {
        let len = NonZeroUsize::new(len)
            .ok_or_else(|| Error::InvalidObject("cannot create an empty mapping".into()))?;
        // SAFETY: The kernel validates the descriptor and length. On success
        // this value uniquely owns the returned mapping.
        let address = unsafe {
            libc::mmap(
                ptr::null_mut(),
                len.get(),
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        if address == libc::MAP_FAILED {
            return Err(Error::system(
                "map perf-event ring",
                io::Error::last_os_error(),
            ));
        }
        let address = NonNull::new(address.cast::<u8>()).ok_or_else(|| {
            Error::system(
                "map perf-event ring",
                io::Error::other("mmap returned null"),
            )
        })?;
        Ok(Self { address, len })
    }

    fn atomic_u64(&self, offset: usize) -> Result<&AtomicU64> {
        self.range(offset, mem::size_of::<AtomicU64>())?;
        if offset % mem::align_of::<AtomicU64>() != 0 {
            return Err(Error::InvalidObject(
                "perf metadata field is not naturally aligned".into(),
            ));
        }
        // SAFETY: Bounds, alignment, and mapping lifetime were checked.
        Ok(unsafe { &*self.address.as_ptr().add(offset).cast::<AtomicU64>() })
    }

    fn bytes(&self, offset: usize, len: usize) -> Result<&[u8]> {
        self.range(offset, len)?;
        // SAFETY: The requested range lies within the live mapping.
        Ok(unsafe { slice::from_raw_parts(self.address.as_ptr().add(offset), len) })
    }

    fn range(&self, offset: usize, len: usize) -> Result<()> {
        let end = offset
            .checked_add(len)
            .ok_or_else(|| Error::InvalidObject("mapping range overflow".into()))?;
        if end <= self.len.get() {
            Ok(())
        } else {
            Err(Error::InvalidObject(
                "perf-buffer access exceeds its mapping".into(),
            ))
        }
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: This value owns this exact live mapping.
        unsafe {
            libc::munmap(self.address.as_ptr().cast(), self.len.get());
        }
    }
}

fn timeout_to_milliseconds(timeout: Option<Duration>) -> libc::c_int {
    match timeout {
        None => -1,
        Some(timeout) if timeout.is_zero() => 0,
        Some(timeout) => timeout.as_millis().max(1).min(libc::c_int::MAX as u128) as libc::c_int,
    }
}

fn page_size() -> Result<usize> {
    // SAFETY: `_SC_PAGESIZE` has no memory-safety preconditions.
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    usize::try_from(size)
        .ok()
        .filter(|size| *size != 0 && size.is_power_of_two())
        .ok_or_else(|| Error::system("read system page size", io::Error::last_os_error()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(record_type: u32, payload: &[u8]) -> Vec<u8> {
        let size = (PERF_HEADER_SIZE + payload.len()) as u16;
        let mut record = Vec::new();
        record.extend(record_type.to_ne_bytes());
        record.extend(0_u16.to_ne_bytes());
        record.extend(size.to_ne_bytes());
        record.extend(payload);
        record
    }

    #[test]
    fn decodes_sample_records() {
        let mut payload = Vec::new();
        payload.extend(3_u32.to_ne_bytes());
        payload.extend([1, 2, 3]);
        let record = record(PERF_RECORD_SAMPLE, &payload);
        let mut events = Vec::new();
        assert_eq!(
            decode_record(7, &record, &mut |event| events.push(format!("{event:?}"))).unwrap(),
            1
        );
        assert_eq!(events, ["Sample { cpu: 7, data: [1, 2, 3] }"]);
    }

    #[test]
    fn decodes_lost_records() {
        let mut payload = Vec::new();
        payload.extend(123_u64.to_ne_bytes());
        payload.extend(42_u64.to_ne_bytes());
        let record = record(PERF_RECORD_LOST, &payload);
        let mut lost = 0;
        decode_record(2, &record, &mut |event| {
            if let PerfEvent::Lost { count, .. } = event {
                lost = count;
            }
        })
        .unwrap();
        assert_eq!(lost, 42);
    }

    #[test]
    fn rejects_truncated_samples() {
        let mut payload = Vec::new();
        payload.extend(100_u32.to_ne_bytes());
        payload.push(1);
        assert!(decode_record(0, &record(PERF_RECORD_SAMPLE, &payload), &mut |_| {}).is_err());
    }
}
