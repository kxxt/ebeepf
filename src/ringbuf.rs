use std::io;
use std::mem;
use std::num::NonZeroUsize;
use std::os::fd::AsRawFd;
use std::ptr::{self, NonNull};
use std::slice;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::Duration;

use crate::{Error, Map, MapType, Result};

const BUSY: u32 = 1 << 31;
const DISCARD: u32 = 1 << 30;
const LENGTH_MASK: u32 = !(BUSY | DISCARD);
const HEADER_SIZE: usize = 8;

/// Builds a consumer for one or more kernel ring-buffer maps.
#[derive(Clone, Debug, Default)]
pub struct RingBufferBuilder {
    maps: Vec<Map>,
}

impl RingBufferBuilder {
    /// Creates an empty builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a ring-buffer map.
    pub fn add(&mut self, map: &Map) -> Result<&mut Self> {
        if map.spec().map_type() != MapType::RingBuffer {
            return Err(Error::InvalidObject(format!(
                "map `{}` is {:?}, not a ring buffer",
                map.name(),
                map.spec().map_type()
            )));
        }
        self.maps.push(map.clone());
        Ok(self)
    }

    /// Maps all configured rings into this process.
    pub fn build(self) -> Result<RingBuffer> {
        if self.maps.is_empty() {
            return Err(Error::InvalidObject(
                "a ring buffer needs at least one map".into(),
            ));
        }
        let rings = self
            .maps
            .into_iter()
            .map(MappedRing::new)
            .collect::<Result<Vec<_>>>()?;
        Ok(RingBuffer { rings })
    }
}

/// A consumer for one or more `BPF_MAP_TYPE_RINGBUF` maps.
///
/// Samples borrow mapped kernel memory only for the duration of the callback.
/// This makes the API zero-copy while preventing samples from outliving their
/// ring or consumer position.
#[derive(Debug)]
pub struct RingBuffer {
    rings: Vec<MappedRing>,
}

impl RingBuffer {
    /// Creates a consumer for one map.
    pub fn new(map: &Map) -> Result<Self> {
        let mut builder = RingBufferBuilder::new();
        builder.add(map)?;
        builder.build()
    }

    /// Consumes all samples currently available without waiting.
    ///
    /// Discarded samples are advanced past but are not passed to the callback.
    /// Returns the number of delivered samples.
    pub fn consume(&mut self, callback: impl FnMut(&[u8])) -> Result<usize> {
        self.consume_up_to(usize::MAX, callback)
    }

    /// Consumes at most `maximum` delivered samples without waiting.
    ///
    /// Discarded records are advanced past but do not count toward the limit.
    pub fn consume_up_to(
        &mut self,
        maximum: usize,
        mut callback: impl FnMut(&[u8]),
    ) -> Result<usize> {
        let mut count = 0;
        for ring in &mut self.rings {
            let remaining = maximum.saturating_sub(count);
            if remaining == 0 {
                break;
            }
            count += ring.consume(&mut callback, remaining)?;
        }
        Ok(count)
    }

    /// Number of mapped ring-buffer maps.
    pub fn len(&self) -> usize {
        self.rings.len()
    }

    /// Whether no ring-buffer maps are configured.
    pub fn is_empty(&self) -> bool {
        self.rings.is_empty()
    }

    /// Iterates over the maps backing this consumer.
    pub fn maps(&self) -> impl ExactSizeIterator<Item = &Map> {
        self.rings.iter().map(|ring| &ring.map)
    }

    /// Waits for data and consumes all currently available samples.
    ///
    /// `None` waits indefinitely. A zero duration performs a nonblocking poll.
    pub fn poll(
        &mut self,
        timeout: Option<Duration>,
        callback: impl FnMut(&[u8]),
    ) -> Result<usize> {
        let mut poll_fds = self
            .rings
            .iter()
            .map(|ring| libc::pollfd {
                fd: ring.map.fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            })
            .collect::<Vec<_>>();
        let timeout = timeout_to_milliseconds(timeout);
        loop {
            // SAFETY: `poll_fds` is a live, writable array for the duration of
            // the call and its length is passed exactly.
            let ready = unsafe {
                libc::poll(
                    poll_fds.as_mut_ptr(),
                    poll_fds.len() as libc::nfds_t,
                    timeout,
                )
            };
            if ready >= 0 {
                break;
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(Error::system("poll ring buffer", error));
            }
        }
        self.consume(callback)
    }
}

#[derive(Debug)]
struct MappedRing {
    // Keeps the map descriptor alive for both mappings.
    map: Map,
    consumer: Mapping,
    producer: Mapping,
    page_size: usize,
    capacity: usize,
}

impl MappedRing {
    fn new(map: Map) -> Result<Self> {
        let capacity = usize::try_from(map.spec().max_entries())
            .map_err(|_| Error::InvalidObject("ring capacity does not fit usize".into()))?;
        if !capacity.is_power_of_two() {
            return Err(Error::InvalidObject(format!(
                "ring buffer `{}` capacity {capacity} is not a power of two",
                map.name()
            )));
        }
        let page_size = page_size()?;
        if capacity < page_size || capacity % page_size != 0 {
            return Err(Error::InvalidObject(format!(
                "ring buffer `{}` capacity {capacity} is not page-aligned",
                map.name()
            )));
        }
        let producer_len =
            page_size
                .checked_add(capacity.checked_mul(2).ok_or_else(|| {
                    Error::InvalidObject("ring-buffer mapping size overflow".into())
                })?)
                .ok_or_else(|| Error::InvalidObject("ring-buffer mapping size overflow".into()))?;
        let consumer = Mapping::shared(
            map.fd.as_raw_fd(),
            page_size,
            libc::PROT_READ | libc::PROT_WRITE,
            0,
        )?;
        let producer = Mapping::shared(
            map.fd.as_raw_fd(),
            producer_len,
            libc::PROT_READ,
            page_size as libc::off_t,
        )?;
        Ok(Self {
            map,
            consumer,
            producer,
            page_size,
            capacity,
        })
    }

    fn consume(&mut self, callback: &mut impl FnMut(&[u8]), maximum: usize) -> Result<usize> {
        let consumer_position = self.consumer.atomic_u64(0)?;
        let producer_position = self.producer.atomic_u64(0)?;
        let mut consumer = consumer_position.load(Ordering::Relaxed);
        let producer = producer_position.load(Ordering::Acquire);
        let mut count = 0;

        while consumer < producer && count < maximum {
            let offset = usize::try_from(consumer & (self.capacity as u64 - 1))
                .map_err(|_| Error::InvalidObject("ring position does not fit usize".into()))?;
            let header_offset = self
                .page_size
                .checked_add(offset)
                .ok_or_else(|| Error::InvalidObject("ring position overflow".into()))?;
            let flags = self
                .producer
                .atomic_u32(header_offset)?
                .load(Ordering::Acquire);
            if flags & BUSY != 0 {
                break;
            }
            let length = (flags & LENGTH_MASK) as usize;
            if length > self.capacity - HEADER_SIZE {
                return Err(Error::InvalidObject(format!(
                    "ring buffer `{}` contains invalid sample length {length}",
                    self.map.name()
                )));
            }
            if flags & DISCARD == 0 {
                let sample_offset = header_offset + HEADER_SIZE;
                callback(self.producer.bytes(sample_offset, length)?);
                count += 1;
            }
            consumer = consumer
                .checked_add(record_size(length) as u64)
                .ok_or_else(|| Error::InvalidObject("ring position overflow".into()))?;
            consumer_position.store(consumer, Ordering::Release);
        }
        Ok(count)
    }
}

#[derive(Debug)]
struct Mapping {
    address: NonNull<u8>,
    len: NonZeroUsize,
}

// SAFETY: this value uniquely owns a process-wide mapping with no thread
// affinity. Ring-buffer consumption requires `&mut RingBuffer`, so moving the
// mapping cannot introduce concurrent userspace consumers.
unsafe impl Send for Mapping {}

impl Mapping {
    fn shared(
        fd: libc::c_int,
        len: usize,
        protection: libc::c_int,
        offset: libc::off_t,
    ) -> Result<Self> {
        let len = NonZeroUsize::new(len)
            .ok_or_else(|| Error::InvalidObject("cannot create an empty mapping".into()))?;
        // SAFETY: The kernel validates the descriptor, length, protection, and
        // page-aligned offset. On success the mapping is owned by this value.
        let address = unsafe {
            libc::mmap(
                ptr::null_mut(),
                len.get(),
                protection,
                libc::MAP_SHARED,
                fd,
                offset,
            )
        };
        if address == libc::MAP_FAILED {
            return Err(Error::system(
                "map ring-buffer memory",
                io::Error::last_os_error(),
            ));
        }
        let address = NonNull::new(address.cast::<u8>()).ok_or_else(|| {
            Error::system(
                "map ring-buffer memory",
                io::Error::other("mmap returned null"),
            )
        })?;
        Ok(Self { address, len })
    }

    fn atomic_u64(&self, offset: usize) -> Result<&AtomicU64> {
        self.range(offset, mem::size_of::<AtomicU64>())?;
        if offset % mem::align_of::<AtomicU64>() != 0 {
            return Err(Error::InvalidObject(
                "ring-buffer u64 is not naturally aligned".into(),
            ));
        }
        // SAFETY: Bounds and alignment were checked, and the mapping stays
        // alive for the returned reference. The kernel ABI specifies atomic
        // shared access to these positions.
        Ok(unsafe { &*self.address.as_ptr().add(offset).cast::<AtomicU64>() })
    }

    fn atomic_u32(&self, offset: usize) -> Result<&AtomicU32> {
        self.range(offset, mem::size_of::<AtomicU32>())?;
        if offset % mem::align_of::<AtomicU32>() != 0 {
            return Err(Error::InvalidObject(
                "ring-buffer u32 is not naturally aligned".into(),
            ));
        }
        // SAFETY: Bounds, alignment, and lifetime are checked above.
        Ok(unsafe { &*self.address.as_ptr().add(offset).cast::<AtomicU32>() })
    }

    fn bytes(&self, offset: usize, len: usize) -> Result<&[u8]> {
        self.range(offset, len)?;
        // SAFETY: The requested byte range is within the live mapping.
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
                "ring-buffer access exceeds its mapping".into(),
            ))
        }
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: This value uniquely owns the live mapping and uses its exact
        // original address and length.
        unsafe {
            libc::munmap(self.address.as_ptr().cast(), self.len.get());
        }
    }
}

fn record_size(payload: usize) -> usize {
    (payload + HEADER_SIZE + 7) & !7
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

    #[test]
    fn record_sizes_include_header_and_alignment() {
        fn assert_send<T: Send>() {}

        assert_eq!(record_size(0), 8);
        assert_eq!(record_size(1), 16);
        assert_eq!(record_size(8), 16);
        assert_eq!(record_size(9), 24);
        assert_send::<RingBuffer>();
    }

    #[test]
    fn poll_timeout_rounds_up_and_saturates() {
        assert_eq!(timeout_to_milliseconds(None), -1);
        assert_eq!(timeout_to_milliseconds(Some(Duration::ZERO)), 0);
        assert_eq!(timeout_to_milliseconds(Some(Duration::from_nanos(1))), 1);
        assert_eq!(
            timeout_to_milliseconds(Some(Duration::from_secs(u64::MAX))),
            i32::MAX
        );
    }
}
