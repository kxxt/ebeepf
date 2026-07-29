use std::io;
use std::mem;
use std::num::NonZeroUsize;
use std::ops::{Deref, DerefMut};
use std::os::fd::AsRawFd;
use std::ptr::{self, NonNull};
use std::slice;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::{Error, Map, MapType, Result};

const BUSY: u32 = 1 << 31;
const DISCARD: u32 = 1 << 30;
const HEADER_SIZE: usize = 8;

/// A user-space producer for `BPF_MAP_TYPE_USER_RINGBUF`.
#[derive(Debug)]
pub struct UserRingBuffer {
    // Keeps the map descriptor alive for both mappings and polling.
    map: Map,
    consumer: Mapping,
    producer: Mapping,
    page_size: usize,
    capacity: usize,
}

impl UserRingBuffer {
    /// Maps a user ring buffer for producing samples.
    pub fn new(map: &Map) -> Result<Self> {
        if map.spec().map_type() != MapType::UserRingBuffer {
            return Err(Error::InvalidObject(format!(
                "map `{}` is {:?}, not a user ring buffer",
                map.name(),
                map.spec().map_type()
            )));
        }
        let capacity = usize::try_from(map.spec().max_entries())
            .map_err(|_| Error::InvalidObject("user-ring capacity does not fit usize".into()))?;
        let page_size = page_size()?;
        if !capacity.is_power_of_two() || capacity < page_size || capacity % page_size != 0 {
            return Err(Error::InvalidObject(format!(
                "user ring `{}` capacity {capacity} is not a page-aligned power of two",
                map.name()
            )));
        }
        let producer_len =
            page_size
                .checked_add(capacity.checked_mul(2).ok_or_else(|| {
                    Error::InvalidObject("user-ring mapping size overflow".into())
                })?)
                .ok_or_else(|| Error::InvalidObject("user-ring mapping size overflow".into()))?;
        let consumer = Mapping::shared(map.fd.as_raw_fd(), page_size, libc::PROT_READ, 0)?;
        let producer = Mapping::shared(
            map.fd.as_raw_fd(),
            producer_len,
            libc::PROT_READ | libc::PROT_WRITE,
            page_size as libc::off_t,
        )?;
        Ok(Self {
            map: map.clone(),
            consumer,
            producer,
            page_size,
            capacity,
        })
    }

    /// Reserves a sample, returning `None` when the ring is full.
    ///
    /// Dropping the reservation without calling [`UserRingReservation::submit`]
    /// marks it discarded, so incomplete samples never reach eBPF code.
    pub fn reserve(&mut self, size: usize) -> Result<Option<UserRingReservation<'_>>> {
        if size > (DISCARD - 1) as usize {
            return Err(Error::InvalidObject(format!(
                "user-ring sample size {size} uses reserved flag bits"
            )));
        }
        let total = record_size(size)?;
        if total > self.capacity {
            return Err(Error::SizeMismatch {
                what: "user-ring sample",
                expected: self.capacity.saturating_sub(HEADER_SIZE),
                actual: size,
            });
        }
        let consumer = self.consumer.atomic_u64(0)?.load(Ordering::Acquire);
        let producer_position = self.producer.atomic_u64(0)?;
        let producer = producer_position.load(Ordering::Acquire);
        let used = producer.checked_sub(consumer).ok_or_else(|| {
            Error::InvalidObject(format!(
                "user ring `{}` consumer position exceeds producer",
                self.map.name()
            ))
        })?;
        if used > self.capacity as u64 {
            return Err(Error::InvalidObject(format!(
                "user ring `{}` positions exceed its capacity",
                self.map.name()
            )));
        }
        if self.capacity - (used as usize) < total {
            return Ok(None);
        }

        let header_offset = self.page_size
            + usize::try_from(producer & (self.capacity as u64 - 1))
                .map_err(|_| Error::InvalidObject("user-ring position is too large".into()))?;
        self.producer
            .atomic_u32(header_offset)?
            .store(size as u32 | BUSY, Ordering::Relaxed);
        self.producer
            .atomic_u32(header_offset + 4)?
            .store(0, Ordering::Relaxed);
        producer_position.store(producer + total as u64, Ordering::Release);
        let sample_offset = self.page_size
            + usize::try_from((producer + HEADER_SIZE as u64) & (self.capacity as u64 - 1))
                .map_err(|_| Error::InvalidObject("user-ring sample offset is too large".into()))?;
        Ok(Some(UserRingReservation {
            ring: self,
            header_offset,
            sample_offset,
            size,
            submitted: false,
        }))
    }

    /// Waits for capacity and reserves a sample.
    ///
    /// `None` waits indefinitely. Returns `None` when a finite timeout expires.
    pub fn reserve_blocking(
        &mut self,
        size: usize,
        timeout: Option<Duration>,
    ) -> Result<Option<UserRingReservation<'_>>> {
        let start = Instant::now();
        loop {
            if self.has_capacity(size)? {
                return self.reserve(size);
            }
            let remaining = match timeout {
                None => None,
                Some(timeout) => match timeout.checked_sub(start.elapsed()) {
                    Some(remaining) if !remaining.is_zero() => Some(remaining),
                    _ => return Ok(None),
                },
            };
            let mut descriptor = libc::pollfd {
                fd: self.map.fd.as_raw_fd(),
                events: libc::POLLOUT,
                revents: 0,
            };
            let timeout_ms = timeout_to_milliseconds(remaining);
            // SAFETY: `descriptor` is a live writable pollfd.
            let ready = unsafe { libc::poll(ptr::from_mut(&mut descriptor), 1, timeout_ms) };
            if ready < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(Error::system("wait for user-ring capacity", error));
            }
            if ready == 0 {
                return Ok(None);
            }
        }
    }

    /// Copies and submits one sample.
    ///
    /// Returns `false` without writing when the ring is full.
    pub fn write(&mut self, sample: &[u8]) -> Result<bool> {
        let Some(mut reservation) = self.reserve(sample.len())? else {
            return Ok(false);
        };
        reservation.copy_from_slice(sample);
        reservation.submit();
        Ok(true)
    }

    fn has_capacity(&self, size: usize) -> Result<bool> {
        let total = record_size(size)?;
        if total > self.capacity {
            return Err(Error::SizeMismatch {
                what: "user-ring sample",
                expected: self.capacity.saturating_sub(HEADER_SIZE),
                actual: size,
            });
        }
        let consumer = self.consumer.atomic_u64(0)?.load(Ordering::Acquire);
        let producer = self.producer.atomic_u64(0)?.load(Ordering::Acquire);
        let used = producer
            .checked_sub(consumer)
            .ok_or_else(|| Error::InvalidObject("invalid user-ring positions".into()))?;
        Ok(used <= self.capacity as u64 && self.capacity - (used as usize) >= total)
    }

    fn commit(&mut self, header_offset: usize, discard: bool) {
        // Construction validates this position, so failure here can only
        // indicate internal corruption. Avoid panicking in `Drop`.
        if let Ok(header) = self.producer.atomic_u32(header_offset) {
            let mut length = header.load(Ordering::Relaxed) & !BUSY;
            if discard {
                length |= DISCARD;
            }
            header.store(length, Ordering::Release);
        }
    }
}

/// A uniquely borrowed sample in a [`UserRingBuffer`].
///
/// It dereferences to a mutable byte slice. Call [`Self::submit`] after filling
/// it; otherwise its `Drop` implementation discards the reservation.
#[derive(Debug)]
pub struct UserRingReservation<'ring> {
    ring: &'ring mut UserRingBuffer,
    header_offset: usize,
    sample_offset: usize,
    size: usize,
    submitted: bool,
}

impl UserRingReservation<'_> {
    /// Makes the completed sample visible to eBPF consumers.
    pub fn submit(mut self) {
        self.ring.commit(self.header_offset, false);
        self.submitted = true;
    }

    /// Explicitly discards the sample.
    pub fn discard(mut self) {
        self.ring.commit(self.header_offset, true);
        self.submitted = true;
    }
}

impl Deref for UserRingReservation<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.ring
            .producer
            .bytes(self.sample_offset, self.size)
            .expect("reservation was validated during construction")
    }
}

impl DerefMut for UserRingReservation<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.ring
            .producer
            .bytes_mut(self.sample_offset, self.size)
            .expect("reservation was validated during construction")
    }
}

impl Drop for UserRingReservation<'_> {
    fn drop(&mut self) {
        if !self.submitted {
            self.ring.commit(self.header_offset, true);
        }
    }
}

#[derive(Debug)]
struct Mapping {
    address: NonNull<u8>,
    len: NonZeroUsize,
}

impl Mapping {
    fn shared(
        fd: libc::c_int,
        len: usize,
        protection: libc::c_int,
        offset: libc::off_t,
    ) -> Result<Self> {
        let len = NonZeroUsize::new(len)
            .ok_or_else(|| Error::InvalidObject("cannot create an empty mapping".into()))?;
        // SAFETY: The kernel validates the descriptor and page-aligned offset.
        // On success this value owns the mapping.
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
                "map user-ring memory",
                io::Error::last_os_error(),
            ));
        }
        let address = NonNull::new(address.cast::<u8>()).ok_or_else(|| {
            Error::system(
                "map user-ring memory",
                io::Error::other("mmap returned null"),
            )
        })?;
        Ok(Self { address, len })
    }

    fn atomic_u64(&self, offset: usize) -> Result<&AtomicU64> {
        self.range(offset, mem::size_of::<AtomicU64>())?;
        if offset % mem::align_of::<AtomicU64>() != 0 {
            return Err(Error::InvalidObject(
                "user-ring u64 is not naturally aligned".into(),
            ));
        }
        // SAFETY: Bounds, alignment, and mapping lifetime were checked.
        Ok(unsafe { &*self.address.as_ptr().add(offset).cast::<AtomicU64>() })
    }

    fn atomic_u32(&self, offset: usize) -> Result<&AtomicU32> {
        self.range(offset, mem::size_of::<AtomicU32>())?;
        if offset % mem::align_of::<AtomicU32>() != 0 {
            return Err(Error::InvalidObject(
                "user-ring u32 is not naturally aligned".into(),
            ));
        }
        // SAFETY: Bounds, alignment, and mapping lifetime were checked.
        Ok(unsafe { &*self.address.as_ptr().add(offset).cast::<AtomicU32>() })
    }

    fn bytes(&self, offset: usize, len: usize) -> Result<&[u8]> {
        self.range(offset, len)?;
        // SAFETY: The requested range lies within the live mapping.
        Ok(unsafe { slice::from_raw_parts(self.address.as_ptr().add(offset), len) })
    }

    fn bytes_mut(&mut self, offset: usize, len: usize) -> Result<&mut [u8]> {
        self.range(offset, len)?;
        // SAFETY: `&mut self` guarantees unique userspace access to the
        // reservation, and the requested range lies within the mapping.
        Ok(unsafe { slice::from_raw_parts_mut(self.address.as_ptr().add(offset), len) })
    }

    fn range(&self, offset: usize, len: usize) -> Result<()> {
        let end = offset
            .checked_add(len)
            .ok_or_else(|| Error::InvalidObject("mapping range overflow".into()))?;
        if end <= self.len.get() {
            Ok(())
        } else {
            Err(Error::InvalidObject(
                "user-ring access exceeds its mapping".into(),
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

fn record_size(payload: usize) -> Result<usize> {
    payload
        .checked_add(HEADER_SIZE + 7)
        .map(|size| size & !7)
        .ok_or_else(|| Error::InvalidObject("user-ring record size overflow".into()))
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
    fn user_records_include_header_and_alignment() {
        assert_eq!(record_size(0).unwrap(), 8);
        assert_eq!(record_size(1).unwrap(), 16);
        assert_eq!(record_size(8).unwrap(), 16);
        assert_eq!(record_size(9).unwrap(), 24);
    }

    #[test]
    fn finite_poll_timeouts_round_up() {
        assert_eq!(timeout_to_milliseconds(None), -1);
        assert_eq!(timeout_to_milliseconds(Some(Duration::ZERO)), 0);
        assert_eq!(timeout_to_milliseconds(Some(Duration::from_nanos(1))), 1);
    }
}
