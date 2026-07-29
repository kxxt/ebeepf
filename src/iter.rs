//! Readers for kernel BPF iterator links.

use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};

use crate::sys;
use crate::{Error, Link, Result};

/// A readable kernel BPF iterator.
///
/// Create an iterator link with [`crate::Program::attach_iterator`], then
/// create this reader from that link. The reader owns its iterator descriptor;
/// the original link may remain available for pinning or metadata queries.
#[derive(Debug)]
pub struct BpfIterator {
    file: File,
}

impl BpfIterator {
    /// Creates a reader from a kernel iterator link.
    pub fn new(link: &Link) -> Result<Self> {
        let link = link.as_fd().ok_or_else(|| {
            Error::Unsupported("only kernel bpf_link objects can create BPF iterators".into())
        })?;
        let fd = sys::iterator_create(link.as_raw_fd())
            .map_err(|source| Error::system("create BPF iterator reader", source))?;
        Ok(Self {
            file: File::from(fd),
        })
    }

    /// Consumes the wrapper and returns the readable file.
    pub fn into_file(self) -> File {
        self.file
    }
}

impl AsFd for BpfIterator {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.file.as_fd()
    }
}

impl Read for BpfIterator {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.file.read(buffer)
    }
}
