use std::fmt;
use std::fs::File;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::path::Path;
use std::sync::Arc;

use crate::{sys, Error, Result};

/// Capabilities delegated by a kernel BPF token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BpfTokenInfo {
    /// Bit set of allowed `bpf()` commands.
    pub allowed_commands: u64,
    /// Bit set of allowed [`crate::MapType`] values.
    pub allowed_map_types: u64,
    /// Bit set of allowed [`crate::ProgramType`] values.
    pub allowed_program_types: u64,
    /// Bit set of allowed [`crate::AttachType`] values.
    pub allowed_attach_types: u64,
}

/// An owned, clonable kernel BPF delegation token.
///
/// Tokens let an appropriately configured bpffs mount delegate selected BPF
/// operations to a less privileged process. Pass a token to an [`crate::Object`]
/// before loading, or to standalone map and BTF creation APIs.
#[derive(Clone)]
pub struct BpfToken {
    fd: Arc<OwnedFd>,
}

impl fmt::Debug for BpfToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BpfToken")
            .field("fd", &self.fd.as_raw_fd())
            .finish()
    }
}

impl BpfToken {
    /// Creates a token from an open bpffs mount using no creation flags.
    pub fn create(bpffs: impl AsFd) -> Result<Self> {
        Self::create_with_flags(bpffs, 0)
    }

    /// Creates a token from an open bpffs mount with forward-compatible flags.
    pub fn create_with_flags(bpffs: impl AsFd, flags: u32) -> Result<Self> {
        let fd = sys::token_create(bpffs.as_fd().as_raw_fd(), flags)
            .map_err(|source| Error::system("create BPF token", source))?;
        Ok(Self { fd: Arc::new(fd) })
    }

    /// Opens a bpffs mount and creates a token from it.
    pub fn create_from_bpffs(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let bpffs = File::open(path).map_err(|source| Error::File {
            operation: "open bpffs mount for BPF token",
            path: path.into(),
            source,
        })?;
        Self::create(bpffs)
    }

    /// Reads the capabilities delegated by this token.
    pub fn info(&self) -> Result<BpfTokenInfo> {
        let info = sys::token_info(self.fd.as_raw_fd())
            .map_err(|source| Error::system("read BPF token metadata", source))?;
        Ok(BpfTokenInfo {
            allowed_commands: info.allowed_commands,
            allowed_map_types: info.allowed_map_types,
            allowed_program_types: info.allowed_program_types,
            allowed_attach_types: info.allowed_attach_types,
        })
    }

    /// Borrows the token descriptor.
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl BpfTokenInfo {
    /// Whether this token delegates creation of `map_type`.
    pub const fn allows_map_type(self, map_type: crate::MapType) -> bool {
        bit_is_set(self.allowed_map_types, map_type.as_raw())
    }

    /// Whether this token delegates loading of `program_type`.
    pub const fn allows_program_type(self, program_type: crate::ProgramType) -> bool {
        bit_is_set(self.allowed_program_types, program_type.as_raw())
    }

    /// Whether this token delegates `attach_type`.
    pub const fn allows_attach_type(self, attach_type: crate::AttachType) -> bool {
        bit_is_set(self.allowed_attach_types, attach_type.as_raw())
    }
}

const fn bit_is_set(mask: u64, bit: u32) -> bool {
    bit < u64::BITS && mask & (1_u64 << bit) != 0
}

impl AsFd for BpfToken {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_capability_checks_are_bounded() {
        let info = BpfTokenInfo {
            allowed_commands: 0,
            allowed_map_types: 1 << crate::MapType::Array.as_raw(),
            allowed_program_types: 1 << crate::ProgramType::SocketFilter.as_raw(),
            allowed_attach_types: 1 << crate::AttachType::PerfEvent.as_raw(),
        };
        assert!(info.allows_map_type(crate::MapType::Array));
        assert!(!info.allows_map_type(crate::MapType::Other(64)));
        assert!(info.allows_program_type(crate::ProgramType::SocketFilter));
        assert!(info.allows_attach_type(crate::AttachType::PerfEvent));
    }
}
