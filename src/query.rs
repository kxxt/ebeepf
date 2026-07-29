//! Read-only enumeration of eBPF resources visible to the calling process.

use crate::sys::{self, ObjectKind};
use std::os::fd::{AsFd, AsRawFd};

use crate::{AttachType, Error, Result};

/// Iterator over kernel object IDs.
#[derive(Clone, Debug)]
pub struct Ids {
    kind: ObjectKind,
    current: u32,
    finished: bool,
}

impl Ids {
    fn new(kind: ObjectKind) -> Self {
        Self {
            kind,
            current: 0,
            finished: false,
        }
    }
}

impl Iterator for Ids {
    type Item = Result<u32>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        match sys::next_id(self.kind, self.current) {
            Ok(Some(id)) => {
                self.current = id;
                Some(Ok(id))
            }
            Ok(None) => {
                self.finished = true;
                None
            }
            Err(source) => {
                self.finished = true;
                Some(Err(Error::system("enumerate kernel eBPF objects", source)))
            }
        }
    }
}

/// Enumerates map IDs.
pub fn map_ids() -> Ids {
    Ids::new(ObjectKind::Map)
}

/// Enumerates program IDs.
pub fn program_ids() -> Ids {
    Ids::new(ObjectKind::Program)
}

/// Enumerates link IDs.
pub fn link_ids() -> Ids {
    Ids::new(ObjectKind::Link)
}

/// Enumerates BTF object IDs.
pub fn btf_ids() -> Ids {
    Ids::new(ObjectKind::Btf)
}

/// One program attachment returned by [`attached_programs`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProgramAttachment {
    /// Attached program ID.
    pub program_id: u32,
    /// Per-program attachment flags.
    pub program_flags: u32,
    /// Kernel link ID, or zero for a legacy attachment.
    pub link_id: u32,
    /// Per-link attachment flags.
    pub link_flags: u32,
}

/// Programs attached to one hook.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProgramAttachments {
    /// Hook-wide attachment flags.
    pub flags: u32,
    /// Monotonic hook revision on kernels that support revisions.
    pub revision: u64,
    /// Attached programs in kernel execution order.
    pub programs: Vec<ProgramAttachment>,
}

/// Queries programs attached to a file-descriptor-backed hook.
pub fn attached_programs(target: impl AsFd, attach_type: AttachType) -> Result<ProgramAttachments> {
    let fd = u32::try_from(target.as_fd().as_raw_fd())
        .map_err(|_| Error::InvalidObject("attachment target descriptor is negative".into()))?;
    attached_programs_raw(fd, attach_type)
}

/// Queries programs attached to a network-interface-backed hook.
pub fn attached_programs_on_interface(
    interface_index: u32,
    attach_type: AttachType,
) -> Result<ProgramAttachments> {
    attached_programs_raw(interface_index, attach_type)
}

fn attached_programs_raw(target: u32, attach_type: AttachType) -> Result<ProgramAttachments> {
    let result = sys::program_query(target, attach_type.as_raw(), 0)
        .map_err(|source| Error::system("query attached eBPF programs", source))?;
    let programs = result
        .program_ids
        .into_iter()
        .enumerate()
        .map(|(index, program_id)| ProgramAttachment {
            program_id,
            program_flags: result
                .program_attach_flags
                .get(index)
                .copied()
                .unwrap_or_default(),
            link_id: result.link_ids.get(index).copied().unwrap_or_default(),
            link_flags: result
                .link_attach_flags
                .get(index)
                .copied()
                .unwrap_or_default(),
        })
        .collect();
    Ok(ProgramAttachments {
        flags: result.attach_flags,
        revision: result.revision,
        programs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_iterator_starts_before_first_kernel_id() {
        let ids = Ids::new(ObjectKind::Map);
        assert_eq!(ids.current, 0);
        assert!(!ids.finished);
    }
}
