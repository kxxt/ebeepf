//! Read-only enumeration of eBPF resources visible to the calling process.

use std::ffi::OsString;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::ffi::OsStringExt;

use crate::sys::{self, ObjectKind};
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

/// Kind of legacy perf-event attachment described by [`task_fd`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum TaskFdType {
    /// Raw tracepoint.
    RawTracepoint,
    /// Tracepoint.
    Tracepoint,
    /// Kernel entry probe.
    Kprobe,
    /// Kernel return probe.
    Kretprobe,
    /// Userspace entry probe.
    Uprobe,
    /// Userspace return probe.
    Uretprobe,
    /// Value introduced after this crate version.
    Other(u32),
}

impl TaskFdType {
    const fn from_raw(value: u32) -> Self {
        match value {
            0 => Self::RawTracepoint,
            1 => Self::Tracepoint,
            2 => Self::Kprobe,
            3 => Self::Kretprobe,
            4 => Self::Uprobe,
            5 => Self::Uretprobe,
            value => Self::Other(value),
        }
    }
}

/// Metadata for a legacy perf-event attachment owned by a task descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskFdInfo {
    /// Attached program ID.
    pub program_id: u32,
    /// Kind of attachment.
    pub attachment_type: TaskFdType,
    /// Tracepoint name, kernel symbol, or userspace executable path.
    pub target: OsString,
    /// Offset from the symbol or file.
    pub probe_offset: u64,
    /// Resolved kernel probe address.
    pub probe_address: u64,
}

/// Options for querying a task-owned legacy attachment descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskFdQueryOptions {
    flags: u32,
    buffer_size: usize,
}

impl Default for TaskFdQueryOptions {
    fn default() -> Self {
        Self {
            flags: 0,
            buffer_size: 4096,
        }
    }
}

impl TaskFdQueryOptions {
    /// Sets kernel query flags.
    pub const fn flags(mut self, flags: u32) -> Self {
        self.flags = flags;
        self
    }

    /// Sets the target name/path buffer capacity.
    pub const fn buffer_size(mut self, buffer_size: usize) -> Self {
        self.buffer_size = buffer_size;
        self
    }
}

/// Queries a legacy perf-event attachment descriptor owned by `process_id`.
pub fn task_fd(
    process_id: u32,
    descriptor: i32,
    options: TaskFdQueryOptions,
) -> Result<TaskFdInfo> {
    if options.buffer_size > u32::MAX as usize {
        return Err(Error::InvalidObject(
            "task-FD query buffer does not fit the kernel ABI".into(),
        ));
    }
    let (raw, buffer) =
        sys::task_fd_query(process_id, descriptor, options.flags, options.buffer_size)
            .map_err(|source| Error::system("query task eBPF attachment", source))?;
    let end = buffer
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(buffer.len());
    Ok(TaskFdInfo {
        program_id: raw.program_id,
        attachment_type: TaskFdType::from_raw(raw.fd_type),
        target: OsString::from_vec(buffer[..end].to_vec()),
        probe_offset: raw.probe_offset,
        probe_address: raw.probe_address,
    })
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

    #[test]
    fn task_fd_types_are_forward_compatible() {
        assert_eq!(TaskFdType::from_raw(0), TaskFdType::RawTracepoint);
        assert_eq!(TaskFdType::from_raw(5), TaskFdType::Uretprobe);
        assert_eq!(TaskFdType::from_raw(99), TaskFdType::Other(99));
        assert_eq!(TaskFdQueryOptions::default().buffer_size, 4096);
    }
}
