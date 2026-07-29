//! Read-only enumeration of eBPF resources visible to the calling process.

use crate::sys::{self, ObjectKind};
use crate::{Error, Result};

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
