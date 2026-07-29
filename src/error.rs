use std::io;
use std::path::PathBuf;
use std::result;

use thiserror::Error as ThisError;

/// The result type used by this crate.
pub type Result<T> = result::Result<T, Error>;

/// An error produced while parsing, loading, or operating on eBPF resources.
#[derive(Debug, ThisError)]
#[non_exhaustive]
pub enum Error {
    /// An operating-system operation failed.
    #[error("{operation}: {source}")]
    System {
        /// The operation that failed.
        operation: &'static str,
        /// The error returned by the operating system.
        #[source]
        source: io::Error,
    },

    /// Reading or writing a path failed.
    #[error("failed to {operation} `{path}`: {source}")]
    File {
        /// The file operation that failed.
        operation: &'static str,
        /// The affected path.
        path: PathBuf,
        /// The error returned by the operating system.
        #[source]
        source: io::Error,
    },

    /// An ELF object is malformed or unsupported.
    #[error("invalid eBPF ELF object: {0}")]
    Elf(String),

    /// BTF data is malformed or unsupported.
    #[error("invalid BTF: {0}")]
    Btf(String),

    /// Object data does not satisfy an eBPF invariant.
    #[error("invalid eBPF object: {0}")]
    InvalidObject(String),

    /// A requested map was not present.
    #[error("map `{0}` was not found")]
    MapNotFound(String),

    /// A requested program was not present.
    #[error("program `{0}` was not found")]
    ProgramNotFound(String),

    /// Bytes supplied to a map operation have the wrong length.
    #[error("{what} has length {actual}, expected {expected}")]
    SizeMismatch {
        /// What value had the wrong size.
        what: &'static str,
        /// Required size.
        expected: usize,
        /// Supplied size.
        actual: usize,
    },

    /// A program was rejected by the kernel verifier.
    #[error("the kernel rejected program `{program}`: {source}\n{log}")]
    Verifier {
        /// Program name.
        program: String,
        /// Error returned by `BPF_PROG_LOAD`.
        #[source]
        source: io::Error,
        /// Verifier diagnostics.
        log: String,
    },

    /// The requested operation is not supported by this crate or kernel.
    #[error("unsupported eBPF feature: {0}")]
    Unsupported(String),
}

impl Error {
    pub(crate) fn system(operation: &'static str, source: io::Error) -> Self {
        Self::System { operation, source }
    }
}
