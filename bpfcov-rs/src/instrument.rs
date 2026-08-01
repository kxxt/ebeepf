//! Build-time helpers for instrumenting BPF programs with the bpfcov LLVM pass.
//!
//! The instrumentation pipeline is:
//! 1. `clang` compiles the BPF source to LLVM IR with profiling metadata
//! 2. `opt` runs the bpfcov LLVM pass to make the IR BPF-compatible
//! 3. `llc` lowers the result to a BPF object file
//!
//! Two object files are produced:
//! - An *instrumented* object (for loading into the kernel).
//! - A *coverage* object (for `llvm-cov`; has stripped initializers).

use std::ffi::{OsStr, OsString};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Result of a successful instrumentation build.
#[derive(Debug, Clone)]
pub struct InstrumentedBuild {
    /// Instrumented BPF object file (for loading into the kernel).
    pub instrumented_obj: PathBuf,
    /// Coverage-only BPF object file (for `llvm-cov show`).
    pub coverage_obj: PathBuf,
}

/// Builder for the instrumentation pipeline.
///
/// ```no_run
/// # use std::path::Path;
/// # use bpfcov::instrument::Pipeline;
/// let result = Pipeline::new()
///     .source(Path::new("my_program.bpf.c"))
///     .lib_bpfcov(Path::new("/path/to/libBPFCov.so"))
///     .output_dir(Path::new("target/bpf"))
///     .clang_arg("-I").clang_arg("include")
///     .run()
///     .expect("instrumentation pipeline failed");
/// ```
pub struct Pipeline {
    source: Option<PathBuf>,
    lib_bpfcov: Option<PathBuf>,
    output_dir: Option<PathBuf>,
    clang: OsString,
    opt: OsString,
    llc: OsString,
    clang_args: Vec<OsString>,
}

impl Default for Pipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl Pipeline {
    /// Create a new pipeline with default tool names (`clang`, `opt`, `llc`)
    /// or values from `CLANG`, `OPT`, `LLC` environment variables. When the
    /// `vendored` feature is enabled, defaults come from the same LLVM
    /// installation used to build the bundled pass when those tools are found.
    ///
    /// When the `vendored` feature is enabled the built-in `libBPFCov.so` is
    /// used automatically unless overridden with [`Pipeline::lib_bpfcov`].
    pub fn new() -> Self {
        Self {
            source: None,
            lib_bpfcov: Self::vendored_lib_path(),
            output_dir: None,
            clang: Self::default_llvm_tool("CLANG", "clang"),
            opt: Self::default_llvm_tool("OPT", "opt"),
            llc: Self::default_llvm_tool("LLC", "llc"),
            clang_args: Vec::new(),
        }
    }

    fn default_llvm_tool(env: &str, tool: &str) -> OsString {
        if let Some(path) = std::env::var_os(env) {
            return path;
        }

        #[cfg(feature = "vendored")]
        if let Some(path) = Self::vendored_llvm_tool(tool) {
            return path;
        }

        tool.into()
    }

    #[cfg(feature = "vendored")]
    fn vendored_llvm_tool(tool: &str) -> Option<OsString> {
        let bindir = option_env!("BPFCOV_LLVM_BINDIR")?;
        if bindir.is_empty() {
            return None;
        }

        let path = PathBuf::from(bindir).join(tool);
        path.exists().then(|| path.into_os_string())
    }

    /// Returns the path to the vendored `libBPFCov.so` when compiled with the
    /// `vendored` feature, or `None` otherwise.
    fn vendored_lib_path() -> Option<PathBuf> {
        #[cfg(feature = "vendored")]
        {
            let dir = env!("BPFCOV_LIB_DIR");
            let p = PathBuf::from(dir).join("libBPFCov.so");
            if p.exists() {
                return Some(p);
            }
        }
        None
    }

    /// BPF C source file to instrument.
    pub fn source(mut self, path: &Path) -> Self {
        self.source = Some(path.to_owned());
        self
    }

    /// Path to the `libBPFCov.so` shared library.
    pub fn lib_bpfcov(mut self, path: &Path) -> Self {
        self.lib_bpfcov = Some(path.to_owned());
        self
    }

    /// Directory where output files are placed.
    pub fn output_dir(mut self, path: &Path) -> Self {
        self.output_dir = Some(path.to_owned());
        self
    }

    /// Override the `clang` binary (default: `$CLANG` or `clang`).
    pub fn clang(mut self, path: impl Into<OsString>) -> Self {
        self.clang = path.into();
        self
    }

    /// Override the `opt` binary (default: `$OPT` or `opt`).
    pub fn opt(mut self, path: impl Into<OsString>) -> Self {
        self.opt = path.into();
        self
    }

    /// Override the `llc` binary (default: `$LLC` or `llc`).
    pub fn llc(mut self, path: impl Into<OsString>) -> Self {
        self.llc = path.into();
        self
    }

    /// Append a single extra argument passed to `clang`.
    pub fn clang_arg(mut self, arg: impl Into<OsString>) -> Self {
        self.clang_args.push(arg.into());
        self
    }

    /// Append multiple extra arguments passed to `clang`.
    pub fn clang_args(mut self, args: impl IntoIterator<Item = impl Into<OsString>>) -> Self {
        self.clang_args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Execute the pipeline.
    pub fn run(&self) -> io::Result<InstrumentedBuild> {
        let source = self
            .source
            .as_deref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "source not set"))?;
        let lib_bpfcov = self
            .lib_bpfcov
            .as_deref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "lib_bpfcov not set"))?;
        let output_dir = self
            .output_dir
            .as_deref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "output_dir not set"))?;

        std::fs::create_dir_all(output_dir)?;

        let stem = source
            .file_stem()
            .and_then(|s| {
                // Strip `.bpf` from `foo.bpf.c` → `foo`
                let s_str = s.to_string_lossy();
                s_str.strip_suffix(".bpf").map(OsString::from)
            })
            .unwrap_or_else(|| {
                source
                    .file_stem()
                    .unwrap_or(OsStr::new("program"))
                    .to_owned()
            });

        let ll_path = output_dir.join(format!("{}.bpf.ll", stem.to_string_lossy()));
        let instrumented_obj = output_dir.join(format!("{}.bpf.o", stem.to_string_lossy()));
        let coverage_obj = output_dir.join(format!("{}.bpf.obj", stem.to_string_lossy()));

        // Step 1: clang → LLVM IR with profiling instrumentation
        run_cmd(
            Command::new(&self.clang)
                .arg("-g")
                .arg("-O2")
                .arg("-target")
                .arg("bpf")
                .args(&self.clang_args)
                .arg("-fprofile-instr-generate")
                .arg("-fcoverage-mapping")
                .arg("-emit-llvm")
                .arg("-S")
                .arg("-c")
                .arg(source)
                .arg("-o")
                .arg(&ll_path),
            "clang (emit LLVM IR)",
        )?;

        // Step 2a: opt + llc → instrumented BPF object (for loading)
        let opt_output = run_cmd_output(
            Command::new(&self.opt)
                .arg("-load-pass-plugin")
                .arg(lib_bpfcov)
                .arg("-passes=bpf-cov")
                .arg(&ll_path)
                .arg("-o")
                .arg("-"),
            "opt (instrumented)",
        )?;
        run_cmd_stdin(
            Command::new(&self.llc)
                .arg("-march=bpf")
                .arg("-filetype=obj")
                .arg("-o")
                .arg(&instrumented_obj)
                .arg("-"),
            &opt_output,
            "llc (instrumented)",
        )?;

        // Step 2b: opt + llc → coverage-only object (for llvm-cov)
        let cov_output = run_cmd_output(
            Command::new(&self.opt)
                .arg("-load-pass-plugin")
                .arg(lib_bpfcov)
                .arg("-strip-initializers-only")
                .arg("-passes=bpf-cov")
                .arg(&ll_path)
                .arg("-o")
                .arg("-"),
            "opt (coverage)",
        )?;
        run_cmd_stdin(
            Command::new(&self.llc)
                .arg("-march=bpf")
                .arg("-filetype=obj")
                .arg("-o")
                .arg(&coverage_obj)
                .arg("-"),
            &cov_output,
            "llc (coverage)",
        )?;

        Ok(InstrumentedBuild {
            instrumented_obj,
            coverage_obj,
        })
    }
}

fn run_cmd(cmd: &mut Command, label: &str) -> io::Result<()> {
    let status = cmd
        .status()
        .map_err(|e| io::Error::new(e.kind(), format!("{label}: failed to execute: {e}")))?;
    if !status.success() {
        return Err(io::Error::other(format!("{label}: exited with {status}")));
    }
    Ok(())
}

fn run_cmd_output(cmd: &mut Command, label: &str) -> io::Result<Vec<u8>> {
    let output = cmd
        .output()
        .map_err(|e| io::Error::new(e.kind(), format!("{label}: failed to execute: {e}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(io::Error::other(format!(
            "{label}: exited with {}: {stderr}",
            output.status
        )));
    }
    Ok(output.stdout)
}

fn run_cmd_stdin(cmd: &mut Command, stdin_data: &[u8], label: &str) -> io::Result<()> {
    use std::process::Stdio;
    let mut child = cmd
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|e| io::Error::new(e.kind(), format!("{label}: failed to spawn: {e}")))?;

    if let Some(ref mut stdin) = child.stdin {
        stdin.write_all(stdin_data)?;
    }
    drop(child.stdin.take()); // close stdin so the child can finish

    let status = child.wait()?;
    if !status.success() {
        return Err(io::Error::other(format!("{label}: exited with {status}")));
    }
    Ok(())
}
