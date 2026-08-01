//! Post-processing helpers that drive `llvm-profdata` and `llvm-cov`.

use std::io;
use std::path::Path;
use std::process::Command;

/// Merge one or more `.profraw` files into a single `.profdata` file.
pub fn merge_profdata(
    profraw_paths: &[&Path],
    output: &Path,
    llvm_profdata: Option<&str>,
) -> io::Result<()> {
    let bin = llvm_profdata.unwrap_or("llvm-profdata");
    let mut cmd = Command::new(bin);
    cmd.arg("merge").arg("-sparse");
    for p in profraw_paths {
        cmd.arg(p);
    }
    cmd.arg("-o").arg(output);
    run_cmd(&mut cmd, bin)
}

/// Generate an HTML coverage report using `llvm-cov show`.
pub fn generate_html_report(
    profdata: &Path,
    coverage_objs: &[&Path],
    output_dir: &Path,
    llvm_cov: Option<&str>,
) -> io::Result<()> {
    let bin = llvm_cov.unwrap_or("llvm-cov");
    let mut cmd = Command::new(bin);
    cmd.arg("show")
        .arg("--format=html")
        .arg("--show-branches=count")
        .arg("--show-line-counts-or-regions")
        .arg("--show-region-summary")
        .arg("--output-dir")
        .arg(output_dir)
        .arg("-instr-profile")
        .arg(profdata);
    for obj in coverage_objs {
        cmd.arg("-object").arg(obj);
    }
    run_cmd(&mut cmd, bin)
}

/// Generate a JSON coverage export using `llvm-cov export`.
pub fn export_json(
    profdata: &Path,
    coverage_objs: &[&Path],
    output: &Path,
    llvm_cov: Option<&str>,
) -> io::Result<()> {
    let bin = llvm_cov.unwrap_or("llvm-cov");
    let mut cmd = Command::new(bin);
    cmd.arg("export")
        .arg("--format=text")
        .arg("--show-branch-summary")
        .arg("--show-region-summary")
        .arg("-instr-profile")
        .arg(profdata);
    for obj in coverage_objs {
        cmd.arg("-object").arg(obj);
    }
    let json_output = run_cmd_output(&mut cmd, bin)?;
    std::fs::write(output, json_output)
}

/// Generate an LCOV tracefile using `llvm-cov export --format=lcov`.
pub fn export_lcov(
    profdata: &Path,
    coverage_objs: &[&Path],
    output: &Path,
    llvm_cov: Option<&str>,
) -> io::Result<()> {
    let bin = llvm_cov.unwrap_or("llvm-cov");
    let mut cmd = Command::new(bin);
    cmd.arg("export")
        .arg("--format=lcov")
        .arg("-instr-profile")
        .arg(profdata);
    for obj in coverage_objs {
        cmd.arg("-object").arg(obj);
    }
    let lcov_output = run_cmd_output(&mut cmd, bin)?;
    std::fs::write(output, lcov_output)
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
