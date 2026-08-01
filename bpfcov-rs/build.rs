fn main() {
    #[cfg(feature = "vendored")]
    build_libbpfcov();
}

#[cfg(feature = "vendored")]
fn build_libbpfcov() {
    use std::process::Command;

    emit_rerun_envs();

    // Query llvm-config for build flags
    let llvm_config = find_llvm_config();

    let llvm_includedir = llvm_config_arg(&llvm_config, "--includedir");
    let llvm_cxxflags = llvm_config_arg(&llvm_config, "--cxxflags");
    let llvm_has_rtti = llvm_config_arg(&llvm_config, "--has-rtti");
    let llvm_bindir = llvm_config_arg(&llvm_config, "--bindir");
    let llvm_version = llvm_config_arg(&llvm_config, "--version");

    let out_dir = std::env::var("OUT_DIR").unwrap();

    // Build BPFCov.cpp → libBPFCov.so using the C++ compiler directly,
    // mirroring what the CMake build does.
    let mut cmd = Command::new(std::env::var("CXX").unwrap_or_else(|_| "c++".into()));

    // Parse cxxflags from llvm-config (includes -std=c++17, defines, etc.)
    for flag in llvm_cxxflags.split_whitespace() {
        cmd.arg(flag);
    }

    cmd.arg("-Wall")
        .arg("-fdiagnostics-color=always")
        .arg("-fvisibility-inlines-hidden");

    // LLVM is normally built without RTTI; match that.
    if llvm_has_rtti.trim() != "YES" {
        cmd.arg("-fno-rtti");
    }

    // Include paths
    cmd.arg(format!("-I{llvm_includedir}"));
    cmd.arg("-I").arg("include");

    // Shared library flags
    cmd.arg("-shared").arg("-fPIC");

    // On macOS, allow undefined symbols (resolved at runtime by opt).
    if cfg!(target_os = "macos") {
        cmd.arg("-undefined").arg("dynamic_lookup");
    }

    let output_path = format!("{out_dir}/libBPFCov.so");

    cmd.arg("-o").arg(&output_path).arg("lib/BPFCov.cpp");

    let output = cmd
        .output()
        .expect("failed to execute C++ compiler to build libBPFCov.so");
    if !output.status.success() {
        panic!(
            "C++ compilation of libBPFCov.so failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    println!("cargo:rustc-env=BPFCOV_LIB_DIR={out_dir}");
    println!("cargo:rustc-env=BPFCOV_LLVM_BINDIR={llvm_bindir}");
    println!("cargo:rustc-env=BPFCOV_LLVM_VERSION={llvm_version}");
    println!("cargo:rerun-if-changed=lib/BPFCov.cpp");
    println!("cargo:rerun-if-changed=include/BPFCov.h");
}

#[cfg(feature = "vendored")]
fn emit_rerun_envs() {
    for env in ["LLVM_CONFIG", "OPT", "CLANG", "LLC", "CXX"] {
        println!("cargo:rerun-if-env-changed={env}");
    }
}

#[cfg(feature = "vendored")]
fn find_llvm_config() -> String {
    if let Ok(llvm_config) = std::env::var("LLVM_CONFIG") {
        return llvm_config;
    }

    for env in ["OPT", "CLANG", "LLC"] {
        if let Some(tool) = std::env::var_os(env) {
            if let Some(llvm_config) = infer_llvm_config_from_tool(&tool) {
                return llvm_config;
            }
        }
    }

    "llvm-config".into()
}

#[cfg(feature = "vendored")]
fn infer_llvm_config_from_tool(tool: &std::ffi::OsStr) -> Option<String> {
    use std::path::Path;

    let tool_path = Path::new(tool);
    let file_name = tool_path.file_name()?.to_string_lossy();

    if let Some(suffix) = llvm_tool_version_suffix(&file_name) {
        if let Some(parent) = non_empty_parent(tool_path) {
            let candidate = parent.join(format!("llvm-config{suffix}"));
            if candidate.exists() {
                return Some(candidate.to_string_lossy().into_owned());
            }
        }
        return Some(format!("llvm-config{suffix}"));
    }

    let parent = non_empty_parent(tool_path)?;
    let candidate = parent.join("llvm-config");
    candidate
        .exists()
        .then(|| candidate.to_string_lossy().into_owned())
}

#[cfg(feature = "vendored")]
fn non_empty_parent(path: &std::path::Path) -> Option<&std::path::Path> {
    let parent = path.parent()?;
    (!parent.as_os_str().is_empty()).then_some(parent)
}

#[cfg(feature = "vendored")]
fn llvm_tool_version_suffix(tool_name: &str) -> Option<&str> {
    for prefix in ["clang++", "clang", "opt", "llc"] {
        if let Some(suffix) = tool_name.strip_prefix(prefix) {
            if let Some(version) = suffix.strip_prefix('-') {
                if version.chars().next().is_some_and(|ch| ch.is_ascii_digit()) {
                    return Some(suffix);
                }
            }
        }
    }
    None
}

#[cfg(feature = "vendored")]
fn llvm_config_arg(llvm_config: &str, arg: &str) -> String {
    let output = std::process::Command::new(llvm_config)
        .arg(arg)
        .output()
        .unwrap_or_else(|e| panic!("failed to run `{llvm_config} {arg}`: {e}"));
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!("`{llvm_config} {arg}` failed: {stderr}");
    }
    String::from_utf8(output.stdout)
        .expect("llvm-config output is not valid UTF-8")
        .trim()
        .to_string()
}
