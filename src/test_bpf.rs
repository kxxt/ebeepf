use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

pub(crate) struct BpfFixture {
    _directory: tempfile::TempDir,
    path: PathBuf,
}

impl BpfFixture {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

pub(crate) fn compile_fixture(name: &str) -> BpfFixture {
    let source_directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/bpf");
    let source = source_directory.join(format!("{name}.bpf.c"));
    assert!(
        source.exists(),
        "missing BPF fixture source `{}`",
        source.display()
    );

    let target = bpf_target();
    let include_directory = source_directory
        .join("include")
        .join(target.vmlinux_directory);
    assert!(
        include_directory.join("vmlinux.h").exists(),
        "missing vmlinux header directory `{}`",
        include_directory.display()
    );

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join(format!("{name}.bpf.o"));
    let output = Command::new("clang")
        .arg("-target")
        .arg(target.llvm_target)
        .arg("-g")
        .arg("-O2")
        .arg(format!("-D__TARGET_ARCH_{}", target.libbpf_arch))
        .arg("-I")
        .arg(&include_directory)
        .arg("-I")
        .arg(&source_directory)
        .arg("-c")
        .arg(&source)
        .arg("-o")
        .arg(&path)
        .output()
        .unwrap_or_else(|source| {
            panic!("failed to execute clang for `{name}` BPF fixture: {source}")
        });
    assert!(
        output.status.success(),
        "failed to compile `{name}` BPF fixture with clang {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    BpfFixture {
        _directory: directory,
        path,
    }
}

struct BpfTarget {
    llvm_target: &'static str,
    libbpf_arch: &'static str,
    vmlinux_directory: &'static str,
}

fn bpf_target() -> BpfTarget {
    let architecture =
        env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_else(|_| env::consts::ARCH.into());
    let llvm_target = if cfg!(target_endian = "big") {
        "bpfeb"
    } else {
        "bpfel"
    };
    let (libbpf_arch, vmlinux_directory) = match architecture.as_str() {
        "x86" | "x86_64" => ("x86", "x86"),
        "arm" => ("arm", "arm"),
        "aarch64" => ("arm64", "aarch64"),
        "loongarch64" => ("loongarch", "loongarch64"),
        "powerpc" | "powerpc64" => ("powerpc", "powerpc"),
        "riscv64" => ("riscv", "riscv64"),
        "s390x" => ("s390", "s390x"),
        value => panic!("target architecture `{value}` has no __TARGET_ARCH mapping"),
    };
    BpfTarget {
        llvm_target,
        libbpf_arch,
        vmlinux_directory,
    }
}
