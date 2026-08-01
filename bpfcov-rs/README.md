# bpfcov-rs

This is a fork of https://github.com/elastic/bpfcov.

`bpfcov` provides source-based coverage for eBPF programs. This workspace
package contains the LLVM instrumentation pass and Rust helpers originally
developed in the `bpfcov-rs` repository.

It has three layers:

- `instrument` compiles an eBPF C source through `clang`, the bpfcov LLVM pass,
  and `llc`, producing an instrumented object for the kernel and a
  coverage-only object for `llvm-cov`;
- `profraw` serializes the three bpfcov profiling maps in LLVM profraw v10
  format;
- `report` invokes `llvm-profdata` and `llvm-cov` to produce HTML, JSON, or LCOV
  reports.

The `libbpf` feature additionally provides collection from a loaded
`libbpf-rs::Object`. The `vendored` feature builds `libBPFCov.so` from the
included C++ source. Both features are enabled by default for standalone use.

## Using it with ebeepf

Applications using `ebeepf` normally do not need a direct `bpfcov` dependency.
Enable `ebeepf`'s `coverage` feature to get coverage-aware skeleton generation,
runtime collection from `ebeepf::LoadedObject`, and the report helpers:

```toml
[dependencies]
ebeepf = { version = "0.1", features = ["coverage"] }

[build-dependencies]
ebeepf = { version = "0.1", features = ["coverage"] }
```

See the workspace [README](../README.md#source-based-coverage) for the complete
build-time and runtime flow.

## Standalone instrumentation

```rust,no_run
use bpfcov::Pipeline;

let result = Pipeline::new()
    .source(std::path::Path::new("my_prog.bpf.c"))
    .output_dir(std::path::Path::new("target/bpfcov"))
    .clang_args(["-Ipath/to/includes", "-D__TARGET_ARCH_x86"])
    .run()?;

println!("load {}", result.instrumented_obj.display());
println!("report with {}", result.coverage_obj.display());
# Ok::<(), std::io::Error>(())
```

The vendored pass needs a C++ compiler and an LLVM installation. Use
`LLVM_CONFIG`, `CXX`, `CLANG`, `OPT`, and `LLC` to select versioned tools, or
`BPFCOV_LIB` through `ebeepf` to use a separately built pass.

## License

BSD-2-Clause. See [LICENSE](LICENSE).
