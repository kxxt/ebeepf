# ebeepf

`ebeepf` is a pure Rust eBPF loader and runtime for Linux. It parses eBPF ELF
and BTF data itself and talks to the kernel through the `bpf(2)` system call;
it does not link to libbpf.

The API follows Rust ownership instead of exposing the C object model:

```rust,no_run
use ebeepf::Object;

let object = Object::open("tracer.bpf.o")?;
let object = object.load()?;

let events = object.map("events")?;
let link = object.program("handle_exec")?
    .attach_tracepoint("syscalls", "sys_enter_execve")?;

// The kernel attachment remains active for the lifetime of `link`.
drop((events, link));
# Ok::<(), ebeepf::Error>(())
```

Rust-native skeletons provide named accessors and preserve the same ownership
model. A build script can compile C and generate a skeleton without libbpf:

```rust,no_run
use ebeepf::SkeletonBuilder;

SkeletonBuilder::new()
    .source("src/bpf/tracer.bpf.c")
    .build_and_generate(
        std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap())
            .join("tracer.skel.rs"),
    )?;
# Ok::<(), ebeepf::Error>(())
```

The generated API has explicit builder, open, and loaded stages. Open
skeletons expose mutable map/program definitions and safe BTF-derived global
data getters and setters. Loaded skeletons retain automatically created links
and expose slots for attachments that need runtime arguments:

```rust,ignore
let mut open = TracerSkelBuilder::new().open()?;
open.rodata_mut()?.set_target_pid(&std::process::id())?;
open.programs_mut().optional_probe()?.set_autoload(false);

let mut skel = open.load()?;
skel.attach()?;
let events = skel.maps().events()?;
```

Existing objects can be generated from the command line with
`ebeepf-skel generate INPUT.bpf.o OUTPUT.rs`. Pass `--reference` to use
`include_bytes!`; the default output is self-contained.

Loading and attaching eBPF generally requires suitable capabilities. Parsing,
inspection, and the unit test suite do not require privileges.

## Status

The crate currently provides:

- owned ELF and BTF parsing, BTF-defined and legacy maps, global data and
  kconfig maps, subprogram linking, BTF.ext metadata, and CO-RE field
  relocations;
- direct `bpf(2)` loading, standalone and reused maps, pinning, rich
  map/program/link/BTF metadata, attachment queries, verifier logs, program
  test runs, type-accurate map/program/helper capability probes, map CRUD and
  batch operations, and per-CPU values;
- tracepoint, kprobe, uprobe, raw tracepoint, cgroup, XDP, TCX, netfilter,
  socket, perf-event, BTF-based, multi-kprobe, multi-uprobe, USDT,
  `freplace`, `struct_ops`, legacy program, and iterator attachments with
  RAII link lifetimes;
- persistent legacy XDP and classic TC `clsact` management through a private
  pure Rust netlink transport, including mode queries, driver features,
  compare-and-replace, and RAII-owned TC filters;
- ring-buffer, user-ring-buffer, and perf-buffer consumers/producers without
  exposing C pointers in the public API;
- build-script and CLI skeleton generation with named open/loaded
  map/program accessors, runtime-configurable transactional auto-attach,
  retained links, and safe typed global-data configuration.

The ordinary suite is unprivileged:

```console
cargo test -p ebeepf --all-targets
cargo clippy -p ebeepf --all-targets -- -D warnings
```

Ignored end-to-end tests load real objects, exercise map CRUD, attach a
Rust-emitted USDT probe, verify its cookie through a kernel ring buffer,
compile and exercise a live BTF `freplace` target, and manage XDP and TC on an
isolated temporary interface. Run them in an
environment with root or the corresponding `CAP_BPF` and `CAP_NET_ADMIN`
capabilities:

```console
cargo test -p ebeepf --test kernel_smoke -- --ignored
```

Unsupported object or kernel features return structured errors rather than
being silently ignored.
