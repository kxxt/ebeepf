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

Loading and attaching eBPF generally requires suitable capabilities. Parsing,
inspection, and the unit test suite do not require privileges.

## Status

The crate currently provides:

- owned ELF and BTF parsing, BTF-defined and legacy maps, global data and
  kconfig maps, subprogram linking, BTF.ext metadata, and CO-RE field
  relocations;
- direct `bpf(2)` loading, pinning, kernel-ID queries, verifier logs, program
  test runs, map CRUD and batch operations, and per-CPU values;
- tracepoint, kprobe, uprobe, raw tracepoint, cgroup, XDP, TCX, netfilter,
  socket, perf-event, and BTF-based attachments with RAII link lifetimes;
- ring-buffer, user-ring-buffer, and perf-buffer consumers/producers without
  exposing C pointers in the public API.

The ordinary suite is unprivileged:

```console
cargo test -p ebeepf --all-targets
cargo clippy -p ebeepf --all-targets -- -D warnings
```

An ignored end-to-end test generates an ELF object, loads it, and exercises map
CRUD against the running kernel. Run it in an environment with root or
`CAP_BPF`:

```console
cargo test -p ebeepf --test kernel_smoke -- --ignored
```

Unsupported object or kernel features return structured errors rather than
being silently ignored.
