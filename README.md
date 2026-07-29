# ebeepf

`ebeepf` is a pure Rust eBPF loader and runtime for Linux. It parses eBPF ELF
and BTF data itself and talks to the kernel through the `bpf(2)` system call;
it does not link to libbpf.

The API follows Rust ownership instead of exposing the C object model:

```rust,no_run
use ebeepf::Object;

let object = Object::open("tracer.bpf.o")?;
let mut object = object.load()?;

let events = object.map("events")?;
let link = object.program_mut("handle_exec")?.attach_tracepoint("syscalls", "sys_enter_execve")?;

// The kernel attachment remains active for the lifetime of `link`.
drop((events, link));
# Ok::<(), ebeepf::Error>(())
```

Loading and attaching eBPF generally requires suitable capabilities. Parsing,
inspection, and the unit test suite do not require privileges.

## Status

The crate supports modern BTF-defined maps, data maps, ELF relocations, program
loading, common link-based attachments, pinning, map operations, BTF parsing,
and ring buffers. Unsupported object features are reported as errors rather
than silently ignored.
