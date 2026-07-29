# libbpf workflow parity

This document records the `ebeepf` loader/runtime audit against libbpf
`2bbc4834e960` and the libbpf-rs source tree beside this crate. “Parity” here
means that an application can perform the same eBPF loading, relocation,
attachment, map, link, buffer, query, and skeleton workflows through safe Rust.
It does not mean source compatibility with libbpf's C ABI.

## Runtime and loader coverage

| Workflow | Rust-native interface |
| --- | --- |
| Open ELF from a file or memory | `Object::open`, `Object::parse`, `Object::parse_named` |
| Inspect and configure before load | `Object`, `MapSpec`, and `ProgramSpec` borrowed accessors |
| Clone or prepare another load | Clone the owned parsed `Object`, configure it, then call `load` |
| Load BTF, maps, and programs | `Object::load`, `Btf::load`, `Map::create`, and `Program::load` |
| Delegated loading | `BpfToken`, retained across BTF, map, and program creation |
| Reuse maps and configure pinning | `Object::reuse_map`, `set_pin_root`, and `MapSpec::set_pinning` |
| Pin one or all objects | `Map`, `Program`, and `Link` pin methods plus transactional `LoadedObject::pin` |
| Directory-relative pinned objects | `ObjectPathOptions::relative_to` with `open_pinned_with` or `pin_with` |
| Parse BTF and split BTF | `Btf::parse`, `parse_split`, `from_vmlinux`, and module-aware `BtfObject` |
| ELF and BTF relocation | map/data/subprogram relocations, BTF.ext, all standard CO-RE kinds, kfuncs, typed and typeless ksyms |
| Kernel-module targets | split BTF, module CO-RE, module kfuncs, module tracing, and module-owned `struct_ops` |
| Object linking | `ObjectLinker` and `LinkedObject`, entirely in Rust |
| Global data | checked pre-load data sections and volatile mmap-backed loaded views |
| Modern map forms | map-in-map, per-CPU, storage, ring buffers, arenas, instruction arrays, resizable hash maps, and `struct_ops` |
| Map operations | checked CRUD, queue/stack operations, iteration, batches, mmap, freeze, and frozen-content hashing |
| Program operations | verifier logs, flags, signatures, BTF records, test runs, map binding, streams, runtime statistics, and detailed metadata |
| Link operations | owned lifetimes, pin/open, update, conditional update, detach, and complete current `bpf_link_info` decoding |
| Resource discovery | ID iterators, open-by-ID, detailed metadata, attachment query, and legacy task-FD query |
| Capability probes | program types, map types, helpers, tokens, XDP features, and kernel ABI fallbacks |
| Event transport | ring buffer, user ring buffer, and perf buffer with safe reservation and callback lifetimes |
| Persistent networking | native netlink XDP and classic TC create/query/replace/detach workflows |

Attachment coverage includes tracepoints, raw tracepoints, kprobes, syscall
wrappers, uprobes, USDT, single/multi/session probes, cgroups, sockets, network
namespaces, XDP, TCX, netkit, netfilter, perf events, BTF tracing, tracing
multi, LSM, iterators, `freplace`, socket maps, and `struct_ops`. Conventional
section targets drive automatic attachment when all required arguments are
encoded in the object; otherwise the generated skeleton exposes an explicit
runtime attachment slot.

## Skeleton coverage

`SkeletonBuilder` can compile a BPF C source with clang or consume an existing
object. It generates self-contained Rust by default, with an
`include_bytes!` reference mode for applications that prefer a separate
object.

Generated code has three ownership stages:

1. A builder configures compilation/object input and optional BPF delegation.
2. An open skeleton owns the parsed object and exposes mutable map/program
   definitions plus typed BTF-derived global-data accessors.
3. A loaded skeleton owns all kernel resources, mapped global-data views, and
   automatically created links.

Loading and attachment are separate operations. `load` performs ELF/BTF
relocation and kernel creation; `attach` is transactional and retains every
successful link in the skeleton. Programs requiring a process, file, cgroup,
network interface, or another program at runtime remain available through
their named accessor.

## Intentional Rust replacements

The C operations for close, unload, free, and link destruction are represented
by ownership and `Drop`. C object iterators become standard Rust iterators.
Raw option structures become typed builders, raw descriptors become
`OwnedFd`/`BorrowedFd`, and libbpf's global section-handler registry is replaced
by per-program `ProgramKind` inspection and mutation.

The crate intentionally does not reproduce implementation-support APIs that
are not loader/runtime workflows:

- libbpf's C pointer/error compatibility and printf callback layers;
- C source skeleton/subskeleton structures and in-kernel loader generation;
- mutable BTF authoring, deduplication/permutation, and C declaration dumping;
- process-wide memlock policy changes.

Raw BTF parsing, resolution, size/alignment queries, kernel loading, split BTF,
and kernel/module discovery are covered. Applications that author or pretty
print BTF can do so as a separate build-time concern without coupling the
runtime loader to libbpf.

## Verification

The unprivileged suite validates parsing, linking, relocation, generated-source
formatting, and type-checks a generated skeleton in a consumer crate. The
privileged suite loads and attaches real programs on Linux and covers CO-RE,
module BTF/kfunc/ksym handling, `freplace`, `struct_ops`, USDT, arenas,
instruction arrays, tokens, XDP, TC, pinned objects, detailed metadata, and
map/program operations.
