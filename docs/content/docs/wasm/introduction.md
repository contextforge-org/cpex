---
title: "Introduction"
weight: 5
---

# Introduction to WebAssembly

A primer on WebAssembly, the Component Model, and why CPEX uses them for plugin sandboxing.

## What is WebAssembly?

WebAssembly (WASM) is a portable binary instruction format designed as a compilation target for high-level languages. Originally created for browsers, it now runs anywhere a conformant runtime exists — servers, CLIs, embedded systems.

- **Portable bytecode** — compile once from Rust, C, Go, or any language with a WASM backend; run on any architecture
- **Near-native speed** — ahead-of-time compiled by runtimes like Wasmtime to optimized machine code
- **Sandboxed by design** — linear memory is isolated; no access to the host filesystem, network, or environment unless explicitly granted
- **Language-agnostic** — plugin authors choose their preferred language; the host only sees the WASM binary

## The WASM Component Model

Core WASM operates on raw integers and floats — passing structured data between modules requires manual encoding. The Component Model is a higher-level standard that solves this interop problem by introducing typed interfaces and clear role separation.

### Key concepts

- **WIT (WebAssembly Interface Type)** — a human-readable IDL that defines the contract between modules. Types (records, variants, lists, options, enums) and functions are declared in `.wit` files.
- **Components** — self-contained WASM binaries that declare what they import (need from the outside) and export (provide to the outside). Unlike raw WASM modules, components carry their interface metadata.
- **Composition** — components can be linked together without sharing memory, enabling modular architectures where each component is independently sandboxed.

### Host and guest

The Component Model defines two roles at the trust boundary:

- **Host** — the native process that loads and executes WASM components. It decides what capabilities to grant, instantiates the runtime, and calls exported functions on the guest.
- **Guest** — the compiled `.wasm` component running inside the sandbox. It can only use functions the host explicitly provides as imports. It cannot reach the filesystem, network, or any OS resource on its own.

This separation is absolute — the guest has no way to escalate beyond what the host links in.

### How the Component Model works


![Wasm Component Model](images/wasm_component_flow.png)

**The communication cycle:**

1. **Compile** — the host loads the `.wasm` binary and compiles it to native code via the runtime
2. **Link** — the host selectively provides import functions (filesystem, HTTP, logging, etc.) based on policy. Functions not linked simply do not exist from the guest's perspective.
3. **Call** — the host invokes an exported function on the guest, passing data as WIT-typed values (records, variants, lists). The Component Model handles serialization/deserialization at the boundary automatically.
4. **Execute** — the guest runs in its own linear memory. It can call imported functions (e.g., log a message, make an HTTP request) but nothing else.
5. **Return** — the guest returns a typed result. The host validates it and applies any post-processing.

All data crosses the boundary **by value** — there are no shared pointers or references between host and guest memory. A crash or trap in the guest is contained; the host process is unaffected.

## How CPEX uses this

CPEX leverages the Component Model to run untrusted or third-party plugins in a controlled sandbox. At a high level:


![CPEX Component Model Usage](images/cpex_wasm_plugin_invocation.png)

<!-- ```
┌─────────────┐         ┌───────────────────┐         ┌──────────────────┐
│  Your App   │────────►│  cpex-wasm-host    │────────►│  Plugin (.wasm)  │
│             │ invoke  │                   │ handle  │                  │
│  payload +  │         │  • Sandbox policy │ -hook   │  • Inspects data │
│  extensions │         │  • Fuel/timeout   │         │  • Returns allow │
│             │◄────────│  • Capability     │◄────────│    or block      │
│             │ result  │    filtering      │ result  │                  │
└─────────────┘         └───────────────────┘         └──────────────────┘
``` -->

- Plugins target `wasm32-wasip2` and are built with the `cpex-wasm-plugin` guest SDK
- The host loads plugins and defines their sandbox policy (filesystem paths, network hosts, env vars, resource budgets) in declarative YAML
- Each plugin exports a single function — `handle-hook` — which the host calls during the pipeline
- The WIT contract (`wit/world.wit`) defines the exact types flowing across the boundary:

```wit
world plugin {
    import wasi:io/poll
    import wasi:io/streams
    import wasi:clocks/monotonic-clock
    import wasi:http/outgoing-handler
    import host-logging

    export handle-hook: func(
        hook-name: string,
        payload: hook-payload,
        extensions: extensions,
        ctx: plugin-context
    ) -> hook-result
}
```

The host controls every dimension of the guest's execution:

| Dimension | Mechanism | Effect |
|-----------|-----------|--------|
| CPU | Fuel budget | Traps after N instructions |
| Wall-clock | Epoch deadline | Interrupts after N ms |
| Memory | Store limiter | Denies `memory.grow` beyond cap |
| Filesystem | Preopened dirs | Only listed paths visible |
| Network | Host allowlist | Only listed hosts reachable |
| Env vars | Explicit inject | Only listed vars exist |
| Capabilities | Extension filter | Only permitted fields visible |

## Advantages

- **Security isolation** — each plugin runs in its own linear memory with no access to host state unless the sandbox policy explicitly grants it
- **Deterministic resource limits** — fuel budgets cap CPU, epoch deadlines enforce wall-clock timeouts, and memory limits prevent unbounded allocation
- **Language flexibility** — plugin authors are not locked to Rust; any language compiling to `wasm32-wasip2` works (Rust, C/C++, Go, JavaScript via weval)
- **Auditability** — sandbox policy is declarative YAML; what a plugin can access is visible in configuration, not buried in code
- **Safe hot-reload** — replacing a `.wasm` file and re-instantiating carries no risk of memory corruption or dangling state from the previous version
- **No shared-memory bugs** — plugins cannot corrupt host memory or each other; a trapped plugin is cleanly dropped without affecting the process
- **Least privilege by default** — a plugin with no policy has zero capabilities; access must be explicitly opted in

## Limitations

- **Serialization overhead** — data crossing the WASM boundary must be serialized/deserialized (the Component Model automates this but the cost is non-zero; typically ~50-200μs per invocation)
- **Cold-start compilation** — the first instantiation of a `.wasm` binary incurs JIT/AOT compilation time (mitigated by caching compiled modules)
- **Ecosystem maturity** — WASI Preview 2 is stable but some host APIs (e.g., async I/O, sockets) are still evolving
- **No direct host memory access** — plugins cannot share references or zero-copy buffers with the host; all data is copied across the boundary
- **Debugging** — stack traces from trapped plugins show WASM offsets rather than source lines; `WASMTIME_BACKTRACE_DETAILS=1` helps but is not as ergonomic as native debugging
- **Binary size** — WASM binaries include their own allocator and standard library; typical plugin size is 2-5 MB (does not affect runtime performance)

## Next steps

- [Quickstart]({{< relref "quickstart" >}}) — build and run your first WASM plugin in under five minutes
- [Architecture]({{< relref "architecture" >}}) — detailed look at the host internals, sandbox manager, and bridge handler
