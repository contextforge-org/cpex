---
title: "Introduction"
weight: 5
---

# Introduction to WebAssembly

A primer on WebAssembly, the Component Model, and why CPEX uses them for plugin sandboxing.

**Prerequisites:** Familiarity with Rust and the CPEX plugin model (`Plugin` trait, `HookHandler`, extensions). No prior WASM knowledge is required — this page covers everything you need.

> Want to skip the theory and start building? Jump to the [Quickstart]({{< relref "quickstart" >}}).

## What is WebAssembly?

WebAssembly (WASM) is a portable binary instruction format designed as a compilation target for high-level languages. Originally created for browsers, it now runs anywhere a conformant runtime exists — servers, CLIs, embedded systems.

- **Portable bytecode** — compile once from Rust, C, Go, or any language with a WASM backend; run on any architecture
- **Near-native speed** — ahead-of-time compiled by runtimes like Wasmtime to optimized machine code
- **Sandboxed by design** — linear memory is isolated; no access to the host filesystem, network, or environment unless explicitly granted
- **Language-agnostic** — plugin authors choose their preferred language; the host only sees the WASM binary

## The WASM Component Model

Core WASM operates on raw integers and floats — passing structured data between modules requires manual encoding. The [Component Model](https://component-model.bytecodealliance.org/) is a higher-level standard that solves this interop problem by introducing typed interfaces and clear role separation.

### Key concepts

- **[WIT (WebAssembly Interface Type)](https://component-model.bytecodealliance.org/design/wit.html)** — a human-readable IDL that defines the contract between modules. Types (records, variants, lists, options, enums) and functions are declared in `.wit` files.
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

## WASI — WebAssembly System Interface

[WASI](https://wasi.dev/) is a standardized set of APIs that give WebAssembly modules access to operating system functionality — files, clocks, networking, random numbers — without breaking the sandbox model. Think of it as a POSIX-like interface designed specifically for WASM's security constraints.

### Why WASI exists

Plain WASM has no built-in way to interact with the outside world. Without WASI, every host would define its own proprietary imports for I/O, making plugins non-portable. WASI provides a common contract: if your plugin uses `wasi:http/outgoing-handler` to make an HTTP request, it works on any WASI-compliant runtime ([Wasmtime](https://wasmtime.dev/), WasmEdge, etc.) without modification.

### WASI Preview 2

CPEX targets **[WASI Preview 2](https://github.com/WebAssembly/WASI/tree/wasi-0.2)** (also called WASI P2 or `wasip2`), the current stable version built on top of the Component Model. Key differences from the older [Preview 1](https://github.com/WebAssembly/WASI/tree/wasi-0.1):

- **Interface-based** — capabilities are defined as WIT interfaces, not raw function imports
- **Stream-oriented I/O** — input/output uses typed streams rather than file descriptors
- **Composable** — each interface can be selectively linked or denied by the host

### How CPEX uses WASI

The host selectively links WASI interfaces based on each plugin's sandbox policy:

| WASI Interface | What it provides | When the host links it |
|----------------|------------------|------------------------|
| `wasi:io/streams` | Byte-level input/output streams | Always (required by HTTP) |
| `wasi:io/poll` | Async poll primitives | Always (required by HTTP) |
| `wasi:io/error` | I/O error types | Always |
| `wasi:clocks/monotonic-clock` | Elapsed time measurement (nanosecond precision) | Always |
| `wasi:http/types` | HTTP request/response types, headers, bodies | Always |
| `wasi:http/outgoing-handler` | Make outbound HTTP requests | Always — but the host's network hooks **deny requests at runtime** unless the target host is on the sandbox policy's allowlist |
| `wasi:filesystem/*` | Read/write preopened directories | Only when `allowed_filesystem` is configured |
| `wasi:cli/environment` | Read environment variables | Only when `allowed_env` lists specific vars |

The critical design choice: WASI interfaces are linked at compile-time, but **access control is enforced at runtime** via host hooks. For example, `wasi:http/outgoing-handler` is always available as an import, but the host's `WasiHttpHooks::send_request()` intercepts every outbound request and returns `HttpRequestDenied` if the target host isn't on the allowlist. This means plugins can be written generically against WASI without knowing their policy — the policy is applied externally.

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

### End-to-end plugin lifecycle

1. **Author** — write your plugin in Rust using the same `Plugin` and `HookHandler<H>` traits as `cpex-core`. Use `register_wasm_plugin!` to generate WIT bindings automatically.
2. **Build** — run `make` in the `cpex-wasm-plugin` crate. This compiles your code to `wasm32-wasip2` and produces a portable `.wasm` component.
3. **Configure** — define a sandbox policy in YAML specifying what the plugin is allowed to access (filesystem paths, network hosts, env vars, resource budgets) and what extension capabilities it declares.
4. **Load** — at startup, `cpex-wasm-host` reads the `.wasm` file, compiles it via Wasmtime, creates a `SandboxManager` with the configured policy, and instantiates the component in an isolated Store.
5. **Invoke** — during pipeline execution, the host calls the plugin's `handle-hook` export, passing the hook name, payload, filtered extensions, and plugin context.
6. **Return** — the plugin returns a `hook-result` (allow, deny, or modify). The host validates the result and merges any authorized modifications back into the pipeline.

### Capability filtering: before and after

The host enforces a two-phase security boundary around every invocation:

**Before the call (pre-invocation filtering):**
- The host inspects the plugin's declared capabilities (e.g., `read_labels`, `read_headers`, `write_headers`)
- Extension slots the plugin has no capability for are **stripped entirely** — the guest never receives unauthorized data
- Raw credential fields (`raw_token`, `bearer_token`) are excluded at the schema level regardless of capabilities

**After the call (post-invocation validation):**
- **Immutable tier** — slots like `request`, `agent`, `mcp`, `completion`, `provenance`, `llm`, `framework`, and `meta` are checked via Arc pointer identity. Any tampering is detected and rejected.
- **Monotonic tier** — security labels must be a superset of the originals. Label removal is always rejected.
- **Write authorization** — modifications to HTTP headers, labels, or delegation chains require the corresponding write capability (`write_headers`, `append_labels`, `append_delegation`). Unauthorized writes are discarded.
- **Filtered slot preservation** — extension slots that were hidden from the guest are preserved unchanged in the pipeline output.

This means a plugin author doesn't need to worry about accidentally seeing or leaking data they shouldn't — the host enforces boundaries on both sides of the call.

### Coexistence with native plugins

WASM plugins are not a replacement for native plugins — they coexist in the same pipeline:

- Both implement the `PluginFactory` trait, so the executor treats them identically
- A pipeline can mix native and WASM plugins in any order and execution mode
- The rest of the system (hook registry, executor, extensions) does not need to know whether a plugin is native or WASM
- Native plugins are ideal for trusted first-party logic where performance matters; WASM plugins are ideal for untrusted or third-party code where isolation matters
- Migration is incremental: you can move individual plugins from native to WASM without touching the rest of the pipeline

### The WIT contract

Each plugin exports a single function — `handle-hook` — which the host calls during the pipeline. The WIT contract (`wit/world.wit`) defines the exact types flowing across the boundary:

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

### Host-controlled execution dimensions

The host controls every dimension of the guest's execution:

| Dimension | Mechanism | Effect |
|-----------|-----------|--------|
| CPU | Fuel budget | Traps after N instructions; resets each invocation |
| Wall-clock | Epoch deadline | Interrupts after N ms (default: 5000) |
| Memory | Store limiter | Denies `memory.grow` beyond configured cap |
| Filesystem | Preopened dirs | Only listed paths visible; 6 permission levels |
| Network | Host allowlist | Only listed hosts reachable; per-host scheme/port/method rules |
| Env vars | Explicit inject | Only listed vars exist in the guest environment |
| Capabilities | Extension filter | Only permitted fields cross the boundary |

## Trade-offs

| You gain | You pay |
|----------|---------|
| Memory isolation — plugins cannot corrupt host or each other | Serialization overhead (~5-8 μs per call with full extensions) |
| Deterministic resource limits (fuel, timeout, memory cap) | Cold-start compilation on first load |
| Language flexibility — any `wasm32-wasip2` language works | No shared references or zero-copy buffers with the host |
| Declarative, auditable sandbox policy (YAML) | Debugging shows WASM offsets, not source lines (`WASMTIME_BACKTRACE_DETAILS=1` helps) |
| Safe hot-reload with no dangling state | Binary size 2-5 MB (includes allocator + std library; no runtime impact) |
| Least privilege by default — zero capabilities unless granted | WASI P2 ecosystem still evolving (async I/O, sockets) |

For a detailed capability-by-capability breakdown, see the [WASM vs Native comparison]({{< relref "_index.md#wasm-vs-native-capability-comparison" >}}).

## Next steps

- [Quickstart]({{< relref "quickstart" >}}) — build and run your first WASM plugin in under five minutes
- [Architecture]({{< relref "architecture" >}}) — detailed look at the host internals, sandbox manager, and bridge handler
