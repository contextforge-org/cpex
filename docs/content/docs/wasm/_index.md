---
title: "WebAssembly Plugins"
weight: 50
bookCollapseSection: false
---

# WebAssembly Plugins

Run plugins in sandboxed WebAssembly instead of trusting them with full process access.

CPEX plugins inspect and modify requests flowing through the hook pipeline — tool calls, LLM messages, identity checks, token delegation. The `cpex-wasm-host` crate lets you execute those plugins inside a Wasmtime sandbox where each plugin gets:

- **Isolated linear memory** — no shared address space with the host or other plugins
- **No filesystem/network/env access** unless explicitly granted via sandbox policy
- **CPU budget** — fuel-based instruction limits prevent runaway computation
- **Wall-clock timeout** — epoch-based interruption catches infinite loops and blocking calls
- **Capability-filtered extensions** — plugins only see the extension fields their config allows

## When to use WASM plugins

| Scenario | Recommended approach |
|----------|---------------------|
| First-party plugin, same repo | Native (in-process) — no overhead |
| Third-party or untrusted plugin | **WASM** — sandbox enforces least privilege |
| Multi-language plugin authors | **WASM** — any language targeting `wasm32-wasip2` works |
| Strict compliance / auditing | **WASM** — policy is declarative YAML, auditable |
| Performance-critical hot path | Native — avoid serialization overhead |

## What's in this section

- [Introduction]({{< relref "introduction" >}}) — what WebAssembly is, the Component Model, and trade-offs
- [Quickstart]({{< relref "quickstart" >}}) — build and run your first WASM plugin in minutes
- [Architecture]({{< relref "architecture" >}}) — how the host, sandbox, and guest interact
- [cpex-wasm-plugin (Guest SDK)]({{< relref "cpex-wasm-plugin" >}}) — writing plugins, WIT interface, build commands
- [cpex-wasm-host (Host Runtime)]({{< relref "cpex-wasm-host" >}}) — loading, sandboxing, and invoking plugins
- [Sandboxing Details]({{< relref "sandboxing-details" >}}) — filesystem, env, network, and resource permissions
- [Benchmarking]({{< relref "benchmarking" >}}) — performance measurements and optimization guidance
- [Tutorials]({{< relref "tutorials" >}}) — hands-on walkthroughs with the built-in demos
