<div>
  <img alt="ContextForge Plugin Extensibility Framework (CPEX) logo" src="https://github.com/contextforge-org/cpex/blob/main/docs/images/cpex_v1.png?raw=true" height=100">
</div>

# CPEX — ContextForge Plugin Extensibility Framework

<i>A composable enforcement framework for AI agents and toolchains.</i>

[![CI](https://github.com/contextforge-org/cpex/actions/workflows/ci.yml/badge.svg)](https://github.com/contextforge-org/cpex/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![crates.io](https://img.shields.io/crates/v/cpex.svg)](https://crates.io/crates/cpex)
[![docs.rs](https://img.shields.io/docsrs/cpex)](https://docs.rs/cpex)
[![MSRV](https://img.shields.io/badge/MSRV-1.96-blue.svg)](rust-toolchain.toml)

> [!NOTE]
> **Looking for CPEX Python?** It now lives on the [`0.1.x` branch](https://github.com/contextforge-org/cpex/tree/0.1.x), maintained for backwards compatibility. `main` (`0.2`+) is the **Rust** substrate. Python bindings (PyO3) over the Rust core are coming in separate PRs.

> [**Read the project vision**](https://contextforge-org.github.io/cpex/docs/vision/) to learn why hooks, plugins, and policy are the path to agent security.

## What's CPEX?

CPEX lets you intercept, enforce, and extend application behavior through plugins without modifying core logic.

Define hook points in your application, write plugins that attach to them, and compose enforcement pipelines that run automatically.

Register your plugins once, and they run at every hook invocation — no changes to your application logic.

## Install

```bash
# Engine only (bring your own plugins):
cargo add cpex

# With the bundled builtin plugins/PDPs:
cargo add cpex --features builtins
```

The default `cpex = "0.2"` is the **engine alone** — no builtin plugins are compiled in. Opt into the bundled extension set with the `builtins` feature, everything (incl. the Valkey session store) with `full`, or a granular subset: `jwt`, `oauth`, `pii`, `audit`, `cedar`, `cel`, `valkey`.

```rust
use std::sync::Arc;
use cpex::PluginManager;

let mgr = Arc::new(PluginManager::default());

// With a builtins feature enabled, register every enabled builtin factory
// and install the APL config visitor in one call:
cpex::install_builtins(&mgr);
// ... then load a config that references the enabled plugin `kind`s.
```

Authoring plugins? Depend on the lean [`cpex-sdk`](crates/cpex-sdk) crate (the `Plugin`/`HookHandler` traits, payloads, and result types) instead of the full runtime. See [`crates/cpex-core/examples`](crates/cpex-core/examples) for runnable examples.

## Why CPEX?

AI agents execute across trust domains, calling tools, accessing data, and delegating to other agents. Adding security, governance, or policy enforcement typically means embedding that logic directly into application code, leading to duplication, tight coupling, and drift.

CPEX introduces **standardized interception hooks** between your application and its operations. Plugins attach to these hooks and run automatically, keeping enforcement logic separate from business logic.

**What you can build with CPEX:**

- **Security** — access control, prompt injection detection, data loss prevention
- **Observability** — request tracing, audit logging, metrics collection
- **Governance** — policy enforcement, compliance validation, approval workflows
- **Reliability** — rate limiting, circuit breakers, response validation

CPEX is designed for modern **AI and agent systems**, but works equally well for any application that needs **safe, modular extensibility**.

## How It Works

Your application defines **hooks** — named interception points before and after critical operations. Plugins register against these hooks and execute automatically when triggered.

```
Application  →  Hook Point  →  Plugin Manager  →  Application (remaining processing)  →  Result
                                     │
                              ┌──────┼──────┐
                              ▼      ▼      ▼
                          Plugin  Plugin  Plugin
```

The plugin manager handles registration, ordering, execution, timeouts, and error isolation. You get a deterministic pipeline with no surprises.

A plugin can **allow** execution to continue, **block** it with a violation, or **modify** the payload (with copy-on-write isolation).

### Execution Modes

Plugins run in phases in this order:

```
sequential → transform → audit → concurrent → fire_and_forget
```

| Mode | Execution | Can block? | Can modify? | Use case |
|------|-----------|:----------:|:-----------:|----------|
| `sequential` | Serial, chained | Yes | Yes | Policy enforcement + transformation |
| `transform` | Serial, chained | No | Yes | Data transformation (redaction, rewriting) |
| `audit` | Serial | No | No | Logging, monitoring, metrics |
| `concurrent` | Parallel, fail-fast | Yes | No | Independent policy gates |
| `fire_and_forget` | Background, after all phases | No | No | Telemetry, audit logs |
| `disabled` | Not loaded | — | — | Plugin off |

Error handling is configured separately with `on_error` (`fail` / `ignore` / `disable`), independent of mode.

## Workspace layout

CPEX is a Cargo workspace of focused crates:

| Crate | Description |
|-------|-------------|
| [`cpex`](crates/cpex) | Host facade — re-exports the runtime and (optionally) the builtins |
| [`cpex-core`](crates/cpex-core) | Plugin runtime — `PluginManager`, executor, hooks, config |
| [`cpex-sdk`](crates/cpex-sdk) | Plugin author SDK — `Plugin`/`HookHandler` traits, payloads, results |
| [`cpex-orchestration`](crates/cpex-orchestration) | Async concurrency primitives shared by the runtime |
| [`cpex-builtins`](crates/cpex-builtins) | Feature-gated bundle of builtin plugins, PDPs, session stores |
| [`cpex-ffi`](crates/cpex-ffi) | C FFI (`cdylib`/`staticlib`) for Go / Python / WASM host bindings |
| [`apl-core`](crates/apl-core) · [`apl-cmf`](crates/apl-cmf) · [`apl-cpex`](crates/apl-cpex) | APL — Attribute Policy Language: compiler/evaluator, CMF bridge, CPEX integration |
| `builtins/*` | Bundled plugins (PII scanner, audit logger, JWT identity, OAuth/Biscuit delegation), PDPs (Cedar, CEL), and the Valkey session store |

The C FFI is distributed as signed prebuilt artifacts — see [`crates/cpex-ffi/RELEASE.md`](crates/cpex-ffi/RELEASE.md). Go bindings live in [`go/cpex`](go/cpex).

## Development

CPEX targets Rust **1.96** (pinned in [`rust-toolchain.toml`](rust-toolchain.toml)). Common tasks:

```bash
make lint        # rustfmt --check + clippy -D warnings
make test        # cargo test --workspace
make audit       # cargo deny check (advisories, licenses, bans, sources)
make examples-build   # build all Rust + Go examples
make ci          # the full local gate (lint + test + examples)
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full workflow and [SECURITY.md](SECURITY.md) to report vulnerabilities.

## Project Status

CPEX is under active development as part of the [ContextForge](https://github.com/contextforge-org) ecosystem. The framework is designed to work across AI gateways, agent frameworks, LLM proxies, and tool servers.

## License

[Apache 2.0](LICENSE)
