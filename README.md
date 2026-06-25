<div>
  <img alt="CPEX logo" src="https://github.com/contextforge-org/cpex/blob/main/docs/images/cpex_v1.png?raw=true" height=100">
</div>

# CPEX

<i>A policy and authorization framework for agentic applications.</i>

[![CI](https://github.com/contextforge-org/cpex/actions/workflows/ci.yml/badge.svg)](https://github.com/contextforge-org/cpex/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![crates.io](https://img.shields.io/crates/v/cpex.svg)](https://crates.io/crates/cpex)
[![docs.rs](https://img.shields.io/docsrs/cpex)](https://docs.rs/cpex)
[![MSRV](https://img.shields.io/badge/MSRV-1.96-blue.svg)](rust-toolchain.toml)

> [!NOTE]
> **Looking for CPEX Python?** It now lives on the [`0.1.x` branch](https://github.com/contextforge-org/cpex/tree/0.1.x), maintained for backwards compatibility. `main` (`0.2`+) is the **Rust** framework, re-architected around policy and authorization. The reposition is a re-architecture, not an abandonment. Python bindings (PyO3) over the Rust core are coming.

## What's CPEX?

CPEX is a deterministic reference monitor between an untrusted agent and the capabilities it invokes.

AI agents can be steered by injected content, confused by tool output, or simply make mistakes. CPEX mediates every operation an agent triggers (tool calls, A2A methods, inference calls, prompt and resource fetches) against state the agent cannot see or forge: identity, delegation chains, taint labels, and an append-only audit log.

<div>
  <img alt="CPEX mediates every operation an untrusted LLM triggers, evaluating APL policy against identity, delegation, taint, and audit state the model cannot forge" src="https://github.com/contextforge-org/cpex/blob/main/docs/static/images/cpex_overview.png?raw=true" />
</div>

You write policy in APL (Authorization Policy Language): declarative, attribute-based rules with explicit effects. CPEX evaluates that policy at the boundary and enforces the result, allowing, denying, redacting, delegating, or tainting before the operation proceeds.

## Same request, different data

Three callers issue the identical `get_compensation` request. The backend returns the same record. What each receives differs, because policy decides per identity.

```yaml
routes:
  - tool: get_compensation
    policy:
      - "require(role.hr)"
    result:
      ssn: "str | redact(!perm.view_ssn)"
```

- An HR analyst with `view_ssn` gets the full record.
- An HR analyst without `view_ssn` gets the record with the SSN redacted before it leaves CPEX. The backend never sees the difference.
- An engineer is denied at `require(role.hr)`. The call never reaches the backend.

No application code changed between the three outcomes. The policy did.

## What you can express

APL composes the controls an agent stack needs, evaluated against identity claims, relationships, roles, and attributes (ReBAC, RBAC, ABAC). A few sketches:

**Authorization** on both request inputs and response outputs, for tools, resources, prompts, A2A methods, and other agent interfaces:

```yaml
policy:
  - "require(role.hr | role.security)"
args:
  region: "enum(us, eu, apac)"        # validate inputs
result:
  salary: "int | redact(!perm.view_comp)"   # redact outputs by permission
```

**PDP composition**: gate with your preferred policy engine (CEL and Cedar ship as builtins; OPA, AuthZEN, and NeMo are recognized dialects you wire to a host resolver):

```yaml
policy:
  - cel:
      expr: "subject.department == 'compliance' || 'admin' in subject.roles"
    on_deny:
      - "deny('not permitted by policy', 'pdp_denied')"
```

**Delegation** as an explicit effect: RFC 8693 token exchange that scopes and reduces privilege before downstream calls, verified after the exchange:

```yaml
policy:
  - "delegate(workday-oauth, target: workday-api, permissions: [read_compensation])"
  - "delegation.granted.permissions contains 'read_compensation': allow"
```

**Information-flow control**: session tainting that detects and blocks write-down, for example refusing an external send after the session touched secret data:

```yaml
# get_compensation taints the session
policy: ["require(role.hr)", "taint(secret, session)"]
# send_email, later in the same session, refuses even with a clean body
policy:
  - "require(perm.email_send)"
  - "security.labels contains \"secret\": deny('write-down blocked', 'session_tainted')"
```

The pipeline underneath (hooks, the plugin manager, execution modes) is the mechanism that runs policy effects. It is the supporting layer. APL is how you express intent; the pipeline is how that intent executes. Plugins are capability-gated, so an effect only sees the context it declares.

## Where it runs

CPEX is direction-agnostic. The same policy enforces whether CPEX sits in front of a tool server as a gateway, beside an agent as an egress sidecar, or inside an agent framework. Move the enforcement point; keep the policy.

## Install

```bash
# Engine only (bring your own plugins):
cargo add cpex

# With the bundled builtin plugins/PDPs:
cargo add cpex --features builtins
```

The default `cpex = "0.2"` is the **engine alone**. Opt into the bundled extension set with the `builtins` feature, everything (incl. the Valkey session store) with `full`, or a granular subset: `jwt`, `oauth`, `pii`, `audit`, `cedar`, `cel`, `valkey`.

```rust
use std::sync::Arc;
use cpex::PluginManager;

let mgr = Arc::new(PluginManager::default());

// With a builtins feature enabled, register every enabled builtin factory
// and install the APL config visitor in one call:
cpex::install_builtins(&mgr);
// ... then load an APL config that references the enabled plugin `kind`s.
```

Authoring plugins or PDP resolvers? Depend on the lean [`cpex-sdk`](crates/cpex-sdk) crate instead of the full runtime. See [`crates/cpex-core/examples`](crates/cpex-core/examples) for runnable examples.

## Documentation

- [**Vision**](https://contextforge-org.github.io/cpex/docs/vision/): the reference-monitor model and where CPEX sits.
- [**Overview**](https://contextforge-org.github.io/cpex/docs/overview/): the model in motion, with the scenario above end to end.
- [**APL**](https://contextforge-org.github.io/cpex/docs/apl/): the policy language: predicates, effects, sequencing, field pipelines.
- [**Quick Start**](https://contextforge-org.github.io/cpex/docs/quickstart/): stand up CPEX as an enforcement point.

## Workspace layout

CPEX is a Cargo workspace of focused crates:

| Crate | Description |
|-------|-------------|
| [`cpex`](crates/cpex) | Host facade, re-exports the runtime and (optionally) the builtins |
| [`cpex-core`](crates/cpex-core) | Plugin runtime: `PluginManager`, executor, hooks, config |
| [`cpex-sdk`](crates/cpex-sdk) | Plugin author SDK: `Plugin`/`HookHandler` traits, payloads, results |
| [`cpex-orchestration`](crates/cpex-orchestration) | Async concurrency primitives shared by the runtime |
| [`cpex-builtins`](crates/cpex-builtins) | Feature-gated bundle of builtin plugins, PDPs, session stores |
| [`cpex-ffi`](crates/cpex-ffi) | C FFI (`cdylib`/`staticlib`) for Go / Python / WASM host bindings |
| [`apl-core`](crates/apl-core) · [`apl-cmf`](crates/apl-cmf) · [`apl-cpex`](crates/apl-cpex) | APL (Authorization Policy Language): compiler/evaluator, CMF bridge, CPEX integration |
| `builtins/*` | Bundled plugins (PII scanner, audit logger, JWT identity, OAuth/Biscuit delegation), PDPs (Cedar, CEL), and the Valkey session store |

The C FFI is distributed as signed prebuilt artifacts. See [`crates/cpex-ffi/RELEASE.md`](crates/cpex-ffi/RELEASE.md). Go bindings live in [`go/cpex`](go/cpex).

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

CPEX is under active development as part of the [ContextForge](https://github.com/contextforge-org) ecosystem. It is designed to work across AI gateways, agent frameworks, LLM proxies, and tool servers.

## License

[Apache 2.0](LICENSE)
