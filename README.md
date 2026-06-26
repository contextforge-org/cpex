<div>
  <img alt="CPEX logo" src="https://github.com/contextforge-org/cpex/blob/main/docs/images/cpex_v1.png?raw=true" height=100">
</div>

# CPEX

<i>A policy enforcement runtime for AI agents.</i>

[![CI](https://github.com/contextforge-org/cpex/actions/workflows/ci.yml/badge.svg)](https://github.com/contextforge-org/cpex/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![crates.io](https://img.shields.io/crates/v/cpex.svg)](https://crates.io/crates/cpex)
[![docs.rs](https://img.shields.io/docsrs/cpex)](https://docs.rs/cpex)
[![MSRV](https://img.shields.io/badge/MSRV-1.96-blue.svg)](rust-toolchain.toml)

> [!NOTE]
> **Looking for CPEX Python?** It now lives on the [`0.1.x` branch](https://github.com/contextforge-org/cpex/tree/0.1.x), maintained for backwards compatibility. `main` (`0.2`+) is the **Rust** framework, re-architected around policy and authorization. The reposition is a re-architecture, not an abandonment. Python bindings (PyO3) over the Rust core are coming.

## What's CPEX?

CPEX is a policy enforcement runtime for AI agents.

It acts as a deterministic reference monitor between an agent and every capability it invokes: tools, prompts, resources, inference providers, and A2A methods. Every operation is evaluated against security state the model cannot observe or influence—identity, delegation chains, information-flow labels, and an append-only audit log.

Instead of scattering authorization, delegation, redaction, auditing, and information-flow controls across application code, CPEX executes them as a single policy-defined pipeline. Identity can be resolved, an external PDP consulted, credentials exchanged, inputs or outputs transformed, session state updated, and the operation audited—all within one deterministic flow.

<div>
  <img alt="CPEX mediates every operation an untrusted LLM triggers, evaluating APL policy against identity, delegation, taint, and audit state the model cannot forge" src="https://github.com/contextforge-org/cpex/blob/main/docs/static/images/cpex_overview.png?raw=true" />
</div>

## Policy lives on the entity

APL is a declarative policy language designed around capabilities rather than requests.

Every entity an agent can invoke—a tool, resource, prompt, or A2A method—owns its own policy. Each policy executes in two phases: before invocation and after the result. Most policies fit comfortably on a single screen.

A route identifies an entity and defines the enforcement pipeline. Predicates decide whether execution may continue (`require`). PDPs evaluate external authorization (`cel`, `cedar`, or custom resolvers). Effects perform enforcement (`delegate`, `redact`, `taint`, `run`). Steps execute deterministically, in order, with only the context they explicitly declare.

## End-to-end enforcement, multiple security contexts

The example below places CPEX between a single agent and three backends: HR records, source repositories, and email. The agent remains unchanged. Policy adapts each operation to the caller's identity, permissions, and session state.

<div>
  <img alt="One agent serves three users across HR, repo, and email backends; CPEX policy produces a different outcome per identity" src="https://github.com/contextforge-org/cpex/blob/main/docs/static/images/demo_scenario.png?raw=true" />
</div>

One policy defines three distinct enforcement pipelines, one for each entity.

```yaml
routes:
  # HR lookup: gate on role, scope a downstream token, redact by permission, taint the session.
  - tool: get_compensation
    policy:
      - "require(role.hr)"
      - "delegate(workday-oauth, target: workday-api, permissions: [read_compensation])"
      - "taint(secret, session)"
      - "run(audit-log)"
    result:
      ssn: "str | redact(!perm.view_ssn)"

  # Repo search: gate on team, decide with CEL (or Cedar), require the scoped grant.
  - tool: search_repos
    policy:
      - "require(team.engineering | team.security)"
      - cel:
          expr: "(role.engineer && args.visibility == 'internal') || role.security"
          on_deny: ["deny('engineers read internal only; security reads any', 'cel.policy_denied')"]
      - "delegate(github-oauth, target: github-api, permissions: [repo:read:internal])"
      - "run(audit-log)"

  # Outbound email: refuse if the session already touched secret data.
  - tool: send_email
    policy:
      - "require(perm.email_send)"
      - "run(pii-scan)"
      - "security.labels contains \"secret\": deny('write-down blocked', 'session_tainted')"
      - "run(audit-log)"
```

Two examples illustrate the behavior:

- **Same request, different result.** An HR analyst with `view_ssn` receives the full record. Without that permission, the SSN is redacted before the response leaves CPEX. Engineers never reach the backend because the request is rejected by `require(role.hr)`.

- **Information follows the session.** Reading compensation data taints the session. Later attempts to send external email are blocked—even if the email itself contains no sensitive content.

The application stays the same. Only the policy changes.

## Beyond request-level authorization

RBAC, ABAC, Cedar, OPA, AuthZEN, and similar systems answer an important question:

> Should this request be allowed?

CPEX answers a broader one:

> What security pipeline should execute for this agent operation?

That pipeline can combine request authorization with credential delegation, response transformation, information-flow tracking, auditing, and session state into a single deterministic policy.

Three capabilities distinguish this model:

- **Information flow across operations.** Policy can carry security state across an entire agent session, preventing write-down and other cross-call attacks rather than evaluating each request in isolation.

- **Delegation as policy.** OAuth token exchange (RFC 8693), capability reduction, and downstream credential verification become ordinary policy steps instead of bespoke integration code.

- **Decision orchestration.** Existing authorization systems remain the source of truth. APL invokes Cedar, CEL, OPA, AuthZEN, or custom resolvers wherever a decision is needed, while CPEX enforces the resulting security pipeline.

## Where it runs

CPEX enforces policy wherever an agent crosses a trust boundary.

It can run in front of tool servers, beside an agent as an egress sidecar, inside an agent framework, or as middleware between components. The enforcement point can move without changing policy, allowing the same APL configuration to span gateways, agents, and services.

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

CPEX is under active development as part of the ContextForge ecosystem.

The project is designed as a reusable enforcement layer for agentic systems, integrating with AI gateways, agent frameworks, LLM proxies, MCP servers, and other capability providers through a common policy model.

## License

[Apache 2.0](LICENSE)
