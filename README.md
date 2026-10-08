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
> **Looking for the pure-Python CPEX framework?** It lives on the [`0.1.x` branch](https://github.com/contextforge-org/cpex/tree/0.1.x), maintained for backwards compatibility. `main` (`0.2`+) is the policy-first runtime, with Rust, Python and Go APIs.
>
> **Upgrading from 0.2?** CPEX 0.3 runs on the [praxis-policy engine](https://github.com/praxis-proxy/policy) (PPE) and renames the API, hook names and several config keys. See the [migration guide](https://contextforge-org.github.io/cpex/docs/migration-0.3/).

## What's CPEX?

CPEX is a policy enforcement runtime for AI agents.

It acts as a deterministic reference monitor between an agent and every capability it invokes: tools, prompts, resources, inference providers, and A2A methods. Every operation is evaluated against security state the model cannot observe or influence, including identity, delegation and escalation chains, information-flow labels, and audit log.

CPEX composes authorization, delegation, redaction, information-flow tracking, and auditing into a single policy-defined pipeline. Every operation executes the same deterministic sequence, from identity resolution and policy evaluation through credential delegation, data transformation, session updates, out-of-band approvals, and auditing.

<div>
  <img alt="CPEX mediates every operation an untrusted LLM triggers, evaluating APL policy against identity, delegation, taint, and audit state the model cannot forge" src="https://github.com/contextforge-org/cpex/blob/main/docs/static/images/cpex_overview.png?raw=true" />
</div>

## Enforcement pipelines

Each capability exposed to an agent defines its own enforcement pipeline, whether it's a tool, resource, prompt, or A2A method.

APL is the configuration that defines that pipeline. A _route_ identifies an entity and sequences the controls that protect it: resolve identity, consult an external PDP, exchange credentials, invoke plugins, redact results, propagate taint, and audit the operation. Each step executes deterministically, in order, with only the context it explicitly declares.

Policies execute in two phases, before the operation and after its result, making the complete enforcement pipeline easy to inspect and reason about.

## Context-aware enforcement

The example below places CPEX between a single agent and three backends: HR records, source repositories, and email. The agent remains unchanged. Policy adapts each operation to the caller's identity, permissions, and session state.

<div>
  <img alt="One agent serves three users across HR, repo, and email backends; CPEX policy produces a different outcome per identity" src="https://github.com/contextforge-org/cpex/blob/main/docs/static/images/demo_scenario.png?raw=true" />
</div>

One policy defines three distinct enforcement pipelines, one for each entity.

```yaml
global:
  authentication: [jwt-user]   # resolve the caller's identity on every route

routes:
  # HR lookup: gate on role, scope a downstream token, redact by permission, taint the session.
  - tool: get_compensation
    authorization:
      pre_invocation:
        - "require(role.hr)"
        - "delegate(workday-oauth, target: workday-api, permissions: [read_compensation])"
        - "taint(secret, session)"
        - "run(audit-log)"
    result:
      ssn: "str | redact(!perm.view_ssn)"

  # Repo search: gate on team, decide with CEL (or Cedar), require the scoped grant.
  - tool: search_repos
    authorization:
      pre_invocation:
        - "require(team.engineering | team.security)"
        - cel:
            expr: "(role.engineer && args.visibility == 'internal') || role.security"
            on_deny: ["deny('engineers read internal only; security reads any', 'cel.policy_denied')"]
        - "delegate(github-oauth, target: github-api, permissions: [repo:read:internal])"
        - "run(audit-log)"

  # Outbound email: refuse if the session already touched secret data.
  - tool: send_email
    authorization:
      pre_invocation:
        - "require(perm.email_send)"
        - "security.labels contains \"secret\": deny('write-down blocked', 'session_tainted')"
        - "run(audit-log)"
```

Two examples illustrate the behavior:

- **Same request, different result.** An HR analyst with `view_ssn` receives the full record. Without that permission, the SSN is redacted before the response leaves CPEX. Engineers never reach the backend because the request is rejected by `require(role.hr)`.

- **Information follows the session.** Reading compensation data taints the session. Later attempts to send external email are blocked, even if the email itself contains no sensitive content.

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
cargo add cpex                 # Rust
pip install maturin && (cd bindings/python && maturin develop)   # Python, from a checkout
go get github.com/contextforge-org/cpex/go/cpex                # Go (links the signed libcpex_ffi artifact)
```

`cpex = "0.3"` compiles in every bundled builtin: JWT and API-key identity, OAuth delegation, CIBA approval, the Cedar, CEL and OPA decision points, the Valkey session store, the Vault secret provider, and an outbound HTTP transport. The one optional feature is `python-host`, which runs existing Python CPEX plugins out of process.

```rust
use std::sync::Arc;
use cpex::PolicyEngine;

let engine = Arc::new(PolicyEngine::default());
// Register every builtin factory and install the APL config visitor:
cpex::install_builtins(&engine);
// Builtins that call out (JWKS, token exchange, CIBA, Vault) borrow this
// transport. It refuses private and loopback destinations by default.
cpex::install_default_http_transport(&engine);
engine.load_config_yaml(yaml)?;
engine.initialize().await?;
```

```python
from cpex import PolicyEngine

engine = PolicyEngine("policy.yaml")   # builtins, transport and secret providers installed
await engine.initialize()
```

```go
engine, _ := cpex.NewPolicyEngineDefault()
engine.EnableAPL()                     // builtins, transport and secret providers
engine.LoadConfig(yaml)
engine.Initialize()
```

`run(audit-log)` in the example above names a host plugin. CPEX ships no audit or PII-scanner plugin of its own; see [Builtins](https://contextforge-org.github.io/cpex/docs/builtins/). Writing a plugin? Implement it against `cpex::prelude` and register it with `engine.register_factory`; the [tutorial](examples/tutorial) shows how.

## Documentation

- [**Vision**](https://contextforge-org.github.io/cpex/docs/vision/): the reference-monitor model and where CPEX sits.
- [**Overview**](https://contextforge-org.github.io/cpex/docs/overview/): the scenario above end to end.
- [**Quick Start**](https://contextforge-org.github.io/cpex/docs/quickstart/): stand up CPEX as an enforcement point.
- [**Use Cases**](https://contextforge-org.github.io/cpex/docs/use-cases/): complete integration examples with external middleware projects.
- [**Tutorial**](https://contextforge-org.github.io/cpex/docs/tutorial/): a complete tour of the framework.
- [**APL**](https://contextforge-org.github.io/cpex/docs/apl/): the policy pipeline configuration: predicates, effects, sequencing, field pipelines.
- [**Migrating to 0.3**](https://contextforge-org.github.io/cpex/docs/migration-0.3/): every API, hook and config change from 0.2.x.

## Workspace layout

The engine, the APL compiler and runtime, and the builtins come from the [praxis-policy](https://github.com/praxis-proxy/policy) crates on crates.io, pinned to an exact version. This repository holds what CPEX adds:

| Path | Description |
|------|-------------|
| [`crates/cpex`](crates/cpex) | Host facade: re-exports `praxis-policy` (`PolicyEngine`, `install_builtins`, `prelude`, the builtin factories, `HyperTransport`) |
| [`crates/cpex-hosts-python`](crates/cpex-hosts-python) | Runs existing Python CPEX plugins out of process, one virtualenv per plugin (`python-host` feature) |
| [`crates/cpex-ffi`](crates/cpex-ffi) | C ABI v3 (`cdylib`/`staticlib`) used by the Go package |
| [`builtins/plugins/delegator-biscuit`](builtins/plugins/delegator-biscuit) | Biscuit capability-token delegator |
| [`bindings/python`](bindings/python) | PyO3 bindings: the Python `cpex` package |
| [`go/cpex`](go/cpex) | Go bindings over the C ABI |
| [`examples/tutorial`](examples/tutorial), [`examples/go-demo`](examples/go-demo) | Runnable tutorial modules and Go demos |

The 0.2.x crates (`cpex-core`, `cpex-sdk`, `cpex-builtins`, `apl-core`, the `cpex-plugin-*` and `cpex-pdp-*` crates, and others) are no longer built; their 0.2.3 releases stay on crates.io. The C FFI is distributed as signed prebuilt artifacts. See [`crates/cpex-ffi/RELEASE.md`](crates/cpex-ffi/RELEASE.md).

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
