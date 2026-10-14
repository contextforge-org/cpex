---
title: "Quick Start"
weight: 20
---

# Quick Start

This walks through standing up CPEX as an enforcement point and running the [scenario]({{< relref "/docs/overview" >}}): the `get_employee` route that authorizes by role and redacts a field by permission.

You need Rust 1.96 or newer ([install with rustup](https://rustup.rs)). Section 4 runs the tutorial's first module, which lives in the repo, so clone it first: `git clone https://github.com/contextforge-org/cpex.git && cd cpex`, and run `cargo` commands from that root.

Upgrading from 0.2.x? Read [Migrating to 0.3]({{< relref "/docs/migration-0.3" >}}) first.

## 1. Add CPEX

```bash
cargo add cpex
```

`cpex` is a facade over the praxis-policy engine (PPE). It compiles in every bundled builtin: JWT and API-key identity, OAuth delegation, CIBA approval, the Cedar, CEL and OPA decision points, the Valkey session store, the Vault secret provider, and an outbound HTTP transport. There are no feature flags to pick; see [Builtins]({{< relref "/docs/builtins" >}}).

## 2. Register the runtime

Create a `PolicyEngine`, register the builtin factories and the APL config visitor, and install the HTTP transport the builtins use to reach an IdP:

```rust
use std::sync::Arc;
use cpex::PolicyEngine;

let engine = Arc::new(PolicyEngine::default());
cpex::install_builtins(&engine);
cpex::install_default_http_transport(&engine);
```

After this, the engine knows every builtin `kind`, and APL routes can reference them. The bundled transport refuses private and loopback destinations. To reach a local IdP during development, install `HyperTransport::new().with_allow_private_destinations()` with `engine.set_http_transport(...)` instead; see [Builtins]({{< relref "/docs/builtins#the-http-transport" >}}) for what that switch opens up.

## 3. Write the policy

`routes:` is a list, one entry per operation. This route matches the `get_employee` tool, authorizes by role, and redacts on the wire by permission:

```yaml
plugins:
  - name: jwt-user
    kind: identity/jwt
    hooks: [identity.resolve]
    capabilities: [perform_http]     # it fetches the IdP's JWKS
    config:
      role: user
      header: X-User-Token
      trusted_issuers:
        - issuer: "https://idp.example.com/realms/agents"
          audiences: ["cpex-gateway"]
          decoding_key:
            kind: jwks_url
            url: "https://idp.example.com/realms/agents/protocol/openid-connect/certs"

routes:
  - tool: get_employee
    authentication: [jwt-user]
    args:
      employee_id: "str"
    authorization:
      pre_invocation:
        - "require(authenticated)"
        - "require(role.hr)"
    result:
      ssn: "str | redact(!perm.view_ssn)"
      salary: "int | redact(!role.hr)"
      employee_id: "str | mask(4)"
```

The `require(authenticated)` and `require(role.hr)` predicates read attributes resolved from the caller's verified token. `authentication: [jwt-user]` names the identity plugin that resolves them; a route that does not list one runs no identity resolution. How those attributes get populated is covered in [Identity]({{< relref "/docs/apl/identity" >}}).

The host selects the route for each request from the request's entity metadata (`meta.entity_type: tool`, `meta.entity_name: get_employee`). A request without it resolves no route and is denied with `unidentified_request`.

## 4. Run it

The fastest way to see CPEX actually run is the tutorial's first module, a complete program you can execute now:

```bash
cargo run -p cpex-tutorial --example m01_hello
```

It builds a `PolicyEngine`, installs the builtins and a transport, loads a policy, and dispatches two operations. The setup is the lines a host writes:

```rust
let engine = Arc::new(PolicyEngine::default());
cpex::install_builtins(&engine);
cpex_tutorial::install_http_transport(&engine); // allows a local IdP; not for production
engine.load_config_yaml(policy).unwrap();
engine.initialize().await.unwrap();
```

Expected output:

```
▸ anonymous → get_compensation (route requires authentication)
  ✗ DENIED   [routes.tool:get_compensation.pre_invocation[0]] access denied

▸ anonymous → search_repos (route has no rule)
  ✓ ALLOWED  {"visibility":"public","repositories":[{"name":"brand-site","visibility":"public"}]}
```

The `get_employee` policy above follows the same model. Once a caller has an identity (tutorial [module 2]({{< relref "/docs/tutorial/02-identity" >}})), its `result` pipeline produces the redaction outcomes (tutorial [module 3]({{< relref "/docs/tutorial/03-shaping" >}})):

- An HR caller with `view_ssn` receives the full record.
- An HR caller without `view_ssn` receives the record with `ssn` redacted before it leaves CPEX.
- A non-HR caller is denied at `require(role.hr)`; the call never reaches the backend.

## From Python or Go

The same engine ships as a Python package and a Go module. Both install the builtins, the transport and the secret providers for you.

```python
from cpex import PolicyEngine

engine = PolicyEngine("policy.yaml")           # allow_private_destinations=True for a local IdP
await engine.initialize()
result = await engine.invoke_hook(
    "cmf.tool_pre_invoke",
    payload,
    {"meta": {"entity_type": "tool", "entity_name": "get_employee"}},
)
```

```go
engine, _ := cpex.NewPolicyEngineDefault()
engine.EnableAPL()                              // cpex.WithPrivateDestinations() for a local IdP
engine.LoadConfig(yaml)
engine.Initialize()
```

See the [Python bindings README](https://github.com/contextforge-org/cpex/tree/main/bindings/python) and the [Go package README](https://github.com/contextforge-org/cpex/tree/main/go/cpex).

## Next

- [Tutorial]({{< relref "/docs/tutorial" >}}): build this up hands-on, one capability per module, with runnable code you can edit and re-run.
- [Use Cases]({{< relref "/docs/use-cases" >}}): the full set of controls running end-to-end behind a real gateway.
- [APL]({{< relref "/docs/apl" >}}): the full language: predicates, effects, field pipelines, phases.
- [Identity]({{< relref "/docs/apl/identity" >}}): resolving callers into the attributes policy reads.
- [PDP Integration]({{< relref "/docs/apl/pdp" >}}): delegating decisions to Cedar, CEL, OPA or an external engine.
- [Delegation]({{< relref "/docs/apl/delegation" >}}): minting scoped downstream credentials.
