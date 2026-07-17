---
title: "Quick Start"
weight: 20
---

# Quick Start

This walks through standing up CPEX as an enforcement point and running the [scenario]({{< relref "/docs/overview" >}}): the `get_employee` route that authorizes by role and redacts a field by permission.

## 1. Add CPEX

```bash
cargo add cpex --features builtins
```

The `builtins` feature compiles in the bundled plugins and PDPs (JWT identity, OAuth delegation, PII scanner, audit logger, Cedar, CEL). For a smaller build, opt into a granular subset: `jwt`, `cedar`, `pii`, and so on (see [Builtins]({{< relref "/docs/builtins" >}})).

## 2. Register the runtime

Create a `PluginManager`, register the enabled builtin factories, and install the APL config visitor in one call:

```rust
use std::sync::Arc;
use cpex::PluginManager;

let mgr = Arc::new(PluginManager::default());
cpex::install_builtins(&mgr);
```

After this, the manager knows every builtin `kind` your features enabled, and APL routes can reference them.

## 3. Write the policy

`routes:` is a list, one entry per operation. This route matches the `get_employee` tool, authorizes by role, and redacts on the wire by permission:

```yaml
routes:
  - tool: get_employee
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

The `require(authenticated)` and `require(role.hr)` predicates read attributes resolved from the caller's verified token. How those attributes get populated is covered in [Identity]({{< relref "/docs/apl/identity" >}}); for now, an identity plugin (for example `identity/jwt`) resolves the subject and roles before policy runs.

## 4. Run it

The fastest way to see CPEX actually run is the tutorial's first module, a complete program you can execute now:

```bash
cargo run -p cpex-tutorial --example m01_hello
```

It builds a `PluginManager`, installs the builtins, loads a policy, and dispatches two operations. The setup is the four lines a host writes:

```rust
let mgr = Arc::new(PluginManager::default());
cpex::install_builtins(&mgr);
mgr.load_config_yaml(policy).unwrap();
mgr.initialize().await.unwrap();
```

Expected output:

```
▸ anonymous → get_compensation (route requires authentication)
  ✗ DENIED   [routes.tool:get_compensation.apl.pre_invocation[0]] access denied

▸ anonymous → search_repos (route has no rule)
  ✓ ALLOWED  {"visibility":"public","repositories":[{"name":"brand-site","visibility":"public"}]}
```

The `get_employee` policy above follows the same model. Once a caller has an identity (tutorial [module 2]({{< relref "/docs/tutorial/02-identity" >}})), its `result` pipeline produces the redaction outcomes (tutorial [module 3]({{< relref "/docs/tutorial/03-shaping" >}})):

- An HR caller with `view_ssn` receives the full record.
- An HR caller without `view_ssn` receives the record with `ssn` redacted before it leaves CPEX.
- A non-HR caller is denied at `require(role.hr)`; the call never reaches the backend.

## Next

- [Tutorial]({{< relref "/docs/tutorial" >}}): build this up hands-on, one capability per module, with runnable code you can edit and re-run.
- [Use Cases]({{< relref "/docs/use-cases" >}}): the full set of controls running end-to-end behind a real gateway.
- [APL]({{< relref "/docs/apl" >}}): the full language: predicates, effects, field pipelines, phases.
- [Identity]({{< relref "/docs/apl/identity" >}}): resolving callers into the attributes policy reads.
- [PDP Integration]({{< relref "/docs/apl/pdp" >}}): delegating decisions to Cedar, CEL, or an external engine.
- [Delegation]({{< relref "/docs/apl/delegation" >}}): minting scoped downstream credentials.
