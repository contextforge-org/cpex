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

APL configs loaded into the manager use the map-keyed `routes:` form, keyed by route name. This route authorizes by role and redacts on the wire by permission:

```yaml
routes:
  get_employee:
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

Load the config into the manager and dispatch operations through it. The four phases run automatically: `args` validates `employee_id`, `authorization.pre_invocation` authorizes, `result` redacts. See [`crates/cpex-core/examples`](https://github.com/contextforge-org/cpex/tree/main/crates/cpex-core/examples) for runnable end-to-end programs that load a config and invoke a route.

The outcome matches the scenario:

- An HR caller with `view_ssn` receives the full record.
- An HR caller without `view_ssn` receives the record with `ssn` redacted before it leaves CPEX.
- A non-HR caller is denied at `require(role.hr)`; the call never reaches the backend.

## Next

- [Tutorial]({{< relref "/docs/tutorial" >}}): build this up hands-on, one capability per module, with runnable code you edit and re-run. This Quick Start is the 10-minute taste; the tutorial is the meal.
- [Use Cases]({{< relref "/docs/use-cases" >}}): the full set of controls running end-to-end behind a real gateway.
- [APL]({{< relref "/docs/apl" >}}): the full language: predicates, effects, field pipelines, phases.
- [Identity]({{< relref "/docs/apl/identity" >}}): resolving callers into the attributes policy reads.
- [PDP Integration]({{< relref "/docs/apl/pdp" >}}): delegating decisions to Cedar, CEL, or an external engine.
- [Delegation]({{< relref "/docs/apl/delegation" >}}): minting scoped downstream credentials.
