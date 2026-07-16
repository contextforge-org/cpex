---
title: "Hello, enforcement"
weight: 2
---

# Module 1: Hello, enforcement

> You are in the [CPEX tutorial]({{< relref "_index" >}}). No IdP needed for this module.

**Goal:** stand up the smallest possible CPEX enforcement point and see a route allow one call and deny another, with no application logic making the decision.

## The problem

You have tools an agent can call. Some should be gated, some open. You do not want that decision scattered through handler code, where it drifts and is hard to audit. You want it in one place, declarative, at the boundary.

## Build it

The host is three lines plus loading a policy. From [`examples/tutorial/examples/m01_hello.rs`](https://github.com/contextforge-org/cpex/tree/main/examples/tutorial/examples/m01_hello.rs):

```rust
let mgr = Arc::new(PluginManager::default());
cpex::install_builtins(&mgr);               // register the bundled plugins + APL visitor
mgr.load_config_yaml(POLICY).unwrap();      // load policies/m01.yaml
mgr.initialize().await.unwrap();
```

The policy ([`policies/m01.yaml`](https://github.com/contextforge-org/cpex/tree/main/examples/tutorial/policies/m01.yaml)) defines two routes:

```yaml
routes:
  - tool: get_compensation
    authorization:
      pre_invocation:
        - "require(authenticated)"    # denies an anonymous caller
  - tool: search_repos
    authorization:
      pre_invocation: []              # no rule, so open
```

Each call goes through `mediate()`, the harness wrapper around the loop a host owns: resolve identity, run policy, call the backend, run policy on the result. It is harness code, not a CPEX API. Module 9 opens it up.

## Run it

```bash
cargo run -p cpex-tutorial --example m01_hello
```

```
▸ anonymous → get_compensation (route requires authentication)
  ✗ DENIED   [routes.tool:get_compensation.apl.pre_invocation[0]] access denied

▸ anonymous → search_repos (route has no rule)
  ✓ ALLOWED  {"visibility":"public","repositories":[{"name":"brand-site","visibility":"public"}]}
```

Same anonymous caller, same host code. The route decided the outcome, and the denial names the exact rule that failed.

{{< asciinema cast="https://asciinema.org/a/GWQ1rUgWufRxMUcE.cast" poster="npt:0:03" >}}

## Try it

1. Change the failing predicate. In `policies/m01.yaml`, change `require(authenticated)` to `require(role.hr)` and re-run. Expect: `get_compensation` still denies, but the reason points at the new rule, since nobody has a role yet.
2. Open the gated route. Delete the `require(authenticated)` line (leave `pre_invocation: []`) and re-run. Expect: both calls allow.
3. Gate the open route. Add `- "require(authenticated)"` under `search_repos` and re-run. Expect: both calls deny.

Reset any time with `git checkout -- examples/tutorial/policies`.

## Checkpoint

{{< details "Why did get_compensation deny when the Rust code never checked anything?" >}}
The route's `require(authenticated)` predicate failed, because the caller is anonymous. The decision lives entirely in policy. `mediate()` just reports what the route decided.
{{< /details >}}

{{< details "What makes search_repos allow?" >}}
It has no denying rule. A route with an empty or absent `pre_invocation` is open by default. CPEX blocks only what policy tells it to.
{{< /details >}}

## Go deeper

- [APL: routes and phases]({{< relref "/docs/apl" >}}) for the full route model.
- [Quick Start]({{< relref "/docs/quickstart" >}}) for the same shape in prose.

## Next

[Module 2: Who's calling?]({{< relref "02-identity" >}}): give callers a real identity so `require(role.hr)` has something to check. Start the IdP first.
