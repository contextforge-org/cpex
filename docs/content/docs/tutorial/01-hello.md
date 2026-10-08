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

The host builds an engine, registers the builtins, installs an HTTP transport, and loads a policy. From [`examples/tutorial/examples/m01_hello.rs`](https://github.com/contextforge-org/cpex/tree/main/examples/tutorial/examples/m01_hello.rs):

```rust
// --- Set up the enforcement point (the same steps a real host writes) ---
let engine = Arc::new(PolicyEngine::default());
cpex::install_builtins(&engine);
// The HTTP transport builtins use to reach an IdP. Module 1 calls no IdP,
// but every module installs it the same way; see `install_http_transport`.
cpex_tutorial::install_http_transport(&engine);
engine
    .load_config_yaml(POLICY)
    .expect("policy m01.yaml should load");
engine.initialize().await.expect("initialize");
```

`install_builtins` registers the bundled plugins and the APL config visitor. `install_http_transport` sets the HTTP client that builtins use to fetch signing keys, exchange tokens, and open approval requests. Builtins do not bring their own: the host installs one on the engine. From [`src/lib.rs`](https://github.com/contextforge-org/cpex/tree/main/examples/tutorial/src/lib.rs):

```rust
pub fn install_http_transport(engine: &Arc<PolicyEngine>) {
    engine.set_http_transport(Arc::new(
        HyperTransport::new().with_allow_private_destinations(),
    ));
}
```

The bundled transport refuses private and loopback destinations. The tutorial IdP runs on `localhost`, so this one allows them. **This is not a production setting:** it lets a policy document point a plugin at anything on the host's network. A production host keeps the default (`cpex::install_default_http_transport`) or installs its own transport with its own egress rules. Module 1 makes no outbound call; the transport matters from module 2 on.

The policy ([`policies/m01.yaml`](https://github.com/contextforge-org/cpex/tree/main/examples/tutorial/policies/m01.yaml)) defines two routes. `get_compensation` requires an authenticated caller, so it denies the anonymous one. `search_repos` has a single unconditional `allow`. An `authorization:` block must name at least one step, so an open route says so explicitly.

```yaml
routes:
  - tool: get_compensation
    authorization:
      pre_invocation:
        - "require(authenticated)"

  - tool: search_repos
    authorization:
      pre_invocation:
        - "allow"
```

Each call goes through `mediate()`, the harness wrapper around the loop a host owns: resolve identity, run policy, call the backend, run policy on the result. It is harness code, not a CPEX API. Module 9 opens it up.

## Run it

```bash
cargo run -p cpex-tutorial --example m01_hello
```

```
▸ anonymous → get_compensation (route requires authentication)
  ✗ DENIED   [routes.tool:get_compensation.pre_invocation[0]] access denied

▸ anonymous → search_repos (route has no rule)
  ✓ ALLOWED  {"visibility":"public","repositories":[{"name":"brand-site","visibility":"public"}]}
```

Same anonymous caller, same host code. The route decided the outcome, and the denial names the exact rule that failed.

{{< asciinema cast="https://asciinema.org/a/GWQ1rUgWufRxMUcE.cast" poster="npt:0:03" >}}

## Try it

1. Change the failing predicate. In `examples/tutorial/policies/m01.yaml`, change `require(authenticated)` to `require(role.hr)` and re-run. Expect: `get_compensation` still denies, because the anonymous caller has no role either. The displayed reason is the same generic, position-based code (`...pre_invocation[0]] access denied`); what changed is which predicate rejected the call, not the visible text.
2. Open the gated route. Replace `require(authenticated)` under `get_compensation` with `allow` and re-run. Expect: both calls allow.
3. Gate the open route. `get_compensation` already denies; replace `allow` under `search_repos` with `require(authenticated)`, leaving `get_compensation` unchanged, and re-run. Expect: both calls now deny.

Reset any time with `git checkout -- examples/tutorial/policies`.

## Checkpoint

{{< details "Why did get_compensation deny when the Rust code never checked anything?" >}}
The route's `require(authenticated)` predicate failed, because the caller is anonymous. The decision lives entirely in policy. `mediate()` just reports what the route decided.
{{< /details >}}

{{< details "What makes search_repos allow?" >}}
Its only step is `allow`, which never denies. CPEX blocks only what policy tells it to. An empty `pre_invocation` list is a load error, so a route that should be open says `allow`.
{{< /details >}}

## Go deeper

- [APL: routes and phases]({{< relref "/docs/apl" >}}) for the full route model.
- [Quick Start]({{< relref "/docs/quickstart" >}}) for the same shape in prose.

## Next

[Module 2: Who's calling?]({{< relref "02-identity" >}}): give callers a real identity so `require(role.hr)` has something to check. Start the IdP first.
