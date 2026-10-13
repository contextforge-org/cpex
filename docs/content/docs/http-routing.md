---
title: "HTTP Routing"
weight: 57
---

# HTTP Routing

Most routes select an operation by name: a `tool:`, a `resource:`, a `prompt:`, an `llm:`. An `http:` route selects on the request line instead, so plain HTTP traffic that names no entity can still be authorized. One CPEX engine can then cover an agent's tool calls and the HTTP traffic around them under one policy document.

**Surfaces.** HTTP routes are reachable from the Rust facade only. The `http.request` and `http.response` hooks carry PPE's `HttpPayload`, which the Python and Go bindings do not build: a Python `invoke_hook("http.request", ...)` resolves the route and then fails with a `plugin_error` saying the `http` family expects `HttpPayload`. The Go `HttpExtension` also has no fields for the method, path or status. Python and Go hosts can still load a document that declares `http:` routes.

## Selector forms

A bare path, or a list of them, matches exactly:

```yaml
routes:
  - http: /admin
    authorization:
      pre_invocation:
        - "require(role.admin)"

  - http: [/metrics, /healthz]
    authorization:
      pre_invocation:
        - "allow"
```

The map form takes exactly one of `path:` or `path_prefix:`, optionally narrowed by `method:`:

```yaml
routes:
  - http:
      path_prefix: /api/v1
      method: [POST, PUT, PATCH]
    authorization:
      pre_invocation:
        - "require(perm.write)"

  - http:
      path: /api/v1/status
      method: GET
    authorization:
      pre_invocation:
        - "allow"
```

Any other key in that map fails to load.

## Precedence

When more than one route could match, the winner is decided in this order:

1. An exact path beats a prefix.
2. A longer prefix beats a shorter one.
3. A narrower method set breaks a remaining tie.

`/api/v1/status` above wins over the `/api/v1` prefix next to it, whatever the declaration order.

Exact paths compare byte for byte, so `/admin` and `/admin/` are different paths. A prefix drops one trailing slash at parse time, so `path_prefix: /api/` and `path_prefix: /api` are the same selector. A prefix matches on segment boundaries: `/api` does not match `/apidocs`.

## The catch-all

A request that matches no `http:` route falls through to global policy. A document that declares `http:` routes without a catch-all is reported at load, because falling through is a real decision. Write one with the root prefix:

```yaml
routes:
  - http:
      path_prefix: /
    authorization:
      pre_invocation:
        - "require(authenticated)"
```

## Invoking it from Rust

The host fires `http.request` with `meta` set to the reserved coordinates (`entity_type: http`, `entity_name: global`) and the request line on the HTTP extension. The engine picks the route from the request line.

```rust
use std::sync::Arc;

use cpex::praxis_policy_core::cmf::constants::{ENTITY_HTTP, ENTITY_NAME_GLOBAL};
use cpex::praxis_policy_core::extensions::{Extensions, HttpExtension, MetaExtension};
use cpex::praxis_policy_core::http_hook::{HttpHook, HttpPayload, HOOK_HTTP_REQUEST};
use cpex::PolicyEngine;

/// An HTTP request as the engine expects it: the reserved entity
/// coordinates on `meta`, and the request line on `http`.
fn http_request(method: &str, path: &str) -> Extensions {
    let mut meta = MetaExtension::default();
    meta.entity_type = Some(ENTITY_HTTP.to_owned());
    meta.entity_name = Some(ENTITY_NAME_GLOBAL.to_owned());
    Extensions {
        meta: Some(Arc::new(meta)),
        http: Some(Arc::new(HttpExtension {
            method: Some(method.to_owned()),
            path: Some(path.to_owned()),
            ..Default::default()
        })),
        ..Default::default()
    }
}

// engine: Arc<PolicyEngine>, loaded and initialized
let (result, _bg) = engine
    .invoke_named::<HttpHook>(HOOK_HTTP_REQUEST, HttpPayload, http_request("GET", "/admin"), None)
    .await;
```

With the `/admin` route and the catch-all above, an anonymous `GET /admin` denies with `routes.http:/admin.pre_invocation[0]`, and `GET /docs` allows.

## Host obligations

If the host skips either of these, a different policy runs and the request does not fail.

**The request line at the identity hook.** A route's own `authentication:` list applies only if the engine knows the method and path when identity is resolved. Put them on the HTTP extension for the `identity.resolve` call too. Without them the global `authentication:` list runs instead, and the engine logs a warning.

**The response hook, fired by the host.** A global `result:` or `post_invocation:` block installs a handler on `http.response`, but the host has to invoke it. Before you do, review your global post steps: HTTP steps that did nothing before now run, and `result.*` is absent for a request with no entity.

Response bodies are not modeled. The response half covers headers and extensions.

## Reading the response status

`http.status` carries the response status to post-phase policy. The host sets it on the response invocation. It enters the attribute bag as an integer under the `read_headers` capability, and it is absent on requests, so a rule that reads it belongs under `post_invocation:`:

```yaml
routes:
  - http:
      path_prefix: /api
    authorization:
      post_invocation:
        - "require(http.status < 500)"
```

## Dispatch mode

`http:` routes need the default `dispatch: policy`. Under `dispatch: hooks` a `routes:` block fails to load, so a document with an `http:` route is in policy mode by construction. A route's policy body replaces its structural plugin chain, so a listed plugin runs only where a step names it with `run(name)`.

## Go deeper

- PPE's [HTTP routing guide](https://github.com/praxis-proxy/policy/blob/v0.5.0/docs/content/http-routing.md), the source for this page.
- [Header Assertions]({{< relref "/docs/assertions" >}}): control the identity and response headers that cross the boundary on these routes.
- [Configuration]({{< relref "/docs/configuration" >}}): the full route schema.
