---
title: "APL"
weight: 30
---

# APL: configuring enforcement pipelines

APL is the declarative configuration that defines a CPEX enforcement pipeline. Each capability an agent can invoke (a tool, resource, prompt, or A2A method) defines its own pipeline through a **route** that sequences the controls protecting it, evaluated at the boundary. You describe the conditions and the effects; you do not write enforcement logic in application code.

![An APL config: plugins and global settings, then per-entity routes with a pre-invocation flow (require, PDP, delegate, run) and post-invocation result handling (taint, redact), plus session tainting across entities](/cpex/images/apl_overview.png)

This page covers the configuration: routes, phases, predicates, rules, and field pipelines. The rest of this section goes deeper on each kind of policy:

- [Effects & Sequencing]({{< relref "/docs/apl/effects" >}}): the effects a rule can run, halt-on-deny ordering, and composition.
- [PDP Integration]({{< relref "/docs/apl/pdp" >}}): hand a decision to Cedar, CEL, or an external engine.
- [Identity & IdP]({{< relref "/docs/apl/identity" >}}): how callers are resolved into the attributes predicates read.
- [Delegation]({{< relref "/docs/apl/delegation" >}}): mint scoped downstream credentials via token exchange.
- [Elicitation]({{< relref "/docs/apl/elicitation" >}}): pause an operation for human approval and resume on retry.
- [Session Tainting]({{< relref "/docs/apl/tainting" >}}): information-flow control across requests.

## Routes and phases

Policy is organized by **route**: an operation CPEX mediates, identified by the tool, A2A method, or other interface it governs. Each route runs through four phases, in order:

```mermaid
flowchart LR
  ARGS["args<br>validate / transform input"] --> POL["authorization.pre_invocation<br>authorize"] --> RES["result<br>transform output"] --> POST["authorization.post_invocation<br>audit / final checks"]
```

- **args**: validate and transform request inputs before the operation runs.
- **authorization.pre_invocation**: authorize the operation. Predicates, PDP calls, delegation, tainting.
- **result**: transform the response. Redaction and masking on the wire.
- **authorization.post_invocation**: checks after the result is known. Audit, post-delegation verification.

The first `deny` in any phase halts that phase and every later phase. Nothing reaches the backend after a deny in `args` or `authorization.pre_invocation`.

`authorization` names *when* the phase runs, not a pure allow/deny gate: alongside the decision, `pre_invocation` (and `post_invocation`) can carry obligations and effects — `taint(...)`, `delegate(...)`, and `plugin(...)` (which may transform the payload) — that run as part of the phase.

```yaml
routes:
  - tool: get_employee
    args:
      employee_id: "str"
    authorization:
      pre_invocation:
        - "require(authenticated)"
        - "delegation.depth > 2: deny"
    result:
      ssn: "str | redact(!perm.view_ssn)"
      salary: "int | redact(!role.hr)"
      employee_id: "str | mask(4)"
```

The `pre_invocation:` / `post_invocation:` lists may also be written flat on the route (without the `authorization:` wrapper); both forms are equivalent.

## Predicates

A predicate reads attributes resolved from the caller's identity and request context (see [Identity]({{< relref "/docs/apl/identity" >}}) for where attributes come from). The forms:

- **Truthiness**: a bare attribute is true when present and truthy. `authenticated`, `role.hr`, `perm.view_ssn`.
- **Comparison**: `delegation.depth > 2`, `client.trust_level == 'trusted'`. Operators: `==`, `!=`, `>`, `>=`, `<`, `<=`.
- **Set membership**: `subject.id in authorized_users`, `subject.id not in banned_list`.
- **Existence**: `exists(delegation.origin_subject_id)` is true when the attribute is present.
- **Containment**: `security.labels contains "secret"`.
- **Logical composition**: `&` (and), `|` (or), `!` (not). Precedence is `()` > `!` > `&` > `|`.

```yaml
- "(role.hr | role.security) & !delegated"
```

## Rules

A `pre_invocation:` (or `post_invocation:`) entry is a rule. Two forms:

**`require(...)`** denies unless the predicate holds:

```yaml
- "require(authenticated)"
- "require(role.hr)"
- "require(!delegated)"
```

`require(a, b)` denies if either is false (an implicit and). `require(a | b)` denies only if both are false.

**`predicate: effect`** runs the effect when the predicate holds:

```yaml
- "delegation.depth > 2: deny"
- "security.labels contains \"secret\": deny('session touched secret data', 'session_tainted')"
```

`deny` takes an optional reason and code: `deny`, `deny('reason')`, or `deny('reason', 'code')`. The code is surfaced to the caller and the audit log.

For richer conditionals, use the `when` / `do` form, where `do` is a single effect or a list:

```yaml
- when: "role.hr & !perm.view_ssn"
  do:
    - "taint(restricted, session)"
    - "plugin(audit-log)"
```

## Custom denial response

By default a deny surfaces a reason and code, and the host renders its own denial. A route can instead attach a custom HTTP response — status, body, headers — through a `response:` block, a sibling of the route's `authorization:` block:

```yaml
routes:
  - tool: locked
    authorization:
      pre_invocation:
        - "require(authenticated)"
    response:
      status: 403
      body: "{\"error\":\"forbidden\"}"
      headers:
        WWW-Authenticate: "Bearer"
```

All three fields are optional; an absent block leaves the host's default denial unchanged. When the route denies, the status/body/headers are carried on the violation for the host to render on the wire. `response:` is honored at route scope and at `global` scope (below); it is inert — and warns at load time — under `defaults` or a policy bundle. It is scope-local: a `global` `response:` is not inherited by entity routes.

## Authorizing HTTP requests without an entity

Routes key on an MCP / A2A entity — a tool, prompt, resource, or LLM. A generic HTTP request that carries no such entity is authorized by the `global` policy instead: when `global` declares an `authorization:` (or `args:`) block, CPEX evaluates it for these requests, reading the request line (`http.method`, `http.path`, `http.host`, `http.scheme`) and headers. Pair it with a `global` `response:` to return a custom denial.

```yaml
global:
  authorization:
    pre_invocation:
      - "http.method != 'GET': deny"
  response:
    status: 405
    headers:
      Allow: "GET"
```

The host must populate `http.host` from a validated request authority, never a raw client `Host` header, so host-based predicates cannot be spoofed by the caller.

## Field pipelines

`args:` and `result:` map a field to a pipeline of stages separated by `|`. Stages run left to right; a failed validator denies the phase.

```yaml
result:
  ssn: "str | redact(!perm.view_ssn)"
  email: "email"
  employee_id: "str | mask(4)"
```

The accepted stages:

| Category | Stages |
|----------|--------|
| Type validators | `str`, `int`, `bool`, `float`, `email`, `url`, `uuid` |
| Constraint validators | `enum(a, b, c)`, `regex("...")`, `len(1..100)`, range like `0..100` |
| Transforms | `mask(N)` (keep last N), `redact`, `redact(!predicate)` (redact unless), `omit`, `hash` |
| Scans | `pii.redact`, `pii.detect`, `injection.scan` |
| Dispatch | `plugin(name)` (alias `run(name)`), `taint(label[, scope])` |

Named-validator dispatch (`validate(name)`) is not implemented in the current build. Use `regex("...")` for pattern checks or `plugin(name)` to hand a field to a plugin.

## Effects beyond predicates

A `pre_invocation:` rule can also call a PDP, mint a delegated token, or invoke a plugin. Those effects and how they sequence are covered in [Effects]({{< relref "/docs/apl/effects" >}}).

Every fragment on this page is drawn from the `apl-core` parser tests and the reference deployments, so the forms shown here parse as written.
