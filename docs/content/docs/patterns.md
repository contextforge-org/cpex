---
title: "Patterns"
weight: 100
---

# Patterns

Production patterns for writing and rolling out CPEX policy. Each is expressed in APL and builds on the concepts in the earlier pages. The [Tutorial]({{< relref "/docs/tutorial" >}}) builds most of these hands-on; this page is the condensed reference for authoring and rollout.

## Layered enforcement

Order effects cheapest-gate-first so expensive work only runs for requests that survive the early checks. Attribute gates, then a PDP call, then delegation (built up in tutorial modules [4]({{< relref "/docs/tutorial/04-effects" >}}), [5]({{< relref "/docs/tutorial/05-pdp" >}}), and [6]({{< relref "/docs/tutorial/06-delegation" >}})):

```yaml
authorization:
  pre_invocation:
    - "require(team.engineering | team.security)"   # cheap
    - cedar:
        action: 'Action::"read"'
        resource:
          type: Repo
          id: ${args.repo_name}
    - "delegate(github-oauth, target: github-api, permissions: [repo:read])"   # expensive, last
```

A deny at any layer halts the rest, so you never mint a token for a request a later layer would reject.

## Shadow rollout with audit mode

Before a new policy blocks traffic, run it in `audit` mode to observe what it would do without enforcing. An audit-mode plugin records decisions but cannot block, so you can measure a policy's deny rate against real traffic, then switch it to `sequential` once the rate is what you expect.

```yaml
plugins:
  - name: new-policy-check
    kind: validator/pii-scan
    mode: audit          # observe only; flip to sequential to enforce
    on_error: ignore
```

## Input and output guardrails

Validate and transform on the way in with `args`, redact on the way out with `result`. The two phases bracket the operation (redaction is tutorial [module 3]({{< relref "/docs/tutorial/03-shaping" >}})):

```yaml
routes:
  - tool: get_employee
    args:
      employee_id: "str | regex(\"^[0-9]{6}$\")"   # reject malformed input
    result:
      ssn: "str | redact(!perm.view_ssn)"           # redact output by permission
```

## Cross-request information flow

Taint a session when it touches sensitive data, then gate later operations on the label. The control spans requests and the model cannot route around it (see [Session Tainting]({{< relref "/docs/apl/tainting" >}}) and tutorial [module 7]({{< relref "/docs/tutorial/07-tainting" >}})):

```yaml
routes:
  - tool: get_compensation
    authorization:
      pre_invocation:
        - "require(role.hr)"
        - "taint(secret, session)"
  - tool: send_email
    authorization:
      pre_invocation:
        - "require(perm.email_send)"
        - "security.labels contains \"secret\": deny('write-down blocked', 'session_tainted')"
```

## Least-privilege effects

Declare the narrowest capabilities each plugin needs, and scope delegated tokens to the minimum. A scanner that reads content does not get identity; a downstream token gets only the scope the operation requires, verified after the exchange (deny if the grant is missing):

```yaml
authorization:
  pre_invocation:
    - "delegate(workday-oauth, target: workday-api, permissions: [read_compensation])"
    - "!(delegation.granted.permissions contains 'read_compensation'): deny"   # fail closed if not granted
```

## Defense in depth

Combine the patterns: an attribute gate, a PDP relationship check, a PII scan on output, a taint, and an audit record, each a separate effect in one policy. No single layer is load-bearing alone; the operation has to pass all of them.
