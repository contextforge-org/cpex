---
title: "Information flow (Tainting)"
weight: 8
---

# Module 7: Information flow (Tainting)

> You are in the [CPEX tutorial]({{< relref "_index" >}}). This module needs the IdP.

**Goal:** carry security state across a session so a later request can be denied because of what an earlier one did. This is how CPEX stops write-down.

## The problem

Most authorization systems judge each request alone. That misses a whole class of leaks: a caller reads sensitive data, then sends it out through a channel that looks harmless on its own. You want the second call blocked because of the first, even though nothing about the second call is suspicious in isolation.

## Build it

One route taints the session; another refuses when the taint is present. From [`policies/m07.yaml`](https://github.com/contextforge-org/cpex/tree/main/examples/tutorial/policies/m07.yaml):

```yaml
routes:
  - tool: get_compensation
    authentication: [keycloak]
    authorization:
      pre_invocation:
        - "require(role.hr)"
        - "taint(secret, session)"        # mark the session as having read secret data

  - tool: send_email
    authentication: [keycloak]
    authorization:
      pre_invocation:
        - "require(authenticated)"
        - "security.labels contains \"secret\": deny('write-down blocked: this session read secret data', 'session_tainted')"
```

`taint(secret, session)` records the `secret` label on the session, and it persists in the session store. `send_email` reads `security.labels`, the accumulated session state, not just this request's arguments. The label outlives the request that set it.

## Run it

```bash
cargo run -p cpex-tutorial --example m07_tainting
```

```
▸ alice, fresh session → send_email (nothing tainted yet)
  ✓ ALLOWED  {"sent":true, ...}

▸ alice, session-hr-work → get_compensation (taints session 'secret')
  ✓ ALLOWED  { ... }

▸ alice, session-hr-work → send_email (write-down blocked)
  ✗ DENIED   [session_tainted] write-down blocked: this session read secret data
```

The same `send_email` call is allowed in a clean session and denied in the session that read compensation. The email's content is irrelevant. The session's history blocks it.

{{< asciinema cast="https://asciinema.org/a/MCo8BWT3DvW7OH8d.cast" poster="npt:0:03" >}}

## Try it

1. Separate the sessions. Give the third call a new session id. Expect: it allows again, because taint is per session.
2. Taint from elsewhere. Add `taint(secret, session)` to a different route and confirm reading through that route also blocks later email.
3. Persist across restarts. Start Valkey (`docker compose -f examples/tutorial/idp/docker-compose.yml --profile valkey up -d`) and point the session store at it, so taint survives a process restart. The in-memory store used here resets when the program exits.

## Checkpoint

{{< details "Why is the email denied when its own content is harmless?" >}}
The denial is based on session state, not the email. `get_compensation` tainted the session with `secret`, and `send_email` refuses whenever that label is present. Information flow is tracked across the whole session.
{{< /details >}}

{{< details "What ties the two calls together?" >}}
A shared session id plus the same authenticated subject. That pair keys the session store, so the taint set by the first call is visible to the second.
{{< /details >}}

## Go deeper

- [Session Tainting]({{< relref "/docs/apl/tainting" >}}) and [Patterns: cross-request information flow]({{< relref "/docs/patterns" >}}).

## Next

[Module 8: Human in the loop]({{< relref "08-elicitation" >}}): suspend an operation until a human approves it.
