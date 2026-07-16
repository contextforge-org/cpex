---
title: "Session Tainting"
weight: 50
---

# Session Tainting and Information Flow

Some controls cannot be decided from a single request. "Do not send anything externally after reading secret data" depends on what the session did earlier. CPEX tracks that history as **taint labels**: facts attached to a session that later policy can read. This is how CPEX enforces information-flow control, including write-down prevention.

## The requirement

A caller reads compensation data, then asks the agent to send an email. The email body is clean: no SSN, no salary, nothing sensitive in the text. It should still be blocked, because this session has handled secret data and an external send is a write-down. The LLM cannot be trusted to remember this or to refuse on its own, and a content scan of the email body would not catch it. The control has to live in state the model cannot see.

## Tainting a session

A `taint` effect attaches a label. The scenario marks the session when compensation is read:

```yaml
routes:
  - tool: get_compensation
    authorization:
      pre_invocation:
        - "require(role.hr)"
        - "taint(secret, session)"
    result:
      ssn: "str | redact(!perm.view_ssn)"
```

`taint(secret, session)` records the label `secret` for the rest of the session. Labels are monotonic: once set, they persist. The second argument is the scope.

| Scope | Lifetime |
|-------|----------|
| `session` | Persists for the whole session, across requests. |
| `message` | Applies to the current message only. |

## Reading taint in a later policy

A different route, later in the same session, refuses based on the label, even with a clean payload:

```yaml
routes:
  - tool: send_email
    authorization:
      pre_invocation:
        - "require(perm.email_send)"
        - "security.labels contains \"secret\": deny('session touched secret data', 'session_tainted')"
```

![The taint produce-and-consume flow: get_compensation runs taint(secret, session), writing the secret label into session state; later in the same session, send_email with a clean body is checked against that CPEX-owned state and denied with session_tainted when the label is present, allowed otherwise](/cpex/images/apl_tainting_flow.png)

The email is denied because the session is tainted, not because of anything in its body. The decision is made from CPEX-owned state, so the model cannot route around it by rewording the email.

## Persistence and isolation

Taint labels are held in a session store. The default is in-process memory; the bundled `valkey` store persists them across processes and restarts:

```yaml
global:
  session_store:
    kind: valkey
    endpoint: localhost:6379
```

Labels are scoped per subject. Two callers sharing a session identifier do not share taint: a label set while acting as one subject does not leak into another subject's decisions. With the Valkey store, labels survive a gateway restart, so a long-running session's information-flow history is not lost.

## How it connects to the pipeline

`taint` is an effect; reading labels is an attribute check (`security.labels contains ...`) like any other predicate. The session store is a registered capability the runtime writes to after a tainting effect and reads from when building the attribute bag. Because both the write and the read happen inside CPEX, the taint history is part of the state the untrusted model cannot forge, which is what makes write-down enforcement reliable rather than advisory.

See [Effects]({{< relref "/docs/apl/effects" >}}) for how `taint` sequences with other effects, and [Configuration]({{< relref "/docs/configuration" >}}) for session-store options.
