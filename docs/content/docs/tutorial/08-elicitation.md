---
title: "Human in the loop"
weight: 9
---

# Module 8: Human in the loop (Elicitation)

> You are in the [CPEX tutorial]({{< relref "_index" >}}). This module needs the IdP.

**Goal:** suspend a sensitive operation until a human approves it, then resume it. The agent cannot proceed on its own.

## The problem

Some actions are too consequential to run on the agent's say-so: a large transfer, an irreversible change, an outbound message to a client. You want policy to pause the call, ask a human, and only continue once they approve. That means the operation must be able to suspend and resume, not just allow or deny.

## Build it

Add an elicitation plugin on the `elicit` hook and a `require_approval(...)` step. From [`policies/m08.yaml`](https://github.com/contextforge-org/cpex/tree/main/examples/tutorial/policies/m08.yaml):

```yaml
plugins:
  - name: keycloak
    kind: identity/jwt
    hooks: [identity.resolve]
    config: { ... as in module 2 ... }
  - name: manager-approval
    kind: approval-channel
    hooks: [elicit]

routes:
  - tool: send_email
    authentication: [keycloak]
    authorization:
      pre_invocation:
        - "require(authenticated)"
        - "require_approval(manager-approval, from: claim.manager, purpose: \"Approve outbound email\")"
```

The first time a caller hits this route, the approval is pending, so policy suspends the call and returns an elicitation id. A human approves out of band. The caller retries with the id, and now the approval is resolved, so the call proceeds. `from: claim.manager` resolves to the caller's manager from their token (evan's manager is mona).

The approval plugin ([`examples/m08_elicitation.rs`](https://github.com/contextforge-org/cpex/tree/main/examples/tutorial/examples/m08_elicitation.rs)) implements the `elicit` hook's three operations against a tiny approval channel:

```rust
match payload.operation() {
    ElicitationOp::Dispatch => { /* open a pending request, return its id */ }
    ElicitationOp::Check    => { /* report Pending / Resolved{Approved|Denied} */ }
    ElicitationOp::Validate => { /* confirm the approver */ }
}
```

The channel is served over HTTP so a human can approve with `curl`. In production this would be an OIDC CIBA backchannel or a push to the approver's phone. CIBA (Client-Initiated Backchannel Authentication, [OpenID spec](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html)) is the OpenID flow where the app asks the identity provider to prompt a user on a separate device and polls for their decision; see [Human-in-the-Loop Elicitation]({{< relref "/docs/apl/elicitation" >}}) for how CPEX drives it. The point here is CPEX's suspend and resume model, not the notification transport.

## Run it

```bash
cargo run -p cpex-tutorial --example m08_elicitation
```

The first attempt suspends:

```
▸ evan → send_email (first attempt: suspends for manager approval)
  ⏸ PENDING  awaiting mona's approval (id elic-mona)

  Approve it from another terminal with:
    curl -X POST localhost:8090/approvals/elic-mona/approve
```

Run that curl in a second terminal. You do not re-run anything: the same program is polling the approval channel in a loop, so a moment after your curl (it polls on an interval, so allow a few seconds) it picks up the decision and resumes on its own:

```
▸ evan → send_email (retry with the approval: resumes and runs)
  ✓ ALLOWED  {"sent":true, ...}
```

Here "retry" means that automatic re-check inside the running program, not a second `cargo run`. In a real agent it is the agent re-sending the request with the elicitation id; the tutorial harness does it for you.

Run with `-- --check` to have it approve itself and exercise the whole path unattended.

{{< asciinema cast="https://asciinema.org/a/xjfOzQwrEnrLLCp8.cast" poster="npt:0:04" >}}

## Try it

1. Deny instead. Use `curl -X POST localhost:8090/approvals/elic-mona/deny`. Expect: the program's next poll picks up the denial (again allow a few seconds), and the call ends denied, not allowed.
2. List pending. `curl localhost:8090/approvals` shows the open request while the program waits.
3. Let it stay pending. Do nothing. The program keeps polling and the operation never runs; it only proceeds once someone approves. There is no manual retry step, the running program resumes itself.

## Checkpoint

{{< details "What is different about pending versus denied?" >}}
A denial ends the call. Pending suspends it: the operation has not run and can still proceed later, once a human approves and the caller retries with the elicitation id. The agent cannot resolve it alone.
{{< /details >}}

{{< details "How does the retry reach the same approval?" >}}
The first attempt returns an elicitation id. The caller echoes it on retry (the harness sends it as a resume header), so policy checks that existing approval instead of opening a new one.
{{< /details >}}

## Go deeper

- [Human-in-the-Loop Elicitation]({{< relref "/docs/apl/elicitation" >}}) for the suspend/resume model, CIBA, and genuineness.

## Next

The capstone reassembles all three backends and every control into the full scenario.
