---
title: "Passthrough (forward, don't mint)"
weight: 15
---

# Module 14: Passthrough (forward the caller's token, mint nothing)

> You are in the [CPEX tutorial]({{< relref "_index" >}}). This module needs the IdP.
>
> **Cookbook recipe:** [Recipe 4: Forward a token the caller already has]({{< relref "/docs/identity-delegation#recipe-4-forward-a-token-the-caller-already-has-passthrough" >}}).

**Goal:** recognize the case where the right move is to mint *nothing*, and instead validate the caller's token and forward it unchanged.

## The problem

Sometimes the caller already holds a token that is correct for the downstream. In the *agent-brokered* case the agent authenticated to the IdP itself and handed CPEX a ready token, and the exchange modules 6, 12 and 13 perform would be pure overhead.

Passthrough is that case, defined by what is *absent*: there is no `delegate(...)` step. CPEX validates the token inbound, authorizes the call, and the token the caller presented is the token that flows on.

## Build it

There is nothing to add, only something to *leave out*: a plain resolver (as in module 2), a route that authorizes, and no delegator plugin at all. From [`policies/m14.yaml`](https://github.com/contextforge-org/cpex/tree/main/examples/tutorial/policies/m14.yaml):

```yaml
plugins:
  - name: keycloak            # validates the inbound token; that is its whole job
    kind: identity/jwt
    hooks: [identity.resolve]
    config: { role: user, ... as in module 2 ... }

routes:
  - tool: search_repos
    authentication: [keycloak]
    authorization:
      pre_invocation:
        - "require(authenticated)"   # no delegate step, so the caller's token is forwarded
```

| Shape | Step | What flows downstream |
|---|---|---|
| Passthrough (this module) | *no* `delegate` | the caller's own token, unchanged |
| Mint (modules 6, 13) | `delegate(subject: …)` | a fresh token, scoped to one audience |

## Run it

```bash
cargo run -p cpex-tutorial --example m14_passthrough
```

```
▸ alice → search_repos (validated and forwarded, no token minted)
  ✓ ALLOWED  { ... "repositories":[ ... ] }

▸ anonymous → search_repos (no token to forward, require(authenticated) denies)
  ✗ DENIED   [...] access denied
```

`alice`'s token was validated and the call went through with no exchange, so her token is what would reach the backend. The anonymous caller had no token to forward, so `require(authenticated)` denied it.

Passthrough is the cheapest option and the least contained: a forwarded token is as broad as it was issued, where a minted one is narrowed to a single audience. Forward only when the caller's token is already scoped for the downstream. It is a security judgment, and in policy it is one line of difference: a `delegate` step, or none.

## Try it

1. **Add a mint step.** Drop a `delegate(workday-oauth, target: workday-api, audience: workday-api, subject: user)` before `require(authenticated)` (and the delegator plugin from module 13). Now the route *mints* instead of forwarding: the same allow result, a narrower token downstream.
2. **Break the audience.** Point `audiences:` at something the token doesn't carry (e.g. `[workday-api]`) and re-run alice. Expect: inbound validation fails, because passthrough still requires a *valid* token, it just doesn't exchange it.

## Checkpoint

{{< details "How is this different from module 2?" >}}
Module 2 resolved identity to make an *authorization* decision. Passthrough is about the *outbound* token: having validated the caller, the route forwards that same token rather than minting a new one. What changes is what leaves the boundary, not how the caller is identified.
{{< /details >}}

{{< details "When is passthrough the wrong choice?" >}}
When the caller's token is broader than the downstream call needs. Forwarding it hands the backend more authority than necessary, and a leak isn't contained. Mint a scoped token instead (modules 6, 13).
{{< /details >}}

## Go deeper

- [Recipe 4: Forward a token the caller already has]({{< relref "/docs/identity-delegation#recipe-4-forward-a-token-the-caller-already-has-passthrough" >}}) for the reference version and where it fits among the delegation subjects.

## Next

[Module 15: Dual-principal]({{< relref "15-dual-principal" >}}): mint on behalf of a user while naming the agent that carried out the call.
