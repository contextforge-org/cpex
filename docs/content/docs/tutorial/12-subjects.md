---
title: "Delegation subjects"
weight: 13
---

# Module 12: Delegation subjects (who the call speaks for)

> You are in the [CPEX tutorial]({{< relref "_index" >}}). This module needs the IdP.
>
> **Cookbook recipes:** [Recipe 1: on-behalf-of a user]({{< relref "/docs/identity-delegation#recipe-1-user-acting-through-an-agent-on-behalf-of" >}}) (`subject: user`) and [Recipe 3: a service acting as itself]({{< relref "/docs/identity-delegation#recipe-3-a-service-acting-as-itself" >}}) (`subject: this_workload`).

**Goal:** choose *whose* authority a minted downstream token carries: the caller's, or the gateway's own.

## The problem

Not every downstream call has a user behind it. A scheduled sync, a shared index lookup, an infrastructure call: there the *gateway* holds the downstream credential and calls as itself, with no caller in the picture. Module 6 minted on behalf of the caller, which is the right default when the agent acts for a signed-in human, and the wrong one here.

The `subject:` argument on a `delegate(...)` step picks which principal the minted token speaks for. The delegation *mode* is derived from it, never declared separately, so a route can't claim to act on-behalf-of-a-user while actually handing over some other credential.

## Build it

Two routes, two subjects. From [`policies/m12.yaml`](https://github.com/contextforge-org/cpex/tree/main/examples/tutorial/policies/m12.yaml):

```yaml
routes:
  # On behalf of the caller: exchange the CALLER's token.
  - tool: get_compensation
    authentication: [keycloak]
    authorization:
      pre_invocation:
        - "delegate(workday-oauth, target: workday-api, audience: workday-api, subject: user)"
        - "require(delegation.granted)"

  # As the gateway itself: mint via the gateway's own client credentials.
  - tool: search_repos
    authorization:
      pre_invocation:
        - "delegate(workday-oauth, target: github-api, audience: github-api, subject: this_workload)"
        - "require(delegation.granted)"
```

- **`subject: user`** (the default) runs an RFC 8693 token exchange on the caller's inbound token. No caller token, nothing to exchange.
- **`subject: this_workload`** runs an RFC 6749 `client_credentials` grant with the gateway's own `client_id` and secret, through the same `workday-oauth` plugin, reading no caller token at all. The `search_repos` route has no `authentication:` line, because this path needs no caller.

## Run it

```bash
cargo run -p cpex-tutorial --example m12_subjects
```

```
▸ alice → get_compensation (subject: user, exchanges alice's token)
  ✓ ALLOWED  { ... }

▸ anonymous → get_compensation (subject: user, no token to exchange, delegation fails)
  ✗ DENIED   [delegation.bad_request] ... empty bearer_token ...

▸ anonymous → search_repos (subject: this_workload, gateway mints via client_credentials)
  ✓ ALLOWED  { ... }

▸ alice → search_repos (subject: this_workload, same result: the caller's identity is not used)
  ✓ ALLOWED  { ... }
```

`subject: user` needs a caller: the anonymous request fails at the exchange with an empty token. `subject: this_workload` needs none, and succeeds anonymously, because the gateway holds the credential.

## Try it

1. **Swap the subjects.** Put `subject: this_workload` on `get_compensation` and re-run the anonymous case. Expect: it now succeeds, because the gateway no longer needs the caller's token.
2. **Ask for a caller that isn't there.** Add `authentication: [keycloak]` to `search_repos` and re-run it anonymously. Expect: the denial moves earlier, to identity resolution, even though the delegation itself never needed a caller.
3. **Drop the audience mapper (advanced).** `subject: this_workload` relies on the `cpex-gateway` client being a service account with an audience mapper for `github-api` (see [`idp/realm-export.json`](https://github.com/contextforge-org/cpex/tree/main/examples/tutorial/idp)). Remove that mapper and the minted token won't carry the audience.

## Checkpoint

{{< details "Why does anonymous fail on one route but not the other?" >}}
`subject: user` exchanges the caller's inbound token; an anonymous request has none, so the exchange fails with `delegation.bad_request`. `subject: this_workload` uses the gateway's own client credentials, so there is nothing about the caller it needs.
{{< /details >}}

{{< details "Is the mode declared or derived?" >}}
Derived. You choose `subject:`, and the delegation mode (on-behalf-of vs. act-as-self) follows from it. There is no separate `mode:` key, so a route can't claim on-behalf-of-user while handing over the gateway's own credential.
{{< /details >}}

## Go deeper

The same rule covers the other subjects, each with its own module:

- **`subject: client`**, the calling OAuth client acting as itself, its own token scoped down: [module 13]({{< relref "13-client" >}}).
- **`subject: caller_workload`**, the calling agent proving itself with a SPIFFE JWT-SVID, exchanged in two legs: [module 16]({{< relref "16-workload" >}}), which needs the SPIRE overlay.
- **`actor:`**, recording the calling agent alongside the user `sub`: [module 15]({{< relref "15-dual-principal" >}}).

See the [Identity & Delegation cookbook]({{< relref "/docs/identity-delegation" >}}) for the reference recipes, and the [Delegation reference]({{< relref "/docs/apl/delegation" >}}) for the full `subject:` / `actor:` contract.

## Next

[Module 13: Delegation as a client]({{< relref "13-client" >}}): scope a token an agent minted for *itself*, when the caller is an OAuth client rather than a user.
