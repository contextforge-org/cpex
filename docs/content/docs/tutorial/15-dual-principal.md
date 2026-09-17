---
title: "Dual-principal (subject + actor)"
weight: 16
---

# Module 15: Dual-principal delegation (who authorized vs. who acted)

> You are in the [CPEX tutorial]({{< relref "_index" >}}). This module needs the IdP.
>
> **Cookbook recipe:** [Recipe 6: User acting through an agent, with the agent named]({{< relref "/docs/identity-delegation#recipe-6-user-acting-through-an-agent-with-the-agent-named-dual-principal" >}}).

**Goal:** mint a token that speaks *for* the user and also *names the agent* that carried out the call: two principals on one exchange.

## The problem

The common agentic shape has two parties: a human decides, and an agent acts. Every delegation so far spoke for one principal, but here you want the audit trail, and the minted token, to record both: the user as the authority (`sub`), and the agent as the acting party (`act`). RFC 8693 calls this *delegation*; recording only the subject is *impersonation*.

Two ideas, kept separate:

- **`subject:`** is who the token speaks for, whose authority it carries. Least-privilege scoping follows the subject.
- **`actor:`** is who is doing it. The `act` claim records the agent; it grants nothing.

## Build it

Both credentials arrive on every call, on different headers, and a resolver picks each up. From [`policies/m15.yaml`](https://github.com/contextforge-org/cpex/tree/main/examples/tutorial/policies/m15.yaml):

```yaml
plugins:
  - name: jwt-user            # the human, on X-User-Token  -> subject slot
    kind: identity/jwt
    config: { role: user,   header: X-User-Token,  audiences: [cpex-tutorial], ... }
  - name: jwt-agent           # the agent, on Authorization -> client slot
    kind: identity/jwt
    config: { role: client, header: Authorization, audiences: [cpex-gateway], ... }

routes:
  - tool: get_compensation
    authentication: [jwt-user, jwt-agent]     # both must resolve
    authorization:
      pre_invocation:
        - "require(role.hr)"                   # authorize on the SUBJECT (the user)
        - "delegate(workday-oauth, target: workday-api, audience: workday-api,
                    subject: user, actor: client)"
        - "require(delegation.granted)"
```

`subject: user` makes the user's token the RFC 8693 `subject_token`; `actor: client` *additionally* attaches the agent's token as the `actor_token`. That is one exchange carrying two principals, not a second leg.

## Run it

```bash
cargo run -p cpex-tutorial --example m15_dual_principal
```

```
▸ alice (X-User-Token) + agent (Authorization) → get_compensation (subject: user, actor: client)
  ✓ ALLOWED  { ... }

▸ alice only, no agent token → get_compensation (actor credential missing)
  ✗ DENIED   [auth.malformed_header] header 'Authorization' missing ... (resolver 'jwt-agent')

▸ sync_index (subject: this_workload + actor: client) → rejected as an invalid combo
  ✗ DENIED   [...] `actor:` is not supported with `subject: caller_workload` or `subject: this_workload` ...
```

The first call carried both principals and went through. The second was missing the agent credential, and a dual-principal route needs both.

The third scenario is a guardrail. `actor:` only pairs with an on-behalf-of subject (`user` or `client`). With `subject: this_workload` (a `client_credentials` grant that carries no `actor_token`) or `subject: caller_workload` (already the acting workload), an actor is meaningless, so CPEX denies the step when it runs rather than silently dropping it.

## Interop: `act` is the token service's call

CPEX always puts the actor on the wire (`actor_token` plus `actor_token_type`), as RFC 8693 delegation prescribes. Whether `act` lands in the minted token is up to the token service:

- A delegation-capable service records the actor in a nested `act` claim.
- An impersonation-only service returns a subject-only token and ignores the actor.

Keycloak's Standard Token Exchange is impersonation-only: it ignores `actor_token` and emits no `act` (verified here on 26.x). So the first scenario succeeds, but the minted token names only alice. To see `act` end to end you need a delegation-capable token service. Against Keycloak, capture the acting agent at the CPEX boundary instead, in audit or a downstream header, since CPEX resolved both principals either way.

That is why the module asserts the exchange *succeeds* rather than inspecting the token for `act`: the CPEX half is correct regardless, and the claim's presence isn't CPEX's to guarantee.

## Try it

1. **Actor as `caller_workload`.** That variant names the agent by its SPIFFE SVID instead of an OAuth client: same `subject: user`, but `actor: caller_workload`. It needs a SPIFFE issuer (SPIRE); see [module 16]({{< relref "16-workload" >}}).
2. **Authorize on the actor by mistake.** Change `require(role.hr)` to gate on a client attribute. Authorization follows the *subject*; the actor is attribution, not authority.

## Checkpoint

{{< details "Why does the ALLOW scenario not prove `act` is in the token?" >}}
Because with Keycloak it isn't: its exchange is impersonation-only and drops the actor. CPEX still sends it correctly, and emitting `act` is the token service's job. The test asserts what CPEX controls (the exchange succeeds, both principals resolved), not what the IdP controls.
{{< /details >}}

{{< details "subject vs. actor: which one is scoped?" >}}
The subject. Least-privilege scoping follows whose authority the token carries. `actor:` only adds attribution: it records who acted, and grants nothing.
{{< /details >}}

## Go deeper

- [Recipe 6: dual-principal]({{< relref "/docs/identity-delegation#recipe-6-user-acting-through-an-agent-with-the-agent-named-dual-principal" >}}) for the reference version and the full interop note.
- [Delegation reference]({{< relref "/docs/apl/delegation" >}}) for the `subject:` / `actor:` contract and valid combinations.

## Next

[Module 16: Workload identity (SVID)]({{< relref "16-workload" >}}): the agent proves itself with a SPIFFE SVID, and CPEX exchanges it in two legs.
