---
title: "Delegation"
weight: 40
---

# Delegation and Token Exchange

When CPEX forwards an operation to a backend, the backend needs a credential. Forwarding the caller's inbound token is usually wrong: it is scoped for the agent, not the backend, and it carries more privilege than the operation needs. Delegation mints a fresh, narrowly scoped credential for the specific downstream call.

## The requirement

The scenario's `get_compensation` reads from a backend HR system that expects its own audience-scoped token with only the `read_compensation` scope. The caller never holds that token. CPEX must exchange the caller's verified identity for a downstream credential, scoped down to exactly what the operation needs, and only after authorization has passed.

## Delegation as an effect

`delegate` is an effect in the `authorization.pre_invocation` phase. It names a delegator plugin and the target it mints for:

```yaml
authorization:
  pre_invocation:
    - "require(role.hr)"
    - "delegate(workday-oauth, target: workday-api, audience: workday-api, permissions: [read_compensation])"
    - "delegation.granted.permissions contains 'read_compensation': allow"
```

The order matters. The `require` gate runs first, so a credential is only minted for a caller who passed authorization. After the exchange, a post-check verifies the credential actually carries the scope requested, and denies the operation if the IdP returned less.

![The delegation flow: the caller's verified token enters delegate(workday-oauth), which performs an RFC 8693 exchange at the IdP token endpoint; the resulting downstream token is audience- and scope-limited, delegation.granted.permissions is verified before forward, and only the minted token reaches the backend](images/apl_delegation_flow.png)

## The delegator plugin

The bundled `delegator/oauth` plugin performs RFC 8693 token exchange against an IdP token endpoint:

```yaml
plugins:
  - name: workday-oauth
    kind: delegator/oauth
    hooks: [token.delegate]
    config:
      token_endpoint: "https://idp.example.com/realms/agents/protocol/openid-connect/token"
      client_id: "cpex-gateway"
      client_secret_source:
        kind: file
        path: /etc/cpex-secrets/client-secret
      default_outbound_header: "Authorization"
```

It exchanges the caller's inbound token for one scoped to `audience` with the requested `permissions`, and attaches it to the outbound request. The result populates delegation attributes that later rules read.

## Choosing who the exchange is for

By default a `delegate` step exchanges the **user's** token: the minted credential speaks for the user, on-behalf-of style. Two step keys change that:

| Key | Meaning | Accepts | Default |
|-----|---------|---------|---------|
| `subject` | Whose identity the minted token speaks for. | `user`, `client`, `caller_workload`, `gateway` | `user` |
| `actor` | An additional credential recorded as the RFC 8693 `actor_token`, naming who is *acting*. | `user`, `client`, `caller_workload` | none |

`actor` accepts only inbound credentials, because an actor is by definition a party that presented itself to us. `subject` additionally accepts `gateway` — us — which is the one principal with no inbound credential at all.

### On-behalf-of a user, with the agent named

The common agentic shape: a user asked for something, and an agent is carrying it out. The user is the subject; the calling agent's SVID rides along as the actor, so the minted token carries `act` alongside `sub` and the backend can see both parties.

```yaml
pre_invocation:
  - "delegate(workday-oauth, target: workday-api, subject: user, actor: caller_workload,
              audience: workday-api, permissions: [read_compensation])"
```

### An agent acting on its own

A scheduled or background agent with no user in the loop exchanges its own SVID:

```yaml
pre_invocation:
  - "delegate(workday-oauth, target: workday-api, subject: caller_workload,
              audience: workday-api, permissions: [read_compensation])"
```

This requires a `role: caller_workload` identity resolver to have populated the SVID slot. With no workload credential present the exchange has no subject token and is denied rather than silently falling back.

### The gateway calling as itself

The common MCP-gateway deployment: agents authenticate to the gateway, but the *gateway* is the one holding access to the backend tools. The agent never possesses a credential the backend would accept.

```yaml
pre_invocation:
  - "require(role.hr)"
  - "delegate(workday-oauth, target: workday-api, subject: gateway,
              audience: workday-api, permissions: [read_compensation])"
```

`subject: gateway` has no inbound credential to exchange, so the delegator switches from RFC 8693 token exchange to an RFC 6749 §4.4 **`client_credentials`** grant: no `subject_token` is sent, and the gateway's identity is the OAuth client identity it already authenticates with. Nothing extra to configure — the delegator's existing `client_id` / `client_secret` *is* the gateway's identity.

Two consequences worth understanding before choosing this shape:

- **The gateway is the only enforcement point.** The backend sees a token that says "the gateway" and has no idea which agent triggered the call. Whatever the `require` gates allow is what happens; there is no second opinion downstream. Gate accordingly.
- **The minted token cannot name the calling agent.** `actor_token` is a token-exchange parameter with no meaning under `client_credentials`, so it is not sent even if the step asks for one. Attribution to the calling agent lives in your audit log, not in the credential. Carrying the agent inside the token requires the gateway to have a real subject credential of its own to exchange — its own SVID — which is not yet wired up.

### Who the minted token speaks for

Each exchange is attributed to exactly one principal, and the attribution is **derived from `subject`** rather than declared:

| `subject` | Attribution | Speaks for |
|-----------|-------------|-----------|
| `user` (default) | `on_behalf_of_user` | The end user |
| `client` | `on_behalf_of_user` | The brokering application |
| `caller_workload` | `as_caller_workload` | The calling agent |
| `gateway` | `as_gateway` | The gateway itself |

There is deliberately **no `mode` key**. If routes could declare the attribution independently of the credential they hand over, a route could claim to act on behalf of a user while exchanging a workload SVID. Deriving it means the operator states one thing — which credential — and the consequence follows.

The attribution is load-bearing beyond the audit trail: minted credentials are cached per `(subject, workload, audience, scopes, attribution)`, so tokens minted for one calling agent are never served to another.

## Delegation attributes

After a `delegate` effect, policy can read the outcome and the delegation context:

| Attribute | Meaning |
|-----------|---------|
| `delegation.granted.permissions` | Scopes the IdP actually granted on the minted token. |
| `delegation.depth` | How many delegations deep this request is. |
| `delegated` | True when the request is acting under a delegated credential. |
| `delegation.origin_subject_id` | The original subject at the head of the chain. |
| `delegation.actor_subject_id` | The acting subject for this hop. |

These let policy reason about the chain itself, for example `require(delegation.depth <= 1)` to refuse deeply nested delegation, or the post-check above to enforce least privilege on what was actually granted.

## How it connects to the pipeline

`delegate` dispatches to a plugin implementing the `token.delegate` hook. The minted credential is recorded in the request's delegation context and the audit log. Because delegation is an explicit effect rather than a side effect of forwarding, it is sequenced like any other effect: gated behind authorization, followed by verification, and halted on error when configured with `on_error: deny`.
