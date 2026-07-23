---
title: "Identity & IdP"
weight: 30
---

# Identity and IdP Integration

Policy reads attributes: `role.hr`, `perm.view_ssn`, `subject.id`. Those attributes have to come from somewhere trustworthy. They come from identity resolution, which runs before policy and turns a verified credential into the attribute bag that predicates read.

## The requirement

The scenario authorizes with `require(role.hr)` and redacts with `redact(!perm.view_ssn)`. For those to mean anything, CPEX must know, for each request, who the caller is and what roles and permissions they hold, established from a token the caller cannot forge, not from anything the LLM said.

## Resolving identity

An identity plugin validates an inbound token and populates the subject. The bundled `identity/jwt` plugin verifies a JWT against a trusted issuer and maps its claims into the bag:

```yaml
plugins:
  - name: jwt-user
    kind: identity/jwt
    hooks: [identity.resolve]
    config:
      role: user
      header: X-User-Token
      trusted_issuers:
        - issuer: "https://idp.example.com/realms/agents"
          audiences: ["cpex-gateway"]
          decoding_key:
            kind: jwks_url
            url: "https://idp.example.com/realms/agents/protocol/openid-connect/certs"
```

The token is verified against the issuer's JWKS. Only after verification do its claims become attributes. An unverified or expired token resolves to no subject, and `require(authenticated)` denies.

## What lands in the bag

A resolved identity populates a flat attribute namespace that predicates read directly:

| Source | Attributes |
|--------|-----------|
| Subject | `subject.id`, `authenticated`, `subject.teams` |
| Roles | `role.<r>` (for example `role.hr`, `role.security`) |
| Permissions | `perm.<p>` (for example `perm.view_ssn`) |
| Claims | `claim.<k>` |
| OAuth client | `client.client_id`, `client.authorized_scopes`, `client.role.<r>` |
| Workload (SPIFFE / mTLS) | `caller_workload.spiffe_id`, `caller_workload.trust_domain` |

So `require(role.hr)` is true when the verified token carried the `hr` role, and `redact(!perm.view_ssn)` redacts unless it carried the `view_ssn` permission.

## Multiple sources

A request often carries more than one identity: the end user, the calling application, and the calling workload. Register an identity plugin per source. The bundled JWT plugin takes a `role` (`user`, `client`, or `caller_workload`) and a `header`, so each inbound credential resolves into its own namespace:

| `role` | Namespace | Typical credential |
|--------|-----------|--------------------|
| `user` | `subject.*` | End-user OIDC token on `X-User-Token` |
| `client` | `client.*` | OAuth client token on `Authorization` |
| `caller_workload` | `caller_workload.*` | SPIFFE JWT-SVID on `X-Workload-Token` |

Policy can then require several at once: `require(authenticated) & client.authorized_scopes contains "tools:invoke"`.

### Workload identity

A `role: caller_workload` resolver is the ingress for the **calling agent's** SPIFFE JWT-SVID:

```yaml
plugins:
  - name: jwt-workload
    kind: identity/jwt
    hooks: [identity.resolve]
    config:
      role: caller_workload
      header: X-Workload-Token
      trusted_issuers:
        - issuer: "https://spire.example.com"
          audiences: ["cpex-gateway"]
          decoding_key:
            kind: jwks_url
            url: "https://spire.example.com/keys"
```

The SPIFFE ID is read from the SVID's `sub` claim, and the trust domain is derived from it, populating `caller_workload.spiffe_id` and `caller_workload.trust_domain`. A token whose `sub` is not SPIFFE-shaped is **rejected** rather than filed into the workload slot, so anything policy finds there really is an attested workload.

Note the distinction the bag makes between two different machine identities:

- **`caller_workload`** — the attested workload on the inbound network peer. The agent calling *us*. Many different agents call through one gateway.
- **`this_workload`** — the gateway's *own* attested identity, used for outbound calls. A single principal.

They are not interchangeable, and confusing them is how a token minted for one agent ends up presented by another. Delegation depends on the distinction — see [Delegation]({{< relref "/docs/apl/delegation" >}}).

## How it connects to the pipeline

Identity resolution is a hook (`identity.resolve`) that runs ahead of the route's policy phase. The resolved subject is filtered by each downstream plugin's declared capabilities (see [Extensions & Capability-Gating]({{< relref "/docs/extensions" >}})): a plugin only sees the identity fields it is entitled to. APL predicates read the same bag, gated the same way.

Once identity is resolved, policy can authorize ([APL]({{< relref "/docs/apl" >}})), delegate downstream ([Delegation]({{< relref "/docs/apl/delegation" >}})), or hand a relationship decision to a PDP ([PDP Integration]({{< relref "/docs/apl/pdp" >}})).
