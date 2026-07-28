---
title: "Scoped credentials (Delegation)"
weight: 7
---

# Module 6: Scoped credentials (Delegation)

> You are in the [CPEX tutorial]({{< relref "_index" >}}). This module needs the IdP.

**Goal:** mint a narrow, downstream-scoped credential for a call with a real OAuth 2.0 token exchange (RFC 8693), instead of forwarding the caller's full token.

## The problem

When your agent calls a downstream API, handing it the caller's original token is over-broad: that token works everywhere, for everything the caller can do. You want a token minted for this one downstream call, scoped to a single audience, so a leak is contained. Token exchange does that, and CPEX makes it a policy step rather than integration code.

## Build it

Add a delegator plugin and a `delegate(...)` step. From [`policies/m06.yaml`](https://github.com/contextforge-org/cpex/tree/main/examples/tutorial/policies/m06.yaml):

```yaml
plugins:
  - name: keycloak
    kind: identity/jwt
    hooks: [identity.resolve]
    config: { ... as in module 2 ... }

  - name: workday-oauth
    kind: delegator/oauth
    hooks: [token.delegate]
    capabilities: [read_inbound_credentials, write_delegated_tokens]
    config:
      token_endpoint: http://localhost:8081/realms/cpex-tutorial/protocol/openid-connect/token
      client_id: cpex-gateway
      client_secret_source: { kind: literal, secret: gateway-dev-secret }
      insecure_http: true

routes:
  - tool: get_compensation
    authentication: [keycloak]
    authorization:
      pre_invocation:
        - "require(role.hr)"
        - "delegate(workday-oauth, target: workday-api, audience: workday-api)"
        - "require(delegation.granted)"
```

The `delegate(...)` step exchanges the caller's token for one scoped to the `workday-api` audience, against the real Keycloak token endpoint. `require(delegation.granted)` then proceeds only if the exchange succeeded.

Two things are load-bearing:

- The plugin declares `capabilities: [read_inbound_credentials, write_delegated_tokens]`. Without them, the caller's inbound token is filtered out before the exchange runs, and delegation fails with an empty token. Capabilities scope what each step may touch.
- The gateway client in Keycloak must be allowed to exchange for the target audience. In the tutorial realm, `cpex-gateway` sets `standard.token.exchange.audiences: workday-api,github-api` and carries audience mappers for those clients (see [`idp/realm-export.json`](https://github.com/contextforge-org/cpex/tree/main/examples/tutorial/idp)).

## Run it

```bash
cargo run -p cpex-tutorial --example m06_delegation
```

```
▸ alice (hr) → get_compensation (delegate mints a workday-api token, then allow)
  ✓ ALLOWED  { ... }

▸ evan (engineer) → get_compensation (denied at require(role.hr), no delegation)
  ✗ DENIED   [...] access denied
```

alice's call runs a real token exchange and gets a `workday-api`-scoped token before the backend call. evan never reaches delegation, because `require(role.hr)` stops him first. Delegation is cheap to skip when it is not needed.

## Try it

1. Drop the capabilities. Remove the `capabilities:` line from the plugin and re-run. Expect: alice is denied with `delegation.bad_request` (empty token), because the inbound credential was filtered out.
2. Wrong audience. Change `audience:` to a client the gateway may not target and re-run. Expect: the exchange is rejected by Keycloak and the step denies.
3. Narrow the grant (advanced). In `policies/m06.yaml`, add a `permissions:` argument to the `delegate(...)` step so it reads `delegate(workday-oauth, target: workday-api, audience: workday-api, permissions: [read_compensation])`. The exchange then requests only that scope. For Keycloak to actually issue it, the `read_compensation` client scope must exist on the realm and be assigned to the `workday-api` client (see [`idp/README.md`](https://github.com/contextforge-org/cpex/tree/main/examples/tutorial/idp)); without that realm setup the exchange returns the default scope. This is how you narrow the downstream grant to exactly what the operation needs.

## Checkpoint

{{< details "Why does the plugin need capabilities to succeed?" >}}
The inbound token is sensitive, so CPEX filters it out at the boundary unless a step declares `read_inbound_credentials`. Declaring the capability is how a delegator opts in to reading it, and `write_delegated_tokens` lets it record the minted token.
{{< /details >}}

{{< details "Where does the scoping happen, CPEX or Keycloak?" >}}
Keycloak mints the scoped token during the exchange, constrained by the requested audience and the gateway client's allowed targets. CPEX drives the exchange as a policy step and enforces that it succeeded.
{{< /details >}}

## Go deeper

- [Delegation]({{< relref "/docs/apl/delegation" >}}) for token exchange, capability reduction, and downstream verification.

## Next

[Module 7: Information flow]({{< relref "07-tainting" >}}): carry security state across a session to block write-down.
