---
title: "Workload identity (SVID)"
weight: 17
---

# Module 16: Workload identity (the agent proves itself with a SPIFFE SVID)

> You are in the [CPEX tutorial]({{< relref "_index" >}}). This module needs the IdP and the SPIRE overlay.
>
> **Cookbook recipe:** [Recipe 2: Agent acting as itself, by its SPIFFE SVID]({{< relref "/docs/identity-delegation#recipe-2-agent-acting-as-itself-by-its-spiffe-svid" >}}).

**Goal:** let a workload authenticate with a SPIFFE SVID, no user and no client secret, and have CPEX broker a scoped downstream token from it.

## The problem

A workload's native identity is a SPIFFE SVID: an ES256 JWT signed by SPIRE, not by your IdP. It proves *what the workload is* (`sub` = `spiffe://…/agent/hr-copilot`), attested by the platform, with no secret to leak. Every caller so far held an OAuth credential instead, whether a user's JWT (module 6), a client's token (module 13), or nothing (passthrough).

An SVID is an identity credential, not an OAuth token: it can't be forwarded downstream or used as an exchange subject as-is. So `subject: caller_workload` runs two legs:

1. **Authenticate.** Present the SVID as an RFC 7523 `client_assertion` (type `…:jwt-spiffe`) so the IdP issues an ordinary token for the agent.
2. **Scope.** Exchange that token (RFC 8693) for the downstream-scoped token.

The agent holds no standing entitlement to the target: CPEX brokers the scope-up with its own gateway credential in leg 2. A compromised agent can prove who it is but cannot mint the downstream token itself.

## Bring up the infrastructure

This module needs a SPIFFE authority (SPIRE) and a Keycloak that speaks SPIFFE. Both come from an opt-in overlay that modules 0 to 15 never use.

```bash
# SPIRE server + OIDC provider, and Keycloak bumped to 26.6.1 with spiffe:v1
docker compose -f examples/tutorial/idp/docker-compose.yml \
  -f examples/tutorial/idp/docker-compose.spire.yml up -d

# Trust SPIRE and bind the agent's SPIFFE ID to a federated-jwt client
./examples/tutorial/idp/spire/setup-spiffe.sh
```

The setup script does two things through the admin API, kept out of the realm export so the base Keycloak never sees SPIFFE config. It registers a SPIFFE identity provider that validates SVIDs against SPIRE's JWKS, and it creates a `federated-jwt` client (`hr-copilot-agent`) bound to `spiffe://cpex.tutorial/agent/hr-copilot`, with an audience mapper so the gateway can exchange its token.

`make tutorial-check-spire` runs the same sequence and then the module in `--check` mode.

## Build it

One resolver for the SVID, and a `subject: caller_workload` delegation. From [`policies/m16.yaml`](https://github.com/contextforge-org/cpex/tree/main/examples/tutorial/policies/m16.yaml):

```yaml
plugins:
  - name: jwt-workload
    kind: identity/jwt
    config:
      role: caller_workload             # -> the caller_workload slot
      header: X-Workload-Token
      trusted_issuers:
        - issuer: http://spire-oidc:8443            # SPIRE, not the IdP
          audiences: [http://localhost:8081/realms/cpex-tutorial]   # SVID aud = the IdP
          algorithms: [ES256]                       # SVIDs are EC-signed
          decoding_key: { kind: jwks_url, url: "http://localhost:8443/keys" }

routes:
  - tool: search_repos
    authentication: [jwt-workload]        # authenticate by the SVID alone
    authorization:
      pre_invocation:
        - "delegate(workday-oauth, target: github-api, audience: github-api, subject: caller_workload)"
        - "require(delegation.granted)"
```

The delegator is the same `cpex-gateway` OAuth delegator as every other module. `subject: caller_workload` is what tells it to run the two legs.

## Run it

```bash
cargo run -p cpex-tutorial --example m16_workload
```

```
▸ agent (SVID on X-Workload-Token) → search_repos (subject: caller_workload, two-leg)
  ✓ ALLOWED  { ... "repositories":[ ... ] }

▸ anonymous → search_repos (no SVID, so nothing to broker from)
  ✗ DENIED   [delegation.bad_request] ... empty bearer_token ...
```

The example mints the SVID off SPIRE (`spire-server jwt mint`), presents it on `X-Workload-Token`, and CPEX does the rest: validate → `caller_workload` → leg 1 → leg 2 → a `github-api`-scoped token. The agent never saw that token.

## The SVID vs. a token minted from one

How this differs from module 13:

| The agent presents | Slot → subject | CPEX does | Legs |
|---|---|---|---|
| its SVID (ES256, SPIRE's JWKS) | `caller_workload` → `subject: caller_workload` | authenticate, then scope | 2 (this module) |
| a token minted from its SVID (RS256, IdP's JWKS) | `client` → `subject: client` | scope only | 1 ([module 13]({{< relref "13-client" >}})) |

Match the subject to what actually arrived. Using `subject: caller_workload` on an already-minted token would misroute it down the two-leg `client_assertion` path.

## Try it

1. **Name the agent as the actor.** Combine with [module 15]({{< relref "15-dual-principal" >}}): add a user on `X-User-Token`, keep the SVID, and use `subject: user, actor: caller_workload`. The human authorizes, the agent is the actor.
2. **Tamper with the SVID.** Change one character of the token before presenting it. Expect: the resolver rejects it, because the ES256 signature no longer verifies against SPIRE's JWKS.
3. **Wrong audience.** Mint the SVID with `-audience something-else`. Expect: leg 1 fails, because the SPIFFE client-auth draft requires the SVID's audience to be the IdP it authenticates to.

## Checkpoint

{{< details "Why two legs, when module 13 needed only one?" >}}
Because an SVID is not an IdP token. Module 13's caller already held an IdP-issued token (it did the authenticate leg itself), so CPEX only scoped it. Here the agent holds an SVID, so CPEX must first turn it into an IdP token (leg 1) and then scope it (leg 2).
{{< /details >}}

{{< details "Where does the downstream authority come from?" >}}
From leg 2, CPEX's own gateway credential, not from the agent. The SVID proves identity and grants nothing downstream, which is why a compromised agent can't mint the target token itself.
{{< /details >}}

## Go deeper

- [Recipe 2: Agent acting as itself, by its SPIFFE SVID]({{< relref "/docs/identity-delegation#recipe-2-agent-acting-as-itself-by-its-spiffe-svid" >}}) for the reference version and the IdP-support notes (tested on Keycloak 26.6, `spiffe:v1`).
- [Delegation reference]({{< relref "/docs/apl/delegation" >}}) for the full `subject:` contract.

## Next

[Module 17: Multi-issuer identity]({{< relref "17-federation" >}}): accept callers from more than one IdP with a single resolver.
