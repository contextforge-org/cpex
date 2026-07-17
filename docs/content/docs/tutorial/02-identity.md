---
title: "Who's calling?"
weight: 3
---

# Module 2: Who's calling? (Identity)

> You are in the [CPEX tutorial]({{< relref "_index" >}}). This module needs the IdP. Start it first:
> `docker compose -f examples/tutorial/idp/docker-compose.yml up -d`

**Goal:** resolve a real bearer token into a subject (an id, roles, and permissions) so authorization predicates have something to read.

## The problem

In module 1, `require(role.hr)` denied everyone because nobody had a role. Roles and permissions come from identity: a verified token the caller presents. CPEX turns that token into attributes policy can gate on, and it must do so without trusting anything the caller could forge.

## Build it

Add an identity plugin and reference it from the route. From [`policies/m02.yaml`](https://github.com/contextforge-org/cpex/tree/main/examples/tutorial/policies/m02.yaml):

```yaml
plugins:
  - name: keycloak
    kind: identity/jwt
    hooks: [identity.resolve]
    config:
      claim_mapper: standard
      trusted_issuers:
        - issuer: http://localhost:8081/realms/cpex-tutorial
          audiences: [cpex-tutorial]
          algorithms: [RS256]
          decoding_key:
            kind: jwks_url
            url: http://localhost:8081/realms/cpex-tutorial/protocol/openid-connect/certs
            insecure_http: true      # localhost speaks http; never in production
          leeway_seconds: 60

routes:
  - tool: get_compensation
    authentication:
      - keycloak
    authorization:
      pre_invocation:
        - "require(authenticated)"
        - "require(role.hr)"
```

The plugin validates the JWT offline against the realm's signing keys, fetched once from the JWKS url and cached. It checks issuer, audience, expiry, and signature. A token that fails any check is rejected before any authorization rule runs. The realm emits flat `roles` and `permissions` claims (see [`idp/README.md`](https://github.com/contextforge-org/cpex/tree/main/examples/tutorial/idp)). The `standard` mapper turns `roles: ["hr"]` into `role.hr = true` and `permissions: ["view_ssn"]` into `perm.view_ssn = true`.

The tutorial personas: alice (hr and `view_ssn`), dana (hr, no `view_ssn`), evan (engineer), sam (security).

## Run it

```bash
cargo run -p cpex-tutorial --example m02_identity
```

```
▸ alice (hr) → get_compensation
  ✓ ALLOWED  { ... }

▸ evan (engineer) → get_compensation (fails require(role.hr))
  ✗ DENIED   [...] access denied

▸ garbage token → get_compensation (rejected at validation)
  ✗ DENIED   [auth.malformed_header] ...
```

The harness mints each persona's token from Keycloak with a password grant (see `src/idp.rs`), then calls the same route. Identity, not code, splits the outcomes.

## Try it

1. Swap personas. In `m02_identity.rs`, mint `dana` instead of `evan`. Expect: dana (also hr) is allowed. The `view_ssn` difference does not matter until module 3.
2. Break the audience. In the policy, change `audiences: [cpex-tutorial]` to `[some-other-api]` and re-run. Expect: every call denies with `auth.audience_mismatch`, because validation fails before authorization.
3. Inspect a token. Mint one by hand (`idp/README.md` has the curl) and decode it to see the `roles`, `permissions`, and `aud` claims the mappers produced.

## Checkpoint

{{< details "Does CPEX call Keycloak on every request?" >}}
No. The plugin fetches the realm's public signing keys once and refreshes them periodically, then validates every token offline. Keycloak is on the token-minting path, not the per-request enforcement path.
{{< /details >}}

{{< details "Why is the garbage token denied with an auth code, not an authorization code?" >}}
Identity resolution runs before authorization. An unverifiable token never produces a subject, so the request is rejected at validation. The `require(role.hr)` rule is never reached.
{{< /details >}}

## Go deeper

- [Identity & IdP]({{< relref "/docs/apl/identity" >}}) for resolvers, the attribute bag, and claim mapping.

## Next

[Module 3: Shaping data]({{< relref "03-shaping" >}}): now that callers differ by permission, return a different view of the same record to each.
