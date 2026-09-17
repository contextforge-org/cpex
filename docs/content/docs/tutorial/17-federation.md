---
title: "Multi-issuer (trust federation)"
weight: 18
---

# Module 17: Multi-issuer identity (trust more than one IdP)

> You are in the [CPEX tutorial]({{< relref "_index" >}}). This module needs the IdP.

**Goal:** accept callers from more than one identity provider with a single resolver, each token validated against its own issuer's keys.

## The problem

A single enforcement point often fronts several identity providers: your own workforce IdP and a partner org's, a legacy realm and its replacement during a migration, one IdP per business unit. You want to accept tokens from all of them, only those, and validate each on the correct keys.

A JWT names its issuer in the `iss` claim. CPEX matches that to a trusted issuer and validates the token against *that* issuer's JWKS. List several, and one resolver federates them; a token whose `iss` is in none is rejected with `auth.untrusted_issuer`.

## Build it

One resolver, two `trusted_issuers`. From [`policies/m17.yaml`](https://github.com/contextforge-org/cpex/tree/main/examples/tutorial/policies/m17.yaml):

```yaml
plugins:
  - name: keycloak
    kind: identity/jwt
    config:
      role: user
      claim_mapper: standard
      trusted_issuers:
        - issuer: http://localhost:8081/realms/cpex-tutorial   # home realm
          audiences: [cpex-tutorial]
          algorithms: [RS256]
          decoding_key: { kind: jwks_url, url: "…/cpex-tutorial/…/certs" }
        - issuer: http://localhost:8081/realms/cpex-partner    # partner realm
          audiences: [cpex-tutorial]
          algorithms: [RS256]
          decoding_key: { kind: jwks_url, url: "…/cpex-partner/…/certs" }   # ITS OWN keys
```

Each entry is a full trust anchor: its own issuer string, its own JWKS, its own accepted audiences. Here both issuers are realms in the same Keycloak, but they could be entirely separate products. The resolver only matches `iss`.

## Run it

The tutorial IdP imports a second realm, `cpex-partner`, with one user (`pat`).

```bash
cargo run -p cpex-tutorial --example m17_federation
```

```
▸ alice (home realm cpex-tutorial) → get_compensation (issuer #1, role.hr)
  ✓ ALLOWED  { ... }

▸ pat (partner realm cpex-partner) → get_compensation (issuer #2, validated on ITS keys)
  ✓ ALLOWED  { ... }

▸ outsider (master realm, an untrusted issuer) → get_compensation (rejected)
  ✗ DENIED   [auth.untrusted_issuer] issuer 'http://localhost:8081/realms/master' is not in the trusted-issuer list
```

Both `alice` and `pat` reach the same route under the same rule (`require(role.hr)`), and the policy never mentions issuers. The third token is a genuine, validly-signed JWT from Keycloak's `master` realm, which the resolver doesn't trust, so it is rejected before any authorization runs.

## Claims still have to line up

Federation validates *signatures*; it does not normalize *claims*. Two IdPs may express roles differently, and the resolver reads a flat `roles` array (module 2). The partner realm here is configured to emit the same `roles` and `permissions` shape as the home realm, which is why `pat` satisfies `require(role.hr)`. Against a real partner IdP, mapping its claims into the shape your policy expects is the harder half; the trust list is the easy one.

## Try it

1. **Drop the partner issuer.** Delete the second `trusted_issuers` entry and re-run. Expect: `pat` now fails with `auth.untrusted_issuer`, the same token, no longer trusted.
2. **Break the partner keys.** Point the partner entry's `decoding_key.url` at the *home* realm's certs. Expect: `pat` fails signature validation, because each issuer must be verified on its own keys.
3. **Diverge the claims.** Give `pat` a role the home realm doesn't use and gate the route on it. That is the per-issuer claim-mapping problem, in one realm.

## Checkpoint

{{< details "How does CPEX pick which keys to validate a token with?" >}}
By the token's `iss` claim. It finds the matching entry in `trusted_issuers` and validates against that entry's JWKS and accepted audiences. No match → `auth.untrusted_issuer`, before any policy runs.
{{< /details >}}

{{< details "Is a trusted issuer the same as trusting everything it says?" >}}
No. Trust means "I accept tokens this issuer signed." What those tokens are *allowed* to do is still your authorization policy, and whether their claims mean what yours mean is still claim mapping. Federation is authentication, not authorization.
{{< /details >}}

## Go deeper

- [Identity → Multiple sources]({{< relref "/docs/apl/identity#multiple-sources" >}}) for the full multi-issuer / multi-resolver model.
- [Configuration]({{< relref "/docs/configuration" >}}#plugins) for the `trusted_issuers` schema.

## Next

[Module 18: Static attributes]({{< relref "18-attributes" >}}): feed policy operator-maintained facts from a data file, read as `data.*`.
