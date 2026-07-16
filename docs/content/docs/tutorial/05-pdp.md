---
title: "Delegating decisions (PDP)"
weight: 6
---

# Module 5: Delegating decisions (PDP)

> You are in the [CPEX tutorial]({{< relref "_index" >}}). This module needs the IdP.

**Goal:** hand an authorization decision to a policy engine (a PDP) instead of writing it as a list of `require()` predicates, then let CPEX enforce the engine's verdict.

## The problem

Some rules mix several inputs at once: "engineers may search internal repos only; security may search anything." Expressing that as separate `require()` lines is awkward and easy to get wrong. A rule engine expression states it directly.

## Build it

Declare a PDP once, then reference it from a step. From [`policies/m05.yaml`](https://github.com/contextforge-org/cpex/tree/main/examples/tutorial/policies/m05.yaml):

```yaml
global:
  apl:
    pdp:
      - kind: cel

routes:
  - tool: search_repos
    authentication:
      - keycloak
    authorization:
      pre_invocation:
        - "require(authenticated)"
        - cel:
            expr: "(has(role.engineer) && role.engineer && args.visibility == 'internal') || (has(role.security) && role.security)"
            on_deny:
              - "deny('engineers read internal only; security reads any', 'repo.policy_denied')"
```

The `cel:` step evaluates a boolean expression over the same attributes predicates see: roles and request arguments. `true` allows, `false` runs `on_deny`. Guard optional attributes with `has(...)`, because referencing an unset attribute is an error, and CEL errors fail closed. Cedar is available too (`kind: cedar-direct`) when you want policy as data rather than an expression.

## Run it

```bash
cargo run -p cpex-tutorial --example m05_pdp
```

```
▸ evan (engineer) → search_repos internal (CEL allows)
  ✓ ALLOWED  { ... internal repos ... }

▸ evan (engineer) → search_repos public (CEL denies: engineers internal-only)
  ✗ DENIED   [repo.policy_denied] engineers read internal only; security reads any

▸ sam (security) → search_repos public (CEL allows: security reads any)
  ✓ ALLOWED  { ... public repos ... }
```

One expression captured a rule that mixes role and argument. The PDP decided, and CPEX enforced.

## Try it

1. Loosen the engineer rule. Change the expression to also allow engineers to read public repos. Re-run and confirm evan's public search now allows.
2. Break a guard. Remove a `has(...)` guard and run as sam. Expect: sam is denied, because the expression errors on the unset `role.engineer` and fails closed.
3. Change the deny code. Edit the `on_deny` code and confirm the reason code changes.

## Checkpoint

{{< details "Who makes the decision, CPEX or the PDP?" >}}
The PDP. CPEX gathers the attributes, calls the engine, and enforces the verdict. The engine is the source of truth for that decision.
{{< /details >}}

{{< details "Why did an unguarded expression fail closed?" >}}
Referencing an attribute that is not set is a CEL error. CPEX treats an errored PDP as a deny, so a typo or a missing attribute never accidentally allows.
{{< /details >}}

## Go deeper

- [PDP Integration]({{< relref "/docs/apl/pdp" >}}) for CEL, Cedar, and external engines.

## Next

[Module 6: Scoped credentials]({{< relref "06-delegation" >}}): mint a downstream-scoped token with a real token exchange.
