---
title: "Identity Claim Mapping"
weight: 56
---

# Identity Claim Mapping

The `identity/jwt` resolver builds a subject, a client and a workload identity from a token's claims. Which claims hold roles, scopes or the client id differs by IdP, so the mapping is configuration. You name a shipped preset or write the map inline, under the plugin's `config:`.

**Surfaces.** Mapping runs inside the engine, so the same config works from Rust, Python and Go. Python hosts call `identity.resolve` with an identity payload dict (`{"source": "bearer", "headers": {...}}`); Go hosts use `NewIdentityPayload`. The resolved subject comes back on the result's modified payload.

## Presets

```yaml
plugins:
  - name: keycloak
    kind: identity/jwt
    hooks: [identity.resolve]
    capabilities: [perform_http]
    config:
      claim_mapper: keycloak       # standard | keycloak | auth0 | cognito | ibmverify
      trusted_issuers: [ ... ]
```

Naming no mapper resolves to `standard`, so an existing config is unaffected.

| Preset | Reads | Leaves out on purpose |
|---|---|---|
| `standard` | `sub`; `roles`; `permissions` or `scope`; `teams` or `groups`; for a client `client_id` or `azp`, `client_name`, scopes, `aud`, roles; a SPIFFE ID from `sub` or `spiffe_id` for a workload | Nothing; collections are read as arrays only. |
| `keycloak` | `realm_access.roles` into roles, `scope` into permissions, `client_id` / `azp` / `clientId` as the client | Per-client roles (`resource_access.<client-id>.roles`), because the client id is yours to choose; teams, because Keycloak's default `groups` claim holds realm roles. |
| `auth0` | `sub`, the `permissions` array ahead of `scope`, `client_id` / `azp` | Roles and teams, which Auth0 only allows under a namespace that is specific to your deployment. |
| `cognito` | `sub`, `cognito:groups` into teams, `scope` into permissions, `client_id` | Roles (`cognito:roles` holds IAM role ARNs) and the client audience. |
| `ibmverify` | Tenant-provisioned roles, teams, permissions, client roles and scopes, as a scalar or an array | A workload section; `gh_permissions` and `manager`, which policy reads as raw claims. |

Each preset leaves a field empty rather than fill it with the wrong concept. Use `ibmverify` for IBM Verify: Verify emits a one-value collection as a bare string, and `standard` would read that as empty. That shows up as a policy deny, not as a config error.

## An inline map

`claim_map` uses the same schema as a preset. Candidate paths are tried in order:

```yaml
config:
  claim_map:
    subject:
      roles:
        paths:
          - realm_access.roles
          - resource_access.my-api.roles
        merge: union             # first_match (default) | union
      permissions:
        paths:
          - { path: permissions, array_only: true }
          - scope
        split: whitespace        # break a delimited string into elements
        on_missing: deny         # ignore (default) | deny
```

Sections and the fields each one may map:

| Section | Fields |
|---|---|
| `subject` | `id`, `roles`, `permissions`, `teams` |
| `client` | `client_id`, `client_name`, `roles`, `permissions`, `teams`, `authorized_scopes`, `authorized_audiences` |
| `workload` | `spiffe_id`, `client_id`, `selectors` |

A workload's trust domain is always derived from its SPIFFE ID, never read from a claim.

A field takes one of three forms:

- `id: sub`: one path.
- `teams: [teams, groups]`: ordered candidates.
- `roles: { paths: [...], merge: union }`: candidates plus options.

Options:

| Option | Effect |
|---|---|
| `array_only` | Accept only an array at this path. |
| `string_only` | Accept only a string at this path. |
| `stop_if_present` | If the claim exists but its value is unusable, stop instead of trying the next candidate. Scalar fields only. |
| `split: whitespace` | Split a string such as an OAuth `scope`. |
| `merge: union` | Combine every resolving candidate. Collections only. |
| `on_missing: deny` | Refuse the token when no candidate resolves, instead of leaving the field empty. |

`.` separates path segments and `\` escapes one. Every other character, `:` and `/` included, is literal: `cognito:groups` is one segment written as is, and escaping the colon is rejected. A field whose candidates all miss is left empty and logged with every path tried.

A malformed map fails when the plugin is built, naming the field and path, so a bad map never reaches a request.

## Gating on the issuer

Registered claims such as `iss` are dropped from the policy-visible claims by default. `claims:` overrides that. It sits next to `claim_mapper` or `claim_map`:

```yaml
config:
  claim_mapper: keycloak
  claims:
    include: [iss]               # keep one the mapper drops
    exclude: [internal_debug]    # drop an otherwise visible claim
```

`claim.iss` is then readable from policy, so a deployment trusting several issuers can gate on which one signed. Both lists take top-level claim names. A dotted entry fails to load; a claim whose own name has a dot is written with `\.`.

## API keys

`identity/api-key` resolves an opaque key against a file or HTTP directory and maps the record's fields with the same mapping machinery, under `record_map:`. See PPE's [identity and delegation guide](https://github.com/praxis-proxy/policy/blob/v0.4.1/docs/content/identity-delegation.md#recipe-7-an-opaque-api-key-resolved-against-a-directory) for the full config and its denial codes.

## A preset for another IdP

Presets are JSON files compiled into PPE's `identity/jwt` builtin, so a new one is a PPE change, not a CPEX one. Prototype it as an inline `claim_map` first: the schema is identical, and the map works today. To contribute it, follow PPE's [guide to adding a claim mapper preset](https://github.com/praxis-proxy/policy/blob/v0.4.1/docs/content/identity-claim-mapping.md). It ships to CPEX when CPEX moves its PPE pin.

## Go deeper

- [Identity & Delegation]({{< relref "/docs/identity-delegation" >}}): resolving and delegating identity end to end.
- [APL identity]({{< relref "/docs/apl/identity" >}}): the `authentication:` block.
- [CMF Extensions]({{< relref "/docs/cmf-extensions" >}}): how the resolved subject and claims become `subject.*`, `role.*` and `claim.*` keys.
