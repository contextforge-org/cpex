---
title: "Identity & Delegation"
weight: 45
---

# Identity & Delegation

CPEX does two identity jobs on every request: it resolves **who is calling in**
(inbound identity) and mints **the credential it calls out with** (outbound
delegation). This page is a recipe book. Find the shape you need — "a user acting
through an agent", "an agent acting as itself", "a service acting as itself" — copy
the plugin config and the route layout, and check the support matrix for where it
has actually been tested.

CPEX is a policy engine, not a particular product: the same config runs wherever you
place it (in front of the tools, inside the tool server, or agent-side — see
[Where to place CPEX](#where-to-place-cpex)). Throughout this page "the enforcement
point" means "wherever this CPEX instance runs."

For the conceptual model first, read [Use Cases]({{< relref "use-cases" >}}) and
[Deployment]({{< relref "deployment" >}}); for the full config schema, see
[Configuration]({{< relref "configuration" >}}).

## The model in one picture

Every request crosses two identity boundaries:

```
        inbound                                   outbound
  ┌──────────────────┐                    ┌──────────────────────┐
  │  identity.resolve │   route + policy   │     token.delegate    │
  │  (who called in)  │ ─────────────────▶ │  (whom we call out as)│
  └──────────────────┘                    └──────────────────────┘
   validates creds →                        mints the downstream
   typed identity slots                     credential per the route
```

- **Inbound** — `identity.resolve` plugins each read one credential (from a header)
  and land a typed identity in a slot. They are additive: one request can carry a
  user token *and* a workload SVID, both validated.
- **Outbound** — a `delegate(...)` step in the route runs a `token.delegate` plugin
  that mints the credential attached to the upstream call. What the minted token
  *speaks for* is chosen by the step's `subject:`.

## Building blocks

### Identity slots (inbound)

| Slot | Who it is | Typical header | Resolver |
|---|---|---|---|
| `subject` | the human on whose behalf the call is made | `X-User-Token` | `identity/jwt` (`role: user`) |
| `client` | the OAuth app / agent as a registered client | `Authorization` | `identity/jwt` (`role: client`) |
| `caller_workload` | the *calling workload's own* identity (e.g. a SPIFFE SVID) | `X-Workload-Token` | `identity/jwt` (`role: caller_workload`) |

### Delegation subjects (outbound)

The `subject:` on a `delegate(...)` step decides the OAuth mechanism the delegator uses:

| `subject:` | Minted token speaks for | Mechanism |
|---|---|---|
| `user` (default) | the human — on-behalf-of | RFC 8693 token exchange (`subject_token` = the user's token) |
| `caller_workload` | the calling agent, as itself | RFC 7523 client assertion (the SVID) → then scope down |
| `this_workload` | **the CPEX instance's own identity** — as itself, no inbound credential | RFC 6749 §4.4 `client_credentials` |

> `this_workload` names *this CPEX instance acting as its own identity*, whatever you've
> deployed it as — it is not a claim that CPEX is a gateway. (`gateway` is accepted as a
> deprecated alias.)

### "I want to…" → mechanism

| I want to… | Use | Spec |
|---|---|---|
| act as a service with no user | `subject: this_workload` → `client_credentials` | RFC 6749 §4.4 |
| act on behalf of a signed-in user | `subject: user` → token exchange | RFC 8693 |
| let a workload authenticate as *itself* by its SVID | `subject: caller_workload` → client assertion | RFC 7523 + `draft-ietf-oauth-spiffe-client-auth` |
| record both the user *and* the calling agent in the token | `subject: user`, `actor: caller_workload` | RFC 8693 `actor_token` |
| forward a token the caller already obtained | no `delegate` — pass the header through | — |

---

## Scoping — how broadly to apply it

CPEX resolves the pipeline for each request across one **broad → narrow stack**, and
**both identity and policy (including delegation) ride it** — narrower layers add to
(or override) broader ones. Pick the broadest layer that's still correct.

The layers, broad to narrow:

| Layer | Applies to | Identity uses… | Policy / delegation uses… |
|---|---|---|---|
| **Global** | every request | `global.authentication` | the `all` policy group's `plugins` |
| **Default** (per entity type) | every tool / prompt / resource | — | `global.defaults.<tool\|prompt\|resource>` |
| **Tag bundle** | routes tagged with `<tag>` | `global.policies.<tag>.authentication` | `global.policies.<tag>.plugins` |
| **Route (entity)** | one route (a `tool: "*"` route is the catch-all) | route `authentication:` | route `apl:` steps / `plugins:` |

So a `delegate(...)` is **not** route-only. To pick its breadth, put it — or a
`token.delegate` plugin — at the matching layer:

- **every tool** → a `delegate()` in a `tool: "*"` route, or the delegator plugin in
  `defaults.tool` / the `all` group,
- **a tagged class** → a tag bundle,
- **one tool** → a specific route (which overrides the `*` default — more specific wins).

### Identity example (the stack in one config)

```yaml
global:
  authentication: [jwt-user]            # every request gets user identity
  policies:
    hr-tools:
      authentication: [jwt-manager]     # + manager identity on HR-tagged routes
routes:
  - tool: get_compensation
    meta: { tags: [hr-tools] }          # inherits jwt-user + jwt-manager
```

**The override** — a route that must stand alone drops the inherited layers:

```yaml
routes:
  - tool: get_directory
    authentication:
      replace_inherited: true           # ignore global + tag layers…
      steps: [jwt-workload]             # …authenticate by the SVID alone
```

That is exactly what [Recipe 2](#recipe-2--agent-acting-as-itself-by-its-spiffe-svid)
uses. (Full tag/bundle/defaults syntax: [Configuration]({{< relref "configuration" >}}).)

### Rule of thumb

| You want… | Put it at |
|---|---|
| the same identity everywhere | **global** `authentication` |
| a recurring identity/plugin set across many tools | a **tag bundle** |
| one route handled differently, standalone | a **route** (`authentication: replace_inherited` for identity) |
| one delegation for most tools, exceptions for a few | a **default** (`tool: "*"` route or `defaults.tool`) + specific overrides |

---

## Recipes

Each recipe is a drop-in: the plugins it needs, the route layout, and where it has
been run. All config is [unified-config]({{< relref "configuration" >}}) YAML.

### Recipe 1 — User acting through an agent (on-behalf-of)

**When:** a human is signed in; the agent calls a downstream API *as that user*.
CPEX exchanges the user's IdP token for a downstream-audience token.

```yaml
plugins:
  - name: jwt-user
    kind: identity/jwt
    hooks: [identity.resolve]
    config:
      role: user
      header: X-User-Token
      trusted_issuers:
        - issuer: "https://idp.example.com/realms/corp"
          audiences: ["cpex"]        # the audience the user token is minted for
          algorithms: ["RS256"]
          decoding_key: { kind: jwks_url, url: "https://idp.example.com/realms/corp/protocol/openid-connect/certs" }

  - name: workday-oauth
    kind: delegator/oauth
    hooks: [token.delegate]
    capabilities: [read_inbound_credentials, write_delegated_tokens]
    config:
      token_endpoint: "https://idp.example.com/realms/corp/protocol/openid-connect/token"
      client_id: "cpex"              # this CPEX instance's own OAuth client
      client_secret_source: { kind: env_var, name: CPEX_CLIENT_SECRET }

global:
  authentication: [jwt-user]

routes:
  - tool: get_compensation
    apl:
      pre_invocation:
        - "require(role.hr)"
        - "delegate(workday-oauth, target: workday-api, audience: workday-api, permissions: [read_compensation])"
```

The minted `workday-api` token is attached to the upstream call. **Tested: Keycloak
26.x (Standard Token Exchange v2).**

### Recipe 2 — Agent acting as itself, by its SPIFFE SVID

**When:** the *agent* is the principal (no human), and you don't trust the agent to
hold downstream authority. The agent presents its SVID; CPEX brokers a scoped
downstream token. The agent holds no standing entitlement to the target.

> **The SVID is a JWT, but not an IdP token.** A JWT-SVID is an `ES256` JWT signed by
> *SPIRE* (validated against SPIRE's JWKS, not your IdP's) — a SPIFFE identity
> credential, not an OAuth access token. It can't be forwarded to the downstream or
> used as a bearer/subject token as-is; CPEX has to **turn it into an IdP-issued token
> first** — that's leg 1 below. (Contrast
> [Recipe 5](#recipe-5--scope-a-token-the-agent-already-holds-1-leg), whose input is a
> token already *minted from* an SVID.)

Add a workload resolver, scoped to the route so only it runs there:

```yaml
plugins:
  - name: jwt-workload
    kind: identity/jwt
    hooks: [identity.resolve]
    on_error: fail
    config:
      role: caller_workload
      header: X-Workload-Token
      trusted_issuers:
        - issuer: "https://spire-oidc.internal:8443"   # SPIRE OIDC discovery
          audiences: ["https://idp.example.com/realms/corp"]   # SVID aud = the IdP
          algorithms: ["ES256"]                                # SVIDs are EC-signed
          decoding_key: { kind: jwks_url, url: "https://spire-oidc.internal:8443/keys" }

routes:
  - tool: get_directory
    # Authenticate this route SOLELY by the SVID — drop the global user/client
    # resolvers. `jwt-workload` is NOT in global.authentication.
    authentication:
      replace_inherited: true
      steps: [jwt-workload]
    apl:
      pre_invocation:
        - "delegate(workday-oauth, target: workday-api, audience: workday-api, permissions: [read_compensation], subject: caller_workload)"
        - "!delegation.granted: deny"
```

For `subject: caller_workload`, the OAuth delegator runs **two legs**: leg 1 presents
the SVID as an RFC 7523 `client_assertion` (type `…:jwt-spiffe`) to authenticate the
agent as its IdP client; leg 2 exchanges that for the scoped downstream token. The
IdP side needs a SPIFFE identity provider (validates the SVID against SPIRE's trust
bundle) and a client bound to that SVID via SPIFFE/federated client authentication —
consult your IdP's SPIFFE client-auth docs. **Tested: Keycloak 26.6 (feature
`spiffe:v1`).**

> Why route-scope it: keeping the workload authority off the agent's own identity,
> and requiring the enforcement point's credential for the scope-up, is what makes
> CPEX the trust boundary — a compromised agent can prove who it is but cannot mint
> the downstream token itself.

### Recipe 3 — A service acting as itself

**When:** CPEX calls a downstream as *itself* — no inbound credential to exchange
(e.g. a scheduled job, or CPEX's own housekeeping).

```yaml
routes:
  - tool: sync_directory
    apl:
      pre_invocation:
        - "delegate(svc-oauth, target: workday-api, audience: workday-api, subject: this_workload)"
```

`subject: this_workload` switches the delegator to `client_credentials` — no
`subject_token`, CPEX's own `client_id`/secret is the identity. **Tested: Keycloak
(client_credentials).**

### Recipe 4 — Forward a token the caller already has (passthrough)

**When:** the agent authenticated to the IdP itself and hands CPEX a ready token.
CPEX just validates it inbound and lets the route forward it — no `delegate` step.
This is the "agent-brokered" case; it needs no delegation code, only that the
inbound resolver validates the token and the route allows the call.

### Recipe 5 — Scope a token the agent already holds (1-leg)

**When:** the agent authenticated to the IdP *itself* with its SVID and got back a
normal JWT — and you still want CPEX to narrow that token per-tool (least privilege
at the boundary) without ever handling the SVID.

> **The token is not the SVID.** The agent presented its SVID as a `client_assertion`
> *upstream* and received an ordinary IdP access token. That token arrives here **just
> like a user token** — same header, same JWKS validation, `RS256` (an IdP-signed
> JWT), *not* the `ES256` SVID. CPEX never sees the SVID; it sees a normal token.

```yaml
plugins:
  - name: jwt-agent
    kind: identity/jwt
    hooks: [identity.resolve]
    config:
      role: client                 # the agent as an OAuth client
      header: Authorization        # a normal bearer token — NOT X-Workload-Token
      trusted_issuers:
        - issuer: "https://idp.example.com/realms/corp"
          audiences: ["cpex"]
          algorithms: ["RS256"]    # an IdP-issued JWT, not the ES256 SVID
          decoding_key: { kind: jwks_url, url: "https://idp.example.com/realms/corp/protocol/openid-connect/certs" }
routes:
  - tool: get_directory
    apl:
      pre_invocation:
        - "delegate(workday-oauth, target: workday-api, audience: workday-api, permissions: [read_compensation], subject: client)"
```

This is a **plain RFC 8693 exchange** — the same engine as
[Recipe 1](#recipe-1--user-acting-through-an-agent-on-behalf-of), just scoping the
*agent's* token instead of a user's. **One leg** (the scope) — the agent already did
the authenticate leg upstream, so CPEX doesn't.

**Don't confuse this with Recipe 2.** The trigger is *what the agent presents* —
an SVID, or a token minted from one:

| Agent presents | Slot → subject | CPEX does | Legs |
|---|---|---|---|
| its **SVID** (`ES256`, SPIRE JWKS) | `caller_workload` → `subject: caller_workload` | authenticate **+** scope | 2 (Recipe 2) |
| a **token minted from its SVID** (`RS256`, IdP JWKS) | `client` → `subject: client` | scope only | 1 (this recipe) |
| a **token already right** for the tool | — | forward as-is | 0 (Recipe 4) |

Using `subject: caller_workload` on an already-minted token would wrongly route it
down the SVID two-leg (`client_assertion`) path — so match the subject to what
actually arrived: **an SVID is a `caller_workload`; a JWT minted from it is a
`client` (or `user`) token.**

---

## Where to place CPEX

The same config runs at any enforcement point. See
[Deployment → Placement guidance]({{< relref "deployment" >}}). The identity-specific read:

| Placement | Use it when | Because |
|---|---|---|
| **In front of the tools** (proxy / gateway) | agents are untrusted; you want one chokepoint | CPEX becomes the trust boundary that holds downstream authority; agents can't bypass it |
| **In the MCP / tool server** | defense in depth, or no proxy in the path | the resource enforces even if a front door is skipped; validates the caller right at the data |
| **Agent-side** | the agent is trusted and you want it to self-limit | least-privilege hygiene at the source — not a control against a compromised agent |

You can run CPEX at more than one point at once (agent hygiene + a chokepoint +
resource defense-in-depth) — same policy, different boundaries.

## IdP support: tested vs. should-work

CPEX's identity/delegation plugins are configured against OAuth/OIDC **standards**,
not any one vendor. What that means per layer:

| Capability | Standard | Tested | Should work (untested) |
|---|---|---|---|
| JWT validation (any inbound token) | JWT + JWKS (RFC 7519/7517) | Keycloak | Okta, IBM Verify, Auth0 — any OIDC IdP; point at its JWKS + issuer |
| Service token (`client_credentials`) | RFC 6749 §4.4 | Keycloak | broadly supported |
| On-behalf-of exchange | RFC 8693 | Keycloak (STE v2) | IdPs vary in RFC 8693 support — verify per target |
| SVID as client credential | RFC 7523 + `draft-ietf-oauth-spiffe-client-auth` | Keycloak 26.6 (`spiffe:v1`) | emerging — an IETF OAuth WG draft; other IdPs not yet confirmed |

**If your IdP doesn't (yet) speak SPIFFE**, you are not blocked. CPEX can validate
the SVID *itself* (it already fetches SPIRE's JWKS in `identity.resolve`), establish
`caller_workload`, and then mint the downstream token using its *own* credentials
(`subject: this_workload`) — carrying the workload identity as a claim. That
"CPEX-validates, CPEX-mints-as-itself" mode works with any OIDC IdP today; only the
recipe-2 *native* flow needs the IdP to understand SVIDs.

> Testing note: "Tested" means we have run it end-to-end against that IdP.
> "Should work" means it relies only on standards that IdP documents supporting —
> treat it as a starting point, not a guarantee, and tell us what you find.

## What to add next

<!-- Stubs to flesh out as recipes are validated:
  - Recipe 5 — user + actor: record the calling agent in `act` alongside the user
    (subject: user, actor: caller_workload) — RFC 8693 actor_token.
  - Recipe 6 — per-tenant / tag-scoped identity (authentication via tag bundles).
  - Recipe 7 — vault-backed delegation (exchange a token for a stored API key).
  - Per-recipe "verified against <IdP> on <date>" as the support matrix grows.
-->
