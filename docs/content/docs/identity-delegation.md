---
title: "Identity & Delegation"
weight: 55
---

# Identity & Delegation

CPEX does two identity jobs on every request: it resolves **who is calling in**
(inbound identity) and mints **the credential it calls out with** (outbound
delegation). Find the shape you need ("a user acting through an agent", "an agent
acting as itself", "a service acting as itself"), copy the plugin config and the
route layout, and check the support matrix for where it has been tested.

The same config runs wherever you place it: in front of the tools, inside the tool
server, or agent-side (see [Where to place CPEX](#where-to-place-cpex)). Throughout
this page "the enforcement point" means "wherever this CPEX instance runs."

For the conceptual model first, read [Use Cases]({{< relref "use-cases" >}}) and
[Deployment]({{< relref "deployment" >}}); for the full config schema, see
[Configuration]({{< relref "configuration" >}}).

## The model in one picture

Every request crosses two identity boundaries:

![Two identity boundaries: an inbound identity.resolve box (who is calling in) that validates credentials and lands typed identity slots, an arrow labelled route + policy, and an outbound token.delegate box (who we call out as) that mints the downstream credential per the route + subject; identity is additive across slots while delegation is chosen per route by subject](images/identity_two_boundaries.png)

- **Inbound.** `identity.resolve` plugins each read one credential (from a header)
  and land a typed identity in a slot. They are additive: one request can carry a
  user token *and* a workload SVID, both validated.
- **Outbound.** A `delegate(...)` step in the route runs a `token.delegate` plugin
  that mints the credential attached to the upstream call. The step's `subject:`
  chooses what the minted token *speaks for*.

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
| `user` (default) | the human, on-behalf-of | RFC 8693 token exchange (`subject_token` = the user's token) |
| `caller_workload` | the calling agent, as itself | RFC 7523 client assertion (the SVID) → then scope down |
| `this_workload` | **the CPEX instance's own identity**, as itself, no inbound credential | RFC 6749 §4.4 `client_credentials` |

> `this_workload` names *this CPEX instance acting as its own identity*, whatever you've
> deployed it as. It does not claim CPEX is a gateway. (`gateway` is accepted as a
> deprecated alias.)

### "I want to…" → mechanism

| I want to… | Use | Spec |
|---|---|---|
| act as a service with no user | `subject: this_workload` → `client_credentials` | RFC 6749 §4.4 |
| act on behalf of a signed-in user | `subject: user` → token exchange | RFC 8693 |
| let a workload authenticate as *itself* by its SVID | `subject: caller_workload` → client assertion | RFC 7523 + `draft-ietf-oauth-spiffe-client-auth` |
| record both the user *and* the calling agent in the token | `subject: user`, `actor: caller_workload` | RFC 8693 `actor_token` |
| forward a token the caller already obtained | no `delegate`, pass the header through | — |

---

## Scoping — how broadly to apply it

CPEX resolves the pipeline for each request across one **broad → narrow stack**, and
**both identity and policy (including delegation) ride it**. Narrower layers add to
(or override) broader ones. Pick the broadest layer that's still correct.

The layers, broad to narrow:

A **group** is a named, reusable bundle of policy (authentication steps +
authorization steps + plugins) that routes opt into. The layers, broad to narrow:

| Layer | Applies to | Identity uses… | Policy / delegation uses… |
|---|---|---|---|
| **Global** | every request | `global.authentication` | always-on global policy |
| **Default** (per entity type) | every tool / prompt / resource | — | `global.defaults.<tool\|prompt\|resource>` |
| **Group** | routes that join `<name>` (via `groups:` or a matching tag) | `groups.<name>.authentication` | `groups.<name>.authorization` / `plugins` |
| **Route (entity)** | one route (a `tool: "*"` route is the catch-all) | route `authentication:` | route `authorization:` steps / `plugins:` |

So a `delegate(...)` is **not** route-only. To pick its breadth, put it (or a
`token.delegate` plugin) at the matching layer:

- **every tool** → a `delegate()` in a `tool: "*"` route, or the delegator plugin in
  `defaults.tool`,
- **a class of tools** → a group,
- **one tool** → a specific route (which overrides the `*` default; more specific wins).

### The stack in one config

```yaml
global:
  authentication: [jwt-user]            # every request gets user identity

groups:
  hr-tools:
    authentication: [jwt-manager]       # + manager identity for this group
    authorization:
      pre_invocation:
        - "require(role.hr)"            # + policy for this group

routes:
  - tool: get_compensation
    groups: hr-tools                    # join the group: jwt-user + jwt-manager, require(role.hr)
    authorization:
      pre_invocation:
        - "delegate(workday-oauth, target: workday-api, audience: workday-api, permissions: [read_compensation])"
```

`groups: hr-tools` is the first-class way to join a group, and it is **sugar over
tags**: `meta: { tags: [hr-tools] }` is exactly equivalent, and host-injected runtime
tags join groups the same way. Tags stay the substrate — `groups:` just names the
common case.

**The override.** A route that must stand alone drops the inherited layers:

```yaml
routes:
  - tool: get_directory
    authentication:
      replace_inherited: true           # ignore global + group layers…
      steps: [jwt-workload]             # …authenticate by the SVID alone
```

That is what [Recipe 2](#recipe-2--agent-acting-as-itself-by-its-spiffe-svid)
uses. (Full group / defaults syntax: [Configuration]({{< relref "configuration" >}}).)

### Rule of thumb

| You want… | Put it at |
|---|---|
| the same identity everywhere | **global** `authentication` |
| a recurring identity/plugin set across many tools | a **group** |
| one route handled differently, standalone | a **route** (`authentication: replace_inherited` for identity) |
| one delegation for most tools, exceptions for a few | a **default** (`tool: "*"` route or `defaults.tool`) + specific overrides |

---

## Recipes

Each recipe is a drop-in: the plugins it needs, the route layout, and where it has
been run. All config is [unified-config]({{< relref "configuration" >}}) YAML.

> **Canonical keys.** These recipes write policy under `authorization:` (with
> `pre_invocation:` / `post_invocation:` inside) — the orchestrator-agnostic spelling.
> The older `apl:` wrapper is still accepted, and `pre_invocation:` may also be written
> flat on the route; all three compile identically.

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
    authorization:
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
> *SPIRE* (validated against SPIRE's JWKS, not your IdP's): a SPIFFE identity
> credential, not an OAuth access token. It can't be forwarded to the downstream or
> used as a bearer/subject token as-is; CPEX has to **turn it into an IdP-issued token
> first** (leg 1 below). Contrast
> [Recipe 5](#recipe-5--scope-a-token-the-agent-already-holds-1-leg), whose input is a
> token already *minted from* an SVID.

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
    # Authenticate this route by the SVID alone: drop the global user/client
    # resolvers. `jwt-workload` is NOT in global.authentication.
    authentication:
      replace_inherited: true
      steps: [jwt-workload]
    authorization:
      pre_invocation:
        - "delegate(workday-oauth, target: workday-api, audience: workday-api, permissions: [read_compensation], subject: caller_workload)"
        - "!delegation.granted: deny"
```

For `subject: caller_workload`, the OAuth delegator runs **two legs**: leg 1 presents
the SVID as an RFC 7523 `client_assertion` (type `…:jwt-spiffe`) to authenticate the
agent as its IdP client; leg 2 exchanges that for the scoped downstream token. The
IdP side needs a SPIFFE identity provider (validates the SVID against SPIRE's trust
bundle) and a client bound to that SVID via SPIFFE/federated client authentication;
consult your IdP's SPIFFE client-auth docs. **Tested: Keycloak 26.6 (feature
`spiffe:v1`).**

> Why route-scope it: keeping the workload authority off the agent's own identity,
> and requiring the enforcement point's credential for the scope-up, is what makes
> CPEX the trust boundary. A compromised agent can prove who it is but cannot mint
> the downstream token itself.

### Recipe 3 — A service acting as itself

**When:** CPEX calls a downstream as *itself*, with no inbound credential to exchange
(e.g. a scheduled job, or CPEX's own housekeeping).

```yaml
routes:
  - tool: sync_directory
    authorization:
      pre_invocation:
        - "delegate(svc-oauth, target: workday-api, audience: workday-api, subject: this_workload)"
```

`subject: this_workload` switches the delegator to `client_credentials`: no
`subject_token`, CPEX's own `client_id`/secret is the identity. **Tested: Keycloak
(client_credentials).**

### Recipe 4 — Forward a token the caller already has (passthrough)

**When:** the agent authenticated to the IdP itself and hands CPEX a ready token.
CPEX validates it inbound and lets the route forward it, with no `delegate` step.
This is the "agent-brokered" case; it needs no delegation code, only that the
inbound resolver validates the token and the route allows the call.

### Recipe 5 — Scope a token the agent already holds (1-leg)

**When:** the agent authenticated to the IdP *itself* with its SVID and got back a
normal JWT, and you still want CPEX to narrow that token per-tool (least privilege
at the boundary) without ever handling the SVID.

> **The token is not the SVID.** The agent presented its SVID as a `client_assertion`
> *upstream* and received an ordinary IdP access token. That token arrives here **like
> a user token**: same header, same JWKS validation, `RS256` (an IdP-signed
> JWT), *not* the `ES256` SVID. CPEX never sees the SVID; it sees a normal token.

```yaml
plugins:
  - name: jwt-agent
    kind: identity/jwt
    hooks: [identity.resolve]
    config:
      role: client                 # the agent as an OAuth client
      header: Authorization        # a normal bearer token, NOT X-Workload-Token
      trusted_issuers:
        - issuer: "https://idp.example.com/realms/corp"
          audiences: ["cpex"]
          algorithms: ["RS256"]    # an IdP-issued JWT, not the ES256 SVID
          decoding_key: { kind: jwks_url, url: "https://idp.example.com/realms/corp/protocol/openid-connect/certs" }
routes:
  - tool: get_directory
    authorization:
      pre_invocation:
        - "delegate(workday-oauth, target: workday-api, audience: workday-api, permissions: [read_compensation], subject: client)"
```

This is a **plain RFC 8693 exchange**, the same engine as
[Recipe 1](#recipe-1--user-acting-through-an-agent-on-behalf-of), scoping the
*agent's* token instead of a user's. **One leg** (the scope): the agent did
the authenticate leg upstream, so CPEX doesn't.

**Don't confuse this with Recipe 2.** The trigger is *what the agent presents*:
an SVID, or a token minted from one:

| Agent presents | Slot → subject | CPEX does | Legs |
|---|---|---|---|
| its **SVID** (`ES256`, SPIRE JWKS) | `caller_workload` → `subject: caller_workload` | authenticate **+** scope | 2 (Recipe 2) |
| a **token minted from its SVID** (`RS256`, IdP JWKS) | `client` → `subject: client` | scope only | 1 (this recipe) |
| a **token already right** for the tool | — | forward as-is | 0 (Recipe 4) |

Using `subject: caller_workload` on an already-minted token misroutes it
down the SVID two-leg (`client_assertion`) path. Match the subject to what
arrived: **an SVID is a `caller_workload`; a JWT minted from it is a
`client` (or `user`) token.**

### Recipe 6 — User acting through an agent, with the agent named (dual-principal)

**When:** a human is signed in *and* you want the record to name the agent that
carried out the call. The minted token speaks for the user (`sub`), and CPEX
additionally names the calling agent as the RFC 8693 acting party (`act`) — so a token
service that honors delegation records **both** who authorized the action and who
performed it. This is the common agentic shape: the human decides, the agent acts.
(Whether the `act` claim actually lands depends on the token service — see the interop
note.)

It composes two inbound resolvers you have already met — `jwt-user`
([Recipe 1](#recipe-1--user-acting-through-an-agent-on-behalf-of)) for the human on
`X-User-Token`, and `jwt-workload`
([Recipe 2](#recipe-2--agent-acting-as-itself-by-its-spiffe-svid)) for the agent's
SVID on `X-Workload-Token`. Both must resolve; both credentials arrive on every call.

```yaml
global:
  # define jwt-user (Recipe 1) and jwt-workload (Recipe 2); run both
  authentication: [jwt-user, jwt-workload]

routes:
  - tool: get_compensation
    authorization:
      pre_invocation:
        - "require(role.hr)"
        - "delegate(workday-oauth, target: workday-api, audience: workday-api,
                    permissions: [read_compensation],
                    subject: user, actor: caller_workload)"
```

`subject: user` makes the user's token the RFC 8693 `subject_token` (exactly as
[Recipe 1](#recipe-1--user-acting-through-an-agent-on-behalf-of)); `actor:
caller_workload` *additionally* attaches the agent's SVID as the `actor_token`,
**requesting** that the minted token carry `act` alongside `sub`. It's **one exchange
call, two principals in the request** — not a second leg. `actor` accepts only inbound
credentials (`user`, `client`, `caller_workload`): the acting party is by definition
one that presented itself to CPEX. Whether `act` actually lands in the token is the
token service's call — see the interop note below.

> **Subject vs. actor.** The *subject* is who the token speaks **for** (whose
> authority); the *actor* is who is **doing** it (attribution). Least-privilege scoping
> still follows the subject — the `act` claim records the agent, it doesn't grant it
> anything.

**Which actor — `client` or `caller_workload`?** Match it to *how the agent
authenticated*. An agent that presented a SPIFFE SVID is a `caller_workload` (above);
one that authenticated as a registered OAuth client — an `Authorization` bearer token,
resolved with `role: client` — is `actor: client`:

```yaml
- "delegate(workday-oauth, target: workday-api, audience: workday-api,
            permissions: [read_compensation], subject: user, actor: client)"
```

> **Valid combinations.** `actor:` pairs with `subject: user` or `subject: client`
> — the on-behalf-of shape. It is **not** supported with `subject: caller_workload`
> (the workload is already the subject) or `subject: this_workload` (a
> `client_credentials` grant carries no `actor_token`); CPEX **rejects** those at
> config time rather than silently dropping the actor.

**CPEX side — implemented and e2e-tested against a mock IdP.** The delegator puts the
actor on the wire exactly as RFC 8693 delegation prescribes (`actor_token` +
`actor_token_type`), and omits it cleanly when no actor is configured. That half is
correct regardless of which token service receives it.

> **Interop: `act` is the token service's job — impersonation vs. delegation.**
> RFC 8693 (§1.1) exchanges come in two flavors. *Impersonation* returns a token that
> speaks purely for the subject — indistinguishable from one the subject fetched
> directly, **no `act` claim**. *Delegation* additionally records the actor in a nested
> `act`. The `actor_token` parameter is what asks for delegation; only a token service
> that implements the delegation path emits `act`. **CPEX always sends the delegation
> request — but the claim only appears if the service honors it.**
>
> **Keycloak does not.** Keycloak's Standard Token Exchange (v2, tested here on 26.6)
> implements impersonation only: it **silently ignores `actor_token`** and returns a
> subject-only token with no `act`. The tell (probed 2026-07-28): passing even a raw,
> untrusted-issuer SVID as the exchange's `actor_token` produces **no error** — Keycloak
> never parses the parameter, so no mapper or config can surface it. To see `act` end-to-end you need a
> delegation-capable token service; against Keycloak, capture the acting agent at the
> CPEX boundary (audit / downstream header) instead — CPEX resolves both principals
> either way.

---

## Where to place CPEX

The same config runs at any enforcement point. See
[Deployment → Placement guidance]({{< relref "deployment" >}}). The identity-specific read:

| Placement | Use it when | Because |
|---|---|---|
| **In front of the tools** (proxy / gateway) | agents are untrusted; you want one chokepoint | CPEX becomes the trust boundary that holds downstream authority; agents can't bypass it |
| **In the MCP / tool server** | defense in depth, or no proxy in the path | the resource enforces even if a front door is skipped; validates the caller right at the data |
| **Agent-side** | the agent is trusted and you want it to self-limit | least-privilege hygiene at the source, not a control against a compromised agent |

You can run CPEX at more than one point at once (agent hygiene + a chokepoint +
resource defense-in-depth): same policy, different boundaries.

## IdP support: tested vs. should-work

CPEX's identity/delegation plugins are configured against OAuth/OIDC **standards**,
not any one vendor. Per layer:

| Capability | Standard | Tested | Should work (untested) |
|---|---|---|---|
| JWT validation (any inbound token) | JWT + JWKS (RFC 7519/7517) | Keycloak | Okta, IBM Verify, Auth0, any OIDC IdP; point at its JWKS + issuer |
| Service token (`client_credentials`) | RFC 6749 §4.4 | Keycloak | broadly supported |
| On-behalf-of exchange | RFC 8693 | Keycloak (STE v2) | IdPs vary in RFC 8693 support; verify per target |
| SVID as client credential | RFC 7523 + `draft-ietf-oauth-spiffe-client-auth` | Keycloak 26.6 (`spiffe:v1`) | emerging; an IETF OAuth WG draft, other IdPs not yet confirmed |

**If your IdP doesn't (yet) speak SPIFFE**, you are not blocked. CPEX can validate
the SVID *itself* (it already fetches SPIRE's JWKS in `identity.resolve`), establish
`caller_workload`, and then mint the downstream token using its *own* credentials
(`subject: this_workload`). Note the trade-off: a `client_credentials` grant carries
**no** caller identity, so the minted token speaks for CPEX, not the agent — capture
the caller at the CPEX boundary (audit) if the backend needs it. That
"CPEX-validates, CPEX-mints-as-itself" mode works with any OIDC IdP today; only the
recipe-2 *native* flow needs the IdP to understand SVIDs.

> Testing note: "Tested" means we have run it end-to-end against that IdP.
> "Should work" means it relies only on standards that IdP documents supporting.
> Treat it as a starting point, not a guarantee, and tell us what you find.

## What to add next

<!-- Stubs to flesh out as recipes are validated:
  - Recipe 7 — per-tenant / tag-scoped identity (authentication via groups / tags).
  - Recipe 8 — vault-backed delegation (exchange a token for a stored API key).
  - Live-IdP validation of Recipe 6's actor_token / `act` claim (currently mock-tested).
  - Per-recipe "verified against <IdP> on <date>" as the support matrix grows.
-->
