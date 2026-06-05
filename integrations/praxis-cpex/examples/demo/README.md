# CPEX-Praxis HR Demo

End-to-end walkthrough wiring **Praxis** (cloud-native AI proxy),
**Keycloak** (OIDC IdP), and an **MCP server** (Model Context
Protocol) through the CPEX/APL plugin stack to enforce:

* multi-role identity (user + client tokens via different headers)
* RFC 8693 OAuth 2.0 token exchange
* attribute-based policy in APL (`require(role.hr)`)
* on-the-wire body rewriting (`redact(args.ssn)`)

> The story: Alice (an engineer) is denied. Bob (HR) is allowed and
> his request reaches the backend with a freshly minted, audience-
> scoped token — **never** his original IdP JWT. Eve (HR but no
> SSN-view permission) is allowed, but `args.ssn` is rewritten to
> `[REDACTED]` before the backend ever sees it.

## What runs where

```
┌──────────────────────────────────────────────────────────────────┐
│ host                                                             │
│                                                                  │
│   praxis-cpex (Rust binary, you build it)        :8090           │
│        │                                                         │
│        ├── identity resolvers (apl-identity-jwt)                 │
│        │   • jwt-user reads X-User-Token                         │
│        │   • jwt-client reads Authorization                      │
│        │                                                         │
│        ├── APL policy evaluator                                  │
│        │   • require(role.hr)                                    │
│        │   • redact(args.ssn) when !perm.view_ssn                │
│        │                                                         │
│        └── apl-delegator-oauth                                   │
│            └── RFC 8693 token-exchange ──────►  Keycloak  :8081  │
│                                                       (docker)   │
│                                                                  │
│                  forwards to ──────►  hr-mcp     :9100           │
│                                       (docker)                   │
└──────────────────────────────────────────────────────────────────┘
```

* **Keycloak** runs in docker-compose. Realm `cpex-demo` is imported
  at startup from `keycloak/realm-export.json`. It defines users
  (alice/bob/charlie/eve), a confidential client `hr-copilot`,
  another confidential client `praxis-gateway` (used by the gateway
  to authenticate to Keycloak for token-exchange), and a public
  client `workday-api` (the downstream audience).
* **hr-mcp** also runs in docker-compose. It's a small FastAPI app
  speaking MCP-shaped JSON-RPC over HTTP. It logs every inbound
  request's `Authorization` + parsed args so you can SEE what
  reached the backend.
* **praxis-cpex** is a Rust binary on the host. You build it once
  with `cargo build --release -p praxis-cpex-bin` from the
  workspace root.

## A note on the credentials in this directory

This demo is fully self-contained — every "secret" you see in
`keycloak/realm-export.json`, `cpex.yaml`, the scenario scripts, and
the LLM agent is a **demo-only value for a local docker-compose
Keycloak realm** (`cpex-demo`). Specifically:

* `hr-copilot-secret` and `praxis-gateway-secret` are the Keycloak
  client secrets for the two OAuth clients in the demo realm. They
  exist only inside the container that `docker compose up -d` brings
  up on `localhost:8081`. There is no production system anywhere that
  trusts them.
* `workday-api-not-used-but-required` and
  `github-api-not-used-but-required` are placeholder secrets on the
  two audience clients (Keycloak requires them syntactically; the
  demo's flows never invoke either client).
* User passwords (`alice`, `bob`, `charlie`, `eve`) are simply the
  usernames — Keycloak's password-grant flow needs them to mint
  bearer tokens for the demo personas.

None of these are credentials anyone outside this docker-compose
should ever see or care about, but third-party secret scanners
(GitGuardian, TruffleHog) may flag them on a literal-string basis.
GitHub's own secret scanner doesn't, because they don't match any
real vendor prefix.

If you fork or copy this directory for a real deployment, **rotate
every one of these strings** before exposing the gateway externally.

## Prerequisites

* Docker / Docker Compose
* `jq` and `curl`
* Rust toolchain (for building the gateway binary)
* CMake (for Pingora — see the parent README for setup)

## Bring it up

From this directory:

```bash
# 1. Start Keycloak + the mock MCP backend.
docker compose up -d

# Wait ~20-30s for Keycloak to import the realm. Check it's ready:
curl -fsS http://localhost:8081/realms/cpex-demo/.well-known/openid-configuration \
  | jq -r '.issuer'
# → http://localhost:8081/realms/cpex-demo

# 2. (Recommended) Verify Keycloak's RFC 8693 token-exchange path
#    works end-to-end before starting the gateway. The realm-export
#    sets up the permission grant for praxis-gateway → workday-api;
#    this script confirms it imported correctly.
./verify-token-exchange.sh
# Expected: "Token exchange works."

# 3. Build the gateway binary (from the workspace root).
( cd ../../.. && cargo build --release -p praxis-cpex-bin )

# 4. Start the gateway pointed at THIS demo's config.
( cd ../../.. && ./integrations/praxis-cpex/target/release/praxis-cpex \
    -c integrations/praxis-cpex/examples/demo/praxis.yaml ) &
```

## Watch the backend (separate terminal)

The MCP server logs what reaches it — this is the headline view
during the demo:

```bash
docker compose logs -f hr-mcp
```

You'll see lines like:

```
INBOUND REQUEST  (this is what reached the MCP server)
  authorization             = Bearer eyJhbGc…[1247 chars elided]
  body.method               = tools/call
  body.params.name          = get_compensation
  body.params.arguments     = {"employee_id": "EMP-001234", "include_ssn": true}
```

The `Authorization` value is what proves the rewriting worked: it's
the IdP-minted token from token-exchange, not the user's original
JWT.

## Run the scenarios

The demo ships two route families that highlight different
authorization patterns. Run all six with:

```bash
# Workday flow — Pattern 1 (perms on the user token)
./scenarios/01-bob-allow.sh
./scenarios/02-alice-deny.sh
./scenarios/03-eve-redact.sh

# GitHub flow — Pattern 3 (per-audience IdP mapper + Cedar PDP)
./scenarios/04-alice-internal-allow.sh
./scenarios/05-alice-external-cedar-deny.sh
./scenarios/06-bob-apl-deny.sh

# Plugin flow — PII scanner + audit logger
./scenarios/07-bob-pii-deny.sh
```

## Architectural patterns this demo shows

Authorization in a multi-system org isn't one mechanism — it's a
stack of them. The two routes in `cpex.yaml` demonstrate the common
shapes:

### Workday flow — Pattern 1 (perms on the user token)

The user's SSO/IdP already knows every permission the user has for
every downstream system. Bob's Keycloak account has
`permissions: [view_ssn, pii_access, ...]` as a user attribute. The
token carries those claims directly. APL's predicates read them as
flat bag keys (`perm.view_ssn`).

```yaml
- tool: get_compensation
  apl:
    policy:
      - "require(role.hr)"                              # principal-only
      - "delegate(workday-oauth, ..., permissions: [...])"
    args:
      ssn: "str | redact(!perm.view_ssn)"               # principal-only
```

Works when the IdP is the source of truth for every system's
permissions — typically via SCIM sync.

### GitHub flow — Pattern 3 (per-audience IdP mapping + Cedar PDP)

The user's SSO token only proves group membership. System-specific
permissions live on the IdP but only get materialized into a token
when that token is for the right audience.

```yaml
- tool: search_repos
  apl:
    policy:
      # 1. APL — coarse gate. Cheap predicate; fast-fails before
      #    Cedar / IdP do real work.
      - "require(group.engineering OR group.security)"

      # 2. Cedar — relationship between principal role and resource
      #    attribute. The kind of decision flat predicates struggle
      #    to express cleanly.
      - cedar:
          action: 'Action::"read"'
          resource:
            type: Repo
            id: args.repo_name
            attributes:
              visibility: args.visibility

      # 3. IdP — token exchange. Keycloak's `github-api` client has
      #    a claim mapper that promotes the user's gh_permissions
      #    attribute onto the `permissions` claim. Other audiences
      #    don't see those perms.
      - "delegate(github-oauth, audience: github-api, permissions: [repo:read:internal])"

      # 4. APL — verify what the IdP granted. If the user's perms
      #    didn't include repo:read:internal, the minted token
      #    came back narrowed; refuse to forward.
      - "!(delegation.granted.permissions contains 'repo:read:internal'): deny"
```

**Four authorization layers**, three at the gateway, one IdP-side:

| Layer | Where | What it gates | Cost |
|---|---|---|---|
| 1. APL coarse | gateway, off the bag | cheap principal predicates | free |
| 2. Cedar PDP | gateway, in-process | principal × resource decisions | µs |
| 3. IdP delegation | Keycloak | system-specific perm injection | ~10ms (HTTP) |
| 4. APL post-check | gateway, off the bag | verify IdP narrowing | free |
| 5. Validator plugin | gateway, in-process | content-aware checks (PII, schema, format) | µs |
| 6. Audit plugin | gateway, in-process | structured observation; never blocks | µs |

### Why Cedar (and why mix it with APL)

Cedar excels at one thing: declarative authorization decisions that
relate principal attributes to resource attributes.

```cedar
permit(principal, action == Action::"read", resource is Repo)
when {
  principal.roles.contains("engineer") &&
  resource.visibility == "internal"   // principal × resource
};
```

That cross-product is awkward in flat predicate languages — Cedar
makes it natural. Plus formal semantics, an analyzer (`cedar
analyze`), schema validation, and deny-overrides-allow composition
across many policies.

APL does NOT replace Cedar. **APL is what calls Cedar at the right
time, with the right inputs, alongside the other things you need at
the gateway: identity from N IdPs, RFC 8693 token exchange, request
body rewriting, capability gating, audit.** Bring your favorite PDP
— Cedar, OPA, Cedarling — APL gives it a home in your request
pipeline.

### Note on the demo's IdP mechanic

Mechanically, this demo's GitHub flow uses Keycloak user attributes
for `gh_permissions` (so it's still Pattern 1 *at the IdP layer*).
A real Pattern 3 deployment would use a JavaScript claim mapper, a
custom claim provider plugin, or a callout to an external authz
service to compute permissions at exchange time. **The APL policy
shape is identical.** The "delegate then check granted" idiom
doesn't care HOW the IdP decided what to grant — it just verifies
what came back. That portability is the architectural value.

## Or: drive it with an LLM

For a more compelling presentation, an interactive LLM agent lives in
`agent/`. It exposes the HR tools to the LLM (via OpenAI-style
function calling), routes calls through Praxis-CPEX, and the LLM
presents whatever it gets back — including `[REDACTED]` values — as
if those WERE the data. The LLM never knows the gateway applied policy.

```bash
cd agent
pip install -r requirements.txt

# Local Ollama default — no API key needed. Install Ollama
# (https://ollama.com) and `ollama pull llama3.1` first.
python chat.py --persona alice

# Or any LiteLLM-supported provider:
OPENAI_API_KEY=… python chat.py --persona bob --model gpt-4o-mini
ANTHROPIC_API_KEY=… python chat.py --persona eve --model anthropic/claude-3-7-sonnet-20250219
```

Inside the chat session, `switch <name>` swaps personas without
restarting — handy for showing deny → allow → redact back-to-back
in one continuous demo. Suggested prompts (workday flow first,
then github flow):

```
# WORKDAY FLOW (Pattern 1 — perms on user token)

Alice:    look up compensation for EMP-001234, include SSN
          → gateway 403s; LLM apologizes politely without knowing why

switch bob

Bob:      look up compensation for EMP-001234, include SSN
          → gateway allows + delegates; LLM shows the full record

switch eve

Eve:      look up compensation for EMP-001234, include SSN
          → gateway allows + delegates BUT redacts ssn on the wire;
             LLM presents "[REDACTED]" as if it were the SSN value


# GITHUB FLOW (Pattern 3 — Cedar PDP + per-audience IdP mapping)

switch alice

Alice:    search the internal repos for anything called "web-app"
          → APL gate passes (engineering), Cedar permits
             (engineer + internal), IdP mints github-scoped token,
             post-check passes, backend returns matches

Alice:    search the external repos for "partner-sdk"
          → APL gate passes (still engineering), BUT Cedar denies
             (engineering policy when-clause fails on
             visibility=external). Cedar's denial fires before
             any IdP call. LLM apologizes.

switch bob

Bob:      look at the internal repos
          → APL gate denies (Bob is in hr, not engineering or
             security). Cedar never runs; IdP never called.
             Fast-path deny.


# PLUGIN FLOW (validator + audit plugins)

switch bob

Bob:      send an email to external@example.com saying
          "Jane's SSN is 555-12-3456"
          → APL gate passes (Bob has email_send), but the PII
             scanner plugin walks args.body, hits the SSN regex,
             and denies with `pii.detected`. The audit logger
             emits a record describing the denied attempt. The
             email backend never sees the request.

(watch the gateway's stderr in another terminal to see the
audit JSON for every decision)
```

### Scenario 1 — Bob (HR + view_ssn) → ALLOWED

Bob is an HR manager with `perm.view_ssn`. Expected:

| Gateway | Backend (hr-mcp logs) |
|---|---|
| `200 OK` | `Authorization` = IdP-minted workday-api token (NOT bob's IdP JWT) |
| | `args.ssn` = the literal value bob sent (no redaction — he has the perm) |

### Scenario 2 — Alice (engineer) → DENIED

Alice has `role.engineer` (not `role.hr`). Expected:

| Gateway | Backend |
|---|---|
| `HTTP 200` + JSON-RPC error envelope `{"error":{"code":-32001,"message":"access denied","data":{"violation":"routes.tool:get_compensation.apl.policy[0]"}}}` | **No request reaches the backend** — `require(role.hr)` short-circuits before delegation runs. The mock IdP never sees a token-exchange call either. |

#### Why HTTP 200 + JSON-RPC error (not HTTP 403)

Per MCP's [Tools spec, "Error Handling"](https://modelcontextprotocol.io/specification/2025-06-18/server/tools), gateway-side denials (policy, PDP, PII) are reported as **JSON-RPC error envelopes inside an HTTP 200 response**, not as HTTP 4xx. This is so MCP clients can correlate the failure to the original request `id` and surface the violation through their normal error UI. HTTP 4xx is reserved for transport-level conditions per MCP's HTTP transport spec — notably, **HTTP 401 + `WWW-Authenticate: Bearer`** for missing/invalid bearer tokens, which the gateway uses for `auth.*` violations (see also MCP's [Authorization spec](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)).

The gateway also emits an `X-Cpex-Violation: <violation-code>` response header on every denial — non-standard but useful for log greps and curl-by-hand debugging.

### Scenario 3 — Eve (HR but no view_ssn) → ALLOWED + REDACTED

Eve has `role.hr` (so the policy guard passes) but **not** `perm.view_ssn`,
so both directions of the redact rule fire:

* **Request body** — if she happens to pass `ssn` in args (e.g. echoing
  back a value), `args:` pipeline rewrites it to `"[REDACTED]"` BEFORE
  the request reaches the backend.
* **Response body** — when the backend returns the SSN unsolicited (as
  `result.content[0].text`), the `result:` pipeline strips it on the
  way back.

Expected:

| Gateway | Backend log (request side) | Client (response side) |
|---|---|---|
| `200 OK` | `Authorization` = IdP-minted workday-api token | `result.ssn` = `"[REDACTED]"` reaches the LLM |
| | `args.ssn` = `"[REDACTED]"` (when present in args) | (the LLM presents `[REDACTED]` as if it were the SSN) |

The result-side redact is what makes the LLM-driven demo work end-to-end:
the LLM doesn't pass `ssn` in args (it just sets `include_ssn=true`), so
the args-side rule is a no-op for the LLM flow. The response-side rule
catches the SSN coming back from the backend regardless of how the call
was shaped.

## What you can claim

After running the demo, you've shown:

* Standards: **OIDC, RFC 8693 OAuth Token Exchange, MCP, JSON-RPC 2.0**
* IdP integration: **Keycloak** (the realm export + token-exchange
  permission shape applies to any RFC 8693-capable IdP — Auth0,
  Cognito, Okta with their respective server-side configs)
* Proxy: **Praxis** with the in-process CPEX/APL plugin
* Zero downstream IdP-token leakage — the user's `X-User-Token` is
  stripped at the gateway; only the audience-scoped minted token
  reaches the backend
* Policy-driven PII redaction enforced at the gateway, transparent
  to both client (it sends `ssn`) and server (it receives
  `"[REDACTED]"`)
* Multi-role identity model: user, client, and (with the appropriate
  resolver) SPIFFE workload as first-class slots

## Tear down

```bash
# Kill the gateway (find its PID; alternately Ctrl-C in its terminal)
pkill -f praxis-cpex || true

# Bring down Keycloak + MCP server.
docker compose down -v
```

## Files

| Path | Purpose |
|---|---|
| `docker-compose.yml` | Brings up Keycloak + the mock MCP server |
| `keycloak/realm-export.json` | Users + clients + token-exchange permission, imported at Keycloak startup |
| `hr-mcp-server/` | FastAPI mock backend — logs inbound headers + args |
| `cpex.yaml` | CPEX runtime config (resolvers + delegator + route + policy + redact) |
| `praxis.yaml` | Praxis listener wiring (mcp → cpex → router) |
| `mint-token.sh` | Persona / client token minting via Keycloak password / client_credentials grants |
| `verify-token-exchange.sh` | Sanity-check that Keycloak imported the RFC 8693 permission and praxis-gateway → workday-api exchange works |
| `scenarios/01-03*.sh` | Workday flow scenarios (Pattern 1 — pure APL predicate + body redact) |
| `scenarios/04-06*.sh` | GitHub flow scenarios (Pattern 3 — APL gate + Cedar PDP + delegate-then-check) |
| `scenarios/07-*.sh` | Plugin scenario — PII scanner blocks send_email containing an SSN |
| `agent/chat.py` | Interactive LiteLLM-powered agent — LLM calls tools, gateway applies policy transparently |
