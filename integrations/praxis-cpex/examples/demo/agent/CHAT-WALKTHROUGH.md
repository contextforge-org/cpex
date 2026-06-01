# chat.py — interactive walkthrough

A cheat-sheet of prompts to type into `chat.py` and what each one should
demonstrate. Read it line-by-line during the demo; the LLM does the rest.

## Setup (once)

In one terminal:

```bash
# from integrations/praxis-cpex/examples/demo
docker compose up -d
./verify-token-exchange.sh           # expect "Token exchange works."
( cd ../../ && cargo build --release -p praxis-cpex-bin )
../../target/release/praxis-cpex -c ./praxis.yaml &
```

In a second terminal (so the audience can see what reaches the backend):

```bash
docker compose logs -f hr-mcp
```

In a third terminal (the demo itself):

```bash
cd agent
./run-watsonx.sh bob                 # opens chat as Bob with watsonx Llama
```

The script writes a banner showing persona + model + gateway URL.
You're now talking to the LLM, which is in front of the CPEX gateway.

---

## Act 1 — WORKDAY FLOW (single-IdP perms on the user token)

### Bob (HR, has `perm.view_ssn`) — happy path

```text
Bob: look up the compensation for EMP-001234, include the SSN
```

**Expected:**
- LLM invokes `get_compensation(employee_id="EMP-001234", include_ssn=true, ssn=...)`
- Gateway response: **HTTP 200** with the full record (salary, SSN, etc.)
- LLM presents the record naturally: "Jane Smith, $125,000 salary, SSN 123-45-6789, …"

**In the hr-mcp log:**
- `authorization = Bearer eyJ…` — note the JWT! Decode it and you'll see
  `aud: workday-api`, NOT `aud: praxis-gateway`. That's the **minted
  workday-api token** from the RFC 8693 exchange — bob's original JWT
  never reaches the backend.
- `body.params.arguments` shows `ssn=<the value bob sent>` intact —
  he has the perm, so no redact fired.

---

### Switch to Alice (engineer, NO `role.hr`) — APL deny

```text
> switch alice
Alice: look up the compensation for EMP-001234
```

**Expected:**
- LLM invokes `get_compensation(employee_id="EMP-001234")`
- Gateway response: **HTTP 200 + JSON-RPC error envelope**, code `-32001`,
  `data.violation = "routes.tool:get_compensation.apl.policy[0]"`
- LLM apologizes politely without revealing the violation code
  (system prompt tells it to do exactly this)

**In the hr-mcp log:**
- Nothing. The request **never reached the backend** — `require(role.hr)`
  short-circuited at the gateway. Keycloak's `/token` endpoint also
  never received a token-exchange call.

---

### Switch to Eve (HR but NO `perm.view_ssn`) — body rewrite

```text
> switch eve
Eve: look up the compensation for EMP-001234, include the SSN
```

**Expected:**
- LLM invokes `get_compensation(employee_id="EMP-001234", include_ssn=true, ssn="…")`
- Gateway response: **HTTP 200** with the record — BUT the LLM sees
  `ssn = "[REDACTED]"` instead of the real value
- LLM presents the record with "[REDACTED]" sitting where the SSN should be

**Where the redact actually fires:**
- The LLM doesn't include `ssn` in args (just `include_ssn=true`), so the
  *request-side* `args:` pipeline is a no-op for this call.
- The backend returns the SSN inside `result.content[0].text` (its
  JSON-RPC tool result block).
- The *response-side* `result:` pipeline fires — `redact(!perm.view_ssn)`
  against `result.ssn` — and rewrites the response body to
  `"ssn": "[REDACTED]"` before the gateway forwards it to the LLM.
- The LLM never sees the real SSN. (Caveat: today both the request and
  response rewrites are padded with trailing whitespace to match
  Content-Length — documented as an upstream praxis issue in
  `docs/upstream-issues/01-content-length-on-body-rewrite.md`.)

---

## Act 2 — GITHUB FLOW (Cedar PDP + per-audience IdP mapping)

### Alice (engineering) — Cedar PERMITS internal repos

The backend seed has `internal/web-app`, `internal/data-pipeline`,
`internal/auth-service` for the internal side, and
`external/partner-sdk`, `external/marketing-site` for external. The
search uses substring matching, so spell repo names exactly (no
trailing "s").

```text
> switch alice
Alice: search the internal repos for anything called web-app
```

**Expected:**
- LLM invokes `search_repos(repo_name="web-app", visibility="internal")`
- Gateway response: **HTTP 200** with a `internal/web-app` match
- LLM presents the result naturally

**Alternative prompts that hit real seed data:**
- "search for `data` in the internal repos" → `internal/data-pipeline`
- "list all the internal repos" → all three matches

**Under the hood (mention to the audience):**
1. APL gate `require(team.engineering | team.security)` — passes
   (Alice is `team.engineering`)
2. Cedar policy `engineering-internal-repos` — permits (engineer +
   `resource.visibility == "internal"`)
3. Token exchange to `github-api` audience — mints a token with
   `permissions: [repo:read:internal]` (driven by Alice's
   `gh_permissions` user attribute via a Keycloak audience mapper)
4. Post-check `delegation.granted.permissions contains 'repo:read:internal'`
   — passes
5. Request forwards to the backend with the minted github token

**In the hr-mcp log:**
- `authorization = Bearer eyJ…` — this token's `aud` is now `github-api`
  (not `workday-api` like the bob case). Same gateway, different
  audience-scoped token per route.

---

### Alice (engineering) — Cedar DENIES external repos

```text
Alice: search the external repos for partner-sdk
```

(or `"marketing-site"` — either one in the external bucket triggers
the Cedar deny path; the LLM never sees the seed since the call is
short-circuited at the PDP.)

**Expected:**
- LLM invokes `search_repos(repo_name="partner-sdk", visibility="external")`
- Gateway response: **HTTP 200 + JSON-RPC error envelope**, code `-32001`,
  `data.violation = "cedar.default_deny"`
- LLM apologizes

**Under the hood:**
- APL gate STILL passes (Alice is engineering)
- Cedar policy `engineering-internal-repos` has `when { resource.visibility
  == "internal" }`. The substitution turns `${args.visibility}` into
  `"external"`, the when-clause fails, no permit fires → default deny
- **No IdP call**. Cedar denied before delegation ran.

**Talking point:** this is the *value* of Cedar over flat APL predicates.
A pure `require(team.engineering)` would have permitted both `internal`
and `external`. Cedar's relationship between principal role and resource
attribute is what catches it.

---

### Switch to Bob (HR) — APL fast-path deny on github

```text
> switch bob
Bob: search the engineering repos for anything
```

**Expected:**
- LLM invokes `search_repos(visibility="internal")` (or similar)
- Gateway response: **HTTP 200 + JSON-RPC error envelope**, code `-32001`,
  `data.violation = "routes.tool:search_repos.apl.policy[0]"`
- LLM apologizes

**Talking point:** the APL gate denied at the cheapest layer — Bob is
`team.hr`, not `team.engineering` or `team.security`. **Cedar never ran**,
**no IdP round-trip**. This is the demo's "fast-path deny" — cheap
predicates first, expensive PDP / IdP work only for requests that clear them.

---

## Act 3 — PLUGIN FLOW (PII scanner + audit logger)

### Bob (has `perm.email_send`) — PII scanner denies

```text
Bob: send an email to alice@corp.com with the subject "FYI"
     and the body "Jane's SSN is 555-12-3456 if you need it"
```

**Expected:**
- LLM invokes `send_email(to="alice@corp.com", subject="FYI", body="Jane's SSN is 555-12-3456 if you need it")`
- Gateway response: **HTTP 200 + JSON-RPC error envelope**, code `-32001`,
  `data.violation = "pii.detected"`
- LLM apologizes

**Under the hood:**
1. APL gate `require(perm.email_send)` — passes (Bob has it)
2. `pii-scan` plugin walks `args.body`, hits the SSN regex pattern
3. Plugin denies; gateway short-circuits
4. `audit-log` plugin still fires (it's wired on the same hook with
   `read_delegated_tokens` etc.) — observation can't block — and emits
   a JSON record describing the denied attempt

**In the gateway's stderr (the praxis-cpex process):**

```json
{"ts":"2026-…","plugin":"audit-log","source":"cpex-demo-gateway",
 "subject":{"id":"<bob's uuid>","roles":["hr"], …},
 "entity":{"type":"tool","name":"send_email"},
 "tool_call":{"name":"send_email","args":{"to":"alice@corp.com", …}},
 "delegated_tokens":[…]}
```

This is the audit-trail story: even denied attempts get a structured
record, no plugin coordination required.

---

## Talking points to weave in

- **Multi-role identity:** the gateway distinguishes `Authorization`
  (the agent's client identity, `azp=hr-copilot`) from `X-User-Token`
  (the human user). Two separate JWKS validations against Keycloak.
  Decode both tokens to show this if asked.

- **Tokens at the boundary:** Bob and Eve see different SSN behavior
  WITHOUT either of them having to log in differently. The token claims
  drive the gateway; the LLM doesn't know about the policy.

- **Different audiences per route:** Bob's workday call → minted with
  `aud: workday-api`. Alice's github call → minted with `aud: github-api`.
  Same gateway, same `praxis-gateway` Keycloak client, different routes
  produce differently-scoped tokens. The downstream services see ONLY
  tokens minted for them — no cross-audience token reuse.

- **The body never lies:** for Eve, the LLM saw `[REDACTED]`. We could
  decode the JWT it sent to confirm the gateway didn't sneak the real
  SSN through some side channel. The rewrite is on the wire.

---

## Things to demo if anyone asks "is this real?"

- Decode `bob`'s token after a tool call — open https://jwt.io and paste
  what hr-mcp logged. Show `aud: workday-api`, signed by Keycloak.
- Run `./verify-token-exchange.sh` live — proves RFC 8693 against
  the actual Keycloak running in docker.
- Edit the cpex.yaml `require(...)` line and `pkill -HUP` the gateway —
  the new policy takes effect immediately (the manager reloads).
- Open `realm-export.json` and show the Keycloak v2 STE setup. Compare
  to MCP's `aud` validation requirement in the authorization spec.

---

## When something goes wrong mid-demo

| Symptom | Fix |
|---|---|
| LLM doesn't call tools, just chats | Try a more directive prompt (`call the get_compensation tool with employee_id…`). Llama 8B forgets tools; switch to 70B. |
| All scenarios return 401 | Keycloak didn't finish importing. `docker compose down -v && docker compose up -d`, wait 30s, re-run `verify-token-exchange.sh`. |
| Gateway response is a Pingora `PrematureBodyEnd` | The body-rewrite pad logic regressed. Body rewrite is the only place this happens. |
| Cedar returns `cedar.default_deny` for an "allow" case | `${args.X}` substitution may have failed — check the gateway log for the resolve error; the bag key it asked for is in the error. |
