# Parity snapshots

Golden decision snapshots recorded from the CPEX 0.2.3 engine. Each scenario
is a config plus an ordered request set. The harness replays the requests and
records what the engine decided, so a later engine can replay the same
requests and diff against these files.

## Provenance

- Engine: CPEX 0.2.3, built from this workspace at commit
  `bf17a8a36031d63e58928a4faa44168c3ef3b94e` (branch
  `refactor/adopt-ppe-core`, 2026-10-07), with the `cpex` facade's `full`
  feature.
- Toolchain: rustc 1.96.0.
- Valkey: `valkey/valkey:8-alpine` in Docker.

The snapshots are only valid against that engine. Regenerate them from the
same commit if the harness or a scenario changes.

## Layout

```
tests/parity/
  harness/                 capture harness (workspace member cpex-parity-harness)
  scenarios/<name>/
    config.yaml            config in 0.2.3 form, with run-time placeholders
    requests.yaml          mocks, test tokens, hook names, ordered requests
  snapshots/<name>.json    recorded outcomes, one file per scenario
  snapshots/valkey/<name>.keyspace.json
                           raw taint:v1 keyspace left by a Valkey scenario
```

## Scenarios

| Scenario | Source | Covers | Requests |
|---|---|---|---|
| `identity-jwt` | tutorial m01, m02 | JWT via JWKS URL; expired, wrong audience, untrusted issuer, forged signature, unknown kid, malformed | 11 |
| `result-shaping` | tutorial m03 | `result:` redact and mask by role and permission | 4 |
| `pdp-cel` | tutorial m05 | CEL with and without a custom `on_deny` code | 7 |
| `pdp-cedar` | cedar-direct crate test | Cedar permit, default deny, named forbid, missing principal | 4 |
| `pdp-opa` | opa crate test | OPA boolean and object decisions | 6 |
| `delegation-oauth` | tutorial m06 | RFC 8693 token exchange against a mock endpoint, refused audience | 4 |
| `session-memory` | tutorial m07 | session taint with the in-memory store | 9 |
| `session-valkey` | tutorial m07, tainting docs | the same requests with the Valkey store, plus keyspace export | 9 |
| `elicitation-ciba` | tutorial m08 | CIBA approve, refuse, unanswered, resume by another subject | 9 |
| `go-demo-cmf` | go-demo `cmf_plugins.yaml` | host plugins: label gate and response header injection | 5 |

Every scenario that needs an identity uses the mock IdP described below.
Tutorial configs that point at Keycloak are rewritten to it; the policy logic
is unchanged.

### Excluded

- `pii-scanner` and `audit-logger` flows. Both builtins are removed in the
  next release, so their snapshots could only ever be recorded as intended
  differences. Configs that use them (tutorial m04 and the capstones,
  `examples/go-demo/plugins.yaml`, the Python binding fixtures
  `pii_deny.yaml` and `pii_redact.yaml`) are left out. The rest of each
  capstone is covered by the scenarios above.
- The Python plugin host (`isolated_venv`): it needs a Python toolchain and
  is covered by its own e2e suites.

## Running

Capture all scenarios, with Valkey:

```sh
docker run -d --rm --name cpex-parity-valkey -p 127.0.0.1:6390:6379 valkey/valkey:8-alpine
cargo run -p cpex-parity-harness -- --valkey-url redis://127.0.0.1:6390/0
docker stop cpex-parity-valkey
```

Options: `--root DIR` (default `tests/parity`), `--out DIR` (default
`<root>/snapshots`), and scenario names to run a subset. `PARITY_VALKEY_URL`
is read when `--valkey-url` is absent. The harness runs `FLUSHDB` on that
database before each Valkey scenario, so point it at a throwaway instance.

Without a Valkey URL, Valkey scenarios print `SKIPPED` and their snapshot and
keyspace files are left as they are. Capture them where Valkey runs, such as
CI with a service container.

Check that two captures are byte-identical and match the committed files:

```sh
PARITY_VALKEY_URL=redis://127.0.0.1:6390/0 cargo test -p cpex-parity-harness
```

Without `PARITY_VALKEY_URL` the test still runs every other scenario and
reports the skip on stderr.

## Request format

`requests.yaml` fields:

- `hooks`: hook names a `mediate` request dispatches. Defaults are
  `identity: identity.resolve`, `pre: cmf.tool_pre_invoke`,
  `post: cmf.tool_post_invoke`. A hook rename is applied here, once per
  scenario.
- `mocks`: routes the mock upstream serves at `{{MOCK_URL}}`. A route
  matches on method, path and `form` fields; `max_hits` lets a later route
  answer the same request differently. `builtin: jwks` serves the test keys.
- `tokens`: JWTs minted at run time from `claims`, signed with a test key.
- `requests`: run in order against one engine instance, so session labels
  and pending approvals carry over. Each has a stable `id`.
  - `kind: mediate` runs the tutorial host loop: the identity hook (only when
    the caller has a credential), the pre hook with a CMF `tool_call`, the
    `backend` value as the tool result, then the post hook. `caller` takes
    `token`, `raw_token`, `credentials`, `session` (sent as the agent
    session id) and `resume` (the id of an earlier request whose pending
    elicitation id is echoed in `X-Policy-Elicitation-Id`).
  - `kind: invoke` dispatches one `hook` with a CMF `MessagePayload` JSON
    `payload` and seeded `extensions` (`meta`, `security`, `http`, `agent`).

Config placeholders: `{{MOCK_URL}}`, `{{CLIENT_SECRET_FILE}}` and
`{{VALKEY_URL}}`.

## Snapshot format

Pretty JSON with sorted keys. Per request:

- `decision`: `allow`, `deny` or `pending`; `code`: the violation code.
  `not_run` with code `harness.no_pending_elicitation:<id>` means a `resume`
  pointed at a request that did not suspend.
- `result`: what the caller sees after the post phase (`mediate` only).
- `stages`: one entry per hook dispatched, with `hook`, `continue`, the
  full `violation` (code, reason, plugin, protocol code, details),
  `payload_modified`, the modified `payload` (CMF message or resolved
  identity), the modified `extensions` (labels, subject, HTTP headers,
  delegation, credential metadata) and non-fatal plugin `errors`.
- `upstream_calls`: mock upstream calls the request caused, in order, with
  credential form fields dropped. `load.upstream_calls` holds calls made
  while the engine initialized (the JWKS fetch).

The keyspace export maps each `taint:v1:*` key to its type, sorted members
and whether a TTL is set.

## Determinism and secrets

- Set-valued fields (roles, permissions, labels, tags, scopes) are sorted.
- Wall-clock values (`expires_at`, `timestamp`, `resolved_at`,
  `attested_at`, `age_seconds`) are replaced with `<time>`. Remaining TTL
  seconds are reduced to `"set"`.
- The mock server's port is replaced with `{{MOCK_URL}}`.
- Minted JWTs, tokens returned by the mocks, any JWT-shaped string, and
  credential header values are replaced with `<token>`.
- Token claims are fixed in data (`iat` 1767225600, `exp` 4102444800, or a
  past `exp` for expiry cases), so tokens do not depend on the clock.
- Signing keys are Ed25519 keys derived from SHA-256 of a public label in
  `harness/src/keys.rs`. They are test-only by construction: anyone can
  rederive them. The OAuth and CIBA client secret is a fixed test-only
  string written to a temporary file and referenced through the plugins'
  `file` secret source. No secret appears in a config.

## Observed 0.2.3 behavior worth knowing

- Route denials without a custom code use the rule source path as the code,
  for example `routes.tool:get_compensation.apl.pre_invocation[1]`. PDP steps
  without `on_deny` use `cel`, `opa`, `cedar.default_deny` or the Cedar
  policy id.
- CIBA polls once inside the dispatching call, so the first call reaches
  `pending` only when that poll is pending.
- A caller can resume another subject's approved elicitation id and is
  allowed without a new upstream check (`approved-resume-by-other-subject`).
- Repeated delegation for the same subject and audience calls the token
  endpoint again (`hr-delegated-again`).
- Session labels are keyed by `sha256(subject : session id)`, so another
  subject with the same session id is not tainted.

## Retargeting

All engine-specific code is in `harness/src/engine.rs`: loading a config,
dispatching hooks and projecting results into the snapshot shape. To replay
on another engine, port that file, keep the projection shape, apply any hook
renames through each scenario's `hooks` block, migrate the configs, and diff
the new output against `snapshots/`. To check that stored labels are read
back unchanged, seed a store from `snapshots/valkey/` before replaying the
Valkey scenario.
