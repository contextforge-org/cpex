# Parity snapshots

Golden decision snapshots recorded from the CPEX 0.2.3 engine, and a parity
check that replays the same requests through CPEX 0.3.0 (PPE 0.4.1) and
diffs the outcomes against them. Each scenario is a config plus an ordered
request set. A difference fails the check unless it is listed, with its
cause, in `intended-differences.yaml`.

## Provenance

- Engine: CPEX 0.2.3, built from this workspace at commit
  `bf17a8a36031d63e58928a4faa44168c3ef3b94e` (branch
  `refactor/adopt-ppe-core`, 2026-10-07), with the `cpex` facade's `full`
  feature.
- Toolchain: rustc 1.96.0.
- Valkey: `valkey/valkey:8-alpine` in Docker.
- Harness: as committed in `c981609` (`test(parity): capture 0.2.3 decision
  snapshots`). Later commits retarget it to 0.3.0, so the 0.2.3 snapshots can
  only be regenerated from a checkout of that commit (see below).

`snapshots/` is the baseline and is never rewritten by the current harness.

## Layout

```
tests/parity/
  harness/                 harness (workspace member cpex-parity-harness)
  hook-renames.yaml        reviewed legacy-to-PPE hook rename table
  intended-differences.yaml
                           reviewed 0.2.3 to 0.3.0 differences, with causes
  scenarios/<name>/
    config.yaml            config in 0.2.3 form, with run-time placeholders
    config.ppe.yaml        the same config migrated to the 0.3.0 form
    requests.yaml          mocks, test tokens, hook names, ordered requests
  snapshots/<name>.json    0.2.3 outcomes, one file per scenario
  snapshots/valkey/<name>.keyspace.json
                           raw taint:v1 keyspace left by a 0.2.3 Valkey run
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

Start a throwaway Valkey on a free port (the harness runs `FLUSHDB` on the
database it is given):

```sh
docker run -d --rm --name cpex-parity-valkey -p 127.0.0.1:6391:6379 valkey/valkey:8-alpine
export PARITY_VALKEY_URL=redis://127.0.0.1:6391/0
```

Run the parity check, the Valkey read-back and the determinism test:

```sh
cargo test -p cpex-parity-harness
```

Print every difference against the baseline, marking the unlisted ones and
rendering them as allow-list entries for review:

```sh
cargo run -p cpex-parity-harness -- --diff
```

Write a 0.3.0 capture, for example to inspect one scenario:

```sh
cargo run -p cpex-parity-harness -- --out /tmp/parity identity-jwt
```

Options: `--root DIR` (default `tests/parity`), `--out DIR` (default
`target/parity` in the workspace; `snapshots/` is refused), `--valkey-url
URL` (default `PARITY_VALKEY_URL`), and scenario names to run a subset.

Without a Valkey URL, Valkey scenarios print `SKIPPED`, the parity test
checks every other scenario (allow-list entries for the skipped one are not
reported as stale), and the read-back test is skipped. All of them report
the skip on stderr.

### Regenerating the 0.2.3 baseline

Only needed when a scenario's requests change. The 0.2.3 engine is gone from
this branch, so capture from the snapshot commit and copy the files back:

```sh
git worktree add /tmp/cpex-0.2.3 c981609
# copy any changed scenarios/<name>/requests.yaml and config.yaml into
# /tmp/cpex-0.2.3/tests/parity/scenarios/ first
(cd /tmp/cpex-0.2.3 && cargo run -p cpex-parity-harness -- --valkey-url "$PARITY_VALKEY_URL")
cp -R /tmp/cpex-0.2.3/tests/parity/snapshots/. tests/parity/snapshots/
git worktree remove /tmp/cpex-0.2.3
```

At that commit the harness writes to its own `tests/parity/snapshots/` and
its test checks two captures against those files. Then rerun the parity
check here and review the allow-list.

## Request format

`requests.yaml` fields:

- `config`, `ppe_config`: the 0.2.3 and 0.3.0 config files. Defaults are
  `config.yaml` and `config.ppe.yaml`.
- `hooks`: hook names a `mediate` request dispatches. Defaults are
  `identity: identity.resolve`, `pre: cmf.tool_pre_invoke`,
  `post: cmf.tool_post_invoke`. The rename table is applied here and to
  each `invoke` request's `hook` before replaying.
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

## Migrated configs

Each `config.ppe.yaml` is its `config.yaml` with only the changes 0.3.0
requires; the policy logic is the same:

- `global.apl.pdp` and `global.apl.session_store` move up to `global.pdp`
  and `global.session_store`.
- Plugins that call out over HTTP (`identity/jwt` with `jwks_url`,
  `delegator/oauth`, `elicitation/ciba`) declare `capabilities:
  [perform_http]`.
- An open route writes `pre_invocation: ["allow"]`; an empty list fails the
  load.
- `go-demo-cmf` follows `examples/go-demo/cmf_plugins.yaml`:
  `engine_settings.dispatch: hooks` replaces `plugin_settings`,
  `global.policies` and the per-route `plugins:` lists (hook dispatch
  rejects `routes:` and `global:`), and the host kinds are `demo/cmf-*`.

The harness installs the builtins and a hyper transport with private
destinations allowed, since the mock upstream listens on 127.0.0.1.

## Hook renames

`hook-renames.yaml` maps every hook name 0.2.3 accepted and PPE rejects to
its PPE name (`tool_pre_invoke` to `cmf.tool_pre_invoke`,
`cmf.prompt_pre_fetch` to `cmf.prompt_pre_invoke`, `cmf.http_request` to
`http.request`, and so on). The scenarios use only names that did not
change, so applying it is the identity on these request sets. It is still
applied on every replay, and to the `hook` of each recorded 0.2.3 stage
before diffing, so a scenario that uses a legacy name is compared under its
new name.

## How the parity check works

1. Replay each scenario through 0.3.0 with its migrated config and renamed
   hooks, normalized exactly as the 0.2.3 capture was.
2. Compare it to `snapshots/<name>.json` leaf by leaf: objects key by key,
   arrays of equal length element by element. Requests are matched by `id`;
   the `load` block reports under the id `<load>`. The top-level `config`
   path is not compared.
3. Each differing leaf must match an entry in `intended-differences.yaml` on
   scenario, request, field, the 0.2.3 value and the 0.3.0 value. An entry
   that matches nothing fails the check too, so the list cannot go stale.

The Valkey read-back test flushes the database, seeds it from
`snapshots/valkey/session-valkey.keyspace.json`, and replays only the
requests that read labels without writing any. The tainted email is denied
with `session_tainted` although nothing in the run tainted it, every
replayed request matches its 0.2.3 record, and the keyspace afterwards
equals the seed.

The determinism test runs two 0.3.0 captures and checks they are
byte-identical.

## Result against PPE 0.4.1

Every request reaches the same decision and the same non-path violation
code as in 0.2.3. 54 of 68 requests match exactly; 14 differ in 26 fields,
all listed in `intended-differences.yaml`:

| Cause | Requests |
|---|---|
| Rule-path deny codes lose the `.apl.` segment (`routes.tool:x.apl.pre_invocation[1]` becomes `routes.tool:x.pre_invocation[1]`) | 10 |
| A token-exchange denial reason no longer carries the IdP's `error_description` | 1 |
| A token with an unknown `kid` triggers one on-demand JWKS refetch | 1 |
| A route without `authentication:` does not run the identity plugin, so no subject reaches it (same decision on this open route) | 1 |

Each entry cites the PPE changelog line behind it.

## Observed behavior worth knowing

These hold in both 0.2.3 and 0.3.0 unless noted.

- Route denials without a custom code use the rule source path as the code,
  for example `routes.tool:get_compensation.pre_invocation[1]` (0.2.3 had
  `.apl.` before `pre_invocation`). PDP steps without `on_deny` use `cel`,
  `opa`, `cedar.default_deny` or the Cedar policy id.
- CIBA polls once inside the dispatching call, so the first call reaches
  `pending` only when that poll is pending.
- A caller can resume another subject's approved elicitation id and is
  allowed without a new upstream check (`approved-resume-by-other-subject`).
  PPE 0.4.1 keeps this: the CIBA correlation store records only the expected
  and resolved approver, `check` replays a cached approval for any caller
  presenting the id, and `validate` compares the resolved approver with the
  approver named at dispatch, not with the requesting subject or that
  subject's own `from:` approver.
- Repeated delegation for the same subject and audience calls the token
  endpoint again (`hr-delegated-again`).
- Session labels are keyed by `sha256(subject : session id)`, so another
  subject with the same session id is not tainted. 0.3.0 derives the same
  keys: a full Valkey replay leaves a keyspace identical to the 0.2.3 export.
- In 0.3.0 an identity plugin runs only on routes whose `authentication:`
  names it. In 0.2.3 it ran on every route.

## Retargeting

All engine-specific code is in `harness/src/engine.rs`: loading a config,
dispatching hooks and projecting results into the snapshot shape. To check
a later engine, port that file, keep the projection shape, extend the rename
table and migrated configs if names or config shape change, and rerun the
parity check. Moving the PPE pin requires rerunning it.
