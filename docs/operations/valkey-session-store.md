# Operating the Valkey Session Store

The Valkey-backed `SessionStore` (`apl-session-valkey`) persists per-session
security **taint labels** across process restarts and shares them across
gateway nodes. Those labels drive information-flow authorization, so the
backend is **fail-closed**: any store error denies the request rather than
letting it proceed with missing taint.

This runbook covers the operator-owned controls the backend depends on but
**cannot enforce from the client**. Getting them wrong silently weakens the
security guarantee, so treat this as part of the deployment contract.

> Build note: the backend is compiled into the FFI artifact only with the
> `valkey` cargo feature (`cargo build -p cpex-ffi --features valkey`).
> Without it, the default in-process memory store is used and nothing here
> applies.

---

## 1. Enabling it

Add a `session_store` block under `global.apl` in the unified config:

```yaml
global:
  apl:
    session_store:
      kind: valkey
      endpoint: valkey.internal:6379   # or rediss://valkey.internal:6379
      tls: true
      username: gateway                # ACL user (see §3)
      password: ${VALKEY_PASSWORD}     # inject from a secrets manager
      key_prefix: taint:v1             # default; bump only on schema change
      ttl_seconds: 86400               # optional sliding TTL (see §4)
      max_session_lifetime_seconds: 86400  # enables the TTL-soundness warning
      command_timeout_ms: 500          # fail-closed hot-path budget (default)
      connect_timeout_ms: 250          # default
```

When no `session_store` block is present, the gateway keeps its in-process
memory store and none of this applies.

---

## 2. `maxmemory-policy noeviction` (required)

Run the Valkey instance backing the label keyspace with:

```
maxmemory-policy noeviction
```

Why: with any `*-lru` / `*-lfu` / `*-random` / `volatile-*` policy, Valkey
can **silently evict** a live session's taint set under memory pressure. A
later read then returns an empty set, the gateway under-labels, and may
**over-authorize** — the exact fail-open this store exists to prevent. With
`noeviction`, a full instance instead fails *writes* with an error, which the
backend converts into a denied request (fail-closed). The client cannot set
or enforce this — it is a server config you own.

Note the volatile policies are **not** safe here even though they sound
scoped: the label keys carry a TTL (§4), so `volatile-lru`/`volatile-ttl`
would happily evict live keys. Use `noeviction` unconditionally.

**Verify and monitor:**

```
valkey-cli CONFIG GET maxmemory-policy   # must be "noeviction"
valkey-cli CONFIG GET maxmemory          # must be a non-zero bound
```

- Alert if `evicted_keys` in `INFO stats` is ever non-zero — it must stay `0`.
- Watch `used_memory` vs `maxmemory` and the OOM write-error rate so you scale
  before the instance fills.

This is operator-owned contract — the backend does **not** verify it for you.
A best-effort startup `CONFIG GET maxmemory-policy` self-check that warns when
the policy is not `noeviction` is a deferred follow-up (it would require the
connection pool to dial at config-load, which today it does not). Until then,
the authoritative control — and its monitoring — is yours.

---

## 3. TLS and least-privilege ACL

**TLS is required for any non-localhost endpoint** — the backend rejects a
plaintext, non-localhost config at load. Security labels reveal which sessions
carry sensitive taint; in plaintext they are exposed to passive interception
and active MITM (label injection/suppression). Prefer **mTLS** so a stolen ACL
password alone cannot connect.

```
# valkey.conf (sketch)
port 0
tls-port 6379
tls-cert-file /etc/valkey/tls/server.crt
tls-key-file  /etc/valkey/tls/server.key
tls-ca-cert-file /etc/valkey/tls/ca.crt
# tls-auth-clients yes   # require client certs (mTLS)
```

**Minimum ACL** for the gateway user — it only needs `SADD`, `SMEMBERS`,
`EXPIRE`, and (for the self-check) `CONFIG|GET`, scoped to the key prefix:

```
ACL SETUSER gateway on >$STRONG_SECRET resetchannels -@all \
  ~taint:v1:* \
  +sadd +smembers +expire +config|get
```

- `~taint:v1:*` confines key access to the label namespace.
- Grant `+config|get` (the subcommand) — never bare `+config`.
- Consider giving `CONFIG|GET` to a separate health/admin user so the hot-path
  writer's surface stays minimal.

**Credentials:** never hard-code the secret; inject from a secrets manager.
Valkey ACL users support multiple password hashes, enabling overlap rotation
(add new, roll clients, drop old) with no downtime; with mTLS, rotate the
client cert via `tls-auto-reload-interval`.

---

## 4. Sliding TTL and the soundness rule

The TTL (`ttl_seconds`) is optional and **off by default**. When set, it is a
sliding TTL: refreshed on every load and append.

**Soundness rule (R8):** a TTL is sound **only if it is ≥ the maximum lifetime
of a session identity.** A shorter TTL lets accumulated taint expire while the
session is still usable — a "downgrade-by-waiting": an adversary holds a
tainted session, waits out the TTL, and resumes it clean. If your gateway's
session identities are not bounded (e.g. header- or identity-derived ids with
no expiry), **leave the TTL off.**

Set `max_session_lifetime_seconds` to your gateway's bound and the backend will
emit a startup warning (`alarm = "session_store_ttl_unsound"`) when the
configured TTL is shorter. This is best-effort; the operator owns the invariant.

**TTL-refresh failures are fail-open for the read** (the labels were read
successfully). A *persistently* failing refresh, though, lets a sliding-TTL key
expire between requests and silently drop taint. Alert on
`alarm = "session_store_ttl_refresh_failed"`.

---

## 5. Persistence and durability (required)

The label keyspace is a **security system-of-record**, not a cache. Promoting
Valkey to hold an authorization input inverts its default durability
assumptions, so its on-disk persistence is part of the deployment contract —
alongside `noeviction` (§2) and the TTL rule (§4), this closes the third way a
label can silently vanish.

**The failure mode this closes.** A `SADD` is acknowledged to the gateway, the
node crashes before the write is fsync'd to disk, and the label is **gone**. On
restart (or replica failover) the next read returns a normal `Ok(empty)` —
*not* an error — so fail-closed never trips. The request proceeds with **less
taint than actually accumulated**: a silent downgrade. Critically, this is
**invisible to every alarm in §7** because nothing errors, which is exactly why
it has to be closed at the server-config layer rather than detected at runtime.

**The fsync options and their crash-loss windows:**

| Setting | On crash | Notes |
|---------|----------|-------|
| `appendonly no` (RDB only) | Lose everything since the last snapshot (minutes) | Cache-shaped; **unsafe** for the label keyspace |
| `appendfsync everysec` | ~1s loss window | Recommended floor |
| `appendfsync always` | Effectively no loss | Per-write latency cost |

**Recommended baseline:** AOF on with `appendfsync everysec` as the floor; use
`appendfsync always` where the threat model cannot tolerate the ~1s window.

```
# valkey.conf (sketch)
appendonly yes
appendfsync everysec   # or: always
```

**Failover interaction with §6.** The "fail over to a healthy primary" guidance
inherits Valkey's **asynchronous** replication: a failover can promote a replica
that is missing the most recent un-replicated appends — the same downgrade by a
different path. Tighten replication durability (e.g. `min-replicas-to-write` /
`min-replicas-max-lag`, or `WAIT`-aware fronting) if your failover budget
demands it.

Like `noeviction`, this is operator-owned contract: the client cannot set or
enforce it, and the backend does **not** self-check it today. A best-effort
startup `CONFIG GET appendonly` / `appendfsync` warning is a deferred follow-up
(same dial-at-config-load constraint as the `noeviction` self-check in §2).

---

## 6. Topology, availability, and blast radius

- **Single endpoint, primary-only reads.** The backend reads and writes one
  endpoint and never read-splits to replicas — replica replication lag would
  return stale (smaller) label sets, a silent downgrade. Achieve HA by pointing
  `endpoint` at a fronting address (K8s Service, VIP, or proxy) that fails over
  to a healthy primary. Client-side Sentinel/Cluster are not supported in v0.

- **Availability tradeoff (accepted).** Because the store is fail-closed,
  single-endpoint, and has no local fallback, a Valkey outage or failover
  denies **session-bearing** requests across all nodes until it recovers. This
  is the deliberate price of never silently under-labeling. The
  `command_timeout_ms` / `connect_timeout_ms` budgets bound how long a request
  waits before failing closed.

- **Anonymous/sessionless traffic is unaffected** — requests with no resolved
  session id never touch the store, so a Valkey outage does not deny them.

- **No live-reload (v0).** Changing the `session_store` config requires a
  reload/restart of the gateway to take effect for newly-installed routes; the
  store is selected during config load and captured by route handlers.

---

## 7. Alarms to wire up

| Signal | Meaning | Action |
|--------|---------|--------|
| `alarm = "session_store_failure"` (op=load/append) | A store load/append failed; request was denied | Investigate Valkey health/connectivity; sustained → outage |
| `alarm = "session_store_ttl_refresh_failed"` | Sliding-TTL refresh failed on an otherwise-successful read | Risk of silent key expiry; check ACL grants `+expire`, instance health |
| `alarm = "session_store_ttl_unsound"` | Configured TTL < declared session lifetime | Raise the TTL or disable it |
| `evicted_keys > 0` (Valkey `INFO`) | Eviction is dropping taint keys | Fix `maxmemory-policy` to `noeviction`; scale memory |

---

## 8. Local development

```
docker compose -f deploy/valkey-compose.yml up -d
VALKEY_TEST_URL=redis://127.0.0.1:6379 \
  cargo test -p apl-session-valkey --test valkey_store_integration -- --ignored
```

The compose file runs a `noeviction`-configured Valkey. It has no TLS/ACL and
runs RDB-default (non-durable, no AOF) — those are dev-only conveniences;
production must add TLS/ACL per §3 and AOF persistence per §5.
