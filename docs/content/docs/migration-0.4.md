---
title: "Migrating to 0.4"
weight: 124
---

# Migrating to CPEX 0.4

CPEX 0.4.0 uses PPE 0.6.0 with the RustCrypto backend. It requires no FIPS provider or OpenSSL FIPS installation. The stable builtin set is unchanged; experimental rate limiting is not enabled.

Upgrade the Rust/Python packages and Go module together. The native FFI artifact now uses **ABI 4** because the conversation-history wire contract changed. An older Go module rejects the new library at startup.

## Configuration

CIBA requires an explicit correlation store and rejects unknown config keys:

```yaml
plugins:
  - name: approver
    kind: elicitation/ciba
    hooks: [elicit]
    capabilities: [perform_http]
    config:
      backchannel_endpoint: https://idp.example.com/ciba
      token_endpoint: https://idp.example.com/token
      client_id: gateway
      client_secret_source: { kind: env_var, name: CIBA_CLIENT_SECRET }
      store: { kind: memory }
```

Memory state is local to the plugin instance. Shared deployments can configure PPE's Valkey correlation store. Storage failures halt approval as `elicitation.store_unavailable` / JSON-RPC `-32122`; do not forward the operation.

JWT credential locations now use `credential: { kind: header, name: Authorization }`. Legacy `header:` remains accepted. Bare-token Rust callers must provide a matching `source_header` for custom locations. Python and Go callers should supply the original header map; identity results omit those secret inputs. Resolver-owned fields remain invalid on binding input.

Review monitoring that matches extraction codes: malformed JWT credentials now report `auth.malformed_credential`; missing, empty and ambiguous locations have distinct credential codes. DPoP is opt in per trusted issuer, needs `read_headers`, and returns verified `key_binding` on the resolved subject, client or workload.

## Request state

Pass each returned context table to the next hook **in the same request**. Start a new table for a new request. Go's `InvokeResolved` carries the table through identity and downstream policy, keeping DPoP proof reuse within one request distinct from replay on another request.

`HttpExtension.query` is the raw query without `?`. Go uses `*string`: nil means no query and an empty string means a bare `?`. Supply `client_address` from the host's trusted peer context; PPE normalizes it. Do not copy these fields from untrusted forwarding headers.

Results redact a present query to `[REDACTED]` and anonymize client addresses (IPv6 to a /64 prefix). Reconstruct live HTTP state from the original request before a separate hook call. Python and FFI reject that query marker as input. Preserve resolved identity and key bindings while restoring HTTP state.

Conversation history is a list of CMF messages, oldest first. Go's `ConversationContext.History` is now `[]Message`; Python uses message dictionaries with `role` and `content`. Move free-form history strings to `summary`.

## Support boundaries

| Capability | Rust host | Python/Go bindings | Isolated Python plugins |
|---|---|---|---|
| Live HTTP query and normalized client address | supported | supported; restore live query between calls | canonical values preserved; query access rejected |
| `llm_request` | typed PPE carrier | non-null input rejected | access and replacement rejected |
| Acquired `metadata` | framework installation API | non-null input rejected | access and replacement rejected |
| `ratelimit.pre_identity`, `ratelimit.post_identity` | typed HTTP hooks; host dispatches stages | rejected; no HTTP payload carrier | unavailable |
| Header credential sources | supported | supported | supported |
| Cookie/query raw credential sources | supported | HTTP state supported; no dedicated raw carrier | rejected rather than converted to headers |

An isolated plugin explicitly requesting `read_query`, `read_llm_request` or `read_metadata` fails before worker startup. `read_all` also fails if its effective view contains these unsupported slots. Use `for_child_request()` for a new Rust child invocation so acquired metadata does not inherit into it.

Rust hosts enabling a limiter must dispatch pre-identity once before resolution, post-identity once after all resolvers, then the governed hook, including anonymous requests. Stop at a denial. CPEX's helpers do not enable or orchestrate a limiter.

## Policy and auditing

APL `&` and `|` can settle from a decisive operand even when the other operand cannot be ordered. Review policies relying on NaN or other unorderable values.

Enabled hookless audit sinks can load beside routes under `dispatch: policy`. Reference audit loggers need an explicit `destination:`, and transcript recorders need `exporters:`. Register their Rust factories before loading; CPEX does not bundle them. See [Auditing]({{< relref "/docs/auditing" >}}).

Keep the existing once-per-engine Rust builtin-install rule and binding guards. PPE #208 and #209 remain open: builtin installation and private-destination opt-in retain their existing behavior.
