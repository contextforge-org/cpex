// Location: ./integrations/praxis-cpex/docs/upstream-issues/01-content-length-on-body-rewrite.md
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor

# Praxis upstream issue: filters cannot adjust `Content-Length` after rewriting the request body

**Target repo:** `shaneutt/praxis` (pinned in this integration at `3bc864cb97cca76623f6c8368998fc22f5e7eba9`)

**Affected commit observed:** same.

**Filed by:** CPEX/APL integration, while implementing field-level body rewrites (`redact(args.ssn)`).

## tl;dr

A praxis filter that rewrites the request body in `on_request_body` has no
supported way to update the `Content-Length` header that gets sent
upstream. As a result:

- If the rewrite **shrinks** the body, Pingora sends the new bytes but the
  upstream's `Content-Length` header still claims the original (larger)
  length → `Upstream PrematureBodyEnd` and the upstream hangs / 504s.
- If the rewrite **grows** the body, Pingora truncates the upstream write
  to the original (smaller) `Content-Length`, silently corrupting the
  upstream payload.

The integration is currently working around this by **padding the
rewritten body with trailing ASCII spaces** to match the original
`Content-Length`. JSON parsers ignore trailing whitespace, so for our
JSON-RPC case this is safe — but it only handles the shrink case, and is
a workaround, not a fix.

## Reproduction

A filter that:

1. Declares `request_body_access() = BodyAccess::ReadWrite`.
2. Declares `request_body_mode() = BodyMode::StreamBuffer { .. }` (so we
   see the whole body at end-of-stream).
3. In `on_request_body(end_of_stream=true)`, replaces `*body` with new
   `Bytes` of a different length than the incoming buffer.

The upstream connection then sees either `PrematureBodyEnd` (shrink) or a
truncated body (grow). The inbound `Content-Length` header was set by the
downstream client and praxis forwards it verbatim — there is no hook that
lets the filter say "I've rewritten the body, please recompute
`Content-Length`."

## Where the limitation lives in the praxis tree

Quick map of the relevant code at the pinned revision:

- `filter/src/context.rs` exposes `HttpFilterContext::request_headers_to_set`
  and `request_headers_to_remove`, which let filters mutate upstream
  headers.
- `protocol/src/http/pingora/handler/request_filter/mod.rs:130-148`
  applies those mutations to `session.req_header_mut()` — **only** during
  the request phase (i.e., before any body chunk has been seen).
- `protocol/src/http/pingora/context.rs` — the `filter_context!` macro
  used by the body phase builds a **fresh** `HttpFilterContext` with
  `request_headers_to_set: Vec::new()`. So even if a filter pushes to
  that vec during `on_request_body`, the body filter handler only reads
  back `body_bytes`, `cluster`, `upstream`, and `filter_metadata` — the
  header mutations are discarded.
- `protocol/src/http/pingora/handler/upstream_request.rs` strips
  `Transfer-Encoding` as a standard hop-by-hop header on the upstream
  hop, so setting `Transfer-Encoding: chunked` from `on_request` (and
  stripping `Content-Length`) does not survive to the upstream — Pingora
  then defaults to a zero-length body and writes our modified bytes
  against an already-closed body channel ("Upstream body is already
  finished. Nothing to write").

So the limitation isn't a missing field on the context — it's that the
body-phase pipeline doesn't apply `request_headers_to_set` to the
upstream request, and there's no other hook with the right timing.

## What we tried

- **Strip `Content-Length` in `on_request`** → Pingora has no length
  signal for the upstream POST and treats the body as zero-length;
  upstream sees an empty body.
- **Strip `Content-Length` + set `Transfer-Encoding: chunked` in
  `on_request`** → praxis's `strip_hop_by_hop` removes
  `Transfer-Encoding` on the upstream hop. Same empty-body outcome.
- **Push `Content-Length: <new_len>` from `on_request_body`** → praxis's
  body-phase handler does not propagate header mutations from the body
  phase to the upstream request. Header value is dropped.

## Proposed fix(es)

These are options, ordered from most-targeted to most-general. Any one
would unblock the integration.

### 1. Propagate body-phase header mutations to the upstream request

In `protocol/src/http/pingora/handler/request_body_filter.rs`, retrieve
`fctx.request_headers_to_set` / `fctx.request_headers_to_remove` after
each invocation of `pipeline.execute_http_request_body(...)` and apply
them to `session.req_header_mut()` (mirroring what
`request_filter/mod.rs:138-146` does for the request phase).

Pro: minimal API surface change; existing context fields are reused.
Con: a body-phase mutation of `Content-Length` is timing-sensitive (it
must land before Pingora has written body bytes upstream). For an h1
upstream this works because Pingora writes headers lazily — but it would
need a small integration test to lock in the contract.

### 2. New `upstream_request_filter` hook on `HttpFilter`

Add an async hook on the `HttpFilter` trait that's called from
`with_body.rs::upstream_request_filter` *after* the body has been fully
buffered (for `BodyMode::StreamBuffer`) and just before Pingora writes
the upstream headers. The filter receives a mutable
`pingora_http::RequestHeader` and the final body bytes, and can adjust
headers (including `Content-Length`) based on the actual upstream
payload it's about to send.

Pro: cleanest semantics — the hook fires when the data needed to compute
the new `Content-Length` is known.
Con: adds a new trait method; needs default impl to avoid breaking
existing filters.

### 3. Automatic `Content-Length` reconciliation in praxis itself

When a filter replaces `*body` in `on_request_body` and the new length
differs from the inbound `Content-Length`, have praxis rewrite the
header automatically before Pingora writes the upstream headers. Either
update `Content-Length` to the new size, or switch to chunked transfer
when streaming.

Pro: filters need no API change.
Con: harder to reason about with chained filters that each mutate the
body. Also takes a policy stance ("we rewrite headers for you"), which
may not match every filter's intent.

## What the integration does today

In `integrations/praxis-cpex/filter/src/lib.rs`, the cpex filter pads
its rewritten JSON-RPC body with trailing ASCII spaces (`b' '`) to match
the inbound `Content-Length` whenever the rewrite shrinks the body, and
logs a warning when the rewrite grows the body (the upstream then sees a
truncated request — which fails noisily). Once any of the proposed fixes
lands upstream, that padding logic can be removed.

Reference: `integrations/praxis-cpex/filter/src/lib.rs`, in the
`on_request_body` arm where `cmf_result.modified_payload.is_some()`.

## Why this matters for the CPEX/APL integration

CPEX is a policy-evaluation framework for AI proxies; one of its core
features is **field-level rewriting** of request payloads — e.g.
`redact(args.ssn)` removes PII from the args struct before the request
reaches the tool. The downstream effect of a redact is almost always a
length change: `"123-45-6789"` (11 bytes) → `"[REDACTED]"` (10 bytes),
or longer ID strings → shorter masks, or struct keys getting dropped.

Without a way to update `Content-Length`, every CPEX deployment that
uses field rewrites on JSON bodies has to either pad (our workaround)
or restrict rewrites to length-preserving substitutions. Neither is a
great long-term answer.

Happy to send a PR for option (1) or (2) once we agree on which fits
the praxis design best.
