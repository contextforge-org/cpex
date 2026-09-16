# Denial telemetry contract

CPEX exposes an attributable snapshot for an explicit denial returned by a
sequential or concurrent plugin. An outcome exists even when no metrics survive
validation. Direct plugin-raised exceptions and infrastructure failures retain
their existing behavior; they do not create an outcome. Audit, transform, and
fire-and-forget modes do not enforce a denial.

## Explicit opt-in

Python 0.1 producers populate `PluginResult.denial_metadata`, whose default is
`None`. Existing `PluginResult.metadata` keeps its current behavior and is never
forwarded automatically. For example:

```python
return PluginResult(
    continue_processing=False,
    violation=PluginViolation(reason="Blocked", description="Policy matched", code="POLICY_DENIED"),
    denial_metadata={"policy.matched": True, "rejected_count": 1, "score": 0.75},
)
```

Rust producers use `PluginResult::deny_with_metadata(violation, metrics)`.
The isolated Python host uses only the worker's explicit `denial_metadata` field.

Metrics are flat exact booleans, signed 64-bit integers, or finite double-precision
floats. Zero and false are meaningful and preserved. Each input map has at most
16 fields; larger maps are rejected entirely. Keys have 1–64 ASCII letters,
digits, dots, underscores, or hyphens. Invalid entries are dropped individually.
Strings (including all backend names), null, nesting, arrays, unsupported objects,
non-finite floats, and integers outside the signed 64-bit range are excluded.
Python types are checked without coercion. Rust validates the decoded JSON
number representation: signed integers and finite floating-point numbers.
An integer literal beyond serde_json's signed range can decode as a floating-point
number; producers must supply typed signed-64-bit integers rather than overflowing
integer literals.

Producers must use static metric names and non-sensitive operational values.
Numeric user, tenant, or request identifiers must never be deliberately supplied.
Type validation cannot prove privacy. Metric names and values do not control
attribution, execution state, or enforcement.

The primitive range follows [OpenTelemetry's common representation](https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/common/README.md).
CPEX deliberately accepts a narrower value set than OpenTelemetry.

## Runtime envelopes and isolation

Python 0.1 exposes `PluginViolationError.denial_outcome`: a detached frozen
`DenialOutcome`, with a frozen `execution` projection, validated protocol fields,
and immutable `metadata`. It does not depend on the mutable `exc.executions`
list or `exc.violation` object. The projection excludes free-form `reason` and
`config_keys`; a field-parity test requires explicit review when the original
execution record gains fields. Existing message, violation, and executions APIs
remain compatible.

Rust 0.2 (PR #179) exposes `PipelineResult.denial_outcome` with trusted identity,
hook, and mode directly on the outcome. It does not expose an execution record.
Python empty metrics and Rust absent metadata both mean “no metrics.”

Python validates outcome violation/error codes as 1–64 character ASCII identifier
labels with the same key alphabet. Invalid labels become absent. HTTP codes must
be exact integers from 100 through 599; MCP codes must be signed 32-bit integers.
Booleans and strings are not protocol codes. Rust consumers apply these same
checks to separately supplied `PipelineResult.violation` fields before exporting;
the Rust raw violation retains its existing API.

## Gateway field mapping

These are the consumer contract for `cpex.control.result` spans in both DB and
OTel sinks. Fields unavailable in a runtime remain absent.

| Gateway attribute | Python 0.1 source | Rust 0.2 source |
| --- | --- | --- |
| `cpex.control.name` | `outcome.execution.plugin_name` | `outcome.plugin_name` |
| `cpex.control.plugin_id` | `outcome.execution.plugin_id` | `outcome.plugin_id` |
| `cpex.control.plugin_kind` | `outcome.execution.plugin_kind` | absent |
| `cpex.control.hook_name` | `outcome.execution.hook_name` | `outcome.hook_name` |
| `cpex.control.mode` | `outcome.execution.mode` | `outcome.mode` |
| `cpex.control.status` | `outcome.execution.status` | absent |
| `cpex.control.result.allowed` | `outcome.execution.effective_allow` | `result.continue_processing` (false) |
| `cpex.control.result.requested_allowed` | `outcome.execution.requested_allow`, when present | absent |
| `cpex.control.duration_ns` | `outcome.execution.duration_ns`, when measured | absent |
| `cpex.control.matched` | `outcome.execution.matched`, when present | absent |
| `cpex.control.applied` | `outcome.execution.applied` | absent |
| `cpex.control.payload_modified` | `outcome.execution.payload_modified` | absent |
| `cpex.control.result.error_code` | `outcome.violation_code` or validated execution error code | validated `result.violation.code` |
| `cpex.control.result.mcp_error_code` | `outcome.mcp_error_code` | validated `result.violation.proto_error_code` |
| `cpex.control.result.http_status_code` | `outcome.http_status_code` | absent (runtime has no HTTP violation field) |
| `cpex.control.result.metadata.<key>` | `outcome.metadata[key]` | `outcome.metadata[key]`, when present |

Python concurrent execution records have zero duration as an unmeasured placeholder;
consumers omit that duration rather than inventing branch timing. Rust consumers do
not invent completed status, successful execution state, duration, or mutation facts.
Enforcement point (`pre` or `post`) comes from Gateway's invocation context.

Gateway must merge the outcome with its accumulated exception execution records,
emitting the denying control exactly once, then emit the denied summary. Matching
must include invocation/hook identity; plugin ID alone does not distinguish
repeated evaluations. Consumers must tolerate absent optional projection fields
(`reason` and `config_keys`) without dropping a denial record.

## Transport and consumer dependencies

MCP carries the optional Python result field through normal model serialization.
gRPC and Unix carry it in additive `PluginResultBase.denial_metadata` protobuf
messages with typed boolean, sint64, and double values; dynamic Struct numbers
cannot preserve signed-64-bit endpoints. The dynamic result remains compatible
with older peers, which ignore the additive field and continue enforcement without
new metrics. Both peers must support the field for lossless denial metrics.

Gateway's current rate-limiter-only metadata filter must adopt generic validation
and this explicit field before arbitrary numeric metrics reach collectors. Existing
plugins keep working without migration; producers wanting denial metrics opt in.
No rate-limiter conversion, backend-name registry, or metric-field registry exists
in the framework.

[Gateway issue #6785](https://github.com/IBM/mcp-context-forge/issues/6785) owns
DB/collector integration and persistence repairs. Acceptance includes an identifiable
denial result plus denied summary, no duplicate denying-control span, no raw
arguments/headers/details, and no upstream dispatch after a pre-hook denial.
Full Gateway DB/collector verification is outside this framework change.
