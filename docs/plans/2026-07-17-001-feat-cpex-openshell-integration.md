---
title: "feat: CPEX-backed Authorization for OpenShell L7 Egress"
type: feat
status: draft
date: 2026-07-21
deepened: 2026-07-17
---

# Proposal: CPEX-backed Authorization for OpenShell L7 Egress

> **Status: solicitation for feedback.** This proposal explores an optional,
> operator-owned CPEX authorization adapter for OpenShell L7 egress. It proposes
> a Phase 0 compatibility and threat-model spike before any in-tree product
> integration. Community and maintainer feedback is requested on the ownership,
> control-plane, identity, and PDP choices described below.

## Proposal summary

This proposal explores whether CPEX can provide a valuable *optional,
operator-owned* identity and fine-grained authorization layer for OpenShell's
L7 egress proxy. Its Cedar/CEL, delegation, elicitation, response transformation, and
session-state model align with the project's policy, provider, middleware, and multi-tenant roadmaps.

### What CPEX adds beyond the current L7 path

OpenShell's egress policy today evaluates each request statelessly against
transport coordinates (host, port, method, path). CPEX contributes capabilities
the current path does not express:

- **Richer authorization and composable policy pipelines** per capability (tool,
  resource, prompt, A2A method), not only host/port/method/path.
- **Cross-operation security.** Session tainting and information-flow control
  that can block a later exfiltration based on what an earlier call read.
- **Pluggable controls.** Authorization delegated to Cedar, CEL, or an external
  PDP, with redaction, delegation, and audit as first-class pipeline steps.
- **Protocol-independent policy.** Policy is expressed once over a canonical
  message form (CMF) rather than re-encoded per wire format.
- **Human-in-the-loop elicitation.** Out-of-band approval of sensitive
  operations, suspended and resumed against the concrete request.
- **Defense in depth.** CPEX composes with, and never replaces, OpenShell's
  L4 and baseline L7 gates.
- **Policy portability.** The same APL policy runs wherever CPEX is embedded:
  sidecar, gateway, or in-process.

Most of these capabilities are deferred beyond the initial pilot (see the
Delivery plan). They motivate the integration, but each requires its own threat
model and approval before it ships.

This is **not** presented as a drop-in replacement for the existing OPA/
`regorus` policy path. The proposed boundaries are:

- OpenShell still needs its local L4 host/port, IP/SSRF, process-identity, and
  baseline L7 protections. Those are enforcement invariants, not merely an
  authorization PDP.
- CPEX's current `main` / 0.2.x release declares Rust **1.96**. OpenShell pins
  Rust **1.95.0** (`rust-toolchain.toml`) and has workspace MSRV **1.90**
  (`Cargo.toml`). Cargo will reject this dependency today.
- OpenShell policies are typed `SandboxPolicy` protobufs sent between gateway,
  drivers, and supervisor; arbitrary top-level YAML cannot simply be read from
  `policy_local.rs` or passed through a Rego data map.
- A bearer token observed in outbound HTTP is not automatically a trustworthy
  user or agent identity. It may be an API key, a credential placeholder, an
  opaque token, or agent-controlled input. Using it as identity without
  verification would be unsafe.

If the Phase 0 gates pass, the proposed first product increment is a narrow
**CPEX authorization adapter** for REST request admission, with a well-defined
trusted identity source and one local PDP. It does not include OAuth exchange or
CPEX's full plugin set. Each later capability requires its own threat model and
approval.

## Current implementation context

### OpenShell integration context

- L4 and L7 evaluation currently share the embedded `regorus`-based
  `TunnelPolicyEngine` in `crates/openshell-supervisor-network/src/opa.rs`.
  L4 endpoint selection and L7 rule evaluation are different queries over the
  same generated policy data.
- `L7EndpointConfig` is extracted from a `regorus::Value` in
  `crates/openshell-supervisor-network/src/l7/mod.rs`, not parsed directly from
  a free-form YAML file. The relays live in `l7/relay.rs`, with additional
  direct evaluations in `l7/websocket.rs` and `proxy.rs`.
- The externally managed policy shape is `SandboxPolicy` in
  `proto/sandbox.proto`; `openshell-policy` uses strict serde
  (`deny_unknown_fields`) to convert policy YAML to/from that protobuf. Any
  endpoint option or policy reference must cross proto generation, policy
  parsing/serialization, composition/merge, gateway validation, and supervisor
  conversion.
- Policy reload already has a `PolicyGenerationGuard`. A CPEX configuration
  must join the *same atomic effective-policy generation*, rather than use an
  independently long-lived runtime.
- The proxy already has valuable security ordering: canonicalization and secret
  redaction before evaluation, then credential injection/signing only after an
  allow decision. That ordering must remain intact.

### CPEX integration context

- CPEX is Apache-2.0 and its 0.2.x facade supports granular `jwt`, `cedar`,
  and `cel` features. It offers an HTTP CMF hook (`cmf.http_request`), not the
  proposed ready-made `CpexRuntime::evaluate(policy_ref, cmf)` API.
- CPEX expects its own structured APL configuration (`global`, routes,
  plugins/PDPs, session stores) to be registered with `PluginManager` and
  invoked via the CMF hook. A `cpex: policies: name: | ...` map and opaque
  `cpex_policy_ref` are an OpenShell adapter design, not CPEX's native schema;
  the adapter must define and validate the mapping.
- CPEX is active but immature for a security-critical dependency: its public
  repository is recently created (December 2025), has low adoption, and its
  README calls it under active development. Pin an exact reviewed release and
  require normal dependency/security approval rather than using a broad
  `version = "0.2"` range.

## Where CPEX fits in the architecture

CPEX is proposed as a **supervisor-side authorizer** with **gateway-side
control-plane surface**. Neither component alone is sufficient: the supervisor
is the only place with process identity, canonicalized request view, and
per-request latency budget; the gateway is the only place with authenticated
operator identity, durable bundle storage, and cross-sandbox composition.

```mermaid
flowchart TB
    subgraph OPERATOR["Operator surface"]
        OPCLI["openshell CLI / SDK<br/>(privileged operator role)"]
    end

    subgraph GATEWAY["Gateway (control plane)"]
        direction TB
        API["gRPC API"]
        INTERCEPT["Interceptor middleware<br/>(pre-existing)"]
        REGISTRY[("CPEX bundle registry<br/>digest-pinned, immutable")]
        POLSTORE[("SandboxPolicy store<br/>+ effective-config resolver")]
        PROVER["openshell-prover<br/>(baseline compatibility check)"]
        DELIVER["Effective-policy delivery<br/>(revision + bundle bytes + digest)"]
    end

    subgraph SUPERVISOR["Sandbox supervisor (data plane)"]
        direction TB
        POLICYGEN["EffectiveL7Policy<br/>{generation, opa, cpex}"]
        L4["L4 gate<br/>(host/port, SSRF, process ID)"]
        BASELINE["Baseline L7 gate<br/>(canonicalize, size, redact)"]
        MW["Middleware chain<br/>(existing)"]
        AUTHZ["L7Authorizer trait"]
        OPA["OPA engine (regorus)"]
        CPEX_RT["CPEX adapter<br/>+ local PDP<br/>(Cedar or CEL)"]
        DECIDE{"Decision"}
        INJECT["Credential injection /<br/>SigV4 signing"]
        UPSTREAM(["Upstream request"])
    end

    OPCLI -- "AttachCpexBundle,<br/>PutCpexBundle" --> API
    API --> INTERCEPT
    INTERCEPT -- "operator admission +<br/>optional profile source" --> REGISTRY
    INTERCEPT --> POLSTORE
    POLSTORE -- "compose with<br/>bundle digest ref" --> PROVER
    PROVER --> DELIVER
    REGISTRY -- "bundle bytes<br/>(pinned by digest)" --> DELIVER
    DELIVER -- "atomic revision" --> POLICYGEN

    UPSTREAM_IN(["Agent egress"]) --> L4 --> BASELINE --> MW --> AUTHZ
    POLICYGEN -.-> AUTHZ
    AUTHZ -- "engine: opa" --> OPA --> DECIDE
    AUTHZ -- "engine: cpex" --> CPEX_RT --> DECIDE
    DECIDE -- "allow" --> INJECT --> UPSTREAM
    DECIDE -- "deny" --> OCSF["OCSF HTTP activity<br/>+ DetectionFinding"]
```

**Placement rationale:**

- Per-request authorization must run inside the supervisor. Only the supervisor
  sees the calling binary identity, canonicalized request view, and redacted
  header set. Round-tripping every L7 request to the gateway would violate
  OpenShell's local-enforcement invariant and add unacceptable latency.
- CPEX cannot preempt the L4/baseline path. The `L7Authorizer` trait fires
  only after L4, canonicalization, redaction, and baseline L7 gates admit the
  request — matching invariant #2 (deny always wins, CPEX never widens).
- The gateway owns bundle authorship. Bundles are large, digest-pinned, and
  operator-signed; they belong in durable gateway state, not inline in
  `SandboxPolicy`. Delivery is atomic within a policy revision so the
  supervisor never runs a CPEX bundle whose OPA companion is stale.
- Delivery is one direction. The supervisor never reaches back to fetch a
  bundle at request time — that would put CPEX bundle egress inside the same
  sandbox network namespace the proxy is guarding.

## Integration paths

There are three ways to bring CPEX into OpenShell's egress path, in increasing
order of depth and OpenShell change required.

1. **External supervisor middleware.** Run CPEX as an out-of-process gRPC
   service invoked by the existing supervisor middleware hook for pre-request
   authorization, argument transformation, and auditing. This is the least
   invasive path and it avoids the Rust toolchain conflict entirely, because the
   service builds with its own toolchain and never links into OpenShell.
   Limitation: OpenShell's V1 supervisor hook is request-only
   (`HTTP_REQUEST/PRE_CREDENTIALS`). It cannot carry a response phase, a
   suspend/pending result, or a credential write, so response redaction,
   result-derived taint, and elicitation are out of reach on this path.
2. **Native supervisor integration.** Embed CPEX's Rust runtime directly in the
   supervisor behind the `L7Authorizer` trait. This gives lower latency,
   in-process locality, and access to richer trusted context (calling-binary
   identity, canonicalized request view, policy generation). Cost: it modifies
   OpenShell and requires reconciling the MSRV gap (CPEX 1.96 vs OpenShell
   1.95). For a PoC this is a non-issue: bump the fork's toolchain to 1.96.
   Upstreaming needs the real fix, either CPEX lowering its MSRV or OpenShell
   advancing it through its own process. Do not raise OpenShell's MSRV for this
   feature alone.
3. **Extended middleware contract.** Add post-response hooks and a structured
   `Suspend` outcome to the supervisor contract so result filtering, taint
   propagation, and CPEX human-approval (elicitation) flows work end to end.
   This is the only path that delivers the full capability set, but it changes
   OpenShell's extension contract and belongs in a hook-system RFC.

**Recommendation.** Demonstrate paths (1) and (2) and make the tradeoffs
explicit. Path (3) can be deferred as a hook-system RFC redesign if maintainers
choose: from the perspective of showing CPEX's authorization benefits it has no
material observable difference from path (2), which can already exercise pre-
and post-invocation in-process. The phased delivery plan below realizes the
path (1)/(2) capabilities incrementally and places response and elicitation work
(which needs path (3) upstream, or a fork for the PoC) in Phase 4.

Regardless of the chosen path, the high-level control flow is the same:

```mermaid
flowchart TD
    A["Parsed HTTP/MCP operation"] --> B["CMF conversion"]
    B --> C["CPEX pre-invocation"]
    C --> D{"Decision"}
    D -->|Deny| E["Protocol-aware denial"]
    D -->|Pending| F["Elicitation response"]
    D -->|Allow| G["Forward operation"]
    G --> H["CPEX post-invocation"]
    H --> I["Filtered result"]
```

In path (1), the `Pending`/elicitation and post-invocation branches are
unavailable: the request-only hook cannot forward the operation and resume, nor
carry a pending result. Paths (2) and (3) enable them (path (2) within a fork of
OpenShell, path (3) as an upstream contract change). This capability-flow view
complements the placement diagram above, which shows path (1)/(2) as a
supervisor-side `L7Authorizer` alongside OPA.

## Can CPEX ride the gateway interceptor middleware?

The gateway interceptor middleware
(`crates/openshell-gateway-interceptors/`, `proto/gateway_interceptor.proto`)
was merged to let external governance services evaluate **gateway control-plane
operations** — `CreateSandbox`, `SetPolicy`, `UpdateProvider`, and similar
allowlisted RPCs — through phases `MODIFY_OPERATION`, `VALIDATE`, and
`POST_COMMIT`. It is not a data-plane request-authorization mechanism.

### Where the interceptor mechanism *is* a good fit

The interceptor system is genuinely useful for two of the CPEX integration's
control-plane needs:

1. **Bundle vending via `SnapshotProviderProfiles` precedent.** The manifest
   already advertises `provider_profiles = true` to expose a snapshot RPC that
   returns a revision-pinned catalog. The same pattern — a new
   `SnapshotCpexBundles` RPC or a shared "artifact catalog" abstraction —
   would let an external CPEX authoring service vend digest-pinned bundles to
   the gateway on the same manifest, freshness, and duplicate-detection path
   used by provider profiles today. The gateway remains the authoritative
   source; the interceptor is a trusted upstream.
2. **Operator admission for CPEX management RPCs.** New privileged operations
   like `PutCpexBundle`, `AttachCpexBundle`, or `SetCpexIssuer` should be added
   to the interceptable-method allowlist. This gives operators a familiar path
   to reject bundle attachments that violate site policy (e.g. "no bundle
   without SBOM annotation") using `VALIDATE` phase.

Both uses are within the interceptor system's design intent: control-plane
governance, ProtoJSON payloads, `fail_open`/`fail_closed` bindings, secret
field elision, atomic per-binding modifications.

### Where the interceptor mechanism is *not* the right vehicle

CPEX's **per-request L7 admission** — the value the proposal is chasing —
cannot run through gateway interceptors:

| Constraint | Why it rules out gateway interceptors |
|---|---|
| Locus of enforcement | Interceptors run in the gateway process; every agent egress request would need to round-trip out of the sandbox, through the supervisor session, into the gateway, through the interceptor gRPC, and back. That path currently does not exist. |
| Latency budget | Interceptors are unary RPCs to an external service. Per-request L7 admission needs p95 in the low-milliseconds range with in-process locality. |
| Visible context | The interceptor payload is a ProtoJSON view of a *gateway operation*, with secret fields elided by the middleware. It is not the sandbox `L7RequestInfo` — no calling-binary identity, no canonicalized request view, no trusted identity provenance. Reshaping it would create a parallel, weakly-typed data plane. |
| Trust boundary | Interceptors are gateway-configured trusted sources. A per-request PDP call would give the interceptor read access to redacted request views for every sandbox on the gateway, breaking tenant isolation. |
| Reload semantics | The immutable `EffectiveL7Policy { generation, opa, cpex }` snapshot must be constructed atomically per sandbox. An out-of-process interceptor cannot join that generation guard. |

### Recommendation

Treat the interceptor system as the **control-plane distribution channel** for
CPEX artifacts and management admission, and keep per-request authorization
in the supervisor via the `L7Authorizer` trait. Phase 1 RFC should specify
whether a new `SnapshotCpexBundles` RPC is added to the existing manifest
service or a broader "trusted artifact source" abstraction is introduced —
either way, do not overload provider profile snapshotting with bundle
distribution semantics.

## How a CPEX policy is stored in the data model

CPEX bundles are **not** stored inline in `SandboxPolicy`. They live in a
separate gateway-owned registry and are referenced by digest from endpoint
configuration. This mirrors the pattern already established by provider
profile catalogs and interceptor-vended sources: reference in policy, bytes in
a versioned catalog with duplicate-ID detection.

### New protobuf surface (illustrative, Phase 1 RFC to finalize)

```proto
// openshell.sandbox.v1
message NetworkEndpoint {
  // ... existing fields ...

  // Optional L7 authorization engine selection. When unset, endpoint uses
  // the existing OPA-generated L7 rules path. Mutually exclusive with the
  // `access` preset and inline `rules`.
  L7Authorization authorization = 20;
}

message L7Authorization {
  oneof engine {
    // Explicit "use OPA" — no bundle reference required.
    OpaEngine opa = 1;
    // Reference to a gateway-registered CPEX bundle by content digest.
    CpexBundleReference cpex = 2;
  }
}

message OpaEngine {}

message CpexBundleReference {
  // Immutable content digest of the registered bundle: "sha256:...".
  // Validated at policy load; unresolved digests reject the revision.
  string digest = 1;

  // Local PDP kind selected for this endpoint. The gateway rejects the
  // revision if the digest's bundle does not declare a matching PDP.
  CpexPdpKind pdp = 2;

  // Optional bundle version tag for audit/UX only. The digest is authoritative.
  string version_tag = 3;
}

enum CpexPdpKind {
  CPEX_PDP_KIND_UNSPECIFIED = 0;
  CPEX_PDP_KIND_CEDAR = 1;
  CPEX_PDP_KIND_CEL = 2;
}
```

### Durable storage (gateway)

Two logically separate tables, both operator-owned:

| Table | Purpose | Ownership |
|---|---|---|
| `cpex_bundle` | Immutable, content-addressed bundle blobs keyed by digest. Rows are append-only. Columns: `digest` (PK), `bytes`, `pdp_kind`, `size`, `sbom_ref`, `signature`, `uploaded_by`, `uploaded_at`. | Written only by `PutCpexBundle` operator RPC. Not writable by sandboxes, policy proposals, or agent-editable paths. |
| `cpex_bundle_attachment` | Which sandbox / gateway scope may use which bundle. Enforces that `SandboxPolicy` revisions can only reference an attached bundle. Columns: `scope` (`gateway` or `sandbox:<id>`), `digest`, `attached_by`, `attached_at`. | Written by `AttachCpexBundle` operator RPC. Detachment leaves the bundle row in place but rejects new revisions referencing it. |

Bundle bytes are never modified in place. Rotation is "upload new digest,
attach it, update endpoint reference, detach old digest." This gives the
policy advisor and audit trail a stable per-revision identity.

### Sandbox-policy revision lifecycle

1. Operator uploads bundle → `cpex_bundle(digest=sha256:abc…, bytes=…)`.
2. Operator attaches → `cpex_bundle_attachment(scope='sandbox:s-42', digest=sha256:abc…)`.
3. Agent or operator submits a `SandboxPolicy` revision with an endpoint
   whose `authorization.cpex.digest = "sha256:abc…"`.
4. Gateway policy validator checks:
   - digest exists in `cpex_bundle`;
   - digest is attached to the target scope;
   - declared `pdp` matches `cpex_bundle.pdp_kind`;
   - baseline compatibility gate (openshell-prover) still passes.
5. Effective config resolver bundles the revision **plus** the referenced
   bundle bytes into the same policy generation payload sent to the
   supervisor. Delivery is atomic per generation.
6. Supervisor's effective-policy constructor compiles the OPA engine, then
   compiles the CPEX runtime from the delivered bundle bytes, then publishes
   `EffectiveL7Policy { generation, opa, cpex }` under the existing
   `PolicyGenerationGuard`. Any failure keeps the last-known-good generation.

### Why not inline the bytes in `SandboxPolicy`

- **Size.** Bundles can be tens of kilobytes of Cedar/CEL plus schema. Inline
  APL bloats every policy revision, every policy proposal message, every
  policy YAML round trip, and the mechanistic mapper's audit history.
- **Attribution.** Bundle authorship must survive policy revision churn.
  Content-addressed storage separates "who authored this bundle" from
  "which sandbox is currently using it."
- **Agent-proposal safety.** `SubmitPolicyAnalysis` accepts proposals from
  agents. Inline APL would let an agent-authored chunk change the effective
  policy engine. Digest reference plus attachment table forces bundle changes
  through the operator-only path.
- **Cache and reuse.** Two sandboxes attached to the same bundle digest
  share compiled CPEX runtime state (per supervisor) and the same audit
  identity across supervisors.

### Interaction with policy advisor

The policy advisor pipeline (`openshell-prover` + auto-approval gate) treats a
CPEX-referenced endpoint as a first-class rule. The prover already answers
categorical questions about baseline reach; it does not evaluate Cedar/CEL
semantics. Phase 1 must decide whether the prover treats any endpoint with
`authorization.cpex` as an implicit `capability_expansion` (safer default,
forces manual review) or extends its model to reason about attached-bundle
allow sets (more accurate but larger scope). The proposal recommends the
former for v1: any policy revision that adds or changes a CPEX bundle
reference bypasses auto-approval.

## Proposed design constraints

The following constraints define the proposal from the outset. They are intended
to focus community discussion on a secure, supportable integration rather than
to prescribe an implementation prematurely.

| Design area | Constraint and rationale | Proposed approach |
|---|---|---|
| Dependency compatibility | CPEX declares `rust-version = 1.96`; OpenShell uses 1.95.0. | First obtain a CPEX release compatible with OpenShell's supported Rust baseline, or upgrade OpenShell through its normal MSRV process. Do not raise the MSRV for this feature alone. |
| Policy configuration | `policy_local.rs` serves the in-sandbox advisor API; it is not policy ingestion. `SandboxPolicy` proto and strict YAML types reject that field. | Define a typed, versioned protobuf/config surface and propagate it through gateway, supervisor, serialization, merge and proposal validation—or use a separately distributed, operator-owned bundle. |
| Baseline enforcement | L4 routing/SSRF/process checks and the existing generated L7 rules remain OPA-backed. A CPEX endpoint with no conventional rules may be denied before the proposed dispatch executes. | Specify a composition contract: **OpenShell baseline gate AND selected authorization engine**. Add an explicit safe baseline mode for CPEX endpoints, never an implicit empty-rule bypass. |
| Identity provenance | Outbound credentials are not authenticated identity and may be agent-controlled, opaque, or secret. Treating them as identity could permit spoofing or disclosure. | Accept identity only from a configured trusted source: verified gateway/supervisor attestation, validated issuer/audience/JWKS with bounded cache, or an explicitly configured mTLS/SPIFFE identity. Treat all outbound authorization headers as secrets; do not log, persist, or use them as identity by default. |
| Policy reload | An independently long-lived runtime can evaluate a stale policy after reload; an OPA guard alone does not prove CPEX configuration is coherent with it. | Build an immutable `EffectiveL7Policy { generation, opa, cpex }`, atomically swap it, and make every evaluation use one snapshot/generation. Close/retry or finish according to explicit reload semantics. |
| Enforcement coverage | There are additional direct calls in WebSocket and forward-proxy paths. An async CPEX path also changes call signatures and error paths. | First inventory and centralize all request-admission paths behind a single engine-neutral interface; prove coverage with tests before enabling CPEX. |
| Initial PDP scope | More code and configuration than the first value needs; no issuer/PDP operation model is supplied. | Start with **one local PDP** (recommend Cedar *or* CEL after benchmark/expressiveness spike), no JWT plugin unless verified identity is a tested requirement. |
| Initial decision surface | Predeclaring mutation outputs would create a misleading public contract before wire and ownership semantics are designed. | Keep the first decision type minimal. Design each mutating capability in a later RFC/spike with explicit ownership, rollback, timeout, and secrecy semantics. |
| Session state | Session keys must be authenticated, tenant/sandbox scoped, bounded, expiry-managed, and reliable under restart/HA. | Treat stateful taint as a separate distributed-security feature, not a mechanical backend substitution. |

## Target architecture

### Invariants

1. **OpenShell controls reachability.** L4 allowlisting, DNS/IP validation,
   process binding, TLS behavior, request canonicalization, and credential
   protection execute before any externalized authorization decision.
2. **CPEX cannot widen the baseline.** A CPEX `allow` only permits a request
   already admitted by OpenShell's fixed baseline gate. Deny always wins.
3. **Operator ownership is explicit.** Only an operator-authorized immutable or
   signed policy bundle can select CPEX, PDP configuration, issuers, JWKS
   origins, routes, and limits. Agent policy proposals cannot add/change these.
4. **Identity is authenticated and provenance-labelled.** Every principal
   attribute has a source (`gateway_attested`, `spiffe_verified`,
   `jwt_verified`) and CPEX policy can require one. Absence is not substituted
   with a parsed bearer token.
5. **Failure is closed in enforce mode.** Parse, configuration, identity,
   runtime, timeout, and PDP errors deny. Audit mode logs a distinguishable
   would-deny result; it never converts a failed initialization into a silent
   allow.
6. **No secret disclosure.** Raw authorization/cookie headers, JWTs, exchanged
   tokens, and sensitive claims never enter OCSF messages, policy denial
   responses, metrics labels, or persistent CPEX session/audit state unless a
   separately approved redaction design permits it.

### Evaluation order (initial REST scope)

```text
CONNECT L4: process + hostname + port + resolved-IP/SSRF gate (existing OpenShell)
  -> TLS termination / HTTP parsing / canonicalization (existing)
  -> redact placeholders and construct a minimal non-secret request view
  -> baseline L7 structural gate (method/path/body/header limits; existing)
  -> supervisor middleware chain (existing; per-entry fail_open/fail_closed)
  -> selected authorization engine:
       OPA: existing generated L7 rules
       CPEX: immutable CPEX adapter + one local PDP, using trusted identity
  -> deny/audit decision and OCSF event
  -> existing token grant injection and SigV4 signing
  -> upstream request
```

CPEX sees a purpose-built request view: method, canonical path, selected
non-secret headers, host/port, request size, trusted workload identity, and
(optional) verified subject claims. Header allowlisting is mandatory; forwarding
all raw headers is not.

### Configuration ownership and shape

Do **not** make raw APL an inline field in tenant/agent-editable sandbox policy.
Choose one of these only after Phase 0:

1. **Preferred initial model — gateway-owned bundle registry:** An operator
   registers a CPEX bundle by immutable digest and limited configuration. A
   typed endpoint reference names that registered bundle. The gateway validates
   it and sends an already-approved, digest-pinned payload to the supervisor.
2. **Typed sandbox-policy model:** Add a small protobuf `L7Authorization`
   message and `CpexBundleReference` with an enum engine, opaque *validated*
   bundle ID/digest, and no inline APL. This requires compatibility/versioning
   work across API clients and all policy serialization paths.

Neither model permits endpoint data to configure arbitrary JWKS URLs, PDP URLs,
plugin kinds, or session stores. Those remain operator configuration.

The configuration must be validated transactionally: collect every endpoint
reference, resolve all bundles/PDPs/trusted issuers, compile/initialize CPEX,
validate endpoint/bundle protocol compatibility, then publish the new effective
policy generation. Any failure rejects the policy revision; it must not result
in one endpoint silently falling back to OPA or audit mode.

### Minimal internal interface

First refactor request admission around an engine-neutral, synchronous-or-async
interface, rather than making each protocol relay know CPEX details:

```rust
struct RequestAuthorizationInput<'a> {
    endpoint: &'a L7EndpointConfig,
    request: &'a L7RequestInfo,
    // Canonical, redacted, header-allowlisted representation only.
    request_view: &'a AuthorizedRequestView,
    identity: &'a TrustedIdentity,
    policy_generation: u64,
}

struct AuthorizationDecision {
    effect: AllowOrDeny,
    reason_code: &'static str, // stable, non-secret code
    policy_id: Option<PolicyId>,
    engine: AuthorizationEngine,
}

trait L7Authorizer: Send + Sync {
    async fn authorize(&self, input: RequestAuthorizationInput<'_>)
        -> Result<AuthorizationDecision, AuthorizationError>;
}
```

`AuthorizationDecision` has no token, raw claims, mutable headers, redaction
patches, or session taints in v1. OCSF records the engine and non-secret policy
identifier in structured fields while keeping the existing HTTP activity event
shape. Use a stable engine value such as `cpex-cedar` rather than overloading
`firewall_rule.rule_uid` with an engine name.

## Delivery plan and decision gates

### Phase 0 — compatibility and threat-model spike (no product surface)

**Goal:** prove that a maintainable and safe embedding exists before changing
OpenShell policy schemas. The spike is a decision gate, not a commitment to adopt CPEX.

1. Create an isolated branch/crate that attempts to compile the exact reviewed
   CPEX release with OpenShell's Rust 1.95.0 toolchain, Linux targets, current
   dependency/license/vulnerability gates, and supervisor image constraints.
2. Implement a 50–100 line host prototype using CPEX's real API:
   `PluginManager`, `register_apl`, `load_config_yaml`, and invocation of
   `cmf.http_request`. Demonstrate a single static allow and deny with the
   intended HTTP CMF fields.
3. Compare one Cedar and one CEL policy for expressiveness, deterministic
   behavior, latency, binary/image size, memory, and error behavior. Select
   exactly one for v1—or stop if neither fits.
4. Write a threat model covering attacker control of request headers/body,
   sandbox process identity, policy update path, JWKS/PDP availability, CPEX
   bundle supply chain, cross-tenant/session contamination, and log disclosure.
5. Establish identity provenance. The prototype must demonstrate a verified
   trusted identity, an absent identity deny, an invalid signature deny, issuer
   and audience mismatch denies, JWKS timeout/cache-expiry denial, and a bearer
   API key that is **not** misclassified as identity.
6. Decide whether CPEX can run fully in-process. If any PDP/JWKS call is
   networked, define separate operator-controlled egress, DNS/IP pinning,
   timeout/concurrency limits, cache behavior, and recursion avoidance. Do not
   let it use the sandbox's own egress proxy path implicitly.

**Exit criteria (all required):** compatible released CPEX artifact or approved
OpenShell MSRV plan; exact dependency lock and security approval; local PDP
prototype; signed-off threat model; p95 authorization latency and resource
budgets; no raw credentials in fixtures/logs; maintainer agreement on ownership
and engine composition. Failure means reject/defer rather than workaround in
production code.

### Phase 1 — policy/control-plane design RFC

**Goal:** settle durable public semantics before implementation.

- Define the baseline-gate/CPEX composition semantics, precedence, audit mode,
  denial reason taxonomy, reload behavior, identity sources, and retention.
- Choose the gateway-owned bundle registry or typed protobuf reference model.
  Include proto compatibility, policy YAML round trips, `PolicyMergeOperation`,
  provider policy composition, policy advisor visibility, and SDK/CLI impacts.
- Define authorization boundaries: only privileged gateway/operator APIs can
  create/update bundles, issuers, PDP configuration, or attach a CPEX bundle.
  Ensure agent proposals and provider profiles cannot widen them.
- Define a narrow bundle format that maps OpenShell endpoint identity to CPEX's
  actual HTTP hook/config model. Pin digest and version; disallow arbitrary
  plugins and external endpoints.
- Produce an operational runbook: startup/reload errors, safe rollback,
  cache clearing/key rotation, metrics, alert conditions, policy provenance,
  and emergency disable.

**Exit criteria:** security review approval, gateway/supervisor API review,
backward-compatible serialization plan, migration/rollback plan, and a named
maintainer for CPEX version/CVE response ownership.

### Phase 2 — internal refactor and test harness

**Goal:** make the existing L7 path safely extensible without enabling CPEX.

- Centralize every REST request-admission site, including shared-route,
  forward-proxy, WebSocket-upgrade, and direct proxy paths, behind the new
  authorization interface. Preserve byte-for-byte OPA decisions and existing
  audit/enforce behavior.
- Introduce an immutable `EffectiveL7Policy` snapshot with a single generation
  covering endpoint config, OPA engine, and optional authorizer registry.
- Add a test-only fake authorizer to exercise permit, deny, timeout, malformed
  request view, reload race, and audit-mode behavior without a CPEX dependency.
- Add structured, redaction-verified OCSF fields and metrics:
  decisions/errors/timeouts by engine and reason code; bounded cardinality;
  no principals/tokens/paths as metric labels.

**Exit criteria:** full existing L7 suite passes unchanged; tests prove all
entry points invoke the same abstraction; reload never evaluates a mixed
OPA/CPEX generation; fuzz/property tests preserve canonicalization and header
redaction guarantees.

### Phase 3 — feature-gated REST/CPEX authorization pilot

**Goal:** ship only a small, reviewable capability behind an off-by-default
build and operator feature gate.

- Add an optional, exact-pinned CPEX dependency only after Phase 0 passes.
  Keep its enabled feature set minimal: core + the selected local PDP. Do not
  enable JWT, OAuth, PII, audit, Valkey, or CPEX `full` by default.
- Implement the adapter against CPEX's real CMF HTTP hook and approved bundle
  format. Compile/load during effective-policy construction, never per request.
- Enable `engine: cpex` only for `protocol: rest`, only when a valid
  operator-owned bundle reference is supplied, and only in an allowlisted
  pilot deployment. All other protocol/feature combinations reject the policy
  revision clearly.
- Run in *shadow* mode first: execute CPEX without affecting traffic, record
  redacted decision-difference telemetry, and require a bounded observation
  period. Promotion to audit then enforce is operator-controlled per bundle.
- Fail closed in enforce mode for runtime/PDP/identity/timeouts; use short,
  bounded deadlines and concurrency controls. Do not silently fall back to
  OPA because the CPEX runtime is unavailable.

**Exit criteria:** integration/e2e tests across gateway-to-supervisor policy
propagation; one allow, deny, authenticated subject, unauthenticated subject,
reload, rollback, timeout, and OPA regression scenario; documented pilot SLOs;
security sign-off before enforce mode.

### Phase 4 — separately approved follow-ups

Each needs a new design review and independently deployable tests:

1. Verified JWT identity from an explicit trusted source, including issuer,
   audience, algorithm allowlist, key rotation/cache policy, clock skew, and
   claim minimization.
2. Additional protocols (GraphQL, JSON-RPC/MCP, WebSocket) after each gets an
   accurate non-secret CMF mapping and correct per-message semantics.
3. Response inspection/redaction with bounded buffering, compression and
   transfer-encoding correctness, content-length updates, streaming behavior,
   and a fail-safe response policy.
4. OAuth/RFC 8693 exchange only through OpenShell's credential-provider
   boundary. Tokens must be `Zeroizing`, never available to arbitrary APL or
   logs, audience/scopes must be attenuated, and cancellation/retry semantics
   must be defined.
5. Cross-request taint/session state only after authenticated session ownership,
   tenant/sandbox namespacing, bounded TTL/size, atomic persistence, restart/HA
   behavior, and deletion/retention semantics are approved.
6. Human-in-the-loop elicitation based on CIBA: policy-gated egress requests
   suspended pending an out-of-band approval bound to the concrete request. Requires
   its own design for pending-decision semantics on a proxied HTTP request (hold
   vs. deny-and-retry), bounded pending state with timeout-as-deny, an operator-owned
   out-of-band channel separate from the sandbox egress path, verified approver identity,
   and no request secrets in elicitation prompts.

## Validation matrix

| Area | Required proof |
|---|---|
| Build/supply chain | OpenShell supported Rust builds; locked exact CPEX version; license/SBOM/advisory review; Linux image size and cross-target checks. |
| Baseline security | CPEX cannot bypass L4, DNS/IP, process, canonicalization, path, request-size, or credential-redaction guards. |
| Identity | Missing/invalid/expired/wrong issuer/wrong audience/unknown key identity denies; arbitrary outbound bearer values never grant identity. |
| Authorization | Allow, deny, PDP error, malformed bundle, missing bundle, duplicate route, timeout, and audit/enforce actions have deterministic non-secret outcomes. |
| Reload | Old and new configurations do not mix; bad revision leaves prior revision active or follows explicitly documented fail-safe behavior; rollback works. |
| Secrets/observability | Snapshot tests and log scans show no authorization/cookie/token/body leakage; OCSF maintains policy provenance and decision attribution. |
| Operations | Cold start, reload, PDP/JWKS outages, cache expiry, concurrency exhaustion, and emergency disable meet stated SLOs. |
| Compatibility | Existing OPA endpoint behavior and policy YAML/protobuf round trips are unchanged when CPEX is disabled. |

## Community context and questions for feedback

This proposal is intentionally scoped as an operator-owned authorization adapter,
not a broad replacement of OPA or an attempt to deliver JWT validation, token
exchange, Cedar/CEL, PII, response transformation, and taint tracking in one
change. The questions below are where community input would help most; the
detailed mapping to OpenShell issues, PRs, and RFCs lives in
[Relevant issues, PRs, and RFCs (alignment)](#relevant-issues-prs-and-rfcs-alignment)
at the end of this document.

- Should CPEX be explored as an in-process adapter, an implementation of the
  existing egress-middleware direction, or not adopted until its ecosystem and
  Rust compatibility mature?
- Is a gateway-owned, digest-pinned bundle registry the appropriate initial
  ownership model, or should a typed `SandboxPolicy` reference be preferred?
- Which trusted identity source and which single local PDP—Cedar or CEL—best
  match OpenShell deployments and operational constraints?
- What pilot users, traffic classes, and success/failure SLOs would make a
  shadow-mode evaluation useful?

### Requested feedback

Please comment on the proposed Phase 0 exit criteria, the baseline-gate/CPEX
composition rule, bundle ownership and distribution, trusted identity sources,
PDP selection, and the shadow-to-enforce rollout. Feedback that identifies a
simpler path through the existing identity, credential, or egress-middleware
work is especially welcome. This proposal does not claim token exchange, PII,
response redaction, or taint support until those capabilities have separately
approved designs.

## Explicit initial non-goals

- Replacing `regorus` / OPA for L4 routing, IP/SSRF checks, process identity,
  or existing baseline L7 controls.
- Reading identity from an unverified outbound `Authorization` header.
- Inline arbitrary APL, PDP, JWKS, plugin, or session-store configuration in
  agent-editable sandbox policy.
- Remote PDP/JWKS access through the sandbox data path without an approved
  control-plane egress design.
- OAuth exchange, credential replacement, PII scanning, response mutation,
  body redaction, taint/session persistence, Valkey, GraphQL, JSON-RPC, MCP,
  WebSocket, and SQL support in the pilot.
- A public schema/API change before Phase 1 approval.

## Proposed next step

Solicit feedback on this proposal, then open a small **Phase 0 spike** if there
is maintainer agreement on the problem statement and ownership model. Its
deliverables are a compatibility report, host prototype, threat model,
benchmark, and RFC decision—not production CPEX code. If the spike cannot
establish compatibility with OpenShell's Rust baseline or meet the trusted
identity and control-plane requirements, it should document that outcome and
recommend whether the existing middleware or provider-roadmap work is a better
path.

## Relevant issues, PRs, and RFCs (alignment)

This section maps the CPEX integration to OpenShell's own issues, PRs, and RFCs.

### Executive summary

There is substantial alignment between OpenShell and the proposed CPEX
integration, but no OpenShell issue tracks CPEX, AuthZen, COAZ, Cedar, or a
generic external PDP directly. The proposal should anchor on the shipped
**supervisor middleware** architecture (RFC 0009 / [#1738], egress middleware /
[#2027]), interoperate with the existing **MCP/JSON-RPC L7 policy** ([#1865] /
[#1938]), and explicitly introduce the missing integration work as new trackers.
Two production gates dominate: extension-connection authentication ([#2430]) and
trusted subject/session context propagation (no tracker yet).

### Relevant alignment and precedent

- **Positive alignment.** OpenShell issues that express demand CPEX serves:
  [#2143] (inbound caller authentication/authorization), [#1736] (dynamic
  identity sources for OAuth token exchange), [#1756] (scope attenuation),
  [#1987] (user-subject dynamic token grants), [#1884] (session and conversation
  lifecycle), [#1043] (Privacy Guard), and [#2109] (managed maximum policies).
- **Strong design precedent.** [#1733] (sandbox egress middleware), [#2282]
  (operator-controlled middleware bindings), and [#2217] (manifest digest
  pinning) support an extension model only when operator authority and manifest
  drift are constrained.
- **Design concerns this proposal addresses.** [#1942] (stale-policy proxy
  race) and active L7 security bugs such as [#2251] (unevaluated pipelined
  bytes) show that reload atomicity, policy provenance, and basic proxy
  correctness will be scrutinized before another authorization runtime is
  trusted. [#1842] (signed frozen policy bundles) has since shipped (closed as
  completed); it strengthens the CPEX bundle-integrity and digest-pinning story
  rather than remaining an open concern.

### Terminology note

OpenShell's tracker does not use "Cedar," "AuthZen," "PDP," "OPA," or "regorus";
those searches returned no on-topic hits. The community talks in terms of a
**Policy Provider** ([#1713]), a **Policy Prover** ([#1058]/[#1059] roadmap), and
a **Policy Advisor** ([#1038]). The regorus/OPA references in this proposal come
from reading the code, not the issue discourse. Frame CPEX against OpenShell's
own policy primitives to land with maintainers.

### Themes

1. Egress proxy / L7 proxy / supervisor middleware / content guard / egress adapters
2. External authorization / policy engine / Policy Provider / PDP
3. Identity: JWT, SPIFFE, OAuth, token exchange (RFC 8693), scope attenuation, delegation
4. Session / conversation lifecycle / stateful policy / information-flow / taint
5. Response inspection / redaction / PII / privacy guard / body transformation
6. MCP / JSON-RPC egress awareness / protocol-aware policy
7. Managed permission modes / policy bundles / signed policy / digest pinning / reload atomicity
8. Gateway interceptors / control-plane extension / operator-controlled middleware bindings
9. Multi-tenant / workspace resource model / RBAC

### Core foundations already merged

| # | Type | Title | Themes | Why it matters for CPEX |
|---|------|-------|--------|-------------------------|
| [#1738] | PR (merged) | RFC 0009: Supervisor Middleware | 1,8 | Defines the primary CPEX integration model: trusted operator extensions with typed supervisor hooks. Anchor the proposal here, not on the still-open RFC 0005. |
| [#2027] | PR (merged) | feat(supervisor-middleware): add network egress middleware | 1 | External gRPC middleware for bounded HTTP requests before credential injection. The best current CPEX pilot surface. |
| [#1865] | PR (merged) | feat(l7): add JSON-RPC and MCP policy enforcement | 6 | OpenShell already parses MCP methods and `tools/call` tool names. CPEX extends this to arbitrary argument, identity, session, and external-PDP decisions; it does not introduce the first MCP layer. |
| [#1938] | PR (merged) | feat(policy): add MCP-aware JSON-RPC L7 governance | 6 | Deeper MCP method-level governance CPEX extends. |
| [#1784] | PR (merged) | feat(providers): support SPIFFE-backed token grants | 3 | Endpoint-scoped dynamic `client_credentials` grants using supervisor SPIFFE identity. CPEX identity substrate. |
| [#1927] | PR (merged) | RFC 0010: Gateway Interceptors | 8 | Control-plane extension model. Candidate for validating CPEX bundle references, ownership, provenance. Not the data-plane PDP hook. |
| [#2005] | PR (merged) | feat(interceptors): initial gateway interceptor implementation + reference example | 8 | Working interceptor impl CPEX could register as (control-plane only). |
| [#2243] | PR (merged) | feat(workspace): add workspace resource model with scoping, membership | 9 | Multi-tenant scoping/membership landed, but the merged version explicitly **deferred authorization enforcement** (see [#2445]). |
| [#720] | PR (merged) | OCSF sandbox events | (audit) | Existing structured audit channel into which CPEX decisions map. |

### Top items (ranked, strongest matches)

| # | Type | State | Title | Themes | Why it matters | Cited in proposal? |
|---|------|-------|-------|--------|----------------|--------------------|
| [#2430] | Issue | OPEN | Authenticate OpenShell extension service connections | 1,8 | **Largest production blocker.** TLS custom roots, extension JWTs, mTLS, rotation, mutual auth for middleware and interceptors. Note: explicitly excludes end-user delegation/identity, so it authenticates "this supervisor called CPEX," not "Alice authorized this." | No (NEW) |
| [#1713] | Issue | OPEN | feat: pluggable policy sourcing via a Policy Provider subsystem | 2,7 | External-policy-source extension point. Reading is not yet settled: either a binding point for CPEX-as-policy-source, or only signed-bundle distribution. | No (NEW) |
| [#2155] | PR | OPEN | RFC 0005: Sandbox proxy egress adapter model | 1 | Future native authorization seam. CPEX does not need to wait for it to build an external middleware pilot. | Yes |
| [#1733] | Issue | OPEN | Supervisor middleware (umbrella) | 1,8 | Umbrella for the middleware layer where a CPEX reference monitor lives. | Yes |
| [#2169] | PR | OPEN | feat(examples): add supervisor middleware content guard | 1,5 | Best implementation scaffold for a CPEX prototype: registration, attachment, inspection, allow/deny/redact, limits, timeouts. Also a template/competitor for CPEX response inspection. | Yes |
| [#2217] | Issue | OPEN | detect/resolve middleware manifest drift with digest pinning + gateway refresh | 7 | CPEX version/config integrity; prevents silent fail-open after manifest drift. | Yes |
| [#2282] | Issue | OPEN | operator-controlled binding policies to supervisor middleware | 8 | `dynamic`/`allowlist`/`exact` authorization over middleware operation/phase. Essential once CPEX exceeds `HTTP_REQUEST/PRE_CREDENTIALS`. | Yes |
| [#2283] | Issue | OPEN | provider-profile and typed middleware attachment selectors | 8 | Select CPEX by provider identity or typed traffic class instead of duplicating host lists. Better long-term attachment model. | No (NEW) |
| [#2109] | Issue | OPEN | Enterprise permission modes with managed maximum policies | 7 | Composition rule: CPEX may narrow OpenShell authority, never widen the managed maximum. | Yes |
| [#2168] | PR | OPEN | feat(policy): add managed maximum permission modes | 7 | Implementation of [#2109]. Note it proposes removing the legacy `openshell policy prove` surface; do not depend on the OPP CLI roadmap. | Yes |
| [#1884] | Issue | OPEN | first-class session and conversation lifecycle support | 4 | Session ownership, TTL, policy/provider context, audit correlation. Does not itself implement information-flow labels. | Yes |
| [#1970] | PR | OPEN | SPIFFE-backed token exchange (addresses [#1987]) | 3 | Active RFC 8693 design preserving user subject + sandbox-agent identity through a two-stage exchange. Overlaps materially with CPEX delegation. | No (NEW) |
| [#2378] | Issue | OPEN | isolate and declassify authenticated MCP discovery responses | 5,6 | Closest response-side / information-flow work. Says generic response scanning alone is insufficient. | No (NEW) |
| [#2286] | Issue | OPEN | expose supervisor middleware registrations through Helm values | 8 | Required for a supported Kubernetes deployment of an external CPEX service. | No (NEW) |
| [#2373] | PR | OPEN | consolidate the proxy egress pipeline | 1 | Active implementation of part of RFC 0005; may create a cleaner future native seam. Pilot need not wait for it. | No (NEW) |

### Direct prerequisites and production gates

The items most important to cite as gates, in rough priority:

1. **[#2430] (authenticate extension connections)** is the largest production
   blocker. It authenticates the workload/service, not the end user. CPEX
   deployment as an external service depends on it.
2. **[#2217] (manifest digest pinning + refresh)** covers CPEX version/config
   integrity and prevents fail-open after drift.
3. **[#2282] (operator-controlled binding policies)** becomes essential once CPEX
   does more than the request-only phase.
4. **[#2283] (typed attachment selectors)** is the better attachment model for
   Workday/GitHub/inference/MCP providers.
5. **[#2286] (Helm registrations)** for supported k8s deployment.
6. **[#2169] (content-guard example)** is the prototype scaffold.
7. **[#2373] (egress pipeline consolidation)** may yield a cleaner native seam
   later; not a blocker for an external pilot.

### Semantic authorization and MCP

| # | State | Proposal implication |
|---|-------|----------------------|
| [#1848] | Issue, OPEN | JSONPath predicates for REST bodies. Validates demand for field-level request authorization; CPEX offers a richer version through middleware without adding every predicate to OpenShell's native schema. |
| [#2174] | Issue, OPEN | Version-aware MCP wire profiles. Prerequisite for trustworthy COAZ-MCP mapping: CPEX must know which MCP revision/session semantics it authorizes. |
| [#2109] / [#2168] | see above | Managed maximum policies reinforce the narrow-not-widen composition rule. |
| [#1058] | Issue, OPEN | MCP tool permission modeling. OpenShell's policy-prover roadmap already recognizes semantic tools and tool-to-API mappings; CPEX is the runtime complement. |
| [#1056] | Issue, OPEN | Cross-sandbox flow verification. Overlaps CPEX information-flow goals but is static multi-sandbox reachability, not runtime session taint. |
| [#1057] | Issue, OPEN | Messaging platform permission modeling. Relevant to the email/exfiltration scenario and provider-specific permission semantics. |
| [#2144] | Issue, OPEN | Protocol-aware inbound authorization for gateway-less deployments. CPEX ext-authz analog. |

The older prover roadmap may be changing: [#2168] proposes removing the legacy
`openshell policy prove` surface. Describe runtime CPEX enforcement as
complementary to managed policy containment without depending on the current OPP
CLI roadmap.

### Identity, sessions, and delegation

| # | State | Relevance |
|---|-------|-----------|
| [#2445] | PR, DRAFT | Workspace authorization: membership/role enforcement on gateway RPCs. Does not yet propagate a trusted user principal into supervisor middleware requests. Completes the authz [#2243] deferred. |
| [#1884] | Issue, OPEN | First-class session/conversation lifecycle. Strong alignment with CPEX session taint; does not itself implement information-flow labels. |
| [#1883] | Issue, OPEN | Request/session-scoped provider credentials. Aligned with per-user short-lived credentials and cleanup. |
| [#1970] | PR, OPEN | SPIFFE-backed token exchange (addresses [#1987]). Active RFC 8693, preserves user subject and sandbox-agent identity. Overlaps CPEX delegation. |
| [#1987] | Issue, OPEN | User-subject dynamic token grants for sandbox agents. Delegation-chain input. |
| [#1755] | Issue, OPEN | General credential broker. Umbrella for gateway-controlled downstream credentials. |
| [#1756] | Issue, OPEN | Scope attenuation for broker-issued downstream tokens. Matches intent-derived least-privilege credentials. |
| [#1754] | Issue, OPEN | Entra OBO. Concrete user-principal delegation for Graph/Outlook/SharePoint. |
| [#1736] | Issue, OPEN | Dynamic token-exchange identity sources. Discusses user tokens, SPIFFE, client assertions, request-scoped middleware exchange. |
| [#2143] | Issue, OPEN | Inbound caller authentication/authorization (sandbox-to-sandbox). Identity CPEX consumes for decisions. |
| [#1667] | Issue, OPEN | Entra Agent ID user-principal tokens. |
| [#2167] | Issue, OPEN | Verify provider-authenticated call ingress. |
| [#1794] | Issue, OPEN | Pass-through Authorization headers. |
| [#2285] | PR, OPEN | Anthropic subscription OAuth. Credential-handling context. |

**Recommendation:** CPEX should authorize the operation and derive the requested
permission/audience intent, while OpenShell retains token custody, exchange,
caching, and injection. That avoids competing credential brokers and preserves
OpenShell's credential isolation boundary. Treat the stale draft [#1681] (Okta
OBO) as not-current; [#1970] is the relevant active implementation.

### Response handling, streaming, and state

- **[#2378]** (authenticated MCP discovery response isolation) is the closest
  response-side work: protocol correlation, normalization, declassification,
  bounds, policy intersection, safe audit. Says generic response scanning alone
  is insufficient.
- **[#2428]** (WebSocket message middleware) proposes `before_forward` and
  `before_return` hooks; could eventually support CPEX policy/redaction for
  bidirectional messages.
- **[#2431]** (streaming HTTP middleware) addresses large requests, HTTP/2, gRPC,
  but explicitly excludes response-body inspection in its first iteration.
- **[#2459]** / **[#2465]** (provider-aware inference-body sanitization) is
  adjacent evidence for provider-aware transformations, though inference-specific.
- **[#1694]** (L7 proxy request transformation middleware) is an older
  post-credential/in-process proposal, superseded by the shipped middleware
  ([#1738]/[#2027]); de-emphasize.

There is no generic HTTP/MCP response middleware issue capable of implementing
the proposal's identity-aware Workday response redaction. Mark that as a later
phase and a needed new tracker.

### Audit and operations

- **[#1933]** (centralized audit/event log) covers events from built-in and
  bring-your-own extensions.
- **[#1055]** (enterprise observability) covers OCSF, JSONL audit, telemetry,
  dashboards.
- **[#1758]** (OpenTelemetry trace correlation) calls for `agent_id`,
  `session_id`, `user_principal`, tool, policy decision, broker action,
  downstream request, and response correlation. Strong fit for CPEX decision
  attribution.

### Enforcement-integrity bugs (motivation)

- **[#2251]** (forward proxy forwards unevaluated pipelined request bytes) is an
  enforcement-bypass bug; CPEX must ensure no unevaluated bytes pass. Motivates
  the no-unevaluated-bytes invariant.
- **[#1942]** (startup stale-policy forward proxy race) motivates the
  reload-atomicity / fail-closed invariant.
- **[#1636]** (revalidate pending policy proposals when effective policy changes)
  is the same reload-atomicity concern on the control plane.

Expect maintainer scrutiny against these before another authorization runtime is
trusted.

### Weak / peripheral (context only)

- Interceptor history/docs: [#1919] (CLOSED), [#2397] (PR, MERGED guide).
- MCP/JSON-RPC depth: [#1793] (CLOSED), [#2082] (CLOSED batch), [#2083] (PR reject batches).
- Content-inspection precursors, superseded by merged middleware: [#1272], [#1906], [#1022] (all CLOSED).
- Policy tooling/governance: [#1059] Policy Prover, [#1038] Policy Advisor, [#1062] agent-driven policy mgmt, [#2025] max-policies-for-spawned-agents, [#1839] audit2allow.
- Tenancy beyond [#2243]/[#2445]: [#1145] / [#1722] / [#1795].
- Proxy internals CPEX rides on: [#2384] DNS-routed proxy, [#2385] shared proxy placement, [#2389] (PR) shared L7 endpoint validation.

[#720]: https://github.com/NVIDIA/OpenShell/pull/720
[#1022]: https://github.com/NVIDIA/OpenShell/issues/1022
[#1038]: https://github.com/NVIDIA/OpenShell/issues/1038
[#1043]: https://github.com/NVIDIA/OpenShell/issues/1043
[#1055]: https://github.com/NVIDIA/OpenShell/issues/1055
[#1056]: https://github.com/NVIDIA/OpenShell/issues/1056
[#1057]: https://github.com/NVIDIA/OpenShell/issues/1057
[#1058]: https://github.com/NVIDIA/OpenShell/issues/1058
[#1059]: https://github.com/NVIDIA/OpenShell/issues/1059
[#1062]: https://github.com/NVIDIA/OpenShell/issues/1062
[#1145]: https://github.com/NVIDIA/OpenShell/issues/1145
[#1272]: https://github.com/NVIDIA/OpenShell/issues/1272
[#1414]: https://github.com/NVIDIA/OpenShell/pull/1414
[#1515]: https://github.com/NVIDIA/OpenShell/pull/1515
[#1636]: https://github.com/NVIDIA/OpenShell/issues/1636
[#1667]: https://github.com/NVIDIA/OpenShell/issues/1667
[#1681]: https://github.com/NVIDIA/OpenShell/pull/1681
[#1694]: https://github.com/NVIDIA/OpenShell/issues/1694
[#1713]: https://github.com/NVIDIA/OpenShell/issues/1713
[#1722]: https://github.com/NVIDIA/OpenShell/issues/1722
[#1733]: https://github.com/NVIDIA/OpenShell/issues/1733
[#1736]: https://github.com/NVIDIA/OpenShell/issues/1736
[#1738]: https://github.com/NVIDIA/OpenShell/pull/1738
[#1754]: https://github.com/NVIDIA/OpenShell/issues/1754
[#1755]: https://github.com/NVIDIA/OpenShell/issues/1755
[#1756]: https://github.com/NVIDIA/OpenShell/issues/1756
[#1758]: https://github.com/NVIDIA/OpenShell/issues/1758
[#1781]: https://github.com/NVIDIA/OpenShell/pull/1781
[#1784]: https://github.com/NVIDIA/OpenShell/pull/1784
[#1793]: https://github.com/NVIDIA/OpenShell/issues/1793
[#1794]: https://github.com/NVIDIA/OpenShell/issues/1794
[#1795]: https://github.com/NVIDIA/OpenShell/issues/1795
[#1839]: https://github.com/NVIDIA/OpenShell/issues/1839
[#1842]: https://github.com/NVIDIA/OpenShell/issues/1842
[#1848]: https://github.com/NVIDIA/OpenShell/issues/1848
[#1865]: https://github.com/NVIDIA/OpenShell/pull/1865
[#1883]: https://github.com/NVIDIA/OpenShell/issues/1883
[#1884]: https://github.com/NVIDIA/OpenShell/issues/1884
[#1906]: https://github.com/NVIDIA/OpenShell/issues/1906
[#1919]: https://github.com/NVIDIA/OpenShell/issues/1919
[#1927]: https://github.com/NVIDIA/OpenShell/pull/1927
[#1933]: https://github.com/NVIDIA/OpenShell/issues/1933
[#1938]: https://github.com/NVIDIA/OpenShell/pull/1938
[#1942]: https://github.com/NVIDIA/OpenShell/issues/1942
[#1970]: https://github.com/NVIDIA/OpenShell/pull/1970
[#1987]: https://github.com/NVIDIA/OpenShell/issues/1987
[#2005]: https://github.com/NVIDIA/OpenShell/pull/2005
[#2025]: https://github.com/NVIDIA/OpenShell/issues/2025
[#2027]: https://github.com/NVIDIA/OpenShell/pull/2027
[#2082]: https://github.com/NVIDIA/OpenShell/issues/2082
[#2083]: https://github.com/NVIDIA/OpenShell/pull/2083
[#2109]: https://github.com/NVIDIA/OpenShell/issues/2109
[#2143]: https://github.com/NVIDIA/OpenShell/issues/2143
[#2144]: https://github.com/NVIDIA/OpenShell/issues/2144
[#2155]: https://github.com/NVIDIA/OpenShell/pull/2155
[#2167]: https://github.com/NVIDIA/OpenShell/issues/2167
[#2168]: https://github.com/NVIDIA/OpenShell/pull/2168
[#2169]: https://github.com/NVIDIA/OpenShell/pull/2169
[#2174]: https://github.com/NVIDIA/OpenShell/issues/2174
[#2184]: https://github.com/NVIDIA/OpenShell/pull/2184
[#2217]: https://github.com/NVIDIA/OpenShell/issues/2217
[#2243]: https://github.com/NVIDIA/OpenShell/pull/2243
[#2251]: https://github.com/NVIDIA/OpenShell/issues/2251
[#2282]: https://github.com/NVIDIA/OpenShell/issues/2282
[#2283]: https://github.com/NVIDIA/OpenShell/issues/2283
[#2285]: https://github.com/NVIDIA/OpenShell/pull/2285
[#2286]: https://github.com/NVIDIA/OpenShell/issues/2286
[#2373]: https://github.com/NVIDIA/OpenShell/pull/2373
[#2378]: https://github.com/NVIDIA/OpenShell/issues/2378
[#2384]: https://github.com/NVIDIA/OpenShell/issues/2384
[#2385]: https://github.com/NVIDIA/OpenShell/issues/2385
[#2389]: https://github.com/NVIDIA/OpenShell/pull/2389
[#2397]: https://github.com/NVIDIA/OpenShell/pull/2397
[#2428]: https://github.com/NVIDIA/OpenShell/issues/2428
[#2430]: https://github.com/NVIDIA/OpenShell/issues/2430
[#2431]: https://github.com/NVIDIA/OpenShell/issues/2431
[#2445]: https://github.com/NVIDIA/OpenShell/pull/2445
[#2459]: https://github.com/NVIDIA/OpenShell/issues/2459
[#2465]: https://github.com/NVIDIA/OpenShell/pull/2465
