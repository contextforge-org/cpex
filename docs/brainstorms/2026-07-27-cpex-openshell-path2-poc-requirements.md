---
date: 2026-07-27
topic: cpex-openshell-path2-poc
---

# CPEX in OpenShell (Path 2): Proof-of-Feasibility PoC

## Summary

Embed CPEX in-process inside an OpenShell fork as a real, engine-neutral authorizer alongside OPA (path 2), and prove it by running the full CPEX differentiator story end to end: a deterministic scripted agent in a real OpenShell sandbox makes genuine REST and MCP egress calls through the supervisor proxy, and CPEX enforces identity-gated allow/deny, identity-aware redaction, per-operation token exchange, cross-call exfil blocking via session taint, plus Cedar/CEL and CIBA. PoC simplifications are allowed wherever they do not fake the enforcement seam.

---

## Problem Frame

OpenShell's egress policy evaluates each request statelessly against transport coordinates (host, port, method, path). It cannot express the multi-step, identity-aware access patterns enterprises need: it cannot block an agent that reads sensitive data from one allowed host and then exfiltrates it to another allowed host, cannot mask response fields based on who is asking, and cannot mint a down-scoped credential per operation. The design proposal argues CPEX closes these gaps as an embeddable reference monitor, and lays out three integration paths.

The proposal is currently a solicitation for feedback. It asserts the value but has not been shown working inside OpenShell. A skeptical reader can still ask "is that how it would really work, or is the value slideware?" The standalone Praxis demo shows CPEX doing all of this, but inside a different proxy (Praxis), not OpenShell. Nothing yet demonstrates the in-process embed against OpenShell's own egress path, its baseline gates, and its policy lifecycle. That gap is what keeps the integration a proposal rather than a decision.

---

## Actors

- A1. Bob (HR role): authorized caller. Passes the identity gate, receives delegated down-scoped access, and is the actor whose session gets tainted and whose sensitive operation triggers CIBA.
- A2. Alice (no HR role): unauthorized caller. Denied at the identity or PDP gate before the request leaves the proxy.
- A3. Eve (partial permissions): authorized to call the tool but not to view sensitive fields. Receives an identity-redacted response.
- A4. Scripted agent: a deterministic program running inside the OpenShell sandbox that performs the multi-step flow and makes the egress calls.
- A5. OpenShell supervisor / egress proxy: the policy enforcement point. Runs L4 and baseline L7 gates, invokes the authorizer seam, and enforces the returned decision.
- A6. CPEX runtime: the reference monitor embedded in-process behind the authorizer seam. Runs the APL pipeline and returns the decision (and, post-invocation, redaction).
- A7. Operator: owns the CPEX bundle and config loaded at supervisor startup. No runtime control-plane exists in this PoC.
- A8. Keycloak: the trusted identity provider for JWT validation, token exchange, and CIBA approvals.

---

## Key Flows

- F1. Cross-call exfil block (marquee)
  - **Trigger:** Bob's agent reads compensation data, then attempts to email it to an external address.
  - **Actors:** A4, A5, A6, A1
  - **Steps:** Agent calls the compensation tool over the proxy. L4 and baseline gates admit it; CPEX authorizes it and marks the session tainted on the sensitive read. Agent then attempts an email send to an allowed destination. L4 and baseline gates admit it; CPEX sees the taint label and denies.
  - **Outcome:** The exfil send is blocked and audited, even though both destinations are individually allowlisted. This is impossible in OpenShell today.
  - **Covered by:** R2, R13, R16

- F2. Identity-gated access and redaction
  - **Trigger:** Bob, Alice, and Eve each invoke the same compensation tool.
  - **Actors:** A1, A2, A3, A5, A6, A8
  - **Steps:** Each caller's request carries a distinct trusted identity. CPEX authorizes per identity: Bob allowed with full fields, Alice denied, Eve allowed but with sensitive fields redacted in the response.
  - **Outcome:** Three different outcomes for the same tool and host, decided by identity.
  - **Covered by:** R10, R11, R12

- F3. Delegation / token exchange
  - **Trigger:** Bob's agent makes an allowed call that needs a downstream credential.
  - **Actors:** A1, A5, A6, A8
  - **Steps:** Instead of injecting a broad credential, CPEX drives an inline exchange that mints a short-lived, audience-bound, down-scoped token for the specific operation.
  - **Outcome:** The upstream receives least-privilege credentials scoped to intent, not a broad admin token.
  - **Covered by:** R13

- F4. CIBA elicitation
  - **Trigger:** Bob's agent invokes a sensitive operation that policy gates behind human approval.
  - **Actors:** A1, A5, A6, A8
  - **Steps:** CPEX suspends the operation pending an out-of-band approval. The approval lands through a channel separate from the sandbox egress path. The operation resumes against the original concrete request.
  - **Outcome:** The agent sees a retry-then-result experience; the operation proceeds only after a verified human approves.
  - **Covered by:** R16

---

## Requirements

**Embedding and enforcement seam**
- R1. Introduce an engine-neutral request-authorization seam in the OpenShell supervisor egress path that both OPA and CPEX implement. CPEX runs as a peer to OPA, selected per endpoint.
- R2. CPEX is consulted only after L4 and baseline L7 gates admit a request. A CPEX allow can only narrow the baseline, never widen it. Deny always wins.
- R3. CPEX configuration joins the same atomic effective-policy generation as OPA. A reload never evaluates a mixed OPA/CPEX generation, and any failure keeps the last-known-good generation. The CPEX runtime is compiled and loaded during effective-policy construction, never per request.
- R4. The integration is feature-gated and off by default. With CPEX disabled, existing OPA endpoint behavior and policy round-trips are byte-for-byte unchanged.
- R5. The CPEX bundle (APL config plus PDP policies) loads directly from supervisor configuration for this PoC. No gateway control-plane, operator RPCs, or digest-pinned object store.

**CPEX embedding surface (cpex-side)**
- R6. Provide a supported embedding entry point in CPEX suitable for a host authorizer: construct the runtime, load config, and evaluate an operation through the CMF hook, so OpenShell calls a real CPEX API rather than reimplementing the tutorial's `mediate()` harness loop.
- R7. The embed runs fully in-process using in-memory session state. No Valkey or external session store.

**Protocol coverage**
- R8. Enforcement covers REST egress and MCP (JSON-RPC) egress through the proxy. MCP is included specifically to demonstrate CPEX authorizing protocol semantics (tool/method identity and arguments), not just transport coordinates.

**Identity**
- R9. Per-request human identity comes from a trusted source: a Keycloak-issued JWT validated by CPEX, associated with the sandbox session. Each persona is a distinct session and token. Raw outbound bearer values are never treated as identity.

**Differentiator capabilities demonstrated end to end**
- R10. Identity-gated allow/deny: the same tool on the same host yields different decisions by caller identity or role.
- R11. Identity-aware response redaction: sensitive response fields are masked based on the caller's permissions, using the post-invocation phase that the path-2 embed enables.
- R12. Delegation / token exchange: a down-scoped, audience-bound token is minted per operation instead of injecting a broad credential.
- R13. Cross-call exfil block via session taint: a prior sensitive read taints the session, and a later exfil send to an otherwise-allowed destination is denied.
- R14. Pluggable PDP: the same relationship decision runs on Cedar and on CEL, swappable via config, and yields the same outcome.
- R15. CIBA elicitation: a policy-gated operation is suspended pending an out-of-band human approval, then resumes against the concrete request.

**Demo harness**
- R16. A deterministic scripted agent runs inside a real OpenShell sandbox and performs the multi-step flow, making genuine egress calls the supervisor proxy intercepts. The critical steps fire reproducibly on every run.
- R17. Reuse the Praxis scenario content: the Workday compensation read plus email exfil scenario, the Bob/Alice/Eve personas, the Cedar/CEL policies, and the mock backends.
- R18. The demo is runnable via a small number of commands and exercises the full scenario matrix in one pass.

**Implementation constraint**
- R19. No requirement or plan document ID references (R-, U-, FN-, or any similar scheme) appear in source code, rustdoc, code comments, or commit messages. Traceability lives only in the requirements and plan documents.

---

## Acceptance Examples

- AE1. **Covers R2, R13, R16.** Given Bob's agent has read compensation data earlier in the session, when it attempts to email that data to an allowlisted external address, then the proxy admits the request at L4 and baseline but CPEX denies it on the session taint label, and the denial is audited.
- AE2. **Covers R10, R11.** Given the same compensation tool and host, when Bob calls it he receives full fields, when Alice calls it she is denied, and when Eve calls it she receives a response with sensitive fields redacted.
- AE3. **Covers R12.** Given Bob makes an allowed call needing a downstream credential, when CPEX authorizes it, then the upstream receives a short-lived token whose audience and scope are attenuated to the operation, not a broad admin credential.
- AE4. **Covers R14.** Given the Cedar bundle is swapped for the CEL bundle via config, when the same request is replayed, then the authorization outcome is identical.
- AE5. **Covers R15.** Given a policy-gated sensitive operation, when Bob's agent invokes it, then CPEX suspends it, the operation completes only after an out-of-band approval lands, and the agent observes a retry-then-result sequence.
- AE6. **Covers R8.** Given the same policy intent, when the flow runs over REST and again over MCP, then CPEX authorizes on tool/method semantics in both cases and the outcomes match.
- AE7. **Covers R4.** Given CPEX is disabled by the feature gate, when the existing OPA endpoint suite runs, then behavior and policy round-trips are unchanged.

---

## Success Criteria

- A reviewer (OpenShell maintainer or stakeholder) can watch the full differentiator matrix run through OpenShell's real egress path and see CPEX enforce decisions OpenShell cannot express today, with the embed being architecturally faithful: a real seam, deny-wins composition, and atomic policy generation. This removes the "is that how it would really work?" objection.
- The cross-call exfil block, the marquee moment, fires reliably on every run of the demo.
- With CPEX disabled, the existing OPA path is provably unchanged (regression passes).
- ce-plan can produce an implementation plan from this document without inventing product behavior, scope, or success criteria. The seam contract, feature gate, protocol coverage, identity source, and scenario matrix are all specified here.

---

## Scope Boundaries

- Path 1 (remote gRPC middleware) and path 3 (extended-contract RFC) are not built. The path-2 fork already reaches the post-invocation phase, which is what redaction and result-derived taint need.
- No upstreaming to NVIDIA/OpenShell, and no real MSRV reconciliation. The 1.96 toolchain bump on the fork is a deliberate PoC shortcut.
- No production hardening: no Helm, HA, multi-node, or performance SLOs.
- No gateway control-plane: no operator bundle RPCs, no digest-pinned object store, no attach/detach lifecycle, no policy prover/advisor integration.
- No formal Phase-0 threat-model sign-off, security review, or shadow-to-audit-to-enforce rollout. The PoC runs in enforce mode directly.
- No multi-tenant or workspace identity resolution, and no SPIFFE delegation chains beyond what the demo identity needs.
- No protocols beyond REST and MCP (no GraphQL, no WebSocket).
- No production credential-provider or token-custody redesign. PoC token exchange hits the demo Keycloak directly.

---

## Key Decisions

- Path 2 over path 1/3: an in-process embed is the only path that shows the full differentiator set (including post-invocation redaction and elicitation) without an upstream contract change, and it is the most convincing to a skeptic because the seam is real.
- Real seam plus broad demo (not a curated subset): the point of the PoC is to defeat both the feasibility doubt and the value doubt at once. The 1.96 bump removes the blocker that would otherwise force a narrower cut.
- Deterministic scripted agent, not a live LLM: the headline is the blocked exfil, and it must fire every run. A real LLM's nondeterminism is a demo liability with no offsetting proof value here.
- Reuse Praxis content: the scenario, personas, policies, and mock backends are already proven; rebuilding them adds effort without adding proof. The novel work is the OpenShell embed underneath.
- Skip the gateway control-plane: bundle loading from config is enough to prove enforcement. The control-plane is distribution and ownership machinery, orthogonal to the "does the embed enforce correctly" question the PoC answers.
- In-memory session store: CPEX ships one, and a single-node PoC does not need Valkey's durability or cross-node guarantees.
- Keycloak as trusted identity source: the proposal is firm that identity must be verified, not read from a raw bearer. Reusing the Praxis Keycloak realm keeps the identity story honest without new infra.

---

## Dependencies / Assumptions

- The OpenShell fork's toolchain is bumped to Rust 1.96 to match CPEX (PoC shortcut, see Scope Boundaries).
- CPEX changes are made on the `feat/openshell_integration` branch in `./cpex`.
- The Praxis demo assets (Keycloak realm, Cedar/CEL policies, mock backends, scenario scripts) are available to reuse.
- Assumes CPEX's `cmf.http_request` hook plus the builtin PDPs, identity/delegation plugins, and in-memory session store are sufficient to cover the full differentiator set in-process. Verified against the CPEX tree: `MemorySessionStore` and the granular `jwt`/`oauth`/`pii`/Cedar/CEL features exist in the facade.
- Verified: OpenShell has no engine-neutral authorizer trait today; the L7 module evaluates OPA directly per protocol relay. The seam in R1 is new work for this PoC.

---

## Outstanding Questions

### Deferred to Planning

- [Affects R1, R11][Technical] Exact placement of the authorizer seam relative to the existing protocol relays, and how the post-invocation (redaction) phase is threaded through the path-2 embed without the extended contract.
- [Affects R9][Technical] How per-persona human identity (the Keycloak JWT) is carried into the sandbox session and surfaced in the request view the proxy hands to CPEX.
- [Affects R8][Technical] How OpenShell's parsed MCP method and tool name map into CPEX's canonical message form for the demo, and whether existing MCP L7 parsing is reused.
- [Affects R12][Needs research] How PoC token exchange integrates with OpenShell's credential-injection point, and whether it goes through OpenShell's credential-provider boundary or a demo-local shortcut.
- [Affects R16][Needs research] Whether the deterministic agent runs as an ordinary sandbox workload or needs a thin custom runner to guarantee the critical steps fire.
