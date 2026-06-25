---
date: 2026-06-24
topic: cpex-docs-reposition
---

# Reposition CPEX Docs Around APL and Agent Authorization

## Summary

Rewrite the CPEX `README.md` and the entire `docs/content` tree to reposition the project from a plugin/extensibility framework to a policy and authorization framework for agentic applications. APL (Authorization Policy Language) leads; cpex-core (hooks and the execution pipeline) is the supporting mechanism that gives policies pluggable effects. The exposition rides one abstracted scenario where CPEX is the deterministic reference monitor over every operation an untrusted LLM triggers. The current Python-era docs are preserved under a `0.1.x` menu entry.

---

## Problem Frame

CPEX started as a Python plugin/extensibility framework (0.1.x). The `main` branch (0.2+) is a Rust workspace that has evolved into something different: a reference monitor that sits between an untrusted LLM and the capabilities it invokes, enforcing identity, authorization, delegation, information-flow, and audit through declarative policy. Real integrations now exist that prove the new shape: a Praxis gateway demo and a Kagenti AuthBridge sidecar demo, both enforcing the same APL policy at different points in the stack.

The documentation has not caught up. The `README.md` and `docs/content/_index.md` still open with "intercept, enforce, and extend application behavior through plugins" and show Python `@hook` examples. Many `docs/content/docs` pages (quickstart, hooks, configuration, testing, cli, isolated-plugins, external-plugins) still describe the Python 0.1.x runtime (`@hook` decorators, Pydantic config, venv isolation). The strongest concepts (APL, CMF, capability-gated extensions, delegation, session tainting) are buried below hook mechanics or scattered.

The cost: readers arrive, pattern-match CPEX as "yet another plugin/hook framework," and leave without understanding it is an authorization and information-flow control plane for agents. The README is the project's primary landing surface, so this misread compounds on every visit. Platform and security engineers who would adopt CPEX as an enforcement point cannot tell from the docs that it does what they need.

---

## Actors

These are the documentation's target readers, in priority order. The docs are optimized so each earlier reader is converted before the next reader's needs are served.

- A1. Platform / security engineer (primary): integrates CPEX as an enforcement point in a gateway, proxy, or agent sidecar. Needs to know where CPEX sits, how identity/PDP/IdP/delegation/taint wire in, and what becomes deterministic once it is in place.
- A2. Technical evaluator / architect (secondary): scanning to decide whether CPEX fits their agentic stack. Needs the category framing, the trust model, and "what is possible now that was impossible or bolted-on before."
- A3. Policy author (tertiary): will write and own APL policies. Needs the language, effects, sequencing, and PDP composition, with worked fragments.
- A4. Rust developer / contributor (last): builds on or extends the crates. Needs workspace layout, the SDK, and dev workflow, demoted below the positioning content.

---

## Key Flows

The docs are artifact output, but the running scenario is itself flow-shaped and is the narrative spine, so the primary flows are captured here to anchor the rewrite.

- F1. Reader journey through the README
  - **Trigger:** A1/A2 lands on the GitHub repo.
  - **Actors:** A1, A2
  - **Steps:** Category reframe (reference monitor over an untrusted LLM) → the abstracted scenario and what it requires → APL as the policy surface with fragments → how cpex-core executes effects (hooks/pipeline as support) → where CPEX deploys (gateway / sidecar / framework) → crates and dev pointers.
  - **Outcome:** Reader can state what CPEX is, why it is not just a plugin framework, and what they would do next.
  - **Covered by:** R1, R2, R3, R4, R5, R8, R12

- F2. The mediated-operation scenario (spine of both README and docs)
  - **Trigger:** An agent backed by an untrusted LLM acts across trust domains.
  - **Actors:** A1, A3
  - **Steps:** Agent triggers an operation (tool call, A2A method, inference call, prompt/resource fetch) → CPEX resolves identity → evaluates APL policy (predicates, PDP calls, delegation, taint) → applies effects (allow/deny/redact/delegate/taint) → forwards or blocks → records audit.
  - **Outcome:** Same request yields different, policy-determined outcomes per identity and session state; the LLM cannot see or forge the controlling state.
  - **Covered by:** R3, R5, R6, R7

- F3. Concept-introduction progression in the docs
  - **Trigger:** A2/A3 reads the conceptual docs in order.
  - **Actors:** A2, A3
  - **Steps:** Each concept (identity/IdP → PDP → delegation → taint/info-flow → effects → sequencing) is introduced as a requirement the scenario raises, immediately followed by the APL fragment that captures it, then the cpex-core mechanism that executes it.
  - **Outcome:** A reader understands the value of each concept without having to grasp the whole system first.
  - **Covered by:** R6, R7, R9

---

## Requirements

**Positioning and framing**
- R1. The README and `docs/content/_index.md` must open by framing CPEX as a policy and authorization framework for agentic applications, specifically a deterministic reference monitor between an untrusted LLM and the capabilities it invokes. The opening must not lead with "plugin" or "extensibility" as the primary category.
- R2. APL (Authorization Policy Language) must be presented as the front-door concept and primary value surface. cpex-core (hooks, plugin manager, execution pipeline) must be presented as the supporting mechanism that gives policies pluggable, composable effects, not as the headline.
- R3. The exposition must be organized around one abstracted, vendor-neutral scenario (generalized from the Praxis/Kagenti HR demos) in which CPEX mediates every operation an untrusted LLM can trigger: tool calls, A2A method invocations, inference/LLM calls, and prompt/resource fetches. The scenario must not be tied to HR specifics.
- R4. Reader priority must be reflected in ordering and emphasis: platform/security engineer (A1) first, technical evaluator/architect (A2) second, policy author (A3) third, Rust contributor (A4) last.

**Core concepts (introduced gradually)**
- R5. The docs must cover, in graduated order, the core concepts: identity resolution and IdP integration; PDP integration (CEL, Cedar, OPA, and the broader set the crates support); delegation / token exchange as an explicit policy effect; session tainting and information-flow controls (including write-down / write-after-secret prevention); effects; and sequencing/phases.
- R6. Each concept must be introduced as a requirement the running scenario raises, immediately illustrated by an APL fragment, then connected to the cpex-core mechanism that executes it. No concept should require the reader to understand the whole system first.
- R7. Two signature illustrations must anchor the value story: (a) "same request, different data" where policy redacts a field on the wire based on identity/permission, and (b) a session-taint control that blocks an action after the session touched secret data, even when the action's payload is itself clean.
- R8. Performance and capability-gating of plugins must be documented as supporting concerns (correctness/security and execution properties), not as front-matter. They must be present but must not compete with APL for the lead.

**Document set and rewrite**
- R9. All pages under `docs/content` must be rewritten to the Rust + APL reality and the new framing. No page may continue to describe the Python 0.1.x runtime as the current system (no `@hook` decorators, Pydantic config, or venv-isolation as the present API in the main tree).
- R10. The current Python-era docs must be preserved under a `0.1.x` section with its own menu entry in the Hugo site, so 0.1.x users retain access. The mechanism (nested section, version switcher, or equivalent in the hugo-book theme) is a planning detail; the outcome (browsable, clearly labeled 0.1.x docs) is the requirement.
- R11. The quickstart / golden-path page must walk the running scenario end to end in Rust + APL, consistent with R3 and R6.

**Examples, figures, voice**
- R12. All APL, Rust, and YAML examples must be drawn from or verified against the crates' tests, examples, and the demo configs (Praxis `cpex.yaml`, Kagenti `cpex-policy.yaml`, `crates/apl-core` tests, `examples/`), not invented. Where source surfaces vary (e.g., `delegate(...)` call form vs `delegate:` block; `plugin(...)` vs `run(...)`), one canonical form must be selected per the crate parser and used consistently across all docs.
- R13. Figures must be specified and sketched as part of this work and rendered inline as Mermaid or ASCII diagrams (no binary image assets). The figure set must at minimum include: reference-monitor placement, the abstracted scenario, the APL evaluation pipeline/phases, the policy spectrum, the delegation/token-exchange flow, and the taint/information-flow control. Figures must render on GitHub (README) and in the Hugo book theme.
- R14. The term "APL" must be expanded consistently as "Authorization Policy Language" across the README and all docs. Prior expansions ("Attribute Policy Language") must be replaced. Inline crate-doc strings are out of scope unless trivially adjacent.
- R15. Voice must be sharp, direct, and clear, with minimal commentary and no em dashes, across the README and all rewritten pages.

---

## Acceptance Examples

- AE1. **Covers R1, R2.** Given a reader who skims only the first screen of the README, when they finish that screen, they can correctly say CPEX is an authorization/policy control plane for agents with APL as the policy language, and would not describe it primarily as a plugin or hook framework.
- AE2. **Covers R3, R7.** Given the abstracted scenario, when the docs present the "same request, different data" moment, two identities issue an identical request and the reader sees that one response has a field redacted on the wire by policy while the other does not, with the controlling decision shown as an APL fragment.
- AE3. **Covers R7.** Given the session-taint illustration, when an agent attempts an action after the session has touched secret data, the action is denied by policy even though the action's own payload contains no secret, and the docs show the taint effect and the gating predicate.
- AE4. **Covers R9, R10.** Given the published Hugo site, when a reader opens the main docs they find only Rust + APL content, and when they open the `0.1.x` menu entry they find the preserved Python docs clearly labeled as the 0.1.x version.
- AE5. **Covers R12.** Given any APL or config example in the docs, when a maintainer checks it against the crate parser/tests or a demo config, the example parses and matches a real, supported form.

---

## Success Criteria

- A platform/security engineer reading only the README can explain where CPEX sits, what it enforces, and why it is more than a plugin framework, and can identify their next step.
- A technical evaluator can place CPEX in the right category (agent authorization / information-flow control plane) and name at least two things it makes deterministic that were previously bolted-on.
- A policy author can read a concept page and reproduce the APL fragment for that concept against the running scenario.
- ce-plan can take this document and sequence the rewrite without having to decide positioning, audience priority, narrative spine, scope of the page set, the 0.1.x preservation requirement, figure handling, or voice.
- The published docs contain no page presenting the Python 0.1.x runtime as the current system outside the `0.1.x` section, and all examples trace to real crate/demo sources.

---

## Scope Boundaries

### Deferred for later

- A standalone APL language specification beyond what the user-facing docs require (e.g., a full grammar reference in `docs/specs`).
- Binary/diagram asset production (PNG/SVG) and any redesign of the existing images referenced by the current `vision.md`; this work uses inline Mermaid/ASCII and may retire the old PNGs.
- Per-crate `rustdoc` / `lib.rs` doc-comment rewrites, except where R14 term consistency is trivially adjacent.
- Migration guides for moving a 0.1.x Python deployment to 0.2+ Rust, beyond preserving the 0.1.x docs.

### Outside this product's identity

- Any change to CPEX/APL code, crate APIs, the parser, or the demos. This work is docs-only; the demos and crates are source material, not deliverables.
- Marketing or landing-site work outside the repo `README.md` and the Hugo `docs/` site.
- Repositioning CPEX as a general-purpose plugin/extensibility framework. The plugin mechanism remains documented strictly as the supporting execution layer for policy effects.

---

## Key Decisions

- Layered audience rather than a single reader: optimize A1 → A2 → A3 → A4. Rationale: the user wants the security/integration engineer converted first, the evaluator reframed second, the policy author equipped third, and contributors served last.
- Abstracted scenario as the spine, blended with concept-first rigor: lead with a vendor-neutral mediated-operation scenario, but introduce each concept rigorously where the scenario raises it. Rationale: maximizes concreteness and gradual onboarding without tying the category to one vertical (HR).
- Full rewrite of `docs/content` plus a preserved `0.1.x` section: rather than triaging stale pages. Rationale: the Python-era pages actively mislead about the current system; a clean Rust + APL tree with versioned legacy docs is coherent and honest.
- APL documented as a real, current surface: the apl-core/apl-cmf/apl-cpex crates and both demos confirm it works today, so docs lead with it rather than treating it as roadmap. Python bindings and WASM remain labeled future.
- Inline Mermaid/ASCII figures over binary assets: keeps diagrams version-controlled and editable in-repo, and renders in both GitHub and Hugo.
- Standardize on "Authorization Policy Language": replacing the older "Attribute Policy Language" expansion to match the user's current naming.

---

## Dependencies / Assumptions

- The hugo-book theme can host a clearly labeled `0.1.x` section with its own menu entry (nested section or version switcher). Assumed available; exact approach is a planning detail.
- The crates' tests, examples, and the two demo configs are the canonical source for APL/config syntax. Assumed accurate and current as of `main`.
- Mermaid renders in the project's GitHub README context and in the deployed Hugo site. Assumed; to be verified during planning if uncertain.
- The two demos (`praxis-demos/demos/cpex`, `kagenti-extensions/authbridge/demos/hr-cpex`) remain accessible as reference material for the abstracted scenario.

---

## Outstanding Questions

### Resolve Before Planning

- (none) The positioning, audience priority, narrative spine, page-set scope, 0.1.x preservation, figure handling, and voice are all decided above.

### Deferred to Planning

- [Affects R10][Technical] Exact hugo-book mechanism for the `0.1.x` menu entry (nested content section vs multi-version config vs separate menu), and how the legacy tree is copied/moved without breaking existing links.
- [Affects R12][Technical] Which canonical APL surface form to adopt where the crate sources diverge (call-form vs block-form effects, `plugin(...)` vs `run(...)`); resolve by reading the `crates/apl-core` parser.
- [Affects R9][Technical] The final page list and table-of-contents ordering for the rewritten docs tree, including which current pages merge, split, or are dropped.
- [Affects R13][Needs research] Whether any figure is better served by reusing/adapting an existing diagram's content as Mermaid versus authoring fresh.
- [Affects R5][Technical] The exact set of PDP dialects and IdP/delegation mechanisms to document as supported (verify against `crates/apl-core` `PdpDialect` and the delegator builtins).
