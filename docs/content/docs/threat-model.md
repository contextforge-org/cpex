---
title: "Threat Model"
weight: 15
---

# Threat Model

> This page describes the adversary CPEX is built against, the trust boundary it draws, and what each deployment placement does and does not cover. For the underlying model, read [Vision]({{< relref "/docs/vision" >}}) first.

## The adversary

CPEX assumes the LLM driving an agent is compromised, or close enough that the difference does not matter. Three things make it untrusted:

- **Its inputs are attacker-reachable.** Prompt injection can arrive through any content the model reads: user messages, tool results, fetched resources, other agents' replies.
- **Its outputs are attacker-shaped.** An injected instruction becomes a tool call, an argument value, an email body. The model is a confused deputy: it acts with the agent's authority on whoever's behalf the text says.
- **It cannot keep secrets or enforce rules.** Anything in the context window can be exfiltrated through an allowed output channel, and any instruction in the prompt can be overridden by a later one.

The assets at stake sit behind the agent: backend data (records, code, mail), the credentials the agent holds, tools with side effects (payments, writes, messages), and the integrity of the audit trail itself.

The consequence is the reference-monitor rule: authorization, delegation, and information-flow decisions cannot live in the model, in the prompt, or in agent code the model steers. They live at a boundary the model's output must cross, evaluated against state the model cannot see or forge.

## The trust boundary

CPEX draws that boundary. Every operation the agent attempts crosses it; nothing the model emits reaches a capability directly.

![The CPEX trust boundary: an untrusted caller and agent on one side, mediated capabilities on the other, with the CPEX reference monitor between them evaluating APL policy against identity, delegation, taint, and audit state the model cannot forge, fed by an IdP and a PDP](/cpex/images/threat_model.png)

Everything to the left of the monitor is assumed hostile, and nothing the policy reads comes from there: verified tokens come from the IdP, decisions from the PDP, taint labels from the session store, and the delegation and audit state is CPEX's own. The model can ask for anything; it can influence none of the state the answer depends on.

## Threats and controls

| Threat | Without mediation | CPEX control |
|---|---|---|
| Prompt-injection-driven tool misuse | injected text becomes an executed tool call | `require(...)` attribute gates and `args` validation run before dispatch; a PDP decides relationship questions ([Effects]({{< relref "/docs/apl/effects" >}}), [PDP]({{< relref "/docs/apl/pdp" >}})) |
| Confused deputy / privilege escalation | the agent acts with one blanket identity for all callers | identity resolved per caller from verified tokens; entitlements differ per subject, not per prompt ([Identity]({{< relref "/docs/apl/identity" >}})) |
| Cross-request data exfiltration (write-down) | data read in one call leaves through a later, innocent-looking call | `taint(...)` labels the session in CPEX-owned state; later operations deny on the label even with clean payloads ([Session Tainting]({{< relref "/docs/apl/tainting" >}})) |
| Credential exposure and over-broad tokens | backends receive the caller's raw IdP credential | `delegate(...)` exchanges it for a fresh audience-scoped token (RFC 8693); the granted scope is verified before use ([Delegation]({{< relref "/docs/apl/delegation" >}})) |
| PII disclosure | sensitive values flow into arguments and out in results | PII scanning on `args`, field-level `redact`/`mask` pipelines on `result` ([Builtins]({{< relref "/docs/builtins" >}})) |
| Unauthorized high-impact actions | the model triggers irreversible operations on its own authority | `require_approval(...)` suspends the call for out-of-band human sign-off ([Elicitation]({{< relref "/docs/apl/elicitation" >}})) |
| Approval replay | one sign-off is reused for a larger or different action | approvals are scope-bound to the live arguments and validated on resume ([Elicitation]({{< relref "/docs/apl/elicitation" >}})) |
| Unaccountable actions | no trustworthy record of what the agent did | an audit plugin emits an append-only record per decision, including denied attempts ([Patterns]({{< relref "/docs/patterns" >}})) |

No single row is load-bearing alone. The [defense-in-depth pattern]({{< relref "/docs/patterns#defense-in-depth" >}}) composes them in one route.

## Where the boundary sits, and what each placement covers

CPEX is direction-agnostic: the same APL policy enforces at any placement (see [Deployment]({{< relref "/docs/deployment" >}})). The placement decides which traffic is mediated, which is the threat-model question: an enforcement point only stops what crosses it.

### Proxy / gateway (inbound)

CPEX fronts a tool server. Every request to that backend crosses the boundary, whichever agent or client sent it.

![CPEX as a gateway: agents and direct clients all pass through the CPEX gateway before reaching the tool server](/cpex/images/threat_model_gateway.png)

**Covers**

- Every caller of the protected backend, including agents you do not operate and callers that bypass the "official" agent.
- On-the-wire transformation: the backend never sees redacted values, and never sees the caller's raw IdP credential when delegation mints a scoped token.
- A single audit chokepoint for the resource.

**Does not cover**

- Anything the agent does that never touches this backend: other tools, other APIs, side channels.
- Agent-internal context. The gateway sees requests, not the conversation, so per-turn or lineage-based policy has less to read.

This is the placement in the end-to-end [Praxis demo]({{< relref "/docs/use-cases" >}}).

### Endpoint / workload sidecar (outbound)

CPEX sits beside one agent and mediates its egress. Everything that agent emits crosses the boundary, whatever it targets.

![CPEX as an egress sidecar: all egress from the agent workload passes through the CPEX sidecar on its way to internal tools, third-party APIs, and other agents](/cpex/images/threat_model_sidecar.png)

**Covers**

- The complete outbound surface of the workload, including third-party APIs you do not control and could never gateway.
- Workload identity: the `workload.*` attributes carry attested identity (SPIFFE / mTLS), so policy can bind decisions to which workload is calling, not just which user.
- Exfiltration control for a specific agent: taint follows the session across every backend the agent reaches.

**Does not cover**

- Other paths to the same backends. The sidecar protects the world from this agent, not the backend from other callers.
- Traffic that escapes the sidecar's capture. Egress must be forced through it at the network level, or the guarantee is advisory.
- Inference traffic, unless you deliberately route it through the policy path (see [Deployment]({{< relref "/docs/deployment#inference-traffic" >}})).

### Agent / agentic framework (in-process)

CPEX runs inside the agent runtime and mediates operations as the framework issues them.

![CPEX in-process: inside the agent runtime the LLM drives the framework, whose operations pass through in-process CPEX before reaching tools and backends](/cpex/images/threat_model_inframework.png)

**Covers**

- The richest policy context: `agent.*` (session, conversation, turn, lineage) and `framework.*` (node and graph ids) attributes let policy reason about where in the agent's execution an operation originates.
- Enforcement before any network hop, including on operations that never leave the process.
- Human-in-the-loop and taint decisions at the reasoning step, closest to the intent.

**Does not cover**

- Process-level compromise. CPEX shares the agent's process; code execution in the runtime can bypass an in-process monitor. This placement hardens the agent's decisions, not its host.
- Traffic from anything other than this runtime.

### Compose them

The placements are not alternatives. The strongest posture pairs an in-framework monitor (rich context, soft and enforcement-tier policy) with a gateway or sidecar at an infrastructure boundary the agent process cannot rewrite (hard-tier policy: identity, information flow, audit). That is the policy spectrum from [Vision]({{< relref "/docs/vision#the-policy-spectrum" >}}): the same APL object at every point, so layering placements costs no policy duplication.

## Out of scope

CPEX is a reference monitor, not a model alignment technique. Explicitly outside this threat model:

- **Model-internal behavior.** CPEX constrains what the model's decisions can do, not what the model decides. A jailbroken model behind CPEX still only reaches what policy allows.
- **Covert channels inside allowed traffic.** If policy permits an output channel, a determined model can encode data into it. Taint narrows this (deny the channel once secrets are touched); it does not eliminate encoding within permitted flows.
- **Compromise of the CPEX host.** The monitor's guarantees hold only as long as the process and state stores it depends on are intact. Run hard-tier enforcement on infrastructure with a smaller attack surface than the agent it guards.
- **Backends themselves.** CPEX decides what reaches a tool and what comes back; it does not vouch for what the tool does internally.

Believe you have found a policy-enforcement bypass? That is our critical severity class. Report it privately via the process in [SECURITY.md](https://github.com/contextforge-org/cpex/blob/main/SECURITY.md).

## What to read next

- [Use Cases]({{< relref "/docs/use-cases" >}}): the controls above running end-to-end in a gateway deployment.
- [Deployment]({{< relref "/docs/deployment" >}}): choosing and wiring a placement.
- [Patterns]({{< relref "/docs/patterns" >}}): layering the controls in production policy.
