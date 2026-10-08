---
title: "Threat Model"
weight: 15
---

# Threat Model

> This threat model defines the adversary CPEX assumes, the boundary it enforces, and what each deployment placement does and does not cover. See [Vision]({{< relref "/docs/vision" >}}) for the underlying model.

## The adversary

CPEX assumes the LLM driving an agent is compromised, or close enough that the difference does not matter. Three things make it untrusted:

- **Its inputs are attacker-reachable.** Prompt injection can arrive through any content the model reads: user messages, tool results, fetched resources, other agents' replies.
- **Its outputs are attacker-shaped.** An injected instruction becomes a tool call, an argument value, an email body. The model is a confused deputy: it acts with the agent's authority on whoever's behalf the text says.
- **It cannot keep secrets or enforce rules.** Anything in the context window can be exfiltrated through an allowed output channel, and any instruction in the prompt can be overridden by a later one.

The assets at stake sit behind the agent: backend data (records, code, mail), the credentials the agent holds, tools with side effects (payments, writes, messages), and the integrity of the audit trail itself.

The consequence is the reference-monitor rule: authorization, delegation, and information-flow decisions cannot live in the model, in the prompt, or in agent code the model steers. They live at a boundary the model's output must cross, evaluated against state the model cannot see or forge.

## The trust boundary

CPEX draws that boundary. Every operation the agent attempts crosses it; nothing the model emits reaches a capability directly.

![The CPEX trust boundary: an untrusted caller and agent on one side, mediated capabilities on the other, with the CPEX reference monitor between them evaluating APL policy against identity, delegation, taint, and audit state the model cannot forge, fed by an IdP and a PDP](images/threat_model.png)

Everything to the left of the monitor is assumed hostile, and nothing the policy reads comes from there: verified tokens come from the IdP (identity provider), decisions from the PDP, taint labels from the session store, and the delegation and audit state is CPEX's own. The model can ask for anything; it can influence none of the state the answer depends on.

## Threats and controls

| Threat | Without mediation | CPEX control |
|---|---|---|
| Prompt-injection-driven tool misuse | injected text becomes an executed tool call | `require(...)` attribute gates and `args` validation run before dispatch; a PDP decides relationship questions ([Effects]({{< relref "/docs/apl/effects" >}}), [PDP]({{< relref "/docs/apl/pdp" >}})) |
| Confused deputy / privilege escalation | the agent acts with one blanket identity for all callers | identity resolved per caller from verified tokens; entitlements differ per subject, not per prompt ([Identity]({{< relref "/docs/apl/identity" >}})) |
| Cross-request data exfiltration (write-down) | data read in one call leaves through a later, innocent-looking call | `taint(...)` labels the session in CPEX-owned state; later operations deny on the label even with clean payloads ([Session Tainting]({{< relref "/docs/apl/tainting" >}})) |
| Credential exposure and over-broad tokens | backends receive the caller's raw IdP credential | `delegate(...)` exchanges it for a fresh audience-scoped token (RFC 8693); the granted scope is verified before use ([Delegation]({{< relref "/docs/apl/delegation" >}})) |
| PII disclosure | sensitive values flow into arguments and out in results | field-level `redact`/`mask` pipelines on `result`, deny rules on `args`, and a host detector plugin where pattern matching is not enough ([Effects]({{< relref "/docs/apl/effects" >}}), [Builtins]({{< relref "/docs/builtins#not-builtins-the-pii-scanner-and-audit-logger" >}})) |
| Unauthorized high-impact actions | the model triggers irreversible operations on its own authority | `require_approval(...)` suspends the call for out-of-band human sign-off ([Elicitation]({{< relref "/docs/apl/elicitation" >}})) |
| Approval replay | one sign-off is reused for a larger or different action | approvals are scope-bound to the live arguments and validated on resume ([Elicitation]({{< relref "/docs/apl/elicitation" >}})) |
| Unaccountable actions | no trustworthy record of what the agent did | a host audit plugin or audit sink records each decision, including denied attempts ([Auditing]({{< relref "/docs/auditing" >}})) |

No single row is load-bearing alone. The [defense-in-depth pattern]({{< relref "/docs/patterns#defense-in-depth" >}}) composes them in one route.

## Where the boundary sits, and what each placement covers

CPEX is direction-agnostic: the same APL policy enforces at any placement (see [Deployment]({{< relref "/docs/deployment" >}})). The placement decides which traffic is mediated, which is the threat-model question: an enforcement point only stops what crosses it.

### Proxy / gateway (inbound)

CPEX fronts a tool server. Every request to that backend crosses the boundary, whichever agent or client sent it.

![CPEX as a gateway: agents and direct clients all pass through the CPEX gateway before reaching the tool server](images/threat_model_gateway.png)

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

![CPEX as an egress sidecar: all egress from the agent workload passes through the CPEX sidecar on its way to internal tools, third-party APIs, and other agents](images/threat_model_sidecar.png)

**Covers**

- The complete outbound surface of the workload, including third-party APIs you do not control and could never gateway.
- Workload identity: the `caller_workload.*` and `this_workload.*` attributes carry attested identity (SPIFFE / mTLS), so policy can bind decisions to which workload is calling, not just which user.
- Exfiltration control for a specific agent: taint follows the session across every backend the agent reaches.

**Does not cover**

- Other paths to the same backends. The sidecar protects the world from this agent, not the backend from other callers.
- Traffic that escapes the sidecar's capture. Egress must be forced through it at the network level, or the guarantee is advisory.
- Inference traffic, unless you deliberately route it through the policy path (see [Deployment]({{< relref "/docs/deployment#inference-traffic" >}})).

### Agent / agentic framework (in-process)

CPEX runs inside the agent runtime and mediates operations as the framework issues them.

![CPEX in-process: inside the agent runtime the LLM drives the framework, whose operations pass through in-process CPEX before reaching tools and backends](images/threat_model_inframework.png)

**Covers**

- The richest policy context: `agent.*` (session, conversation, turn, lineage) and `framework.*` (node and graph ids) attributes let policy reason about where in the agent's execution an operation originates.
- Enforcement before any network hop, including on operations that never leave the process.
- Human-in-the-loop and taint decisions at the reasoning step, closest to the intent.

**Does not cover**

- Process-level compromise. CPEX shares the agent's process; code execution in the runtime can bypass an in-process monitor. This placement hardens the agent's decisions, not its host.
- Traffic from anything other than this runtime.

### Compose them

The placements are not alternatives. The strongest posture pairs an in-framework monitor (rich context, soft and enforcement-tier policy) with a gateway or sidecar at an infrastructure boundary the agent process cannot rewrite (hard-tier policy: identity, information flow, audit). That is the policy spectrum from [Vision]({{< relref "/docs/vision#the-policy-spectrum" >}}): the same APL object at every point, so layering placements costs no policy duplication.

## Builtins that reach outside the process

Since 0.3.0 the Python and Go builds carry the same builtins as the Rust facade, including four that hold credentials or call out. Each widens what the host process is trusted with.

### Vault secret provider

The `vault` provider reads `secrets:` values from Vault KV v2 with Kubernetes or AppRole auth. The engine holds a Vault token and the resolved values in memory for the life of the process.

- The address must be `https://` unless the document sets `insecure_http: true`. Keep it off outside local development.
- An AppRole `secret_id` comes from an environment variable or a file. A `literal` is refused unless the document also sets `allow_insecure_literal: true`.
- Kubernetes login rereads the projected service-account token on every login, so a rotated token is picked up.
- Refresh reports and their log lines name the secret, the provider and a failure class, never the value. Treat the process's memory and core dumps as holding every declared secret.
- Anyone who can edit the policy document chooses which Vault paths the process reads, within what the Vault role allows. Scope the role to the paths the policy needs.

### Secret refresh is the host's responsibility

The engine reads secrets once, at `initialize()`, and never re-reads on its own. A binding host that rotates credentials must call refresh (`refresh_secrets`, `RefreshSecrets`, `cpex_refresh_secrets`) on an interval and alarm when a provider's last success grows old. A failed re-read keeps the last good value, so a Vault outage degrades silently to a stale credential. The refresh interval is the upper bound on how long a revoked credential stays in use. A host that never calls refresh never rotates.

### CIBA approval channel

`elicitation/ciba` trusts the approver identity in the token the OP returns, because it arrives over a client-authenticated TLS poll; it does not verify that token's signature itself. Reach the CIBA and token endpoints over `https://` with real client credentials. See [Elicitation]({{< relref "/docs/apl/elicitation#a-note-on-genuineness-and-args-binding" >}}).

### API-key directory

`identity/api-key` resolves opaque keys against a file of SHA-256 digests or an HTTP directory.

- The file stores digests, not keys. Use high-entropy keys so a leaked file does not yield to offline guessing.
- A revoked key can still authenticate until the next successful file reload (`refresh_secs`) or until its HTTP cache entry expires (`cache.ttl_secs`). If a reload fails, old records stay in use up to `max_staleness_secs`, then lookups deny.
- An HTTP directory is an outbound call: it needs `perform_http` and goes through the host transport.
- The presented key is not kept in the raw credentials, so it is never forwarded downstream.

### OPA decision point

`opa` evaluates Rego in process (regorus); it makes no network call. Its inputs are the attribute bag plus structured `args` and `llm.request`, which come from the client. The sensitive headers `Authorization`, `Cookie` and `X-API-Key` are stripped before any PDP sees the request. PDP-generated errors name types, not values, but text a policy author writes (an OPA `reason`, an APL `deny('...')`) reaches the client verbatim: do not copy payload values into it.

## Outbound HTTP and private destinations

Every outbound builtin (JWKS fetch, token exchange, CIBA, API-key HTTP directory, Vault) uses one transport the host installs. The bundled transport refuses loopback, RFC 1918, link-local (including cloud metadata) and CGNAT addresses at the address it would dial, including hostnames that resolve only to such addresses. This blocks the common SSRF path where a policy author, or a token's issuer field, points a plugin at an internal service.

Each surface has a host-side opt-in that lifts the block (`with_allow_private_destinations()`, `allow_private_destinations=True`, `WithPrivateDestinations()`, `CPEX_APL_ALLOW_PRIVATE_DESTINATIONS`). It is engine-wide: once set, every outbound builtin may reach every private address, including `169.254.169.254`. No policy document can set it. The tutorial and demos set it to reach a local IdP; production hosts should not. To reach an in-cluster IdP or Vault, install a host transport with explicit egress rules.

A refused call fails closed: `delegation.egress_denied`, `elicitation.egress_denied`, or `auth.jwks_unavailable` for JWT, which an operator may read as an IdP outage.

## The Python plugin host

The `isolated_venv` host runs each Python plugin in its own subprocess and virtualenv, so a plugin crash or a dependency conflict stays out of the engine's process. It does not sandbox the plugin: the subprocess runs with the host's user and network access.

For a Python worker that does not claim CMF support, the host translates each `cmf.*` hook into the legacy hook and payload the worker knows. Where it cannot represent a request faithfully (an LLM hook, a message with zero or several matching parts, a binary resource, a modified payload the message cannot hold), it fails closed with `legacy_shim_unsupported` rather than allowing or skipping the plugin.

## Known limitations

### Elicitation approval is not bound to the requester

An approved elicitation id can be resumed by a different subject. The CIBA correlation store records the expected and resolved approver; resume replays a cached approval for any caller presenting the id, and validation compares the resolved approver with the one named at dispatch, not with the subject that asked. A caller who obtains another subject's approved id can use it once the approval lands.

This is present in CPEX 0.2.3 and in PPE 0.4.1, which 0.3.0 runs on. An upstream fix is pending. Until it lands:

- keep the approval `timeout` short, so an approved id is usable for as little time as possible;
- treat elicitation ids as secrets: return them only to the requesting client, and keep them out of logs and shared transcripts other callers can read;
- prefer approval flows where the approver, not the requester, holds the id needed to resume.

### Audit sinks cannot run beside routes

Under `dispatch: policy`, PPE 0.4.1 cannot attach an audit sink to a config that has routes: a sink no step names fails the load, and `run(<sink>)` denies. The "unaccountable actions" control above therefore needs a hook plugin that a `run(...)` step names, or a host that logs the `PipelineResult` of every call. A host that does neither has no decision record. See [Auditing]({{< relref "/docs/auditing" >}}).

### Host-supplied client identity is visible only through `read_client`

A host may pass `security.client` in the extensions it sends, but route rules see `client.*` only when a plugin the route references declares `read_client`. Otherwise the attributes read as absent. Rules written as `require(...)` then deny, which is safe; a rule that allows on the absence of a client attribute would not be. Resolve the client with an identity plugin on the route, and write client checks as `require(...)`.

### HTTP routes are Rust-only

`http:` routes and the `http.request` / `http.response` hooks work from a Rust host only. The Python and Go bindings cannot build the HTTP payload, so a binding host cannot enforce generic HTTP policy. Put that enforcement in a Rust host or gateway.

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
