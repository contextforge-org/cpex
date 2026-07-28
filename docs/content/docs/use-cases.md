---
title: "Use Cases"
weight: 18
---

# Use Cases

> Each use case below runs end-to-end in the [Praxis demo](https://github.com/praxis-proxy/demos/tree/main/demos/cpex): CPEX as the policy engine inside a real AI gateway, backed by a real IdP and a mock MCP backend. Every snippet is quoted from the demo's live config, and every scenario is a script you can run.

The demo realizes the [running scenario]({{< relref "/docs/overview" >}}): one agent, three callers, three kinds of backend reached over MCP. Identity decides the outcome.

| Persona | Identity | Result |
|---|---|---|
| Bob | HR, `view_ssn` | Full compensation record, SSN included |
| Eve | HR, no `view_ssn` | Same record, SSN redacted on the wire |
| Alice | Engineering | Denied HR tools; allowed internal repos, denied external |

[Praxis](https://github.com/praxis-proxy/praxis) is an AI-native proxy built around a filter chain. CPEX ships as its `policy` filter (the `cpex-policy-engine` feature), so the gateway parses MCP JSON-RPC, runs the full policy pass, and only then forwards a scoped request upstream:

![The Praxis demo topology: a chat agent calls the Praxis gateway over MCP, where the mcp, policy (CPEX), and router filters run in sequence before forwarding to the hr-mcp server; the policy filter is configured by cpex.yaml and talks to Keycloak for identity, token exchange, and CIBA, and to Valkey for session taint, while Keycloak pushes CIBA approvals to the auth-channel UI](images/use_cases_topology.png)

The wiring is two files: [`praxis.yaml`](https://github.com/praxis-proxy/demos/blob/main/demos/cpex/praxis.yaml) declares the listener and filter chain, and [`cpex.yaml`](https://github.com/praxis-proxy/demos/blob/main/demos/cpex/cpex.yaml) holds everything CPEX: identity plugins, delegators, validators, routes, and the PDP policy. The use cases below are that one config, taken apart.

## Watch it run

The recording below shows an interactive session against the gateway, driven by an LLM agent, covering an allow with token exchange, on-the-wire redaction, session taint, a CEL policy decision, and a human-in-the-loop manager approval, with the governing policy shown alongside each step.

{{< asciinema cast="https://asciinema.org/a/NsnafpaR7xzyjm7a.cast" poster="npt:0:03" >}}

## 1. Identity-aware tool access

Who may call this tool at all? The `get_compensation` route opens with an attribute gate, and the attributes come from verified JWTs, not from anything the agent claims:

```yaml
routes:
  - tool: get_compensation
    pre_invocation:
      - "require(role.hr)"
```

Bob and Eve pass (HR role in their tokens). Alice is denied with a JSON-RPC error envelope before the request ever leaves the gateway; the backend never sees it. The demo resolves two identities per request, the human (`X-User-Token`) and the client (`Authorization`), each validated by its own `identity/jwt` plugin against Keycloak.

Run it: [`scenarios/01-bob-allow.sh`](https://github.com/praxis-proxy/demos/blob/main/demos/cpex/scenarios/01-bob-allow.sh), [`scenarios/02-alice-deny.sh`](https://github.com/praxis-proxy/demos/tree/main/demos/cpex/scenarios). More: [Identity]({{< relref "/docs/apl/identity" >}}).

## 2. On-the-wire redaction

This is the [same-request-different-data]({{< relref "/docs/overview#same-request-different-data" >}}) outcome from the Overview, now running in a real gateway. Bob and Eve send the byte-for-byte same request; the field pipeline rewrites Eve's response body inside the proxy, after the tool returns and before the agent sees it:

```yaml
    result:
      ssn: "str | redact(!perm.view_ssn)"
```

The tool does not implement this, cannot get it wrong, and cannot be talked out of it. The novelty here over the Overview is where it happens: in the proxy's response path, so an unmodified MCP backend gets per-caller redaction for free.

Run it: [`scenarios/03-eve-redact.sh`](https://github.com/praxis-proxy/demos/tree/main/demos/cpex/scenarios). More: field pipelines in [Effects]({{< relref "/docs/apl/effects" >}}).

## 3. Credential custody and token exchange

The backend should never hold or even see the user's IdP credential. Before forwarding, the route exchanges Bob's token for a fresh one scoped to exactly this backend (RFC 8693, via Keycloak):

```yaml
      - "delegate(workday-oauth, target: workday-api, audience: workday-api, permissions: [read_compensation])"
```

What reaches `workday-api` is a short-lived token with `audience: workday-api` and only `read_compensation`. A leak at the backend leaks that, not Bob's session. The `search_repos` route goes one step further and verifies the grant before trusting it:

```yaml
      - "!(delegation.granted.permissions contains 'repo:read:internal'): deny"
```

Run it: [`scenarios/01-bob-allow.sh`](https://github.com/praxis-proxy/demos/blob/main/demos/cpex/scenarios/01-bob-allow.sh) plus [`verify-token-exchange.sh`](https://github.com/praxis-proxy/demos/blob/main/demos/cpex/verify-token-exchange.sh). More: [Delegation]({{< relref "/docs/apl/delegation" >}}).

## 4. Cross-tool data-flow control

The classic exfiltration path: read something sensitive, then send it somewhere. Content filters miss it when the outbound message is clean. CPEX instead taints the session at the read and gates the send on the label:

```yaml
  # get_compensation
  - "taint(secret, session)"

  # send_email
  - "security.labels contains \"secret\": deny('external email blocked: this session accessed secret data', 'session_tainted_secret')"
```

Once a session touches compensation data, its emails are blocked, even with a spotless body. The label lives in CPEX's session store (Valkey in the demo), keyed by a hash of subject and session id, so it survives gateway restarts and cannot cross principals: Eve tainting a session id does not poison Bob's use of the same id.

Run it: [`scenarios/08-bob-taint-deny.sh`](https://github.com/praxis-proxy/demos/tree/main/demos/cpex/scenarios), [`scenarios/09-cross-principal-taint-isolation.sh`](https://github.com/praxis-proxy/demos/tree/main/demos/cpex/scenarios). More: [Session Tainting]({{< relref "/docs/apl/tainting" >}}).

## 5. PII guardrails on arguments

Session taint is state-based; this control is content-based, and they complement each other. A validator plugin scans tool arguments for sensitive patterns and denies before dispatch:

```yaml
  - name: pii-scan
    kind: validator/pii-scan
    hooks: [cmf.tool_pre_invoke]
    config:
      detect:
        - { kind: ssn }
        - { kind: credit_card }
      mode: deny
```

Bob pasting an SSN into an email body gets a deny, and the audit record of the attempt is still written: the route runs `run(audit-log)` before `run(pii-scan)`, so observation happens before the gate blocks. Flip `mode: deny` to `audit` to shadow-test the scanner against real traffic first (see [Patterns]({{< relref "/docs/patterns#shadow-rollout-with-audit-mode" >}})).

Run it: [`scenarios/07-bob-pii-deny.sh`](https://github.com/praxis-proxy/demos/tree/main/demos/cpex/scenarios). More: [Builtins]({{< relref "/docs/builtins" >}}).

## 6. Human-in-the-loop approval

Some actions should not happen on the caller's authority alone. `adjust_compensation` changes a salary, so anything over $10,000 requires the requester's manager to sign off, out-of-band, before the tool runs:

```yaml
  - tool: adjust_compensation
    pre_invocation:
      - "require(role.hr)"
      - when: "args.amount > 10000"
        do:
          - "require_approval(manager-approver, from: claim.manager, channel: \"ciba\", scope: \"args.amount <= 25000\", purpose: \"Approve a compensation adjustment\", timeout: 24h)"
      - "run(audit-log)"
```

The gateway never blocks. It suspends the call, answers the agent with JSON-RPC `-32120` and an elicitation id, and drives an OIDC CIBA backchannel request to Keycloak, which pushes the prompt to the manager's device. The `scope` binds the approval to the live amount, so a sign-off cannot be replayed against a larger change.

![The approval sequence: the agent sends adjust_compensation for $25k and the gateway answers -32120 pending with an elicitation id while firing a CIBA backchannel request to Keycloak, which pushes the prompt to the manager's device; after the manager approves, the agent's peek returns -32121 approved, and re-sending with X-Policy-Elicitation-Id applies the change with a 200](images/use_cases_hil_sequence.png)

The agent needs no approval protocol; it sees "retry later" and, later, a result. In the demo's chat client the conversation simply continues until the approval lands and the result cuts back in.

Run it: [`scenarios/10-bob-adjust-under-threshold.sh`](https://github.com/praxis-proxy/demos/tree/main/demos/cpex/scenarios), [`scenarios/11-bob-adjust-approval.sh`](https://github.com/praxis-proxy/demos/tree/main/demos/cpex/scenarios). More: [Elicitation]({{< relref "/docs/apl/elicitation" >}}).

## 7. Pluggable policy decisions

Attribute gates answer "does the caller have this role?". Relationship questions ("may this principal read this resource?") go to a PDP, and the demo ships the same decision in two dialects. Cedar, as a versioned policy set:

```yaml
      - cedar:
          action: 'Action::"read"'
          resource:
            type: Repo
            id: ${args.repo_name}
            attributes:
              visibility: ${args.visibility}
```

```cedar
@id("engineering-internal-repos")
permit(
  principal,
  action == Action::"read",
  resource is Repo
) when {
  principal.roles.contains("engineer") &&
  resource.visibility == "internal"
};
```

CEL, as an inline predicate on the route:

```yaml
      - cel:
          expr: |
            (has(role.engineer) && role.engineer && args.visibility == "internal")
            || (has(role.security) && role.security)
          on_deny:
            - "deny('engineering may read internal repos only; security may read any', 'cel.policy_denied')"
```

Same route, same outcome, different authoring model: Cedar suits versioned or signed policy sets with an entity model; CEL suits a self-contained predicate with no external policy store. Both backends compile into one binary; the config selects which runs.

Run it: [`scenarios/04-alice-internal-allow.sh`](https://github.com/praxis-proxy/demos/tree/main/demos/cpex/scenarios), [`scenarios/05-alice-external-cedar-deny.sh`](https://github.com/praxis-proxy/demos/tree/main/demos/cpex/scenarios), then again with `GATEWAY_CONFIG=praxis-cel.yaml`. More: [PDP Integration]({{< relref "/docs/apl/pdp" >}}).

## Run it yourself

The whole demo is one command from [`demos/cpex`](https://github.com/praxis-proxy/demos/tree/main/demos/cpex) (Docker plus a Rust toolchain):

```bash
./restart.sh       # build the gateway, bring up Keycloak + backend + valkey
./walkthrough.sh   # narrated tour of the core scenarios
```

Eleven scripted scenarios cover every control above, and `agent/chat.py --persona bob` drives the same gateway from an LLM chat agent, approvals included.

Prefer the library-embedded flavor? The in-repo [Tutorial]({{< relref "/docs/tutorial" >}}) builds the same scenario with CPEX as a Rust crate inside the host process, one capability per module.

## What to read next

- [Threat Model]({{< relref "/docs/threat-model" >}}): what these controls defend against, and what each placement covers.
- [Quick Start]({{< relref "/docs/quickstart" >}}): stand up your own enforcement point in ten minutes.
- [Deployment]({{< relref "/docs/deployment" >}}): gateway, sidecar, and in-framework placements.
