---
title: "Elicitation"
weight: 45
---

# Human-in-the-Loop Elicitation

Some operations should not proceed on the caller's say-so alone. A large payroll change wants a manager's approval; a destructive action wants the user to confirm; a sensitive read wants a fresh second factor. Elicitation lets a policy **pause an operation to ask a human** and resume once they respond — without blocking the request path, and with the decision bound to the actual request rather than to an LLM's paraphrase of it.

## The requirement

The scenario's `approve_raise` may run only after the requester's manager approves, and the approval must cover the specific amount being requested. The manager is not the caller, may take hours to respond, and their answer must be genuine — a signed decision from the right person, not a value the agent asserts. CPEX must dispatch the ask, hold the operation open across the agent's retries, and verify the response before letting the tool run.

## Elicitation as an effect

Elicitation is an effect in the `authorization.pre_invocation` phase. A sugar verb names an elicitation handler plugin and who to ask:

```yaml
plugins:
  - name: manager-approver
    kind: elicitation/ciba
    hooks: [elicit]

routes:
  - tool: approve_raise
    authorization:
      pre_invocation:
        - "require(authenticated)"
        - when: "args.amount > 10000"
          do:
            - "require_approval(manager-approver, from: claim.manager, channel: \"ciba\", scope: \"args.amount <= 25000\", purpose: \"Approve raise\")"
```

- `from` is **who to ask** — an attribute reference resolved against the request bag (here `claim.manager`, the requester's manager, who differs from the subject). An attribute `from` that doesn't resolve fails closed rather than dispatching to a bogus identity.
- `scope` is the **args binding** — an APL boolean expression the runtime checks against the live request when the response comes back.
- `purpose` is the **audited, human-readable** description of what is being asked.

The other verbs (`confirm`, `require_step_up`, `require_attestation`, `request_info`, `require_review`) parse to the same effect with a different kind; each selects the validation contract the runtime applies to the response.

## The model: suspend and resume

An elicitation has three short, synchronous touch-points. The hours-long human gap lives in the **channel** (e.g. Keycloak CIBA), never in a blocking call:

1. **Dispatch** — first arrival: register the intent, open the channel backchannel, return a correlation id.
2. **Check** — on each agent retry: read status (`pending` / `resolved` / `expired`) without blocking.
3. **Validate** — once resolved: verify the response is *genuine*, then the runtime layers the `scope`-over-args *sufficiency* check before honoring the approval.

While pending, the phase **suspends** rather than denies. The decision stays `Allow`, but a pending marker rides alongside it, and the host maps that to JSON-RPC **`-32120`** ("not complete — retry echoing this id"). The forward rule is one clause: *forward only when the decision is `Allow` and nothing is pending.* Expiry, channel error, a genuine denial, or a failed validation all fail closed (default `on_error: deny`).

![The elicitation suspend-and-resume flow: an agent request hits require_approval, which opens a Keycloak CIBA backchannel and returns -32120 with an elicitation id; agent retries hit a non-blocking status check that keeps returning pending until the channel resolves; validate then verifies genuineness and scope over the live args, forwarding to the tool when approved and sufficient, and failing closed on denial, expiry, or invalid responses](images/apl_elicitation_flow.png)

## The CIBA channel plugin

The bundled `elicitation/ciba` plugin drives the ask through OpenID Connect CIBA (Client-Initiated Backchannel Authentication) against Keycloak or any CIBA-capable OP:

```yaml
plugins:
  - name: manager-approver
    kind: elicitation/ciba
    hooks: [elicit]
    config:
      backchannel_endpoint: "https://idp.example.com/realms/corp/protocol/openid-connect/ext/ciba/auth"
      token_endpoint:       "https://idp.example.com/realms/corp/protocol/openid-connect/token"
      client_id: "cpex-gateway"
      client_secret_source:
        kind: file
        path: /etc/cpex-secrets/client-secret
      approver_claim: preferred_username
```

`from` becomes the CIBA `login_hint`, `purpose` seeds the `binding_message`, and `timeout` maps to `requested_expiry`. Dispatch returns an `auth_req_id` that doubles as the elicitation id the agent echoes on retry.

## Elicitation attributes

Dispatch and resolution write `elicitation.*` attributes that later rules in the same phase — and the audit log — can read:

| Attribute | Meaning |
|-----------|---------|
| `elicitation.id` | Correlation id the agent echoes on retry. |
| `elicitation.status` | `pending` / `resolved` / `expired`. |
| `elicitation.outcome` | `approved` / `denied`, once resolved. |
| `elicitation.approver` | Resolved approver identity, cross-checked against `from`. |
| `elicitation.channel` | Audit label for how the human was reached (not a routing key). |

## A note on genuineness and args binding

Two independent checks stand between an approval and the tool call, and it is worth understanding where each is enforced:

- **Genuineness** is the channel plugin's job. For CIBA, the approver identity is extracted from the token the OP returns and cross-checked against the `login_hint`. The plugin trusts the token because it comes straight from the OP over a client-authenticated TLS poll — it does **not** independently verify the JWT signature. That trust therefore rests on the token endpoint being reached over correctly configured TLS with client authentication; deploy accordingly (always `https://`, real client credentials) and do not point a CIBA handler at a plaintext or unauthenticated endpoint outside local development.
- **Sufficiency** is the runtime's job. Keycloak has no RFC 9396 rich authorization request, so the binding between "what was approved" and "what is being executed" lives in APL: the `scope:` expression is evaluated against the live request args at validation. A human can approve, but if the args drift outside `scope` (e.g. the amount was raised after approval), the operation fails closed regardless.

The `purpose` is recorded verbatim as the source of truth for what was approved — it is never derived from model output.

## How it connects to the pipeline

`require_approval(...)` and its sibling verbs dispatch to a plugin implementing the `elicit` hook, resolved by name off the route's dispatch plan exactly like `delegate(...)`. Because elicitation is an explicit, sequenced effect — gated behind authentication, checked on every retry, and validated before the forward — a pending or unapproved operation never reaches the tool.
