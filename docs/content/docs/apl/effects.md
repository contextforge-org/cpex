---
title: "Effects & Sequencing"
weight: 10
---

# Effects and Sequencing

An APL rule does something. That something is an **effect**. Effects are the building blocks of policy: a `pre_invocation:` block is an ordered list of them, and they run in sequence until one denies.

## The effects

| Effect | What it does |
|--------|--------------|
| `allow` | No-op. Continue to the next effect. |
| `deny` / `deny('reason')` / `deny('reason', 'code')` | Halt the phase and all later phases with a violation. |
| `plugin(name)` (alias `run(name)`) | Invoke a registered plugin (PII scan, audit log, custom check). |
| `delegate(name, ...)` | Mint a downstream credential via a delegator plugin. See [Delegation]({{< relref "/docs/apl/delegation" >}}). |
| `taint(label[, scope])` | Attach a label to the session or message. See [Session Tainting]({{< relref "/docs/apl/tainting" >}}). |
| field pipelines | Validate or transform `args`/`result` fields. See [APL]({{< relref "/docs/apl" >}}). |
| PDP call (`cedar:`, `cel:`, `opa(...)`) | Delegate the decision to a policy engine. See [PDP Integration]({{< relref "/docs/apl/pdp" >}}). |

## Sequencing and halt-on-deny

Effects in a `pre_invocation:` block run top to bottom. The first `deny` halts the phase and skips every later phase, so order is a tool: put cheap gates first and expensive effects last.

```yaml
authorization:
  pre_invocation:
    - "require(role.hr)"                                  # cheap attribute gate
    - cedar:                                              # relationship decision
        action: 'Action::"read"'
        resource:
          type: Repo
          id: ${args.repo_name}
    - "delegate(github-oauth, target: github-api, permissions: [repo:read])"  # expensive, last
```

If `require(role.hr)` denies, the Cedar call and the token exchange never run. This is both faster and safer: you do not mint a credential for a caller you were going to reject.

## Reactions: on_allow and on_deny

A PDP call can carry reaction blocks that run depending on the decision:

```yaml
authorization:
  pre_invocation:
    - cedar:
        action: 'Action::"read"'
        resource:
          type: Document
          id: ${args.doc_id}
      on_allow:
        - "taint(cedar_approved, session)"
      on_deny:
        - "deny('not permitted by Cedar policy', 'cedar_denied')"
```

`on_allow` runs its effects when the PDP permits; `on_deny` runs when it denies. Without an `on_deny`, a PDP denial halts the phase on its own.

## Composition: sequential and parallel

Effects can be grouped. `sequential` runs its members in order and halts on the first deny. `parallel` runs independent gates concurrently; any deny fails the group, and taints from the branches accumulate.

```yaml
authorization:
  pre_invocation:
    - parallel:
        - "require(perm.read_pii)"
        - cel: { expr: "subject.department == 'compliance'" }
```

`parallel` is for independent decisions only. It rejects field operations and delegation, because a discarded branch would silently lose those effects. Use `sequential` (the default for a `pre_invocation:` list) whenever one effect depends on another.

## Phases recap

Effects run within the four route phases: `args`, `authorization.pre_invocation`, `result`, `authorization.post_invocation` (see [APL]({{< relref "/docs/apl" >}})). `delegate` and PDP calls belong in `pre_invocation` or `post_invocation`; field pipelines belong in `args` and `result`. A deny anywhere halts the rest.
