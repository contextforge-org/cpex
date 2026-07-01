---
title: "PDP Integration"
weight: 20
---

# PDP Integration

APL predicates handle attribute checks well: roles, permissions, scopes, comparisons. They are a poor fit for relationship questions ("is this user on the team that owns this repo?") and for policy you already maintain in a dedicated engine. For those, APL hands the decision to a **Policy Decision Point**.

## The requirement

The scenario's repository search must allow a read when the caller is an engineer and the repo is internal, or when the caller is on the security team, regardless of repo. That is a relationship-and-attribute decision over entities, which is exactly what an engine like Cedar exists to express. APL should make the coarse gate and let the engine make the fine-grained call.

## Calling a PDP from policy

A PDP call is an effect in the `policy` phase. It names a dialect and passes the request; `on_allow` and `on_deny` react to the decision:

```yaml
policy:
  - "require(team.engineering | team.security)"
  - cedar:
      action: 'Action::"read"'
      resource:
        type: Repo
        id: ${args.repo_name}
        attributes:
          visibility: ${args.visibility}
    on_deny:
      - "deny('not permitted by repo policy', 'cedar_denied')"
```

The cheap APL gate runs first. Only if it passes does CPEX evaluate the Cedar policy against the request entities. The Cedar policy itself lives in the config:

```yaml
global:
  pdp:
    - kind: cedar-direct
      policy_text: |
        @id("engineering-internal-repos")
        permit(principal, action == Action::"read", resource is Repo)
        when {
          principal.roles.contains("engineer") &&
          resource.visibility == "internal"
        };

        @id("security-team-any-repo")
        permit(principal, action == Action::"read", resource is Repo)
        when { principal.roles.contains("security") };
```

## Supported dialects

APL recognizes a fixed set of PDP dialects. Two ship as builtin resolvers; the rest are recognized by APL and dispatched to a resolver you provide on the host.

| Dialect | Status |
|---------|--------|
| `cedar` | Ships as the `cedar-direct` builtin resolver. |
| `cel` | Ships as the `cel` builtin resolver (safe, bounded expressions). |
| `opa` | Recognized dialect; wire a host resolver (Rego / OPA). |
| `authzen` | Recognized dialect; wire a host resolver (AuthZEN protocol). |
| `nemo` | Recognized dialect; wire a host resolver (NeMo Guardrails). |

This is a deliberate pluggable-resolver surface, not a maturity checklist. APL speaks the dialect; the resolver is an implementation. Cedar and CEL are provided so you can start without writing one. For OPA, AuthZEN, or NeMo, implement the resolver trait and register it; the APL `opa:` / `authzen:` / `nemo:` call forms then work unchanged.

CEL is the lightest option for inline boolean policy:

```yaml
policy:
  - cel: { expr: "subject.department == 'compliance' || 'admin' in subject.roles" }
```

## How it connects to the pipeline

A PDP resolver is registered with the manager like any other capability. When the evaluator hits a PDP effect, it dispatches to the resolver for that dialect, passing the attribute bag and the call's arguments, and routes the `Allow` / `Deny` decision through `on_allow` / `on_deny`. The decision and its diagnostics are recorded in the audit log. See [Effects]({{< relref "/docs/apl/effects" >}}) for how PDP reactions sequence with the rest of a policy.
