---
title: "Static attributes (data.*)"
weight: 19
---

# Module 18: Static attributes (operator-maintained facts)

> You are in the [CPEX tutorial]({{< relref "_index" >}}). This module needs the IdP.

**Goal:** feed policy the facts no token carries, operator decisions maintained in a data file, and read them per request as `data.*`.

## The problem

Some facts are carried by nothing. Which region a deployment's data must stay in. Which tools are switched on this week. The org's default tier. These are operator decisions, known at configuration time and belonging in neither the token nor the application code, unlike the attributes of modules 2 and 7, which arrive with the request.

CPEX provisions them from a plain data file into the `data.*` namespace. Identity turns a token into `subject.*`; static provisioning turns a config file into `data.*`, and predicates read both the same way.

## Build it

A data file of facts (note the top-level `data:` wrapper). From [`policies/attributes/controls.yaml`](https://github.com/contextforge-org/cpex/tree/main/examples/tutorial/policies/attributes/controls.yaml):

```yaml
data:
  org:
    data_region: eu
  controls:
    tools:
      get_compensation: { enabled: false }   # frozen by operations
      search_repos: { enabled: true }
```

List it under `global.apl.attribute_files`, and read it in a rule. From [`policies/m18.yaml`](https://github.com/contextforge-org/cpex/tree/main/examples/tutorial/policies/m18.yaml):

```yaml
global:
  apl:
    attribute_files:
      - examples/tutorial/policies/attributes/controls.yaml   # relative to repo root

routes:
  - tool: get_compensation
    authentication: [keycloak]
    authorization:
      pre_invocation:
        - "require(authenticated)"
        - when: "data.controls.tools.get_compensation.enabled == false"
          do:
            - "deny('get_compensation is disabled by operations', 'ops.tool_disabled')"
```

The whole file flattens into the bag: `data.org.data_region`, `data.controls.tools.get_compensation.enabled`, and so on. Multiple files deep-merge in order, and the merge is fail-fast: two files setting the same leaf differently is a load error, and a file missing its `data:` wrapper is rejected. A config mistake stops startup rather than quietly mis-routing.

The tree holds literal values only, with no conditionals, computed fields, or cross-references. A data document has no syntax for logic, so the static layer cannot grow into a second, shadow policy engine. It provisions the facts; APL decides with them.

## Run it

Run this one from the repo root: `attribute_files` paths resolve against the working directory.

```bash
cargo run -p cpex-tutorial --example m18_attributes
```

```
▸ alice → get_compensation (data.controls says this tool is disabled)
  ✗ DENIED   [ops.tool_disabled] get_compensation is disabled by operations

▸ alice → search_repos (data.controls says this tool is enabled)
  ✓ ALLOWED  { ... }
```

The same caller reached one tool and was refused another. Nothing about alice changed between the two calls; the outcome came from a fact in a file, read as `data.*`.

## Reading the tree per caller

This module reads fixed paths, but a path can also be indexed by a *request* value, so one rule serves every caller:

```yaml
- when: "data.tenants[subject.tenant].data_region == 'eu'"
  do: [ "taint(eu_resident, session)" ]
```

`[subject.tenant]` is substituted at evaluation time, so the predicate reads `data.tenants.<this caller's tenant>.data_region`. A missing value resolves to absent and the predicate is false, so a `require` on it fails closed. [Static Attributes]({{< relref "/docs/apl/attributes" >}}) has the runnable version, along with the `restrict` fields that take a `data.*` reference the same way.

## Try it

1. **Flip a switch.** Set `search_repos.enabled: false` in `controls.yaml` and re-run. Expect: now *both* tools are refused, and you changed behavior by editing a data file, touching no policy and no code.
2. **Break the merge.** Add a second file to `attribute_files` that sets `data.org.data_region` to a *different* value. Expect: a load-time error, because the merge is fail-fast, not last-wins.
3. **Forget the wrapper.** Remove the top-level `data:` key from the file. Expect: rejected at load, because the file must declare `data:`.

## Checkpoint

{{< details "How is data.* different from subject.*?" >}}
`subject.*` is dynamic, resolved from the token this request carried. `data.*` is static, provisioned from a file at startup and shared across requests. One is what the caller *is*; the other is what the operator has *decided*. Predicates read both identically and combine them freely.
{{< /details >}}

{{< details "Why not just put the flag in the route?" >}}
You could, but then flipping a tool off is a policy edit and review. Facts an operator changes often (kill switches, region maps, per-tenant tiers) live better as data an operator maintains, keyed by the request, so one rule serves everyone and the change is a data edit, not a policy one.
{{< /details >}}

## Go deeper

- [Static Attributes]({{< relref "/docs/apl/attributes" >}}) for the full `data.*` model, merge rules, and the `AttributeSource` trait (etcd / DB / ConfigMap sources).
- [Backend Restriction]({{< relref "/docs/apl/restrict" >}}) for where `data.*` references feed per-caller routing constraints.

## Next

[Capstone]({{< relref "capstone" >}}): reconstruct the full scenario end to end.
