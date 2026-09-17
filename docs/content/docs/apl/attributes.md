---
title: "Static Attributes"
weight: 35
---

# Static Attributes

Policy reads attributes. Most come from the request: the verified subject and its roles ([Identity]({{< relref "/docs/apl/identity" >}})), request headers, session labels. But some attributes are carried by nothing and fetched from nowhere — they are **operator-maintained facts** known at configuration time. Which region a tenant's data is resident in. Which models an agent is allowed to use. The org's default region. These are the *static attributes*, and they live in a plain data tree under the `data.*` namespace.

This is the counterpart to identity resolution. Identity turns a token into `subject.*` and `role.*`; static provisioning turns a config file into `data.*`. Both feed the same attribute bag predicates read.

## The requirement

An EU tenant's data must stay in-region (see [Backend Restriction]({{< relref "/docs/apl/restrict" >}})). To enforce that, policy has to know *which* region a given tenant is resident in — a fact that is not in the caller's token and does not belong in application code. It is an operator's decision, maintained alongside the deployment. Policy needs to read it per request, keyed by the caller's tenant.

## The data tree

Static attributes are a plain nested document. The operator organizes it however they like — by tenant, team, environment — and everything lives under a top-level `data:` mapping:

```yaml
# attributes/tenants.yaml
data:
  org:
    default_region: us
  tenants:
    acme-eu: { data_region: eu, allowed_models: ["anthropic/*", "vllm/*"] }
    acme-us: { data_region: us, allowed_models: ["openai/*", "vllm/*"] }
```

The whole tree flattens into the bag under `data.*`: `data.org.default_region`, `data.tenants.acme-eu.data_region`, and so on. A list of strings (like `allowed_models`) becomes a set, so `contains` works against it.

## Loading it

List the attribute files in APL's config namespace. They deep-merge, in order, into one `data.*` tree:

```yaml
global:
  apl:
    attribute_files:
      - attributes/org.yaml
      - attributes/tenants.yaml
      - attributes/agents.yaml
```

Different subtrees combine freely — `org.yaml` sets `data.org.*`, `tenants.yaml` sets `data.tenants.*`. The merge is **fail-fast**: two files setting the *same* leaf to different values is a load-time error, not a silent last-wins, and a file that forgets the `data:` wrapper is rejected. A configuration mistake stops the gateway from starting rather than producing quietly-wrong routing.

The built-in loader reads files. A host whose attributes live in etcd, a database, or a k8s ConfigMap implements the `AttributeSource` trait, loads the tree at startup, and injects it in code — an injected tree takes precedence over the declarative file list.

## Reading it in policy

Two ways, depending on whether the path is fixed or keyed by the request.

**Dot-path** — a fixed lookup:

```yaml
- "data.org.default_region == 'eu': deny('org is EU-only')"
```

**Interpolation** — index the tree by a *request* value, using `[...]`:

```yaml
routes:
  - llm: "*"
    pre_invocation:
      - when: "data.tenants[subject.tenant].data_region == 'eu'"
        do:
          - restrict: { allow_regions: [eu], on_empty: deny }
```

`[subject.tenant]` is resolved at evaluation time: the caller's `subject.tenant` (say `acme-eu`) is substituted into the path, so the predicate reads `data.tenants.acme-eu.data_region`. This is what makes the tree useful — "look up *this caller's* tenant" rather than a single hard-coded path.

If the indexed value is missing — no `subject.tenant` on this request — the whole path resolves to *absent*, and the predicate is simply false (and a `require(...)` on it fails closed). A lookup keyed on an unknown value never matches a half-built key.

Beyond predicates, a `data.*` reference can be the **value of a `restrict` field** — `allow_models: "data.agents[subject.id].allowed_models"` — so a single routing rule reads each caller's own allow-list from the tree. See [Backend Restriction]({{< relref "/docs/apl/restrict" >}}).

## Data, not a rules engine

The tree holds **literal values only**: no conditionals, no computed fields, no references to other entries. Any "if X then Y" is policy's job — put it in a route. This guardrail is structural rather than enforced: a plain data document has no syntax to express logic, so the static layer cannot quietly grow into a second, shadow policy engine. It provisions the facts; APL decides with them.

## How it connects to the pipeline

`data.*` is an ordinary bag namespace (see [Extensions & Capability-Gating]({{< relref "/docs/extensions" >}})): predicates read it exactly like `subject.*` or `session.labels`, and it composes with them freely — `data.tenants[subject.tenant].data_region` ties a static fact to a per-request identity in one predicate. The tree is loaded once at startup and shared across requests, so reading it costs nothing on the hot path. Where [Identity]({{< relref "/docs/apl/identity" >}}) supplies the *dynamic* attributes a request carries, static provisioning supplies the *stable* ones a deployment maintains — together they are the full picture a predicate reasons about.
