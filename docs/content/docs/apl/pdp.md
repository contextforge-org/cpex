---
title: "PDP Integration"
weight: 20
---

# PDP Integration

APL predicates handle attribute checks well: roles, permissions, scopes,
comparisons. They are a poor fit for relationship questions ("is this user on
the team that owns this repo?") and for policy you already maintain in a
dedicated engine. For those, APL hands the decision to a Policy Decision
Point.

## Decision requirement

The scenario's repository search must allow a read when the caller is an
engineer and the repo is internal, or when the caller is on the security team,
regardless of repo. That is a relationship-and-attribute decision over entities,
which is exactly what an engine like Cedar exists to express. APL should make
the coarse gate and let the engine make the fine-grained call.

## Calling a PDP from policy

A PDP call is an effect in the `authorization.pre_invocation` phase. It names a
dialect and passes the request; `on_allow` and `on_deny` react to the decision:

```yaml
authorization:
  pre_invocation:
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

The cheap APL gate runs first. Only if it passes does CPEX evaluate the Cedar
policy against the request entities. The Cedar policy itself lives in the
config:

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

A `pdp:` entry may carry an optional `cache:` block with positive
`ttl_seconds` and `max_entries`. Omission leaves evaluation uncached.
The cache stores Allow and Deny only; dispatch errors are never stored.
Keys are a digest of the dialect, the call arguments, the full attribute bag
and the structured input, so request data is not retained. External PDP policy
can still go stale until the TTL expires.

## Supported dialects

APL recognizes a fixed set of PDP dialects. Three ship as builtin resolvers; the
rest are recognized by APL and dispatched to a resolver you provide on the host.

| Dialect | Status |
|---------|--------|
| `cedar` | Ships as the `cedar-direct` builtin resolver. |
| `cel` | Ships as the `cel` builtin resolver (safe, bounded expressions). |
| `opa` | Ships as the `opa` builtin resolver (embedded Rego via regorus, no sidecar). |
| `authzen` | Recognized dialect; wire a host resolver (AuthZEN protocol). |
| `nemo` | Recognized dialect; wire a host resolver (NeMo Guardrails). |

This is a deliberate pluggable-resolver surface, not a maturity checklist. APL
speaks the dialect; the resolver is an implementation. Cedar, CEL, and OPA are
provided so you can start without writing one. For AuthZEN or NeMo, implement
the resolver trait and register it; the APL `authzen:` / `nemo:` call forms then
work unchanged.

CEL is the lightest option for inline boolean policy:

```yaml
authorization:
  pre_invocation:
    - cel: { expr: "subject.department == 'compliance' || 'admin' in subject.roles" }
```

With CEL 0.14, use `in` for list membership; container `.contains()` and the default `min`/`max` functions are unavailable. If the host registers custom CEL functions, give them names distinct from built-ins such as `double`, whose overloads may take precedence.

All three builtin resolvers ship in every CPEX surface: the Rust facade, the Python package, the Go module and the C ABI.

## Structured request input

The attribute bag holds scalars and string sets, so it cannot carry a list of
objects such as an LLM request's `tools`. OPA, CEL, and Cedar also receive two
JSON values beside the bag. APL predicates do not; they read the flat bag as
before.

| Name | Where it is set | What it holds |
|---|---|---|
| `llm.request` | Any route whose host supplied it, including an `http:` route that proxies inference. | The request body as the host parsed it, from `Extensions.llm_request`. The slot is immutable, so plugins cannot replace it, and a PDP always sees the original body. |
| `args` | `tool:` routes | The first tool call's arguments, taken before any `args:` pipeline runs. Only an object counts. |

Each engine names them as follows:

| Engine | Request body | Tool arguments |
|---|---|---|
| OPA | `input.llm.request` | `input.args` |
| CEL | `llm.request` | `args` |
| Cedar | `context.llm.request` | `context.args` |

The request document keeps the provider's wire shape. Prefer normalized bag
attributes for rules that must work across providers, and use `llm.request`
when the rule intentionally targets one provider format.

Provider-side MCP declarations can be checked in `llm.request`, but their
later calls do not pass through a `tool:` route. Allowing a server here does
not add per-call policy enforcement for tools the provider invokes itself.

In OPA and CEL, `llm.request` sits beside the existing `llm.model_id`,
`llm.provider`, and `llm.capabilities`. Structured `args` replaces the
flattened `args.*` keys, so a field has one type whatever the client sent.
See [Migrating `args` policies](#migrating-args-policies). Cedar never read
`args` from the bag, so `context.args` is new. APL predicates and `${args.X}`
substitution in step arguments still read the flattened bag. On `llm:` routes
there is no structured `args`, and `args` stays the prompt string.

Structured input nested more than 128 levels deep, the limit serde_json
applies when parsing, is refused for any engine: every PDP step on that
request denies with the code `pdp.input_too_deep` and a reason that quotes no
value, and the engine never runs. A scalar is depth 1, and each enclosing
array or object adds one. APL-only steps are unaffected.

### Types across engines

| JSON | OPA | CEL | Cedar |
|---|---|---|---|
| object | object | map | record |
| array | array, order and duplicates kept | list, order and duplicates kept | set: unordered, duplicates collapsed |
| integer | number | `int` (`uint` above the `int` range) | `Long`; outside the `Long` range, a string |
| float such as `0.7` | number | `double` | string `"0.7"` |
| `null` | `null` | `null` | dropped, so the attribute is absent |
| object with an `__entity`, `__extn`, or `__expr` key | plain object | plain map | the step denies with `cedar.input_withheld` |
| document absent | undefined | missing key: evaluation error, so the step denies | missing attribute: evaluation error, so the step denies |

A document the host did not supply is absent, never an empty object.

Set `require_llm_request: true` on a PDP step when its decision depends on the
document. The evaluator then denies an absent document with
`pdp.llm_request_missing` before invoking the engine on any route.

Structured `args` is the received value. An `args:` pipeline can change the
value forwarded to the tool after this snapshot is taken.

### Absent and null values

**OPA.** An absent document is undefined. An explicit `null` is a present
value: `input.args.note == null` holds, and `not input.args.note` does not.
To treat absent and `null` alike, write
`object.get(input.args, "note", null) == null`. What an undefined document
does depends on the decision shape the query returns:

| Decision shape | Absent document | Safe idiom |
|---|---|---|
| Boolean `allow` | undefined, so the step denies | `default allow := false` |
| Decision object | undefined, so the step denies | build the object only when the rule holds |
| Deny set | every rule that reads it is undefined, the set is empty, and the step **allows** | add a rule that denies when the document is missing |

Guard a deny set like this:

```rego
package authz

deny contains "request document missing" if not input.llm.request

deny contains "model not allowed" if input.llm.request.model != "gpt-4o"
```

**CEL.** A reference to an absent document, or to a missing field, is an
evaluation error. The default `on_error: deny` turns it into a deny, so do not
set `on_error: allow` on a step that reads structured input. Guard an optional
field with `has()`: `!has(llm.request.tools) || size(llm.request.tools) < 8`.
`has()` is true for an explicit `null`, so test the value too when `null` must
count as missing: `has(args.note) && args.note != null`.

**Cedar.** A `null` is dropped, so `has` is false for it. Reading an absent
document is a missing-attribute error, and any evaluation error denies the
step, in a `permit` or a `forbid`. Guard optional paths with `has`:
`context has llm && context.llm has request && context.llm.request has tools`.

### Example: allowlist tool types

This guard rejects an inference request when any entry in `tools[]` has a
`type` that matches none of the allowed patterns. A request with no `tools`
passes, a request with no document denies, and a tool with no string `type`
denies. Anchor each pattern: both engines search for a match anywhere in the
string.

OPA, with `regex.match`:

```yaml
global:
  pdp:
    - kind: opa
      modules:
        - |
          package ssrf

          allowed_types := ["^function$", "^code_execution_[0-9]+$"]

          default allow := false

          allow if {
              input.llm.request
              not unlisted_tool
          }

          unlisted_tool if {
              some t in input.llm.request.tools
              not type_allowed(t)
          }

          type_allowed(t) if {
              some pattern in allowed_types
              regex.match(pattern, t.type)
          }
routes:
  - llm: "*"
    authorization:
      pre_invocation:
        - opa:
            query: data.ssrf.allow
            require_llm_request: true
```

CEL, with `matches`. Extra keys on a `cel:` step become variables, so the
patterns live in the step as `allowed`:

```yaml
global:
  pdp:
    - kind: cel
routes:
  - llm: "*"
    authorization:
      pre_invocation:
        - cel:
            expr: >-
              !has(llm.request.tools) ||
              llm.request.tools.all(t, allowed.exists(p, t.type.matches(p)))
            allowed: ["^function$", "^code_execution_[0-9]+$"]
```

A request carrying `{"type": "web_search_20250305"}` denies under both.

### Cedar limits

Cedar's JSON form cannot hold every JSON value, so the structured input is
sanitized first:

- `null` is dropped from objects and arrays.
- Floats, and integers outside the `Long` range, become strings. Compare them
  as strings, or through `decimal()` when the value fits it.
- Arrays become sets: unordered, with duplicates collapsed. Cedar cannot count
  or order array elements.
- An object with an `__entity`, `__extn`, or `__expr` key would be read as an
  entity or extension value and silently change what a rule means. Such a key
  anywhere in either value withholds the input, and the step denies with the
  violation code `cedar.input_withheld` before Cedar runs, whether or not the
  policy reads that value.

A step's own `context:` may not define `llm` or `args`, since those keys carry
the structured input. Config load rejects such a step, including one nested in
a reaction.

**With a schema.** A Cedar schema gives each action a closed context type, so
an undeclared `args` or `llm` key fails request validation and the step denies.
A `cedar-direct` resolver with `schema_text` or `schema_file` therefore
requires `structured_context: true` when a Cedar step reaches any route,
because the host can attach an LLM request document to each route. Config
load rejects a schema-backed Cedar step without the flag. Declare `llm` as
optional in the context type of every action such a step calls, and also
declare `args` for `tool:` routes:

```yaml
global:
  pdp:
    - kind: cedar-direct
      structured_context: true
      policy_file: /etc/cpex/policy.cedar
      schema_text: |
        entity User = { ... };
        entity Tool;
        action call appliesTo {
          principal: User,
          resource: Tool,
          context: {
            args?: { repo: String, limit?: Long },
            llm?: { request: { model: String } },
          },
        };
```

Cedar record types are closed, so declare every field the input can carry,
after sanitizing: a float is a `String` and an array is a `Set`. A request
whose structured input does not match denies with `Cedar request validation
failed: context does not match the action's context type`.

**Do not use Cedar for deny-lists over `llm.request.tools`.** Set `contains`
over records needs an exact match on the whole record. This rule misses a
forbidden tool that carries one extra field, such as a `name`:

```text
forbid(principal, action, resource)
when { context.llm.request.tools.contains({"type": "web_search"}) };
```

Cedar has no quantifier to test one field of each element. Write deny-lists
over `tools` in OPA or CEL.

### Payload values in reasons and diagnostics

Values under `args`, `result`, and `llm.request` come from the client, and a
deny reason can reach the client. Text a PDP generates therefore names types,
not values:

- CEL diagnostics print `llm.request=map` or `args=list(2)`, and eval errors
  name a fixed category.
- OPA eval errors give a category and the policy location, such as
  `OPA eval error: policy runtime error at global-0.rego:2:33`. A result that
  carries no decision is described by its type.
- Cedar errors name the policy and a category, such as
  ``policy `limit-cap`: type error``. Entity, action, and request validation
  errors name at most the entity type, never an id or value that `${args.X}`
  filled in.

Text the policy author wrote passes through unchanged: an OPA `reason` or
`message`, a string violation or its `msg`, and an APL `deny('...')` message.
Do not copy payload values into your own reasons, for example with
`sprintf("tool %v is not allowed", [t.type])` in Rego, because that text
reaches the client.

### Host PDP resolvers

The `read_llm_request` capability gates plugins, not PDP resolvers (see
[Extensions]({{< relref "/docs/extensions" >}})). A resolver is host code that already receives
the whole bag. The evaluator calls `PdpResolver::evaluate_structured(call,
bag, structured)`, whose default ignores `structured` and calls
`evaluate(call, bag)`. A host resolver opts in by overriding
`evaluate_structured` and reading `StructuredInput::llm_request` and
`StructuredInput::args`. It may override `validate_call` for call-local checks
and `validate_call_with_input` for checks that depend on the route's available
structured values. Input past the depth limit never reaches a resolver.

### Migrating `args` policies

This changed between CPEX 0.2.x and 0.3. On `tool:` routes, OPA and CEL used to read `args` from the flattened bag. A
scalar array arrived as a sorted, deduplicated set of strings, an explicit
`null` field was absent, and an array of objects was dropped. Now `args` is the
native JSON. Review every OPA and CEL rule that reads `args` on a `tool:`
route before upgrading. Rules that do not read `args`, APL predicates, and
Cedar `${args.X}` substitution are unaffected.

Number and bool arrays hold numbers and bools, not strings:

```rego
# before
deny contains "blocked id" if "13" in input.args.ids
# after
deny contains "blocked id" if 13 in input.args.ids
```

```text
before: !("13" in args.ids)
after:  !(13 in args.ids)
```

Arrays keep the client's order, so a rule that relied on sorting must not
index or compare them as ordered:

```rego
# before: relied on the sorted set
allow if input.args.regions == ["eu", "us"]
# after: compare as a set
allow if {r | some r in input.args.regions} == {"eu", "us"}
```

```text
before: args.regions == ["eu", "us"]
after:  args.regions.all(r, r in ["eu", "us"]) &&
        ["eu", "us"].all(r, r in args.regions)
```

Arrays keep duplicates, so a count is no longer a count of distinct values:

```rego
# before: counted distinct ids
allow if count(input.args.ids) <= 3
# after
allow if count({i | some i in input.args.ids}) <= 3
```

CEL has no set type. Write the rule with `all` or `exists`, whose answer does
not change with duplicates.

An explicit `null` is present:

```rego
# before: true for a missing or null note
allow if not input.args.note
# after
allow if object.get(input.args, "note", null) == null
```

```text
before: !has(args.note)
after:  !has(args.note) || args.note == null
```

A rule that relied on an array of objects being dropped, such as
`not input.args.items`, now sees the array.

## How it connects to the pipeline

A PDP resolver is registered with the manager like any other capability. When
the evaluator hits a PDP effect, it dispatches to the resolver for that dialect,
passing the attribute bag, the structured input, and the call's arguments, and
routes the `Allow` / `Deny` decision through `on_allow` / `on_deny`. The
decision and its diagnostics are recorded in the audit log. See
[Effects]({{< relref "/docs/apl/effects" >}}) for how PDP reactions sequence with the rest of a policy.

