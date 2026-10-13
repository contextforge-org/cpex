---
title: "CMF Extensions"
weight: 42
---

# CMF Extensions and the Attribute Bag

Policy reads a flat attribute bag. The engine fills it by walking each present slot on the request's `Extensions` into dotted keys. Plugins that are handed a typed slot still see the original struct. This page is the contract for what the bridge writes, how collections relate to the flattened booleans, and what each decision point does with a missing key.

[Extensions & Capability-Gating]({{< relref "/docs/extensions" >}}) covers which capability unlocks each slot. This page covers the keys.

Twelve slots are bridged. Three slots never enter the bag: `raw_credentials` (credentials stay out of policy), `candidate_constraint` (a routing constraint, not an attribute) and `llm_request` (it reaches PDPs as structured JSON instead).

## Setting slots from each surface

The host supplies the extensions on every invocation.

- **Rust:** build `cpex::praxis_policy_core::extensions::Extensions` directly. Every slot is available.
- **Python:** pass a dict as the `extensions` argument of `invoke_hook`. It is deserialized into the same `Extensions` type, so every slot on this page can be set, for example `{"meta": {...}, "security": {"subject": {...}}, "http": {"request_headers": {...}}}`.
- **Go:** fill `cpex.Extensions`. It declares a subset of the fields. It has no `security.client`, `caller_workload` or `this_workload`, no HTTP request line or status (`method`, `path`, `host`, `scheme`, `status`), and `SubjectExtension.Claims` holds strings only, so nested claims cannot be set from Go. Keys that depend on those fields are never written for a Go request unless a plugin on the engine side sets them, such as an identity resolver.

## Which slots a route's policy sees

A route's rules read the bag through the route's own handler, and that handler is capability-gated like a plugin. It always holds `read_subject`, `read_roles`, `read_permissions`, `read_teams`, `read_claims`, `read_labels`, `read_delegation`, `read_agent`, `read_meta` and `read_headers`, plus every capability declared by a plugin the route references. Other slots are filtered out. For example, a host that sets `security.client` on a route that references no plugin with `read_client` gets a deny from `require(client.client_id == "app-1")`, because `client.*` is never written for that route. A Rust host can change the base set with `AplOptions::base_capabilities` and `register_apl`; `install_builtins` and the bindings use the default.

## Absent values

The rule is per attribute type, and it applies only inside a present slot. An absent slot writes nothing for its namespace.

| Type | When the field is empty or unset | Why |
|---|---|---|
| String set | Present and empty. Membership is false. | CEL treats a missing key as an error, so `!("banned" in subject.roles)` would deny every subject with no roles. |
| Bool field (`delegation.delegated`) | Present, including `false`. | The field is not optional. |
| Flattened bool (`role.hr`) | Omitted. Presence means true. Only membership names without dots get one. | APL reads a missing flattened bool as false. In CEL, do not guard with `has(role.hr)`: if no `role.*` key exists, that is an evaluation error. Use `"hr" in subject.roles`. |
| Derived bool (`authenticated`) | Omitted unless `subject.id` is set. | `!authenticated` is true and `require(authenticated)` denies. In CEL, use `has(subject.id)` as the guard. |
| String | Omitted when unset. A non-optional string (`client.client_id`) is always written, even if empty. | Empty and missing are different questions. |
| Int, Float | Omitted when unset (`http.status`, `agent.turn`, `completion.latency_ms`). Non-optional ones (`delegation.depth`, `delegation.age_seconds`) are always written. | A missing status is not zero: `http.status >= 500` and `http.status == 0` would both lie. |
| JSON object or claims | No parent key. Each scalar or scalar-array child is written under a dotted path. `{}`, `null`, and arrays holding containers write nothing. | The bag has no map type. |

## Collections and flattened booleans

| Collection | Flattened form |
|---|---|
| `subject.roles` | `role.<name> = true` |
| `subject.permissions` | `perm.<name> = true` |
| `subject.teams` | `team.<name> = true` |
| `client.roles` | `client.role.<name> = true` |
| `client.permissions` | `client.perm.<name> = true` |

The set is the primary form. Only these five get flattened aliases. Other sets are set-only: `client.teams`, `client.authorized_scopes`, `client.authorized_audiences`, `caller_workload.selectors`, `this_workload.selectors`, `security.labels`, `agent.conversation.topics`, `meta.tags`, `llm.capabilities`. So `require(tag.pii)` is always false; use `meta.tags contains "pii"`.

A dotted membership name such as `admin.readonly` stays in `subject.roles` but gets no `role.admin.readonly` key, because CEL would read that key as nested maps. Test dotted names through the set.

Prefer the set for membership in every dialect: `subject.roles contains "hr"` in APL, `"hr" in subject.roles` in CEL, `"hr" in input.subject.roles` in OPA. The set is present whenever the subject is, so all decision points agree on empty.

Cedar reads `principal.roles`, `principal.permissions` and `principal.teams` from the sets. It does not surface `client.*`, `http.*` or other slots as principal attributes.

## Claims

There is no `subject.claims` key. Each claim goes through the same JSON flattener as `custom.*` and `args.*`:

- a scalar lands at `claim.<name>` with its type kept
- a scalar array, empty included, lands as a string set
- `{}`, `null`, and an array holding a container write nothing
- a nested object writes only its children (`claim.realm_access.roles`), never the parent

Client claims use the same shape under `client.claim.<name>`. That covers `claim.tenant == "acme"` and `claim.realm_access.roles contains "admin"`, but not "any claim at all". Plugins read the typed `SubjectExtension.claims`.

## Missing keys per decision point

| Engine | Missing key | Empty set |
|---|---|---|
| APL | False for presence, equality, membership and order. Every negated form is true: `!=`, `!key`, `!(...)`, `not in`. | `contains` / `in` is false |
| CEL | Evaluation error, which the default `on_error: deny` turns into a deny that reports a key error | `in` is false |
| cedar-direct | Empty `roles`, `permissions`, `teams` and `claims` exist on the principal. No `subject.id` is a dispatch error. A missing `subject.type` defaults to `User`; the bridge writes lowercase types. | `contains` is false |
| OPA | Undefined. Without `default allow := false`, the query is a default deny. `not` of undefined is true. | `in` is false |

`require` denies when its predicate is false, so on omitted keys:

| Rule | APL | Other engines |
|---|---|---|
| `require(claim.tenant == "acme")` | Deny | Deny |
| `require(subject.roles contains "hr")` | Deny | Deny |
| `require(claim.tenant != "acme")` | Allow | Deny |
| `require(subject.type not in blocked_types)` | Allow | CEL and cedar-direct deny; OPA allows |

To keep a denylist closed when the key is missing, write `require(exists(claim.tenant) & claim.tenant != "acme")`.

## The twelve slots

Keys marked **always** are written whenever the slot (or the noted sub-record) is present. The rest are omitted when unset.

### `security`

Subject (when present):

| Key | Type | When |
|---|---|---|
| `subject.id` | String | set |
| `subject.type` | String (`user`, `agent`, `service`, `system`) | set |
| `subject.roles`, `subject.permissions`, `subject.teams` | String set | always |
| `role.<name>`, `perm.<name>`, `team.<name>` | Bool | each member without a dot |
| `claim.<dotted>` | flattened JSON | each claim |
| `authenticated` | Bool | `subject.id` is set |

Client (when present):

| Key | Type | When |
|---|---|---|
| `client.client_id` | String | always |
| `client.client_name` | String | set |
| `client.trust_level` | String (`first_party`, `third_party`, `internal`, custom, `unknown`) | always |
| `client.roles`, `client.permissions`, `client.teams` | String set | always |
| `client.role.<name>`, `client.perm.<name>` | Bool | each member without a dot |
| `client.authorized_scopes`, `client.authorized_audiences` | String set | always |
| `client.claim.<dotted>` | flattened JSON | each claim |

Workload (`caller_workload` and `this_workload`, same shape):

| Key | Type | When |
|---|---|---|
| `<ns>.spiffe_id`, `<ns>.trust_domain`, `<ns>.attestor`, `<ns>.client_id` | String | set |
| `<ns>.selectors` | String set | always |

Other, whenever the security slot is present: `auth_method` (String, set), `security.labels` (String set, always), `security.classification` (String, set). `security.objects` and `security.data` are not in the bag; plugins read them from the typed slot.

### `delegation`

| Key | Type | When |
|---|---|---|
| `delegation.depth` | Int | always |
| `delegation.delegated`, `delegated` | Bool | always |
| `delegation.origin_subject_id`, `delegation.actor_subject_id` | String | set |
| `delegation.age_seconds` | Float | always |

Per-hop scopes, audience and strategy stay on the typed chain.

### `agent`

| Key | Type | When |
|---|---|---|
| `agent.input`, `agent.session_id`, `agent.conversation_id`, `agent.agent_id`, `agent.parent_agent_id` | String | set |
| `agent.turn` | Int | set |
| `agent.conversation.summary` | String | conversation present and summary set |
| `agent.conversation.topics` | String set | conversation present |

### `meta`

| Key | Type | When |
|---|---|---|
| `meta.entity_type`, `meta.entity_name`, `meta.scope` | String | set |
| `meta.tags` | String set | always |
| `meta.properties.<k>` | String | each entry |

### `request`

`request.environment`, `request.request_id`, `request.timestamp`, `request.trace_id`, `request.span_id`: String, when set.

### `http`

| Key | Type | When |
|---|---|---|
| `http.method`, `http.path`, `http.host`, `http.scheme` | String | set |
| `http.status` | Int | set (response half) |
| `http.request_headers.<name>`, `http.response_headers.<name>` | String | each header, name lowercased |

### `llm`

`llm.model_id`, `llm.provider` (String, set) and `llm.capabilities` (String set, always). The parsed request body is the separate `llm_request` slot: OPA and CEL read it as `llm.request`, Cedar as `context.llm.request`.

### `mcp`

| Key | Type | When |
|---|---|---|
| `mcp.tool.name` | String | tool present |
| `mcp.tool.title`, `mcp.tool.description`, `mcp.tool.server_id`, `mcp.tool.namespace` | String | set |
| `mcp.resource.uri` | String | resource present |
| `mcp.resource.name`, `mcp.resource.description`, `mcp.resource.mime_type`, `mcp.resource.server_id` | String | set |
| `mcp.prompt.name` | String | prompt present |
| `mcp.prompt.description`, `mcp.prompt.server_id` | String | set |

Schemas and annotations are not flattened.

### `completion`

| Key | Type | When |
|---|---|---|
| `completion.stop_reason` | String | set |
| `completion.tokens.input`, `completion.tokens.output`, `completion.tokens.total` | Int | tokens present |
| `completion.model`, `completion.raw_format`, `completion.created_at` | String | set |
| `completion.latency_ms` | Int | set |

### `provenance`

`provenance.source`, `provenance.message_id`, `provenance.parent_id`: String, when set.

### `framework`

`framework.framework`, `framework.framework_version`, `framework.node_id`, `framework.graph_id` (String, set) and `framework.metadata.<dotted>` (flattened JSON).

### `custom`

`custom.<dotted>`: flattened JSON for each entry.

## Keys that do not come from slots

| Source | Keys |
|---|---|
| Request arguments | `args.<dotted>`. A top-level scalar is `args`; a top-level scalar array is `args` as a string set. |
| Upstream result | The same shapes under `result` and `result.<dotted>`. |
| Static `data:` tree | `data` and `data.<dotted>`. |
| Route | `route.key` |

On `tool:` routes, OPA and CEL do not read the flattened `args.*` keys. They get the arguments as native JSON, so arrays of objects, order, numbers and `null` survive. Cedar gets the same JSON, sanitized, as `context.args`. APL still reads the flattened keys. See [PDP]({{< relref "/docs/apl/pdp" >}}).

## Go deeper

- PPE's [CMF extensions contract](https://github.com/praxis-proxy/policy/blob/v0.5.0/docs/content/cmf-extensions.md), the source for this page.
- [Common Message Format]({{< relref "/docs/cmf" >}}): the message the extensions travel with.
- [Identity Claim Mapping]({{< relref "/docs/identity-claim-mapping" >}}): how token claims become `subject.*` and `client.*`.
