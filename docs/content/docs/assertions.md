---
title: "Header Assertions"
weight: 58
---

# Header Assertions

CPEX validates tokens, maps claims into a typed identity, mints delegated credentials and accumulates labels. None of that reaches an upstream on its own. The `assertions:` block says which of it does, as request headers, and which response headers an upstream may not send back to a client.

The block sits next to `authentication:` and holds two contracts:

```yaml
global:
  assertions:
    request:                 # toward the upstream, on a pre-phase hook
      headers: [...]
      strip: [...]
    response:                # toward the client, on a post-phase hook
      headers: [...]
      strip: [...]
```

**Surfaces.** Assertions run inside the engine, so they work the same from Rust, Python and Go. The host passes the inbound headers on the HTTP extension (`http.request_headers`) and forwards what comes back on the modified extensions: `result.modified_extensions["http"]` in Python, `ModifiedExtensions` on the Go result. The `http:` route level is Rust only; see [HTTP Routing]({{< relref "/docs/http-routing" >}}).

## Trust model

Nothing that crosses either boundary is signed. An upstream that reads `x-auth-user-id` trusts it because it trusts the network path, not because it can verify anything. If nothing on that path stops a client from setting the header, this feature does not fix that.

That is why removal is unconditional. Every header an entry targets is removed before injection, whether or not its source resolved. Otherwise a missing claim would leave the client's own value in place under a name the upstream reads as the gateway's.

## An entry

```yaml
headers:
  - name: x-auth-user-id     # the target header
    from: subject.id         # one source
    on_missing: deny         # or `omit`, the default

  - name: x-auth-scope
    from: claim.projects
    encode: csv              # required: the source is a collection

  - name: x-auth-attributes  # one JSON object, keys you choose
    members:
      roles:    subject.roles
      projects: claim.projects
```

`from:` and `members:` are alternatives; an entry with both fails to load. A `members:` entry always renders as a JSON object, so `encode:` on it fails to load too.

`encode:` says how a value that is not a scalar becomes one header value. `json` renders every value as JSON, so a string renders quoted. `csv` joins an array with commas. With neither, a scalar renders bare and a structured value renders as compact JSON. A source that is always a collection, such as `subject.roles`, must declare one.

Collections render sorted, and a members object's keys are sorted, so one identity produces the same header bytes on every request. A rendered value with CR, LF or NUL is dropped instead of emitted: claims come from a provider and can carry attacker input.

## Sources

```text
subject.id  subject.type  subject.roles  subject.teams  subject.permissions
claim.<name>
client.client_id  client.client_name  client.trust_level  client.roles
client.permissions  client.teams  client.authorized_scopes
client.authorized_audiences  client.claim.<name>
```

A claim name is taken whole, so a name with dots needs no escaping. A bare `claim` names the whole map and is refused.

These can never be a source, in either direction:

```text
raw_credentials.*          the inbound bearer tokens, before validation
http.request_headers.*     the client's own request headers
http.response_headers.*    the upstream's own response headers
```

Copying a client header into a header the upstream trusts is the laundering this feature exists to stop. The request line and status (`http.method`, `http.path`, `http.host`, `http.scheme`, `http.status`) are refused as well, as paths outside the grammar.

## Removal

**Automatic removal.** Every header an entry targets is removed from the wire map before injection: the client's request in the request direction, the upstream's response in the response direction. It happens whether or not `strip:` exists and whether or not the source resolved. It also stops an upstream echoing an asserted header back to the client.

**`strip:`.** Removes names no entry targets. It takes header names and trailing-glob patterns, matched case-insensitively. Every level's entries apply, so a lower level cannot undo an inherited removal by leaving it out.

Removal and injection are one replacement of the header map, so a client value and an asserted one never exist side by side.

## The two directions differ

`request:` can withhold anything it does not name, because the engine produces every value it asserts.

`response:` cannot. A response is the upstream's own output, and removing everything unnamed would drop `content-type`, `content-length`, caching, CORS, rate-limit and tracing headers. A response header nothing names reaches the client unchanged. `strip:` works the same in both directions.

## Protocol floor

Each direction has a fixed set of headers that `strip:` can never remove, because the recipient needs them to read the message. A `strip:` entry that would remove one fails at load and names the header. A `headers:` entry that targets a floor header is refused too.

- **Request floor:** `host`, `content-type`, `content-length`, `transfer-encoding`. `authorization` is not in it, so you can strip the client's bearer before forwarding to an upstream that gets a delegated credential.
- **Response floor:** content negotiation and framing, caching and conditional requests, retry signalling, and the CORS response set. `set-cookie`, `server` and `x-powered-by` are not in it.

`strip: ["*"]` fails to load in either direction.

## Four levels that stack

A contract can be written at any of four levels, and they accumulate the way `authentication:` does:

1. `global:`
2. `global.defaults.<entity>:`, for `tool`, `resource`, `prompt`, `llm` or `http`
3. `groups.<name>:`
4. a `routes[]` entry

Resolution runs per direction, so a level can declare one direction and inherit the other. An entity default covers every request of that type, including one that matched no route.

`headers:` unions by target name, compared case-insensitively. A repeated name takes the more specific level's entry whole. `strip:` unions. Two groups on one route asserting the same header in the same direction is a load error that names the route, direction, header and both groups.

### Opting out

```yaml
routes:
  - tool: analytics.*
    assertions:
      request:
        replace_inherited: true
        headers:
          - name: x-auth-user-id
            from: subject.id
```

`replace_inherited: true` drops what accumulated above that level, for that direction only. It reaches `headers:` and `strip:` content you wrote and nothing else: automatic removal, the source exclusions and the floor still apply. On a route it is silent. On a group or an entity default it is reported at load, naming every route that lost inherited content.

## When the contract applies

The direction comes from the hook's phase. A pre-phase hook such as `cmf.tool_pre_invoke` applies `request:`, a post-phase hook such as `cmf.tool_post_invoke` applies `response:`, and other hooks apply neither.

The contract runs after that phase's policy, so a rule still sees the client's headers unchanged. A rule that reads `http.request_headers.x-auth-user-id` is reading the client's value, not an asserted one.

When a plugin denied the request, the request direction still removes what it names and injects nothing, and the response direction does not run.

## Example from Python

```yaml
global:
  assertions:
    request:
      headers:
        - name: x-auth-user-id
          from: subject.id
      strip: [authorization]
routes:
  - tool: get_compensation
    authorization:
      pre_invocation:
        - "allow"
```

```python
ext = {
    "meta": {"entity_type": "tool", "entity_name": "get_compensation"},
    "security": {"subject": {"id": "alice"}},
    "http": {"request_headers": {
        "authorization": "Bearer abc",
        "x-auth-user-id": "mallory",
        "accept": "json",
    }},
}
result = await engine.invoke_hook("cmf.tool_pre_invoke", payload, ext)
result.modified_extensions["http"]["request_headers"]
# {'x-auth-user-id': 'alice', 'accept': 'json'}
```

The client's forged `x-auth-user-id` is replaced, `authorization` is stripped, and `accept` passes through.

## Reading the effective policy

When a block is configured, the engine logs the whole boundary as one document at `info`. A Rust host can also get it from `cpex::praxis_policy_core::assertions::effective_policy` and expose it. It lists every header that can be emitted with its source and gating capability, the removal set, the exclusions and the floor, and the accumulated contract per route with the level each header came from.

## Go deeper

- PPE's [assertions wire contract](https://github.com/praxis-proxy/policy/blob/v0.5.0/docs/content/assertions.md), the source for this page. It also covers nested dispatch through `invoke_entries` and the `http:` route obligations in detail.
- [Identity & Delegation]({{< relref "/docs/identity-delegation" >}}): where the subject, client and claims come from.
- [Deployment]({{< relref "/docs/deployment" >}}): where the boundary sits.
