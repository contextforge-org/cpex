# CPEX Go — Public API Specification

**Status**: Draft
**Date**: May 2026
**Source**: `github.com/contextforge-org/contextforge-plugins-framework/go/cpex`

CPEX Go is the Golang consumption API for the ContextForge Plugin Extension Framework (CPEX). It embeds the Rust plugin runtime in-process via CGo/FFI, providing Go host systems with a high-performance hook-based extensibility layer. Payloads and extensions cross the FFI boundary as MessagePack bytes; plugin execution happens entirely in the Rust async runtime.

## 1. Architecture

```
┌──────────────────────────────────────────────────────┐
│  Go Host (e.g., AuthBridge)                          │
│                                                      │
│   PluginManager  ───────────────────────────────┐    │
│   │  NewPluginManager[Default]()                │    │
│   │  RegisterFactories(fn)                      │    │
│   │  LoadConfig(yaml)                           │    │
│   │  Initialize()                               │    │
│   │  InvokeByName(hook, payload, ext, ctx)      │    │
│   │  Invoke[P](hook, payload, ext, ctx)         │    │
│   │  HasHooksFor(hook) / PluginCount()          │    │
│   │  Shutdown()                                 │    │
│   └─────────────────────────────────────────────┘    │
│                        │ CGo / MessagePack           │
├────────────────────────┼─────────────────────────────┤
│  libcpex_ffi (Rust)    ▼                             │
│   cpex_manager_new / cpex_invoke / cpex_shutdown     │
│   ┌─────────────────────────────────────────────┐    │
│   │  cpex-core (Rust)                           │    │
│   │  • PluginManager → Executor → Plugins       │    │
│   │  • tokio runtime (async plugin execution)   │    │
│   │  • Phase ordering, capability gating        │    │
│   │  • Route resolution, policy composition     │    │
│   └─────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────┘
```

**Key design decisions:**

- Plugins are written in Rust (native) and compiled into `libcpex_ffi`. The Go layer is the host embedding API, not a plugin authoring API.
- The FFI boundary uses MessagePack for payloads/extensions and opaque handles for stateful objects (ContextTable, BackgroundTasks).
- All `PluginManager`s in a process share a single tokio runtime (process-singleton via `OnceLock`). Async plugin execution works from synchronous CGo calls without exploding thread count under multi-tenant hosts. Worker thread count is configurable — see §5.8.

## 2. Package & Import

```go
import cpex "github.com/contextforge-org/contextforge-plugins-framework/go/cpex"
```

**Dependencies:**

| Dependency | Purpose |
|---|---|
| `github.com/vmihailenco/msgpack/v5` | MessagePack serialization across FFI |

**Build requirements:**

```bash
# Build the Rust FFI library first
cargo build --release -p cpex-ffi

# Then build/test Go code
go test -v ./...
```

CGo links against `libcpex_ffi` from `target/release/`.

## 3. Lifecycle

```
[ConfigureRuntime(N)]       ← optional, package-level, before any manager
        │
        ▼
NewPluginManagerDefault()
        │
        ▼
RegisterFactories(fn)       ← register Rust plugin factories via callback
        │
        ▼
LoadConfig(yaml)            ← YAML with plugin definitions, routing, policies
        │
        ▼
Initialize()                ← instantiate and wire all plugins
        │
        ▼
InvokeByName / Invoke[P]   ← dispatch hooks (repeatable)
        │
        ▼
Shutdown()                  ← graceful teardown
```

## 4. Quick Reference

| Operation | Method |
|---|---|
| Configure runtime (optional) | `cpex.ConfigureRuntime(workerThreads)` |
| Create manager | `NewPluginManagerDefault()` or `NewPluginManager(yaml)` |
| Register factories | `mgr.RegisterFactories(fn)` |
| Load config | `mgr.LoadConfig(yaml)` |
| Initialize | `mgr.Initialize()` |
| Query lifecycle | `mgr.IsInitialized()` |
| Check hooks exist | `mgr.HasHooksFor(hookName)` |
| Count plugins | `mgr.PluginCount()` |
| List plugins | `mgr.PluginNames()` |
| Invoke (untyped) | `mgr.InvokeByName(hook, type, payload, ext, ctx)` |
| Invoke (typed) | `Invoke[P](mgr, hook, type, payload, ext, ctx)` |
| Check denial | `result.IsDenied()` |
| Get violation | `result.Violation` |
| Get pipeline errors | `result.Errors` (from `on_error: ignore`/`disable` plugins) |
| Thread context | Pass returned `*ContextTable` to next invoke |
| Wait background | `bg.Wait()` returns `([]PluginError, error)` |
| Release background | `bg.Close()` |
| Classify error | `errors.Is(err, ErrCpexTimeout)` (and other sentinels — §14) |
| Shutdown | `mgr.Shutdown()` |

## 5. Core Types

### 5.1 PluginManager

The top-level object. Owns the Rust runtime and plugin registry.

```go
type PluginManager struct { /* opaque CGo handle, sync.RWMutex */ }

// Construction
func NewPluginManager(yaml string) (*PluginManager, error)
func NewPluginManagerDefault() (*PluginManager, error)

// Factory registration
func (m *PluginManager) RegisterFactories(fn FactoryRegistrar) error

// Configuration
func (m *PluginManager) LoadConfig(yaml string) error

// Initialization
func (m *PluginManager) Initialize() error

// Query
func (m *PluginManager) HasHooksFor(hookName string) bool
func (m *PluginManager) PluginCount() int
func (m *PluginManager) IsInitialized() bool
func (m *PluginManager) PluginNames() ([]string, error)

// Invocation
func (m *PluginManager) InvokeByName(
    hookName string,
    payloadType uint8,
    payload any,
    extensions *Extensions,
    contextTable *ContextTable,
) (*PipelineResult, *ContextTable, *BackgroundTasks, error)

// Typed invocation (generics)
func Invoke[P any](
    m *PluginManager,
    hookName string,
    payloadType uint8,
    payload P,
    extensions *Extensions,
    contextTable *ContextTable,
) (*TypedPipelineResult[P], *ContextTable, *BackgroundTasks, error)

// Teardown
func (m *PluginManager) Shutdown()
```

**Notes:**
- `NewPluginManager(yaml)` creates the manager AND loads config in one call (factories auto-registered).
- `NewPluginManagerDefault()` creates an empty manager — call `RegisterFactories` then `LoadConfig` separately.
- A Go finalizer calls `Shutdown()` if the caller forgets, but explicit `Shutdown()` is recommended.
- The `PluginManager` wrapper holds a `sync.RWMutex` so `Shutdown()` cannot race with concurrent `Invoke*` calls; Operation methods take the read lock, lifecycle methods take the write lock.
- `PluginNames()` returns the registered plugin names in registration order (no guaranteed sort).

### 5.2 FactoryRegistrar

```go
type FactoryRegistrar func(handle unsafe.Pointer) error
```

A callback that receives the raw C manager handle. The caller uses this to invoke their own `extern "C"` factory registration function. This is the bridge for registering custom Rust plugin factories that are compiled into a separate shared library.

**Example:**

```go
/*
#include <stdlib.h>
int my_register_factories(void* mgr);
*/
import "C"

err := mgr.RegisterFactories(func(handle unsafe.Pointer) error {
    rc := C.my_register_factories(handle)
    if rc != 0 {
        return fmt.Errorf("factory registration failed: %d", rc)
    }
    return nil
})
```

### 5.3 ContextTable

```go
type ContextTable struct { /* opaque CGo handle */ }
func (ct *ContextTable) Close()
```

Per-plugin state that persists across hook invocations within a single request. Thread the returned `ContextTable` from one `Invoke` call into the next to maintain plugin-local context.

- Pass `nil` on the first invocation.
- After use, the handle is consumed by the next `Invoke` call (ownership transfers to Rust).
- Call `Close()` to release without further use.

### 5.4 BackgroundTasks

```go
type BackgroundTasks struct { /* opaque CGo handle */ }
func (bg *BackgroundTasks) Wait() ([]PluginError, error)
func (bg *BackgroundTasks) Close()
```

Handle to fire-and-forget tasks spawned by plugins (e.g., async audit logging). Tasks run in the shared Rust tokio runtime outside the request's latency budget.

- `Wait()` blocks until all background tasks complete. Returns a structured `[]PluginError` from any that failed (typed shape — `PluginName`, `Code`, `Message`, etc.; see §5.7) plus an `error` for FFI-level failures (e.g., the manager was shut down between invoke and wait — returns `ErrCpexInvalidHandle`).
- `Close()` releases the handle without waiting — tasks continue running.
- The handle holds a `*PluginManager` reference and checks `mgr.handle != nil` under the manager's lock before calling into Rust, so `Wait()` after `Shutdown()` is safe (returns `ErrCpexInvalidHandle` rather than dereferencing freed memory).

### 5.5 PipelineResult

```go
type PipelineResult struct {
    ContinueProcessing bool
    Violation          *PluginViolation
    Metadata           map[string]any
    PayloadType        uint8
    ModifiedPayload    []byte           // raw MessagePack
    ModifiedExtensions []byte           // raw MessagePack
    Errors             []PluginError    // see §5.7
}

func (r *PipelineResult) IsDenied() bool
func (r *PipelineResult) DeserializeExtensions() (*Extensions, error)
func DeserializePayload[T any](result *PipelineResult) (*T, error)
```

`Errors` carries structured records for failures from plugins that ran with `on_error: ignore` or `on_error: disable` — previously these were only logged and invisible to callers. Use them to drive retry logic, dashboards, or audit trails. See §13.6 for the consumption pattern, and §5.7 for the synthetic FFI-layer record.

### 5.6 TypedPipelineResult

```go
type TypedPipelineResult[P any] struct {
    ContinueProcessing bool
    Violation          *PluginViolation
    Metadata           map[string]any
    PayloadType        uint8
    ModifiedPayload    *P
    ModifiedExtensions *Extensions
    Errors             []PluginError
}

func (r *TypedPipelineResult[P]) IsDenied() bool
```

The typed invoke path (`Invoke[P]`) automatically deserializes the modified payload and extensions into concrete Go types. `Errors` is the same shape as `PipelineResult.Errors`.

### 5.7 PluginError

```go
type PluginError struct {
    PluginName     string         `msgpack:"plugin_name"`
    Message        string         `msgpack:"message"`
    Code           string         `msgpack:"code,omitempty"`
    Details        map[string]any `msgpack:"details,omitempty"`
    ProtoErrorCode *int64         `msgpack:"proto_error_code,omitempty"`
}
```

Structured plugin failure record. Used by `PipelineResult.Errors`, `TypedPipelineResult[P].Errors`, and `BackgroundTasks.Wait()`. All entries are framework-emitted — plugins influence the record (via the error they return) but cannot forge `PluginName`, which is set by the executor from the registered plugin metadata.

**Reserved synthetic plugin names:**

| `PluginName` | Source |
|---|---|
| `<ffi>` | Framework-emitted at the FFI boundary. Currently issued when a plugin's modified payload cannot be re-serialized across the wire (`Code: "ffi_serialize_error"`). The rest of the result remains valid; the failure is surfaced via `Errors` rather than failing the whole call. |

Filter or branch by `PluginName == "<ffi>"` if your host wants to distinguish FFI-layer failures from plugin-emitted failures.

### 5.8 PluginViolation

```go
type PluginViolation struct {
    Code           string
    Reason         string
    Description    string
    Details        map[string]any
    PluginName     string
    ProtoErrorCode *int64
}
```

Structured denial. `Code` is a machine-readable identifier; `Reason` is a short human-readable explanation.

### 5.9 ConfigureRuntime (package-level)

```go
func ConfigureRuntime(workerThreads int) error
```

Sets the worker thread count for the shared tokio runtime that backs every `PluginManager` in the process. **Must** be called before the first `NewPluginManager*` — once a manager has been created the runtime is fixed for process lifetime.

```go
// In main(), before any manager construction:
if err := cpex.ConfigureRuntime(8); err != nil {
    log.Fatal(err)  // returns ErrCpexInvalidInput on <=0 or after init
}
```

**Precedence (highest first):**

1. `ConfigureRuntime(N)` — explicit FFI call, before first use.
2. `CPEX_FFI_WORKER_THREADS` env var — operator-friendly default. Read once on lazy init.
3. tokio default (`num_cpus`) — when neither knob is set.

Use case: multi-tenant hosts that want to bound total worker threads regardless of how many `PluginManager`s are alive (one per tenant, dynamic plugin reload, etc.). Without this knob, N managers × `num_cpus` workers each can blow up the OS thread count.

## 6. Extensions

Extensions carry capability-gated metadata alongside the payload. Each plugin sees only the extensions its declared capabilities grant. Serialized as MessagePack across the FFI boundary.

```go
type Extensions struct {
    Meta       *MetaExtension
    Security   *SecurityExtension
    Http       *HttpExtension
    Delegation *DelegationExtension
    Agent      *AgentExtension
    Request    *RequestExtension
    MCP        *MCPExtension
    Completion *CompletionExtension
    Provenance *ProvenanceExtension
    LLM        *LLMExtension
    Framework  *FrameworkExtension
    Custom     map[string]any
}
```

### 6.1 Extension Types

| Extension | Purpose | Key Fields |
|---|---|---|
| `Meta` | Entity identification for route resolution | `EntityType`, `EntityName`, `Tags`, `Scope`, `Properties` |
| `Security` | Identity, labels, data policies | `Subject`, `Agent`, `Labels`, `Classification`, `AuthMethod`, `Objects`, `Data` |
| `Http` | HTTP request/response context | `RequestHeaders`, `ResponseHeaders` |
| `Delegation` | Token delegation chain | `Chain[]`, `Depth`, `OriginSubjectID`, `ActorSubjectID` |
| `Agent` | Agent execution context | `Input`, `SessionID`, `ConversationID`, `Turn` (`*uint32`), `AgentID`, `ParentAgentID`, `Conversation` (`*ConversationContext`) |
| `Request` | Execution environment and tracing | `Environment`, `RequestID`, `TraceID`, `SpanID`, `Timestamp` |
| `MCP` | MCP entity metadata | `Tool`, `Resource`, `Prompt` |
| `Completion` | LLM completion stats | `StopReason`, `Tokens`, `Model`, `RawFormat`, `CreatedAt`, `LatencyMs` |
| `Provenance` | Origin and message threading | `Source`, `MessageID`, `ParentID` |
| `LLM` | Model identity | `ModelID`, `Provider`, `Capabilities` |
| `Framework` | Agentic framework context | `Framework`, `FrameworkVersion`, `NodeID`, `GraphID` |
| `Custom` | Arbitrary key-value pairs | `map[string]any` |

### 6.2 Security Extension Detail

```go
type SecurityExtension struct {
    Labels         []string
    Classification string
    Subject        *SubjectExtension    // authenticated caller
    Agent          *AgentIdentity       // this agent's workload identity
    AuthMethod     string
    Objects        map[string]ObjectSecurityProfile
    Data           map[string]DataPolicy
}

type SubjectExtension struct {
    ID, SubjectType string
    Roles, Permissions, Teams []string
    Claims map[string]string
}

type AgentIdentity struct {
    ClientID, WorkloadID, TrustDomain string
}
```

### 6.3 Delegation Extension Detail

```go
type DelegationExtension struct {
    Chain           []DelegationHop
    Depth           int
    OriginSubjectID string
    ActorSubjectID  string
    Delegated       bool
    AgeSeconds      float64
}

type DelegationHop struct {
    SubjectID, SubjectType, Audience, Strategy, Timestamp string
    ScopesGranted []string
    TTLSeconds    *uint64
    FromCache     bool
}
```

### 6.4 Capability-Gated Writes (Rust Plugin Side)

The `capabilities` list in a plugin's YAML config controls which extension fields the plugin can read **and** write. The Rust executor translates declared capabilities into write tokens before calling `Plugin::handle`. A plugin that lacks `write_headers`, for example, receives `http_write_token: None` and cannot modify `HttpExtension`.

The Rust write pattern uses COW (copy-on-write) ownership:

```rust
// In Plugin::handle — capability-gated extension modification
let mut owned = extensions.cow_copy();          // clone mutable slots

if let Some(ref token) = owned.http_write_token {  // token present iff capability declared
    if let Some(http) = owned.http.as_mut() {
        let h = http.write(token);
        h.set_response_header("X-Tool-Name", name);
        h.set_response_header("X-CPEX-Processed", "true");
    }
}

PluginResult::modify_extensions(owned)          // emit modified extensions back to Go
```

On the Go side, `result.ModifiedExtensions` (or `typed.ModifiedExtensions`) carries the updated extensions returned by the plugin. The Go caller can deserialize them with `result.DeserializeExtensions()` (see §13.3).

**Rust `PluginResult` constructors:**

| Constructor | What it signals |
|---|---|
| `PluginResult::allow()` | Pass, no changes |
| `PluginResult::deny(violation)` | Halt pipeline, return violation to Go |
| `PluginResult::modify_extensions(owned)` | Pass, return modified extensions |
| `PluginResult::modify_payload(payload)` | Pass, return modified payload |

## 7. Payload Types

### 7.1 Payload Type Registry

CPEX uses a `payloadType` discriminator to tell the Rust core how to deserialize the payload:

| Constant | Value | Payload Type |
|---|---|---|
| `PayloadGeneric` | `0` | `map[string]any` — untyped JSON-like payload |
| `PayloadCMFMessage` | `1` | `MessagePayload` — CMF message |

Hosts define their own payload structs (e.g., `InboundPreValidationPayload`) and serialize them as `PayloadGeneric`. The type ID tells Rust how to deserialize; Go callers choose the ID and matching struct.

### 7.2 Generic Payload

Any `map[string]any` or struct with msgpack tags. Serialized as MessagePack, deserialized in Rust as a `serde_json::Value`.

```go
payload := map[string]any{
    "tool_name": "get_compensation",
    "user":      "alice",
}
result, ct, bg, err := mgr.InvokeByName("tool_pre_invoke", cpex.PayloadGeneric, payload, ext, nil)
```

### 7.3 CMF MessagePayload

The ContextForge Message Format — a typed, multi-part message with schema versioning.

```go
type MessagePayload struct {
    Message Message `msgpack:"message"`
}

type Message struct {
    SchemaVersion string        `msgpack:"schema_version"`
    Role          string        `msgpack:"role"`
    Content       []ContentPart `msgpack:"content"`
    Channel       string        `msgpack:"channel,omitempty"`
}

func NewMessage(role string, content ...ContentPart) Message
```

### 7.4 Content Parts

`ContentPart` is a tagged union discriminated by `content_type`. Custom msgpack encoding produces the same wire format as Rust's `#[serde(tag = "content_type")]`.

| Content Type | Constructor | Data Field |
|---|---|---|
| `text` | `NewTextPart(s)` | `.Text` |
| `thinking` | `NewThinkingPart(s)` | `.Text` |
| `tool_call` | `NewToolCallPart(tc)` | `.ToolCallContent` |
| `tool_result` | `NewToolResultPart(tr)` | `.ToolResultContent` |
| `resource` | `NewResourcePart(r)` | `.ResourceContent` |
| `resource_ref` | `NewResourceRefPart(r)` | `.ResourceRefContent` |
| `prompt_request` | `NewPromptRequestPart(pr)` | `.PromptRequestContent` |
| `prompt_result` | `NewPromptResultPart(pr)` | `.PromptResultContent` |
| `image` | `NewImagePart(img)` | `.ImageContent` |
| `video` | `NewVideoPart(vid)` | `.VideoContent` |
| `audio` | `NewAudioPart(aud)` | `.AudioContent` |
| `document` | `NewDocumentPart(doc)` | `.DocumentContent` |

Constructors follow Go's `NewXyz` convention so they don't shadow the like-named struct fields on `ContentPart` (e.g., the `ToolCallContent *ToolCall` field vs the `NewToolCallPart` constructor).

Unknown `content_type` discriminators are preserved on decode via an internal `rawMap` and re-emitted unchanged on encode — so a Go host running an older SDK against a newer Rust runtime won't silently drop content parts it doesn't recognize.

**Example:**

```go
msg := cpex.MessagePayload{
    Message: cpex.NewMessage("assistant",
        cpex.NewTextPart("Looking up compensation data"),
        cpex.NewToolCallPart(cpex.ToolCall{
            ToolCallID: "tc_001",
            Name:       "get_compensation",
            Arguments:  map[string]any{"employee_id": 42},
        }),
    ),
}

result, ct, bg, err := cpex.Invoke[cpex.MessagePayload](
    mgr, "cmf.tool_pre_invoke", cpex.PayloadCMFMessage, msg, ext, nil,
)
```

## 8. Hook Types (Built-in)

Hooks are open strings — hosts define their own. The following are built into `cpex-core`:

### 8.1 Legacy Hooks (typed payloads)

| Hook Name | Lifecycle Stage |
|---|---|
| `tool_pre_invoke` | Before tool execution |
| `tool_post_invoke` | After tool execution |
| `prompt_pre_fetch` | Before prompt template fetch |
| `prompt_post_fetch` | After prompt template fetch |
| `resource_pre_fetch` | Before resource fetch |
| `resource_post_fetch` | After resource fetch |
| `identity_resolve` | Identity resolution |
| `token_delegate` | Token delegation |

### 8.2 CMF Hooks (MessagePayload)

| Hook Name | Lifecycle Stage |
|---|---|
| `cmf.tool_pre_invoke` | Before tool execution (CMF message) |
| `cmf.tool_post_invoke` | After tool execution (CMF message) |
| `cmf.llm_input` | Before LLM call |
| `cmf.llm_output` | After LLM response |
| `cmf.prompt_pre_fetch` | Before prompt fetch (CMF) |
| `cmf.prompt_post_fetch` | After prompt fetch (CMF) |
| `cmf.resource_pre_fetch` | Before resource fetch (CMF) |
| `cmf.resource_post_fetch` | After resource fetch (CMF) |

### 8.3 Custom Hooks

Hosts register their own hook names. Any string works:

```go
mgr.InvokeByName("inbound.pre_validation", cpex.PayloadGeneric, payload, ext, nil)
mgr.InvokeByName("outbound.pre_exchange", cpex.PayloadGeneric, payload, ext, nil)
```

## 9. Plugin Configuration (YAML)

Plugins are declared in YAML and loaded via `LoadConfig`. The YAML is parsed by the Rust core.

```yaml
plugin_settings:
  routing_enabled: true
  plugin_timeout: 30

global:
  policies:
    all:
      plugins: [identity-checker]
    pii:
      plugins: [pii-guard]

plugins:
  - name: identity-checker
    kind: builtin/identity
    hooks: [tool_pre_invoke, tool_post_invoke]
    mode: sequential
    priority: 10
    on_error: fail

  - name: pii-guard
    kind: builtin/pii
    hooks: [tool_pre_invoke]
    mode: sequential
    priority: 20
    on_error: fail
    capabilities:
      - read_labels
      - read_subject

  - name: audit-logger
    kind: builtin/audit
    hooks: [tool_pre_invoke, tool_post_invoke]
    mode: fire_and_forget
    priority: 100
    on_error: ignore

  - name: header-injector
    kind: builtin/cmf-header-injector
    hooks: [cmf.tool_pre_invoke, cmf.tool_post_invoke]
    mode: sequential
    priority: 50
    on_error: ignore
    capabilities:
      - read_headers
      - write_headers

routes:
  # Tool-specific route — tags applied to all invocations of this tool
  - tool: get_compensation
    meta:
      tags: [pii, hr]
    plugins:
      - audit-logger

  - tool: list_departments
    plugins:
      - audit-logger

  # Wildcard route — applies to all tools not matched above
  - tool: "*"
    plugins:
      - audit-logger
```

### 9.1 Plugin Modes

| Mode | Behavior |
|---|---|
| `sequential` | Serial execution, can block (deny) AND modify payload |
| `transform` | Serial execution, can modify payload but cannot block |
| `audit` | Serial execution, read-only (no modify, no block) |
| `concurrent` | Parallel execution, can block but cannot modify |
| `fire_and_forget` | Background execution, non-blocking, runs after pipeline completes |
| `disabled` | Plugin loaded but not executed |

### 9.2 Error Handling (`on_error`)

| Value | Behavior |
|---|---|
| `fail` | Halt pipeline, propagate error to caller |
| `ignore` | Log error, continue pipeline |
| `disable` | Log error, disable plugin for remaining lifetime, continue |

### 9.3 Plugin Capabilities

The optional `capabilities` list controls which extension fields a plugin can read and write. The Rust executor passes write tokens only for declared capabilities; undeclared extension slots arrive as `None` in the plugin's `handle()` call.

| Capability | Extensions access granted |
|---|---|
| `read_labels` | `SecurityExtension.labels` (read) |
| `read_subject` | `SecurityExtension.subject` (read) |
| `read_headers` | `HttpExtension.request_headers` (read) |
| `write_headers` | `HttpExtension.response_headers` (read + write token) |

Capabilities declared in YAML are enforced at the Rust core level — a plugin cannot write to extensions it did not declare. See §6.4 for the Rust-side write pattern.

### 9.4 Routes

Routes match invocations by tool name and apply additional plugin overrides or tag injection. Evaluated in order; first match wins. The `"*"` wildcard matches any tool not matched by an earlier route.

```yaml
routes:
  # Exact match — injects meta tags for this tool's invocations
  - tool: get_compensation
    meta:
      tags: [pii, hr]
    plugins:
      - audit-logger

  # Exact match — no meta tags
  - tool: list_departments
    plugins:
      - audit-logger

  # Wildcard — catch-all for remaining tools
  - tool: "*"
    plugins:
      - audit-logger
```

The `meta.tags` field under a route entry augments (or sets) the `MetaExtension.Tags` seen by plugins for that tool, enabling tag-based policy groups to trigger without requiring the Go caller to set tags on every invocation.

## 10. Integration Pattern

The canonical integration pattern for a Go host:

```go
package main

import (
    "fmt"
    "os"
    "unsafe"

    cpex "github.com/contextforge-org/contextforge-plugins-framework/go/cpex"
)

/*
// macOS: add -framework CoreFoundation -framework Security
// Linux: -lm -ldl -lpthread are sufficient
#cgo LDFLAGS: -L${SRCDIR}/../../target/release -lmy_plugins_ffi -lm -ldl -lpthread
#include <stdlib.h>
int my_register_factories(void* mgr);
*/
import "C"

func main() {
    // 1. Create manager
    mgr, err := cpex.NewPluginManagerDefault()
    if err != nil {
        panic(err)
    }
    defer mgr.Shutdown()

    // 2. Register custom plugin factories
    if err := mgr.RegisterFactories(func(handle unsafe.Pointer) error {
        if C.my_register_factories(handle) != 0 {
            return fmt.Errorf("factory registration failed")
        }
        return nil
    }); err != nil {
        panic(err)
    }

    // 3. Load configuration
    yaml, err := os.ReadFile("plugins.yaml")
    if err != nil {
        panic(err)
    }
    if err := mgr.LoadConfig(string(yaml)); err != nil {
        panic(err)
    }

    // 4. Initialize plugins
    if err := mgr.Initialize(); err != nil {
        panic(err)
    }

    // 5. Invoke hooks in the request lifecycle
    ext := &cpex.Extensions{
        Meta: &cpex.MetaExtension{
            EntityType: "tool",
            EntityName: "get_compensation",
            Tags:       []string{"pii"},
        },
        Security: &cpex.SecurityExtension{
            Subject: &cpex.SubjectExtension{
                ID:    "user-123",
                Roles: []string{"analyst"},
            },
        },
    }

    result, ct, bg, err := mgr.InvokeByName(
        "tool_pre_invoke", cpex.PayloadGeneric,
        map[string]any{"tool_name": "get_compensation", "user": "alice"},
        ext, nil,
    )
    if err != nil {
        panic(err)
    }

    if result.IsDenied() {
        fmt.Printf("Denied: %s [%s]\n", result.Violation.Reason, result.Violation.Code)
        ct.Close()
        bg.Close()
        return
    }

    // 6. Thread context into post-invoke
    result2, ct2, bg2, err := mgr.InvokeByName(
        "tool_post_invoke", cpex.PayloadGeneric,
        map[string]any{"tool_name": "get_compensation", "result": "..."},
        ext, ct, // pass context from pre-invoke
    )
    if err != nil {
        panic(err)
    }
    _ = result2
    bg.Close()
    bg2.Close()
    ct2.Close()
}
```

## 11. Typed Invoke Pattern

For hosts using CMF messages or custom structs with strong typing:

```go
// Define a custom payload type with msgpack tags
type InboundPreValidationPayload struct {
    Path     string `msgpack:"path"`
    Audience string `msgpack:"audience"`
}

// Invoke with type safety
result, ct, bg, err := cpex.Invoke[InboundPreValidationPayload](
    mgr,
    "inbound.pre_validation",
    cpex.PayloadGeneric,    // serialized as generic msgpack
    InboundPreValidationPayload{Path: "/api/v1/users", Audience: "my-api"},
    ext,
    nil,
)
if err != nil { /* handle */ }

// result.ModifiedPayload is *InboundPreValidationPayload (or nil if unmodified)
if result.ModifiedPayload != nil {
    fmt.Println("Modified audience:", result.ModifiedPayload.Audience)
}
```

## 12. Zero-Cost Guard Pattern

Check for registered plugins before constructing payloads:

```go
if !mgr.HasHooksFor("inbound.pre_validation") {
    // No plugins configured — skip payload construction and FFI overhead
    return handleRequestDirectly(req)
}

// Only build payload and extensions if plugins are registered
payload := buildPreValidationPayload(req)
ext := buildExtensions(req)
result, ct, bg, err := mgr.InvokeByName("inbound.pre_validation", ...)
```

This pattern ensures zero cost when no plugins are configured for a hook point.

## 13. Result Handling

### 13.1 Allow/Deny

```go
result, ct, bg, err := mgr.InvokeByName(...)
if result.IsDenied() {
    // Pipeline halted by a plugin
    v := result.Violation
    return denyResponse(v.Code, v.Reason, v.Description)
}
// Proceed with original or modified payload
```

### 13.2 Modified Payload

```go
// Raw path — manual deserialization
if len(result.ModifiedPayload) > 0 {
    modified, err := cpex.DeserializePayload[MyPayload](result)
    // use modified
}

// Typed path — automatic deserialization
typed, ct, bg, err := cpex.Invoke[MyPayload](mgr, hook, payloadType, payload, ext, nil)
if typed.ModifiedPayload != nil {
    // use typed.ModifiedPayload directly
}
```

### 13.3 Modified Extensions

```go
if len(result.ModifiedExtensions) > 0 {
    ext, _ := result.DeserializeExtensions()
    // Plugins may have enriched Security.Subject, added Labels, etc.
}
```

### 13.4 Background Tasks

```go
// Option A: Wait for background tasks (e.g., at request boundary)
bgErrors, err := bg.Wait()
if err != nil {
    // FFI-level failure — e.g., ErrCpexInvalidHandle if the manager
    // was shut down between Invoke and Wait. The handle is still
    // safely consumed; no need to call Close after a Wait error.
    log.Warn("bg.Wait failed:", err)
}
for _, e := range bgErrors {
    log.Warn("background task error: plugin=%s code=%s msg=%s",
        e.PluginName, e.Code, e.Message)
}

// Option B: Fire and forget
bg.Close()
```

### 13.5 Metadata

```go
if result.Metadata != nil {
    // Aggregate metadata from all plugins in the chain
    if decision, ok := result.Metadata["_decision_plugin"]; ok {
        log.Info("decided by:", decision)
    }
}
```

### 13.6 Pipeline Errors (ignore / disable)

When a plugin fails and its `on_error` mode is `ignore` or `disable`, the pipeline continues and the failure is recorded in `result.Errors` rather than halting via `result.Violation`. This is the canonical surface for non-fatal plugin errors that callers may still want to act on.

```go
result, ct, bg, err := mgr.InvokeByName(...)
if err != nil { /* FFI-level error */ }
if result.IsDenied() { /* halted by a fail/deny plugin */ }

// Pipeline ran to completion. Inspect any soft errors.
for _, e := range result.Errors {
    if e.PluginName == "<ffi>" {
        // Framework-emitted — e.g., the modified payload couldn't be
        // re-serialized across the FFI boundary. The rest of the
        // result is still valid; the plugin's modification was
        // dropped.
        metrics.Inc("cpex.ffi_serialize_error")
    } else {
        // Plugin-attributed — the plugin failed but ran with
        // on_error: ignore/disable, so we got here. Code is the
        // plugin's machine-readable identifier.
        log.Warn("plugin %s failed [%s]: %s", e.PluginName, e.Code, e.Message)
    }
}
```

Note that `result.Errors` is *separate* from `result.Violation` — a violation halts the pipeline (no further plugins run); errors recorded here mean the pipeline kept going.

## 14. Error Handling

CPEX Go classifies errors via typed sentinels. Use `errors.Is(err, ErrCpexX)` rather than string-matching `err.Error()` — the message text is not part of the API.

### 14.1 Sentinels

```go
var (
    // ErrCpexInvalidHandle: the manager handle is null or the
    // manager was shut down. Returned when calling methods on a
    // shut-down manager, or when BackgroundTasks.Wait runs after
    // Shutdown.
    ErrCpexInvalidHandle = errors.New("cpex: invalid handle ...")

    // ErrCpexInvalidInput: caller-supplied input was malformed —
    // bad UTF-8 in hookName, payloadType out of range, oversized
    // buffer, etc. Calling code bug.
    ErrCpexInvalidInput  = errors.New("cpex: invalid input")

    // ErrCpexParse: parse / deserialize failed (YAML config,
    // MessagePack payload, MessagePack extensions). Often a wire
    // format mismatch between Go and Rust struct definitions.
    ErrCpexParse         = errors.New("cpex: parse / deserialize failed")

    // ErrCpexPipeline: pipeline / lifecycle step failed —
    // load_config returned Err, initialize returned Err, or a
    // plugin signalled failure during invoke (without timeout or
    // panic). The plugin's structured error is in result.Errors
    // when on_error is ignore/disable.
    ErrCpexPipeline      = errors.New("cpex: pipeline / lifecycle error")

    // ErrCpexSerialize: result serialization failed after the
    // pipeline ran — usually OOM on rmp_serde::to_vec_named, or an
    // unserializable JSON value. Distinct from the per-modified-
    // payload synthetic error in result.Errors (see §5.7).
    ErrCpexSerialize     = errors.New("cpex: result serialize failed")

    // ErrCpexTimeout: the FFI wall-clock timeout (60s) was
    // exceeded. A plugin is likely CPU-bound or blocking the OS
    // thread without yielding. Rust per-plugin timeouts only
    // catch cooperative-async timeouts; this catches the rest.
    ErrCpexTimeout       = errors.New("cpex: wall-clock timeout")

    // ErrCpexPanic: a plugin panicked; caught by catch_unwind at
    // the FFI boundary. Indicates a bug in plugin Rust code.
    ErrCpexPanic         = errors.New("cpex: plugin panicked")
)
```

### 14.2 Classification Pattern

```go
result, ct, bg, err := mgr.InvokeByName(...)
if err != nil {
    switch {
    case errors.Is(err, cpex.ErrCpexTimeout):
        metrics.Inc("cpex.timeout")
        return retryWithBackoff(req)
    case errors.Is(err, cpex.ErrCpexPanic):
        // Plugin bug — log, alert, fail closed.
        metrics.Inc("cpex.panic")
        return denyOnPluginPanic()
    case errors.Is(err, cpex.ErrCpexInvalidHandle):
        // Manager has been shut down — recreate or fail closed.
        return errors.New("plugin runtime offline")
    default:
        // ErrCpexParse / Serialize / Pipeline / InvalidInput —
        // typically caller or config bugs.
        log.Error("cpex invoke:", err)
        return err
    }
}
```

### 14.3 Two error channels

CPEX Go reports failures through two distinct channels, and they have different semantics:

| Channel | Triggers | Meaning |
|---|---|---|
| `error` return value | FFI-level failures (timeout, panic, parse, invalid handle) | The pipeline did not complete usefully — `result` is `nil` |
| `result.Errors` | Plugin failures with `on_error: ignore` or `on_error: disable`; FFI-layer modified-payload serialize failures | The pipeline ran to completion — `result` is valid; treat as soft errors |

A pipeline can return `err == nil`, `result.IsDenied() == false`, AND non-empty `result.Errors`. That means: "everything ran, nothing halted, but here are the things that didn't work." Don't ignore `result.Errors` just because `err` was nil.

## 15. Serialization

All types use `msgpack` struct tags matching Rust field names for zero-copy serialization across the FFI boundary. The wire format is MessagePack with named fields (`rmp_serde::to_vec_named` on the Rust side).

**Rules:**
- Go struct fields map 1:1 to Rust struct fields via `msgpack:"field_name"` tags.
- Optional fields use `omitempty` — nil/zero values are not serialized.
- `ContentPart` uses custom `EncodeMsgpack`/`DecodeMsgpack` for tagged-union encoding.
- Byte slices (`[]byte`) are serialized as MessagePack binary, not arrays.

## 16. Thread Safety

- `PluginManager` is safe for concurrent use from multiple goroutines. The Go wrapper holds a `sync.RWMutex` so concurrent `Invoke*` calls take the read lock while `Shutdown` takes the write lock — preventing a use-after-free if Shutdown lands between an in-flight invoke and its FFI return.
- The Rust core uses `ArcSwap<RuntimeSnapshot>` for the registry — concurrent invokes read a stable snapshot; mutations clone-and-swap. This means an in-flight invoke sees the registry as it was when the invoke started, not as it is mid-call.
- `ContextTable` is NOT safe for concurrent use — it represents per-request state that is threaded sequentially through hook invocations.
- `BackgroundTasks` is safe to call `Wait()` or `Close()` from any goroutine, but only once.

## 17. Gaps and Unimplemented Features

The following features exist in the Python CPEX implementation but are not yet exposed in the Go API. These are tracked for future implementation:

| Feature | Python Location | Status in Go |
|---|---|---|
| `invoke_hook_for_plugin(name, hook, payload)` | `manager.py` | Not implemented — no single-plugin invoke |
| `HookPayloadPolicy` (field-level write control) | `manager.py` / `hooks/policies.py` | Handled in Rust core via plugin capabilities, not configurable from Go |
| `TenantPluginManager` (per-tenant isolation) | `manager.py` | Not implemented — single global manager only (multi-tenant hosts can use one manager per tenant since Pass 9's shared runtime caps total threads) |
| Plugin introspection | `hooks/registry.py` | Partial — `HasHooksFor`, `PluginCount`, `PluginNames`, `IsInitialized` exposed; per-hook plugin lookup is not |
| Observability provider injection | `manager.py` | Not exposed — observability configured in Rust |
| Plugin conditions (runtime skip) | `manager.py` | Handled in Rust core via YAML config (`MatchContext` evaluated against extensions) |
| `OnError.DISABLE` runtime status query | `manager.py` | Not exposed (errors from disabled plugins surface in `result.Errors` though) |
| `reset()` (reinitialize without restart) | `manager.py` | Not implemented — shutdown and recreate |
| Programmatic capability gating | `extensions/tiers.py` | YAML-only — capabilities declared per-plugin in config (§9.3); no runtime API to override or rebind capabilities per-invoke |
| gRPC/Unix/MCP external plugin transports | `framework/external/` | Not yet in Rust core |
| Plugin loader with search paths | `loader/` | Rust uses factory registration instead |
| PDP (AuthZen/OPA) integration | `framework/pdp/` | Not yet in Rust core |
| Isolated (subprocess) plugins | `framework/isolated/` | Not yet in Rust core |
| `retry_delay_ms` in result | `models.py` | Not exposed in FFI result |

## 18. Build & Test

The repo ships a Makefile with the canonical commands. The raw `cargo` / `go` invocations are still listed below for environments without `make`.

### 18.1 Make targets (recommended)

| Target | What it does |
|---|---|
| `make rust-build` / `rust-build-release` | Build Rust workspace (debug / release) |
| `make rust-test` | Full Rust workspace tests |
| `make rust-test-ffi` | Only the cpex-ffi crate tests |
| `make rust-lint-check` | Read-only `cargo fmt --check` + `cargo clippy -- -D warnings` |
| `make rust-lint` (or `rust-lint-fix`) | Mutating: `cargo fmt` + `clippy --fix` |
| `make go-build` | Build the Go cpex package (auto-rebuilds cdylib first) |
| `make go-test` / `go-test-race` | Go tests (with optional race detector) |
| `make go-lint-check` | Read-only `gofmt -l` + `go vet` + `golangci-lint run` |
| `make go-lint` (or `go-lint-fix`) | Mutating: `gofmt -w` + `vet` + `golangci-lint run --fix` |
| `make examples-build` | Build all 4 examples — catches stale public-API usage |
| `make examples-run` | Build + run each example end-to-end |
| `make test-all` | `rust-test` + `go-test-race` (the canonical "everything") |
| `make ci` | `rust-lint-check` + `test-all` + `examples-build` (the CI gate) |

`golangci-lint` is required for `go-lint*`; install with `brew install golangci-lint`.

### 18.2 Raw commands

```bash
# 1. Build the Rust FFI library
cargo build --release -p cpex-ffi

# 2. Run Go tests (links against libcpex_ffi)
cd go/cpex && go test -count=1 -race ./...

# 3. Run the demo (requires demo plugin library)
cd examples/go-demo/ffi && cargo build --release
cd examples/go-demo && go run .

# 4. Run the CMF demo
cd examples/go-demo && go run ./cmd/cmf-demo
```

**Platform notes:**
- macOS: link with `-framework CoreFoundation -framework Security`
- Linux: link with `-lm -ldl -lpthread`
- The `#cgo LDFLAGS` directive in `ffi.go` points to `target/release/`

