# Common Message Format (CMF) Specification

**Version**: 2.0
**Related**: [Plugin Framework Specification](../specs/plugin-framework-spec.md)

## Introduction

The Common Message Format (CMF) defines a **provider-agnostic, structured representation** for interactions between users, agents, tools, and language models.

CMF provides a canonical message model that supports interoperability, policy enforcement, access control, data governance, and end-to-end auditing across heterogeneous model providers and agent frameworks.

The format explicitly separates:

* **Transport** (provider-specific wire protocols)
* **Canonical message representation** (CMF Message)
* **Policy and enforcement surface** (MessageView abstraction)

This separation allows transport adapters, processing pipelines, and policy engines to evolve independently while operating over a consistent enforcement-ready message model.

```mermaid
flowchart LR
    A([Provider Wire Format]) --> B[Adapter]
    B --> C([CMF Message])
    C --> D[Processing Pipeline]
    D --> E([CMF Message])
    E --> F[Adapter]
    F --> G([Wire Format])
```

## Table of Contents

1. [Design Goals](#1-design-goals)
2. [Message](#2-message)
   - 2.1 [Role](#21-role)
   - 2.2 [Content](#22-content)
   - 2.3 [Channel](#23-channel)
3. [Extensions](#3-extensions)
   - 3.1 [Mutability Tiers](#31-mutability-tiers)
   - 3.2 [Extension Types](#32-extension-types)
   - 3.3 [RequestExtension (immutable)](#33-requestextension-immutable)
   - 3.4 [AgentExtension (immutable)](#34-agentextension-immutable)
   - 3.5 [HttpExtension (guarded)](#35-httpextension-guarded)
   - 3.6 [SecurityExtension (monotonic)](#36-securityextension-monotonic)
     - 3.6.1 [SubjectExtension (immutable)](#361-subjectextension-immutable)
     - 3.6.2 [Objects (immutable)](#362-objects-immutable)
     - 3.6.3 [Data (immutable)](#363-data-immutable)
   - 3.7 [MCPExtension (immutable)](#37-mcpextension-immutable)
   - 3.8 [CompletionExtension (immutable)](#38-completionextension-immutable)
   - 3.9 [ProvenanceExtension (immutable)](#39-provenanceextension-immutable)
   - 3.10 [LLMExtension (immutable)](#310-llmextension-immutable)
   - 3.11 [FrameworkExtension (immutable)](#311-frameworkextension-immutable)
   - 3.12 [MetaExtension (monotonic tags, mutable properties)](#312-metaextension-monotonic-tags-mutable-properties)
   - 3.13 [Custom Extensions (mutable)](#313-custom-extensions-mutable)
4. [MessageView](#4-messageview)
   - 4.1 [Message vs. MessageView](#41-message-vs-messageview)
   - 4.2 [Supporting Both LLM and Framework Formats](#42-supporting-both-llm-and-framework-formats)
   - 4.3 [Core Attributes](#43-core-attributes)
   - 4.4 [Direction](#44-direction)
   - 4.5 [Flat Accessors (capability-gated)](#45-flat-accessors-capability-gated)
   - 4.6 [Type-Specific Properties](#46-type-specific-properties)
   - 4.7 [Serialization](#47-serialization)
5. [Security Properties](#5-security-properties)
   - 5.1 [Label Propagation](#51-label-propagation)
   - 5.2 [Extension Tier Enforcement](#52-extension-tier-enforcement)

## 1. Design Goals

The CMF is designed to satisfy the following goals:

* **Interoperable, canonical representation**
  Define a provider-agnostic message format that decouples transport wire protocols from internal processing, enabling consistent handling across LLM providers, agent frameworks, tools, and enforcement systems.

* **Complete and explicit enforcement surface**
  Represent all policy-relevant data—including identity, access control metadata, governance attributes, execution context, and provenance—as structured, typed fields on the message.

* **Integrity and safety by construction**
  Protect security-relevant data through explicit mutability tiers (immutable, monotonic, guarded, mutable) enforced by the processing pipeline, and enable safe read-only inspection for policy evaluation.

* **Extensibility without compromising correctness**
  Support structured extensions while preserving interoperability, enforcement guarantees, and message integrity.

To realize these goals, CMF defines the following abstractions:

| Concept              | Purpose                                                                        |
| -------------------- | ------------------------------------------------------------------------------ |
| **Message**          | Canonical structure representing a single agent interaction.                   |
| **Extensions**       | Structured metadata for identity, security, governance, and execution context. |
| **Mutability Tiers** | Explicit contracts governing how fields may be modified.                       |
| **MessageView**      | Read-only projection providing uniform access for policy evaluation.           |

## 2. Message

A `Message` represents a single turn in a conversation. It has four fields:

```
Message
├── schema_version: str                 # Message schema version
├── role: Role                          # WHO is speaking
├── content: list[ContentPart]          # WHAT they said (multimodal parts)
├── channel: Channel | None             # WHAT KIND of output (analysis, commentary, final)
└── extensions: Extensions              # Everything: context, identity, security, completion, provenance
```

### 2.1 Role

Role is a closed-set enumeration type.

| Role | Meaning |
|------|---------|
| `system` | System-level instructions |
| `developer` | Developer-provided instructions (Harmony concept) |
| `user` | Human user input |
| `assistant` | LLM/agent response |
| `tool` | Tool execution result |

### 2.2 Content

Content is a list of typed `ContentPart`s for multimodal messages.

This is the **wire format**, which preserves the LLM's response grouping. A single assistant message can contain text, thinking, and multiple tool calls, just as the provider API returns them.

**ContentPart:**

Each `ContentPart` must include a `ContentType` type discriminator.

| Attribute | Type | Description |
|-----------|------|-------------|
| `content_type` | `ContentType` | The content type |

**ContentPart types:**

| Content Type | Value Type | Description |
|--------------|------------|-------------|
| `text` | `str` | Plain text content |
| `thinking` | `str` | Chain-of-thought / reasoning (may not be shown to end user) |
| `tool_call` | `ToolCall` | Tool/function invocation request |
| `tool_result` | `ToolResult` | Result from tool execution |
| `resource` | `Resource` | Embedded resource with content (MCP) |
| `resource_ref` | `ResourceReference` | Lightweight resource reference without embedded content |
| `prompt_request` | `PromptRequest` | Prompt template invocation request (MCP) |
| `prompt_result` | `PromptResult` | Rendered prompt template result |
| `image` | `ImageSource` | Image content (URL or base64) |
| `video` | `VideoSource` | Video content (URL or base64) |
| `audio` | `AudioSource` | Audio content (URL or base64) |
| `document` | `DocumentSource` | Document content (PDF, Word, etc.) |

**ToolCall:**

| Attribute | Type | Description |
|-----------|------|-------------|
| `tool_call_id` | `str` | Unique request correlation ID |
| `name` | `str` | Tool name |
| `arguments` | `dict[str, Any]` | Arguments as a JSON-serializable dict |
| `namespace` | `str \| None` | Namespace for namespaced tools |

**ToolResult:**

| Attribute | Type | Description |
|-----------|------|-------------|
| `tool_call_id` | `str` | Correlation ID linking to the corresponding tool call |
| `tool_name` | `str` | Name of the tool that was executed |
| `content` | `JSONValue` | Result content, any JSON-serializable value |
| `is_error` | `bool` | Whether the result represents an error |

**Resource:**

| Attribute | Type | Description |
|-----------|------|-------------|
| `resource_request_id` | `str` | Unique request correlation ID |
| `uri` | `str` | Unique identifier (URI format) |
| `name` | `str \| None` | Human-readable name |
| `description` | `str \| None` | What this resource contains |
| `resource_type` | `ResourceType` | `file`, `blob`, `uri`, `database`, `api`, `memory`, `artifact` |
| `content` | `str \| None` | Text content (if embedded) |
| `blob` | `bytes \| None` | Binary content (if embedded) |
| `mime_type` | `str \| None` | MIME type of content |
| `size_bytes` | `int \| None` | Size information |
| `annotations` | `dict` | Metadata (classification, retention, etc.) |
| `version` | `str \| None` | Version tracking |

**ResourceReference:**

| Attribute | Type | Description |
|-----------|------|-------------|
| `resource_request_id` | `str` | Correlation ID linking to the originating resource request |
| `uri` | `str` | Resource URI |
| `name` | `str \| None` | Human-readable name |
| `resource_type` | `ResourceType` | Type of resource |
| `range_start` | `int \| None` | Line number or byte offset (partial references) |
| `range_end` | `int \| None` | End of range |
| `selector` | `str \| None` | CSS/XPath/JSONPath selector |

**ResourceType:**

`ResourceType` is a closed-set enumeration.

| Value | Description |
|-------|-------------|
| `file` | File-system resource |
| `blob` | Binary large object |
| `uri` | Generic URI-addressable resource |
| `database` | Database entity |
| `api` | API endpoint |
| `memory` | In-memory or ephemeral resource |
| `artifact` | Produced artifact (generated output, build result) |

**PromptRequest:**

| Attribute | Type | Description |
|-----------|------|-------------|
| `prompt_request_id` | `str` | Request ID for correlation |
| `name` | `str` | Prompt template name |
| `arguments` | `dict[str, Any]` | Arguments to pass to the template |
| `server_id` | `str \| None` | Source server (multi-server scenarios) |

**PromptResult:**

| Attribute | Type | Description |
|-----------|------|-------------|
| `prompt_request_id` | `str` | ID of the corresponding prompt request |
| `prompt_name` | `str` | Name of the prompt that was rendered |
| `messages` | `list[Message]` | Rendered messages (prompts produce messages) |
| `content` | `str \| None` | Single text result for simple prompts |
| `is_error` | `bool` | Whether rendering failed |
| `error_message` | `str \| None` | Error details if rendering failed |

**ImageSource:**

| Attribute | Type | Description |
|-----------|------|-------------|
| `type` | `"url" \| "base64"` | Source type |
| `data` | `str` | URL or base64-encoded string |
| `media_type` | `str \| None` | MIME type (e.g., `image/jpeg`) |

**VideoSource:**

| Attribute | Type | Description |
|-----------|------|-------------|
| `type` | `"url" \| "base64"` | Source type |
| `data` | `str` | URL or base64-encoded string |
| `media_type` | `str \| None` | MIME type (e.g., `video/mp4`) |
| `duration_ms` | `int \| None` | Duration in milliseconds |

**AudioSource:**

| Attribute | Type | Description |
|-----------|------|-------------|
| `type` | `"url" \| "base64"` | Source type |
| `data` | `str` | URL or base64-encoded string |
| `media_type` | `str \| None` | MIME type (e.g., `audio/mp3`) |
| `duration_ms` | `int \| None` | Duration in milliseconds |

**DocumentSource:**

| Attribute | Type | Description |
|-----------|------|-------------|
| `type` | `"url" \| "base64"` | Source type |
| `data` | `str` | URL or base64-encoded string |
| `media_type` | `str \| None` | MIME type (e.g., `application/pdf`) |
| `title` | `str \| None` | Document title |

### 2.3 Channel

`Channel` is a closed-set enumeration that classifies the kind of output a message represents. It is **optional**, and when unset, it indicates a standard, unclassified message. Channels allow agentic frameworks and pipelines to route or filter messages by output type without inspecting content.

| Channel | Description |
|---------|-------------|
| `analysis` | Intermediate analytical output, such as reasoning, evaluation, or investigation produced during task execution, not intended as the final response. |
| `commentary` | Meta-level observations about the task or process, such as notes, warnings, or annotations produced alongside primary output. |
| `final` | The terminal response for a task or conversation turn, such as the output intended for delivery to the end consumer. |

## 3. Extensions

Extensions are the sole carrier of all contextual data. Everything a consumer or policy engine needs (e.g., identity, security classification, HTTP context, entity metadata, agent lineage, execution environment, completion info, provenance) is stored as a typed message extension with an explicit mutability tier.

```
Extensions
├── request: RequestExtension | None
├── agent: AgentExtension | None
├── http: HttpExtension | None
├── security: SecurityExtension | None
├── mcp: MCPExtension | None
├── completion: CompletionExtension | None
├── provenance: ProvenanceExtension | None
├── llm: LLMExtension | None
├── framework: FrameworkExtension | None
├── meta: MetaExtension | None
└── custom: dict[str, Any] | None
```

### 3.1 Mutability Tiers

Every extension declares its mutability tier. The processing pipeline enforces these contracts during copy-on-write.

| Tier | Copy Behavior | Pipeline Validation |
|------|-------------|---------------------|
| **Immutable** | Shared reference, not deep-copied | Rejects if changed in returned copy |
| **Monotonic** | Copied, but only additive operations allowed | Rejects if any element was removed |
| **Guarded** | Copied, but write requires a declared capability | Rejects if modified without the required capability |
| **Mutable** | Normal deep copy, fully modifiable | Accepted as-is |

### 3.2 Extension Types

| Extension | Mutability | Contents |
|-----------|-----------|----------|
| `request` | Immutable | Execution environment, request ID, timestamp, distributed tracing |
| `agent` | Immutable | Session ID, conversation ID, turn, agent lineage, original user intent |
| `http` | Guarded | HTTP headers (readable with `read_headers`, writable with `write_headers`) |
| `security` | Monotonic | Security labels, classification level, and the nested immutable fields below |
| `security.subject` | Immutable | Authenticated identity: ID, type, roles, permissions, teams, claims |
| `security.objects` | Immutable | Access control profiles keyed by entity |
| `security.data` | Immutable | Data governance policies keyed by entity |
| `mcp` | Immutable | Tool, resource, or prompt metadata (name, schema, annotations, server ID) |
| `completion` | Immutable | Stop reason, token usage, model identifier, wire format, latency |
| `provenance` | Immutable | Source identifier, message ID, parent message ID |
| `llm` | Immutable | Model identifier, provider, model capabilities |
| `framework` | Immutable | Agentic framework context (LangGraph, CrewAI, etc.) |
| `meta` | Immutable | Host-provided entity tags, scope, and arbitrary properties |
| `custom` | Mutable | Custom extensions |

### 3.3 RequestExtension (immutable)

Execution environment and request-level timing/tracing. Available to all consumers without any capability requirement (base tier).

| Attribute | Type | Description |
|-----------|------|-------------|
| `environment` | `str \| None` | Execution environment (`production`, `staging`, `dev`) |
| `request_id` | `str \| None` | Request correlation ID |
| `timestamp` | `str \| None` | ISO timestamp of the request |
| `trace_id` | `str \| None` | Distributed tracing ID (OpenTelemetry) |
| `span_id` | `str \| None` | Distributed tracing span ID |

### 3.4 AgentExtension (immutable)

Agent execution context — session tracking, multi-agent lineage, and the original user intent. Immutable because the user's intent and session identity must not be modifiable by processing components.

| Attribute | Type | Description |
|-----------|------|-------------|
| `input` | `str \| None` | Original user intent that triggered this action |
| `session_id` | `str \| None` | Broad session identifier |
| `conversation_id` | `str \| None` | Specific dialogue/task within a session |
| `turn` | `int \| None` | Position in conversation (0-indexed) |
| `agent_id` | `str \| None` | Identifier of the producing agent |
| `parent_agent_id` | `str \| None` | Spawning agent's ID (multi-agent lineage) |
| `conversation` | `ConversationContext \| None` | Windowed conversation context |

**ConversationContext:**

| Attribute | Type | Description |
|-----------|------|-------------|
| `history` | `list[Message] \| None` | Windowed message history (recent turns) |
| `summary` | `str \| None` | Summarized prior context |
| `topics` | `list[str]` | Extracted topics or intents |

### 3.5 HttpExtension (guarded)

HTTP request context. Readable with `read_headers`, writable with `write_headers`. The write capability exists because consumers sometimes need to inject headers for downstream systems — e.g., adding an OAuth token for an API call, or a correlation ID for tracing.

| Attribute | Read Capability | Write Capability | Type | Description |
|-----------|----------------|-----------------|------|-------------|
| `headers` | `read_headers` | `write_headers` | `dict[str, str]` | HTTP headers as key-value pairs |

Sensitive headers (`Authorization`, `Cookie`, `X-API-Key`) are stripped when serialized for external policy engines. Consumers with `write_headers` can inject new headers; the pipeline audits all header modifications.

### 3.6 SecurityExtension (monotonic and immutable)

Data classification, security labels, and all security-relevant contextual data: subject identity, access control profiles, and data governance policies. The `SecurityExtension` labels are add-only during normal message flow. Its nested immutable fields (`subject`, `objects`, `data`) cannot be replaced or modified.

| Attribute | Type | Description |
|-----------|------|-------------|
| `labels` | `set[str]` | Security/data labels (`PII`, `CONFIDENTIAL`, `SECRET`, etc.) |
| `classification` | `str \| None` | Data classification level |
| `subject` | `SubjectExtension \| None` | Authenticated identity (see 3.6.1) |
| `objects` | `dict[str, ObjectSecurityProfile]` | Access control profiles, keyed by entity identifier (see 3.6.2) |
| `data` | `dict[str, DataPolicy]` | Data governance policies, keyed by entity identifier (see 3.6.3) |

Requires `read_labels` capability to see labels. Any consumer can add labels (through copy-on-write), but the pipeline validates that no labels were removed (`before.labels ⊆ after.labels`). Removal requires a privileged declassification operation that is audited separately.

#### 3.6.1 SubjectExtension (immutable)

The authenticated entity making the request. Access to individual fields is controlled by declared capabilities.

`SubjectType` is a closed-set enumeration: `user`, `agent`, `service`, `system`.

| Attribute | Capability Required | Type | Description |
|-----------|-------------------|------|-------------|
| `id` | `read_subject` | `str` | Unique subject identifier |
| `type` | `read_subject` | `SubjectType` | Subject kind |
| `roles` | `read_roles` | `set[str]` | Assigned roles (`developer`, `admin`, `viewer`, etc.) |
| `permissions` | `read_permissions` | `set[str]` | Granted permissions (`tools.execute`, `db.read`, etc.) |
| `teams` | `read_teams` | `set[str]` | Team memberships (for multi-tenant scoping) |
| `claims` | `read_claims` | `dict` | Raw identity claims (JWT, SAML) |

#### 3.6.2 Objects (immutable)

Access control profiles for entities referenced in the message, keyed by entity identifier (tool name, resource URI, prompt name). Each entry is an `ObjectSecurityProfile` declaring the entity's access requirements and data scope.

```
objects: dict[str, ObjectSecurityProfile] = {}
```

**ObjectSecurityProfile** (flat):

| Attribute | Type | Description |
|-----------|------|-------------|
| `managed_by` | `str` | Who enforces access control: `"host"`, `"tool"`, or `"both"` |
| `permissions` | `list[str]` | Required permissions to invoke (e.g., `["read:compensation"]`) |
| `trust_domain` | `str \| None` | Trust domain: `"internal"`, `"external"`, `"privileged"` |
| `data_scope` | `list[str]` | Field names this entity accesses/returns (e.g., `["salary", "bonus"]`) |

For MCP/framework messages (single entity), this map has one entry. For LLM provider messages with multiple tool calls, it has one entry per entity. The host pipeline populates this map during message ingestion by looking up each entity's registered profile from an implementation-defined registry (e.g., tool registration metadata, MCP server manifests, or a policy store). Profile lookup is keyed by entity identifier — the tool name, resource URI, or prompt name that appears in the message content.

The `MessageView` exposes a singular accessor — each view resolves its own profile from the map:

```
view.object → ObjectSecurityProfile | None
  (resolved by: extensions.security.objects.get(view.name))
```

For the full model and policy integration, see the [Object Security Profile Spec](object-security-profile-spec.md).

#### 3.6.3 Data (immutable)

Data governance policies for entities referenced in the message, keyed by entity identifier (tool name, resource URI, prompt name). Each entry is a `DataPolicy` declaring labeling, action restrictions, and retention rules for the entity's output.

```
data: dict[str, DataPolicy] = {}
```

**DataPolicy:**

| Attribute | Type | Description |
|-----------|------|-------------|
| `apply_labels` | `list[str]` | Labels to stamp on output (e.g., `["PII", "financial"]`) |
| `allowed_actions` | `list[str] \| None` | What downstream can do. `None` = unrestricted. |
| `denied_actions` | `list[str]` | What downstream cannot do (e.g., `["export", "forward"]`) |
| `retention` | `RetentionPolicy \| None` | How long data can be kept |

**RetentionPolicy:**

| Attribute | Type | Description |
|-----------|------|-------------|
| `max_age_seconds` | `int \| None` | Maximum retention duration in seconds |
| `policy` | `str` | Retention class: `"session"`, `"transient"`, `"persistent"`, `"none"` |
| `delete_after` | `str \| None` | ISO timestamp after which data must be deleted |

The `data` extension is evaluated on post views (tool results, resource responses, prompt results). When a tool returns data, the pipeline looks up its `DataPolicy`, stamps `apply_labels` onto the message's `SecurityExtension`, and enforces action restrictions downstream.

The `MessageView` exposes a singular accessor:

```
view.data_policy → DataPolicy | None
  (resolved by: extensions.security.data.get(view.name))
```

For the full model, action vocabulary, and policy integration, see the [Object Security Profile Spec](object-security-profile-spec.md).

### 3.7 MCPExtension (immutable)

Typed metadata about the MCP entity being processed. Gives consumers access to the schema and annotations of the tool, resource, or prompt being evaluated.

**ToolMetadata** (`ext.mcp.metadata.tool`):

| Attribute | Type | Description |
|-----------|------|-------------|
| `name` | `str` | Unique tool identifier |
| `title` | `str \| None` | Human-readable display name |
| `description` | `str \| None` | Description of tool functionality |
| `input_schema` | `dict \| None` | JSON Schema defining expected parameters |
| `output_schema` | `dict \| None` | JSON Schema for structured output |
| `server_id` | `str \| None` | ID of the server providing this tool |
| `namespace` | `str \| None` | Tool namespace (server/origin) |
| `annotations` | `dict` | MCP annotations (e.g., `readOnlyHint`, `destructiveHint`) |

**ResourceMetadata** (`ext.mcp.metadata.resource`):

| Attribute | Type | Description |
|-----------|------|-------------|
| `uri` | `str` | Resource URI (`file:///path`, `db://table/id`, etc.) |
| `name` | `str \| None` | Resource name |
| `description` | `str \| None` | Resource description |
| `mime_type` | `str \| None` | MIME type (`text/csv`, `application/json`, etc.) |
| `server_id` | `str \| None` | ID of the server providing this resource |
| `annotations` | `dict` | MCP annotations (classification, retention, access hints) |

**PromptMetadata** (`ext.mcp.metadata.prompt`):

| Attribute | Type | Description |
|-----------|------|-------------|
| `name` | `str` | Prompt template name |
| `description` | `str \| None` | Prompt description |
| `arguments` | `list[dict] \| None` | Argument definitions — each entry has `name`, `description`, `required` |
| `server_id` | `str \| None` | ID of the server providing this prompt |
| `annotations` | `dict` | MCP annotations |

Note: Prompts use an argument list rather than JSON Schema for input definition, following the MCP prompt specification. There is no output schema — prompt output is always rendered messages.

### 3.8 CompletionExtension (immutable)

LLM completion information. Fields like `model` and `stop_reason` can drive policy decisions (e.g., "only allow gpt-4 for financial queries", "flag max_tokens responses for review").

`StopReason` is a closed-set enumeration: `end`, `return`, `call`, `max_tokens`, `stop_sequence`.

**TokenUsage:**

| Attribute | Type | Description |
|-----------|------|-------------|
| `input_tokens` | `int` | Tokens consumed by the input |
| `output_tokens` | `int` | Tokens generated in the output |
| `total_tokens` | `int` | Total tokens (input + output) |

| Attribute | Type | Description |
|-----------|------|-------------|
| `stop_reason` | `StopReason \| None` | Why the model stopped |
| `tokens` | `TokenUsage \| None` | Token counts |
| `model` | `str \| None` | Model identifier that generated this response |
| `raw_format` | `str \| None` | Original wire format (`chatml`, `harmony`, `gemini`, `anthropic`) |
| `created_at` | `str \| None` | ISO timestamp when the message was created |
| `latency_ms` | `int \| None` | Response generation time in milliseconds |

### 3.9 ProvenanceExtension (immutable)

Origin and threading information for the message. Enables lineage tracking across multi-turn conversations and multi-agent systems.

| Attribute | Type | Description |
|-----------|------|-------------|
| `source` | `str \| None` | Source identifier (`"user"`, `"agent:xyz"`, `"mcp-server:abc"`) |
| `message_id` | `str \| None` | Unique message identifier |
| `parent_id` | `str \| None` | Parent message ID (threading/replies) |

Note: `conversation_id`, `session_id`, and agent lineage (`agent_id`, `parent_agent_id`) live on `AgentExtension` (section 3.4) since they are per-request context, not per-message. `trace_id` and `span_id` live on `RequestExtension` (section 3.3) alongside `request_id`.

### 3.10 LLMExtension (immutable)

Model identity and capability metadata. Used for routing, policy evaluation, and audit when the producing model's identity matters independently of the completion itself.

| Attribute | Type | Description |
|-----------|------|-------------|
| `model_id` | `str \| None` | Model identifier (e.g., `gpt-4o`, `claude-sonnet-4-20250514`) |
| `provider` | `str \| None` | Provider name (e.g., `openai`, `anthropic`, `google`) |
| `capabilities` | `list[str]` | Declared model capabilities (e.g., `["vision", "tool_use", "extended_thinking"]`) |

### 3.11 FrameworkExtension (immutable)

Agentic framework context. Captures the framework-level execution environment for messages that originate from or pass through agentic orchestration layers.

| Attribute | Type | Description |
|-----------|------|-------------|
| `framework` | `str \| None` | Framework identifier (e.g., `langgraph`, `crewai`, `autogen`, `a2a`) |
| `framework_version` | `str \| None` | Framework version |
| `node_id` | `str \| None` | Framework-specific node or step identifier |
| `graph_id` | `str \| None` | Graph or workflow identifier |
| `metadata` | `dict[str, Any]` | Framework-specific metadata |

### 3.12 MetaExtension (immutable)

Host-provided operational metadata about the entity being processed. Set by the host system (gateway registration, static config, MCP manifest, admin UI) before the plugin pipeline runs. Plugins can read this data for routing and policy decisions but cannot modify it.

`MetaExtension` is protocol-agnostic — it carries the same structure regardless of whether the entity came from MCP, A2A, gRPC, or REST.

| Attribute | Type | Description |
|-----------|------|-------------|
| `tags` | `set[str]` | Entity tags (e.g., `pii`, `hr`, `external-comms`). Merged from static config and host-injected runtime tags. Drive route matching and policy group inheritance. |
| `scope` | `str \| None` | Host-defined grouping. ContextForge maps this to virtual server ID, Kagenti to namespace, etc. CPEX core treats it as an opaque string for matching. |
| `properties` | `dict[str, str]` | Arbitrary key-value metadata (e.g., `owner`, `region`, `data_classification`). Available in policy conditions as `meta.properties.{key}`. |

**Relationship to other extensions:**

| Extension | Purpose | Who sets it | Mutable by plugins? |
|-----------|---------|-------------|---------------------|
| `meta.tags` | What this entity *is* (operational classification) | Host / config | No (immutable) |
| `security.labels` | What *happened* during processing (data flow tracking) | Plugins / pipeline | Add-only (monotonic) |
| `mcp` | Protocol-specific schema and annotations | MCP transport layer | No (immutable) |

### 3.13 Custom Extensions (mutable)

Custom extensions. Fully mutable through copy-on-write, no restrictions on modification.

## 4. MessageView

`Message` is the **storage format** — it preserves the wire structure exactly as the LLM sent it. `MessageView` is the **policy and interaction surface** — it decomposes a message into individually addressable parts, enriches each with computed semantics, and provides a uniform interface regardless of content type.

### 4.1 Message vs. MessageView

A single LLM response can contain text, reasoning, and multiple tool calls bundled together. That's one `Message` but potentially many things that need to be evaluated independently.

**Message** (one object, wire format):
```json
{
  "role": "assistant",
  "content": [
    {"content_type": "thinking", "text": "The user wants admin users. I'll query the database..."},
    {"content_type": "text", "text": "Let me look that up for you."},
    {"content_type": "tool_call", "name": "execute_sql", "arguments": {"query": "SELECT * FROM users WHERE role='admin'"}},
    {"content_type": "tool_call", "name": "send_email", "arguments": {"to": "boss@company.com", "body": "..."}}
  ]
}
```

Calling `message.iter_views()` produces **four MessageViews**, each with a uniform interface:

| # | `kind` | `name` | `action` | `is_pre` | `uri` | `content` |
|---|--------|--------|----------|----------|-------|-----------|
| 1 | `thinking` | — | `generate` | `false` | — | `"The user wants admin users..."` |
| 2 | `text` | — | `send` | `false` | — | `"Let me look that up for you."` |
| 3 | `tool_call` | `execute_sql` | `execute` | `true` | `tool://db-server/execute_sql` | `'{"query": "SELECT..."}'` |
| 4 | `tool_call` | `send_email` | `execute` | `true` | `tool://email-server/send_email` | `'{"to": "boss@..."}'` |

**What the view adds** that doesn't exist on the raw content parts:

| Property | Raw ContentPart | MessageView |
|----------|----------------|-------------|
| Identity | No URI | Synthetic URI (`tool://ns/name`, `prompt://server/name`, `file:///path`) |
| Direction | No concept | `is_pre`/`is_post` computed from kind + role |
| Semantic action | No concept | `action`: `read`, `write`, `execute`, `invoke`, `send`, `receive`, `generate` |
| Context | Not attached | Capability-gated flat accessors (`roles`, `labels`, `environment`, etc.) |
| Content normalization | Type-specific | `content` always returns scannable text (serialized arguments for tool calls) |
| Uniform query API | Type-specific fields | `has_role()`, `has_label()`, `matches_uri_pattern()`, `get_arg()`, etc. |

### 4.2 Supporting Both LLM and Framework Formats

The CMF naturally supports two messaging patterns through the same structure:

| Pattern | Content | Views | Example |
|---------|---------|-------|---------|
| **LLM wire format** | Multiple ContentParts per message | Many views per message | OpenAI/Anthropic assistant response with text + thinking + tool calls |
| **Framework/protocol format** | Single ContentPart per message | One view per message | MCP tool call, A2A task message, LangGraph node output |

An MCP tool invocation is simply a Message with one `tool_call` content part:

```json
{"role": "assistant", "content": [{"content_type": "tool_call", "name": "get_user", "arguments": {"id": "123"}}]}
```

This produces one view. An OpenAI assistant response that bundles reasoning with two tool calls produces three views. The processing pipeline doesn't care — `iter_views()` yields the right number either way, and every view has the same interface.

This means the CMF does not force a choice between "one action per message" (MCP, A2A) and "bundled response" (LLM providers). Both are first-class, and the same policies and routing rules work across both patterns without adaptation.

### 4.3 Core Attributes

`ViewKind` is a closed-set enumeration: `text`, `thinking`, `tool_call`, `tool_result`, `resource`, `resource_ref`, `prompt_request`, `prompt_result`, `image`, `video`, `audio`, `document`.

`ViewAction` is a closed-set enumeration: `read`, `write`, `execute`, `invoke`, `send`, `receive`, `generate`.

| Attribute | Type | Description |
|-----------|------|-------------|
| `kind` | `ViewKind` | Content type of this view |
| `role` | `Role` | Role of the parent message (`user`, `assistant`, `system`, `developer`, `tool`) |
| `content` | `str \| None` | Scannable text. For tool calls and prompt requests: JSON-serialized arguments. For tool results: JSON-serialized content. For resources: embedded content string. |
| `uri` | `str \| None` | Synthetic identity: `tool://ns/name`, `prompt://server/name`, `tool_result://name`, `file:///path` |
| `name` | `str \| None` | Human-readable name (tool name, resource name, prompt name) |
| `action` | `ViewAction` | Semantic action |
| `args` | `dict \| None` | Alias for the underlying `arguments` dict on `tool_call` and `prompt_request` content parts; `None` for other kinds |
| `mime_type` | `str \| None` | MIME type for resources and images |
| `size_bytes` | `int \| None` | Content size in bytes (computed from content) |
| `properties` | `dict` | Type-specific properties (see 4.6) |

### 4.4 Direction

Direction is determined by a combination of ViewKind and Role:

| Content | Direction | Rule |
|---------|-----------|------|
| `tool_call`, `prompt_request`, `resource_ref` | **pre** | Always requests |
| `tool_result`, `prompt_result`, `resource` | **post** | Always responses |
| `text`, `thinking`, media | **pre** if role is user/system/developer/tool | Input to LLM |
| `text`, `thinking`, media | **post** if role is assistant | Output from LLM |

| Attribute | Type | Description |
|-----------|------|-------------|
| `is_pre` | `bool` | True if input/request (before processing) |
| `is_post` | `bool` | True if output/response (after processing) |
| `is_tool` | `bool` | True if `tool_call` or `tool_result` |
| `is_prompt` | `bool` | True if `prompt_request` or `prompt_result` |
| `is_resource` | `bool` | True if `resource` or `resource_ref` |
| `is_text` | `bool` | True if `text` or `thinking` |
| `is_media` | `bool` | True if `image`, `video`, `audio`, or `document` |

### 4.5 Flat Accessors (capability-gated)

MessageView provides flat accessor properties over extensions. These hide the underlying extension nesting — consumers write `view.roles`, not `view.extensions.security.subject.roles`. Availability depends on the consumer's declared capabilities — extensions for which access has not been granted are `None` on the view.

| Accessor | Capability | Type | Reads From |
|----------|-----------|------|------------|
| `environment` | _(base)_ | `str \| None` | `ext.request.environment` |
| `request_id` | _(base)_ | `str \| None` | `ext.request.request_id` |
| `subject` | `read_subject` | `SubjectExtension \| None` | `ext.security.subject` |
| `roles` | `read_roles` | `set[str]` | `ext.security.subject.roles` |
| `permissions` | `read_permissions` | `set[str]` | `ext.security.subject.permissions` |
| `teams` | `read_teams` | `set[str]` | `ext.security.subject.teams` |
| `headers` | `read_headers` | `dict[str, str]` | `ext.http.headers` |
| `labels` | `read_labels` | `set[str]` | `ext.security.labels` |
| `agent_input` | `read_agent` | `str \| None` | `ext.agent.input` |
| `session_id` | `read_agent` | `str \| None` | `ext.agent.session_id` |
| `conversation_id` | `read_agent` | `str \| None` | `ext.agent.conversation_id` |
| `turn` | `read_agent` | `int \| None` | `ext.agent.turn` |
| `agent_id` | `read_agent` | `str \| None` | `ext.agent.agent_id` |
| `parent_agent_id` | `read_agent` | `str \| None` | `ext.agent.parent_agent_id` |
| `object` | `read_objects` | `ObjectSecurityProfile \| None` | `ext.security.objects.get(view.name)` |
| `data_policy` | `read_data` | `DataPolicy \| None` | `ext.security.data.get(view.name)` |

Helper methods:

| Method | Description |
|--------|-------------|
| `has_role(role)` | Check if subject has a specific role |
| `has_permission(perm)` | Check if subject has a specific permission |
| `has_label(label)` | Check if a security label is present |
| `has_header(name)` | Check if an HTTP header exists (case-insensitive) |
| `get_header(name)` | Get header value (case-insensitive) |
| `get_arg(name)` | Get a single argument value |
| `has_arg(name)` | Check if an argument exists |
| `matches_uri_pattern(glob)` | Glob match on URI (`*`, `**` wildcards) |
| `has_content()` | True if scannable text content is available |

### 4.6 Type-Specific Properties

Each ViewKind exposes additional properties via `get_property(name)` or `properties`:

| ViewKind | Property | Type | Description |
|----------|----------|------|-------------|
| `resource` | `resource_type` | `str` | `file`, `blob`, `uri`, `database`, `api`, `memory`, `artifact` |
| `resource` | `version` | `str \| None` | Resource version |
| `resource` | `annotations` | `dict \| None` | Resource annotations (classification, retention, etc.) |
| `tool_call` | `namespace` | `str \| None` | Tool namespace (server/origin) |
| `tool_call` | `tool_id` | `str \| None` | Call correlation ID |
| `tool_result` | `is_error` | `bool` | Whether the tool execution errored |
| `tool_result` | `tool_name` | `str` | Name of the tool that produced this result |
| `prompt_request` | `server_id` | `str \| None` | Source server for the prompt |
| `prompt_result` | `is_error` | `bool` | Whether prompt rendering errored |
| `prompt_result` | `message_count` | `int` | Number of messages in the rendered prompt |

### 4.7 Serialization

| Method | Description |
|--------|-------------|
| `to_dict()` | Serialize to JSON-compatible dict. Options: `include_content`, `include_context` |
| `to_opa_input()` | Wrap in OPA envelope: `{"input": {...view...}}` |

Sensitive headers (`Authorization`, `Cookie`, `X-API-Key`) are automatically stripped from serialized output. The serialized `extensions` block is assembled from capability-gated extensions, mirroring the extension hierarchy.

## 5. Security Properties

### 5.1 Label Propagation

Security labels on `extensions.security` are **monotonically accumulating** during normal message flow. A message that touches PII data carries the `PII` label for its lifetime. Labels propagate through the pipeline:

- Tool result carries labels → subsequent messages inherit them
- Multiple data sources → union of labels

Removal requires explicit declassification, a privileged operation that is audited separately.

### 5.2 Extension Tier Enforcement

The four mutability tiers (immutable, monotonic, guarded, mutable) provide layered protection:

| Layer | What it prevents | How |
|-------|-----------------|-----|
| **MessageView** | Accidental mutation through read path | Read-only by design; no mutation API |
| **Capability gating** | Unauthorized access to sensitive extensions | Extensions not populated if capability not declared |
| **Write validation** | Unauthorized modification through write path | Pipeline validates tier constraints on returned copies |
