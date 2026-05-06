// Location: ./go/cpex/types.go
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// CPEX Go types — extensions, pipeline results, and payload constants.
//
// All types use msgpack struct tags matching the Rust field names
// for zero-copy serialization across the FFI boundary. Extension
// types mirror crates/cpex-core/src/extensions/.

package cpex

import "github.com/vmihailenco/msgpack/v5"

// Extensions carries capability-gated data alongside the payload.
// Serialized to/from MessagePack when crossing the FFI boundary.
type Extensions struct {
	Meta       *MetaExtension       `msgpack:"meta,omitempty"`
	Security   *SecurityExtension   `msgpack:"security,omitempty"`
	Http       *HttpExtension       `msgpack:"http,omitempty"`
	Delegation *DelegationExtension `msgpack:"delegation,omitempty"`
	Agent      *AgentExtension      `msgpack:"agent,omitempty"`
	Request    *RequestExtension    `msgpack:"request,omitempty"`
	MCP        *MCPExtension        `msgpack:"mcp,omitempty"`
	Completion *CompletionExtension `msgpack:"completion,omitempty"`
	Provenance *ProvenanceExtension `msgpack:"provenance,omitempty"`
	LLM        *LLMExtension        `msgpack:"llm,omitempty"`
	Framework  *FrameworkExtension  `msgpack:"framework,omitempty"`
	Custom     map[string]any       `msgpack:"custom,omitempty"`
}

// MetaExtension carries entity identification for route resolution.
type MetaExtension struct {
	EntityType string            `msgpack:"entity_type,omitempty"`
	EntityName string            `msgpack:"entity_name,omitempty"`
	Tags       []string          `msgpack:"tags,omitempty"`
	Scope      string            `msgpack:"scope,omitempty"`
	Properties map[string]string `msgpack:"properties,omitempty"`
}

// SecurityExtension carries identity, labels, and data policies.
type SecurityExtension struct {
	Labels         []string                         `msgpack:"labels,omitempty"`
	Classification string                           `msgpack:"classification,omitempty"`
	Subject        *SubjectExtension                `msgpack:"subject,omitempty"`
	Agent          *AgentIdentity                   `msgpack:"agent,omitempty"`
	AuthMethod     string                           `msgpack:"auth_method,omitempty"`
	Objects        map[string]ObjectSecurityProfile `msgpack:"objects,omitempty"`
	Data           map[string]DataPolicy            `msgpack:"data,omitempty"`
}

// SubjectExtension represents the authenticated caller.
type SubjectExtension struct {
	ID          string            `msgpack:"id,omitempty"`
	SubjectType string            `msgpack:"subject_type,omitempty"`
	Roles       []string          `msgpack:"roles,omitempty"`
	Permissions []string          `msgpack:"permissions,omitempty"`
	Teams       []string          `msgpack:"teams,omitempty"`
	Claims      map[string]string `msgpack:"claims,omitempty"`
}

// AgentIdentity represents this agent's own workload identity.
type AgentIdentity struct {
	ClientID    string `msgpack:"client_id,omitempty"`
	WorkloadID  string `msgpack:"workload_id,omitempty"`
	TrustDomain string `msgpack:"trust_domain,omitempty"`
}

// ObjectSecurityProfile is a security profile for a managed object.
type ObjectSecurityProfile struct {
	ManagedBy   string   `msgpack:"managed_by,omitempty"`
	Permissions []string `msgpack:"permissions,omitempty"`
	TrustDomain string   `msgpack:"trust_domain,omitempty"`
	DataScope   []string `msgpack:"data_scope,omitempty"`
}

// DataPolicy defines data handling policies.
type DataPolicy struct {
	ApplyLabels    []string         `msgpack:"apply_labels,omitempty"`
	AllowedActions []string         `msgpack:"allowed_actions,omitempty"`
	DeniedActions  []string         `msgpack:"denied_actions,omitempty"`
	Retention      *RetentionPolicy `msgpack:"retention,omitempty"`
}

// RetentionPolicy defines data retention rules.
type RetentionPolicy struct {
	MaxAgeSeconds *uint64 `msgpack:"max_age_seconds,omitempty"`
	Policy        string  `msgpack:"policy,omitempty"`
	DeleteAfter   string  `msgpack:"delete_after,omitempty"`
}

// HttpExtension carries HTTP request and response headers.
type HttpExtension struct {
	RequestHeaders  map[string]string `msgpack:"request_headers,omitempty"`
	ResponseHeaders map[string]string `msgpack:"response_headers,omitempty"`
}

// DelegationExtension carries the token delegation chain.
type DelegationExtension struct {
	Chain           []DelegationHop `msgpack:"chain,omitempty"`
	Depth           int             `msgpack:"depth,omitempty"`
	OriginSubjectID string          `msgpack:"origin_subject_id,omitempty"`
	ActorSubjectID  string          `msgpack:"actor_subject_id,omitempty"`
	Delegated       bool            `msgpack:"delegated,omitempty"`
	AgeSeconds      float64         `msgpack:"age_seconds,omitempty"`
}

// DelegationHop is a single step in the delegation chain.
type DelegationHop struct {
	SubjectID     string   `msgpack:"subject_id,omitempty"`
	SubjectType   string   `msgpack:"subject_type,omitempty"`
	Audience      string   `msgpack:"audience,omitempty"`
	ScopesGranted []string `msgpack:"scopes_granted,omitempty"`
	Timestamp     string   `msgpack:"timestamp,omitempty"`
	TTLSeconds    *uint64  `msgpack:"ttl_seconds,omitempty"`
	Strategy      string   `msgpack:"strategy,omitempty"`
	FromCache     bool     `msgpack:"from_cache,omitempty"`
}

// AgentExtension carries agent execution context.
type AgentExtension struct {
	Input          string `msgpack:"input,omitempty"`
	SessionID      string `msgpack:"session_id,omitempty"`
	ConversationID string `msgpack:"conversation_id,omitempty"`
	// Turn is *uint32 to match Rust's Option<u32>. Previously *int (64-bit
	// in Go) — values >2^32 would overflow the Rust side silently.
	Turn          *uint32 `msgpack:"turn,omitempty"`
	AgentID       string  `msgpack:"agent_id,omitempty"`
	ParentAgentID string  `msgpack:"parent_agent_id,omitempty"`
	// Conversation mirrors Rust's `conversation: Option<ConversationContext>`.
	// Previously absent — Rust serialized this field but Go silently dropped
	// it (P2 #16).
	Conversation *ConversationContext `msgpack:"conversation,omitempty"`
}

// ConversationContext is per-conversation summary state, shared across
// turns. Mirrors `cpex_core::extensions::agent::ConversationContext`.
type ConversationContext struct {
	// Recent conversation history, lightweight summaries (free-form
	// JSON-style values to match Rust's Vec<serde_json::Value>).
	History []any `msgpack:"history,omitempty"`
	// LLM-generated conversation summary.
	Summary string `msgpack:"summary,omitempty"`
	// Detected topics for routing / classification.
	Topics []string `msgpack:"topics,omitempty"`
}

// RequestExtension carries execution environment and tracing.
type RequestExtension struct {
	Environment string `msgpack:"environment,omitempty"`
	RequestID   string `msgpack:"request_id,omitempty"`
	Timestamp   string `msgpack:"timestamp,omitempty"`
	TraceID     string `msgpack:"trace_id,omitempty"`
	SpanID      string `msgpack:"span_id,omitempty"`
}

// MCPExtension carries MCP entity metadata.
type MCPExtension struct {
	Tool     *ToolMetadata     `msgpack:"tool,omitempty"`
	Resource *ResourceMetadata `msgpack:"resource,omitempty"`
	Prompt   *PromptMetadata   `msgpack:"prompt,omitempty"`
}

// ToolMetadata is MCP tool metadata.
type ToolMetadata struct {
	Name        string         `msgpack:"name"`
	Title       string         `msgpack:"title,omitempty"`
	Description string         `msgpack:"description,omitempty"`
	InputSchema map[string]any `msgpack:"input_schema,omitempty"`
	// OutputSchema and Annotations were missing — Rust serialized them,
	// Go silently dropped them (P2 #15).
	OutputSchema map[string]any `msgpack:"output_schema,omitempty"`
	ServerID     string         `msgpack:"server_id,omitempty"`
	Namespace    string         `msgpack:"namespace,omitempty"`
	Annotations  map[string]any `msgpack:"annotations,omitempty"`
}

// ResourceMetadata is MCP resource metadata.
type ResourceMetadata struct {
	URI         string `msgpack:"uri"`
	Name        string `msgpack:"name,omitempty"`
	Description string `msgpack:"description,omitempty"`
	MimeType    string `msgpack:"mime_type,omitempty"`
	ServerID    string `msgpack:"server_id,omitempty"`
}

// PromptMetadata is MCP prompt metadata.
type PromptMetadata struct {
	Name        string `msgpack:"name"`
	Description string `msgpack:"description,omitempty"`
	ServerID    string `msgpack:"server_id,omitempty"`
}

// CompletionExtension carries LLM completion information.
type CompletionExtension struct {
	StopReason string      `msgpack:"stop_reason,omitempty"`
	Tokens     *TokenUsage `msgpack:"tokens,omitempty"`
	Model      string      `msgpack:"model,omitempty"`
	// RawFormat and CreatedAt were missing — Rust serialized them,
	// Go silently dropped them (P2 #14).
	RawFormat string  `msgpack:"raw_format,omitempty"`
	CreatedAt string  `msgpack:"created_at,omitempty"`
	LatencyMs *uint64 `msgpack:"latency_ms,omitempty"`
}

// TokenUsage is token usage statistics.
type TokenUsage struct {
	InputTokens  int `msgpack:"input_tokens,omitempty"`
	OutputTokens int `msgpack:"output_tokens,omitempty"`
	TotalTokens  int `msgpack:"total_tokens,omitempty"`
}

// ProvenanceExtension carries origin and message threading.
type ProvenanceExtension struct {
	Source    string `msgpack:"source,omitempty"`
	MessageID string `msgpack:"message_id,omitempty"`
	ParentID  string `msgpack:"parent_id,omitempty"`
}

// LLMExtension carries model identity and capabilities.
type LLMExtension struct {
	ModelID      string   `msgpack:"model_id,omitempty"`
	Provider     string   `msgpack:"provider,omitempty"`
	Capabilities []string `msgpack:"capabilities,omitempty"`
}

// FrameworkExtension carries agentic framework context.
type FrameworkExtension struct {
	Framework        string         `msgpack:"framework,omitempty"`
	FrameworkVersion string         `msgpack:"framework_version,omitempty"`
	NodeID           string         `msgpack:"node_id,omitempty"`
	GraphID          string         `msgpack:"graph_id,omitempty"`
	Metadata         map[string]any `msgpack:"metadata,omitempty"`
}

// PluginViolation is a structured policy denial.
type PluginViolation struct {
	Code           string         `msgpack:"code"`
	Reason         string         `msgpack:"reason"`
	Description    string         `msgpack:"description,omitempty"`
	Details        map[string]any `msgpack:"details,omitempty"`
	PluginName     string         `msgpack:"plugin_name,omitempty"`
	ProtoErrorCode *int64         `msgpack:"proto_error_code,omitempty"`
}

// PluginError is a plugin execution error.
type PluginError struct {
	PluginName     string         `msgpack:"plugin_name"`
	Message        string         `msgpack:"message"`
	Code           string         `msgpack:"code,omitempty"`
	Details        map[string]any `msgpack:"details,omitempty"`
	ProtoErrorCode *int64         `msgpack:"proto_error_code,omitempty"`
}

// PipelineResult is the aggregate result from a hook invocation.
type PipelineResult struct {
	ContinueProcessing bool             `msgpack:"continue_processing"`
	Violation          *PluginViolation `msgpack:"violation,omitempty"`
	// Errors from plugins that ran with on_error: ignore or
	// on_error: disable. Empty when no plugin errored on a non-halt
	// path. Fire-and-forget errors live on BackgroundTasks.Wait()
	// instead.
	Errors   []PluginError  `msgpack:"errors,omitempty"`
	Metadata map[string]any `msgpack:"metadata,omitempty"`
	// Payload type ID — tells the caller how to deserialize ModifiedPayload.
	PayloadType uint8 `msgpack:"payload_type"`
	// Modified payload as raw MessagePack bytes.
	ModifiedPayload []byte `msgpack:"modified_payload,omitempty"`
	// Modified extensions as raw MessagePack bytes.
	ModifiedExtensions []byte `msgpack:"modified_extensions,omitempty"`
}

// TypedPipelineResult is a PipelineResult with the modified payload
// and extensions deserialized into concrete Go types.
type TypedPipelineResult[P any] struct {
	ContinueProcessing bool
	Violation          *PluginViolation
	Errors             []PluginError
	Metadata           map[string]any
	PayloadType        uint8
	ModifiedPayload    *P
	ModifiedExtensions *Extensions
}

// IsDenied returns true if the pipeline was halted by a plugin.
func (r *TypedPipelineResult[P]) IsDenied() bool {
	return !r.ContinueProcessing
}

// DeserializePayload deserializes the modified payload into a typed struct.
func DeserializePayload[T any](result *PipelineResult) (*T, error) {
	if len(result.ModifiedPayload) == 0 {
		return nil, nil
	}
	var v T
	if err := msgpack.Unmarshal(result.ModifiedPayload, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

// DeserializeExtensions deserializes the modified extensions.
func (r *PipelineResult) DeserializeExtensions() (*Extensions, error) {
	if len(r.ModifiedExtensions) == 0 {
		return nil, nil
	}
	var ext Extensions
	if err := msgpack.Unmarshal(r.ModifiedExtensions, &ext); err != nil {
		return nil, err
	}
	return &ext, nil
}

// IsDenied returns true if the pipeline was halted by a plugin.
func (r *PipelineResult) IsDenied() bool {
	return !r.ContinueProcessing
}
