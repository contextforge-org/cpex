// Location: ./go/cpex/types.go
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// CPEX Go types — extensions, pipeline results, and payload constants.
//
// All types use msgpack struct tags matching the Rust field names
// for zero-copy serialization across the FFI boundary. Extension
// types mirror praxis_policy_core::extensions.

package cpex

import (
	"fmt"
	"log/slog"

	"github.com/vmihailenco/msgpack/v5"
)

// Extensions carries capability-gated data alongside the payload.
// Serialized to/from MessagePack when crossing the FFI boundary.
//
// The Rust raw_credentials slot has no Go field. Its tokens are never
// serialized, so a copy that crossed the FFI would carry empty tokens;
// use InvokeResolved to keep inbound credentials in Rust memory.
type Extensions struct {
	Meta       *MetaExtension       `msgpack:"meta,omitempty"`
	Security   *SecurityExtension   `msgpack:"security,omitempty"`
	Http       *HttpExtension       `msgpack:"http,omitempty"`
	Delegation *DelegationExtension `msgpack:"delegation,omitempty"`
	Agent      *AgentExtension      `msgpack:"agent,omitempty"`
	Request    *RequestExtension    `msgpack:"request,omitempty"`
	// CandidateConstraint narrows the model or backend candidate set.
	// Plugins holding write_candidate_constraint fill it; a host reads it
	// back from the result to filter its routing choices.
	CandidateConstraint *CandidateConstraintExtension `msgpack:"candidate_constraint,omitempty"`
	MCP                 *MCPExtension                 `msgpack:"mcp,omitempty"`
	Completion          *CompletionExtension          `msgpack:"completion,omitempty"`
	Provenance          *ProvenanceExtension          `msgpack:"provenance,omitempty"`
	LLM                 *LLMExtension                 `msgpack:"llm,omitempty"`
	Framework           *FrameworkExtension           `msgpack:"framework,omitempty"`
	Custom              map[string]any                `msgpack:"custom,omitempty"`
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
//
// It holds four identity slots: Subject (the user), Client (the OAuth
// client that brokered the request), CallerWorkload (the attested peer
// that called this service) and ThisWorkload (this service's own
// workload identity).
type SecurityExtension struct {
	Labels         []string                         `msgpack:"labels,omitempty"`
	Classification string                           `msgpack:"classification,omitempty"`
	Subject        *SubjectExtension                `msgpack:"subject,omitempty"`
	Client         *ClientExtension                 `msgpack:"client,omitempty"`
	CallerWorkload *WorkloadIdentity                `msgpack:"caller_workload,omitempty"`
	ThisWorkload   *WorkloadIdentity                `msgpack:"this_workload,omitempty"`
	AuthMethod     string                           `msgpack:"auth_method,omitempty"`
	Objects        map[string]ObjectSecurityProfile `msgpack:"objects,omitempty"`
	Data           map[string]DataPolicy            `msgpack:"data,omitempty"`
}

// SubjectExtension represents the authenticated caller.
type SubjectExtension struct {
	ID          string   `msgpack:"id,omitempty"`
	SubjectType string   `msgpack:"subject_type,omitempty"`
	Roles       []string `msgpack:"roles,omitempty"`
	Permissions []string `msgpack:"permissions,omitempty"`
	Teams       []string `msgpack:"teams,omitempty"`
	// Claims holds the token claims the resolver kept, with their JSON
	// shape: a value can be a string, bool, number, array or nested map.
	Claims map[string]any `msgpack:"claims,omitempty"`
}

// Client trust levels. A resolver can also set an operator-defined
// string, which travels verbatim.
const (
	ClientTrustFirstParty = "first_party"
	ClientTrustThirdParty = "third_party"
	ClientTrustInternal   = "internal"
)

// ClientExtension is the OAuth client or gateway that brokered the
// request, as distinct from the user in SubjectExtension.
type ClientExtension struct {
	ClientID   string `msgpack:"client_id"`
	ClientName string `msgpack:"client_name,omitempty"`
	// TrustLevel is one of the ClientTrust constants or a custom string.
	// Empty means first_party on the Rust side.
	TrustLevel          string         `msgpack:"trust_level,omitempty"`
	AuthorizedScopes    []string       `msgpack:"authorized_scopes,omitempty"`
	AuthorizedAudiences []string       `msgpack:"authorized_audiences,omitempty"`
	Roles               []string       `msgpack:"roles,omitempty"`
	Permissions         []string       `msgpack:"permissions,omitempty"`
	Teams               []string       `msgpack:"teams,omitempty"`
	Claims              map[string]any `msgpack:"claims,omitempty"`
}

// WorkloadIdentity is an attested workload identity, used for both
// SecurityExtension.CallerWorkload and SecurityExtension.ThisWorkload.
type WorkloadIdentity struct {
	SpiffeID    string `msgpack:"spiffe_id,omitempty"`
	TrustDomain string `msgpack:"trust_domain,omitempty"`
	// AttestedAt is an RFC 3339 timestamp.
	AttestedAt string   `msgpack:"attested_at,omitempty"`
	Attestor   string   `msgpack:"attestor,omitempty"`
	Selectors  []string `msgpack:"selectors,omitempty"`
	ClientID   string   `msgpack:"client_id,omitempty"`
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
	ApplyLabels []string `msgpack:"apply_labels,omitempty"`
	// AllowedActions distinguishes nil from empty: nil allows every
	// action, an empty non-nil slice allows none. The tag has no
	// omitempty so an empty slice is not dropped on the way to Rust.
	AllowedActions []string         `msgpack:"allowed_actions"`
	DeniedActions  []string         `msgpack:"denied_actions,omitempty"`
	Retention      *RetentionPolicy `msgpack:"retention,omitempty"`
}

// RetentionPolicy defines data retention rules.
type RetentionPolicy struct {
	MaxAgeSeconds *uint64 `msgpack:"max_age_seconds,omitempty"`
	Policy        string  `msgpack:"policy,omitempty"`
	DeleteAfter   string  `msgpack:"delete_after,omitempty"`
}

// HttpExtension carries the HTTP request line, headers and response
// status. Method and Path select `http:` routes; set them at the
// identity.resolve invocation so the route's own authentication list
// applies.
type HttpExtension struct {
	RequestHeaders  map[string]string `msgpack:"request_headers,omitempty"`
	ResponseHeaders map[string]string `msgpack:"response_headers,omitempty"`
	// Status is the response status code. Zero means unset.
	Status uint16 `msgpack:"status,omitempty"`
	Method string `msgpack:"method,omitempty"`
	Path   string `msgpack:"path,omitempty"`
	Host   string `msgpack:"host,omitempty"`
	Scheme string `msgpack:"scheme,omitempty"`
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
	// SubjectID is required on the Rust side, so it is always sent.
	SubjectID     string   `msgpack:"subject_id"`
	SubjectType   string   `msgpack:"subject_type,omitempty"`
	Audience      string   `msgpack:"audience,omitempty"`
	ScopesGranted []string `msgpack:"scopes_granted,omitempty"`
	// AuthorizationDetails holds RFC 9396 authorization_details entries.
	// Each is a JSON-shaped map with a "type" key plus any other fields.
	AuthorizationDetails []map[string]any `msgpack:"authorization_details,omitempty"`
	// Timestamp is an RFC 3339 timestamp.
	Timestamp  string  `msgpack:"timestamp,omitempty"`
	TTLSeconds *uint64 `msgpack:"ttl_seconds,omitempty"`
	Strategy   string  `msgpack:"strategy,omitempty"`
	FromCache  bool    `msgpack:"from_cache,omitempty"`
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
// turns. Mirrors `praxis_policy_core::extensions::agent::ConversationContext`.
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
	URI         string         `msgpack:"uri"`
	Name        string         `msgpack:"name,omitempty"`
	Description string         `msgpack:"description,omitempty"`
	MimeType    string         `msgpack:"mime_type,omitempty"`
	ServerID    string         `msgpack:"server_id,omitempty"`
	Annotations map[string]any `msgpack:"annotations,omitempty"`
}

// PromptMetadata is MCP prompt metadata.
type PromptMetadata struct {
	Name        string `msgpack:"name"`
	Description string `msgpack:"description,omitempty"`
	// Arguments are the prompt's declared arguments, JSON-shaped.
	Arguments   []any          `msgpack:"arguments,omitempty"`
	ServerID    string         `msgpack:"server_id,omitempty"`
	Annotations map[string]any `msgpack:"annotations,omitempty"`
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

// Candidate-constraint OnEmpty values.
const (
	OnEmptyDeny     = "deny"
	OnEmptyFallback = "fallback"
)

// CandidateConstraintExtension narrows the set of models, regions or
// sites a router may pick. The Allow* fields distinguish nil from
// empty: nil leaves that dimension unconstrained, an empty non-nil
// slice allows nothing. Their tags have no omitempty so an empty slice
// reaches Rust as an empty list.
type CandidateConstraintExtension struct {
	AllowModels  []string          `msgpack:"allow_models"`
	DenyModels   []string          `msgpack:"deny_models,omitempty"`
	AllowRegions []string          `msgpack:"allow_regions"`
	AllowSites   []string          `msgpack:"allow_sites"`
	MaxCostTiers []string          `msgpack:"max_cost_tiers,omitempty"`
	Custom       map[string]string `msgpack:"custom,omitempty"`
	// OnEmpty is OnEmptyDeny or OnEmptyFallback. Empty means deny.
	OnEmpty string `msgpack:"on_empty,omitempty"`
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
	// Modified payload as raw MessagePack bytes. Present on every allowed
	// pipeline, carrying the final payload whether or not a plugin touched
	// it — check PayloadModified to learn whether anything changed.
	ModifiedPayload []byte `msgpack:"modified_payload,omitempty"`
	// PayloadModified reports whether a plugin's payload modification was
	// accepted. This is the signal to test; a non-empty ModifiedPayload
	// only means the pipeline carried a payload, and comparing payload
	// contents cannot see mutations to non-text content parts.
	PayloadModified bool `msgpack:"payload_modified"`
	// Modified extensions as raw MessagePack bytes.
	ModifiedExtensions []byte `msgpack:"modified_extensions,omitempty"`
	// DelegatedCredentials are the credentials delegate() steps minted
	// for this request, for the host to attach upstream. Populated only
	// on allowed results of an engine enabled WithDelegatedCredentials.
	DelegatedCredentials []DelegatedCredential `msgpack:"delegated_credentials,omitempty"`
}

// DelegatedCredential is one minted delegated credential: send it
// upstream as the header Header with the value Value.Reveal().
type DelegatedCredential struct {
	// Header is the outbound header name, for example "Authorization".
	Header string `msgpack:"header"`
	// Value is the full header value, scheme prefix included
	// ("Bearer ...", "token ...", or a bare API key).
	Value SecretValue `msgpack:"value"`
	// Delegator is the plugin instance that minted it.
	Delegator string `msgpack:"delegator"`
	// Target is the logical target named by the delegate() step.
	Target   string   `msgpack:"target"`
	Audience string   `msgpack:"audience"`
	Scopes   []string `msgpack:"scopes,omitempty"`
	// ExpiresAt is an RFC 3339 timestamp.
	ExpiresAt string `msgpack:"expires_at"`
}

// SecretValue holds credential bytes. Every formatting path (fmt verbs,
// JSON and text marshalling, slog) prints a redaction marker; Reveal
// returns the value.
type SecretValue string

const redacted = "[REDACTED]"

// Reveal returns the secret.
func (s SecretValue) Reveal() string { return string(s) }

// String redacts.
func (s SecretValue) String() string { return redacted }

// GoString redacts.
func (s SecretValue) GoString() string { return redacted }

// Format redacts under every verb.
func (s SecretValue) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(redacted)) }

// MarshalText redacts, which also covers encoding/json.
func (s SecretValue) MarshalText() ([]byte, error) { return []byte(redacted), nil }

// LogValue redacts.
func (s SecretValue) LogValue() slog.Value { return slog.StringValue(redacted) }

// TypedPipelineResult is a PipelineResult with the modified payload
// and extensions deserialized into concrete Go types.
type TypedPipelineResult[P any] struct {
	ContinueProcessing bool
	Violation          *PluginViolation
	Errors             []PluginError
	Metadata           map[string]any
	PayloadType        uint8
	ModifiedPayload    *P
	// PayloadModified reports whether a plugin actually changed the
	// payload. See PipelineResult.PayloadModified.
	PayloadModified      bool
	ModifiedExtensions   *Extensions
	DelegatedCredentials []DelegatedCredential
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
