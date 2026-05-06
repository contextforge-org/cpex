// Location: ./go/cpex/cmf.go
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// CMF (ContextForge Message Format) types for Go.
//
// Mirrors the Rust types in crates/cpex-core/src/cmf/. The Message
// struct carries typed content parts (text, tool calls, resources,
// media, etc.) without extensions — those are passed separately.
//
// ContentPart is a tagged union discriminated by the "content_type"
// field. Custom msgpack Encoder/Decoder methods produce the same
// wire format as Rust's #[serde(tag = "content_type")] enum.

package cpex

import "github.com/vmihailenco/msgpack/v5"

// ---------------------------------------------------------------------------
// CMF Message Types
// ---------------------------------------------------------------------------

// MessagePayload wraps a Message for FFI transport.
// Matches Rust's cpex_core::cmf::MessagePayload.
type MessagePayload struct {
	Message Message `msgpack:"message"`
}

// Message is the ContextForge Message Format (CMF) message.
// No extensions — those are passed separately to the plugin pipeline.
type Message struct {
	SchemaVersion string        `msgpack:"schema_version"`
	Role          string        `msgpack:"role"`
	Content       []ContentPart `msgpack:"content"`
	Channel       string        `msgpack:"channel,omitempty"`
}

// NewMessage creates a Message with the default schema version.
func NewMessage(role string, content ...ContentPart) Message {
	return Message{
		SchemaVersion: "2.0",
		Role:          role,
		Content:       content,
	}
}

// ---------------------------------------------------------------------------
// Content Parts — tagged union via content_type discriminator
// ---------------------------------------------------------------------------

// ContentPart represents one element in a Message's content list.
// Uses custom msgpack marshaling to produce the tagged-union wire format:
//
//	{"content_type": "text", "text": "hello"}
//	{"content_type": "tool_call", "content": {...}}
//
// The ContentType field determines which content field is populated.
// Text and Thinking use the Text field directly; all other types use
// their respective content field.
type ContentPart struct {
	ContentType string

	// Text/Thinking — "text" field at top level
	Text string

	// Structured content — "content" field wrapping a domain object.
	// Only one is set based on ContentType.
	ToolCallContent      *ToolCall
	ToolResultContent    *ToolResult
	ResourceContent      *Resource
	ResourceRefContent   *ResourceReference
	PromptRequestContent *PromptRequest
	PromptResultContent  *PromptResult
	ImageContent         *ImageSource
	VideoContent         *VideoSource
	AudioContent         *AudioSource
	DocumentContent      *DocumentSource

	// rawMap captures the full original wire form for content_type
	// values this Go SDK doesn't have a typed accessor for. Lets a
	// newer Rust runtime emitting a future variant pass through
	// older Go bindings without losing data on round-trip — Encode
	// emits rawMap verbatim when ContentType isn't a known case.
	// Private because users with an unknown ContentType have no
	// safe way to interpret it; they can only forward it.
	rawMap map[string]any
}

// EncodeMsgpack produces the tagged-union wire format.
func (cp ContentPart) EncodeMsgpack(enc *msgpack.Encoder) error {
	// Helper: a body envelope wrapping a typed `content` value.
	body := func(content any) map[string]any {
		return map[string]any{
			wireKeyContentType: cp.ContentType,
			wireKeyContent:     content,
		}
	}

	switch cp.ContentType {
	case ContentTypeText, ContentTypeThinking:
		return enc.Encode(map[string]any{
			wireKeyContentType: cp.ContentType,
			wireKeyText:        cp.Text,
		})
	case ContentTypeToolCall:
		return enc.Encode(body(cp.ToolCallContent))
	case ContentTypeToolResult:
		return enc.Encode(body(cp.ToolResultContent))
	case ContentTypeResource:
		return enc.Encode(body(cp.ResourceContent))
	case ContentTypeResourceRef:
		return enc.Encode(body(cp.ResourceRefContent))
	case ContentTypePromptRequest:
		return enc.Encode(body(cp.PromptRequestContent))
	case ContentTypePromptResult:
		return enc.Encode(body(cp.PromptResultContent))
	case ContentTypeImage:
		return enc.Encode(body(cp.ImageContent))
	case ContentTypeVideo:
		return enc.Encode(body(cp.VideoContent))
	case ContentTypeAudio:
		return enc.Encode(body(cp.AudioContent))
	case ContentTypeDocument:
		return enc.Encode(body(cp.DocumentContent))
	default:
		// Unknown content_type. If we captured the raw wire form on
		// decode (forward-compat path), emit it verbatim so we don't
		// lose data on round-trip. Otherwise fall back to a minimal
		// content_type-only message (a Go-side construction with an
		// unrecognized ContentType — rare).
		if cp.rawMap != nil {
			return enc.Encode(cp.rawMap)
		}
		out := map[string]any{wireKeyContentType: cp.ContentType}
		if cp.Text != "" {
			out[wireKeyText] = cp.Text
		}
		return enc.Encode(out)
	}
}

// DecodeMsgpack reads the tagged-union wire format.
func (cp *ContentPart) DecodeMsgpack(dec *msgpack.Decoder) error {
	var raw map[string]any
	if err := dec.Decode(&raw); err != nil {
		return err
	}

	if ct, ok := raw[wireKeyContentType].(string); ok {
		cp.ContentType = ct
	}

	switch cp.ContentType {
	case ContentTypeText, ContentTypeThinking:
		if t, ok := raw[wireKeyText].(string); ok {
			cp.Text = t
		}
	case ContentTypeToolCall:
		cp.ToolCallContent = decodeAs[ToolCall](raw[wireKeyContent])
	case ContentTypeToolResult:
		cp.ToolResultContent = decodeAs[ToolResult](raw[wireKeyContent])
	case ContentTypeResource:
		cp.ResourceContent = decodeAs[Resource](raw[wireKeyContent])
	case ContentTypeResourceRef:
		cp.ResourceRefContent = decodeAs[ResourceReference](raw[wireKeyContent])
	case ContentTypePromptRequest:
		cp.PromptRequestContent = decodeAs[PromptRequest](raw[wireKeyContent])
	case ContentTypePromptResult:
		cp.PromptResultContent = decodeAs[PromptResult](raw[wireKeyContent])
	case ContentTypeImage:
		cp.ImageContent = decodeAs[ImageSource](raw[wireKeyContent])
	case ContentTypeVideo:
		cp.VideoContent = decodeAs[VideoSource](raw[wireKeyContent])
	case ContentTypeAudio:
		cp.AudioContent = decodeAs[AudioSource](raw[wireKeyContent])
	case ContentTypeDocument:
		cp.DocumentContent = decodeAs[DocumentSource](raw[wireKeyContent])
	default:
		// Unknown content_type — preserve the full wire form so
		// EncodeMsgpack can pass it through unchanged. Forward
		// compat for newer Rust variants the Go SDK doesn't know
		// about yet (P2 #17).
		cp.rawMap = raw
	}

	return nil
}

// ---------------------------------------------------------------------------
// Content Part Constructors
// ---------------------------------------------------------------------------

// Constructor functions are named `NewXPart` to avoid shadowing the
// matching `XContent` field on ContentPart. Previously a constructor
// like `ToolCallContent(tc)` had the same name as the field
// `cp.ToolCallContent` — confusing in code and hostile to IDE
// autocomplete. The `New*Part` form mirrors common Go conventions
// (`NewClient`, `NewBuffer`).

// NewTextPart creates a text content part.
func NewTextPart(text string) ContentPart {
	return ContentPart{ContentType: ContentTypeText, Text: text}
}

// NewThinkingPart creates a thinking content part.
func NewThinkingPart(text string) ContentPart {
	return ContentPart{ContentType: ContentTypeThinking, Text: text}
}

// NewToolCallPart creates a tool_call content part.
func NewToolCallPart(tc ToolCall) ContentPart {
	return ContentPart{ContentType: ContentTypeToolCall, ToolCallContent: &tc}
}

// NewToolResultPart creates a tool_result content part.
func NewToolResultPart(tr ToolResult) ContentPart {
	return ContentPart{ContentType: ContentTypeToolResult, ToolResultContent: &tr}
}

// NewResourcePart creates a resource content part.
func NewResourcePart(r Resource) ContentPart {
	return ContentPart{ContentType: ContentTypeResource, ResourceContent: &r}
}

// NewResourceRefPart creates a resource_ref content part.
func NewResourceRefPart(r ResourceReference) ContentPart {
	return ContentPart{ContentType: ContentTypeResourceRef, ResourceRefContent: &r}
}

// NewPromptRequestPart creates a prompt_request content part.
func NewPromptRequestPart(pr PromptRequest) ContentPart {
	return ContentPart{ContentType: ContentTypePromptRequest, PromptRequestContent: &pr}
}

// NewPromptResultPart creates a prompt_result content part.
func NewPromptResultPart(pr PromptResult) ContentPart {
	return ContentPart{ContentType: ContentTypePromptResult, PromptResultContent: &pr}
}

// NewImagePart creates an image content part.
func NewImagePart(img ImageSource) ContentPart {
	return ContentPart{ContentType: ContentTypeImage, ImageContent: &img}
}

// NewVideoPart creates a video content part.
func NewVideoPart(vid VideoSource) ContentPart {
	return ContentPart{ContentType: ContentTypeVideo, VideoContent: &vid}
}

// NewAudioPart creates an audio content part.
func NewAudioPart(aud AudioSource) ContentPart {
	return ContentPart{ContentType: ContentTypeAudio, AudioContent: &aud}
}

// NewDocumentPart creates a document content part.
func NewDocumentPart(doc DocumentSource) ContentPart {
	return ContentPart{ContentType: ContentTypeDocument, DocumentContent: &doc}
}

// ---------------------------------------------------------------------------
// Domain Objects
// ---------------------------------------------------------------------------

// ToolCall represents a tool invocation request.
type ToolCall struct {
	ToolCallID string         `msgpack:"tool_call_id"`
	Name       string         `msgpack:"name"`
	Arguments  map[string]any `msgpack:"arguments,omitempty"`
	Namespace  string         `msgpack:"namespace,omitempty"`
}

// ToolResult represents the output of a tool execution.
type ToolResult struct {
	ToolCallID string `msgpack:"tool_call_id"`
	ToolName   string `msgpack:"tool_name"`
	Content    any    `msgpack:"content,omitempty"`
	IsError    bool   `msgpack:"is_error,omitempty"`
}

// Resource represents an embedded resource with content (MCP).
type Resource struct {
	ResourceRequestID string         `msgpack:"resource_request_id"`
	URI               string         `msgpack:"uri"`
	Name              string         `msgpack:"name,omitempty"`
	Description       string         `msgpack:"description,omitempty"`
	ResourceType      string         `msgpack:"resource_type"`
	Content           string         `msgpack:"content,omitempty"`
	Blob              []byte         `msgpack:"blob,omitempty"`
	MimeType          string         `msgpack:"mime_type,omitempty"`
	SizeBytes         *uint64        `msgpack:"size_bytes,omitempty"`
	Annotations       map[string]any `msgpack:"annotations,omitempty"`
	Version           string         `msgpack:"version,omitempty"`
}

// ResourceReference is a lightweight resource reference without content.
type ResourceReference struct {
	ResourceRequestID string  `msgpack:"resource_request_id"`
	URI               string  `msgpack:"uri"`
	Name              string  `msgpack:"name,omitempty"`
	ResourceType      string  `msgpack:"resource_type"`
	RangeStart        *uint64 `msgpack:"range_start,omitempty"`
	RangeEnd          *uint64 `msgpack:"range_end,omitempty"`
	Selector          string  `msgpack:"selector,omitempty"`
}

// PromptRequest represents a prompt template invocation request (MCP).
type PromptRequest struct {
	PromptRequestID string         `msgpack:"prompt_request_id"`
	Name            string         `msgpack:"name"`
	Arguments       map[string]any `msgpack:"arguments,omitempty"`
	ServerID        string         `msgpack:"server_id,omitempty"`
}

// PromptResult represents a rendered prompt template result.
type PromptResult struct {
	PromptRequestID string    `msgpack:"prompt_request_id"`
	PromptName      string    `msgpack:"prompt_name"`
	Messages        []Message `msgpack:"messages,omitempty"`
	Content         string    `msgpack:"content,omitempty"`
	IsError         bool      `msgpack:"is_error,omitempty"`
	ErrorMessage    string    `msgpack:"error_message,omitempty"`
}

// ---------------------------------------------------------------------------
// Media Source Types
// ---------------------------------------------------------------------------

// ImageSource holds image data (URL or base64).
type ImageSource struct {
	SourceType string `msgpack:"type"`
	Data       string `msgpack:"data"`
	MediaType  string `msgpack:"media_type,omitempty"`
}

// VideoSource holds video data (URL or base64).
type VideoSource struct {
	SourceType string  `msgpack:"type"`
	Data       string  `msgpack:"data"`
	MediaType  string  `msgpack:"media_type,omitempty"`
	DurationMs *uint64 `msgpack:"duration_ms,omitempty"`
}

// AudioSource holds audio data (URL or base64).
type AudioSource struct {
	SourceType string  `msgpack:"type"`
	Data       string  `msgpack:"data"`
	MediaType  string  `msgpack:"media_type,omitempty"`
	DurationMs *uint64 `msgpack:"duration_ms,omitempty"`
}

// DocumentSource holds document data (URL or base64).
type DocumentSource struct {
	SourceType string `msgpack:"type"`
	Data       string `msgpack:"data"`
	MediaType  string `msgpack:"media_type,omitempty"`
	Title      string `msgpack:"title,omitempty"`
}

// ---------------------------------------------------------------------------
// Decode helpers — extract typed domain objects from a decoded `any` value.
// ---------------------------------------------------------------------------

// decodeAs re-encodes a decoded msgpack value and unmarshals it into a
// typed struct, letting the struct's msgpack tags drive field selection.
// Replaces 11 hand-rolled decoders that each had to enumerate fields
// manually — that pattern was the source of the silent data loss
// reviewer flagged in #13 (`DurationMs`, `RangeStart/End`, `Blob`,
// `SizeBytes`, `Messages` were all dropped). Adding a new field to a
// struct now Just Works without a corresponding decoder edit.
//
// Cost: an extra msgpack marshal + unmarshal per content part. This is
// on the per-message decode path, not per-pipeline-step. msgpack is
// fast; in practice it's microseconds. If this ever shows up on a hot
// path we can switch to msgpack's `Decoder.Query()` or hand-roll
// targeted decoders for specific high-volume types.
func decodeAs[T any](v any) *T {
	if v == nil {
		return nil
	}
	bytes, err := msgpack.Marshal(v)
	if err != nil {
		return nil
	}
	var out T
	if err := msgpack.Unmarshal(bytes, &out); err != nil {
		return nil
	}
	return &out
}
