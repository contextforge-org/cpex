// Location: ./go/cpex/constants.go
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Wire-format constants used across the encoder, decoder, and constructor
// helpers. Centralizing them prevents the silent mismatches you'd get from
// a typo in one of the three sites a value would otherwise be duplicated.
//
// All values match Rust's serde tag/field names exactly — adding a new
// variant requires syncing this file with the corresponding Rust enum.

package cpex

// Payload type IDs — must match Rust's PAYLOAD_* constants in
// crates/cpex-ffi/src/lib.rs. Used as the `payload_type` discriminator
// when crossing the FFI boundary.
const (
	// PayloadGeneric is a generic JSON-like payload (map[string]any).
	PayloadGeneric uint8 = 0
	// PayloadCMFMessage is a CMF MessagePayload.
	PayloadCMFMessage uint8 = 1
)

// ContentType values — the discriminator for ContentPart's tagged union.
// Wire-compatible with Rust's `#[serde(tag = "content_type")]` enum in
// `crates/cpex-core/src/cmf/`. Every string literal in cmf.go's encoder /
// decoder / constructor switches resolves to one of these.
const (
	ContentTypeText          = "text"
	ContentTypeThinking      = "thinking"
	ContentTypeToolCall      = "tool_call"
	ContentTypeToolResult    = "tool_result"
	ContentTypeResource      = "resource"
	ContentTypeResourceRef   = "resource_ref"
	ContentTypePromptRequest = "prompt_request"
	ContentTypePromptResult  = "prompt_result"
	ContentTypeImage         = "image"
	ContentTypeVideo         = "video"
	ContentTypeAudio         = "audio"
	ContentTypeDocument      = "document"
)

// Wire-format keys for the ContentPart tagged-union envelope. Unexported
// because they're an internal serialization detail — users build
// ContentPart via the constructors (NewTextPart, NewToolCallPart, …)
// and never touch the wire keys directly.
const (
	wireKeyContentType = "content_type"
	wireKeyContent     = "content"
	wireKeyText        = "text"
)

// FFI return codes from libcpex_ffi. 0 means success; negative codes
// classify the failure. Stable wire ABI with the Rust side — values must
// match `RC_*` constants in `crates/cpex-ffi/src/lib.rs`. Don't renumber.
const (
	rcOK             = 0
	rcInvalidHandle  = -1
	rcInvalidInput   = -2
	rcParseError     = -3
	rcPipelineError  = -4
	rcSerializeError = -5
	rcTimeout        = -6
	rcPanic          = -7
)
