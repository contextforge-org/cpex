// Location: ./go/cpex/cmf_test.go
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// MessagePack roundtrip coverage for the CMF tagged-union ContentPart.
//
// Pass 4 of the CGO review fixed an audit's worth of dropped fields
// across the per-variant decoders (DurationMs, RangeStart/End, Blob,
// SizeBytes, Messages, etc.) and rewrote them on top of a generic
// `decodeAs[T]` helper. These tests pin that fix: every variant must
// roundtrip msgpack with all its fields intact, and unknown variants
// must passthrough via the rawMap path.

package cpex

import (
	"reflect"
	"testing"

	"github.com/vmihailenco/msgpack/v5"
)

// roundTripContentPart encodes via ContentPart.EncodeMsgpack and
// decodes via ContentPart.DecodeMsgpack — the same path the FFI
// uses on either side of the boundary. Returns the decoded value
// for the caller to deep-compare.
func roundTripContentPart(t *testing.T, original ContentPart) ContentPart {
	t.Helper()
	bytes, err := msgpack.Marshal(original)
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}
	var decoded ContentPart
	if err := msgpack.Unmarshal(bytes, &decoded); err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	return decoded
}

func u64ptr(v uint64) *uint64 { return &v }

// Each subtest below builds a fully-populated variant — every field
// present, including the ones Pass 4's review found dropped — and
// asserts roundtrip equality via reflect.DeepEqual. A missing field
// in either the encoder or decoder produces a diff and a clean
// failure pointing at the variant.

func TestContentPart_RoundTripText(t *testing.T) {
	original := NewTextPart("hello world")
	got := roundTripContentPart(t, original)
	if !reflect.DeepEqual(original, got) {
		t.Errorf("text roundtrip mismatch:\n  want: %+v\n  got:  %+v", original, got)
	}
}

func TestContentPart_RoundTripThinking(t *testing.T) {
	original := NewThinkingPart("internal monologue")
	got := roundTripContentPart(t, original)
	if !reflect.DeepEqual(original, got) {
		t.Errorf("thinking roundtrip mismatch:\n  want: %+v\n  got:  %+v", original, got)
	}
}

func TestContentPart_RoundTripToolCall(t *testing.T) {
	original := NewToolCallPart(ToolCall{
		ToolCallID: "call-1",
		Name:       "search",
		Arguments:  map[string]any{"q": "anthropic", "limit": int64(10)},
		Namespace:  "tools.web",
	})
	got := roundTripContentPart(t, original)
	if !reflect.DeepEqual(original, got) {
		t.Errorf("tool_call roundtrip mismatch:\n  want: %+v\n  got:  %+v", original, got)
	}
}

func TestContentPart_RoundTripToolResult(t *testing.T) {
	original := NewToolResultPart(ToolResult{
		ToolCallID: "call-1",
		ToolName:   "search",
		Content:    "result body",
		IsError:    false,
	})
	got := roundTripContentPart(t, original)
	if !reflect.DeepEqual(original, got) {
		t.Errorf("tool_result roundtrip mismatch:\n  want: %+v\n  got:  %+v", original, got)
	}
}

func TestContentPart_RoundTripResource(t *testing.T) {
	// All Pass 4-restored fields populated: Blob, SizeBytes, plus the
	// existing ones. If decodeAs[Resource] drops any of these the
	// reflect.DeepEqual catches it.
	original := NewResourcePart(Resource{
		ResourceRequestID: "req-1",
		URI:               "file://x",
		Name:              "x.txt",
		Description:       "a file",
		ResourceType:      "text",
		Content:           "body",
		Blob:              []byte{0x01, 0x02, 0x03},
		MimeType:          "text/plain",
		SizeBytes:         u64ptr(3),
		Annotations:       map[string]any{"tag": "v1"},
		Version:           "v1",
	})
	got := roundTripContentPart(t, original)
	if !reflect.DeepEqual(original, got) {
		t.Errorf("resource roundtrip mismatch:\n  want: %+v\n  got:  %+v", original, got)
	}
}

func TestContentPart_RoundTripResourceRef(t *testing.T) {
	// RangeStart/RangeEnd were both dropped pre-Pass 4 — explicit fields here.
	original := NewResourceRefPart(ResourceReference{
		ResourceRequestID: "req-2",
		URI:               "file://y",
		Name:              "y.txt",
		ResourceType:      "text",
		RangeStart:        u64ptr(0),
		RangeEnd:          u64ptr(100),
		Selector:          "$.body",
	})
	got := roundTripContentPart(t, original)
	if !reflect.DeepEqual(original, got) {
		t.Errorf("resource_ref roundtrip mismatch:\n  want: %+v\n  got:  %+v", original, got)
	}
}

func TestContentPart_RoundTripPromptRequest(t *testing.T) {
	original := NewPromptRequestPart(PromptRequest{
		PromptRequestID: "pr-1",
		Name:            "summarize",
		Arguments:       map[string]any{"length": "short"},
		ServerID:        "srv-1",
	})
	got := roundTripContentPart(t, original)
	if !reflect.DeepEqual(original, got) {
		t.Errorf("prompt_request roundtrip mismatch:\n  want: %+v\n  got:  %+v", original, got)
	}
}

func TestContentPart_RoundTripPromptResult(t *testing.T) {
	// Messages was dropped entirely pre-Pass 4. Populating it here
	// pins the fix.
	original := NewPromptResultPart(PromptResult{
		PromptRequestID: "pr-1",
		PromptName:      "summarize",
		Messages: []Message{
			NewMessage("user", NewTextPart("input")),
			NewMessage("assistant", NewTextPart("output")),
		},
		Content:      "summary text",
		IsError:      false,
		ErrorMessage: "",
	})
	got := roundTripContentPart(t, original)
	if !reflect.DeepEqual(original, got) {
		t.Errorf("prompt_result roundtrip mismatch:\n  want: %+v\n  got:  %+v", original, got)
	}
}

func TestContentPart_RoundTripImage(t *testing.T) {
	original := NewImagePart(ImageSource{
		SourceType: "base64",
		Data:       "aW1hZ2U=",
		MediaType:  "image/png",
	})
	got := roundTripContentPart(t, original)
	if !reflect.DeepEqual(original, got) {
		t.Errorf("image roundtrip mismatch:\n  want: %+v\n  got:  %+v", original, got)
	}
}

func TestContentPart_RoundTripVideo(t *testing.T) {
	// DurationMs was dropped pre-Pass 4 — explicit field here.
	original := NewVideoPart(VideoSource{
		SourceType: "url",
		Data:       "https://example/v.mp4",
		MediaType:  "video/mp4",
		DurationMs: u64ptr(15000),
	})
	got := roundTripContentPart(t, original)
	if !reflect.DeepEqual(original, got) {
		t.Errorf("video roundtrip mismatch:\n  want: %+v\n  got:  %+v", original, got)
	}
}

func TestContentPart_RoundTripAudio(t *testing.T) {
	// Same DurationMs drop — explicit field.
	original := NewAudioPart(AudioSource{
		SourceType: "base64",
		Data:       "YXVkaW8=",
		MediaType:  "audio/mp3",
		DurationMs: u64ptr(5500),
	})
	got := roundTripContentPart(t, original)
	if !reflect.DeepEqual(original, got) {
		t.Errorf("audio roundtrip mismatch:\n  want: %+v\n  got:  %+v", original, got)
	}
}

func TestContentPart_RoundTripDocument(t *testing.T) {
	original := NewDocumentPart(DocumentSource{
		SourceType: "url",
		Data:       "https://example/d.pdf",
		MediaType:  "application/pdf",
		Title:      "doc",
	})
	got := roundTripContentPart(t, original)
	if !reflect.DeepEqual(original, got) {
		t.Errorf("document roundtrip mismatch:\n  want: %+v\n  got:  %+v", original, got)
	}
}

// Forward-compat: a content_type the Go decoder doesn't recognize
// must passthrough via rawMap so that re-encoding produces the same
// wire bytes. This protects against silent drops when Rust adds a
// variant that Go hasn't been updated for yet.
func TestContentPart_UnknownVariantPassesThrough(t *testing.T) {
	// Build a payload by encoding a known structure with an
	// unrecognized content_type tag — simulate Rust shipping a future
	// variant.
	wireMap := map[string]any{
		"content_type": "future_variant_v2",
		"content": map[string]any{
			"foo": "bar",
			"n":   int64(42),
		},
	}
	originalBytes, err := msgpack.Marshal(wireMap)
	if err != nil {
		t.Fatalf("encode wire fixture failed: %v", err)
	}

	var cp ContentPart
	if err := msgpack.Unmarshal(originalBytes, &cp); err != nil {
		t.Fatalf("decode unknown variant failed: %v", err)
	}

	// Re-encode and compare to the original wire bytes. The tag and
	// the body must both survive intact — that's what rawMap is for.
	roundTripBytes, err := msgpack.Marshal(cp)
	if err != nil {
		t.Fatalf("re-encode failed: %v", err)
	}

	// Decode both sides into generic maps to compare semantically
	// (msgpack key ordering is not guaranteed across encode passes).
	var originalMap, roundTripMap map[string]any
	if err := msgpack.Unmarshal(originalBytes, &originalMap); err != nil {
		t.Fatalf("decode original to map: %v", err)
	}
	if err := msgpack.Unmarshal(roundTripBytes, &roundTripMap); err != nil {
		t.Fatalf("decode roundtrip to map: %v", err)
	}
	if !reflect.DeepEqual(originalMap, roundTripMap) {
		t.Errorf("unknown variant passthrough mismatch:\n  want: %+v\n  got:  %+v",
			originalMap, roundTripMap)
	}
}
