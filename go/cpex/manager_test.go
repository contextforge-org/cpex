// Location: ./go/cpex/manager_test.go
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// Tests for the CPEX Go SDK.
//
// These tests run against the real Rust runtime via cgo. The
// libcpex_ffi staticlib must be built before running:
//
//	cargo build --release -p cpex-ffi
//	go test -v ./...

package cpex

import (
	"errors"
	"sync"
	"testing"

	"github.com/vmihailenco/msgpack/v5"
)

func TestNewPluginManagerDefault(t *testing.T) {
	mgr, err := NewPluginManagerDefault()
	if err != nil {
		t.Fatalf("NewPluginManagerDefault failed: %v", err)
	}
	defer mgr.Shutdown()

	if mgr.PluginCount() != 0 {
		t.Errorf("expected 0 plugins, got %d", mgr.PluginCount())
	}

	if mgr.HasHooksFor("test_hook") {
		t.Error("expected no hooks registered")
	}
}

func TestNewPluginManagerFromYAML(t *testing.T) {
	yaml := `
plugin_settings:
  plugin_timeout: 30
`
	mgr, err := NewPluginManager(yaml)
	if err != nil {
		t.Fatalf("NewPluginManager failed: %v", err)
	}
	defer mgr.Shutdown()

	if err := mgr.Initialize(); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	if mgr.PluginCount() != 0 {
		t.Errorf("expected 0 plugins, got %d", mgr.PluginCount())
	}
}

func TestNewPluginManagerInvalidYAML(t *testing.T) {
	_, err := NewPluginManager("not: [valid: yaml: {{}")
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestInvokeByNameNoPlugins(t *testing.T) {
	mgr, err := NewPluginManagerDefault()
	if err != nil {
		t.Fatalf("NewPluginManagerDefault failed: %v", err)
	}
	defer mgr.Shutdown()

	if err := mgr.Initialize(); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	// Invoke with no registered plugins — should return allowed
	payload := map[string]any{
		"tool_name": "test_tool",
		"user":      "alice",
	}

	ext := &Extensions{
		Meta: &MetaExtension{
			EntityType: "tool",
			EntityName: "test_tool",
		},
	}

	result, ctxTable, bg, err := mgr.InvokeByName("test_hook", PayloadGeneric, payload, ext, nil)
	if err != nil {
		t.Fatalf("InvokeByName failed: %v", err)
	}
	defer ctxTable.Close()
	defer bg.Close()

	if result.IsDenied() {
		t.Error("expected allowed result with no plugins")
	}

	if !result.ContinueProcessing {
		t.Error("expected continue_processing=true")
	}
}

func TestInvokeByNameWithContextTableThreading(t *testing.T) {
	mgr, err := NewPluginManagerDefault()
	if err != nil {
		t.Fatalf("NewPluginManagerDefault failed: %v", err)
	}
	defer mgr.Shutdown()

	if err := mgr.Initialize(); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	payload := map[string]any{"tool_name": "test"}
	ext := &Extensions{}

	// First invocation — nil context table
	result1, ctxTable1, bg1, err := mgr.InvokeByName("hook1", PayloadGeneric, payload, ext, nil)
	if err != nil {
		t.Fatalf("first invoke failed: %v", err)
	}
	bg1.Close()

	if result1.IsDenied() {
		t.Error("first invoke should be allowed")
	}

	// Second invocation — thread context table from first
	result2, ctxTable2, bg2, err := mgr.InvokeByName("hook2", PayloadGeneric, payload, ext, ctxTable1)
	if err != nil {
		t.Fatalf("second invoke failed: %v", err)
	}
	bg2.Close()

	if result2.IsDenied() {
		t.Error("second invoke should be allowed")
	}

	ctxTable2.Close()
}

func TestBackgroundTasksWait(t *testing.T) {
	mgr, err := NewPluginManagerDefault()
	if err != nil {
		t.Fatalf("NewPluginManagerDefault failed: %v", err)
	}
	defer mgr.Shutdown()

	if err := mgr.Initialize(); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	payload := map[string]any{"test": true}

	result, ctxTable, bg, err := mgr.InvokeByName("test", PayloadGeneric, payload, nil, nil)
	if err != nil {
		t.Fatalf("invoke failed: %v", err)
	}
	defer ctxTable.Close()

	_ = result

	// Wait should return with no errors (no plugins to run)
	errors, err := bg.Wait()
	if err != nil {
		t.Errorf("bg.Wait failed: %v", err)
	}
	if len(errors) > 0 {
		t.Errorf("expected no background errors, got: %v", errors)
	}
}

// Concurrent goroutines invoking against a single manager must be safe
// (validates the P0 #1 aliased-&mut fix and the Pass 2 RWMutex). Run
// under -race to surface any data races on the handle.
func TestConcurrentInvokesAreSafe(t *testing.T) {
	mgr, err := NewPluginManagerDefault()
	if err != nil {
		t.Fatalf("NewPluginManagerDefault failed: %v", err)
	}
	defer mgr.Shutdown()

	const goroutines = 32
	const callsPerGoroutine = 16

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < callsPerGoroutine; j++ {
				payload := map[string]any{"i": i, "j": j}
				_, ct, bg, err := mgr.InvokeByName("noop", PayloadGeneric, payload, nil, nil)
				if err != nil {
					t.Errorf("invoke failed: %v", err)
					return
				}
				if ct != nil {
					ct.Close()
				}
				if bg != nil {
					_, _ = bg.Wait()
				}
			}
		}()
	}
	wg.Wait()
}

// Calling Shutdown while goroutines are mid-invoke must not double-free
// or panic. After Shutdown, in-flight invokes should observe that the
// manager is shutdown and return an error gracefully.
func TestShutdownDuringInvokesIsSafe(t *testing.T) {
	mgr, err := NewPluginManagerDefault()
	if err != nil {
		t.Fatalf("NewPluginManagerDefault failed: %v", err)
	}

	// Spawn workers that invoke in a tight loop until they observe shutdown.
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				payload := map[string]any{"x": 1}
				_, ct, bg, err := mgr.InvokeByName("noop", PayloadGeneric, payload, nil, nil)
				if err != nil {
					// Expected once Shutdown lands; just stop.
					return
				}
				if ct != nil {
					ct.Close()
				}
				if bg != nil {
					_, _ = bg.Wait()
				}
			}
		}()
	}

	// Let them spin for a moment, then shutdown.
	mgr.Shutdown()
	close(stop)
	wg.Wait()

	// Second Shutdown must be a no-op (P1 #4 fix — finalizer cleared,
	// double-call returns immediately).
	mgr.Shutdown()
}

// BackgroundTasks.Wait() called after the manager has been Shutdown
// must return ErrCpexInvalidHandle without crashing or reading
// uninitialized output pointers. Direct regression for the P1 #3 +
// P1 #5 fix path where bg holds a *PluginManager and checks handle
// nullness under the manager's RWMutex.
func TestBackgroundTasksWaitAfterShutdownReturnsTypedError(t *testing.T) {
	mgr, err := NewPluginManagerDefault()
	if err != nil {
		t.Fatalf("NewPluginManagerDefault failed: %v", err)
	}
	if err := mgr.Initialize(); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	_, _, bg, err := mgr.InvokeByName("noop", PayloadGeneric, map[string]any{}, nil, nil)
	if err != nil {
		t.Fatalf("InvokeByName failed: %v", err)
	}

	// Tear the manager down BEFORE waiting on the background tasks.
	mgr.Shutdown()

	// Wait must observe the shutdown handle and return a typed error
	// — not panic, not segfault on a stale C pointer, not silently
	// return empty.
	results, err := bg.Wait()
	if !errors.Is(err, ErrCpexInvalidHandle) {
		t.Errorf("expected ErrCpexInvalidHandle, got %v", err)
	}
	if results != nil {
		t.Errorf("expected nil results on error path, got %v", results)
	}
}

// Invoking with an unknown payload_type discriminator must return an
// error wrapping ErrCpexParse — the deserialize_payload registry
// rejects unknown values with RC_PARSE_ERROR, which the Go side
// classifies via errorFromRC.
func TestInvokeUnknownPayloadTypeReturnsParseError(t *testing.T) {
	mgr, err := NewPluginManagerDefault()
	if err != nil {
		t.Fatalf("NewPluginManagerDefault failed: %v", err)
	}
	defer mgr.Shutdown()
	if err := mgr.Initialize(); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	const unknownType uint8 = 99 // not in the FFI payload registry
	_, _, _, err = mgr.InvokeByName("test_hook", unknownType, map[string]any{}, nil, nil)
	if !errors.Is(err, ErrCpexParse) {
		t.Errorf("expected ErrCpexParse for unknown payload_type, got %v", err)
	}
}

// IsInitialized reports manager lifecycle accurately: false until
// Initialize is called, true after, false again after Shutdown.
// Validates agent-native gap #4 — introspection FFI.
func TestIsInitializedTracksLifecycle(t *testing.T) {
	mgr, err := NewPluginManagerDefault()
	if err != nil {
		t.Fatalf("NewPluginManagerDefault failed: %v", err)
	}

	if mgr.IsInitialized() {
		t.Error("expected IsInitialized=false before Initialize")
	}
	if err := mgr.Initialize(); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
	if !mgr.IsInitialized() {
		t.Error("expected IsInitialized=true after Initialize")
	}

	mgr.Shutdown()
	if mgr.IsInitialized() {
		t.Error("expected IsInitialized=false after Shutdown")
	}
}

// PluginNames returns the names of plugins registered via YAML config.
// Validates agent-native gap #4 — introspection FFI.
func TestPluginNamesEmptyByDefault(t *testing.T) {
	mgr, err := NewPluginManagerDefault()
	if err != nil {
		t.Fatalf("NewPluginManagerDefault failed: %v", err)
	}
	defer mgr.Shutdown()

	names, err := mgr.PluginNames()
	if err != nil {
		t.Fatalf("PluginNames failed: %v", err)
	}
	if len(names) != 0 {
		t.Errorf("expected empty plugin names on a default manager, got %v", names)
	}
}

// BackgroundTasks.Wait returns []PluginError (structured) — gap #3.
// On a no-plugin invoke the slice is empty but non-nil-shaped.
func TestBackgroundTasksWaitReturnsStructuredErrors(t *testing.T) {
	mgr, err := NewPluginManagerDefault()
	if err != nil {
		t.Fatalf("NewPluginManagerDefault failed: %v", err)
	}
	defer mgr.Shutdown()
	if err := mgr.Initialize(); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	_, _, bg, err := mgr.InvokeByName("test", PayloadGeneric, map[string]any{}, nil, nil)
	if err != nil {
		t.Fatalf("Invoke failed: %v", err)
	}

	errs, err := bg.Wait()
	if err != nil {
		t.Errorf("Wait failed: %v", err)
	}
	// errs is []PluginError — typed at compile time. Empty for a
	// no-plugin manager, but the structured type is what we wanted.
	if len(errs) != 0 {
		t.Errorf("expected no errors on no-plugin invoke, got %d: %v", len(errs), errs)
	}
}

// Operations on a shutdown manager must return an error wrapping
// ErrCpexInvalidHandle so callers can classify with errors.Is.
// Validates the P2 #18 typed-error mapping end-to-end.
func TestOperationsAfterShutdownReturnTypedError(t *testing.T) {
	mgr, err := NewPluginManagerDefault()
	if err != nil {
		t.Fatalf("NewPluginManagerDefault failed: %v", err)
	}
	mgr.Shutdown()

	if err := mgr.Initialize(); !errors.Is(err, ErrCpexInvalidHandle) {
		t.Errorf("Initialize after shutdown: expected ErrCpexInvalidHandle, got %v", err)
	}
	if err := mgr.LoadConfig("plugin_settings: {}"); !errors.Is(err, ErrCpexInvalidHandle) {
		t.Errorf("LoadConfig after shutdown: expected ErrCpexInvalidHandle, got %v", err)
	}
	_, _, _, err = mgr.InvokeByName("test", PayloadGeneric, map[string]any{}, nil, nil)
	if !errors.Is(err, ErrCpexInvalidHandle) {
		t.Errorf("InvokeByName after shutdown: expected ErrCpexInvalidHandle, got %v", err)
	}
}

func TestPluginManagerDoubleShutdown(t *testing.T) {
	mgr, err := NewPluginManagerDefault()
	if err != nil {
		t.Fatalf("NewPluginManagerDefault failed: %v", err)
	}

	mgr.Shutdown()
	// Second shutdown should not panic
	mgr.Shutdown()
}

func TestContextTableDoubleClose(t *testing.T) {
	ct := &ContextTable{}
	ct.Close() // should not panic
	ct.Close() // should not panic
}

func TestBackgroundTasksDoubleClose(t *testing.T) {
	bg := &BackgroundTasks{}
	bg.Close() // should not panic
	bg.Close() // should not panic
}

func TestPipelineResultIsDenied(t *testing.T) {
	allowed := PipelineResult{ContinueProcessing: true}
	if allowed.IsDenied() {
		t.Error("expected not denied")
	}

	denied := PipelineResult{
		ContinueProcessing: false,
		Violation: &PluginViolation{
			Code:   "test_denied",
			Reason: "test reason",
		},
	}
	if !denied.IsDenied() {
		t.Error("expected denied")
	}
}

func TestExtensionsSerialization(t *testing.T) {
	ext := Extensions{
		Meta: &MetaExtension{
			EntityType: "tool",
			EntityName: "get_compensation",
			Tags:       []string{"pii", "hr"},
		},
		Security: &SecurityExtension{
			Labels:         []string{"PII"},
			Classification: "confidential",
			Agent: &AgentIdentity{
				ClientID:    "hr-agent",
				WorkloadID:  "spiffe://corp.com/hr-agent",
				TrustDomain: "corp.com",
			},
		},
		Http: &HttpExtension{
			RequestHeaders: map[string]string{
				"Authorization": "Bearer tok",
				"X-Request-ID":  "req-123",
			},
		},
	}

	// Verify it can be marshaled without error
	_, err := msgpackMarshal(ext)
	if err != nil {
		t.Fatalf("extensions marshal failed: %v", err)
	}
}

// msgpackMarshal is a helper that imports msgpack for the test
func msgpackMarshal(v any) ([]byte, error) {
	return msgpack.Marshal(v)
}

// ---------------------------------------------------------------------------
// Typed Invoke Tests
// ---------------------------------------------------------------------------

func TestInvokeTypedGenericPayload(t *testing.T) {
	mgr, err := NewPluginManagerDefault()
	if err != nil {
		t.Fatalf("NewPluginManagerDefault failed: %v", err)
	}
	defer mgr.Shutdown()

	if err := mgr.Initialize(); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	payload := map[string]any{
		"tool_name": "test_tool",
		"user":      "alice",
	}

	result, ct, bg, err := Invoke[map[string]any](
		mgr, "test_hook", PayloadGeneric, payload, &Extensions{}, nil,
	)
	if err != nil {
		t.Fatalf("Invoke failed: %v", err)
	}
	defer ct.Close()
	defer bg.Close()

	if result.IsDenied() {
		t.Error("expected allowed result")
	}

	if !result.ContinueProcessing {
		t.Error("expected continue_processing=true")
	}
}

func TestInvokeTypedCMFPayload(t *testing.T) {
	mgr, err := NewPluginManagerDefault()
	if err != nil {
		t.Fatalf("NewPluginManagerDefault failed: %v", err)
	}
	defer mgr.Shutdown()

	if err := mgr.Initialize(); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	msg := MessagePayload{
		Message: NewMessage("assistant",
			NewTextPart("Looking up compensation data"),
			NewToolCallPart(ToolCall{
				ToolCallID: "tc_001",
				Name:       "get_compensation",
				Arguments:  map[string]any{"employee_id": 42},
			}),
		),
	}

	ext := &Extensions{
		Meta: &MetaExtension{
			EntityType: "tool",
			EntityName: "get_compensation",
			Tags:       []string{"pii"},
		},
	}

	result, ct, bg, err := Invoke[MessagePayload](
		mgr, "cmf.tool_pre_invoke", PayloadCMFMessage, msg, ext, nil,
	)
	if err != nil {
		t.Fatalf("Invoke failed: %v", err)
	}
	defer ct.Close()
	defer bg.Close()

	if result.IsDenied() {
		t.Error("expected allowed with no plugins")
	}
}

func TestInvokeTypedContextThreading(t *testing.T) {
	mgr, err := NewPluginManagerDefault()
	if err != nil {
		t.Fatalf("NewPluginManagerDefault failed: %v", err)
	}
	defer mgr.Shutdown()

	if err := mgr.Initialize(); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	payload := map[string]any{"tool_name": "test"}

	// First call — nil context table
	r1, ct1, bg1, err := Invoke[map[string]any](
		mgr, "hook1", PayloadGeneric, payload, &Extensions{}, nil,
	)
	if err != nil {
		t.Fatalf("first invoke failed: %v", err)
	}
	bg1.Close()

	if r1.IsDenied() {
		t.Error("first invoke should be allowed")
	}

	// Second call — thread context table
	r2, ct2, bg2, err := Invoke[map[string]any](
		mgr, "hook2", PayloadGeneric, payload, &Extensions{}, ct1,
	)
	if err != nil {
		t.Fatalf("second invoke failed: %v", err)
	}
	bg2.Close()

	if r2.IsDenied() {
		t.Error("second invoke should be allowed")
	}

	ct2.Close()
}

func TestTypedPipelineResultIsDenied(t *testing.T) {
	allowed := TypedPipelineResult[map[string]any]{ContinueProcessing: true}
	if allowed.IsDenied() {
		t.Error("expected not denied")
	}

	denied := TypedPipelineResult[map[string]any]{
		ContinueProcessing: false,
		Violation: &PluginViolation{
			Code:   "test",
			Reason: "denied",
		},
	}
	if !denied.IsDenied() {
		t.Error("expected denied")
	}
}

// ---------------------------------------------------------------------------
// CMF Content Part Tests
// ---------------------------------------------------------------------------

func TestContentPartTextRoundTrip(t *testing.T) {
	part := NewTextPart("hello world")

	data, err := msgpack.Marshal(part)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var decoded ContentPart
	if err := msgpack.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if decoded.ContentType != "text" {
		t.Errorf("expected content_type=text, got %s", decoded.ContentType)
	}
	if decoded.Text != "hello world" {
		t.Errorf("expected text='hello world', got '%s'", decoded.Text)
	}
}

func TestContentPartThinkingRoundTrip(t *testing.T) {
	part := NewThinkingPart("let me analyze...")

	data, err := msgpack.Marshal(part)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var decoded ContentPart
	if err := msgpack.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if decoded.ContentType != "thinking" {
		t.Errorf("expected content_type=thinking, got %s", decoded.ContentType)
	}
	if decoded.Text != "let me analyze..." {
		t.Errorf("expected thinking text, got '%s'", decoded.Text)
	}
}

func TestContentPartToolCallRoundTrip(t *testing.T) {
	part := NewToolCallPart(ToolCall{
		ToolCallID: "tc_001",
		Name:       "get_weather",
		Arguments:  map[string]any{"city": "London"},
		Namespace:  "tools",
	})

	data, err := msgpack.Marshal(part)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var decoded ContentPart
	if err := msgpack.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if decoded.ContentType != "tool_call" {
		t.Errorf("expected content_type=tool_call, got %s", decoded.ContentType)
	}
	if decoded.ToolCallContent == nil {
		t.Fatal("expected ToolCallContent to be set")
	}
	if decoded.ToolCallContent.Name != "get_weather" {
		t.Errorf("expected name=get_weather, got %s", decoded.ToolCallContent.Name)
	}
	if decoded.ToolCallContent.ToolCallID != "tc_001" {
		t.Errorf("expected tool_call_id=tc_001, got %s", decoded.ToolCallContent.ToolCallID)
	}
	if decoded.ToolCallContent.Namespace != "tools" {
		t.Errorf("expected namespace=tools, got %s", decoded.ToolCallContent.Namespace)
	}
}

func TestContentPartToolResultRoundTrip(t *testing.T) {
	part := NewToolResultPart(ToolResult{
		ToolCallID: "tc_001",
		ToolName:   "get_weather",
		Content:    map[string]any{"temp": 20, "unit": "C"},
		IsError:    false,
	})

	data, err := msgpack.Marshal(part)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var decoded ContentPart
	if err := msgpack.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if decoded.ContentType != "tool_result" {
		t.Errorf("expected content_type=tool_result, got %s", decoded.ContentType)
	}
	if decoded.ToolResultContent == nil {
		t.Fatal("expected ToolResultContent to be set")
	}
	if decoded.ToolResultContent.ToolName != "get_weather" {
		t.Errorf("expected tool_name=get_weather, got %s", decoded.ToolResultContent.ToolName)
	}
}

func TestContentPartResourceRoundTrip(t *testing.T) {
	part := NewResourcePart(Resource{
		ResourceRequestID: "rr_001",
		URI:               "file:///data.txt",
		ResourceType:      "file",
		Content:           "Hello from file",
		MimeType:          "text/plain",
	})

	data, err := msgpack.Marshal(part)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var decoded ContentPart
	if err := msgpack.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if decoded.ContentType != "resource" {
		t.Errorf("expected content_type=resource, got %s", decoded.ContentType)
	}
	if decoded.ResourceContent == nil {
		t.Fatal("expected ResourceContent to be set")
	}
	if decoded.ResourceContent.URI != "file:///data.txt" {
		t.Errorf("expected uri=file:///data.txt, got %s", decoded.ResourceContent.URI)
	}
	if decoded.ResourceContent.Content != "Hello from file" {
		t.Errorf("expected content='Hello from file', got '%s'", decoded.ResourceContent.Content)
	}
}

func TestContentPartImageRoundTrip(t *testing.T) {
	part := NewImagePart(ImageSource{
		SourceType: "url",
		Data:       "https://example.com/photo.jpg",
		MediaType:  "image/jpeg",
	})

	data, err := msgpack.Marshal(part)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var decoded ContentPart
	if err := msgpack.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if decoded.ContentType != "image" {
		t.Errorf("expected content_type=image, got %s", decoded.ContentType)
	}
	if decoded.ImageContent == nil {
		t.Fatal("expected ImageContent to be set")
	}
	if decoded.ImageContent.SourceType != "url" {
		t.Errorf("expected type=url, got %s", decoded.ImageContent.SourceType)
	}
	if decoded.ImageContent.Data != "https://example.com/photo.jpg" {
		t.Errorf("expected data URL, got %s", decoded.ImageContent.Data)
	}
}

func TestContentPartDocumentRoundTrip(t *testing.T) {
	part := NewDocumentPart(DocumentSource{
		SourceType: "base64",
		Data:       "dGVzdA==",
		MediaType:  "application/pdf",
		Title:      "Quarterly Report",
	})

	data, err := msgpack.Marshal(part)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var decoded ContentPart
	if err := msgpack.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if decoded.ContentType != "document" {
		t.Errorf("expected content_type=document, got %s", decoded.ContentType)
	}
	if decoded.DocumentContent == nil {
		t.Fatal("expected DocumentContent to be set")
	}
	if decoded.DocumentContent.Title != "Quarterly Report" {
		t.Errorf("expected title='Quarterly Report', got '%s'", decoded.DocumentContent.Title)
	}
}

// Regression for P2 #13 — `decodeVideoSource`/`decodeAudioSource`
// previously dropped DurationMs. With the generic decodeAs[T] helper
// driven by msgpack tags, fields can no longer be silently lost.
func TestContentPartVideoRoundTripWithDuration(t *testing.T) {
	dur := uint64(15000)
	part := NewVideoPart(VideoSource{
		SourceType: "url",
		Data:       "https://example.com/v.mp4",
		MediaType:  "video/mp4",
		DurationMs: &dur,
	})
	data, err := msgpack.Marshal(part)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded ContentPart
	if err := msgpack.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.VideoContent == nil {
		t.Fatal("VideoContent nil")
	}
	if decoded.VideoContent.DurationMs == nil || *decoded.VideoContent.DurationMs != 15000 {
		t.Errorf("DurationMs lost: %v", decoded.VideoContent.DurationMs)
	}
}

// Regression for P2 #13 — `decodeResource` previously dropped Blob
// and SizeBytes; `decodeResourceRef` dropped RangeStart and RangeEnd.
func TestContentPartResourceFieldsPreserved(t *testing.T) {
	size := uint64(2048)
	rstart := uint64(100)
	rend := uint64(500)

	resource := NewResourcePart(Resource{
		ResourceRequestID: "rr_1",
		URI:               "file:///doc.bin",
		ResourceType:      "binary",
		Blob:              []byte{0xDE, 0xAD, 0xBE, 0xEF},
		SizeBytes:         &size,
		MimeType:          "application/octet-stream",
	})
	data, err := msgpack.Marshal(resource)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var d1 ContentPart
	if err := msgpack.Unmarshal(data, &d1); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if d1.ResourceContent == nil {
		t.Fatal("ResourceContent nil")
	}
	if string(d1.ResourceContent.Blob) != "\xDE\xAD\xBE\xEF" {
		t.Errorf("Blob lost: %v", d1.ResourceContent.Blob)
	}
	if d1.ResourceContent.SizeBytes == nil || *d1.ResourceContent.SizeBytes != 2048 {
		t.Errorf("SizeBytes lost: %v", d1.ResourceContent.SizeBytes)
	}

	ref := NewResourceRefPart(ResourceReference{
		ResourceRequestID: "rr_2",
		URI:               "file:///doc.bin",
		ResourceType:      "binary",
		RangeStart:        &rstart,
		RangeEnd:          &rend,
	})
	data, err = msgpack.Marshal(ref)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var d2 ContentPart
	if err := msgpack.Unmarshal(data, &d2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if d2.ResourceRefContent == nil {
		t.Fatal("ResourceRefContent nil")
	}
	if d2.ResourceRefContent.RangeStart == nil || *d2.ResourceRefContent.RangeStart != 100 {
		t.Errorf("RangeStart lost: %v", d2.ResourceRefContent.RangeStart)
	}
	if d2.ResourceRefContent.RangeEnd == nil || *d2.ResourceRefContent.RangeEnd != 500 {
		t.Errorf("RangeEnd lost: %v", d2.ResourceRefContent.RangeEnd)
	}
}

// Regression for P2 #13 — `decodePromptResult` previously dropped
// the Messages field entirely (with a "TODO: nested decode" comment).
// The generic helper handles it correctly, including nested Messages
// with their own ContentPart custom decoder.
func TestContentPartPromptResultPreservesMessages(t *testing.T) {
	pr := NewPromptResultPart(PromptResult{
		PromptRequestID: "pr_1",
		PromptName:      "summarize",
		Messages: []Message{
			NewMessage("system", NewTextPart("You are concise.")),
			NewMessage("user", NewTextPart("Summarize the report.")),
		},
	})
	data, err := msgpack.Marshal(pr)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded ContentPart
	if err := msgpack.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.PromptResultContent == nil {
		t.Fatal("PromptResultContent nil")
	}
	if len(decoded.PromptResultContent.Messages) != 2 {
		t.Fatalf("expected 2 nested messages, got %d", len(decoded.PromptResultContent.Messages))
	}
	if decoded.PromptResultContent.Messages[0].Role != "system" {
		t.Errorf("first nested role lost: %s", decoded.PromptResultContent.Messages[0].Role)
	}
	if len(decoded.PromptResultContent.Messages[1].Content) != 1 ||
		decoded.PromptResultContent.Messages[1].Content[0].Text != "Summarize the report." {
		t.Errorf("nested content lost: %+v", decoded.PromptResultContent.Messages[1].Content)
	}
}

// Regression for P2 #17 — unknown content_type variants previously
// decoded to an empty ContentPart and re-encoded as a text fallback,
// silently dropping the original payload. Now the raw map is captured
// on decode and emitted verbatim on encode, so a future variant from
// Rust passes through an older Go SDK without data loss.
func TestContentPartUnknownContentTypeRoundTrip(t *testing.T) {
	// Simulate a future Rust variant by encoding a map directly.
	original := map[string]any{
		"content_type": "future_variant",
		"content": map[string]any{
			"new_field": "value",
			"count":     uint64(42),
		},
	}
	wire, err := msgpack.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Decode through ContentPart's custom decoder, then re-encode.
	var cp ContentPart
	if err := msgpack.Unmarshal(wire, &cp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if cp.ContentType != "future_variant" {
		t.Errorf("ContentType lost: %s", cp.ContentType)
	}
	roundtripped, err := msgpack.Marshal(cp)
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}

	// Decode the roundtripped wire as a plain map and verify the
	// new_field is still there.
	var back map[string]any
	if err := msgpack.Unmarshal(roundtripped, &back); err != nil {
		t.Fatalf("unmarshal back: %v", err)
	}
	contentMap, ok := back["content"].(map[string]any)
	if !ok {
		t.Fatalf("content field missing or wrong type after roundtrip: %#v", back)
	}
	if contentMap["new_field"] != "value" {
		t.Errorf("new_field lost across roundtrip: %#v", contentMap)
	}
}

// Regression for P2 #14, #15, #16 — Extension fields that Rust
// serializes but Go was silently dropping. Round-trip a populated
// Extensions through msgpack and verify each field survives.
func TestExtensionsAddedFieldsRoundTrip(t *testing.T) {
	turn := uint32(7)
	ext := &Extensions{
		Agent: &AgentExtension{
			SessionID:      "sess_1",
			ConversationID: "conv_1",
			Turn:           &turn,
			AgentID:        "agent_1",
			Conversation: &ConversationContext{
				History: []any{"prior turn"},
				Summary: "user asked for compensation lookup",
				Topics:  []string{"hr", "compensation"},
			},
		},
		MCP: &MCPExtension{
			Tool: &ToolMetadata{
				Name:         "get_compensation",
				OutputSchema: map[string]any{"type": "object"},
				Annotations:  map[string]any{"audit_required": true},
			},
		},
		Completion: &CompletionExtension{
			Model:     "claude-sonnet-4-6",
			RawFormat: "anthropic",
			CreatedAt: "2026-05-04T10:00:00Z",
		},
	}

	data, err := msgpack.Marshal(ext)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back Extensions
	if err := msgpack.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if back.Agent == nil || back.Agent.Conversation == nil {
		t.Fatal("Agent.Conversation lost")
	}
	if back.Agent.Conversation.Summary != "user asked for compensation lookup" {
		t.Errorf("Conversation.Summary lost: %q", back.Agent.Conversation.Summary)
	}
	if len(back.Agent.Conversation.Topics) != 2 {
		t.Errorf("Conversation.Topics lost: %v", back.Agent.Conversation.Topics)
	}
	if back.Agent.Turn == nil || *back.Agent.Turn != 7 {
		t.Errorf("Turn lost or wrong type: %v", back.Agent.Turn)
	}

	if back.MCP == nil || back.MCP.Tool == nil {
		t.Fatal("MCP.Tool lost")
	}
	if back.MCP.Tool.OutputSchema == nil {
		t.Error("Tool.OutputSchema lost")
	}
	if back.MCP.Tool.Annotations == nil {
		t.Error("Tool.Annotations lost")
	}

	if back.Completion == nil {
		t.Fatal("Completion lost")
	}
	if back.Completion.RawFormat != "anthropic" {
		t.Errorf("Completion.RawFormat lost: %q", back.Completion.RawFormat)
	}
	if back.Completion.CreatedAt != "2026-05-04T10:00:00Z" {
		t.Errorf("Completion.CreatedAt lost: %q", back.Completion.CreatedAt)
	}
}

func TestMessagePayloadSerialization(t *testing.T) {
	msg := MessagePayload{
		Message: NewMessage("assistant",
			NewTextPart("I'll look that up for you."),
			NewToolCallPart(ToolCall{
				ToolCallID: "tc_001",
				Name:       "get_compensation",
				Arguments:  map[string]any{"employee_id": 42},
			}),
		),
	}

	data, err := msgpack.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	if len(data) == 0 {
		t.Fatal("expected non-empty msgpack bytes")
	}

	// Verify it round-trips as a generic map (to check wire format)
	var raw map[string]any
	if err := msgpack.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal to map failed: %v", err)
	}

	message, ok := raw["message"].(map[string]any)
	if !ok {
		t.Fatal("expected 'message' key in payload")
	}

	if message["schema_version"] != "2.0" {
		t.Errorf("expected schema_version=2.0, got %v", message["schema_version"])
	}

	if message["role"] != "assistant" {
		t.Errorf("expected role=assistant, got %v", message["role"])
	}

	content, ok := message["content"].([]any)
	if !ok {
		t.Fatal("expected content to be a list")
	}

	if len(content) != 2 {
		t.Fatalf("expected 2 content parts, got %d", len(content))
	}

	// First part should be text
	part0, ok := content[0].(map[string]any)
	if !ok {
		t.Fatal("expected content[0] to be a map")
	}
	if part0["content_type"] != "text" {
		t.Errorf("expected content_type=text, got %v", part0["content_type"])
	}

	// Second part should be tool_call
	part1, ok := content[1].(map[string]any)
	if !ok {
		t.Fatal("expected content[1] to be a map")
	}
	if part1["content_type"] != "tool_call" {
		t.Errorf("expected content_type=tool_call, got %v", part1["content_type"])
	}
}

func TestLoadConfigOnDefaultManager(t *testing.T) {
	mgr, err := NewPluginManagerDefault()
	if err != nil {
		t.Fatalf("NewPluginManagerDefault failed: %v", err)
	}
	defer mgr.Shutdown()

	// LoadConfig with valid YAML (no plugins, just settings)
	err = mgr.LoadConfig(`
plugin_settings:
  plugin_timeout: 30
`)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if err := mgr.Initialize(); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
}

func TestLoadConfigInvalidYAML(t *testing.T) {
	mgr, err := NewPluginManagerDefault()
	if err != nil {
		t.Fatalf("NewPluginManagerDefault failed: %v", err)
	}
	defer mgr.Shutdown()

	err = mgr.LoadConfig("not: [valid: yaml: {{}")
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}
