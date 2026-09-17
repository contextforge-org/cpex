// Location: ./examples/go-demo/cmd/cmf-demo/main.go
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// CPEX CMF Demo — typed message processing with rich extensions.
//
// Demonstrates CMF (ContextForge Message Format) message processing
// through the CPEX plugin pipeline:
//
//   1. Build typed CMF messages (tool calls, tool results)
//   2. Attach security extensions (labels, subject), HTTP headers,
//      and agent context
//   3. Invoke cmf.tool_pre_invoke — policy checks tool permissions
//      against security labels and meta tags
//   4. Invoke cmf.tool_post_invoke — header injector adds response
//      headers using capability-gated write access
//   5. Inspect modified extensions (injected headers) in results
//
// Build & run:
//
//	cd examples/go-demo/ffi && cargo build --release
//	cd examples/go-demo && go run ./cmd/cmf-demo

package main

/*
#cgo LDFLAGS: -L${SRCDIR}/../../../../target/release -lcpex_demo_ffi -lm -ldl -lpthread
// CoreFoundation/Security are macOS-only; the Rust staticlib pulls them
// in transitively there. Linux gcc rejects `-framework`, so scope these
// to darwin and leave Linux with the portable flags above.
#cgo darwin LDFLAGS: -framework CoreFoundation -framework Security
#include <stdlib.h>

int cpex_demo_register_factories(void* mgr);
*/
import "C"

import (
	"fmt"
	"os"
	"unsafe"

	cpex "github.com/contextforge-org/cpex/go/cpex"
)

func main() {
	fmt.Println("=== CPEX CMF Demo ===")
	fmt.Println()

	// --- Setup ---
	mgr, err := cpex.NewPluginManagerDefault()
	if err != nil {
		fatal("create manager: %v", err)
	}
	defer mgr.Shutdown()

	err = mgr.RegisterFactories(func(handle unsafe.Pointer) error {
		if C.cpex_demo_register_factories(handle) != 0 {
			return fmt.Errorf("factory registration failed")
		}
		return nil
	})
	if err != nil {
		fatal("register factories: %v", err)
	}

	yaml, err := os.ReadFile("../../cmf_plugins.yaml")
	if err != nil {
		// Try current directory too
		yaml, err = os.ReadFile("cmf_plugins.yaml")
		if err != nil {
			fatal("read config: %v", err)
		}
	}

	if err := mgr.LoadConfig(string(yaml)); err != nil {
		fatal("load config: %v", err)
	}
	if err := mgr.Initialize(); err != nil {
		fatal("initialize: %v", err)
	}

	fmt.Printf("Plugins loaded: %d\n", mgr.PluginCount())
	fmt.Printf("Hooks: cmf.tool_pre_invoke=%v  cmf.tool_post_invoke=%v\n\n",
		mgr.HasHooksFor("cmf.tool_pre_invoke"),
		mgr.HasHooksFor("cmf.tool_post_invoke"),
	)

	// -----------------------------------------------------------------------
	// Scenario 1: PII tool call WITHOUT security label — DENIED
	// -----------------------------------------------------------------------
	fmt.Println("=== Scenario 1: get_compensation tool call (no PII label) ===")
	fmt.Println()

	msg := cpex.MessagePayload{
		Message: cpex.NewMessage("assistant",
			cpex.NewTextPart("I'll look up the compensation data for you."),
			cpex.NewToolCallPart(cpex.ToolCall{
				ToolCallID: "tc_001",
				Name:       "get_compensation",
				Arguments:  map[string]any{"employee_id": 42},
				Namespace:  "hr",
			}),
		),
	}

	ext := &cpex.Extensions{
		Meta: &cpex.MetaExtension{
			EntityType: "tool",
			EntityName: "get_compensation",
			Tags:       []string{"pii", "hr"},
		},
		Security: &cpex.SecurityExtension{
			Labels: []string{}, // no PII label — should be denied
			Subject: &cpex.SubjectExtension{
				ID:    "alice",
				Roles: []string{"hr_analyst"},
			},
		},
		Http: &cpex.HttpExtension{
			RequestHeaders: map[string]string{
				"Authorization": "Bearer eyJ...",
				"X-Request-ID":  "req-001",
			},
		},
		Agent: &cpex.AgentExtension{
			SessionID: "sess_abc123",
			AgentID:   "hr-assistant",
		},
	}

	result, ct, bg, err := mgr.InvokeByName("cmf.tool_pre_invoke",
		cpex.PayloadCMFMessage, msg, ext, nil)
	if err != nil {
		fatal("invoke: %v", err)
	}
	printResult(result)
	bg.Close()
	ct.Close()

	// -----------------------------------------------------------------------
	// Scenario 2: PII tool call WITH security label — ALLOWED
	// -----------------------------------------------------------------------
	fmt.Println("=== Scenario 2: get_compensation tool call (with PII label) ===")
	fmt.Println()

	ext.Security.Labels = []string{"PII", "HR"} // now has PII label

	result, ct, bg, err = mgr.InvokeByName("cmf.tool_pre_invoke",
		cpex.PayloadCMFMessage, msg, ext, nil)
	if err != nil {
		fatal("invoke: %v", err)
	}
	printResult(result)

	// Check for modified extensions (header injector adds response headers)
	// Check for modified extensions (header injector adds response headers)
	if len(result.ModifiedExtensions) > 0 {
		modExt, err := result.DeserializeExtensions()
		if err != nil {
			fmt.Printf("  (failed to deserialize modified extensions: %v)\n\n", err)
		} else if modExt != nil && modExt.Http != nil && len(modExt.Http.ResponseHeaders) > 0 {
			fmt.Println("  Modified response headers:")
			for k, v := range modExt.Http.ResponseHeaders {
				fmt.Printf("    %s: %s\n", k, v)
			}
			fmt.Println()
		}
	}
	bg.Close()

	// -----------------------------------------------------------------------
	// Scenario 3: Post-invoke with tool result — header injection
	// -----------------------------------------------------------------------
	fmt.Println("=== Scenario 3: tool result post-invoke (header injection) ===")
	fmt.Println()

	resultMsg := cpex.MessagePayload{
		Message: cpex.NewMessage("tool",
			cpex.NewToolResultPart(cpex.ToolResult{
				ToolCallID: "tc_001",
				ToolName:   "get_compensation",
				Content: map[string]any{
					"employee_id": 42,
					"salary":      125000,
					"currency":    "USD",
				},
				IsError: false,
			}),
		),
	}

	postExt := &cpex.Extensions{
		Meta: &cpex.MetaExtension{
			EntityType: "tool",
			EntityName: "get_compensation",
			Tags:       []string{"pii", "hr"},
		},
		Security: &cpex.SecurityExtension{
			Labels: []string{"PII", "HR"},
		},
		Http: &cpex.HttpExtension{
			RequestHeaders: map[string]string{
				"Authorization": "Bearer eyJ...",
				"X-Request-ID":  "req-001",
			},
		},
	}

	result2, ct2, bg2, err := mgr.InvokeByName("cmf.tool_post_invoke",
		cpex.PayloadCMFMessage, resultMsg, postExt, ct)
	if err != nil {
		fatal("post-invoke: %v", err)
	}
	printResult(result2)

	if len(result2.ModifiedExtensions) > 0 {
		modExt, err := result2.DeserializeExtensions()
		if err != nil {
			fmt.Printf("  (failed to deserialize modified extensions: %v)\n\n", err)
		} else if modExt != nil && modExt.Http != nil {
			fmt.Println("  Modified response headers:")
			for k, v := range modExt.Http.ResponseHeaders {
				fmt.Printf("    %s: %s\n", k, v)
			}
			fmt.Println()
		}
	}
	bg2.Close()
	ct2.Close()

	// -----------------------------------------------------------------------
	// Scenario 4: Non-PII tool — allowed, no policy restriction
	// -----------------------------------------------------------------------
	fmt.Println("=== Scenario 4: list_departments (non-PII, text message) ===")
	fmt.Println()

	textMsg := cpex.MessagePayload{
		Message: cpex.NewMessage("user",
			cpex.NewTextPart("Show me the list of departments"),
		),
	}

	textExt := &cpex.Extensions{
		Meta: &cpex.MetaExtension{
			EntityType: "tool",
			EntityName: "list_departments",
		},
	}

	result, ct, bg, err = mgr.InvokeByName("cmf.tool_pre_invoke",
		cpex.PayloadCMFMessage, textMsg, textExt, nil)
	if err != nil {
		fatal("invoke: %v", err)
	}
	printResult(result)
	bg.Close()
	ct.Close()

	fmt.Println("=== CMF Demo complete ===")
}

func printResult(result *cpex.PipelineResult) {
	if !result.IsDenied() {
		fmt.Printf("  Result: ALLOWED\n\n")
	} else {
		v := result.Violation
		fmt.Printf("  Result: DENIED — %s [%s]\n\n", v.Reason, v.Code)
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "ERROR: "+format+"\n", args...)
	os.Exit(1)
}
