// Location: ./examples/go-demo/main.go
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// CPEX Go Demo — generic payload example.
//
// Demonstrates the full CPEX plugin pipeline from Go using
// GenericPayload (untyped map payloads):
//
//   1. Create a PluginManager via the Go SDK
//   2. Register demo plugin factories (identity, PII, audit)
//   3. Load YAML config with routing rules and policy groups
//   4. Invoke hooks with MetaExtension for route resolution
//   5. Inspect results (allow/deny, violations)
//   6. Thread ContextTable between pre-invoke and post-invoke
//
// Build & run:
//
//	cd examples/go-demo/ffi && cargo build --release
//	cd examples/go-demo && go run main.go

package main

/*
#cgo LDFLAGS: -L${SRCDIR}/../../target/release -lcpex_demo_ffi -lm -ldl -lpthread -framework CoreFoundation -framework Security
#include <stdlib.h>

int cpex_demo_register_factories(void* mgr);
*/
import "C"

import (
	"fmt"
	"os"
	"unsafe"

	cpex "github.com/contextforge-org/contextforge-plugins-framework/go/cpex"
)

func main() {
	fmt.Println("=== CPEX Go Demo ===")
	fmt.Println()

	// --- Create manager ---
	mgr, err := cpex.NewPluginManagerDefault()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}
	defer mgr.Shutdown()

	// --- Register demo factories via callback ---
	err = mgr.RegisterFactories(func(handle unsafe.Pointer) error {
		rc := C.cpex_demo_register_factories(handle)
		if rc != 0 {
			return fmt.Errorf("cpex_demo_register_factories returned %d", rc)
		}
		return nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}

	// --- Load YAML config ---
	yaml, err := os.ReadFile("plugins.yaml")
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}

	if err := mgr.LoadConfig(string(yaml)); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}

	// --- Initialize ---
	if err := mgr.Initialize(); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Plugins loaded: %d\n", mgr.PluginCount())
	fmt.Printf("Hooks: tool_pre_invoke=%v  tool_post_invoke=%v\n\n",
		mgr.HasHooksFor("tool_pre_invoke"),
		mgr.HasHooksFor("tool_post_invoke"),
	)

	// -----------------------------------------------------------------------
	// Scenario 1: PII tool WITHOUT clearance — should be DENIED
	// -----------------------------------------------------------------------
	fmt.Println("=== Scenario 1: get_compensation (no PII clearance) ===")
	fmt.Println()

	result, ct, bg, err := mgr.InvokeByName("tool_pre_invoke",
		cpex.PayloadGeneric,
		map[string]any{
			"tool_name": "get_compensation",
			"user":      "alice",
			"arguments": "employee_id=42",
		},
		&cpex.Extensions{
			Meta: &cpex.MetaExtension{
				EntityType: "tool",
				EntityName: "get_compensation",
				Tags:       []string{"pii", "hr"},
			},
		},
		nil,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}
	printResult(result)
	bg.Close()
	ct.Close()

	// -----------------------------------------------------------------------
	// Scenario 2: PII tool WITH clearance — should be ALLOWED
	// -----------------------------------------------------------------------
	fmt.Println("=== Scenario 2: get_compensation (with PII clearance) ===")
	fmt.Println()

	result, ct, bg, err = mgr.InvokeByName("tool_pre_invoke",
		cpex.PayloadGeneric,
		map[string]any{
			"tool_name":     "get_compensation",
			"user":          "alice",
			"arguments":     "employee_id=42",
			"pii_clearance": true,
		},
		&cpex.Extensions{
			Meta: &cpex.MetaExtension{
				EntityType: "tool",
				EntityName: "get_compensation",
				Tags:       []string{"pii", "hr"},
			},
		},
		nil,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}
	printResult(result)
	bg.Close()

	// Thread context table into post-invoke
	fmt.Println("  --- post-invoke for get_compensation ---")
	fmt.Println()

	result2, ct2, bg2, err := mgr.InvokeByName("tool_post_invoke",
		cpex.PayloadGeneric,
		map[string]any{
			"tool_name": "get_compensation",
			"user":      "alice",
		},
		&cpex.Extensions{
			Meta: &cpex.MetaExtension{
				EntityType: "tool",
				EntityName: "get_compensation",
				Tags:       []string{"pii", "hr"},
			},
		},
		ct, // thread context table from pre-invoke
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}
	printResult(result2)
	bg2.Close()
	ct2.Close()

	// -----------------------------------------------------------------------
	// Scenario 3: Non-PII tool — should be ALLOWED
	// -----------------------------------------------------------------------
	fmt.Println("=== Scenario 3: list_departments (non-PII tool) ===")
	fmt.Println()

	result, ct, bg, err = mgr.InvokeByName("tool_pre_invoke",
		cpex.PayloadGeneric,
		map[string]any{
			"tool_name": "list_departments",
			"user":      "bob",
		},
		&cpex.Extensions{
			Meta: &cpex.MetaExtension{
				EntityType: "tool",
				EntityName: "list_departments",
			},
		},
		nil,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}
	printResult(result)
	bg.Close()
	ct.Close()

	// -----------------------------------------------------------------------
	// Scenario 4: No user identity — should be DENIED by identity-checker
	// -----------------------------------------------------------------------
	fmt.Println("=== Scenario 4: list_departments (no user identity) ===")
	fmt.Println()

	result, ct, bg, err = mgr.InvokeByName("tool_pre_invoke",
		cpex.PayloadGeneric,
		map[string]any{
			"tool_name": "list_departments",
		},
		&cpex.Extensions{
			Meta: &cpex.MetaExtension{
				EntityType: "tool",
				EntityName: "list_departments",
			},
		},
		nil,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}
	printResult(result)
	bg.Close()
	ct.Close()

	fmt.Println("=== Demo complete ===")
}

func printResult(result *cpex.PipelineResult) {
	if !result.IsDenied() {
		fmt.Printf("  Result: ALLOWED\n\n")
	} else {
		v := result.Violation
		fmt.Printf("  Result: DENIED — %s [%s]\n\n", v.Reason, v.Code)
	}
}
