// Package cpexruntime is the AuthBridge plugin that embeds a CPEX plugin
// runtime inside the pipeline. From AuthBridge's perspective it is a single
// `pipeline.Plugin`; internally it manages a chain of CPEX plugins
// configured via YAML, dispatching each CPEX sub-plugin and emitting one
// `pipeline.Invocation` per sub-plugin so abctl shows them as if they
// were native AuthBridge plugins.
//
// Registration follows the standard AuthBridge convention: this package's
// `init()` calls plugins.RegisterPlugin("cpex-runtime", ...). The custom
// `cmd/cpex-authbridge-envoy/main.go` anonymously imports this package
// alongside the standard AuthBridge plugins so the binary contains all of
// them.
//
// CPEX-side plugins are written in Rust and registered via the FFI library
// at `integrations/authbridge/ffi/` (built as `libkagenti_cpex_ffi.a`).
// This package's Init hook calls `kagenti_cpex_register_factories` via cgo
// before loading the YAML config — so by the time the YAML names a CPEX
// plugin, its factory is already in the registry.
//
// For v0 (workshop demo) this is statically linked. See the integration
// README's "Future work" section for the dynamic-loading shape.
package cpexruntime

/*
#cgo darwin LDFLAGS: -L${SRCDIR}/../../../target/release -lkagenti_cpex_ffi -lm -ldl -lpthread -framework CoreFoundation -framework Security
#cgo linux LDFLAGS: -L${SRCDIR}/../../../target/release -lkagenti_cpex_ffi -lm -ldl -lpthread
#include <stdlib.h>

int kagenti_cpex_register_factories(void* mgr);
*/
import "C"

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"unsafe"

	"github.com/kagenti/kagenti-extensions/authbridge/authlib/pipeline"
	"github.com/kagenti/kagenti-extensions/authbridge/authlib/plugins"

	cpex "github.com/contextforge-org/contextforge-plugins-framework/go/cpex"
)

// pluginName is the canonical name AuthBridge uses to look this up from
// the YAML config and to attribute Invocations to.
const pluginName = "cpex-runtime"

// init registers cpex-runtime with AuthBridge's plugin registry. The
// custom main.go anonymously imports this package, which triggers this
// init() and makes the plugin name resolvable from the YAML config.
func init() {
	plugins.RegisterPlugin(pluginName, func() pipeline.Plugin {
		return New()
	})
}

// CPEXRuntime is the AuthBridge plugin that embeds a CPEX manager. Each
// AuthBridge pipeline that includes "cpex-runtime" gets its own instance
// (AuthBridge's RegisterPlugin factory is invoked once per pipeline
// position), so the manager lifecycle is per-pipeline.
type CPEXRuntime struct {
	cfg     Config
	manager *cpex.PluginManager
}

// New creates an unconfigured CPEXRuntime. The pipeline framework calls
// Configure / Init in order before serving traffic.
func New() *CPEXRuntime {
	return &CPEXRuntime{}
}

// Name returns the canonical plugin name. Matches the YAML config name and
// the Invocation.Plugin attribution that abctl renders.
func (r *CPEXRuntime) Name() string { return pluginName }

// Capabilities declares what this plugin reads/writes on pctx, and what
// CPEX-side sub-plugins it needs upstream parsers to have populated.
//
// Reads names only slots that an earlier plugin in the *same direction*
// writes — AuthBridge's slot validator enforces this. Inbound-set slots
// (security from jwt-validation, a2a from a2a-parser, delegation) still
// flow through pctx to outbound and the bridge can read them in OnRequest,
// they just aren't declared as outbound Reads dependencies. WritesBody is
// on because llm-pii-redactor rewrites the LLM prompt body.
//
// RequiresAny: at least one protocol parser must run before us so the
// bridge has something to translate into MessagePayload. Pipeline.New
// fails at startup if none are present.
func (r *CPEXRuntime) Capabilities() pipeline.PluginCapabilities {
	return pipeline.PluginCapabilities{
		Reads:       []string{"mcp", "inference"},
		ReadsBody:   true,
		WritesBody:  true,
		RequiresAny: []string{"mcp-parser", "inference-parser"},
	}
}

// Configure decodes the YAML config block for this plugin. AuthBridge
// invokes this once at pipeline build time, before Init.
func (r *CPEXRuntime) Configure(raw json.RawMessage) error {
	dec := json.NewDecoder(jsonReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r.cfg); err != nil {
		return fmt.Errorf("cpex-runtime: invalid config: %w", err)
	}
	if err := r.cfg.validate(); err != nil {
		return fmt.Errorf("cpex-runtime: %w", err)
	}
	return nil
}

// Init builds the CPEX manager, registers FFI plugin factories, loads the
// per-instance YAML, and initializes the manager. Called once before the
// pipeline starts serving traffic. An error here aborts pipeline start.
func (r *CPEXRuntime) Init(_ context.Context) error {
	mgr, err := cpex.NewPluginManagerDefault()
	if err != nil {
		return fmt.Errorf("cpex-runtime: NewPluginManagerDefault: %w", err)
	}

	// Register the Rust plugin factories (scope-tool-gate, llm-pii-redactor)
	// before LoadConfig — otherwise LoadConfig fails when the YAML names a
	// plugin whose factory isn't yet registered.
	err = mgr.RegisterFactories(func(handle unsafe.Pointer) error {
		rc := C.kagenti_cpex_register_factories(handle)
		if rc != 0 {
			return fmt.Errorf("kagenti_cpex_register_factories returned %d", rc)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("cpex-runtime: register FFI factories: %w", err)
	}

	// Build the CPEX manager YAML from our config's `chain:` list. CPEX
	// expects a top-level `plugins:` array — translate our schema into
	// that shape (one CPEX plugin entry per chain entry, in order).
	cpexYAML, err := r.cfg.renderCPEXYAML()
	if err != nil {
		return fmt.Errorf("cpex-runtime: render CPEX YAML: %w", err)
	}
	if err := mgr.LoadConfig(cpexYAML); err != nil {
		return fmt.Errorf("cpex-runtime: LoadConfig: %w", err)
	}
	if err := mgr.Initialize(); err != nil {
		return fmt.Errorf("cpex-runtime: Initialize: %w", err)
	}

	r.manager = mgr
	slog.Info("cpex-runtime initialized",
		"chain", r.cfg.chainNames(),
		"plugin_count", mgr.PluginCount())
	return nil
}

// Shutdown releases the CPEX manager. Called once during pipeline stop.
func (r *CPEXRuntime) Shutdown(_ context.Context) error {
	if r.manager != nil {
		r.manager.Shutdown()
		r.manager = nil
	}
	return nil
}

// OnRequest dispatches the configured CPEX chain on the request-path
// pass. The real bridge translation + dispatch lives in bridge.go.
func (r *CPEXRuntime) OnRequest(_ context.Context, pctx *pipeline.Context) pipeline.Action {
	return r.dispatchOnRequest(pctx)
}

// OnResponse dispatches the configured CPEX chain on the response-path
// pass. v0 is observe-only; see bridge.go for the upgrade path.
func (r *CPEXRuntime) OnResponse(_ context.Context, pctx *pipeline.Context) pipeline.Action {
	return r.dispatchOnResponse(pctx)
}
