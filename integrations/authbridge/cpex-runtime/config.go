// Location: ./integrations/authbridge/cpex-runtime/config.go
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// YAML config decode for cpex-runtime.
//
// Shape (as it appears under cpex-runtime's `config:` block in
// authbridge-runtime-config):
//
//   chain:
//     - name: llm-pii-redactor
//       config:
//         patterns:
//           email: '\b[\w.+-]+@[\w-]+\.[\w.-]+\b'
//     - name: scope-tool-gate
//       config:
//         tool_scopes:
//           get_weather: weather:read
//
// `chain` lists CPEX plugins in dispatch order. Each entry's `name`
// must match a factory registered by `kagenti_cpex_register_factories`.
// `config` is opaque to cpex-runtime — it's passed through to the CPEX
// plugin's PluginConfig at LoadConfig time.

package cpexruntime

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

// Config is the YAML decode target. Only `chain` is meaningful; other
// fields would be rejected because Configure uses DisallowUnknownFields.
type Config struct {
	Chain []ChainEntry `json:"chain" yaml:"chain"`
}

// ChainEntry names a CPEX plugin and supplies its config. The `Config`
// field is the per-plugin config that the Rust plugin sees as its
// `PluginConfig`. Kept as a raw map so cpex-runtime doesn't need to know
// the schema of each downstream plugin.
type ChainEntry struct {
	Name   string                 `json:"name" yaml:"name"`
	Config map[string]interface{} `json:"config,omitempty" yaml:"config,omitempty"`
}

func (c *Config) validate() error {
	if len(c.Chain) == 0 {
		return fmt.Errorf("config.chain must contain at least one plugin entry")
	}
	for i, e := range c.Chain {
		if e.Name == "" {
			return fmt.Errorf("config.chain[%d].name is required", i)
		}
	}
	return nil
}

// chainNames returns just the plugin names in the chain, for logging.
func (c *Config) chainNames() []string {
	out := make([]string, len(c.Chain))
	for i, e := range c.Chain {
		out[i] = e.Name
	}
	return out
}

// renderCPEXYAML translates this Config into the YAML shape CPEX's
// PluginManager.LoadConfig expects — a top-level `plugins:` array, one
// entry per chain entry, in order.
//
// CPEX's manager takes care of routing each plugin to the right hook
// based on the handlers each plugin registers; cpex-runtime doesn't
// need to specify hook names here.
func (c *Config) renderCPEXYAML() (string, error) {
	type cpexPluginEntry struct {
		Name   string                 `yaml:"name"`
		Kind   string                 `yaml:"kind"`
		Config map[string]interface{} `yaml:"config,omitempty"`
	}
	type cpexDoc struct {
		Plugins []cpexPluginEntry `yaml:"plugins"`
	}

	// CPEX requires both `name` (unique plugin instance) and `kind`
	// (factory key). For factory-registered FFI plugins, both are the
	// same string — the value passed to manager.register_factory in
	// the Rust register() function.
	doc := cpexDoc{
		Plugins: make([]cpexPluginEntry, len(c.Chain)),
	}
	for i, e := range c.Chain {
		doc.Plugins[i] = cpexPluginEntry{
			Name:   e.Name,
			Kind:   e.Name,
			Config: e.Config,
		}
	}

	out, err := yaml.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("marshal CPEX YAML: %w", err)
	}
	return string(out), nil
}

// jsonReader wraps a json.RawMessage as an io.Reader for use with
// json.NewDecoder. json.RawMessage doesn't implement io.Reader natively;
// using a Decoder lets Configure call DisallowUnknownFields() to reject
// stale or misspelled keys at startup rather than silently ignoring them.
func jsonReader(raw json.RawMessage) io.Reader {
	return bytes.NewReader([]byte(raw))
}
