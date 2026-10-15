// Location: ./go/cpex/credentials_test.go
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0

package cpex

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/vmihailenco/msgpack/v5"
)

const testMinted = "Bearer test-only-minted-token"

func TestDelegatedCredentialDecodesFromResult(t *testing.T) {
	wire, err := msgpack.Marshal(map[string]any{
		"continue_processing": true,
		"payload_type":        0,
		"payload_modified":    false,
		"delegated_credentials": []map[string]any{{
			"header": "Authorization", "value": testMinted, "delegator": "oauth",
			"target": "api", "audience": "api", "expires_at": "2026-01-01T00:00:00Z",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var res PipelineResult
	if err := msgpack.Unmarshal(wire, &res); err != nil {
		t.Fatal(err)
	}
	if len(res.DelegatedCredentials) != 1 || res.DelegatedCredentials[0].Value.Reveal() != testMinted {
		t.Fatalf("decoded %d credentials", len(res.DelegatedCredentials))
	}
}

func TestSecretValueRedacts(t *testing.T) {
	c := DelegatedCredential{Header: "Authorization", Value: SecretValue(testMinted), Target: "api"}
	res := &PipelineResult{DelegatedCredentials: []DelegatedCredential{c}}

	var out bytes.Buffer
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d"} {
		fmt.Fprintf(&out, verb+"|", c.Value)
		fmt.Fprintf(&out, verb+"|", c)
		fmt.Fprintf(&out, verb+"|", res)
	}
	fmt.Fprint(&out, c.Value.String(), c.Value.GoString())
	j, _ := json.Marshal(res)
	out.Write(j)
	slog.New(slog.NewJSONHandler(&out, nil)).Info("x", "cred", c, "value", c.Value, "res", res)
	slog.New(slog.NewTextHandler(&out, nil)).Info("x", "cred", c, "value", c.Value)

	if strings.Contains(out.String(), "test-only-minted-token") {
		t.Fatalf("secret leaked: %s", out.String())
	}
	if !strings.Contains(out.String(), "[REDACTED]") {
		t.Fatal("no redaction marker")
	}
}
