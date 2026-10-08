// Location: ./go/cpex/extensions_test.go
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
//
// Wire-shape tests for the Go mirrors of the Rust extension and payload
// types: values Rust emits must decode, and values Go emits must reach
// Rust intact. The FFI tests need the staticlib:
//
//	cargo build --release -p cpex-ffi

package cpex

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/vmihailenco/msgpack/v5"
)

// nonStringClaims are the claim shapes an IdP commonly sends beyond
// plain strings.
func nonStringClaims() map[string]any {
	return map[string]any{
		"email":          "alice@corp.com",
		"email_verified": true,
		"auth_time":      int64(1700000000),
		"ratio":          0.75,
		"realm_access":   map[string]any{"roles": []any{"admin", "hr"}, "level": int64(3)},
		"amr":            []any{"pwd", "mfa"},
	}
}

// assertClaims checks the decoded claims against nonStringClaims.
// Numbers are compared through float64 because a JSON round trip and
// the msgpack decoder pick different integer widths.
func assertClaims(t *testing.T, label string, got map[string]any) {
	t.Helper()
	if got == nil {
		t.Fatalf("%s: claims are nil", label)
	}
	if v, ok := got["email"].(string); !ok || v != "alice@corp.com" {
		t.Errorf("%s: email = %#v", label, got["email"])
	}
	if v, ok := got["email_verified"].(bool); !ok || !v {
		t.Errorf("%s: email_verified = %#v", label, got["email_verified"])
	}
	if v, ok := asFloat(got["auth_time"]); !ok || v != 1700000000 {
		t.Errorf("%s: auth_time = %#v", label, got["auth_time"])
	}
	if v, ok := asFloat(got["ratio"]); !ok || v != 0.75 {
		t.Errorf("%s: ratio = %#v", label, got["ratio"])
	}
	realm, ok := got["realm_access"].(map[string]any)
	if !ok {
		t.Fatalf("%s: realm_access = %#v", label, got["realm_access"])
	}
	if !reflect.DeepEqual(realm["roles"], []any{"admin", "hr"}) {
		t.Errorf("%s: realm_access.roles = %#v", label, realm["roles"])
	}
	if v, ok := asFloat(realm["level"]); !ok || v != 3 {
		t.Errorf("%s: realm_access.level = %#v", label, realm["level"])
	}
	if !reflect.DeepEqual(got["amr"], []any{"pwd", "mfa"}) {
		t.Errorf("%s: amr = %#v", label, got["amr"])
	}
}

func asFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case int8:
		return float64(n), true
	case int16:
		return float64(n), true
	case int32:
		return float64(n), true
	case int64:
		return float64(n), true
	case uint8:
		return float64(n), true
	case uint16:
		return float64(n), true
	case uint32:
		return float64(n), true
	case uint64:
		return float64(n), true
	case float32:
		return float64(n), true
	case float64:
		return n, true
	}
	return 0, false
}

// TestSubjectClaimsDecodeNonStringValues decodes the shape Rust emits
// for a subject whose claims are not all strings, both as an
// IdentityPayload and inside Extensions.
func TestSubjectClaimsDecodeNonStringValues(t *testing.T) {
	subject := map[string]any{
		"id":     "alice",
		"roles":  []string{"hr"},
		"claims": nonStringClaims(),
	}

	idBytes, err := msgpack.Marshal(map[string]any{
		"source":     "bearer",
		"subject":    subject,
		"raw_claims": nonStringClaims(),
	})
	if err != nil {
		t.Fatalf("marshal identity: %v", err)
	}
	var idp IdentityPayload
	if err := msgpack.Unmarshal(idBytes, &idp); err != nil {
		t.Fatalf("decode IdentityPayload: %v", err)
	}
	if idp.Subject == nil {
		t.Fatal("IdentityPayload.Subject is nil")
	}
	assertClaims(t, "IdentityPayload.Subject.Claims", idp.Subject.Claims)
	assertClaims(t, "IdentityPayload.RawClaims", idp.RawClaims)

	extBytes, err := msgpack.Marshal(map[string]any{
		"security": map[string]any{
			"subject": subject,
			"client":  map[string]any{"client_id": "web", "claims": nonStringClaims()},
		},
	})
	if err != nil {
		t.Fatalf("marshal extensions: %v", err)
	}
	var ext Extensions
	if err := msgpack.Unmarshal(extBytes, &ext); err != nil {
		t.Fatalf("decode Extensions: %v", err)
	}
	if ext.Security == nil || ext.Security.Subject == nil || ext.Security.Client == nil {
		t.Fatalf("security slots missing: %+v", ext.Security)
	}
	assertClaims(t, "Extensions.Security.Subject.Claims", ext.Security.Subject.Claims)
	assertClaims(t, "Extensions.Security.Client.Claims", ext.Security.Client.Claims)
}

// mintJWTWithClaims signs an HS256 token for sub with roles and the
// extra claims merged in.
func mintJWTWithClaims(t *testing.T, sub string, roles []string, extra map[string]any) string {
	t.Helper()
	now := time.Now()
	claims := map[string]any{
		"iss":   accIssuer,
		"aud":   accAudience,
		"sub":   sub,
		"iat":   now.Add(-5 * time.Second).Unix(),
		"exp":   now.Add(10 * time.Minute).Unix(),
		"roles": roles,
	}
	for k, v := range extra {
		claims[k] = v
	}
	header, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT", "kid": accKID})
	body, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	signing := b64url(header) + "." + b64url(body)
	mac := hmac.New(sha256.New, accSecret)
	mac.Write([]byte(signing))
	return signing + "." + b64url(mac.Sum(nil))
}

// TestAcceptanceJWTNonStringClaimsRoundTrip resolves a JWT whose claims
// include a bool, numbers, a nested map and an array, and reads them
// back from both the resolved IdentityPayload and the extensions of an
// InvokeResolved call.
func TestAcceptanceJWTNonStringClaimsRoundTrip(t *testing.T) {
	idp := newMockIdP(t)
	eng := accEngine(t, idpPlugin(idp.srv.URL+"/jwks", true)+accIdentityRoutes, WithPrivateDestinations())
	token := mintJWTWithClaims(t, "alice", []string{"hr"}, nonStringClaims())
	headers := map[string]string{"authorization": "Bearer " + token}
	meta := &MetaExtension{EntityType: "tool", EntityName: "get_compensation"}

	t.Run("identity.resolve payload", func(t *testing.T) {
		res, ct, bg, err := eng.InvokeByName(HookIdentityResolve, PayloadIdentity,
			NewIdentityPayload(TokenSourceBearer, headers), &Extensions{Meta: meta}, nil)
		if err != nil {
			t.Fatalf("InvokeByName(identity.resolve): %v", err)
		}
		defer bg.Close()
		defer ct.Close()
		wantAllowed(t, "identity.resolve", res)
		resolved, err := DeserializePayload[IdentityPayload](res)
		if err != nil {
			t.Fatalf("decode resolved IdentityPayload: %v", err)
		}
		if resolved == nil || resolved.Subject == nil {
			t.Fatalf("no resolved subject: %+v", resolved)
		}
		if resolved.Subject.ID != "alice" {
			t.Errorf("subject id = %q", resolved.Subject.ID)
		}
		assertClaims(t, "resolved Subject.Claims", resolved.Subject.Claims)
	})

	t.Run("InvokeResolved extensions", func(t *testing.T) {
		payload := MessagePayload{Message: NewMessage("assistant", NewToolCallPart(ToolCall{
			ToolCallID: "acc-claims", Name: "get_compensation",
			Arguments: map[string]any{"employee_id": "e-1"},
		}))}
		res, ct, bg, err := eng.InvokeResolved(NewIdentityPayload(TokenSourceBearer, headers),
			"cmf.tool_pre_invoke", PayloadCMFMessage, payload, &Extensions{Meta: meta}, nil)
		if err != nil {
			t.Fatalf("InvokeResolved: %v", err)
		}
		defer bg.Close()
		defer ct.Close()
		wantAllowed(t, "tool call", res)
		ext, err := res.DeserializeExtensions()
		if err != nil {
			t.Fatalf("decode extensions: %v", err)
		}
		if ext == nil || ext.Security == nil || ext.Security.Subject == nil {
			t.Fatalf("no subject in result extensions: %+v", ext)
		}
		assertClaims(t, "result Security.Subject.Claims", ext.Security.Subject.Claims)
	})
}

// roundTripFFI sends payload and ext through an engine with no plugins
// and returns what came back.
func roundTripFFI(t *testing.T, payload MessagePayload, ext *Extensions) (*MessagePayload, *Extensions) {
	t.Helper()
	eng, err := NewPolicyEngineDefault()
	if err != nil {
		t.Fatalf("NewPolicyEngineDefault: %v", err)
	}
	defer eng.Shutdown()
	if err := eng.Initialize(); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	res, ct, bg, err := eng.InvokeByName("cmf.tool_pre_invoke", PayloadCMFMessage, payload, ext, nil)
	if err != nil {
		t.Fatalf("InvokeByName: %v", err)
	}
	defer bg.Close()
	defer ct.Close()
	gotPayload, err := DeserializePayload[MessagePayload](res)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	gotExt, err := res.DeserializeExtensions()
	if err != nil {
		t.Fatalf("decode extensions: %v", err)
	}
	return gotPayload, gotExt
}

// TestFFIRoundTripResourceBlob checks a resource blob crosses the FFI
// both ways. Rust encodes bytes as an array of integers, not bin.
func TestFFIRoundTripResourceBlob(t *testing.T) {
	blob := []byte{0x00, 0x7f, 0x80, 0xff}
	got, _ := roundTripFFI(t, MessagePayload{Message: NewMessage("user", NewResourcePart(Resource{
		ResourceRequestID: "rr-1", URI: "file:///a.bin", ResourceType: "blob", Blob: blob,
	}))}, nil)
	if got == nil || len(got.Message.Content) != 1 || got.Message.Content[0].ResourceContent == nil {
		t.Fatalf("resource lost: %+v", got)
	}
	if b := got.Message.Content[0].ResourceContent.Blob; string(b) != string(blob) {
		t.Errorf("blob = %v, want %v", b, blob)
	}
}

// TestFFIRoundTripEmptyMessage checks a message with no content parts
// is accepted.
func TestFFIRoundTripEmptyMessage(t *testing.T) {
	got, _ := roundTripFFI(t, MessagePayload{Message: NewMessage("user")}, nil)
	if got == nil || got.Message.Role != "user" || len(got.Message.Content) != 0 {
		t.Errorf("unexpected payload: %+v", got)
	}
}

// TestFFIRoundTripExtensionSlots sends every slot the Go mirror added
// and checks it comes back, including the nil versus empty distinction
// on Option<Vec> fields.
func TestFFIRoundTripExtensionSlots(t *testing.T) {
	ttl := uint64(60)
	ext := &Extensions{
		Security: &SecurityExtension{
			Subject: &SubjectExtension{ID: "alice", Claims: nonStringClaims()},
			Client: &ClientExtension{
				ClientID: "web", ClientName: "Web", TrustLevel: ClientTrustThirdParty,
				AuthorizedScopes: []string{"read"}, Claims: map[string]any{"tier": int64(2)},
			},
			CallerWorkload: &WorkloadIdentity{
				SpiffeID: "spiffe://corp.com/caller", TrustDomain: "corp.com",
				AttestedAt: "2026-01-02T03:04:05Z", Selectors: []string{"k8s:ns:a"},
			},
			ThisWorkload: &WorkloadIdentity{SpiffeID: "spiffe://corp.com/gw", ClientID: "gw"},
			Data: map[string]DataPolicy{
				"none": {AllowedActions: []string{}},
				"any":  {},
				"read": {AllowedActions: []string{"read"}},
			},
		},
		Http: &HttpExtension{
			RequestHeaders: map[string]string{"x-a": "1"},
			Method:         "POST", Path: "/v1/items", Host: "api.corp.com", Scheme: "https", Status: 201,
		},
		Delegation: &DelegationExtension{Chain: []DelegationHop{{
			SubjectID: "alice", Audience: "api", TTLSeconds: &ttl, Strategy: "token_exchange",
			Timestamp:            "2026-01-02T03:04:05Z",
			AuthorizationDetails: []map[string]any{{"type": "payment", "actions": []any{"pay"}, "amount": "10"}},
		}}, Depth: 1},
		CandidateConstraint: &CandidateConstraintExtension{
			AllowModels: []string{}, DenyModels: []string{"m-old"}, OnEmpty: OnEmptyFallback,
		},
		MCP: &MCPExtension{
			Resource: &ResourceMetadata{URI: "hr://x", Annotations: map[string]any{"audience": []any{"user"}}},
			Prompt: &PromptMetadata{
				Name:        "p",
				Arguments:   []any{map[string]any{"name": "q", "required": true}},
				Annotations: map[string]any{"priority": 0.5},
			},
		},
	}
	_, got := roundTripFFI(t, MessagePayload{Message: NewMessage("user", NewTextPart("hi"))}, ext)
	if got == nil || got.Security == nil {
		t.Fatalf("security lost: %+v", got)
	}
	sec := got.Security
	assertClaims(t, "subject claims", sec.Subject.Claims)
	if sec.Client == nil || sec.Client.ClientID != "web" || sec.Client.TrustLevel != ClientTrustThirdParty ||
		!reflect.DeepEqual(sec.Client.AuthorizedScopes, []string{"read"}) {
		t.Errorf("client = %+v", sec.Client)
	}
	if v, ok := asFloat(sec.Client.Claims["tier"]); !ok || v != 2 {
		t.Errorf("client claims = %#v", sec.Client.Claims)
	}
	if sec.CallerWorkload == nil || sec.CallerWorkload.SpiffeID != "spiffe://corp.com/caller" ||
		sec.CallerWorkload.AttestedAt == "" || len(sec.CallerWorkload.Selectors) != 1 {
		t.Errorf("caller workload = %+v", sec.CallerWorkload)
	}
	if sec.ThisWorkload == nil || sec.ThisWorkload.ClientID != "gw" {
		t.Errorf("this workload = %+v", sec.ThisWorkload)
	}
	if a := sec.Data["none"].AllowedActions; a == nil || len(a) != 0 {
		t.Errorf("empty allowed_actions must stay empty, got %#v", a)
	}
	if a := sec.Data["any"].AllowedActions; a != nil {
		t.Errorf("unset allowed_actions must stay nil, got %#v", a)
	}
	if a := sec.Data["read"].AllowedActions; !reflect.DeepEqual(a, []string{"read"}) {
		t.Errorf("allowed_actions = %#v", a)
	}

	if h := got.Http; h == nil || h.Method != "POST" || h.Path != "/v1/items" || h.Host != "api.corp.com" ||
		h.Scheme != "https" || h.Status != 201 {
		t.Errorf("http = %+v", got.Http)
	}

	if d := got.Delegation; d == nil || len(d.Chain) != 1 || d.Chain[0].Strategy != "token_exchange" ||
		len(d.Chain[0].AuthorizationDetails) != 1 || d.Chain[0].AuthorizationDetails[0]["amount"] != "10" {
		t.Errorf("delegation = %+v", got.Delegation)
	}

	cc := got.CandidateConstraint
	if cc == nil || cc.AllowModels == nil || len(cc.AllowModels) != 0 || cc.AllowRegions != nil ||
		!reflect.DeepEqual(cc.DenyModels, []string{"m-old"}) || cc.OnEmpty != OnEmptyFallback {
		t.Errorf("candidate constraint = %+v", cc)
	}

	if m := got.MCP; m == nil || m.Resource == nil || m.Resource.Annotations["audience"] == nil ||
		m.Prompt == nil || len(m.Prompt.Arguments) != 1 || m.Prompt.Annotations["priority"] != 0.5 {
		t.Errorf("mcp = %+v", got.MCP)
	}
}
