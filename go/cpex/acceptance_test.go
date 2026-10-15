// Location: ./go/cpex/acceptance_test.go
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
//
// Acceptance flows through the FFI, the way a Go host drives them:
// config load, JWT identity, delegation, a Cedar and an OPA decision,
// and session labels. Identity and the tool hook run in one
// InvokeResolved call so inbound tokens reach the delegator.
//
// The JWT issuer and the OAuth token endpoint are loopback httptest
// servers, so engines opt in with EnableAPL(WithPrivateDestinations()).
// Tokens are HS256 against an `oct` JWKS key, which keeps the tests free
// of key files.
//
// The Valkey test is opt in: set CPEX_TEST_VALKEY_URL (for example
// redis://127.0.0.1:6390) to run it against a live server.
//
// Build the staticlib first:
//
//	cargo build --release -p cpex-ffi
//	go test -v -run Acceptance ./...

package cpex

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	accIssuer   = "https://idp.acceptance.test"
	accAudience = "cpex-acceptance"
	accKID      = "acceptance-key"
)

var accSecret = []byte("acceptance-only-hs256-secret-0123456789")

// ---------------------------------------------------------------------------
// Loopback issuer and token endpoint
// ---------------------------------------------------------------------------

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// mintJWT signs an HS256 token for sub with roles. A negative expIn
// mints an expired token; a non-nil key signs with that key instead.
func mintJWT(t *testing.T, sub string, roles []string, expIn time.Duration, key []byte) string {
	t.Helper()
	if key == nil {
		key = accSecret
	}
	now := time.Now()
	header, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT", "kid": accKID})
	claims, _ := json.Marshal(map[string]any{
		"iss":   accIssuer,
		"aud":   accAudience,
		"sub":   sub,
		"iat":   now.Add(-5 * time.Second).Unix(),
		"exp":   now.Add(expIn).Unix(),
		"roles": roles,
	})
	signing := b64url(header) + "." + b64url(claims)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(signing))
	return signing + "." + b64url(mac.Sum(nil))
}

// mockIdP serves the JWKS and an RFC 8693 token endpoint that grants
// audience "workday-api" and refuses every other audience.
type mockIdP struct {
	srv *httptest.Server

	mu          sync.Mutex
	jwksFetches int
	exchanges   []url.Values
}

func newMockIdP(t *testing.T) *mockIdP {
	t.Helper()
	m := &mockIdP{}
	mux := http.NewServeMux()
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		m.mu.Lock()
		m.jwksFetches++
		m.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"keys": []map[string]string{{
			"kty": "oct", "kid": accKID, "alg": "HS256", "use": "sig", "k": b64url(accSecret),
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
			return
		}
		m.mu.Lock()
		m.exchanges = append(m.exchanges, r.PostForm)
		m.mu.Unlock()
		if r.PostForm.Get("audience") != "workday-api" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_target"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token":      "acceptance-only-workday-token",
			"token_type":        "Bearer",
			"expires_in":        300,
			"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
		})
	})
	m.srv = httptest.NewServer(mux)
	t.Cleanup(m.srv.Close)
	return m
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func (m *mockIdP) fetches() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.jwksFetches
}

func (m *mockIdP) tokenExchanges() []url.Values {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]url.Values(nil), m.exchanges...)
}

// idpPlugin is the identity/jwt plugin block for the mock issuer.
func idpPlugin(jwksURL string, performHTTP bool) string {
	caps := ""
	if performHTTP {
		caps = "    capabilities: [perform_http]\n"
	}
	return `
plugins:
  - name: idp
    kind: identity/jwt
    hooks: [identity.resolve]
` + caps + `    config:
      claim_mapper: standard
      trusted_issuers:
        - issuer: ` + accIssuer + `
          audiences: [` + accAudience + `]
          algorithms: [HS256]
          decoding_key:
            kind: jwks_url
            url: "` + jwksURL + `"
            insecure_http: true
`
}

// accEngine builds an engine with builtins and the loopback opt-in,
// loads yaml and initializes it.
func accEngine(t *testing.T, yaml string, opts ...APLOption) *PolicyEngine {
	t.Helper()
	eng, err := NewPolicyEngineDefault()
	if err != nil {
		t.Fatalf("NewPolicyEngineDefault: %v", err)
	}
	t.Cleanup(eng.Shutdown)
	if err := eng.EnableAPL(opts...); err != nil {
		t.Fatalf("EnableAPL: %v", err)
	}
	if err := eng.LoadConfig(yaml); err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if err := eng.Initialize(); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	return eng
}

// callTool resolves the bearer token and runs cmf.tool_pre_invoke for
// tool in one InvokeResolved call. session is the agent session id, or
// empty for none.
func callTool(t *testing.T, eng *PolicyEngine, token, tool string, args map[string]any, session string) *PipelineResult {
	t.Helper()
	identity := NewIdentityPayload(TokenSourceBearer, map[string]string{"authorization": "Bearer " + token})
	ext := &Extensions{Meta: &MetaExtension{EntityType: "tool", EntityName: tool}}
	if session != "" {
		ext.Agent = &AgentExtension{SessionID: session}
	}
	payload := MessagePayload{Message: NewMessage("assistant", NewToolCallPart(ToolCall{
		ToolCallID: "acc-1", Name: tool, Arguments: args,
	}))}
	res, ct, bg, err := eng.InvokeResolved(identity, "cmf.tool_pre_invoke", PayloadCMFMessage, payload, ext, nil)
	if err != nil {
		t.Fatalf("InvokeResolved(%s): %v", tool, err)
	}
	if bg != nil {
		bg.Close()
	}
	if ct != nil {
		ct.Close()
	}
	return res
}

func wantAllowed(t *testing.T, label string, r *PipelineResult) {
	t.Helper()
	if r.IsDenied() {
		t.Errorf("%s: expected allowed, got violation %+v", label, r.Violation)
	}
}

func wantDenied(t *testing.T, label string, r *PipelineResult, code string) {
	t.Helper()
	if !r.IsDenied() {
		t.Errorf("%s: expected denied with %q, got allowed", label, code)
		return
	}
	if code != "" && (r.Violation == nil || !strings.Contains(r.Violation.Code, code)) {
		t.Errorf("%s: expected violation code containing %q, got %+v", label, code, r.Violation)
	}
}

// ---------------------------------------------------------------------------
// Config load
// ---------------------------------------------------------------------------

// TestAcceptanceRemovedConfigKeysFailToLoad checks 0.2.x config shapes
// are refused at load. The C ABI returns a code, not the message; the
// message naming the key goes to the library's tracing log.
func TestAcceptanceRemovedConfigKeysFailToLoad(t *testing.T) {
	cases := []struct {
		name, yaml string
		want       error
	}{
		{"global.policies", "global:\n  policies:\n    - name: legacy\n", ErrCpexParse},
		{"global.apl", "global:\n  apl:\n    pdp:\n      - kind: cel\n", ErrCpexParse},
		{"legacy hook name", "engine_settings:\n  dispatch: hooks\nplugins:\n  - name: idp\n    kind: identity/jwt\n    hooks: [identity_resolve]\n", ErrCpexParse},
		{"removed builtin", "engine_settings:\n  dispatch: hooks\nplugins:\n  - name: pii\n    kind: validator/pii-scan\n    hooks: [cmf.tool_pre_invoke]\n", ErrCpexPipeline},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			eng, err := NewPolicyEngineDefault()
			if err != nil {
				t.Fatalf("NewPolicyEngineDefault: %v", err)
			}
			defer eng.Shutdown()
			if err := eng.EnableAPL(); err != nil {
				t.Fatalf("EnableAPL: %v", err)
			}
			if err := eng.LoadConfig(c.yaml); !errors.Is(err, c.want) {
				t.Errorf("expected %v, got %v", c.want, err)
			}
			if got := eng.PluginCount(); got != 0 {
				t.Errorf("a refused config must not install plugins; got %d", got)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

const accIdentityRoutes = `
routes:
  - tool: get_compensation
    authentication: [idp]
    authorization:
      pre_invocation:
        - "require(authenticated)"
        - "require(role.hr)"
`

func TestAcceptanceJWTIdentityGatesByRole(t *testing.T) {
	idp := newMockIdP(t)
	eng := accEngine(t, idpPlugin(idp.srv.URL+"/jwks", true)+accIdentityRoutes, WithPrivateDestinations())
	if got := idp.fetches(); got != 1 {
		t.Errorf("expected one JWKS fetch at Initialize, got %d", got)
	}
	args := map[string]any{"employee_id": "e-1"}

	wantAllowed(t, "hr", callTool(t, eng, mintJWT(t, "alice", []string{"hr"}, 10*time.Minute, nil), "get_compensation", args, ""))
	wantDenied(t, "engineer", callTool(t, eng, mintJWT(t, "evan", []string{"engineer"}, 10*time.Minute, nil), "get_compensation", args, ""), "")
	wantDenied(t, "expired", callTool(t, eng, mintJWT(t, "alice", []string{"hr"}, -time.Hour, nil), "get_compensation", args, ""), "auth.token_expired")
	wantDenied(t, "forged", callTool(t, eng, mintJWT(t, "alice", []string{"hr"}, 10*time.Minute, []byte("not-the-issuer-key-not-the-issuer")), "get_compensation", args, ""), "auth.signature_invalid")
}

func TestAcceptanceLoopbackJWKSRefusedWithoutOptIn(t *testing.T) {
	idp := newMockIdP(t)
	eng := accEngine(t, idpPlugin(idp.srv.URL+"/jwks", true)+accIdentityRoutes)
	res := callTool(t, eng, mintJWT(t, "alice", []string{"hr"}, 10*time.Minute, nil), "get_compensation", map[string]any{}, "")
	if got := idp.fetches(); got != 0 {
		t.Errorf("expected no JWKS fetch without the opt-in, got %d", got)
	}
	wantDenied(t, "blocked jwks", res, "auth.jwks_unavailable")
}

func TestAcceptanceJWKSWithoutPerformHTTPFailsToStart(t *testing.T) {
	idp := newMockIdP(t)
	eng, err := NewPolicyEngineDefault()
	if err != nil {
		t.Fatalf("NewPolicyEngineDefault: %v", err)
	}
	defer eng.Shutdown()
	if err := eng.EnableAPL(WithPrivateDestinations()); err != nil {
		t.Fatalf("EnableAPL: %v", err)
	}
	if err := eng.LoadConfig(idpPlugin(idp.srv.URL+"/jwks", false) + accIdentityRoutes); err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if err := eng.Initialize(); err == nil {
		t.Fatal("expected Initialize to fail without perform_http")
	}
	if got := idp.fetches(); got != 0 {
		t.Errorf("expected no JWKS fetch, got %d", got)
	}
}

// ---------------------------------------------------------------------------
// Delegation
// ---------------------------------------------------------------------------

func TestAcceptanceOAuthDelegation(t *testing.T) {
	idp := newMockIdP(t)
	yaml := idpPlugin(idp.srv.URL+"/jwks", true) + `
  - name: workday-oauth
    kind: delegator/oauth
    hooks: [token.delegate]
    capabilities: [read_inbound_credentials, write_delegated_tokens, perform_http]
    config:
      token_endpoint: "` + idp.srv.URL + `/token"
      client_id: cpex-gateway
      client_secret_source: {kind: literal, secret: acceptance-only}
      insecure_http: true

routes:
  - tool: get_compensation
    authentication: [idp]
    authorization:
      pre_invocation:
        - "require(role.hr)"
        - "delegate(workday-oauth, target: workday-api, audience: workday-api)"
        - "require(delegation.granted)"

  - tool: read_repo
    authentication: [idp]
    authorization:
      pre_invocation:
        - "require(authenticated)"
        - "delegate(workday-oauth, target: github-api, audience: github-api)"
        - "require(delegation.granted)"
`
	eng := accEngine(t, yaml, WithPrivateDestinations())
	alice := mintJWT(t, "alice", []string{"hr"}, 10*time.Minute, nil)

	wantAllowed(t, "hr delegated", callTool(t, eng, alice, "get_compensation", map[string]any{"employee_id": "e-1"}, ""))
	ex := idp.tokenExchanges()
	if len(ex) != 1 {
		t.Fatalf("expected one token exchange, got %d", len(ex))
	}
	if got := ex[0].Get("subject_token"); got != alice {
		t.Errorf("the inbound bearer token must be the subject_token; got %q", got)
	}
	if got := ex[0].Get("grant_type"); got != "urn:ietf:params:oauth:grant-type:token-exchange" {
		t.Errorf("unexpected grant_type %q", got)
	}

	wantDenied(t, "engineer denied before delegation",
		callTool(t, eng, mintJWT(t, "evan", []string{"engineer"}, 10*time.Minute, nil), "get_compensation", map[string]any{}, ""), "")
	if got := len(idp.tokenExchanges()); got != 1 {
		t.Errorf("a role denial must not reach the token endpoint; exchanges = %d", got)
	}

	wantDenied(t, "audience refused", callTool(t, eng, alice, "read_repo", map[string]any{"repo": "cpex"}, ""), "")

	// Without the host opt-in the minted token stays in the engine.
	if got := callTool(t, eng, alice, "get_compensation", map[string]any{}, ""); len(got.DelegatedCredentials) != 0 {
		t.Errorf("credentials returned without WithDelegatedCredentials: %d", len(got.DelegatedCredentials))
	}

	// With it, the allowed result carries the header to send upstream.
	exposed := accEngine(t, yaml, WithPrivateDestinations(), WithDelegatedCredentials())
	res := callTool(t, exposed, alice, "get_compensation", map[string]any{"employee_id": "e-1"}, "")
	wantAllowed(t, "hr delegated, exposed", res)
	if len(res.DelegatedCredentials) != 1 {
		t.Fatalf("expected one delegated credential, got %d", len(res.DelegatedCredentials))
	}
	c := res.DelegatedCredentials[0]
	if c.Header != "Authorization" || c.Value.Reveal() != "Bearer acceptance-only-workday-token" {
		t.Errorf("credential = %s: <value len %d>", c.Header, len(c.Value.Reveal()))
	}
	if c.Delegator != "workday-oauth" || c.Target != "workday-api" || c.Audience != "workday-api" {
		t.Errorf("credential metadata = %+v", c)
	}
	if exp, err := time.Parse(time.RFC3339, c.ExpiresAt); err != nil || !exp.After(time.Now()) {
		t.Errorf("expires_at %q: %v", c.ExpiresAt, err)
	}
	if strings.Contains(fmt.Sprintf("%v %+v %#v", res, *res, c), "acceptance-only-workday-token") {
		t.Error("a printed result leaked the minted token")
	}
	evan := mintJWT(t, "evan", []string{"engineer"}, 10*time.Minute, nil)
	if got := callTool(t, exposed, evan, "get_compensation", map[string]any{}, ""); len(got.DelegatedCredentials) != 0 {
		t.Error("a denied result must carry no credentials")
	}
}

// ---------------------------------------------------------------------------
// PDP decisions on the resolved subject
// ---------------------------------------------------------------------------

func TestAcceptanceCedarDecision(t *testing.T) {
	idp := newMockIdP(t)
	yaml := `
global:
  pdp:
    - kind: cedar-direct
      policy_text: |
        @id("hr-read-compensation")
        permit(principal, action == Action::"read", resource)
        when { principal.roles.contains("hr") };

        @id("contractor-forbid")
        forbid(principal, action, resource)
        when { principal.roles.contains("contractor") };
` + idpPlugin(idp.srv.URL+"/jwks", true) + `
routes:
  - tool: get_compensation
    authentication: [idp]
    authorization:
      pre_invocation:
        - cedar:
            action: 'Action::"read"'
            resource:
              type: Compensation
              id: e-1001
`
	eng := accEngine(t, yaml, WithPrivateDestinations())
	args := map[string]any{"employee_id": "e-1001"}
	ten := 10 * time.Minute

	wantAllowed(t, "hr", callTool(t, eng, mintJWT(t, "alice", []string{"hr"}, ten, nil), "get_compensation", args, ""))
	wantDenied(t, "engineer", callTool(t, eng, mintJWT(t, "evan", []string{"engineer"}, ten, nil), "get_compensation", args, ""), "cedar.default_deny")
	wantDenied(t, "contractor", callTool(t, eng, mintJWT(t, "carl", []string{"hr", "contractor"}, ten, nil), "get_compensation", args, ""), "contractor-forbid")
}

func TestAcceptanceOPADecision(t *testing.T) {
	idp := newMockIdP(t)
	yaml := `
global:
  pdp:
    - kind: opa
      modules:
        - |
          package cpex.acceptance
          default allow := false
          allow if {
            input.subject.id == "alice"
            input.args.amount <= 100
          }
` + idpPlugin(idp.srv.URL+"/jwks", true) + `
routes:
  - tool: transfer
    authentication: [idp]
    authorization:
      pre_invocation:
        - opa:
            query: "data.cpex.acceptance.allow"
`
	eng := accEngine(t, yaml, WithPrivateDestinations())
	ten := 10 * time.Minute
	alice := mintJWT(t, "alice", []string{"finance"}, ten, nil)

	wantAllowed(t, "alice small", callTool(t, eng, alice, "transfer", map[string]any{"amount": 50}, ""))
	wantDenied(t, "alice large", callTool(t, eng, alice, "transfer", map[string]any{"amount": 500}, ""), "opa")
	wantDenied(t, "evan", callTool(t, eng, mintJWT(t, "evan", []string{"finance"}, ten, nil), "transfer", map[string]any{"amount": 50}, ""), "opa")
}

// ---------------------------------------------------------------------------
// Session labels
// ---------------------------------------------------------------------------

const accSessionRoutes = `
routes:
  - tool: get_compensation
    authentication: [idp]
    authorization:
      pre_invocation:
        - "require(role.hr)"
        - "taint(secret, session)"

  - tool: send_email
    authentication: [idp]
    authorization:
      pre_invocation:
        - "require(authenticated)"
        - "security.labels contains \"secret\": deny('write-down blocked', 'session_tainted')"
`

func TestAcceptanceSessionLabelsMemoryStore(t *testing.T) {
	idp := newMockIdP(t)
	eng := accEngine(t, idpPlugin(idp.srv.URL+"/jwks", true)+accSessionRoutes, WithPrivateDestinations())
	ten := 10 * time.Minute
	alice := mintJWT(t, "alice", []string{"hr"}, ten, nil)
	email := map[string]any{"to": "bob@corp.example"}

	wantAllowed(t, "email before taint", callTool(t, eng, alice, "send_email", email, "sess-1"))
	wantAllowed(t, "read taints", callTool(t, eng, alice, "get_compensation", map[string]any{"employee_id": "e-1"}, "sess-1"))
	wantDenied(t, "email after taint", callTool(t, eng, alice, "send_email", email, "sess-1"), "session_tainted")
	wantAllowed(t, "fresh session", callTool(t, eng, alice, "send_email", email, "sess-2"))
	wantAllowed(t, "other subject", callTool(t, eng, mintJWT(t, "evan", []string{"engineer"}, ten, nil), "send_email", email, "sess-1"))
}

// TestAcceptanceSessionLabelsSharedValkey taints a session on one engine
// and checks a second engine sharing the Valkey store sees the label.
// Skipped unless CPEX_TEST_VALKEY_URL names a reachable server.
func TestAcceptanceSessionLabelsSharedValkey(t *testing.T) {
	valkeyURL := os.Getenv("CPEX_TEST_VALKEY_URL")
	if valkeyURL == "" {
		t.Skip("set CPEX_TEST_VALKEY_URL (e.g. redis://127.0.0.1:6390) to run")
	}
	idp := newMockIdP(t)
	yaml := `
global:
  session_store:
    kind: valkey
    endpoint: "` + valkeyURL + `"
    ttl_seconds: 300
` + idpPlugin(idp.srv.URL+"/jwks", true) + accSessionRoutes
	first := accEngine(t, yaml, WithPrivateDestinations())
	second := accEngine(t, yaml, WithPrivateDestinations())

	ten := 10 * time.Minute
	alice := mintJWT(t, "alice", []string{"hr"}, ten, nil)
	email := map[string]any{"to": "bob@corp.example"}
	// A per-run session id keeps reruns against the same server independent.
	session := fmt.Sprintf("acc-%d", time.Now().UnixNano())

	wantAllowed(t, "second engine before taint", callTool(t, second, alice, "send_email", email, session))
	wantAllowed(t, "first engine taints", callTool(t, first, alice, "get_compensation", map[string]any{"employee_id": "e-1"}, session))
	wantDenied(t, "second engine after taint", callTool(t, second, alice, "send_email", email, session), "session_tainted")
	wantAllowed(t, "fresh session on second engine", callTool(t, second, alice, "send_email", email, session+"-fresh"))
}
