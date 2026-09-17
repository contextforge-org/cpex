// Location: ./go/cpex/identity.go
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
//
// IdentityPayload — Go view of the identity.resolve hook's input/output
// state (crates/cpex-core/src/identity/payload.rs).
//
// Hosts that don't run in-process Rust (i.e. the Go FFI bindings) drive
// identity resolution like this:
//
//	idp := cpex.NewIdentityPayload(cpex.TokenSourceBearer, headers)
//	res, ct, bg, err := mgr.InvokeByName(
//	    cpex.HookIdentityResolve, cpex.PayloadIdentity, idp, ext, nil)
//	// On success res.ModifiedPayload holds the resolved IdentityPayload.
//	resolved, _ := cpex.DeserializePayload[cpex.IdentityPayload](res)
//	// resolved.Subject carries roles / permissions / teams.
//
// The resolved Subject / Client / RawCredentials are then applied onto
// the Extensions passed to the downstream tool/prompt/resource hook so
// per-route APL gates (require(role.*), redact(!perm.*), Cedar) and the
// OAuth delegator can see the principal and its inbound credentials.

package cpex

import "github.com/vmihailenco/msgpack/v5"

// HookIdentityResolve is the hook name the identity resolver chain is
// registered under. Matches HOOK_IDENTITY_RESOLVE in
// crates/cpex-core/src/identity/hook.rs.
const HookIdentityResolve = "identity.resolve"

// TokenSource values identify where a credential comes from. Wire form
// is snake_case to match the Rust TokenSource enum
// (#[serde(rename_all = "snake_case")]).
const (
	TokenSourceBearer        = "bearer"
	TokenSourceUserToken     = "user_token"
	TokenSourceMTLS          = "mtls"
	TokenSourceSpiffeJwtSvid = "spiffe_jwt_svid"
	TokenSourceAPIKey        = "api_key"
)

// IdentityPayload mirrors the Rust IdentityPayload. Input fields
// (Source, SourceHeader, Headers, ClientHost, ClientPort) are set by the
// host before the call; output fields (Subject, Client, …) are populated
// by the resolver chain and read back from the result.
//
// raw_token is intentionally absent: it is #[serde(skip)] on the Rust
// side (zeroized, never serialized). Tokens travel in Headers — each
// jwt resolver reads its configured header (X-User-Token, Authorization)
// from there.
//
// Output slots the Go side doesn't model field-by-field are carried as
// msgpack.RawMessage so they round-trip verbatim — a host can forward
// them onto the next hook's Extensions without the bindings needing a
// typed mirror of every Rust extension.
type IdentityPayload struct {
	Source       string            `msgpack:"source"`
	SourceHeader string            `msgpack:"source_header,omitempty"`
	Headers      map[string]string `msgpack:"headers,omitempty"`
	ClientHost   string            `msgpack:"client_host,omitempty"`
	ClientPort   uint16            `msgpack:"client_port,omitempty"`

	Subject        *SubjectExtension  `msgpack:"subject,omitempty"`
	Client         msgpack.RawMessage `msgpack:"client,omitempty"`
	CallerWorkload msgpack.RawMessage `msgpack:"caller_workload,omitempty"`
	Delegation     msgpack.RawMessage `msgpack:"delegation,omitempty"`
	RawCredentials msgpack.RawMessage `msgpack:"raw_credentials,omitempty"`
	ResolvedAt     string             `msgpack:"resolved_at,omitempty"`
	RawClaims      map[string]any     `msgpack:"raw_claims,omitempty"`
}

// NewIdentityPayload builds an input payload for identity.resolve. The
// header map should carry the inbound request's auth headers (lowercased
// keys — the resolvers look their configured header up case-folded).
func NewIdentityPayload(source string, headers map[string]string) IdentityPayload {
	if source == "" {
		source = TokenSourceBearer
	}
	return IdentityPayload{Source: source, Headers: headers}
}
