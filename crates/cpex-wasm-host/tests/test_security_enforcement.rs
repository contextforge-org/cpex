// Tests for defense-in-depth security enforcement in WasmBridgeHandler.
//
// These tests validate the four security checks:
// 1. Pre-invocation capability-based extension filtering
// 2. Post-invocation immutable tier validation
// 3. Post-invocation monotonic label enforcement
// 4. Post-invocation write authorization checking

use std::collections::HashSet;
use std::sync::Arc;

use cpex_core::extensions::{
    filter_extensions, DelegationExtension, Extensions, Guarded, HttpExtension, MonotonicSet,
    OwnedExtensions, RequestExtension, SecurityExtension,
};

// ---------------------------------------------------------------------------
// Fix 1: Pre-invocation capability filtering
// ---------------------------------------------------------------------------

#[test]
fn test_pre_filter_strips_ungated_extensions() {
    let ext = build_full_extensions();
    let caps: HashSet<String> = ["read_headers"].iter().map(|s| s.to_string()).collect();

    let filtered = filter_extensions(&ext, &caps);

    // HTTP is visible (has read_headers)
    assert!(filtered.http.is_some());
    // Security labels require read_labels — not granted
    assert!(
        filtered.security.is_none()
            || filtered
                .security
                .as_ref()
                .unwrap()
                .labels
                .is_empty()
    );
    // Agent requires read_agent — not granted
    assert!(filtered.agent.is_none());
    // Delegation requires read_delegation — not granted
    assert!(filtered.delegation.is_none());
    // Unrestricted immutable slots are always visible
    assert!(filtered.request.is_some());
}

#[test]
fn test_pre_filter_allows_all_with_full_capabilities() {
    let ext = build_full_extensions();
    let caps: HashSet<String> = [
        "read_headers",
        "read_labels",
        "read_subject",
        "read_agent",
        "read_delegation",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();

    let filtered = filter_extensions(&ext, &caps);

    assert!(filtered.http.is_some());
    assert!(filtered.security.is_some());
    assert!(filtered.agent.is_some());
    assert!(filtered.delegation.is_some());
    assert!(filtered.request.is_some());
}

// ---------------------------------------------------------------------------
// Fix 2: Immutable tier validation
// ---------------------------------------------------------------------------

#[test]
fn test_immutable_tier_violation_detected() {
    let ext = build_full_extensions();
    let mut owned = ext.cow_copy();

    // Tamper with an immutable slot by replacing the Arc pointer
    owned.request = Some(Arc::new(RequestExtension {
        request_id: Some("tampered".into()),
        ..Default::default()
    }));

    assert!(!ext.validate_immutable(&owned));
}

#[test]
fn test_immutable_tier_passes_when_arcs_preserved() {
    let ext = build_full_extensions();
    let owned = ext.cow_copy();

    assert!(ext.validate_immutable(&owned));
}

// ---------------------------------------------------------------------------
// Fix 3: Monotonic label enforcement
// ---------------------------------------------------------------------------

#[test]
fn test_monotonic_violation_when_label_removed() {
    let ext = build_extensions_with_labels(&["PII", "HIPAA"]);
    let mut owned = ext.cow_copy();

    // Replace security with only one label (removed HIPAA)
    let mut new_sec = SecurityExtension::default();
    new_sec.labels = MonotonicSet::from_set(["PII".to_string()].into_iter().collect());
    owned.security = Some(new_sec);

    // With read_labels capability, this should be detected
    let caps: HashSet<String> = ["read_labels"].iter().map(|s| s.to_string()).collect();

    let result = validate_monotonic(&ext, &owned, &caps);
    assert!(!result, "should reject when label removed");
}

#[test]
fn test_monotonic_passes_when_labels_only_added() {
    let ext = build_extensions_with_labels(&["PII"]);
    let mut owned = ext.cow_copy();

    // Add a label (superset of original)
    let mut new_sec = SecurityExtension::default();
    new_sec.labels =
        MonotonicSet::from_set(["PII".to_string(), "HIPAA".to_string()].into_iter().collect());
    owned.security = Some(new_sec);

    let caps: HashSet<String> = ["read_labels"].iter().map(|s| s.to_string()).collect();

    let result = validate_monotonic(&ext, &owned, &caps);
    assert!(result, "should accept when labels only added");
}

#[test]
fn test_monotonic_not_enforced_without_read_labels() {
    let ext = build_extensions_with_labels(&["PII", "HIPAA"]);
    let mut owned = ext.cow_copy();

    // Remove a label
    let mut new_sec = SecurityExtension::default();
    new_sec.labels = MonotonicSet::from_set(["PII".to_string()].into_iter().collect());
    owned.security = Some(new_sec);

    // Without read_labels capability, plugin never saw labels — not a violation
    let caps: HashSet<String> = HashSet::new();

    let result = validate_monotonic(&ext, &owned, &caps);
    assert!(result, "should not enforce monotonic without read_labels cap");
}

// ---------------------------------------------------------------------------
// Fix 4: Write authorization checking
// ---------------------------------------------------------------------------

#[test]
fn test_unauthorized_http_write_detected() {
    let ext = build_full_extensions();
    let mut owned = ext.cow_copy();

    // Modify HTTP headers
    let mut new_http = HttpExtension::default();
    new_http.request_headers.insert("X-Injected".into(), "evil".into());
    owned.http = Some(Guarded::new(new_http));

    // Plugin lacks write_headers capability
    let caps: HashSet<String> = ["read_headers"].iter().map(|s| s.to_string()).collect();

    let result = validate_write_auth_http(&ext, &owned, &caps);
    assert!(!result, "should reject HTTP write without write_headers cap");
}

#[test]
fn test_authorized_http_write_passes() {
    let ext = build_full_extensions();
    let mut owned = ext.cow_copy();

    // Modify HTTP headers
    let mut new_http = HttpExtension::default();
    new_http.request_headers.insert("X-Processed".into(), "ok".into());
    owned.http = Some(Guarded::new(new_http));

    // Plugin HAS write_headers capability
    let caps: HashSet<String> = ["read_headers", "write_headers"]
        .iter()
        .map(|s| s.to_string())
        .collect();

    let result = validate_write_auth_http(&ext, &owned, &caps);
    assert!(result, "should accept HTTP write with write_headers cap");
}

#[test]
fn test_unauthorized_labels_write_detected() {
    let ext = build_extensions_with_labels(&["PII"]);
    let mut owned = ext.cow_copy();

    // Add a label without append_labels capability
    let mut new_sec = SecurityExtension::default();
    new_sec.labels =
        MonotonicSet::from_set(["PII".to_string(), "NEW".to_string()].into_iter().collect());
    owned.security = Some(new_sec);

    let caps: HashSet<String> = ["read_labels"].iter().map(|s| s.to_string()).collect();

    let result = validate_write_auth_labels(&ext, &owned, &caps);
    assert!(!result, "should reject label write without append_labels cap");
}

#[test]
fn test_authorized_labels_write_passes() {
    let ext = build_extensions_with_labels(&["PII"]);
    let mut owned = ext.cow_copy();

    // Add a label WITH append_labels capability
    let mut new_sec = SecurityExtension::default();
    new_sec.labels =
        MonotonicSet::from_set(["PII".to_string(), "NEW".to_string()].into_iter().collect());
    owned.security = Some(new_sec);

    let caps: HashSet<String> = ["read_labels", "append_labels"]
        .iter()
        .map(|s| s.to_string())
        .collect();

    let result = validate_write_auth_labels(&ext, &owned, &caps);
    assert!(result, "should accept label write with append_labels cap");
}

#[test]
fn test_unauthorized_delegation_write_detected() {
    let ext = build_full_extensions();
    let mut owned = ext.cow_copy();

    // Modify delegation
    let mut new_deleg = DelegationExtension::default();
    new_deleg.delegated = true;
    new_deleg.depth = 1;
    owned.delegation = Some(new_deleg);

    // Plugin lacks append_delegation capability
    let caps: HashSet<String> = ["read_delegation"].iter().map(|s| s.to_string()).collect();

    let result = validate_write_auth_delegation(&ext, &owned, &caps);
    assert!(!result, "should reject delegation write without append_delegation cap");
}

#[test]
fn test_no_modifications_skips_validation() {
    let ext = build_full_extensions();
    let owned = ext.cow_copy();

    // No changes — all checks should pass
    let caps: HashSet<String> = HashSet::new();

    assert!(ext.validate_immutable(&owned));
    // Monotonic: no caps means no enforcement
    assert!(validate_monotonic(&ext, &owned, &caps));
}

// ---------------------------------------------------------------------------
// Helpers — mirror the validation logic from factory.rs
// ---------------------------------------------------------------------------

fn validate_monotonic(
    original: &Extensions,
    owned: &OwnedExtensions,
    capabilities: &HashSet<String>,
) -> bool {
    if capabilities.contains("read_labels") {
        if let (Some(ref orig_sec), Some(ref new_sec)) = (&original.security, &owned.security) {
            if !new_sec.labels.is_superset(&orig_sec.labels) {
                return false;
            }
        }
    }
    true
}

fn validate_write_auth_http(
    original: &Extensions,
    owned: &OwnedExtensions,
    capabilities: &HashSet<String>,
) -> bool {
    if !capabilities.contains("write_headers") {
        if let Some(ref http_guarded) = owned.http {
            let new_http = http_guarded.read();
            let http_changed = match original.http.as_ref() {
                Some(orig) => {
                    new_http.request_headers != orig.request_headers
                        || new_http.response_headers != orig.response_headers
                }
                None => {
                    !new_http.request_headers.is_empty()
                        || !new_http.response_headers.is_empty()
                }
            };
            if http_changed {
                return false;
            }
        }
    }
    true
}

fn validate_write_auth_labels(
    original: &Extensions,
    owned: &OwnedExtensions,
    capabilities: &HashSet<String>,
) -> bool {
    if !capabilities.contains("append_labels") {
        if let Some(ref new_sec) = owned.security {
            let labels_changed = match original.security.as_ref() {
                Some(orig) => new_sec.labels.len() != orig.labels.len(),
                None => !new_sec.labels.is_empty(),
            };
            if labels_changed {
                return false;
            }
        }
    }
    true
}

fn validate_write_auth_delegation(
    original: &Extensions,
    owned: &OwnedExtensions,
    capabilities: &HashSet<String>,
) -> bool {
    if !capabilities.contains("append_delegation") {
        if let Some(ref new_deleg) = owned.delegation {
            let delegation_changed = match original.delegation.as_ref() {
                Some(orig) => {
                    new_deleg.chain.len() != orig.chain.len()
                        || new_deleg.depth != orig.depth
                        || new_deleg.delegated != orig.delegated
                }
                None => new_deleg.delegated || !new_deleg.chain.is_empty(),
            };
            if delegation_changed {
                return false;
            }
        }
    }
    true
}

// ---------------------------------------------------------------------------
// Fix 5: Filtered slot preservation (hidden slots not nulled on writeback)
// ---------------------------------------------------------------------------

#[test]
fn test_hidden_http_slot_preserved_when_plugin_modifies_labels() {
    use cpex_core::extensions::filter_extensions;
    use cpex_wasm_host::conversions::{
        native_extensions_to_wit, wit_hook_result_to_native_filtered,
    };
    use cpex_wasm_host::payload_registry::PayloadSerializerRegistry;

    // Pipeline has HTTP headers
    let ext = build_full_extensions();
    assert!(ext.http.is_some(), "precondition: HTTP exists in pipeline");

    // Plugin only has label capabilities — no read_headers
    let caps: HashSet<String> = ["read_labels", "append_labels"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let filtered = filter_extensions(&ext, &caps);
    assert!(filtered.http.is_none(), "precondition: HTTP filtered out");

    // Simulate guest modifying labels and returning extensions
    let mut wit_ext = native_extensions_to_wit(&filtered);
    if let Some(ref mut s) = wit_ext.security {
        s.labels.push("NEW_LABEL".to_string());
    }

    // Build a HookResult with modified extensions
    let result = cpex_wasm_host::sandbox_manager::types::HookResult {
        continue_processing: true,
        modified_payload: None,
        modified_extensions: Some(wit_ext),
        modified_context: None,
        violation: None,
        metadata: None,
    };

    let registry = PayloadSerializerRegistry::new();
    let (fields, _) =
        wit_hook_result_to_native_filtered(result, &registry, &ext, Some(&filtered));

    let owned = fields
        .modified_extensions
        .expect("extensions should be present");

    // HTTP must be preserved (not nulled) because the guest never saw it
    assert!(
        owned.http.is_some(),
        "HTTP slot was nulled even though guest never received it"
    );
    let http = owned.http.as_ref().unwrap().read();
    assert_eq!(
        http.request_headers.get("Authorization").map(|s| s.as_str()),
        Some("Bearer token"),
        "HTTP headers lost during writeback"
    );

    // Labels should reflect the guest's modification
    let sec = owned.security.as_ref().unwrap();
    assert!(sec.has_label("NEW_LABEL"));
    assert!(sec.has_label("PII"));
}

#[test]
fn test_hidden_delegation_preserved_when_plugin_modifies_http() {
    use cpex_core::extensions::filter_extensions;
    use cpex_wasm_host::conversions::{
        native_extensions_to_wit, wit_hook_result_to_native_filtered,
    };
    use cpex_wasm_host::payload_registry::PayloadSerializerRegistry;

    // Pipeline has delegation
    let ext = build_full_extensions();
    assert!(ext.delegation.is_some());

    // Plugin has HTTP caps but not delegation
    let caps: HashSet<String> = ["read_headers", "write_headers"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let filtered = filter_extensions(&ext, &caps);
    assert!(filtered.delegation.is_none(), "delegation should be filtered");
    assert!(filtered.http.is_some(), "HTTP should be visible");

    // Guest modifies HTTP and returns extensions
    let mut wit_ext = native_extensions_to_wit(&filtered);
    if let Some(ref mut h) = wit_ext.http {
        h.request_headers
            .push(("X-Added".to_string(), "value".to_string()));
    }

    let result = cpex_wasm_host::sandbox_manager::types::HookResult {
        continue_processing: true,
        modified_payload: None,
        modified_extensions: Some(wit_ext),
        modified_context: None,
        violation: None,
        metadata: None,
    };

    let registry = PayloadSerializerRegistry::new();
    let (fields, _) =
        wit_hook_result_to_native_filtered(result, &registry, &ext, Some(&filtered));

    let owned = fields
        .modified_extensions
        .expect("extensions should be present");

    // Delegation must be preserved
    assert!(
        owned.delegation.is_some(),
        "Delegation slot nulled even though guest never received it"
    );
}

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

fn build_full_extensions() -> Extensions {
    let mut security = SecurityExtension::default();
    security.labels = MonotonicSet::from_set(["PII".to_string()].into_iter().collect());

    let mut http = HttpExtension::default();
    http.request_headers
        .insert("Authorization".into(), "Bearer token".into());

    Extensions {
        request: Some(Arc::new(RequestExtension {
            request_id: Some("req-001".into()),
            ..Default::default()
        })),
        security: Some(Arc::new(security)),
        http: Some(Arc::new(http)),
        delegation: Some(Arc::new(DelegationExtension::default())),
        agent: Some(Arc::new(cpex_core::extensions::AgentExtension::default())),
        ..Default::default()
    }
}

fn build_extensions_with_labels(labels: &[&str]) -> Extensions {
    let mut security = SecurityExtension::default();
    security.labels =
        MonotonicSet::from_set(labels.iter().map(|s| s.to_string()).collect());

    Extensions {
        request: Some(Arc::new(RequestExtension {
            request_id: Some("req-001".into()),
            ..Default::default()
        })),
        security: Some(Arc::new(security)),
        http: Some(Arc::new(HttpExtension::default())),
        delegation: Some(Arc::new(DelegationExtension::default())),
        ..Default::default()
    }
}
