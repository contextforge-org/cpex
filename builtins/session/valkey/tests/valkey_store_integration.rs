// Location: ./builtins/session/valkey/tests/valkey_store_integration.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Fred Araujo
//
// Integration tests for ValkeySessionStore against a real `valkey/valkey`
// container (testcontainers). These are `#[ignore]`d by default so unit
// runs don't require Docker; run them with:
//
//   cargo test -p cpex-session-valkey -- --ignored
//
// Skip discipline (learning from PR #67's silent no-op tests):
//   - If `VALKEY_TEST_URL` is set, run against that endpoint (a CI service
//     container or a locally-run `valkey/valkey`) — no testcontainers.
//   - Else start a testcontainers `valkey/valkey`. If that can't start AND
//     `REQUIRE_VALKEY_TESTS=1` is set (CI), that is a hard failure (panic)
//     — the test genuinely ran.
//   - Otherwise (local, no Docker) the helper prints a loud SKIPPED line
//     and the test returns without asserting. The visible line is what
//     stops a silent green.

use apl_cpex::{SessionStore, SessionStoreError};
use cpex_session_valkey::{ValkeyConfig, ValkeySessionStore};
use sha2::{Digest, Sha256};
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::ContainerAsync;
use testcontainers_modules::valkey::{Valkey, VALKEY_PORT};

/// A Valkey endpoint to test against, plus the container handle when one
/// was started (kept alive for the test's duration).
struct Target {
    url: String,
    _container: Option<ContainerAsync<Valkey>>,
}

/// Resolve a Valkey target, or skip loudly when none is available.
/// Returns `None` to signal the caller should return early (skip).
async fn valkey_target() -> Option<Target> {
    if let Ok(url) = std::env::var("VALKEY_TEST_URL") {
        return Some(Target {
            url,
            _container: None,
        });
    }
    match Valkey::default().start().await {
        Ok(node) => {
            let host = node.get_host().await.expect("container host");
            let port = node
                .get_host_port_ipv4(VALKEY_PORT)
                .await
                .expect("container port");
            Some(Target {
                url: format!("redis://{host}:{port}"),
                _container: Some(node),
            })
        },
        Err(e) => {
            if std::env::var("REQUIRE_VALKEY_TESTS").as_deref() == Ok("1") {
                panic!("REQUIRE_VALKEY_TESTS=1 but no Valkey available: {e} (set VALKEY_TEST_URL or start Docker)");
            }
            eprintln!(
                "SKIPPED: no Valkey available ({e}); set VALKEY_TEST_URL or REQUIRE_VALKEY_TESTS=1"
            );
            None
        },
    }
}

/// Build a store pointed at the target.
fn store_for(target: &Target, ttl_seconds: Option<u64>) -> ValkeySessionStore {
    let mut yaml = format!("kind: valkey\nendpoint: {}\n", target.url);
    if let Some(ttl) = ttl_seconds {
        yaml.push_str(&format!("ttl_seconds: {ttl}\n"));
    }
    let value: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
    let cfg = ValkeyConfig::from_value(&value).expect("valid config");
    ValkeySessionStore::from_config(&cfg).expect("build store")
}

/// Raw connection for white-box assertions (TTL, seeding a wrong-typed key).
async fn raw_conn(target: &Target) -> redis::aio::MultiplexedConnection {
    redis::Client::open(target.url.clone())
        .unwrap()
        .get_multiplexed_async_connection()
        .await
        .unwrap()
}

/// Replicate the store's key schema so white-box tests can target the
/// exact key (documents the schema as a side effect).
fn store_key(session_id: &str) -> String {
    let digest = Sha256::digest(session_id.as_bytes());
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    format!("taint:v1:{hex}")
}

/// AE4 / R16: concurrent appends from two "nodes" (separate store
/// instances against one Valkey) union without loss; a third reader sees
/// the full set.
#[tokio::test]
#[ignore]
async fn cross_node_concurrent_append_unions() {
    let Some(target) = valkey_target().await else {
        return;
    };
    let node_a = store_for(&target, None);
    let node_b = store_for(&target, None);
    let sid = "sess-union";

    let labels_a = vec!["PII".to_string()];
    let labels_b = vec!["INTERNAL".to_string()];
    let (ra, rb) = tokio::join!(
        node_a.append_labels(sid, &labels_a),
        node_b.append_labels(sid, &labels_b),
    );
    ra.expect("node A append");
    rb.expect("node B append");

    let reader = store_for(&target, None);
    let mut labels = reader.load_labels(sid).await.expect("load");
    labels.sort();
    assert_eq!(labels, vec!["INTERNAL".to_string(), "PII".to_string()]);
}

/// R15: an unknown session is a confirmed key-miss → Ok(empty), not Err.
#[tokio::test]
#[ignore]
async fn unknown_session_returns_empty_ok() {
    let Some(target) = valkey_target().await else {
        return;
    };
    let store = store_for(&target, None);
    let labels = store
        .load_labels("never-written")
        .await
        .expect("unknown session must be Ok(empty), not Err");
    assert!(labels.is_empty());
}

/// R5: a reachable but undecodable reply (key holds a string, not a SET)
/// fails closed (Err) rather than returning Ok(empty).
#[tokio::test]
#[ignore]
async fn wrongtype_reply_fails_closed() {
    let Some(target) = valkey_target().await else {
        return;
    };
    let store = store_for(&target, None);

    // Seed the exact key as a plain string so SMEMBERS returns WRONGTYPE.
    let mut conn = raw_conn(&target).await;
    let sid = "sess-wrongtype";
    let _: () = redis::cmd("SET")
        .arg(store_key(sid))
        .arg("not-a-set")
        .query_async(&mut conn)
        .await
        .unwrap();

    let result = store.load_labels(sid).await;
    assert!(
        matches!(result, Err(SessionStoreError::Backend(_))),
        "WRONGTYPE must fail closed, got {result:?}"
    );
}

/// R5: an unreachable endpoint fails closed quickly (bounded by the
/// command timeout). No container needed, but kept with the suite.
#[tokio::test]
#[ignore]
async fn unreachable_endpoint_fails_closed() {
    // Port 1 is not listening; localhost so TLS is not required.
    let value: serde_yaml::Value =
        serde_yaml::from_str("kind: valkey\nendpoint: 127.0.0.1:1\ncommand_timeout_ms: 300\n")
            .unwrap();
    let cfg = ValkeyConfig::from_value(&value).unwrap();
    let store = ValkeySessionStore::from_config(&cfg).unwrap();

    let result = store.load_labels("sess-x").await;
    assert!(
        matches!(result, Err(SessionStoreError::Backend(_))),
        "unreachable endpoint must fail closed, got {result:?}"
    );
}

/// AE2 / R7: a configured TTL is set on append and refreshed on load.
#[tokio::test]
#[ignore]
async fn ttl_set_on_append_and_refreshed_on_load() {
    let Some(target) = valkey_target().await else {
        return;
    };
    let store = store_for(&target, Some(100));
    let sid = "sess-ttl";
    store
        .append_labels(sid, &["PII".to_string()])
        .await
        .expect("append");

    let mut conn = raw_conn(&target).await;
    let ttl_after_append: i64 = redis::cmd("TTL")
        .arg(store_key(sid))
        .query_async(&mut conn)
        .await
        .unwrap();
    assert!(
        ttl_after_append > 0 && ttl_after_append <= 100,
        "append should set a positive TTL, got {ttl_after_append}"
    );

    // A load refreshes the sliding TTL back toward the configured window.
    let _ = store.load_labels(sid).await.expect("load");
    let ttl_after_load: i64 = redis::cmd("TTL")
        .arg(store_key(sid))
        .query_async(&mut conn)
        .await
        .unwrap();
    assert!(
        ttl_after_load > 0,
        "load should keep/refresh a positive TTL, got {ttl_after_load}"
    );
}
