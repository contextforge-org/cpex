// Location: ./tests/parity/harness/src/valkey.rs
// SPDX-License-Identifier: Apache-2.0
//
// Raw keyspace access for session-label scenarios: clear the database
// before a capture, then export every key under the label prefix so a
// later run can seed a store from it and check it reads the same labels.

use std::collections::BTreeMap;

use serde_json::{json, Value};

/// Key prefix the session store writes under.
pub const KEY_PREFIX: &str = "taint:v1";

fn connect(url: &str) -> Result<redis::Connection, String> {
    redis::Client::open(url)
        .and_then(|c| c.get_connection())
        .map_err(|e| format!("valkey {url}: {e}"))
}

/// Empty the selected database. The capture URL must point at a database
/// used only for parity runs.
pub fn flush(url: &str) -> Result<(), String> {
    let mut con = connect(url)?;
    redis::cmd("FLUSHDB")
        .query::<()>(&mut con)
        .map_err(|e| format!("FLUSHDB: {e}"))
}

/// Export `taint:v1:*` as `{ key: { type, members, ttl } }`. Set members are
/// sorted. `ttl` is `null` for keys without expiry and `"set"` otherwise,
/// since the remaining seconds depend on timing.
pub fn export(url: &str) -> Result<Value, String> {
    let mut con = connect(url)?;
    let mut keys: Vec<String> = Vec::new();
    let mut cursor: u64 = 0;
    loop {
        let (next, batch): (u64, Vec<String>) = redis::cmd("SCAN")
            .arg(cursor)
            .arg("MATCH")
            .arg(format!("{KEY_PREFIX}:*"))
            .arg("COUNT")
            .arg(1000)
            .query(&mut con)
            .map_err(|e| format!("SCAN: {e}"))?;
        keys.extend(batch);
        if next == 0 {
            break;
        }
        cursor = next;
    }
    keys.sort();
    keys.dedup();

    let mut out = BTreeMap::new();
    for key in keys {
        let kind: String = redis::cmd("TYPE")
            .arg(&key)
            .query(&mut con)
            .map_err(|e| format!("TYPE {key}: {e}"))?;
        let members: Value = if kind == "set" {
            let mut m: Vec<String> = redis::cmd("SMEMBERS")
                .arg(&key)
                .query(&mut con)
                .map_err(|e| format!("SMEMBERS {key}: {e}"))?;
            m.sort();
            json!(m)
        } else {
            Value::Null
        };
        let ttl: i64 = redis::cmd("TTL")
            .arg(&key)
            .query(&mut con)
            .map_err(|e| format!("TTL {key}: {e}"))?;
        out.insert(
            key,
            json!({
                "type": kind,
                "members": members,
                "ttl": if ttl >= 0 { json!("set") } else { Value::Null },
            }),
        );
    }
    Ok(json!({ "key_prefix": KEY_PREFIX, "keys": out }))
}
