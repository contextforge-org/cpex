// Location: ./tests/parity/harness/src/lib.rs
// SPDX-License-Identifier: Apache-2.0
//
// Parity harness. For each scenario under `<root>/scenarios`: map its hook
// names through the rename table, template its migrated config, start the
// mock upstream, mint its test tokens, load the engine, and replay the
// request set in order into one normalized snapshot. `capture` writes it to
// `<out>/<scenario>.json` (plus the raw `taint:v1` keyspace for Valkey
// scenarios under `<out>/valkey/`); `check_parity` diffs it against the
// 0.2.3 baseline in `<root>/snapshots` instead.
//
// Engine-specific code lives in `engine.rs`; everything else reads and
// writes engine-neutral data.

pub mod engine;
pub mod keys;
pub mod mock;
pub mod normalize;
pub mod parity;
pub mod spec;
pub mod valkey;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use engine::{Engine, ResolvedCaller};
use keys::KeyRing;
use mock::MockServer;
use normalize::{to_snapshot_string, Scrubber};
use spec::{HookRenames, Request, Scenario};

/// TEST-ONLY client secret handed to OAuth and CIBA plugins through a file
/// source. The mock upstream does not check it.
const TEST_CLIENT_SECRET: &str = "parity-test-only-client-secret";

/// The reviewed legacy-to-current hook rename table, relative to the root.
pub const HOOK_RENAMES_FILE: &str = "hook-renames.yaml";

pub struct Options {
    /// Directory holding `scenarios/`.
    pub root: PathBuf,
    /// Where snapshots are written.
    pub out: PathBuf,
    /// Run only these scenarios (all when empty).
    pub only: Vec<String>,
    /// Valkey URL for scenarios that require it. The database is flushed.
    pub valkey_url: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Status {
    Written,
    Skipped(String),
}

pub fn default_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("harness lives under tests/parity")
        .to_path_buf()
}

/// Where the binary writes a capture unless told otherwise: `target/parity`
/// in the workspace, away from the committed baseline.
pub fn default_out() -> PathBuf {
    default_root().join("../../target/parity")
}

pub fn scenario_names(root: &Path) -> Result<Vec<String>, String> {
    let dir = root.join("scenarios");
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .filter_map(Result::ok)
        .filter(|e| e.path().join("requests.yaml").is_file())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    Ok(names)
}

pub async fn capture(opts: &Options) -> Result<Vec<(String, Status)>, String> {
    let names = scenario_names(&opts.root)?;
    let mut results = Vec::new();
    for name in names {
        if !opts.only.is_empty() && !opts.only.contains(&name) {
            continue;
        }
        let status = capture_one(opts, &name).await?;
        results.push((name, status));
    }
    Ok(results)
}

async fn capture_one(opts: &Options, name: &str) -> Result<Status, String> {
    let (snapshot, keyspace) = match replay(opts, name, &Replay::default()).await? {
        Replayed::Skipped(why) => return Ok(Status::Skipped(why)),
        Replayed::Done { snapshot, keyspace } => (snapshot, keyspace),
    };
    std::fs::create_dir_all(&opts.out).map_err(|e| format!("{}: {e}", opts.out.display()))?;
    write(
        &opts.out.join(format!("{name}.json")),
        &to_snapshot_string(snapshot),
    )?;
    if let Some(dump) = keyspace {
        let vdir = opts.out.join("valkey");
        std::fs::create_dir_all(&vdir).map_err(|e| format!("{}: {e}", vdir.display()))?;
        write(
            &vdir.join(format!("{name}.keyspace.json")),
            &to_snapshot_string(dump),
        )?;
    }
    Ok(Status::Written)
}

/// How one scenario is replayed. The default replays every request against
/// an empty store.
#[derive(Default)]
pub struct Replay {
    /// Seed the Valkey database with this keyspace export (the
    /// `valkey/<name>.keyspace.json` shape) after flushing it.
    pub valkey_seed: Option<Value>,
    /// Replay only these request ids, in scenario order (all when empty).
    pub only_requests: Vec<String>,
}

pub enum Replayed {
    Skipped(String),
    /// The normalized snapshot, and the Valkey keyspace left afterwards
    /// when the scenario uses Valkey.
    Done {
        snapshot: Value,
        keyspace: Option<Value>,
    },
}

/// Replay one scenario and return its normalized snapshot without writing
/// anything.
pub async fn replay(opts: &Options, name: &str, plan: &Replay) -> Result<Replayed, String> {
    let dir = opts.root.join("scenarios").join(name);
    let raw = read(&dir.join("requests.yaml"))?;
    let mut scenario: Scenario =
        serde_yaml::from_str(&raw).map_err(|e| format!("{name}/requests.yaml: {e}"))?;
    scenario.apply_hook_renames(&load_hook_renames(&opts.root)?);

    let needs_valkey = scenario.requires.iter().any(|r| r == "valkey");
    if let Some(other) = scenario.requires.iter().find(|r| *r != "valkey") {
        return Err(format!("{name}: unknown requirement '{other}'"));
    }
    if needs_valkey && opts.valkey_url.is_none() {
        return Ok(Replayed::Skipped(
            "requires Valkey; pass --valkey-url or set PARITY_VALKEY_URL".into(),
        ));
    }
    if plan.valkey_seed.is_some() && !needs_valkey {
        return Err(format!("{name}: a Valkey seed needs a Valkey scenario"));
    }

    let keys = KeyRing::default();
    let mut scrub = Scrubber::default();
    let mut tokens = BTreeMap::new();
    for (tname, tspec) in &scenario.tokens {
        let jwt = keys
            .mint(tspec)
            .map_err(|e| format!("{name}: token {tname}: {e}"))?;
        scrub.add_secret(jwt.clone());
        tokens.insert(tname.clone(), jwt);
    }
    for route in &scenario.mocks {
        if let Some(body) = &route.json {
            scrub.harvest_tokens(body);
        }
    }
    let mock = MockServer::start(scenario.mocks.clone(), &keys)?;
    scrub.set_mock_url(mock.url());

    let work = std::env::temp_dir().join(format!("cpex-parity-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&work).map_err(|e| format!("{}: {e}", work.display()))?;
    let secret_file = work.join("client_secret");
    std::fs::write(&secret_file, TEST_CLIENT_SECRET)
        .map_err(|e| format!("{}: {e}", secret_file.display()))?;
    scrub.add_secret(TEST_CLIENT_SECRET);

    let config = read(&dir.join(&scenario.ppe_config))?
        .replace("{{MOCK_URL}}", mock.url())
        .replace("{{CLIENT_SECRET_FILE}}", &secret_file.to_string_lossy())
        .replace(
            "{{VALKEY_URL}}",
            opts.valkey_url
                .as_deref()
                .unwrap_or("redis://127.0.0.1:6379"),
        );

    let valkey_url = opts.valkey_url.as_deref().unwrap_or_default();
    if needs_valkey {
        valkey::flush(valkey_url)?;
        if let Some(seed) = &plan.valkey_seed {
            valkey::seed(valkey_url, seed)?;
        }
    }

    let mut snapshot = json!({
        "scenario": name,
        "description": scenario.description,
        "config": format!("scenarios/{name}/{}", scenario.ppe_config),
    });

    match Engine::load(&config, &scenario.host_plugins).await {
        Err(e) => {
            snapshot["load"] = json!({ "ok": false, "error": e });
            snapshot["requests"] = json!([]);
        },
        Ok(engine) => {
            snapshot["load"] = json!({ "ok": true, "upstream_calls": mock.drain_calls() });
            let mut outcomes = Vec::new();
            let mut elicitations: BTreeMap<String, String> = BTreeMap::new();
            for req in &scenario.requests {
                if !plan.only_requests.is_empty()
                    && !plan.only_requests.iter().any(|id| id == req.id())
                {
                    continue;
                }
                let mut rec = run_request(&engine, &scenario, req, &tokens, &elicitations).await?;
                if let Some(eid) = rec
                    .remove("elicitation_id")
                    .and_then(|v| v.as_str().map(str::to_string))
                {
                    elicitations.insert(req.id().to_string(), eid);
                }
                rec.insert("upstream_calls".into(), json!(mock.drain_calls()));
                outcomes.push(Value::Object(rec.into_iter().collect()));
            }
            engine.shutdown().await;
            snapshot["requests"] = json!(outcomes);
        },
    }

    let keyspace = if needs_valkey {
        Some(valkey::export(valkey_url)?)
    } else {
        None
    };

    let _ = std::fs::remove_dir_all(&work);
    drop(mock);
    Ok(Replayed::Done {
        snapshot: scrub.apply(snapshot),
        keyspace,
    })
}

/// Replay every selected scenario through the engine and diff each against
/// its recorded snapshot under `<root>/snapshots`, then check the
/// differences against `<root>/intended-differences.yaml`. Nothing is
/// written. Returns the report and each scenario's status.
pub async fn check_parity(
    opts: &Options,
) -> Result<(parity::Report, Vec<(String, Status)>), String> {
    let renames = load_hook_renames(&opts.root)?;
    let intended = parity::load_intended(&opts.root)?;
    let mut differences = Vec::new();
    let mut statuses = Vec::new();
    let mut checked = Vec::new();
    for name in scenario_names(&opts.root)? {
        if !opts.only.is_empty() && !opts.only.contains(&name) {
            continue;
        }
        let snapshot = match replay(opts, &name, &Replay::default()).await? {
            Replayed::Skipped(why) => {
                statuses.push((name, Status::Skipped(why)));
                continue;
            },
            Replayed::Done { snapshot, .. } => snapshot,
        };
        // Round-trip through the snapshot text so both sides compare in the
        // same form.
        let current: Value = serde_json::from_str(&to_snapshot_string(snapshot))
            .map_err(|e| format!("{name}: {e}"))?;
        let path = opts.root.join("snapshots").join(format!("{name}.json"));
        let baseline: Value =
            serde_json::from_str(&read(&path)?).map_err(|e| format!("{}: {e}", path.display()))?;
        differences.extend(parity::diff_scenario(&name, &baseline, &current, &renames));
        checked.push(name.clone());
        statuses.push((name, Status::Written));
    }
    Ok((parity::check(differences, &intended, &checked), statuses))
}

/// The reviewed hook rename table at `<root>/hook-renames.yaml`.
pub fn load_hook_renames(root: &Path) -> Result<HookRenames, String> {
    let path = root.join(HOOK_RENAMES_FILE);
    serde_yaml::from_str(&read(&path)?).map_err(|e| format!("{}: {e}", path.display()))
}

async fn run_request(
    engine: &Engine,
    scenario: &Scenario,
    req: &Request,
    tokens: &BTreeMap<String, String>,
    elicitations: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, Value>, String> {
    let mut rec = BTreeMap::new();
    rec.insert("id".to_string(), json!(req.id()));
    match req {
        Request::Invoke(r) => {
            let stage = engine.invoke(r).await?;
            let allowed = stage["continue"].as_bool().unwrap_or(false);
            rec.insert("kind".into(), json!("invoke"));
            rec.insert(
                "decision".into(),
                json!(if allowed { "allow" } else { "deny" }),
            );
            rec.insert("code".into(), stage["violation"]["code"].clone());
            rec.insert("stages".into(), json!([stage]));
        },
        Request::Mediate(r) => {
            let token = |n: &String| {
                tokens
                    .get(n)
                    .cloned()
                    .ok_or_else(|| format!("{}: unknown token '{n}'", r.id))
            };
            let mut caller = ResolvedCaller {
                session: r.caller.session.clone(),
                ..Default::default()
            };
            caller.bearer = match (&r.caller.token, &r.caller.raw_token) {
                (Some(n), _) => Some(token(n)?),
                (None, Some(raw)) => Some(raw.clone()),
                (None, None) => None,
            };
            for (h, n) in &r.caller.credentials {
                caller.credentials.insert(h.clone(), token(n)?);
            }
            if let Some(prior) = &r.caller.resume {
                match elicitations.get(prior) {
                    Some(eid) => caller.elicitation_id = Some(eid.clone()),
                    None => {
                        // Recorded rather than fatal: a changed engine may
                        // stop suspending, and the snapshot should say so.
                        rec.insert("kind".into(), json!("mediate"));
                        rec.insert("decision".into(), json!("not_run"));
                        rec.insert(
                            "code".into(),
                            json!(format!("harness.no_pending_elicitation:{prior}")),
                        );
                        return Ok(rec);
                    },
                }
            }
            let out = engine
                .mediate(&scenario.hooks, &caller, &r.tool, &r.args, &r.backend)
                .await;
            rec.insert("kind".into(), json!("mediate"));
            rec.insert("decision".into(), json!(out.decision));
            rec.insert("code".into(), json!(out.code));
            rec.insert("result".into(), json!(out.result));
            rec.insert("stages".into(), json!(out.stages));
            if let Some(eid) = out.elicitation_id {
                rec.insert("elicitation_id".into(), json!(eid));
            }
        },
    }
    Ok(rec)
}

fn read(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))
}

fn write(path: &Path, body: &str) -> Result<(), String> {
    std::fs::write(path, body).map_err(|e| format!("{}: {e}", path.display()))
}
