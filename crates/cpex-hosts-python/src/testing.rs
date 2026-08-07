// Location: ./crates/cpex-hosts-python/src/testing.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Ted Habeck
//
// Test-only helpers. Compiled under `cfg(test)` for unit tests and behind the
// `testing` feature for the integration tests in `tests/`, which cannot see a
// `cfg(test)` module.
//
// The venv and worker tests need a scratch directory that cleans itself up.
// The workspace carries no temp-dir dependency, and adding one for this is not
// worth the supply-chain surface for ~40 lines.

use std::path::{Path, PathBuf};

/// A scratch directory removed when the value drops.
///
/// Names combine the process id with a monotonic counter, so concurrent test
/// threads (and concurrent `cargo test` invocations) never collide.
#[derive(Debug)]
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// Create a uniquely named directory under the system temp dir.
    pub fn new() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);

        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("cpex-hosts-python-{}-{unique}", std::process::id()));

        // A leftover directory from a killed run would otherwise leak state
        // into this one.
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create temp dir");

        Self { path }
    }

    /// The directory path.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Default for TempDir {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        // Best-effort: a failed cleanup must not mask the test's own failure.
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Whether a usable `python3` is on PATH.
///
/// The venv and end-to-end tests need a real interpreter. When one is absent
/// they skip rather than fail, so a developer machine without the Python side
/// stays green — while not pretending to have covered the path.
pub fn python3_available() -> bool {
    std::process::Command::new("python3")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Env var that turns every skip in these tests into a failure.
///
/// The tests below are `#[ignore]`d, so a default `cargo test` reports them as
/// *ignored* and never claims to have run them. The lane that does run them
/// (`make test-python-e2e`, and the `python-e2e` CI job) exists precisely
/// because the environment is supposed to be complete there — so a skip in that
/// lane is a broken lane, not an absent dependency, and must be loud.
pub const REQUIRE_ENV: &str = "CPEX_REQUIRE_PYTHON_E2E";

/// Whether skips must fail instead of returning `None`.
pub fn skips_are_failures() -> bool {
    std::env::var(REQUIRE_ENV).is_ok_and(|v| !v.is_empty() && v != "0")
}

/// Record a skip: print it, or panic when [`REQUIRE_ENV`] demands a real run.
///
/// Every skip path in `tests/` routes through here, so there is exactly one
/// place that decides whether an unmet prerequisite is tolerated. Returning
/// `()` keeps the call sites' `return`/`None` shape unchanged.
pub fn skip(test_name: &str, reason: &str) {
    assert!(
        !skips_are_failures(),
        "{test_name} cannot run and {REQUIRE_ENV} is set: {reason}\n\nThis lane is supposed to \
         have a complete Python end-to-end environment. Fix the environment (python3 on PATH, and \
         {SOURCE_ENV} pointing at a cpex Python checkout with \
         cpex/framework/isolated/worker.py) rather than unsetting {REQUIRE_ENV} — a silent skip \
         here reports coverage that does not exist."
    );
    println!("SKIP {test_name}: {reason}");
}

/// Skip the calling test when python3 is missing.
///
/// Rust has no first-class runtime skip, so this returns a bool the caller
/// early-returns on. Under [`REQUIRE_ENV`] it panics instead of returning
/// `true`, so the run cannot report "ok" without having executed.
#[must_use]
pub fn skip_without_python3(test_name: &str) -> bool {
    if python3_available() {
        return false;
    }
    skip(test_name, "python3 not found on PATH");
    true
}

/// Env var naming a checkout of the `cpex` Python package for the e2e tests.
pub const SOURCE_ENV: &str = "CPEX_PYTHON_SOURCE";

/// Locate a `cpex` Python source tree, or explain why there is none.
///
/// The Python framework lives on a different branch than this Rust host, and
/// the published PyPI package is behind it (its `worker.py` predates the
/// credential field). So the e2e tests install from a local checkout: set
/// `CPEX_PYTHON_SOURCE`, or keep a sibling checkout.
pub fn python_source() -> Result<PathBuf, String> {
    if let Ok(explicit) = std::env::var(SOURCE_ENV) {
        let path = PathBuf::from(&explicit);
        if path.join("pyproject.toml").is_file() {
            return Ok(path);
        }
        return Err(format!("{SOURCE_ENV}={explicit} has no pyproject.toml"));
    }

    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or("could not locate the repository root")?;

    [
        repo_root.join("cpex-python"),
        repo_root.join("../cpex-python"),
        repo_root.to_path_buf(),
    ]
    .iter()
    .find(|p| {
        p.join("pyproject.toml").is_file() && p.join("cpex/framework/isolated/worker.py").is_file()
    })
    .cloned()
    .ok_or_else(|| {
        format!(
            "no cpex Python source tree found — set {SOURCE_ENV} to a checkout of the Python side \
             (the branch carrying cpex/framework/isolated/worker.py)"
        )
    })
}

/// Whether a framework checkout's worker consumes the `credential` field.
///
/// The credential path needs a `worker.py` that reads the DTO and repopulates
/// the redacted `SecretStr`. An older worker silently drops the field, so a
/// credential test should skip with a precise reason rather than fail.
pub fn worker_consumes_credentials(source: &Path) -> bool {
    std::fs::read_to_string(source.join("cpex/framework/isolated/worker.py"))
        .map(|s| s.contains("reconstruct_credential_payload") && s.contains("CREDENTIAL_FIELD"))
        .unwrap_or(false)
}

/// Whether a framework checkout's worker delivers the `extensions` field.
///
/// The extensions channel needs a `worker.py` that reads the task's
/// `extensions` field, reconstructs a Python `Extensions`, and passes it as
/// `extensions=` to `execute_plugin`. A worker predating that change calls
/// `execute_plugin` without the argument, so every hook sees `extensions=None`
/// and an extensions test would fail for the wrong reason. Gate on the field
/// name and the keyword argument together — the name alone appears in
/// unrelated comments.
pub fn worker_delivers_extensions(source: &Path) -> bool {
    std::fs::read_to_string(source.join("cpex/framework/isolated/worker.py"))
        .map(|s| s.contains("EXTENSIONS_FIELD") && s.contains("extensions="))
        .unwrap_or(false)
}

/// Lay out a plugin package under `<dir>/plugins/<package>`.
///
/// Writes `__init__.py`, the plugin module, and a `requirements.txt` pointing
/// at the local framework checkout — so the venv gets *that* `worker.py` rather
/// than whatever version PyPI currently serves. Returns the plugin dir.
pub fn scaffold_plugin(
    dir: &TempDir,
    source: &Path,
    package: &str,
    module: &str,
    plugin_source: &str,
) -> PathBuf {
    let plugin_dir = dir.path().join("plugins");
    let package_dir = plugin_dir.join(package);
    std::fs::create_dir_all(&package_dir).expect("create package dir");

    std::fs::write(package_dir.join("__init__.py"), "").expect("write __init__.py");
    std::fs::write(package_dir.join(format!("{module}.py")), plugin_source)
        .expect("write plugin module");
    std::fs::write(
        package_dir.join("requirements.txt"),
        format!("{}\n", source.display()),
    )
    .expect("write requirements.txt");

    plugin_dir
}

/// Pre-build a plugin's venv and write the cache metadata that makes the host
/// reuse it.
///
/// # Why the test builds the venv instead of letting the host do it
///
/// The Python framework's declared dependencies currently have no satisfiable
/// resolution: `pyproject.toml` requires `mcp>=1.26`, but
/// `cpex.framework.__init__` imports its MCP client, which does
/// `from mcp import McpError` — a symbol mcp renamed to `MCPError` in 1.26. A
/// clean install therefore pulls an mcp whose API the framework cannot import,
/// and the worker dies with an `ImportError` before reading a task. Adding
/// `mcp<1.26` to the requirements file instead makes pip fail outright with
/// `ResolutionImpossible`, because that contradicts the framework's own floor.
///
/// The only combination that runs is "install as declared, then downgrade mcp"
/// — two sequential pip passes. The venv manager issues one `pip install -r`,
/// which is correct for a working package; contorting production code around a
/// contradictory upstream manifest would be the wrong fix, and the Python
/// framework is out of scope here. So the test arranges the venv and the host
/// then finds it cached, which exercises a real host path
/// (`CacheVerdict::Valid` → reuse) rather than bypassing one.
///
/// Returns `Err` with a printable reason when the venv cannot be built.
pub fn prebuild_venv(
    plugin_dir: &Path,
    source: &Path,
    class_name: &str,
    package: &str,
) -> Result<(), String> {
    let venv = crate::venv::VenvManager::new(
        &[plugin_dir.display().to_string()],
        class_name,
        Some("requirements.txt"),
        Some("1.0.0"),
    )
    .map_err(|e| format!("could not resolve the venv layout: {e}"))?;

    let layout = venv.layout();
    std::fs::create_dir_all(&layout.cache_dir).map_err(|e| e.to_string())?;

    let run = |program: &Path, args: &[&std::ffi::OsStr]| -> Result<(), String> {
        let output = std::process::Command::new(program)
            .args(args)
            .output()
            .map_err(|e| format!("could not run {}: {e}", program.display()))?;
        if output.status.success() {
            return Ok(());
        }
        Err(format!(
            "{} exited {}: {}",
            program.display(),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    };

    run(
        Path::new("python3"),
        &["-m".as_ref(), "venv".as_ref(), layout.venv_path.as_os_str()],
    )?;

    let python = layout.python_executable();
    // Pass 1: the framework as declared, with its full transitive tree.
    run(
        &python,
        &[
            "-m".as_ref(),
            "pip".as_ref(),
            "install".as_ref(),
            "-q".as_ref(),
            source.as_os_str(),
        ],
    )?;
    // Pass 2: downgrade mcp to a version whose API the framework can import.
    // pip warns about the deliberate conflict; that warning is expected.
    run(
        &python,
        &[
            "-m".as_ref(),
            "pip".as_ref(),
            "install".as_ref(),
            "-q".as_ref(),
            "mcp<1.26".as_ref(),
        ],
    )?;

    // Metadata matching what the host computes, so its cache check says Valid
    // and `initialize()` skips the (unsatisfiable) reinstall.
    let requirements = plugin_dir.join(package).join("requirements.txt");
    let metadata = serde_json::json!({
        "venv_path": layout.venv_path.display().to_string(),
        "requirements_file": requirements.display().to_string(),
        "requirements_hash": crate::venv::hash_file_or_empty(Some(&requirements)),
        "manifest_version": "1.0.0",
        // No manifest file on disk — the empty-content digest, matching what
        // the host computes for an absent manifest.
        "manifest_hash": crate::venv::hash_file_or_empty(None),
    });
    std::fs::write(
        &layout.metadata_path,
        serde_json::to_string_pretty(&metadata).unwrap(),
    )
    .map_err(|e| e.to_string())?;

    if !venv.cache_verdict().is_valid() {
        return Err(format!(
            "the pre-built venv is not recognized as cached ({:?}) — the metadata written here \
             disagrees with what the host computes",
            venv.cache_verdict()
        ));
    }
    Ok(())
}
