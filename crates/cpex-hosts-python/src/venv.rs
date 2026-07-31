// Location: ./crates/cpex-hosts-python/src/venv.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Ted Habeck
//
// Venv manager — builds, caches, and reuses a per-plugin virtualenv.
//
// Ported from `cpex/framework/isolated/client.py` (`create_venv`,
// `_is_venv_cache_valid`, `_save_cache_metadata`, `_manifest_path`). The
// layout is deliberately identical to the Python CLI's so a venv built by
// either side is reusable by the other: `.venv` under the plugin's class-root
// directory, cache metadata under `.cpex/venv_cache`.
//
// # Cache validity
//
// Reuse is keyed on a SHA256 of the requirements file plus the persisted
// manifest's version and content hash. Requirements alone is not enough: a
// plugin installed by FQN conversion has no requirements file, so its
// requirements hash is a constant and the manifest signals are the only way
// to notice it changed.
//
// The manifest signals are read as *optional*. Metadata written by an older
// CLI has no `manifest_version` / `manifest_hash` keys, and reading an absent
// key as `None` and comparing it against a real value would treat every
// pre-existing install as a mismatch — wiping and rebuilding every venv on
// the first run after an upgrade. An absent key therefore means "no signal"
// and is skipped; only a key that is present *and* differs invalidates.
//
// # Blocking work
//
// `initialize()` is awaited sequentially by the manager, so a multi-minute
// pip install on the runtime thread would stall every other plugin's init
// and the rollback path with it. Subprocesses go through `tokio::process`
// and synchronous filesystem work through `spawn_blocking`.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::HostError;

/// Cache metadata persisted next to each venv.
///
/// Field names match what `client.py`'s `_save_cache_metadata` writes, so
/// metadata is interchangeable between the two implementations.
///
/// `manifest_version` and `manifest_hash` are `Option` to distinguish
/// "absent" (older metadata, no signal) from "present and different"
/// (a real change). That distinction is the whole point — see the module
/// docs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheMetadata {
    /// Absolute path of the venv this metadata describes.
    pub venv_path: String,

    /// Absolute path of the requirements file, when there was one.
    #[serde(default)]
    pub requirements_file: Option<String>,

    /// SHA256 of the requirements file content (empty-content digest when
    /// there is no file).
    pub requirements_hash: String,

    /// Manifest version at install time. Absent in metadata written before
    /// this signal existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_version: Option<String>,

    /// SHA256 of the persisted manifest content. Absent in older metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_hash: Option<String>,

    /// Interpreter version the venv was built with, for diagnostics.
    #[serde(default)]
    pub python_version: Option<String>,
}

/// Why a cached venv was rejected. Carried rather than logged-and-dropped so
/// tests can pin the specific rule that fired and operators get a precise
/// reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheVerdict {
    /// The cache is usable as-is.
    Valid,
    /// The venv directory does not exist.
    VenvMissing,
    /// No metadata file sits alongside the venv.
    MetadataMissing,
    /// The metadata file could not be parsed.
    MetadataUnreadable,
    /// The requirements file content changed.
    RequirementsChanged,
    /// The manifest version changed (signal present in metadata).
    ManifestVersionChanged,
    /// The manifest content changed (signal present in metadata).
    ManifestHashChanged,
}

impl CacheVerdict {
    /// Whether the cached venv can be reused without a rebuild.
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid)
    }
}

/// SHA256 of a file's bytes, hex-encoded.
///
/// An absent or unreadable path hashes to the empty-content digest, matching
/// `client.py`'s `_compute_requirements_hash`: a plugin with no requirements
/// file gets a stable constant rather than an error, so the manifest signals
/// carry the change detection instead.
pub fn hash_file_or_empty(path: Option<&Path>) -> String {
    let mut hasher = Sha256::new();
    match path {
        Some(p) => match std::fs::read(p) {
            Ok(bytes) => hasher.update(&bytes),
            Err(_) => hasher.update(b""),
        },
        None => hasher.update(b""),
    }
    format!("{:x}", hasher.finalize())
}

/// Filesystem-safe stem for a fully-qualified class name.
///
/// Sanitization must match the Python side's `manifest_filename_for_class`
/// byte for byte: non-alphanumerics (other than `-` and `_`) become `-`,
/// leading and trailing `-` are stripped, and an empty result degrades to
/// `plugin` rather than producing a dotfile.
fn manifest_stem_for_class(class_name: &str) -> String {
    let safe: String = class_name
        .trim()
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let safe = safe.trim_matches('-');
    if safe.is_empty() {
        "plugin".to_string()
    } else {
        safe.to_string()
    }
}

/// Per-plugin manifest filename for a fully-qualified class name.
///
/// Plugins that share a package share one venv directory (it is keyed on the
/// class root), but each needs its own manifest file: if `pkg.a.PluginA` and
/// `pkg.b.PluginB` shared one, installing either would change the other's
/// manifest hash and both would rebuild forever.
///
/// Must produce byte-identical output to the Python side's
/// `manifest_filename_for_class` — both implementations resolve the same path,
/// and a divergence means each sees the other's install as a change.
pub fn manifest_filename_for_class(class_name: &str) -> String {
    format!(
        "{}.plugin-manifest.yaml",
        manifest_stem_for_class(class_name)
    )
}

/// Decide whether a cached venv can be reused.
///
/// `expected_manifest_version` and `expected_manifest_hash` are what the
/// plugin declares *now*; the metadata carries what was true at install
/// time. A metadata signal that is absent is skipped rather than compared —
/// see the module docs for why that asymmetry matters.
pub fn evaluate_cache(
    venv_path: &Path,
    metadata_path: &Path,
    expected_requirements_hash: &str,
    expected_manifest_version: Option<&str>,
    expected_manifest_hash: Option<&str>,
) -> CacheVerdict {
    if !venv_path.exists() {
        return CacheVerdict::VenvMissing;
    }
    if !metadata_path.exists() {
        return CacheVerdict::MetadataMissing;
    }

    let Ok(raw) = std::fs::read_to_string(metadata_path) else {
        return CacheVerdict::MetadataUnreadable;
    };
    let Ok(metadata) = serde_json::from_str::<CacheMetadata>(&raw) else {
        return CacheVerdict::MetadataUnreadable;
    };

    if metadata.requirements_hash != expected_requirements_hash {
        return CacheVerdict::RequirementsChanged;
    }

    // Present-and-different invalidates; absent is "no signal" and skipped.
    if let Some(cached) = metadata.manifest_version.as_deref() {
        if Some(cached) != expected_manifest_version {
            return CacheVerdict::ManifestVersionChanged;
        }
    }
    if let Some(cached) = metadata.manifest_hash.as_deref() {
        if Some(cached) != expected_manifest_hash {
            return CacheVerdict::ManifestHashChanged;
        }
    }

    CacheVerdict::Valid
}

/// Resolved on-disk layout for one plugin's venv.
///
/// The class *root* (the first dotted segment of the class name) names the
/// directory, which is what makes plugins in one package share a venv.
#[derive(Debug, Clone)]
pub struct VenvLayout {
    /// Directory holding the venv and its cache — `<plugin_dir>/<class_root>`.
    pub plugin_path: PathBuf,
    /// The virtualenv itself.
    pub venv_path: PathBuf,
    /// Cache-metadata directory.
    pub cache_dir: PathBuf,
    /// This plugin's metadata file within `cache_dir`.
    pub metadata_path: PathBuf,
    /// This plugin's persisted manifest.
    pub manifest_path: PathBuf,
}

impl VenvLayout {
    /// Resolve the layout for a class name under the first configured plugin
    /// dir, mirroring `client.py`'s `__init__`.
    pub fn resolve(plugin_dirs: &[String], class_name: &str) -> Result<Self, HostError> {
        // The host supplies `<project root>/plugins`, so an empty list here is
        // an internal error rather than a misconfiguration — the message avoids
        // naming a config key an operator could set, because there isn't one.
        let first = plugin_dirs.first().ok_or_else(|| HostError::Config {
            message: "isolated_venv requires at least one plugin directory — \
                      the venv is built under the first one"
                .into(),
        })?;

        let class_root = class_name.split('.').next().unwrap_or(class_name);
        if class_root.is_empty() {
            return Err(HostError::Config {
                message: format!("`class_name` '{class_name}' has no leading package segment"),
            });
        }

        let plugin_path = Path::new(first).join(class_root);
        let venv_path = plugin_path.join(".venv");
        let cache_dir = plugin_path.join(".cpex").join("venv_cache");

        // Both filenames are keyed on the full class name.
        //
        // This diverges from `client.py`, which keys the *metadata* filename on
        // the venv directory name (`_get_cache_metadata_path` reads
        // `Path(venv_path).name`, always `.venv`) while keying the *manifest*
        // per class. Since plugins in one package deliberately share a venv
        // directory, that gives them one shared `.venv_metadata.json`: each
        // install overwrites the other's `requirements_hash` and
        // `manifest_hash`, so each plugin's build invalidates its neighbour's
        // cache and the two rebuild in a loop — the exact thrash the per-class
        // manifest naming exists to prevent, left half-solved.
        //
        // Keying both on the class name closes it. The cost is that a venv
        // built by the Python CLI is not recognized as cached by this host on
        // first run (its metadata sits under the other filename), so the host
        // rebuilds once and is a cache hit forever after. That one-time
        // rebuild is strictly better than a permanent rebuild loop.
        let metadata_path = cache_dir.join(format!(
            "{}_metadata.json",
            manifest_stem_for_class(class_name)
        ));
        let manifest_path = plugin_path.join(manifest_filename_for_class(class_name));

        Ok(Self {
            plugin_path,
            venv_path,
            cache_dir,
            metadata_path,
            manifest_path,
        })
    }

    /// The venv's own Python interpreter.
    pub fn python_executable(&self) -> PathBuf {
        if cfg!(windows) {
            self.venv_path.join("Scripts").join("python.exe")
        } else {
            self.venv_path.join("bin").join("python")
        }
    }
}

/// Outcome of a `VenvManager::ensure` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnsureOutcome {
    /// The cached venv was reused — no rebuild, no reinstall.
    Reused,
    /// The venv was created (or recreated) and requirements installed.
    Built {
        /// Whether a requirements install actually ran. False when the plugin
        /// has no requirements file — the venv is still fresh.
        installed_requirements: bool,
    },
}

/// Builds and caches one plugin's virtualenv.
///
/// Construction is cheap and does no I/O; `ensure()` does the work and is
/// called from the plugin's `initialize()`.
#[derive(Debug, Clone)]
pub struct VenvManager {
    layout: VenvLayout,
    /// Absolute path of the requirements file, when the plugin has one and it
    /// exists on disk.
    requirements_file: Option<PathBuf>,
    /// Manifest version the plugin declares now, if any.
    manifest_version: Option<String>,
}

impl VenvManager {
    /// Resolve the layout for a plugin and record its cache inputs.
    ///
    /// `requirements_file` is interpreted relative to the resolved plugin
    /// path when it is not already absolute, mirroring `client.py`'s
    /// `package_path / requirements_file_input`.
    pub fn new(
        plugin_dirs: &[String],
        class_name: &str,
        requirements_file: Option<&str>,
        manifest_version: Option<&str>,
    ) -> Result<Self, HostError> {
        let layout = VenvLayout::resolve(plugin_dirs, class_name)?;

        let requirements_file = requirements_file.map(|rel| {
            let path = Path::new(rel);
            if path.is_absolute() {
                path.to_path_buf()
            } else {
                layout.plugin_path.join(path)
            }
        });

        Ok(Self {
            layout,
            requirements_file,
            manifest_version: manifest_version.map(str::to_string),
        })
    }

    /// The resolved on-disk layout.
    pub fn layout(&self) -> &VenvLayout {
        &self.layout
    }

    /// The venv's interpreter, for launching the worker.
    pub fn python_executable(&self) -> PathBuf {
        self.layout.python_executable()
    }

    /// Whether the cached venv is currently reusable, and why not if it isn't.
    pub fn cache_verdict(&self) -> CacheVerdict {
        evaluate_cache(
            &self.layout.venv_path,
            &self.layout.metadata_path,
            &hash_file_or_empty(self.requirements_file.as_deref()),
            self.manifest_version.as_deref(),
            Some(&hash_file_or_empty(Some(&self.layout.manifest_path))),
        )
    }

    /// Ensure a usable venv exists, building and installing only when the
    /// cache says it must.
    ///
    /// All blocking work is moved off the runtime thread: the manager awaits
    /// each plugin's `initialize()` sequentially, so a cold pip install run
    /// inline would stall every other plugin's init and the rollback path.
    pub async fn ensure(&self) -> Result<EnsureOutcome, HostError> {
        let verdict = self.cache_verdict();
        if verdict.is_valid() {
            tracing::info!(venv = %self.layout.venv_path.display(), "reusing cached venv");
            return Ok(EnsureOutcome::Reused);
        }

        tracing::info!(
            venv = %self.layout.venv_path.display(),
            reason = ?verdict,
            "building venv"
        );

        self.prepare_directories().await?;
        self.create_venv().await?;

        let installed_requirements = self.install_requirements().await?;
        self.save_metadata().await?;

        Ok(EnsureOutcome::Built {
            installed_requirements,
        })
    }

    /// Create the cache directory and clear any stale venv.
    async fn prepare_directories(&self) -> Result<(), HostError> {
        let venv_path = self.layout.venv_path.clone();
        let cache_dir = self.layout.cache_dir.clone();
        let plugin_path = self.layout.plugin_path.clone();

        tokio::task::spawn_blocking(move || {
            std::fs::create_dir_all(&plugin_path).map_err(|e| HostError::VenvBuild {
                message: format!("could not create plugin dir {}: {e}", plugin_path.display()),
            })?;
            std::fs::create_dir_all(&cache_dir).map_err(|e| HostError::VenvBuild {
                message: format!("could not create cache dir {}: {e}", cache_dir.display()),
            })?;

            // An invalid cache means the venv contents cannot be trusted;
            // client.py rmtree's before rebuilding rather than upgrading in
            // place, so a removed dependency actually disappears.
            if venv_path.exists() {
                std::fs::remove_dir_all(&venv_path).map_err(|e| HostError::VenvBuild {
                    message: format!("could not remove stale venv {}: {e}", venv_path.display()),
                })?;
            }
            Ok(())
        })
        .await
        .map_err(|e| HostError::VenvBuild {
            message: format!("venv directory preparation panicked: {e}"),
        })?
    }

    /// Run `python3 -m venv --system-site-packages=false` on the venv path.
    ///
    /// `client.py` uses `venv.EnvBuilder(with_pip=True, symlinks=True)`; the
    /// CLI equivalent is `python3 -m venv` with pip left enabled.
    async fn create_venv(&self) -> Result<(), HostError> {
        let output = tokio::process::Command::new("python3")
            .arg("-m")
            .arg("venv")
            .arg(&self.layout.venv_path)
            .output()
            .await
            .map_err(|e| HostError::VenvBuild {
                message: format!("could not run `python3 -m venv`: {e} (is python3 on PATH?)"),
            })?;

        if !output.status.success() {
            return Err(HostError::VenvBuild {
                message: format!(
                    "`python3 -m venv {}` exited {}: {}",
                    self.layout.venv_path.display(),
                    output.status,
                    String::from_utf8_lossy(&output.stderr).trim()
                ),
            });
        }
        Ok(())
    }

    /// Install the plugin's requirements into the venv.
    ///
    /// Returns whether an install ran. A plugin with no requirements file is
    /// not an error: an FQN-converted plugin gets its package from the install
    /// channel instead, and installing requirements transitively brings in the
    /// `cpex` framework (and with it `worker.py`).
    async fn install_requirements(&self) -> Result<bool, HostError> {
        let Some(requirements) = self.requirements_file.as_ref().filter(|p| p.exists()) else {
            tracing::info!("no requirements file; skipping install");
            return Ok(false);
        };

        let python = self.python_executable();
        let output = tokio::process::Command::new(&python)
            .args(["-m", "pip", "install", "-r"])
            .arg(requirements)
            .output()
            .await
            .map_err(|e| HostError::VenvBuild {
                message: format!("could not run pip in {}: {e}", python.display()),
            })?;

        if !output.status.success() {
            return Err(HostError::VenvBuild {
                message: format!(
                    "pip install -r {} exited {}: {}",
                    requirements.display(),
                    output.status,
                    String::from_utf8_lossy(&output.stderr).trim()
                ),
            });
        }
        Ok(true)
    }

    /// Persist the cache metadata that makes the next run a cache hit.
    async fn save_metadata(&self) -> Result<(), HostError> {
        let metadata = CacheMetadata {
            venv_path: self.layout.venv_path.display().to_string(),
            requirements_file: self
                .requirements_file
                .as_ref()
                .filter(|p| p.exists())
                .map(|p| p.display().to_string()),
            requirements_hash: hash_file_or_empty(self.requirements_file.as_deref()),
            manifest_version: self.manifest_version.clone(),
            manifest_hash: Some(hash_file_or_empty(Some(&self.layout.manifest_path))),
            python_version: None,
        };

        let path = self.layout.metadata_path.clone();
        let json = serde_json::to_string_pretty(&metadata).map_err(|e| HostError::VenvBuild {
            message: format!("could not serialize cache metadata: {e}"),
        })?;

        tokio::task::spawn_blocking(move || {
            std::fs::write(&path, json).map_err(|e| HostError::VenvBuild {
                message: format!("could not write cache metadata {}: {e}", path.display()),
            })
        })
        .await
        .map_err(|e| HostError::VenvBuild {
            message: format!("cache metadata write panicked: {e}"),
        })?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::TempDir;

    /// Empty-content SHA256 — what a plugin with no requirements file hashes
    /// to, so it appears in most of these fixtures.
    const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    /// Lay down a venv dir plus a metadata file, and return both paths.
    fn scaffold(dir: &TempDir, metadata: &str) -> (PathBuf, PathBuf) {
        let venv = dir.path().join(".venv");
        std::fs::create_dir_all(&venv).unwrap();
        let metadata_path = dir.path().join("metadata.json");
        std::fs::write(&metadata_path, metadata).unwrap();
        (venv, metadata_path)
    }

    fn metadata_json(
        requirements_hash: &str,
        version: Option<&str>,
        manifest_hash: Option<&str>,
    ) -> String {
        let mut obj = serde_json::json!({
            "venv_path": "/tmp/.venv",
            "requirements_file": null,
            "requirements_hash": requirements_hash,
            "python_version": "3.12.1",
        });
        if let Some(v) = version {
            obj["manifest_version"] = serde_json::json!(v);
        }
        if let Some(h) = manifest_hash {
            obj["manifest_hash"] = serde_json::json!(h);
        }
        serde_json::to_string(&obj).unwrap()
    }

    // --- hashing ------------------------------------------------------------

    #[test]
    fn absent_requirements_file_hashes_to_the_empty_digest() {
        // client.py hashes b"" for both "no file configured" and "configured
        // but not on disk", so both reuse a venv rather than erroring.
        assert_eq!(hash_file_or_empty(None), EMPTY_SHA256);
        assert_eq!(
            hash_file_or_empty(Some(Path::new("/nonexistent/requirements.txt"))),
            EMPTY_SHA256
        );
    }

    #[test]
    fn requirements_hash_tracks_content_not_path() {
        let dir = TempDir::new();
        let a = dir.path().join("a.txt");
        let b = dir.path().join("b.txt");
        std::fs::write(&a, "requests==2.31.0\n").unwrap();
        std::fs::write(&b, "requests==2.31.0\n").unwrap();
        assert_eq!(hash_file_or_empty(Some(&a)), hash_file_or_empty(Some(&b)));

        std::fs::write(&b, "requests==2.32.0\n").unwrap();
        assert_ne!(hash_file_or_empty(Some(&a)), hash_file_or_empty(Some(&b)));
    }

    // --- manifest filename (contract with the Python side) ------------------

    #[test]
    fn manifest_filename_matches_the_python_sanitization_rule() {
        // Byte-for-byte agreement with utils.manifest_filename_for_class:
        // dots become dashes, alphanumerics and -_ survive.
        assert_eq!(
            manifest_filename_for_class("pkg.module.ClassName"),
            "pkg-module-ClassName.plugin-manifest.yaml"
        );
        assert_eq!(
            manifest_filename_for_class("my_pkg.filters.PiiFilter"),
            "my_pkg-filters-PiiFilter.plugin-manifest.yaml"
        );
        // Leading/trailing separators are stripped, and an all-separator name
        // degrades to "plugin" rather than producing a dotfile.
        assert_eq!(
            manifest_filename_for_class("  .A.  "),
            "A.plugin-manifest.yaml"
        );
        assert_eq!(
            manifest_filename_for_class("..."),
            "plugin.plugin-manifest.yaml"
        );
    }

    #[test]
    fn plugins_sharing_a_package_get_distinct_manifest_filenames() {
        // The anti-thrash guarantee: one shared venv dir, one manifest each.
        assert_ne!(
            manifest_filename_for_class("pkg.a.PluginA"),
            manifest_filename_for_class("pkg.b.PluginB")
        );
    }

    // --- cache validity -----------------------------------------------------

    #[test]
    fn valid_when_every_present_signal_agrees() {
        let dir = TempDir::new();
        let (venv, meta) = scaffold(
            &dir,
            &metadata_json(EMPTY_SHA256, Some("1.0.0"), Some("abc123")),
        );

        assert_eq!(
            evaluate_cache(&venv, &meta, EMPTY_SHA256, Some("1.0.0"), Some("abc123")),
            CacheVerdict::Valid
        );
    }

    #[test]
    fn invalid_when_the_venv_directory_is_gone() {
        let dir = TempDir::new();
        let meta = dir.path().join("metadata.json");
        std::fs::write(&meta, metadata_json(EMPTY_SHA256, None, None)).unwrap();

        assert_eq!(
            evaluate_cache(&dir.path().join(".venv"), &meta, EMPTY_SHA256, None, None),
            CacheVerdict::VenvMissing
        );
    }

    #[test]
    fn invalid_when_metadata_is_absent() {
        let dir = TempDir::new();
        let venv = dir.path().join(".venv");
        std::fs::create_dir_all(&venv).unwrap();

        assert_eq!(
            evaluate_cache(
                &venv,
                &dir.path().join("missing.json"),
                EMPTY_SHA256,
                None,
                None
            ),
            CacheVerdict::MetadataMissing
        );
    }

    #[test]
    fn invalid_when_metadata_will_not_parse() {
        // client.py catches JSONDecodeError and returns False — a corrupt
        // metadata file rebuilds rather than propagating.
        let dir = TempDir::new();
        let (venv, meta) = scaffold(&dir, "{ this is not json");

        assert_eq!(
            evaluate_cache(&venv, &meta, EMPTY_SHA256, None, None),
            CacheVerdict::MetadataUnreadable
        );
    }

    #[test]
    fn changed_requirements_hash_invalidates() {
        let dir = TempDir::new();
        let (venv, meta) = scaffold(
            &dir,
            &metadata_json("old-hash", Some("1.0.0"), Some("abc123")),
        );

        assert_eq!(
            evaluate_cache(&venv, &meta, "new-hash", Some("1.0.0"), Some("abc123")),
            CacheVerdict::RequirementsChanged
        );
    }

    #[test]
    fn changed_manifest_version_invalidates_when_the_signal_is_present() {
        let dir = TempDir::new();
        let (venv, meta) = scaffold(
            &dir,
            &metadata_json(EMPTY_SHA256, Some("1.0.0"), Some("abc123")),
        );

        assert_eq!(
            evaluate_cache(&venv, &meta, EMPTY_SHA256, Some("2.0.0"), Some("abc123")),
            CacheVerdict::ManifestVersionChanged
        );
    }

    #[test]
    fn changed_manifest_hash_invalidates_when_the_signal_is_present() {
        let dir = TempDir::new();
        let (venv, meta) = scaffold(
            &dir,
            &metadata_json(EMPTY_SHA256, Some("1.0.0"), Some("abc123")),
        );

        assert_eq!(
            evaluate_cache(&venv, &meta, EMPTY_SHA256, Some("1.0.0"), Some("def456")),
            CacheVerdict::ManifestHashChanged
        );
    }

    #[test]
    fn absent_manifest_signals_do_not_invalidate() {
        // THE upgrade-safety rule. Metadata written by an older CLI carries
        // neither manifest key. Reading absent-as-None and comparing against a
        // live value would report a mismatch and wipe every existing venv on
        // the first run after upgrading the host.
        let dir = TempDir::new();
        let (venv, meta) = scaffold(&dir, &metadata_json(EMPTY_SHA256, None, None));

        assert_eq!(
            evaluate_cache(&venv, &meta, EMPTY_SHA256, Some("1.0.0"), Some("abc123")),
            CacheVerdict::Valid,
            "absent manifest signals mean 'no signal', not 'mismatch'"
        );
    }

    #[test]
    fn each_manifest_signal_is_evaluated_independently() {
        // Half-populated metadata is real: only the key that is present gets
        // compared, so a version-only record still catches a version bump and
        // still ignores the hash.
        let dir = TempDir::new();
        let (venv, meta) = scaffold(&dir, &metadata_json(EMPTY_SHA256, Some("1.0.0"), None));

        assert_eq!(
            evaluate_cache(&venv, &meta, EMPTY_SHA256, Some("1.0.0"), Some("any-hash")),
            CacheVerdict::Valid,
            "an absent manifest_hash is skipped even when manifest_version is present"
        );
        assert_eq!(
            evaluate_cache(&venv, &meta, EMPTY_SHA256, Some("9.9.9"), Some("any-hash")),
            CacheVerdict::ManifestVersionChanged,
            "the present signal is still enforced"
        );
    }

    #[test]
    fn a_present_signal_against_an_unknown_expected_value_invalidates() {
        // The converse of the upgrade rule: metadata that recorded a version
        // while the plugin now declares none is a real change, not "no signal".
        let dir = TempDir::new();
        let (venv, meta) = scaffold(&dir, &metadata_json(EMPTY_SHA256, Some("1.0.0"), None));

        assert_eq!(
            evaluate_cache(&venv, &meta, EMPTY_SHA256, None, None),
            CacheVerdict::ManifestVersionChanged
        );
    }

    #[test]
    fn requirements_are_checked_before_manifest_signals() {
        // Ordering matters for the reported reason: client.py compares the
        // requirements hash first, so a config that changed both should
        // attribute the rebuild to requirements.
        let dir = TempDir::new();
        let (venv, meta) = scaffold(&dir, &metadata_json("old", Some("1.0.0"), Some("abc")));

        assert_eq!(
            evaluate_cache(&venv, &meta, "new", Some("2.0.0"), Some("def")),
            CacheVerdict::RequirementsChanged
        );
    }

    #[test]
    fn metadata_round_trips_without_inventing_manifest_keys() {
        // Serializing must not write `manifest_version: null` — the Python
        // side reads key *presence* as the signal, so a null key would turn
        // "no signal" into a permanent mismatch.
        let metadata = CacheMetadata {
            venv_path: "/tmp/x/.venv".into(),
            requirements_file: None,
            requirements_hash: EMPTY_SHA256.into(),
            manifest_version: None,
            manifest_hash: None,
            python_version: Some("3.12.1".into()),
        };
        let json = serde_json::to_string(&metadata).unwrap();
        assert!(
            !json.contains("manifest_version"),
            "absent signals must stay absent: {json}"
        );
        assert!(!json.contains("manifest_hash"));

        let parsed: CacheMetadata = serde_json::from_str(&json).unwrap();
        assert!(parsed.manifest_version.is_none());
    }

    // --- layout -------------------------------------------------------------

    #[test]
    fn layout_is_keyed_on_the_class_root_so_a_package_shares_one_venv() {
        let dirs = vec!["/plugins".to_string()];
        let a = VenvLayout::resolve(&dirs, "pkg.a.PluginA").unwrap();
        let b = VenvLayout::resolve(&dirs, "pkg.b.PluginB").unwrap();

        assert_eq!(a.venv_path, PathBuf::from("/plugins/pkg/.venv"));
        assert_eq!(a.venv_path, b.venv_path, "one venv per package root");
        assert_eq!(a.cache_dir, PathBuf::from("/plugins/pkg/.cpex/venv_cache"));

        // ...but distinct manifests, so neither install invalidates the other.
        assert_ne!(a.manifest_path, b.manifest_path);
    }

    #[test]
    fn layout_uses_the_first_plugin_dir() {
        let dirs = vec!["/first".to_string(), "/second".to_string()];
        let layout = VenvLayout::resolve(&dirs, "pkg.Plugin").unwrap();
        assert_eq!(layout.plugin_path, PathBuf::from("/first/pkg"));
    }

    #[test]
    fn layout_requires_at_least_one_plugin_dir() {
        let err = VenvLayout::resolve(&[], "pkg.Plugin").unwrap_err();
        assert!(matches!(err, HostError::Config { .. }));
        assert!(
            err.to_string().contains("plugin directory"),
            "the message should explain what is missing: {err}"
        );
    }

    #[test]
    fn metadata_filename_is_keyed_on_the_full_class_name() {
        // Deliberately unlike client.py, which keys this on the venv directory
        // name and so hands every plugin in a shared package the same file.
        // See the comment in `VenvLayout::resolve`.
        let layout = VenvLayout::resolve(&["/plugins".to_string()], "pkg.Plugin").unwrap();
        assert_eq!(
            layout.metadata_path,
            PathBuf::from("/plugins/pkg/.cpex/venv_cache/pkg-Plugin_metadata.json")
        );
    }

    #[test]
    fn plugins_sharing_a_package_get_distinct_metadata_files() {
        // The other half of the anti-thrash guarantee. A shared metadata file
        // would let each plugin's build overwrite the other's requirements and
        // manifest hashes, invalidating it on the next run — forever.
        let dirs = vec!["/plugins".to_string()];
        let a = VenvLayout::resolve(&dirs, "pkg.a.PluginA").unwrap();
        let b = VenvLayout::resolve(&dirs, "pkg.b.PluginB").unwrap();
        assert_eq!(a.venv_path, b.venv_path, "still one shared venv");
        assert_ne!(a.metadata_path, b.metadata_path);
    }

    #[test]
    fn python_executable_sits_inside_the_venv() {
        let layout = VenvLayout::resolve(&["/plugins".to_string()], "pkg.Plugin").unwrap();
        let exe = layout.python_executable();
        assert!(exe.starts_with(&layout.venv_path));
        assert!(exe.ends_with(if cfg!(windows) {
            "python.exe"
        } else {
            "python"
        }));
    }

    // --- manager ------------------------------------------------------------

    fn manager_in(dir: &TempDir, class_name: &str, requirements: Option<&str>) -> VenvManager {
        VenvManager::new(
            &[dir.path().display().to_string()],
            class_name,
            requirements,
            Some("1.0.0"),
        )
        .expect("layout resolves")
    }

    #[test]
    fn relative_requirements_paths_resolve_under_the_plugin_path() {
        let dir = TempDir::new();
        let mgr = manager_in(&dir, "pkg.Plugin", Some("requirements.txt"));
        assert_eq!(
            mgr.requirements_file.as_deref(),
            Some(dir.path().join("pkg").join("requirements.txt").as_path())
        );
    }

    #[test]
    fn absolute_requirements_paths_are_left_alone() {
        let dir = TempDir::new();
        let mgr = manager_in(&dir, "pkg.Plugin", Some("/etc/shared/requirements.txt"));
        assert_eq!(
            mgr.requirements_file.as_deref(),
            Some(Path::new("/etc/shared/requirements.txt"))
        );
    }

    #[test]
    fn a_missing_venv_reports_an_invalid_cache() {
        let dir = TempDir::new();
        let mgr = manager_in(&dir, "pkg.Plugin", None);
        assert_eq!(mgr.cache_verdict(), CacheVerdict::VenvMissing);
    }

    #[tokio::test]
    async fn ensure_builds_then_reuses_the_venv() {
        // The cached-venv-reuse acceptance example: a second initialize with
        // unchanged inputs must not rebuild or reinstall.
        if crate::testing::skip_without_python3("ensure_builds_then_reuses_the_venv") {
            return;
        }
        let dir = TempDir::new();
        let mgr = manager_in(&dir, "pkg.Plugin", None);

        let first = mgr.ensure().await.expect("venv builds");
        assert_eq!(
            first,
            EnsureOutcome::Built {
                installed_requirements: false
            },
            "no requirements file means a fresh venv with no install"
        );
        assert!(
            mgr.python_executable().exists(),
            "the interpreter must exist after a build"
        );

        let second = mgr.ensure().await.expect("cached venv is reusable");
        assert_eq!(
            second,
            EnsureOutcome::Reused,
            "unchanged inputs must not rebuild"
        );
    }

    #[tokio::test]
    async fn a_changed_requirements_hash_forces_a_rebuild() {
        if crate::testing::skip_without_python3("a_changed_requirements_hash_forces_a_rebuild") {
            return;
        }
        let dir = TempDir::new();
        std::fs::create_dir_all(dir.path().join("pkg")).unwrap();
        let requirements = dir.path().join("pkg").join("requirements.txt");
        // Empty requirements: pip succeeds without network access, which keeps
        // this test hermetic while still exercising the install branch.
        std::fs::write(&requirements, "").unwrap();

        let mgr = manager_in(&dir, "pkg.Plugin", Some("requirements.txt"));
        assert!(matches!(
            mgr.ensure().await.unwrap(),
            EnsureOutcome::Built { .. }
        ));
        assert_eq!(mgr.ensure().await.unwrap(), EnsureOutcome::Reused);

        // Editing the file changes its hash, which must invalidate.
        std::fs::write(&requirements, "# a comment changes the hash\n").unwrap();
        assert_eq!(mgr.cache_verdict(), CacheVerdict::RequirementsChanged);
        assert!(matches!(
            mgr.ensure().await.unwrap(),
            EnsureOutcome::Built { .. }
        ));
    }

    #[tokio::test]
    async fn an_absent_requirements_file_builds_and_skips_install() {
        if crate::testing::skip_without_python3(
            "an_absent_requirements_file_builds_and_skips_install",
        ) {
            return;
        }
        let dir = TempDir::new();
        // Configured but not present on disk — must not error.
        let mgr = manager_in(&dir, "pkg.Plugin", Some("does-not-exist.txt"));

        assert_eq!(
            mgr.ensure()
                .await
                .expect("a missing requirements file is not fatal"),
            EnsureOutcome::Built {
                installed_requirements: false
            }
        );
    }

    #[tokio::test]
    async fn two_plugins_sharing_a_package_do_not_thrash_each_others_cache() {
        // Both resolve to one venv dir but distinct manifest + metadata files,
        // so building either leaves the other's cache valid.
        if crate::testing::skip_without_python3(
            "two_plugins_sharing_a_package_do_not_thrash_each_others_cache",
        ) {
            return;
        }
        let dir = TempDir::new();
        let a = manager_in(&dir, "pkg.a.PluginA", None);
        let b = manager_in(&dir, "pkg.b.PluginB", None);

        assert_eq!(
            a.layout().venv_path,
            b.layout().venv_path,
            "one shared venv"
        );
        assert_ne!(a.layout().metadata_path, b.layout().metadata_path);

        assert!(matches!(
            a.ensure().await.unwrap(),
            EnsureOutcome::Built { .. }
        ));
        assert_eq!(a.ensure().await.unwrap(), EnsureOutcome::Reused);

        // B has no metadata yet, so it builds once...
        assert!(matches!(
            b.ensure().await.unwrap(),
            EnsureOutcome::Built { .. }
        ));
        // ...and crucially A is still a cache hit afterwards. A shared manifest
        // filename here would have invalidated A and started a rebuild loop.
        assert_eq!(
            a.ensure().await.unwrap(),
            EnsureOutcome::Reused,
            "B's build must not invalidate A"
        );
        assert_eq!(b.ensure().await.unwrap(), EnsureOutcome::Reused);
    }

    #[tokio::test]
    async fn a_manifest_edit_invalidates_the_cache() {
        if crate::testing::skip_without_python3("a_manifest_edit_invalidates_the_cache") {
            return;
        }
        let dir = TempDir::new();
        let mgr = manager_in(&dir, "pkg.Plugin", None);
        assert!(matches!(
            mgr.ensure().await.unwrap(),
            EnsureOutcome::Built { .. }
        ));
        assert_eq!(mgr.ensure().await.unwrap(), EnsureOutcome::Reused);

        // Writing a manifest where there was none changes the manifest hash —
        // the sole change signal for a plugin with no requirements file.
        std::fs::write(&mgr.layout().manifest_path, "version: 1.0.1\n").unwrap();
        assert_eq!(mgr.cache_verdict(), CacheVerdict::ManifestHashChanged);
    }

    #[tokio::test]
    async fn a_declared_version_bump_invalidates_the_cache() {
        if crate::testing::skip_without_python3("a_declared_version_bump_invalidates_the_cache") {
            return;
        }
        let dir = TempDir::new();
        let v1 = manager_in(&dir, "pkg.Plugin", None);
        assert!(matches!(
            v1.ensure().await.unwrap(),
            EnsureOutcome::Built { .. }
        ));

        // Same plugin, newer declared version: the metadata recorded 1.0.0.
        let v2 = VenvManager::new(
            &[dir.path().display().to_string()],
            "pkg.Plugin",
            None,
            Some("2.0.0"),
        )
        .unwrap();
        assert_eq!(v2.cache_verdict(), CacheVerdict::ManifestVersionChanged);
    }

    #[tokio::test]
    async fn metadata_written_by_this_host_is_a_cache_hit_for_it() {
        // Round-trip guard: whatever `save_metadata` writes must satisfy
        // `evaluate_cache` on the next run. A field-name drift between the two
        // would otherwise rebuild every venv on every single run.
        if crate::testing::skip_without_python3(
            "metadata_written_by_this_host_is_a_cache_hit_for_it",
        ) {
            return;
        }
        let dir = TempDir::new();
        let mgr = manager_in(&dir, "pkg.Plugin", None);
        mgr.ensure().await.unwrap();

        let raw = std::fs::read_to_string(&mgr.layout().metadata_path).unwrap();
        let parsed: CacheMetadata =
            serde_json::from_str(&raw).expect("our own metadata must parse");
        assert_eq!(parsed.manifest_version.as_deref(), Some("1.0.0"));
        assert!(parsed.manifest_hash.is_some());
        assert_eq!(mgr.cache_verdict(), CacheVerdict::Valid);
    }
}
