// Location: ./crates/cpex-hosts-python/src/isolated/venv.rs
// Copyright 2026
// SPDX-License-Identifier: Apache-2.0
// Authors: Ted Habeck
//
// Venv creation and requirements-hash cache, mirroring the Python-side
// IsolatedVenvPlugin._compute_requirements_hash / _is_venv_cache_valid /
// _save_cache_metadata / create_venv logic.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info, warn};

#[derive(Debug, Error)]
pub enum VenvError {
    #[error("venv creation failed: {0}")]
    Create(String),
    #[error("pip install failed: {0}")]
    PipInstall(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Outcome of `ensure_venv()`.
#[derive(Debug, PartialEq, Eq)]
pub enum VenvState {
    /// Venv already existed and requirements hash matched — reused as-is.
    Reused,
    /// Venv was (re-)created and requirements installed.
    Created,
}

#[derive(Debug, Serialize, Deserialize)]
struct VenvMetadata {
    venv_path: String,
    requirements_file: Option<String>,
    requirements_hash: String,
    python_version: String,
}

/// Manages the lifecycle of a single venv associated with one Python plugin.
pub struct VenvManager {
    pub venv_path: PathBuf,
    pub requirements_file: Option<PathBuf>,
    /// `<venv_path>/../.cpex/venv_cache/<venv_name>_metadata.json`
    cache_metadata_path: PathBuf,
}

impl VenvManager {
    /// Create a new VenvManager.
    ///
    /// * `venv_path` — where the venv lives (or will be created)
    /// * `requirements_file` — optional path to requirements.txt
    pub fn new(venv_path: PathBuf, requirements_file: Option<PathBuf>) -> Self {
        let venv_name = venv_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let plugin_dir = venv_path.parent().unwrap_or(Path::new("."));
        let cache_metadata_path = plugin_dir
            .join(".cpex")
            .join("venv_cache")
            .join(format!("{}_metadata.json", venv_name));
        // Relative requirements paths are resolved against the plugin dir
        // (venv_path.parent()), mirroring Python's `package_path / requirements_file`.
        let requirements_file = requirements_file.map(|r| {
            if r.is_relative() {
                plugin_dir.join(r)
            } else {
                r
            }
        });
        Self {
            venv_path,
            requirements_file,
            cache_metadata_path,
        }
    }

    /// Compute SHA-256 of the requirements file, or an empty-bytes hash if absent.
    /// Matches Python's `hashlib.sha256(); hasher.update(content); hasher.hexdigest()`.
    fn compute_requirements_hash(&self) -> String {
        use sha2::{Digest, Sha256};
        use std::io::Read;
        let mut hasher = Sha256::new();
        if let Some(ref req) = self.requirements_file {
            if let Ok(mut f) = std::fs::File::open(req) {
                let mut buf = Vec::new();
                if f.read_to_end(&mut buf).is_ok() {
                    hasher.update(&buf);
                }
            }
        }
        // No file or unreadable: finalize over zero bytes — identical to
        // Python's `hasher.update(b"")` fallthrough.
        format!("{:x}", hasher.finalize())
    }

    fn is_cache_valid(&self) -> bool {
        if !self.venv_path.exists() {
            debug!("venv path does not exist: {:?}", self.venv_path);
            return false;
        }
        if !self.cache_metadata_path.exists() {
            debug!(
                "metadata file does not exist: {:?}",
                self.cache_metadata_path
            );
            return false;
        }
        match std::fs::read_to_string(&self.cache_metadata_path) {
            Ok(s) => match serde_json::from_str::<VenvMetadata>(&s) {
                Ok(meta) => {
                    let current = self.compute_requirements_hash();
                    if meta.requirements_hash != current {
                        info!(
                            "requirements changed (cached={}, current={})",
                            meta.requirements_hash, current
                        );
                        false
                    } else {
                        info!("valid venv cache at {:?}", self.venv_path);
                        true
                    }
                },
                Err(e) => {
                    warn!("could not parse venv metadata: {}", e);
                    false
                },
            },
            Err(e) => {
                warn!("could not read venv metadata: {}", e);
                false
            },
        }
    }

    fn save_metadata(&self) -> Result<(), VenvError> {
        if let Some(parent) = self.cache_metadata_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let meta = VenvMetadata {
            venv_path: self.venv_path.display().to_string(),
            requirements_file: self
                .requirements_file
                .as_ref()
                .map(|p| p.display().to_string()),
            requirements_hash: self.compute_requirements_hash(),
            python_version: python_version_string(),
        };
        let json = serde_json::to_string_pretty(&meta)?;
        std::fs::write(&self.cache_metadata_path, json)?;
        info!(
            "saved venv cache metadata to {:?}",
            self.cache_metadata_path
        );
        Ok(())
    }

    fn create_venv(&self) -> Result<(), VenvError> {
        if self.venv_path.exists() {
            info!("removing stale venv at {:?}", self.venv_path);
            std::fs::remove_dir_all(&self.venv_path)?;
        }
        info!("creating venv at {:?}", self.venv_path);
        let status = Command::new("python3")
            .args(["-m", "venv"])
            .arg(&self.venv_path)
            .status()?;
        if !status.success() {
            return Err(VenvError::Create(format!(
                "python3 -m venv exited with {:?}",
                status.code()
            )));
        }
        Ok(())
    }

    fn pip_install(&self) -> Result<(), VenvError> {
        let Some(ref req) = self.requirements_file else {
            return Ok(());
        };
        if !req.exists() {
            debug!(
                "requirements file {:?} does not exist — skipping pip install",
                req
            );
            return Ok(());
        }
        let python = self.python_executable();
        info!("running pip install -r {:?}", req);
        let status = Command::new(&python)
            .args(["-m", "pip", "install", "-r"])
            .arg(req)
            .status()?;
        if !status.success() {
            return Err(VenvError::PipInstall(format!(
                "pip install exited with {:?}",
                status.code()
            )));
        }
        Ok(())
    }

    /// Return the platform-correct path to the Python interpreter inside the venv.
    pub fn python_executable(&self) -> PathBuf {
        #[cfg(windows)]
        {
            self.venv_path.join("Scripts").join("python.exe")
        }
        #[cfg(not(windows))]
        {
            self.venv_path.join("bin").join("python")
        }
    }

    /// Ensure the venv exists and requirements are installed.
    ///
    /// Returns `VenvState::Reused` if the cache was valid; `VenvState::Created`
    /// after creating/reinstalling.
    pub async fn ensure_venv(&self) -> Result<VenvState, VenvError> {
        if self.is_cache_valid() {
            return Ok(VenvState::Reused);
        }
        self.create_venv()?;
        self.pip_install()?;
        self.save_metadata()?;
        Ok(VenvState::Created)
    }
}

fn python_version_string() -> String {
    Command::new("python3")
        .args(["--version"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn req_path(dir: &TempDir, content: &str) -> PathBuf {
        let p = dir.path().join("requirements.txt");
        std::fs::write(&p, content).unwrap();
        p
    }

    #[tokio::test]
    async fn fresh_venv_is_created() {
        let dir = TempDir::new().unwrap();
        let venv = dir.path().join(".venv");
        let req = req_path(&dir, "");
        let mgr = VenvManager::new(venv.clone(), Some(req));
        let state = mgr.ensure_venv().await.unwrap();
        assert_eq!(state, VenvState::Created);
        assert!(venv.exists(), "venv dir should exist after creation");
        assert!(
            mgr.python_executable().exists(),
            "python executable should exist"
        );
    }

    #[tokio::test]
    async fn cache_hit_reuses_venv() {
        let dir = TempDir::new().unwrap();
        let venv = dir.path().join(".venv");
        let req = req_path(&dir, "");
        let mgr = VenvManager::new(venv.clone(), Some(req));
        mgr.ensure_venv().await.unwrap();
        // Second call should hit the cache.
        let state = mgr.ensure_venv().await.unwrap();
        assert_eq!(state, VenvState::Reused);
    }

    #[tokio::test]
    async fn cache_miss_on_requirements_change() {
        let dir = TempDir::new().unwrap();
        let venv = dir.path().join(".venv");
        let req = req_path(&dir, "");
        let mgr = VenvManager::new(venv.clone(), Some(req.clone()));
        mgr.ensure_venv().await.unwrap();
        // Mutate requirements file.
        let mut f = std::fs::OpenOptions::new().append(true).open(&req).unwrap();
        writeln!(f, "# changed").unwrap();
        drop(f);
        let state = mgr.ensure_venv().await.unwrap();
        assert_eq!(state, VenvState::Created);
    }

    #[tokio::test]
    async fn missing_requirements_file_still_creates_venv() {
        let dir = TempDir::new().unwrap();
        let venv = dir.path().join(".venv");
        // No requirements file.
        let mgr = VenvManager::new(venv.clone(), None);
        let state = mgr.ensure_venv().await.unwrap();
        assert_eq!(state, VenvState::Created);
        assert!(venv.exists());
    }

    #[test]
    fn python_executable_path_is_inside_venv() {
        let dir = TempDir::new().unwrap();
        let venv = dir.path().join(".venv");
        let mgr = VenvManager::new(venv.clone(), None);
        let exe = mgr.python_executable();
        assert!(exe.starts_with(&venv));
    }
}
