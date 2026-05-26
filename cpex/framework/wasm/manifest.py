# -*- coding: utf-8 -*-
"""Location: ./cpex/framework/wasm/manifest.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0

WASM plugin manifest loader and validator.

Parses `plugin-manifest.yaml`, validates it against the JSON Schema, and
exposes a typed Pydantic model used by WasmPlugin during load.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any, Optional

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator


class WasmArtifact(BaseModel):
    """The `.wasm` Component Model file referenced by a manifest."""

    model_config = ConfigDict(frozen=True)

    path: str
    sha256: str
    signature: Optional[str] = None
    signature_format: Optional[str] = None
    public_key: Optional[str] = None

    @field_validator("sha256")
    @classmethod
    def _validate_sha256(cls, v: str) -> str:
        if not re.fullmatch(r"[a-f0-9]{64}", v):
            raise ValueError("sha256 must be 64 lowercase hex characters")
        return v


class WasmLimits(BaseModel):
    """Per-instance resource caps enforced by the runtime."""

    model_config = ConfigDict(frozen=True)

    max_memory_mb: int = Field(default=64, ge=1, le=4096)
    max_fuel: int = Field(default=100_000_000, ge=1000)
    max_table_elements: int = Field(default=10_000, ge=0)
    call_timeout_ms: int = Field(default=5_000, ge=1, le=60_000)
    max_payload_bytes: int = Field(default=1_048_576, ge=1024)


class WasmManifest(BaseModel):
    """Validated `plugin-manifest.yaml`.

    Loaded by `from_path(...)` which also verifies the .wasm SHA-256
    on disk. Signature verification is performed by WasmPlugin at load
    time when public_key is available.
    """

    model_config = ConfigDict(frozen=True)

    api_version: str
    name: str
    version: str
    description: Optional[str] = None
    author: Optional[str] = None
    license: Optional[str] = None
    homepage: Optional[str] = None

    artifact: WasmArtifact
    hooks: list[str]
    capabilities: list[str] = Field(default_factory=list)
    limits: WasmLimits = Field(default_factory=WasmLimits)
    config_schema: Optional[dict[str, Any]] = None
    metadata: Optional[dict[str, Any]] = None

    # Filled by from_path() once the manifest is located on disk.
    # Not serialized.
    manifest_dir: Path = Field(default=Path("."), exclude=True)

    @field_validator("api_version")
    @classmethod
    def _validate_api_version(cls, v: str) -> str:
        if v != "cpex.plugin/v1":
            raise ValueError(
                f"Unsupported api_version {v!r}; this host supports 'cpex.plugin/v1'"
            )
        return v

    @field_validator("name")
    @classmethod
    def _validate_name(cls, v: str) -> str:
        if not re.fullmatch(r"[a-z][a-z0-9_-]{1,63}", v):
            raise ValueError(
                f"Invalid plugin name {v!r}: must match [a-z][a-z0-9_-]{{1,63}}"
            )
        return v

    @field_validator("version")
    @classmethod
    def _validate_version(cls, v: str) -> str:
        if not re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", v):
            raise ValueError(f"Invalid semver {v!r}")
        return v

    @field_validator("hooks")
    @classmethod
    def _validate_hooks(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("hooks must list at least one hook name")
        if len(set(v)) != len(v):
            raise ValueError(f"duplicate hooks: {v}")
        for h in v:
            if not re.fullmatch(r"[a-z][a-z0-9_]{1,63}", h):
                raise ValueError(f"invalid hook name: {h!r}")
        return v

    @field_validator("capabilities")
    @classmethod
    def _validate_capabilities(cls, v: list[str]) -> list[str]:
        # Defer detailed validation to capabilities.py; here we just check
        # the structural pattern: token or token:scope.
        from cpex.framework.wasm.capabilities import validate_capability_string

        for cap in v:
            validate_capability_string(cap)
        if len(set(v)) != len(v):
            raise ValueError(f"duplicate capabilities: {v}")
        return v

    @property
    def artifact_path(self) -> Path:
        """Resolve artifact path relative to the manifest directory.

        Enforces that the resolved path stays within the manifest dir to
        prevent directory traversal.
        """
        resolved = (self.manifest_dir / self.artifact.path).resolve()
        try:
            resolved.relative_to(self.manifest_dir.resolve())
        except ValueError as e:
            raise ValueError(
                f"artifact.path escapes manifest directory: {self.artifact.path!r}"
            ) from e
        return resolved

    def verify_artifact_integrity(self) -> None:
        """Verify the on-disk .wasm matches the declared SHA-256.

        Raises:
            FileNotFoundError: if the artifact is missing.
            ValueError: if the hash does not match.
        """
        path = self.artifact_path
        if not path.is_file():
            raise FileNotFoundError(f"wasm artifact not found: {path}")

        hasher = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                hasher.update(chunk)
        actual = hasher.hexdigest()
        if actual != self.artifact.sha256:
            raise ValueError(
                f"sha256 mismatch for {path}: "
                f"manifest declares {self.artifact.sha256}, file is {actual}"
            )

    @classmethod
    def from_path(cls, manifest_path: str | Path) -> "WasmManifest":
        """Load, parse, and validate a `plugin-manifest.yaml`.

        Side effects:
            - Reads the manifest file.
            - Reads the referenced .wasm file in full to verify its SHA-256.
            - Does NOT verify signatures (caller's responsibility, since
              signature backends may require external tooling).
        """
        path = Path(manifest_path).resolve()
        if not path.is_file():
            raise FileNotFoundError(f"manifest not found: {path}")

        with path.open("r", encoding="utf-8") as f:
            raw = yaml.safe_load(f)
        if not isinstance(raw, dict):
            raise ValueError(f"manifest root must be a mapping: {path}")

        manifest = cls.model_validate({**raw, "manifest_dir": path.parent})
        manifest.verify_artifact_integrity()
        return manifest
