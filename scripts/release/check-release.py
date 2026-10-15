#!/usr/bin/env python3
"""Validate the release contract shared by local packaging and CI."""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tomllib

ROOT = Path(__file__).resolve().parents[2]
PUBLISHED = {"cpex", "cpex-hosts-python", "cpex-plugin-delegator-biscuit", "cpex-python"}
UNPUBLISHED = {"cpex-ffi", "cpex-demo-ffi", "cpex-tutorial", "cpex-parity-harness"}


def check(condition, message):
    if not condition:
        raise SystemExit(f"release-check: {message}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", help="Expected version or v-prefixed release tag")
    args = parser.parse_args()
    manifest = tomllib.loads((ROOT / "Cargo.toml").read_text())
    version = manifest["workspace"]["package"]["version"]
    if args.version:
        check(args.version.removeprefix("v") == version,
              f"requested {args.version} does not match workspace {version}")
    metadata = json.loads(subprocess.check_output(
        [os.environ.get("CARGO", "cargo"), "metadata", "--no-deps", "--locked", "--format-version", "1"],
        cwd=ROOT, text=True,
    ))
    members = [p for p in metadata["packages"] if p["id"] in metadata["workspace_members"]]
    check({p["name"] for p in members if p["publish"] != []} == PUBLISHED,
          "publishable members differ from the four retained release crates")
    check({p["name"] for p in members if p["publish"] == []} == UNPUBLISHED,
          "unpublished members differ from the FFI, demos and parity harness")
    for package in members:
        check(package["version"] == version, f"{package['name']} has stale version {package['version']}")
        for dep in package["dependencies"]:
            if dep["name"].startswith("praxis-policy"):
                check(dep["req"] == "=0.5.0", f"{package['name']}: {dep['name']} must pin PPE =0.5.0")
            if package["name"] in PUBLISHED and dep["kind"] != "dev" and dep.get("path") is not None:
                check(dep["name"] in PUBLISHED, f"{package['name']} depends on unpublished {dep['name']}")
                check(dep["req"] == f"^{version}", f"{package['name']}: stale requirement for {dep['name']}")
    go_mod = (ROOT / "examples/go-demo/go.mod").read_text()
    check(re.search(rf"(?m)^require github\.com/contextforge-org/cpex/go/cpex v{re.escape(version)}$", go_mod),
          "Go demo module requirement does not match the workspace")
    rust_abi = re.search(r"pub const FFI_ABI_VERSION: u32 = (\d+);",
                         (ROOT / "crates/cpex-ffi/src/lib.rs").read_text())
    go_abi = re.search(r"const expectedFFIABIVersion uint32 = (\d+)", (ROOT / "go/cpex/abi.go").read_text())
    check(rust_abi and go_abi and rust_abi[1] == go_abi[1], "Rust and Go FFI ABI versions differ")
    check(f"## [{version}] - " in (ROOT / "CHANGELOG.md").read_text(), "missing dated changelog entry")
    print(f"release-check: CPEX {version}, four publishable crates, PPE 0.5.0, FFI ABI {rust_abi[1]}")


if __name__ == "__main__":
    main()
