#!/usr/bin/env python3
# Location: ./bindings/python/tests/smoke_wheel.py
# Copyright 2025
# SPDX-License-Identifier: Apache-2.0
#
# Wheel smoke test: build the cpex wheel, install it into a fresh venv,
# import cpex there and run a policy.
#
# This checks what the in-tree `maturin develop` tests cannot: that the
# built wheel is self-contained (native module, Python package, stubs)
# and works outside the source tree.
#
# Usage (from anywhere):
#   python bindings/python/tests/smoke_wheel.py              # build, then test
#   python bindings/python/tests/smoke_wheel.py --wheel W.whl  # test a built wheel
#
# Building uses `maturin` from PATH, or installs it into a throwaway build
# venv when it is missing. Only the standard library is needed to run
# this script. Exits non-zero on any failure. Not collected by pytest.

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
import venv
from pathlib import Path

BINDINGS_DIR = Path(__file__).resolve().parents[1]

POLICY = """\
global:
  pdp:
    - kind: cel

routes:
  - tool: lookup_person
    authorization:
      pre_invocation:
        - cel:
            expr: "!has(args.ssn)"
            on_deny:
              - "deny('ssn found in tool arguments', 'pii.ssn_detected')"
"""

# Runs inside the fresh venv. Must not see the source tree.
CHECK = """\
import asyncio, importlib.resources, sys
import cpex
from cpex import PipelineResult, PluginManager, PolicyEngine

assert "site-packages" in cpex.__file__, f"imported from the source tree: {cpex.__file__}"
assert PluginManager is PolicyEngine

# The stubs ship in the wheel: PEP 561 marker plus the native module's stub.
pkg = importlib.resources.files("cpex")
for stub in ("py.typed", "_lib.pyi"):
    assert pkg.joinpath(stub).is_file(), f"wheel is missing cpex/{stub}"

def call(args):
    return {"message": {"role": "assistant", "content": [{"content_type": "tool_call",
            "content": {"tool_call_id": "tc_1", "name": "lookup_person", "arguments": args}}]}}

ROUTE = {"meta": {"entity_type": "tool", "entity_name": "lookup_person"}}

async def main(path):
    engine = PolicyEngine(path)
    await engine.initialize()
    allowed = await engine.invoke_hook("cmf.tool_pre_invoke", call({"name": "Alice"}), ROUTE)
    denied = await engine.invoke_hook("cmf.tool_pre_invoke", call({"ssn": "123-45-6789"}), ROUTE)
    report = await engine.refresh_secrets()
    await engine.shutdown()
    assert isinstance(allowed, PipelineResult)
    assert allowed.continue_processing is True, allowed.violation
    assert denied.continue_processing is False
    assert denied.violation["code"] == "pii.ssn_detected", denied.violation
    assert report == {"updated": [], "unchanged": 0, "failed": []}, report
    print(f"cpex wheel smoke test passed ({cpex.__file__})")

asyncio.run(main(sys.argv[1]))
"""


def run(cmd: list[str], **kwargs) -> None:
    print("+", " ".join(str(c) for c in cmd), flush=True)
    subprocess.run(cmd, check=True, **kwargs)


def venv_python(root: Path) -> Path:
    scripts = "Scripts" if sys.platform == "win32" else "bin"
    exe = "python.exe" if sys.platform == "win32" else "python"
    return root / scripts / exe


def make_venv(root: Path) -> Path:
    venv.EnvBuilder(with_pip=True, clear=True).create(root)
    return venv_python(root)


def build_wheel(work: Path) -> Path:
    out = work / "dist"
    maturin = shutil.which("maturin")
    if maturin is None:
        build_py = make_venv(work / "build-venv")
        run([str(build_py), "-m", "pip", "install", "--quiet", "maturin>=1,<2"])
        cmd = [str(build_py), "-m", "maturin"]
    else:
        cmd = [maturin]
    run(
        cmd + ["build", "--release", "--interpreter", sys.executable, "--out", str(out)],
        cwd=BINDINGS_DIR,
    )
    wheels = sorted(out.glob("cpex-*.whl"))
    if len(wheels) != 1:
        sys.exit(f"expected one wheel in {out}, found {wheels}")
    return wheels[0]


def main() -> int:
    parser = argparse.ArgumentParser(description="Build and smoke test the CPEX Python wheel")
    parser.add_argument("--wheel", type=Path, help="test this wheel instead of building one")
    parser.add_argument("--keep", action="store_true", help="keep the scratch directory")
    args = parser.parse_args()

    work = Path(tempfile.mkdtemp(prefix="cpex-wheel-smoke-"))
    try:
        wheel = args.wheel.resolve() if args.wheel else build_wheel(work)
        print(f"testing {wheel}", flush=True)

        py = make_venv(work / "smoke-venv")
        run([str(py), "-m", "pip", "install", "--quiet", "--no-deps", str(wheel)])

        policy = work / "policy.yaml"
        policy.write_text(POLICY)
        check = work / "check.py"
        check.write_text(CHECK)
        # Run from the scratch dir with -I so neither the cwd nor the source
        # tree can shadow the installed package.
        run([str(py), "-I", str(check), str(policy)], cwd=work)
    finally:
        if args.keep:
            print(f"kept {work}")
        else:
            shutil.rmtree(work, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
