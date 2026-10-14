#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run the retained capture harness against the immutable CPEX 0.2.3 tree."""

import argparse
import io
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile


# v0.2.3; the engine sources also match the original snapshot engine commit.
ENGINE_REV = "e3a2b30bbaf14682808f4e1de4e3e5fa5be9f481"


def main():
    parity = Path(__file__).resolve().parent
    repo = parity.parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--workdir", type=Path)
    args, capture_args = parser.parse_known_args()
    output = args.out.resolve()
    if output == parity / "snapshots" or parity / "snapshots" in output.parents:
        parser.error("write to a scratch directory, then review the baseline diff")
    work = args.workdir or Path(tempfile.mkdtemp(prefix="cpex-baseline-"))
    work = work.resolve()
    work.mkdir(parents=True, exist_ok=True)
    if any(work.iterdir()):
        parser.error("--workdir must be empty")
    archive = subprocess.check_output(["git", "archive", ENGINE_REV], cwd=repo)
    with tarfile.open(fileobj=io.BytesIO(archive)) as tree:
        tree.extractall(work, filter="data")
    shutil.copytree(parity / "baseline", work / "tests/parity/harness")
    for directory in ["scenarios", "snapshots"]:
        shutil.copytree(parity / directory, work / "tests/parity" / directory)
    shutil.copyfile(parity / "baseline/Cargo.lock", work / "Cargo.lock")
    manifest = work / "Cargo.toml"
    manifest.write_text(manifest.read_text().replace(
        "members = [\n", 'members = [\n    "tests/parity/harness",\n', 1
    ))
    print(f"CPEX 0.2.3 ({ENGINE_REV}) prepared in {work}", flush=True)
    if not args.prepare_only:
        subprocess.run([
            "cargo", "run", "--locked", "-p", "cpex-parity-harness", "--",
            "--root", str(parity), "--out", str(output), *capture_args,
        ], cwd=work, check=True)


if __name__ == "__main__":
    main()
