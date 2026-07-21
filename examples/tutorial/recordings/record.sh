#!/usr/bin/env bash
# Record the four tutorial casts into ./casts/. Run from the repo root or
# from this directory; paths are resolved relative to the repo root.
#
#   ./record.sh            # record all four
#   ./record.sh m01-hello  # record just one
#
# Prerequisites: asciinema installed, and (for m07/m08) the tutorial IdP up:
#   docker compose -f examples/tutorial/idp/docker-compose.yml up -d
#
# Each recording runs a module binary once. The sessions are scripted (no
# manual typing) so re-recording is deterministic. Module 8 is recorded in
# --check mode so it approves itself and the cast completes unattended; the
# docs describe the interactive curl step in prose alongside it.
set -euo pipefail

# Resolve the repo root (two levels up from this script).
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
CASTS="$(dirname "${BASH_SOURCE[0]}")/casts"
mkdir -p "$CASTS"

record() {
  local name="$1" example="$2"
  shift 2
  echo "→ recording $name"
  asciinema rec --overwrite \
    --title "CPEX tutorial: $name" \
    --command "cd '$ROOT' && cargo run -q -p cpex-tutorial --example $example -- $*" \
    "$CASTS/$name.cast"
}

target="${1:-all}"

if [[ "$target" == "all" || "$target" == "m01-hello" ]]; then
  record "m01-hello" m01_hello
fi
if [[ "$target" == "all" || "$target" == "m03-shaping" ]]; then
  record "m03-shaping" m03_shaping
fi
if [[ "$target" == "all" || "$target" == "m07-tainting" ]]; then
  record "m07-tainting" m07_tainting
fi
if [[ "$target" == "all" || "$target" == "m08-elicitation" ]]; then
  # --check so the cast self-approves and completes without a second terminal.
  record "m08-elicitation" m08_elicitation --check
fi

echo "done. Casts in $CASTS/. Upload with: asciinema upload $CASTS/<name>.cast"
