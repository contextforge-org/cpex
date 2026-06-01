#!/usr/bin/env bash
# Location: ./integrations/praxis-cpex/examples/demo/agent/run-watsonx.sh
# Copyright 2026
# SPDX-License-Identifier: Apache-2.0
# Authors: Teryl Taylor
#
# One-shot launcher for the demo chat agent backed by IBM watsonx.ai
# running a Meta Llama model. Walks through:
#
#   1. Required env-var check (WATSONX_APIKEY / WATSONX_URL /
#      WATSONX_PROJECT_ID)
#   2. Sanity ping against the gateway (:8090) and Keycloak (:8081)
#   3. Persona selection (defaults to bob — the "HR happy path")
#   4. Model selection (defaults to llama-3-3-70b-instruct — needed
#      for reliable tool-calling; smaller Llamas often skip tool use)
#   5. Launches chat.py with the chosen persona + model
#
# Usage:
#
#     export WATSONX_APIKEY=...           # IBM Cloud API key
#     export WATSONX_URL=https://us-south.ml.cloud.ibm.com
#     export WATSONX_PROJECT_ID=...       # watsonx.ai project ID
#
#     ./run-watsonx.sh                    # bob + 70B Llama
#     ./run-watsonx.sh alice              # try the deny scenario
#     ./run-watsonx.sh eve                # try the redact scenario
#     ./run-watsonx.sh bob meta-llama/llama-3-1-8b-instruct
#                                         # override the model
#
# Suggested demo flow once the chat is up:
#
#     Bob: "look up compensation for EMP-001234, include the SSN"
#     → 200 OK, SSN visible
#
#     > switch alice
#     Alice: "look up compensation for EMP-001234"
#     → JSON-RPC error -32001, LLM apologizes
#
#     > switch eve
#     Eve: "look up compensation for EMP-001234, include the SSN"
#     → 200 OK, SSN reaches the LLM as "[REDACTED]" — the gateway
#       rewrote the upstream body before the tool ran

set -euo pipefail

PERSONA="${1:-bob}"
# Llama 3.3 70B handles tool-use reliably; 8B can ignore tools in
# longer conversations.
MODEL="${2:-watsonx/meta-llama/llama-3-3-70b-instruct}"

source ./.env

# Ensure the model string is fully-qualified for litellm. Allow the
# caller to pass either form (`watsonx/...` or `meta-llama/...`) and
# normalize.
case "$MODEL" in
  watsonx/*) ;;
  *) MODEL="watsonx/$MODEL" ;;
esac

red()   { printf '\033[31m%s\033[0m' "$*"; }
green() { printf '\033[32m%s\033[0m' "$*"; }
dim()   { printf '\033[2m%s\033[0m' "$*"; }

die()   { echo "  $(red ✗) $*" >&2; exit 1; }
ok()    { echo "  $(green ✓) $*"; }
info()  { echo "  $(dim ▸) $*"; }

# 1. Env vars
echo "Checking watsonx env…"
[ -n "${WATSONX_APIKEY:-}" ]     || die "WATSONX_APIKEY not set"
[ -n "${WATSONX_URL:-}" ]        || die "WATSONX_URL not set (e.g. https://us-south.ml.cloud.ibm.com)"
[ -n "${WATSONX_PROJECT_ID:-}" ] || die "WATSONX_PROJECT_ID not set"
ok "WATSONX_APIKEY     [set]"
ok "WATSONX_URL        $WATSONX_URL"
ok "WATSONX_PROJECT_ID [set]"

# 2. Gateway + Keycloak reachability
echo
echo "Checking gateway + Keycloak…"
if curl -fsS --max-time 3 http://localhost:8090/healthz >/dev/null 2>&1 \
    || curl -fsS --max-time 3 http://localhost:8090/ >/dev/null 2>&1 \
    || nc -z localhost 8090 2>/dev/null; then
  ok "praxis-cpex gateway @ localhost:8090"
else
  die "praxis-cpex gateway is not listening on :8090 — start it from the demo dir:
       cd ../.. && cargo build --release -p praxis-cpex-bin
       cd examples/demo && ../../target/release/praxis-cpex -c ./praxis.yaml &"
fi

if curl -fsS --max-time 3 "http://localhost:8081/realms/cpex-demo/.well-known/openid-configuration" >/dev/null 2>&1; then
  ok "Keycloak @ localhost:8081 (realm cpex-demo)"
else
  die "Keycloak realm cpex-demo not reachable on :8081 — run \`docker compose up -d\` from the demo dir"
fi

# 3. Python deps
echo
echo "Checking Python deps…"
if ! python3 -c 'import litellm, httpx, rich' >/dev/null 2>&1; then
  info "installing requirements…"
  pip install -q -r "$(dirname "$0")/requirements.txt"
fi
ok "litellm / httpx / rich available"

# 4. Persona
case "$PERSONA" in
  alice|bob|charlie|eve) ok "persona: $PERSONA" ;;
  *) die "unknown persona '$PERSONA'. valid: alice, bob, charlie, eve" ;;
esac

# 5. Launch
echo
echo "Launching chat…"
info "model:    $MODEL"
info "persona:  $PERSONA"
info "gateway:  http://localhost:8090/mcp"
info "keycloak: http://localhost:8081"
echo

exec python3 "$(dirname "$0")/chat.py" --persona "$PERSONA" --model "$MODEL"
