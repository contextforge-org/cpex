#!/usr/bin/env bash
# Fire an outbound LLM call carrying PII from inside the weather-service
# agent container. The cpex-runtime plugin's llm-pii-redactor should match
# `alice@corp.com` against the `email` regex and rewrite the body before
# it leaves the sidecar.
#
# Expected outcome:
#   - HTTP 200 from upstream (Ollama at host.docker.internal:11434)
#   - Session API event shows `cpex-runtime modify body_rewritten`
#   - abctl Detail pane shows the body-mutation diagnostic
#   - The on-wire LLM prompt has `[REDACTED:email]` in place of the email
#
# Prereq: weather-service pod up, Ollama listening on the host, cpex-runtime
# enabled in authbridge-runtime-config.

set -euo pipefail

POD=$(kubectl get pod -n team1 \
    -l app.kubernetes.io/name=weather-service \
    -o jsonpath='{.items[0].metadata.name}')

echo "Pod: $POD"
echo "Firing LLM call with PII ('alice@corp.com')..."

kubectl exec -i -n team1 "$POD" -c agent -- python3 - <<'PY'
import urllib.request, json

body = {
    "messages": [
        {"role": "user", "content": "please email alice@corp.com the weather forecast"}
    ],
    "model": "llama3.2:3b-instruct-fp16",
    "max_tokens": 10,
}
req = urllib.request.Request(
    "http://host.docker.internal:11434/v1/chat/completions",
    data=json.dumps(body).encode(),
    headers={"Content-Type": "application/json"},
)
print(urllib.request.urlopen(req, timeout=20).read()[:200].decode())
PY
