#!/usr/bin/env bash
# Fire an outbound MCP `tools/call` for `get_weather` from inside the
# weather-service agent container. The cpex-runtime plugin's
# scope-tool-gate is configured (in authbridge-runtime-config) to require
# the `weather:read` scope for this tool. A direct curl from inside the
# pod has no inbound JWT, so Subject.Permissions is empty and the gate
# should deny.
#
# Expected outcome:
#   - HTTP 403 with body {"error":"policy.forbidden","plugin":"cpex-runtime"}
#   - Session API event shows phase=denied, cpex-runtime deny reason
#     "missing required scope"
#   - abctl Detail pane on the deny row shows the violation context
#
# Prereq: weather-service pod up, weather-tool-mcp reachable, cpex-runtime
# enabled with tool_scopes mapping `get_weather: weather:read`.

set -euo pipefail

POD=$(kubectl get pod -n team1 \
    -l app.kubernetes.io/name=weather-service \
    -o jsonpath='{.items[0].metadata.name}')

echo "Pod: $POD"
echo "Firing MCP tools/call for get_weather (no scope) — expect 403..."

kubectl exec -i -n team1 "$POD" -c agent -- python3 - <<'PY'
import urllib.request, json, urllib.error

body = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {"name": "get_weather", "arguments": {"city": "NYC"}},
}
req = urllib.request.Request(
    "http://weather-tool-mcp.team1.svc.cluster.local:8000/mcp",
    data=json.dumps(body).encode(),
    headers={
        "Content-Type": "application/json",
        # MCP Streamable HTTP transport requires both
        "Accept": "application/json, text/event-stream",
    },
)
try:
    print(urllib.request.urlopen(req, timeout=10).read()[:200].decode())
except urllib.error.HTTPError as e:
    print(f"HTTP {e.code}", e.read()[:200].decode())
PY
