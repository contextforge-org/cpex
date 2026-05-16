# Demo quickstart — CPEX × AuthBridge workshop (Mac)

Zero-to-baseline setup for the CPEX-as-AuthBridge-plugin demo. Goal: a working
Kind cluster running the AuthBridge weather-agent demo, with `abctl` attached,
ready for the `cpex-runtime` plugin to be added.

**Time budget:** ~45–60 min on a fast machine, mostly waiting on image pulls.
**Target:** Mac (Apple Silicon or Intel) running Rancher Desktop or Docker Desktop.

If anything is *not* obvious from the upstream docs, that's the part this guide
flags. Defer to the upstream docs for anything outside this happy path:
- Kagenti install: [`kagenti/docs/install.md`](https://github.com/kagenti/kagenti/blob/main/docs/install.md)
- Weather agent + abctl demo: [`authbridge/demos/weather-agent/demo-with-abctl.md`](https://github.com/kagenti/kagenti-extensions/blob/main/authbridge/demos/weather-agent/demo-with-abctl.md)

---

## Phase 1 — Local prerequisites (~10 min)

### 1.1. Container runtime

Use **Rancher Desktop** or **Docker Desktop**. Either works. Allocate generously:

- **Memory: ≥ 12 GB** (Kagenti runs SPIRE + Keycloak + operator + the agent stack)
- **CPUs: 4+**
- **Disk: 30 GB+ free in the VM**

For **Rancher Desktop specifically**:
- Settings → Kubernetes → **uncheck "Enable Kubernetes"** (we run our own `kind` cluster)
- Settings → Container Engine → **dockerd (moby)** (kind expects a docker daemon)

### 1.2. CLI tools

```bash
brew install kind kubectl helm git
```

Verify:
```bash
kubectl version --client                  # ≥ 1.32
helm version                              # ≥ 3.18
kind version                              # any recent version
```

### 1.3. Ollama (local LLM)

```bash
brew install ollama
ollama serve &                            # leave running in a separate tab
ollama pull llama3.2:3b-instruct-fp16     # ~2 GB download
```

> **Heads-up — model mismatch in the deploy script.** The CLI deploy script
> sets `LLM_MODEL=qwen2.5:3b` by default, not what we pull above. You have two
> options: (a) also `ollama pull qwen2.5:3b` to match the default, or
> (b) leave Ollama with `llama3.2:3b-instruct-fp16` and override `LLM_MODEL`
> on the deployment (see Phase 3.1). Option (b) is what this guide does.

Quick sanity check:
```bash
curl http://localhost:11434/api/tags | jq '.models[].name'
# Should list whichever model(s) you pulled
```

---

## Phase 2 — Install Kagenti platform (~20–25 min)

### 2.1. Clone Kagenti

```bash
git clone https://github.com/kagenti/kagenti.git
cd kagenti
```

### 2.2. Run the installer (minimal set — workshop-tuned)

```bash
scripts/kind/setup-kagenti.sh --with-spire --with-ui
```

**Why these flags only:**
- `--with-spire` — workload identity. The AuthBridge sidecar needs a SPIFFE ID.
- `--with-ui` — Kagenti UI for chat (we'll send the workshop's chat messages through it).
- *Skipping* `--with-builds`, `--with-istio`, `--with-mcp-gateway`, etc. — saves ~20 min of install time. We deploy the weather agent from a pre-built image instead of building from source through the UI.

If you've already kicked off `--with-all`, it's fine — just slower.

### 2.3. Wait for cluster ready

Installer logs will indicate completion. Sanity check:

```bash
kubectl get nodes
kubectl get pods -A | grep -v Running | grep -v Completed
# Second command should print only the headers (everything Running)
```

### 2.4. Retrieve service URLs + credentials

```bash
./.github/scripts/local-setup/show-services.sh
```

Write down (or keep visible):
- Kagenti UI: `http://kagenti-ui.localtest.me:8080`
- Keycloak admin: `http://keycloak.localtest.me:8080`
- **alice's password** (workshop user)
- Keycloak admin password

---

## Phase 3 — Deploy the weather agent (CLI fast path, ~2 min)

The UI deployment flow builds from source (needs `--with-builds`, ~15 min).
The CLI scripts deploy pre-built images from `ghcr.io` — much faster, no build infra.

From inside the `kagenti/` repo:

```bash
# Three commands in parallel (run each in a separate terminal or use & + wait):
./.github/scripts/kagenti-operator/70-setup-team1-namespace.sh
./.github/scripts/kagenti-operator/74-deploy-weather-agent.sh
./.github/scripts/kagenti-operator/72-deploy-weather-tool.sh
```

### 3.1. Pre-edited source files

The deployment YAML at `kagenti/kagenti/examples/agents/weather_service_deployment.yaml`
has already been edited in this workspace with two fixes that are required on Kind:

| Env var | Upstream default | Workshop value |
|---|---|---|
| `LLM_API_BASE` | `http://dockerhost:11434/v1` | `http://host.docker.internal:11434/v1` |
| `LLM_MODEL` | `qwen2.5:3b` | `llama3.2:3b-instruct-fp16` |

If you have **freshly cloned** kagenti, you'll need to apply those edits manually:
```bash
# In kagenti/kagenti/examples/agents/weather_service_deployment.yaml
# Change the LLM_API_BASE and LLM_MODEL values as shown above.
```

> **Note:** `host.docker.internal` works on Docker Desktop *and* Rancher Desktop
> (dockerd mode). If using Podman, use `host.containers.internal`.

> **Heads-up — `kubectl patch` does NOT persist.** The kagenti-operator
> reconciles deployment env arrays and reverts strategic-merge patches.
> Fix at the source YAML, then redeploy. Or use `kubectl edit` (which
> the operator respects) if you must mutate the live deployment.

### 3.2. Verify

```bash
kubectl rollout status deployment/weather-service -n team1
kubectl get pod -n team1 -l app.kubernetes.io/name=weather-service -o yaml \
  | grep -E "LLM_API_BASE|LLM_MODEL" -A1
# Both values should reflect what's in the YAML
```

### 3.3. Confirm pods are up

```bash
kubectl get pods -n team1
# Expected: weather-service-XXX  3/3 Running   (agent + envoy-proxy + spiffe-helper)
#           weather-tool-XXX     1/1 Running
```

Should be ~3-4 minutes from running the scripts until both pods are Running.
The agent pod may show one `RESTARTS` count during startup — usually the agent
container retrying the Ollama connection. Benign if it stabilizes.

> **Note: AuthBridge port exclusion.** AuthBridge defaults `OUTBOUND_PORTS_EXCLUDE=8080`
> on the envoy-proxy sidecar. In practice, the chat works without adding `11434`
> (Ollama) — the default outbound `passthrough` policy handles unrouted
> destinations correctly. Skip unless you see odd LLM-call failures that look
> like proxy refusal (5xx from Envoy, connection resets). The env var is
> webhook-injected, not on the deployment spec.

---

## Phase 4 — Verify baseline demo works (~5 min)

### 4.1. Open the Kagenti UI

Direct chat URL:
```
http://kagenti-ui.localtest.me:8080/agents/team1/weather-service
```

Login with the credentials from `show-services.sh` output (Kagenti UI login —
typically `admin` plus a generated password). The chat session will run as
whichever Keycloak realm user is authenticated by the UI's OAuth flow (may
be `alice` if a realm user has been created, otherwise the UI admin).

### 4.2. Send a chat message

- Type: *"What's the weather in New York?"*
- Wait for the response (~5–15s on first call as Ollama warms the model).

If the agent replies with weather, baseline works. If it errors, see Troubleshooting.

---

## Phase 5 — Enable protocol parsers (~3 min)

The default AuthBridge pipeline only runs `jwt-validation` (inbound) and
`token-exchange` (outbound). For our demo we need the **parsers** running so
the LLM body lands in `pctx.Extensions.Inference` (which our future
`llm-pii-redactor` will read from) and abctl shows protocol events.

### 5.1. Pre-edited chart template

The Helm chart template at
`kagenti/charts/kagenti/templates/authbridge-template-configmaps.yaml` has
already been edited in this workspace to include the three parsers:
- `a2a-parser` (inbound)
- `mcp-parser` (outbound)
- `inference-parser` (outbound)

For a **fresh kagenti clone**, add those parser entries to the `pipeline:`
section of the `authbridge-runtime-config` ConfigMap in the chart template
before installing.

### 5.2. Apply the updated chart

The running cluster has the *old* template. Re-render and apply with Helm —
don't try to `kubectl patch` the live ConfigMap; the patch nukes the other
top-level keys (`mode:`, etc.) and the envoy-proxy fails to start.

From `kagenti/`:
```bash
helm upgrade kagenti charts/kagenti \
  -n kagenti-system \
  --reuse-values
```

Then propagate to `team1` (the operator should do this on its next reconcile;
if it doesn't pick it up quickly, copy directly):
```bash
kubectl get configmap authbridge-runtime-config -n kagenti-system -o yaml \
  | sed 's/namespace: kagenti-system/namespace: team1/' \
  | kubectl apply -f -
```

### 5.3. Restart the agent to pick up the new config

```bash
kubectl rollout restart deployment/weather-service -n team1
kubectl rollout status deployment/weather-service -n team1
```

**If the new pod hangs in `PodInitializing`** while the old one stays
Running, you've hit a containerd subpath-mount race on Rancher Desktop (old
pod holds the Secret subpath, new pod races to grab it). Force a clean cycle:
```bash
kubectl scale deployment weather-service -n team1 --replicas=0
kubectl wait --for=delete pod -n team1 -l app.kubernetes.io/name=weather-service --timeout=60s
kubectl scale deployment weather-service -n team1 --replicas=1
kubectl rollout status deployment/weather-service -n team1
```

---

## Phase 6 — Build and run abctl (~3 min)

`abctl` is the terminal UI for AuthBridge's session events — it's what shows
the plugin pipeline to the workshop audience.

### 6.1. Build

```bash
git clone https://github.com/kagenti/kagenti-extensions.git ~/kagenti-extensions
cd ~/kagenti-extensions/authbridge/cmd/abctl
go build .                                # requires Go ≥ 1.24, brew install go if needed
```

Produces a ~10 MB binary at `./abctl`.

### 6.2. Port-forward the agent's session API

abctl reads from `localhost:9094`. Forward the agent pod's port `9094` to it:

```bash
POD=$(kubectl get pod -n team1 -l app.kubernetes.io/name=weather-service \
  -o jsonpath='{.items[0].metadata.name}')
echo "Pod: $POD"
kubectl port-forward -n team1 "$POD" 9094:9094 &
sleep 2
```

**Verify before launching abctl** (saves debugging "connection refused" in the UI):
```bash
curl -s http://localhost:9094/v1/sessions
# Should return JSON: {"sessions":[...]} — possibly empty until a chat has been sent.
```

If the curl fails:
- Port-forward died → re-run the `kubectl port-forward` line above. (Common
  cause: an earlier port-forward survived the previous pod, then died when
  the pod cycled; `$POD` re-resolves to the current pod each time.)
- Curl works but JSON looks wrong → check `kubectl logs deployment/weather-service
  -n team1 -c envoy-proxy --tail=20` for AuthBridge boot errors.

### 6.3. Launch abctl

```bash
cd ~/kagenti-extensions/authbridge/cmd/abctl
./abctl
```

The TUI opens on the **Sessions** pane. Send a chat message in the Kagenti UI
("What's the weather in Chicago?") and watch the Sessions pane populate.
Press `Enter` on a session to see the **Events** pane — you should see `a2a`,
`mcp`, and `inf` protocol rows (these only appear because the parsers are
running; without Phase 5 you'd see only auth events).

Press `Tab` to switch to the **Pipeline** pane. You should see all five
plugins listed:
- inbound: `jwt-validation`, `a2a-parser`
- outbound: `token-exchange`, `mcp-parser`, `inference-parser`

**This is the baseline state — same as the published abctl demo.**

Keybindings: `↑↓` nav, `Enter` drill, `Tab` switch pane, `/` filter, `p` pause,
`q` quit. Press `?` in-app for the full list.

---

## Phase 7 — Bolt on `cpex-runtime` (workshop value-add)

Phase 1–6 is the baseline that ships with AuthBridge today. Phase 7 swaps
in a drop-in replacement sidecar image (`cpex-authbridge-envoy`) that
hosts the CPEX plugin runtime as one AuthBridge plugin, then enables it
via YAML.

```
AuthBridge pipeline (in agent pod, outbound):
  token-exchange  →  mcp-parser  →  inference-parser  →  cpex-runtime
                                                          │
                                                          ├─ llm-pii-redactor   (CPEX sub-plugin)
                                                          └─ scope-tool-gate    (CPEX sub-plugin)
```

To AuthBridge, `cpex-runtime` is a single Go plugin. Inside it, CPEX runs
its own configured Rust plugin chain — and emits one `pipeline.Invocation`
per CPEX sub-plugin so abctl's Pipeline pane shows them as native rows.

### 7.0. Prerequisites for the build

Two things must be in place before `docker build` succeeds.

**(a) `kagenti-extensions` checkout at the repo root.** The Dockerfile
copies `kagenti-extensions/authbridge/authlib/` into the build context,
and `integrations/authbridge/cpex-runtime/go.mod` has a `replace`
directive pointing at `../../../kagenti-extensions/authbridge/authlib`.
Both expect the upstream repo to be cloned **alongside the contextforge
crates**, NOT in `$HOME`:

```bash
# From the contextforge-plugins-framework repo root:
git clone https://github.com/kagenti/kagenti-extensions.git
# Pin to the release the runtime image is built from so the Go plugin
# interface matches the binary we're replacing:
cd kagenti-extensions && git checkout v0.5.0-rc.2 && cd ..
```

(If you already cloned it to `~/kagenti-extensions` for abctl in Phase 6,
either move that checkout in or do a second clone here — they're
independent.)

**(b) Apply the `content-length` listener patch** (until the upstream PR
lands). Without this, the PII redaction path returns HTTP 500 with
"mismatch between content length and the length of the mutated body" —
Envoy's ext_proc rejects body mutations whose length doesn't match the
original `Content-Length` header.

Edit `kagenti-extensions/authbridge/authlib/listener/extproc/server.go`,
find the `withBodyMutation` function (~line 716), and change:

```go
cr.HeaderMutation.RemoveHeaders = append(cr.HeaderMutation.RemoveHeaders, "content-encoding")
```

to:

```go
cr.HeaderMutation.RemoveHeaders = append(cr.HeaderMutation.RemoveHeaders,
    "content-encoding", "content-length")
```

A one-line fix. Tracked as a follow-up PR to kagenti-extensions; remove
this step once that lands.

### 7.1. Build the custom sidecar image

From the **`contextforge-plugins-framework` repo root** (NOT from a
subdirectory — the Dockerfile expects the workspace root as build context):

```bash
docker build -t cpex-authbridge-envoy:demo \
  -f integrations/authbridge/deploy/Dockerfile .
```

Multi-stage build: Rust 1.85 produces two staticlibs (`libkagenti_cpex_ffi.a`
+ `libcpex_ffi.a`), Go 1.25 with cgo links them into a single binary,
and the runtime stage is `ghcr.io/kagenti/kagenti-extensions/authbridge-envoy:v0.5.0-rc.2`
with our binary overwriting `/usr/local/bin/authbridge` (the image is
*named* `authbridge-envoy` but the binary inside is just `authbridge`).
First build ~3–5 min; subsequent builds are fast (layer cache).

```bash
docker images cpex-authbridge-envoy:demo
# Should show ~160 MB
```

### 7.2. Load into Kind

```bash
kind load docker-image cpex-authbridge-envoy:demo --name kagenti
docker exec kagenti-control-plane crictl images | grep cpex-authbridge-envoy
```

### 7.3. Swap the webhook-injected image

The agent's `envoy-proxy` container is webhook-injected by the
kagenti-controller-manager, not present in the deployment spec —
`kubectl set image deployment/...` will reject the request. The image
reference lives in the platform config ConfigMap. Patch it:

```bash
# Pause the controller so it doesn't fight our patch while we apply it:
kubectl scale deployment kagenti-controller-manager -n kagenti-system --replicas=0

# Read the current config, edit the envoyProxy line, re-apply:
kubectl get configmap kagenti-platform-config -n kagenti-system \
  -o jsonpath='{.data.config\.yaml}' > /tmp/platform.yaml

sed -i.bak \
  's|envoyProxy: ghcr.io/kagenti/kagenti-extensions/authbridge-envoy:.*|envoyProxy: cpex-authbridge-envoy:demo|' \
  /tmp/platform.yaml

kubectl create configmap kagenti-platform-config \
  --from-file=config.yaml=/tmp/platform.yaml -n kagenti-system \
  --dry-run=client -o yaml | kubectl apply -f -

# Bring the controller back up so the webhook can inject:
kubectl scale deployment kagenti-controller-manager -n kagenti-system --replicas=1
kubectl rollout status deployment/kagenti-controller-manager -n kagenti-system
```

### 7.4. Add `cpex-runtime` to the AuthBridge runtime config

Sample file lives at
[`integrations/authbridge/deploy/plugins.yaml`](integrations/authbridge/deploy/plugins.yaml).
Either `kubectl edit configmap authbridge-runtime-config -n team1` and
paste the `cpex-runtime` entry into the outbound list, or apply the full
sample:

```bash
kubectl create configmap authbridge-runtime-config -n team1 \
  --from-file=config.yaml=integrations/authbridge/deploy/plugins.yaml \
  --dry-run=client -o yaml | kubectl apply -f -
```

Note the `chain:` block under `cpex-runtime`'s `config:` — it lists CPEX
sub-plugins in order. Each entry's `name` must match a factory registered
in `integrations/authbridge/ffi/src/lib.rs`.

### 7.5. Cycle the agent pod to pick up image + config

Use `scale 0 → scale 1` rather than `rollout restart` — the latter races
the containerd subpath-mount cleanup for `/shared/client-secret.txt`:

```bash
kubectl scale deployment weather-service -n team1 --replicas=0
kubectl wait --for=delete pod -n team1 -l app.kubernetes.io/name=weather-service --timeout=60s
kubectl scale deployment weather-service -n team1 --replicas=1
kubectl rollout status deployment/weather-service -n team1
```

### 7.6. Verify the integration

In logs you should see CPEX initialize with its sub-plugins:

```bash
POD=$(kubectl get pod -n team1 -l app.kubernetes.io/name=weather-service -o jsonpath='{.items[0].metadata.name}')
kubectl logs -n team1 $POD -c envoy-proxy | grep -E "cpex|cpex-runtime"
# Should show:
#   cpex-runtime initialized   chain="[llm-pii-redactor scope-tool-gate]"   plugin_count=2
#   cpex-authbridge-envoy starting   mode=envoy-sidecar
```

### 7.7. Fire the demo events

Two scripts ship next to this guide for repeatable demo traffic. They
both `kubectl exec` into the weather-service agent container and POST a
single request — no UI, no Keycloak token needed. Useful for the
sanity-check dry-run before the audience is watching, and as the
fallback if the live Kagenti UI flow gets flaky.

```bash
# Make sure the port-forward is up (same as Phase 6)
POD=$(kubectl get pod -n team1 -l app.kubernetes.io/name=weather-service -o jsonpath='{.items[0].metadata.name}')
kubectl port-forward -n team1 "$POD" 9094:9094 &

# Then, from this directory:
./redaction.sh   # LLM call with PII — expect 200 + body rewrite
./deny.sh        # MCP tools/call for get_weather — expect 403
```

#### What you should see in abctl

Have abctl open (built and run in Phase 6) before firing. Each script
adds events to the `default` session.

**After `./redaction.sh`** — two new events in Sessions:

1. **Outbound `request`** event, host `host.docker.internal:11434`.
   - Pipeline pane rows:
     ```
     token-exchange     skip      no_matching_route
     inference-parser   observe   matched_llama3.2:3b-instruct-fp16
     cpex-runtime       modify    body_rewritten          ← redaction fired
     ```
   - Drill into the `cpex-runtime / modify` row. Detail pane shows:
     - `plugins.body-mutation`: `length_before`, `length_after`, and
       `sha256_before` / `sha256_after` — wire-level proof the bytes
       changed.
     - `plugins.cpex-runtime`: a `rewrites` array with the actual
       before/after text:
       ```
       before: "please email alice@corp.com the weather forecast"
       after:  "please email [REDACTED:email] the weather forecast"
       ```
     This is the projector moment — audience reads
     `alice@corp.com → [REDACTED:email]` directly.

2. **Outbound `response`** event, status `200`, from Ollama. Confirms
   the redacted body was accepted upstream.

**After `./deny.sh`** — one new event, phase `denied`:

   - Host: `weather-tool-mcp.team1.svc.cluster.local:8000`
   - Status: `403`
   - Pipeline pane rows:
     ```
     token-exchange     skip      no_matching_route
     mcp-parser         observe   matched_tools/call
     cpex-runtime       deny      missing required scope  ← scope-gate fired
     ```
   - Drill into the `cpex-runtime / deny` row. Detail pane shows the
     violation: code `policy.forbidden`, `tool: get_weather`,
     `required_scope: weather:read`.
   - HTTP response back to the caller:
     `{"error":"policy.forbidden","plugin":"cpex-runtime"}`.

#### About the inference field

A subtle thing the audience may ask: the `inference.messages[0].content`
on the modify event still shows the **original** prompt (with the email)
— not the redacted version. That's because `inference-parser` runs
**before** `cpex-runtime` in the chain; it snapshots the parsed prompt
at parse time, and `cpex-runtime` doesn't re-run the parser after
mutation. The `plugins.cpex-runtime.rewrites` and the body-mutation
sha256s are the authoritative records of what actually went out on the
wire.

Framing for the audience: *"We capture user intent in `inference`. We
prove the data egressing the trust boundary differs from intent via
`body-mutation` (hashes) and `cpex-runtime.rewrites` (the diff). Full
audit trail of both sides."*

#### Quick verify without abctl

If abctl isn't running and you just want to confirm the chain fired:

```bash
curl -s http://localhost:9094/v1/sessions/default \
  | python3 -c "import sys,json; d=json.load(sys.stdin)
out=[e for e in d['events'] if e.get('direction')=='outbound']
for e in out[-4:]:
    print('---', e.get('at'), 'phase=', e.get('phase'), 'status=', e.get('statusCode'))
    for inv in e.get('invocations',{}).get('outbound',[]):
        print(' ', inv['plugin'], inv['action'], inv.get('reason',''))"
```

#### Through the Kagenti UI (the actual demo path)

Type a chat message containing PII into the agent at
`http://kagenti-ui.localtest.me:8080/agents/team1/weather-service`. Something
like `What's the weather in NYC? My email is alice@corp.com`.

The LangGraph agent will:
1. Call the LLM to plan a reply → `cpex-runtime modify` fires on the LLM
   hook (PII redacted).
2. Call `get_weather` via MCP → `cpex-runtime deny` fires on the tool
   hook (scope-gate denies; agent reports tool failure back to the user).

Both Acts in one chat message. Watch abctl in real time alongside.

### Plugin behavior (as of 2026-05-16)

Both Rust sub-plugins are real:

- **`llm-pii-redactor`** (hook `cmf.llm_input`) — config `patterns: {name: regex}`
  is compiled at factory time; each request's Text/Thinking content parts
  are scanned and matches replaced with `[REDACTED:<name>]`. Returns
  `modify_payload` when matched, `allow` when not.

- **`scope-tool-gate`** (hook `cmf.tool_pre_invoke`) — config `tool_scopes: {tool: scope}`;
  reads `extensions.security.subject.permissions` (from `pctx.Identity.Scopes()`)
  and `extensions.mcp.tool.name` (from mcp-parser); denies with
  `policy.forbidden` (HTTP 403) when the required scope isn't in the
  subject's permissions. Tools with no policy entry pass through.

### Workshop demo arc (target)

**Act 1 — Baseline.** Phase 1–6. abctl shows the 5 native plugins.

**Act 2 — Swap the image.** Phase 7.1–7.3. Same pipeline UI, new sidecar
underneath. Plumbing in place but no behavior change.

**Act 3 — One YAML edit enables CPEX.** Phase 7.4. abctl gains a
`cpex-runtime` row with two expandable sub-invocations. Send the same
query — `llm-pii-redactor: modify` fires, Detail pane shows
`alice@corp.com` → `[REDACTED]` in the body diff. LLM egressed redacted.

**Act 4 — Scope deny.** Edit `tool_scopes` in the YAML to require a scope
the user doesn't have. Hot-reload (~60s). Same query →
`scope-tool-gate: deny`. 403 back to the caller.

**Landing message:** *Two new guardrails. One YAML edit. Same abctl
visibility you already have. No sidecar rebuild after `cpex-runtime`
ships.*

### Rollback

To go back to upstream:

```bash
# Restore envoyProxy in platform config
kubectl edit configmap kagenti-platform-config -n kagenti-system
# Change envoyProxy back to ghcr.io/kagenti/kagenti-extensions/authbridge-envoy:v0.5.0-rc.2

# Remove cpex-runtime entry from team1 runtime config
kubectl edit configmap authbridge-runtime-config -n team1

# Cycle pod
kubectl scale deployment weather-service -n team1 --replicas=0
kubectl wait --for=delete pod -n team1 -l app.kubernetes.io/name=weather-service --timeout=60s
kubectl scale deployment weather-service -n team1 --replicas=1
```

---

## Troubleshooting

### Pods stuck in `Pending` after install

VM is out of resources. Check `kubectl describe node` for `FailedScheduling`.
Bump Rancher/Docker Desktop VM allocation.

### Agent can't reach Ollama

Likely missing the patch from §3.1 or Ollama isn't running.

```bash
# From inside the agent pod:
kubectl exec -n team1 deployment/weather-service -c agent -- \
  curl -s http://host.docker.internal:11434/api/tags
```

If this fails: `host.docker.internal` doesn't resolve from inside Kind. The patch
in §3.1 is the standard fix. If Podman, use `host.containers.internal`.

### abctl shows `✗ failed`

Port-forward died. Re-run the `kubectl port-forward` command from §6.

### "Multiple session buckets per conversation" in abctl

Known issue — see [kagenti#1481](https://github.com/kagenti/kagenti/pull/1481).
Not blocking for the workshop.

### Inbound JWT fails with `audience mismatch`

The agent's Keycloak client registration didn't finish before the first request.
Wait 60s and retry, or:
```bash
kubectl logs deployment/weather-service -n team1 -c kagenti-client-registration
```
should show "Client registration complete!"

### Pod shows 3/4 ready (one sidecar failing)

```bash
kubectl describe pod -n team1 <pod-name>
```
Usually the `envoy-proxy` container is waiting on `/shared/client-id.txt` from
`kagenti-client-registration`. Same fix as above — wait or check logs.

---

## Cleanup

```bash
# Reset just the weather demo (keep the cluster):
kubectl delete deployment weather-service weather-tool -n team1
kubectl delete svc weather-service weather-tool-mcp -n team1

# Or nuke the whole cluster:
cd kagenti
scripts/kind/cleanup-kagenti.sh --destroy-cluster
```
