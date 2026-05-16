# Deploying cpex-authbridge-envoy

The integration's runtime artifact is a custom `cpex-authbridge-envoy`
container image — a drop-in replacement for upstream's
`ghcr.io/kagenti/kagenti-extensions/authbridge-envoy` that bundles the
`cpex-runtime` plugin (and the Rust CPEX sub-plugins it loads).

Prerequisites:
- Kagenti baseline cluster already up (see `../demo-quickstart.md`,
  Phases 1–6). Weather agent must already be working with the upstream
  AuthBridge image.
- Docker / Podman / Rancher Desktop able to build images.
- `kind` CLI in `$PATH`.

---

## 1. Build the image

From the **contextforge-plugins-framework repo root** (NOT from this
directory — the Dockerfile expects the workspace root as build context):

```bash
docker build -t cpex-authbridge-envoy:demo \
  -f integrations/authbridge/deploy/Dockerfile .
```

First build takes ~3-5 min (Rust compilation dominates). Subsequent
builds are fast thanks to Docker layer caching.

Verify the image:
```bash
docker images cpex-authbridge-envoy:demo
# Should show ~150-200 MB image (UBI9-micro base + Envoy + spiffe-helper + our binary)
```

---

## 2. Load into the Kind cluster

```bash
kind load docker-image cpex-authbridge-envoy:demo --name kagenti
```

Verify the image is present on the cluster's node:
```bash
docker exec -it kagenti-control-plane crictl images | grep cpex-authbridge-envoy
```

---

## 3. Swap the agent's envoy-proxy image

The simplest path — patch the live deployment:

```bash
kubectl set image deployment/weather-service -n team1 \
  envoy-proxy=cpex-authbridge-envoy:demo
kubectl rollout status deployment/weather-service -n team1
```

> **Heads-up — kagenti-operator may reconcile this.** If you see the
> image revert to the upstream tag after a few seconds, the operator is
> overwriting our patch. Two ways around it:
>
> 1. **Quick demo hack:** scale the operator to 0 replicas while you
>    demo, so it can't reconcile:
>    ```bash
>    kubectl scale deployment kagenti-operator -n kagenti-system --replicas=0
>    # ... after demo:
>    kubectl scale deployment kagenti-operator -n kagenti-system --replicas=1
>    ```
> 2. **Proper fix:** find where the operator templates the envoy-proxy
>    image (likely in the kagenti Helm chart's `authBridge.image` value
>    or similar) and `helm upgrade` with the override. We took the same
>    approach for `LLM_API_BASE` in the quickstart — see Phase 3.

---

## 4. Enable cpex-runtime in the AuthBridge config

Even with our image swapped in, cpex-runtime doesn't actually do anything
until the YAML config names it. Edit the agent's runtime config:

```bash
kubectl edit configmap authbridge-runtime-config -n team1
```

Find the outbound pipeline section and add the cpex-runtime entry from
[`plugins.yaml`](./plugins.yaml). The full file in this directory has
the canonical sample.

> **Hot reload note:** AuthBridge's reloader picks up ConfigMap changes
> within ~60s (kubelet sync interval). If you want the change to take
> effect immediately, force a pod cycle:
> ```bash
> kubectl scale deployment weather-service -n team1 --replicas=0
> kubectl wait --for=delete pod -n team1 -l app.kubernetes.io/name=weather-service --timeout=60s
> kubectl scale deployment weather-service -n team1 --replicas=1
> ```

---

## 5. Verify in abctl

Send another chat message through the Kagenti UI:

```
http://kagenti-ui.localtest.me:8080/agents/team1/weather-service
```

In abctl's Pipeline pane, the outbound chain should now include
`cpex-runtime` as a row alongside the standard plugins. In the Events
pane, each outbound request should show an `observe / v0_stub` Invocation
for cpex-runtime (the v0 stub doesn't actually do anything yet — it
just demonstrates the plumbing).

When the real plugin logic lands:
- A query containing `alice@corp.com` will show `cpex-runtime → llm-pii-redactor / modify` and the Detail pane will show the body diff.
- A query for `get_weather` from a user lacking `weather:read` scope will show `cpex-runtime → scope-tool-gate / deny` and a 403 back to the caller.

---

## Troubleshooting

### Build fails in stage 1 with "cargo: command not found"
Likely on a system without docker buildkit or with an unusual platform.
Confirm `rust:1.75-bookworm` pulls correctly and that the Dockerfile is
parsed (no Windows line-endings introduced by an editor).

### Build fails in stage 2 with "missing libkagenti_cpex_ffi.a"
Stage 1 didn't produce the artifact. Check `cargo build -p kagenti-cpex-ffi`
runs cleanly from the workspace root; if so, the issue is that the
COPY paths in stage 2 don't match where stage 1 put the .a.

### Pod stays in `ImagePullBackOff`
The image is locally tagged but Kubernetes thinks it should pull from a
registry. Check the deployment's `imagePullPolicy` — it should be
`IfNotPresent` (default) when using `kind load`. If it's `Always`,
either patch the deployment or rebuild with a registry tag.

### cpex-runtime crashes with "kagenti_cpex_register_factories returned -1"
Our FFI got a NULL manager handle. Likely a corrupted .a file or a
glibc/musl mismatch between the Rust build and the runtime image. Try
rebuilding with `--no-cache` to force fresh stages.

### abctl shows the plugin but no Invocations
The `cpex-runtime` row is in the Pipeline pane but the Events column
shows zero. Means our plugin is registered but its OnRequest never
fires. Check the AuthBridge config — did the chain entry actually
include `cpex-runtime`? `kubectl get configmap authbridge-runtime-config
-n team1 -o yaml | grep cpex-runtime` should print exactly one match.

### "cpex-runtime: invalid config" at pod startup
The YAML decode failed. Check that the `chain:` block under
cpex-runtime's `config:` is present and has at least one entry. The
plugin uses `DisallowUnknownFields` so misspelled keys cause loud failure
at boot rather than silent ignore.

---

## Cleanup

```bash
# Revert the image swap:
kubectl set image deployment/weather-service -n team1 \
  envoy-proxy=ghcr.io/kagenti/kagenti-extensions/authbridge-envoy:v0.5.0-rc.2

# Remove the cpex-runtime entry from the ConfigMap.
kubectl edit configmap authbridge-runtime-config -n team1

# Restart to pick up the reverted config.
kubectl rollout restart deployment/weather-service -n team1
```
