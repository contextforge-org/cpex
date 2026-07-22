# Benchmarking Guide

Step-by-step guide to running the CPEX WASM plugin performance benchmarks. This measures how much overhead the WASM sandbox adds compared to native plugin execution.

---

## What You'll Learn

After running these benchmarks, you'll know:

1. **How much slower is WASM than native?** — for identical workloads (noop, real computation, full extensions)
2. **How long does the first plugin load take?** — cold start includes WASM compilation
3. **Does the payload format matter?** — custom JSON payload vs structured WIT types
4. **How does concurrency scale?** — what happens when multiple requests hit the same plugin simultaneously

---

## Prerequisites

Before you start, make sure you have these installed:

```bash
# 1. Rust with the WASM target
rustup target add wasm32-wasip2

# 2. Python 3 + matplotlib (for chart generation — optional)
pip3 install matplotlib

# 3. Verify you're in the repository root
cd /path/to/contextforge-plugins-framework
```

---

## Step 1: Build the WASM Plugin Binaries

The benchmarks load pre-compiled `.wasm` binaries from the `wasm/` directory. You need to build them first.

**Easiest way (builds everything):**

```bash
cd crates/cpex-wasm-host
make build-all-plugins build-bench-plugins build-test-plugins
```

This builds:
- `noop.wasm` — does nothing, returns immediately (measures pure sandbox overhead)
- `compute-bench.wasm` — does real work: JSON parsing, string manipulation, hash computation
- `tool-invoke-checker.wasm` — handles a custom payload type (measures the JSON serde path)
- All other plugin binaries needed for the full benchmark suite

**Manual way (if you only want specific benchmarks):**

```bash
cd crates/cpex-wasm-plugin

# For invocation.rs benchmarks (overhead measurement)
cargo build --target wasm32-wasip2 --release --features noop --no-default-features
cp target/wasm32-wasip2/release/cpex_wasm_plugin.wasm ../cpex-wasm-host/wasm/noop.wasm

# For comprehensive.rs benchmarks (real-work comparison)
cargo build --target wasm32-wasip2 --release --features compute-bench --no-default-features
cp target/wasm32-wasip2/release/cpex_wasm_plugin.wasm ../cpex-wasm-host/wasm/compute-bench.wasm

# For custom payload benchmark
cargo build --target wasm32-wasip2 --release --features tool-invoke-checker --no-default-features
cp target/wasm32-wasip2/release/cpex_wasm_plugin.wasm ../cpex-wasm-host/wasm/tool-invoke-checker.wasm
```

---

## Step 2: Run the Benchmarks

From the repository root (or `crates/cpex-wasm-host`):

```bash
# Run ALL benchmarks (both suites)
cargo bench -p cpex-wasm-host
```

This runs two benchmark suites:

### Suite 1: `invocation` — Measures sandbox overhead

| Benchmark | What it measures |
|-----------|-----------------|
| `native_noop` | Baseline: calling a native handler directly (no sandbox) |
| `native_with_full_extensions` | Native handler with realistic extensions (security + HTTP) |
| `conversion_native_to_wit` | Just the type conversion cost (native types → WIT types) |
| `wasm_noop` | Full WASM round-trip with minimal payload (pure overhead) |
| `wasm_with_full_extensions` | Full WASM round-trip with realistic extensions |

### Suite 2: `comprehensive` — Measures real-world scenarios

| Benchmark | What it measures |
|-----------|-----------------|
| `cold_start_wasm` | Time to load a `.wasm` file + compile it + run the first call |
| `compute_native` | Native handler doing real work (JSON parse + string ops + hash) |
| `compute_wasm` | Same real work through the WASM sandbox |
| `custom_payload_wasm` | User-defined payload via JSON serde (`HookPayload::Custom`) |
| `structured_payload_wasm` | Built-in CMF payload via WIT types (`HookPayload::Cmf`) |
| `concurrent_contention/1` | 1 task calling the sandbox (baseline) |
| `concurrent_contention/4` | 4 tasks contending on the same sandbox mutex |
| `concurrent_contention/8` | 8 tasks contending on the same sandbox mutex |

**To run just one suite:**

```bash
cargo bench -p cpex-wasm-host --bench invocation
cargo bench -p cpex-wasm-host --bench comprehensive
```

**To run a specific benchmark:**

```bash
cargo bench -p cpex-wasm-host -- compute_native
cargo bench -p cpex-wasm-host -- cold_start
```

---

## Step 3: Read the Results

Criterion prints results to the terminal like this:

```
compute_native          time:   [870 ns 874 ns 878 ns]
compute_wasm            time:   [10.4 µs 10.5 µs 10.6 µs]
```

The three numbers are: [lower bound, median, upper bound] of the 95% confidence interval.

**How to interpret:**
- `compute_native: 874 ns` = calling the handler natively takes ~874 nanoseconds
- `compute_wasm: 10.5 µs` = same work through WASM takes ~10,500 nanoseconds
- Ratio: 10,500 / 874 = **~12x overhead** for the sandbox

### HTML Reports

Criterion also generates detailed HTML reports with histograms and regression analysis:

```bash
open target/criterion/report/index.html
```

Each benchmark has its own page with:
- Distribution plot (how spread out the measurements are)
- Regression comparison (if you've run before, shows improvement/regression)
- Outlier analysis

---

## Step 4: Generate the Comparison Chart (Optional)

A Python script reads Criterion's JSON output and produces a visual bar chart:

```bash
cd crates/cpex-wasm-host/benchmarking
python3 plot_results.py
```

This produces `performance_comparison.png` in the same directory — a 3-panel chart showing:
1. Native vs WASM for identical workloads (log scale)
2. Payload path cost + cold start
3. Mutex contention scaling

**Requirements:** Python 3 + matplotlib (`pip3 install matplotlib`)

---

## Step 5: One-Command Full Run (Recommended)

If you just want to do everything at once:

```bash
cd crates/cpex-wasm-host
make bench-all
```

This:
1. Builds all WASM plugin binaries (demo + bench + test plugins)
2. Runs both benchmark suites
3. Generates the performance comparison chart

---

## Understanding the Results

### What the numbers mean for your use case

| Your scenario | Plugin calls per request | WASM overhead | Request latency | Impact |
|---------------|:-----------------------:|:-------------:|:---------------:|:------:|
| LLM tool invoke | 2-4 calls | 20-40 µs | 200ms - 2s | **< 0.02%** |
| HTTP API gateway | 3-6 calls | 30-60 µs | 5-50ms | **0.06-1.2%** |
| Real-time streaming | 100+ calls | 500µs+ | per-token | **Consider native** |

### Key takeaways

- **WASM is 12-120x slower than native** depending on workload and extensions size
- **Cold start is ~550ms** — load plugins at startup, not per-request
- **Custom payload vs structured**: nearly identical cost (~5µs each) — JSON serde is not a bottleneck
- **Mutex contention**: per-call latency stays flat as tasks increase (the mutex serializes, but each call is fast)
- **For typical usage** (2-4 plugin calls per 200ms+ LLM request): overhead is invisible

### When to choose WASM vs native

| Choose WASM when... | Choose native when... |
|--------------------|-----------------------|
| Running untrusted/third-party plugins | Running your own trusted code |
| Multi-tenant isolation is required | Per-call latency is critical (<1µs) |
| You need resource limits (fuel, memory, timeout) | You need async I/O in the plugin |
| Plugins should not access filesystem/network | Plugins need streaming/per-token hooks |

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `SKIP: noop.wasm not found` | Run `make build-all-plugins build-bench-plugins build-test-plugins` |
| `SKIP: compute-bench.wasm not found` | Run `make build-bench-plugins` |
| Benchmark numbers vary wildly | Close other apps, disable Turbo Boost, run multiple times |
| `cargo bench` shows "0 benchmarks" | Make sure you're running from the workspace root or using `-p cpex-wasm-host` |
| `python3 plot_results.py` fails | Install matplotlib: `pip3 install matplotlib` |
| Chart shows "No benchmark results found" | Run `cargo bench -p cpex-wasm-host` first to generate Criterion data |

---

## File Reference

| File | Purpose |
|------|---------|
| `invocation.rs` | Benchmark suite 1: measures framework overhead (sandbox crossing cost) |
| `comprehensive.rs` | Benchmark suite 2: measures real-world scenarios (compute, cold start, contention) |
| `plot_results.py` | Reads Criterion JSON output, generates `performance_comparison.png` |
| `performance_comparison.png` | Generated chart — commit this to show results in README |
