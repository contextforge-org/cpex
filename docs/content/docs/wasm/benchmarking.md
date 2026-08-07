---
title: "Benchmarking"
weight: 60
---

# Benchmarking

Performance measurements for WASM plugin execution compared to native in-process plugins.

## Test environment

| Parameter | Value |
|-----------|-------|
| CPU | Apple M4 Max |
| RAM | 64 GB |
| Rust | 1.96.0 |
| Wasmtime | 45.0 |
| OS | macOS (ARM64) |

## Results summary

| Scenario | Latency | vs Native |
|----------|---------|-----------|
| Native no-op | 87 ns | 1× |
| Native compute | 874 ns | 10× |
| WASM no-op | 5.1 μs | 58× |
| WASM compute | 10.5 μs | 120× |
| Custom payload (JSON serde) | 5.3 μs | 61× |
| Structured payload (WIT types) | 5.6 μs | 64× |
| Cold start (compile + first call) | 547 ms | one-time |

### Key takeaways

- **WASM is 12-120× slower** than native depending on workload complexity
- **Cold start is ~550ms** (one-time per plugin; amortized over the process lifetime)
- **Custom vs structured payload**: nearly identical (~5μs each); the serialization format doesn't dominate
- **For typical LLM tool invoke** (2-4 plugin calls per 200ms+ LLM request): sandbox overhead is **0.01-0.02%** of total request time

## Benchmark suites

### Invocation overhead (`benchmarking/invocation.rs`)

Isolates the sandbox overhead by comparing equivalent operations:

| Benchmark | What it measures |
|-----------|-----------------|
| `native_noop` | Baseline: calling a native no-op handler directly |
| `native_with_full_extensions` | Native no-op with realistic extensions (12 types populated) |
| `conversion_native_to_wit` | Type conversion cost alone (no WASM execution) |
| `wasm_noop` | Full WASM round-trip: convert → sandbox → convert back |
| `wasm_with_full_extensions` | Full round-trip with realistic extensions |

### Comprehensive suite (`benchmarking/comprehensive.rs`)

End-to-end measurements including real computation:

| Benchmark | What it measures |
|-----------|-----------------|
| `cold_start` | WASM module load + compile + first invocation |
| `real_compute_native` | Native plugin doing JSON parsing + string ops + FNV-1a hash |
| `real_compute_wasm` | Same workload inside the WASM sandbox |
| `custom_payload` | Round-trip with JSON-serialized custom payload |
| `structured_payload` | Round-trip with WIT-typed `MessagePayload` |
| `mutex_contention_N` | Throughput under concurrent access (1, 4, 8 tasks) |

## Running benchmarks

### Prerequisites

```bash
cd crates/cpex-wasm-host
make build-bench-plugins   # Compiles compute-bench.wasm
```

### Run all benchmarks

```bash
make bench-all
```

This runs `cargo bench -p cpex-wasm-host` and generates a comparison chart via `plot_results.py`.

### Run individually

```bash
cargo bench -p cpex-wasm-host -- invocation
cargo bench -p cpex-wasm-host -- comprehensive
```

### Generate chart

```bash
python3 benchmarking/plot_results.py
# Outputs: benchmarking/performance_comparison.png
```

## Interpreting results

### Where the time goes (WASM no-op breakdown)

```
Total: ~5.1 μs
├── Fuel reset + epoch deadline:  ~0.1 μs
├── Native → WIT conversion:     ~1.5 μs
├── WASM function call overhead:  ~1.5 μs
├── WIT → Native conversion:     ~1.5 μs
└── Capability validation:        ~0.5 μs
```

### When to use WASM vs native

| Use WASM when | Use native when |
|---------------|-----------------|
| Plugin is third-party or untrusted | Plugin is first-party, same repo |
| Multi-language support needed | Performance is critical (sub-microsecond) |
| Audit/compliance requires sandboxing | Plugin needs shared memory with host |
| Plugin count is high (isolation per plugin) | Cold start budget is zero |

### Practical impact

For a typical agentic workflow:

```
LLM inference:     200-2000 ms
Network I/O:       50-500 ms
WASM plugin (×3):  15 μs total
─────────────────────────────
Plugin overhead:   0.003-0.06% of request
```

The sandbox overhead is negligible compared to LLM inference and network latency in real deployments.

## Mutex contention

The `SharedEngine` uses `Arc<Mutex<SandboxManager>>` for thread safety. Under concurrent load:

| Concurrent tasks | Throughput | Notes |
|-----------------|------------|-------|
| 1 | ~195k ops/sec | No contention |
| 4 | ~180k ops/sec | Minimal degradation |
| 8 | ~165k ops/sec | Lock wait becomes measurable |

For high-concurrency deployments, consider one `SandboxManager` per thread or a pool of pre-warmed instances.
