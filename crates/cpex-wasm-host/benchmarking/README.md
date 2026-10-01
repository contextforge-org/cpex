# Benchmarking

Performance measurements for WASM plugin execution compared to native in-process plugins.

## Test environment

| Parameter | Value |
|-----------|-------|
| CPU | Apple M4 Max |
| RAM | 64 GB |
| Rust | 1.96.0 |
| Wasmtime | 46.0 |
| OS | macOS (ARM64) |

## Results summary

| Scenario | Latency | vs Native |
|----------|---------|-----------|
| Native no-op | 96 ns | 1× |
| Native with full extensions | 95 ns | 1× |
| Native compute | 884 ns | 9.2× |
| Type conversion (Native → WIT) | 877 ns | 9.1× |
| WASM no-op | 5.7 μs | 59× |
| Custom payload (JSON serde) | 5.8 μs | 60× |
| Structured payload (WIT types) | 6.2 μs | 64× |
| WASM with full extensions | 8.9 μs | 93× |
| WASM compute | 10.9 μs | 113× |
| Cold start (compile + first call) | 513 ms | one-time |

### Key takeaways

- **WASM is 59-113× slower** than native depending on workload complexity
- **Cold start is ~513ms** (one-time per plugin; amortized over the process lifetime)
- **Custom vs structured payload**: nearly identical (~6μs each); the serialization format doesn't dominate
- **Type conversion alone costs ~877ns** — roughly half the overhead is in Native ↔ WIT marshalling
- **Full extensions add ~3μs** over no-op (8.9μs vs 5.7μs) — proportional to the number of populated fields

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
| `cold_start_wasm` | WASM module load + compile + first invocation (includes epoch ticker thread spawn) |
| `compute_native` | Native plugin doing JSON parsing + string ops + FNV-1a hash |
| `compute_wasm` | Same workload inside the WASM sandbox |
| `custom_payload_wasm` | Round-trip with JSON-serialized custom payload via `PayloadSerializerRegistry` |
| `structured_payload_wasm` | Round-trip with WIT-typed `MessagePayload` (uses `native_payload_to_wit` conversion) |
| `concurrent_contention/N` | Throughput under concurrent access (N = 1, 4, 8 tasks) |

## Running benchmarks

### Prerequisites

```bash
cd crates/cpex-wasm-host

# Build all required plugins:
#   - compute-bench.wasm (BENCH_PLUGINS)
#   - noop.wasm (TEST_PLUGINS — used by invocation benchmarks)
#   - tool-invoke-checker.wasm (DEMO_PLUGINS — used by custom_payload_wasm)
make build-bench-plugins build-test-plugins build-all-plugins
```

### Run all benchmarks

```bash
make bench-all
```

This builds all required plugins, runs `cargo bench`, and generates a comparison chart via `plot_results.py`.

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
Total: ~5.7 μs
├── Fuel reset + epoch deadline:  ~0.1 μs
├── Native → WIT conversion:     ~1.8 μs
├── WASM function call overhead:  ~1.8 μs
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

The sandbox overhead is negligible compared to LLM inference and network latency in real deployments.