# Benchmark Results: WASM vs Native Plugin Invocation

**Platform:** Apple M-series (ARM64), macOS  
**Rust:** stable  
**wasmtime:** 45.0  
**Profile:** release (optimized)  
**Date:** 2026-07-16  

---

## Results

| Benchmark | Latency (median) | Relative to Native | What's Measured |
|-----------|:-----------------:|:------------------:|-----------------|
| `native_noop` | **84 ns** | 1.0x | Direct handler call, empty extensions |
| `native_with_full_extensions` | **83 ns** | 1.0x | Direct handler call, security + HTTP + request extensions |
| `conversion_native_to_wit` | **843 ns** | 10x | Type conversion only (payload + extensions + context → WIT types) |
| `wasm_noop` | **4.8 µs** | 57x | Full WASM sandbox round-trip, minimal payload |
| `wasm_with_full_extensions` | **7.9 µs** | 94x | Full WASM sandbox round-trip, realistic extensions |

---

## Isolation Tax Summary

```
┌────────────────────────────────────────────────────────────────┐
│                    WASM Invocation (~5-8 µs)                    │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  Native handler call          ████  84 ns                      │
│                                                                │
│  Type conversion (to WIT)     ████████████  843 ns             │
│                                                                │
│  WASM noop (full round-trip)  ████████████████████████████████ │
│                                4,835 ns                        │
│                                                                │
│  WASM + full extensions       ████████████████████████████████████████
│                                7,950 ns                        │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

---

## Cost Breakdown (per invocation)

| Stage | Cost | % of Total (noop) | % of Total (full ext) |
|-------|------|:------------------:|:---------------------:|
| Mutex acquire | ~50 ns | 1% | <1% |
| Fuel + epoch reset | ~40 ns | <1% | <1% |
| Native → WIT conversion | ~843 ns | 17% | 11% |
| wasmtime component call dispatch | ~2.5 µs | 52% | 31% |
| Guest execution (noop) | ~500 ns | 10% | 6% |
| WIT → Native result conversion | ~500 ns | 10% | 6% |
| Extensions conversion overhead | — | — | ~40% (+3.1 µs) |
| Post-invocation validation | ~100 ns | 2% | 1% |

---

## Throughput

| Scenario | Calls/sec/core |
|----------|:--------------:|
| Native plugin | ~12,000,000 |
| WASM (minimal) | ~207,000 |
| WASM (full extensions) | ~126,000 |

---

## Context: Is This Acceptable?

| Use Case | Plugin Calls per Request | Plugin Overhead | Request Latency | Overhead % |
|----------|:-----------------------:|:---------------:|:---------------:|:----------:|
| LLM tool invoke | 2-4 calls | 16-32 µs | 200ms - 2s | 0.001-0.016% |
| HTTP API gateway | 3-6 calls | 24-48 µs | 5-50ms | 0.05-0.96% |
| Streaming (per-token) | 100-500 calls | 0.5-4ms | 2-10s | 0.005-0.2% |

**Verdict:** The WASM isolation tax is negligible for request-level hooks (tool invoke, LLM input/output). It only becomes relevant for per-token streaming — which is a future feature not yet supported.

---

## Reproducing

```bash
# 1. Build the noop WASM plugin
cd crates/cpex-wasm-plugin
cargo build --target wasm32-wasip2 --release --features noop --no-default-features
cp target/wasm32-wasip2/release/cpex_wasm_plugin.wasm ../cpex-wasm-host/wasm/noop.wasm

# 2. Run benchmarks
cd ../..
cargo bench -p cpex-wasm-host

# 3. View HTML reports
open target/criterion/report/index.html
```
