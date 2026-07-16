# WASM Plugin Benchmarks

Performance benchmarks comparing native plugin invocation vs WASM sandbox execution. Measures the isolation tax of the WASM boundary.

## Running

```bash
# From workspace root
cargo bench -p cpex-wasm-host
```

Results are saved to `target/criterion/` with HTML reports.

## Prerequisites

The `noop.wasm` plugin binary must exist at `crates/cpex-wasm-host/wasm/noop.wasm`. Build it with:

```bash
cd crates/cpex-wasm-plugin
cargo build --target wasm32-wasip2 --release --features noop --no-default-features
cp target/wasm32-wasip2/release/cpex_wasm_plugin.wasm ../cpex-wasm-host/wasm/noop.wasm
```

If the binary is missing, WASM benchmarks are skipped with a message.

## What's Measured

| Benchmark | What it does |
|-----------|-------------|
| `native_noop` | Call a native `HookHandler` that returns `allow()` immediately. Baseline. |
| `native_with_full_extensions` | Same handler, but extensions include security labels + HTTP headers + request metadata. Shows that native calls are zero-cost reference passes. |
| `conversion_native_to_wit` | Convert payload + extensions + context from native types to WIT types. Measures serialization overhead without WASM execution. |
| `wasm_noop` | Full WASM round-trip: acquire mutex, reset fuel, reset epoch, convert to WIT, call guest `handle-hook`, convert result back. Minimal payload, empty extensions. |
| `wasm_with_full_extensions` | Full WASM round-trip with security labels, HTTP headers, and request metadata populated. Measures conversion cost at realistic payload sizes. |

## Typical Results

On Apple M-series (ARM64), release mode:

| Benchmark | Latency | Relative |
|-----------|---------|----------|
| `native_noop` | ~86 ns | 1x |
| `native_with_full_extensions` | ~86 ns | 1x |
| `conversion_native_to_wit` | ~860 ns | 10x |
| `wasm_noop` | ~5.0 µs | 58x |
| `wasm_with_full_extensions` | ~8.1 µs | 94x |

## Interpreting Results

- **5-8 µs per WASM invocation** means ~125,000 plugin calls/second/core — sufficient for most production workloads.
- **The conversion cost (~860 ns)** accounts for 10-17% of total WASM call time. The rest is wasmtime dispatch overhead (fuel reset, epoch deadline, component call).
- **Extensions add ~3 µs** (8.1 vs 5.0) proportional to the number of fields being converted (HashMap clones, String allocations, JSON serialization for complex fields).
- **Native calls are effectively free** (~86 ns) because extensions are passed by reference, not copied.

## Cost Breakdown (approximate)

```
WASM invocation (~5-8 µs total):
  ├── Mutex acquire:        ~50 ns
  ├── Fuel reset:           ~20 ns
  ├── Epoch deadline reset: ~20 ns
  ├── Type conversion:      ~860 ns (grows with payload complexity)
  ├── Wasmtime dispatch:    ~2-3 µs (component call overhead)
  ├── Guest execution:      ~500 ns (for noop)
  └── Result conversion:    ~500 ns - 2 µs (grows with modifications)
```

## Adding New Benchmarks

Add functions to `invocation.rs` following the existing pattern:

```rust
fn bench_my_scenario(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    // setup outside measurement...

    c.bench_function("my_scenario", |b| {
        b.to_async(&rt).iter(|| async {
            // measured code here
            black_box(result);
        });
    });
}
```

Then add to the `criterion_group!` macro at the bottom of the file.

## Comparing Across Runs

Criterion automatically detects regressions. After establishing a baseline:

```bash
# First run establishes baseline
cargo bench -p cpex-wasm-host

# Make changes, then re-run — Criterion reports % change
cargo bench -p cpex-wasm-host
```

Look for lines like:
```
wasm_noop   time: [5.0 µs 5.1 µs 5.2 µs]
            change: [+2.1% +3.5% +4.8%] (p = 0.02 < 0.05)
            Performance has regressed.
```
