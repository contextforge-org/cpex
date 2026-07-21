#!/usr/bin/env python3
"""
Performance comparison chart generator for CPEX WASM benchmarks.

Reads Criterion JSON output and produces a grouped bar chart comparing
native vs WASM performance across scenarios.

Usage:
    cd crates/cpex-wasm-host/benchmarking
    python3 plot_results.py

Requires: matplotlib (pip install matplotlib)

Output: performance_comparison.png
"""

import json
import os
import sys
from pathlib import Path

try:
    import matplotlib.pyplot as plt
    import matplotlib.ticker as ticker
except ImportError:
    print("Error: matplotlib is required. Install with: pip install matplotlib")
    sys.exit(1)


def find_criterion_dir():
    """Find the Criterion output directory."""
    candidates = [
        Path("../../../target/criterion"),
        Path("../../target/criterion"),
        Path("target/criterion"),
    ]
    for c in candidates:
        if c.exists():
            return c.resolve()
    return None


def read_estimate(criterion_dir, bench_name):
    """Read the median estimate (in nanoseconds) for a benchmark."""
    estimate_path = criterion_dir / bench_name / "new" / "estimates.json"
    if not estimate_path.exists():
        # Try group format (concurrent_contention/N)
        return None
    with open(estimate_path) as f:
        data = json.load(f)
    return data["median"]["point_estimate"]


def read_group_estimates(criterion_dir, group_name):
    """Read estimates for a benchmark group (e.g., concurrent_contention/1, /4, /8)."""
    results = {}
    group_dir = criterion_dir / group_name
    if not group_dir.exists():
        return results
    for entry in sorted(group_dir.iterdir()):
        if entry.is_dir() and entry.name != "report":
            estimate_path = entry / "new" / "estimates.json"
            if estimate_path.exists():
                with open(estimate_path) as f:
                    data = json.load(f)
                results[entry.name] = data["median"]["point_estimate"]
    return results


def format_time(ns):
    """Format nanoseconds to human-readable string."""
    if ns >= 1_000_000:
        return f"{ns / 1_000_000:.1f} ms"
    elif ns >= 1_000:
        return f"{ns / 1_000:.1f} µs"
    else:
        return f"{ns:.0f} ns"


def main():
    criterion_dir = find_criterion_dir()
    if criterion_dir is None:
        print("Error: Criterion output not found. Run benchmarks first:")
        print("  cargo bench -p cpex-wasm-host")
        sys.exit(1)

    print(f"Reading from: {criterion_dir}\n")

    # --- Collect results ---
    benchmarks = {
        # From invocation.rs
        "native_noop": read_estimate(criterion_dir, "native_noop"),
        "native_with_full_extensions": read_estimate(criterion_dir, "native_with_full_extensions"),
        "conversion_native_to_wit": read_estimate(criterion_dir, "conversion_native_to_wit"),
        "wasm_noop": read_estimate(criterion_dir, "wasm_noop"),
        "wasm_with_full_extensions": read_estimate(criterion_dir, "wasm_with_full_extensions"),
        # From comprehensive.rs
        "cold_start_wasm": read_estimate(criterion_dir, "cold_start_wasm"),
        "compute_native": read_estimate(criterion_dir, "compute_native"),
        "compute_wasm": read_estimate(criterion_dir, "compute_wasm"),
        "custom_payload_wasm": read_estimate(criterion_dir, "custom_payload_wasm"),
        "structured_payload_wasm": read_estimate(criterion_dir, "structured_payload_wasm"),
    }

    contention = read_group_estimates(criterion_dir, "concurrent_contention")

    # Filter out None values
    available = {k: v for k, v in benchmarks.items() if v is not None}

    if not available:
        print("Error: No benchmark results found. Run benchmarks first:")
        print("  cargo bench -p cpex-wasm-host")
        sys.exit(1)

    # --- Print ASCII table ---
    print("=" * 70)
    print(f"{'Benchmark':<35} {'Latency':>12} {'vs Native':>12}")
    print("-" * 70)

    native_noop = available.get("native_noop", 84)
    for name, ns in sorted(available.items(), key=lambda x: x[1]):
        ratio = ns / native_noop if native_noop else 0
        print(f"  {name:<33} {format_time(ns):>12} {ratio:>10.1f}x")

    if contention:
        print()
        print("  Concurrent contention:")
        for tasks, ns in sorted(contention.items(), key=lambda x: int(x[0])):
            print(f"    {tasks} tasks: {format_time(ns):>12}")

    print("=" * 70)

    # --- Generate chart ---
    fig, axes = plt.subplots(1, 3, figsize=(16, 6))
    fig.suptitle("CPEX WASM Plugin Performance", fontsize=14, fontweight="bold")

    # Panel 1: "How much slower is WASM than native?"
    ax1 = axes[0]
    comparison_pairs = []

    if "native_noop" in available and "wasm_noop" in available:
        comparison_pairs.append(("Noop\n(sandbox overhead)", available["native_noop"], available["wasm_noop"]))
    if "compute_native" in available and "compute_wasm" in available:
        comparison_pairs.append(("Real Work\n(JSON + hash)", available["compute_native"], available["compute_wasm"]))
    if "native_with_full_extensions" in available and "wasm_with_full_extensions" in available:
        comparison_pairs.append(("Full Extensions\n(production-like)", available["native_with_full_extensions"], available["wasm_with_full_extensions"]))

    if comparison_pairs:
        labels = [p[0] for p in comparison_pairs]
        native_vals = [p[1] / 1000 for p in comparison_pairs]  # convert to µs
        wasm_vals = [p[2] / 1000 for p in comparison_pairs]

        x = range(len(labels))
        width = 0.35
        bars1 = ax1.bar([i - width/2 for i in x], native_vals, width, label="Native", color="#2196F3", alpha=0.85)
        bars2 = ax1.bar([i + width/2 for i in x], wasm_vals, width, label="WASM", color="#FF9800", alpha=0.85)

        ax1.set_ylabel("Latency (µs, log scale)")
        ax1.set_title("Native vs WASM\n(same workload, lower is better)")
        ax1.set_xticks(list(x))
        ax1.set_xticklabels(labels, fontsize=9)
        ax1.set_yscale("log")
        ax1.legend(loc="upper left")
        ax1.grid(axis="y", alpha=0.3)

        for bar in bars1:
            h = bar.get_height()
            ax1.annotate(f"{h:.2f}µs", xy=(bar.get_x() + bar.get_width()/2, h),
                        xytext=(0, 3), textcoords="offset points", ha="center", fontsize=8)
        for bar in bars2:
            h = bar.get_height()
            ax1.annotate(f"{h:.1f}µs", xy=(bar.get_x() + bar.get_width()/2, h),
                        xytext=(0, 3), textcoords="offset points", ha="center", fontsize=8)

    # Panel 2: "Custom JSON payload vs structured WIT payload + cold start"
    ax2 = axes[1]
    payload_bars = []

    if "custom_payload_wasm" in available:
        payload_bars.append(("Custom Payload\n(JSON serde)", available["custom_payload_wasm"] / 1000, "#FF9800"))
    if "structured_payload_wasm" in available:
        payload_bars.append(("Structured Payload\n(WIT types)", available["structured_payload_wasm"] / 1000, "#4CAF50"))
    if "cold_start_wasm" in available:
        payload_bars.append(("Cold Start\n(first load + compile)", available["cold_start_wasm"] / 1000, "#F44336"))

    if payload_bars:
        labels = [b[0] for b in payload_bars]
        vals = [b[1] for b in payload_bars]
        colors = [b[2] for b in payload_bars]

        bars = ax2.bar(range(len(labels)), vals, color=colors, alpha=0.85)
        ax2.set_ylabel("Latency (µs, log scale)")
        ax2.set_title("Payload Path Cost & Cold Start\n(one-time vs per-call)")
        ax2.set_xticks(range(len(labels)))
        ax2.set_xticklabels(labels, fontsize=9)
        ax2.set_yscale("log")
        ax2.grid(axis="y", alpha=0.3)

        for bar in bars:
            h = bar.get_height()
            if h > 1000:
                label = f"{h/1000:.0f}ms"
            else:
                label = f"{h:.1f}µs"
            ax2.annotate(label, xy=(bar.get_x() + bar.get_width()/2, h),
                        xytext=(0, 3), textcoords="offset points", ha="center", fontsize=9, fontweight="bold")

    # Panel 3: "How does mutex contention scale?"
    ax3 = axes[2]
    if contention:
        tasks = sorted(contention.keys(), key=int)
        vals = [contention[t] / 1000 for t in tasks]  # convert to µs
        per_call = [contention[t] / 1000 / int(t) for t in tasks]  # per-call latency

        ax3.bar(range(len(tasks)), vals, color="#9C27B0", alpha=0.85, label="Total (all tasks)")
        ax3.plot(range(len(tasks)), per_call, "o-", color="#E91E63", linewidth=2, markersize=8, label="Per-call effective")

        ax3.set_ylabel("Latency (µs)")
        ax3.set_title("Mutex Contention\n(N tasks sharing 1 sandbox)")
        ax3.set_xticks(range(len(tasks)))
        ax3.set_xticklabels([f"{t} tasks" for t in tasks], fontsize=9)
        ax3.legend(loc="upper left")
        ax3.grid(axis="y", alpha=0.3)

        for i, (v, pc) in enumerate(zip(vals, per_call)):
            ax3.annotate(f"{v:.0f}µs", xy=(i, v),
                        xytext=(0, 3), textcoords="offset points", ha="center", fontsize=8)
            ax3.annotate(f"{pc:.0f}µs/call", xy=(i, pc),
                        xytext=(5, -10), textcoords="offset points", ha="left", fontsize=8, color="#E91E63")

    plt.tight_layout()
    output_path = Path(__file__).parent / "performance_comparison.png"
    plt.savefig(output_path, dpi=150, bbox_inches="tight")
    print(f"\nChart saved: {output_path}")


if __name__ == "__main__":
    main()
