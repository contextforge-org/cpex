#!/usr/bin/env python3
"""
Performance benchmark comparing Rust backend vs Pure Python backend.

Usage:
    PYTHONPATH="." python tests/benchmarks/benchmark_rust_vs_python.py
"""

import asyncio
import os
import time
from statistics import mean, stdev

# Force Rust backend
os.environ["CPEX_BACKEND"] = "rust"
from cpex import PluginManager as RustPluginManager, BACKEND as RUST_BACKEND

# Force Python backend
os.environ["CPEX_BACKEND"] = "python"
import importlib
import cpex
importlib.reload(cpex)
from cpex import PluginManager as PythonPluginManager, BACKEND as PYTHON_BACKEND


async def benchmark_hook_invocation(manager_class, backend_name, iterations=1000):
    """Benchmark hook invocation performance."""
    manager = manager_class("tests/unit/cpex/fixtures/configs/valid_no_plugin.yaml")
    await manager.initialize()
    
    payload = {
        "schema_version": "1.0",
        "role": "user",
        "content": [{"content_type": "text", "text": "Hello, world!"}],
    }
    
    times = []
    
    # Warmup
    for _ in range(10):
        await manager.invoke_hook("cmf.tool_pre_invoke", payload, {}, None)
    
    # Actual benchmark
    for _ in range(iterations):
        start = time.perf_counter()
        await manager.invoke_hook("cmf.tool_pre_invoke", payload, {}, None)
        end = time.perf_counter()
        times.append((end - start) * 1000)  # Convert to milliseconds
    
    await manager.shutdown()
    
    return {
        "backend": backend_name,
        "iterations": iterations,
        "mean_ms": mean(times),
        "stdev_ms": stdev(times) if len(times) > 1 else 0,
        "min_ms": min(times),
        "max_ms": max(times),
        "total_ms": sum(times),
    }


async def benchmark_payload_conversion(manager_class, backend_name, iterations=1000):
    """Benchmark payload conversion overhead."""
    manager = manager_class("tests/unit/cpex/fixtures/configs/valid_no_plugin.yaml")
    await manager.initialize()
    
    # Complex multimodal payload
    payload = {
        "schema_version": "1.0",
        "role": "user",
        "content": [
            {"content_type": "text", "text": "Analyze this image"},
            {
                "content_type": "image",
                "content": {
                    "type": "url",
                    "data": "https://example.com/image.jpg",
                    "media_type": "image/jpeg",
                }
            },
            {"content_type": "text", "text": "What do you see?"},
        ],
    }
    
    times = []
    
    # Warmup
    for _ in range(10):
        await manager.invoke_hook("cmf.tool_pre_invoke", payload, {}, None)
    
    # Actual benchmark
    for _ in range(iterations):
        start = time.perf_counter()
        await manager.invoke_hook("cmf.tool_pre_invoke", payload, {}, None)
        end = time.perf_counter()
        times.append((end - start) * 1000)
    
    await manager.shutdown()
    
    return {
        "backend": backend_name,
        "test": "multimodal_payload",
        "iterations": iterations,
        "mean_ms": mean(times),
        "stdev_ms": stdev(times) if len(times) > 1 else 0,
        "min_ms": min(times),
        "max_ms": max(times),
    }


async def main():
    """Run all benchmarks."""
    print("=" * 80)
    print("CPEX Performance Benchmark: Rust Backend vs Pure Python Backend")
    print("=" * 80)
    print()
    
    print(f"Rust Backend Active: {RUST_BACKEND}")
    print(f"Python Backend Active: {PYTHON_BACKEND}")
    print()
    
    # Benchmark 1: Basic hook invocation
    print("Benchmark 1: Basic Hook Invocation (1000 iterations)")
    print("-" * 80)
    
    rust_result = await benchmark_hook_invocation(RustPluginManager, "Rust", 1000)
    python_result = await benchmark_hook_invocation(PythonPluginManager, "Python", 1000)
    
    print(f"Rust Backend:")
    print(f"  Mean: {rust_result['mean_ms']:.4f} ms")
    print(f"  StdDev: {rust_result['stdev_ms']:.4f} ms")
    print(f"  Min: {rust_result['min_ms']:.4f} ms")
    print(f"  Max: {rust_result['max_ms']:.4f} ms")
    print(f"  Total: {rust_result['total_ms']:.2f} ms")
    print()
    
    print(f"Python Backend:")
    print(f"  Mean: {python_result['mean_ms']:.4f} ms")
    print(f"  StdDev: {python_result['stdev_ms']:.4f} ms")
    print(f"  Min: {python_result['min_ms']:.4f} ms")
    print(f"  Max: {python_result['max_ms']:.4f} ms")
    print(f"  Total: {python_result['total_ms']:.2f} ms")
    print()
    
    speedup = python_result['mean_ms'] / rust_result['mean_ms']
    print(f"Speedup: {speedup:.2f}x (Rust is {speedup:.2f}x faster)")
    print()
    
    # Benchmark 2: Multimodal payload conversion
    print("Benchmark 2: Multimodal Payload Conversion (1000 iterations)")
    print("-" * 80)
    
    rust_multimodal = await benchmark_payload_conversion(RustPluginManager, "Rust", 1000)
    python_multimodal = await benchmark_payload_conversion(PythonPluginManager, "Python", 1000)
    
    print(f"Rust Backend:")
    print(f"  Mean: {rust_multimodal['mean_ms']:.4f} ms")
    print(f"  StdDev: {rust_multimodal['stdev_ms']:.4f} ms")
    print(f"  Min: {rust_multimodal['min_ms']:.4f} ms")
    print(f"  Max: {rust_multimodal['max_ms']:.4f} ms")
    print()
    
    print(f"Python Backend:")
    print(f"  Mean: {python_multimodal['mean_ms']:.4f} ms")
    print(f"  StdDev: {python_multimodal['stdev_ms']:.4f} ms")
    print(f"  Min: {python_multimodal['min_ms']:.4f} ms")
    print(f"  Max: {python_multimodal['max_ms']:.4f} ms")
    print()
    
    speedup_multimodal = python_multimodal['mean_ms'] / rust_multimodal['mean_ms']
    print(f"Speedup: {speedup_multimodal:.2f}x (Rust is {speedup_multimodal:.2f}x faster)")
    print()
    
    print("=" * 80)
    print("Summary")
    print("=" * 80)
    print(f"Basic Invocation: Rust is {speedup:.2f}x faster than Python")
    print(f"Multimodal Payload: Rust is {speedup_multimodal:.2f}x faster than Python")
    print()


if __name__ == "__main__":
    asyncio.run(main())

# Made with Bob
