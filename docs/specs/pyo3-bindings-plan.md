# PyO3 Python Bindings Implementation Plan

**Issue**: [#19 - Python bindings (PyO3)](https://github.com/contextforge-org/cpex/issues/19)  
**Epic**: CPEX Rust Core (#12)

## Executive Summary

This plan outlines the implementation of PyO3 bindings for CPEX, enabling Python code (like the ContextForge gateway) to use the Rust PluginManager as a drop-in replacement. The bindings provide compile-time invariant enforcement and the typed hook system while maintaining compatibility with existing Python integration code.

## Architecture Overview

### Current State

```
┌─────────────────────────────────────────┐
│   Python ContextForge Gateway           │
│                                         │
│  ┌───────────────────────────────────┐ │
│  │  cpex.framework.manager           │ │
│  │  (Pure Python PluginManager)      │ │
│  └───────────────────────────────────┘ │
│           │                             │
│           ▼                             │
│  ┌───────────────────────────────────┐ │
│  │  Python Plugins                   │ │
│  │  (Native, Isolated, External)     │ │
│  └───────────────────────────────────┘ │
└─────────────────────────────────────────┘
```

### Target State

```
┌─────────────────────────────────────────────────────┐
│   Python ContextForge Gateway                       │
│                                                     │
│  ┌───────────────────────────────────────────────┐ │
│  │  cpex.__init__.py (Import Switch)             │ │
│  │  ┌─────────────────┐  ┌──────────────────┐   │ │
│  │  │ Rust Backend    │  │ Python Fallback  │   │ │
│  │  │ (if compiled)   │  │ (if not)         │   │ │
│  │  └─────────────────┘  └──────────────────┘   │ │
│  └───────────────────────────────────────────────┘ │
│           │                                         │
│           ▼                                         │
│  ┌───────────────────────────────────────────────┐ │
│  │  cpex._native (PyO3 Module)                   │ │
│  │  ┌─────────────────────────────────────────┐ │ │
│  │  │  PyPluginManager                        │ │ │
│  │  │  (wraps cpex_core::PluginManager)       │ │ │
│  │  └─────────────────────────────────────────┘ │ │
│  └───────────────────────────────────────────────┘ │
│           │                                         │
│           ▼                                         │
│  ┌───────────────────────────────────────────────┐ │
│  │  Rust Core (cpex-core)                        │ │
│  │  ┌─────────────────────────────────────────┐ │ │
│  │  │  5-Phase Executor                       │ │ │
│  │  │  SEQUENTIAL → TRANSFORM → AUDIT →       │ │ │
│  │  │  CONCURRENT → FIRE_AND_FORGET           │ │ │
│  │  └─────────────────────────────────────────┘ │ │
│  └───────────────────────────────────────────────┘ │
│           │                                         │
│           ▼                                         │
│  ┌───────────────────────────────────────────────┐ │
│  │  Python Plugins (via PyO3 bridge)            │ │
│  │  - Receive PyO3-wrapped payloads             │ │
│  │  - Typed attribute access                    │ │
│  │  - Rust controls memory safety               │ │
│  └───────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────┘
```

## Design Decisions

### 1. Crate Structure

**Decision**: Create `crates/cpex-python` as a separate crate from `cpex-ffi`

**Rationale**:
- `cpex-ffi` targets C ABI for Go/C/C++ interop (uses MessagePack serialization)
- `cpex-python` uses PyO3's native Python object protocol (no serialization overhead)
- Different build configurations: `cdylib` for FFI vs `cdylib` with PyO3 features
- Cleaner separation of concerns and dependencies

### 2. PyO3 vs FFI Approach

**Decision**: Use PyO3 native bindings instead of ctypes/cffi over `cpex-ffi`

**Rationale**:
- **Performance**: Direct Python object protocol, no serialization overhead
- **Type Safety**: PyO3 provides compile-time type checking for Python↔Rust boundary
- **Ergonomics**: Natural Python API with proper exceptions, not error codes
- **Memory Safety**: PyO3 handles GIL and reference counting automatically
- **IDE Support**: Type stubs work better with native Python objects

### 3. Payload Wrapping Strategy

**Decision**: Wrap Rust payloads in PyO3 classes with `#[pyclass]`, expose attributes via `#[pymethods]`

**Rationale**:
- Rust controls memory layout and access patterns (prevents corruption)
- Python plugins see familiar attribute access: `payload.prompt_id`
- Copy-on-write semantics preserved (modifications create new instances)
- Type validation happens in Rust before Python sees the data

**Example**:
```rust
#[pyclass]
pub struct PyMessagePayload {
    inner: Arc<MessagePayload>,
}

#[pymethods]
impl PyMessagePayload {
    #[getter]
    fn prompt_id(&self) -> PyResult<String> {
        Ok(self.inner.prompt_id.clone())
    }
    
    fn model_copy(&self, py: Python, updates: &PyDict) -> PyResult<Self> {
        // Create modified copy with Rust validation
    }
}
```

### 4. Import Switch Pattern

**Decision**: Conditional import in `cpex/__init__.py` with graceful fallback

**Implementation**:
```python
# cpex/__init__.py
try:
    from cpex._native import PluginManager as _RustPluginManager
    PluginManager = _RustPluginManager
    BACKEND = "rust"
except ImportError:
    from cpex.framework.manager import PluginManager as _PythonPluginManager
    PluginManager = _PythonPluginManager
    BACKEND = "python"
```

**Rationale**:
- Zero breaking changes for existing code
- Developers can opt-in by building the Rust extension
- CI/CD can test both backends
- Gradual migration path

### 5. Build System Integration

**Decision**: Use Maturin for building PyO3 extensions

**Rationale**:
- Industry standard for PyO3 projects
- Integrates with `pyproject.toml` (PEP 517/518)
- Handles cross-compilation and wheel building
- Works with existing `pip install -e .` workflow

## Implementation Phases

### Phase 1: Core Infrastructure (Days 1-3)

**Goal**: Establish basic PyO3 bindings with minimal functionality

#### Tasks:

1. **Create `crates/cpex-python` crate**
   - `Cargo.toml` with PyO3 dependencies
   - Basic `lib.rs` with `#[pymodule]` definition
   - Add to workspace in root `Cargo.toml`

2. **Implement `PyPluginManager`**
   - Wrap `cpex_core::PluginManager` in `#[pyclass]`
   - Implement `__new__` for initialization from config path
   - Implement `invoke_hook` method (basic version)
   - Handle async execution (PyO3 async or sync wrapper)

3. **Configure Maturin build**
   - Update `pyproject.toml` with `[tool.maturin]` section
   - Set module name to `cpex._native`
   - Configure build dependencies

4. **Add Makefile targets**
   - `make python-build`: Build PyO3 extension in debug mode
   - `make python-build-release`: Build in release mode
   - `make python-install`: Install with `maturin develop`
   - `make python-test`: Run tests with Rust backend

#### Deliverables:
- Compilable `cpex-python` crate
- Basic `PyPluginManager` that can be imported
- Build system integration

### Phase 2: Type Bindings (Days 4-6)

**Goal**: Create PyO3 wrappers for all core types

#### Tasks:

1. **Implement PyO3 config types**
   - `PyPluginConfig` wrapping `PluginConfig`
   - `PyPluginMode` enum mapping
   - `PyOnError` enum mapping
   - Conversion traits: `FromPyObject`, `IntoPy`

2. **Implement PyO3 context types**
   - `PyPluginContext` wrapping `PluginContext`
   - `PyGlobalContext` wrapping `GlobalContext`
   - `PyPluginContextTable` (dict-like interface)

3. **Implement PyO3 extension types**
   - `PyExtensions` wrapping `Extensions`
   - Capability filtering integration
   - Dict-like access patterns

4. **Implement PyO3 result types**
   - `PyPluginResult` wrapping `PluginResult`
   - `allow()`, `deny()`, `modify()` factory methods
   - Error conversion to Python exceptions

#### Deliverables:
- Complete type system in PyO3
- Bidirectional conversions (Python ↔ Rust)
- Unit tests for each type

### Phase 3: Payload System (Days 7-9)

**Goal**: Implement PyO3-wrapped payloads with typed attribute access

#### Tasks:

1. **Design payload wrapper architecture**
   - Generic `PyPayload<T>` wrapper pattern
   - Attribute access via `#[pymethods]` getters
   - `model_copy(update={...})` for modifications

2. **Implement common payload types**
   - `PyMessagePayload` (CMF messages)
   - `PyToolPayload` (tool invocations)
   - `PyPromptPayload` (prompt hooks)
   - Add more as needed

3. **Implement payload registry**
   - Map hook names to payload types
   - Dynamic dispatch based on hook name
   - Validation and error handling

4. **Test payload isolation**
   - Verify copy-on-write semantics
   - Test modification tracking
   - Ensure Rust controls memory

#### Deliverables:
- PyO3-wrapped payload types
- Attribute access working from Python
- Modification system functional

### Phase 4: Hook Execution (Days 10-12)

**Goal**: Complete `invoke_hook` implementation with full 5-phase execution

#### Tasks:

1. **Implement async bridge**
   - Handle Python async/await in Rust
   - Use `pyo3-asyncio` or sync wrapper
   - Manage GIL properly during execution

2. **Implement phase execution**
   - SEQUENTIAL: serial, chained, blocking + modifying
   - TRANSFORM: serial, chained, modifying only
   - AUDIT: serial, observe-only
   - CONCURRENT: parallel, blocking only
   - FIRE_AND_FORGET: background, no blocking/modifying

3. **Implement error handling**
   - Map Rust errors to Python exceptions
   - Respect `on_error` settings (fail/ignore/disable)
   - Proper error propagation

4. **Implement timeout handling**
   - Per-plugin timeouts
   - Wall-clock timeout protection
   - Timeout error reporting

#### Deliverables:
- Full 5-phase executor working
- Error handling complete
- Timeout protection functional

### Phase 5: Integration & Testing (Days 13-15)

**Goal**: Ensure compatibility with existing Python ecosystem

#### Tasks:

1. **Update `cpex/__init__.py`**
   - Implement import switch logic
   - Export `BACKEND` variable
   - Maintain API compatibility

2. **Create integration tests**
   - Test with existing YAML configs
   - Verify Python plugins work with PyO3 payloads
   - Test all hook types
   - Test all plugin modes

3. **Generate type stubs**
   - Create `cpex/_native.pyi`
   - Document all public APIs
   - Ensure IDE autocomplete works

4. **Test fallback behavior**
   - Verify pure Python backend still works
   - Test import switch logic
   - Ensure no breaking changes

#### Deliverables:
- Working import switch
- Comprehensive integration tests
- Type stubs for IDE support
- Verified backward compatibility

### Phase 6: Documentation & Polish (Days 16-18)

**Goal**: Complete documentation and prepare for release

#### Tasks:

1. **Update documentation**
   - Add PyO3 bindings guide to docs/
   - Document build process
   - Add performance comparison
   - Update quickstart with Rust backend option

2. **Performance benchmarking**
   - Compare Rust vs Python backend
   - Document performance characteristics
   - Identify optimization opportunities

3. **CI/CD integration**
   - Add Rust backend tests to CI
   - Test both backends in parallel
   - Add wheel building for releases

4. **Final polish**
   - Code review and cleanup
   - Address any edge cases
   - Prepare release notes

#### Deliverables:
- Complete documentation
- Performance benchmarks
- CI/CD integration
- Release-ready code

## Technical Specifications

### Crate Structure

```
crates/cpex-python/
├── Cargo.toml
├── src/
│   ├── lib.rs              # PyO3 module definition
│   ├── manager.rs          # PyPluginManager implementation
│   ├── types/
│   │   ├── mod.rs
│   │   ├── config.rs       # PyPluginConfig, PyPluginMode, etc.
│   │   ├── context.rs      # PyPluginContext, PyGlobalContext
│   │   ├── extensions.rs   # PyExtensions
│   │   └── result.rs       # PyPluginResult
│   ├── payloads/
│   │   ├── mod.rs
│   │   ├── base.rs         # Generic PyPayload<T> wrapper
│   │   ├── message.rs      # PyMessagePayload
│   │   ├── tool.rs         # PyToolPayload
│   │   └── prompt.rs       # PyPromptPayload
│   ├── executor.rs         # Async bridge and phase execution
│   ├── error.rs            # Error conversion
│   └── utils.rs            # Helper functions
└── tests/
    └── integration_test.rs
```

### Key Dependencies

```toml
[dependencies]
pyo3 = { version = "0.21", features = ["extension-module", "abi3-py311"] }
pyo3-asyncio = { version = "0.21", features = ["tokio-runtime"] }
cpex-core = { path = "../cpex-core" }
tokio = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
```

### Maturin Configuration

```toml
# pyproject.toml
[build-system]
requires = ["maturin>=1.0,<2.0"]
build-backend = "maturin"

[tool.maturin]
module-name = "cpex._native"
python-source = "cpex"
features = ["pyo3/extension-module"]
```

### API Surface

```python
# cpex._native module (generated by PyO3)

class PluginManager:
    """Rust-backed plugin manager."""
    
    def __init__(self, config_path: str) -> None:
        """Initialize from YAML config file."""
        ...
    
    async def initialize(self) -> None:
        """Initialize all plugins."""
        ...
    
    async def invoke_hook(
        self,
        hook_name: str,
        payload: dict,
        context: dict,
        extensions: dict | None = None,
    ) -> tuple[dict, dict]:
        """
        Invoke a hook with the given payload.
        
        Returns:
            Tuple of (modified_payload, context_table)
        """
        ...
    
    async def shutdown(self) -> None:
        """Shutdown all plugins."""
        ...

# Type stubs in cpex/_native.pyi
from typing import Any, Dict, Tuple

class PluginManager:
    def __init__(self, config_path: str) -> None: ...
    async def initialize(self) -> None: ...
    async def invoke_hook(
        self,
        hook_name: str,
        payload: Dict[str, Any],
        context: Dict[str, Any],
        extensions: Dict[str, Any] | None = None,
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]: ...
    async def shutdown(self) -> None: ...
```

## Testing Strategy

### Unit Tests (Rust)

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use pyo3::prelude::*;
    
    #[test]
    fn test_py_plugin_manager_creation() {
        Python::with_gil(|py| {
            let manager = PyPluginManager::new(py, "test-config.yaml").unwrap();
            assert!(manager.is_ok());
        });
    }
    
    #[test]
    fn test_payload_wrapping() {
        Python::with_gil(|py| {
            let payload = MessagePayload { /* ... */ };
            let py_payload = PyMessagePayload::from_rust(payload);
            assert_eq!(py_payload.prompt_id(py).unwrap(), "test-id");
        });
    }
}
```

### Integration Tests (Python)

```python
# tests/unit/cpex/test_rust_backend.py

import pytest
from cpex import PluginManager, BACKEND

@pytest.mark.skipif(BACKEND != "rust", reason="Rust backend not available")
class TestRustBackend:
    async def test_basic_invocation(self):
        manager = PluginManager("tests/fixtures/configs/valid_single_plugin.yaml")
        await manager.initialize()
        
        payload = {"prompt_id": "123", "name": "test"}
        context = {"request_id": "456"}
        
        result, contexts = await manager.invoke_hook(
            "prompt_pre_fetch",
            payload,
            context
        )
        
        assert result is not None
        assert contexts is not None
    
    async def test_existing_yaml_configs(self):
        """Verify all existing test configs work with Rust backend."""
        configs = [
            "valid_single_plugin.yaml",
            "valid_multiple_plugins.yaml",
            "context_plugin.yaml",
            # ... all existing configs
        ]
        
        for config in configs:
            manager = PluginManager(f"tests/fixtures/configs/{config}")
            await manager.initialize()
            # Test basic invocation
            await manager.shutdown()
```

### Compatibility Tests

```python
# tests/unit/cpex/test_backend_compatibility.py

import pytest
from cpex import PluginManager, BACKEND

class TestBackendCompatibility:
    """Ensure both backends produce identical results."""
    
    @pytest.mark.parametrize("backend", ["rust", "python"])
    async def test_identical_results(self, backend):
        # Force specific backend
        if backend == "rust" and BACKEND != "rust":
            pytest.skip("Rust backend not available")
        
        manager = PluginManager("test-config.yaml")
        result = await manager.invoke_hook(...)
        
        # Compare results between backends
        assert result == expected_result
```

## Risk Mitigation

### Risk 1: Breaking Changes to Python API

**Mitigation**:
- Maintain strict API compatibility in import switch
- Comprehensive integration tests with existing configs
- Test both backends in CI
- Document any unavoidable differences

### Risk 2: Performance Regression

**Mitigation**:
- Benchmark both backends
- Profile PyO3 overhead
- Optimize hot paths
- Document performance characteristics

### Risk 3: Build Complexity

**Mitigation**:
- Clear build documentation
- Makefile targets for common operations
- CI/CD automation
- Fallback to pure Python if build fails

### Risk 4: Async/GIL Issues

**Mitigation**:
- Use `pyo3-asyncio` for proper async bridge
- Careful GIL management
- Extensive async testing
- Document async behavior

## Success Criteria

1. ✅ `from cpex import PluginManager` loads Rust backend when compiled
2. ✅ `manager.invoke_hook()` dispatches through Rust 5-phase executor
3. ✅ Python plugins receive PyO3-wrapped payloads with typed attributes
4. ✅ Existing `PluginConfig` YAML format works without changes
5. ✅ Falls back to pure Python implementation if Rust module not compiled
6. ✅ All existing integration tests pass with Rust backend
7. ✅ Performance improvement over pure Python backend
8. ✅ Type stubs provide IDE autocomplete
9. ✅ Documentation complete and accurate
10. ✅ CI/CD tests both backends

## Timeline

- **Phase 1**: Days 1-3 (Core Infrastructure)
- **Phase 2**: Days 4-6 (Type Bindings)
- **Phase 3**: Days 7-9 (Payload System)
- **Phase 4**: Days 10-12 (Hook Execution)
- **Phase 5**: Days 13-15 (Integration & Testing)
- **Phase 6**: Days 16-18 (Documentation & Polish)

**Total Estimated Time**: 18 working days (~3.5 weeks)

## References

- [PyO3 Documentation](https://pyo3.rs/)
- [Maturin Documentation](https://www.maturin.rs/)
- [Issue #19](https://github.com/contextforge-org/cpex/issues/19)
- [Epic #12 - CPEX Rust Core](https://github.com/contextforge-org/cpex/issues/12)
- Existing `cpex-ffi` implementation for FFI patterns
- Existing `cpex/framework/manager.py` for API compatibility