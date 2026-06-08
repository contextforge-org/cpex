# PyO3 Python Bindings Implementation Plan

**Issue**: [#19 - Python bindings (PyO3)](https://github.com/contextforge-org/cpex/issues/19)
**Epic**: CPEX Rust Core (#12)
**Status**: Updated based on technical review feedback

## Executive Summary

This plan outlines the implementation of PyO3 bindings for CPEX, enabling Python code (like the ContextForge gateway) to use the Rust PluginManager as a drop-in replacement. The bindings provide compile-time invariant enforcement and the typed hook system while maintaining compatibility with existing Python integration code.

## Review Feedback Addressed

This plan has been updated to address critical technical issues identified in review:

1. **✅ Async Runtime**: Replaced deprecated `pyo3-asyncio` with maintained `pyo3-async-runtimes`
2. **✅ Payload Design**: Eliminated generic `PyPayload<T>` in favor of concrete `#[pyclass]` types per payload
3. **✅ API Contract**: Clarified that Python plugins receive typed PyO3 wrapper objects, not dicts
4. **✅ Initialization**: Separated sync `__new__` (config loading) from async `initialize()` (plugin init)
5. **✅ Testing Strategy**: Revised compatibility tests to explicitly import both backends
6. **✅ Performance Claims**: Scoped performance expectations with realistic benchmarks
7. **✅ Type Stubs**: Will use PyO3's stub generation tooling instead of hand-written stubs

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

**Decision**: Create concrete `#[pyclass]` types for each payload (no generics)

**Rationale**:
- PyO3 `#[pyclass]` cannot be generic - must be concrete, monomorphized types
- Each payload type gets its own `#[pyclass]` implementation
- Rust controls memory layout and access patterns (prevents corruption)
- Python plugins receive typed wrapper objects with attribute access: `payload.prompt_id`
- Copy-on-write semantics preserved (modifications create new instances)
- Type validation happens in Rust before Python sees the data

**Implementation Pattern**:
```rust
// Concrete pyclass for each payload type (no generics)
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
        let mut modified = (*self.inner).clone();
        // Apply updates from dict...
        Ok(PyMessagePayload {
            inner: Arc::new(modified)
        })
    }
}

// Repeat for PyToolPayload, PyPromptPayload, etc.
// Use a macro to reduce boilerplate if needed
```

**Note**: Python plugins receive these typed wrapper objects directly, NOT dicts. The `invoke_hook` API accepts dicts for convenience but immediately converts them to typed wrappers before passing to plugins.

### 4. Import Switch Pattern

**Decision**: Conditional import in `cpex/__init__.py` with graceful fallback, plus explicit backend imports

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

# Always expose both backends explicitly for testing
from cpex.framework.manager import PluginManager as PythonPluginManager
try:
    from cpex._native import PluginManager as RustPluginManager
except ImportError:
    RustPluginManager = None
```

**Rationale**:
- Zero breaking changes for existing code
- Developers can opt-in by building the Rust extension
- CI/CD can test both backends
- Gradual migration path
- Explicit backend imports enable proper compatibility testing

### 5. Build System Integration

**Decision**: Use Maturin for building PyO3 extensions

**Rationale**:
- Industry standard for PyO3 projects
- Integrates with `pyproject.toml` (PEP 517/518)
- Handles cross-compilation and wheel building
- Works with existing `pip install -e .` workflow

### 6. Initialization Pattern

**Decision**: Separate sync construction from async initialization

**Implementation**:
```python
# Sync construction - loads config, validates YAML
manager = PluginManager("config.yaml")

# Async initialization - calls plugin.initialize() on all plugins
await manager.initialize()
```

**Rationale**:
- Config loading and validation can be synchronous
- Plugin initialization may require async I/O (network, files, etc.)
- Matches existing Python API pattern
- Clear separation of concerns

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
   - Implement `__new__` for sync config loading and validation
   - Implement async `initialize()` for plugin initialization
   - Implement `invoke_hook` method (basic version)
   - Use `pyo3-async-runtimes` for async bridge (NOT deprecated `pyo3-asyncio`)

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
   - Concrete `#[pyclass]` per payload type (NO generics - PyO3 limitation)
   - Consider macro to reduce boilerplate across payload types
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
   - Use `pyo3-async-runtimes` (maintained successor to deprecated `pyo3-asyncio`)
   - Manage GIL properly during execution
   - Support tokio runtime integration

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
   - Use PyO3's stub generation tooling (avoid hand-written stubs that drift)
   - Generate `cpex/_native.pyi` automatically
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
   - Define realistic benchmark workloads upfront
   - Measure hook dispatch overhead (both backends)
   - Note: Python plugins under GIL limit parallelism gains
   - Document where Rust backend provides benefits:
     * Reduced orchestration overhead
     * Better memory safety guarantees
     * Compile-time type checking
   - Be realistic: dict↔Rust marshaling adds overhead
   - Performance gains most visible with Rust-native plugins

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
│   │   ├── macros.rs       # Macro to reduce boilerplate (optional)
│   │   ├── message.rs      # PyMessagePayload (concrete #[pyclass])
│   │   ├── tool.rs         # PyToolPayload (concrete #[pyclass])
│   │   └── prompt.rs       # PyPromptPayload (concrete #[pyclass])
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
pyo3-async-runtimes = { version = "0.21", features = ["tokio"] }
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
    
    def __new__(cls, config_path: str) -> Self:
        """
        Create manager from YAML config file (sync).
        Loads and validates config but does not initialize plugins.
        """
        ...
    
    async def initialize(self) -> None:
        """
        Initialize all plugins (async).
        Must be called after construction before invoking hooks.
        """
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
        
        Note: payload dict is converted to typed PyO3 wrapper internally.
        Python plugins receive typed wrapper objects, not dicts.
        
        Returns:
            Tuple of (modified_payload, context_table)
        """
        ...
    
    async def shutdown(self) -> None:
        """Shutdown all plugins."""
        ...

# Type stubs in cpex/_native.pyi (auto-generated by PyO3 tooling)
from typing import Any, Dict, Tuple, Self

class PluginManager:
    """Rust-backed plugin manager with 5-phase execution."""
    
    def __new__(cls, config_path: str) -> Self:
        """Load config (sync). Call initialize() before use."""
        ...
    
    async def initialize(self) -> None:
        """Initialize all plugins (async)."""
        ...
    
    async def invoke_hook(
        self,
        hook_name: str,
        payload: Dict[str, Any],
        context: Dict[str, Any],
        extensions: Dict[str, Any] | None = None,
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Invoke hook. Payload dict converted to typed wrapper internally.
        Python plugins receive typed PyO3 objects, not dicts.
        """
        ...
    
    async def shutdown(self) -> None:
        """Shutdown all plugins."""
        ...
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
from cpex import PythonPluginManager, RustPluginManager, BACKEND

class TestBackendCompatibility:
    """Ensure both backends produce identical results."""
    
    async def test_python_backend(self):
        """Test pure Python backend."""
        manager = PythonPluginManager("test-config.yaml")
        await manager.initialize()
        result = await manager.invoke_hook(...)
        assert result == expected_result
    
    @pytest.mark.skipif(RustPluginManager is None, reason="Rust backend not compiled")
    async def test_rust_backend(self):
        """Test Rust backend."""
        manager = RustPluginManager("test-config.yaml")
        await manager.initialize()
        result = await manager.invoke_hook(...)
        assert result == expected_result
    
    @pytest.mark.skipif(RustPluginManager is None, reason="Rust backend not compiled")
    async def test_backends_produce_identical_results(self):
        """Compare outputs from both backends."""
        py_manager = PythonPluginManager("test-config.yaml")
        rust_manager = RustPluginManager("test-config.yaml")
        
        await py_manager.initialize()
        await rust_manager.initialize()
        
        payload = {"prompt_id": "123", "name": "test"}
        context = {"request_id": "456"}
        
        py_result = await py_manager.invoke_hook("test_hook", payload, context)
        rust_result = await rust_manager.invoke_hook("test_hook", payload, context)
        
        # Both backends should produce identical results
        assert py_result == rust_result
```

**Note**: This approach explicitly imports both backends, avoiding the "force backend" pattern that doesn't work with the import switch.

## Risk Mitigation

### Risk 1: Breaking Changes to Python API

**Mitigation**:
- Maintain strict API compatibility in import switch
- Comprehensive integration tests with existing configs
- Test both backends in CI
- Document any unavoidable differences

### Risk 2: Performance Expectations

**Reality Check**:
- Python plugins run under GIL - no true parallelism in CONCURRENT phase
- Dict↔Rust marshaling adds overhead vs pure Python
- Performance gains come from:
  * Reduced orchestration overhead
  * Better memory safety (fewer defensive copies)
  * Compile-time guarantees (fewer runtime checks)
  * Rust-native plugins (when available)

**Mitigation**:
- Define realistic benchmark workloads upfront
- Measure and document actual performance characteristics
- Don't oversell performance gains
- Focus on correctness and safety benefits

### Risk 3: Build Complexity

**Mitigation**:
- Clear build documentation
- Makefile targets for common operations
- CI/CD automation
- Fallback to pure Python if build fails

### Risk 4: Async/GIL Issues

**Mitigation**:
- Use `pyo3-async-runtimes` (maintained successor to deprecated `pyo3-asyncio`)
- Careful GIL management
- Extensive async testing
- Document async behavior

## Success Criteria

1. ✅ `from cpex import PluginManager` loads Rust backend when compiled
2. ✅ `manager.invoke_hook()` dispatches through Rust 5-phase executor
3. ✅ Python plugins receive PyO3-wrapped payloads with typed attribute access (not dicts)
4. ✅ Existing `PluginConfig` YAML format works without changes
5. ✅ Falls back to pure Python implementation if Rust module not compiled
6. ✅ All existing integration tests pass with Rust backend
7. ✅ Performance characteristics documented with realistic benchmarks
8. ✅ Auto-generated type stubs provide IDE autocomplete
9. ✅ Documentation complete and accurate
10. ✅ CI/CD tests both backends explicitly
11. ✅ Sync `__new__` + async `initialize()` pattern implemented correctly
12. ✅ Uses maintained `pyo3-async-runtimes` (not deprecated `pyo3-asyncio`)
13. ✅ Concrete `#[pyclass]` per payload type (no generics)

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