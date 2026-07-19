# CPEX MCP SDK v1 → v2 Migration Strategy

**Date:** 2025-07-03
**Target SDK:** `mcp==2.0.0b2`, `mcp-types==2.0.0b2` (already pinned in `pyproject.toml`)
**Source of truth:** [MCP Python SDK v2 Migration Guide](https://py.sdk.modelcontextprotocol.io/v2/migration/)

---

## 1. Scope Inventory

### Source files touching MCP SDK APIs

| File | SDK surfaces used | v2 impact |
|---|---|---|
| `cpex/framework/external/mcp/client.py` | `ClientSession`, `McpError`, `StdioServerParameters`, `stdio_client`, `streamablehttp_client`, `mcp.types.TextContent`, `mcp.server.streamable_http.MCP_SESSION_ID_HEADER` | **High** — transport removed, error renamed, types repackaged |
| `cpex/framework/external/mcp/server/runtime.py` | `FastMCP`, `TransportSecuritySettings` | **High** — class renamed+relocated, constructor signature changed |

### Test files

| File | SDK surfaces used | v2 impact |
|---|---|---|
| `tests/.../test_client_config.py` | `mcp.types.CallToolResult`, `mcp.types.TextContent` | **Medium** — import path change |
| `tests/.../test_client_coverage.py` | `mcp.types.TextContent`, patches on `streamablehttp_client`, `ClientSession`, `stdio_client` | **High** — transport name + mock paths |
| `tests/.../test_client_reconnect.py` | `mcp.McpError`, `mcp.types.ErrorData`, `mcp.types.CallToolResult`, `mcp.types.TextContent` | **High** — error renamed + constructor changed |
| `tests/.../test_client_stdio.py` | `mcp.ClientSession`, `mcp.StdioServerParameters`, `mcp.client.stdio.stdio_client` | **Low** — top-level re-exports preserved |

### Files NOT affected (import CPEX internal modules only, not SDK directly)

- `cpex/framework/external/mcp/server/__init__.py` — imports `ExternalPluginServer` from CPEX
- `cpex/framework/external/mcp/server/server.py` — CPEX's own `ExternalPluginServer` class
- `cpex/framework/external/mcp/tls_utils.py` — no MCP SDK imports
- `cpex/framework/external/grpc/server/` — imports CPEX internal `ExternalPluginServer`
- `cpex/framework/external/unix/server/server.py` — imports CPEX internal `ExternalPluginServer`

---

## 2. Breaking Changes That Apply to CPEX

Each change maps to a section in the [Migration Guide](https://py.sdk.modelcontextprotocol.io/v2/migration/).

### 2.1 `mcp.types` → `mcp_types` package
**Guide section:** ["mcp.types moved to the mcp-types package"](https://py.sdk.modelcontextprotocol.io/v2/migration/#mcptypes-moved-to-the-mcp-types-package)

`mcp.types` submodule is **removed**. Types are in the separate `mcp-types` distribution, imported as `mcp_types`. Top-level `mcp` re-exports key types but NOT via `mcp.types`.

| v1 import | v2 import |
|---|---|
| `from mcp.types import TextContent` | `from mcp_types import TextContent` |
| `from mcp.types import CallToolResult` | `from mcp_types import CallToolResult` |
| `from mcp.types import ErrorData` | `from mcp_types import ErrorData` |

**Impact on CPEX:** All `from mcp.types import ...` in `client.py` and every test file.

### 2.2 `McpError` → `MCPError` (renamed + constructor changed)
**Guide section:** ["McpError renamed to MCPError"](https://py.sdk.modelcontextprotocol.io/v2/migration/#mcperror-renamed-to-mcperror)

- Class renamed `McpError` → `MCPError`
- Top-level export: `from mcp import MCPError`
- **Constructor changed:** takes `(code, message, data=None)` directly — no more wrapping in `ErrorData`
- **Attribute access changed:** `e.error.message` → `e.message`; `e.error.code` → `e.code`
- Instance still has `e.error: ErrorData` for backward compat

| v1 | v2 |
|---|---|
| `from mcp import McpError` | `from mcp import MCPError` |
| `raise McpError(ErrorData(code=-1, message="..."))` | `raise MCPError(-1, "...")` |
| `except McpError as e: e.error.message` | `except MCPError as e: e.message` |

**Impact on CPEX:** `client.py:573` catches `McpError`, `test_client_reconnect.py` constructs `McpError(ErrorData(...))`.

### 2.3 `streamablehttp_client` removed → `streamable_http_client`
**Guide section:** ["streamablehttp_client removed"](https://py.sdk.modelcontextprotocol.io/v2/migration/#streamablehttp_client-removed)

This is the **most impactful** change. The old `streamablehttp_client` context manager is **gone**, replaced by `streamable_http_client` with a fundamentally different API:

| Aspect | v1 (`streamablehttp_client`) | v2 (`streamable_http_client`) |
|---|---|---|
| **Import** | `mcp.client.streamable_http.streamablehttp_client` | `mcp.client.streamable_http.streamable_http_client` |
| **HTTP client param** | `httpx_client_factory: Callable[..., httpx.AsyncClient]` | `http_client: httpx.AsyncClient \| None` (pre-built instance) |
| **Session termination** | `terminate_on_close: bool` — sends DELETE on exit | `terminate_on_close: bool` — same, built into transport |
| **Session ID** | 3-tuple `(read, write, get_session_id)` | `TransportStreams` 2-tuple `(read_stream, write_stream)`; session ID on `StreamableHTTPTransport.session_id` |
| **`get_session_id` callback** | Returned as 3rd element of yield | **Removed entirely** — use `transport.get_session_id()` or `transport.session_id` |

**Impact on CPEX `client.py`:**
- `__connect_to_http_server`: factory pattern → pre-built client, 3-tuple unpacking → 2-tuple
- `__terminate_http_session`: can be removed if `terminate_on_close=True` is used (SDK sends DELETE)
- `_get_session_id` / `_session_id` fields: need new mechanism via transport's `session_id` property
- The `MCP_SESSION_ID_HEADER` lazy import (`mcp.server.streamable_http`) is still valid for the header constant string `"mcp-session-id"`

### 2.4 `FastMCP` → `MCPServer` (renamed + relocated)
**Guide section:** ["FastMCP renamed to MCPServer"](https://py.sdk.modelcontextprotocol.io/v2/migration/#fastmcp-renamed-to-mcpserver)

| v1 | v2 |
|---|---|
| `from mcp.server.fastmcp import FastMCP` | `from mcp.server.mcpserver import MCPServer` |

**Impact on CPEX:** `server/runtime.py` defines `SSLCapableFastMCP(FastMCP)`.

### 2.5 Transport params removed from MCPServer constructor
**Guide section:** ["Transport-specific parameters moved from MCPServer constructor to run()/app methods"](https://py.sdk.modelcontextprotocol.io/v2/migration/#transport-specific-parameters-moved-from-mcpserver-constructor-to-runapp-methods)

`host`, `port`, `transport_security`, `json_response`, `stateless_http` are **no longer accepted** by `MCPServer.__init__()`. They are passed to `run()`, `run_streamable_http_async()`, `streamable_http_app()`, etc.

| v1 | v2 |
|---|---|
| `FastMCP("name", host="0.0.0.0", port=8000)` | `MCPServer("name")` + `await mcp.run_streamable_http_async(host="0.0.0.0", port=8000)` |

**Impact on CPEX:** `SSLCapableFastMCP.__init__` passes `host`/`port` via `kwargs` to `super().__init__()`. Must stop doing this. The `run_streamable_http_async()` override already passes them to `uvicorn.Config` directly — the `self.settings.host` / `self.settings.port` access must be replaced with `self.server_config.host` / `self.server_config.port`.

### 2.6 `MCPServer` constructor positional parameter order changed
**Guide section:** ["MCPServer constructor: title, description, and version added"](https://py.sdk.modelcontextprotocol.io/v2/migration/#mcpserver-constructor-title-description-and-version-added-to-the-positional-parameters)

New order: `name, title, description, instructions, website_url, icons, version`.

CPEX uses keyword args (`name=...`, `instructions=...`) so this is **not a breaking issue** for us, but the strategy doc records it for awareness.

### 2.7 `run_stdio_async()` signature unchanged
The `MCPServer.run_stdio_async()` method exists with the same signature. CPEX's `run()` function calls it directly — no change needed.

### 2.8 `streamable_http_app()` gains `host` parameter
Used internally for transport security auto-configuration. CPEX calls `self.streamable_http_app()` without kwargs — still valid.

### 2.9 `stdio_client` unchanged
**Guide section:** ["stdio_client shutdown reworked"](https://py.sdk.modelcontextprotocol.io/v2/migration/#stdio_client-shutdown-reworked-a-gracefully-exited-servers-children-are-left-alive-on-posix)

The `stdio_client` context manager signature is the same: `stdio_client(server_params) → TransportStreams`. Only shutdown behavior on POSIX changed (children left alive). **No code changes needed** for CPEX.

### 2.10 `ClientSession` constructor changed
**Guide section:** ["ClientSession now runs on JSONRPCDispatcher"](https://py.sdk.modelcontextprotocol.io/v2/migration/#clientsession-now-runs-on-jsonrpcdispatcher-basesession-removed)

`ClientSession` now takes `(read_stream, write_stream, ...)` as the first two positional args. This matches the v1 `ClientSession(read, write)` usage — **no change needed** for the constructor call, only the stream types are internally different.

The session is still used as an async context manager: `async with ClientSession(read, write) as session:`.

### 2.11 `TransportSecuritySettings` still at same path
`from mcp.server.transport_security import TransportSecuritySettings` — **unchanged**.

### 2.12 Field names camelCase → snake_case
**Guide section:** ["Field names changed from camelCase to snake_case"](https://py.sdk.modelcontextprotocol.io/v2/migration/#field-names-changed-from-camelcase-to-snake_case)

CPEX does not access `isError`, `nextCursor`, `inputSchema` etc. on MCP types. **No impact.**

### 2.13 `Client` defaults to `mode='auto'`
**Guide section:** ["Client defaults to mode='auto'"](https://py.sdk.modelcontextprotocol.io/v2/migration/#client-defaults-to-modeauto)

CPEX does not use the high-level `Client` class (uses `ClientSession` directly). **No impact.**

---

## 3. Migration Order

Following the [Suggested migration order](https://py.sdk.modelcontextprotocol.io/v2/migration/#suggested-migration-order) from the guide, adapted to CPEX:

### Phase 1 — Mechanical import renames (low risk, all files)
1. `from mcp.types import X` → `from mcp_types import X` (client.py, all tests)
2. `from mcp import McpError` → `from mcp import MCPError` (client.py, test_client_reconnect.py)
3. `from mcp.server.fastmcp import FastMCP` → `from mcp.server.mcpserver import MCPServer` (runtime.py)

### Phase 2 — Server surface (runtime.py)
4. Rename `SSLCapableFastMCP` → `SSLCapableMCPServer` (or keep name, change base class)
5. Remove `host`/`port` from `super().__init__()` kwargs
6. Replace `self.settings.host` / `self.settings.port` with `self.server_config.host` / `self.server_config.port` in `run_streamable_http_async()` and `_start_health_check_server()`
7. Update docstrings referencing "FastMCP"

### Phase 3 — Client transport (client.py) — highest risk
8. Replace `streamablehttp_client` import with `streamable_http_client` (and optionally `StreamableHTTPTransport`)
9. Replace `httpx_client_factory` pattern with pre-built `httpx.AsyncClient` instance
10. Update 3-tuple unpacking `(read, write, get_session_id)` → 2-tuple `(read_stream, write_stream)`
11. Replace `_get_session_id` callback with `StreamableHTTPTransport.session_id` access
12. Remove `__terminate_http_session()` — use `terminate_on_close=True`
13. Remove `MCP_SESSION_ID_HEADER` lazy import (no longer needed for termination)
14. Update `McpError` → `MCPError` in catch block

### Phase 4 — Tests
15. `test_client_reconnect.py`: `McpError(ErrorData(...))` → `MCPError(code, message)`
16. `test_client_config.py`: `mcp.types` → `mcp_types`
17. `test_client_coverage.py`: `mcp.types` → `mcp_types`, update mock paths for `streamablehttp_client` → `streamable_http_client`
18. `test_client_stdio.py`: verify top-level `mcp` re-exports still work (they should)

### Phase 5 — Server tests
19. `test_runtime.py`, `test_runtime_coverage.py`, `test_server.py`: update `FastMCP` → `MCPServer` references

### Phase 6 — Verification
20. Run full test suite
21. Smoke test stdio + streamable HTTP external plugin flows

---

## 4. Detailed Change Specifications

### 4.1 `cpex/framework/external/mcp/client.py`

#### 4.1.1 Import block (lines 24-27)

```python
# BEFORE (v1):
from mcp import ClientSession, McpError, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamablehttp_client
from mcp.types import TextContent

# AFTER (v2):
from mcp import ClientSession, MCPError, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client, StreamableHTTPTransport
from mcp_types import TextContent
```

#### 4.1.2 `__connect_to_http_server` — factory → pre-built client

The current pattern builds a factory function, then calls `streamablehttp_client(uri, httpx_client_factory=factory, terminate_on_close=False)`. The v2 `streamable_http_client` takes `http_client: httpx.AsyncClient | None` — a **pre-built** client instance.

```python
# BEFORE (v1) — lines ~380-398:
streamable_client = streamablehttp_client(
    uri, httpx_client_factory=client_factory, terminate_on_close=False
)
http_transport = await self._exit_stack.enter_async_context(streamable_client)
self._http, self._write, get_session_id = http_transport   # 3-tuple
self._get_session_id = get_session_id
self._session = await self._exit_stack.enter_async_context(ClientSession(self._http, self._write))

# AFTER (v2):
http_client_instance = _tls_httpx_client_factory()
streamable_client = streamable_http_client(
    uri, http_client=http_client_instance, terminate_on_close=True
)
http_transport = await self._exit_stack.enter_async_context(streamable_client)
self._http, self._write = http_transport   # 2-tuple (TransportStreams)
self._session = await self._exit_stack.enter_async_context(ClientSession(self._http, self._write))
```

Key decisions:
- **`terminate_on_close=True`**: Let the SDK send the DELETE on session close. This replaces the manual `__terminate_http_session()` entirely.
- **Session ID retrieval**: Store a reference to the `StreamableHTTPTransport` (accessible via the transport's `.session_id` property). Option A: create the transport explicitly and wrap it. Option B: access the transport through the context manager. The simplest approach: store the transport as an instance attribute and read `.session_id` from it after initialize().

#### 4.1.3 Session ID tracking

The v1 code stored `get_session_id` callback and called `self._get_session_id()` after initialize. In v2, the `StreamableHTTPTransport` instance has a `.session_id` property populated by the transport during the initialize POST response.

Approach: Create the transport explicitly, keep a reference, use `terminate_on_close=True`:

```python
transport = StreamableHTTPTransport(uri)
# ... but streamable_http_client creates its own transport internally
```

Alternative: Use `streamable_http_client` as a context manager and access the transport from the exit stack. The cleanest approach is to build the client, create the transport manually, and use the transport directly with `ClientSession`:

```python
transport = StreamableHTTPTransport(uri)
async with streamable_http_client(uri, http_client=http_client_instance, terminate_on_close=True) as (read_stream, write_stream):
    self._session = ClientSession(read_stream, write_stream)
    await self._session.initialize()
    self._session_id = transport.session_id  # populated after initialize
```

However, `streamable_http_client` creates its own internal `StreamableHTTPTransport`. To access `session_id`, we'd need to either:
1. **Use the high-level `Client` class** which exposes session info
2. **Create the transport manually** and use it as a transport (it's an async context manager itself)
3. **Store the session ID from the response headers** in a custom way

**Recommended approach:** Since `StreamableHTTPTransport` is itself an async context manager yielding `TransportStreams`, and the `streamable_http_client` is a convenience wrapper, we can construct the transport directly for full control. However, this is complex (the transport needs a task group, httpx client, etc.).

**Pragmatic approach for CPEX:** The `streamable_http_client` yields `(read_stream, write_stream)`. The internal transport's `session_id` is extracted from the POST response headers during `initialize()`. After `session.initialize()`, we can get the session ID by making a lightweight HTTP GET and reading the `mcp-session-id` header, OR we can simply not track session ID at all since `terminate_on_close=True` handles cleanup.

**Best pragmatic approach:** Keep `_session_id` tracking by using the `MCP_SESSION_ID_HEADER` constant and reading it from a diagnostic request, OR accept that `terminate_on_close=True` eliminates the need for manual session tracking. Given that `_session_id` is only used in `__terminate_http_session` (which we're removing), **we can drop session ID tracking entirely** and remove `_get_session_id`, `_session_id`, and `__terminate_http_session`.

#### 4.1.4 Remove `__terminate_http_session` and related state

Remove:
- `__terminate_http_session()` method (lines 646-663)
- `self._get_session_id` instance attribute
- `self._session_id` instance attribute
- `self._http_client_factory` instance attribute (no longer needed — client is built inline)
- The `MCP_SESSION_ID_HEADER` lazy import (line 651)
- `shutdown()` calls to `__terminate_http_session` (line 641)
- Cleanup of `_get_session_id`, `_session_id`, `_http_client_factory` in `_cleanup_session` and `shutdown`

#### 4.1.5 `McpError` → `MCPError` (line 573)

```python
# BEFORE:
except McpError as e:
    logger.warning("McpError for plugin %s: %s", self.name, e)

# AFTER:
except MCPError as e:
    logger.warning("MCPError for plugin %s: %s", self.name, e)
```

#### 4.1.6 Stdio transport — no changes needed

`stdio_client` signature and return type are compatible. `StdioServerParameters` is still exported from `mcp` top-level.

### 4.2 `cpex/framework/external/mcp/server/runtime.py`

#### 4.2.1 Import block (lines 69-70)

```python
# BEFORE:
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

# AFTER:
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
```

#### 4.2.2 Class rename and base class

```python
# BEFORE:
class SSLCapableFastMCP(FastMCP):

# AFTER:
class SSLCapableFastMCP(MCPServer):
```

(Keep the class name `SSLCapableFastMCP` to minimize ripple effects in tests/docstrings, or rename to `SSLCapableMCPServer` — either is fine. Recommend renaming for clarity.)

#### 4.2.3 Constructor — remove host/port from super() kwargs

```python
# BEFORE (lines ~224-248):
if "host" not in kwargs:
    kwargs["host"] = self.server_config.host
if "port" not in kwargs:
    kwargs["port"] = self.server_config.port
# ... transport_security setup ...
super().__init__(*args, **kwargs)

# AFTER:
if self.server_config.uds and kwargs.get("transport_security") is None:
    kwargs["transport_security"] = TransportSecuritySettings(...)

# Remove host/port from kwargs before passing to MCPServer
kwargs.pop("host", None)
kwargs.pop("port", None)
super().__init__(*args, **kwargs)
```

Actually, the cleaner approach: just don't inject them at all:

```python
def __init__(self, server_config: MCPServerConfig, *args, **kwargs):
    self.server_config = server_config

    if self.server_config.uds and kwargs.get("transport_security") is None:
        kwargs["transport_security"] = TransportSecuritySettings(...)

    # MCPServer v2 does not accept host/port in constructor
    super().__init__(*args, **kwargs)
```

#### 4.2.4 `self.settings.host` / `self.settings.port` → `self.server_config.*`

The `MCPServer.Settings` class no longer has `host`/`port` fields. CPEX's `run_streamable_http_async()` override uses `self.settings.host` and `self.settings.port` extensively:

- Line 364: `host=self.settings.host` (health check uvicorn)
- Line 365: `port=health_port` (health check port)
- Line 366: `logger.info(f"Starting HTTP health check server on {self.settings.host}:{health_port}")`
- Line 439-443: `host=self.settings.host`, `port=self.settings.port` (main uvicorn)
- Line 451: `logger.info(f"Starting plugin server on {self.settings.host}:{self.settings.port}")`
- Line 459: `health_port = self.settings.port + 1000`

Replace all `self.settings.host` → `self.server_config.host`
Replace all `self.settings.port` → `self.server_config.port`

Also: `self.settings.log_level` (line 444) — the `MCPServer.Settings` still has `log_level`. This is fine, no change.

#### 4.2.5 `run()` function — FastMCP instantiation (line 528-531)

```python
# BEFORE:
mcp = FastMCP(
    name=MCP_SERVER_NAME,
    instructions=MCP_SERVER_INSTRUCTIONS,
)

# AFTER:
mcp = MCPServer(
    name=MCP_SERVER_NAME,
    instructions=MCP_SERVER_INSTRUCTIONS,
)
```

#### 4.2.6 Doctest strings

Update all docstring references to "FastMCP" → "MCPServer" throughout the file. The docstrings at lines 8-55 reference `FastMCP` by name and in example code blocks.

#### 4.2.7 `run_stdio_async()` call (line 542)

`MCPServer.run_stdio_async()` exists with the same signature. No change needed.

#### 4.2.8 `streamable_http_app()` call (line 388)

`MCPServer.streamable_http_app()` exists. CPEX calls it without args: `self.streamable_http_app()`. In v2 this method accepts keyword args but has defaults. **No change needed.**

### 4.3 Test files

#### 4.3.1 `test_client_reconnect.py` (lines 216-227, 295-296)

```python
# BEFORE:
from mcp import McpError
from mcp.types import ErrorData
raise McpError(ErrorData(code=-1, message="Connection lost"))

# AFTER:
from mcp import MCPError
raise MCPError(-1, "Connection lost")
```

Also update `from mcp.types import CallToolResult, TextContent` → `from mcp_types import CallToolResult, TextContent` (lines 226, 253).

#### 4.3.2 `test_client_config.py` (lines 19-20)

```python
# BEFORE:
from mcp.types import CallToolResult
from mcp.types import TextContent as MCPTextContent

# AFTER:
from mcp_types import CallToolResult
from mcp_types import TextContent as MCPTextContent
```

#### 4.3.3 `test_client_coverage.py` (line 13)

```python
# BEFORE:
from mcp.types import TextContent

# AFTER:
from mcp_types import TextContent
```

Update mock paths:
- `patch("cpex.framework.external.mcp.client.streamablehttp_client", ...)` → `patch("cpex.framework.external.mcp.client.streamable_http_client", ...)`
- Mock return values change from 3-tuple to 2-tuple `(read_stream, write_stream)`

#### 4.3.4 `test_client_stdio.py` (lines 21-22)

```python
# These are fine — ClientSession, StdioServerParameters, stdio_client are all still
# exported from the same top-level paths in v2:
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
```

**No changes needed** — the top-level `mcp` package re-exports `ClientSession`, `StdioServerParameters`, and `stdio_client`.

---

## 5. Risk Assessment

| Risk | Severity | Mitigation |
|---|---|---|
| `streamable_http_client` internal behavior differs (task groups, SSE handling) | **High** | The transport is a black box; integration tests are mandatory after migration |
| Session ID tracking removal — TLS session termination may fail silently | **Medium** | `terminate_on_close=True` handles this; the SDK sends DELETE with session ID from the transport's internal state |
| `MCPServer` `Settings` class differs — `self.settings.host` returns undefined | **High** | Replace with `self.server_config.host` — this is a deterministic find-and-replace |
| Test mocks for `streamablehttp_client` break | **Medium** | Update mock paths and return value shapes |
| `stdio_client` POSIX shutdown behavior change | **Low** | Only affects child process cleanup on graceful exit; doesn't affect CPEX functionality |
| `MCPError` attribute access (`e.message` vs `e.error.message`) | **Low** | CPEX only logs `e` (the exception repr), doesn't access `.error.message` directly |

---

## 6. Dependencies

The `pyproject.toml` already pins:
```toml
    "mcp==2.0.0b2",
    "mcp-types==2.0.0b2",
```

Per the [Dependency floors section](https://py.sdk.modelcontextprotocol.io/v2/migration/#dependency-floors-raised-and-new-required-dependencies), these new floors apply:
- `anyio>=4.9` (Python <3.14) — check if CPEX pins below this
- `pydantic>=2.12` — CPEX pins `pydantic>=2.12.5` ✅
- `sse-starlette>=3.0.0` — CPEX does not directly depend on this; it's a transitive dep of `mcp`
- `typing-extensions>=4.13.0` — transitive
- `opentelemetry-api>=1.28.0` — **new required dep**, transitive from `mcp`

No action needed on `pyproject.toml` — the pins are already correct.

---

## 7. Execution Plan

| Step | File | Action | Estimated complexity |
|---|---|---|---|
| 1 | `client.py` | Import renames | Trivial |
| 2 | `client.py` | HTTP transport rewrite (factory→instance, 3-tuple→2-tuple, remove termination) | **Complex** |
| 3 | `client.py` | Remove session ID tracking | Moderate |
| 4 | `runtime.py` | Import + class rename | Trivial |
| 5 | `runtime.py` | Constructor host/port removal | Moderate |
| 6 | `runtime.py` | `self.settings.host/port` → `self.server_config.host/port` | Moderate |
| 7 | `runtime.py` | Doctest updates | Trivial |
| 8 | `test_client_reconnect.py` | MCPError + mcp_types | Moderate |
| 9 | `test_client_config.py` | mcp_types | Trivial |
| 10 | `test_client_coverage.py` | mcp_types + mock paths | Moderate |
| 11 | All | Run tests, fix failures | Variable |

**Recommended dispatch:** Steps 1-3 (client.py) and steps 4-7 (runtime.py) are independent and can be done in parallel by two `@fixer` agents. Steps 8-10 (tests) depend on the source files being correct and should follow. Step 11 is the orchestrator's responsibility.

---

## 8. Migration Guide References

All changes reference these sections of the [MCP Python SDK v2 Migration Guide](https://py.sdk.modelcontextprotocol.io/v2/migration/):

| CPEX change | Guide anchor |
|---|---|
| `mcp.types` → `mcp_types` | [`#mcptypes-moved-to-the-mcp-types-package`](https://py.sdk.modelcontextprotocol.io/v2/migration/#mcptypes-moved-to-the-mcp-types-package) |
| `McpError` → `MCPError` | [`#mcperror-renamed-to-mcperror`](https://py.sdk.modelcontextprotocol.io/v2/migration/#mcperror-renamed-to-mcperror) |
| `streamablehttp_client` → `streamable_http_client` | [`#streamablehttp_client-removed`](https://py.sdk.modelcontextprotocol.io/v2/migration/#streamablehttp_client-removed) |
| `get_session_id` callback removed | [`#get_session_id-callback-removed-from-streamable_http_client`](https://py.sdk.modelcontextprotocol.io/v2/migration/#get_session_id-callback-removed-from-streamable_http_client) |
| `FastMCP` → `MCPServer` | [`#fastmcp-renamed-to-mcpserver`](https://py.sdk.modelcontextprotocol.io/v2/migration/#fastmcp-renamed-to-mcpserver) |
| host/port moved from constructor | [`#transport-specific-parameters-moved-from-mcpserver-constructor-to-run-app-methods`](https://py.sdk.modelcontextprotocol.io/v2/migration/#transport-specific-parameters-moved-from-mcpserver-constructor-to-runapp-methods) |
| Constructor param order | [`#mcpserver-constructor-title-description-and-version-added-to-the-positional-parameters`](https://py.sdk.modelcontextprotocol.io/v2/migration/#mcpserver-constructor-title-description-and-version-added-to-the-positional-parameters) |
| Dependency floors | [`#dependency-floors-raised-and-new-required-dependencies`](https://py.sdk.modelcontextprotocol.io/v2/migration/#dependency-floors-raised-and-new-required-dependencies) |
| camelCase → snake_case fields | [`#field-names-changed-from-camelcase-to-snake_case`](https://py.sdk.modelcontextprotocol.io/v2/migration/#field-names-changed-from-camelcase-to-snake_case) |
| stdio_client shutdown | [`#stdio_client-shutdown-reworked`](https://py.sdk.modelcontextprotocol.io/v2/migration/#stdio_client-shutdown-reworked-a-gracefully-exited-servers-children-are-left-alive-on-posix) |
| ClientSession on JSONRPCDispatcher | [`#clientsession-now-runs-on-jsonrpcdispatcher-basesession-removed`](https://py.sdk.modelcontextprotocol.io/v2/migration/#clientsession-now-runs-on-jsonrpcdispatcher-basesession-removed) |
