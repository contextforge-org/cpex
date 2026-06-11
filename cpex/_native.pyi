"""
Type stubs for cpex._native (Rust PyO3 extension module).

This file provides type hints for the Rust-based native extension.
"""

from typing import Any, Awaitable, Dict, List, Optional

class PyPluginMode:
    """Plugin execution mode enum."""

    SEQUENTIAL: int
    TRANSFORM: int
    AUDIT: int
    CONCURRENT: int
    FIRE_AND_FORGET: int

class PyOnError:
    """Error handling strategy enum."""

    FAIL: int
    LOG: int
    IGNORE: int

class PyPluginConfig:
    """Plugin configuration wrapper."""

    def __init__(
        self,
        name: str,
        kind: str,
        mode: int,
        on_error: int,
        hooks: List[str],
        config: Dict[str, Any],
    ) -> None: ...
    @property
    def name(self) -> str: ...
    @property
    def kind(self) -> str: ...
    @property
    def mode(self) -> int: ...
    @property
    def on_error(self) -> int: ...
    @property
    def hooks(self) -> List[str]: ...
    @property
    def config(self) -> Dict[str, Any]: ...

class PyPluginResult:
    """Plugin execution result."""

    @staticmethod
    def allow() -> PyPluginResult:
        """Create an allow result."""
        ...

    @staticmethod
    def deny(reason: str) -> PyPluginResult:
        """Create a deny result with reason."""
        ...

    @staticmethod
    def modify(payload: Dict[str, Any]) -> PyPluginResult:
        """Create a modify result with new payload."""
        ...

    @property
    def blocked(self) -> bool: ...
    @property
    def reason(self) -> Optional[str]: ...
    @property
    def modified_payload(self) -> Optional[Dict[str, Any]]: ...

class PyPluginContext:
    """Plugin execution context."""

    @property
    def plugin_name(self) -> str: ...
    @property
    def hook_name(self) -> str: ...
    @property
    def request_id(self) -> Optional[str]: ...

class PyPluginContextTable:
    """Plugin context table (dict-like)."""

    def get(self, plugin_name: str) -> Optional[Dict[str, Any]]: ...
    def set(self, plugin_name: str, data: Dict[str, Any]) -> None: ...
    def keys(self) -> List[str]: ...
    def to_dict(self) -> Dict[str, Dict[str, Any]]: ...

class PyExtensions:
    """Extensions wrapper."""

    def __init__(self, data: Optional[Dict[str, Dict[str, Any]]] = None) -> None: ...
    def get(self, namespace: str) -> Optional[Dict[str, Any]]: ...
    def set(self, namespace: str, data: Dict[str, Any]) -> None: ...
    def keys(self) -> List[str]: ...
    def to_dict(self) -> Dict[str, Dict[str, Any]]: ...

class PyMessagePayload:
    """CMF Message payload wrapper."""

    def __init__(self, data: Dict[str, Any]) -> None: ...
    @property
    def schema_version(self) -> str: ...
    @property
    def role(self) -> str: ...
    @property
    def content(self) -> List[Dict[str, Any]]: ...
    @property
    def tool_call_id(self) -> Optional[str]: ...
    @property
    def name(self) -> Optional[str]: ...
    @property
    def channel(self) -> Optional[str]: ...
    def model_copy(self) -> PyMessagePayload:
        """Create a deep copy of the payload."""
        ...

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        ...

class PyPluginManager:
    """
    Rust-based Plugin Manager.

    Provides high-performance plugin execution using Rust backend.
    """

    def __new__(cls, config_path: str) -> PyPluginManager:
        """
        Create a new PluginManager instance.

        Args:
            config_path: Path to the YAML configuration file

        Returns:
            PyPluginManager instance

        Raises:
            ValueError: If config is invalid
        """
        ...

    def initialize(self) -> Awaitable[None]:
        """
        Initialize all plugins asynchronously.

        Returns:
            Awaitable that completes when all plugins are initialized

        Raises:
            RuntimeError: If initialization fails
        """
        ...

    def invoke_hook(
        self,
        hook_name: str,
        payload: Dict[str, Any],
        extensions: Optional[Dict[str, Dict[str, Any]]],
        context_table: Optional[Dict[str, Dict[str, Any]]],
    ) -> Awaitable[Any]:
        """
        Invoke a hook with the given payload.

        Args:
            hook_name: Name of the hook to invoke (e.g., "cmf.tool_pre_invoke")
            payload: Hook payload as dictionary
            extensions: Optional extensions dictionary
            context_table: Optional context table dictionary

        Returns:
            Awaitable that resolves to the pipeline result

        Raises:
            ValueError: If payload is invalid
            RuntimeError: If hook execution fails
        """
        ...

    def shutdown(self) -> Awaitable[None]:
        """
        Shutdown the plugin manager and all plugins.

        Returns:
            Awaitable that completes when shutdown is finished
        """
        ...

    @property
    def config_path(self) -> str:
        """Get the configuration file path."""
        ...

    @property
    def plugin_count(self) -> int:
        """Get the number of loaded plugins."""
        ...

def get_version() -> str:
    """Get the cpex-python extension version."""
    ...

# Made with Bob
