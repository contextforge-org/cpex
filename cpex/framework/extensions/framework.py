# -*- coding: utf-8 -*-
"""Location: ./cpex/framework/extensions/framework.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Teryl Taylor

Framework extension model.
Captures the agentic framework execution environment for messages
originating from or passing through orchestration layers.
Immutable tier — shared reference, no modifications allowed.
"""

# Standard
from typing import Any

# Third-Party
from pydantic import BaseModel, ConfigDict, Field


class FrameworkExtension(BaseModel):
    """Agentic framework execution context.

    Captures framework-level metadata for messages that originate
    from or pass through agentic orchestration layers (LangGraph,
    CrewAI, AutoGen, A2A, etc.). Immutable — the processing pipeline
    rejects any modifications.

    Attributes:
        framework: Framework identifier (e.g., langgraph, crewai, autogen, a2a).
        framework_version: Framework version.
        node_id: Framework-specific node or step identifier.
        graph_id: Graph or workflow identifier.
        metadata: Framework-specific metadata.

    Examples:
        >>> ext = FrameworkExtension(
        ...     framework="langgraph",
        ...     framework_version="0.2.0",
        ...     node_id="weather_node",
        ...     graph_id="travel_planner",
        ... )
        >>> ext.framework
        'langgraph'
        >>> ext.node_id
        'weather_node'
    """

    model_config = ConfigDict(frozen=True)

    framework: str | None = Field(default=None, description="Framework identifier.")
    framework_version: str | None = Field(default=None, description="Framework version.")
    node_id: str | None = Field(default=None, description="Framework-specific node or step identifier.")
    graph_id: str | None = Field(default=None, description="Graph or workflow identifier.")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Framework-specific metadata.")
