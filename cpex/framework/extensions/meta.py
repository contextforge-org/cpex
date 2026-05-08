# -*- coding: utf-8 -*-
"""Location: ./cpex/framework/extensions/meta.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Teryl Taylor

Meta extension model.
Host-provided operational metadata about the entity being processed.
Set by the host system (gateway registration, static config, MCP manifest)
before the plugin pipeline runs. Immutable tier — plugins can read
this data for routing and policy decisions but cannot modify it.

Protocol-agnostic: carries the same structure regardless of whether the
entity came from MCP, A2A, gRPC, or REST.
"""

# Third-Party
from pydantic import BaseModel, ConfigDict, Field


class MetaExtension(BaseModel):
    """Host-provided operational metadata about the entity being processed.

    Tags drive route matching and policy group inheritance. Scope provides
    a host-defined grouping (e.g., virtual server ID, namespace). Properties
    carry arbitrary key-value metadata available in policy conditions.

    Immutable — the processing pipeline rejects any modifications.
    Tags are set by the host and static config before the pipeline runs.
    For pipeline-accumulated labels, use ``SecurityExtension.labels`` instead.

    Attributes:
        tags: Entity tags (e.g., ``pii``, ``hr``, ``external-comms``).
            Merged from static config and host-injected runtime tags.
        scope: Host-defined grouping. ContextForge maps this to virtual
            server ID, Kagenti to namespace, etc. CPEX core treats it
            as an opaque string for matching.
        properties: Arbitrary key-value metadata (e.g., ``owner``,
            ``region``, ``data_classification``). Available in policy
            conditions as ``meta.properties.{key}``.

    Examples:
        >>> ext = MetaExtension(
        ...     tags=frozenset({"pii", "hr"}),
        ...     scope="hr-services",
        ...     properties={"owner": "hr-team", "data_classification": "confidential"},
        ... )
        >>> "pii" in ext.tags
        True
        >>> ext.scope
        'hr-services'
        >>> ext.properties["owner"]
        'hr-team'
    """

    model_config = ConfigDict(frozen=True)

    tags: frozenset[str] = Field(
        default_factory=frozenset, description="Entity tags for routing and policy group inheritance."
    )
    scope: str | None = Field(default=None, description="Host-defined grouping (opaque string for matching).")
    properties: dict[str, str] = Field(default_factory=dict, description="Arbitrary key-value metadata.")
