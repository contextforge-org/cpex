# -*- coding: utf-8 -*-
"""Tests for cpex.framework.extensions.tiers module.

Covers mutability tiers, capability gating, extension filtering,
tier constraint validation, and lockdown (private registry, frozen config).
"""

# Standard
from __future__ import annotations

# Third-Party
import pytest

# First-Party
from cpex.framework.extensions.agent import AgentExtension
from cpex.framework.extensions.constants import SlotName
from cpex.framework.extensions.extensions import Extensions
from cpex.framework.extensions.http import HttpExtension
from cpex.framework.extensions.request import RequestExtension
from cpex.framework.extensions.security import (
    SecurityExtension,
    SubjectExtension,
    SubjectType,
)
from cpex.framework.extensions.tiers import (
    AccessPolicy,
    Capability,
    MutabilityTier,
    SlotPolicy,
    TierViolationError,
    _slot_registry,
    filter_extensions,
    merge_extensions,
    validate_tier_constraints,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def subject():
    return SubjectExtension(
        id="user-alice",
        type=SubjectType.USER,
        roles=frozenset({"admin", "developer"}),
        teams=frozenset({"platform"}),
        claims={"sub": "alice", "iss": "idp"},
        permissions=frozenset({"tools.execute", "db.read"}),
    )


@pytest.fixture()
def security_ext(subject):
    return SecurityExtension(
        labels=frozenset({"PII", "CONFIDENTIAL"}),
        classification="confidential",
        subject=subject,
    )


@pytest.fixture()
def full_extensions(security_ext):
    return Extensions(
        request=RequestExtension(environment="test", request_id="req-1"),
        agent=AgentExtension(session_id="sess-1"),
        http=HttpExtension(headers={"Authorization": "Bearer tok"}),
        security=security_ext,
        custom={"key": "value"},
    )


# ---------------------------------------------------------------------------
# Enum / SlotPolicy basics
# ---------------------------------------------------------------------------


class TestMutabilityTier:
    def test_values(self):
        assert MutabilityTier.IMMUTABLE.value == "immutable"
        assert MutabilityTier.MONOTONIC.value == "monotonic"
        assert MutabilityTier.MUTABLE.value == "mutable"

    def test_string_enum(self):
        assert MutabilityTier("immutable") == MutabilityTier.IMMUTABLE


class TestAccessPolicy:
    def test_values(self):
        assert AccessPolicy.UNRESTRICTED.value == "unrestricted"
        assert AccessPolicy.CAPABILITY_GATED.value == "capability_gated"

    def test_string_enum(self):
        assert AccessPolicy("unrestricted") == AccessPolicy.UNRESTRICTED


class TestCapability:
    def test_all_values(self):
        assert len(Capability) == 12  # noqa: PLR2004
        assert Capability.READ_SUBJECT.value == "read_subject"
        assert Capability.APPEND_LABELS.value == "append_labels"
        assert Capability.WRITE_HEADERS.value == "write_headers"
        assert Capability.READ_DELEGATION.value == "read_delegation"
        assert Capability.APPEND_DELEGATION.value == "append_delegation"

    def test_string_enum(self):
        assert Capability("read_agent") == Capability.READ_AGENT


class TestSlotPolicy:
    def test_frozen(self):
        policy = SlotPolicy(MutabilityTier.IMMUTABLE)
        with pytest.raises(AttributeError):
            policy.tier = MutabilityTier.MUTABLE  # type: ignore[misc]

    def test_defaults(self):
        policy = SlotPolicy(MutabilityTier.IMMUTABLE)
        assert policy.access == AccessPolicy.UNRESTRICTED
        assert policy.read_cap is None
        assert policy.write_cap is None

    def test_capability_gated(self):
        policy = SlotPolicy(
            MutabilityTier.IMMUTABLE,
            access=AccessPolicy.CAPABILITY_GATED,
            read_cap=Capability.READ_AGENT,
        )
        assert policy.access == AccessPolicy.CAPABILITY_GATED
        assert policy.read_cap == Capability.READ_AGENT


class TestSlotRegistry:
    def test_base_tier_slots_unrestricted(self):
        for slot in (
            SlotName.REQUEST,
            SlotName.PROVENANCE,
            SlotName.COMPLETION,
            SlotName.LLM,
            SlotName.FRAMEWORK,
            SlotName.MCP,
        ):
            policy = _slot_registry[slot]
            assert policy.tier == MutabilityTier.IMMUTABLE
            assert policy.access == AccessPolicy.UNRESTRICTED
            assert policy.read_cap is None
            assert policy.write_cap is None

    def test_agent_capability_gated(self):
        policy = _slot_registry[SlotName.AGENT]
        assert policy.access == AccessPolicy.CAPABILITY_GATED
        assert policy.read_cap == Capability.READ_AGENT
        assert policy.write_cap is None

    def test_http_capability_gated(self):
        policy = _slot_registry[SlotName.HTTP]
        assert policy.access == AccessPolicy.CAPABILITY_GATED
        assert policy.read_cap == Capability.READ_HEADERS
        assert policy.write_cap == Capability.WRITE_HEADERS

    def test_labels_monotonic_capability_gated(self):
        policy = _slot_registry[SlotName.SECURITY_LABELS]
        assert policy.tier == MutabilityTier.MONOTONIC
        assert policy.access == AccessPolicy.CAPABILITY_GATED
        assert policy.read_cap == Capability.READ_LABELS
        assert policy.write_cap == Capability.APPEND_LABELS

    def test_custom_mutable_unrestricted(self):
        policy = _slot_registry[SlotName.CUSTOM]
        assert policy.tier == MutabilityTier.MUTABLE
        assert policy.access == AccessPolicy.UNRESTRICTED

    def test_security_objects_unrestricted(self):
        policy = _slot_registry[SlotName.SECURITY_OBJECTS]
        assert policy.access == AccessPolicy.UNRESTRICTED

    def test_security_data_unrestricted(self):
        policy = _slot_registry[SlotName.SECURITY_DATA]
        assert policy.access == AccessPolicy.UNRESTRICTED

    def test_subject_subfields_capability_gated(self):
        for slot in (
            SlotName.SECURITY_SUBJECT,
            SlotName.SECURITY_SUBJECT_ROLES,
            SlotName.SECURITY_SUBJECT_TEAMS,
            SlotName.SECURITY_SUBJECT_CLAIMS,
            SlotName.SECURITY_SUBJECT_PERMISSIONS,
        ):
            policy = _slot_registry[slot]
            assert policy.access == AccessPolicy.CAPABILITY_GATED, f"{slot} should be capability-gated"

    def test_registry_is_read_only(self):
        with pytest.raises(TypeError):
            _slot_registry[SlotName.CUSTOM] = SlotPolicy(MutabilityTier.IMMUTABLE)  # type: ignore[index]

    def test_registry_not_in_public_exports(self):
        import cpex.framework.extensions as ext_pkg

        assert "SLOT_REGISTRY" not in ext_pkg.__all__
        assert "filter_extensions" not in ext_pkg.__all__
        assert "validate_tier_constraints" not in ext_pkg.__all__
        assert "SlotPolicy" not in ext_pkg.__all__


# ---------------------------------------------------------------------------
# filter_extensions
# ---------------------------------------------------------------------------


class TestFilterExtensions:
    def test_none_input(self):
        assert filter_extensions(None, frozenset()) is None

    def test_no_capabilities_hides_gated_slots(self, full_extensions):
        filtered = filter_extensions(full_extensions, frozenset())
        # Unrestricted slots pass through
        assert filtered.request is not None
        assert filtered.custom is not None
        # Capability-gated slots hidden
        assert filtered.agent is None
        assert filtered.http is None
        # Security sub-fields: subject hidden, labels hidden
        assert filtered.security is not None
        assert filtered.security.subject is None
        assert filtered.security.labels == frozenset()

    def test_read_agent_makes_agent_visible(self, full_extensions):
        caps = frozenset({"read_agent"})
        filtered = filter_extensions(full_extensions, caps)
        assert filtered.agent is not None
        assert filtered.agent.session_id == "sess-1"

    def test_read_headers_makes_http_visible(self, full_extensions):
        caps = frozenset({"read_headers"})
        filtered = filter_extensions(full_extensions, caps)
        assert filtered.http is not None
        assert filtered.http.headers["Authorization"] == "Bearer tok"

    def test_write_headers_implies_read(self, full_extensions):
        caps = frozenset({"write_headers"})
        filtered = filter_extensions(full_extensions, caps)
        assert filtered.http is not None

    def test_append_labels_implies_read(self, full_extensions):
        caps = frozenset({"append_labels"})
        filtered = filter_extensions(full_extensions, caps)
        assert filtered.security.labels == frozenset({"PII", "CONFIDENTIAL"})

    def test_read_labels_makes_labels_visible(self, full_extensions):
        caps = frozenset({"read_labels"})
        filtered = filter_extensions(full_extensions, caps)
        assert filtered.security.labels == frozenset({"PII", "CONFIDENTIAL"})

    def test_no_filtering_returns_equal_object(self):
        ext = Extensions(request=RequestExtension(environment="test", request_id="r1"))
        result = filter_extensions(ext, frozenset())
        assert result == ext  # Build-up always creates a new frozen instance
        assert result is not ext

    def test_ungated_security_subfields_pass_through(self, full_extensions):
        """security.objects and security.data are always visible."""
        filtered = filter_extensions(full_extensions, frozenset())
        assert filtered.security.objects == full_extensions.security.objects
        assert filtered.security.data == full_extensions.security.data


class TestFilterSubjectGranular:
    """Subject sub-field filtering: roles, teams, claims, permissions gated independently."""

    def test_read_subject_only_hides_subfields(self, full_extensions):
        caps = frozenset({"read_subject"})
        filtered = filter_extensions(full_extensions, caps)
        subj = filtered.security.subject
        assert subj is not None
        assert subj.id == "user-alice"
        assert subj.type == SubjectType.USER
        # Sub-fields hidden
        assert subj.roles == frozenset()
        assert subj.teams == frozenset()
        assert subj.claims == {}
        assert subj.permissions == frozenset()

    def test_read_roles_implies_read_subject(self, full_extensions):
        caps = frozenset({"read_roles"})
        filtered = filter_extensions(full_extensions, caps)
        subj = filtered.security.subject
        assert subj is not None
        assert subj.id == "user-alice"
        assert "admin" in subj.roles
        # Other sub-fields still hidden
        assert subj.teams == frozenset()
        assert subj.claims == {}
        assert subj.permissions == frozenset()

    def test_read_teams_implies_read_subject(self, full_extensions):
        caps = frozenset({"read_teams"})
        filtered = filter_extensions(full_extensions, caps)
        subj = filtered.security.subject
        assert subj is not None
        assert "platform" in subj.teams
        assert subj.roles == frozenset()

    def test_read_claims_implies_read_subject(self, full_extensions):
        caps = frozenset({"read_claims"})
        filtered = filter_extensions(full_extensions, caps)
        subj = filtered.security.subject
        assert subj is not None
        assert subj.claims == {"sub": "alice", "iss": "idp"}
        assert subj.roles == frozenset()

    def test_read_permissions_implies_read_subject(self, full_extensions):
        caps = frozenset({"read_permissions"})
        filtered = filter_extensions(full_extensions, caps)
        subj = filtered.security.subject
        assert subj is not None
        assert "tools.execute" in subj.permissions
        assert subj.roles == frozenset()

    def test_multiple_subject_caps(self, full_extensions):
        caps = frozenset({"read_roles", "read_permissions"})
        filtered = filter_extensions(full_extensions, caps)
        subj = filtered.security.subject
        assert "admin" in subj.roles
        assert "tools.execute" in subj.permissions
        assert subj.teams == frozenset()
        assert subj.claims == {}

    def test_no_subject_extension_no_error(self):
        ext = Extensions(
            security=SecurityExtension(labels=frozenset({"PII"})),
        )
        filtered = filter_extensions(ext, frozenset({"read_labels"}))
        assert filtered.security.labels == frozenset({"PII"})
        assert filtered.security.subject is None


# ---------------------------------------------------------------------------
# validate_tier_constraints
# ---------------------------------------------------------------------------


class TestValidateTierConstraints:
    def test_both_none(self):
        validate_tier_constraints(None, None, frozenset(), "test-plugin")

    def test_no_change_passes(self, full_extensions):
        validate_tier_constraints(full_extensions, full_extensions, frozenset(), "test-plugin")

    def test_immutable_no_write_cap_rejects_change(self):
        before = Extensions(
            request=RequestExtension(environment="prod", request_id="r1"),
        )
        after = Extensions(
            request=RequestExtension(environment="staging", request_id="r1"),
        )
        with pytest.raises(TierViolationError) as exc_info:
            validate_tier_constraints(before, after, frozenset(), "bad-plugin")
        assert exc_info.value.plugin_name == "bad-plugin"
        assert exc_info.value.slot == SlotName.REQUEST
        assert exc_info.value.tier == MutabilityTier.IMMUTABLE

    def test_immutable_gated_rejects_without_cap(self):
        before = Extensions(
            http=HttpExtension(headers={"X-Foo": "bar"}),
        )
        after = Extensions(
            http=HttpExtension(headers={"X-Foo": "baz"}),
        )
        with pytest.raises(TierViolationError) as exc_info:
            validate_tier_constraints(before, after, frozenset(), "bad-plugin")
        assert "write_headers" in exc_info.value.detail

    def test_immutable_gated_allows_with_write_cap(self):
        before = Extensions(
            http=HttpExtension(headers={"X-Foo": "bar"}),
        )
        after = Extensions(
            http=HttpExtension(headers={"X-Foo": "baz"}),
        )
        caps = frozenset({"write_headers"})
        # Should not raise
        validate_tier_constraints(before, after, caps, "good-plugin")

    def test_monotonic_superset_passes(self):
        before = Extensions(
            security=SecurityExtension(labels=frozenset({"PII"})),
        )
        after = Extensions(
            security=SecurityExtension(labels=frozenset({"PII", "CONFIDENTIAL"})),
        )
        caps = frozenset({"append_labels"})
        validate_tier_constraints(before, after, caps, "good-plugin")

    def test_monotonic_removal_rejects(self):
        before = Extensions(
            security=SecurityExtension(labels=frozenset({"PII", "CONFIDENTIAL"})),
        )
        after = Extensions(
            security=SecurityExtension(labels=frozenset({"PII"})),
        )
        caps = frozenset({"append_labels"})
        with pytest.raises(TierViolationError) as exc_info:
            validate_tier_constraints(before, after, caps, "bad-plugin")
        assert "monotonic" in str(exc_info.value)
        assert exc_info.value.tier == MutabilityTier.MONOTONIC

    def test_monotonic_without_cap_rejects(self):
        before = Extensions(
            security=SecurityExtension(labels=frozenset({"PII"})),
        )
        after = Extensions(
            security=SecurityExtension(labels=frozenset({"PII", "SECRET"})),
        )
        with pytest.raises(TierViolationError) as exc_info:
            validate_tier_constraints(before, after, frozenset(), "bad-plugin")
        assert "append_labels" in exc_info.value.detail

    def test_mutable_allows_any_change(self):
        before = Extensions(custom={"key": "value"})
        after = Extensions(custom={"key": "changed", "new": "stuff"})
        validate_tier_constraints(before, after, frozenset(), "plugin")

    def test_mutable_allows_deletion(self):
        before = Extensions(custom={"key": "value"})
        after = Extensions(custom=None)
        validate_tier_constraints(before, after, frozenset(), "plugin")


class TestTierViolationError:
    def test_attributes(self):
        err = TierViolationError("my-plugin", SlotName.REQUEST, MutabilityTier.IMMUTABLE, "changed")
        assert err.plugin_name == "my-plugin"
        assert err.slot == SlotName.REQUEST
        assert err.tier == MutabilityTier.IMMUTABLE
        assert err.detail == "changed"

    def test_message(self):
        err = TierViolationError("p", SlotName.REQUEST, MutabilityTier.IMMUTABLE, "nope")
        assert "p" in str(err)
        assert "immutable" in str(err)
        assert "request" in str(err)
        assert "nope" in str(err)


# ---------------------------------------------------------------------------
# merge_extensions
# ---------------------------------------------------------------------------


class TestMergeExtensions:
    def test_none_original_returns_none(self):
        output = Extensions(custom={"key": "val"})
        assert merge_extensions(None, output, frozenset(), "p") is None

    def test_none_output_returns_original(self):
        original = Extensions(custom={"key": "val"})
        assert merge_extensions(original, None, frozenset(), "p") is original

    def test_no_changes_returns_original(self):
        original = Extensions(
            request=RequestExtension(environment="prod", request_id="r1"),
            custom={"key": "val"},
        )
        output = original.model_copy()
        result = merge_extensions(original, output, frozenset(), "p")
        assert result is original

    def test_immutable_slots_ignored(self):
        original = Extensions(
            request=RequestExtension(environment="prod", request_id="r1"),
        )
        output = Extensions(
            request=RequestExtension(environment="staging", request_id="r1"),
        )
        result = merge_extensions(original, output, frozenset(), "p")
        assert result is original
        assert result.request.environment == "prod"

    def test_immutable_agent_ignored(self):
        original = Extensions(
            agent=AgentExtension(agent_id="a1", session_id="s1"),
        )
        output = Extensions(
            agent=AgentExtension(agent_id="hijacked", session_id="s1"),
        )
        result = merge_extensions(original, output, frozenset({"read_agent"}), "p")
        assert result is original
        assert result.agent.agent_id == "a1"

    def test_custom_accepted_without_cap(self):
        original = Extensions(custom={"key": "val"})
        output = Extensions(custom={"key": "changed", "new": "stuff"})
        result = merge_extensions(original, output, frozenset(), "p")
        assert result.custom == {"key": "changed", "new": "stuff"}
        # Immutable slots unchanged
        assert result.request is None

    def test_custom_deletion_accepted(self):
        original = Extensions(custom={"key": "val"})
        output = Extensions(custom=None)
        result = merge_extensions(original, output, frozenset(), "p")
        assert result.custom is None

    def test_http_accepted_with_write_cap(self):
        original = Extensions(
            http=HttpExtension(headers={"X-Foo": "bar"}),
        )
        output = Extensions(
            http=HttpExtension(headers={"X-Foo": "baz"}),
        )
        caps = frozenset({"write_headers"})
        result = merge_extensions(original, output, caps, "p")
        assert result.http.headers == {"X-Foo": "baz"}

    def test_http_ignored_without_write_cap(self):
        original = Extensions(
            http=HttpExtension(headers={"X-Foo": "bar"}),
        )
        output = Extensions(
            http=HttpExtension(headers={"X-Foo": "baz"}),
        )
        result = merge_extensions(original, output, frozenset({"read_headers"}), "p")
        assert result is original
        assert result.http.headers == {"X-Foo": "bar"}

    def test_labels_accepted_with_append_cap(self):
        original = Extensions(
            security=SecurityExtension(labels=frozenset({"PII"})),
        )
        output = Extensions(
            security=SecurityExtension(labels=frozenset({"PII", "CONFIDENTIAL"})),
        )
        caps = frozenset({"append_labels"})
        result = merge_extensions(original, output, caps, "p")
        assert result.security.labels == frozenset({"PII", "CONFIDENTIAL"})

    def test_labels_ignored_without_cap(self):
        original = Extensions(
            security=SecurityExtension(labels=frozenset({"PII"})),
        )
        output = Extensions(
            security=SecurityExtension(labels=frozenset({"PII", "CONFIDENTIAL"})),
        )
        result = merge_extensions(original, output, frozenset(), "p")
        assert result is original
        assert result.security.labels == frozenset({"PII"})

    def test_labels_removal_rejected(self):
        original = Extensions(
            security=SecurityExtension(labels=frozenset({"PII", "CONFIDENTIAL"})),
        )
        output = Extensions(
            security=SecurityExtension(labels=frozenset({"PII"})),
        )
        caps = frozenset({"append_labels"})
        with pytest.raises(TierViolationError) as exc_info:
            merge_extensions(original, output, caps, "bad-plugin")
        assert exc_info.value.tier == MutabilityTier.MONOTONIC

    def test_security_subject_ignored(self):
        """Subject is immutable — plugin changes are discarded."""
        original = Extensions(
            security=SecurityExtension(
                subject=SubjectExtension(
                    id="alice",
                    type=SubjectType.USER,
                    roles=frozenset({"admin"}),
                ),
            ),
        )
        output = Extensions(
            security=SecurityExtension(
                subject=SubjectExtension(
                    id="eve",
                    type=SubjectType.USER,
                    roles=frozenset({"root"}),
                ),
            ),
        )
        caps = frozenset({"read_subject", "read_roles"})
        result = merge_extensions(original, output, caps, "p")
        assert result is original
        assert result.security.subject.id == "alice"

    def test_mixed_changes(self, full_extensions):
        """Only writable slots are accepted in a single merge."""
        output = full_extensions.model_copy(
            update={
                # Immutable — should be ignored
                "request": RequestExtension(environment="hijacked", request_id="r1"),
                # Mutable — should be accepted
                "custom": {"injected": True},
            }
        )
        result = merge_extensions(full_extensions, output, frozenset(), "p")
        assert result.request.environment == full_extensions.request.environment
        assert result.custom == {"injected": True}


# ---------------------------------------------------------------------------
# PluginConfig capabilities and frozen lockdown
# ---------------------------------------------------------------------------


class TestPluginConfigCapabilities:
    _PLUGIN_BASE = {"name": "test-plugin", "kind": "test.Plugin"}

    def test_valid_capabilities(self):
        from cpex.framework.models import PluginConfig

        conf = PluginConfig(
            **self._PLUGIN_BASE,
            capabilities=["read_headers", "append_labels"],
        )
        assert conf.capabilities == frozenset({"read_headers", "append_labels"})

    def test_unknown_capability_rejected(self):
        from cpex.framework.models import PluginConfig

        with pytest.raises(ValueError, match="Unknown capability"):
            PluginConfig(**self._PLUGIN_BASE, capabilities=["bogus_cap"])

    def test_empty_capabilities_default(self):
        from cpex.framework.models import PluginConfig

        conf = PluginConfig(**self._PLUGIN_BASE)
        assert conf.capabilities == frozenset()

    def test_capabilities_serialization(self):
        import orjson

        from cpex.framework.models import PluginConfig

        conf = PluginConfig(
            **self._PLUGIN_BASE,
            capabilities=["read_agent", "read_headers"],
        )
        data = orjson.loads(orjson.dumps(conf.model_dump()))
        assert sorted(data["capabilities"]) == ["read_agent", "read_headers"]

    def test_frozen_config_prevents_capability_escalation(self):
        from pydantic import ValidationError

        from cpex.framework.models import PluginConfig

        conf = PluginConfig(**self._PLUGIN_BASE)
        with pytest.raises(ValidationError):
            conf.capabilities = frozenset({"write_headers"})  # type: ignore[misc]

    def test_frozen_config_prevents_field_mutation(self):
        from pydantic import ValidationError

        from cpex.framework.models import PluginConfig

        conf = PluginConfig(**self._PLUGIN_BASE)
        with pytest.raises(ValidationError):
            conf.name = "hijacked"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Defensive config copy and PluginRef trusted config
# ---------------------------------------------------------------------------


class TestDefensiveConfigCopy:
    """Verify the trust boundary between Manager and plugins."""

    _PLUGIN_BASE = {"name": "copy-test", "kind": "test.Plugin"}

    def test_plugin_ref_trusted_config_is_separate_from_plugin(self):
        """PluginRef's trusted_config should be a different object than the plugin's config."""
        from cpex.framework.base import Plugin, PluginRef
        from cpex.framework.models import PluginConfig

        original = PluginConfig(**self._PLUGIN_BASE, capabilities=["read_headers"])
        copy = original.model_copy()
        plugin = Plugin(copy)
        ref = PluginRef(plugin, trusted_config=original)

        # The plugin holds the copy, the ref holds the original
        assert ref.trusted_config is original
        assert plugin.config is copy
        assert ref.trusted_config is not plugin.config

    def test_plugin_ref_reads_from_trusted_config(self):
        """PluginRef properties should read from trusted_config, not from the plugin."""
        from cpex.framework.base import Plugin, PluginRef
        from cpex.framework.models import PluginConfig, PluginMode

        original = PluginConfig(
            **self._PLUGIN_BASE,
            mode=PluginMode.CONCURRENT,
            priority=42,
            tags=["trusted"],
            capabilities=["read_headers"],
        )
        # Give the plugin a different copy with different values
        plugin_copy = PluginConfig(
            name="copy-test",
            kind="test.Plugin",
            mode=PluginMode.SEQUENTIAL,
            priority=99,
            tags=["untrusted"],
        )
        plugin = Plugin(plugin_copy)
        ref = PluginRef(plugin, trusted_config=original)

        # All properties come from trusted_config
        assert ref.mode == PluginMode.CONCURRENT
        assert ref.priority == 42
        assert ref.tags == ["trusted"]
        assert ref.capabilities == frozenset({"read_headers"})

    def test_plugin_ref_fallback_without_trusted_config(self):
        """Without trusted_config, PluginRef falls back to plugin.config."""
        from cpex.framework.base import Plugin, PluginRef
        from cpex.framework.models import PluginConfig

        config = PluginConfig(**self._PLUGIN_BASE)
        plugin = Plugin(config)
        ref = PluginRef(plugin)

        assert ref.trusted_config is plugin.config

    def test_model_copy_produces_equal_but_distinct_config(self):
        """model_copy() should produce an equal but distinct PluginConfig."""
        from cpex.framework.models import PluginConfig

        original = PluginConfig(**self._PLUGIN_BASE, capabilities=["append_labels"])
        copy = original.model_copy()

        assert copy == original
        assert copy is not original
        assert copy.capabilities == original.capabilities

    def test_registry_passes_trusted_config_to_ref(self):
        """PluginInstanceRegistry.register() should pass trusted_config to PluginRef."""
        from cpex.framework.base import Plugin
        from cpex.framework.models import PluginConfig
        from cpex.framework.registry import PluginInstanceRegistry

        original = PluginConfig(**self._PLUGIN_BASE, capabilities=["read_headers"])
        copy = original.model_copy()
        plugin = Plugin(copy)

        registry = PluginInstanceRegistry()
        registry.register(plugin, trusted_config=original)

        ref = registry.get_plugin("copy-test")
        assert ref is not None
        assert ref.trusted_config is original
        assert ref.plugin.config is copy
        assert ref.trusted_config is not ref.plugin.config
