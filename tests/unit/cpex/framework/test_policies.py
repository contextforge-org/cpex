# -*- coding: utf-8 -*-
"""Location: ./tests/unit/cpex/framework/test_policies.py
Copyright 2026
SPDX-License-Identifier: Apache-2.0
Authors: Fred Araujo

Tests for hook payload policies.
"""

# Standard
from unittest.mock import patch

# Third-Party
import pytest
from pydantic import BaseModel, Field, ValidationError

# First-Party
from cpex.framework.hooks.policies import DefaultHookPolicy, HookPayloadPolicy, apply_policy
from cpex.framework.models import PluginPayload
from tests.unit.cpex.fixtures.common.models import Message, PromptResult, Role, TextContent


class SamplePayload(PluginPayload):
    """Test payload with writable and non-writable fields."""

    name: str
    args: dict = Field(default_factory=dict)
    secret: str = "original"


class TestHookPayloadPolicy:
    """Tests for HookPayloadPolicy dataclass."""

    def test_policy_is_frozen(self):
        policy = HookPayloadPolicy(writable_fields=frozenset({"name"}))
        with pytest.raises(AttributeError):
            policy.writable_fields = frozenset({"other"})  # type: ignore[misc]

    def test_writable_fields_membership(self):
        policy = HookPayloadPolicy(writable_fields=frozenset({"name", "args"}))
        assert "name" in policy.writable_fields
        assert "args" in policy.writable_fields
        assert "secret" not in policy.writable_fields


class TestDefaultHookPolicy:
    """Tests for DefaultHookPolicy enum."""

    def test_allow_value(self):
        assert DefaultHookPolicy.ALLOW.value == "allow"

    def test_deny_value(self):
        assert DefaultHookPolicy.DENY.value == "deny"

    def test_from_string(self):
        assert DefaultHookPolicy("allow") == DefaultHookPolicy.ALLOW
        assert DefaultHookPolicy("deny") == DefaultHookPolicy.DENY


class TestApplyPolicy:
    """Tests for apply_policy function."""

    def test_allows_writable_field_change(self):
        policy = HookPayloadPolicy(writable_fields=frozenset({"name", "args"}))
        original = SamplePayload(name="old", args={"key": "val"}, secret="s")
        modified = SamplePayload(name="new", args={"key": "val"}, secret="s")

        result = apply_policy(original, modified, policy)
        assert result is not None
        assert result.name == "new"  # type: ignore[union-attr]

    def test_filters_non_writable_field(self):
        policy = HookPayloadPolicy(writable_fields=frozenset({"name"}))
        original = SamplePayload(name="old", secret="original")
        modified = SamplePayload(name="new", secret="hacked")

        result = apply_policy(original, modified, policy)
        assert result is not None
        assert result.name == "new"  # type: ignore[union-attr]
        assert result.secret == "original"  # type: ignore[union-attr]

    def test_returns_none_when_no_effective_changes(self):
        policy = HookPayloadPolicy(writable_fields=frozenset({"name"}))
        original = SamplePayload(name="same", secret="s")
        modified = SamplePayload(name="same", secret="hacked")

        result = apply_policy(original, modified, policy)
        assert result is None

    def test_returns_none_for_identical_payloads(self):
        policy = HookPayloadPolicy(writable_fields=frozenset({"name", "args", "secret"}))
        original = SamplePayload(name="same", args={}, secret="s")
        modified = SamplePayload(name="same", args={}, secret="s")

        result = apply_policy(original, modified, policy)
        assert result is None

    def test_multiple_writable_fields_changed(self):
        policy = HookPayloadPolicy(writable_fields=frozenset({"name", "args"}))
        original = SamplePayload(name="old", args={"a": "1"}, secret="s")
        modified = SamplePayload(name="new", args={"b": "2"}, secret="hacked")

        result = apply_policy(original, modified, policy)
        assert result is not None
        assert result.name == "new"  # type: ignore[union-attr]
        assert result.args == {"b": "2"}  # type: ignore[union-attr]
        assert result.secret == "s"  # type: ignore[union-attr]

    def test_empty_writable_fields_rejects_all(self):
        policy = HookPayloadPolicy(writable_fields=frozenset())
        original = SamplePayload(name="old", secret="s")
        modified = SamplePayload(name="new", secret="hacked")

        result = apply_policy(original, modified, policy)
        assert result is None

    def test_sentinel_skip_for_missing_attribute(self):
        """When a declared field is absent from the modified instance's __dict__
        (defensive guard), the field is skipped via the _SENTINEL check."""
        policy = HookPayloadPolicy(writable_fields=frozenset({"name", "secret"}))
        original = SamplePayload(name="old", secret="s")
        modified = SamplePayload(name="new", secret="changed")

        # Remove 'secret' from the modified instance's internal storage
        # to trigger the new_val is _SENTINEL branch
        del modified.__dict__["secret"]

        result = apply_policy(original, modified, policy)
        assert result is not None
        assert result.name == "new"  # type: ignore[union-attr]
        # secret should be unchanged (skipped because sentinel)
        assert result.secret == "s"  # type: ignore[union-attr]

    def test_basemodel_field_equal_skipped(self):
        """When both old and new values are BaseModel instances with identical
        content, apply_policy uses model_dump() comparison and skips the field."""

        class Inner(BaseModel):
            x: int = 1
            y: str = "hello"

        class PayloadWithModel(PluginPayload):
            name: str
            nested: Inner = Field(default_factory=Inner)

        policy = HookPayloadPolicy(writable_fields=frozenset({"name", "nested"}))
        original = PayloadWithModel(name="old", nested=Inner(x=1, y="hello"))
        modified = PayloadWithModel(name="new", nested=Inner(x=1, y="hello"))

        result = apply_policy(original, modified, policy)
        assert result is not None
        assert result.name == "new"  # type: ignore[union-attr]
        # nested is structurally identical so should not appear in updates
        assert result.nested.x == 1  # type: ignore[union-attr]

    def test_basemodel_field_changed_accepted(self):
        """When both old and new values are BaseModel but differ, the writable
        field change is accepted via model_dump() comparison."""

        class Inner(BaseModel):
            x: int = 1

        class PayloadWithModel(PluginPayload):
            name: str
            nested: Inner = Field(default_factory=Inner)

        policy = HookPayloadPolicy(writable_fields=frozenset({"nested"}))
        original = PayloadWithModel(name="old", nested=Inner(x=1))
        modified = PayloadWithModel(name="old", nested=Inner(x=99))

        result = apply_policy(original, modified, policy)
        assert result is not None
        assert result.nested.x == 99  # type: ignore[union-attr]

    def test_copyonwritedict_args_empty_modification_preserved(self):
        """Regression test for bug where CopyOnWriteDict equality caused
        apply_policy to drop valid empty args modification.
        
        When a plugin receives args as CopyOnWriteDict with data and returns
        an empty dict, apply_policy should treat this as a valid modification.
        Previously, CopyOnWriteDict.__eq__ was not implemented, causing the
        comparison to use dict's default equality which compared the empty
        base storage, incorrectly returning True for CopyOnWriteDict({...}) == {}.
        """
        from cpex.framework.memory import CopyOnWriteDict

        policy = HookPayloadPolicy(writable_fields=frozenset({"args"}))
        
        # Simulate plugin receiving payload with CopyOnWriteDict args
        original = SamplePayload(
            name="test",
            args=CopyOnWriteDict({
                "wxo_connection_id": "",
                "wxo_auth": "fake-token",
                "wxo_environment_id": "draft",
            }),
            secret="s",
        )
        
        # Plugin strips all args, returning empty dict
        modified = SamplePayload(name="test", args={}, secret="s")
        
        result = apply_policy(original, modified, policy)
        
        # The modification should be preserved, not dropped
        assert result is not None, "apply_policy should not return None when args changed from {...} to {}"
        assert result.args == {}  # type: ignore[union-attr]
        assert result.name == "test"  # type: ignore[union-attr]
        assert result.secret == "s"  # type: ignore[union-attr]

    def test_copyonwritedict_args_partial_modification_preserved(self):
        """Test that partial arg removal is also preserved correctly."""
        from cpex.framework.memory import CopyOnWriteDict

        policy = HookPayloadPolicy(writable_fields=frozenset({"args"}))
        
        original = SamplePayload(
            name="test",
            args=CopyOnWriteDict({
                "wxo_auth": "token",
                "real_arg": "value",
            }),
            secret="s",
        )
        
        # Plugin removes only wxo_auth, keeping real_arg
        modified = SamplePayload(name="test", args={"real_arg": "value"}, secret="s")
        
        result = apply_policy(original, modified, policy)
        
        assert result is not None
        assert result.args == {"real_arg": "value"}  # type: ignore[union-attr]


class TestPluginPayloadFrozen:
    """Tests for frozen PluginPayload base class."""

    def test_payload_is_immutable(self):
        payload = SamplePayload(name="test", args={}, secret="s")
        with pytest.raises(ValidationError, match="frozen"):
            payload.name = "changed"  # type: ignore[misc]

    def test_payload_model_copy(self):
        payload = SamplePayload(name="test", args={}, secret="s")
        copied = payload.model_copy(update={"name": "updated"})
        assert copied.name == "updated"
        assert payload.name == "test"  # original unchanged


class TestAgentMessageCoercion:
    """Tests for _coerce_messages field validator on agent payloads."""

    def test_pre_invoke_dict_messages_coerced(self):
        from cpex.framework.hooks.agents import AgentPreInvokePayload
        from cpex.framework.utils import StructuredData

        payload = AgentPreInvokePayload(
            agent_id="agent-1",
            messages=[{"role": "user", "content": {"type": "text", "text": "hello"}}],
        )
        assert isinstance(payload.messages[0], StructuredData)
        assert payload.messages[0].role == "user"
        assert payload.messages[0].content.text == "hello"

    def test_post_invoke_dict_messages_coerced(self):
        from cpex.framework.hooks.agents import AgentPostInvokePayload
        from cpex.framework.utils import StructuredData

        payload = AgentPostInvokePayload(
            agent_id="agent-1",
            messages=[{"role": "assistant", "content": {"type": "text", "text": "world"}}],
        )
        assert isinstance(payload.messages[0], StructuredData)
        assert payload.messages[0].content.text == "world"

    def test_real_message_objects_pass_through(self):
        from cpex.framework.hooks.agents import AgentPreInvokePayload

        msg = Message(role="user", content=TextContent(type="text", text="hi"))
        payload = AgentPreInvokePayload(agent_id="agent-1", messages=[msg])
        assert payload.messages[0] is msg

    def test_empty_messages_list(self):
        from cpex.framework.hooks.agents import AgentPreInvokePayload

        payload = AgentPreInvokePayload(agent_id="agent-1", messages=[])
        assert payload.messages == []


class TestProtocolConformance:
    """Verify gateway concrete types satisfy framework protocols."""

    def test_message_satisfies_message_like(self):
        from cpex.framework.protocols import MessageLike

        msg = Message(role="user", content=TextContent(type="text", text="hello"))
        assert isinstance(msg, MessageLike)

    def test_prompt_result_satisfies_prompt_result_like(self):
        from cpex.framework.protocols import PromptResultLike

        result = PromptResult(
            messages=[Message(role="user", content=TextContent(type="text", text="hi"))],
            description="test",
        )
        assert isinstance(result, PromptResultLike)

    def test_simple_namespace_satisfies_message_like(self):
        from types import SimpleNamespace

        from cpex.framework.protocols import MessageLike

        msg = SimpleNamespace(role=Role.USER, content="hello")
        assert isinstance(msg, MessageLike)


class TestPromptPosthookCoercion:
    """Tests for PromptPosthookPayload._coerce_result field validator."""

    def test_dict_result_coerced_to_structured_data(self):
        from cpex.framework.hooks.prompts import PromptPosthookPayload
        from cpex.framework.utils import StructuredData

        payload = PromptPosthookPayload(
            prompt_id="test",
            result={"messages": [{"role": "user", "content": {"type": "text", "text": "hi"}}]},
        )
        assert isinstance(payload.result, StructuredData)
        assert payload.result.messages[0].content.text == "hi"

    def test_non_dict_result_passthrough(self):
        from cpex.framework.hooks.prompts import PromptPosthookPayload

        ns = PromptResult(messages=[], description=None)
        payload = PromptPosthookPayload(prompt_id="test", result=ns)
        assert payload.result is ns

    def test_pydantic_model_result_passthrough(self):
        from cpex.framework.hooks.prompts import PromptPosthookPayload

        class FakeResult(BaseModel):
            messages: list = []
            description: str = "test"

        fake = FakeResult()
        payload = PromptPosthookPayload(prompt_id="test", result=fake)
        assert payload.result is fake


class TestExecutorPolicyEnforcement:
    """Tests for policy enforcement in PluginExecutor.execute()."""

    @pytest.mark.asyncio
    async def test_explicit_policy_filters_writable_fields(self):
        from cpex.framework.base import HookRef, Plugin, PluginRef
        from cpex.framework.manager import PluginExecutor
        from cpex.framework.models import GlobalContext, PluginConfig, PluginResult

        class ModifyingPlugin(Plugin):
            async def test_hook(self, payload, context):
                modified = payload.model_copy(update={"name": "new", "secret": "hacked"})
                return PluginResult(continue_processing=True, modified_payload=modified)

        config = PluginConfig(name="modifier", kind="test.Plugin", version="1.0", hooks=["test_hook"])
        plugin = ModifyingPlugin(config)
        ref = PluginRef(plugin)
        hook_ref = HookRef("test_hook", ref)

        policies = {"test_hook": HookPayloadPolicy(writable_fields=frozenset({"name"}))}
        executor = PluginExecutor(hook_policies=policies)

        payload = SamplePayload(name="old", secret="original")
        global_ctx = GlobalContext(request_id="1")

        result, _ = await executor.execute(
            [hook_ref],
            payload,
            global_ctx,
            hook_type="test_hook",
        )
        assert result.modified_payload is not None
        assert result.modified_payload.name == "new"
        assert result.modified_payload.secret == "original"  # filtered by policy

    @pytest.mark.asyncio
    async def test_default_deny_rejects_modifications(self):
        from cpex.framework.base import HookRef, Plugin, PluginRef
        from cpex.framework.manager import PluginExecutor
        from cpex.framework.models import GlobalContext, PluginConfig, PluginResult

        class ModifyingPlugin(Plugin):
            async def test_hook(self, payload, context):
                modified = payload.model_copy(update={"name": "new"})
                return PluginResult(continue_processing=True, modified_payload=modified)

        config = PluginConfig(name="modifier", kind="test.Plugin", version="1.0", hooks=["test_hook"])
        plugin = ModifyingPlugin(config)
        ref = PluginRef(plugin)
        hook_ref = HookRef("test_hook", ref)

        # No policies passed — default deny should reject all
        with patch("cpex.framework.manager.settings") as mock_settings:
            mock_settings.default_hook_policy = "deny"
            executor = PluginExecutor(hook_policies={})

        payload = SamplePayload(name="old", secret="original")
        global_ctx = GlobalContext(request_id="1")

        result, _ = await executor.execute(
            [hook_ref],
            payload,
            global_ctx,
            hook_type="test_hook",
        )
        # With deny policy, modifications should be rejected — modified_payload is None
        assert result.modified_payload is None

    @pytest.mark.asyncio
    async def test_explicit_policy_no_effective_change(self):
        from cpex.framework.base import HookRef, Plugin, PluginRef
        from cpex.framework.manager import PluginExecutor
        from cpex.framework.models import GlobalContext, PluginConfig, PluginResult

        class ModifyingPlugin(Plugin):
            async def test_hook(self, payload, context):
                # Only modify 'secret' which is NOT writable
                modified = payload.model_copy(update={"secret": "hacked"})
                return PluginResult(continue_processing=True, modified_payload=modified)

        config = PluginConfig(name="modifier", kind="test.Plugin", version="1.0", hooks=["test_hook"])
        plugin = ModifyingPlugin(config)
        ref = PluginRef(plugin)
        hook_ref = HookRef("test_hook", ref)

        policies = {"test_hook": HookPayloadPolicy(writable_fields=frozenset({"name"}))}
        executor = PluginExecutor(hook_policies=policies)

        payload = SamplePayload(name="old", secret="original")
        global_ctx = GlobalContext(request_id="1")

        result, _ = await executor.execute(
            [hook_ref],
            payload,
            global_ctx,
            hook_type="test_hook",
        )
        # apply_policy returns None because no writable fields changed — so modified_payload stays None
        assert result.modified_payload is None

    @pytest.mark.asyncio
    async def test_in_place_nested_mutation_caught_by_policy(self):
        """Plugins that mutate nested dicts in place should not bypass policy filtering."""
        from cpex.framework.base import HookRef, Plugin, PluginRef
        from cpex.framework.manager import PluginExecutor
        from cpex.framework.models import GlobalContext, PluginConfig, PluginResult

        class InPlaceMutatingPlugin(Plugin):
            async def test_hook(self, payload, context):
                # Mutate the nested dict in place — bypasses frozen=True
                # because Pydantic's frozen only protects top-level assignment.
                payload.args["injected"] = "evil"
                # Also mutate 'secret' (non-writable) via in-place nested trick
                # and return the mutated payload as modified_payload.
                return PluginResult(
                    continue_processing=True,
                    modified_payload=payload.model_copy(
                        update={"secret": "hacked", "args": {**payload.args, "injected": "evil"}}
                    ),
                )

        config = PluginConfig(name="mutator", kind="test.Plugin", version="1.0", hooks=["test_hook"])
        plugin = InPlaceMutatingPlugin(config)
        ref = PluginRef(plugin)
        hook_ref = HookRef("test_hook", ref)

        # Only 'name' is writable — 'args' and 'secret' should be rejected
        policies = {"test_hook": HookPayloadPolicy(writable_fields=frozenset({"name"}))}
        executor = PluginExecutor(hook_policies=policies)

        payload = SamplePayload(name="old", args={"key": "value"}, secret="original")
        global_ctx = GlobalContext(request_id="1")

        result, _ = await executor.execute(
            [hook_ref],
            payload,
            global_ctx,
            hook_type="test_hook",
        )
        # The snapshot preserves the original args, so the in-place
        # mutation and 'secret' change are both caught by the policy diff
        # and rejected.  No writable field ('name') was changed, so
        # modified_payload should be None.
        assert result.modified_payload is None

    @pytest.mark.asyncio
    async def test_enforce_early_return_uses_policy_filtered_payload(self):
        """When a CONCURRENT plugin short-circuits after a prior plugin made
        policy-approved modifications, the early return must carry those
        filtered modifications via current_payload — not the raw result."""
        from cpex.framework.base import HookRef, Plugin, PluginRef
        from cpex.framework.manager import PluginExecutor
        from cpex.framework.models import GlobalContext, PluginConfig, PluginMode, PluginResult

        class ModifyingPlugin(Plugin):
            async def test_hook(self, payload, context):
                modified = payload.model_copy(update={"name": "filtered", "secret": "hacked"})
                return PluginResult(continue_processing=True, modified_payload=modified)

        class BlockingPlugin(Plugin):
            async def test_hook(self, payload, context):
                return PluginResult(continue_processing=False)

        modify_config = PluginConfig(name="modifier", kind="test.Plugin", version="1.0", hooks=["test_hook"])
        modify_plugin = ModifyingPlugin(modify_config)
        modify_ref = PluginRef(modify_plugin)
        modify_hook = HookRef("test_hook", modify_ref)

        block_config = PluginConfig(
            name="blocker", kind="test.Plugin", version="1.0", hooks=["test_hook"], mode=PluginMode.CONCURRENT
        )
        block_plugin = BlockingPlugin(block_config)
        block_ref = PluginRef(block_plugin)
        block_hook = HookRef("test_hook", block_ref)

        # Only 'name' is writable
        policies = {"test_hook": HookPayloadPolicy(writable_fields=frozenset({"name"}))}
        executor = PluginExecutor(hook_policies=policies)

        payload = SamplePayload(name="old", secret="original")
        global_ctx = GlobalContext(request_id="1")

        result, _ = await executor.execute(
            [modify_hook, block_hook],
            payload,
            global_ctx,
            hook_type="test_hook",
        )
        assert result.continue_processing is False
        # The first plugin's writable modification must survive via current_payload
        assert result.modified_payload is not None
        assert result.modified_payload.name == "filtered"  # writable — accepted
        assert result.modified_payload.secret == "original"  # non-writable — filtered
        assert result.violation is None

    @pytest.mark.asyncio
    async def test_enforce_early_return_carries_metadata(self):
        """The early-return path must carry accumulated metadata from earlier
        plugins, consistent with the normal return path."""
        from cpex.framework.base import HookRef, Plugin, PluginRef
        from cpex.framework.manager import PluginExecutor
        from cpex.framework.models import GlobalContext, PluginConfig, PluginMode, PluginResult

        class MetadataPlugin(Plugin):
            async def test_hook(self, payload, context):
                return PluginResult(continue_processing=True, metadata={"source": "plugin_a"})

        class BlockingPlugin(Plugin):
            async def test_hook(self, payload, context):
                return PluginResult(continue_processing=False)

        meta_config = PluginConfig(name="meta", kind="test.Plugin", version="1.0", hooks=["test_hook"])
        meta_plugin = MetadataPlugin(meta_config)
        meta_ref = PluginRef(meta_plugin)
        meta_hook = HookRef("test_hook", meta_ref)

        block_config = PluginConfig(
            name="blocker", kind="test.Plugin", version="1.0", hooks=["test_hook"], mode=PluginMode.CONCURRENT
        )
        block_plugin = BlockingPlugin(block_config)
        block_ref = PluginRef(block_plugin)
        block_hook = HookRef("test_hook", block_ref)

        policies = {"test_hook": HookPayloadPolicy(writable_fields=frozenset({"name"}))}
        executor = PluginExecutor(hook_policies=policies)

        payload = SamplePayload(name="old")
        global_ctx = GlobalContext(request_id="1")

        result, _ = await executor.execute(
            [meta_hook, block_hook],
            payload,
            global_ctx,
            hook_type="test_hook",
        )
        assert result.continue_processing is False
        assert result.metadata == {"source": "plugin_a"}

    @pytest.mark.asyncio
    async def test_enforce_early_return_deny_default_rejects_all(self):
        """When default=deny and a CONCURRENT plugin short-circuits with modifications,
        all modifications must be rejected (modified_payload=None)."""
        from cpex.framework.base import HookRef, Plugin, PluginRef
        from cpex.framework.manager import PluginExecutor
        from cpex.framework.models import GlobalContext, PluginConfig, PluginMode, PluginResult

        class BlockingPlugin(Plugin):
            async def test_hook(self, payload, context):
                modified = payload.model_copy(update={"name": "new"})
                return PluginResult(continue_processing=False, modified_payload=modified)

        config = PluginConfig(
            name="blocker", kind="test.Plugin", version="1.0", hooks=["test_hook"], mode=PluginMode.CONCURRENT
        )
        plugin = BlockingPlugin(config)
        ref = PluginRef(plugin)
        hook_ref = HookRef("test_hook", ref)

        # No policies, default deny
        with patch("cpex.framework.manager.settings") as mock_settings:
            mock_settings.default_hook_policy = "deny"
            executor = PluginExecutor(hook_policies={})

        payload = SamplePayload(name="old", secret="original")
        global_ctx = GlobalContext(request_id="1")

        result, _ = await executor.execute(
            [hook_ref],
            payload,
            global_ctx,
            hook_type="test_hook",
        )
        assert result.continue_processing is False
        assert result.modified_payload is None  # all modifications rejected


class TestCrossTypePolicyHandling:
    """Tests for cross-type payload results (e.g. HTTP hooks)."""

    @pytest.mark.asyncio
    async def test_cross_type_result_accepted_when_policy_exists(self):
        """When modified_payload is a different PluginPayload subtype from the
        input, the policy's presence authorises the hook and the result is accepted."""
        from cpex.framework.base import HookRef, Plugin, PluginRef
        from cpex.framework.manager import PluginExecutor
        from cpex.framework.models import GlobalContext, PluginConfig, PluginPayload, PluginResult

        class DifferentResult(PluginPayload):
            granted: bool = True
            reason: str = "ok"

        class CrossTypePlugin(Plugin):
            async def test_hook(self, payload, context):
                return PluginResult(continue_processing=True, modified_payload=DifferentResult())

        config = PluginConfig(name="cross", kind="test.Plugin", version="1.0", hooks=["test_hook"])
        plugin = CrossTypePlugin(config)
        ref = PluginRef(plugin)
        hook_ref = HookRef("test_hook", ref)

        policies = {"test_hook": HookPayloadPolicy(writable_fields=frozenset({"granted", "reason"}))}
        executor = PluginExecutor(hook_policies=policies)

        payload = SamplePayload(name="old")
        global_ctx = GlobalContext(request_id="1")

        result, _ = await executor.execute([hook_ref], payload, global_ctx, hook_type="test_hook")
        assert result.modified_payload is not None
        assert result.modified_payload.granted is True

    @pytest.mark.asyncio
    async def test_cross_type_dict_result_accepted_when_policy_exists(self):
        """dict results (e.g. http_auth_resolve_user) are accepted when a policy exists."""
        from cpex.framework.base import HookRef, Plugin, PluginRef
        from cpex.framework.manager import PluginExecutor
        from cpex.framework.models import GlobalContext, PluginConfig, PluginResult

        class DictResultPlugin(Plugin):
            async def test_hook(self, payload, context):
                return PluginResult(continue_processing=True, modified_payload={"email": "user@example.com"})

        config = PluginConfig(name="auth", kind="test.Plugin", version="1.0", hooks=["test_hook"])
        plugin = DictResultPlugin(config)
        ref = PluginRef(plugin)
        hook_ref = HookRef("test_hook", ref)

        policies = {"test_hook": HookPayloadPolicy(writable_fields=frozenset())}
        executor = PluginExecutor(hook_policies=policies)

        payload = SamplePayload(name="old")
        global_ctx = GlobalContext(request_id="1")

        result, _ = await executor.execute([hook_ref], payload, global_ctx, hook_type="test_hook")
        assert result.modified_payload == {"email": "user@example.com"}

    @pytest.mark.asyncio
    async def test_deny_default_snapshots_payload_for_in_place_isolation(self):
        """When default=deny, in-place nested mutations must not persist on the live payload."""
        from cpex.framework.base import HookRef, Plugin, PluginRef
        from cpex.framework.manager import PluginExecutor
        from cpex.framework.models import GlobalContext, PluginConfig, PluginResult

        class InPlaceMutator(Plugin):
            async def no_policy_hook(self, payload, context):
                payload.args["injected"] = "evil"
                return PluginResult(continue_processing=True, modified_payload=None)

        config = PluginConfig(name="mutator", kind="test.Plugin", version="1.0", hooks=["no_policy_hook"])
        plugin = InPlaceMutator(config)
        ref = PluginRef(plugin)
        hook_ref = HookRef("no_policy_hook", ref)

        # No policy for this hook, default=deny
        with patch("cpex.framework.manager.settings") as mock_settings:
            mock_settings.default_hook_policy = "deny"
            executor = PluginExecutor(hook_policies={})

        payload = SamplePayload(name="old", args={"key": "value"})
        global_ctx = GlobalContext(request_id="1")

        result, _ = await executor.execute([hook_ref], payload, global_ctx, hook_type="no_policy_hook")
        # The plugin mutated args in-place, but the deep-copy snapshot means
        # the original payload passed to the next plugin (or returned) is clean
        assert result.modified_payload is None, "deny-default should reject all modifications"
        assert payload.args == {"key": "value"}, "Original payload must not be mutated"


class TestBorgPolicyBackfill:
    """Tests for PluginManager Borg pattern policy injection."""

    def test_get_plugin_manager_injects_policies(self, monkeypatch, tmp_path):
        """Verify get_plugin_manager() always injects hook policies."""
        import cpex.framework as fw
        from cpex.framework.settings import settings as plugin_settings
        from tests.unit.cpex.fixtures.common.policy import HOOK_PAYLOAD_POLICIES

        config_file = tmp_path / "plugins.yaml"
        config_file.write_text("plugin_settings:\n  plugin_timeout: 30\nplugin_dirs: []\nplugins: []\n")

        monkeypatch.setenv("PLUGINS_ENABLED", "true")
        monkeypatch.setenv("PLUGINS_CONFIG_FILE", str(config_file))

        # Reset singleton state
        fw.PluginManager.reset()
        fw._plugin_manager = None
        plugin_settings.cache_clear()

        pm = fw.get_plugin_manager(hook_policies=HOOK_PAYLOAD_POLICIES)
        assert pm is not None
        assert pm._executor.hook_policies, "get_plugin_manager() should inject hook policies"

        # Verify known policy keys are present
        assert "tool_pre_invoke" in pm._executor.hook_policies
        assert "prompt_post_fetch" in pm._executor.hook_policies

    def test_service_via_get_plugin_manager_has_policies(self, monkeypatch, tmp_path):
        """Verify that services using get_plugin_manager() get policies regardless of creation order."""
        import cpex.framework as fw
        from cpex.framework.settings import settings as plugin_settings
        from tests.unit.cpex.fixtures.common.policy import HOOK_PAYLOAD_POLICIES

        config_file = tmp_path / "plugins.yaml"
        config_file.write_text("plugin_settings:\n  plugin_timeout: 30\nplugin_dirs: []\nplugins: []\n")

        monkeypatch.setenv("PLUGINS_ENABLED", "true")
        monkeypatch.setenv("PLUGINS_CONFIG_FILE", str(config_file))

        # Reset state
        fw.PluginManager.reset()
        fw._plugin_manager = None
        plugin_settings.cache_clear()

        # Simulate service creating manager via get_plugin_manager
        pm1 = fw.get_plugin_manager(hook_policies=HOOK_PAYLOAD_POLICIES)

        # Simulate another access (e.g. from another service)
        pm2 = fw.get_plugin_manager(hook_policies=HOOK_PAYLOAD_POLICIES)

        # Both should share the same executor with policies
        assert pm1 is pm2
        assert pm1._executor.hook_policies

    @pytest.mark.asyncio
    async def test_policy_enforcement_through_manager(self, monkeypatch, tmp_path):
        """Integration test: policies enforced through PluginManager.execute flow."""
        from cpex.framework.base import HookRef, Plugin, PluginRef
        from cpex.framework.hooks.policies import HookPayloadPolicy
        from cpex.framework.manager import PluginExecutor
        from cpex.framework.models import GlobalContext, PluginConfig, PluginResult

        class InjectPlugin(Plugin):
            async def tool_pre_invoke(self, payload, context):
                modified = payload.model_copy(
                    update={"name": "injected", "args": {"injected": "true"}, "secret": "hacked"}
                )
                return PluginResult(continue_processing=True, modified_payload=modified)

        # Set up executor with tool_pre_invoke policy
        policies = {
            "tool_pre_invoke": HookPayloadPolicy(writable_fields=frozenset({"name", "args"})),
        }
        executor = PluginExecutor(hook_policies=policies)

        config = PluginConfig(name="injector", kind="test.Plugin", version="1.0", hooks=["tool_pre_invoke"])
        plugin = InjectPlugin(config)
        ref = PluginRef(plugin)
        hook_ref = HookRef("tool_pre_invoke", ref)

        payload = SamplePayload(name="original", args={}, secret="safe")
        global_ctx = GlobalContext(request_id="test-1")

        result, _ = await executor.execute(
            [hook_ref],
            payload,
            global_ctx,
            hook_type="tool_pre_invoke",
        )

        assert result.modified_payload is not None
        assert result.modified_payload.name == "injected"
        assert result.modified_payload.args == {"injected": "true"}
        assert result.modified_payload.secret == "safe"  # Policy filtered this out


    @pytest.mark.asyncio
    async def test_tool_pre_invoke_empty_args_modification_preserved_through_executor(self):
        """Regression test for the tool_pre_invoke executor path.

        A plugin receives CoW-wrapped args containing only specific fields,
        strips them all, and returns a payload with args={}. The executor should
        preserve that empty args modification instead of dropping it as
        "unchanged".
        """
        from cpex.framework.base import HookRef, Plugin, PluginRef
        from cpex.framework.hooks.policies import HookPayloadPolicy
        from cpex.framework.hooks.tools import ToolPreInvokePayload
        from cpex.framework.manager import PluginExecutor
        from cpex.framework.memory import CopyOnWriteDict
        from cpex.framework.models import GlobalContext, PluginConfig, PluginResult

        seen_arg_types = []

        class StripWxoArgsPlugin(Plugin):
            async def tool_pre_invoke(self, payload, context):
                seen_arg_types.append(type(payload.args))
                cleaned_args = {k: v for k, v in payload.args.items() if not k.startswith("wxo_")}
                modified = payload.model_copy(update={"args": cleaned_args})
                return PluginResult(continue_processing=True, modified_payload=modified)

        policies = {
            "tool_pre_invoke": HookPayloadPolicy(writable_fields=frozenset({"args"})),
        }
        executor = PluginExecutor(hook_policies=policies)

        config = PluginConfig(name="stripper", kind="test.Plugin", version="1.0", hooks=["tool_pre_invoke"])
        plugin = StripWxoArgsPlugin(config)
        hook_ref = HookRef("tool_pre_invoke", PluginRef(plugin))

        payload = ToolPreInvokePayload(
            name="list_all_secrets",
            args={
                "wxo_connection_id": "",
                "wxo_auth": "fake-token",
                "wxo_environment_id": "draft",
            },
        )
        global_ctx = GlobalContext(request_id="tool-pre-empty-args")

        result, _ = await executor.execute([hook_ref], payload, global_ctx, hook_type="tool_pre_invoke")

        assert seen_arg_types == [CopyOnWriteDict]
        assert result.modified_payload is not None
        assert result.modified_payload == ToolPreInvokePayload(name="list_all_secrets", args={})
        assert payload.args == {
            "wxo_connection_id": "",
            "wxo_auth": "fake-token",
            "wxo_environment_id": "draft",
        }

class TestMultiPluginDictChain:
    """Tests for multi-plugin chains where an earlier plugin returns a dict payload."""

    @pytest.mark.asyncio
    async def test_dict_payload_deep_copied_for_next_plugin(self):
        """When plugin 1 returns a dict, the next plugin receives a deep-copied
        dict without crashing on model_copy (which dicts don't have)."""
        from cpex.framework.base import HookRef, Plugin, PluginRef
        from cpex.framework.manager import PluginExecutor
        from cpex.framework.models import GlobalContext, PluginConfig, PluginResult

        class AuthPlugin(Plugin):
            async def auth_hook(self, payload, context):
                return PluginResult(
                    continue_processing=True, modified_payload={"email": "user@test.com", "role": "admin"}
                )

        class AuditPlugin(Plugin):
            async def auth_hook(self, payload, context):
                # Second plugin just passes through
                return PluginResult(continue_processing=True)

        auth_config = PluginConfig(name="auth", kind="test.Plugin", version="1.0", hooks=["auth_hook"])
        audit_config = PluginConfig(name="audit", kind="test.Plugin", version="1.0", hooks=["auth_hook"])

        auth_plugin = AuthPlugin(auth_config)
        audit_plugin = AuditPlugin(audit_config)

        hook_refs = [
            HookRef("auth_hook", PluginRef(auth_plugin)),
            HookRef("auth_hook", PluginRef(audit_plugin)),
        ]

        policies = {"auth_hook": HookPayloadPolicy(writable_fields=frozenset())}
        executor = PluginExecutor(hook_policies=policies)

        payload = SamplePayload(name="original")
        global_ctx = GlobalContext(request_id="multi-1")

        result, _ = await executor.execute(hook_refs, payload, global_ctx, hook_type="auth_hook")
        assert result.continue_processing is True
        assert result.modified_payload == {"email": "user@test.com", "role": "admin"}

    @pytest.mark.asyncio
    async def test_dict_to_dict_accepted_without_apply_policy(self):
        """When effective_payload is a dict and plugin also returns a dict,
        the result is accepted directly (not routed through apply_policy)."""
        from cpex.framework.base import HookRef, Plugin, PluginRef
        from cpex.framework.manager import PluginExecutor
        from cpex.framework.models import GlobalContext, PluginConfig, PluginResult

        class FirstAuth(Plugin):
            async def auth_hook(self, payload, context):
                return PluginResult(continue_processing=True, modified_payload={"email": "first@test.com"})

        class SecondAuth(Plugin):
            async def auth_hook(self, payload, context):
                return PluginResult(
                    continue_processing=True, modified_payload={"email": "second@test.com", "enriched": True}
                )

        first_config = PluginConfig(name="first", kind="test.Plugin", version="1.0", hooks=["auth_hook"])
        second_config = PluginConfig(name="second", kind="test.Plugin", version="1.0", hooks=["auth_hook"])

        hook_refs = [
            HookRef("auth_hook", PluginRef(FirstAuth(first_config))),
            HookRef("auth_hook", PluginRef(SecondAuth(second_config))),
        ]

        policies = {"auth_hook": HookPayloadPolicy(writable_fields=frozenset())}
        executor = PluginExecutor(hook_policies=policies)

        payload = SamplePayload(name="original")
        global_ctx = GlobalContext(request_id="multi-2")

        result, _ = await executor.execute(hook_refs, payload, global_ctx, hook_type="auth_hook")
        assert result.continue_processing is True
        assert result.modified_payload == {"email": "second@test.com", "enriched": True}

    @pytest.mark.asyncio
    async def test_empty_dict_payload_not_dropped_by_truthiness(self):
        """An empty dict returned by a plugin must not be replaced by the
        original payload due to falsy truthiness evaluation."""
        from cpex.framework.base import HookRef, Plugin, PluginRef
        from cpex.framework.manager import PluginExecutor
        from cpex.framework.models import GlobalContext, PluginConfig, PluginResult

        class EmptyDictPlugin(Plugin):
            async def auth_hook(self, payload, context):
                return PluginResult(continue_processing=True, modified_payload={})

        class PassthroughPlugin(Plugin):
            """Runs after EmptyDictPlugin; receives the empty dict if chaining works."""

            async def auth_hook(self, payload, context):
                return PluginResult(continue_processing=True)

        hook_refs = [
            HookRef(
                "auth_hook",
                PluginRef(
                    EmptyDictPlugin(PluginConfig(name="empty", kind="test.Plugin", version="1.0", hooks=["auth_hook"]))
                ),
            ),
            HookRef(
                "auth_hook",
                PluginRef(
                    PassthroughPlugin(PluginConfig(name="pass", kind="test.Plugin", version="1.0", hooks=["auth_hook"]))
                ),
            ),
        ]

        policies = {"auth_hook": HookPayloadPolicy(writable_fields=frozenset())}
        executor = PluginExecutor(hook_policies=policies)

        payload = SamplePayload(name="original")
        global_ctx = GlobalContext(request_id="multi-3")

        result, _ = await executor.execute(hook_refs, payload, global_ctx, hook_type="auth_hook")
        assert result.modified_payload == {}, "Empty dict should be preserved, not replaced by original payload"


@pytest.mark.asyncio
async def test_http_auth_permission_result_includes_decision_plugin_provenance():
    """Permission hook decisions should carry deciding plugin identity even with empty plugin metadata."""
    from cpex.framework.base import HookRef, Plugin, PluginRef
    from cpex.framework.hooks.http import HttpAuthCheckPermissionPayload, HttpAuthCheckPermissionResultPayload
    from cpex.framework.manager import PluginExecutor
    from cpex.framework.models import GlobalContext, PluginConfig, PluginResult

    class DecisionPlugin(Plugin):
        async def http_auth_check_permission(self, payload, context):
            return PluginResult(
                continue_processing=True,
                modified_payload=HttpAuthCheckPermissionResultPayload(granted=False, reason="Denied by policy"),
                metadata={},
            )

    config = PluginConfig(
        name="decision-plugin", kind="test.Plugin", version="1.0", hooks=["http_auth_check_permission"]
    )
    hook_ref = HookRef("http_auth_check_permission", PluginRef(DecisionPlugin(config)))

    executor = PluginExecutor(
        hook_policies={"http_auth_check_permission": HookPayloadPolicy(writable_fields=frozenset({"reason"}))}
    )
    payload = HttpAuthCheckPermissionPayload(
        user_email="user@example.com", permission="tools.read", resource_type="tool"
    )
    result, _ = await executor.execute(
        [hook_ref], payload, GlobalContext(request_id="decision-1"), hook_type="http_auth_check_permission"
    )

    assert result.modified_payload is not None
    assert result.modified_payload.granted is False
    assert result.metadata["_decision_plugin"] == "decision-plugin"


@pytest.mark.asyncio
async def test_http_auth_permission_provenance_overrides_forged_metadata_from_decider():
    """Manager-owned provenance must overwrite forged plugin metadata keys."""
    from cpex.framework.base import HookRef, Plugin, PluginRef
    from cpex.framework.hooks.http import HttpAuthCheckPermissionPayload, HttpAuthCheckPermissionResultPayload
    from cpex.framework.manager import PluginExecutor
    from cpex.framework.models import GlobalContext, PluginConfig, PluginResult

    class ForgingDecisionPlugin(Plugin):
        async def http_auth_check_permission(self, payload, context):
            return PluginResult(
                continue_processing=True,
                modified_payload=HttpAuthCheckPermissionResultPayload(granted=False, reason="Denied by policy"),
                metadata={"_decision_plugin": "spoofed-name", "note": "kept"},
            )

    config = PluginConfig(
        name="real-decision-plugin", kind="test.Plugin", version="1.0", hooks=["http_auth_check_permission"]
    )
    hook_ref = HookRef("http_auth_check_permission", PluginRef(ForgingDecisionPlugin(config)))
    executor = PluginExecutor(
        hook_policies={"http_auth_check_permission": HookPayloadPolicy(writable_fields=frozenset({"reason"}))}
    )
    payload = HttpAuthCheckPermissionPayload(
        user_email="user@example.com", permission="tools.read", resource_type="tool"
    )

    result, _ = await executor.execute(
        [hook_ref], payload, GlobalContext(request_id="decision-forge-1"), hook_type="http_auth_check_permission"
    )

    assert result.metadata["_decision_plugin"] == "real-decision-plugin"
    assert result.metadata["note"] == "kept"


@pytest.mark.asyncio
async def test_http_auth_permission_provenance_uses_actual_decider_in_multi_plugin_chain():
    """Metadata-only plugins must not control provenance when a later plugin decides."""
    from cpex.framework.base import HookRef, Plugin, PluginRef
    from cpex.framework.hooks.http import HttpAuthCheckPermissionPayload, HttpAuthCheckPermissionResultPayload
    from cpex.framework.manager import PluginExecutor
    from cpex.framework.models import GlobalContext, PluginConfig, PluginResult

    class MetadataOnlyPlugin(Plugin):
        async def http_auth_check_permission(self, payload, context):
            return PluginResult(
                continue_processing=True, metadata={"_decision_plugin": "metadata-only-plugin", "source": "plugin-a"}
            )

    class DecisionPluginB(Plugin):
        async def http_auth_check_permission(self, payload, context):
            return PluginResult(
                continue_processing=True,
                modified_payload=HttpAuthCheckPermissionResultPayload(granted=True, reason="Allowed by policy"),
                metadata={},
            )

    hook_refs = [
        HookRef(
            "http_auth_check_permission",
            PluginRef(
                MetadataOnlyPlugin(
                    PluginConfig(
                        name="metadata-a", kind="test.Plugin", version="1.0", hooks=["http_auth_check_permission"]
                    )
                )
            ),
        ),
        HookRef(
            "http_auth_check_permission",
            PluginRef(
                DecisionPluginB(
                    PluginConfig(
                        name="decision-b", kind="test.Plugin", version="1.0", hooks=["http_auth_check_permission"]
                    )
                )
            ),
        ),
    ]
    executor = PluginExecutor(
        hook_policies={"http_auth_check_permission": HookPayloadPolicy(writable_fields=frozenset({"reason"}))}
    )
    payload = HttpAuthCheckPermissionPayload(
        user_email="user@example.com", permission="tools.read", resource_type="tool"
    )

    result, _ = await executor.execute(
        hook_refs, payload, GlobalContext(request_id="decision-forge-2"), hook_type="http_auth_check_permission"
    )

    assert result.modified_payload is not None
    assert result.modified_payload.granted is True
    assert result.metadata["_decision_plugin"] == "decision-b"
    assert result.metadata["source"] == "plugin-a"


@pytest.mark.asyncio
async def test_http_auth_permission_enforce_short_circuit_records_decision_plugin():
    """CONCURRENT short-circuit path should still persist authoritative decision provenance."""
    from cpex.framework.base import HookRef, Plugin, PluginRef
    from cpex.framework.hooks.http import HttpAuthCheckPermissionPayload, HttpAuthCheckPermissionResultPayload
    from cpex.framework.manager import PluginExecutor
    from cpex.framework.models import GlobalContext, PluginConfig, PluginMode, PluginResult

    class DecisionPlugin(Plugin):
        async def http_auth_check_permission(self, payload, context):
            return PluginResult(
                continue_processing=True,
                modified_payload=HttpAuthCheckPermissionResultPayload(granted=False, reason="Denied"),
                metadata={},
            )

    class EnforceBlockPlugin(Plugin):
        async def http_auth_check_permission(self, payload, context):
            return PluginResult(continue_processing=False, metadata={})

    decision_config = PluginConfig(
        name="decision-plugin", kind="test.Plugin", version="1.0", hooks=["http_auth_check_permission"]
    )
    block_config = PluginConfig(
        name="enforce-block-plugin",
        kind="test.Plugin",
        version="1.0",
        hooks=["http_auth_check_permission"],
        mode=PluginMode.CONCURRENT,
    )
    hook_refs = [
        HookRef("http_auth_check_permission", PluginRef(DecisionPlugin(decision_config))),
        HookRef("http_auth_check_permission", PluginRef(EnforceBlockPlugin(block_config))),
    ]

    executor = PluginExecutor(
        hook_policies={"http_auth_check_permission": HookPayloadPolicy(writable_fields=frozenset({"reason"}))}
    )
    payload = HttpAuthCheckPermissionPayload(
        user_email="user@example.com", permission="tools.execute", resource_type="tool"
    )

    result, _ = await executor.execute(
        hook_refs, payload, GlobalContext(request_id="decision-short-circuit"), hook_type="http_auth_check_permission"
    )

    assert result.continue_processing is False
    assert result.metadata["_decision_plugin"] == "decision-plugin"
