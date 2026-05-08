# -*- coding: utf-8 -*-
"""Integration tests for the extensions pipeline.

Covers the end-to-end flow:
1. Plugin receives capability-filtered extensions
2. Plugin modifies allowed slots (labels, custom)
3. Manager merges modifications back with tier validation
4. Immutable/monotonic violations are rejected
"""

import pytest

from cpex.framework.extensions.delegation import DelegationExtension, DelegationHop
from cpex.framework.extensions.extensions import Extensions
from cpex.framework.extensions.http import HttpExtension
from cpex.framework.extensions.security import (
    SecurityExtension,
    SubjectExtension,
    SubjectType,
)
from cpex.framework.extensions.tiers import (
    TierViolationError,
    filter_extensions,
    merge_extensions,
)


class TestFilterAndMergeIntegration:
    """End-to-end: filter → plugin modifies → merge back."""

    def _make_extensions(self):
        """Create a fully-populated Extensions for testing."""
        return Extensions(
            security=SecurityExtension(
                labels=frozenset({"internal"}),
                subject=SubjectExtension(
                    id="alice@corp.com",
                    type=SubjectType.USER,
                    roles=frozenset({"engineer"}),
                    permissions=frozenset({"tool_execute"}),
                    teams=frozenset({"engineering"}),
                ),
            ),
            http=HttpExtension(headers={"authorization": "Bearer tok", "x-request-id": "req-1"}),
            delegation=DelegationExtension(),
            custom={"trace": True},
        )

    def test_plugin_with_read_labels_sees_labels(self):
        """A plugin with read_labels capability sees security labels."""
        ext = self._make_extensions()
        filtered = filter_extensions(ext, frozenset({"read_labels"}))
        assert filtered.security is not None
        assert "internal" in filtered.security.labels

    def test_plugin_without_read_labels_gets_no_labels(self):
        """A plugin without read_labels capability does not see labels."""
        ext = self._make_extensions()
        filtered = filter_extensions(ext, frozenset())
        # Security may still be present (for objects/data) but labels should be empty
        if filtered.security:
            assert len(filtered.security.labels) == 0

    def test_plugin_with_read_subject_sees_identity(self):
        ext = self._make_extensions()
        filtered = filter_extensions(ext, frozenset({"read_subject"}))
        assert filtered.security is not None
        assert filtered.security.subject is not None
        assert filtered.security.subject.id == "alice@corp.com"

    def test_plugin_without_read_subject_gets_no_identity(self):
        ext = self._make_extensions()
        filtered = filter_extensions(ext, frozenset())
        if filtered.security and filtered.security.subject:
            pytest.fail("Plugin without read_subject should not see subject")

    def test_plugin_with_read_headers_sees_headers(self):
        ext = self._make_extensions()
        filtered = filter_extensions(ext, frozenset({"read_headers"}))
        assert filtered.http is not None
        assert "authorization" in filtered.http.headers

    def test_plugin_without_read_headers_gets_no_http(self):
        ext = self._make_extensions()
        filtered = filter_extensions(ext, frozenset())
        assert filtered.http is None

    def test_delegation_visible_with_capability(self):
        ext = self._make_extensions()
        filtered = filter_extensions(ext, frozenset({"read_delegation"}))
        assert filtered.delegation is not None

    def test_delegation_hidden_without_capability(self):
        ext = self._make_extensions()
        filtered = filter_extensions(ext, frozenset())
        assert filtered.delegation is None

    def test_merge_accepts_label_addition(self):
        """Labels are monotonic — additions are accepted."""
        original = self._make_extensions()
        # Simulate plugin adding a label
        new_labels = original.security.labels | frozenset({"PII"})
        new_security = original.security.model_copy(update={"labels": new_labels})
        modified = original.model_copy(update={"security": new_security})

        merged = merge_extensions(
            original,
            modified,
            frozenset({"read_labels", "append_labels"}),
            "test-plugin",
        )
        assert "PII" in merged.security.labels
        assert "internal" in merged.security.labels  # original preserved

    def test_merge_rejects_label_removal(self):
        """Labels are monotonic — removals are rejected."""
        original = self._make_extensions()
        # Simulate plugin removing a label
        new_security = original.security.model_copy(update={"labels": frozenset()})
        modified = original.model_copy(update={"security": new_security})

        with pytest.raises(TierViolationError):
            merge_extensions(
                original,
                modified,
                frozenset({"read_labels", "append_labels"}),
                "bad-plugin",
            )

    def test_merge_accepts_delegation_chain_growth(self):
        """Delegation chain is monotonic — growth is accepted with capability."""
        original = self._make_extensions()
        hop = DelegationHop(subject_id="alice", subject_type="user", scopes_granted=("read",))
        new_delegation = original.delegation.with_new_hop(hop)
        modified = original.model_copy(update={"delegation": new_delegation})

        merged = merge_extensions(
            original,
            modified,
            frozenset({"read_delegation", "append_delegation"}),
            "test-plugin",
        )
        assert merged.delegation.depth == 1
        assert merged.delegation.chain[0].subject_id == "alice"

    def test_merge_ignores_delegation_without_capability(self):
        """Delegation changes are ignored without append_delegation capability."""
        original = self._make_extensions()
        hop = DelegationHop(subject_id="alice", subject_type="user")
        new_delegation = original.delegation.with_new_hop(hop)
        modified = original.model_copy(update={"delegation": new_delegation})

        merged = merge_extensions(
            original,
            modified,
            frozenset(),  # no append_delegation
            "no-cap-plugin",
        )
        # Original delegation preserved — plugin's changes silently dropped
        assert merged.delegation.depth == 0

    def test_merge_rejects_delegation_chain_shrink(self):
        """Delegation chain is monotonic — shrinking is rejected."""
        # Build a 2-hop chain
        ext = self._make_extensions()
        hop1 = DelegationHop(subject_id="alice", subject_type="user")
        hop2 = DelegationHop(subject_id="bob", subject_type="agent")
        ext1 = ext.model_copy(update={"delegation": ext.delegation.with_new_hop(hop1)})
        ext2 = ext1.model_copy(update={"delegation": ext1.delegation.with_new_hop(hop2)})

        # Try to shrink back to empty
        shrunk = ext2.model_copy(update={"delegation": DelegationExtension()})
        with pytest.raises(TierViolationError):
            merge_extensions(
                ext2,
                shrunk,
                frozenset({"read_delegation", "append_delegation"}),
                "bad-plugin",
            )

    def test_merge_rejects_delegation_chain_tamper(self):
        """Delegation chain is monotonic — modifying existing hops is rejected."""
        ext = self._make_extensions()
        hop1 = DelegationHop(subject_id="alice", subject_type="user")
        ext1 = ext.model_copy(update={"delegation": ext.delegation.with_new_hop(hop1)})

        # Tamper with the existing hop
        tampered_hop = DelegationHop(subject_id="mallory", subject_type="user")
        tampered = ext1.model_copy(
            update={
                "delegation": DelegationExtension(
                    chain=(tampered_hop,),
                    depth=1,
                    delegated=True,
                    origin_subject_id="mallory",
                    actor_subject_id="mallory",
                )
            }
        )
        with pytest.raises(TierViolationError):
            merge_extensions(
                ext1,
                tampered,
                frozenset({"read_delegation", "append_delegation"}),
                "tamper-plugin",
            )

    def test_merge_accepts_custom_changes(self):
        """Custom extensions are mutable — any change is accepted."""
        original = self._make_extensions()
        modified = original.model_copy(update={"custom": {"trace": False, "new_key": "val"}})

        merged = merge_extensions(original, modified, frozenset(), "test-plugin")
        assert merged.custom["trace"] is False
        assert merged.custom["new_key"] == "val"

    def test_merge_accepts_header_changes_with_capability(self):
        """HTTP headers are writable with write_headers capability."""
        original = self._make_extensions()
        new_http = HttpExtension(headers={"x-request-id": "req-1", "x-custom": "added"})
        modified = original.model_copy(update={"http": new_http})

        merged = merge_extensions(
            original,
            modified,
            frozenset({"read_headers", "write_headers"}),
            "test-plugin",
        )
        assert "x-custom" in merged.http.headers

    def test_merge_ignores_header_changes_without_capability(self):
        """HTTP headers are NOT writable without write_headers capability."""
        original = self._make_extensions()
        new_http = HttpExtension(headers={"x-custom": "sneaky"})
        modified = original.model_copy(update={"http": new_http})

        merged = merge_extensions(
            original,
            modified,
            frozenset(),  # no write_headers
            "no-cap-plugin",
        )
        # Original headers preserved — plugin's changes ignored
        assert "x-custom" not in merged.http.headers
        assert "authorization" in merged.http.headers
