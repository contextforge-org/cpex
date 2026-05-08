# -*- coding: utf-8 -*-
"""Tests for DelegationExtension and DelegationHop.

Covers:
- DelegationHop construction and timestamp (timezone-aware)
- DelegationExtension.with_new_hop() monotonic chain growth
- Scope narrowing on hop creation
- age_seconds calculation
- Immutability of frozen models
"""

from datetime import UTC, datetime, timedelta

import pytest

from cpex.framework.extensions.delegation import DelegationExtension, DelegationHop


class TestDelegationHop:
    """Tests for DelegationHop construction."""

    def test_basic_construction(self):
        hop = DelegationHop(subject_id="alice@corp.com", subject_type="user")
        assert hop.subject_id == "alice@corp.com"
        assert hop.subject_type == "user"
        assert hop.audience is None
        assert hop.scopes_granted == ()
        assert hop.from_cache is False

    def test_timestamp_is_timezone_aware(self):
        hop = DelegationHop(subject_id="alice", subject_type="user")
        assert hop.timestamp.tzinfo is not None

    def test_with_scopes(self):
        hop = DelegationHop(
            subject_id="alice",
            subject_type="user",
            scopes_granted=("read:compensation", "read:directory"),
            audience="hr-service",
            strategy="token_exchange",
        )
        assert len(hop.scopes_granted) == 2
        assert "read:compensation" in hop.scopes_granted
        assert hop.audience == "hr-service"
        assert hop.strategy == "token_exchange"

    def test_frozen(self):
        hop = DelegationHop(subject_id="alice", subject_type="user")
        with pytest.raises(Exception):  # ValidationError for frozen
            hop.subject_id = "bob"


class TestDelegationExtension:
    """Tests for DelegationExtension."""

    def test_empty_extension(self):
        ext = DelegationExtension()
        assert ext.delegated is False
        assert ext.depth == 0
        assert ext.chain == ()
        assert ext.origin_subject_id is None
        assert ext.actor_subject_id is None

    def test_with_new_hop_first_hop(self):
        ext = DelegationExtension()
        hop = DelegationHop(
            subject_id="alice@corp.com",
            subject_type="user",
            scopes_granted=("read",),
        )
        new_ext = ext.with_new_hop(hop)

        assert new_ext.delegated is True
        assert new_ext.depth == 1
        assert len(new_ext.chain) == 1
        assert new_ext.origin_subject_id == "alice@corp.com"
        assert new_ext.actor_subject_id == "alice@corp.com"

    def test_with_new_hop_preserves_origin(self):
        ext = DelegationExtension()
        hop1 = DelegationHop(subject_id="alice", subject_type="user", scopes_granted=("read", "write"))
        hop2 = DelegationHop(subject_id="agent-1", subject_type="agent", scopes_granted=("read",))

        ext1 = ext.with_new_hop(hop1)
        ext2 = ext1.with_new_hop(hop2)

        assert ext2.depth == 2
        assert ext2.origin_subject_id == "alice"  # preserved from first hop
        assert ext2.actor_subject_id == "agent-1"  # updated to latest hop

    def test_with_new_hop_is_immutable(self):
        """with_new_hop returns a NEW extension — original is unchanged."""
        ext = DelegationExtension()
        hop = DelegationHop(subject_id="alice", subject_type="user")
        new_ext = ext.with_new_hop(hop)

        assert ext.depth == 0  # original unchanged
        assert new_ext.depth == 1  # new one has the hop

    def test_with_new_hop_chain_grows_monotonically(self):
        ext = DelegationExtension()
        hop1 = DelegationHop(subject_id="alice", subject_type="user")
        hop2 = DelegationHop(subject_id="bob", subject_type="agent")
        hop3 = DelegationHop(subject_id="charlie", subject_type="service")

        ext1 = ext.with_new_hop(hop1)
        ext2 = ext1.with_new_hop(hop2)
        ext3 = ext2.with_new_hop(hop3)

        assert ext3.depth == 3
        assert ext3.chain[0].subject_id == "alice"
        assert ext3.chain[1].subject_id == "bob"
        assert ext3.chain[2].subject_id == "charlie"

    def test_age_seconds_increases(self):
        """age_seconds should reflect time since first hop."""
        # Create a hop with a timestamp in the past
        old_hop = DelegationHop(
            subject_id="alice",
            subject_type="user",
            timestamp=datetime.now(UTC) - timedelta(seconds=10),
        )
        ext = DelegationExtension()
        ext1 = ext.with_new_hop(old_hop)

        # Add a second hop — age should be > 0
        hop2 = DelegationHop(subject_id="bob", subject_type="agent")
        ext2 = ext1.with_new_hop(hop2)
        assert ext2.age_seconds >= 9.0  # at least ~10s minus timing

    def test_frozen(self):
        ext = DelegationExtension()
        with pytest.raises(Exception):
            ext.delegated = True
