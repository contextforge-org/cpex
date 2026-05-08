# -*- coding: utf-8 -*-
"""Location: ./tests/unit/cpex/framework/test_memory.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Fred Araujo

Tests for memory module.
"""

# Standard
import weakref

# Third-Party
import pytest
from pydantic import BaseModel, ConfigDict, Field, RootModel

# First-Party
from cpex.framework.memory import (
    CopyOnWriteDict,
    CopyOnWriteList,
    _safe_deepcopy,
    _wrap_value,
    copyonwrite,
    wrap_payload_for_isolation,
)


class TestCopyOnWriteDict:
    """Test suite for CopyOnWriteDict class."""

    def test_is_dict_subclass(self):
        """Test that CopyOnWriteDict is a subclass of dict."""
        original = {"a": 1}
        cow = CopyOnWriteDict(original)

        assert isinstance(cow, dict)
        assert issubclass(CopyOnWriteDict, dict)

    def test_initialization(self):
        """Test that CopyOnWriteDict initializes correctly."""
        original = {"a": 1, "b": 2, "c": 3}
        cow = CopyOnWriteDict(original)

        # Verify all original keys are accessible
        assert cow["a"] == 1
        assert cow["b"] == 2
        assert cow["c"] == 3

        # Verify original is unchanged
        assert original == {"a": 1, "b": 2, "c": 3}

    def test_initialization_empty_dict(self):
        """Test initialization with an empty dictionary."""
        original = {}
        cow = CopyOnWriteDict(original)

        assert len(cow) == 0
        assert list(cow.keys()) == []

    def test_getitem_existing_key(self):
        """Test getting an existing key from the original dict."""
        original = {"a": 1, "b": 2}
        cow = CopyOnWriteDict(original)

        assert cow["a"] == 1
        assert cow["b"] == 2

    def test_getitem_nonexistent_key(self):
        """Test that getting a non-existent key raises KeyError."""
        original = {"a": 1}
        cow = CopyOnWriteDict(original)

        with pytest.raises(KeyError):
            _ = cow["nonexistent"]

    def test_getitem_deleted_key(self):
        """Test that getting a deleted key raises KeyError."""
        original = {"a": 1, "b": 2}
        cow = CopyOnWriteDict(original)

        del cow["a"]

        with pytest.raises(KeyError):
            _ = cow["a"]

    def test_setitem_new_key(self):
        """Test setting a new key that doesn't exist in original."""
        original = {"a": 1}
        cow = CopyOnWriteDict(original)

        cow["b"] = 2

        assert cow["b"] == 2
        assert "b" not in original  # Original unchanged
        assert original == {"a": 1}

    def test_setitem_override_existing_key(self):
        """Test overriding an existing key from the original dict."""
        original = {"a": 1, "b": 2}
        cow = CopyOnWriteDict(original)

        cow["a"] = 10

        assert cow["a"] == 10
        assert original["a"] == 1  # Original unchanged

    def test_setitem_after_delete(self):
        """Test setting a key after it was deleted."""
        original = {"a": 1, "b": 2}
        cow = CopyOnWriteDict(original)

        del cow["a"]
        cow["a"] = 10

        assert cow["a"] == 10
        assert "a" not in cow.get_deleted()

    def test_delitem_existing_key(self):
        """Test deleting an existing key from the original dict."""
        original = {"a": 1, "b": 2}
        cow = CopyOnWriteDict(original)

        del cow["a"]

        assert "a" not in cow
        assert "a" in original  # Original unchanged
        assert original == {"a": 1, "b": 2}

    def test_delitem_modified_key(self):
        """Test deleting a key that was modified."""
        original = {"a": 1}
        cow = CopyOnWriteDict(original)

        cow["a"] = 10
        del cow["a"]

        assert "a" not in cow
        assert original["a"] == 1  # Original unchanged

    def test_delitem_new_key(self):
        """Test deleting a key that was added to modifications."""
        original = {"a": 1}
        cow = CopyOnWriteDict(original)

        cow["b"] = 2
        del cow["b"]

        assert "b" not in cow

    def test_delitem_nonexistent_key(self):
        """Test that deleting a non-existent key raises KeyError."""
        original = {"a": 1}
        cow = CopyOnWriteDict(original)

        with pytest.raises(KeyError):
            del cow["nonexistent"]

    def test_delitem_already_deleted(self):
        """Test that deleting an already deleted key raises KeyError."""
        original = {"a": 1}
        cow = CopyOnWriteDict(original)

        del cow["a"]

        with pytest.raises(KeyError):
            del cow["a"]

    def test_contains_existing_key(self):
        """Test __contains__ for an existing key."""
        original = {"a": 1, "b": 2}
        cow = CopyOnWriteDict(original)

        assert "a" in cow
        assert "b" in cow

    def test_contains_new_key(self):
        """Test __contains__ for a newly added key."""
        original = {"a": 1}
        cow = CopyOnWriteDict(original)

        cow["b"] = 2

        assert "b" in cow

    def test_contains_nonexistent_key(self):
        """Test __contains__ for a non-existent key."""
        original = {"a": 1}
        cow = CopyOnWriteDict(original)

        assert "nonexistent" not in cow

    def test_contains_deleted_key(self):
        """Test __contains__ for a deleted key."""
        original = {"a": 1, "b": 2}
        cow = CopyOnWriteDict(original)

        del cow["a"]

        assert "a" not in cow
        assert "b" in cow

    def test_len_original_only(self):
        """Test __len__ with only original keys."""
        original = {"a": 1, "b": 2, "c": 3}
        cow = CopyOnWriteDict(original)

        assert len(cow) == 3

    def test_len_with_additions(self):
        """Test __len__ with added keys."""
        original = {"a": 1}
        cow = CopyOnWriteDict(original)

        cow["b"] = 2
        cow["c"] = 3

        assert len(cow) == 3

    def test_len_with_deletions(self):
        """Test __len__ with deleted keys."""
        original = {"a": 1, "b": 2, "c": 3}
        cow = CopyOnWriteDict(original)

        del cow["a"]
        del cow["b"]

        assert len(cow) == 1

    def test_len_with_modifications(self):
        """Test __len__ with modifications (should not change length)."""
        original = {"a": 1, "b": 2}
        cow = CopyOnWriteDict(original)

        cow["a"] = 10

        assert len(cow) == 2

    def test_len_empty(self):
        """Test __len__ when all keys are deleted."""
        original = {"a": 1}
        cow = CopyOnWriteDict(original)

        del cow["a"]

        assert len(cow) == 0

    def test_iter_original_only(self):
        """Test __iter__ with only original keys."""
        original = {"a": 1, "b": 2, "c": 3}
        cow = CopyOnWriteDict(original)

        keys = list(cow)
        assert set(keys) == {"a", "b", "c"}

    def test_iter_with_additions(self):
        """Test __iter__ with added keys."""
        original = {"a": 1}
        cow = CopyOnWriteDict(original)

        cow["b"] = 2
        cow["c"] = 3

        keys = list(cow)
        assert set(keys) == {"a", "b", "c"}

    def test_iter_with_deletions(self):
        """Test __iter__ with deleted keys."""
        original = {"a": 1, "b": 2, "c": 3}
        cow = CopyOnWriteDict(original)

        del cow["b"]

        keys = list(cow)
        assert set(keys) == {"a", "c"}

    def test_get_existing_key(self):
        """Test get() method for an existing key."""
        original = {"a": 1, "b": 2}
        cow = CopyOnWriteDict(original)

        assert cow.get("a") == 1
        assert cow.get("b") == 2

    def test_get_nonexistent_key_default_none(self):
        """Test get() method for non-existent key with default None."""
        original = {"a": 1}
        cow = CopyOnWriteDict(original)

        assert cow.get("nonexistent") is None

    def test_get_nonexistent_key_custom_default(self):
        """Test get() method for non-existent key with custom default."""
        original = {"a": 1}
        cow = CopyOnWriteDict(original)

        assert cow.get("nonexistent", "default") == "default"

    def test_get_deleted_key(self):
        """Test get() method for a deleted key returns default."""
        original = {"a": 1, "b": 2}
        cow = CopyOnWriteDict(original)

        del cow["a"]

        assert cow.get("a") is None
        assert cow.get("a", "default") == "default"

    def test_keys_original_only(self):
        """Test keys() method with only original keys."""
        original = {"a": 1, "b": 2, "c": 3}
        cow = CopyOnWriteDict(original)

        keys = list(cow.keys())
        assert set(keys) == {"a", "b", "c"}

    def test_keys_with_modifications(self):
        """Test keys() method with modifications."""
        original = {"a": 1, "b": 2}
        cow = CopyOnWriteDict(original)

        cow["c"] = 3
        del cow["a"]

        keys = list(cow.keys())
        assert set(keys) == {"b", "c"}

    def test_values_original_only(self):
        """Test values() method with only original values."""
        original = {"a": 1, "b": 2, "c": 3}
        cow = CopyOnWriteDict(original)

        values = list(cow.values())
        assert set(values) == {1, 2, 3}

    def test_values_with_modifications(self):
        """Test values() method with modifications."""
        original = {"a": 1, "b": 2}
        cow = CopyOnWriteDict(original)

        cow["a"] = 10
        cow["c"] = 3
        del cow["b"]

        values = list(cow.values())
        assert set(values) == {10, 3}

    def test_items_original_only(self):
        """Test items() method with only original items."""
        original = {"a": 1, "b": 2, "c": 3}
        cow = CopyOnWriteDict(original)

        items = list(cow.items())
        assert set(items) == {("a", 1), ("b", 2), ("c", 3)}

    def test_items_with_modifications(self):
        """Test items() method with modifications."""
        original = {"a": 1, "b": 2}
        cow = CopyOnWriteDict(original)

        cow["a"] = 10
        cow["c"] = 3
        del cow["b"]

        items = list(cow.items())
        assert set(items) == {("a", 10), ("c", 3)}

    def test_copy_original_only(self):
        """Test copy() method with only original data."""
        original = {"a": 1, "b": 2, "c": 3}
        cow = CopyOnWriteDict(original)

        copied = cow.copy()

        assert copied == {"a": 1, "b": 2, "c": 3}
        assert isinstance(copied, dict)
        assert copied is not original

    def test_copy_with_modifications(self):
        """Test copy() method with modifications."""
        original = {"a": 1, "b": 2}
        cow = CopyOnWriteDict(original)

        cow["a"] = 10
        cow["c"] = 3
        del cow["b"]

        copied = cow.copy()

        assert copied == {"a": 10, "c": 3}
        assert isinstance(copied, dict)

    def test_get_modifications_no_changes(self):
        """Test get_modifications() with no changes."""
        original = {"a": 1, "b": 2}
        cow = CopyOnWriteDict(original)

        mods = cow.get_modifications()

        assert mods == {}

    def test_get_modifications_with_additions(self):
        """Test get_modifications() with added keys."""
        original = {"a": 1}
        cow = CopyOnWriteDict(original)

        cow["b"] = 2
        cow["c"] = 3

        mods = cow.get_modifications()

        assert mods == {"b": 2, "c": 3}

    def test_get_modifications_with_overrides(self):
        """Test get_modifications() with overridden keys."""
        original = {"a": 1, "b": 2}
        cow = CopyOnWriteDict(original)

        cow["a"] = 10
        cow["c"] = 3

        mods = cow.get_modifications()

        assert mods == {"a": 10, "c": 3}

    def test_get_modifications_with_deletions(self):
        """Test get_modifications() after deletions."""
        original = {"a": 1, "b": 2}
        cow = CopyOnWriteDict(original)

        cow["c"] = 3
        del cow["b"]

        mods = cow.get_modifications()

        # Deletions are not in modifications, only in deleted set
        assert mods == {"c": 3}

    def test_get_modifications_returns_copy(self):
        """Test that get_modifications() returns a copy, not the original."""
        original = {"a": 1}
        cow = CopyOnWriteDict(original)

        cow["b"] = 2

        mods1 = cow.get_modifications()
        mods2 = cow.get_modifications()

        assert mods1 == mods2
        assert mods1 is not mods2

    def test_get_deleted_no_deletions(self):
        """Test get_deleted() with no deletions."""
        original = {"a": 1, "b": 2}
        cow = CopyOnWriteDict(original)

        deleted = cow.get_deleted()

        assert deleted == set()

    def test_get_deleted_with_deletions(self):
        """Test get_deleted() with deleted keys."""
        original = {"a": 1, "b": 2, "c": 3}
        cow = CopyOnWriteDict(original)

        del cow["a"]
        del cow["c"]

        deleted = cow.get_deleted()

        assert deleted == {"a", "c"}

    def test_get_deleted_returns_copy(self):
        """Test that get_deleted() returns a copy, not the original set."""
        original = {"a": 1, "b": 2}
        cow = CopyOnWriteDict(original)

        del cow["a"]

        deleted1 = cow.get_deleted()
        deleted2 = cow.get_deleted()

        assert deleted1 == deleted2
        assert deleted1 is not deleted2

    def test_has_modifications_false(self):
        """Test has_modifications() returns False with no changes."""
        original = {"a": 1, "b": 2}
        cow = CopyOnWriteDict(original)

        assert not cow.has_modifications()

    def test_has_modifications_true_with_additions(self):
        """Test has_modifications() returns True with additions."""
        original = {"a": 1}
        cow = CopyOnWriteDict(original)

        cow["b"] = 2

        assert cow.has_modifications()

    def test_has_modifications_true_with_overrides(self):
        """Test has_modifications() returns True with overrides."""
        original = {"a": 1}
        cow = CopyOnWriteDict(original)

        cow["a"] = 10

        assert cow.has_modifications()

    def test_has_modifications_true_with_deletions(self):
        """Test has_modifications() returns True with deletions."""
        original = {"a": 1, "b": 2}
        cow = CopyOnWriteDict(original)

        del cow["a"]

        assert cow.has_modifications()

    def test_repr(self):
        """Test __repr__ method."""
        original = {"a": 1, "b": 2}
        cow = CopyOnWriteDict(original)

        repr_str = repr(cow)

        assert "CopyOnWriteDict" in repr_str
        assert "a" in repr_str or "1" in repr_str

    def test_repr_with_modifications(self):
        """Test __repr__ with modifications."""
        original = {"a": 1}
        cow = CopyOnWriteDict(original)

        cow["b"] = 2
        del cow["a"]

        repr_str = repr(cow)

        assert "CopyOnWriteDict" in repr_str
        assert "b" in repr_str or "2" in repr_str

    def test_complex_workflow(self):
        """Test a complex workflow with multiple operations."""
        original = {"a": 1, "b": 2, "c": 3, "d": 4}
        cow = CopyOnWriteDict(original)

        # Perform various operations
        cow["a"] = 10  # Override
        cow["e"] = 5  # Add new
        del cow["b"]  # Delete
        cow["c"] = 30  # Override

        # Verify state
        assert cow["a"] == 10
        assert "b" not in cow
        assert cow["c"] == 30
        assert cow["d"] == 4
        assert cow["e"] == 5

        # Verify original unchanged
        assert original == {"a": 1, "b": 2, "c": 3, "d": 4}

        # Verify modifications
        assert cow.get_modifications() == {"a": 10, "c": 30, "e": 5}
        assert cow.get_deleted() == {"b"}
        assert cow.has_modifications()

        # Verify copy
        assert cow.copy() == {"a": 10, "c": 30, "d": 4, "e": 5}

    def test_original_dict_mutations_not_reflected(self):
        """Test that mutations to the original dict after COW creation are visible."""
        original = {"a": 1, "b": 2}
        cow = CopyOnWriteDict(original)

        # Mutate original - this WILL be visible in COW since ChainMap references the original
        original["c"] = 3

        # ChainMap references the original, so this change is visible
        assert cow["c"] == 3

    def test_nested_values(self):
        """Test that nested values work correctly."""
        original = {"a": {"nested": 1}, "b": [1, 2, 3]}
        cow = CopyOnWriteDict(original)

        # Read nested values
        assert cow["a"] == {"nested": 1}
        assert cow["b"] == [1, 2, 3]

        # Modify nested value
        cow["a"] = {"nested": 10}

        assert cow["a"] == {"nested": 10}
        assert original["a"] == {"nested": 1}

    def test_duplicate_operations(self):
        """Test duplicate operations on the same key."""
        original = {"a": 1}
        cow = CopyOnWriteDict(original)

        # Multiple modifications to same key
        cow["a"] = 10
        cow["a"] = 20
        cow["a"] = 30

        assert cow["a"] == 30
        assert cow.get_modifications() == {"a": 30}

    def test_delete_and_recreate(self):
        """Test deleting a key and then recreating it."""
        original = {"a": 1}
        cow = CopyOnWriteDict(original)

        del cow["a"]
        assert "a" not in cow

        cow["a"] = 10
        assert cow["a"] == 10
        assert "a" not in cow.get_deleted()

    def test_update_with_dict(self):
        """Test update() method with a dictionary."""
        original = {"a": 1}
        cow = CopyOnWriteDict(original)

        cow.update({"b": 2, "c": 3})

        assert cow["a"] == 1
        assert cow["b"] == 2
        assert cow["c"] == 3
        assert original == {"a": 1}

    def test_update_with_kwargs(self):
        """Test update() method with keyword arguments."""
        original = {"a": 1}
        cow = CopyOnWriteDict(original)

        cow.update(b=2, c=3)

        assert cow["b"] == 2
        assert cow["c"] == 3

    def test_update_with_both(self):
        """Test update() method with both dict and kwargs."""
        original = {"a": 1}
        cow = CopyOnWriteDict(original)

        cow.update({"b": 2}, c=3, d=4)

        assert cow["b"] == 2
        assert cow["c"] == 3
        assert cow["d"] == 4

    def test_update_with_iterable(self):
        """Test update() method with an iterable of pairs."""
        original = {"a": 1}
        cow = CopyOnWriteDict(original)

        cow.update([("b", 2), ("c", 3)])

        assert cow["b"] == 2
        assert cow["c"] == 3

    def test_update_overwrites_existing(self):
        """Test that update() overwrites existing keys."""
        original = {"a": 1, "b": 2}
        cow = CopyOnWriteDict(original)

        cow.update({"a": 10, "c": 3})

        assert cow["a"] == 10
        assert cow["b"] == 2
        assert cow["c"] == 3
        assert original["a"] == 1

    def test_pop_existing_key(self):
        """Test pop() method with existing key."""
        original = {"a": 1, "b": 2}
        cow = CopyOnWriteDict(original)

        value = cow.pop("a")

        assert value == 1
        assert "a" not in cow
        assert original == {"a": 1, "b": 2}

    def test_pop_nonexistent_key_with_default(self):
        """Test pop() method with non-existent key and default."""
        original = {"a": 1}
        cow = CopyOnWriteDict(original)

        value = cow.pop("nonexistent", "default")

        assert value == "default"

    def test_pop_nonexistent_key_no_default(self):
        """Test pop() method with non-existent key and no default raises KeyError."""
        original = {"a": 1}
        cow = CopyOnWriteDict(original)

        with pytest.raises(KeyError):
            cow.pop("nonexistent")

    def test_pop_too_many_args(self):
        """Test pop() with too many arguments raises TypeError."""
        original = {"a": 1}
        cow = CopyOnWriteDict(original)

        with pytest.raises(TypeError, match="pop\\(\\) accepts 1 or 2 arguments"):
            cow.pop("a", "default1", "default2")

    def test_pop_modified_key(self):
        """Test pop() on a key that was modified."""
        original = {"a": 1}
        cow = CopyOnWriteDict(original)

        cow["a"] = 10
        value = cow.pop("a")

        assert value == 10
        assert "a" not in cow

    def test_setdefault_existing_key(self):
        """Test setdefault() with an existing key."""
        original = {"a": 1}
        cow = CopyOnWriteDict(original)

        value = cow.setdefault("a", 10)

        assert value == 1
        assert cow["a"] == 1
        assert original == {"a": 1}

    def test_setdefault_new_key(self):
        """Test setdefault() with a new key."""
        original = {"a": 1}
        cow = CopyOnWriteDict(original)

        value = cow.setdefault("b", 2)

        assert value == 2
        assert cow["b"] == 2
        assert original == {"a": 1}

    def test_setdefault_default_none(self):
        """Test setdefault() with default None."""
        original = {"a": 1}
        cow = CopyOnWriteDict(original)

        value = cow.setdefault("b")

        assert value is None
        assert cow["b"] is None

    def test_clear(self):
        """Test clear() method."""
        original = {"a": 1, "b": 2, "c": 3}
        cow = CopyOnWriteDict(original)

        cow["d"] = 4
        cow.clear()

        assert len(cow) == 0
        assert list(cow.keys()) == []
        assert original == {"a": 1, "b": 2, "c": 3}

    def test_clear_empty_dict(self):
        """Test clear() on an empty dict."""
        original = {}
        cow = CopyOnWriteDict(original)

        cow.clear()

        assert len(cow) == 0

    def test_update_after_clear(self):
        """Test that update works after clear."""
        original = {"a": 1, "b": 2}
        cow = CopyOnWriteDict(original)

        cow.clear()
        cow.update({"c": 3, "d": 4})

        assert len(cow) == 2
        assert cow["c"] == 3
        assert cow["d"] == 4
        assert "a" not in cow
        assert "b" not in cow

    def test_iter_modifications_before_original(self):
        """Test that __iter__ yields modifications before original keys."""
        original = {"a": 1, "b": 2}
        cow = CopyOnWriteDict(original)

        # Modify existing key
        cow["a"] = 10

        keys = list(cow)
        # Should have both keys, but modifications take precedence
        assert set(keys) == {"a", "b"}
        # First key should be from modifications (a), since we modified it
        assert keys[0] == "a"

    def test_iter_skips_deleted_keys_in_modifications(self):
        """Test that __iter__ skips keys that are in modifications but marked deleted."""
        original = {"a": 1, "b": 2}
        cow = CopyOnWriteDict(original)

        # Modify a key (adds to modifications layer)
        cow["a"] = 10
        # Add a new key (also in modifications layer)
        cow["c"] = 3
        # Delete the modified key (marks as deleted but it's still in modifications layer)
        del cow["a"]

        keys = list(cow)
        # Should only have b (from original) and c (from modifications, not deleted)
        assert set(keys) == {"b", "c"}
        assert "a" not in keys


class TestCopyOnWriteFunction:
    """Test suite for copyonwrite() factory function."""

    def test_copyonwrite_with_dict(self):
        """Test copyonwrite() function with a dictionary."""
        original = {"a": 1, "b": 2}
        cow = copyonwrite(original)

        assert isinstance(cow, CopyOnWriteDict)
        assert isinstance(cow, dict)
        assert cow["a"] == 1
        assert cow["b"] == 2

    def test_copyonwrite_returns_copyonwritedict(self):
        """Test that copyonwrite() returns a CopyOnWriteDict instance."""
        original = {"x": 10}
        result = copyonwrite(original)

        assert type(result).__name__ == "CopyOnWriteDict"
        assert result["x"] == 10

    def test_copyonwrite_with_empty_dict(self):
        """Test copyonwrite() function with an empty dictionary."""
        original = {}
        cow = copyonwrite(original)

        assert isinstance(cow, CopyOnWriteDict)
        assert len(cow) == 0

    def test_copyonwrite_preserves_original(self):
        """Test that copyonwrite() doesn't modify the original dict."""
        original = {"a": 1}
        cow = copyonwrite(original)

        cow["a"] = 10
        cow["b"] = 2

        assert original == {"a": 1}
        assert cow["a"] == 10

    def test_copyonwrite_with_list(self):
        """Test copyonwrite() function with a list."""
        original = [1, 2, 3]
        cow = copyonwrite(original)

        assert isinstance(cow, CopyOnWriteList)
        assert isinstance(cow, list)
        assert list(cow) == [1, 2, 3]

    def test_copyonwrite_with_list_preserves_original(self):
        """Test that copyonwrite() doesn't modify the original list."""
        original = [1, 2, 3]
        cow = copyonwrite(original)

        cow[0] = 10
        cow.append(4)

        assert original == [1, 2, 3]
        assert list(cow) == [10, 2, 3, 4]

    def test_copyonwrite_with_unsupported_raises_typeerror(self):
        """Test that copyonwrite() raises TypeError for unsupported types."""
        with pytest.raises(TypeError, match="No copy-on-write wrapper available"):
            copyonwrite("string")

        with pytest.raises(TypeError, match="No copy-on-write wrapper available"):
            copyonwrite(42)

        with pytest.raises(TypeError, match="No copy-on-write wrapper available"):
            copyonwrite({1, 2, 3})

        with pytest.raises(TypeError, match="No copy-on-write wrapper available"):
            copyonwrite(None)


class TestCopyOnWriteList:
    """Test suite for CopyOnWriteList class."""

    def test_is_list_subclass(self):
        original = [1, 2, 3]
        cow = CopyOnWriteList(original)
        assert isinstance(cow, list)
        assert issubclass(CopyOnWriteList, list)

    def test_read_delegation(self):
        """Read operations delegate to original without materializing."""
        original = [1, 2, 3]
        cow = CopyOnWriteList(original)

        assert cow[0] == 1
        assert cow[2] == 3
        assert len(cow) == 3
        assert list(cow) == [1, 2, 3]
        assert 2 in cow
        assert 99 not in cow
        assert not cow.has_modifications()

    def test_read_with_slice(self):
        original = [10, 20, 30, 40]
        cow = CopyOnWriteList(original)
        assert cow[1:3] == [20, 30]
        assert not cow.has_modifications()

    def test_setitem_materializes(self):
        """First write materializes the list and protects original."""
        original = [1, 2, 3]
        cow = CopyOnWriteList(original)

        cow[0] = 10

        assert cow[0] == 10
        assert list(cow) == [10, 2, 3]
        assert original == [1, 2, 3]
        assert cow.has_modifications()

    def test_delitem(self):
        original = [1, 2, 3]
        cow = CopyOnWriteList(original)

        del cow[1]

        assert list(cow) == [1, 3]
        assert original == [1, 2, 3]

    def test_append(self):
        original = [1, 2]
        cow = CopyOnWriteList(original)

        cow.append(3)

        assert list(cow) == [1, 2, 3]
        assert original == [1, 2]
        assert cow.has_modifications()

    def test_extend(self):
        original = [1]
        cow = CopyOnWriteList(original)

        cow.extend([2, 3])

        assert list(cow) == [1, 2, 3]
        assert original == [1]

    def test_insert(self):
        original = [1, 3]
        cow = CopyOnWriteList(original)

        cow.insert(1, 2)

        assert list(cow) == [1, 2, 3]
        assert original == [1, 3]

    def test_remove(self):
        original = [1, 2, 3]
        cow = CopyOnWriteList(original)

        cow.remove(2)

        assert list(cow) == [1, 3]
        assert original == [1, 2, 3]

    def test_pop(self):
        original = [1, 2, 3]
        cow = CopyOnWriteList(original)

        val = cow.pop()

        assert val == 3
        assert list(cow) == [1, 2]
        assert original == [1, 2, 3]

    def test_pop_index(self):
        original = [1, 2, 3]
        cow = CopyOnWriteList(original)

        val = cow.pop(0)

        assert val == 1
        assert list(cow) == [2, 3]

    def test_clear(self):
        original = [1, 2, 3]
        cow = CopyOnWriteList(original)

        cow.clear()

        assert list(cow) == []
        assert len(cow) == 0
        assert original == [1, 2, 3]

    def test_sort(self):
        original = [3, 1, 2]
        cow = CopyOnWriteList(original)

        cow.sort()

        assert list(cow) == [1, 2, 3]
        assert original == [3, 1, 2]

    def test_reverse(self):
        original = [1, 2, 3]
        cow = CopyOnWriteList(original)

        cow.reverse()

        assert list(cow) == [3, 2, 1]
        assert original == [1, 2, 3]

    def test_has_modifications_false_initially(self):
        cow = CopyOnWriteList([1, 2])
        assert not cow.has_modifications()

    def test_has_modifications_true_after_write(self):
        cow = CopyOnWriteList([1, 2])
        cow.append(3)
        assert cow.has_modifications()

    def test_copy(self):
        original = [1, 2, 3]
        cow = CopyOnWriteList(original)
        copied = cow.copy()
        assert copied == [1, 2, 3]
        assert isinstance(copied, list)
        assert not isinstance(copied, CopyOnWriteList)

    def test_repr(self):
        cow = CopyOnWriteList([1, 2])
        assert "CopyOnWriteList" in repr(cow)
        assert "1" in repr(cow)

    def test_empty_list(self):
        original = []
        cow = CopyOnWriteList(original)
        assert len(cow) == 0
        assert list(cow) == []

    def test_multiple_writes(self):
        """Multiple writes only materialize once."""
        original = [1, 2, 3]
        cow = CopyOnWriteList(original)

        cow[0] = 10
        cow[1] = 20
        cow.append(4)

        assert list(cow) == [10, 20, 3, 4]
        assert original == [1, 2, 3]


# ---------------------------------------------------------------------------
# Pydantic helpers for wrap_payload_for_isolation tests
# ---------------------------------------------------------------------------


class _FrozenPayload(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str = "test"
    args: dict = Field(default_factory=dict)


class _PayloadWithList(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str = "test"
    items: list = Field(default_factory=list)


class _PayloadWithNested(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str = "test"
    inner: _FrozenPayload = Field(default_factory=_FrozenPayload)


class _HeaderLike(RootModel[dict[str, str]]):
    model_config = ConfigDict(frozen=True)


class _PayloadWithAny(BaseModel):
    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    name: str = "test"
    data: object = None


class TestWrapPayloadForIsolation:
    """Tests for wrap_payload_for_isolation()."""

    def test_dict_field_wrapped(self):
        """Dict fields are wrapped with CopyOnWriteDict."""
        original_args = {"key": "val"}
        p = _FrozenPayload(name="x", args=original_args)

        wrapped = wrap_payload_for_isolation(p)

        assert isinstance(wrapped.args, CopyOnWriteDict)
        assert wrapped.args["key"] == "val"
        # Mutation on wrapped copy doesn't affect original
        wrapped.args["key"] = "changed"
        assert original_args["key"] == "val"

    def test_list_field_wrapped(self):
        """List fields are wrapped with CopyOnWriteList."""
        original_items = [1, 2, 3]
        p = _PayloadWithList(name="x", items=original_items)

        wrapped = wrap_payload_for_isolation(p)

        assert isinstance(wrapped.items, CopyOnWriteList)
        assert list(wrapped.items) == [1, 2, 3]
        wrapped.items.append(4)
        assert original_items == [1, 2, 3]

    def test_nested_basemodel_recursively_wrapped(self):
        """Nested BaseModel fields are recursively wrapped."""
        inner_args = {"nested": "data"}
        inner = _FrozenPayload(name="inner", args=inner_args)
        p = _PayloadWithNested(name="outer", inner=inner)

        wrapped = wrap_payload_for_isolation(p)

        assert isinstance(wrapped.inner.args, CopyOnWriteDict)
        wrapped.inner.args["nested"] = "changed"
        assert inner_args["nested"] == "data"

    def test_rootmodel_payload_wrapped(self):
        """RootModel payloads have their .root dict wrapped."""
        original_root = {"Content-Type": "text/plain"}
        p = _HeaderLike(root=original_root)

        wrapped = wrap_payload_for_isolation(p)

        assert isinstance(wrapped.root, CopyOnWriteDict)
        assert wrapped.root["Content-Type"] == "text/plain"
        wrapped.root["X-New"] = "header"
        assert "X-New" not in original_root

    def test_primitives_shared(self):
        """Primitive fields are not copied."""
        p = _FrozenPayload(name="hello", args={})

        wrapped = wrap_payload_for_isolation(p)

        assert wrapped.name is p.name

    def test_none_fields_skipped(self):
        """None-valued fields are not wrapped."""
        p = _PayloadWithAny(name="x", data=None)

        wrapped = wrap_payload_for_isolation(p)

        assert wrapped.data is None

    def test_any_typed_dict_field_wrapped(self):
        """Any-typed fields that are dicts get wrapped."""
        original = {"a": 1}
        p = _PayloadWithAny(name="x", data=original)

        wrapped = wrap_payload_for_isolation(p)

        assert isinstance(wrapped.data, CopyOnWriteDict)
        wrapped.data["a"] = 99
        assert original["a"] == 1

    def test_any_typed_list_field_wrapped(self):
        """Any-typed fields that are lists get wrapped."""
        original = [1, 2, 3]
        p = _PayloadWithAny(name="x", data=original)

        wrapped = wrap_payload_for_isolation(p)

        assert isinstance(wrapped.data, CopyOnWriteList)
        wrapped.data[0] = 99
        assert original[0] == 1

    def test_payload_with_no_mutable_fields_unchanged(self):
        """Payload with only primitive fields returns same instance."""
        p = _FrozenPayload(name="x", args={})

        wrapped = wrap_payload_for_isolation(p)
        assert wrapped.name == "x"
        assert wrapped.args == {}

        # Empty dict is not None, so it will be wrapped — test with no dict
        p2 = _PayloadWithAny(name="x", data=42)
        wrapped2 = wrap_payload_for_isolation(p2)
        # data=42 is a primitive, name="x" is a primitive — no updates needed
        assert wrapped2.name == "x"
        assert wrapped2.data == 42


# ---------------------------------------------------------------------------
# Helper: a target class for weakref proxies
# ---------------------------------------------------------------------------


class _Service:
    """Dummy service object that supports weak references."""

    def __init__(self, name: str = "svc"):
        self.name = name

    def greet(self) -> str:
        return f"hello from {self.name}"


class _PayloadWithWeakref(BaseModel):
    """Payload with a weakref proxy field (non-writable by convention)."""

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    label: str = "test"
    service: object = None  # Will hold a weakref.proxy


class _PayloadWithWeakrefAndDict(BaseModel):
    """Payload with both a weakref proxy and a mutable dict field."""

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    label: str = "test"
    service: object = None
    args: dict = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Tests: weakref proxies through isolation
# ---------------------------------------------------------------------------


class TestWeakrefIsolation:
    """Tests for weakref proxy handling in payload isolation."""

    def test_wrap_value_passes_proxy_through(self):
        """_wrap_value returns a weakref.proxy as-is (no copy)."""
        svc = _Service("alpha")
        proxy = weakref.proxy(svc)

        result = _wrap_value(proxy)

        assert result is proxy
        assert result.greet() == "hello from alpha"

    def test_wrap_value_passes_callable_proxy_through(self):
        """_wrap_value returns a callable weakref.proxy as-is."""
        svc = _Service("beta")
        proxy = weakref.proxy(svc)  # proxy to an object with __call__-able methods

        result = _wrap_value(proxy)

        assert result is proxy

    def test_payload_weakref_field_preserved_after_isolation(self):
        """Weakref proxy field survives wrap_payload_for_isolation unchanged."""
        svc = _Service("gamma")
        proxy = weakref.proxy(svc)
        p = _PayloadWithWeakref(label="x", service=proxy)

        wrapped = wrap_payload_for_isolation(p)

        # The proxy is the same object — not copied
        assert wrapped.service is proxy
        assert wrapped.service.greet() == "hello from gamma"

    def test_payload_weakref_alongside_mutable_field(self):
        """Weakref proxy is preserved while mutable dict field is CoW-wrapped."""
        svc = _Service("delta")
        proxy = weakref.proxy(svc)
        original_args = {"key": "val"}
        p = _PayloadWithWeakrefAndDict(label="x", service=proxy, args=original_args)

        wrapped = wrap_payload_for_isolation(p)

        # Weakref proxy passed through
        assert wrapped.service is proxy
        assert wrapped.service.greet() == "hello from delta"
        # Dict field is CoW-wrapped and isolates mutations
        assert isinstance(wrapped.args, CopyOnWriteDict)
        wrapped.args["key"] = "changed"
        assert original_args["key"] == "val"

    def test_multiple_isolations_share_same_proxy(self):
        """Multiple isolation calls return the same proxy identity."""
        svc = _Service("echo")
        proxy = weakref.proxy(svc)
        p = _PayloadWithWeakref(label="x", service=proxy)

        w1 = wrap_payload_for_isolation(p)
        w2 = wrap_payload_for_isolation(p)

        assert w1.service is w2.service is proxy

    def test_weakref_in_dict_field_passed_through(self):
        """A weakref proxy stored inside a dict value is not deep-copied."""
        svc = _Service("foxtrot")
        proxy = weakref.proxy(svc)
        original = {"svc": proxy, "count": 1}
        p = _PayloadWithAny(name="x", data=original)

        wrapped = wrap_payload_for_isolation(p)

        # The dict itself is CoW-wrapped
        assert isinstance(wrapped.data, CopyOnWriteDict)
        # The proxy inside the dict is the same object (read from original)
        assert wrapped.data["svc"] is proxy
        assert wrapped.data["svc"].greet() == "hello from foxtrot"

    def test_weakref_in_list_field_passed_through(self):
        """A weakref proxy stored inside a list element is not deep-copied."""
        svc = _Service("golf")
        proxy = weakref.proxy(svc)
        original = [proxy, 42]
        p = _PayloadWithAny(name="x", data=original)

        wrapped = wrap_payload_for_isolation(p)

        assert isinstance(wrapped.data, CopyOnWriteList)
        # Proxy is read from the original list (no copy)
        assert wrapped.data[0] is proxy
        assert wrapped.data[0].greet() == "hello from golf"

    def test_expired_weakref_raises_on_access(self):
        """If the referent is garbage-collected, accessing the proxy raises ReferenceError."""
        svc = _Service("hotel")
        proxy = weakref.proxy(svc)
        p = _PayloadWithWeakref(label="x", service=proxy)

        wrapped = wrap_payload_for_isolation(p)

        # Delete the referent
        del svc
        with pytest.raises(ReferenceError):
            wrapped.service.greet()


# ---------------------------------------------------------------------------
# Tests: _safe_deepcopy diagnostics
# ---------------------------------------------------------------------------


class TestSafeDeepCopy:
    """Tests for _safe_deepcopy error handling."""

    def test_copyable_value_returned(self):
        """Normal objects are deep-copied successfully."""
        original = {"a": [1, 2, 3]}
        result = _safe_deepcopy(original)

        assert result == original
        assert result is not original
        assert result["a"] is not original["a"]

    def test_non_copyable_returns_shared_reference(self):
        """Non-copyable objects return a shared reference with a warning."""
        import threading

        lock = threading.Lock()

        result = _safe_deepcopy(lock)

        # Should return the original object as a shared reference
        assert result is lock

    def test_non_copyable_logs_warning(self, caplog):
        """Non-copyable objects log a warning when falling back to shared reference."""
        import logging
        import threading

        lock = threading.Lock()

        with caplog.at_level(logging.WARNING):
            result = _safe_deepcopy(lock)

        assert result is lock
        assert "Cannot deep-copy" in caplog.text or "sharing reference" in caplog.text


# ---------------------------------------------------------------------------
# Tests: BaseException isolation (no deepcopy)
# ---------------------------------------------------------------------------


class _NonCopyableError(Exception):
    """Exception whose __init__ uses keyword-only args, breaking deepcopy."""

    def __init__(self, *, message: str = "error", request: object = None):
        super().__init__(message)
        self.request = request


class _PayloadWithException(BaseModel):
    """Payload carrying an exception field (like GenerationErrorPayload)."""

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    name: str = "test"
    exception: BaseException


class _PayloadWithExceptionAndDict(BaseModel):
    """Payload with both an exception and a mutable dict field."""

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    name: str = "test"
    exception: BaseException
    args: dict = Field(default_factory=dict)


class TestExceptionIsolation:
    """Tests for BaseException handling in payload isolation."""

    def test_wrap_value_returns_exception_as_is(self):
        """_wrap_value returns a BaseException instance without copying."""
        exc = ValueError("something went wrong")
        result = _wrap_value(exc)
        assert result is exc

    def test_wrap_value_returns_non_copyable_exception_as_is(self):
        """_wrap_value returns exceptions with keyword-only __init__ as-is."""
        exc = _NonCopyableError(message="conn error", request=None)
        result = _wrap_value(exc)
        assert result is exc

    def test_wrap_payload_exception_field_shared(self):
        """Exception field in a payload is shared by reference after isolation."""
        exc = _NonCopyableError(message="conn error", request=None)
        p = _PayloadWithException(name="x", exception=exc)

        wrapped = wrap_payload_for_isolation(p)

        assert wrapped.exception is exc

    def test_wrap_payload_exception_no_warning(self, caplog):
        """Isolating a payload with an exception field produces no deepcopy warning."""
        import logging

        exc = _NonCopyableError(message="conn error", request=None)
        p = _PayloadWithException(name="x", exception=exc)

        with caplog.at_level(logging.WARNING):
            wrap_payload_for_isolation(p)

        assert "Cannot deep-copy" not in caplog.text

    def test_wrap_payload_exception_alongside_dict(self):
        """Exception is shared while dict field is CoW-wrapped."""
        exc = _NonCopyableError(message="conn error", request=None)
        original_args = {"key": "val"}
        p = _PayloadWithExceptionAndDict(
            name="x", exception=exc, args=original_args
        )

        wrapped = wrap_payload_for_isolation(p)

        assert wrapped.exception is exc
        assert isinstance(wrapped.args, CopyOnWriteDict)
        wrapped.args["key"] = "changed"
        assert original_args["key"] == "val"

    def test_wrap_value_base_exception_subclass(self):
        """_wrap_value handles BaseException subclasses (not just Exception)."""
        exc = KeyboardInterrupt()
        result = _wrap_value(exc)
        assert result is exc

    def test_wrap_value_standard_exception(self):
        """_wrap_value handles standard copyable exceptions as-is too."""
        exc = RuntimeError("boom")
        result = _wrap_value(exc)
        assert result is exc
