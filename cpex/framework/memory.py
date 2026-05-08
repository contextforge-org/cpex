# -*- coding: utf-8 -*-
"""Location: ./cpex/framework/memory.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Fred Araujo

Memory management utilities for plugin framework.

This module provides copy-on-write data structures for efficient memory management
in plugin contexts.
"""

# Standard
import copy
import logging
import weakref
from typing import Any, Iterator, Optional, TypeVar

# Third-Party
from pydantic import BaseModel, RootModel

T = TypeVar("T")
logger = logging.getLogger(__name__)


class CopyOnWriteDict(dict):
    """
    A dictionary subclass that implements copy-on-write behavior.

    Inherits from dict and layers modifications over an original dictionary
    without mutating the original. The dict itself stores modifications, while
    reads check the modifications first, then fall back to the original.

    This is useful for plugin contexts where you want to isolate modifications
    without copying the entire original dictionary upfront. Since it subclasses
    dict, it's compatible with type checking and validation frameworks like Pydantic.

    Example:
        >>> original = {"a": 1, "b": 2, "c": 3}
        >>> cow = CopyOnWriteDict(original)
        >>> isinstance(cow, dict)
        True
        >>> cow["a"] = 10  # Modification stored in dict
        >>> cow["d"] = 4   # New key stored in dict
        >>> del cow["b"]   # Deletion tracked separately
        >>> cow["a"]
        10
        >>> "b" in cow
        False
        >>> original  # Original unchanged
        {'a': 1, 'b': 2, 'c': 3}
        >>> cow.get_modifications()
        {'a': 10, 'd': 4}
    """

    def __init__(self, original: dict):
        """
        Initialize a copy-on-write dictionary wrapper.

        Args:
            original: The original dictionary to wrap. This will not be modified.
        """
        # Initialize parent dict without any data
        # The parent dict (self via super()) will store modifications only
        super().__init__()
        self._original = original
        self._deleted = set()  # Track keys that have been deleted

    def __getitem__(self, key: Any) -> Any:
        """
        Get an item from the dictionary.

        Args:
            key: The key to look up.

        Returns:
            The value associated with the key.

        Raises:
            KeyError: If the key is not found or has been deleted.
        """
        if key in self._deleted:
            raise KeyError(key)
        # Check modifications first (via super()), then original
        if super().__contains__(key):
            return super().__getitem__(key)
        if key in self._original:
            return self._original[key]
        raise KeyError(key)

    def __setitem__(self, key: Any, value: Any) -> None:
        """
        Set an item in the dictionary.

        The modification is stored in the wrapper layer, not the original dict.

        Args:
            key: The key to set.
            value: The value to associate with the key.
        """
        super().__setitem__(key, value)  # Store in modifications (parent dict)
        self._deleted.discard(key)  # If we're setting it, it's not deleted

    def __delitem__(self, key: Any) -> None:
        """
        Delete an item from the dictionary.

        The key is marked as deleted in the wrapper layer.

        Args:
            key: The key to delete.

        Raises:
            KeyError: If the key doesn't exist in the dictionary.
        """
        if key not in self:
            raise KeyError(key)
        self._deleted.add(key)
        if super().__contains__(key):
            super().__delitem__(key)  # Remove from modifications if present

    def __contains__(self, key: Any) -> bool:
        """
        Check if a key exists in the dictionary.

        Args:
            key: The key to check.

        Returns:
            True if the key exists and hasn't been deleted, False otherwise.
        """
        if key in self._deleted:
            return False
        return super().__contains__(key) or key in self._original

    def __len__(self) -> int:
        """
        Get the number of items in the dictionary.

        Returns:
            The count of non-deleted keys.
        """
        # Get all keys from both modifications and original, excluding deleted
        all_keys = set(super().keys()) | set(self._original.keys())
        return len(all_keys - self._deleted)

    def __iter__(self) -> Iterator:
        """
        Iterate over keys in the dictionary.

        Yields keys in insertion order: first keys from the original dict (in their
        original order), then new keys from modifications (in their insertion order).

        Yields:
            Keys that haven't been deleted.
        """
        # First, yield keys from original (in original order)
        for key in self._original:
            if key not in self._deleted:
                yield key

        # Then yield new keys from modifications (not in original)
        for key in super().__iter__():
            if key not in self._original and key not in self._deleted:
                yield key

    def __repr__(self) -> str:
        """
        Get a string representation of the dictionary.

        Returns:
            A string representation showing the current state.
        """
        return f"CopyOnWriteDict({dict(self.items())})"

    def get(self, key: Any, default: Optional[Any] = None) -> Any:
        """
        Get an item with a default fallback.

        Args:
            key: The key to look up.
            default: The value to return if the key is not found.

        Returns:
            The value associated with the key, or default if not found/deleted.
        """
        try:
            return self[key]
        except KeyError:
            return default

    def keys(self):
        """
        Get all non-deleted keys.

        Returns:
            A generator of keys.
        """
        return iter(self)

    def values(self):
        """
        Get all values for non-deleted keys.

        Returns:
            A generator of values.
        """
        return (self[k] for k in self)

    def items(self):
        """
        Get all key-value pairs for non-deleted keys.

        Returns:
            A generator of (key, value) tuples.
        """
        return ((k, self[k]) for k in self)

    def copy(self) -> dict:
        """
        Create a regular dictionary with all current key-value pairs.

        Returns:
            A new dict containing the current state (original + modifications - deletions).
        """
        return dict(self.items())

    def get_modifications(self) -> dict:
        """
        Get only the modifications made to the wrapper.

        This returns only the keys that were added or changed in the modification layer,
        not including values from the original dictionary that weren't modified.

        Returns:
            A copy of the modifications dictionary.
        """
        # The parent dict (super()) contains only modifications
        return dict(super().items())

    def get_deleted(self) -> set:
        """
        Get the set of deleted keys.

        Returns:
            A copy of the deleted keys set.
        """
        return self._deleted.copy()

    def has_modifications(self) -> bool:
        """
        Check if any modifications have been made.

        Returns:
            True if there are any modifications or deletions, False otherwise.
        """
        # Check if parent dict has any entries (modifications) or if anything was deleted
        return super().__len__() > 0 or len(self._deleted) > 0

    def update(self, other=None, **kwargs) -> None:
        """
        Update the dictionary with key-value pairs from another mapping or iterable.

        Args:
            other: A mapping or iterable of key-value pairs.
            **kwargs: Additional key-value pairs to update.

        Examples:
            >>> cow = CopyOnWriteDict({"a": 1})
            >>> cow.update({"b": 2, "c": 3})
            >>> cow.update(d=4, e=5)
            >>> dict(cow.items())
            {'a': 1, 'b': 2, 'c': 3, 'd': 4, 'e': 5}
        """
        if other is not None:
            if hasattr(other, "items"):
                for key, value in other.items():
                    self[key] = value
            else:
                for key, value in other:
                    self[key] = value
        for key, value in kwargs.items():
            self[key] = value

    def pop(self, key: Any, *args) -> Any:
        """
        Remove and return the value for a key.

        Args:
            key: The key to remove.
            *args: Optional default value if key is not found.

        Returns:
            The value associated with the key.

        Raises:
            KeyError: If key is not found and no default is provided.
            TypeError: If more than one default argument is provided.

        Examples:
            >>> cow = CopyOnWriteDict({"a": 1, "b": 2})
            >>> cow.pop("a")
            1
            >>> cow.pop("c", "default")
            'default'
        """
        if len(args) > 1:
            raise TypeError(f"pop() accepts 1 or 2 arguments ({len(args) + 1} given)")

        try:
            value = self[key]
            del self[key]
            return value
        except KeyError:
            if args:
                return args[0]
            raise

    def setdefault(self, key: Any, default: Any = None) -> Any:
        """
        Get a value, setting it to a default if not present.

        Args:
            key: The key to look up.
            default: The default value to set if key is not present.

        Returns:
            The value associated with the key (existing or newly set).

        Examples:
            >>> cow = CopyOnWriteDict({"a": 1})
            >>> cow.setdefault("a", 10)
            1
            >>> cow.setdefault("b", 2)
            2
            >>> cow["b"]
            2
        """
        if key in self:
            return self[key]
        self[key] = default
        return default

    def clear(self) -> None:
        """
        Remove all items from the dictionary.

        This marks all keys (from original and modifications) as deleted.

        Examples:
            >>> cow = CopyOnWriteDict({"a": 1, "b": 2})
            >>> cow.clear()
            >>> len(cow)
            0
        """
        # Mark all current keys as deleted
        for key in list(self.keys()):
            self._deleted.add(key)
        # Clear modifications from parent dict
        super().clear()


class CopyOnWriteList(list):
    """
    A list subclass that implements copy-on-write behavior using lazy-copy strategy.

    Read operations delegate to the original list; on first write, the entire
    list is materialized into the parent ``list`` storage. This is O(0) for
    read-only access (common case) and O(n) on first write.

    Example:
        >>> original = [1, 2, 3]
        >>> cow = CopyOnWriteList(original)
        >>> isinstance(cow, list)
        True
        >>> cow[0]
        1
        >>> cow[0] = 10  # triggers materialization
        >>> cow[0]
        10
        >>> original  # unchanged
        [1, 2, 3]
    """

    def __init__(self, original: list):
        """Initialize with the original list to wrap."""
        super().__init__()
        self._original = original
        self._materialized = False

    # -- internal helpers --------------------------------------------------

    def _materialize(self):
        """Copy original data into parent list storage on first write."""
        if not self._materialized:
            super().extend(self._original)
            self._materialized = True

    def _source(self):
        """Return the backing data: parent list if materialized, else original."""
        return super().__iter__() if self._materialized else self._original

    # -- read operations (delegate to original when not materialized) ------

    def __getitem__(self, index):
        """Return item at index from the active backing store."""
        if self._materialized:
            return super().__getitem__(index)
        return self._original[index]

    def __len__(self):
        """Return the length of the active backing store."""
        if self._materialized:
            return super().__len__()
        return len(self._original)

    def __iter__(self):
        """Iterate over the active backing store."""
        if self._materialized:
            return super().__iter__()
        return iter(self._original)

    def __contains__(self, item):
        """Return True if item is in the active backing store."""
        if self._materialized:
            return super().__contains__(item)
        return item in self._original

    # -- write operations (materialize on first write) ---------------------

    def __setitem__(self, index, value):
        """Set item at index, materializing on first write."""
        self._materialize()
        super().__setitem__(index, value)

    def __delitem__(self, index):
        """Delete item at index, materializing on first write."""
        self._materialize()
        super().__delitem__(index)

    def append(self, value):
        """Append value, materializing on first write."""
        self._materialize()
        super().append(value)

    def extend(self, values):
        """Extend with values, materializing on first write."""
        self._materialize()
        super().extend(values)

    def insert(self, index, value):
        """Insert value at index, materializing on first write."""
        self._materialize()
        super().insert(index, value)

    def remove(self, value):
        """Remove first occurrence of value, materializing on first write."""
        self._materialize()
        super().remove(value)

    def pop(self, index=-1):
        """Remove and return item at index, materializing on first write."""
        self._materialize()
        return super().pop(index)

    def clear(self):
        """Clear all items, materializing on first write."""
        self._materialize()
        super().clear()

    def sort(self, *, key=None, reverse=False):
        """Sort in place, materializing on first write."""
        self._materialize()
        super().sort(key=key, reverse=reverse)

    def reverse(self):
        """Reverse in place, materializing on first write."""
        self._materialize()
        super().reverse()

    # -- introspection -----------------------------------------------------

    def has_modifications(self) -> bool:
        """Return True if any write operation has been performed."""
        return self._materialized

    def copy(self) -> list:
        """Return a plain list snapshot of the current contents."""
        return list(self)

    def __repr__(self) -> str:
        """Return a string representation of the list."""
        return f"CopyOnWriteList({list(self)})"


def copyonwrite(o: T) -> T:
    """
    Returns a copy-on-write wrapper of the original object.

    Args:
        o: The object to wrap. Supports dict and list objects.

    Returns:
        A copy-on-write wrapper around the object.

    Raises:
        TypeError: If the object type is not supported for copy-on-write wrapping.
    """
    if isinstance(o, dict):
        return CopyOnWriteDict(o)
    if isinstance(o, list):
        return CopyOnWriteList(o)
    raise TypeError(f"No copy-on-write wrapper available for {type(o)}")


# ---------------------------------------------------------------------------
# Payload isolation helpers
# ---------------------------------------------------------------------------

_PRIMITIVE_TYPES = (str, int, float, bool, bytes, type(None))


_memory_logger = logging.getLogger(__name__)


def _safe_deepcopy(value: Any) -> Any:
    """Deep-copy *value*, falling back to a shared reference on failure.

    For objects that are not (e.g. objects holding locks, sockets, or async state),
    a warning is logged and the original value is returned as a shared reference.
    CoW isolation still applies to all other fields in the payload.
    """
    try:
        return copy.deepcopy(value)
    except Exception as e:
        _memory_logger.warning(
            "Cannot deep-copy value of type %s — sharing reference: %s",
            type(value).__qualname__,
            e,
        )
        return value


def _wrap_value(value: Any) -> Any:
    """Wrap a single value with the appropriate CoW wrapper.

    - dict → CopyOnWriteDict
    - list → CopyOnWriteList
    - RootModel → reconstruct with wrapped .root
    - BaseModel (non-RootModel) → recursively wrap
    - Primitives → share as-is
    - Other mutable types → copy.deepcopy fallback
    """
    # Weak-reference proxies must be checked first — isinstance() with
    # other types dereferences the proxy and raises ReferenceError if
    # the referent has been garbage-collected.
    if isinstance(value, (weakref.ProxyType, weakref.CallableProxyType)):
        return value
    if isinstance(value, _PRIMITIVE_TYPES):
        return value
    if isinstance(value, BaseException):
        return value
    if isinstance(value, RootModel):
        root = value.root
        if isinstance(root, dict):
            wrapped_root = CopyOnWriteDict(root)
        elif isinstance(root, list):
            wrapped_root = CopyOnWriteList(root)
        else:
            wrapped_root = _safe_deepcopy(root)
        return value.model_construct(root=wrapped_root)
    if isinstance(value, BaseModel):
        return wrap_payload_for_isolation(value)
    if isinstance(value, dict):
        return CopyOnWriteDict(value)
    if isinstance(value, list):
        return CopyOnWriteList(value)
    # Other mutable types — attempt deep copy, fall back to shared reference.
    return _safe_deepcopy(value)


def wrap_payload_for_isolation(payload: BaseModel) -> BaseModel:
    """Return a shallow copy of *payload* with mutable nested fields wrapped
    in copy-on-write containers.

    This replaces ``model_copy(deep=True)`` / ``copy.deepcopy()`` for Pydantic
    payload isolation.  Only fields that contain mutable containers (dicts,
    lists, BaseModels) are wrapped; primitives are shared as-is.

    Args:
        payload: A frozen Pydantic BaseModel (typically a PluginPayload).

    Returns:
        A new model instance with mutable fields CoW-wrapped.
    """
    # RootModel payloads (e.g. HttpHeaderPayload) — wrap .root directly
    if isinstance(payload, RootModel):
        root = payload.root
        if isinstance(root, dict):
            wrapped_root = CopyOnWriteDict(root)
        elif isinstance(root, list):
            wrapped_root = CopyOnWriteList(root)
        else:
            wrapped_root = _safe_deepcopy(root)
        return payload.model_construct(root=wrapped_root)

    updates = {}
    for field_name, field_info in type(payload).model_fields.items():
        value = getattr(payload, field_name, None)
        if value is None:
            continue
        # Weak-reference proxies are passed through as-is (checked before
        # _PRIMITIVE_TYPES to avoid dereferencing a dead proxy).
        if isinstance(value, (weakref.ProxyType, weakref.CallableProxyType)):
            continue
        if isinstance(value, _PRIMITIVE_TYPES):
            continue
        updates[field_name] = _wrap_value(value)

    if not updates:
        return payload

    return payload.model_copy(update=updates)
