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
from collections.abc import Mapping
from typing import Any, TypeVar

# Third-Party
from pydantic import BaseModel, RootModel

T = TypeVar("T")
logger = logging.getLogger(__name__)


class CopyOnWriteDict(dict):
    """
    A dictionary subclass that isolates modifications from an original dictionary.

    On construction the original's key/value pairs are copied into this dict's own
    (real) storage, so every inherited ``dict`` operation -- including ones this
    class does not override, such as ``json.dumps()``, ``copy.deepcopy()``,
    ``|``, ``popitem()`` and Pydantic serialization -- observes the correct
    contents. Writes mutate only this copy; the original is never touched. Keys
    that were written or deleted are tracked separately so callers can still ask
    what changed via :meth:`get_modifications`, :meth:`get_deleted` and
    :meth:`has_modifications`.

    The copy is *shallow*: nested containers are shared with the original, which
    is what keeps this cheap. The class exists to avoid ``copy.deepcopy()`` of
    payloads, not to avoid the shallow copy itself.

    Note:
        Because construction snapshots the original, later mutations of the
        original are *not* visible here. That is the intended isolation
        semantics; an earlier lazy implementation leaked them through.

    Performance:
        Constructing this is modestly more expensive than the lazy wrapper it
        replaces -- 0.43 us vs 0.20 us for a 100-key dict, since the snapshot
        plus two tracking containers are built up front rather than deferred.
        It remains ~45x cheaper than the ``copy.deepcopy()`` (19.9 us) it exists
        to avoid, so the trade buys correctness in inherited methods for a
        sub-microsecond cost per wrap.

    Example:
        >>> original = {"a": 1, "b": 2, "c": 3}
        >>> cow = CopyOnWriteDict(original)
        >>> isinstance(cow, dict)
        True
        >>> cow["a"] = 10  # Overwrite an existing key
        >>> cow["d"] = 4   # Add a new key
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
        # Copy the original's pairs into our own storage so that inherited dict
        # behaviour (serialization, copying, operators) sees real data. No
        # reference to `original` is retained: reads no longer delegate to it,
        # so holding it would only pin it in memory and invite the read-through
        # aliasing the lazy implementation suffered from.
        super().__init__(original)
        self._modified: dict = {}  # Written keys, as an insertion-ordered set
        self._deleted: set = set()  # Track keys that have been deleted

    def __setitem__(self, key: Any, value: Any) -> None:
        """
        Set an item in the dictionary.

        The original dict is not affected.

        Args:
            key: The key to set.
            value: The value to associate with the key.
        """
        super().__setitem__(key, value)
        self._modified[key] = None
        self._deleted.discard(key)  # If we're setting it, it's not deleted

    def __delitem__(self, key: Any) -> None:
        """
        Delete an item from the dictionary.

        The original dict is not affected.

        Args:
            key: The key to delete.

        Raises:
            KeyError: If the key doesn't exist in the dictionary.
        """
        super().__delitem__(key)  # Raises KeyError when absent
        self._deleted.add(key)
        self._modified.pop(key, None)

    def __repr__(self) -> str:
        """
        Get a string representation of the dictionary.

        Returns:
            A string representation showing the current state.
        """
        return f"CopyOnWriteDict({dict(self.items())})"

    __hash__ = None

    def __eq__(self, other: Any) -> bool:
        """
        Compare equality with another mapping.

        Retained after the switch to eager snapshotting -- inherited
        ``dict.__eq__`` would now be correct for plain dicts, but this widens
        the comparison to any ``Mapping`` (e.g. ``MappingProxyType``), which
        inherited behaviour rejects outright.

        Args:
            other: The object to compare with.

        Returns:
            True if other is a Mapping with the same key-value pairs, False otherwise.
            Returns NotImplemented for non-Mapping types to allow other.__eq__ to handle it.
        """
        if not isinstance(other, Mapping):
            return NotImplemented

        # Fast-path: if lengths differ, mappings cannot be equal
        if len(self) != len(other):
            return False

        return dict(self) == dict(other)

    def __ne__(self, other: Any) -> bool:
        """
        Compare inequality with another mapping.

        Args:
            other: The object to compare with.

        Returns:
            True if not equal, False if equal.
            Returns NotImplemented for non-Mapping types.
        """
        eq = self.__eq__(other)
        if eq is NotImplemented:
            return NotImplemented
        return not eq

    def copy(self) -> dict:
        """
        Create a regular dictionary with all current key-value pairs.

        Returns:
            A new dict containing the current state.
        """
        return dict(self)

    # -- copying -----------------------------------------------------------
    #
    # Explicit hooks are needed because the default reconstruction path replays
    # the pairs through __setitem__, which would flag an untouched copy as
    # modified. Pairs are written via dict.* to bypass the tracking overrides.

    def __copy__(self) -> "CopyOnWriteDict":
        """Return a shallow copy, preserving the modification tracking state."""
        new = type(self)(self)
        new._modified = dict(self._modified)
        new._deleted = set(self._deleted)
        return new

    def __deepcopy__(self, memo: dict) -> "CopyOnWriteDict":
        """Return a deep copy, preserving the modification tracking state."""
        new = type(self)({})
        memo[id(self)] = new
        for key, value in self.items():
            dict.__setitem__(new, copy.deepcopy(key, memo), copy.deepcopy(value, memo))
        new._modified = copy.deepcopy(self._modified, memo)
        new._deleted = copy.deepcopy(self._deleted, memo)
        return new

    def get_modifications(self) -> dict:
        """
        Get only the modifications made to the wrapper.

        This returns only the keys that were added or changed since construction,
        not including values from the original dictionary that weren't modified.
        Keys that were written and later deleted are excluded.

        Returns:
            A dict of the modified key-value pairs, in the order first written.
        """
        return {key: self[key] for key in self._modified if key in self}

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
        return bool(self._modified) or bool(self._deleted)

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

    def popitem(self) -> tuple:
        """
        Remove and return the most recently inserted key-value pair.

        Args:
            None.

        Returns:
            A (key, value) tuple.

        Raises:
            KeyError: If the dictionary is empty.

        Examples:
            >>> cow = CopyOnWriteDict({"a": 1, "b": 2})
            >>> cow.popitem()
            ('b', 2)
            >>> cow.get_deleted()
            {'b'}
        """
        key, value = super().popitem()  # Raises KeyError when empty
        self._deleted.add(key)
        self._modified.pop(key, None)
        return key, value

    def __ior__(self, other):
        """
        In-place merge (``|=``) that records the merged keys as modifications.

        Args:
            other: A mapping or iterable of key-value pairs to merge in.

        Returns:
            This dictionary, updated in place.

        Examples:
            >>> cow = CopyOnWriteDict({"a": 1})
            >>> cow |= {"b": 2}
            >>> cow.get_modifications()
            {'b': 2}
        """
        self.update(other)
        return self

    def clear(self) -> None:
        """
        Remove all items from the dictionary.

        This marks every key currently present as deleted. The original dict is
        not affected.

        Examples:
            >>> cow = CopyOnWriteDict({"a": 1, "b": 2})
            >>> cow.clear()
            >>> len(cow)
            0
        """
        # Mark all current keys as deleted
        self._deleted.update(self.keys())
        self._modified.clear()
        super().clear()


class CopyOnWriteList(list):
    """
    A list subclass that isolates modifications from an original list.

    On construction the original's items are copied into this list's own (real)
    storage, so every inherited ``list`` operation -- including ones this class
    does not override, such as ``+``, ``*``, ``<``, ``index()``, ``count()``,
    ``reversed()``, ``copy.deepcopy()`` and Pydantic serialization -- observes
    the correct contents. Writes mutate only this copy; the original is never
    touched, and :meth:`has_modifications` reports whether any write happened.

    The copy is *shallow*: nested items are shared with the original, which is
    what keeps this cheap. The class exists to avoid ``copy.deepcopy()`` of
    payloads, not to avoid the shallow copy itself.

    Note:
        Because construction snapshots the original, later mutations of the
        original are *not* visible here. That is the intended isolation
        semantics; an earlier lazy implementation leaked them through.

    Performance:
        Constructing this is modestly more expensive than the lazy wrapper it
        replaces -- 0.26 us vs 0.17 us for a 100-item list, since the snapshot
        is taken up front rather than deferred to the first write. It remains
        ~38x cheaper than the ``copy.deepcopy()`` (9.7 us) it exists to avoid,
        so the trade buys correctness in inherited methods for a sub-microsecond
        cost per wrap.

    Example:
        >>> original = [1, 2, 3]
        >>> cow = CopyOnWriteList(original)
        >>> isinstance(cow, list)
        True
        >>> cow[0]
        1
        >>> cow[0] = 10
        >>> cow[0]
        10
        >>> original  # unchanged
        [1, 2, 3]
    """

    def __init__(self, original: list):
        """Initialize with the original list to wrap."""
        # Copy the original's items into our own storage so that inherited list
        # behaviour (serialization, copying, operators) sees real data. No
        # reference to `original` is retained: reads no longer delegate to it,
        # so holding it would only pin it in memory and invite the read-through
        # aliasing the lazy implementation suffered from.
        super().__init__(original)
        self._modified = False

    # -- write operations (flag the write, then mutate our own copy) --------
    #
    # The flag is set before delegating, so an operation that raises (e.g.
    # remove() of an absent value) still counts as a write attempt. This
    # mirrors the behaviour of the materialize-first implementation this
    # replaced.

    def __setitem__(self, index, value):
        """Set item at index (or slice)."""
        self._modified = True
        super().__setitem__(index, value)

    def __delitem__(self, index):
        """Delete item at index (or slice)."""
        self._modified = True
        super().__delitem__(index)

    def __iadd__(self, values):
        """Extend in place (``+=``)."""
        self._modified = True
        return super().__iadd__(values)

    def __imul__(self, count):
        """Repeat in place (``*=``)."""
        self._modified = True
        return super().__imul__(count)

    def append(self, value):
        """Append value."""
        self._modified = True
        super().append(value)

    def extend(self, values):
        """Extend with values."""
        self._modified = True
        super().extend(values)

    def insert(self, index, value):
        """Insert value at index."""
        self._modified = True
        super().insert(index, value)

    def remove(self, value):
        """Remove first occurrence of value."""
        self._modified = True
        super().remove(value)

    def pop(self, index=-1):
        """Remove and return item at index."""
        self._modified = True
        return super().pop(index)

    def clear(self):
        """Clear all items."""
        self._modified = True
        super().clear()

    def sort(self, *, key=None, reverse=False):
        """Sort in place."""
        self._modified = True
        super().sort(key=key, reverse=reverse)

    def reverse(self):
        """Reverse in place."""
        self._modified = True
        super().reverse()

    # -- copying -----------------------------------------------------------
    #
    # Explicit hooks are needed because the default reconstruction path replays
    # the items through append/extend, which would flag an untouched copy as
    # modified. Items are written via list.* to bypass the tracking overrides.

    def __copy__(self) -> "CopyOnWriteList":
        """Return a shallow copy, preserving the modification flag."""
        new = type(self)(self)
        new._modified = self._modified
        return new

    def __deepcopy__(self, memo: dict) -> "CopyOnWriteList":
        """Return a deep copy, preserving the modification flag."""
        new = type(self)([])
        memo[id(self)] = new
        list.extend(new, (copy.deepcopy(item, memo) for item in self))
        new._modified = self._modified
        return new

    # -- introspection -----------------------------------------------------

    def has_modifications(self) -> bool:
        """Return True if any write operation has been performed."""
        return self._modified

    def copy(self) -> list:
        """Return a plain list snapshot of the current contents."""
        return list(self)

    def __repr__(self) -> str:
        """Return a string representation of the list."""
        return f"CopyOnWriteList({list(self)})"

    __hash__ = None

    def __eq__(self, other: Any) -> bool:
        """
        Compare equality with another list.

        Retained after the switch to eager snapshotting: inherited
        ``list.__eq__`` is now correct on its own, but keeping an explicit
        implementation pins the ``NotImplemented``-for-non-list contract that
        the regression tests for this class assert.

        Args:
            other: The object to compare with.

        Returns:
            True if other is a list with the same items in the same order,
            False otherwise. Returns NotImplemented for any non-list to let
            other.__eq__ handle the comparison.
        """
        if not isinstance(other, list):
            return NotImplemented

        # Fast-path: if lengths differ, sequences cannot be equal
        if len(self) != len(other):
            return False

        return list(self) == list(other)

    def __ne__(self, other: Any) -> bool:
        """
        Compare inequality with another sequence.

        Args:
            other: The object to compare with.

        Returns:
            True if not equal, False if equal.
            Returns NotImplemented for unsupported types.
        """
        eq = self.__eq__(other)
        if eq is NotImplemented:
            return NotImplemented
        return not eq


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
