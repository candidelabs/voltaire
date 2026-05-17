"""
In-memory cache wrapper used by the bundler RPC layer.

Phase 1 of the caching refactor: this class wraps the previous module-level
``dict`` caches behind a small ``get/set/delete`` interface so subsequent
phases can swap the storage layer (per-entry FIFO eviction, on-disk
persistence) without changing call sites.

Eviction matches the legacy behavior exactly: when the underlying dict
grows past ``capacity`` entries on insert, the whole dict is replaced with
an empty one. Per-entry FIFO eviction lands in phase 2.
"""
from typing import Any


class InMemoryFIFOCache:
    def __init__(self, name: str, capacity: int = 10_000) -> None:
        self.name = name
        self.capacity = capacity
        self._data: dict[str, Any] = {}

    def get(self, key: str) -> Any | None:
        return self._data.get(key)

    def set(self, key: str, value: Any) -> None:
        # Preserve the legacy "drop everything when full" policy until phase 2
        # swaps it for OrderedDict.popitem(last=False).
        if len(self._data) > self.capacity:
            self._data = {}
        self._data[key] = value

    def delete(self, key: str) -> None:
        self._data.pop(key, None)

    def __contains__(self, key: str) -> bool:
        return key in self._data

    def __len__(self) -> int:
        return len(self._data)
