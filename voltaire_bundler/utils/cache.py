"""
In-memory FIFO cache wrapper used by the bundler RPC layer.

Strict FIFO eviction: ``set`` of a new key past capacity drops the single
oldest entry. ``set`` of an existing key updates the value in place and
does NOT refresh insertion order — older entries don't get a second life
just because they were re-written.

The class exposes a small ``get/set/delete`` interface so the storage
layer can be swapped in later phases (on-disk SQLite tier) without
touching call sites.
"""
from collections import OrderedDict
from typing import Any


class InMemoryFIFOCache:
    def __init__(self, name: str, capacity: int = 10_000) -> None:
        self.name = name
        self.capacity = capacity
        self._data: OrderedDict[str, Any] = OrderedDict()

    def get(self, key: str) -> Any | None:
        # Pure FIFO: reads do not promote — order is fixed at insertion time.
        return self._data.get(key)

    def set(self, key: str, value: Any) -> None:
        # OrderedDict preserves the existing position on overwrite, which is
        # the strict-FIFO behavior we want. Only new keys grow the dict and
        # can trigger eviction.
        self._data[key] = value
        if len(self._data) > self.capacity:
            self._data.popitem(last=False)

    def delete(self, key: str) -> None:
        self._data.pop(key, None)

    def __contains__(self, key: str) -> bool:
        return key in self._data

    def __len__(self) -> int:
        return len(self._data)
