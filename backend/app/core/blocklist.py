import json
import os

_PATH = "blocked_ips.json"

def _load():
    if os.path.exists(_PATH):
        try:
            with open(_PATH) as f:
                return set(json.load(f))
        except Exception:
            pass
    return set()

def _save(s):
    try:
        with open(_PATH, "w") as f:
            json.dump(list(s), f)
    except Exception as e:
        print(f"[blocklist] save failed: {e}")


class PersistentSet:
    """A set that auto-saves to disk on every add/remove."""

    def __init__(self, initial: set):
        self._data = initial

    def add(self, item):
        self._data.add(item)
        _save(self._data)

    def discard(self, item):
        self._data.discard(item)
        _save(self._data)

    def remove(self, item):
        self._data.remove(item)
        _save(self._data)

    def __contains__(self, item):
        return item in self._data

    def __iter__(self):
        return iter(self._data)

    def __len__(self):
        return len(self._data)

    def __repr__(self):
        return f"PersistentSet({self._data!r})"


blocked_ips = PersistentSet(_load())
