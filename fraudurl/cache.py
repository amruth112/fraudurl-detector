"""Tiny append-only JSON-lines cache (one file per lookup type), keyed by domain.

No database: a JSONL file is loaded into a dict at start-up and new results are
appended. Entries older than ``ttl_days`` are ignored and refreshed.

Several processes may share one cache folder (e.g. parallel pipeline jobs): every append
takes a cross-process lock on a small side file, so lines from different processes never
interleave. A torn last line (crash mid-write) is skipped on load.
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time


class _FileLock:
    """Exclusive cross-process lock on ``path`` (msvcrt on Windows, fcntl elsewhere)."""

    def __init__(self, path: str):
        self._fh = open(path, "a+b")

    def __enter__(self):
        if sys.platform == "win32":
            import msvcrt
            while True:
                try:
                    self._fh.seek(0)
                    msvcrt.locking(self._fh.fileno(), msvcrt.LK_LOCK, 1)  # gives up after ~10 s -> retry
                    break
                except OSError:
                    continue
        else:
            import fcntl
            fcntl.flock(self._fh.fileno(), fcntl.LOCK_EX)
        return self

    def __exit__(self, *exc):
        if sys.platform == "win32":
            import msvcrt
            self._fh.seek(0)
            msvcrt.locking(self._fh.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
        return False

    def close(self):
        self._fh.close()


class JsonlCache:
    def __init__(self, path: str | None, ttl_days: float = 7.0):
        self.path, self.ttl = path, ttl_days * 86400
        self._d: dict[str, dict] = {}
        self._lock = threading.Lock()
        self._fh = None
        self._flock = None
        if path:
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
            if os.path.exists(path):
                with open(path, encoding="utf-8") as fh:
                    for line in fh:
                        try:
                            rec = json.loads(line)
                            self._d[rec["k"]] = rec
                        except (ValueError, KeyError):
                            continue  # tolerate a torn last line after a crash
            self._fh = open(path, "a", encoding="utf-8")

    def get(self, key: str):
        rec = self._d.get(key)
        if rec is None or (self.ttl and time.time() - rec.get("t", 0) > self.ttl):
            return None
        return rec["v"]

    def put(self, key: str, value) -> None:
        rec = {"k": key, "t": time.time(), "v": value}
        line = json.dumps(rec, separators=(",", ":"), default=str) + "\n"
        with self._lock:
            self._d[key] = rec
            if self._fh:
                if self._flock is None:  # created on first write: read-only runs leave the folder untouched
                    self._flock = _FileLock(self.path + ".lock")
                with self._flock:
                    self._fh.write(line)
                    self._fh.flush()

    def __len__(self):
        return len(self._d)

    def close(self):
        if self._fh:
            self._fh.close()
            self._fh = None
        if self._flock:
            self._flock.close()
            self._flock = None
