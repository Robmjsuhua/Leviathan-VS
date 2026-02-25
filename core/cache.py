#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    LEVIATHAN VS - Result Cache v14.2.0

    Simple SQLite-backed cache for scan/dispatch results.
    Avoids repeated network calls and stores results for offline analysis.

    Usage:
        from core.cache import ResultCache

        cache = ResultCache()
        cache.put("scan", "https://api.example.com", {"status": 200, ...})
        result = cache.get("scan", "https://api.example.com")
        cache.list_recent(10)
        cache.clear(older_than_hours=24)
================================================================================
"""

import hashlib
import json
import os
import sqlite3
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

VERSION = "14.2.0"
CACHE_DIR = Path(__file__).parent / ".cache"
CACHE_DB = CACHE_DIR / "leviathan_cache.db"


class ResultCache:
    """SQLite-backed result cache with TTL support."""

    def __init__(self, db_path: Optional[Path] = None, default_ttl_hours: int = 24):
        self.db_path = db_path or CACHE_DB
        self.default_ttl = default_ttl_hours * 3600
        self._ensure_db()

    def _ensure_db(self):
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cache (
                    key TEXT PRIMARY KEY,
                    category TEXT NOT NULL,
                    target TEXT NOT NULL,
                    data TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    hit_count INTEGER DEFAULT 0
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_category ON cache(category)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_expires ON cache(expires_at)
            """)

    @staticmethod
    def _make_key(category: str, target: str) -> str:
        raw = f"{category}:{target}"
        return hashlib.sha256(raw.encode()).hexdigest()[:32]

    def put(self, category: str, target: str, data: Any,
            ttl_hours: Optional[int] = None) -> str:
        """Store a result. Returns the cache key."""
        key = self._make_key(category, target)
        now = time.time()
        ttl = (ttl_hours * 3600) if ttl_hours else self.default_ttl
        expires = now + ttl
        serialized = json.dumps(data, default=str, ensure_ascii=False)

        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO cache (key, category, target, data, created_at, expires_at, hit_count)
                VALUES (?, ?, ?, ?, ?, ?, 0)
            """, (key, category, target, serialized, now, expires))
        return key

    def get(self, category: str, target: str) -> Optional[Any]:
        """Retrieve a cached result (returns None if expired or missing)."""
        key = self._make_key(category, target)
        now = time.time()

        with sqlite3.connect(str(self.db_path)) as conn:
            row = conn.execute(
                "SELECT data, expires_at FROM cache WHERE key = ?", (key,)
            ).fetchone()

            if row is None:
                return None

            data_str, expires_at = row
            if now > expires_at:
                conn.execute("DELETE FROM cache WHERE key = ?", (key,))
                return None

            conn.execute(
                "UPDATE cache SET hit_count = hit_count + 1 WHERE key = ?", (key,)
            )
            return json.loads(data_str)

    def has(self, category: str, target: str) -> bool:
        """Check if a valid (non-expired) entry exists."""
        return self.get(category, target) is not None

    def list_recent(self, limit: int = 20, category: Optional[str] = None) -> List[Dict]:
        """List recent cache entries."""
        with sqlite3.connect(str(self.db_path)) as conn:
            if category:
                rows = conn.execute(
                    "SELECT key, category, target, created_at, hit_count FROM cache "
                    "WHERE category = ? ORDER BY created_at DESC LIMIT ?",
                    (category, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT key, category, target, created_at, hit_count FROM cache "
                    "ORDER BY created_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()

        return [
            {
                "key": r[0],
                "category": r[1],
                "target": r[2],
                "created": datetime.fromtimestamp(r[3]).isoformat(),
                "hits": r[4],
            }
            for r in rows
        ]

    def clear(self, older_than_hours: Optional[int] = None, category: Optional[str] = None):
        """Clear cache entries. If older_than_hours given, only clears expired + old entries."""
        with sqlite3.connect(str(self.db_path)) as conn:
            if older_than_hours is not None:
                cutoff = time.time() - (older_than_hours * 3600)
                if category:
                    conn.execute(
                        "DELETE FROM cache WHERE category = ? AND created_at < ?",
                        (category, cutoff),
                    )
                else:
                    conn.execute("DELETE FROM cache WHERE created_at < ?", (cutoff,))
            else:
                if category:
                    conn.execute("DELETE FROM cache WHERE category = ?", (category,))
                else:
                    conn.execute("DELETE FROM cache")

    def purge_expired(self) -> int:
        """Remove all expired entries. Returns count removed."""
        now = time.time()
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.execute(
                "DELETE FROM cache WHERE expires_at < ?", (now,)
            )
            return cursor.rowcount

    def stats(self) -> Dict[str, Any]:
        """Return cache statistics."""
        with sqlite3.connect(str(self.db_path)) as conn:
            total = conn.execute("SELECT COUNT(*) FROM cache").fetchone()[0]
            expired = conn.execute(
                "SELECT COUNT(*) FROM cache WHERE expires_at < ?", (time.time(),)
            ).fetchone()[0]
            cats = conn.execute(
                "SELECT category, COUNT(*) FROM cache GROUP BY category"
            ).fetchall()
            size = self.db_path.stat().st_size if self.db_path.exists() else 0

        return {
            "total_entries": total,
            "expired": expired,
            "active": total - expired,
            "categories": {c: n for c, n in cats},
            "db_size_kb": round(size / 1024, 1),
            "db_path": str(self.db_path),
        }


# ============================================================================
# CLI
# ============================================================================


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Leviathan Result Cache")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("stats", help="Show cache statistics")
    sub.add_parser("list", help="List recent entries")
    sub.add_parser("purge", help="Purge expired entries")
    sub.add_parser("clear", help="Clear all cache")

    args = parser.parse_args()
    cache = ResultCache()

    if args.command == "stats":
        s = cache.stats()
        print(json.dumps(s, indent=2))
    elif args.command == "list":
        entries = cache.list_recent(20)
        for e in entries:
            print(f"  [{e['category']}] {e['target'][:60]} (hits: {e['hits']})")
    elif args.command == "purge":
        n = cache.purge_expired()
        print(f"Purged {n} expired entries")
    elif args.command == "clear":
        cache.clear()
        print("Cache cleared")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
