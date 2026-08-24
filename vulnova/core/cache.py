"""SQLite-based TTL cache for VulNova.

Provides fast repeats and offline-friendly caching of all API responses.
"""

import hashlib
import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Optional


class Cache:
    """TTL-based SQLite cache for API responses."""

    def __init__(self, db_path: Path, default_ttl: int = 86400):
        """Initialize the cache.

        Args:
            db_path: Path to the SQLite database file.
            default_ttl: Default time-to-live in seconds (24h default).
        """
        self.db_path = db_path
        self.default_ttl = default_ttl
        self._conn: Optional[sqlite3.Connection] = None
        self._init_db()

    def _init_db(self) -> None:
        """Create the cache table if it doesn't exist."""
        conn = self._get_conn()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS cache (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                created_at REAL NOT NULL,
                ttl INTEGER NOT NULL,
                source TEXT DEFAULT ''
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_cache_source ON cache(source)
        """)
        conn.commit()

    def _get_conn(self) -> sqlite3.Connection:
        """Get or create a database connection."""
        if self._conn is None:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(self.db_path))
            self._conn.execute("PRAGMA journal_mode=WAL")
        return self._conn

    @staticmethod
    def _make_key(namespace: str, identifier: str) -> str:
        """Create a cache key from namespace and identifier."""
        raw = f"{namespace}:{identifier}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def get(self, namespace: str, identifier: str) -> Optional[Any]:
        """Retrieve a cached value if it exists and hasn't expired.

        Args:
            namespace: Category of the cached item (e.g., 'nvd', 'epss').
            identifier: Unique identifier within the namespace.

        Returns:
            The cached value (deserialized from JSON) or None if expired/missing.
        """
        key = self._make_key(namespace, identifier)
        conn = self._get_conn()
        cursor = conn.execute(
            "SELECT value, created_at, ttl FROM cache WHERE key = ?", (key,)
        )
        row = cursor.fetchone()
        if row is None:
            return None

        value, created_at, ttl = row
        if time.time() - created_at > ttl:
            # Expired - clean it up
            conn.execute("DELETE FROM cache WHERE key = ?", (key,))
            conn.commit()
            return None

        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return None

    def set(
        self,
        namespace: str,
        identifier: str,
        value: Any,
        ttl: Optional[int] = None,
    ) -> None:
        """Store a value in the cache.

        Args:
            namespace: Category of the cached item.
            identifier: Unique identifier within the namespace.
            value: The data to cache (must be JSON-serializable).
            ttl: Time-to-live in seconds (uses default if not specified).
        """
        key = self._make_key(namespace, identifier)
        ttl = ttl if ttl is not None else self.default_ttl
        conn = self._get_conn()
        conn.execute(
            """INSERT OR REPLACE INTO cache (key, value, created_at, ttl, source)
               VALUES (?, ?, ?, ?, ?)""",
            (key, json.dumps(value), time.time(), ttl, namespace),
        )
        conn.commit()

    def invalidate(self, namespace: str, identifier: str) -> None:
        """Remove a specific item from cache."""
        key = self._make_key(namespace, identifier)
        conn = self._get_conn()
        conn.execute("DELETE FROM cache WHERE key = ?", (key,))
        conn.commit()

    def clear_namespace(self, namespace: str) -> int:
        """Clear all cached items in a namespace. Returns count of removed items."""
        conn = self._get_conn()
        cursor = conn.execute("DELETE FROM cache WHERE source = ?", (namespace,))
        conn.commit()
        return cursor.rowcount

    def clear_all(self) -> int:
        """Clear entire cache. Returns count of removed items."""
        conn = self._get_conn()
        cursor = conn.execute("DELETE FROM cache")
        conn.commit()
        return cursor.rowcount

    def cleanup_expired(self) -> int:
        """Remove all expired entries. Returns count of removed items."""
        conn = self._get_conn()
        cursor = conn.execute(
            "DELETE FROM cache WHERE (? - created_at) > ttl", (time.time(),)
        )
        conn.commit()
        return cursor.rowcount

    def source_last_updated(self) -> dict:
        """Return {namespace: {"last_updated": epoch, "count": n}} for each source.

        Uses the most recent cache write per namespace as the "last refreshed"
        time for that data source.
        """
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT source, MAX(created_at), COUNT(*) FROM cache GROUP BY source"
        ).fetchall()
        return {
            r[0]: {"last_updated": r[1], "count": r[2]}
            for r in rows if r[0]
        }

    def stats(self) -> dict:
        """Return cache statistics."""
        conn = self._get_conn()
        total = conn.execute("SELECT COUNT(*) FROM cache").fetchone()[0]
        expired = conn.execute(
            "SELECT COUNT(*) FROM cache WHERE (? - created_at) > ttl", (time.time(),)
        ).fetchone()[0]
        sources = conn.execute(
            "SELECT source, COUNT(*) FROM cache GROUP BY source"
        ).fetchall()
        size_bytes = self.db_path.stat().st_size if self.db_path.exists() else 0

        return {
            "total_entries": total,
            "expired_entries": expired,
            "active_entries": total - expired,
            "sources": {s: c for s, c in sources},
            "size_bytes": size_bytes,
            "size_mb": round(size_bytes / (1024 * 1024), 2),
        }

    def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None
