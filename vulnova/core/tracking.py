"""Persistent CVE tracking store for VulNova (the Orbit watchlist).

Unlike the TTL response cache, tracked CVEs are user data that must never
expire. They live in their own SQLite database at ``~/.vulnova/tracking.db``.

Each tracked item records the CVE, how many assets are affected, a start and
due date for remediation, free-form notes, and a status. A fresh connection is
opened per operation so the store is safe to use from Flask's request threads.
"""

import sqlite3
import time
from pathlib import Path
from typing import Optional

from vulnova.core.config import Config

VALID_STATUS = {"open", "in_progress", "resolved"}


class TrackingStore:
    """CRUD store for tracked CVEs, backed by a dedicated SQLite file."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or (Config().app_dir / "tracking.db")
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        conn = self._conn()
        try:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS tracked_cves (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve_id TEXT NOT NULL,
                    assets_affected INTEGER NOT NULL DEFAULT 0,
                    start_date TEXT NOT NULL DEFAULT '',
                    due_date TEXT NOT NULL DEFAULT '',
                    notes TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'open',
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                )
                """
            )
            conn.commit()
        finally:
            conn.close()

    @staticmethod
    def _clean_status(value: str) -> str:
        v = (value or "").strip().lower()
        return v if v in VALID_STATUS else "open"

    @staticmethod
    def _clean_assets(value) -> int:
        try:
            n = int(value)
        except (TypeError, ValueError):
            return 0
        return max(0, n)

    def list_all(self) -> list[dict]:
        """Return all tracked items, newest first."""
        conn = self._conn()
        try:
            rows = conn.execute(
                "SELECT * FROM tracked_cves ORDER BY updated_at DESC"
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def get(self, item_id: int) -> Optional[dict]:
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT * FROM tracked_cves WHERE id = ?", (item_id,)
            ).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def add(self, data: dict) -> dict:
        """Insert a new tracked CVE and return the stored row."""
        cve_id = (data.get("cve_id") or "").strip().upper()
        if not cve_id:
            raise ValueError("cve_id is required")

        now = time.time()
        conn = self._conn()
        try:
            cur = conn.execute(
                """
                INSERT INTO tracked_cves
                    (cve_id, assets_affected, start_date, due_date, notes,
                     status, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    cve_id,
                    self._clean_assets(data.get("assets_affected")),
                    (data.get("start_date") or "").strip(),
                    (data.get("due_date") or "").strip(),
                    (data.get("notes") or "").strip(),
                    self._clean_status(data.get("status", "open")),
                    now,
                    now,
                ),
            )
            conn.commit()
            new_id = cur.lastrowid
        finally:
            conn.close()
        return self.get(new_id)

    def update(self, item_id: int, data: dict) -> Optional[dict]:
        """Update editable fields of a tracked CVE; return the updated row."""
        existing = self.get(item_id)
        if not existing:
            return None

        fields, values = [], []
        if "cve_id" in data:
            cve = (data.get("cve_id") or "").strip().upper()
            if cve:
                fields.append("cve_id = ?")
                values.append(cve)
        if "assets_affected" in data:
            fields.append("assets_affected = ?")
            values.append(self._clean_assets(data.get("assets_affected")))
        if "start_date" in data:
            fields.append("start_date = ?")
            values.append((data.get("start_date") or "").strip())
        if "due_date" in data:
            fields.append("due_date = ?")
            values.append((data.get("due_date") or "").strip())
        if "notes" in data:
            fields.append("notes = ?")
            values.append((data.get("notes") or "").strip())
        if "status" in data:
            fields.append("status = ?")
            values.append(self._clean_status(data.get("status")))

        if not fields:
            return existing

        fields.append("updated_at = ?")
        values.append(time.time())
        values.append(item_id)

        conn = self._conn()
        try:
            conn.execute(
                f"UPDATE tracked_cves SET {', '.join(fields)} WHERE id = ?",
                values,
            )
            conn.commit()
        finally:
            conn.close()
        return self.get(item_id)

    def delete(self, item_id: int) -> bool:
        """Delete a tracked CVE. Returns True if a row was removed."""
        conn = self._conn()
        try:
            cur = conn.execute("DELETE FROM tracked_cves WHERE id = ?", (item_id,))
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()
