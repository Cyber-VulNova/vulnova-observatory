"""Metasploit module lookup.

Resolves Metasploit Framework modules for a CVE using Rapid7's shipped module
metadata (`db/modules_metadata_base.json`). To avoid keeping the large (~20 MB)
source file around, VulNova downloads it, extracts only the CVE-relevant fields,
and persists a compact CVE→module index to a small local JSON file. That index
is auto-refreshed on a daily interval and served locally in between, so lookups
are fast and work offline once built.
"""

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import httpx

from vulnova.core.cache import Cache


METADATA_URL = (
    "https://raw.githubusercontent.com/rapid7/metasploit-framework/"
    "master/db/modules_metadata_base.json"
)
MODULE_BLOB_BASE = (
    "https://github.com/rapid7/metasploit-framework/blob/master/modules"
)

# Metasploit numeric rank → label
_RANK_MAP = {
    0: "Manual", 100: "Low", 200: "Average", 300: "Normal",
    400: "Good", 500: "Great", 600: "Excellent",
}


@dataclass
class MetasploitModule:
    """A Metasploit Framework module."""
    name: str
    full_path: str
    type: str  # exploit, auxiliary, post, etc.
    url: str
    cve_ids: list[str]
    platform: str = ""
    rank: str = ""
    description: str = ""

    def to_dict(self) -> dict:
        # Compact on-disk form — only the fields the UI needs.
        return {
            "name": self.name,
            "full_path": self.full_path,
            "type": self.type,
            "url": self.url,
            "platform": self.platform,
            "rank": self.rank,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "MetasploitModule":
        return cls(
            name=data.get("name", ""),
            full_path=data.get("full_path", ""),
            type=data.get("type", ""),
            url=data.get("url", ""),
            platform=data.get("platform", ""),
            rank=data.get("rank", ""),
            cve_ids=data.get("cve_ids", []),
            description=data.get("description", ""),
        )

    @property
    def use_command(self) -> str:
        """Return the msfconsole use command for this module."""
        return f"use {self.full_path}"

    @property
    def msfconsole_commands(self) -> str:
        return (
            f"msfconsole\n"
            f"use {self.full_path}\n"
            f"show options\n"
            f"set RHOSTS <target>\n"
            f"run"
        )


class MetasploitClient:
    """Metasploit module lookup backed by a small, auto-refreshed local index."""

    NAMESPACE = "metasploit"

    def __init__(self, config=None, cache: Optional[Cache] = None):
        self.config = config
        self.cache = cache
        self._index: Optional[dict[str, list[MetasploitModule]]] = None

    # ─── Local index file helpers ─────────────────────────────────────

    @property
    def index_path(self) -> Optional[Path]:
        return self.config.metasploit_index_path if self.config else None

    @property
    def refresh_seconds(self) -> int:
        hours = self.config.metasploit_refresh_hours if self.config else 24
        return hours * 3600

    @property
    def is_available(self) -> bool:
        """True if a local index file exists."""
        p = self.index_path
        return bool(p and p.exists())

    @property
    def last_updated(self) -> float:
        """Epoch time the local index was last built (0 if never)."""
        data = self._read_local()
        return data.get("built_at", 0.0) if data else 0.0

    @property
    def module_count(self) -> int:
        """Number of CVEs with at least one Metasploit module."""
        return len(self._build_index())

    def _read_local(self) -> Optional[dict]:
        p = self.index_path
        if not p or not p.exists():
            return None
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return None

    def _write_local(self, cve_map: dict) -> None:
        p = self.index_path
        if not p:
            return
        try:
            p.write_text(
                json.dumps({"built_at": time.time(), "cves": cve_map}),
                encoding="utf-8",
            )
        except OSError:
            pass

    # ─── Index build / refresh ────────────────────────────────────────

    def _download_and_trim(self) -> Optional[dict]:
        """Download the full metadata and extract a compact CVE→module map.

        Returns a dict {CVE: [compact module dict, ...]} or None on failure.
        """
        try:
            resp = httpx.get(METADATA_URL, timeout=90.0, follow_redirects=True)
            resp.raise_for_status()
            metadata = resp.json()
        except (httpx.HTTPError, Exception):
            return None

        cve_map: dict[str, list[dict]] = {}
        for fullname, mod in metadata.items():
            cve_ids = []
            for ref in mod.get("references", []):
                if isinstance(ref, (list, tuple)) and len(ref) == 2 and ref[0] == "CVE":
                    cve_ids.append(f"CVE-{ref[1]}")
                elif isinstance(ref, str) and ref.upper().startswith("CVE-"):
                    cve_ids.append(ref.upper())
            if not cve_ids:
                continue

            fp = mod.get("fullname", fullname)
            compact = {
                "name": mod.get("name", fp.split("/")[-1]),
                "full_path": fp,
                "type": mod.get("type", fp.split("/")[0] if "/" in fp else ""),
                "url": f"{MODULE_BLOB_BASE}/{fp}.rb",
                "platform": _normalize_platform(mod.get("platform", "")),
                "rank": _RANK_MAP.get(mod.get("rank", 0), str(mod.get("rank", 0))),
            }
            for cve in cve_ids:
                cve_map.setdefault(cve, []).append(compact)

        return cve_map

    def refresh(self, force: bool = False) -> bool:
        """Refresh the local index if stale (or forced). Returns True if refreshed."""
        local = self._read_local()
        fresh = local and (time.time() - local.get("built_at", 0)) < self.refresh_seconds
        if fresh and not force:
            return False

        cve_map = self._download_and_trim()
        if cve_map is None:
            return False  # keep whatever stale copy we have
        self._write_local(cve_map)
        self._index = {
            cve: [MetasploitModule.from_dict(m) for m in mods]
            for cve, mods in cve_map.items()
        }
        return True

    def _build_index(self) -> dict[str, list[MetasploitModule]]:
        """Load the index, refreshing from source when missing or stale."""
        if self._index is not None:
            return self._index

        local = self._read_local()
        age = (time.time() - local.get("built_at", 0)) if local else None

        if local is not None and age is not None and age < self.refresh_seconds:
            # Fresh local copy — use it
            self._index = {
                cve: [MetasploitModule.from_dict(m) for m in mods]
                for cve, mods in local.get("cves", {}).items()
            }
            return self._index

        # Missing or stale → download & trim
        cve_map = self._download_and_trim()
        if cve_map is not None:
            self._write_local(cve_map)
            self._index = {
                cve: [MetasploitModule.from_dict(m) for m in mods]
                for cve, mods in cve_map.items()
            }
        elif local is not None:
            # Download failed — fall back to stale local copy
            self._index = {
                cve: [MetasploitModule.from_dict(m) for m in mods]
                for cve, mods in local.get("cves", {}).items()
            }
        else:
            self._index = {}
        return self._index

    # ─── Lookup ───────────────────────────────────────────────────────

    def search(self, cve_id: str) -> list[MetasploitModule]:
        """Return Metasploit modules that reference the given CVE."""
        index = self._build_index()
        return index.get(cve_id.upper(), [])

    def has_module(self, cve_id: str) -> bool:
        """Quick check if a Metasploit module exists for a CVE."""
        return len(self.search(cve_id)) > 0


def _normalize_platform(platform) -> str:
    """Metadata platform can be a string or list; return a short label."""
    if isinstance(platform, list):
        return ", ".join(platform[:3])
    return str(platform or "")
