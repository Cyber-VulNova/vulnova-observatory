"""MITRE ATT&CK (Enterprise) source — tactics + techniques matrix.

Downloads the MITRE ATT&CK Enterprise STIX bundle once, parses a trimmed
tactics/techniques index, and caches it to ~/.vulnova/attack/attack_index.json
(refreshed periodically). No API key required.

Data: https://github.com/mitre-attack/attack-stix-data
"""

import json
import time
from pathlib import Path
from typing import Optional

import httpx

from vulnova.core.config import Config

STIX_URL = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
            "master/enterprise-attack/enterprise-attack.json")
UA = {"User-Agent": "VulNova-Observatory/1.0 (+https://github.com/Cyber-VulNova)"}

# Canonical left-to-right kill-chain ordering by tactic shortname.
_TACTIC_ORDER = {
    "reconnaissance": 1, "resource-development": 2, "initial-access": 3,
    "execution": 4, "persistence": 5, "privilege-escalation": 6,
    "defense-evasion": 7, "stealth": 7, "defense-impairment": 8,
    "credential-access": 9, "discovery": 10, "lateral-movement": 11,
    "collection": 12, "command-and-control": 13, "exfiltration": 14, "impact": 15,
}


def _mitre_ref(obj: dict) -> dict:
    for e in obj.get("external_references", []) or []:
        if e.get("source_name") == "mitre-attack":
            return e
    return {}


class AttackClient:
    """Loads and caches the MITRE ATT&CK Enterprise matrix."""

    REFRESH_SECONDS = 30 * 24 * 3600  # 30 days

    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self.dir = self.config.app_dir / "attack"
        self.path = self.dir / "attack_index.json"

    def get_index(self, force: bool = False) -> dict:
        """Return {tactics, techniques, count, updated}. Builds/refreshes as needed."""
        local = self._load_local()
        if local and not force and (time.time() - local.get("updated", 0) < self.REFRESH_SECONDS):
            return local
        fresh = self._build()
        if fresh:
            self._save(fresh)
            return fresh
        return local or {"tactics": [], "techniques": [], "count": 0, "updated": 0}

    @property
    def last_updated(self) -> float:
        idx = self._load_local()
        return idx.get("updated", 0) if idx else 0

    # ─── internal ──────────────────────────────────────────────────────────

    def _load_local(self) -> Optional[dict]:
        if self.path.exists():
            try:
                return json.loads(self.path.read_text(encoding="utf-8"))
            except (ValueError, OSError):
                return None
        return None

    def _save(self, idx: dict) -> None:
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(idx), encoding="utf-8")
        except OSError:
            pass

    def _build(self) -> Optional[dict]:
        try:
            resp = httpx.get(STIX_URL, headers=UA, timeout=120.0, follow_redirects=True)
            resp.raise_for_status()
            objs = resp.json().get("objects", [])
        except (httpx.HTTPError, ValueError):
            return None

        tactics = []
        for o in objs:
            if o.get("type") != "x-mitre-tactic":
                continue
            sn = o.get("x_mitre_shortname", "")
            tactics.append({
                "id": _mitre_ref(o).get("external_id", ""),
                "shortname": sn,
                "name": o.get("name", ""),
                "order": _TACTIC_ORDER.get(sn, 50),
            })
        tactics.sort(key=lambda t: (t["order"], t["name"]))

        techniques = []
        for o in objs:
            if o.get("type") != "attack-pattern":
                continue
            if o.get("revoked") or o.get("x_mitre_deprecated"):
                continue
            ref = _mitre_ref(o)
            tid = ref.get("external_id", "")
            if not tid:
                continue
            phases = [p.get("phase_name") for p in o.get("kill_chain_phases", []) or []
                      if p.get("kill_chain_name") == "mitre-attack"]
            techniques.append({
                "id": tid,
                "name": o.get("name", ""),
                "tactics": phases,
                "platforms": o.get("x_mitre_platforms", []) or [],
                "is_sub": bool(o.get("x_mitre_is_subtechnique")),
                "url": ref.get("url", ""),
                "desc": (o.get("description") or "").split("\n")[0][:240],
            })
        techniques.sort(key=lambda t: t["id"])

        return {
            "tactics": tactics,
            "techniques": techniques,
            "count": len(techniques),
            "updated": time.time(),
        }
