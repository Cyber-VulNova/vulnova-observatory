"""CAPEC → ATT&CK bridge for CVE weakness mapping.

There is no authoritative free CVE→ATT&CK mapping. The pragmatic bridge is
CWE → CAPEC → ATT&CK: a CVE's CWE weaknesses point to CAPEC attack patterns,
and MITRE's CAPEC catalog carries a taxonomy mapping to ATT&CK techniques.

MITRE only records the ATT&CK mapping on the more abstract CAPEC entries, while
CWEs reference the detailed ones — so we also inherit each CAPEC's mapping from
its ancestors (``x_capec_child_of_refs``) to lift coverage. This is a heuristic
bridge, not a precise attribution, so we keep provenance (which CAPEC produced
each technique) and flag whether the mapping was direct or inherited.

The CAPEC STIX bundle (~4.5 MB) is downloaded once, inverted into a trimmed
``CWE -> [techniques]`` index, and cached to
``~/.vulnova/capec/capec_index.json`` (refreshed ~30 days). No API key needed.

Data: https://github.com/mitre/cti (capec/2.1/stix-capec.json)
"""

import json
import threading
import time
from typing import Optional

import httpx

from vulnova.core.config import Config

CAPEC_STIX_URL = ("https://raw.githubusercontent.com/mitre/cti/master/"
                  "capec/2.1/stix-capec.json")
UA = {"User-Agent": "VulNova-Observatory/1.0 (+https://github.com/Cyber-VulNova)",
      "Accept": "application/json"}

# Guards a single in-process background build.
_build_lock = threading.Lock()
_building = False


class CapecClient:
    """Builds/reads the CWE -> ATT&CK-technique bridge from CAPEC data."""

    REFRESH_SECONDS = 30 * 24 * 3600  # 30 days

    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self.dir = self.config.app_dir / "capec"
        self.path = self.dir / "capec_index.json"

    # ─── public API ──────────────────────────────────────────────────────

    def get_index(self, force: bool = False) -> dict:
        """Return the trimmed index, building/refreshing when stale (blocking)."""
        local = self._load_local()
        fresh = local and (time.time() - local.get("updated", 0) < self.REFRESH_SECONDS)
        if local and fresh and not force:
            return local
        built = self._build()
        if built:
            self._save(built)
            return built
        return local or {"cwe_to_techniques": {}, "capec_names": {},
                         "cwe_count": 0, "updated": 0}

    def techniques_for_cwes(self, cwe_ids: list[str]) -> list[dict]:
        """Aggregate ATT&CK techniques for a set of CWE ids.

        Returns a de-duplicated list of
        ``{"id", "direct", "capecs": [{"id", "name"}]}`` sorted with direct
        (non-inherited) mappings first. Reads the cached index only.
        """
        if not cwe_ids:
            return []
        idx = self._load_local()
        if not idx:
            self._ensure_background_build()
            return []
        cwe_map = idx.get("cwe_to_techniques", {})
        capec_names = idx.get("capec_names", {})

        merged: dict[str, dict] = {}
        for raw in cwe_ids:
            cwe = (raw or "").strip().upper()
            for entry in cwe_map.get(cwe, []):
                tid = entry.get("id")
                if not tid:
                    continue
                slot = merged.setdefault(tid, {"id": tid, "direct": False, "_capecs": set()})
                if entry.get("direct"):
                    slot["direct"] = True
                for cap in entry.get("capecs", []):
                    slot["_capecs"].add(cap)

        out = []
        for tid, slot in merged.items():
            caps = [{"id": c, "name": capec_names.get(c, "")} for c in sorted(slot["_capecs"])]
            out.append({"id": tid, "direct": slot["direct"], "capecs": caps})
        # Direct mappings first, then by technique id for stable ordering.
        out.sort(key=lambda x: (not x["direct"], x["id"]))
        return out

    @property
    def last_updated(self) -> float:
        idx = self._load_local()
        return idx.get("updated", 0) if idx else 0

    # ─── internal ────────────────────────────────────────────────────────

    def _ensure_background_build(self) -> None:
        global _building
        with _build_lock:
            if _building:
                return
            _building = True

        def _run():
            global _building
            try:
                self.get_index(force=True)
            except Exception:
                pass
            finally:
                with _build_lock:
                    _building = False

        threading.Thread(target=_run, name="vulnova-capec-build",
                         daemon=True).start()

    def _build(self) -> Optional[dict]:
        objs = None
        for attempt in range(4):
            try:
                resp = httpx.get(CAPEC_STIX_URL, headers=UA, timeout=120.0,
                                 follow_redirects=True)
                resp.raise_for_status()
                objs = resp.json().get("objects", [])
                break
            except (httpx.HTTPError, ValueError):
                time.sleep(2 + attempt * 2)  # GitHub raw occasionally resets TLS
        if not objs:
            return None

        # First pass: index every CAPEC attack-pattern.
        stix_to_capec: dict[str, str] = {}
        nodes: dict[str, dict] = {}  # capec_id -> {name, techs, parents, cwes}
        for o in objs:
            if o.get("type") != "attack-pattern":
                continue
            refs = o.get("external_references", []) or []
            cid = next((e.get("external_id") for e in refs
                        if e.get("source_name") == "capec"), None)
            if not cid:
                continue
            cid = cid.upper()
            stix_to_capec[o["id"]] = cid
            techs = {e.get("external_id") for e in refs
                     if (e.get("source_name") or "").upper() == "ATTACK" and e.get("external_id")}
            cwes = {(e.get("external_id") or "").upper() for e in refs
                    if e.get("source_name") == "cwe"}
            nodes[cid] = {
                "name": o.get("name", ""),
                "techs": techs,
                "parents": o.get("x_capec_child_of_refs", []) or [],
                "cwes": {c for c in cwes if c.startswith("CWE-")},
            }

        # Resolve each CAPEC's techniques including ancestor inheritance.
        memo: dict[str, set] = {}

        def resolve(cid: str, seen: Optional[set] = None) -> set:
            if cid in memo:
                return memo[cid]
            seen = seen or set()
            if cid in seen:
                return set()
            seen.add(cid)
            node = nodes.get(cid)
            if not node:
                return set()
            acc = set(node["techs"])
            for pref in node["parents"]:
                pcid = stix_to_capec.get(pref)
                if pcid:
                    acc |= resolve(pcid, seen)
            memo[cid] = acc
            return acc

        # Invert into CWE -> [technique entries with provenance].
        capec_names: dict[str, str] = {}
        cwe_to_techniques: dict[str, list] = {}
        for cid, node in nodes.items():
            if not node["cwes"]:
                continue
            direct = node["techs"]
            allt = resolve(cid)
            if not allt:
                continue
            capec_names[cid] = node["name"]
            for cwe in node["cwes"]:
                bucket = cwe_to_techniques.setdefault(cwe, [])
                for tid in allt:
                    bucket.append({
                        "id": tid,
                        "direct": tid in direct,
                        "capecs": [cid],
                    })

        return {
            "cwe_to_techniques": cwe_to_techniques,
            "capec_names": capec_names,
            "cwe_count": len(cwe_to_techniques),
            "updated": time.time(),
        }

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
