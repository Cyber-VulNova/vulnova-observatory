"""Ransomware.live (Pro API) source — links ransomware groups to the CVEs
they are known to exploit.

The Pro API is group-centric: there is no CVE-lookup endpoint. So we build a
``CVE -> [groups]`` index by walking every tracked group once
(``/groups`` then ``/group/{slug}``), reading each group's ``vulnerabilities``
list, and inverting it. The trimmed index is cached to
``~/.vulnova/ransomwarelive/cve_index.json`` and rebuilt on a slow cadence
(default 7 days) to stay well within the 3,000 calls/day budget.

At request time we only ever read the cached index (a dict lookup) — the
build never runs inside a web request. If the index is missing, a one-shot
background build is kicked off and an empty result is returned until it lands.

Requires the ``ransomwarelive`` API key (env ``RANSOMWARE_LIVE_API_KEY``).
Base URL: https://api-pro.ransomware.live  ·  Header: ``X-API-KEY``
"""

import json
import re
import threading
import time
from typing import Optional

import httpx

from vulnova.core.config import Config

BASE_URL = "https://api-pro.ransomware.live"
UA = {"User-Agent": "VulNova-Observatory/1.0 (+https://github.com/Cyber-VulNova)"}
PROFILE_URL = "https://www.ransomware.live/group/{slug}"

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# Guards a single in-process background build so concurrent requests don't
# each spawn their own 394-call walk.
_build_lock = threading.Lock()
_building = False


class RansomwareLiveClient:
    """Builds/reads the CVE -> ransomware-groups index from the Pro API."""

    REFRESH_SECONDS = 7 * 24 * 3600  # rebuild the index weekly
    HTTP_TIMEOUT = 20.0

    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self.dir = self.config.app_dir / "ransomwarelive"
        self.path = self.dir / "cve_index.json"

    # ─── public API ──────────────────────────────────────────────────────

    @property
    def api_key(self) -> Optional[str]:
        return self.config.get_api_key("ransomwarelive")

    def lookup_cve(self, cve_id: str) -> list[dict]:
        """Return the ransomware groups linked to ``cve_id`` (cached only).

        Never triggers a synchronous build. If no index exists yet and a key
        is configured, a background build is started and ``[]`` is returned.
        """
        if not cve_id:
            return []
        idx = self._load_local()
        if not idx:
            if self.api_key:
                self._ensure_background_build()
            return []
        return idx.get("cves", {}).get(cve_id.upper(), [])

    def get_index(self, force: bool = False) -> dict:
        """Return the full index, building/refreshing when stale. Blocking.

        Intended for the background refresh cycle, not for web requests.
        """
        local = self._load_local()
        fresh = local and (time.time() - local.get("updated", 0) < self.REFRESH_SECONDS)
        if local and fresh and not force:
            return local
        built = self._build()
        if built:
            self._save(built)
            return built
        return local or {"cves": {}, "group_count": 0, "cve_count": 0, "updated": 0}

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

        threading.Thread(target=_run, name="vulnova-ransomwarelive-build",
                          daemon=True).start()

    def _client(self) -> httpx.Client:
        headers = dict(UA)
        headers["Accept"] = "application/json"
        key = self.api_key
        if key:
            headers["X-API-KEY"] = key
        return httpx.Client(base_url=BASE_URL, headers=headers,
                            timeout=self.HTTP_TIMEOUT, follow_redirects=True)

    def _build(self) -> Optional[dict]:
        """Walk every group and invert vulnerabilities into CVE -> [groups]."""
        if not self.api_key:
            return None
        try:
            with self._client() as client:
                resp = client.get("/groups")
                resp.raise_for_status()
                groups = resp.json().get("groups", []) or []

                cves: dict[str, list[dict]] = {}
                seen: dict[str, set] = {}
                group_count = 0

                for g in groups:
                    slug = g.get("group") if isinstance(g, dict) else g
                    if not slug:
                        continue
                    try:
                        r = client.get(f"/group/{slug}")
                        if r.status_code != 200:
                            continue
                        detail = r.json()
                    except (httpx.HTTPError, ValueError):
                        continue
                    if isinstance(detail, list):
                        detail = detail[0] if detail else {}

                    vulns = detail.get("vulnerabilities") or []
                    if not vulns:
                        continue
                    group_count += 1
                    display = detail.get("group") or slug
                    # Some group records come back fully lowercased; title-case
                    # those for display while preserving intentional casing
                    # (e.g. "BrainCipher", "Cl0p").
                    if display and display == display.lower():
                        display = display.replace("-", " ").replace("_", " ").title()

                    for v in vulns:
                        if not isinstance(v, dict):
                            continue
                        raw = str(v.get("CVE") or v.get("cve") or "")
                        for cid in {m.upper() for m in _CVE_RE.findall(raw)}:
                            bucket = cves.setdefault(cid, [])
                            key = (cid, slug)
                            if key in seen.setdefault(cid, set()):
                                continue
                            seen[cid].add(slug)
                            bucket.append({
                                "name": display,
                                "slug": slug,
                                "url": PROFILE_URL.format(slug=slug),
                                "vendor": (v.get("Vendor") or v.get("vendor") or "").strip(),
                                "product": (v.get("Product") or v.get("product") or "").strip(),
                            })

                # Sort each CVE's groups alphabetically for stable display.
                for cid in cves:
                    cves[cid].sort(key=lambda x: x["name"].lower())

                return {
                    "cves": cves,
                    "group_count": group_count,
                    "cve_count": len(cves),
                    "updated": time.time(),
                }
        except (httpx.HTTPError, ValueError):
            return None

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
