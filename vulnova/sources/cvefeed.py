"""CVEfeed.io client — enriches CVE detail with remediation + SSVC intel.

Uses the public ``GET /api/vulnerability/{cve_id}/`` endpoint (no token
required). When a CVEfeed API token is configured (CVEFEED_API_KEY via .env)
it is sent as a Bearer token, which raises the rate limit. Results are cached.

Docs: https://docs.cvefeed.io/api/
"""

from typing import Optional

import httpx

from vulnova.core.cache import Cache
from vulnova.core.config import Config

API_BASE = "https://cvefeed.io/api"
UA = {"User-Agent": "VulNova-Observatory/1.0 (+https://github.com/Cyber-VulNova)"}


class CVEFeedClient:
    """Fetches enriched CVE details from CVEfeed.io."""

    NAMESPACE = "cvefeed"
    CACHE_TTL = 12 * 3600  # 12 hours

    def __init__(self, config: Optional[Config] = None, cache: Optional[Cache] = None):
        self.config = config or Config()
        self.cache = cache

    def _headers(self) -> dict:
        headers = dict(UA)
        token = self.config.get_api_key("cvefeed")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def get_details(self, cve_id: str, force: bool = False) -> Optional[dict]:
        """Return normalized CVEfeed.io enrichment for a CVE, or None.

        Extracts the value-adds beyond NVD: a remediation solution, SSVC
        decision points, a remote-exploitability flag, and the CVEfeed link.
        """
        cve_id = (cve_id or "").strip().upper()
        if not cve_id:
            return None

        if self.cache and not force:
            cached = self.cache.get(self.NAMESPACE, cve_id)
            if cached is not None:
                return cached or None  # cached {} means "looked up, nothing"

        try:
            resp = httpx.get(
                f"{API_BASE}/vulnerability/{cve_id}/",
                headers=self._headers(), timeout=15.0, follow_redirects=True,
            )
            if resp.status_code != 200:
                self._cache_empty(cve_id)
                return None
            raw = resp.json()
        except (httpx.HTTPError, ValueError):
            return None

        data = self._normalize(raw)
        if self.cache:
            self.cache.set(self.NAMESPACE, cve_id, data, ttl=self.CACHE_TTL)
        return data or None

    def _cache_empty(self, cve_id: str) -> None:
        if self.cache:
            self.cache.set(self.NAMESPACE, cve_id, {}, ttl=self.CACHE_TTL)

    @staticmethod
    def _normalize(raw: dict) -> dict:
        if not isinstance(raw, dict):
            return {}

        # Remediation solution (overview + concrete actions).
        solution = {}
        sol = raw.get("solution") or {}
        if isinstance(sol, dict) and (sol.get("overview") or sol.get("actions")):
            solution = {
                "overview": (sol.get("overview") or "").strip(),
                "actions": [a for a in (sol.get("actions") or []) if a],
            }

        # SSVC decision points (CISA Stakeholder-Specific Vulnerability Categorization).
        ssvc = {}
        for m in (raw.get("metrics", {}) or {}).get("ssvcV203", []) or []:
            for opt in (m.get("ssvcData", {}) or {}).get("options", []) or []:
                if isinstance(opt, dict):
                    ssvc.update(opt)

        return {
            "cve_id": raw.get("id", ""),
            "title": (raw.get("title") or "").strip(),
            "cvefeed_url": raw.get("url", ""),
            "status": raw.get("status", ""),
            # CVSS from CVEfeed (often present when NVD is still "awaiting analysis").
            "cvss_score": raw.get("cvss_score") or 0.0,
            "severity": (raw.get("severity") or "").upper(),
            "cvss_version": raw.get("cvss_version", ""),
            "is_remote": bool(raw.get("is_remote")),
            "is_rejected": bool(raw.get("is_rejected")),
            "solution": solution,
            "ssvc": ssvc,
            "affected_product_count": len(raw.get("affected_products", []) or []),
        }
