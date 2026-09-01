"""EPSS (Exploit Prediction Scoring System) client.

Fetches exploit probability scores from FIRST.org API.
Reference: https://www.first.org/epss/api
"""

from dataclasses import dataclass
from typing import Optional

import httpx

from vulnova.core.cache import Cache


EPSS_API_BASE = "https://api.first.org/data/v1/epss"


@dataclass
class EPSSScore:
    """EPSS score for a CVE."""
    cve_id: str
    epss: float  # Probability 0.0-1.0
    percentile: float  # 0.0-1.0
    date: str = ""

    @property
    def epss_percent(self) -> float:
        """EPSS as a percentage (0-100)."""
        return round(self.epss * 100, 2)

    @property
    def percentile_percent(self) -> float:
        """Percentile as a percentage (0-100)."""
        return round(self.percentile * 100, 1)

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "epss": self.epss,
            "percentile": self.percentile,
            "date": self.date,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "EPSSScore":
        return cls(
            cve_id=data.get("cve_id", ""),
            epss=data.get("epss", 0.0),
            percentile=data.get("percentile", 0.0),
            date=data.get("date", ""),
        )


class EPSSClient:
    """Client for the FIRST.org EPSS API."""

    NAMESPACE = "epss"

    def __init__(self, cache: Optional[Cache] = None):
        self.cache = cache

    def get_score(self, cve_id: str) -> Optional[EPSSScore]:
        """Get EPSS score for a single CVE.

        Args:
            cve_id: CVE identifier (e.g., CVE-2023-44487).

        Returns:
            EPSSScore or None if not found.
        """
        cve_id = cve_id.upper()

        if self.cache:
            cached = self.cache.get(self.NAMESPACE, cve_id)
            if cached:
                return EPSSScore.from_dict(cached)

        try:
            resp = httpx.get(
                EPSS_API_BASE,
                params={"cve": cve_id},
                timeout=15.0,
            )
            resp.raise_for_status()
            data = resp.json()
        except (httpx.HTTPError, Exception):
            return None

        entries = data.get("data", [])
        if not entries:
            return None

        entry = entries[0]
        score = EPSSScore(
            cve_id=entry.get("cve", cve_id),
            epss=float(entry.get("epss", 0.0)),
            percentile=float(entry.get("percentile", 0.0)),
            date=entry.get("date", ""),
        )

        if self.cache:
            self.cache.set(self.NAMESPACE, cve_id, score.to_dict(), ttl=43200)  # 12h TTL

        return score

    def get_history(self, cve_id: str) -> list[dict]:
        """Fetch the EPSS time-series (recent history) for a CVE.

        Uses FIRST.org's scope=time-series, which returns up to ~30 days of
        daily EPSS scores. Useful for showing whether exploit probability is
        trending up or down.

        Returns:
            List of {"date", "epss", "percentile"} sorted oldest → newest.
        """
        cve_id = cve_id.upper()
        cache_key = f"hist:{cve_id}"

        if self.cache:
            cached = self.cache.get(self.NAMESPACE, cache_key)
            if cached is not None:
                return cached

        try:
            resp = httpx.get(
                EPSS_API_BASE,
                params={"cve": cve_id, "scope": "time-series"},
                timeout=15.0,
            )
            resp.raise_for_status()
            data = resp.json()
        except (httpx.HTTPError, Exception):
            return []

        entries = data.get("data", [])
        if not entries:
            return []

        series = entries[0].get("time-series", [])
        history = []
        for point in series:
            try:
                history.append({
                    "date": point.get("date", "")[:10],
                    "epss": float(point.get("epss", 0.0)),
                    "percentile": float(point.get("percentile", 0.0)),
                })
            except (ValueError, TypeError):
                continue

        # Include today's current score as the most recent point
        current = entries[0]
        try:
            history.append({
                "date": current.get("date", "")[:10],
                "epss": float(current.get("epss", 0.0)),
                "percentile": float(current.get("percentile", 0.0)),
            })
        except (ValueError, TypeError):
            pass

        # Sort oldest → newest, dedupe by date
        seen = {}
        for h in history:
            if h["date"]:
                seen[h["date"]] = h
        history = sorted(seen.values(), key=lambda x: x["date"])

        if self.cache:
            self.cache.set(self.NAMESPACE, cache_key, history, ttl=43200)  # 12h

        return history

    def get_top(self, limit: int = 100) -> list[EPSSScore]:
        """Return the CVEs with the highest EPSS probability, descending.

        Uses the FIRST.org API's ``order=!epss`` sort. Cached briefly since the
        global ranking only shifts on daily EPSS recomputation.
        """
        limit = max(1, min(int(limit), 200))
        cache_key = f"top:{limit}"
        if self.cache:
            cached = self.cache.get(self.NAMESPACE, cache_key)
            if cached is not None:
                return [EPSSScore.from_dict(x) for x in cached]

        try:
            resp = httpx.get(
                EPSS_API_BASE,
                params={"order": "!epss", "limit": limit},
                timeout=20.0,
            )
            resp.raise_for_status()
            data = resp.json()
        except (httpx.HTTPError, Exception):
            return []

        scores = []
        for entry in data.get("data", []):
            scores.append(EPSSScore(
                cve_id=entry.get("cve", ""),
                epss=float(entry.get("epss", 0.0)),
                percentile=float(entry.get("percentile", 0.0)),
                date=entry.get("date", ""),
            ))

        if self.cache and scores:
            self.cache.set(self.NAMESPACE, cache_key,
                           [s.to_dict() for s in scores], ttl=21600)  # 6h
        return scores

    def count_above(self, threshold: float) -> int:
        """Return how many CVEs have an EPSS probability above ``threshold``.

        The FIRST.org API reports the matching ``total`` even with limit=1, so
        this is a single cheap call per threshold.
        """
        cache_key = f"count-gt:{threshold}"
        if self.cache:
            cached = self.cache.get(self.NAMESPACE, cache_key)
            if cached is not None:
                return cached

        try:
            resp = httpx.get(
                EPSS_API_BASE,
                params={"epss-gt": threshold, "limit": 1},
                timeout=15.0,
            )
            resp.raise_for_status()
            total = int(resp.json().get("total", 0))
        except (httpx.HTTPError, Exception):
            return 0

        if self.cache:
            self.cache.set(self.NAMESPACE, cache_key, total, ttl=21600)  # 6h
        return total

    def get_scores_bulk(self, cve_ids: list[str]) -> dict[str, EPSSScore]:
        """Get EPSS scores for multiple CVEs in one request.

        Args:
            cve_ids: List of CVE identifiers.

        Returns:
            Dict mapping CVE ID -> EPSSScore.
        """
        if not cve_ids:
            return {}

        results: dict[str, EPSSScore] = {}
        uncached: list[str] = []

        # Check cache first
        for cve_id in cve_ids:
            cve_id = cve_id.upper()
            if self.cache:
                cached = self.cache.get(self.NAMESPACE, cve_id)
                if cached:
                    results[cve_id] = EPSSScore.from_dict(cached)
                    continue
            uncached.append(cve_id)

        if not uncached:
            return results

        # Fetch remaining in bulk (API supports comma-separated CVEs)
        # Process in chunks of 30 to avoid URL length limits
        for i in range(0, len(uncached), 30):
            chunk = uncached[i:i + 30]
            cve_param = ",".join(chunk)

            try:
                resp = httpx.get(
                    EPSS_API_BASE,
                    params={"cve": cve_param},
                    timeout=20.0,
                )
                resp.raise_for_status()
                data = resp.json()
            except (httpx.HTTPError, Exception):
                continue

            for entry in data.get("data", []):
                score = EPSSScore(
                    cve_id=entry.get("cve", ""),
                    epss=float(entry.get("epss", 0.0)),
                    percentile=float(entry.get("percentile", 0.0)),
                    date=entry.get("date", ""),
                )
                results[score.cve_id] = score
                if self.cache:
                    self.cache.set(self.NAMESPACE, score.cve_id, score.to_dict(), ttl=43200)

        return results
