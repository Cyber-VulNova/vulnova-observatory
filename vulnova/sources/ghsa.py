"""GitHub Advisory Database (GHSA) client — the anchor source for Flare.

Fetches security advisories from GitHub's global Advisory Database. Many GHSA
entries have **no CVE assigned** (especially for npm/PyPI/Go/Rust packages and
smaller projects), which is exactly the gap Flare fills — vendor/ecosystem
advisories that aren't (yet) in the CVE/NVD system.

Reference: https://docs.github.com/en/rest/security-advisories/global-advisories
"""

from dataclasses import dataclass, field
from typing import Optional

import httpx

from vulnova.core.cache import Cache
from vulnova.core.config import Config


GHSA_API = "https://api.github.com/advisories"


@dataclass
class Advisory:
    """A normalized security advisory (source-agnostic)."""
    advisory_id: str       # GHSA-…, USN-…, RHSA-…
    cve_id: str            # "" when no CVE assigned
    summary: str
    severity: str          # critical | high | medium | low | unknown
    cvss_score: float
    published: str         # ISO date (YYYY-MM-DD)
    updated: str
    url: str
    source: str            # "GitHub Advisory Database"
    ecosystems: list = field(default_factory=list)
    packages: list = field(default_factory=list)   # ["npm/lodash", ...]
    cwes: list = field(default_factory=list)
    epss_percent: float = 0.0
    references: list = field(default_factory=list)
    type: str = "reviewed"

    @property
    def has_cve(self) -> bool:
        return bool(self.cve_id)

    def to_dict(self) -> dict:
        return {
            "advisory_id": self.advisory_id,
            "cve_id": self.cve_id,
            "summary": self.summary,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "published": self.published,
            "updated": self.updated,
            "url": self.url,
            "source": self.source,
            "ecosystems": self.ecosystems,
            "packages": self.packages,
            "cwes": self.cwes,
            "epss_percent": self.epss_percent,
            "references": self.references,
            "type": self.type,
            "has_cve": self.has_cve,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Advisory":
        known = {
            "advisory_id", "cve_id", "summary", "severity", "cvss_score",
            "published", "updated", "url", "source", "ecosystems",
            "packages", "cwes", "epss_percent", "references", "type",
        }
        return cls(**{k: v for k, v in d.items() if k in known})


class GHSAClient:
    """Client for the GitHub Advisory Database."""

    NAMESPACE = "ghsa"
    CACHE_TTL = 3600  # 1 hour

    def __init__(self, config: Optional[Config] = None, cache: Optional[Cache] = None):
        self.config = config or Config()
        self.cache = cache
        self._token = self.config.get_api_key("github")

    def _headers(self) -> dict:
        h = {"Accept": "application/vnd.github+json", "User-Agent": "VulNova/1.0"}
        if self._token:
            h["Authorization"] = f"Bearer {self._token}"
        return h

    def _parse(self, a: dict) -> Advisory:
        vulns = a.get("vulnerabilities") or []
        ecosystems, packages = [], []
        for v in vulns:
            pkg = (v or {}).get("package") or {}
            eco = pkg.get("ecosystem", "")
            name = pkg.get("name", "")
            if eco and eco not in ecosystems:
                ecosystems.append(eco)
            if name:
                label = f"{eco}/{name}" if eco else name
                if label not in packages:
                    packages.append(label)

        cvss = a.get("cvss") or {}
        cwes = [c.get("cwe_id", "") for c in (a.get("cwes") or []) if c.get("cwe_id")]
        epss = a.get("epss") or {}
        try:
            epss_pct = round(float(epss.get("percentage", 0) or 0) * 100, 2) if epss.get("percentage") else round(float(epss.get("percentile", 0) or 0), 2)
        except (TypeError, ValueError):
            epss_pct = 0.0

        return Advisory(
            advisory_id=a.get("ghsa_id", ""),
            cve_id=(a.get("cve_id") or ""),
            summary=(a.get("summary") or "")[:300],
            severity=(a.get("severity") or "unknown").lower(),
            cvss_score=float((cvss.get("score") or 0) or 0),
            published=(a.get("published_at") or "")[:10],
            updated=(a.get("updated_at") or "")[:10],
            url=a.get("html_url", ""),
            source="GitHub Advisory Database",
            ecosystems=ecosystems,
            packages=packages[:6],
            cwes=cwes[:5],
            epss_percent=epss_pct,
            references=[r.get("url", "") for r in (a.get("references") or []) if isinstance(r, dict)][:6],
            type=a.get("type", "reviewed"),
        )

    def fetch(
        self,
        severity: str = "",
        ecosystem: str = "",
        adv_type: str = "reviewed",
        limit: int = 200,
        force: bool = False,
    ) -> list[Advisory]:
        """Fetch recent advisories (newest first), following cursor pages.

        Args:
            severity: optional GHSA severity filter (low/medium/high/critical).
            ecosystem: optional ecosystem filter (npm, pip, go, rust, ...).
            adv_type: reviewed | unreviewed | malware.
            limit: max advisories to gather.
            force: bypass cache.

        Returns:
            List of Advisory, newest published first.
        """
        cache_key = f"list:{severity}:{ecosystem}:{adv_type}:{limit}"
        if self.cache and not force:
            cached = self.cache.get(self.NAMESPACE, cache_key)
            if cached is not None:
                return [Advisory.from_dict(x) for x in cached]

        params = {
            "sort": "published",
            "direction": "desc",
            "per_page": 100,
            "type": adv_type or "reviewed",
        }
        if severity:
            params["severity"] = severity
        if ecosystem:
            params["ecosystem"] = ecosystem

        advisories: list[Advisory] = []
        url = GHSA_API
        pages = 0
        try:
            while url and len(advisories) < limit and pages < 5:
                resp = httpx.get(url, params=params if pages == 0 else None,
                                 headers=self._headers(), timeout=25.0)
                if resp.status_code != 200:
                    break
                for a in resp.json():
                    advisories.append(self._parse(a))
                pages += 1
                # Cursor pagination via Link header (rel="next")
                url = _next_link(resp.headers.get("link", ""))
        except (httpx.HTTPError, Exception):
            pass

        advisories = advisories[:limit]
        if self.cache and advisories:
            self.cache.set(self.NAMESPACE, cache_key,
                           [a.to_dict() for a in advisories], ttl=self.CACHE_TTL)
        return advisories


def _next_link(link_header: str) -> str:
    """Extract the rel="next" URL from a GitHub Link header, if present."""
    if not link_header:
        return ""
    for part in link_header.split(","):
        segs = part.split(";")
        if len(segs) < 2:
            continue
        url_part = segs[0].strip().strip("<>")
        if 'rel="next"' in part:
            return url_part
    return ""
