"""NVD API v2 client for CVE lookup.

Supports searching by:
- CVE ID (e.g., CVE-2023-44487)
- CPE string (e.g., cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*)
- Component name + version (e.g., "apache httpd 2.4.49")

Reference: https://nvd.nist.gov/developers/vulnerabilities
"""

import re
from dataclasses import dataclass, field
from typing import Optional

import httpx

from vulnova.core.cache import Cache
from vulnova.core.config import Config


CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
CPE_PATTERN = re.compile(r"^cpe:2\.3:[aoh]:", re.IGNORECASE)

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


@dataclass
class CVSSData:
    """CVSS score information."""
    version: str = ""
    vector_string: str = ""
    base_score: float = 0.0
    severity: str = "NONE"
    exploitability_score: float = 0.0
    impact_score: float = 0.0


@dataclass
class CVEReference:
    """A reference link associated with a CVE."""
    url: str = ""
    source: str = ""
    tags: list[str] = field(default_factory=list)


@dataclass
class CVEResult:
    """Structured CVE data from NVD."""
    cve_id: str = ""
    description: str = ""
    published: str = ""
    last_modified: str = ""
    status: str = ""
    cvss: Optional[CVSSData] = None
    cpes: list[str] = field(default_factory=list)
    references: list[CVEReference] = field(default_factory=list)
    weaknesses: list[str] = field(default_factory=list)
    affected_products: list[dict] = field(default_factory=list)  # CNA vendor/product/versions
    cvss_metrics: list[dict] = field(default_factory=list)  # all CVSS scores (v2/v3/v4)
    cve_tags: list[str] = field(default_factory=list)  # NVD tags (Disputed, Unsupported…)
    raw: dict = field(default_factory=dict)

    @property
    def base_score(self) -> float:
        return self.cvss.base_score if self.cvss else 0.0

    @property
    def severity(self) -> str:
        return self.cvss.severity if self.cvss else "NONE"

    def to_dict(self) -> dict:
        """Serialize to dict for caching and output."""
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "published": self.published,
            "last_modified": self.last_modified,
            "status": self.status,
            "cvss": {
                "version": self.cvss.version,
                "vector_string": self.cvss.vector_string,
                "base_score": self.cvss.base_score,
                "severity": self.cvss.severity,
                "exploitability_score": self.cvss.exploitability_score,
                "impact_score": self.cvss.impact_score,
            } if self.cvss else None,
            "cpes": self.cpes,
            "references": [
                {"url": r.url, "source": r.source, "tags": r.tags}
                for r in self.references
            ],
            "weaknesses": self.weaknesses,
            "affected_products": self.affected_products,
            "cvss_metrics": self.cvss_metrics,
            "cve_tags": self.cve_tags,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "CVEResult":
        """Deserialize from cached dict."""
        cvss_data = data.get("cvss")
        cvss = CVSSData(**cvss_data) if cvss_data else None
        refs = [CVEReference(**r) for r in data.get("references", [])]
        return cls(
            cve_id=data.get("cve_id", ""),
            description=data.get("description", ""),
            published=data.get("published", ""),
            last_modified=data.get("last_modified", ""),
            status=data.get("status", ""),
            cvss=cvss,
            cpes=data.get("cpes", []),
            references=refs,
            weaknesses=data.get("weaknesses", []),
            affected_products=data.get("affected_products", []),
            cvss_metrics=data.get("cvss_metrics", []),
            cve_tags=data.get("cve_tags", []),
        )


class NVDClient:
    """Client for the NVD API v2."""

    NAMESPACE = "nvd"

    def __init__(self, config: Optional[Config] = None, cache: Optional[Cache] = None):
        self.config = config or Config()
        self.cache = cache
        self._api_key = self.config.get_api_key("nvd")

    def _headers(self) -> dict:
        headers = {"User-Agent": "VulNova/1.0"}
        if self._api_key:
            headers["apiKey"] = self._api_key
        return headers

    def _parse_cve(self, vuln: dict) -> CVEResult:
        """Parse a single vulnerability object from NVD response."""
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "")

        # Description (English preferred)
        descriptions = cve.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break
        if not description and descriptions:
            description = descriptions[0].get("value", "")

        # CVSS — capture ALL metrics (every version, primary + secondary sources)
        cvss = None
        cvss_metrics = []
        metrics = cve.get("metrics", {})
        # Order newest → oldest so the first is the preferred "primary" score
        for version_key in ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            for m in metrics.get(version_key, []):
                cvss_data = m.get("cvssData", {})
                entry = {
                    "version": cvss_data.get("version", ""),
                    "source_type": m.get("type", ""),  # Primary | Secondary
                    "source": m.get("source", ""),
                    "vector": cvss_data.get("vectorString", ""),
                    "base_score": cvss_data.get("baseScore", 0.0),
                    "severity": cvss_data.get("baseSeverity", m.get("baseSeverity", "NONE")),
                    "exploitability_score": m.get("exploitabilityScore", 0.0),
                    "impact_score": m.get("impactScore", 0.0),
                }
                cvss_metrics.append(entry)
                # Use the first (newest version, NVD lists Primary first) as headline
                if cvss is None:
                    cvss = CVSSData(
                        version=entry["version"],
                        vector_string=entry["vector"],
                        base_score=entry["base_score"],
                        severity=entry["severity"],
                        exploitability_score=entry["exploitability_score"],
                        impact_score=entry["impact_score"],
                    )

        # CPEs
        cpes = []
        configurations = cve.get("configurations", [])
        for config_node in configurations:
            for node in config_node.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if cpe_match.get("vulnerable", False):
                        cpes.append(cpe_match.get("criteria", ""))

        # References
        references = []
        for ref in cve.get("references", []):
            references.append(CVEReference(
                url=ref.get("url", ""),
                source=ref.get("source", ""),
                tags=ref.get("tags", []),
            ))

        # Weaknesses (CWE IDs)
        weaknesses = []
        for weakness in cve.get("weaknesses", []):
            for desc in weakness.get("description", []):
                val = desc.get("value", "")
                if val and val != "NVD-CWE-noinfo":
                    weaknesses.append(val)

        # Affected products (CNA-supplied vendor/product/versions, pre-analysis)
        affected_products = []
        seen_ap = set()
        for aff in cve.get("affected", []):
            data_list = aff.get("affectedData")
            if data_list is None:
                data_list = [aff]  # some records hold vendor/product inline
            for ad in data_list:
                vendor = (ad.get("vendor") or "").strip()
                product = (ad.get("product") or "").strip()
                # Normalize placeholder values
                if vendor.lower() in ("n/a", "na", "*", "unknown"):
                    vendor = ""
                if product.lower() in ("n/a", "na", "*", "unknown"):
                    product = ""
                if not (vendor or product):
                    continue
                key = (vendor.lower(), product.lower())
                if key in seen_ap:
                    continue
                seen_ap.add(key)

                # Version ranges + fixed versions
                affected_ranges = []
                fixed_versions = []
                default_status = ad.get("defaultStatus", "")
                for ver in ad.get("versions", []):
                    status = ver.get("status", "")
                    v = ver.get("version", "")
                    lt = ver.get("lessThan", "")
                    lte = ver.get("lessThanOrEqual", "")
                    if status == "affected":
                        if lt:
                            affected_ranges.append(f">= {v}, < {lt}")
                        elif lte:
                            affected_ranges.append(f">= {v}, <= {lte}")
                        elif v:
                            affected_ranges.append(v)
                    elif status == "unaffected" and v and v not in ("0",):
                        fixed_versions.append(v)
                    # Version-level status changes (e.g., "fixed at 2.15")
                    for ch in ver.get("changes", []):
                        if ch.get("status") == "unaffected" and ch.get("at"):
                            fixed_versions.append(ch["at"])

                affected_products.append({
                    "vendor": vendor,
                    "product": product,
                    "package": ad.get("packageURL", ""),
                    "default_status": default_status,
                    "affected_ranges": affected_ranges,
                    "fixed_versions": sorted(set(fixed_versions)),
                })

        # NVD tags (Disputed, Unsupported When Assigned, etc.)
        cve_tags = []
        for tag_entry in cve.get("cveTags", []):
            for t in tag_entry.get("tags", []):
                if t not in cve_tags:
                    cve_tags.append(t)

        return CVEResult(
            cve_id=cve_id,
            description=description,
            published=cve.get("published", ""),
            last_modified=cve.get("lastModified", ""),
            status=cve.get("vulnStatus", ""),
            cvss=cvss,
            cpes=cpes,
            references=references,
            weaknesses=weaknesses,
            affected_products=affected_products,
            cvss_metrics=cvss_metrics,
            cve_tags=cve_tags,
            raw=vuln,
        )

    def lookup_cve(self, cve_id: str) -> Optional[CVEResult]:
        """Look up a specific CVE by ID.

        Args:
            cve_id: CVE identifier (e.g., CVE-2023-44487).

        Returns:
            CVEResult or None if not found.
        """
        cve_id = cve_id.upper()

        # Check cache
        if self.cache:
            cached = self.cache.get(self.NAMESPACE, cve_id)
            if cached:
                return CVEResult.from_dict(cached)

        params = {"cveId": cve_id}
        try:
            resp = httpx.get(
                NVD_API_BASE,
                params=params,
                headers=self._headers(),
                timeout=30.0,
            )
            resp.raise_for_status()
            data = resp.json()
        except (httpx.HTTPError, Exception):
            return None

        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return None

        result = self._parse_cve(vulnerabilities[0])

        # Cache the result
        if self.cache:
            self.cache.set(self.NAMESPACE, cve_id, result.to_dict())

        return result

    def search_by_cpe(self, cpe_string: str, results_per_page: int = 20) -> list[CVEResult]:
        """Search CVEs by CPE string.

        Args:
            cpe_string: Full CPE 2.3 string.
            results_per_page: Max results to return.

        Returns:
            List of CVEResult objects.
        """
        cache_key = f"cpe:{cpe_string}"

        if self.cache:
            cached = self.cache.get(self.NAMESPACE, cache_key)
            if cached:
                return [CVEResult.from_dict(c) for c in cached]

        params = {
            "cpeName": cpe_string,
            "resultsPerPage": results_per_page,
        }
        try:
            resp = httpx.get(
                NVD_API_BASE,
                params=params,
                headers=self._headers(),
                timeout=30.0,
            )
            resp.raise_for_status()
            data = resp.json()
        except (httpx.HTTPError, Exception):
            return []

        results = [self._parse_cve(v) for v in data.get("vulnerabilities", [])]

        if self.cache and results:
            self.cache.set(self.NAMESPACE, cache_key, [r.to_dict() for r in results])

        return results

    def search_by_keyword(self, keyword: str, results_per_page: int = 20) -> list[CVEResult]:
        """Search CVEs by keyword (component name, version, etc.).

        Args:
            keyword: Search term (e.g., "apache httpd 2.4.49").
            results_per_page: Max results to return.

        Returns:
            List of CVEResult objects.
        """
        cache_key = f"kw:{keyword.lower()}"

        if self.cache:
            cached = self.cache.get(self.NAMESPACE, cache_key)
            if cached:
                return [CVEResult.from_dict(c) for c in cached]

        params = {
            "keywordSearch": keyword,
            "resultsPerPage": results_per_page,
        }
        try:
            resp = httpx.get(
                NVD_API_BASE,
                params=params,
                headers=self._headers(),
                timeout=30.0,
            )
            resp.raise_for_status()
            data = resp.json()
        except (httpx.HTTPError, Exception):
            return []

        results = [self._parse_cve(v) for v in data.get("vulnerabilities", [])]

        if self.cache and results:
            self.cache.set(self.NAMESPACE, cache_key, [r.to_dict() for r in results])

        return results

    def _build_list_params(self, keyword: str, cvss_severity: str, days_back: int) -> dict:
        """Build the shared NVD query params for list/count requests."""
        params: dict = {}
        if keyword.strip():
            params["keywordSearch"] = keyword.strip()
        if cvss_severity.strip():
            params["cvssV3Severity"] = cvss_severity.strip().upper()
        if days_back and days_back > 0:
            from datetime import datetime, timedelta, timezone
            # NVD limits each published-date range to 120 days
            window = min(days_back, 120)
            end = datetime.now(timezone.utc)
            start = end - timedelta(days=window)
            params["pubStartDate"] = start.strftime("%Y-%m-%dT%H:%M:%S.000")
            params["pubEndDate"] = end.strftime("%Y-%m-%dT%H:%M:%S.000")
        return params

    def count_cves(self, keyword: str = "", cvss_severity: str = "", days_back: int = 0) -> int:
        """Return the total number of CVEs matching the given filters.

        Uses a minimal (resultsPerPage=1) request and reads totalResults.
        Cached so repeated pagination requests don't re-query.
        """
        cache_key = f"count:{keyword.lower()}:{cvss_severity.upper()}:{days_back}"
        if self.cache:
            cached = self.cache.get(self.NAMESPACE, cache_key)
            if cached is not None:
                return cached.get("total", 0)

        params = self._build_list_params(keyword, cvss_severity, days_back)
        params["resultsPerPage"] = 1
        params["startIndex"] = 0
        try:
            resp = httpx.get(NVD_API_BASE, params=params, headers=self._headers(), timeout=45.0)
            resp.raise_for_status()
            total = resp.json().get("totalResults", 0)
        except (httpx.HTTPError, Exception):
            return 0

        if self.cache:
            self.cache.set(self.NAMESPACE, cache_key, {"total": total}, ttl=1800)
        return total

    def list_cves(
        self,
        page: int = 1,
        results_per_page: int = 50,
        keyword: str = "",
        cvss_severity: str = "",
        days_back: int = 0,
    ) -> tuple[list[CVEResult], int]:
        """List CVEs page-by-page, newest published first.

        NVD returns results in ascending order (oldest CVEs at startIndex 0),
        so to surface the most recently published CVEs first this method
        computes the offset from the *end* of the result set and reverses
        each page. Supports optional keyword/severity filters and a recency
        window (days_back).

        Args:
            page: 1-based page number.
            results_per_page: Number of CVEs per page (NVD max is 2000).
            keyword: Optional keyword to filter by.
            cvss_severity: Optional severity filter (LOW/MEDIUM/HIGH/CRITICAL).
            days_back: If > 0, only CVEs published within this many days
                (NVD caps each date range at 120 days).

        Returns:
            Tuple of (list of CVEResult sorted newest-first, total count).
        """
        page = max(page, 1)
        results_per_page = min(max(results_per_page, 1), 2000)
        cache_key = (
            f"listpg:{page}:{results_per_page}:"
            f"{keyword.lower()}:{cvss_severity.upper()}:{days_back}"
        )

        if self.cache:
            cached = self.cache.get(self.NAMESPACE, cache_key)
            if cached:
                results = [CVEResult.from_dict(c) for c in cached.get("results", [])]
                return results, cached.get("total", len(results))

        # Determine total so we can index from the end (newest CVEs).
        total = self.count_cves(keyword, cvss_severity, days_back)
        if total <= 0:
            return [], 0

        # Compute the NVD startIndex for this page counting from the newest.
        real_start = total - page * results_per_page
        count = results_per_page
        if real_start < 0:
            # Last page: fewer items than a full page.
            count = results_per_page + real_start
            real_start = 0
        if count <= 0:
            return [], total

        params = self._build_list_params(keyword, cvss_severity, days_back)
        params["startIndex"] = real_start
        params["resultsPerPage"] = count

        try:
            resp = httpx.get(NVD_API_BASE, params=params, headers=self._headers(), timeout=45.0)
            resp.raise_for_status()
            data = resp.json()
        except (httpx.HTTPError, Exception):
            return [], total

        results = [self._parse_cve(v) for v in data.get("vulnerabilities", [])]

        # NVD gives ascending order; reverse so newest is first, then
        # stable-sort by published date descending as a safety net.
        results.reverse()
        results.sort(key=lambda r: r.published, reverse=True)

        if self.cache:
            self.cache.set(
                self.NAMESPACE,
                cache_key,
                {"results": [r.to_dict() for r in results], "total": total},
                ttl=1800,
            )

        return results, total

    def search(self, query: str) -> list[CVEResult]:
        """Auto-detect query type and search accordingly.

        Detects whether query is a CVE ID, CPE string, or keyword and
        routes to the appropriate method.

        Args:
            query: CVE ID, CPE string, or keyword search.

        Returns:
            List of CVEResult objects.
        """
        query = query.strip()

        if CVE_PATTERN.match(query):
            result = self.lookup_cve(query)
            return [result] if result else []
        elif CPE_PATTERN.match(query):
            return self.search_by_cpe(query)
        else:
            return self.search_by_keyword(query)
