"""CISA Known Exploited Vulnerabilities (KEV) catalog integration.

The KEV catalog is the #1 triage signal - if a CVE is in KEV,
it means it's being actively exploited in the wild.

Reference: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
"""

from dataclasses import dataclass
from typing import Optional

import httpx

from vulnova.core.cache import Cache


KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


@dataclass
class KEVEntry:
    """An entry from the CISA KEV catalog."""
    cve_id: str
    vendor: str
    product: str
    vulnerability_name: str
    date_added: str
    short_description: str
    required_action: str
    due_date: str
    known_ransomware_use: str = "Unknown"

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "vendor": self.vendor,
            "product": self.product,
            "vulnerability_name": self.vulnerability_name,
            "date_added": self.date_added,
            "short_description": self.short_description,
            "required_action": self.required_action,
            "due_date": self.due_date,
            "known_ransomware_use": self.known_ransomware_use,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "KEVEntry":
        return cls(
            cve_id=data.get("cve_id", data.get("cveID", "")),
            vendor=data.get("vendor", data.get("vendorProject", "")),
            product=data.get("product", ""),
            vulnerability_name=data.get("vulnerability_name", data.get("vulnerabilityName", "")),
            date_added=data.get("date_added", data.get("dateAdded", "")),
            short_description=data.get("short_description", data.get("shortDescription", "")),
            required_action=data.get("required_action", data.get("requiredAction", "")),
            due_date=data.get("due_date", data.get("dueDate", "")),
            known_ransomware_use=data.get("known_ransomware_use",
                                          data.get("knownRansomwareCampaignUse", "Unknown")),
        )


class KEVClient:
    """Client for the CISA Known Exploited Vulnerabilities catalog."""

    NAMESPACE = "kev"
    CATALOG_KEY = "full_catalog"

    def __init__(self, cache: Optional[Cache] = None):
        self.cache = cache
        self._catalog: Optional[dict[str, KEVEntry]] = None

    def _load_catalog(self, force: bool = False) -> dict[str, KEVEntry]:
        """Load the full KEV catalog, using cache if available.

        Args:
            force: bypass the in-memory and on-disk cache and refetch from CISA.
        """
        if self._catalog is not None and not force:
            return self._catalog

        # Check cache (longer TTL since KEV updates ~weekly)
        if self.cache and not force:
            cached = self.cache.get(self.NAMESPACE, self.CATALOG_KEY)
            if cached:
                self._catalog = {
                    k: KEVEntry.from_dict(v) for k, v in cached.items()
                }
                return self._catalog

        # Fetch from CISA
        try:
            resp = httpx.get(KEV_URL, timeout=30.0)
            resp.raise_for_status()
            data = resp.json()
        except (httpx.HTTPError, Exception):
            self._catalog = {}
            return self._catalog

        catalog: dict[str, KEVEntry] = {}
        for vuln in data.get("vulnerabilities", []):
            entry = KEVEntry(
                cve_id=vuln.get("cveID", ""),
                vendor=vuln.get("vendorProject", ""),
                product=vuln.get("product", ""),
                vulnerability_name=vuln.get("vulnerabilityName", ""),
                date_added=vuln.get("dateAdded", ""),
                short_description=vuln.get("shortDescription", ""),
                required_action=vuln.get("requiredAction", ""),
                due_date=vuln.get("dueDate", ""),
                known_ransomware_use=vuln.get("knownRansomwareCampaignUse", "Unknown"),
            )
            catalog[entry.cve_id] = entry

        # Cache for 6 hours
        if self.cache:
            self.cache.set(
                self.NAMESPACE,
                self.CATALOG_KEY,
                {k: v.to_dict() for k, v in catalog.items()},
                ttl=21600,
            )

        self._catalog = catalog
        return self._catalog

    def is_in_kev(self, cve_id: str) -> bool:
        """Check if a CVE is in the KEV catalog (actively exploited).

        Args:
            cve_id: CVE identifier.

        Returns:
            True if the CVE is in the KEV catalog.
        """
        catalog = self._load_catalog()
        return cve_id.upper() in catalog

    def get_entry(self, cve_id: str) -> Optional[KEVEntry]:
        """Get the KEV entry for a CVE if it exists.

        Args:
            cve_id: CVE identifier.

        Returns:
            KEVEntry or None.
        """
        catalog = self._load_catalog()
        return catalog.get(cve_id.upper())

    def get_all(self, force: bool = False) -> list[KEVEntry]:
        """Get all entries in the KEV catalog.

        Args:
            force: bypass the cache and refetch the catalog from CISA.
        """
        catalog = self._load_catalog(force=force)
        return list(catalog.values())

    @property
    def catalog_size(self) -> int:
        """Number of CVEs in the KEV catalog."""
        return len(self._load_catalog())
