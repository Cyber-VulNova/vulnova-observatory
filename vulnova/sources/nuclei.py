"""Nuclei Templates lookup from ProjectDiscovery.

Resolves a CVE to its Nuclei detection template using the nuclei-templates
repository's strict file-path convention (e.g. http/cves/2021/CVE-2021-44228.yaml).
This needs no GitHub token and no code search — it fetches the raw template
directly and parses its name + severity.

Reference: https://github.com/projectdiscovery/nuclei-templates
"""

import re
from dataclasses import dataclass
from typing import Optional

import httpx

from vulnova.core.cache import Cache


NUCLEI_RAW_BASE = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main"
NUCLEI_BLOB_BASE = "https://github.com/projectdiscovery/nuclei-templates/blob/main"

# Candidate path templates within the repo, in priority order.
_PATH_TEMPLATES = [
    "http/cves/{year}/{cve}.yaml",
    "network/cves/{year}/{cve}.yaml",
    "http/cnvd/{year}/{cve}.yaml",
    "cves/{year}/{cve}.yaml",  # legacy layout
]

_SEVERITY_RE = re.compile(r"severity:\s*([a-zA-Z]+)")
_NAME_RE = re.compile(r"name:\s*(.+)")


@dataclass
class NucleiTemplate:
    """A Nuclei template for vulnerability detection."""
    id: str
    name: str
    path: str
    severity: str
    url: str
    raw_url: str
    tags: list[str]

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "path": self.path,
            "severity": self.severity,
            "url": self.url,
            "raw_url": self.raw_url,
            "tags": self.tags,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "NucleiTemplate":
        return cls(**data)

    @property
    def nuclei_command(self) -> str:
        """Return the nuclei command to use this template."""
        return f"nuclei -t {self.path} -u <target>"


class NucleiClient:
    """Client for ProjectDiscovery Nuclei Templates (path-based resolution)."""

    NAMESPACE = "nuclei"

    def __init__(self, config=None, cache: Optional[Cache] = None):
        self.config = config
        self.cache = cache

    def search(self, cve_id: str) -> list[NucleiTemplate]:
        """Resolve the Nuclei template(s) for a CVE via known repo paths.

        Args:
            cve_id: CVE identifier (e.g., CVE-2021-44228).

        Returns:
            List with the matching NucleiTemplate (usually 0 or 1).
        """
        cve_id = cve_id.upper()
        cache_key = f"tmpl:{cve_id}"

        if self.cache:
            cached = self.cache.get(self.NAMESPACE, cache_key)
            if cached is not None:
                return [NucleiTemplate.from_dict(t) for t in cached]

        parts = cve_id.split("-")
        year = parts[1] if len(parts) >= 2 else ""
        # Template files are named with the UPPER-case CVE id; only the
        # directory segments are lower-case.
        cve_lower = cve_id.lower()

        templates: list[NucleiTemplate] = []
        for tmpl in _PATH_TEMPLATES:
            path = tmpl.format(year=year, cve=cve_id)
            raw_url = f"{NUCLEI_RAW_BASE}/{path}"
            content = self._fetch(raw_url)
            if content is None:
                continue

            sev_match = _SEVERITY_RE.search(content)
            name_match = _NAME_RE.search(content)
            severity = sev_match.group(1).lower() if sev_match else "unknown"
            name = name_match.group(1).strip().strip('"\'') if name_match else cve_id

            templates.append(NucleiTemplate(
                id=cve_lower,
                name=name,
                path=path,
                severity=severity,
                url=f"{NUCLEI_BLOB_BASE}/{path}",
                raw_url=raw_url,
                tags=[cve_lower],
            ))
            break  # first hit is authoritative

        # Cache result (including negative results, shorter TTL) for speed
        if self.cache:
            ttl = 43200 if templates else 3600
            self.cache.set(self.NAMESPACE, cache_key, [t.to_dict() for t in templates], ttl=ttl)

        return templates

    @staticmethod
    def _fetch(url: str) -> Optional[str]:
        """GET a raw template with retries (raw.githubusercontent is flaky).

        Returns the body on HTTP 200, or None (including on 404 = no template).
        """
        import time
        for attempt in range(3):
            try:
                resp = httpx.get(url, timeout=12.0, follow_redirects=True)
                if resp.status_code == 200:
                    return resp.text
                if resp.status_code == 404:
                    return None  # definitively no template at this path
            except Exception:
                pass
            if attempt < 2:
                time.sleep(1.0)
        return None

    def has_template(self, cve_id: str) -> bool:
        """Quick check if a Nuclei template exists for a CVE."""
        return len(self.search(cve_id)) > 0
