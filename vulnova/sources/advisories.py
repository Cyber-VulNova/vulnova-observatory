"""Multi-source advisory aggregation for Flare.

Combines the GitHub Advisory Database (GHSA) with genuinely non-GitHub vendor
sources — Ubuntu Security Notices and Red Hat Security Advisories — into one
normalized `Advisory` stream. All sources are free and need no API key.

Adding a new vendor source = write a small client that returns `Advisory`
objects and register it in `SOURCE_FETCHERS`.
"""

import re
from typing import Optional

import feedparser
import httpx

from vulnova.core.cache import Cache
from vulnova.core.config import Config
from vulnova.sources.ghsa import Advisory, GHSAClient
from vulnova.sources.nvd import NVDClient


UA = {"User-Agent": "VulNova/1.0"}

# Vendor severity → our scale
_RH_SEV = {"low": "low", "moderate": "medium", "important": "high", "critical": "critical"}
_MS_SEV = {"low": "low", "moderate": "medium", "important": "high", "critical": "critical"}
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


class UbuntuUSNClient:
    """Ubuntu Security Notices (USN) — free JSON API, no key."""

    NAMESPACE = "adv_ubuntu"
    URL = "https://ubuntu.com/security/notices.json"

    def __init__(self, cache: Optional[Cache] = None):
        self.cache = cache

    PAGE = 20  # Ubuntu USN API rejects limit > 20 (HTTP 422)

    def fetch(self, limit: int = 60, force: bool = False) -> list[Advisory]:
        key = f"usn:{limit}"
        if self.cache and not force:
            cached = self.cache.get(self.NAMESPACE, key)
            if cached is not None:
                return [Advisory.from_dict(x) for x in cached]

        # Paginate in pages of 20 via offset until we reach `limit`.
        notices = []
        try:
            offset = 0
            while len(notices) < limit and offset < limit + self.PAGE:
                resp = httpx.get(
                    self.URL,
                    params={"limit": self.PAGE, "offset": offset},
                    headers=UA, timeout=25.0,
                )
                if resp.status_code != 200:
                    break
                batch = resp.json().get("notices", [])
                if not batch:
                    break
                notices.extend(batch)
                offset += self.PAGE
            notices = notices[:limit]
        except (httpx.HTTPError, Exception):
            return []

        out = []
        for n in notices:
            cves = n.get("cves_ids") or n.get("cves") or []
            cves = [c if isinstance(c, str) else c.get("id", "") for c in cves]
            cves = [c for c in cves if c]
            pkgs = []
            rp = n.get("release_packages") or {}
            if isinstance(rp, dict):
                for rel, items in rp.items():
                    for it in (items or [])[:2]:
                        name = it.get("name") if isinstance(it, dict) else str(it)
                        if name and name not in pkgs:
                            pkgs.append(name)
                    if len(pkgs) >= 5:
                        break
            out.append(Advisory(
                advisory_id=n.get("id", ""),
                cve_id=cves[0] if cves else "",
                summary=n.get("title", "")[:300],
                severity="unknown",
                cvss_score=0.0,
                published=(n.get("published") or "")[:10],
                updated=(n.get("published") or "")[:10],
                url=f"https://ubuntu.com/security/notices/{n.get('id','')}",
                source="Ubuntu Security Notices",
                ecosystems=["Ubuntu"],
                packages=pkgs[:6],
                cwes=[],
                references=[],
                type="reviewed",
            ))

        if self.cache and out:
            self.cache.set(self.NAMESPACE, key, [a.to_dict() for a in out], ttl=3600)
        return out


class RedHatClient:
    """Red Hat Security Advisories (RHSA) — free security-data API, no key."""

    NAMESPACE = "adv_redhat"
    URL = "https://access.redhat.com/hydra/rest/securitydata/csaf.json"

    def __init__(self, cache: Optional[Cache] = None):
        self.cache = cache

    def fetch(self, limit: int = 75, force: bool = False) -> list[Advisory]:
        key = f"rhsa:{limit}"
        if self.cache and not force:
            cached = self.cache.get(self.NAMESPACE, key)
            if cached is not None:
                return [Advisory.from_dict(x) for x in cached]

        try:
            resp = httpx.get(self.URL, params={"per_page": limit}, headers=UA, timeout=25.0)
            resp.raise_for_status()
            items = resp.json()
        except (httpx.HTTPError, Exception):
            return []

        out = []
        for it in items:
            rhsa = it.get("RHSA", "")
            cves = it.get("CVEs") or []
            pkgs = [p.split("@")[0] for p in (it.get("released_packages") or [])]
            pkgs = list(dict.fromkeys(pkgs))[:6]
            # Synthesize a title from the affected packages (RH list has none)
            if pkgs:
                extra = f" (+{len(it.get('released_packages', [])) - 1} builds)" if len(it.get("released_packages", [])) > 1 else ""
                summary = f"Security update for {pkgs[0]}{extra}"
            else:
                summary = "Red Hat security advisory"
            out.append(Advisory(
                advisory_id=rhsa,
                cve_id=cves[0] if cves else "",
                summary=summary,
                severity=_RH_SEV.get((it.get("severity") or "").lower(), "unknown"),
                cvss_score=0.0,
                published=(it.get("released_on") or "")[:10],
                updated=(it.get("released_on") or "")[:10],
                url=f"https://access.redhat.com/errata/{rhsa}",
                source="Red Hat",
                ecosystems=["Red Hat"],
                packages=pkgs,
                cwes=[],
                references=[],
                type="reviewed",
            ))

        if self.cache and out:
            self.cache.set(self.NAMESPACE, key, [a.to_dict() for a in out], ttl=3600)
        return out


class PaloAltoClient:
    """Palo Alto Networks Security Advisories — free RSS, no key."""

    NAMESPACE = "adv_paloalto"
    URL = "https://security.paloaltonetworks.com/rss.xml"

    def __init__(self, cache: Optional[Cache] = None):
        self.cache = cache

    def fetch(self, limit: int = 40, force: bool = False) -> list[Advisory]:
        key = f"pan:{limit}"
        if self.cache and not force:
            cached = self.cache.get(self.NAMESPACE, key)
            if cached is not None:
                return [Advisory.from_dict(x) for x in cached]

        try:
            resp = httpx.get(self.URL, headers=UA, timeout=25.0, follow_redirects=True)
            resp.raise_for_status()
            parsed = feedparser.parse(resp.content)
        except (httpx.HTTPError, Exception):
            return []

        out = []
        for e in parsed.entries[:limit]:
            title = e.get("title", "")
            link = e.get("link", "")
            cve_m = _CVE_RE.search(title) or _CVE_RE.search(link)
            cve = cve_m.group(0).upper() if cve_m else ""
            # Title format: "CVE-xxxx Product: Description (Severity: HIGH ...)"
            sev = "unknown"
            sm = re.search(r"Severity:\s*([A-Za-z]+)", title)
            if sm:
                sev = sm.group(1).lower()
            # Product = between the CVE id and the first colon
            product = ""
            pm = re.search(r"CVE-\d{4}-\d{4,}\s+([^:]+):", title)
            if pm:
                product = pm.group(1).strip()
            # Clean summary = drop leading CVE + trailing severity note
            summary = re.sub(r"^\s*CVE-\d{4}-\d{4,}\s*", "", title)
            summary = re.sub(r"\s*\(Severity:.*$", "", summary).strip()

            out.append(Advisory(
                advisory_id=cve or (e.get("id", "") or link),
                cve_id=cve,
                summary=summary[:300] or title[:300],
                severity=sev if sev in ("low", "medium", "high", "critical") else "unknown",
                cvss_score=0.0,
                published=_rss_date(e),
                updated=_rss_date(e),
                url=link,
                source="Palo Alto Networks",
                ecosystems=["Palo Alto"],
                packages=[product] if product else [],
                cwes=[],
                references=[],
                type="reviewed",
            ))

        if self.cache and out:
            self.cache.set(self.NAMESPACE, key, [a.to_dict() for a in out], ttl=3600)
        return out


class MicrosoftMSRCClient:
    """Microsoft Security Response Center (MSRC) — free CVRF API, no key.

    MSRC publishes one big CVRF document per month (Patch Tuesday), each with
    ~1000+ vulnerabilities. To avoid flooding Flare, only the most recent
    `limit` vulnerabilities from the latest month are surfaced.
    """

    NAMESPACE = "adv_microsoft"
    UPDATES_URL = "https://api.msrc.microsoft.com/cvrf/v3.0/updates"

    def __init__(self, cache: Optional[Cache] = None):
        self.cache = cache

    def fetch(self, limit: int = 60, force: bool = False) -> list[Advisory]:
        key = f"msrc:{limit}"
        if self.cache and not force:
            cached = self.cache.get(self.NAMESPACE, key)
            if cached is not None:
                return [Advisory.from_dict(x) for x in cached]

        hdrs = {**UA, "Accept": "application/json"}
        try:
            updates = httpx.get(self.UPDATES_URL, headers=hdrs, timeout=20.0).json().get("value", [])
            if not updates:
                return []
            # Latest month by release date
            latest = max(updates, key=lambda u: u.get("CurrentReleaseDate", ""))
            doc = httpx.get(latest["CvrfUrl"], headers=hdrs, timeout=40.0).json()
        except (httpx.HTTPError, Exception):
            return []

        vulns = doc.get("Vulnerability", []) or []
        # Newest first by release date
        vulns.sort(key=lambda v: v.get("ReleaseDate", ""), reverse=True)

        out = []
        for v in vulns[:limit]:
            cve = v.get("CVE", "")
            title = (v.get("Title", {}) or {}).get("Value", "")
            # Severity from Threats (Type 3 = Severity)
            sev = "unknown"
            for t in v.get("Threats", []) or []:
                desc = (t.get("Description", {}) or {}).get("Value", "").lower()
                if desc in _MS_SEV:
                    sev = _MS_SEV[desc]
                    break
            # CVSS base score
            cvss = 0.0
            css = v.get("CVSSScoreSets", []) or []
            if css and css[0].get("BaseScore"):
                try:
                    cvss = float(css[0]["BaseScore"])
                except (TypeError, ValueError):
                    cvss = 0.0

            out.append(Advisory(
                advisory_id=cve or title[:40],
                cve_id=cve,
                summary=title[:300],
                severity=sev,
                cvss_score=cvss,
                published=(v.get("ReleaseDate", "") or "")[:10],
                updated=(v.get("ReleaseDate", "") or "")[:10],
                url=f"https://msrc.microsoft.com/update-guide/vulnerability/{cve}" if cve else "https://msrc.microsoft.com/update-guide",
                source="Microsoft",
                ecosystems=["Microsoft"],
                packages=[],
                cwes=[w for w in [(v.get("CWE") or "")] if w][:1],
                references=[],
                type="reviewed",
            ))

        if self.cache and out:
            self.cache.set(self.NAMESPACE, key, [a.to_dict() for a in out], ttl=3600)
        return out


class VMwareClient:
    """VMware advisories via NVD.

    Post-Broadcom, VMware has no clean no-key machine-readable advisory feed
    (the Broadcom portal is a JS SPA and the security blog RSS is marketing).
    As a reliable fallback we surface recent VMware vulnerabilities from NVD,
    which VMware (as a CNA) populates. These are CVE-level rather than
    VMSA-grouped, but give a dependable VMware-focused view.
    """

    NAMESPACE = "adv_vmware"

    def __init__(self, config: Optional[Config] = None, cache: Optional[Cache] = None):
        self.config = config or Config()
        self.cache = cache

    def fetch(self, limit: int = 40, force: bool = False) -> list[Advisory]:
        key = f"vmware:{limit}"
        if self.cache and not force:
            cached = self.cache.get(self.NAMESPACE, key)
            if cached is not None:
                return [Advisory.from_dict(x) for x in cached]

        try:
            nvd = NVDClient(config=self.config, cache=self.cache)
            cves, _total = nvd.list_cves(page=1, results_per_page=limit, keyword="VMware")
        except Exception:
            return []

        sev_map = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
                   "LOW": "low", "NONE": "unknown"}
        out = []
        for c in cves:
            out.append(Advisory(
                advisory_id=c.cve_id,
                cve_id=c.cve_id,
                summary=(c.description or "")[:300],
                severity=sev_map.get((c.severity or "").upper(), "unknown"),
                cvss_score=c.base_score,
                published=(c.published or "")[:10],
                updated=(c.last_modified or "")[:10],
                url=f"https://nvd.nist.gov/vuln/detail/{c.cve_id}",
                source="VMware",
                ecosystems=["VMware"],
                packages=[],
                cwes=c.weaknesses[:3],
                references=[],
                type="reviewed",
            ))

        if self.cache and out:
            self.cache.set(self.NAMESPACE, key, [a.to_dict() for a in out], ttl=3600)
        return out


class OSVClient:
    """OSV.dev open-source ecosystem advisories (RustSec, PyPI/PYSEC, Go).

    This is Flare's primary **no-CVE** source. Unlike vendor PSIRTs (Palo Alto,
    Microsoft, Red Hat, VMware) — which are CNAs and therefore almost always
    ship a CVE — OSV aggregates open-source advisory databases where a large
    share of entries have **no CVE assigned**:

        crates.io (RustSec) ~42% no-CVE, PyPI (PYSEC) ~49%, Go ~9%.

    We download each ecosystem's `all.zip` dump, take the most recently modified
    advisories, and normalize them. Results are cached for 6 h since the dumps
    change slowly and each refresh is a multi-MB download + parse.

    Reference: https://osv.dev  |  https://google.github.io/osv.dev/data/
    """

    NAMESPACE = "adv_osv"
    BUCKET = "https://osv-vulnerabilities.storage.googleapis.com/{eco}/all.zip"
    # OSV ecosystem id -> display label used in the Flare ecosystem filter
    ECOSYSTEMS = {
        "crates.io": "crates.io",
        "PyPI": "PyPI",
        "Go": "Go",
    }
    _NATIVE_PREFIXES = ("RUSTSEC", "PYSEC", "GO")
    _SEV = {"critical": "critical", "high": "high", "moderate": "medium",
            "medium": "medium", "low": "low"}
    CACHE_TTL = 6 * 3600  # 6 hours

    def __init__(self, cache: Optional[Cache] = None):
        self.cache = cache

    def fetch(self, per_eco: int = 60, force: bool = False) -> list[Advisory]:
        key = f"osv:{per_eco}"
        if self.cache and not force:
            cached = self.cache.get(self.NAMESPACE, key)
            if cached is not None:
                return [Advisory.from_dict(x) for x in cached]

        out: list[Advisory] = []
        for eco, label in self.ECOSYSTEMS.items():
            out.extend(self._fetch_eco(eco, label, per_eco))

        if self.cache and out:
            self.cache.set(self.NAMESPACE, key,
                           [a.to_dict() for a in out], ttl=self.CACHE_TTL)
        return out

    def _fetch_eco(self, eco: str, label: str, per_eco: int) -> list[Advisory]:
        import io
        import json
        import zipfile

        url = self.BUCKET.format(eco=eco)
        try:
            resp = httpx.get(url, headers=UA, timeout=90.0, follow_redirects=True)
            resp.raise_for_status()
            zf = zipfile.ZipFile(io.BytesIO(resp.content))
        except (httpx.HTTPError, Exception):
            return []

        recs = []
        for name in zf.namelist():
            if not name.endswith(".json"):
                continue
            try:
                rec = json.loads(zf.read(name))
            except (ValueError, KeyError):
                continue
            # Skip malicious-package takedown notices (MAL-…). They flood the
            # recent PyPI feed and are a different category from the "no-CVE
            # vulnerability advisory" Flare is meant to surface.
            if (rec.get("id", "") or "").upper().startswith("MAL-"):
                continue
            recs.append(rec)

        # Most recently modified first, then take the top slice per ecosystem.
        recs.sort(key=lambda r: r.get("modified", "") or "", reverse=True)
        return [self._parse(r, label) for r in recs[:per_eco]]

    def _parse(self, r: dict, label: str) -> Advisory:
        aliases = r.get("aliases", []) or []
        cve = next((a.upper() for a in aliases if a.upper().startswith("CVE-")), "")
        rid = r.get("id", "")
        # Prefer a native ecosystem ID (RUSTSEC-/PYSEC-/GO-) over a GHSA mirror id.
        native = next(
            (a for a in aliases if a.split("-")[0].upper() in self._NATIVE_PREFIXES),
            "",
        )
        advisory_id = native or rid

        ds = r.get("database_specific", {}) or {}
        severity = self._SEV.get((ds.get("severity") or "").lower(), "unknown")

        pkgs = []
        for aff in r.get("affected", []) or []:
            nm = ((aff or {}).get("package", {}) or {}).get("name", "")
            if nm and nm not in pkgs:
                pkgs.append(nm)

        refs = [x.get("url", "") for x in (r.get("references") or [])
                if isinstance(x, dict) and x.get("url")]

        return Advisory(
            advisory_id=advisory_id,
            cve_id=cve,
            summary=(r.get("summary") or r.get("details") or "")[:300],
            severity=severity,
            cvss_score=0.0,  # OSV carries CVSS vectors, not base scores
            published=(r.get("published") or "")[:10],
            updated=(r.get("modified") or "")[:10],
            url=f"https://osv.dev/vulnerability/{rid}",
            source="OSV",
            ecosystems=[label],
            packages=pkgs[:6],
            cwes=(ds.get("cwe_ids") or [])[:5],
            references=refs[:6],
            type="reviewed",
        )


def _rss_date(entry) -> str:
    """Best-effort ISO date (YYYY-MM-DD) from a feed entry."""
    import time as _t
    for k in ("published_parsed", "updated_parsed"):
        p = entry.get(k)
        if p:
            try:
                return _t.strftime("%Y-%m-%d", p)
            except Exception:
                pass
    raw = entry.get("published", entry.get("updated", ""))
    return raw[:10] if raw else ""


# Registry of non-GHSA source fetchers
def _ubuntu(cache, limit, force):
    return UbuntuUSNClient(cache=cache).fetch(limit=limit, force=force)


def _redhat(cache, limit, force):
    return RedHatClient(cache=cache).fetch(limit=limit, force=force)


def _paloalto(cache, limit, force):
    return PaloAltoClient(cache=cache).fetch(limit=limit, force=force)


def _microsoft(cache, limit, force):
    return MicrosoftMSRCClient(cache=cache).fetch(limit=limit, force=force)


def _osv(cache, per_eco, force):
    return OSVClient(cache=cache).fetch(per_eco=per_eco, force=force)


VENDOR_SOURCES = {
    "ubuntu": "Ubuntu Security Notices",
    "redhat": "Red Hat",
    "paloalto": "Palo Alto Networks",
    "microsoft": "Microsoft",
    "vmware": "VMware",
}

# Open-source ecosystem aggregators — the no-CVE-heavy sources.
OSS_SOURCES = {
    "osv": "OSV",
}

ALL_SOURCES = {"github": "GitHub Advisory Database", **VENDOR_SOURCES, **OSS_SOURCES}


def fetch_all_advisories(
    config: Config,
    cache: Cache,
    sources: Optional[list[str]] = None,
    adv_type: str = "reviewed",
    limit: int = 300,
    force: bool = False,
) -> list[Advisory]:
    """Fetch and merge advisories from all selected sources, newest first.

    Args:
        sources: subset of {"github","ubuntu","redhat"}; defaults to all.
        adv_type: GHSA type (reviewed/unreviewed/malware) — GHSA only.
        limit: overall cap on returned advisories.
    """
    selected = sources or list(ALL_SOURCES.keys())
    merged: list[Advisory] = []

    # Fetched sequentially — each source is cached (~1 h), so repeat loads are
    # fast, and this avoids sharing the SQLite cache across threads.
    if "github" in selected:
        try:
            merged.extend(GHSAClient(config=config, cache=cache).fetch(
                adv_type=adv_type, limit=200, force=force))
        except Exception:
            pass
    if "ubuntu" in selected:
        try:
            merged.extend(_ubuntu(cache, 75, force))
        except Exception:
            pass
    if "redhat" in selected:
        try:
            merged.extend(_redhat(cache, 75, force))
        except Exception:
            pass
    if "paloalto" in selected:
        try:
            merged.extend(_paloalto(cache, 40, force))
        except Exception:
            pass
    if "microsoft" in selected:
        try:
            merged.extend(_microsoft(cache, 60, force))
        except Exception:
            pass
    if "vmware" in selected:
        try:
            merged.extend(VMwareClient(config=config, cache=cache).fetch(limit=40, force=force))
        except Exception:
            pass
    if "osv" in selected:
        try:
            merged.extend(_osv(cache, 60, force))
        except Exception:
            pass

    merged.sort(key=lambda a: a.published, reverse=True)
    return merged[:limit]
