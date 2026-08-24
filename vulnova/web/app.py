"""Flask application for VulNova Web UI.

Provides a browser-based CVE data table sourced from the NVD API v2 and the
CISA KEV catalog, enriched with EPSS scores, product/vendor identification,
public-exploit status, and a deterministic triage priority score. Also serves
the VulNova Pulse cyber-news feed.
"""

import logging
import os
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import httpx
from flask import Flask, Response, jsonify, render_template, request

from vulnova.core.cache import Cache
from vulnova.core.config import Config
from vulnova.core.cpe_match import parse_cpe
from vulnova.core.cvss import parse_vector
from vulnova.core.cwe_data import lookup_cwe
from vulnova.core.triage import compute_triage_score
from vulnova.sources.epss import EPSSClient
from vulnova.sources.exploitdb import ExploitDBClient
from vulnova.sources.advisories import ALL_SOURCES, fetch_all_advisories
from vulnova.sources.ghsa import GHSAClient
from vulnova.sources.github_poc import GitHubPoCClient
from vulnova.sources.kev import KEVClient
from vulnova.sources.metasploit import MetasploitClient
from vulnova.sources.news import SOURCES, NewsAggregator
from vulnova.sources.nuclei import NucleiClient
from vulnova.sources.nvd import NVDClient
from vulnova.sources.vulhub import VulhubClient
from vulnova.core.tagger import extract_tags, extract_product_text


logger = logging.getLogger(__name__)


def _install_basic_auth(app: Flask) -> None:
    """Optionally protect the whole app with HTTP Basic Auth.

    Enabled only when BOTH ``VULNOVA_BASIC_AUTH_USER`` and
    ``VULNOVA_BASIC_AUTH_PASS`` environment variables are set — otherwise the
    app stays open (fine for local/dev use). Recommended for any public
    deployment, ideally in addition to a reverse proxy.
    """
    import base64
    import hmac

    user = os.environ.get("VULNOVA_BASIC_AUTH_USER")
    password = os.environ.get("VULNOVA_BASIC_AUTH_PASS")
    if not (user and password):
        return  # auth disabled

    expected = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()

    @app.before_request
    def _require_basic_auth():
        provided = request.headers.get("Authorization", "")
        # Constant-time comparison to avoid timing side-channels.
        if not hmac.compare_digest(provided, expected):
            return Response(
                "Authentication required.", 401,
                {"WWW-Authenticate": 'Basic realm="VulNova Observatory"'},
            )

    logger.info("HTTP Basic Auth enabled for all routes.")


# ─── Product / vendor prettification ──────────────────────────────────────────

# Common CPE tokens that don't title-case nicely.
_PRETTY_OVERRIDES = {
    "mac_os_x": "macOS",
    "macos": "macOS",
    "iphone_os": "iOS",
    "ipados": "iPadOS",
    "http_server": "HTTP Server",
    "windows_10": "Windows 10",
    "windows_11": "Windows 11",
    "windows_server_2019": "Windows Server 2019",
    "windows_server_2022": "Windows Server 2022",
    "esxi": "ESXi",
    "vcenter_server": "vCenter Server",
    "jdk": "JDK",
    "jre": "JRE",
    "openssl": "OpenSSL",
    "openssh": "OpenSSH",
    "php": "PHP",
    "mysql": "MySQL",
    "postgresql": "PostgreSQL",
    "ios_xe": "IOS XE",
    "fortios": "FortiOS",
    "pan-os": "PAN-OS",
    "paloaltonetworks": "Palo Alto Networks",
    "palo_alto_networks": "Palo Alto Networks",
    "linux_kernel": "Linux Kernel",
    "google": "Google",
    "apache": "Apache",
    "wordpress": "WordPress",
    "gitlab": "GitLab",
    "github": "GitHub",
    "nvidia": "NVIDIA",
    "ibm": "IBM",
    "sap": "SAP",
    "vmware": "VMware",
    "sonicwall": "SonicWall",
    "sonicos": "SonicOS",
    "qnap": "QNAP",
    "d-link": "D-Link",
    "tp-link": "TP-Link",
    "zyxel": "Zyxel",
}


def _prettify(token: str) -> str:
    """Turn a CPE token like 'mac_os_x' into a readable label."""
    if not token or token in ("*", "-", ""):
        return ""
    key = token.lower().strip()
    if key in _PRETTY_OVERRIDES:
        return _PRETTY_OVERRIDES[key]
    cleaned = token.replace("\\", "").replace("_", " ").strip()
    # Title-case but keep short all-caps tokens uppercase
    parts = []
    for word in cleaned.split():
        if len(word) <= 3 and word.isalpha():
            parts.append(word.upper())
        else:
            parts.append(word[:1].upper() + word[1:])
    return " ".join(parts)


def _tagger_products(description: str) -> list[str]:
    """Extract known product names mentioned in the description."""
    tags = extract_tags(description or "", max_tags=20)
    return [t["label"] for t in tags if t["type"] == "product"]


def _derive_product(cpes: list[str], description: str = "", affected: list = None) -> dict:
    """Identify the primary affected vendor/product for a CVE.

    Priority (best/most-available first):
    1. CNA-supplied "affected" vendor/product — present at publication for
       almost every CVE, even before NVD assigns CPEs.
    2. Most common vendor/product pair from CPEs (analyzed CVEs).
    3. Named products detected in the description (tagger dictionary).
    4. Vendor-only from CPEs.
    """
    affected = affected or []

    # 1. CNA affected data (authoritative, available pre-analysis)
    ap_pairs = []
    for a in affected:
        v = (a.get("vendor") or "").strip()
        p = (a.get("product") or "").strip()
        if v or p:
            ap_pairs.append((v, p))
    if ap_pairs:
        v, p = ap_pairs[0]
        label = f"{_shorten_vendor(v)} / {p}" if v and p else (p or _shorten_vendor(v))
        distinct = len({(x[0].lower(), x[1].lower()) for x in ap_pairs})
        return {"vendor": v, "product": p, "label": label, "more": max(0, distinct - 1)}

    # 2. CPE-derived vendor/product
    pair_counter: Counter = Counter()
    vendor_set: set = set()
    for cpe in cpes:
        pc = parse_cpe(cpe)
        vendor = pc.get("vendor", "")
        product = pc.get("product", "")
        if vendor and vendor not in ("*", "-"):
            vendor_set.add(vendor)
            if product and product not in ("*", "-"):
                pair_counter[(vendor, product)] += 1

    tagger_prods = _tagger_products(description)
    distinct_vendors = len(vendor_set)

    # CPE sprawl (a component embedded in many products) → prefer named product
    if (not pair_counter or distinct_vendors >= 4) and tagger_prods:
        return {"vendor": tagger_prods[0], "product": "",
                "label": " · ".join(tagger_prods[:2]),
                "more": max(0, len(tagger_prods) - 2)}

    if pair_counter:
        (vendor, product), _ = pair_counter.most_common(1)[0]
        v, pr = _prettify(vendor), _prettify(product)
        label = f"{v} / {pr}" if pr else v
        return {"vendor": v, "product": pr, "label": label,
                "more": max(0, len(pair_counter) - 1)}

    # 3. Tagger dictionary from description
    if tagger_prods:
        return {"vendor": tagger_prods[0], "product": "",
                "label": " · ".join(tagger_prods[:2]),
                "more": max(0, len(tagger_prods) - 2)}

    # 4. Free-text extraction from the description (long-tail products)
    text_prod = extract_product_text(description)
    if text_prod:
        return {"vendor": "", "product": text_prod, "label": text_prod, "more": 0}

    # 5. Vendor only
    if vendor_set:
        v = _prettify(sorted(vendor_set)[0])
        return {"vendor": v, "product": "", "label": v, "more": 0}
    return {"vendor": "", "product": "", "label": "", "more": 0}


def _shorten_vendor(vendor: str) -> str:
    """Trim noisy corporate suffixes from CNA vendor names for the label."""
    for suffix in (" Software Foundation", ", Inc.", " Inc.", ", LLC", " LLC",
                   " Corporation", " Corp.", " GmbH", " Pty Ltd", " Ltd.", " Ltd"):
        if vendor.endswith(suffix):
            return vendor[: -len(suffix)].strip()
    return vendor


# ─── Public-exploit status (lightweight, table-level) ─────────────────────────

def _exploit_status(in_kev: bool, ransomware: str, epss_prob: float, has_edb: bool) -> dict:
    """Derive a coarse public-exploit status from cheap signals.

    Deep PoC discovery (GitHub/Metasploit/Nuclei/Vulhub) happens in the row
    expander instead, to stay within API rate limits for a full page.
    """
    ransom = (ransomware or "").strip().lower() == "known"
    if in_kev:
        label = "Weaponized"
        if ransom:
            label = "Weaponized · Ransomware"
        return {"label": label, "level": "weaponized",
                "detail": "Listed in CISA KEV (actively exploited)"}
    if has_edb:
        return {"label": "Public Exploit", "level": "public",
                "detail": "Exploit-DB entry available"}
    if epss_prob >= 0.5:
        return {"label": "Likely", "level": "likely",
                "detail": f"High EPSS ({round(epss_prob * 100)}%)"}
    if epss_prob >= 0.1:
        return {"label": "Elevated", "level": "elevated",
                "detail": f"EPSS {round(epss_prob * 100)}%"}
    return {"label": "None known", "level": "none", "detail": ""}


def _reference_category(tags: list[str]) -> str:
    """Bucket an NVD reference by its tags for the expander."""
    t = {x.lower() for x in tags}
    if {"exploit"} & t:
        return "exploit"
    if {"patch", "vendor advisory", "release notes", "mitigation"} & t:
        return "vendor"
    if {"third party advisory", "us government resource"} & t:
        return "advisory"
    return "other"


# ─── Data-source catalog (for the /sources status page) ──────────────────────

SOURCE_CATALOG = [
    {
        "key": "nvd", "name": "NVD API v2", "category": "Vulnerability Data",
        "namespace": "nvd",
        "purpose": "Primary CVE feed — descriptions, CVSS scores, CPEs, affected/fixed versions, references, and CWE mappings. Powers the CVE database table and detail pages.",
        "check_url": "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1",
        "doc_url": "https://nvd.nist.gov/developers/vulnerabilities",
        "refresh_note": "Recent-CVE pages cached ~30 min; single CVEs ~24 h.",
    },
    {
        "key": "epss", "name": "EPSS (FIRST.org)", "category": "Risk Scoring",
        "namespace": "epss",
        "purpose": "Exploit Prediction Scoring System — probability a CVE will be exploited in the next 30 days. Feeds the triage score and the EPSS trend sparkline.",
        "check_url": "https://api.first.org/data/v1/epss?cve=CVE-2021-44228",
        "doc_url": "https://www.first.org/epss/",
        "refresh_note": "Scores cached ~12 h; history ~12 h.",
    },
    {
        "key": "kev", "name": "CISA KEV Catalog", "category": "Exploitation Intel",
        "namespace": "kev",
        "purpose": "Known Exploited Vulnerabilities — CVEs confirmed exploited in the wild. The #1 triage signal and the source for the KEV & Ransomware feeds.",
        "check_url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "doc_url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "refresh_note": "Full catalog cached ~6 h.",
    },
    {
        "key": "exploitdb", "name": "Exploit-DB (local CSV)", "category": "Exploitation Intel",
        "namespace": None, "local": True,
        "purpose": "Archive of public exploits, matched by CVE ID. Downloaded once from GitLab and indexed locally for fast, offline lookups.",
        "doc_url": "https://www.exploit-db.com/",
        "refresh_note": "Auto-downloads on first use; refreshes every 7 days.",
    },
    {
        "key": "github", "name": "GitHub API", "category": "Proof-of-Concept",
        "namespace": "github_poc", "github": True,
        "purpose": "Searches public repositories for proof-of-concept exploits, ranked by stars with collection/awesome-lists filtered out.",
        "check_url": "https://api.github.com/rate_limit",
        "doc_url": "https://docs.github.com/en/rest",
        "refresh_note": "PoC results cached ~6 h. Add a GitHub token to raise rate limits.",
    },
    {
        "key": "nuclei", "name": "Nuclei Templates", "category": "Detection",
        "namespace": "nuclei", "github": True,
        "purpose": "Ready-to-run vulnerability detection templates from ProjectDiscovery, resolved directly by the CVE's template path (no token needed).",
        "check_url": "https://api.github.com/repos/projectdiscovery/nuclei-templates",
        "doc_url": "https://github.com/projectdiscovery/nuclei-templates",
        "refresh_note": "Cached ~12 h per CVE.",
    },
    {
        "key": "metasploit", "name": "Metasploit Framework", "category": "Exploitation Intel",
        "namespace": None, "msf_index": True,
        "purpose": "Maps a CVE to Metasploit modules using Rapid7's shipped module metadata. VulNova keeps only a trimmed CVE→module index locally (~1 MB) and auto-refreshes it daily — no token, works offline.",
        "check_url": "https://api.github.com/repos/rapid7/metasploit-framework",
        "doc_url": "https://github.com/rapid7/metasploit-framework",
        "refresh_note": "Local index auto-refreshes every 24 h.",
    },
    {
        "key": "vulhub", "name": "Vulhub", "category": "Proof-of-Concept",
        "namespace": "vulhub",
        "purpose": "Docker-based vulnerable environments for safely reproducing a CVE.",
        "check_url": "https://api.github.com/repos/vulhub/vulhub",
        "doc_url": "https://github.com/vulhub/vulhub",
        "refresh_note": "Environment index cached ~24 h.",
    },
    {
        "key": "ghsa", "name": "GitHub Advisory Database", "category": "Advisories",
        "namespace": "ghsa", "github": True,
        "purpose": "Powers Flare — security advisories for open-source ecosystems (npm, PyPI, Go, Rust…), including the many that have no CVE assigned.",
        "check_url": "https://api.github.com/advisories?per_page=1",
        "doc_url": "https://github.com/advisories",
        "refresh_note": "Advisory pages cached ~1 h.",
    },
    {
        "key": "osv", "name": "OSV.dev (RustSec / PyPI / Go)", "category": "Advisories",
        "namespace": "adv_osv",
        "purpose": "Powers Flare's no-CVE coverage — open-source ecosystem advisories (crates.io/RustSec, PyPI/PYSEC, Go), a large share of which have no CVE assigned.",
        "check_url": "https://osv-vulnerabilities.storage.googleapis.com/crates.io/all.zip",
        "doc_url": "https://osv.dev",
        "refresh_note": "Ecosystem dumps downloaded + cached ~6 h.",
    },
    {
        "key": "news", "name": "Pulse News Feeds (14 sources)", "category": "News",
        "namespace": "news",
        "purpose": "Aggregates RSS/Atom feeds from 14 security outlets (The Hacker News, BleepingComputer, ZDI, Krebs, Talos, …) for the Pulse feed, with entity tagging.",
        "check_url": "https://feeds.feedburner.com/TheHackersNews",
        "doc_url": "/news",
        "refresh_note": "Each feed cached ~15 min.",
    },
]


def _check_connection(url: str, headers: dict, timeout: float = 8.0) -> dict:
    """Lightweight connectivity check — reads only the status, not the body.

    Uses a streaming request so large endpoints (KEV JSON, Metasploit metadata)
    aren't fully downloaded just to confirm reachability.
    """
    last_err = "error"
    for attempt in range(2):
        t0 = time.time()
        try:
            with httpx.stream("GET", url, headers=headers, timeout=timeout,
                              follow_redirects=True) as resp:
                code = resp.status_code
            latency = round((time.time() - t0) * 1000)
            if code == 200:
                return {"status": "ok", "code": 200, "latency_ms": latency}
            if code in (403, 429):
                return {"status": "degraded", "code": code,
                        "latency_ms": latency, "message": "rate limited"}
            return {"status": "degraded", "code": code, "latency_ms": latency}
        except httpx.TimeoutException:
            last_err = "timeout"
        except Exception as e:
            last_err = type(e).__name__
        if attempt == 0:
            time.sleep(0.8)
    return {"status": "error", "code": 0, "message": last_err}


def create_app() -> Flask:
    """Create and configure the Flask application."""
    template_dir = Path(__file__).parent / "templates"
    static_dir = Path(__file__).parent / "static"

    app = Flask(
        __name__,
        template_folder=str(template_dir),
        static_folder=str(static_dir),
    )
    app.config["JSON_SORT_KEYS"] = False

    # Optional HTTP Basic Auth (enabled via env vars) — recommended for public
    # deployments. No-op when the env vars are unset.
    _install_basic_auth(app)

    # ─── Pages ────────────────────────────────────────────────────────

    @app.route("/")
    def index():
        """Main CVE table dashboard."""
        return render_template("index.html")

    @app.route("/news")
    def news():
        """VulNova Pulse — cybersecurity news feed."""
        return render_template("news.html", sources=SOURCES)

    @app.route("/cve/<cve_id>")
    def cve_page(cve_id):
        """Standalone CVE detail page (exploits, timeline, references)."""
        return render_template("cve.html", cve_id=cve_id.upper())

    @app.route("/flare")
    def flare_page():
        """Flare — vendor / GHSA advisories (incl. those with no CVE)."""
        return render_template("flare.html")

    @app.route("/api/advisories", methods=["GET"])
    def api_advisories():
        """Advisories from the GitHub Advisory Database.

        Query params:
            sources: comma list of github,ubuntu,redhat (default all)
            type: reviewed | unreviewed | malware (GHSA only; default reviewed)
            limit: max advisories to gather (default 300)
            refresh: '1' to bypass cache
        """
        try:
            sources_param = request.args.get("sources", "").strip().lower()
            sources = [s for s in sources_param.split(",") if s in ALL_SOURCES] or None
            adv_type = request.args.get("type", "reviewed").strip().lower()
            limit = min(max(int(request.args.get("limit", 600)), 1), 800)
            force = request.args.get("refresh", "") in ("1", "true", "yes")

            config = Config()
            cache = Cache(config.cache_db_path, config.cache_ttl)
            advisories = fetch_all_advisories(
                config=config, cache=cache, sources=sources,
                adv_type=adv_type, limit=limit, force=force,
            )
            rows = [a.to_dict() for a in advisories]
            cache.close()

            no_cve = sum(1 for r in rows if not r["has_cve"])
            ecosystems = sorted({e for r in rows for e in r["ecosystems"]})
            source_names = sorted({r["source"] for r in rows})
            return jsonify({
                "advisories": rows,
                "total": len(rows),
                "no_cve": no_cve,
                "ecosystems": ecosystems,
                "sources": source_names,
            })
        except Exception:
            logger.exception("Unhandled error handling API request")
            return jsonify({"error": "Internal server error"}), 500

    @app.route("/sources")
    def sources_page():
        """Data-source connection status page."""
        return render_template("sources.html")

    @app.route("/api/sources", methods=["GET"])
    def api_sources():
        """Live connectivity + last-refresh status for every data source."""
        try:
            config = Config()
            cache = Cache(config.cache_db_path, config.cache_ttl)
            last_updated = cache.source_last_updated()

            github_token = config.get_api_key("github")

            # Run all network connectivity checks concurrently
            results = {}
            with ThreadPoolExecutor(max_workers=8) as pool:
                futures = {}
                for src in SOURCE_CATALOG:
                    if src.get("local") or not src.get("check_url"):
                        continue
                    hdrs = {"User-Agent": "VulNova/1.0"}
                    if src.get("github") and github_token:
                        hdrs["Authorization"] = f"Bearer {github_token}"
                    futures[pool.submit(_check_connection, src["check_url"], hdrs)] = src["key"]
                for fut in as_completed(futures):
                    results[futures[fut]] = fut.result()

            sources = []
            for src in SOURCE_CATALOG:
                entry = {
                    "key": src["key"],
                    "name": src["name"],
                    "purpose": src["purpose"],
                    "category": src["category"],
                    "doc_url": src.get("doc_url", ""),
                    "refresh_note": src.get("refresh_note", ""),
                }
                # Last refresh from cache namespace
                ns = src.get("namespace")
                lu = last_updated.get(ns) if ns else None
                entry["last_updated"] = lu["last_updated"] if lu else 0
                entry["cached_items"] = lu["count"] if lu else 0

                if src.get("msf_index"):
                    # Metasploit — status from the trimmed local index (offline).
                    msf = MetasploitClient(config=config)
                    if msf.is_available:
                        entry["status"] = "ok"
                        entry["detail"] = f"{msf.module_count:,} CVEs indexed locally (~1 MB)"
                        entry["last_updated"] = msf.last_updated
                    else:
                        chk = results.get(src["key"], {"status": "error", "code": 0})
                        if chk["status"] == "ok":
                            entry["status"] = "ok"
                            entry["detail"] = "index builds on first lookup"
                        else:
                            entry["status"] = "degraded"
                            entry["detail"] = "index not built; source unreachable to build it"
                elif src.get("local"):
                    # Local file source (ExploitDB CSV)
                    edb = ExploitDBClient(config=config)
                    if edb.is_available:
                        entry["status"] = "ok"
                        entry["detail"] = f"{edb.total_exploits} exploits indexed"
                        try:
                            entry["last_updated"] = edb.csv_path.stat().st_mtime
                        except OSError:
                            pass
                    else:
                        entry["status"] = "missing"
                        entry["detail"] = "CSV not downloaded"
                else:
                    chk = results.get(src["key"], {"status": "error", "code": 0})
                    entry["status"] = chk["status"]
                    entry["code"] = chk.get("code", 0)
                    entry["latency_ms"] = chk.get("latency_ms", 0)
                    entry["detail"] = chk.get("message", "")
                sources.append(entry)

            cache.close()
            healthy = sum(1 for s in sources if s["status"] == "ok")
            return jsonify({
                "sources": sources,
                "healthy": healthy,
                "total": len(sources),
                "checked_at": time.time(),
            })
        except Exception:
            logger.exception("Unhandled error handling API request")
            return jsonify({"error": "Internal server error"}), 500

    # ─── News API ─────────────────────────────────────────────────────

    @app.route("/api/news", methods=["GET"])
    def api_news():
        """Aggregated cyber news feed."""
        try:
            sources_param = request.args.get("sources", "").strip()
            handles = [h for h in sources_param.split(",") if h] or None
            limit = min(max(int(request.args.get("limit", 120)), 1), 500)
            per_source = min(max(int(request.args.get("per_source", 25)), 1), 200)
            force = request.args.get("refresh", "") in ("1", "true", "yes")

            config = Config()
            cache = Cache(config.cache_db_path, config.cache_ttl)
            agg = NewsAggregator(cache=cache)

            items = agg.fetch_all(handles=handles, limit_per_source=per_source, force=force)
            rows = [i.to_dict() for i in items[:limit]]
            cache.close()

            return jsonify({
                "articles": rows,
                "total": len(rows),
                "sources": [
                    {"handle": s["handle"], "name": s["name"],
                     "category": s["category"], "accent": s["accent"]}
                    for s in SOURCES
                ],
            })
        except Exception:
            logger.exception("Unhandled error handling API request")
            return jsonify({"error": "Internal server error"}), 500

    # ─── CVE list API ─────────────────────────────────────────────────

    @app.route("/api/cves", methods=["GET"])
    def api_cves():
        """Paginated, enriched CVE list.

        Query params:
            feed: 'recent' (default, NVD) | 'kev' | 'ransomware'
            page: 1-based page number
            size: results per page (max 200)
            keyword: keyword filter
            severity: CVSS v3 severity (recent feed only)
            days: recency window in days (recent feed only)
        """
        try:
            feed = request.args.get("feed", "recent").strip().lower()
            page = max(int(request.args.get("page", 1)), 1)
            size = min(max(int(request.args.get("size", 50)), 1), 2000)
            keyword = request.args.get("keyword", "").strip()
            severity = request.args.get("severity", "").strip()
            days_back = int(request.args.get("days", 0) or 0)
            force = request.args.get("refresh", "") in ("1", "true", "yes")

            config = Config()
            cache = Cache(config.cache_db_path, config.cache_ttl)
            epss_client = EPSSClient(cache=cache)
            kev_client = KEVClient(cache=cache)
            exploitdb = ExploitDBClient(config=config)
            edb_ready = exploitdb.is_available

            if feed in ("kev", "ransomware"):
                payload = _kev_feed(
                    feed, page, size, keyword,
                    epss_client, kev_client, exploitdb, edb_ready, force=force,
                )
            else:
                payload = _recent_feed(
                    page, size, keyword, severity, days_back,
                    config, cache, epss_client, kev_client, exploitdb, edb_ready,
                    force=force,
                )

            cache.close()
            return jsonify(payload)

        except Exception:
            logger.exception("Unhandled error handling API request")
            return jsonify({"error": "Internal server error"}), 500

    # ─── CVE detail API (row expander) ────────────────────────────────

    @app.route("/api/cve/<cve_id>", methods=["GET"])
    def api_cve_detail(cve_id):
        """Full detail for one CVE, including deep exploit intel."""
        try:
            config = Config()
            cache = Cache(config.cache_db_path, config.cache_ttl)

            nvd = NVDClient(config=config, cache=cache)
            epss_client = EPSSClient(cache=cache)
            kev_client = KEVClient(cache=cache)
            exploitdb = ExploitDBClient(config=config)

            cve = nvd.lookup_cve(cve_id)
            if not cve:
                cache.close()
                return jsonify({"error": "CVE not found"}), 404

            epss = epss_client.get_score(cve.cve_id)
            epss_prob = epss.epss if epss else 0.0
            kev_entry = kev_client.get_entry(cve.cve_id)
            in_kev = kev_entry is not None

            # Deep exploit discovery (one CVE at a time — safe for rate limits)
            edb = exploitdb.search_by_cve(cve.cve_id) if exploitdb.is_available else []
            pocs = GitHubPoCClient(config=config, cache=cache).search_all(
                cve.cve_id, exclude_collections=True)
            nuclei = NucleiClient(config=config, cache=cache).search(cve.cve_id)
            msf = MetasploitClient(config=config, cache=cache).search(cve.cve_id)
            vulhub = VulhubClient(cache=cache).search(cve.cve_id)

            triage = compute_triage_score(
                cve_id=cve.cve_id,
                cvss_base=cve.base_score,
                epss_probability=epss_prob,
                in_kev=in_kev,
                has_exploitdb=len(edb) > 0,
                has_github_poc=len(pocs) > 0,
                has_metasploit=len(msf) > 0,
                has_nuclei=len(nuclei) > 0,
                has_vulhub=len(vulhub) > 0,
            )

            exploits = []
            for e in edb[:6]:
                exploits.append({"source": "ExploitDB", "name": e.title[:80],
                                 "url": e.exploit_url, "date": (e.date_published or "")[:10]})
            for p in pocs[:8]:
                exploits.append({"source": "GitHub", "name": p.full_name, "url": p.url,
                                 "stars": p.stars, "date": (p.created_at or "")[:10]})
            for m in msf[:4]:
                exploits.append({"source": "Metasploit", "name": m.name,
                                 "url": m.url, "command": m.use_command})
            for n in nuclei[:4]:
                nname = n.name if n.name and n.name != n.id else n.path
                exploits.append({"source": "Nuclei",
                                 "name": f"{nname} ({n.severity})" if n.severity and n.severity != "unknown" else nname,
                                 "url": n.url})
            for v in vulhub[:3]:
                exploits.append({"source": "Vulhub", "name": v.name, "url": v.url})

            # Build a chronological timeline from all known dated events
            timeline = []
            if cve.published:
                timeline.append({"date": cve.published[:10],
                                 "label": "CVE published to NVD", "kind": "publish"})
            edb_dates = [e.date_published[:10] for e in edb if getattr(e, "date_published", "")]
            if edb_dates:
                timeline.append({"date": min(edb_dates),
                                 "label": "Exploit-DB entry published", "kind": "exploit"})
            # Only count PoC repos created on/after disclosure — GitHub search
            # otherwise surfaces old "awesome-list" repos that predate the CVE.
            pub_day = cve.published[:10] if cve.published else ""
            poc_dates = [
                p.created_at[:10] for p in pocs
                if getattr(p, "created_at", "") and (not pub_day or p.created_at[:10] >= pub_day)
            ]
            if poc_dates:
                timeline.append({"date": min(poc_dates),
                                 "label": "First public PoC on GitHub", "kind": "poc"})
            if kev_entry and kev_entry.date_added:
                timeline.append({"date": kev_entry.date_added[:10],
                                 "label": "Added to CISA KEV (actively exploited)", "kind": "kev"})
            if kev_entry and kev_entry.due_date:
                timeline.append({"date": kev_entry.due_date[:10],
                                 "label": "CISA remediation deadline", "kind": "kev_due"})
            if cve.last_modified:
                lm = cve.last_modified[:10]
                if not cve.published or lm != cve.published[:10]:
                    timeline.append({"date": lm, "label": "CVE record last updated", "kind": "update"})
            timeline.sort(key=lambda x: x["date"])

            # Categorize references
            refs = []
            for r in cve.references:
                refs.append({
                    "url": r.url,
                    "tags": r.tags,
                    "category": _reference_category(r.tags),
                })

            product = _derive_product(cve.cpes, cve.description, cve.affected_products)

            # CVSS breakdown: parse each metric's vector into readable components
            cvss_breakdown = []
            for m in cve.cvss_metrics:
                cvss_breakdown.append({
                    "version": m.get("version", ""),
                    "source_type": m.get("source_type", ""),
                    "base_score": m.get("base_score", 0.0),
                    "severity": m.get("severity", ""),
                    "vector": m.get("vector", ""),
                    "exploitability_score": m.get("exploitability_score", 0.0),
                    "impact_score": m.get("impact_score", 0.0),
                    "components": parse_vector(m.get("vector", "")),
                })

            # CWE details + CAPEC attack patterns
            cwe_details = [lookup_cwe(w) for w in cve.weaknesses]

            # Affected / fixed versions (from CNA data)
            affected_versions = []
            for ap in cve.affected_products:
                if ap.get("affected_ranges") or ap.get("fixed_versions"):
                    affected_versions.append({
                        "vendor": ap.get("vendor", ""),
                        "product": ap.get("product", ""),
                        "ranges": ap.get("affected_ranges", []),
                        "fixed": ap.get("fixed_versions", []),
                        "default_status": ap.get("default_status", ""),
                    })

            # EPSS trend history
            epss_history = epss_client.get_history(cve.cve_id)

            # Related CVEs — other CVEs on the same product (best-effort, cached).
            # Use the product name only; the full CNA vendor string (e.g.
            # "Apache Software Foundation") is too restrictive for keyword search.
            related = []
            rel_query = ""
            if cve.affected_products:
                ap0 = cve.affected_products[0]
                rel_query = (ap0.get("product") or ap0.get("vendor") or "").strip()
            if not rel_query and product.get("label"):
                rel_query = product["label"].split(" · ")[0].split(" / ")[-1]
            if rel_query:
                for rc in nvd.search_by_keyword(rel_query, results_per_page=8):
                    if rc.cve_id == cve.cve_id:
                        continue
                    related.append({
                        "cve_id": rc.cve_id,
                        "cvss_score": rc.base_score,
                        "severity": rc.severity,
                        "published": rc.published[:10] if rc.published else "",
                    })
                    if len(related) >= 6:
                        break

            cache.close()
            return jsonify({
                "cve_id": cve.cve_id,
                "description": cve.description,
                "published": cve.published,
                "last_modified": cve.last_modified,
                "cvss_score": cve.base_score,
                "severity": cve.severity,
                "vector": cve.cvss.vector_string if cve.cvss else "",
                "cvss_breakdown": cvss_breakdown,
                "epss_percent": round(epss_prob * 100, 2),
                "epss_history": epss_history,
                "in_kev": in_kev,
                "kev_details": kev_entry.to_dict() if kev_entry else None,
                "cve_tags": cve.cve_tags,
                "triage_score": triage.total_score,
                "triage_label": triage.severity_label,
                "recommendation": triage.recommendation,
                "weaknesses": cve.weaknesses,
                "cwe_details": cwe_details,
                "product": product,
                "affected_versions": affected_versions,
                "cpes": cve.cpes[:20],
                "exploits": exploits,
                "exploit_count": len(exploits),
                "references": refs,
                "timeline": timeline,
                "related": related,
            })

        except Exception:
            logger.exception("Unhandled error handling API request")
            return jsonify({"error": "Internal server error"}), 500

    @app.route("/api/refresh-status", methods=["GET"])
    def api_refresh_status():
        """Report auto-refresh state: last run, next run, and interval."""
        try:
            from vulnova.core.refresh import get_refresh_status
            return jsonify(get_refresh_status())
        except Exception:
            logger.exception("Unhandled error in /api/refresh-status")
            return jsonify({"error": "Internal server error"}), 500

    # Optional in-process auto-refresh scheduler. Enable by setting
    # VULNOVA_REFRESH_HOURS (e.g. 6) or launching `vulnova web --refresh-hours 6`.
    try:
        _hours = float(os.environ.get("VULNOVA_REFRESH_HOURS", "0") or 0)
    except ValueError:
        _hours = 0.0
    if _hours > 0:
        from vulnova.core.refresh import start_background_refresh
        start_background_refresh(_hours)

    return app


# ─── Feed builders ────────────────────────────────────────────────────────────

def _recent_feed(page, size, keyword, severity, days_back,
                 config, cache, epss_client, kev_client, exploitdb, edb_ready,
                 force=False):
    """Build a page of the NVD recent-CVE feed with full enrichment."""
    nvd = NVDClient(config=config, cache=cache)
    # On a forced refresh, warm the KEV catalog once so per-row lookups below
    # use the freshly fetched data (get_entry reads the in-memory catalog).
    if force:
        kev_client.get_all(force=True)
    cves, total = nvd.list_cves(
        page=page, results_per_page=size,
        keyword=keyword, cvss_severity=severity, days_back=days_back,
        force=force,
    )
    if not cves:
        return {"rows": [], "total": total, "page": page, "size": size, "pages": 0, "feed": "recent"}

    epss_scores = epss_client.get_scores_bulk([c.cve_id for c in cves])
    rows = []
    for cve in cves:
        epss = epss_scores.get(cve.cve_id)
        epss_prob = epss.epss if epss else 0.0
        kev_entry = kev_client.get_entry(cve.cve_id)
        in_kev = kev_entry is not None
        has_edb = exploitdb.has_exploit(cve.cve_id) if edb_ready else False
        ransomware = kev_entry.known_ransomware_use if kev_entry else ""

        triage = compute_triage_score(
            cve_id=cve.cve_id, cvss_base=cve.base_score,
            epss_probability=epss_prob, in_kev=in_kev, has_exploitdb=has_edb,
        )
        product = _derive_product(cve.cpes, cve.description, cve.affected_products)

        rows.append({
            "cve_id": cve.cve_id,
            "description": cve.description,
            "published": cve.published[:10] if cve.published else "",
            "last_modified": cve.last_modified[:10] if cve.last_modified else "",
            "cvss_score": cve.base_score,
            "cvss_version": cve.cvss.version if cve.cvss else "",
            "severity": cve.severity,
            "epss_percent": round(epss_prob * 100, 2),
            "in_kev": in_kev,
            "kev_date_added": kev_entry.date_added if kev_entry else "",
            "kev_ransomware": ransomware,
            "triage_score": triage.total_score,
            "triage_label": triage.severity_label,
            "product": product,
            "exploit_status": _exploit_status(in_kev, ransomware, epss_prob, has_edb),
            "weaknesses": cve.weaknesses,
            "cve_tags": cve.cve_tags,
            "reference_count": len(cve.references),
            "cvss_pending": False,
            "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve.cve_id}",
        })

    total_pages = (total + size - 1) // size
    return {"rows": rows, "total": total, "page": page, "size": size,
            "pages": total_pages, "feed": "recent"}


def _kev_feed(feed, page, size, keyword, epss_client, kev_client, exploitdb, edb_ready,
              force=False):
    """Build a page from the CISA KEV catalog (optionally ransomware-only)."""
    entries = kev_client.get_all(force=force)

    if feed == "ransomware":
        entries = [e for e in entries if (e.known_ransomware_use or "").lower() == "known"]

    if keyword:
        kw = keyword.lower()
        entries = [
            e for e in entries
            if kw in f"{e.cve_id} {e.vendor} {e.product} {e.vulnerability_name} {e.short_description}".lower()
        ]

    # Newest additions first
    entries.sort(key=lambda e: e.date_added, reverse=True)
    total = len(entries)
    start = (page - 1) * size
    page_entries = entries[start:start + size]

    epss_scores = epss_client.get_scores_bulk([e.cve_id for e in page_entries])
    rows = []
    for e in page_entries:
        epss = epss_scores.get(e.cve_id)
        epss_prob = epss.epss if epss else 0.0
        has_edb = exploitdb.has_exploit(e.cve_id) if edb_ready else False

        triage = compute_triage_score(
            cve_id=e.cve_id, cvss_base=0.0,
            epss_probability=epss_prob, in_kev=True, has_exploitdb=has_edb,
        )
        vendor, product = _prettify(e.vendor), _prettify(e.product)
        label = f"{vendor} / {product}" if product else vendor

        rows.append({
            "cve_id": e.cve_id,
            "description": e.short_description or e.vulnerability_name,
            "published": "",  # KEV doesn't carry the CVE publish date
            "last_modified": "",
            "cvss_score": 0.0,
            "cvss_version": "",
            "severity": "",
            "epss_percent": round(epss_prob * 100, 2),
            "in_kev": True,
            "kev_date_added": e.date_added,
            "kev_ransomware": e.known_ransomware_use,
            "triage_score": triage.total_score,
            "triage_label": triage.severity_label,
            "product": {"vendor": vendor, "product": product, "label": label, "more": 0},
            "exploit_status": _exploit_status(True, e.known_ransomware_use, epss_prob, has_edb),
            "weaknesses": [],
            "reference_count": 0,
            "cvss_pending": True,  # CVSS/description fill in on expand
            "nvd_url": f"https://nvd.nist.gov/vuln/detail/{e.cve_id}",
        })

    total_pages = (total + size - 1) // size
    return {"rows": rows, "total": total, "page": page, "size": size,
            "pages": total_pages, "feed": feed}


def run_web(host: str = "127.0.0.1", port: int = 5000, debug: bool = False,
            refresh_hours: float = 0.0):
    """Run the VulNova web server.

    Args:
        refresh_hours: if > 0, start an in-process scheduler that force-refreshes
            all data sources on that interval (e.g. 6). 0 disables it.
    """
    if refresh_hours and refresh_hours > 0:
        os.environ["VULNOVA_REFRESH_HOURS"] = str(refresh_hours)
    app = create_app()
    app.run(host=host, port=port, debug=debug)
