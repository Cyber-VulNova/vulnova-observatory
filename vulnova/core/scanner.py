"""Asset Scanning - URL fingerprinting and technology detection.

Fingerprints live URLs to detect technologies (web servers, frameworks,
CMS, libraries) and then auto-triggers CVE scans per detected tech.

Uses HTTP headers, HTML meta tags, cookies, and response patterns
for lightweight fingerprinting without requiring heavy dependencies.
"""

import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

import httpx

from vulnova.core.cache import Cache


@dataclass
class DetectedTechnology:
    """A detected technology/component on a target URL."""
    name: str
    version: str = ""
    category: str = ""  # e.g., "web-server", "cms", "framework", "js-library"
    confidence: int = 100  # 0-100
    cpe_hint: str = ""  # Suggested CPE search query

    @property
    def search_query(self) -> str:
        """Generate a search query for CVE lookup."""
        if self.version:
            return f"{self.name} {self.version}"
        return self.name

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "category": self.category,
            "confidence": self.confidence,
            "cpe_hint": self.cpe_hint,
        }


@dataclass
class ScanResult:
    """Result of scanning a URL for technologies."""
    url: str
    status_code: int = 0
    title: str = ""
    technologies: list[DetectedTechnology] = field(default_factory=list)
    headers: dict = field(default_factory=dict)
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "status_code": self.status_code,
            "title": self.title,
            "technologies": [t.to_dict() for t in self.technologies],
            "error": self.error,
        }


# ─── Fingerprint Rules ────────────────────────────────────────────────────────
# Each rule: (header/pattern, regex, tech_name, category, version_group)

HEADER_FINGERPRINTS = [
    # Web Servers
    ("server", r"Apache[/ ]?([\d.]+)?", "Apache HTTP Server", "web-server", 1),
    ("server", r"nginx[/ ]?([\d.]+)?", "nginx", "web-server", 1),
    ("server", r"Microsoft-IIS[/ ]?([\d.]+)?", "Microsoft IIS", "web-server", 1),
    ("server", r"LiteSpeed[/ ]?([\d.]+)?", "LiteSpeed", "web-server", 1),
    ("server", r"Caddy", "Caddy", "web-server", None),
    ("server", r"openresty[/ ]?([\d.]+)?", "OpenResty", "web-server", 1),
    ("server", r"Tomcat[/ ]?([\d.]+)?", "Apache Tomcat", "web-server", 1),
    ("server", r"Jetty\(([\d.]+)\)", "Eclipse Jetty", "web-server", 1),
    # Frameworks / Languages
    ("x-powered-by", r"PHP[/ ]?([\d.]+)?", "PHP", "language", 1),
    ("x-powered-by", r"ASP\.NET", "ASP.NET", "framework", None),
    ("x-powered-by", r"Express", "Express.js", "framework", None),
    ("x-powered-by", r"Next\.js[/ ]?([\d.]+)?", "Next.js", "framework", 1),
    ("x-aspnet-version", r"([\d.]+)", "ASP.NET", "framework", 1),
    ("x-drupal-cache", r"", "Drupal", "cms", None),
    ("x-generator", r"Drupal\s*([\d.]+)?", "Drupal", "cms", 1),
    ("x-generator", r"WordPress\s*([\d.]+)?", "WordPress", "cms", 1),
    # Security headers (informational)
    ("x-frame-options", r"", None, None, None),  # Skip - just informational
]

COOKIE_FINGERPRINTS = [
    (r"PHPSESSID", "PHP", "language"),
    (r"JSESSIONID", "Java", "language"),
    (r"ASP\.NET_SessionId", "ASP.NET", "framework"),
    (r"wp-settings-", "WordPress", "cms"),
    (r"drupal", "Drupal", "cms"),
    (r"laravel_session", "Laravel", "framework"),
    (r"XSRF-TOKEN", "Angular/Laravel", "framework"),
    (r"csrftoken", "Django", "framework"),
    (r"_rails_session", "Ruby on Rails", "framework"),
]

HTML_FINGERPRINTS = [
    # Meta generators
    (r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s*([\d.]*)', "WordPress", "cms", 1),
    (r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Joomla[!]?\s*([\d.]*)', "Joomla", "cms", 1),
    (r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Drupal\s*([\d.]*)', "Drupal", "cms", 1),
    (r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Hugo\s*([\d.]*)', "Hugo", "ssg", 1),
    # Script / CSS patterns
    (r'/wp-content/', "WordPress", "cms", None),
    (r'/wp-includes/', "WordPress", "cms", None),
    (r'jquery[.-]?([\d.]+)?\.min\.js', "jQuery", "js-library", 1),
    (r'bootstrap[.-]?([\d.]+)?\.min\.(js|css)', "Bootstrap", "css-framework", 1),
    (r'react[.-]production\.min\.js', "React", "js-framework", None),
    (r'vue[.-]?([\d.]+)?\.min\.js', "Vue.js", "js-framework", 1),
    (r'angular[.-]?([\d.]+)?\.min\.js', "Angular", "js-framework", 1),
    (r'/_next/', "Next.js", "framework", None),
    (r'/__nuxt/', "Nuxt.js", "framework", None),
]


class AssetScanner:
    """Fingerprint live URLs and detect technologies."""

    NAMESPACE = "scanner"

    def __init__(self, cache: Optional[Cache] = None):
        self.cache = cache

    def scan_url(self, url: str, timeout: float = 15.0) -> ScanResult:
        """Fingerprint a URL and detect its technology stack.

        Args:
            url: Target URL to scan.
            timeout: Request timeout in seconds.

        Returns:
            ScanResult with detected technologies.
        """
        # Normalize URL
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        # Check cache
        if self.cache:
            cached = self.cache.get(self.NAMESPACE, url)
            if cached:
                result = ScanResult(url=url)
                result.status_code = cached.get("status_code", 0)
                result.title = cached.get("title", "")
                result.technologies = [
                    DetectedTechnology(**t) for t in cached.get("technologies", [])
                ]
                return result

        result = ScanResult(url=url)

        try:
            resp = httpx.get(
                url,
                timeout=timeout,
                follow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (compatible; VulNova/1.0)"},
                verify=False,  # Allow self-signed certs for scanning
            )
            result.status_code = resp.status_code
            result.headers = dict(resp.headers)
        except httpx.ConnectError:
            result.error = "Connection refused or host unreachable"
            return result
        except httpx.TimeoutException:
            result.error = "Connection timed out"
            return result
        except httpx.HTTPError as e:
            result.error = f"HTTP error: {e}"
            return result
        except Exception as e:
            result.error = f"Scan error: {e}"
            return result

        body = resp.text[:50000]  # Limit body parsing to first 50KB

        # Extract title
        title_match = re.search(r"<title[^>]*>([^<]+)</title>", body, re.IGNORECASE)
        if title_match:
            result.title = title_match.group(1).strip()

        # Run fingerprinting
        techs: dict[str, DetectedTechnology] = {}

        # Header-based fingerprinting
        self._fingerprint_headers(resp.headers, techs)

        # Cookie-based fingerprinting
        cookie_header = resp.headers.get("set-cookie", "")
        self._fingerprint_cookies(cookie_header, techs)

        # HTML-based fingerprinting
        self._fingerprint_html(body, techs)

        result.technologies = list(techs.values())

        # Cache result for 1 hour
        if self.cache:
            self.cache.set(self.NAMESPACE, url, result.to_dict(), ttl=3600)

        return result

    def _fingerprint_headers(self, headers, techs: dict) -> None:
        """Detect technologies from HTTP response headers."""
        for header_name, pattern, tech_name, category, ver_group in HEADER_FINGERPRINTS:
            if tech_name is None:
                continue
            header_val = headers.get(header_name, "")
            if not header_val:
                continue
            match = re.search(pattern, header_val, re.IGNORECASE)
            if match:
                version = ""
                if ver_group and match.lastindex and match.lastindex >= ver_group:
                    version = match.group(ver_group) or ""
                key = f"{tech_name}:{version}"
                if key not in techs:
                    techs[key] = DetectedTechnology(
                        name=tech_name,
                        version=version,
                        category=category,
                        confidence=90,
                    )

    def _fingerprint_cookies(self, cookie_header: str, techs: dict) -> None:
        """Detect technologies from cookies."""
        for pattern, tech_name, category in COOKIE_FINGERPRINTS:
            if re.search(pattern, cookie_header, re.IGNORECASE):
                key = f"{tech_name}:"
                if key not in techs:
                    techs[key] = DetectedTechnology(
                        name=tech_name,
                        version="",
                        category=category,
                        confidence=70,
                    )

    def _fingerprint_html(self, body: str, techs: dict) -> None:
        """Detect technologies from HTML content."""
        for pattern, tech_name, category, ver_group in HTML_FINGERPRINTS:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                version = ""
                if ver_group and match.lastindex and match.lastindex >= ver_group:
                    version = match.group(ver_group) or ""
                key = f"{tech_name}:{version}"
                if key not in techs:
                    techs[key] = DetectedTechnology(
                        name=tech_name,
                        version=version,
                        category=category,
                        confidence=80,
                    )
