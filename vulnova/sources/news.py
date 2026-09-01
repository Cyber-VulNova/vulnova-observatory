"""Cyber news aggregator — VulNova Pulse.

Pulls RSS/Atom feeds from a curated set of cybersecurity news sources,
normalizes them into a common article shape, and caches the results in
SQLite so the feed loads fast and works offline between refreshes.
"""

import html
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import feedparser
import httpx

from vulnova.core.cache import Cache
from vulnova.core.tagger import extract_tags


# ─── Source Catalog ───────────────────────────────────────────────────────────
# Each source: handle, display name, feed URL, category, and an accent color
# used by the UI. "kind" groups sources for filtering.

SOURCES: list[dict] = [
    {
        "handle": "thehackernews",
        "name": "The Hacker News",
        "url": "https://feeds.feedburner.com/TheHackersNews",
        "category": "News",
        "accent": "#e94560",
    },
    {
        "handle": "bleepingcomputer",
        "name": "BleepingComputer",
        "url": "https://www.bleepingcomputer.com/feed/",
        "category": "News",
        "accent": "#00b3b3",
    },
    {
        "handle": "theregister",
        "name": "The Register · Security",
        "url": "https://www.theregister.com/security/headlines.atom",
        "category": "News",
        "accent": "#ff6600",
    },
    {
        "handle": "securityweek",
        "name": "SecurityWeek",
        "url": "https://www.securityweek.com/feed/",
        "category": "News",
        "accent": "#3498db",
    },
    {
        "handle": "darkreading",
        "name": "Dark Reading",
        "url": "https://www.darkreading.com/rss.xml",
        "category": "News",
        "accent": "#9b59b6",
    },
    {
        "handle": "therecord",
        "name": "The Record",
        "url": "https://therecord.media/feed/",
        "category": "News",
        "accent": "#1abc9c",
    },
    {
        "handle": "krebs",
        "name": "Krebs on Security",
        "url": "https://krebsonsecurity.com/feed/",
        "category": "News",
        "accent": "#e67e22",
    },
    {
        "handle": "sans_isc",
        "name": "SANS Internet Storm Center",
        "url": "https://isc.sans.edu/rssfeed_full.xml",
        "category": "Research",
        "accent": "#c0392b",
    },
    {
        "handle": "unit42",
        "name": "Palo Alto Unit 42",
        "url": "https://unit42.paloaltonetworks.com/feed/",
        "category": "Research",
        "accent": "#f39c12",
    },
    {
        "handle": "talos",
        "name": "Cisco Talos Intelligence",
        "url": "https://blog.talosintelligence.com/rss/",
        "category": "Research",
        "accent": "#2980b9",
    },
    {
        "handle": "rapid7",
        "name": "Rapid7 Blog",
        "url": "https://www.rapid7.com/blog/rss/",
        "category": "Research",
        "accent": "#e94560",
    },
    {
        "handle": "projectzero",
        "name": "Google Project Zero",
        "url": "https://googleprojectzero.blogspot.com/feeds/posts/default",
        "category": "Research",
        "accent": "#4285f4",
    },
    {
        "handle": "zdi_published",
        "name": "ZDI · Published Advisories",
        "url": "https://www.zerodayinitiative.com/rss/published/",
        "category": "Advisories",
        "accent": "#e74c3c",
    },
    {
        "handle": "zdi_upcoming",
        "name": "ZDI · Upcoming Advisories",
        "url": "https://www.zerodayinitiative.com/rss/upcoming/",
        "category": "Advisories",
        "accent": "#f1c40f",
    },
    # ── Vendor threat-research blogs (free RSS) ──────────────────────────
    {
        "handle": "msft_security",
        "name": "Microsoft Security Blog",
        "url": "https://www.microsoft.com/en-us/security/blog/feed/",
        "category": "Research",
        "accent": "#00a4ef",
    },
    {
        "handle": "eset",
        "name": "ESET WeLiveSecurity",
        "url": "https://www.welivesecurity.com/en/rss/feed/",
        "category": "Research",
        "accent": "#00a9e0",
    },
    {
        "handle": "sentinellabs",
        "name": "SentinelLabs",
        "url": "https://www.sentinelone.com/labs/feed/",
        "category": "Research",
        "accent": "#6b0aea",
    },
    {
        "handle": "sophos_xops",
        "name": "Sophos X-Ops",
        "url": "https://news.sophos.com/en-us/category/threat-research/feed/",
        "category": "Research",
        "accent": "#0a5ed7",
    },
    {
        "handle": "watchtowr",
        "name": "watchTowr Labs",
        "url": "https://labs.watchtowr.com/rss/",
        "category": "Research",
        "accent": "#00e0a4",
    },
]

SOURCE_BY_HANDLE = {s["handle"]: s for s in SOURCES}

_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")

USER_AGENT = (
    "Mozilla/5.0 (compatible; VulNova/1.0; +https://github.com/vulnova/vulnova)"
)


@dataclass
class NewsItem:
    """A normalized news article from any source."""
    title: str
    link: str
    summary: str
    published: str          # ISO 8601 string
    published_ts: float     # epoch seconds for sorting
    source_handle: str
    source_name: str
    category: str
    accent: str
    tags: list = field(default_factory=list)  # [{"type","label"}, ...]

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "link": self.link,
            "summary": self.summary,
            "published": self.published,
            "published_ts": self.published_ts,
            "source_handle": self.source_handle,
            "source_name": self.source_name,
            "category": self.category,
            "accent": self.accent,
            "tags": self.tags,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "NewsItem":
        # Tolerate cached entries created before a field was added.
        known = {
            "title", "link", "summary", "published", "published_ts",
            "source_handle", "source_name", "category", "accent", "tags",
        }
        filtered = {k: v for k, v in d.items() if k in known}
        filtered.setdefault("tags", [])
        return cls(**filtered)


def _clean_text(raw: str, limit: int = 320) -> str:
    """Strip HTML tags, decode entities, and collapse whitespace."""
    if not raw:
        return ""
    text = _TAG_RE.sub(" ", raw)
    # Decode all HTML entities (named + numeric, e.g. &#x3f; &amp;)
    text = html.unescape(text)
    text = _WS_RE.sub(" ", text).strip()
    if len(text) > limit:
        text = text[:limit].rsplit(" ", 1)[0] + "…"
    return text


def _entry_timestamp(entry) -> tuple[str, float]:
    """Extract an ISO date + epoch timestamp from a feed entry."""
    for key in ("published_parsed", "updated_parsed"):
        parsed = entry.get(key)
        if parsed:
            try:
                ts = time.mktime(parsed)
                iso = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
                return iso, ts
            except (OverflowError, ValueError, OSError):
                continue
    # Fallback: no date
    return "", 0.0


class NewsAggregator:
    """Fetches, parses, caches, and merges cybersecurity news feeds."""

    NAMESPACE = "news"
    CACHE_TTL = 900  # 15 minutes

    def __init__(self, cache: Optional[Cache] = None, max_workers: int = 8):
        self.cache = cache
        self.max_workers = max_workers

    # ─── Single source ────────────────────────────────────────────────

    def fetch_source(self, handle: str, force: bool = False) -> list[NewsItem]:
        """Fetch and parse a single source feed (cached).

        Args:
            handle: Source handle from the SOURCES catalog.
            force: Bypass the cache and re-fetch.

        Returns:
            List of NewsItem for that source (newest first).
        """
        source = SOURCE_BY_HANDLE.get(handle)
        if not source:
            return []

        if self.cache and not force:
            cached = self.cache.get(self.NAMESPACE, handle)
            if cached is not None:
                return [NewsItem.from_dict(i) for i in cached]

        items = self._download_and_parse(source)

        if self.cache:
            self.cache.set(
                self.NAMESPACE, handle,
                [i.to_dict() for i in items], ttl=self.CACHE_TTL,
            )
        return items

    def _download_and_parse(self, source: dict) -> list[NewsItem]:
        """Download the raw feed and parse it into NewsItems.

        Retries a couple of times to absorb transient connection errors,
        which some feeds (e.g. The Register) return intermittently.
        """
        headers = {
            "User-Agent": USER_AGENT,
            "Accept": (
                "application/rss+xml, application/atom+xml, "
                "application/xml, text/xml, */*"
            ),
        }
        content = None
        for attempt in range(3):
            try:
                resp = httpx.get(
                    source["url"],
                    headers=headers,
                    timeout=20.0,
                    follow_redirects=True,
                )
                resp.raise_for_status()
                content = resp.content
                break
            except Exception:
                if attempt < 2:
                    time.sleep(1.5)
                continue
        if content is None:
            return []

        parsed = feedparser.parse(content)
        items: list[NewsItem] = []

        for entry in parsed.entries:
            title = _clean_text(entry.get("title", ""), limit=200)
            link = entry.get("link", "")
            if not title or not link:
                continue

            summary = _clean_text(
                entry.get("summary", entry.get("description", "")), limit=320
            )
            iso, ts = _entry_timestamp(entry)
            tags = extract_tags(title, summary)

            items.append(NewsItem(
                title=title,
                link=link,
                summary=summary,
                published=iso,
                published_ts=ts,
                source_handle=source["handle"],
                source_name=source["name"],
                category=source["category"],
                accent=source["accent"],
                tags=tags,
            ))

        # Newest first
        items.sort(key=lambda i: i.published_ts, reverse=True)
        return items

    # ─── All sources ──────────────────────────────────────────────────

    def fetch_all(
        self,
        handles: Optional[list[str]] = None,
        limit_per_source: int = 25,
        force: bool = False,
    ) -> list[NewsItem]:
        """Fetch multiple sources concurrently and merge them.

        Only the network download/parse runs in worker threads. Cache reads
        and writes happen on the calling thread, because the SQLite cache
        connection is not safe to share across threads.

        Args:
            handles: Optional subset of source handles. Defaults to all.
            limit_per_source: Max items kept from each source.
            force: Bypass cache and re-fetch all.

        Returns:
            Merged list of NewsItems, newest first.
        """
        selected = handles or [s["handle"] for s in SOURCES]
        results_by_handle: dict[str, list[NewsItem]] = {}
        to_fetch: list[str] = []

        # 1. Cache reads (calling thread only)
        for h in selected:
            if h not in SOURCE_BY_HANDLE:
                continue
            if self.cache and not force:
                cached = self.cache.get(self.NAMESPACE, h)
                if cached is not None:
                    results_by_handle[h] = [NewsItem.from_dict(i) for i in cached]
                    continue
            to_fetch.append(h)

        # 2. Parallel network fetch (worker threads, no cache access)
        if to_fetch:
            with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
                future_map = {
                    pool.submit(self._download_and_parse, SOURCE_BY_HANDLE[h]): h
                    for h in to_fetch
                }
                for future in as_completed(future_map):
                    h = future_map[future]
                    try:
                        items = future.result()
                    except Exception:
                        items = []
                    results_by_handle[h] = items
                    # 3. Cache write (calling thread)
                    if self.cache:
                        self.cache.set(
                            self.NAMESPACE, h,
                            [i.to_dict() for i in items], ttl=self.CACHE_TTL,
                        )

        # 4. Merge, newest first
        merged: list[NewsItem] = []
        for h in selected:
            merged.extend(results_by_handle.get(h, [])[:limit_per_source])
        merged.sort(key=lambda i: i.published_ts, reverse=True)
        return merged

    def source_status(self) -> list[dict]:
        """Return per-source metadata plus cached item counts (no fetch)."""
        status = []
        for s in SOURCES:
            count = 0
            if self.cache:
                cached = self.cache.get(self.NAMESPACE, s["handle"])
                if cached is not None:
                    count = len(cached)
            status.append({**s, "cached_items": count})
        return status
