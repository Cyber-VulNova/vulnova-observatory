"""GitHub PoC (Proof of Concept) discovery.

Uses the GitHub Search API to find proof-of-concept repositories for a CVE,
ranked by stars with aggregator/awesome-list repos filtered out and repos that
name the CVE promoted to the top.
"""

from dataclasses import dataclass
from typing import Optional

import httpx

from vulnova.core.cache import Cache
from vulnova.core.config import Config


# Repo names/descriptions that indicate an aggregator/list rather than a PoC.
_COLLECTION_TERMS = (
    "awesome", "awesome-", "-list", "list-of", "collection", "cheat", "cheatsheet",
    "cheat-sheet", "resources", "roadmap", "study", "notes", "bookmarks", "books",
    "payloadsallthethings", "payloads-all", "all-poc", "poc-collection", "cve-poc-list",
    "writeups", "write-ups", "curated", "compilation", "database-of", "knowledge-base",
    "security-list", "pentest-", "hacktricks", "wiki", "how-to", "how_to", "howto",
    "-guide", "guide-", "tutorial", "learning", "learn-", "top-10", "top10",
    "secure-a-", "damn-vulnerable", "vulnerable-app", "vulnerable-application",
    "penetration_testing_poc", "penetration-testing", "malwoverview", "reference-",
)


def is_collection_repo(full_name: str, description: str = "") -> bool:
    """Heuristic: True if a repo looks like an aggregator/list, not a real PoC."""
    haystack = f"{full_name} {description}".lower()
    return any(term in haystack for term in _COLLECTION_TERMS)


@dataclass
class GitHubPoC:
    """A GitHub Proof-of-Concept repository."""
    name: str
    full_name: str
    url: str
    description: str
    stars: int
    forks: int
    created_at: str
    updated_at: str
    language: str
    source: str  # "trickest" or "github_search"

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "full_name": self.full_name,
            "url": self.url,
            "description": self.description,
            "stars": self.stars,
            "forks": self.forks,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "language": self.language,
            "source": self.source,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "GitHubPoC":
        return cls(**data)


class GitHubPoCClient:
    """Client for discovering GitHub PoC exploits."""

    NAMESPACE = "github_poc"

    def __init__(self, config: Optional[Config] = None, cache: Optional[Cache] = None):
        self.config = config or Config()
        self.cache = cache
        self._github_token = self.config.get_api_key("github")

    def _github_headers(self) -> dict:
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "VulNova/1.0",
        }
        if self._github_token:
            headers["Authorization"] = f"Bearer {self._github_token}"
        return headers

    def search_github(
        self,
        cve_id: str,
        min_stars: int = 0,
        max_forks_only: bool = True,
        limit: int = 10,
    ) -> list[GitHubPoC]:
        """Search GitHub API for PoC repositories.

        Searches for repositories matching the CVE ID, ranked by stars.
        Optionally filters out repos that appear to be forks.

        Args:
            cve_id: CVE identifier.
            min_stars: Minimum stars filter.
            max_forks_only: If True, deprioritize repos that are forks.
            limit: Maximum results.

        Returns:
            List of GitHubPoC entries from GitHub Search.
        """
        cve_id = cve_id.upper()
        cache_key = f"github:{cve_id}:{min_stars}"

        if self.cache:
            cached = self.cache.get(self.NAMESPACE, cache_key)
            if cached is not None:
                return [GitHubPoC.from_dict(p) for p in cached]

        search_url = "https://api.github.com/search/repositories"
        params = {
            "q": f"{cve_id} in:name,description,readme",
            "sort": "stars",
            "order": "desc",
            "per_page": min(limit * 2, 30),  # Fetch extra to filter
        }

        try:
            resp = httpx.get(
                search_url,
                params=params,
                headers=self._github_headers(),
                timeout=15.0,
            )
            resp.raise_for_status()
            data = resp.json()
        except (httpx.HTTPError, Exception):
            return []

        pocs = []
        for item in data.get("items", []):
            # Filter forks if requested
            if max_forks_only and item.get("fork", False):
                continue
            # Filter by stars
            if item.get("stargazers_count", 0) < min_stars:
                continue

            pocs.append(GitHubPoC(
                name=item.get("name", ""),
                full_name=item.get("full_name", ""),
                url=item.get("html_url", ""),
                description=item.get("description", "") or "",
                stars=item.get("stargazers_count", 0),
                forks=item.get("forks_count", 0),
                created_at=item.get("created_at", ""),
                updated_at=item.get("updated_at", ""),
                language=item.get("language", "") or "",
                source="github_search",
            ))

            if len(pocs) >= limit:
                break

        # Sort by stars descending
        pocs.sort(key=lambda p: p.stars, reverse=True)

        if self.cache:
            self.cache.set(self.NAMESPACE, cache_key, [p.to_dict() for p in pocs], ttl=21600)

        return pocs

    def search_all(self, cve_id: str, exclude_collections: bool = False) -> list[GitHubPoC]:
        """Search GitHub for PoC repositories, filter and rank the results.

        Args:
            cve_id: CVE identifier.
            exclude_collections: When True, drop aggregator/awesome-list style
                repos that merely mention the CVE (higher-signal PoC results).

        Returns:
            Deduplicated list of PoCs, CVE-in-name repos first, then by stars.
        """
        # Fetch a wider candidate pool so dedicated (lower-star) PoC repos
        # survive collection filtering and CVE-in-name ranking.
        github_results = self.search_github(cve_id, limit=30)

        # Deduplicate by full_name
        seen = set()
        combined = []
        for poc in github_results:
            if poc.full_name.lower() not in seen:
                seen.add(poc.full_name.lower())
                combined.append(poc)

        if exclude_collections:
            filtered = [p for p in combined if not is_collection_repo(p.full_name, p.description)]
            # Keep the filter from wiping out everything on false positives
            combined = filtered if filtered else combined

        # Rank: repos that name the CVE (strong PoC signal) first, then by stars
        cid = cve_id.lower()
        combined.sort(
            key=lambda p: (cid in p.full_name.lower(), p.stars),
            reverse=True,
        )
        return combined
