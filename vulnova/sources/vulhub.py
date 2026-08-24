"""Vulhub integration - Docker-based PoC environments.

Auto-discovers Vulhub environments that match a given CVE.
Reference: https://github.com/vulhub/vulhub
"""

import re
from dataclasses import dataclass
from typing import Optional

import httpx

from vulnova.core.cache import Cache


VULHUB_API_BASE = "https://api.github.com/repos/vulhub/vulhub"
VULHUB_RAW_BASE = "https://raw.githubusercontent.com/vulhub/vulhub/master"


@dataclass
class VulhubEnvironment:
    """A Vulhub Docker-based PoC environment."""
    name: str
    path: str
    url: str
    cve_ids: list[str]
    readme_url: str
    docker_compose_url: str

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "path": self.path,
            "url": self.url,
            "cve_ids": self.cve_ids,
            "readme_url": self.readme_url,
            "docker_compose_url": self.docker_compose_url,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "VulhubEnvironment":
        return cls(**data)

    @property
    def docker_command(self) -> str:
        """Return the docker-compose command to start this environment."""
        return (
            f"# Clone vulhub and start the environment\n"
            f"git clone https://github.com/vulhub/vulhub.git\n"
            f"cd vulhub/{self.path}\n"
            f"docker compose up -d"
        )


class VulhubClient:
    """Client for discovering Vulhub Docker environments."""

    NAMESPACE = "vulhub"
    INDEX_KEY = "environment_index"

    def __init__(self, cache: Optional[Cache] = None):
        self.cache = cache
        self._index: Optional[dict[str, list[VulhubEnvironment]]] = None

    def _build_index(self) -> dict[str, list[VulhubEnvironment]]:
        """Build an index of CVE -> Vulhub environments.

        Fetches the Vulhub repo tree and parses directory names
        for CVE IDs.
        """
        if self._index is not None:
            return self._index

        # Check cache
        if self.cache:
            cached = self.cache.get(self.NAMESPACE, self.INDEX_KEY)
            if cached:
                self._index = {}
                for cve_id, envs in cached.items():
                    self._index[cve_id] = [VulhubEnvironment.from_dict(e) for e in envs]
                return self._index

        # Fetch repo tree from GitHub API
        try:
            resp = httpx.get(
                f"{VULHUB_API_BASE}/git/trees/master",
                params={"recursive": "1"},
                headers={"User-Agent": "VulNova/1.0"},
                timeout=30.0,
            )
            resp.raise_for_status()
            data = resp.json()
        except (httpx.HTTPError, Exception):
            self._index = {}
            return self._index

        cve_pattern = re.compile(r"(CVE-\d{4}-\d{4,})", re.IGNORECASE)
        index: dict[str, list[VulhubEnvironment]] = {}

        # Look for directories containing docker-compose.yml
        docker_compose_paths = set()
        for item in data.get("tree", []):
            if item.get("type") == "blob" and "docker-compose" in item.get("path", ""):
                # Get the parent directory
                path = item["path"]
                parent = "/".join(path.split("/")[:-1])
                docker_compose_paths.add(parent)

        for path in docker_compose_paths:
            # Check if path contains a CVE ID
            matches = cve_pattern.findall(path)
            if not matches:
                # Try the directory name itself
                dirname = path.split("/")[-1] if "/" in path else path
                matches = cve_pattern.findall(dirname)

            if matches:
                env = VulhubEnvironment(
                    name=path.split("/")[-1] if "/" in path else path,
                    path=path,
                    url=f"https://github.com/vulhub/vulhub/tree/master/{path}",
                    cve_ids=[m.upper() for m in matches],
                    readme_url=f"{VULHUB_RAW_BASE}/{path}/README.md",
                    docker_compose_url=f"{VULHUB_RAW_BASE}/{path}/docker-compose.yml",
                )
                for cve_id in env.cve_ids:
                    if cve_id not in index:
                        index[cve_id] = []
                    index[cve_id].append(env)

        # Cache for 24 hours
        if self.cache:
            serialized = {
                k: [e.to_dict() for e in v] for k, v in index.items()
            }
            self.cache.set(self.NAMESPACE, self.INDEX_KEY, serialized, ttl=86400)

        self._index = index
        return self._index

    def search(self, cve_id: str) -> list[VulhubEnvironment]:
        """Find Vulhub environments for a CVE.

        Args:
            cve_id: CVE identifier.

        Returns:
            List of matching VulhubEnvironment objects.
        """
        index = self._build_index()
        return index.get(cve_id.upper(), [])

    def has_environment(self, cve_id: str) -> bool:
        """Quick check if a CVE has a Vulhub environment."""
        index = self._build_index()
        return cve_id.upper() in index

    @property
    def total_environments(self) -> int:
        """Total number of indexed environments."""
        index = self._build_index()
        return sum(len(v) for v in index.values())
