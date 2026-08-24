"""Batch Scanning - scan multiple URLs with concurrency control.

Reads URLs from a file and scans them concurrently using asyncio
with configurable concurrency limits.
"""

import asyncio
from pathlib import Path
from typing import Optional

import httpx

from vulnova.core.cache import Cache
from vulnova.core.scanner import AssetScanner, ScanResult


class BatchScanner:
    """Batch scan multiple URLs with concurrency control."""

    def __init__(self, cache: Optional[Cache] = None, concurrency: int = 5):
        """Initialize batch scanner.

        Args:
            cache: Optional cache instance.
            concurrency: Maximum number of concurrent scans.
        """
        self.cache = cache
        self.concurrency = concurrency
        self.scanner = AssetScanner(cache=cache)

    def scan_file(self, filepath: str | Path) -> list[ScanResult]:
        """Scan all URLs from a file.

        File format: one URL per line. Blank lines and lines starting
        with # are ignored.

        Args:
            filepath: Path to file containing URLs.

        Returns:
            List of ScanResult objects.
        """
        urls = self._load_urls(filepath)
        if not urls:
            return []

        return asyncio.run(self._scan_urls_async(urls))

    def _load_urls(self, filepath: str | Path) -> list[str]:
        """Load URLs from a file, filtering comments and blanks."""
        path = Path(filepath)
        if not path.exists():
            return []

        urls = []
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                urls.append(line)
        return urls

    async def _scan_urls_async(self, urls: list[str]) -> list[ScanResult]:
        """Scan URLs with concurrency control using asyncio semaphore."""
        semaphore = asyncio.Semaphore(self.concurrency)
        results: list[ScanResult] = []

        async def scan_one(url: str) -> ScanResult:
            async with semaphore:
                # Run synchronous scanner in thread pool
                loop = asyncio.get_event_loop()
                return await loop.run_in_executor(
                    None, self.scanner.scan_url, url
                )

        tasks = [scan_one(url) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Convert exceptions to error results
        final_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                final_results.append(ScanResult(
                    url=urls[i],
                    error=str(result),
                ))
            else:
                final_results.append(result)

        return final_results
