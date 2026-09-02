"""EPSS (Exploit Prediction Scoring System) client.

Fetches exploit probability scores from FIRST.org API.
Reference: https://www.first.org/epss/api
"""

import gzip
import re
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional

import httpx

from vulnova.core.cache import Cache


EPSS_API_BASE = "https://api.first.org/data/v1/epss"

# Full daily EPSS snapshot (gzipped CSV: cve,epss,percentile). Reliable bulk
# source — used for the dashboard (top-by-EPSS, deltas, band counts) instead of
# the rate-limited per-query API.
EPSS_CSV_URL = "https://epss.empiricalsecurity.com/epss_scores-{day}.csv.gz"
_CSV_UA = {"User-Agent": "VulNova-Observatory/1.0 (+https://github.com/Cyber-VulNova)"}


@dataclass
class EPSSScore:
    """EPSS score for a CVE."""
    cve_id: str
    epss: float  # Probability 0.0-1.0
    percentile: float  # 0.0-1.0
    date: str = ""

    @property
    def epss_percent(self) -> float:
        """EPSS as a percentage (0-100)."""
        return round(self.epss * 100, 2)

    @property
    def percentile_percent(self) -> float:
        """Percentile as a percentage (0-100)."""
        return round(self.percentile * 100, 1)

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "epss": self.epss,
            "percentile": self.percentile,
            "date": self.date,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "EPSSScore":
        return cls(
            cve_id=data.get("cve_id", ""),
            epss=data.get("epss", 0.0),
            percentile=data.get("percentile", 0.0),
            date=data.get("date", ""),
        )


class EPSSClient:
    """Client for the FIRST.org EPSS API + bulk daily snapshots."""

    NAMESPACE = "epss"

    def __init__(self, cache: Optional[Cache] = None, config=None):
        self.cache = cache
        from vulnova.core.config import Config
        self.config = config or Config()
        self._snap_dir = self.config.app_dir / "epss"

    def get_score(self, cve_id: str) -> Optional[EPSSScore]:
        """Get EPSS score for a single CVE.

        Args:
            cve_id: CVE identifier (e.g., CVE-2023-44487).

        Returns:
            EPSSScore or None if not found.
        """
        cve_id = cve_id.upper()

        if self.cache:
            cached = self.cache.get(self.NAMESPACE, cve_id)
            if cached:
                return EPSSScore.from_dict(cached)

        try:
            resp = httpx.get(
                EPSS_API_BASE,
                params={"cve": cve_id},
                timeout=15.0,
            )
            resp.raise_for_status()
            data = resp.json()
        except (httpx.HTTPError, Exception):
            return None

        entries = data.get("data", [])
        if not entries:
            return None

        entry = entries[0]
        score = EPSSScore(
            cve_id=entry.get("cve", cve_id),
            epss=float(entry.get("epss", 0.0)),
            percentile=float(entry.get("percentile", 0.0)),
            date=entry.get("date", ""),
        )

        if self.cache:
            self.cache.set(self.NAMESPACE, cve_id, score.to_dict(), ttl=43200)  # 12h TTL

        return score

    def get_history(self, cve_id: str) -> list[dict]:
        """Fetch the EPSS time-series (recent history) for a CVE.

        Uses FIRST.org's scope=time-series, which returns up to ~30 days of
        daily EPSS scores. Useful for showing whether exploit probability is
        trending up or down.

        Returns:
            List of {"date", "epss", "percentile"} sorted oldest → newest.
        """
        cve_id = cve_id.upper()
        cache_key = f"hist:{cve_id}"

        if self.cache:
            cached = self.cache.get(self.NAMESPACE, cache_key)
            if cached is not None:
                return cached

        try:
            resp = httpx.get(
                EPSS_API_BASE,
                params={"cve": cve_id, "scope": "time-series"},
                timeout=15.0,
            )
            resp.raise_for_status()
            data = resp.json()
        except (httpx.HTTPError, Exception):
            return []

        entries = data.get("data", [])
        if not entries:
            return []

        series = entries[0].get("time-series", [])
        history = []
        for point in series:
            try:
                history.append({
                    "date": point.get("date", "")[:10],
                    "epss": float(point.get("epss", 0.0)),
                    "percentile": float(point.get("percentile", 0.0)),
                })
            except (ValueError, TypeError):
                continue

        # Include today's current score as the most recent point
        current = entries[0]
        try:
            history.append({
                "date": current.get("date", "")[:10],
                "epss": float(current.get("epss", 0.0)),
                "percentile": float(current.get("percentile", 0.0)),
            })
        except (ValueError, TypeError):
            pass

        # Sort oldest → newest, dedupe by date
        seen = {}
        for h in history:
            if h["date"]:
                seen[h["date"]] = h
        history = sorted(seen.values(), key=lambda x: x["date"])

        if self.cache:
            self.cache.set(self.NAMESPACE, cache_key, history, ttl=43200)  # 12h

        return history

    def get_top(self, limit: int = 100) -> list[EPSSScore]:
        """Return the CVEs with the highest EPSS probability, descending.

        Uses the FIRST.org API's ``order=!epss`` sort. Cached briefly since the
        global ranking only shifts on daily EPSS recomputation.
        """
        limit = max(1, min(int(limit), 200))
        cache_key = f"top:{limit}"
        if self.cache:
            cached = self.cache.get(self.NAMESPACE, cache_key)
            if cached is not None:
                return [EPSSScore.from_dict(x) for x in cached]

        try:
            resp = httpx.get(
                EPSS_API_BASE,
                params={"order": "!epss", "limit": limit},
                timeout=20.0,
            )
            resp.raise_for_status()
            data = resp.json()
        except (httpx.HTTPError, Exception):
            return []

        scores = []
        for entry in data.get("data", []):
            scores.append(EPSSScore(
                cve_id=entry.get("cve", ""),
                epss=float(entry.get("epss", 0.0)),
                percentile=float(entry.get("percentile", 0.0)),
                date=entry.get("date", ""),
            ))

        if self.cache and scores:
            self.cache.set(self.NAMESPACE, cache_key,
                           [s.to_dict() for s in scores], ttl=21600)  # 6h
        return scores

    def count_above(self, threshold: float) -> int:
        """Return how many CVEs have an EPSS probability above ``threshold``.

        The FIRST.org API reports the matching ``total`` even with limit=1, so
        this is a single cheap call per threshold.
        """
        cache_key = f"count-gt:{threshold}"
        if self.cache:
            cached = self.cache.get(self.NAMESPACE, cache_key)
            if cached is not None:
                return cached

        try:
            resp = httpx.get(
                EPSS_API_BASE,
                params={"epss-gt": threshold, "limit": 1},
                timeout=15.0,
            )
            resp.raise_for_status()
            total = int(resp.json().get("total", 0))
        except (httpx.HTTPError, Exception):
            return 0

        if self.cache:
            self.cache.set(self.NAMESPACE, cache_key, total, ttl=21600)  # 6h
        return total

    # ─── Bulk snapshot + dashboard ─────────────────────────────────────────

    def _snapshot_bytes(self, day: str) -> bytes:
        """Return the gzipped snapshot for a day, using an on-disk cache.

        "current" is re-downloaded when older than 12 h; dated snapshots are
        immutable, so they're cached forever. Avoids re-downloading 2.5 MB on
        every request.
        """
        path = self._snap_dir / f"epss-{day}.csv.gz"
        fresh = 12 * 3600
        try:
            if path.exists():
                age = time.time() - path.stat().st_mtime
                if day != "current" or age < fresh:
                    return path.read_bytes()
        except OSError:
            pass
        url = EPSS_CSV_URL.format(day=day)
        for attempt in range(3):
            try:
                r = httpx.get(url, headers=_CSV_UA, timeout=45.0, follow_redirects=True)
                if r.status_code != 200:
                    return b""
                try:
                    self._snap_dir.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(r.content)
                except OSError:
                    pass
                return r.content
            except (httpx.HTTPError, OSError):
                time.sleep(2 + attempt * 2)
        return b""

    def _fetch_csv(self, day: str) -> tuple[dict, str]:
        """Return ({cve: (epss, percentile)}, score_date) for a snapshot day."""
        content = self._snapshot_bytes(day)
        if not content:
            return {}, ""
        try:
            text = gzip.decompress(content).decode("utf-8", "replace")
        except (OSError, ValueError):
            return {}, ""
        lines = text.splitlines()
        if not lines:
            return {}, ""
        score_date = ""
        if lines[0].startswith("#"):
            m = re.search(r"score_date:([0-9T:\-]+)", lines[0])
            if m:
                score_date = m.group(1)
        start = 2 if len(lines) > 1 and lines[1].startswith("cve") else 1
        out: dict[str, tuple] = {}
        for line in lines[start:]:
            parts = line.split(",")
            if len(parts) >= 3:
                try:
                    out[parts[0]] = (float(parts[1]), float(parts[2]))
                except ValueError:
                    continue
        return out, score_date

    def top_recent(self, cve_ids: list[str], top_n: int = 12) -> list[dict]:
        """Rank the given CVEs by current EPSS (highest first).

        Used to build the "top-rated recent vulnerabilities" cards: pass the
        recently-published CVE ids and this returns the ones with the highest
        exploitation probability, read from the cached current snapshot.
        """
        if not cve_ids:
            return []
        cur, _ = self._fetch_csv("current")
        if not cur:
            return []
        scored = []
        for cid in cve_ids:
            v = cur.get(cid.upper()) or cur.get(cid)
            if v:
                scored.append((cid.upper(), v[0], v[1]))
        scored.sort(key=lambda x: x[1], reverse=True)
        return [{"cve": c, "epss": round(e * 100, 2), "percentile": round(p * 100, 2)}
                for c, e, p in scored[:top_n]]

    def dashboard(self, top_n: int = 12, movers_n: int = 10, force: bool = False) -> dict:
        """Build the EPSS dashboard payload from the bulk snapshots.

        Returns {score_date, prev_date, total, bands, top, movers}:
          * top    — highest-EPSS CVEs (probability + percentile).
          * movers — biggest positive EPSS shift vs. ~2 days ago.
          * bands  — counts above the 50% / 10% / 1% probability thresholds.

        The derived result is small and cached ~12 h (EPSS recomputes daily).
        """
        cache_key = f"dash:{top_n}:{movers_n}"
        if self.cache and not force:
            cached = self.cache.get(self.NAMESPACE, cache_key)
            if cached is not None:
                return cached

        cur, cur_date = self._fetch_csv("current")
        if not cur:
            # Never cache an empty result — return whatever's cached or empty.
            return (self.cache.get(self.NAMESPACE, cache_key) if self.cache else None) or {
                "score_date": "", "prev_date": "", "total": 0,
                "bands": {"high": 0, "elevated": 0, "moderate": 0},
                "top": [], "movers": [],
            }

        # Past snapshot for deltas — current date minus a couple days, with
        # fallbacks for gaps.
        past: dict = {}
        prev_date = ""
        base = None
        if cur_date:
            try:
                base = datetime.strptime(cur_date[:10], "%Y-%m-%d")
            except ValueError:
                base = None
        if base:
            for off in (2, 3, 1, 4):
                ds = (base - timedelta(days=off)).strftime("%Y-%m-%d")
                past, _ = self._fetch_csv(ds)
                if past:
                    prev_date = ds
                    break

        movers = []
        if past:
            deltas = []
            for c, (e, _p) in cur.items():
                pt = past.get(c)
                if pt is None:
                    continue
                d = e - pt[0]
                if d > 0:
                    deltas.append((c, e, d))
            deltas.sort(key=lambda x: x[2], reverse=True)
            movers = [{
                "cve": c,
                "epss": round(e * 100, 2),
                "delta": round(d * 100, 2),
            } for c, e, d in deltas[:movers_n]]

        hi = el = mo = 0
        for v in cur.values():
            e = v[0]
            if e >= 0.5:
                hi += 1
            if e >= 0.1:
                el += 1
            if e >= 0.01:
                mo += 1

        result = {
            "score_date": cur_date[:10] if cur_date else "",
            "prev_date": prev_date,
            "total": len(cur),
            "bands": {"high": hi, "elevated": el, "moderate": mo},
            "movers": movers,
        }
        if self.cache:
            self.cache.set(self.NAMESPACE, cache_key, result, ttl=43200)  # 12h
        return result

    def get_scores_bulk(self, cve_ids: list[str]) -> dict[str, EPSSScore]:
        """Get EPSS scores for multiple CVEs in one request.

        Args:
            cve_ids: List of CVE identifiers.

        Returns:
            Dict mapping CVE ID -> EPSSScore.
        """
        if not cve_ids:
            return {}

        results: dict[str, EPSSScore] = {}
        uncached: list[str] = []

        # Check cache first
        for cve_id in cve_ids:
            cve_id = cve_id.upper()
            if self.cache:
                cached = self.cache.get(self.NAMESPACE, cve_id)
                if cached:
                    results[cve_id] = EPSSScore.from_dict(cached)
                    continue
            uncached.append(cve_id)

        if not uncached:
            return results

        # Fetch remaining in bulk (API supports comma-separated CVEs)
        # Process in chunks of 30 to avoid URL length limits
        for i in range(0, len(uncached), 30):
            chunk = uncached[i:i + 30]
            cve_param = ",".join(chunk)

            try:
                resp = httpx.get(
                    EPSS_API_BASE,
                    params={"cve": cve_param},
                    timeout=20.0,
                )
                resp.raise_for_status()
                data = resp.json()
            except (httpx.HTTPError, Exception):
                continue

            for entry in data.get("data", []):
                score = EPSSScore(
                    cve_id=entry.get("cve", ""),
                    epss=float(entry.get("epss", 0.0)),
                    percentile=float(entry.get("percentile", 0.0)),
                    date=entry.get("date", ""),
                )
                results[score.cve_id] = score
                if self.cache:
                    self.cache.set(self.NAMESPACE, score.cve_id, score.to_dict(), ttl=43200)

        return results
