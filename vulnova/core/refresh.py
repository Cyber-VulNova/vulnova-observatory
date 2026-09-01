"""Proactive data refresh for VulNova.

Force-warms the SQLite cache for every major data source so the web dashboard
serves fresh data without a visitor paying the fetch cost — and so data stays
current even when nobody is browsing.

Two ways to use it:

* **In-process scheduler** — set the ``VULNOVA_REFRESH_HOURS`` environment
  variable (e.g. ``6``), or launch with ``vulnova web --refresh-hours 6``. A
  daemon thread then refreshes on that interval. Works under any WSGI server
  because it is started from ``create_app()``.

* **External scheduler** — run ``vulnova refresh`` every 6 hours from cron
  (Linux), Task Scheduler (Windows), or a PaaS scheduled job. This is the most
  robust option for multi-worker production deployments, since it refreshes in
  a single dedicated process instead of once per web worker.
"""

import threading
import time

from vulnova.core.cache import Cache
from vulnova.core.config import Config


_scheduler_started = False
_scheduler_lock = threading.Lock()

# Cross-process soft lock so multiple web workers don't all refresh at once.
_LOCK_NS = "refresh"
_LOCK_KEY = "lock"
_STATUS_KEY = "status"    # {"last_ts": float, "summary": {...}}
_CONFIG_KEY = "config"    # {"hours": float, "auto": bool}
# Status must never expire on its own — keep it effectively forever.
_STATUS_TTL = 10 * 365 * 24 * 3600


def refresh_all_sources(force: bool = True) -> dict:
    """Force-warm the cache for the main data sources; return a summary dict.

    Creates its own ``Config`` + ``Cache`` so it is safe to call from a
    background thread — the SQLite connection must not be shared across
    threads. Each source is isolated in its own try/except so one failing
    feed never aborts the rest.
    """
    # Imported lazily to avoid a heavy import chain at module load.
    from vulnova.sources.advisories import fetch_all_advisories
    from vulnova.sources.kev import KEVClient
    from vulnova.sources.news import NewsAggregator
    from vulnova.sources.nvd import NVDClient

    config = Config()
    cache = Cache(config.cache_db_path, config.cache_ttl)
    summary: dict = {}
    try:
        # Recent CVEs — matches the default Atlas view (last 30 days, page 1).
        try:
            cves, _total = NVDClient(config=config, cache=cache).list_cves(
                page=1, results_per_page=50, days_back=30, force=force)
            summary["nvd_recent"] = len(cves)
        except Exception as e:  # noqa: BLE001
            summary["nvd_recent"] = f"error: {e}"

        # CISA KEV catalog.
        try:
            summary["kev"] = len(KEVClient(cache=cache).get_all(force=force))
        except Exception as e:  # noqa: BLE001
            summary["kev"] = f"error: {e}"

        # Pulse news feeds.
        try:
            summary["news"] = len(NewsAggregator(cache=cache).fetch_all(force=force))
        except Exception as e:  # noqa: BLE001
            summary["news"] = f"error: {e}"

        # Flare advisories — GHSA + vendors + OSV (the no-CVE source).
        try:
            advs = fetch_all_advisories(
                config=config, cache=cache, limit=600, force=force)
            summary["advisories"] = len(advs)
        except Exception as e:  # noqa: BLE001
            summary["advisories"] = f"error: {e}"

        # Ransomware.live CVE->groups index (only when a key is set). Uses its
        # own weekly TTL rather than the caller's `force` so we never burn the
        # ~394-call walk on every 6-hour cycle.
        try:
            from vulnova.sources.ransomwarelive import RansomwareLiveClient
            rl = RansomwareLiveClient(config=config)
            if rl.api_key:
                idx = rl.get_index(force=False)
                summary["ransomware_groups"] = idx.get("cve_count", 0)
        except Exception as e:  # noqa: BLE001
            summary["ransomware_groups"] = f"error: {e}"

        # Record when this refresh finished so the UI can show last/next run.
        try:
            cache.set(_LOCK_NS, _STATUS_KEY,
                      {"last_ts": time.time(), "summary": summary},
                      ttl=_STATUS_TTL)
        except Exception:  # noqa: BLE001
            pass
    finally:
        try:
            cache.close()
        except Exception:  # noqa: BLE001
            pass
    return summary


def get_refresh_status() -> dict:
    """Return auto-refresh state for the UI.

    Keys:
        auto_enabled: whether the in-process scheduler is running.
        interval_hours: configured refresh interval (or None).
        last_refresh: ISO-8601 UTC of the last completed refresh (or None).
        last_refresh_ts / next_refresh_ts: epoch seconds (or None).
        next_refresh: ISO-8601 UTC of the next scheduled refresh (or None).
        seconds_since_last / seconds_until_next: convenience deltas.
        last_summary: per-source counts from the last refresh.
    """
    from datetime import datetime, timezone

    config = Config()
    cache = Cache(config.cache_db_path, config.cache_ttl)
    try:
        status = cache.get(_LOCK_NS, _STATUS_KEY) or {}
        cfg = cache.get(_LOCK_NS, _CONFIG_KEY) or {}
    finally:
        try:
            cache.close()
        except Exception:  # noqa: BLE001
            pass

    def _iso(ts):
        if not ts:
            return None
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    now = time.time()
    last_ts = status.get("last_ts")
    hours = cfg.get("hours")
    auto = bool(cfg.get("auto"))

    next_ts = None
    if auto and hours:
        # Next run is one interval after the last completed refresh; if we've
        # already passed it (e.g. server was down), it's effectively "due now".
        base = last_ts or now
        next_ts = base + hours * 3600.0

    return {
        "auto_enabled": auto,
        "interval_hours": hours,
        "last_refresh": _iso(last_ts),
        "last_refresh_ts": last_ts,
        "seconds_since_last": (now - last_ts) if last_ts else None,
        "next_refresh": _iso(next_ts),
        "next_refresh_ts": next_ts,
        "seconds_until_next": (next_ts - now) if next_ts else None,
        "last_summary": status.get("summary", {}),
    }


def _acquire_soft_lock(cache: Cache, min_gap_seconds: float) -> bool:
    """Return True if this process may refresh now.

    A tiny cross-process guard: if another worker refreshed within
    ``min_gap_seconds``, skip. Best-effort — on any error we allow the refresh.
    """
    try:
        last = cache.get(_LOCK_NS, _LOCK_KEY)
        now = time.time()
        if last and (now - float(last.get("ts", 0))) < min_gap_seconds:
            return False
        cache.set(_LOCK_NS, _LOCK_KEY, {"ts": now},
                  ttl=int(min_gap_seconds * 4) or 3600)
        return True
    except Exception:  # noqa: BLE001
        return True


def _run_loop(hours: float) -> None:
    interval = max(hours * 3600.0, 60.0)
    time.sleep(15)  # let the server finish starting before the first run
    while True:
        try:
            config = Config()
            cache = Cache(config.cache_db_path, config.cache_ttl)
            allowed = _acquire_soft_lock(cache, interval * 0.5)
            try:
                cache.close()
            except Exception:  # noqa: BLE001
                pass
            if allowed:
                refresh_all_sources(force=True)
        except Exception:  # noqa: BLE001
            pass
        time.sleep(interval)


def start_background_refresh(hours: float) -> bool:
    """Start the in-process refresh scheduler once. Returns True if started.

    Guarded so repeated calls (or multiple ``create_app()`` invocations in the
    same process) start only one thread. A daemon thread, so it never blocks
    interpreter shutdown.
    """
    global _scheduler_started
    if not hours or hours <= 0:
        return False
    with _scheduler_lock:
        if _scheduler_started:
            return False
        _scheduler_started = True

    # Persist the interval so /api/refresh-status can compute the next run.
    try:
        config = Config()
        cache = Cache(config.cache_db_path, config.cache_ttl)
        cache.set(_LOCK_NS, _CONFIG_KEY, {"hours": hours, "auto": True},
                  ttl=_STATUS_TTL)
        cache.close()
    except Exception:  # noqa: BLE001
        pass

    threading.Thread(
        target=_run_loop, args=(hours,),
        name="vulnova-refresh", daemon=True,
    ).start()
    return True
