"""Doctor command - system health check.

Verifies API keys, connectivity, cache health, and LLM readiness
in a single command.
"""

import click
import httpx

from vulnova.core.cache import Cache
from vulnova.core.config import Config
from vulnova.core.llm import LLMClient
from vulnova.core.output import console, print_error, print_info, print_success, print_warning
from vulnova.sources.exploitdb import ExploitDBClient


def run_doctor(ctx):
    """Run all health checks."""
    config = Config()
    console.print("[bold]VulNova Doctor[/bold]")
    console.print("=" * 50)

    all_ok = True

    # ─── API Keys ─────────────────────────────────────────────────────
    console.print("\n[bold cyan]API Keys[/bold cyan]")
    keys = config.list_keys()
    for key_name, configured in keys.items():
        if configured:
            print_success(f"{key_name}: configured")
        else:
            print_warning(f"{key_name}: not configured (optional but recommended)")

    # ─── Connectivity ─────────────────────────────────────────────────
    console.print("\n[bold cyan]Connectivity[/bold cyan]")

    endpoints = {
        "NVD API": "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1",
        "EPSS API": "https://api.first.org/data/v1/epss?cve=CVE-2021-44228",
        "CISA KEV": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "GitHub API": "https://api.github.com/rate_limit",
    }

    for name, url in endpoints.items():
        try:
            headers = {"User-Agent": "VulNova/1.0"}
            if name == "GitHub API" and config.get_api_key("github"):
                headers["Authorization"] = f"Bearer {config.get_api_key('github')}"
            resp = httpx.get(url, timeout=10.0, headers=headers)
            if resp.status_code == 200:
                print_success(f"{name}: reachable (HTTP {resp.status_code})")
            elif resp.status_code == 403:
                print_warning(f"{name}: rate limited (HTTP 403)")
            else:
                print_warning(f"{name}: HTTP {resp.status_code}")
        except httpx.ConnectError:
            print_error(f"{name}: unreachable (connection refused)")
            all_ok = False
        except httpx.TimeoutException:
            print_error(f"{name}: timeout")
            all_ok = False
        except Exception as e:
            print_error(f"{name}: error ({e})")
            all_ok = False

    # ─── Cache Health ─────────────────────────────────────────────────
    console.print("\n[bold cyan]Cache[/bold cyan]")
    try:
        cache = Cache(config.cache_db_path, config.cache_ttl)
        stats = cache.stats()
        print_success(f"SQLite cache: OK ({stats['size_mb']} MB)")
        print_info(f"  Entries: {stats['active_entries']} active, {stats['expired_entries']} expired")
        if stats['sources']:
            sources_str = ", ".join(f"{k}={v}" for k, v in stats['sources'].items())
            print_info(f"  Sources: {sources_str}")
        cache.close()
    except Exception as e:
        print_error(f"Cache: error ({e})")
        all_ok = False

    # ─── ExploitDB CSV ────────────────────────────────────────────────
    console.print("\n[bold cyan]ExploitDB[/bold cyan]")
    edb = ExploitDBClient(config=config)
    if edb.is_available:
        print_success(f"ExploitDB CSV: available ({edb.total_exploits} exploits indexed)")
    else:
        print_warning("ExploitDB CSV: not downloaded")
        print_info("  → Run: vulnova update-exploitdb")

    # ─── Local LLM ────────────────────────────────────────────────────
    console.print("\n[bold cyan]Local LLM (Ollama)[/bold cyan]")
    llm = LLMClient(config=config)
    if llm.is_available():
        models = llm.list_models()
        print_success(f"Ollama: running at {config.llm_endpoint}")
        if models:
            print_info(f"  Models: {', '.join(models[:5])}")
            if config.llm_model in [m.split(":")[0] for m in models]:
                print_success(f"  Default model '{config.llm_model}': available")
            else:
                print_warning(f"  Default model '{config.llm_model}': not found")
                print_info(f"  → Run: ollama pull {config.llm_model}")
        else:
            print_warning("  No models installed")
            print_info(f"  → Run: ollama pull {config.llm_model}")
    else:
        print_warning("Ollama: not running (--summarize won't work)")
        print_info("  → Install: https://ollama.ai")
        print_info(f"  → Then: ollama pull {config.llm_model}")

    # ─── Summary ──────────────────────────────────────────────────────
    console.print("\n" + "=" * 50)
    if all_ok:
        print_success("[bold]All systems operational![/bold]")
    else:
        print_warning("[bold]Some checks failed - see above for details.[/bold]")
