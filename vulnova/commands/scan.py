"""Asset Scanning command - fingerprint live URLs and auto CVE scan.

Detects technologies on a target URL and automatically searches
for CVEs affecting each detected component.
"""

from typing import Optional

import click

from vulnova.core.cache import Cache
from vulnova.core.config import Config
from vulnova.core.llm import LLMClient
from vulnova.core.output import (
    console, format_output, print_cve_panel, print_error,
    print_info, print_section, print_success, print_warning,
)
from vulnova.core.report import generate_report
from vulnova.core.scanner import AssetScanner
from vulnova.core.triage import compute_triage_score
from vulnova.sources.epss import EPSSClient
from vulnova.sources.exploitdb import ExploitDBClient
from vulnova.sources.github_poc import GitHubPoCClient
from vulnova.sources.kev import KEVClient
from vulnova.sources.metasploit import MetasploitClient
from vulnova.sources.nuclei import NucleiClient
from vulnova.sources.nvd import NVDClient
from vulnova.sources.vulhub import VulhubClient


def run_scan(ctx, url: str, summarize: bool, report: Optional[str]):
    """Execute the asset scan command."""
    output_mode = ctx.obj.get("output", "table")
    config = Config()
    cache = Cache(config.cache_db_path, config.cache_ttl)

    try:
        _do_scan(url, output_mode, summarize, report, config, cache)
    finally:
        cache.close()


def _do_scan(
    url: str,
    output_mode: str,
    summarize: bool,
    report: Optional[str],
    config: Config,
    cache: Cache,
):
    """Core scan logic."""
    scanner = AssetScanner(cache=cache)

    # ─── Step 1: Fingerprint ──────────────────────────────────────────
    if output_mode != "silent":
        print_info(f"Scanning: {url}")

    result = scanner.scan_url(url)

    if result.error:
        print_error(f"Scan failed: {result.error}")
        return

    if output_mode != "silent":
        print_success(f"Status: {result.status_code} | Title: {result.title}")

    if not result.technologies:
        print_warning("No technologies detected.")
        return

    # Display detected technologies
    if output_mode == "table":
        tech_data = [t.to_dict() for t in result.technologies]
        print_section("Detected Technologies", tech_data, ["name", "version", "category", "confidence"])
    elif output_mode == "json":
        import json
        click.echo(json.dumps(result.to_dict(), indent=2))
        return
    elif output_mode == "csv":
        tech_data = [t.to_dict() for t in result.technologies]
        output = format_output(tech_data, "csv")
        click.echo(output)
        return

    # ─── Step 2: CVE scan per technology ──────────────────────────────
    nvd = NVDClient(config=config, cache=cache)
    epss_client = EPSSClient(cache=cache)
    kev_client = KEVClient(cache=cache)
    exploitdb = ExploitDBClient(config=config)
    github_poc = GitHubPoCClient(config=config, cache=cache)
    nuclei = NucleiClient(config=config, cache=cache)
    metasploit = MetasploitClient(config=config, cache=cache)
    vulhub = VulhubClient(cache=cache)

    all_enriched = []

    for tech in result.technologies:
        if not tech.version:
            continue  # Skip techs without version info for CVE lookup

        search_query = tech.search_query
        if output_mode != "silent":
            print_info(f"Searching CVEs for: {search_query}")

        cve_results = nvd.search_by_keyword(search_query, results_per_page=5)
        if not cve_results:
            continue

        for cve in cve_results[:3]:  # Limit per tech to avoid overwhelming output
            epss = epss_client.get_score(cve.cve_id)
            epss_prob = epss.epss if epss else 0.0
            in_kev = kev_client.is_in_kev(cve.cve_id)
            has_edb = exploitdb.has_exploit(cve.cve_id) if exploitdb.is_available else False

            triage = compute_triage_score(
                cve_id=cve.cve_id,
                cvss_base=cve.base_score,
                epss_probability=epss_prob,
                in_kev=in_kev,
                has_exploitdb=has_edb,
            )

            enriched = {
                "cve_id": cve.cve_id,
                "technology": tech.name,
                "tech_version": tech.version,
                "description": cve.description[:200],
                "published": cve.published[:10] if cve.published else "",
                "cvss_score": cve.base_score,
                "severity": cve.severity,
                "epss_percent": round(epss_prob * 100, 2),
                "in_kev": in_kev,
                "triage_score": triage.total_score,
                "triage_label": triage.severity_label,
                "recommendation": triage.recommendation,
                "exploits": [],
                "nuclei_templates": [],
                "metasploit_modules": [],
                "vulhub_envs": [],
            }
            all_enriched.append(enriched)

    # ─── Step 3: Output results ───────────────────────────────────────
    if not all_enriched:
        print_warning("No CVEs found for detected technologies.")
        return

    # Sort by triage score descending
    all_enriched.sort(key=lambda x: x["triage_score"], reverse=True)

    if output_mode == "table":
        console.print(f"\n[bold]Found {len(all_enriched)} CVEs across {len(result.technologies)} technologies[/]")
        summary = []
        for c in all_enriched:
            summary.append({
                "cve_id": c["cve_id"],
                "technology": f"{c['technology']} {c['tech_version']}",
                "cvss": c["cvss_score"],
                "triage_score": c["triage_score"],
                "triage_label": c["triage_label"],
                "in_kev": c["in_kev"],
            })
        print_section("Vulnerability Summary", summary,
                      ["cve_id", "technology", "cvss", "triage_score", "triage_label", "in_kev"])

    # ─── Step 4: Report ───────────────────────────────────────────────
    if report:
        report_path = generate_report(report, f"Scan: {url}", all_enriched)
        print_success(f"Report saved to: {report_path}")
