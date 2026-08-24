"""Batch Scanning command - scan multiple URLs from a file.

Reads a file containing URLs (one per line) and scans each with
configurable concurrency.
"""

from typing import Optional

import click

from vulnova.core.batch import BatchScanner
from vulnova.core.cache import Cache
from vulnova.core.config import Config
from vulnova.core.output import (
    console, format_output, print_error, print_info,
    print_section, print_success, print_warning,
)
from vulnova.core.report import generate_report
from vulnova.core.scanner import AssetScanner
from vulnova.sources.nvd import NVDClient
from vulnova.sources.epss import EPSSClient
from vulnova.sources.kev import KEVClient
from vulnova.core.triage import compute_triage_score


def run_batch(ctx, file: str, concurrency: int, summarize: bool, report: Optional[str]):
    """Execute the batch scan command."""
    output_mode = ctx.obj.get("output", "table")
    config = Config()
    cache = Cache(config.cache_db_path, config.cache_ttl)

    try:
        _do_batch(file, concurrency, output_mode, summarize, report, config, cache)
    finally:
        cache.close()


def _do_batch(
    file: str,
    concurrency: int,
    output_mode: str,
    summarize: bool,
    report: Optional[str],
    config: Config,
    cache: Cache,
):
    """Core batch scan logic."""
    batch_scanner = BatchScanner(cache=cache, concurrency=concurrency)

    if output_mode != "silent":
        print_info(f"Batch scanning URLs from: {file} (concurrency: {concurrency})")

    # ─── Step 1: Scan all URLs ────────────────────────────────────────
    results = batch_scanner.scan_file(file)

    if not results:
        print_error("No URLs found or all scans failed.")
        return

    successful = [r for r in results if not r.error]
    failed = [r for r in results if r.error]

    if output_mode != "silent":
        print_success(f"Scanned {len(results)} URLs: {len(successful)} successful, {len(failed)} failed")

    if failed and output_mode != "silent":
        for r in failed:
            print_warning(f"  Failed: {r.url} - {r.error}")

    # ─── Step 2: Aggregate technologies ───────────────────────────────
    all_techs = []
    for scan in successful:
        for tech in scan.technologies:
            all_techs.append({
                "url": scan.url,
                "technology": tech.name,
                "version": tech.version,
                "category": tech.category,
            })

    if output_mode == "table" and all_techs:
        print_section("Detected Technologies", all_techs, ["url", "technology", "version", "category"])

    # ─── Step 3: CVE lookup per unique tech+version ───────────────────
    nvd = NVDClient(config=config, cache=cache)
    epss_client = EPSSClient(cache=cache)
    kev_client = KEVClient(cache=cache)

    # Deduplicate tech+version combos
    seen_queries = set()
    all_enriched = []

    for scan in successful:
        for tech in scan.technologies:
            if not tech.version:
                continue
            query_key = f"{tech.name}:{tech.version}"
            if query_key in seen_queries:
                continue
            seen_queries.add(query_key)

            cve_results = nvd.search_by_keyword(tech.search_query, results_per_page=3)
            for cve in cve_results[:2]:
                epss = epss_client.get_score(cve.cve_id)
                epss_prob = epss.epss if epss else 0.0
                in_kev = kev_client.is_in_kev(cve.cve_id)

                triage = compute_triage_score(
                    cve_id=cve.cve_id,
                    cvss_base=cve.base_score,
                    epss_probability=epss_prob,
                    in_kev=in_kev,
                )

                all_enriched.append({
                    "cve_id": cve.cve_id,
                    "technology": f"{tech.name} {tech.version}",
                    "description": cve.description[:150],
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
                })

    # Sort by triage score
    all_enriched.sort(key=lambda x: x["triage_score"], reverse=True)

    # ─── Step 4: Output ───────────────────────────────────────────────
    if output_mode == "table" and all_enriched:
        summary = [{
            "cve_id": c["cve_id"],
            "technology": c["technology"],
            "cvss": c["cvss_score"],
            "triage_score": c["triage_score"],
            "triage_label": c["triage_label"],
            "in_kev": c["in_kev"],
        } for c in all_enriched]
        print_section("CVE Results", summary,
                      ["cve_id", "technology", "cvss", "triage_score", "triage_label", "in_kev"])
    elif output_mode == "json":
        import json
        click.echo(json.dumps(all_enriched, indent=2, default=str))
    elif output_mode == "csv":
        summary = [{
            "cve_id": c["cve_id"],
            "technology": c["technology"],
            "cvss_score": c["cvss_score"],
            "epss_percent": c["epss_percent"],
            "in_kev": c["in_kev"],
            "triage_score": c["triage_score"],
        } for c in all_enriched]
        output = format_output(summary, "csv")
        click.echo(output)

    # ─── Step 5: Report ───────────────────────────────────────────────
    if report and all_enriched:
        report_path = generate_report(report, f"Batch scan: {file}", all_enriched)
        print_success(f"Report saved to: {report_path}")
    elif not all_enriched:
        print_warning("No CVEs found for detected technologies.")
