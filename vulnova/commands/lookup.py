"""CVE Lookup command - the primary VulNova command.

Looks up CVEs by ID, component name+version, or CPE string.
Enriches results with EPSS, KEV, exploit data, and triage scoring.
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
from vulnova.core.triage import compute_triage_score
from vulnova.sources.epss import EPSSClient
from vulnova.sources.exploitdb import ExploitDBClient
from vulnova.sources.github_poc import GitHubPoCClient
from vulnova.sources.kev import KEVClient
from vulnova.sources.metasploit import MetasploitClient
from vulnova.sources.nuclei import NucleiClient
from vulnova.sources.nvd import NVDClient
from vulnova.sources.vulhub import VulhubClient


def run_lookup(ctx, query: str, summarize: bool, report: Optional[str]):
    """Execute the CVE lookup command with full enrichment."""
    output_mode = ctx.obj.get("output", "table")
    config = Config()
    cache = Cache(config.cache_db_path, config.cache_ttl)

    try:
        _do_lookup(query, output_mode, summarize, report, config, cache)
    finally:
        cache.close()


def _do_lookup(
    query: str,
    output_mode: str,
    summarize: bool,
    report: Optional[str],
    config: Config,
    cache: Cache,
):
    """Core lookup logic."""
    # Initialize clients
    nvd = NVDClient(config=config, cache=cache)
    epss_client = EPSSClient(cache=cache)
    kev_client = KEVClient(cache=cache)
    exploitdb = ExploitDBClient(config=config)
    github_poc = GitHubPoCClient(config=config, cache=cache)
    nuclei = NucleiClient(config=config, cache=cache)
    metasploit = MetasploitClient(config=config, cache=cache)
    vulhub = VulhubClient(cache=cache)

    # ─── Step 1: NVD Lookup ───────────────────────────────────────────
    if output_mode != "silent":
        print_info(f"Searching NVD for: {query}")

    cve_results = nvd.search(query)
    if not cve_results:
        print_error(f"No CVE results found for: {query}")
        return

    if output_mode != "silent":
        print_success(f"Found {len(cve_results)} CVE(s)")

    # ─── Step 2: Enrich each CVE ──────────────────────────────────────
    enriched_cves = []

    for cve in cve_results:
        if output_mode != "silent":
            print_info(f"Enriching {cve.cve_id}...")

        # EPSS
        epss = epss_client.get_score(cve.cve_id)
        epss_prob = epss.epss if epss else 0.0

        # KEV
        kev_entry = kev_client.get_entry(cve.cve_id)
        in_kev = kev_entry is not None

        # ExploitDB
        edb_results = exploitdb.search_by_cve(cve.cve_id)
        has_exploitdb = len(edb_results) > 0

        # GitHub PoCs
        poc_results = github_poc.search_all(cve.cve_id)
        has_github_poc = len(poc_results) > 0

        # Nuclei
        nuclei_results = nuclei.search(cve.cve_id)
        has_nuclei = len(nuclei_results) > 0

        # Metasploit
        msf_results = metasploit.search(cve.cve_id)
        has_metasploit = len(msf_results) > 0

        # Vulhub
        vulhub_results = vulhub.search(cve.cve_id)
        has_vulhub = len(vulhub_results) > 0

        # ─── Triage Score ─────────────────────────────────────────────
        triage = compute_triage_score(
            cve_id=cve.cve_id,
            cvss_base=cve.base_score,
            epss_probability=epss_prob,
            in_kev=in_kev,
            has_exploitdb=has_exploitdb,
            has_github_poc=has_github_poc,
            has_metasploit=has_metasploit,
            has_nuclei=has_nuclei,
            has_vulhub=has_vulhub,
        )

        # Build exploit list for display
        exploits = []
        for e in edb_results:
            exploits.append({"source": "ExploitDB", "name": e.title[:60], "url": e.exploit_url})
        for p in poc_results[:5]:
            exploits.append({"source": "GitHub", "name": p.full_name, "url": p.url})
        for m in msf_results:
            exploits.append({"source": "Metasploit", "name": m.name, "url": m.url})

        enriched = {
            "cve_id": cve.cve_id,
            "description": cve.description,
            "published": cve.published[:10] if cve.published else "",
            "cvss_score": cve.base_score,
            "severity": cve.severity,
            "epss_percent": round(epss_prob * 100, 2),
            "in_kev": in_kev,
            "triage_score": triage.total_score,
            "triage_label": triage.severity_label,
            "recommendation": triage.recommendation,
            "exploits": exploits,
            "nuclei_templates": [{"path": t.path, "severity": t.severity, "nuclei_command": t.nuclei_command} for t in nuclei_results],
            "metasploit_modules": [{"name": m.name, "type": m.type, "use_command": m.use_command} for m in msf_results],
            "vulhub_envs": [v.to_dict() for v in vulhub_results],
            "github_pocs": [p.to_dict() for p in poc_results[:5]],
        }
        enriched_cves.append(enriched)

    # ─── Step 3: Output ───────────────────────────────────────────────
    if output_mode == "table":
        for cve_data in enriched_cves:
            print_cve_panel(cve_data)

            # Show exploits section
            if cve_data["exploits"]:
                print_section("Known Exploits", cve_data["exploits"], ["source", "name", "url"])

            # Nuclei templates
            if cve_data["nuclei_templates"]:
                print_section("Nuclei Templates", cve_data["nuclei_templates"], ["path", "severity"])

            # Metasploit modules
            if cve_data["metasploit_modules"]:
                print_section("Metasploit Modules", cve_data["metasploit_modules"], ["name", "type", "use_command"])

            # Vulhub environments
            if cve_data["vulhub_envs"]:
                print_section("Vulhub Environments", cve_data["vulhub_envs"], ["name", "url"])

            console.print()

    elif output_mode == "json":
        import json
        click.echo(json.dumps(enriched_cves, indent=2, default=str))

    elif output_mode == "csv":
        summary = []
        for c in enriched_cves:
            summary.append({
                "cve_id": c["cve_id"],
                "cvss": c["cvss_score"],
                "epss_percent": c["epss_percent"],
                "in_kev": c["in_kev"],
                "triage_score": c["triage_score"],
                "triage_label": c["triage_label"],
                "exploits_count": len(c["exploits"]),
            })
        output = format_output(summary, "csv")
        click.echo(output)

    # ─── Step 4: AI Briefing ──────────────────────────────────────────
    if summarize:
        if output_mode != "silent":
            print_info("Generating AI triage briefing...")
        llm = LLMClient(config=config)
        if not llm.is_available():
            print_warning("Local LLM not available. Install Ollama and pull a model.")
            print_warning("  → ollama pull mistral")
        else:
            for cve_data in enriched_cves:
                exploit_summary = ", ".join(
                    [f"{e['source']}: {e['name']}" for e in cve_data["exploits"][:3]]
                ) or "None known"

                briefing = llm.generate_briefing(
                    cve_id=cve_data["cve_id"],
                    description=cve_data["description"][:500],
                    cvss_score=cve_data["cvss_score"],
                    severity=cve_data["severity"],
                    epss_score=cve_data["epss_percent"],
                    kev_status="ACTIVELY EXPLOITED (CISA KEV)" if cve_data["in_kev"] else "Not in KEV",
                    triage_score=cve_data["triage_score"],
                    triage_label=cve_data["triage_label"],
                    exploits=exploit_summary,
                )
                if briefing:
                    console.print(f"\n[bold magenta]AI Triage Briefing - {cve_data['cve_id']}[/]")
                    console.print(briefing)
                    console.print()

    # ─── Step 5: Report Generation ────────────────────────────────────
    if report:
        report_path = generate_report(report, query, enriched_cves)
        print_success(f"Report saved to: {report_path}")
