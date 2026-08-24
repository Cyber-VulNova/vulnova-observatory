"""VulNova CLI entry point."""

import click

from vulnova import __version__


@click.group()
@click.version_option(version=__version__, prog_name="vulnova")
@click.option("--output", "-o", type=click.Choice(["table", "json", "csv", "silent"]),
              default="table", help="Output format")
@click.pass_context
def main(ctx, output):
    """VulNova - CVE tracking, vulnerability intelligence, and exploit discovery."""
    ctx.ensure_object(dict)
    ctx.obj["output"] = output


# Import and register subcommands (will be implemented in later tasks)
# Placeholder to make CLI runnable immediately
@main.command()
@click.argument("query")
@click.option("--summarize", is_flag=True, help="Generate AI triage briefing via local LLM")
@click.option("--report", type=click.Path(), help="Generate report (file.md or file.html)")
@click.pass_context
def lookup(ctx, query, summarize, report):
    """Look up a CVE by ID, component name+version, or CPE string."""
    from vulnova.commands.lookup import run_lookup
    run_lookup(ctx, query, summarize, report)


@main.command()
@click.argument("url")
@click.option("--summarize", is_flag=True, help="Generate AI triage briefing via local LLM")
@click.option("--report", type=click.Path(), help="Generate report (file.md or file.html)")
@click.pass_context
def scan(ctx, url, summarize, report):
    """Fingerprint a live URL and auto CVE scan per detected technology."""
    from vulnova.commands.scan import run_scan
    run_scan(ctx, url, summarize, report)


@main.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--concurrency", "-c", type=int, default=5, help="Number of concurrent scans")
@click.option("--summarize", is_flag=True, help="Generate AI triage briefing via local LLM")
@click.option("--report", type=click.Path(), help="Generate report (file.md or file.html)")
@click.pass_context
def batch(ctx, file, concurrency, summarize, report):
    """Batch scan multiple URLs from a file with concurrency control."""
    from vulnova.commands.batch import run_batch
    run_batch(ctx, file, concurrency, summarize, report)


@main.command()
@click.pass_context
def doctor(ctx):
    """Check API keys, connectivity, cache health, and LLM readiness."""
    from vulnova.commands.doctor import run_doctor
    run_doctor(ctx)


@main.command("set-key")
@click.argument("key_name", type=click.Choice(["nvd", "github"]))
@click.argument("key_value")
def set_key(key_name, key_value):
    """Store an API key (nvd or github) in ~/.vulnova/."""
    from vulnova.core.config import Config
    config = Config()
    config.set_api_key(key_name, key_value)
    click.echo(f"[+] {key_name} API key saved.")


@main.command()
@click.option("--host", "-h", default="127.0.0.1", help="Host to bind to")
@click.option("--port", "-p", type=int, default=5000, help="Port to listen on")
@click.option("--debug", is_flag=True, help="Enable debug mode")
@click.option("--refresh-hours", type=float, default=0.0,
              help="Auto-refresh all data sources every N hours (e.g. 6). 0 = off.")
def web(host, port, debug, refresh_hours):
    """Launch the VulNova web dashboard in your browser."""
    from vulnova.web.app import run_web
    click.echo(f"[*] VulNova Web UI starting at http://{host}:{port}")
    if refresh_hours and refresh_hours > 0:
        click.echo(f"[*] Auto-refresh enabled: every {refresh_hours} h")
    click.echo("[*] Press Ctrl+C to stop")
    import webbrowser
    webbrowser.open(f"http://{host}:{port}")
    run_web(host=host, port=port, debug=debug, refresh_hours=refresh_hours)


@main.command()
def refresh():
    """Force-refresh all data-source caches (for cron / scheduled runs)."""
    from vulnova.core.refresh import refresh_all_sources
    click.echo("[*] Refreshing all VulNova data sources…")
    summary = refresh_all_sources(force=True)
    for name, result in summary.items():
        click.echo(f"    {name}: {result}")
    click.echo("[+] Refresh complete.")


if __name__ == "__main__":
    main()
