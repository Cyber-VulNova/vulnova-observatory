"""Output formatting - Table, JSON, CSV, Silent modes.

Provides consistent output formatting across all VulNova commands
using Rich for beautiful terminal tables.
"""

import csv
import io
import json
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


console = Console()


def format_output(data: list[dict[str, Any]], mode: str = "table", columns: list[str] = None) -> str:
    """Format data for output in the specified mode.

    Args:
        data: List of dicts to format.
        mode: Output mode (table, json, csv, silent).
        columns: Column names to include (defaults to all keys).

    Returns:
        Formatted string (empty for table mode as it prints directly).
    """
    if mode == "silent":
        return ""
    elif mode == "json":
        return json.dumps(data, indent=2, default=str)
    elif mode == "csv":
        return _format_csv(data, columns)
    else:
        _print_table(data, columns)
        return ""


def _format_csv(data: list[dict], columns: list[str] = None) -> str:
    """Format data as CSV."""
    if not data:
        return ""
    if columns is None:
        columns = list(data[0].keys())

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    for row in data:
        writer.writerow(row)
    return output.getvalue()


def _print_table(data: list[dict], columns: list[str] = None) -> None:
    """Print data as a rich table."""
    if not data:
        console.print("[dim]No results found.[/dim]")
        return

    if columns is None:
        columns = list(data[0].keys())

    table = Table(show_header=True, header_style="bold cyan", border_style="dim")
    for col in columns:
        table.add_column(col.replace("_", " ").title())

    for row in data:
        values = []
        for col in columns:
            val = row.get(col, "")
            values.append(_style_value(col, val))
        table.add_row(*values)

    console.print(table)


def _style_value(column: str, value: Any) -> str:
    """Apply styling to values based on column type."""
    if value is None:
        return "[dim]—[/dim]"

    val_str = str(value)

    # Severity coloring
    if column in ("severity", "triage_label", "severity_label"):
        colors = {
            "CRITICAL": "[bold red]",
            "HIGH": "[red]",
            "MEDIUM": "[yellow]",
            "LOW": "[green]",
            "INFO": "[dim]",
            "NONE": "[dim]",
        }
        color = colors.get(val_str.upper(), "")
        if color:
            return f"{color}{val_str}[/]"

    # Score coloring
    if column in ("triage_score", "total_score"):
        try:
            score = int(value)
            if score >= 80:
                return f"[bold red]{score}[/]"
            elif score >= 60:
                return f"[red]{score}[/]"
            elif score >= 40:
                return f"[yellow]{score}[/]"
            elif score >= 20:
                return f"[green]{score}[/]"
            else:
                return f"[dim]{score}[/]"
        except (ValueError, TypeError):
            pass

    # Boolean styling
    if column in ("in_kev", "kev_in_catalog"):
        if value in (True, "True", "true", "Yes", "yes"):
            return "[bold red]YES[/]"
        return "[green]No[/]"

    # URL styling
    if column in ("url", "exploit_url", "html_url"):
        return f"[blue underline]{val_str}[/]"

    return val_str


def print_cve_panel(cve_data: dict) -> None:
    """Print a detailed CVE panel with rich formatting."""
    cve_id = cve_data.get("cve_id", "Unknown")
    severity = cve_data.get("severity", "NONE")
    triage_score = cve_data.get("triage_score", 0)
    triage_label = cve_data.get("triage_label", "INFO")

    # Header color based on severity
    header_colors = {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "green",
        "INFO": "dim",
    }
    header_style = header_colors.get(triage_label, "white")

    lines = []
    lines.append(f"[bold]{cve_id}[/bold]")
    lines.append("")
    lines.append(f"[bold]Description:[/bold] {cve_data.get('description', 'N/A')[:200]}")
    lines.append("")
    lines.append(f"  CVSS:          {cve_data.get('cvss_score', 0)} ({severity})")
    lines.append(f"  EPSS:          {cve_data.get('epss_percent', 0)}%")
    lines.append(f"  CISA KEV:      {'YES - Actively Exploited' if cve_data.get('in_kev') else 'No'}")
    lines.append(f"  Triage Score:  {triage_score}/100 ({triage_label})")
    lines.append(f"  Published:     {cve_data.get('published', 'N/A')}")
    lines.append("")
    lines.append(f"[bold]Recommendation:[/bold] {cve_data.get('recommendation', 'N/A')}")

    content = "\n".join(lines)
    panel = Panel(content, title=f"[{header_style}]{cve_id}[/]", border_style=header_style)
    console.print(panel)


def print_section(title: str, items: list[dict], columns: list[str]) -> None:
    """Print a titled section with a table."""
    if not items:
        return
    console.print(f"\n[bold cyan]{title}[/bold cyan]")
    _print_table(items, columns)


def print_success(message: str) -> None:
    console.print(f"[green][+][/green] {message}")


def print_error(message: str) -> None:
    console.print(f"[red][-][/red] {message}")


def print_warning(message: str) -> None:
    console.print(f"[yellow][!][/yellow] {message}")


def print_info(message: str) -> None:
    console.print(f"[blue][*][/blue] {message}")
