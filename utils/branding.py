# utils/branding.py
"""
Branding and visual display module for Password!AtTheDisco.
Provides ASCII art, Rich panels, and beautiful terminal output.
"""

from typing import Dict, Any, Optional, List
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box
from datetime import datetime

console = Console()


def show_banner():
    """Display the Password!AtTheDisco ASCII art banner."""
    banner_text = """
   ___                                 ____
  / _ \___ ____ ____    _____  _______/ / /
 / ___/ _ `(_-<(_-< |/|/ / _ \/ __/ _  /_/
/_/   \_,_/___/___/__,__/\___/_/  \_,_(_)
   ___  __ ________       ___  _
  / _ |/ //_  __/ /  ___ / _ \(_)__ _______
 / __ / __// / / _ \/ -_) // / (_-</ __/ _ \\
/_/ |_\__//_/ /_//_/\__/____/_/___/\__/\___/

        🎵 Enterprise Password Security Audit Platform 🔐
"""
    console.print(banner_text, style="bold cyan", highlight=False)
    console.print()


def show_config_panel(config: Dict[str, Any]):
    """
    Display audit configuration in a Rich panel.

    Args:
        config: Dictionary with configuration details
            - domains: List of domain names
            - total_accounts: Estimated total accounts
            - output_dir: Output directory path
            - hibp_enabled: HIBP integration status
            - hibp_index_size: Number of indexed hashes (if enabled)
            - bloodhound_enabled: BloodHound integration status
    """
    # Format domains
    domains_str = ", ".join(config.get("domains", []))
    if len(domains_str) > 50:
        domains_str = domains_str[:47] + "..."

    # Build config text
    config_text = Text()

    # Domains
    config_text.append("Domains:         ", style="bold white")
    config_text.append(f"{domains_str}\n", style="cyan")

    # Total accounts
    total_accounts = config.get("total_accounts", "Unknown")
    config_text.append("Total Accounts:  ", style="bold white")
    config_text.append(f"{total_accounts:,}" if isinstance(total_accounts, int) else str(total_accounts), style="yellow")
    config_text.append(" (estimated)\n", style="dim")

    # Output directory
    output_dir = config.get("output_dir", "")
    if len(output_dir) > 50:
        output_dir = "..." + output_dir[-47:]
    config_text.append("Output Dir:      ", style="bold white")
    config_text.append(f"{output_dir}\n", style="magenta")

    # HIBP status
    hibp_enabled = config.get("hibp_enabled", False)
    config_text.append("HIBP Enabled:    ", style="bold white")
    if hibp_enabled:
        hibp_index = config.get("hibp_index_size", 0)
        config_text.append("✓ Yes", style="bold green")
        if hibp_index > 0:
            config_text.append(f" ({hibp_index:,} indexed hashes)", style="dim green")
    else:
        config_text.append("✗ No", style="bold red")
    config_text.append("\n")

    # BloodHound status
    bh_enabled = config.get("bloodhound_enabled", False)
    config_text.append("BloodHound:      ", style="bold white")
    if bh_enabled:
        config_text.append("✓ Connected", style="bold green")
    else:
        config_text.append("✗ Not Connected", style="bold red")

    # Create panel
    panel = Panel(
        config_text,
        title="[bold cyan]🎵 Audit Configuration 🎵[/bold cyan]",
        border_style="cyan",
        box=box.DOUBLE
    )

    console.print(panel)
    console.print()


def show_completion_summary(metadata: Dict[str, Any]):
    """
    Display completion summary with Rich formatting.

    Args:
        metadata: Dictionary with audit results
            - domains: List of domains processed
            - total_accounts: Total accounts analyzed
            - cracked_accounts: Number of cracked passwords
            - uncracked_accounts: Number of uncracked passwords
            - duration_seconds: Processing time in seconds
            - risk_summary: Dict with critical, high, medium, low counts
            - hibp_breached: Number of passwords found in HIBP
            - hibp_not_breached: Number not in HIBP
            - output_dir: Path to report directory
    """
    # Build summary content
    summary = Text()

    # Processing stats
    domains_count = len(metadata.get("domains", []))
    duration = _format_duration(metadata.get("duration_seconds", 0))
    summary.append(f"✓ Processed {domains_count} domain", style="bold green")
    if domains_count != 1:
        summary.append("s", style="bold green")
    summary.append(f" in {duration}\n", style="green")

    # Account stats
    total = metadata.get("total_accounts", 0)
    cracked = metadata.get("cracked_accounts", 0)
    uncracked = metadata.get("uncracked_accounts", 0)
    summary.append(f"✓ Analyzed {total:,} accounts", style="bold green")
    summary.append(f" ({cracked:,} cracked, {uncracked:,} uncracked)\n", style="green")

    # Report formats
    summary.append("✓ Generated 5 report formats\n\n", style="bold green")

    # Risk summary table
    risk_summary = metadata.get("risk_summary", {})
    if risk_summary:
        summary.append("📊 Risk Summary:\n", style="bold yellow")

        table = Table(show_header=True, header_style="bold magenta", box=box.SIMPLE)
        table.add_column("Risk Level", style="white", width=15)
        table.add_column("Count", justify="right", style="cyan", width=10)
        table.add_column("Percentage", justify="right", style="yellow", width=12)

        # Add rows with emoji indicators
        risk_levels = [
            ("Critical", "critical", "🔴"),
            ("High", "high", "🟠"),
            ("Medium", "medium", "🟡"),
            ("Low", "low", "🟢")
        ]

        for label, key, emoji in risk_levels:
            count = risk_summary.get(key, 0)
            percentage = (count / total * 100) if total > 0 else 0
            table.add_row(
                f"{emoji} {label}",
                f"{count:,}",
                f"{percentage:.1f}%"
            )

        # Create table panel
        table_panel = Panel(table, border_style="yellow", box=box.ROUNDED)
        console.print(table_panel)
        console.print()

        summary = Text()  # Reset for next section

    # HIBP findings
    hibp_breached = metadata.get("hibp_breached", 0)
    hibp_not_breached = metadata.get("hibp_not_breached", 0)
    if hibp_breached > 0 or hibp_not_breached > 0:
        summary.append("🔑 HIBP Findings:\n", style="bold cyan")
        summary.append(f"   • {hibp_breached:,} passwords found in breach databases\n", style="red")
        summary.append(f"   • {hibp_not_breached:,} passwords NOT in known breaches\n\n", style="green")

    # Output directory
    output_dir = metadata.get("output_dir", "")
    summary.append("📁 Reports saved to:\n", style="bold magenta")
    summary.append(f"   {output_dir}\n\n", style="cyan")

    # Usage instructions
    summary.append("🌐 To view reports:\n", style="bold green")
    summary.append("   python main.py --serve\n", style="white")
    summary.append("   python main.py --serve --latest\n", style="white")

    # Create main panel
    panel = Panel(
        summary,
        title="[bold green]✨ Audit Complete ✨[/bold green]",
        border_style="green",
        box=box.DOUBLE
    )

    console.print(panel)
    console.print()


def show_report_menu_header():
    """Display header for report selection menu."""
    header = Text()
    header.append("🪩 ", style="bold yellow")
    header.append("Password!AtTheDisco Report Viewer", style="bold cyan")
    header.append(" 🪩", style="bold yellow")

    panel = Panel(
        header,
        border_style="cyan",
        box=box.DOUBLE
    )

    console.print(panel)
    console.print()


def show_report_list(reports: List[Dict[str, Any]]):
    """
    Display list of available reports.

    Args:
        reports: List of report metadata dictionaries
    """
    console.print("[bold cyan]Available Report Directories:[/bold cyan]\n")

    for idx, report in enumerate(reports, 1):
        run_id = report.get("run_id", "Unknown")
        domains = report.get("domains", [])
        total_accounts = report.get("total_accounts", 0)
        timestamp = report.get("timestamp", "")
        risk = report.get("risk_summary", {})
        duration = _format_duration(report.get("duration_seconds", 0))

        # Main entry
        console.print(f"[bold white][{idx}][/bold white] [cyan]{run_id}[/cyan]")

        # Details
        console.print(f"    ├─ {len(domains)} domain{'s' if len(domains) != 1 else ''} • {total_accounts:,} accounts", style="dim")
        console.print(f"    ├─ Generated: {timestamp}", style="dim")

        # Risk summary
        crit = risk.get("critical", 0)
        high = risk.get("high", 0)
        med = risk.get("medium", 0)
        low = risk.get("low", 0)
        console.print(
            f"    ├─ Risk: {crit} critical, {high} high, {med} medium, {low} low",
            style="dim"
        )
        console.print(f"    └─ Duration: {duration}\n", style="dim")

    # Additional options
    console.print("[bold white][L][/bold white] [green]Latest Report[/green] (auto-select most recent)")
    console.print("[bold white][Q][/bold white] [red]Quit[/red]\n")


def show_format_menu():
    """Display format selection menu."""
    console.print("\n[bold cyan]Select Report Format:[/bold cyan]\n")

    formats = [
        ("1", "🌐 HTML", "Interactive, searchable web reports", "cyan"),
        ("2", "📄 Markdown", "Text-based, readable", "yellow"),
        ("3", "📑 PDF", "Printable, shareable", "magenta"),
        ("4", "📊 CSV", "Spreadsheet, data analysis", "green"),
        ("5", "📈 Excel", "Actionable, remediation steps", "blue"),
    ]

    for num, emoji_name, desc, color in formats:
        console.print(f"[bold white][{num}][/bold white] [{color}]{emoji_name}[/{color}] ({desc})")

    console.print("\n[bold white][B][/bold white] [yellow]Back[/yellow] to directory selection")
    console.print("[bold white][Q][/bold white] [red]Quit[/red]\n")


def show_server_panel(url: str, directory: str):
    """
    Display server started panel.

    Args:
        url: Server URL
        directory: Directory being served
    """
    server_text = Text()
    server_text.append("🌐 Serving reports...\n\n", style="bold green")
    server_text.append("URL:  ", style="bold white")
    server_text.append(f"{url}\n", style="cyan underline")
    server_text.append("Dir:  ", style="bold white")

    # Truncate directory if too long
    if len(directory) > 45:
        directory = "..." + directory[-42:]
    server_text.append(f"{directory}\n\n", style="magenta")
    server_text.append("📋 Press Ctrl+C to stop", style="yellow")

    panel = Panel(
        server_text,
        title="[bold green]Server Started[/bold green]",
        border_style="green",
        box=box.DOUBLE
    )

    console.print(panel)


def _format_duration(seconds: float) -> str:
    """
    Format duration in human-readable form.

    Args:
        seconds: Duration in seconds

    Returns:
        Formatted duration string (HH:MM:SS)
    """
    hours, remainder = divmod(int(seconds), 3600)
    minutes, secs = divmod(remainder, 60)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


def print_error(message: str):
    """Print error message in red panel."""
    panel = Panel(
        f"[red]{message}[/red]",
        title="[bold red]Error[/bold red]",
        border_style="red"
    )
    console.print(panel)


def print_warning(message: str):
    """Print warning message in yellow panel."""
    panel = Panel(
        f"[yellow]{message}[/yellow]",
        title="[bold yellow]Warning[/bold yellow]",
        border_style="yellow"
    )
    console.print(panel)


def print_success(message: str):
    """Print success message in green."""
    console.print(f"[bold green]✓[/bold green] {message}")


def print_info(message: str):
    """Print info message."""
    console.print(f"[cyan]ℹ[/cyan] {message}")
