"""
Terminal animation module for password security audit tool.
Provides rich visualization during the analysis process.
"""

import random
import time
from datetime import datetime
from collections import deque
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn
from rich.table import Table
from rich.text import Text
from rich import box

class PasswordAuditAnimation:
    """
    Main class for the password audit animation.
    Provides a rich visual interface during password analysis.
    """
    
    def __init__(self, domains):
        """
        Initialize the animation.
        
        Args:
            domains (list): List of domains being analyzed
        """
        self.domains = domains
        self.total_domains = len(domains)
        self.current_domain_index = 0
        self.completed_domains = 0
        self.start_time = time.time()
        self.stats = {
            "total_accounts": 0,
            "analyzed_accounts": 0,
            "cracked_accounts": 0,
            "uncracked_accounts": 0,
            "da_pathway_accounts": 0,
            "compliance_issues": 0,
            "non_expiring_accounts": 0,
        }
        self.risk_counts = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0
        }
        self.risk_history = {
            "Critical": deque([0] * 20, maxlen=20),
            "High": deque([0] * 20, maxlen=20),
            "Medium": deque([0] * 20, maxlen=20),
            "Low": deque([0] * 20, maxlen=20)
        }
        self.recent_findings = []
        self.frame_counter = 0
        
        # Initialize layout
        self.setup_layout()
        
        # Progress tracking
        self.setup_progress()
    
    def setup_layout(self):
        """Set up the rich layout for the animation."""
        self.layout = Layout(name="root")
        
        # Split into header, body, and footer
        self.layout.split(
            Layout(name="header", size=3),
            Layout(name="body", ratio=1),
            Layout(name="footer", size=3)
        )
        
        # Split body into left and right columns
        self.layout["body"].split_row(
            Layout(name="left", ratio=2),
            Layout(name="right", ratio=1)
        )
        
        # Split left into sections
        self.layout["left"].split(
            Layout(name="progress", size=12),
            Layout(name="stats", size=12),
            Layout(name="findings", ratio=1)
        )
        
        # Split right into sections
        self.layout["right"].split(
            Layout(name="domain_list", ratio=1),
            Layout(name="risk_meter", size=14)
        )

    def setup_progress(self):
        """Set up progress bars."""
        # Overall progress (domains)
        self.overall_progress = Progress(
            TimeElapsedColumn(),
            BarColumn(bar_width=40),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("•"),
            TimeRemainingColumn(),
            expand=True
        )
        self.overall_task = self.overall_progress.add_task(
            "[bold blue]Overall Progress", 
            total=self.total_domains
        )
        
        # Domain progress (accounts)
        self.domain_progress = Progress(
            SpinnerColumn("dots"),
            TextColumn("[bold green]{task.description}"),
            BarColumn(bar_width=30),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("({task.completed}/{task.total})"),
            expand=True
        )
        self.domain_task = self.domain_progress.add_task(
            f"[cyan]Processing domain: {self.domains[0]}", 
            total=100
        )
        
        # Analysis progress (detailed steps)
        self.analysis_progress = Progress(
            SpinnerColumn("dots2"),
            TextColumn("[bold magenta]{task.description}"),
            BarColumn(bar_width=20),
            TextColumn("{task.completed:.0f}/{task.total}"),
            expand=True
        )
        
        # Add some standard analysis tasks
        self.analysis_tasks = {}
        self.analysis_tasks["cracking"] = self.analysis_progress.add_task(
            "[magenta]Password analysis", total=100
        )
        self.analysis_tasks["risk_scoring"] = self.analysis_progress.add_task(
            "[yellow]Risk scoring", total=100
        )
        self.analysis_tasks["bloodhound"] = self.analysis_progress.add_task(
            "[red]BloodHound integration", total=100
        )
    
    def update_header(self):
        """Update the header content."""
        header_text = Text()
        header_text.append("Password Security Audit - ", style="bold")
        header_text.append("CVSS-Style Risk Analysis", style="bold green")
        
        # Running time
        elapsed = time.time() - self.start_time
        hours, remainder = divmod(int(elapsed), 3600)
        minutes, seconds = divmod(remainder, 60)
        time_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
        header_text.append(f" - Running time: {time_str}", style="dim")
        
        self.layout["header"].update(Panel(
            header_text,
            style="white on blue",
            box=box.HEAVY
        ))
    
    def update_footer(self):
        """Update the footer content."""
        footer_text = Text()
        
        # Add a pulsing indicator for authenticity
        if self.frame_counter % 8 < 4:
            indicator = "⚡ ACTIVE ⚡"
            style = "bold green"
        else:
            indicator = "⚡ ACTIVE ⚡"
            style = "green"
        
        footer_text.append(indicator, style=style)
        footer_text.append(" | ")
        footer_text.append(f"Domains: {self.completed_domains}/{self.total_domains}", style="cyan")
        footer_text.append(" | ")
        footer_text.append(f"Accounts: {self.stats['analyzed_accounts']}", style="yellow")
        footer_text.append(" | ")
        footer_text.append("Press Ctrl+C to abort", style="dim")
        
        self.layout["footer"].update(Panel(
            footer_text,
            style="white on dark_blue",
            box=box.HEAVY
        ))
    
    def update_progress_section(self):
        """Update the progress section."""
        progress_group = Panel(
            self.overall_progress, 
            title="[b]Overall Status", 
            border_style="blue",
            box=box.ROUNDED
        )
        
        # Main progress panel with nested progress bars
        self.layout["progress"].update(
            Panel(
                Layout(
                    Layout(progress_group, size=3),
                    Layout(self.domain_progress, size=3),
                    Layout(self.analysis_progress, size=9)
                ),
                title="[b]Analysis Progress",
                border_style="blue",
                box=box.ROUNDED,
                padding=(0, 1)
            )
        )
    
    def update_stats_section(self):
        """Update the statistics section."""
        stats_table = Table(box=box.SIMPLE, expand=True)
        stats_table.add_column("Metric", style="cyan")
        stats_table.add_column("Value", justify="right", style="green")
        stats_table.add_column("Details", style="yellow")
        
        # Add rows for each stat with detailed breakdowns
        cracked_percent = 0
        if self.stats["analyzed_accounts"] > 0:
            cracked_percent = (self.stats["cracked_accounts"] / self.stats["analyzed_accounts"]) * 100
        
        stats_table.add_row(
            "Total Accounts", 
            str(self.stats["analyzed_accounts"]), 
            ""
        )
        stats_table.add_row(
            "Cracked", 
            str(self.stats["cracked_accounts"]), 
            f"[yellow]{cracked_percent:.1f}%[/yellow]"
        )
        stats_table.add_row(
            "Uncracked", 
            str(self.stats["uncracked_accounts"]), 
            f"[green]{100-cracked_percent:.1f}%[/green]"
        )
        stats_table.add_row(
            "DA Pathway", 
            str(self.stats["da_pathway_accounts"]), 
            "[red]High Risk[/red]"
        )
        stats_table.add_row(
            "Non-Expiring", 
            str(self.stats["non_expiring_accounts"]), 
            "[yellow]Policy Violation[/yellow]"
        )
        stats_table.add_row(
            "Compliance Issues", 
            str(self.stats["compliance_issues"]), 
            "[yellow]Out of Policy[/yellow]"
        )
        
        self.layout["stats"].update(
            Panel(
                stats_table,
                title="[b]Analysis Summary",
                border_style="green",
                box=box.ROUNDED
            )
        )
    
    def update_findings_section(self):
        """Update the findings section with recently discovered issues."""
        findings_text = Text()
        
        if not self.recent_findings:
            findings_text.append("No significant findings yet...", style="dim")
        else:
            for i, finding in enumerate(self.recent_findings[:10]):
                severity_style = {
                    "Critical": "bold red",
                    "High": "red",
                    "Medium": "yellow",
                    "Low": "green"
                }.get(finding["severity"], "white")
                
                findings_text.append(f"{finding['timestamp']} ", style="dim")
                findings_text.append(f"[{finding['severity']}] ", style=severity_style)
                findings_text.append(f"{finding['message']}\n")
        
        self.layout["findings"].update(
            Panel(
                findings_text,
                title="[b]Recent Findings",
                border_style="yellow",
                box=box.ROUNDED
            )
        )
    
    def update_domain_list(self):
        """Update the domain list with processing status."""
        domain_table = Table(box=None, expand=True)
        domain_table.add_column("Domain", style="cyan")
        domain_table.add_column("Status", justify="right")
        
        for i, domain in enumerate(self.domains):
            if i < self.current_domain_index:
                # Completed domain
                status = "[bold green]COMPLETE[/bold green]"
            elif i == self.current_domain_index:
                # Current domain - with animated indicator
                if self.frame_counter % 4 == 0:
                    status = "[bold blue]PROCESSING [white]⚡[/white][/bold blue]"
                elif self.frame_counter % 4 == 1:
                    status = "[bold blue]PROCESSING [white]⚡⚡[/white][/bold blue]"
                elif self.frame_counter % 4 == 2:
                    status = "[bold blue]PROCESSING [white]⚡⚡⚡[/white][/bold blue]"
                else:
                    status = "[bold blue]PROCESSING [white]⚡⚡[/white][/bold blue]"
            else:
                # Pending domain
                status = "[dim]PENDING[/dim]"
            
            domain_table.add_row(domain, status)
        
        self.layout["domain_list"].update(
            Panel(
                domain_table,
                title="[b]Domain Queue",
                border_style="cyan",
                box=box.ROUNDED
            )
        )
    
    def update_risk_meter(self):
        """Update the risk assessment meter."""
        # Update risk history
        for level in self.risk_counts:
            # Append current count to history
            self.risk_history[level].append(self.risk_counts[level])
        
        risk_table = Table(box=box.SIMPLE, expand=True)
        risk_table.add_column("Risk Level", style="white")
        risk_table.add_column("Count", justify="right")
        risk_table.add_column("Bar")
        
        total_risks = sum(self.risk_counts.values())
        
        # Calculate percentage of total for each risk level
        for level in ["Critical", "High", "Medium", "Low"]:
            count = self.risk_counts[level]
            
            # Calculate bar width based on percentage
            if total_risks > 0:
                percentage = count / total_risks
                width = int(20 * percentage)
            else:
                width = 0
            
            # Create bar with appropriate color
            bar_color = {
                "Critical": "red",
                "High": "yellow",
                "Medium": "blue",
                "Low": "green"
            }[level]
            
            # Create animated "filling" bar for visual effect
            bar = ""
            if width > 0:
                # Display fuller bar when frame count is higher
                fill_chars = ['▏', '▎', '▍', '▌', '▋', '▊', '▉', '█']
                
                # Main filled part
                bar += f"[{bar_color}]{'█' * (width-1)}[/{bar_color}]" if width > 1 else ""
                
                # Animated end character
                end_char = fill_chars[self.frame_counter % len(fill_chars)]
                bar += f"[{bar_color}]{end_char}[/{bar_color}]"
            
            risk_table.add_row(level, str(count), bar)
            
        # Create a trending indicator based on history
        trend_table = Table.grid()
        trend_table.add_column("Level", style="dim")
        trend_table.add_column("Trend", style="bold")
        
        for level in ["Critical", "High", "Medium", "Low"]:
            # Check if we have enough history for trend
            if len(self.risk_history[level]) >= 3:
                # Get last few points
                recent = list(self.risk_history[level])[-3:]
                if recent[2] > recent[0]:
                    trend = "[bold red]↑ INCREASING[/bold red]"
                elif recent[2] < recent[0]:
                    trend = "[bold green]↓ DECREASING[/bold green]"
                else:
                    trend = "[yellow]→ STABLE[/yellow]"
            else:
                trend = "[dim]... MONITORING[/dim]"
            
            trend_table.add_row(level, trend)
        
        # Combine tables into risk panel
        risk_panel = Panel(
            Layout(
                Layout(risk_table),
                Layout(trend_table, size=6)
            ),
            title="[b]Risk Distribution",
            border_style="red",
            box=box.ROUNDED
        )
        
        self.layout["risk_meter"].update(risk_panel)
    
    def add_finding(self, message, severity):
        """
        Add a new finding to the recent findings list.
        
        Args:
            message (str): Finding message
            severity (str): Severity level (Critical, High, Medium, Low)
        """
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.recent_findings.insert(0, {
            "timestamp": timestamp,
            "severity": severity,
            "message": message
        })
        
        # Keep only the most recent findings
        self.recent_findings = self.recent_findings[:20]
    
    def update(self):
        """Update the animation frame."""
        # Update frame counter
        self.frame_counter += 1
        
        # Update all sections
        self.update_header()
        self.update_footer()
        self.update_progress_section()
        self.update_stats_section()
        self.update_findings_section()
        self.update_domain_list()
        self.update_risk_meter()
    
    def render(self):
        """Render the current frame."""
        return self.layout