# utils/terminal_animation.py
"""
Improved terminal animation module for password security audit tool.
"""

import time
import threading
from datetime import datetime
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn
from rich.text import Text
from rich import box
from rich.table import Table
from rich.layout import Layout

class PasswordAuditAnimation:
    """
    Animation class for the password audit with improved tracking.
    """
    
    def __init__(self, domains):
        """
        Initialize the animation.
        
        Args:
            domains (list): List of domains being analyzed
        """
        self.domains = domains
        self.total_domains = len(domains)
        self.completed_domains = 0
        self.start_time = time.time()
        self.total_accounts = 0
        self.processed_accounts = 0
        self.frame_counter = 0
        
        # Domain tracking
        self.domain_status = {domain: "PENDING" for domain in domains}
        self.active_domains = set()
        self.domain_progress_data = {}  # Track progress for each domain
        
        # For real-time clock updates
        self.current_time = time.time()
        
        # Create a progress container for multiple domains
        self.domain_progress = Progress(
            TextColumn("[bold cyan]Domain:"),
            TextColumn("[bold green]{task.description}"),
            BarColumn(bar_width=40),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("({task.completed}/{task.total})"),
            expand=True
        )
        
        # Create a task ID for each domain
        self.domain_tasks = {}
        for domain in domains:
            task_id = self.domain_progress.add_task(
                domain, 
                total=100,  # Default
                visible=False  # Hide initially
            )
            self.domain_tasks[domain] = task_id
            self.domain_progress_data[domain] = {
                "total": 100,
                "completed": 0
            }
        
        # Start timer thread immediately
        self._start_timer_thread()
    
    def _start_timer_thread(self):
        """Start a separate thread to update the timer continuously."""
        def update_timer():
            try:
                while True:
                    self.current_time = time.time()
                    time.sleep(0.1)  # Update 10 times per second for smoother display
            except Exception:
                pass
                
        timer_thread = threading.Thread(target=update_timer, daemon=True)
        timer_thread.start()
    
    def get_header(self):
        """Create the header panel with current running time."""
        # Force recalculation of elapsed time directly from start_time
        elapsed = time.time() - self.start_time
        
        hours, remainder = divmod(int(elapsed), 3600)
        minutes, seconds = divmod(remainder, 60)
        time_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
        
        header_text = Text()
        header_text.append("Password! At The Disco - ", style="bold white")
        header_text.append("Vector Based Risk Analysis", style="bold green")
        header_text.append(f" - Running time: {time_str}", style="bold cyan")
        
        return Panel(
            header_text,
            box=box.HEAVY,
            border_style="blue",
            title="Security Audit",
            title_align="center"
        )
    
    def get_domains_list(self):
        """Create a table with domain status."""
        domains_table = Table(show_header=False, box=None, expand=True)
        domains_table.add_column("Domain", style="cyan")
        domains_table.add_column("Status", style="green", justify="right")
        
        # Determine which domains to show (all processing domains + some others)
        visible_domains = list(self.active_domains)
        
        # Add some completed and pending domains to fill out the table
        remaining_slots = 10 - len(visible_domains)
        if remaining_slots > 0:
            # Add some completed domains
            completed_domains = [d for d in self.domains if 
                                self.domain_status.get(d) == "COMPLETE" and 
                                d not in visible_domains][:remaining_slots//2]
            visible_domains.extend(completed_domains)
            
            # Add some pending domains
            remaining_slots = 10 - len(visible_domains)
            if remaining_slots > 0:
                pending_domains = [d for d in self.domains if 
                                  self.domain_status.get(d) == "PENDING" and 
                                  d not in visible_domains][:remaining_slots]
                visible_domains.extend(pending_domains)
        
        # Ensure we don't show more than 10 domains total
        visible_domains = visible_domains[:10]
        
        # Show domains with appropriate status indicators
        for domain in visible_domains:
            status = self.domain_status.get(domain, "PENDING")
            
            # For any currently processing domain, add animated lightning bolt
            if status == "PROCESSING":
                bolt = "⚡" * (1 + (self.frame_counter % 3))
                domains_table.add_row(domain, f"{bolt} {status}")
            elif status == "ERROR":
                domains_table.add_row(domain, "[bold red]ERROR[/bold red]")
            elif status == "COMPLETE":
                domains_table.add_row(domain, "[bold green]COMPLETE[/bold green]")
            else:
                domains_table.add_row(domain, status)
        
        return Panel(
            domains_table,
            title="Domain Queue",
            border_style="green",
            box=box.ROUNDED
        )
    
    def get_footer(self):
        """Create the footer panel with account processing stats."""
        # Choose lightning bolt animation frame
        bolt_patterns = ["⚡", "⚡⚡", "⚡⚡⚡", "⚡⚡"]
        bolt = bolt_patterns[self.frame_counter % len(bolt_patterns)]
        
        # Include both current domain and total account processing info
        footer_text = Text()
        footer_text.append(f"{bolt} ", style="bold yellow")
        footer_text.append(f"Domains: {self.completed_domains}/{self.total_domains} | ", style="bold cyan")
        
        # Display the active domains
        processing_domains = " | ".join(sorted(self.active_domains))
        if processing_domains:
            footer_text.append(f"Processing: {processing_domains} | ", style="bold red")
        else:
            footer_text.append(f"Processing: None | ", style="bold red")
        
        # Add account count info
        domains_with_progress = [d for d in self.active_domains if d in self.domain_progress_data]
        current_domain_counts = []
        for domain in domains_with_progress:
            data = self.domain_progress_data[domain]
            current_domain_counts.append(f"{domain}: {data['completed']}/{data['total']}")
            
        if current_domain_counts:
            footer_text.append(f"Current domain accounts: {' | '.join(current_domain_counts)} | ", style="bold magenta")
        
        footer_text.append(f"Total accounts: {self.processed_accounts} | ", style="bold green")
        footer_text.append("Press Ctrl+C to abort", style="dim")
        
        return Panel(
            footer_text, 
            box=box.HEAVY, 
            border_style="blue"
        )
    
    def render(self):
        """Render the full UI."""
        # Create main layout
        layout = Layout()
        
        # Split into header, body, footer
        layout.split(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="footer", size=3)
        )
        
        # Update header and footer
        layout["header"].update(self.get_header())
        layout["footer"].update(self.get_footer())
        
        # Create body with progress and domains
        body = Layout()
        body.split_row(
            Layout(name="progress", ratio=3),
            Layout(name="domains", ratio=2)
        )
        
        # Update the progress section with visible progress bars for active domains
        for domain in self.domains:
            if self.domain_status[domain] == "PROCESSING":
                self.domain_progress.update(
                    self.domain_tasks[domain],
                    visible=True
                )
            else:
                self.domain_progress.update(
                    self.domain_tasks[domain],
                    visible=False
                )
        
        # Update the body sections
        body["progress"].update(self.domain_progress)
        body["domains"].update(self.get_domains_list())
        
        # Update the main body
        layout["body"].update(body)
        
        # Increment frame counter for animations
        self.frame_counter += 1
        
        return layout
    
    def set_domain_progress(self, domain, total=None, completed=None, increment=None):
        """
        Update progress for a specific domain.
        
        Args:
            domain (str): Domain name
            total (int, optional): Total accounts for this domain
            completed (int, optional): Current completed count
            increment (int, optional): Amount to increment completed count
        """
        if domain not in self.domain_tasks:
            return
        
        # Update domain data
        domain_data = self.domain_progress_data[domain]
        
        if total is not None:
            domain_data["total"] = max(1, total)
            self.domain_progress.update(self.domain_tasks[domain], total=domain_data["total"])
        
        if completed is not None:
            domain_data["completed"] = min(completed, domain_data["total"])
        elif increment is not None:
            domain_data["completed"] = min(domain_data["completed"] + increment, domain_data["total"])
        
        # Update progress bar
        self.domain_progress.update(
            self.domain_tasks[domain],
            completed=domain_data["completed"],
            visible=self.domain_status[domain] == "PROCESSING"
        )
    
    def set_domain_active(self, domain, is_active=True, total_accounts=None):
        """
        Set a domain as active or inactive.
        
        Args:
            domain (str): Domain name
            is_active (bool): Whether domain is active
            total_accounts (int, optional): Total accounts for this domain
        """
        if domain not in self.domains:
            return
        
        # Update status
        if is_active:
            self.domain_status[domain] = "PROCESSING"
            self.active_domains.add(domain)
            
            if total_accounts is not None:
                self.set_domain_progress(domain, total=total_accounts, completed=0)
        else:
            if domain in self.active_domains:
                self.active_domains.remove(domain)
            
            # Mark as complete
            self.domain_status[domain] = "COMPLETE"
            
            # Update progress to 100%
            self.set_domain_progress(
                domain, 
                completed=self.domain_progress_data[domain]["total"]
            )
    
    def mark_domain_completed(self, domain, accounts_processed=None):
        """
        Mark a domain as completed and update stats.
        
        Args:
            domain (str): Domain name
            accounts_processed (int, optional): Number of accounts processed
        """
        # Remove from active domains
        if domain in self.active_domains:
            self.active_domains.remove(domain)
        
        # Update domain status
        self.domain_status[domain] = "COMPLETE"
        
        # Update completed domains count
        self.completed_domains += 1
        
        # Update progress to 100%
        domain_data = self.domain_progress_data.get(domain, {"total": 100})
        self.set_domain_progress(domain, completed=domain_data["total"])
        
        # Add to total accounts processed
        if accounts_processed is not None:
            self.processed_accounts += accounts_processed
    
    def mark_domain_error(self, domain):
        """
        Mark a domain as having an error.
        
        Args:
            domain (str): Domain name
        """
        if domain in self.active_domains:
            self.active_domains.remove(domain)
            
        self.domain_status[domain] = "ERROR"
        self.completed_domains += 1