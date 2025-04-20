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
        self.current_domain_index = 0
        self.completed_domains = 0
        self.start_time = time.time()
        self.total_accounts = 0
        self.processed_accounts = 0
        self.frame_counter = 0
        self.current_domain = domains[0] if domains else "Unknown"
        self.current_domain_total = 100  # Default
        self.current_domain_completed = 0
        self.domain_status = {domain: "PENDING" for domain in domains}
        if domains:
            self.domain_status[domains[0]] = "PROCESSING"
        
        # For real-time clock updates
        self.current_time = time.time()
        self.timer_lock = threading.Lock()
        self._start_timer_thread()
        
        # Create progress bars
        self.domain_progress = Progress(
            TextColumn("[bold cyan]Domain:"),
            TextColumn("[bold green]{task.description}"),
            BarColumn(bar_width=40),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("({task.completed}/{task.total})"),
            expand=True
        )
        
        self.domain_task = self.domain_progress.add_task(
            self.current_domain, 
            total=self.current_domain_total
        )
    
    def _start_timer_thread(self):
        """Start a separate thread to update the timer continuously."""
        def update_timer():
            while True:
                with self.timer_lock:
                    self.current_time = time.time()
                time.sleep(0.2)  # Update 5 times per second
                
        timer_thread = threading.Thread(target=update_timer, daemon=True)
        timer_thread.start()
    
    def get_header(self):
        """Create the header panel with current running time."""
        # Calculate current elapsed time using the thread-updated time
        with self.timer_lock:
            elapsed = self.current_time - self.start_time
        
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
        
        # Determine which domains to show (focus on current + a few before/after)
        visible_count = min(10, len(self.domains))
        
        # Calculate start index to center around current domain
        current_idx = self.current_domain_index
        if current_idx < visible_count // 2:
            start_idx = 0
        elif current_idx > len(self.domains) - visible_count // 2:
            start_idx = max(0, len(self.domains) - visible_count)
        else:
            start_idx = max(0, current_idx - visible_count // 2)
            
        end_idx = min(len(self.domains), start_idx + visible_count)
        
        # Show domains with appropriate status indicators
        for i in range(start_idx, end_idx):
            domain = self.domains[i]
            status = self.domain_status.get(domain, "PENDING")
            
            # For the current processing domain, add animated lightning bolt
            if domain == self.current_domain and status == "PROCESSING":
                bolt = "⚡" * (1 + (self.frame_counter % 3))
                domains_table.add_row(domain, f"{bolt} {status}")
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
        
        # Display the active domain and account info
        domain_display = self.current_domain if self.current_domain else "None"
        footer_text.append(f"Processing: {domain_display} | ", style="bold red")
        
        # Add current domain account info if available
        if self.current_domain_total > 0:
            footer_text.append(f"Current domain accounts: {self.current_domain_completed}/{self.current_domain_total} | ", style="bold magenta")
            
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
            Layout(name="progress"),
            Layout(name="domains")
        )
        
        # Update the body sections
        body["progress"].update(self.domain_progress)
        body["domains"].update(self.get_domains_list())
        
        # Update the main body
        layout["body"].update(body)
        
        # Increment frame counter for animations
        self.frame_counter += 1
        
        return layout
    
    def set_domain(self, domain_index, total_accounts=None):
        """
        Set the active domain and update progress.
        
        Args:
            domain_index (int): Index of domain in the domains list
            total_accounts (int, optional): Total accounts in the domain
        """
        if 0 <= domain_index < len(self.domains):
            # Mark previous domain as complete if it was being processed
            if self.current_domain_index < len(self.domains):
                prev_domain = self.domains[self.current_domain_index]
                if prev_domain != self.domains[domain_index]:  # Only if changing domains
                    if self.domain_status.get(prev_domain) == "PROCESSING":
                        self.domain_status[prev_domain] = "COMPLETE"
            
            # Set new current domain
            self.current_domain_index = domain_index
            self.current_domain = self.domains[domain_index]
            self.domain_status[self.current_domain] = "PROCESSING"
            
            if total_accounts is not None:
                self.current_domain_total = max(1, total_accounts)
                self.current_domain_completed = 0
            
            # Update the progress bar
            self.domain_progress.update(
                self.domain_task,
                description=self.current_domain,
                completed=0,
                total=self.current_domain_total
            )
    
    def update_progress(self, completed=None, increment=None):
        """
        Update current domain progress.
        
        Args:
            completed (int, optional): Directly set completed count
            increment (int, optional): Increment current completed count
        """
        if completed is not None:
            self.current_domain_completed = min(completed, self.current_domain_total)
        elif increment is not None:
            self.current_domain_completed = min(
                self.current_domain_completed + increment, 
                self.current_domain_total
            )
            
        self.domain_progress.update(
            self.domain_task,
            completed=self.current_domain_completed
        )
    
    def complete_domain(self):
        """Mark current domain as complete and move to next."""
        # Update counters
        self.completed_domains += 1
        self.processed_accounts += self.current_domain_completed
        
        # Mark current domain as complete
        if self.current_domain:
            self.domain_status[self.current_domain] = "COMPLETE"
        
        # Set progress to 100%
        self.update_progress(completed=self.current_domain_total)
        
    def set_total_accounts(self, count):
        """Set the total number of accounts processed across all domains."""
        self.processed_accounts = count