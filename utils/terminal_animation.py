# utils/terminal_animation.py
"""
Simplified terminal animation module for password security audit tool.
Shows basic domain processing status and running time with Rich formatting.
"""

import threading
import time

# Optional import for Rich (not required for basic functionality)
try:
    from rich.console import Console
    from rich.text import Text
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    Console = None
    Text = None

class SimpleDomainTracker:
    """
    Simple domain progress tracker with minimal console output.
    Uses Rich formatting for colors and emojis while maintaining simple design.
    """
    
    def __init__(self, domains):
        """
        Initialize the tracker with list of domains to process.
        
        Args:
            domains (list): List of domain names to process
        """
        self.domains = domains
        self.total_domains = len(domains)
        self.completed_domains = 0
        self.start_time = time.time()
        self.active_domains = set()
        self.domain_status = {domain: "PENDING" for domain in domains}
        self.lock = threading.Lock()  # Thread safety for console updates
        self.console = Console()
        self.accounts_processed = 0
        
        # Print initial status
        self._print_status()
        
        # Start a timer thread to update elapsed time
        self.running = True
        self.timer_thread = threading.Thread(target=self._time_updater, daemon=True)
        self.timer_thread.start()
    
    def _time_updater(self):
        """Thread that updates the display every second to show elapsed time."""
        while self.running:
            time.sleep(1)
            self._print_status()
    
    def _print_status(self):
        """Print the current status line with elapsed time and active domains."""
        with self.lock:
            # Calculate elapsed time
            elapsed = time.time() - self.start_time
            hours, remainder = divmod(int(elapsed), 3600)
            minutes, seconds = divmod(remainder, 60)
            time_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
            
            # Create rich text for status
            text = Text()
            text.append("🔐 ", style="bold yellow")  # Lock emoji
            text.append("Password! At The Disco ", style="bold cyan")
            text.append("⏱️ ", style="bold white")  # Timer emoji
            text.append(f"Running time: {time_str}", style="cyan")
            text.append(" | ", style="white")
            text.append("Progress: ", style="green")
            text.append(f"{self.completed_domains}/{self.total_domains}", style="bold green")
            text.append(" domains", style="green")
            text.append(" | ", style="white")
            
            # Add active domains
            text.append("⚡ ", style="bold yellow")  # Lightning emoji for processing
            text.append("Processing: ", style="magenta")
            
            if self.active_domains:
                active_domains_str = ", ".join(sorted(self.active_domains))
                text.append(active_domains_str, style="bold magenta")
            else:
                text.append("None", style="dim magenta")
                
            # Add account count if available
            if self.accounts_processed > 0:
                text.append(" | ", style="white")
                text.append("🔑 ", style="bold yellow")  # Key emoji
                text.append(f"Accounts: {self.accounts_processed}", style="cyan")
            
            # Print the status (overwriting the previous line)
            self.console.print(text, end="\r")
    
    def set_domain_active(self, domain, is_active=True, total_accounts=None):
        """
        Mark a domain as active/processing.
        
        Args:
            domain (str): Domain name
            is_active (bool): Whether domain is active
            total_accounts (int, optional): Total accounts in domain
        """
        with self.lock:
            if is_active:
                self.active_domains.add(domain)
                self.domain_status[domain] = "PROCESSING"
            else:
                if domain in self.active_domains:
                    self.active_domains.remove(domain)
        self._print_status()
    
    def mark_domain_completed(self, domain, accounts_processed=None):
        """
        Mark a domain as completed.
        
        Args:
            domain (str): Domain name
            accounts_processed (int, optional): Number of accounts processed
        """
        with self.lock:
            if domain in self.active_domains:
                self.active_domains.remove(domain)
            self.completed_domains += 1
            self.domain_status[domain] = "COMPLETE"
            
            if accounts_processed is not None:
                self.accounts_processed += accounts_processed
                
        self._print_status()
    
    def mark_domain_error(self, domain):
        """
        Mark a domain as errored.
        
        Args:
            domain (str): Domain name
        """
        with self.lock:
            if domain in self.active_domains:
                self.active_domains.remove(domain)
            self.completed_domains += 1
            self.domain_status[domain] = "ERROR"
        self._print_status()
    
    def stop(self):
        """Stop the timer thread and print final newline."""
        self.running = False
        if self.timer_thread.is_alive():
            self.timer_thread.join(timeout=1.0)
        
        # Final status with completion emoji
        with self.lock:
            text = Text()
            text.append("✅ ", style="bold green")  # Complete emoji
            text.append(f"Processed {self.completed_domains}/{self.total_domains} domains", style="bold green")
            text.append(f" and {self.accounts_processed} accounts", style="green")
            text.append(" in ", style="white")
            
            # Calculate total time
            elapsed = time.time() - self.start_time
            hours, remainder = divmod(int(elapsed), 3600)
            minutes, seconds = divmod(remainder, 60)
            time_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
            text.append(time_str, style="cyan")
            
            # Print with newline
            self.console.print(text)

# Compatibility wrapper class to match the original interface
class PasswordAuditAnimation:
    """
    Compatibility wrapper class that uses SimpleDomainTracker
    but maintains the original PasswordAuditAnimation interface.
    """
    def __init__(self, domains):
        """Initialize with domains list."""
        self.tracker = SimpleDomainTracker(domains)
        self.completed_domains = 0
        self.domain_status = {domain: "PENDING" for domain in domains}
        
    def set_domain_active(self, domain, is_active=True, total_accounts=None):
        """Set domain as active/inactive."""
        self.tracker.set_domain_active(domain, is_active, total_accounts)
        
    def mark_domain_completed(self, domain, accounts_processed=None):
        """Mark domain as completed."""
        self.tracker.mark_domain_completed(domain, accounts_processed)
        self.completed_domains += 1
        self.domain_status[domain] = "COMPLETE"
        
    def mark_domain_error(self, domain):
        """Mark domain as errored."""
        self.tracker.mark_domain_error(domain)
        self.completed_domains += 1
        self.domain_status[domain] = "ERROR"
        
    def render(self):
        """For compatibility with Rich's Live display (returns None)."""
        return None