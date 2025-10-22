# utils/terminal_animation_simple.py
"""
Simple terminal animation fallback when Rich is not available.
Provides basic console output without fancy formatting.
"""

import time
import threading

class SimpleDomainTracker:
    """
    Simple domain progress tracker without Rich dependency.
    """

    def __init__(self, domains):
        """Initialize the tracker with list of domains to process."""
        self.domains = domains
        self.domain_status = {domain: {"status": "pending", "accounts": 0} for domain in domains}
        self.start_time = time.time()
        self.is_displaying = False

    def set_domain_active(self, domain, is_active=True, total_accounts=None):
        """Set domain as active or inactive."""
        if domain in self.domain_status:
            self.domain_status[domain]["status"] = "active" if is_active else "inactive"
            if total_accounts:
                self.domain_status[domain]["accounts"] = total_accounts
            print(f"Processing {domain}... ({total_accounts or 0} accounts)")

    def mark_domain_completed(self, domain, accounts_processed=None):
        """Mark a domain as completed."""
        if domain in self.domain_status:
            self.domain_status[domain]["status"] = "completed"
            if accounts_processed:
                self.domain_status[domain]["accounts"] = accounts_processed
            print(f"✓ {domain} completed ({accounts_processed or 0} accounts)")

    def mark_domain_error(self, domain):
        """Mark a domain as having an error."""
        if domain in self.domain_status:
            self.domain_status[domain]["status"] = "error"
            print(f"✗ {domain} failed")

    def start_display(self):
        """Start the display loop."""
        self.is_displaying = True
        # No animation in simple mode

    def stop_display(self):
        """Stop the display loop."""
        self.is_displaying = False
        elapsed = time.time() - self.start_time
        print(f"\nTotal time: {int(elapsed)}s")


class PasswordAuditAnimation:
    """
    Compatibility wrapper class for simple animation.
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

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        pass