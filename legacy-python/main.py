# main.py
#!/usr/bin/env python3
"""
Password Security Audit Tool with CVSS-Style Risk Scoring
Main entry point for the application
"""

import logging
import sys

from cli import parse_arguments
from core.bloodhound_integration import test_bloodhound_connection
from core.processor import count_accounts_in_domain, generate_pdfs, process_domains
from utils.branding import show_banner, show_completion_summary, show_config_panel
from utils.logging import setup_logging
from utils.serve import serve_html_reports


def main():
    """Main entry point for the password audit tool."""
    # Set console_level to ERROR to suppress debug, info, and warning messages in the console
    # All messages will still go to the log file for troubleshooting
    logger = setup_logging(log_level=logging.DEBUG, console_level=logging.ERROR)
    args = parse_arguments()

    if args.test_bh:
        # Test BloodHound connection
        success, results = test_bloodhound_connection(verbose=True)
        sys.exit(0 if success else 1)

    if args.serve:
        # Serve HTML reports via simple HTTP server
        serve_html_reports(logger)
        return

    if args.pdf:
        generate_pdfs(logger)
        return

    if args.domains:
        # Show banner
        show_banner()

        # Prepare configuration display
        domain_list = [d.split(':')[0] for d in args.domains]

        # Estimate total accounts
        total_accounts = 0
        for domain_entry in args.domains:
            try:
                count = count_accounts_in_domain(domain_entry)
                total_accounts += count
            except Exception:
                pass

        # Check HIBP and BloodHound status
        try:
            from core.config import HIBP_CONFIG
            from core.hibp_correlation import HIBPChecker
            hibp_enabled = HIBP_CONFIG.get("ENABLE_LOOKUP", False)
            if hibp_enabled:
                # Try to check index size
                try:
                    checker = HIBPChecker()
                    hibp_index_size = len(checker.index) if checker.index else 0
                except Exception:
                    hibp_index_size = 0
            else:
                hibp_index_size = 0
        except Exception:
            hibp_enabled = False
            hibp_index_size = 0

        try:
            from core.bloodhound_integration import get_bloodhound_client
            bh_client = get_bloodhound_client()
            bh_enabled = bh_client is not None
        except Exception:
            bh_enabled = False

        # Show configuration panel
        config_info = {
            "domains": domain_list,
            "total_accounts": total_accounts if total_accounts > 0 else "Unknown",
            "output_dir": f"reports/{'-'.join([d.split('.')[0] for d in domain_list[:3]])}-...",
            "hibp_enabled": hibp_enabled,
            "hibp_index_size": hibp_index_size,
            "bloodhound_enabled": bh_enabled
        }
        show_config_panel(config_info)

        # Process domains
        metadata = process_domains(args.domains, logger)

        # Show completion summary
        if metadata:
            show_completion_summary(metadata)
    else:
        print("No arguments provided. Use -d/--domains to process domains, "
              "-p/--pdf to generate PDFs, -s/--serve to start HTTP server, "
              "or --test-bh to test BloodHound connection.")
        sys.exit(1)

if __name__ == "__main__":
    main()