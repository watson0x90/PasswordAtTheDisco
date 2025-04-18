# main.py
#!/usr/bin/env python3
"""
Password Security Audit Tool with CVSS-Style Risk Scoring
Main entry point for the application
"""

import sys
import logging  # Add this import
from cli import parse_arguments
from processor import process_domains, generate_pdfs
from serve import serve_html_reports
from utils.logging import setup_logging

def main():
    """Main entry point for the password audit tool."""
    # Set console_level to ERROR to suppress debug, info, and warning messages in the console
    # All messages will still go to the log file for troubleshooting
    logger = setup_logging(log_level=logging.DEBUG, console_level=logging.ERROR)
    args = parse_arguments()
    
    if args.serve:
        serve_html_reports(logger)
        return
    
    if args.pdf:
        generate_pdfs(logger)
        return
    
    if args.domains:
        process_domains(args.domains, logger)
    else:
        print("No arguments provided. Use -d/--domains to process domains, "
              "-p/--pdf to generate PDFs, or -s/--serve to serve HTML reports.")
        sys.exit(1)

if __name__ == "__main__":
    main()