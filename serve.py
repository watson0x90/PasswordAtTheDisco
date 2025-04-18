# serve.py
#!/usr/bin/env python3
"""
Server module for hosting HTML password audit reports.
Provides a local HTTP server to view the generated reports.
"""

import os
import sys
import http.server
import socketserver
from contextlib import redirect_stdout, redirect_stderr
from core.config import html_reports_folder

PORT = 8000

def serve_html_reports(logger):
    """Start a local HTTP server to serve the HTML reports."""
    if not os.path.exists(html_reports_folder):
        logger.error(f"Directory {html_reports_folder} does not exist. "
                     f"Please run the audit first with -d to generate reports.")
        sys.exit(1)
    
    os.chdir(html_reports_folder)
    handler = http.server.SimpleHTTPRequestHandler
    
    # Suppress terminal output while preserving logging
    with open(os.devnull, 'w') as null_file:
        with redirect_stdout(null_file), redirect_stderr(null_file):
            try:
                with socketserver.TCPServer(("", PORT), handler) as httpd:
                    logger.info(f"Serving HTML reports at http://localhost:{PORT}")
                    logger.info("Press Ctrl+C to stop the server")
                    httpd.serve_forever()
            except KeyboardInterrupt:
                logger.info("Server stopped.")
                sys.exit(0)