import os
import http.server
import socketserver
from contextlib import redirect_stdout, redirect_stderr
from core.config import html_reports_folder

PORT = 8000

def serve_html_reports(logger):
    
    if not os.path.exists(html_reports_folder):
        logger.error(f"Directory {html_reports_folder} does not exist. Please run the audit first.")
        exit(1)
    
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
                exit(0)

if __name__ == "__main__":
    serve_html_reports()