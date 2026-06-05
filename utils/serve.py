# serve.py
#!/usr/bin/env python3
"""
Interactive server module for hosting HTML password audit reports.
Provides a menu-driven interface to select and view reports.
"""

import os
import socket
import http.server
import socketserver
from pathlib import Path
from contextlib import redirect_stdout, redirect_stderr
from core.config import list_report_directories, get_latest_report_dir, REPORTS_BASE_DIR, APP_CONFIG

# Optional Rich imports (not required for basic functionality)
try:
    from rich.console import Console
    from rich.prompt import Prompt
    from utils.branding import (show_report_menu_header, show_report_list,
                                show_server_panel, print_error)
    console = Console()
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    console = None
    Prompt = None

# Get PORT from configuration
PORT = APP_CONFIG["SERVER"]["PORT"]


def is_port_available(port):
    """
    Check if a port is available for binding.

    Args:
        port (int): Port number to check

    Returns:
        bool: True if port is available, False otherwise
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('', port))
            return True
    except OSError:
        return False


def select_report_directory():
    """
    Display interactive menu to select a report directory.

    Returns:
        Path to selected report directory, or None if user quits
    """
    # Get all report directories
    reports = list_report_directories()

    if not reports:
        print_error("No report directories found in reports/\n"
                   "Please run an audit first with: python main.py -d <domains>")
        return None

    while True:
        # Clear screen and show header
        console.clear()
        show_report_menu_header()
        show_report_list(reports)

        # Get user selection
        try:
            choice = Prompt.ask(
                "[bold cyan]Select report[/bold cyan]",
                choices=[str(i) for i in range(1, len(reports) + 1)] + ["L", "l", "Q", "q"],
                default="L"
            )
        except (EOFError, KeyboardInterrupt):
            # Non-interactive environment or user interrupted
            console.print("\n[yellow]Non-interactive mode detected, using latest report...[/yellow]")
            choice = "L"

        if choice.upper() == 'Q':
            console.print("\n[yellow]Exiting...[/yellow]")
            return None
        elif choice.upper() == 'L':
            # Get latest report
            latest_dir = get_latest_report_dir()
            if latest_dir:
                return latest_dir
            else:
                print_error("No latest report found")
                return None
        else:
            # User selected a number
            try:
                index = int(choice) - 1
                if 0 <= index < len(reports):
                    # Return the base_dir from metadata
                    report_base = reports[index].get('base_dir')
                    if report_base:
                        return Path(report_base)
                    else:
                        # Fallback: construct from run_id
                        run_id = reports[index].get('run_id')
                        return REPORTS_BASE_DIR / run_id
            except (ValueError, IndexError):
                pass

        console.print("[red]Invalid selection. Please try again.[/red]")
        console.input("\nPress Enter to continue...")




def serve_directory(directory: Path):
    """
    Start HTTP server to serve the selected directory.

    Args:
        directory: Directory to serve
    """
    if not directory.exists():
        print_error(f"Directory does not exist: {directory}")
        return

    # Change to the directory
    os.chdir(directory)

    # Create handler
    handler = http.server.SimpleHTTPRequestHandler

    # Check if port is available before starting server
    if not is_port_available(PORT):
        print_error(f"Port {PORT} is already in use.\n"
                   f"Please stop the other process using this port or kill it with:\n"
                   f"  lsof -ti :{PORT} | xargs kill")
        return

    # Show server panel
    console.clear()
    show_server_panel(f"http://localhost:{PORT}", str(directory))

    # Start server with output suppression for server logs only
    try:
        with open(os.devnull, 'w') as null_file:
            with redirect_stdout(null_file), redirect_stderr(null_file):
                with socketserver.TCPServer(("", PORT), handler) as httpd:
                    httpd.serve_forever()
    except KeyboardInterrupt:
        console.print("\n[green]Server stopped.[/green]")
    except OSError as e:
        if "Address already in use" in str(e):
            print_error(f"Port {PORT} is already in use.\n"
                       f"Please stop the other server or choose a different port.")
        else:
            print_error(f"Error starting server: {e}")


def serve_html_reports(logger):
    """
    Interactive menu system for serving HTML reports.

    Args:
        logger: Logger instance
    """
    if not RICH_AVAILABLE:
        # Simple fallback - just serve the latest report
        logger.info("Rich library not available. Serving latest HTML report on http://localhost:8008")
        latest = get_latest_report_dir()
        if latest:
            html_dir = latest / 'html'
            if html_dir.exists():
                os.chdir(html_dir)
                with socketserver.TCPServer(("", 8008), http.server.SimpleHTTPRequestHandler) as httpd:
                    print(f"Serving {html_dir} at http://localhost:8008")
                    httpd.serve_forever()
        else:
            logger.error("No reports found")
        return

    try:
        while True:
            # Step 1: Select report directory
            report_dir = select_report_directory()
            if report_dir is None:
                return  # User quit

            # Step 2: Serve the HTML directory directly
            html_dir = report_dir / 'html'

            # Check if HTML directory exists
            if not html_dir.exists():
                print_error(f"HTML directory not found: {html_dir}\n"
                           "Please ensure the report was generated with HTML output.")
                try:
                    console.input("\nPress Enter to continue...")
                except (EOFError, KeyboardInterrupt):
                    return
                continue

            # Check if HTML directory has files
            if not any(html_dir.iterdir()):
                print_error(f"No files found in {html_dir}")
                try:
                    console.input("\nPress Enter to continue...")
                except (EOFError, KeyboardInterrupt):
                    return
                continue

            # Step 3: Serve the HTML directory
            serve_directory(html_dir)

            # After server stops, ask if user wants to serve another report
            console.print()
            try:
                continue_choice = Prompt.ask(
                    "[cyan]Serve another report?[/cyan]",
                    choices=["y", "n"],
                    default="n"
                )
            except (EOFError, KeyboardInterrupt):
                console.print("\n[green]Goodbye![/green]")
                return

            if continue_choice.lower() != 'y':
                console.print("\n[green]Goodbye![/green]")
                return

    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user.[/yellow]")
        return
    except Exception as e:
        logger.error(f"Error in serve menu: {e}", exc_info=True)
        print_error(f"An error occurred: {e}")
        return
