# cli.py
#!/usr/bin/env python3
"""
Command line interface module for the password audit tool.
Handles argument parsing and command-line options.
"""

import argparse


def parse_arguments():
    """Parse command-line arguments for the password audit tool."""
    parser = argparse.ArgumentParser(description='Audit password files across multiple domains.')

    parser.add_argument('-d', '--domains', nargs='+',
                        help='Domain and files in format domain:cracked_file:uncracked_file')
    parser.add_argument('-p', '--pdf', action='store_true',
                        help='Generate PDFs from existing Markdown reports')
    parser.add_argument('-s', '--serve', action='store_true',
                        help='Start HTTP server to view HTML reports (port 8008)')
    parser.add_argument('--test-bh', action='store_true',
                        help='Test BloodHound API connection and credentials')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s 1.0',
                        help='Show program version and exit')

    return parser.parse_args()