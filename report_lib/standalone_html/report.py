# reports/html/report.py
"""
HTML report generation module for password security audit.
Provides functions to generate interactive HTML reports.
"""

import os
from core.config import html_reports_folder

# Import all submodules for convenience
from report_lib.standalone_html.single_domain import generate_html_report
from report_lib.standalone_html.actionable import generate_html_actionable_report
from report_lib.standalone_html.combined import generate_combined_html_report, generate_main_html
from report_lib.standalone_html.search import generate_search_html, generate_search_redacted_html

# Ensure directory exists
os.makedirs(html_reports_folder, exist_ok=True)

# Re-export all public functions
__all__ = [
    'generate_html_report',
    'generate_html_actionable_report',
    'generate_combined_html_report',
    'generate_main_html',
    'generate_search_html',
    'generate_search_redacted_html'
]