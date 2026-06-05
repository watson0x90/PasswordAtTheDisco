# reports/html/__init__.py
"""
HTML report generation module for password security audit.
"""

from report_lib.standalone_html.report import (
    generate_combined_html_report,
    generate_html_actionable_report,
    generate_html_report,
    generate_main_html,
    generate_search_html,
    generate_search_redacted_html,
)

__all__ = [
    'generate_html_report',
    'generate_html_actionable_report',
    'generate_combined_html_report',
    'generate_main_html',
    'generate_search_html',
    'generate_search_redacted_html'
]