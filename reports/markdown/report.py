# reports/markdown/report.py
"""
Main entry point for Markdown report generation.
"""

import os
from pathlib import Path
from core.config import markdown_folder

# Import all the report generation functions
from reports.markdown.single_domain import generate_markdown_report
from reports.markdown.combined import generate_combined_report
from reports.markdown.actionable import (
    generate_actionable_report,
    generate_combined_actionable_report,
    generate_explained_actionable_report
)

# Ensure directory exists
os.makedirs(markdown_folder, exist_ok=True)

# Re-export all public functions
__all__ = [
    'generate_markdown_report',
    'generate_combined_report',
    'generate_actionable_report',
    'generate_explained_actionable_report'
]