# reports/__init__.py
"""
Module for password security audit report generation.
"""

from report_lib.csv.report import write_csv_report

# Excel import is optional (requires pandas)
try:
    from report_lib.excel.report import write_actionable_excel
except ImportError:
    write_actionable_excel = None

# Markdown import is optional (requires markdown module)
try:
    from report_lib.markdown.report import (generate_markdown_report, generate_combined_report,
                                     generate_actionable_report, generate_explained_actionable_report)
except ImportError:
    generate_markdown_report = None
    generate_combined_report = None
    generate_actionable_report = None
    generate_explained_actionable_report = None