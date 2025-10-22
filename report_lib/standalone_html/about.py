# report_lib/standalone_html/about.py
"""
About page generator for HTML reports.
"""

import os
from pathlib import Path
from report_lib.standalone_html.components import (
    html_head, create_navbar, create_sidebar, create_page_wrapper, create_about_content
)


def generate_about_html(report_metadata, domains=None, logger=None):
    """
    Generate About page with Risk Vector info, scoring system docs, metadata, and methodology.

    Args:
        report_metadata (dict): {
            'timestamp': 'YYYY-MM-DD HH:MM:SS',
            'domains': ['DOMAIN1.COM', 'DOMAIN2.COM'],
            'version': '1.0.0',
            'total_accounts': 1234,
            'cracked_accounts': 567,
            'uncracked_accounts': 667,
            'tool_name': 'Password!AtTheDisco'
        }
        domains (list, optional): List of domain names for sidebar menu
        logger (Logger, optional): Logger instance

    Returns:
        None (writes about.html file)
    """
    try:
        if domains is None:
            domains = report_metadata.get('domains', [])

        # Create HTML components
        navbar = create_navbar(current_page='about', include_search=True, include_export=False)
        sidebar = create_sidebar(current_page='about', domains=domains)
        about_content = create_about_content(report_metadata)

        # Build complete HTML
        html = html_head("About - Password Security Audit", enable_sidebar=True)
        html += create_page_wrapper(about_content, navbar, sidebar)
        html += """
</body>
</html>
        """

        # Write to file
        from core import config as config_module
        html_dir = getattr(config_module, 'html_reports_folder', Path('output/html_report'))
        output_path = html_dir / 'about.html'
        os.makedirs(output_path.parent, exist_ok=True)

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)

        if logger:
            logger.info(f"Generated About page: {output_path}")
        else:
            print(f"Generated About page: {output_path}")

    except Exception as e:
        if logger:
            logger.error(f"Error generating About page: {str(e)}")
        else:
            print(f"Error generating About page: {str(e)}")
        raise
