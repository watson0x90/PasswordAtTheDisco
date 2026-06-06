# reports/html/search.py
"""
Search functionality for HTML reports.
"""

import os
from pathlib import Path

from report_lib.standalone_html.components import (
    create_breadcrumb,
    create_navbar,
    create_page_wrapper,
    create_sidebar,
    create_user_detail_offcanvas,
    html_head,
)
from report_lib.standalone_html.scripts import SEARCH_JS, SEARCH_REDACTED_JS, TABLE_SORT_JS, USER_DETAIL_JS


def generate_search_html(json_file, logger=None):
    """
    Generate HTML page for searching accounts with improved error handling and pagination.

    Args:
        json_file (Path): Path to the password data JSON file
        logger (Logger, optional): Logger instance
    """
    try:
        # For search pages, we don't have domain list yet (it's loaded from JSON)
        # So we'll pass an empty list for now - the sidebar will still show search options
        domains = []

        # Create navbar and sidebar
        navbar = create_navbar(current_page='search', include_search=True, include_export=True)
        sidebar = create_sidebar(current_page='search', domains=domains)

        # Start building content (without body tag - that's in page_wrapper)
        content = f"""
                {create_breadcrumb([
                    ('Main Report', './main.html'),
                    ('Account Search', None)
                ])}

                <div class="mb-4">
                    <h1 class="display-4"><i class="bi bi-search me-3"></i>Account Search</h1>
                    <p class="lead text-muted">Search and filter accounts across all domains</p>
                </div>
        """

        # Add search input with Bootstrap form styling
        content += """
                <div class="card mb-4 shadow-sm">
                    <div class="card-header bg-primary text-white">
                        <h5 class="mb-0"><i class="bi bi-funnel me-2"></i>Search Filters</h5>
                    </div>
                    <div class="card-body">
                        <div class="mb-3">
                            <label for="searchInput" class="form-label">Search by Username</label>
                            <input type="text" class="form-control form-control-lg" id="searchInput"
                                   placeholder="Enter username to search...">
                        </div>
                        <div id="resultCount" class="text-muted"></div>
                        <div id="errorMessage" class="alert alert-danger" style="display: none;" role="alert">
                            <i class="bi bi-exclamation-triangle-fill me-2"></i>
                            <span></span>
                        </div>
                    </div>
                </div>
        """

        # Add results table with Bootstrap styling
        content += """
                <div class="card shadow-sm">
                    <div class="card-header bg-info text-dark">
                        <h5 class="mb-0"><i class="bi bi-table me-2"></i>Search Results</h5>
                    </div>
                    <div class="card-body p-0">
                        <div class="table-responsive">
                            <table class="table table-hover table-striped table-bordered mb-0" id="resultsTable">
                                <thead class="table-dark">
                                    <tr>
                                        <th scope="col" data-column="Username">Username</th>
                                        <th scope="col" data-column="Domain">Domain</th>
                                        <th scope="col" data-column="Password">Password</th>
                                        <th scope="col" data-column="Type">Type</th>
                                        <th scope="col" data-column="Risk Level">Risk Level</th>
                                        <th scope="col" data-column="Enabled">Enabled</th>
                                        <th scope="col" data-column="Last Logon Timestamp">Last Logon</th>
                                        <th scope="col" data-column="Password Set to Expire">Expires</th>
                                        <th scope="col" data-column="Controlled Object Count">Controllables</th>
                                        <th scope="col" data-column="DA Domains">DA Pathway</th>
                                        <th scope="col" data-column="Shared With">Shared With</th>
                                        <th scope="col" data-column="Last Password Set">Last Set</th>
                                        <th scope="col" data-column="Days Out of Compliance">Non-Compliant</th>
                                        <th scope="col" data-column="Risk Vector">Risk Vector</th>
                                    </tr>
                                </thead>
                                <tbody>
                                </tbody>
                            </table>
                        </div>
                    </div>
                    <div class="card-footer">
                        <nav aria-label="Search results pagination">
                            <ul class="pagination pagination-sm mb-0 justify-content-center" id="pagination"></ul>
                        </nav>
                    </div>
                </div>
        """

        # Add offcanvas HTML structure
        content += create_user_detail_offcanvas()

        # Add JavaScript (table sorting, search, and user detail)
        # Note: User data will be loaded from password_data.json by SEARCH_JS
        # and made available to USER_DETAIL_JS via the allAccounts array
        # Initialize userDetailsData as empty object - SEARCH_JS will populate it dynamically
        user_detail_script = USER_DETAIL_JS.replace('{USER_DATA_JSON}', '{}')

        content += f"""
                {TABLE_SORT_JS}
                {SEARCH_JS}
                {user_detail_script}
        """

        # Wrap content with navbar and sidebar using page wrapper
        html = html_head("Account Search", include_pdf_export=True, include_search=True, enable_sidebar=True)
        html += create_page_wrapper(content, navbar, sidebar)
        html += """
</body>
</html>
        """

        # Write to file
        from core import config as config_module
        html_dir = getattr(config_module, 'html_reports_folder', Path('output/html_report'))
        output_path = html_dir / 'search.html'
        os.makedirs(output_path.parent, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
        if logger:
            logger.info(f"Generated search HTML report: {output_path}")

    except Exception as e:
        if logger:
            logger.error(f"Error generating search HTML report: {str(e)}")
        else:
            print(f"Error generating search HTML report: {str(e)}")


def generate_search_redacted_html(json_file_with_placeholders, logger=None):
    """
    Generate HTML page for searching accounts with redacted passwords.

    Args:
        json_file_with_placeholders (Path): Path to the redacted password data JSON file
        logger (Logger, optional): Logger instance
    """
    try:
        # For search pages, we don't have domain list yet (it's loaded from JSON)
        # So we'll pass an empty list for now - the sidebar will still show search options
        domains = []

        # Create navbar and sidebar
        navbar = create_navbar(current_page='search_redacted', include_search=True, include_export=True)
        sidebar = create_sidebar(current_page='search_redacted', domains=domains)

        # Start building content (without body tag - that's in page_wrapper)
        content = f"""
                {create_breadcrumb([
                    ('Main Report', './main.html'),
                    ('Account Search (Redacted)', None)
                ])}

                <div class="mb-4">
                    <h1 class="display-4"><i class="bi bi-search me-3"></i>Account Search <small class="text-muted">(Redacted)</small></h1>
                    <p class="lead text-muted">Search and filter accounts with password placeholders</p>
                    <div class="alert alert-warning" role="alert">
                        <i class="bi bi-eye-slash-fill me-2"></i>
                        <strong>Privacy Mode:</strong> Passwords are displayed as placeholders to protect sensitive information.
                    </div>
                </div>
        """

        # Add search input with Bootstrap form styling
        content += """
                <div class="card mb-4 shadow-sm">
                    <div class="card-header bg-primary text-white">
                        <h5 class="mb-0"><i class="bi bi-funnel me-2"></i>Search Filters</h5>
                    </div>
                    <div class="card-body">
                        <div class="mb-3">
                            <label for="searchInput" class="form-label">Search by Username</label>
                            <input type="text" class="form-control form-control-lg" id="searchInput"
                                   placeholder="Enter username to search...">
                        </div>
                        <div id="resultCount" class="text-muted"></div>
                        <div id="errorMessage" class="alert alert-danger" style="display: none;" role="alert">
                            <i class="bi bi-exclamation-triangle-fill me-2"></i>
                            <span></span>
                        </div>
                    </div>
                </div>
        """

        # Add results table with Bootstrap styling
        content += """
                <div class="card shadow-sm">
                    <div class="card-header bg-info text-dark">
                        <h5 class="mb-0"><i class="bi bi-table me-2"></i>Search Results</h5>
                    </div>
                    <div class="card-body p-0">
                        <div class="table-responsive">
                            <table class="table table-hover table-striped table-bordered mb-0" id="resultsTable">
                                <thead class="table-dark">
                                    <tr>
                                        <th scope="col" data-column="Username">Username</th>
                                        <th scope="col" data-column="Domain">Domain</th>
                                        <th scope="col" data-column="Password Placeholder">Password Placeholder</th>
                                        <th scope="col" data-column="Type">Type</th>
                                        <th scope="col" data-column="Risk Level">Risk Level</th>
                                        <th scope="col" data-column="Enabled">Enabled</th>
                                        <th scope="col" data-column="Last Logon Timestamp">Last Logon</th>
                                        <th scope="col" data-column="Password Set to Expire">Expires</th>
                                        <th scope="col" data-column="Controlled Object Count">Controllables</th>
                                        <th scope="col" data-column="DA Domains">DA Pathway</th>
                                        <th scope="col" data-column="Shared With">Shared With</th>
                                        <th scope="col" data-column="Last Password Set">Last Set</th>
                                        <th scope="col" data-column="Days Out of Compliance">Non-Compliant</th>
                                        <th scope="col" data-column="Risk Vector">Risk Vector</th>
                                    </tr>
                                </thead>
                                <tbody>
                                </tbody>
                            </table>
                        </div>
                    </div>
                    <div class="card-footer">
                        <nav aria-label="Search results pagination">
                            <ul class="pagination pagination-sm mb-0 justify-content-center" id="pagination"></ul>
                        </nav>
                    </div>
                </div>
        """

        # Add offcanvas HTML structure
        content += create_user_detail_offcanvas()

        # Add JavaScript (table sorting, redacted search, and user detail)
        # Initialize userDetailsData as empty object - SEARCH_REDACTED_JS will populate it dynamically
        user_detail_script = USER_DETAIL_JS.replace('{USER_DATA_JSON}', '{}')

        content += f"""
                {TABLE_SORT_JS}
                {SEARCH_REDACTED_JS}
                {user_detail_script}
        """

        # Wrap content with navbar and sidebar using page wrapper
        html = html_head("Account Search (Redacted)", include_pdf_export=True, include_redacted_search=True, enable_sidebar=True)
        html += create_page_wrapper(content, navbar, sidebar)
        html += """
</body>
</html>
        """

        # Write to file
        from core import config as config_module
        html_dir = getattr(config_module, 'html_reports_folder', Path('output/html_report'))
        output_path = html_dir / 'search_redacted.html'
        os.makedirs(output_path.parent, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
        if logger:
            logger.info(f"Generated redacted search HTML report: {output_path}")

    except Exception as e:
        if logger:
            logger.error(f"Error generating redacted search HTML report: {str(e)}")
        else:
            print(f"Error generating redacted search HTML report: {str(e)}")