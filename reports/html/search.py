# reports/html/search.py
"""
Search functionality for HTML reports.
"""

import os
from pathlib import Path
from reports.html.components import html_head, RISK_VECTOR_EXPLANATION
from reports.html.scripts import SEARCH_JS, SEARCH_REDACTED_JS, TABLE_SORT_JS

def generate_search_html(json_file, logger=None):
    """
    Generate HTML page for searching accounts with improved error handling and pagination.
    
    Args:
        json_file (Path): Path to the password data JSON file
        logger (Logger, optional): Logger instance
    """
    try:
        # Create HTML head
        html = html_head("Account Search", include_pdf_export=True, include_search=True)
        
        html += """
        <body>
            <div id="reportContent">
                <h1>Account Search</h1>
                <p><a href="./main.html">Back to Main</a></p>
        """
        
        # Add search input
        html += """
        <input type="text" id="searchInput" placeholder="Search by Username...">
        <div id="resultCount"></div>
        <div id="errorMessage" style="display: none; color: red; padding: 10px; background-color: #ffeeee; border: 1px solid #ffcccc; margin: 10px 0;"></div>
        """
        
        # Add risk vector explanation
        html += RISK_VECTOR_EXPLANATION
        
        # Add results table - update column names to match the actual data fields
        html += """
        <div class="table-container">
            <table id="resultsTable">
                <thead>
                    <tr>
                        <th data-column="Username">Username</th>
                        <th data-column="Domain">Domain</th>
                        <th data-column="Password">Password</th>
                        <th data-column="Type">Type</th>
                        <th data-column="Risk Level">Risk Level</th>
                        <th data-column="Enabled">Enabled</th>
                        <th data-column="Last Logon Timestamp">Last Logon Timestamp</th>
                        <th data-column="Password Set to Expire">Password Set to Expire</th>
                        <th data-column="Controlled Object Count">Controlled Objects</th>
                        <th data-column="DA Domains">DA Pathway</th>
                        <th data-column="Shared With">Shared With</th>
                        <th data-column="Last Password Set">Last Password Set</th>
                        <th data-column="Days Out of Compliance">Days Out of Compliance</th>
                        <th data-column="Risk Vector">Risk Vector</th>
                    </tr>
                </thead>
                <tbody>
                </tbody>
            </table>
        </div>
        <div id="pagination" class="pagination"></div>
        """
        
        # Add JavaScript and close HTML
        html += f"""
        {TABLE_SORT_JS}
        {SEARCH_JS}
        </div>
        </body>
        </html>
        """

        # Write to file
        output_path = Path(os.path.join('output', 'html_report', 'search.html'))
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
        # Create HTML head
        html = html_head("Account Search (Redacted)", include_pdf_export=True, include_redacted_search=True)
        
        html += """
        <body>
            <div id="reportContent">
                <h1>Account Search (Redacted)</h1>
                <p><a href="./main.html">Back to Main</a></p>
        """
        
        # Add search input
        html += """
        <input type="text" id="searchInput" placeholder="Search by Username...">
        <div id="resultCount"></div>
        <div id="errorMessage" style="display: none; color: red; padding: 10px; background-color: #ffeeee; border: 1px solid #ffcccc; margin: 10px 0;"></div>
        """
        
        # Add risk vector explanation
        html += RISK_VECTOR_EXPLANATION
        
        # Add results table - update column names to match the actual data fields
        html += """
        <div class="table-container">
            <table id="resultsTable">
                <thead>
                    <tr>
                        <th data-column="Username">Username</th>
                        <th data-column="Domain">Domain</th>
                        <th data-column="Password Placeholder">Password Placeholder</th>
                        <th data-column="Type">Type</th>
                        <th data-column="Risk Level">Risk Level</th>
                        <th data-column="Enabled">Enabled</th>
                        <th data-column="Last Logon Timestamp">Last Logon Timestamp</th>
                        <th data-column="Password Set to Expire">Password Set to Expire</th>
                        <th data-column="Controlled Object Count">Controllables Count</th>
                        <th data-column="DA Domains">DA Pathway</th>
                        <th data-column="Shared With">Shared With</th>
                        <th data-column="Last Password Set">Last Password Set</th>
                        <th data-column="Days Out of Compliance">Days Out of Compliance</th>
                        <th data-column="Risk Vector">Risk Vector</th>
                    </tr>
                </thead>
                <tbody>
                </tbody>
            </table>
        </div>
        <div id="pagination" class="pagination"></div>
        """
        
        # Add JavaScript and close HTML
        html += f"""
        {TABLE_SORT_JS}
        {SEARCH_REDACTED_JS}
        </div>
        </body>
        </html>
        """

        # Write to file
        output_path = Path(os.path.join('output', 'html_report', 'search_redacted.html'))
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