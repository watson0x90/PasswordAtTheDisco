# reports/html/combined.py
"""
Combined domain report generation module.
"""

import os
from pathlib import Path
from collections import Counter
from reports.html.components import (
    html_head, get_export_button, create_error_message, 
    create_visualization_container, RISK_VECTOR_EXPLANATION
)
from reports.html.scripts import TABLE_SORT_JS
from reports.html.styles import BASE_CSS
from utils.visualization_helper import add_visualization_to_html

def generate_combined_html_report(combined_rows, global_password_to_users, global_hash_to_users, visuals, logger=None):
    """
    Generate combined HTML report for cross-domain analysis with improved error handling.
    
    Args:
        combined_rows (list): Combined account rows across domains
        global_password_to_users (dict): Mapping of passwords to users across domains
        global_hash_to_users (dict): Mapping of hashes to users across domains
        visuals (dict): Dictionary of visualization paths
        logger (Logger, optional): Logger instance
    """
    try:
        # Create HTML head
        html = html_head("Cross-Domain Password Security Report")
        
        html += """
        <body>
            <div id="reportContent">
                <h1>Cross-Domain Password Security Report</h1>
                <p><a href="./main.html">Back to Main</a> | <a href="./search.html">Search Accounts</a></p>
        """
        
        # Add export button
        html += get_export_button('reportContent', 'cross_domain_report.pdf')
        
        # Add risk vector explanation
        html += RISK_VECTOR_EXPLANATION
        
        # Add error message div (hidden by default)
        html += '<div id="errorMessage" style="display: none; color: red; padding: 10px; background-color: #ffeeee; border: 1px solid #ffcccc; margin: 10px 0;"></div>'

        try:
            total_shared = len(combined_rows)
            shared_da = sum(1 for row in combined_rows if row.get('DA Domains', 'None') not in ('None', 'Unknown') and row['Shared With'] > 0)
        except Exception as e:
            if logger:
                logger.error(f"Error computing basic metrics for combined report: {str(e)}")
            total_shared = 0
            shared_da = 0
            html += create_error_message(f"Error computing basic metrics: {str(e)}")

        # Overview section
        html += f"""
        <h2>Overview</h2>
        <ul>
            <li><strong>Accounts Sharing Credentials Across Domains:</strong> {total_shared}</li>
            <li><strong>Shared DA Pathway Accounts:</strong> {shared_da}</li>
        </ul>
        """
        
        if total_shared == 0:
            html += "<p>No cross-domain sharing detected.</p>\n"

        # Top shared passwords section with error handling
        try:
            password_counts = Counter({pw: len(users) for pw, users in global_password_to_users.items() if len(users) > 1})
            top_passwords = password_counts.most_common(5)
            html += """
            <h2>Top Shared Passwords</h2>
            """
            if top_passwords:
                html += """
                <div class="table-container">
                    <table>
                        <thead>
                            <tr><th>Password</th><th>Total Accounts</th><th>Instances per Domain</th></tr>
                        </thead>
                        <tbody>
                """
                for pw, _ in top_passwords:
                    domain_counts = Counter()
                    for u in global_password_to_users[pw]:
                        domain = None
                        if isinstance(u, tuple) and len(u) > 1:
                            domain = u[1]
                        elif isinstance(u, str) and '@' in u:
                            domain = u.split('@')[1]
                        
                        if domain:
                            domain_counts[domain] += 1
                    
                    instances = ', '.join(f"{d}: {c}" for d, c in domain_counts.items())
                    total = sum(domain_counts.values())
                    html += f"                <tr><td>{pw}</td><td>{total}</td><td>{instances}</td></tr>\n"
                html += "            </tbody>\n        </table>\n</div>\n"
            else:
                html += "<p>No passwords shared across domains.</p>\n"
        except Exception as e:
            if logger:
                logger.error(f"Error processing top shared passwords: {str(e)}")
            html += create_error_message(f"Error processing top shared passwords: {str(e)}")

        # Add cross-domain visualizations
        for vis_type, title in [
            ('combined_sharing', 'Cross-Domain Sharing'),
            ('sharing_heatmap', 'Sharing Heatmap'),
            ('da_exposure', 'DA Exposure by Domain'),
            ('shared_network', 'Password Sharing Network')
        ]:
            vis_html = add_visualization_to_html(visuals, vis_type, title)
            if vis_html:
                html += vis_html

        # Generate password sharing details table
        try:
            html += build_password_sharing_section(combined_rows, global_password_to_users, global_hash_to_users)
        except Exception as e:
            if logger:
                logger.error(f"Error generating password sharing details: {str(e)}")
            html += create_error_message(f"Error generating password sharing details: {str(e)}")

        # Add JavaScript and close HTML
        html += f"""
        {TABLE_SORT_JS}
        </div>
        </body>
        </html>
        """

        # Write to file
        output_path = Path(os.path.join('output', 'html_report', 'combined_report.html'))
        os.makedirs(output_path.parent, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
        if logger:
            logger.info(f"Generated combined HTML report: {output_path}")
            
    except Exception as e:
        if logger:
            logger.error(f"Error generating combined HTML report: {str(e)}")
        else:
            print(f"Error generating combined HTML report: {str(e)}")


def build_password_sharing_section(combined_rows, global_password_to_users, global_hash_to_users):
    """
    Build the password sharing details section.
    
    Args:
        combined_rows (list): Combined account rows across domains
        global_password_to_users (dict): Mapping of passwords to users across domains
        global_hash_to_users (dict): Mapping of hashes to users across domains
        
    Returns:
        str: HTML string for the section
    """
    from collections import defaultdict
    
    # Prepare DA sharing analysis
    html = "<h2>Cross-Domain Privilege Exposure</h2>"
    
    # Group DA accounts by password
    da_accounts = [row for row in combined_rows 
                  if row.get('DA Domains', 'None') not in ('None', 'Unknown')]
    
    if da_accounts:
        cracked_by_password = defaultdict(list)
        for acc in da_accounts:
            if isinstance(acc.get('Password', ''), str):
                # Only include cracked passwords, not hashes
                if acc['Password'] not in global_hash_to_users:
                    cracked_by_password[acc['Password']].append(acc)
        
        if cracked_by_password:
            html += """
            <h3>Cracked Accounts with DA Pathways</h3>
            <p>Cracked accounts with Domain Admin privileges that share passwords across domains:</p>
            <div class="table-container">
                <table>
                    <thead>
                        <tr><th>Username</th><th>Domain</th><th>Password</th><th>DA Domains</th>
                        <th>Domains Shared</th><th>Risk Level</th><th>Risk Vector</th></tr>
                    </thead>
                    <tbody>
            """
            
            for password, accounts in cracked_by_password.items():
                for acc in accounts:
                    da_domains = acc.get('DA Domains', 'None')
                    domains_shared = acc.get('Domains Shared', '')
                    risk_level = acc.get('Risk Level', 'Unknown')
                    risk_vector = acc.get('Risk Vector', 'N/A')
                    domain = acc.get('Domain', 'Unknown')
                    
                    html += f"""
                    <tr class="risk-{risk_level.lower()}">
                        <td>{acc['Username']}</td>
                        <td>{domain}</td>
                        <td>{password}</td>
                        <td>{da_domains}</td>
                        <td>{domains_shared}</td>
                        <td>{risk_level}</td>
                        <td>{risk_vector}</td>
                    </tr>
                    """
            
            html += """
                    </tbody>
                </table>
            </div>
            """
        else:
            html += "<p>No cracked accounts with DA pathways found sharing passwords across domains.</p>"
    else:
        html += "<p>No accounts with DA pathways detected.</p>"
    
    # Analyze accounts sharing passwords with DA accounts
    html += "<h3>Accounts Sharing Passwords with DA Accounts</h3>"
    
    # Find passwords used by DA accounts
    da_passwords = set()
    for row in combined_rows:
        if row.get('DA Domains', 'None') not in ('None', 'Unknown'):
            if isinstance(row.get('Password', ''), str) and row['Password'] not in global_hash_to_users:
                da_passwords.add(row['Password'])
    
    # Find non-DA accounts using those passwords
    shared_with_da = [row for row in combined_rows 
                     if row.get('Password', '') in da_passwords and 
                     row.get('DA Domains', 'None') in ('None', 'Unknown')]
    
    if shared_with_da:
        html += """
        <p>Non-privileged accounts sharing passwords with Domain Admin accounts:</p>
        <div class="table-container">
            <table>
                <thead>
                    <tr><th>Username</th><th>Domain</th><th>Password</th><th>Shared With</th>
                    <th>Domains Shared</th><th>Risk Level</th></tr>
                </thead>
                <tbody>
        """
        
        for acc in shared_with_da:
            html += f"""
            <tr class="risk-{acc.get('Risk Level', 'Unknown').lower()}">
                <td>{acc['Username']}</td>
                <td>{acc.get('Domain', 'Unknown')}</td>
                <td>{acc['Password']}</td>
                <td>{acc.get('Shared With', 0)}</td>
                <td>{acc.get('Domains Shared', '')}</td>
                <td>{acc.get('Risk Level', 'Unknown')}</td>
            </tr>
            """
        
        html += """
                </tbody>
            </table>
        </div>
        """
    else:
        html += "<p>No non-privileged accounts found sharing passwords with DA accounts.</p>"
    
    return html


def generate_main_html(domains, logger=None):
    """
    Generate main HTML dashboard page with links to all reports.
    
    Args:
        domains (list): List of domain names
        logger (Logger, optional): Logger instance
    """
    try:
        # Create HTML head with dashboard styles
        from reports.html.styles import DASHBOARD_CSS
        from reports.html.scripts import DOMAIN_DATA_LOADER_JS
        
        html = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
            <title>Password Security Audit - Dashboard</title>
            <style>
            {BASE_CSS}
            {DASHBOARD_CSS}
            </style>
        </head>
        <body>
            <h1>Password Security Audit Dashboard</h1>
            
            <h2>Domain Overview</h2>
            <div class="dashboard-grid">
        """
        
        # Try to load data for each domain
        for domain in domains:
            # Create domain card
            html += f"""
            <div class="domain-card">
                <h3>{domain}</h3>
                <p class="metric">--</p>
                <p class="metric-label">Accounts Analyzed</p>
                <div class="card-links">
                    <a href="./{domain}_report.html">View Report</a> | 
                    <a href="./{domain}_actionable_report.html">View Actions</a>
                </div>
            </div>
            """
        
        # Add available reports section
        html += """
            </div>
            
            <h2>Available Reports</h2>
            <ul>
                <li><a href="./combined_report.html">Combined Cross-Domain Report</a></li>
                <li><a href="./search.html">Search Accounts</a></li>
                <li><a href="./search_redacted.html">Search Accounts (Redacted)</a></li>
        """
        
        for domain in domains:
            html += f"""
                <li><a href="./{domain}_report.html">{domain} - Single Domain Report</a></li>
                <li><a href="./{domain}_actionable_report.html">{domain} - Actionable Report</a></li>
            """
        
        # Add JavaScript for loading domain data and close HTML
        html += f"""
            </ul>
            {DOMAIN_DATA_LOADER_JS}
        </body>
        </html>
        """

        # Write to file
        output_path = Path(os.path.join('output', 'html_report', 'main.html'))
        os.makedirs(output_path.parent, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
        if logger:
            logger.info(f"Generated main HTML dashboard: {output_path}")
            
    except Exception as e:
        if logger:
            logger.error(f"Error generating main HTML dashboard: {str(e)}")
        else:
            print(f"Error generating main HTML dashboard: {str(e)}")