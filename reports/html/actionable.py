# reports/html/actionable.py
"""
Actionable report generation module.
"""

import os
import hashlib
from pathlib import Path
from reports.html.components import (
    html_head, create_error_message,
    DA_EXPLANATION, CONTROLLABLES_EXPLANATION, NONEXPIRING_EXPLANATION,
    COMPLIANCE_EXPLANATION, RISK_VECTOR_EXPLANATION
)
from reports.html.scripts import TABLE_SORT_JS, TAB_SWITCH_JS

def generate_html_actionable_report(domain, data, seed, visuals, logger=None):
    """
    Generate HTML actionable report for a domain.
    
    Args:
        domain (str): Domain name
        data (dict): Domain analysis data
        seed (str): Seed for password placeholders
        visuals (dict): Dictionary of visualization paths
        logger (Logger, optional): Logger instance
    """
    # Call the combined implementation for consistency
    return generate_combined_actionable_report(domain, data, seed, visuals, logger)


def generate_combined_actionable_report(domain, data, seed, visuals, logger=None):
    """
    Generate a combined actionable and explanatory HTML report.
    
    Args:
        domain (str): Domain name
        data (dict): Domain analysis data
        seed (str): Seed for password placeholders
        visuals (dict): Dictionary of visualization paths
        logger (Logger, optional): Logger instance
    """
    try:
        # Create HTML head
        html = html_head(f"Actionable Password Security Report - {domain}")
        
        html += f"""
        <body>
            <div id="reportContent">
                <h1>Actionable Password Security Report for {domain}</h1>
                <p><a href="./main.html">Back to Main</a> | <a href="./search.html">Search Accounts</a></p>
        """
        
        html += f"""
        <p>Actionable items for cracked passwords with critical issues.</p>
        {RISK_VECTOR_EXPLANATION}
        <div id="errorMessage" style="display: none; color: red; padding: 10px; background-color: #ffeeee; border: 1px solid #ffcccc; margin: 10px 0;"></div>
        """

        try:
            cracked_rows = [row for row in data['output_rows'] if row.get('Password Length', 'N/A') != 'N/A']
            risk_order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Unknown": 0}

            # DA accounts section with explanation
            da_accounts = [row for row in cracked_rows if row.get('DA Domains', 'None') not in ('None', 'Unknown')]
            da_count = len(da_accounts)
            
            html += build_section_with_tabs(
                "Riskiest Cracked Accounts with DA Pathway",
                f"**Count in this Domain**: {da_count} accounts",
                DA_EXPLANATION,
                build_da_accounts_table(da_accounts, seed),
                "tab-action",
                "tab-explanation"
            )
            
            # Controllables section with explanation
            controllables_accounts = sorted(
                cracked_rows,
                key=lambda x: (
                    not (x.get('Enabled', 'Unknown') == 'Yes'),
                    -int(x.get('Controlled Object Count', 0) if x.get('Controlled Object Count', 'Unknown') != 'Unknown' else 0)
                )
            )[:100]
            controllables_count = len(controllables_accounts)
            
            html += build_section_with_tabs(
                "Top 100 Accounts by Controllables",
                f"**Count in this Domain**: {controllables_count} accounts (top 100 shown)",
                CONTROLLABLES_EXPLANATION,
                build_controllables_table(controllables_accounts, seed),
                "tab-action-controllables",
                "tab-explanation-controllables"
            )

            # Non-expiring passwords section
            non_expiring_accounts = [row for row in cracked_rows if row.get('Password Set to Expire', 'Yes') == 'No']
            non_expiring_count = len(non_expiring_accounts)
            
            html += build_section_with_tabs(
                "Accounts with Non-Expiring Passwords",
                f"**Count in this Domain**: {non_expiring_count} accounts",
                NONEXPIRING_EXPLANATION,
                build_nonexpiring_table(non_expiring_accounts, seed),
                "tab-action-nonexpiring",
                "tab-explanation-nonexpiring"
            )

            # Out-of-compliance section
            out_of_compliance_accounts = [row for row in cracked_rows 
                                        if row.get('Days Out of Compliance', 'N/A') not in ('N/A', 'Unknown') 
                                        and int(row.get('Days Out of Compliance', 0)) > 0]
            
            html += build_section_with_tabs(
                "Out-of-Compliance Accounts",
                f"**Count in this Domain**: {len(out_of_compliance_accounts)} accounts",
                COMPLIANCE_EXPLANATION,
                build_compliance_table(out_of_compliance_accounts),
                "tab-action-compliance",
                "tab-explanation-compliance"
            )

            if not any([da_accounts, controllables_accounts, non_expiring_accounts, out_of_compliance_accounts]):
                html += "<p><strong>No actionable items identified for this domain.</strong></p>\n"

        except Exception as e:
            if logger:
                logger.error(f"Error processing data for actionable report for domain {domain}: {str(e)}")
            html += create_error_message(f"Error processing actionable data: {str(e)}")

        # Add JavaScript
        html += f"""
        {TAB_SWITCH_JS}
        {TABLE_SORT_JS}
        </div>
        </body>
        </html>
        """

        # Write to file
        output_path = Path(os.path.join('output', 'html_report', f'{domain}_actionable_report.html'))
        os.makedirs(output_path.parent, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
        if logger:
            logger.info(f"Generated combined actionable HTML report: {output_path}")
            
    except Exception as e:
        if logger:
            logger.error(f"Error generating combined actionable HTML report for domain {domain}: {str(e)}")
        else:
            print(f"Error generating combined actionable HTML report for domain {domain}: {str(e)}")


def build_section_with_tabs(title, subtitle, explanation, table_html, action_tab_id, explanation_tab_id):
    """Build a section with action and explanation tabs."""
    return f"""
    <div class="tab-container">
        <div class="tab-buttons">
            <button class="tablink active" onclick="openTab(event, '{action_tab_id}')">Actions</button>
            <button class="tablink" onclick="openTab(event, '{explanation_tab_id}')">Explanation</button>
        </div>
        
        <div id="{action_tab_id}" class="tab-content" style="display: block;">
            <h2>{title}</h2>
            <p>{subtitle}</p>
            {table_html}
        </div>
        <div id="{explanation_tab_id}" class="tab-content">
            <h2>{title} - Explanation</h2>
            {explanation}
        </div>
    </div>
    """


def build_da_accounts_table(accounts, seed):
    """Build the DA accounts table HTML."""
    if not accounts:
        return "<p>No cracked accounts with DA pathways identified.</p>"
    
    # Sort by enabled status and risk level
    risk_order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Unknown": 0}
    accounts.sort(key=lambda x: (not (x.get('Enabled', 'Unknown') == 'Yes'), -risk_order.get(x['Risk Level'], 0)))
    
    # Build the table
    table_html = """
    <div class="table-container">
        <div class="filter-container">
            <span>Filter by risk: </span>
            <button class="filter-button active" onclick="filterByRisk('all', this)">All</button>
            <button class="filter-button" onclick="filterByRisk('Critical', this)">Critical</button>
            <button class="filter-button" onclick="filterByRisk('High', this)">High</button>
            <button class="filter-button" onclick="filterByRisk('Medium', this)">Medium</button>
            <button class="filter-button" onclick="filterByRisk('Low', this)">Low</button>
        </div>
        <table>
            <thead>
                <tr><th>Username</th><th>Password Placeholder</th><th>Risk Level</th><th>Risk Vector</th>
                <th>Shared With</th><th>Enabled</th><th>Last Logon</th><th>When Created</th><th>Action</th></tr>
            </thead>
            <tbody>
    """
    
    for acc in accounts:
        placeholder = hashlib.md5((seed + acc['Password']).encode()).hexdigest()
        action = "Reset Immediately" if acc.get('Enabled', 'No') == 'Yes' and acc.get('Risk Level', '') in ('High', 'Critical') else "Review and Secure"
        risk_vector = acc.get('Risk Vector', 'N/A')
        risk_level = acc.get('Risk Level', 'Unknown')
        
        table_html += f"""
        <tr class="risk-row risk-{risk_level.lower()}">
            <td>{acc['Username']}</td>
            <td>{placeholder}</td>
            <td>{risk_level}</td>
            <td>{risk_vector}</td>
            <td>{acc.get('Shared With', 'N/A')}</td>
            <td>{acc.get('Enabled', 'Unknown')}</td>
            <td>{acc.get('Last Logon', 'Unknown')}</td>
            <td>{acc.get('When Created', 'Unknown')}</td>
            <td>{action}</td>
        </tr>
        """
    
    table_html += """
            </tbody>
        </table>
    </div>
    """
    
    return table_html


def build_controllables_table(accounts, seed):
    """Build the controllables accounts table HTML."""
    if not accounts:
        return "<p>No cracked accounts with controlled objects identified.</p>"
    
    # Build the table
    table_html = """
    <div class="table-container">
        <div class="filter-container">
            <span>Filter by risk: </span>
            <button class="filter-button active" onclick="filterByRisk('all', this)">All</button>
            <button class="filter-button" onclick="filterByRisk('Critical', this)">Critical</button>
            <button class="filter-button" onclick="filterByRisk('High', this)">High</button>
            <button class="filter-button" onclick="filterByRisk('Medium', this)">Medium</button>
            <button class="filter-button" onclick="filterByRisk('Low', this)">Low</button>
        </div>
        <table>
            <thead>
                <tr><th>Username</th><th>Password Placeholder</th><th>Risk Level</th><th>Risk Vector</th>
                <th>Shared With</th><th>Enabled</th><th>Controllables</th><th>Last Logon</th>
                <th>When Created</th><th>Action</th></tr>
            </thead>
            <tbody>
    """
    
    for acc in accounts:
        placeholder = hashlib.md5((seed + acc['Password']).encode()).hexdigest()
        action = "Reset Immediately" if acc.get('Enabled', 'No') == 'Yes' and acc.get('Risk Level', '') in ('High', 'Critical') else "Review and Secure"
        risk_vector = acc.get('Risk Vector', 'N/A')
        controllables = acc.get('Controlled Object Count', 'Unknown')
        risk_level = acc.get('Risk Level', 'Unknown')
        
        table_html += f"""
        <tr class="risk-row risk-{risk_level.lower()}">
            <td>{acc['Username']}</td>
            <td>{placeholder}</td>
            <td>{risk_level}</td>
            <td>{risk_vector}</td>
            <td>{acc.get('Shared With', 'N/A')}</td>
            <td>{acc.get('Enabled', 'Unknown')}</td>
            <td>{controllables}</td>
            <td>{acc.get('Last Logon', 'Unknown')}</td>
            <td>{acc.get('When Created', 'Unknown')}</td>
            <td>{action}</td>
        </tr>
        """
    
    table_html += """
            </tbody>
        </table>
    </div>
    """
    
    return table_html


def build_nonexpiring_table(accounts, seed):
    """Build the non-expiring accounts table HTML."""
    if not accounts:
        return "<p>No cracked accounts with non-expiring passwords identified.</p>"
    
    # Sort by enabled status
    accounts.sort(key=lambda x: not (x.get('Enabled', 'Unknown') == 'Yes'))
    
    # Build the table
    table_html = """
    <div class="table-container">
        <div class="filter-container">
            <span>Filter by risk: </span>
            <button class="filter-button active" onclick="filterByRisk('all', this)">All</button>
            <button class="filter-button" onclick="filterByRisk('Critical', this)">Critical</button>
            <button class="filter-button" onclick="filterByRisk('High', this)">High</button>
            <button class="filter-button" onclick="filterByRisk('Medium', this)">Medium</button>
            <button class="filter-button" onclick="filterByRisk('Low', this)">Low</button>
        </div>
        <table>
            <thead>
                <tr><th>Username</th><th>Password Placeholder</th><th>Risk Level</th><th>Risk Vector</th>
                <th>Enabled</th><th>Last Logon</th><th>When Created</th><th>Action</th></tr>
            </thead>
            <tbody>
    """
    
    for acc in accounts:
        placeholder = hashlib.md5((seed + acc['Password']).encode()).hexdigest()
        action = "Set to Expire and Reset" if acc.get('Enabled', 'No') == 'Yes' else "Review and Update"
        risk_vector = acc.get('Risk Vector', 'N/A')
        risk_level = acc.get('Risk Level', 'Unknown')
        
        table_html += f"""
        <tr class="risk-row risk-{risk_level.lower()}">
            <td>{acc['Username']}</td>
            <td>{placeholder}</td>
            <td>{risk_level}</td>
            <td>{risk_vector}</td>
            <td>{acc.get('Enabled', 'Unknown')}</td>
            <td>{acc.get('Last Logon', 'Unknown')}</td>
            <td>{acc.get('When Created', 'Unknown')}</td>
            <td>{action}</td>
        </tr>
        """
    
    table_html += """
            </tbody>
        </table>
    </div>
    """
    
    return table_html


def build_compliance_table(accounts):
    """Build the out-of-compliance accounts table HTML."""
    if not accounts:
        return "<p>No cracked accounts out of compliance identified.</p>"
    
    # Sort by enabled status, password length, and days out of compliance
    accounts.sort(key=lambda x: (
        not (x.get('Enabled', 'Unknown') == 'Yes'),
        int(x['Password Length']),
        -int(x.get('Days Out of Compliance', 0))
    ))
    
    # Build the table
    table_html = """
    <div class="table-container">
        <div class="filter-container">
            <span>Filter by risk: </span>
            <button class="filter-button active" onclick="filterByRisk('all', this)">All</button>
            <button class="filter-button" onclick="filterByRisk('Critical', this)">Critical</button>
            <button class="filter-button" onclick="filterByRisk('High', this)">High</button>
            <button class="filter-button" onclick="filterByRisk('Medium', this)">Medium</button>
            <button class="filter-button" onclick="filterByRisk('Low', this)">Low</button>
        </div>
        <table>
            <thead>
                <tr><th>Username</th><th>Password Length</th><th>Days Out of Compliance</th><th>Risk Vector</th>
                <th>Enabled</th><th>Last Logon</th><th>When Created</th><th>Risk Level</th><th>Action</th></tr>
            </thead>
            <tbody>
    """
    
    for acc in accounts:
        action = "Reset Immediately" if acc['Risk Level'] in ('High', 'Critical') and acc.get('Enabled', 'No') == 'Yes' else "Enforce Compliance"
        risk_vector = acc.get('Risk Vector', 'N/A')
        risk_level = acc.get('Risk Level', 'Unknown')
        
        table_html += f"""
        <tr class="risk-row risk-{risk_level.lower()}">
            <td>{acc['Username']}</td>
            <td>{acc['Password Length']}</td>
            <td>{acc.get('Days Out of Compliance', 'N/A')}</td>
            <td>{risk_vector}</td>
            <td>{acc.get('Enabled', 'Unknown')}</td>
            <td>{acc.get('Last Logon', 'Unknown')}</td>
            <td>{acc.get('When Created', 'Unknown')}</td>
            <td>{risk_level}</td>
            <td>{action}</td>
        </tr>
        """
    
    table_html += """
            </tbody>
        </table>
    </div>
    """
    
    return table_html