# reports/html/components.py
"""
Reusable HTML components for reports.
"""

# Risk vector explanation component
RISK_VECTOR_EXPLANATION = """
<div class="explanation-block">
    <h3>Risk Vector Format</h3>
    <p>Risk vectors provide a compact representation of risk factors in the format: <code>C:X/L:Y/D:Z/...</code></p>
    <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 10px;">
        <div>
            <strong>C: Complexity (C1-C10)</strong>
            <ul>
                <li>C1: Excellent complexity</li>
                <li>C5: Moderate complexity</li>
                <li>C10: Very poor complexity</li>
            </ul>
        </div>
        <div>
            <strong>L: Length</strong>
            <ul>
                <li>VL: Very Long (16+ chars)</li>
                <li>L: Long (12-15 chars)</li>
                <li>M: Medium (8-11 chars)</li>
                <li>S: Short (6-7 chars)</li>
                <li>VS: Very Short (<6 chars)</li>
            </ul>
        </div>
        <div>
            <strong>D: Dictionary Issues</strong>
            <ul>
                <li>N: None</li>
                <li>CO: Common password</li>
                <li>DW: Dictionary word</li>
                <li>BW: Banned words</li>
                <li>KP: Keyboard pattern</li>
            </ul>
        </div>
        <div>
            <strong>SM: Similarity</strong>
            <ul>
                <li>N: No significant similarity</li>
                <li>M: Medium (70-79%)</li>
                <li>H: High (80-89%)</li>
                <li>VH: Very High (90%+)</li>
            </ul>
        </div>
        <div>
            <strong>CM: Compliance</strong>
            <ul>
                <li>N: Compliant</li>
                <li>L: Low (<1 month)</li>
                <li>M: Medium (1-3 months)</li>
                <li>H: High (3-12 months)</li>
                <li>VH: Very High (1-2 years)</li>
                <li>E: Extreme (>2 years)</li>
            </ul>
        </div>
        <div>
            <strong>EX: Expiration</strong>
            <ul>
                <li>Y: Password set to expire</li>
                <li>N: Never expires</li>
                <li>U: Unknown</li>
            </ul>
        </div>
        <div>
            <strong>DA: Domain Admin Pathway</strong>
            <ul>
                <li>N: No pathway</li>
                <li>Y: Has pathway</li>
                <li>M: Multiple pathways</li>
                <li>S: Shared with DA account</li>
            </ul>
        </div>
        <div>
            <strong>CO: Controlled Objects</strong>
            <ul>
                <li>L: Low (1-10)</li>
                <li>M: Medium (11-50)</li>
                <li>M+: Medium-High (51-100)</li>
                <li>H: High (101-500)</li>
                <li>VH: Very High (501-1000)</li>
                <li>E: Extreme (>1000)</li>
            </ul>
        </div>
        <div>
            <strong>S: Sharing</strong>
            <ul>
                <li>0: Not shared</li>
                <li>1: 1-9 accounts</li>
                <li>2: 10-99 accounts</li>
                <li>3: 100-999 accounts</li>
                <li>4: 1000+ accounts</li>
            </ul>
        </div>
        <div>
            <strong>DR: Domain Risk</strong>
            <ul>
                <li>L: Low risk domain</li>
                <li>M: Medium risk domain</li>
                <li>H: High risk domain</li>
                <li>C: Critical risk domain</li>
                <li>U: Unknown</li>
            </ul>
        </div>
    </div>
</div>
"""

# Domain Admin explanation component
DA_EXPLANATION = """
<div class="explanation-block">
    <p>This section lists accounts with cracked passwords that have pathways to Domain Admin (DA) privileges, identified via BloodHound analysis. These accounts are critical because they can be exploited to gain full control over the domain.</p>
    
    <h3>Why It's Important</h3>
    <p>Compromised accounts with DA pathways enable attackers to escalate privileges rapidly. According to the 2023 Verizon Data Breach Investigations Report (DBIR), 86% of breaches involved misuse of privileged credentials.</p>
    
    <h3>Expected Actions</h3>
    <ul>
        <li><strong>Reset Passwords Immediately</strong>: For accounts marked 'Reset Immediately' (Enabled = Yes, Risk Level = High/Critical):
            <ol>
                <li>Log into Active Directory Users and Computers (ADUC).</li>
                <li>Locate the user (e.g., `Username`).</li>
                <li>Right-click > Reset Password, enforce a strong, unique password (e.g., 16+ characters, mixed case, numbers, special characters).</li>
                <li>Check 'User must change password at next logon' to ensure immediate update.</li>
            </ol>
        </li>
        <li><strong>Review and Secure</strong>: For accounts marked 'Review and Secure' (Disabled or lower risk):
            <ol>
                <li>Verify if the account is still needed.</li>
                <li>If active, reset the password as above.</li>
                <li>If unused, disable or delete the account to reduce attack surface.</li>
            </ol>
        </li>
        <li><strong>Audit DA Pathways</strong>: Use BloodHound to review and restrict these pathways (e.g., remove unnecessary privileges).</li>
    </ul>
</div>
"""

# Controllables explanation component
CONTROLLABLES_EXPLANATION = """
<div class="explanation-block">
    <p>This section identifies the top 100 cracked accounts controlling the most objects (e.g., users, groups, computers) in the domain. High controllables increase the impact of a compromise.</p>
    
    <h3>Why It's Important</h3>
    <p>Accounts with many controllables can manipulate multiple resources, amplifying damage. NIST SP 800-53 highlights that excessive privileges contribute to 80% of insider threat incidents.</p>
    
    <h3>Expected Actions</h3>
    <ul>
        <li><strong>Reset Passwords Immediately</strong>: For enabled accounts with High/Critical risk:
            <ol>
                <li>Follow the ADUC password reset steps above.</li>
                <li>Use a unique, complex password.</li>
            </ol>
        </li>
        <li><strong>Review and Secure</strong>: For other accounts:
            <ol>
                <li>Assess if the account needs such extensive control.</li>
                <li>Reduce permissions via ADUC or PowerShell (e.g., `Remove-ADGroupMember`).</li>
                <li>Reset passwords if still active.</li>
            </ol>
        </li>
        <li><strong>Monitor Usage</strong>: Implement logging to detect abuse of these accounts.</li>
    </ul>
</div>
"""

# Non-expiring passwords explanation component
NONEXPIRING_EXPLANATION = """
<div class="explanation-block">
    <p>This section lists cracked accounts with passwords set to never expire, bypassing standard rotation policies.</p>
    
    <h3>Why It's Important</h3>
    <p>Non-expiring passwords increase exposure over time. The 2022 Ponemon Institute report found that 60% of breaches involved credentials unchanged for over a year.</p>
    
    <h3>Expected Actions</h3>
    <ul>
        <li><strong>Set to Expire and Reset</strong>: For enabled accounts:
            <ol>
                <li>In ADUC, locate the user.</li>
                <li>Reset the password (as above).</li>
                <li>Uncheck 'Password never expires' in Account properties.</li>
                <li>Set a policy-compliant expiration (e.g., 90 days).</li>
            </ol>
        </li>
        <li><strong>Review and Update</strong>: For disabled/unused accounts:
            <ol>
                <li>Confirm necessity.</li>
                <li>Disable or delete if obsolete.</li>
            </ol>
        </li>
        <li><strong>Enforce Policy</strong>: Update domain policy to prevent future non-expiring settings (e.g., via Group Policy).</li>
    </ul>
</div>
"""

# Out-of-compliance explanation component
COMPLIANCE_EXPLANATION = """
<div class="explanation-block">
    <p>This section highlights cracked accounts with passwords exceeding the maximum age (e.g., >90 days), violating compliance policies.</p>
    
    <h3>Why It's Important</h3>
    <p>Stale passwords are more likely to be compromised. IBM's 2023 Cost of a Data Breach report notes that outdated credentials contribute to 19% of breaches, with an average cost of $4.37M.</p>
    
    <h3>Expected Actions</h3>
    <ul>
        <li><strong>Reset Immediately</strong>: For High/Critical risk enabled accounts:
            <ol>
                <li>Reset passwords via ADUC (as above).</li>
                <li>Enforce immediate user change.</li>
            </ol>
        </li>
        <li><strong>Enforce Compliance</strong>: For other accounts:
            <ol>
                <li>Reset passwords.</li>
                <li>Verify last set date aligns with policy (e.g., <90 days).</li>
            </ol>
        </li>
        <li><strong>Automate Rotation</strong>: Implement password expiration policies via Group Policy (e.g., `Set-ADDefaultDomainPasswordPolicy -MaxPasswordAge 90`).</li>
    </ul>
</div>
"""

# Risk score explanation component
RISK_SCORE_EXPLANATION = """
<div class="explanation-block">
    <p>This report uses a CVSS-style 0-10 risk scoring system:</p>
    <ul>
        <li><strong>Critical Risk (8.0-10.0)</strong>: Severe security threat requiring immediate action</li>
        <li><strong>High Risk (6.0-7.9)</strong>: Significant vulnerability requiring prompt attention</li>
        <li><strong>Medium Risk (4.0-5.9)</strong>: Moderate vulnerability for regular security maintenance</li>
        <li><strong>Low Risk (0.0-3.9)</strong>: Minor issue with limited security impact</li>
    </ul>
    
    <h3>Score Components</h3>
    <ul>
        <li><strong>Base Score</strong>: Evaluates password complexity, length, and dictionary factors</li>
        <li><strong>Temporal Score</strong>: Adjusts for password age and expiration policy</li>
        <li><strong>Environmental Score</strong>: Incorporates account privileges and password sharing</li>
    </ul>
</div>
"""

def html_head(title, include_pdf_export=True, include_search=False, include_redacted_search=False):
    """Generate standard HTML head section."""
    from reports.html.styles import BASE_CSS, IFRAME_CSS, TABLE_SORT_CSS
    from reports.html.scripts import PDF_EXPORT_JS
    
    css = f"""
    <style>
    {BASE_CSS}
    {IFRAME_CSS}
    {TABLE_SORT_CSS}
    </style>
    """
    
    scripts = ""
    if include_pdf_export:
        scripts += PDF_EXPORT_JS
    
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
        <title>{title}</title>
        {css}
        {scripts}
    </head>
    """

def create_error_message(message="An error occurred while processing the data."):
    """Create an error message div."""
    return f"""
    <div class="error-message" style="display: block; color: red; padding: 10px; background-color: #ffeeee; border: 1px solid #ffcccc; margin: 10px 0;">
        {message}
    </div>
    """

def create_visualization_container(title, iframe_path=None, fallback_text=None):
    """Create a visualization container with iframe or fallback text."""
    if iframe_path:
        content = f"""
        <iframe src="./{iframe_path}" width="100%" height="500" frameborder="0" 
                loading="lazy" class="visualization-frame" title="{title}"></iframe>
        """
    else:
        content = f"""<p class="error-message">{fallback_text or 'Visualization not available'}</p>"""
    
    return f"""
    <div class="visualization-container">
        <h3>{title}</h3>
        {content}
    </div>
    """

def get_risk_distribution_html(distribution, total=None):
    """Generate HTML for risk distribution."""
    if not distribution:
        return "<p>No risk distribution data available.</p>"
    
    if total is None:
        total = sum(distribution.values())
    
    html = "<ul>"
    for level in ['Critical', 'High', 'Medium', 'Low']:
        count = distribution.get(level, 0)
        percentage = round((count/total)*100, 1) if total > 0 else 0
        html += f"<li>{level}: {count} accounts ({percentage}%)</li>"
    html += "</ul>"
    
    return html

def get_accounts_table_html(accounts, columns, include_risk_class=True):
    """Generate HTML table for accounts."""
    if not accounts:
        return "<p>No accounts available.</p>"
    
    # Create header row
    header_row = "<tr>"
    for col in columns:
        header_row += f"<th>{col}</th>"
    header_row += "</tr>"
    
    # Create data rows
    rows = ""
    for acc in accounts:
        row_class = ""
        if include_risk_class and 'Risk Level' in acc:
            risk_level = acc['Risk Level'].lower() if acc['Risk Level'] else ""
            row_class = f'class="risk-{risk_level}"'
        
        rows += f"<tr {row_class}>"
        for col in columns:
            value = acc.get(col, "N/A")
            rows += f"<td>{value}</td>"
        rows += "</tr>"
    
    return f"""
    <div class="table-container">
        <table>
            <thead>
                {header_row}
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </div>
    """

def get_export_button(element_id, filename):
    """Generate HTML for PDF export button."""
    return f"""
    <div class="no-print">
        <button class="export-button" onclick="exportToPDF('{element_id}', '{filename}')">Export to PDF</button>
    </div>
    """