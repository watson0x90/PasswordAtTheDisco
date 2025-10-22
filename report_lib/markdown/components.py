# reports/markdown/components.py
"""
Reusable Markdown components for report generation.
"""

from datetime import datetime
from collections import Counter

def get_markdown_header(title, include_timestamp=True):
    """
    Generate a standard markdown header with title and timestamp.
    
    Args:
        title (str): Report title
        include_timestamp (bool): Whether to include generation timestamp
        
    Returns:
        str: Markdown header text
    """
    markdown = f"# {title}\n\n"
    
    if include_timestamp:
        markdown += f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
    
    return markdown

def get_risk_score_explanation():
    """
    Get markdown explanation of the risk scoring system.
    
    Returns:
        str: Markdown text explaining risk scoring
    """
    markdown = "## Risk Score Explanation\n\n"
    markdown += "This report uses a CVSS-style 0-10 risk scoring system:\n\n"
    markdown += "- **Critical Risk (8.0-10.0)**: Severe security threat requiring immediate action\n"
    markdown += "- **High Risk (6.0-7.9)**: Significant vulnerability requiring prompt attention\n"
    markdown += "- **Medium Risk (4.0-5.9)**: Moderate vulnerability for regular security maintenance\n"
    markdown += "- **Low Risk (0.0-3.9)**: Minor issue with limited security impact\n\n"

    markdown += "### Score Components\n\n"
    markdown += "1. **Base Score**: Evaluates password complexity, length, and dictionary factors\n"
    markdown += "2. **Temporal Score**: Adjusts for password age and expiration policy\n"
    markdown += "3. **Environmental Score**: Incorporates account privileges and password sharing\n\n"
    
    return markdown

def get_risk_vector_explanation():
    """
    Get markdown explanation of the risk vector format.
    
    Returns:
        str: Markdown text explaining risk vector notation
    """
    markdown = "### Risk Vector Format\n\n"
    markdown += "Risk vectors provide a compact representation of risk factors in the format: `C:X/L:Y/D:Z/...`\n\n"
    markdown += "- **C**: Complexity (C1-C10, lower is better)\n"
    markdown += "- **L**: Length (VL=Very Long, L=Long, M=Medium, S=Short, VS=Very Short)\n"
    markdown += "- **D**: Dictionary issues (CO=Common, DW=Dictionary Word, BW=Banned Words, KP=Keyboard Pattern)\n"
    markdown += "- **SM**: Similarity (VH=Very High, H=High, M=Medium, N=None)\n"
    markdown += "- **CM**: Compliance (E=Extreme (>2yr), VH=Very High (1-2yr), H=High (3mo-1yr), M=Medium (1-3mo), L=Low (<1mo), N=None)\n"
    markdown += "- **EX**: Expiration (Y=Yes, N=No)\n"
    markdown += "- **DA**: Domain Admin pathway (M=Multiple paths, Y=Yes, N=No, S=Shared with DA account)\n"
    markdown += "- **CO**: Controlled Objects (E=Extreme (>1000), VH=Very High (501-1000), H=High (101-500), M+=Medium-High (51-100), M=Medium (11-50), L=Low (1-10))\n"
    markdown += "- **S**: Sharing (logarithmic scale: 0=None, 1=1-9 accounts, 2=10-99 accounts, 3=100-999 accounts, 4=1000+ accounts)\n"
    markdown += "- **DR**: Domain Risk (C=Critical, H=High, M=Medium, L=Low, U=Unknown)\n"
    markdown += "- **HIBP**: Breach Exposure (C=Critical (100K+), E=Extreme (10K-99.9K), VH=Very High (1K-9.9K), H=High (100-999), M=Medium (10-99), L=Low (1-9), N=Not breached)\n\n"
    
    return markdown

def get_markdown_table(headers, rows):
    """
    Generate a markdown table with provided headers and rows.
    
    Args:
        headers (list): List of column headers
        rows (list): List of row data (each a list/dict of values)
        
    Returns:
        str: Markdown table
    """
    markdown = ""
    
    # Create header row
    markdown += "| " + " | ".join(headers) + " |\n"
    
    # Create separator row
    markdown += "|" + "|".join(["---"] * len(headers)) + "|\n"
    
    # Create data rows
    for row in rows:
        if isinstance(row, dict):
            values = [str(row.get(h, "")) for h in headers]
        else:
            values = [str(val) for val in row]
        
        markdown += "| " + " | ".join(values) + " |\n"
    
    markdown += "\n"
    return markdown

def format_risk_distribution(risk_distribution, total=None):
    """
    Format risk distribution as markdown list.
    
    Args:
        risk_distribution (dict): Risk level counts
        total (int, optional): Total count for percentage calculation
        
    Returns:
        str: Markdown formatted risk distribution
    """
    if not risk_distribution:
        return "*No risk distribution data available.*\n\n"
    
    if total is None:
        total = sum(risk_distribution.values())
    
    markdown = ""
    for level in ['Critical', 'High', 'Medium', 'Low']:
        count = risk_distribution.get(level, 0)
        percentage = round((count/total)*100, 1) if total > 0 else 0
        markdown += f"  - {level}: {count} accounts ({percentage}%)\n"
    
    return markdown

def get_executive_summary(domain, total_accounts, cracked, domain_risk):
    """
    Generate the executive summary section.
    
    Args:
        domain (str): Domain name
        total_accounts (int): Total accounts analyzed
        cracked (int): Number of cracked accounts
        domain_risk (dict): Domain risk data
        
    Returns:
        str: Markdown for executive summary
    """
    markdown = "## Executive Summary\n\n"
    
    if total_accounts > 0:
        cracked_percentage = (cracked/total_accounts) * 100 if total_accounts > 0 else 0
        markdown += f"This report analyzes {total_accounts} accounts in the {domain} domain, "
        markdown += f"of which {cracked} ({cracked_percentage:.1f}%) had cracked passwords.\n\n"
        
        # Include domain risk score in executive summary
        if domain_risk:
            risk_level = domain_risk.get('overall_risk_level', 'Unknown')
            score = domain_risk.get('risk_score', 'N/A')
            markdown += f"The overall domain risk score is **{score}/10.0** "
            markdown += f"({risk_level} risk).\n\n"
            
            # Count high/critical risk accounts
            risk_counts = domain_risk.get('risk_distribution', {})
            high_risk = risk_counts.get('High', 0) + risk_counts.get('Critical', 0)
            high_risk_percentage = (high_risk/total_accounts) * 100 if total_accounts > 0 else 0
            markdown += f"**{high_risk}** accounts ({high_risk_percentage:.1f}% of all accounts) were identified as High or Critical risk.\n\n"
    
    # Add key recommendations
    markdown += "### Key Recommendations\n\n"
    markdown += "1. **Immediately reset passwords** for all Critical risk accounts\n"
    markdown += "2. **Review and secure** accounts with Domain Admin pathways\n"
    markdown += "3. **Enforce password expiration** for accounts with non-expiring passwords\n"
    markdown += "4. **Implement MFA** for high-privilege accounts\n\n"
    
    return markdown

def get_domain_overview(total_accounts, cracked, uncracked, out_of_compliance, non_expiring, hibp_breached=0, hibp_total_exposures=0):
    """
    Generate the domain overview section.

    Args:
        total_accounts (int): Total accounts analyzed
        cracked (int): Number of cracked accounts
        uncracked (int): Number of uncracked accounts
        out_of_compliance (int): Number of out-of-compliance accounts
        non_expiring (int): Number of non-expiring accounts
        hibp_breached (int, optional): Number of HIBP breached accounts
        hibp_total_exposures (int, optional): Total HIBP breach exposure count

    Returns:
        str: Markdown for domain overview
    """
    if total_accounts > 0:
        cracked_percentage = (cracked/total_accounts) * 100
        uncracked_percentage = (uncracked/total_accounts) * 100
        compliance_percentage = (out_of_compliance/total_accounts) * 100
        nonexpiring_percentage = (non_expiring/total_accounts) * 100
        hibp_percentage = (hibp_breached/total_accounts) * 100 if hibp_breached > 0 else 0
    else:
        cracked_percentage = 0
        uncracked_percentage = 0
        compliance_percentage = 0
        nonexpiring_percentage = 0
        hibp_percentage = 0

    markdown = "## Overview\n\n"
    markdown += f"- **Total Accounts Analyzed:** {total_accounts}\n"
    markdown += f"- **Cracked Passwords:** {cracked} ({cracked_percentage:.1f}%)\n"
    markdown += f"- **Uncracked Passwords:** {uncracked} ({uncracked_percentage:.1f}%)\n"
    markdown += f"- **Out of Compliance Accounts:** {out_of_compliance} ({compliance_percentage:.1f}%)\n"
    markdown += f"- **Non-Expiring Passwords:** {non_expiring} ({nonexpiring_percentage:.1f}%)\n"
    markdown += f"- **🔴 HIBP Breached Passwords:** {hibp_breached} ({hibp_percentage:.1f}%) - {hibp_total_exposures:,} total breach exposures\n\n"

    return markdown

def get_domain_admin_explanation():
    """
    Get explanation text for domain admin section.
    
    Returns:
        str: Markdown explanation of domain admin importance
    """
    markdown = "### Explanation\n\n"
    markdown += "This section lists accounts with cracked passwords that have pathways to Domain Admin (DA) privileges, identified via BloodHound analysis. These accounts are critical because they can be exploited to gain full control over the domain.\n\n"
    
    markdown += "### Why It's Important\n\n"
    markdown += "Compromised accounts with DA pathways enable attackers to escalate privileges rapidly. According to the 2023 Verizon Data Breach Investigations Report (DBIR), 86% of breaches involved misuse of privileged credentials.\n\n"
    
    markdown += "### Expected Actions\n\n"
    markdown += "- **Reset Passwords Immediately**: For accounts marked 'Reset Immediately' (Enabled = Yes, Risk Level = High/Critical):\n"
    markdown += "  1. Log into Active Directory Users and Computers (ADUC).\n"
    markdown += "  2. Locate the user (e.g., `Username`).\n"
    markdown += "  3. Right-click > Reset Password, enforce a strong, unique password (e.g., 16+ characters, mixed case, numbers, special characters).\n"
    markdown += "  4. Check 'User must change password at next logon' to ensure immediate update.\n"
    markdown += "- **Review and Secure**: For accounts marked 'Review and Secure' (Disabled or lower risk):\n"
    markdown += "  1. Verify if the account is still needed.\n"
    markdown += "  2. If active, reset the password as above.\n"
    markdown += "  3. If unused, disable or delete the account to reduce attack surface.\n"
    markdown += "- **Audit DA Pathways**: Use BloodHound to review and restrict these pathways (e.g., remove unnecessary privileges).\n\n"
    
    return markdown

def get_controllables_explanation():
    """
    Get explanation text for controllables section.
    
    Returns:
        str: Markdown explanation of controllables importance
    """
    markdown = "### Explanation\n\n"
    markdown += "This section identifies the top 100 cracked accounts controlling the most objects (e.g., users, groups, computers) in the domain. High controllables increase the impact of a compromise.\n\n"
    
    markdown += "### Why It's Important\n\n"
    markdown += "Accounts with many controllables can manipulate multiple resources, amplifying damage. NIST SP 800-53 highlights that excessive privileges contribute to 80% of insider threat incidents.\n\n"
    
    markdown += "### Expected Actions\n\n"
    markdown += "- **Reset Passwords Immediately**: For enabled accounts with High/Critical risk:\n"
    markdown += "  1. Follow the ADUC password reset steps above.\n"
    markdown += "  2. Use a unique, complex password.\n"
    markdown += "- **Review and Secure**: For other accounts:\n"
    markdown += "  1. Assess if the account needs such extensive control.\n"
    markdown += "  2. Reduce permissions via ADUC or PowerShell (e.g., `Remove-ADGroupMember`).\n"
    markdown += "  3. Reset passwords if still active.\n"
    markdown += "- **Monitor Usage**: Implement logging to detect abuse of these accounts.\n\n"
    
    return markdown

def get_nonexpiring_explanation():
    """
    Get explanation text for non-expiring passwords section.
    
    Returns:
        str: Markdown explanation of non-expiring passwords importance
    """
    markdown = "### Explanation\n\n"
    markdown += "This section lists cracked accounts with passwords set to never expire, bypassing standard rotation policies.\n\n"
    
    markdown += "### Why It's Important\n\n"
    markdown += "Non-expiring passwords increase exposure over time. The 2022 Ponemon Institute report found that 60% of breaches involved credentials unchanged for over a year.\n\n"
    
    markdown += "### Expected Actions\n\n"
    markdown += "- **Set to Expire and Reset**: For enabled accounts:\n"
    markdown += "  1. In ADUC, locate the user.\n"
    markdown += "  2. Reset the password (as above).\n"
    markdown += "  3. Uncheck 'Password never expires' in Account properties.\n"
    markdown += "  4. Set a policy-compliant expiration (e.g., 90 days).\n"
    markdown += "- **Review and Update**: For disabled/unused accounts:\n"
    markdown += "  1. Confirm necessity.\n"
    markdown += "  2. Disable or delete if obsolete.\n"
    markdown += "- **Enforce Policy**: Update domain policy to prevent future non-expiring settings (e.g., via Group Policy).\n\n"
    
    return markdown

def get_compliance_explanation():
    """
    Get explanation text for compliance section.
    
    Returns:
        str: Markdown explanation of compliance importance
    """
    markdown = "### Explanation\n\n"
    markdown += "This section highlights cracked accounts with passwords exceeding the maximum age (e.g., >90 days), violating compliance policies.\n\n"
    
    markdown += "### Why It's Important\n\n"
    markdown += "Stale passwords are more likely to be compromised. IBM's 2023 Cost of a Data Breach report notes that outdated credentials contribute to 19% of breaches, with an average cost of $4.37M.\n\n"
    
    markdown += "### Expected Actions\n\n"
    markdown += "- **Reset Immediately**: For High/Critical risk enabled accounts:\n"
    markdown += "  1. Reset passwords via ADUC (as above).\n"
    markdown += "  2. Enforce immediate user change.\n"
    markdown += "- **Enforce Compliance**: For other accounts:\n"
    markdown += "  1. Reset passwords.\n"
    markdown += "  2. Verify last set date aligns with policy (e.g., <90 days).\n"
    markdown += "- **Automate Rotation**: Implement password expiration policies via Group Policy (e.g., `Set-ADDefaultDomainPasswordPolicy -MaxPasswordAge 90`).\n\n"
    
    return markdown