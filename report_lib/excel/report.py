# reports/excel/report.py
"""
Excel report generation module for password security audit.
Provides functions to generate actionable Excel reports.
"""

import os
import hashlib
import pandas as pd
from collections import Counter
from core.config import reports_folder, excel_folder

def write_actionable_excel(domain, rows, seed, logger=None):
    """
    Generate actionable Excel report with separate sheets for different risk categories.
    
    Args:
        domain (str): Domain name
        rows (list): List of data rows
        seed (str): Seed for password placeholders
        logger (Logger, optional): Logger instance
    """
    os.makedirs(excel_folder, exist_ok=True)
    filename = f"{domain}_actionable_report.xlsx"
    output_path = excel_folder / filename
    
    # Comprehensive fieldnames list
    fieldnames = [
        'Domain', 'Username', 'Password Placeholder', 'Password Length', 'Complexity Label', 'Contains Unicode',
        'Meets Policy', 'Policy Violations', 'Similar Passwords', 'Share Count',
        'HIBP Breached', 'HIBP Breach Count', 'HIBP Risk Level',
        'Risk Level', 'Score', 'Base Score', 'Temporal Score', 'Environmental Score',
        'Base Factors', 'Temporal Factors', 'Environmental Factors',
        'DA Domains', 'Controlled Object Count', 'Days Out of Compliance',
        'Last Password Set', 'Password Set to Expire', 'Enabled', 'When Created', 'Last Logon',
        'Last Logon Timestamp', 'Password Cant Change', 'Action', 'Risk Vector'
    ]
    
    # Filter and categorize data
    cracked_rows = [row for row in rows if row['Password Length'] != 'N/A']
    risk_order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Unknown": 0}

    # Add score breakdowns and factor descriptions
    for row in cracked_rows:
        # Get password placeholder
        row['Password Placeholder'] = hashlib.md5((seed + row['Password']).encode()).hexdigest()
        
        # Extract score breakdown components
        breakdown = row.get('Score Breakdown', {})
        
        # Add score components
        row['Base Score'] = breakdown.get('base_score', 'N/A')
        row['Temporal Score'] = breakdown.get('temporal_score', 'N/A')
        row['Environmental Score'] = breakdown.get('environmental_score', 'N/A')
        
        # Extract and format base factors
        base_components = breakdown.get('base_components', {})
        base_factors = []
        if base_components.get('complexity_factor', 0) >= 0.7:
            base_factors.append("Weak Complexity")
        if base_components.get('length_factor', 0) >= 0.7:
            base_factors.append("Insufficient Length")
        if base_components.get('dictionary_factor', 0) >= 0.3:
            base_factors.append("Dictionary Terms")
        if base_components.get('similarity_factor', 0) >= 0.2:
            base_factors.append("Similar to Other Passwords")
        row['Base Factors'] = ', '.join(base_factors) if base_factors else 'None'
        
        # Extract and format temporal factors
        temporal_components = breakdown.get('temporal_components', {})
        temporal_factors = []
        if temporal_components.get('compliance_factor', 0) >= 0.8:
            temporal_factors.append("Out of Compliance")
        if temporal_components.get('expiration_factor', 0) >= 0.95:
            temporal_factors.append("No Expiration")
        row['Temporal Factors'] = ', '.join(temporal_factors) if temporal_factors else 'None'
        
        # Extract and format environmental factors
        env_components = breakdown.get('environmental_components', {})
        env_factors = []
        if env_components.get('privilege_factor', 0) >= 1.2:
            env_factors.append("Privileged Access")
        if env_components.get('share_factor', 0) >= 1.1:
            env_factors.append("Widely Shared")
        if env_components.get('domain_factor', 0) >= 1.1:
            env_factors.append("High-Risk Domain")
        if env_components.get('hibp_factor', 0) >= 1.2:
            env_factors.append("Breached Password")
        row['Environmental Factors'] = ', '.join(env_factors) if env_factors else 'None'
        
        # Share count from shared with
        row['Share Count'] = row.get('Shared With', 0)

    # Riskiest Cracked Accounts with DA Pathway
    da_accounts = [row for row in cracked_rows if row.get('DA Domains', 'None') not in ('None', 'Unknown')]
    if da_accounts:
        da_accounts.sort(key=lambda x: (not (x.get('Enabled', 'Unknown') == 'Yes'), -risk_order.get(x['Risk Level'], 0)))
    da_data = []
    for acc in da_accounts:
        row_data = {field: acc.get(field, 'N/A') for field in fieldnames if field in acc}
        row_data['Action'] = "Reset Immediately" if acc.get('Enabled', 'No') == 'Yes' and acc['Risk Level'] in ('High', 'Critical') else "Review and Secure"
        da_data.append(row_data)

    # Top 100 Accounts by Controllables
    controllables_accounts = sorted(
        cracked_rows,
        key=lambda x: (
            not (x.get('Enabled', 'Unknown') == 'Yes'),
            -int(x.get('Controlled Object Count', 0) if x.get('Controlled Object Count', 'Unknown') != 'Unknown' else 0)
        )
    )[:100]
    controllables_data = []
    for acc in controllables_accounts:
        row_data = {field: acc.get(field, 'N/A') for field in fieldnames if field in acc}
        row_data['Action'] = "Reset Immediately" if acc.get('Enabled', 'No') == 'Yes' and acc['Risk Level'] in ('High', 'Critical') else "Review and Secure"
        controllables_data.append(row_data)

    # Accounts with Non-Expiring Passwords
    non_expiring_accounts = [row for row in cracked_rows if row.get('Password Set to Expire', 'Yes') == 'No']
    if non_expiring_accounts:
        non_expiring_accounts.sort(key=lambda x: not (x.get('Enabled', 'Unknown') == 'Yes'))
    non_expiring_data = []
    for acc in non_expiring_accounts:
        row_data = {field: acc.get(field, 'N/A') for field in fieldnames if field in acc}
        row_data['Action'] = "Set to Expire and Reset" if acc.get('Enabled', 'No') == 'Yes' else "Review and Update"
        non_expiring_data.append(row_data)

    # Out-of-Compliance Accounts
    out_of_compliance_accounts = [row for row in cracked_rows if row.get('Days Out of Compliance', 'N/A') not in ('N/A', 'Unknown') and int(row['Days Out of Compliance']) > 0]
    if out_of_compliance_accounts:
        out_of_compliance_accounts.sort(key=lambda x: (
            not (x.get('Enabled', 'Unknown') == 'Yes'),
            int(x['Password Length']),
            -int(x.get('Days Out of Compliance', 0))
        ))
    out_of_compliance_data = []
    for acc in out_of_compliance_accounts:
        row_data = {field: acc.get(field, 'N/A') for field in fieldnames if field in acc}
        row_data['Action'] = "Reset Immediately" if acc['Risk Level'] in ('High', 'Critical') and acc.get('Enabled', 'No') == 'Yes' else "Enforce Compliance"
        out_of_compliance_data.append(row_data)
    
    # Accounts with Similar Passwords
    similar_passwords_accounts = [row for row in cracked_rows if row.get('Similar Passwords', 'None') != 'None']
    if similar_passwords_accounts:
        similar_passwords_accounts.sort(key=lambda x: -risk_order.get(x['Risk Level'], 0))
    similar_passwords_data = []
    for acc in similar_passwords_accounts:
        row_data = {field: acc.get(field, 'N/A') for field in fieldnames if field in acc}
        row_data['Action'] = "Diversify Passwords" if acc.get('Enabled', 'No') == 'Yes' else "Review Similarity"
        similar_passwords_data.append(row_data)

    # HIBP Breached Accounts (sorted by breach count)
    hibp_breached_accounts = [row for row in cracked_rows if row.get('HIBP Breached', 'No') == 'Yes']
    if hibp_breached_accounts:
        hibp_breached_accounts.sort(key=lambda x: (
            not (x.get('Enabled', 'Unknown') == 'Yes'),
            -int(x.get('HIBP Breach Count', 0)),
            -risk_order.get(x['Risk Level'], 0)
        ))
    hibp_breached_data = []
    for acc in hibp_breached_accounts:
        row_data = {field: acc.get(field, 'N/A') for field in fieldnames if field in acc}
        breach_count = int(acc.get('HIBP Breach Count', 0))
        if breach_count >= 100000:
            row_data['Action'] = "URGENT: Reset Immediately - Extremely Common"
        elif breach_count >= 10000:
            row_data['Action'] = "Reset Immediately - Very Common"
        elif breach_count >= 1000:
            row_data['Action'] = "Reset Soon - Common Breach"
        else:
            row_data['Action'] = "Consider Reset - Known Breach"
        hibp_breached_data.append(row_data)

    # Summary of all accounts by risk level
    summary_data = []
    for level in risk_order.keys():
        level_accounts = [acc for acc in cracked_rows if acc.get('Risk Level') == level]
        if level_accounts:
            count = len(level_accounts)
            avg_score = sum(acc.get('Score', 0) for acc in level_accounts) / count
            summary_data.append({
                'Risk Level': level,
                'Count': count,
                'Average Score': round(avg_score, 2),
                'DA Pathways': sum(1 for acc in level_accounts if acc.get('DA Domains', 'None') not in ('None', 'Unknown')),
                'Non-Expiring': sum(1 for acc in level_accounts if acc.get('Password Set to Expire', 'Yes') == 'No'),
                'Out of Compliance': sum(1 for acc in level_accounts if acc.get('Days Out of Compliance', 'N/A') not in ('N/A', 'Unknown') and int(acc['Days Out of Compliance']) > 0),
                'Similar Passwords': sum(1 for acc in level_accounts if acc.get('Similar Passwords', 'None') != 'None'),
                'HIBP Breached': sum(1 for acc in level_accounts if acc.get('HIBP Breached', 'No') == 'Yes')
            })

    # Write to Excel with multiple sheets
    try:
        with pd.ExcelWriter(output_path, engine='openpyxl') as writer:
            # Ensure there's at least one sheet even if no data
            has_data = False
            
            # Write summary first
            if summary_data:
                pd.DataFrame(summary_data).to_excel(writer, sheet_name='Risk Summary', index=False)
                has_data = True
            
            # Then other sheets
            if da_data:
                pd.DataFrame(da_data).to_excel(writer, sheet_name='DA Pathways', index=False)
                has_data = True
            if controllables_data:
                pd.DataFrame(controllables_data).to_excel(writer, sheet_name='Top Controllables', index=False)
                has_data = True
            if non_expiring_data:
                pd.DataFrame(non_expiring_data).to_excel(writer, sheet_name='Non-Expiring', index=False)
                has_data = True
            if out_of_compliance_data:
                pd.DataFrame(out_of_compliance_data).to_excel(writer, sheet_name='Out of Compliance', index=False)
                has_data = True
            if similar_passwords_data:
                pd.DataFrame(similar_passwords_data).to_excel(writer, sheet_name='Similar Passwords', index=False)
                has_data = True
            if hibp_breached_data:
                pd.DataFrame(hibp_breached_data).to_excel(writer, sheet_name='HIBP Breached', index=False)
                has_data = True

            # If no data was written, add a default sheet
            if not has_data:
                pd.DataFrame([{'No Data': f'No actionable data for {domain}'}]).to_excel(
                    writer, sheet_name='No Data', index=False)
        
        if logger:
            logger.info(f"Generated actionable Excel report: {output_path}")
    except Exception as e:
        if logger:
            logger.error(f"Error writing Excel report: {str(e)}")
        else:
            print(f"Error writing Excel report: {str(e)}")