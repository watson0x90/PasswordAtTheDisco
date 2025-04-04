import csv
from core.config import reports_folder
import os
import hashlib
import pandas as pd
from collections import Counter

def write_csv_report(domain, rows, is_combined=False):
    output_dir = reports_folder / 'csv_report'
    os.makedirs(output_dir, exist_ok=True)
    filename = f"{domain}_report.csv" if not is_combined else "combined_report.csv"
    output_path = output_dir / filename
    
    # Define fieldnames based on report type
    if is_combined:
        fieldnames = [
            'Domain', 'Username', 'Password', 'Shared With', 'Domains Shared', 'Score', 'Risk Level',
            'DA Domains', 'Controlled Object Count', 'Days Out of Compliance', 'Last Password Set',
            'Password Set to Expire', 'Enabled', 'When Created', 'Last Logon', 'Last Logon Timestamp',
            'Password Cant Change'
        ]
    else:
        fieldnames = [
            'Domain', 'Username', 'Password', 'Password Length', 'Complexity Label', 'Contains Unicode',
            'Meets Policy', 'Policy Violations', 'Forbidden Words', 'Keyboard Patterns',
            'Common Password', 'Is Exactly Dictionary Word', 'Shared With', 'Risk Level', 'Score',
            'DA Domains', 'Controlled Object Count', 'Days Out of Compliance', 'Last Password Set',
            'Password Set to Expire', 'Enabled', 'When Created', 'Last Logon', 'Last Logon Timestamp',
            'Password Cant Change'
        ]
    
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            # Filter row to only include defined fieldnames
            filtered_row = {key: row.get(key, default) for key, default in {
                'Domain': 'N/A',
                'Username': 'N/A',
                'Password': 'N/A',
                'Password Length': 'N/A' if not is_combined else None,
                'Complexity Label': 'N/A' if not is_combined else None,
                'Contains Unicode': 'No' if not is_combined else None,
                'Meets Policy': 'N/A' if not is_combined else None,
                'Policy Violations': 'N/A' if not is_combined else None,
                'Forbidden Words': 'N/A' if not is_combined else None,
                'Keyboard Patterns': 'N/A' if not is_combined else None,
                'Common Password': 'No' if not is_combined else None,
                'Is Exactly Dictionary Word': 'No' if not is_combined else None,
                'Shared With': '0',
                'Domains Shared': 'N/A' if is_combined else None,
                'Risk Level': 'N/A',
                'Score': 'N/A',
                'DA Domains': 'None',
                'Controlled Object Count': 'N/A',
                'Days Out of Compliance': 'N/A',
                'Last Password Set': 'Unknown',
                'Password Set to Expire': 'Unknown',
                'Enabled': 'Unknown',
                'When Created': 'Unknown',
                'Last Logon': 'Unknown',
                'Last Logon Timestamp': 'Unknown',
                'Password Cant Change': 'Unknown'
            }.items() if key in fieldnames}
            writer.writerow(filtered_row)

def write_actionable_excel(domain, rows, seed):
    output_dir = reports_folder / 'excel_report'
    os.makedirs(output_dir, exist_ok=True)
    filename = f"{domain}_actionable_report.xlsx"
    output_path = output_dir / filename
    
    # Comprehensive fieldnames list
    fieldnames = [
        'Domain', 'Username', 'Password Placeholder', 'Password Length', 'Complexity Label', 'Contains Unicode',
        'Meets Policy', 'Policy Violations', 'Shares Password', 'Share Count',
        'Risk Level', 'Score', 'DA Domains', 'Controlled Object Count', 'Days Out of Compliance',
        'Last Password Set', 'Password Set to Expire', 'Enabled', 'When Created', 'Last Logon',
        'Last Logon Timestamp', 'Password Cant Change', 'Action'
    ]
    
    # Filter and categorize data
    cracked_rows = [row for row in rows if row['Password Length'] != 'N/A']
    risk_order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Unknown": 0}

    # Riskiest Cracked Accounts with DA Pathway
    da_accounts = [row for row in cracked_rows if row.get('DA Domains', 'None') not in ('None', 'Unknown')]
    if da_accounts:
        da_accounts.sort(key=lambda x: (not (x.get('Enabled', 'Unknown') == 'Yes'), -risk_order.get(x['Risk Level'], 0)))
    da_data = [
        {
            'Domain': acc.get('Domain', 'N/A'),
            'Username': acc.get('Username', 'N/A'),
            'Password Placeholder': hashlib.md5((seed + acc['Password']).encode()).hexdigest(),
            'Password Length': acc.get('Password Length', 'N/A'),
            'Complexity Label': acc.get('Complexity Label', 'N/A'),
            'Contains Unicode': acc.get('Contains Unicode', 'No'),
            'Meets Policy': acc.get('Meets Policy', 'N/A'),
            'Policy Violations': acc.get('Policy Violations', 'N/A'),
            'Shares Password': acc.get('Shares Password', 'No'),
            'Share Count': acc.get('Shared With', '0'),
            'Risk Level': acc.get('Risk Level', 'N/A'),
            'Score': acc.get('Score', 'N/A'),
            'DA Domains': acc.get('DA Domains', 'None'),
            'Controlled Object Count': acc.get('Controlled Object Count', 'N/A'),
            'Days Out of Compliance': acc.get('Days Out of Compliance', 'N/A'),
            'Last Password Set': acc.get('Last Password Set', 'Unknown'),
            'Password Set to Expire': acc.get('Password Set to Expire', 'Unknown'),
            'Enabled': acc.get('Enabled', 'Unknown'),
            'When Created': acc.get('When Created', 'Unknown'),
            'Last Logon': acc.get('Last Logon', 'Unknown'),
            'Last Logon Timestamp': acc.get('Last Logon Timestamp', 'Unknown'),
            'Password Cant Change': acc.get('Password Cant Change', 'Unknown'),
            'Action': "Reset Immediately" if acc.get('Enabled', 'No') == 'Yes' and acc['Risk Level'] in ('High', 'Critical') else "Review and Secure"
        }
        for acc in da_accounts
    ]

    # Top 100 Accounts by Controllables
    controllables_accounts = sorted(
        cracked_rows,
        key=lambda x: (
            not (x.get('Enabled', 'Unknown') == 'Yes'),
            -int(x.get('Controlled Object Count', 0) if x.get('Controlled Object Count', 'Unknown') != 'Unknown' else 0)
        )
    )[:100]
    controllables_data = [
        {
            'Domain': acc.get('Domain', 'N/A'),
            'Username': acc.get('Username', 'N/A'),
            'Password Placeholder': hashlib.md5((seed + acc['Password']).encode()).hexdigest(),
            'Password Length': acc.get('Password Length', 'N/A'),
            'Complexity Label': acc.get('Complexity Label', 'N/A'),
            'Contains Unicode': acc.get('Contains Unicode', 'No'),
            'Meets Policy': acc.get('Meets Policy', 'N/A'),
            'Policy Violations': acc.get('Policy Violations', 'N/A'),
            'Shares Password': acc.get('Shares Password', 'No'),
            'Share Count': acc.get('Shared With', '0'),
            'Risk Level': acc.get('Risk Level', 'N/A'),
            'Score': acc.get('Score', 'N/A'),
            'DA Domains': acc.get('DA Domains', 'None'),
            'Controlled Object Count': acc.get('Controlled Object Count', 'N/A'),
            'Days Out of Compliance': acc.get('Days Out of Compliance', 'N/A'),
            'Last Password Set': acc.get('Last Password Set', 'Unknown'),
            'Password Set to Expire': acc.get('Password Set to Expire', 'Unknown'),
            'Enabled': acc.get('Enabled', 'Unknown'),
            'When Created': acc.get('When Created', 'Unknown'),
            'Last Logon': acc.get('Last Logon', 'Unknown'),
            'Last Logon Timestamp': acc.get('Last Logon Timestamp', 'Unknown'),
            'Password Cant Change': acc.get('Password Cant Change', 'Unknown'),
            'Action': "Reset Immediately" if acc.get('Enabled', 'No') == 'Yes' and acc['Risk Level'] in ('High', 'Critical') else "Review and Secure"
        }
        for acc in controllables_accounts
    ]

    # Accounts with Non-Expiring Passwords
    non_expiring_accounts = [row for row in cracked_rows if row.get('Password Set to Expire', 'Yes') == 'No']
    if non_expiring_accounts:
        non_expiring_accounts.sort(key=lambda x: not (x.get('Enabled', 'Unknown') == 'Yes'))
    non_expiring_data = [
        {
            'Domain': acc.get('Domain', 'N/A'),
            'Username': acc.get('Username', 'N/A'),
            'Password Placeholder': hashlib.md5((seed + acc['Password']).encode()).hexdigest(),
            'Password Length': acc.get('Password Length', 'N/A'),
            'Complexity Label': acc.get('Complexity Label', 'N/A'),
            'Contains Unicode': acc.get('Contains Unicode', 'No'),
            'Meets Policy': acc.get('Meets Policy', 'N/A'),
            'Policy Violations': acc.get('Policy Violations', 'N/A'),
            'Shares Password': acc.get('Shares Password', 'No'),
            'Share Count': acc.get('Shared With', '0'),
            'Risk Level': acc.get('Risk Level', 'N/A'),
            'Score': acc.get('Score', 'N/A'),
            'DA Domains': acc.get('DA Domains', 'None'),
            'Controlled Object Count': acc.get('Controlled Object Count', 'N/A'),
            'Days Out of Compliance': acc.get('Days Out of Compliance', 'N/A'),
            'Last Password Set': acc.get('Last Password Set', 'Unknown'),
            'Password Set to Expire': acc.get('Password Set to Expire', 'Unknown'),
            'Enabled': acc.get('Enabled', 'Unknown'),
            'When Created': acc.get('When Created', 'Unknown'),
            'Last Logon': acc.get('Last Logon', 'Unknown'),
            'Last Logon Timestamp': acc.get('Last Logon Timestamp', 'Unknown'),
            'Password Cant Change': acc.get('Password Cant Change', 'Unknown'),
            'Action': "Set to Expire and Reset" if acc.get('Enabled', 'No') == 'Yes' else "Review and Update"
        }
        for acc in non_expiring_accounts
    ]

    # Out-of-Compliance Accounts
    out_of_compliance_accounts = [row for row in cracked_rows if row.get('Days Out of Compliance', 'N/A') not in ('N/A', 'Unknown') and int(row['Days Out of Compliance']) > 0]
    if out_of_compliance_accounts:
        out_of_compliance_accounts.sort(key=lambda x: (
            not (x.get('Enabled', 'Unknown') == 'Yes'),
            int(x['Password Length']),
            -int(x.get('Days Out of Compliance', 0))
        ))
    out_of_compliance_data = [
        {
            'Domain': acc.get('Domain', 'N/A'),
            'Username': acc.get('Username', 'N/A'),
            'Password Placeholder': hashlib.md5((seed + acc['Password']).encode()).hexdigest(),
            'Password Length': acc.get('Password Length', 'N/A'),
            'Complexity Label': acc.get('Complexity Label', 'N/A'),
            'Contains Unicode': acc.get('Contains Unicode', 'No'),
            'Meets Policy': acc.get('Meets Policy', 'N/A'),
            'Policy Violations': acc.get('Policy Violations', 'N/A'),
            'Shares Password': acc.get('Shares Password', 'No'),
            'Share Count': acc.get('Shared With', '0'),
            'Risk Level': acc.get('Risk Level', 'N/A'),
            'Score': acc.get('Score', 'N/A'),
            'DA Domains': acc.get('DA Domains', 'None'),
            'Controlled Object Count': acc.get('Controlled Object Count', 'N/A'),
            'Days Out of Compliance': acc.get('Days Out of Compliance', 'N/A'),
            'Last Password Set': acc.get('Last Password Set', 'Unknown'),
            'Password Set to Expire': acc.get('Password Set to Expire', 'Unknown'),
            'Enabled': acc.get('Enabled', 'Unknown'),
            'When Created': acc.get('When Created', 'Unknown'),
            'Last Logon': acc.get('Last Logon', 'Unknown'),
            'Last Logon Timestamp': acc.get('Last Logon Timestamp', 'Unknown'),
            'Password Cant Change': acc.get('Password Cant Change', 'Unknown'),
            'Action': "Reset Immediately" if acc['Risk Level'] in ('High', 'Critical') and acc.get('Enabled', 'No') == 'Yes' else "Enforce Compliance"
        }
        for acc in out_of_compliance_accounts
    ]

    # Write to Excel with multiple sheets
    with pd.ExcelWriter(output_path, engine='openpyxl') as writer:
        if da_data:
            pd.DataFrame(da_data).to_excel(writer, sheet_name='DA Pathways', index=False)
        if controllables_data:
            pd.DataFrame(controllables_data).to_excel(writer, sheet_name='Top Controllables', index=False)
        if non_expiring_data:
            pd.DataFrame(non_expiring_data).to_excel(writer, sheet_name='Non-Expiring', index=False)
        if out_of_compliance_data:
            pd.DataFrame(out_of_compliance_data).to_excel(writer, sheet_name='Out of Compliance', index=False)            