# reports/markdown/actionable.py
"""
Actionable Markdown report generation module.
"""

import os
import hashlib
from core.config import markdown_folder
from report_lib.markdown.components import (
    get_markdown_header, get_risk_vector_explanation, get_markdown_table,
    get_domain_admin_explanation, get_controllables_explanation, 
    get_nonexpiring_explanation, get_compliance_explanation
)

def generate_combined_actionable_report(domain, data, seed, logger=None):
    """
    Generate a combined actionable and explanatory Markdown report.
    
    Args:
        domain (str): Domain name
        data (dict): Domain analysis data
        seed (str): Seed for password placeholders
        logger (Logger, optional): Logger instance
    """
    try:
        os.makedirs(markdown_folder, exist_ok=True)
        
        # Generate header
        markdown = get_markdown_header(f"Actionable Password Security Report - {domain}")
        markdown += "This report provides actionable items for cracked passwords with critical issues along with explanations of why they matter and how to address them.\n\n"
        
        try:
            cracked_rows = [row for row in data['output_rows'] if row['Password Length'] != 'N/A']
            risk_order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Unknown": 0}
        except Exception as e:
            if logger:
                logger.error(f"Error processing data for actionable report for domain {domain}: {str(e)}")
            markdown += "*Error processing data. Some information may be unavailable.*\n\n"
            cracked_rows = []
            risk_order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Unknown": 0}

        # Risk Vector explanation
        markdown += get_risk_vector_explanation()
        
        # DA accounts section with explanation
        da_accounts = [row for row in cracked_rows if row.get('DA Domains', 'None') not in ('None', 'Unknown')]
        da_count = len(da_accounts)
        
        markdown += "## Riskiest Cracked Accounts with DA Pathway\n\n"
        markdown += f"**Count in this Domain**: {da_count} accounts\n\n"
        
        markdown += get_domain_admin_explanation()
        
        if da_accounts:
            da_accounts.sort(key=lambda x: (not (x.get('Enabled', 'Unknown') == 'Yes'), -risk_order.get(x['Risk Level'], 0)))
            markdown += "### Accounts\n\n"
            
            # Create table data
            table_headers = ['Username', 'Password Placeholder', 'Risk Level', 'Shared With', 'Risk Vector', 
                           'Enabled', 'Last Logon', 'When Created', 'Action']
            table_rows = []
            
            for acc in da_accounts:
                placeholder = hashlib.md5((seed + acc['Password']).encode()).hexdigest()
                action = "Reset Immediately" if acc.get('Enabled', 'No') == 'Yes' and acc['Risk Level'] in ('High', 'Critical') else "Review and Secure"
                risk_vector = acc.get('Risk Vector', 'N/A')
                
                table_rows.append({
                    'Username': acc['Username'],
                    'Password Placeholder': placeholder,
                    'Risk Level': acc['Risk Level'],
                    'Shared With': acc.get('Shared With', 'N/A'),
                    'Risk Vector': risk_vector,
                    'Enabled': acc.get('Enabled', 'Unknown'),
                    'Last Logon': acc.get('Last Logon', 'Unknown'),
                    'When Created': acc.get('When Created', 'Unknown'),
                    'Action': action
                })
            
            markdown += get_markdown_table(table_headers, table_rows)
        else:
            markdown += "### Accounts\n\nNo cracked accounts with DA pathways identified.\n\n"

        # Controllables section with explanation
        controllables_accounts = sorted(
            cracked_rows,
            key=lambda x: (
                not (x.get('Enabled', 'Unknown') == 'Yes'),
                -int(x.get('Controlled Object Count', 0) if x.get('Controlled Object Count', 'Unknown') != 'Unknown' else 0)
            )
        )[:100]
        controllables_count = len(controllables_accounts)
        
        markdown += "## Top 100 Accounts by Controllables\n\n"
        markdown += f"**Count in this Domain**: {controllables_count} accounts (top 100 shown)\n\n"
        
        markdown += get_controllables_explanation()
        
        if controllables_accounts:
            markdown += "### Accounts\n\n"
            
            # Create table data
            table_headers = ['Username', 'Password Placeholder', 'Risk Level', 'Shared With', 'Risk Vector',
                           'Enabled', 'Controllables', 'Last Logon', 'When Created', 'Action']
            table_rows = []
            
            for acc in controllables_accounts:
                placeholder = hashlib.md5((seed + acc['Password']).encode()).hexdigest()
                action = "Reset Immediately" if acc.get('Enabled', 'No') == 'Yes' and acc['Risk Level'] in ('High', 'Critical') else "Review and Secure"
                risk_vector = acc.get('Risk Vector', 'N/A')
                controllables = acc.get('Controlled Object Count', 'Unknown')
                
                table_rows.append({
                    'Username': acc['Username'],
                    'Password Placeholder': placeholder,
                    'Risk Level': acc['Risk Level'],
                    'Shared With': acc.get('Shared With', 'N/A'),
                    'Risk Vector': risk_vector,
                    'Enabled': acc.get('Enabled', 'Unknown'),
                    'Controllables': controllables,
                    'Last Logon': acc.get('Last Logon', 'Unknown'),
                    'When Created': acc.get('When Created', 'Unknown'),
                    'Action': action
                })
            
            markdown += get_markdown_table(table_headers, table_rows)
        else:
            markdown += "### Accounts\n\nNo cracked accounts with controlled objects identified.\n\n"

        # Non-expiring passwords section
        non_expiring_accounts = [row for row in cracked_rows if row.get('Password Set to Expire', 'Yes') == 'No']
        non_expiring_count = len(non_expiring_accounts)
        
        markdown += "## Accounts with Non-Expiring Passwords\n\n"
        markdown += f"**Count in this Domain**: {non_expiring_count} accounts\n\n"
        
        markdown += get_nonexpiring_explanation()
        
        if non_expiring_accounts:
            non_expiring_accounts.sort(key=lambda x: not (x.get('Enabled', 'Unknown') == 'Yes'))
            markdown += "### Accounts\n\n"
            
            # Create table data
            table_headers = ['Username', 'Password Placeholder', 'Risk Level', 'Risk Vector',
                           'Enabled', 'Last Logon', 'When Created', 'Action']
            table_rows = []
            
            for acc in non_expiring_accounts:
                placeholder = hashlib.md5((seed + acc['Password']).encode()).hexdigest()
                action = "Set to Expire and Reset" if acc.get('Enabled', 'No') == 'Yes' else "Review and Update"
                risk_vector = acc.get('Risk Vector', 'N/A')
                
                table_rows.append({
                    'Username': acc['Username'],
                    'Password Placeholder': placeholder,
                    'Risk Level': acc['Risk Level'],
                    'Risk Vector': risk_vector,
                    'Enabled': acc.get('Enabled', 'Unknown'),
                    'Last Logon': acc.get('Last Logon', 'Unknown'),
                    'When Created': acc.get('When Created', 'Unknown'),
                    'Action': action
                })
            
            markdown += get_markdown_table(table_headers, table_rows)
        else:
            markdown += "### Accounts\n\nNo cracked accounts with non-expiring passwords identified.\n\n"

        # Out-of-compliance section
        out_of_compliance_accounts = [row for row in cracked_rows 
                                    if row.get('Days Out of Compliance', 'N/A') not in ('N/A', 'Unknown') 
                                    and int(row['Days Out of Compliance']) > 0]
        out_of_compliance_count = len(out_of_compliance_accounts)
        
        markdown += "## Out-of-Compliance Accounts\n\n"
        markdown += f"**Count in this Domain**: {out_of_compliance_count} accounts\n\n"
        
        markdown += get_compliance_explanation()
        
        if out_of_compliance_accounts:
            out_of_compliance_accounts.sort(key=lambda x: (
                not (x.get('Enabled', 'Unknown') == 'Yes'),
                int(x['Password Length']),
                -int(x.get('Days Out of Compliance', 0))
            ))
            markdown += "### Accounts\n\n"
            
            # Create table data
            table_headers = ['Username', 'Password Length', 'Days Out of Compliance', 'Risk Vector',
                           'Enabled', 'Last Logon', 'When Created', 'Risk Level', 'Action']
            table_rows = []
            
            for acc in out_of_compliance_accounts:
                action = "Reset Immediately" if acc['Risk Level'] in ('High', 'Critical') and acc.get('Enabled', 'No') == 'Yes' else "Enforce Compliance"
                risk_vector = acc.get('Risk Vector', 'N/A')
                
                table_rows.append({
                    'Username': acc['Username'],
                    'Password Length': acc['Password Length'],
                    'Days Out of Compliance': acc.get('Days Out of Compliance', 'N/A'),
                    'Risk Vector': risk_vector,
                    'Enabled': acc.get('Enabled', 'Unknown'),
                    'Last Logon': acc.get('Last Logon', 'Unknown'),
                    'When Created': acc.get('When Created', 'Unknown'),
                    'Risk Level': acc['Risk Level'],
                    'Action': action
                })
            
            markdown += get_markdown_table(table_headers, table_rows)
        else:
            markdown += "### Accounts\n\nNo cracked accounts out of compliance identified.\n\n"

        if not any([da_accounts, controllables_accounts, non_expiring_accounts, out_of_compliance_accounts]):
            markdown += "**No actionable items identified for this domain.**\n"
        
        output_path = markdown_folder / f'{domain}_actionable_report.md'
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(markdown)
        if logger:
            logger.info(f"Generated combined actionable report: {output_path}")
            
    except Exception as e:
        if logger:
            logger.error(f"Error generating combined actionable report for domain {domain}: {str(e)}")
        else:
            print(f"Error generating combined actionable report for domain {domain}: {str(e)}")

def generate_actionable_report(domain, data, seed, logger=None):
    """
    Legacy function that now calls the combined actionable report.
    
    Args:
        domain (str): Domain name
        data (dict): Domain analysis data
        seed (str): Seed for password placeholders
        logger (Logger, optional): Logger instance
    """
    return generate_combined_actionable_report(domain, data, seed, logger)

def generate_explained_actionable_report(domain, data, seed, logger=None):
    """
    Legacy function that now calls the combined actionable report.
    
    Args:
        domain (str): Domain name
        data (dict): Domain analysis data
        seed (str): Seed for password placeholders
        logger (Logger, optional): Logger instance
    """
    return generate_combined_actionable_report(domain, data, seed, logger)