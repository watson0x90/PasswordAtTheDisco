# reports/csv/report.py
"""
CSV report generation module for password security audit.
Provides functions to generate various CSV report formats.
"""

import csv
import os
import json
from core.config import reports_folder, csv_folder

def write_csv_report(domain, rows, is_combined=False):
    """
    Generate CSV report for domain analysis.
    
    Args:
        domain (str): Domain name
        rows (list): List of data rows
        is_combined (bool): Whether this is a combined cross-domain report
    """
    os.makedirs(csv_folder, exist_ok=True)
    filename = f"{domain}_report.csv" if not is_combined else "combined_report.csv"
    output_path = csv_folder / filename
    
    # Define fieldnames based on report type
    if is_combined:
        fieldnames = [
            'Domain', 'Username', 'Password', 'Shared With', 'Domains Shared', 'Score', 'Risk Level',
            'Risk Vector',
            'DA Domains', 'Controlled Object Count', 'Days Out of Compliance', 'Last Password Set',
            'Password Set to Expire', 'Enabled', 'When Created', 'Last Logon', 'Last Logon Timestamp',
            'Password Cant Change'
        ]
    else:
        fieldnames = [
            'Domain', 'Username', 'Password', 'Password Length', 'Complexity Label', 'Contains Unicode',
            'Meets Policy', 'Policy Violations', 'Forbidden Words', 'Keyboard Patterns',
            'Common Password', 'Is Exactly Dictionary Word', 'Similar Passwords', 'Shared With', 'Risk Level', 'Score',
            'Risk Vector',
            'DA Domains', 'Controlled Object Count', 'Days Out of Compliance', 'Last Password Set',
            'Password Set to Expire', 'Enabled', 'When Created', 'Last Logon', 'Last Logon Timestamp',
            'Password Cant Change'
        ]
    
    # Write to CSV
    try:
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
                    'Similar Passwords': 'None' if not is_combined else None,
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
    except Exception as e:
        print(f"Error writing CSV report: {str(e)}")
        
    # Create a detailed JSON export with all data including score breakdowns
    try:
        json_filename = f"{domain}_detailed_report.json" if not is_combined else "combined_detailed_report.json"
        json_path = csv_folder / json_filename
        
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(rows, f, indent=2)
    except Exception as e:
        print(f"Error writing detailed JSON report: {str(e)}")