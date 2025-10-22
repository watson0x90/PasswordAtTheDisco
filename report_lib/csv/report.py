# reports/csv/report.py
"""
CSV report generation module for password security audit.
Provides functions to generate various CSV report formats.
"""

import csv
import os
import json
from core import config as config_module

def write_csv_report(domain, rows, is_combined=False):
    """
    Generate CSV report for domain analysis.

    Args:
        domain (str): Domain name
        rows (list): List of data rows
        is_combined (bool): Whether this is a combined cross-domain report
    """
    # Access csv_folder dynamically to support runtime directory changes
    csv_folder = config_module.csv_folder
    os.makedirs(csv_folder, exist_ok=True)
    filename = f"{domain}_report.csv" if not is_combined else "combined_report.csv"
    output_path = csv_folder / filename
    
    # Define fieldnames based on report type
    if is_combined:
        fieldnames = [
            'Domain', 'Username', 'Password', 'Shared With', 'Domains Shared',
            'HIBP Breached', 'HIBP Breach Count', 'HIBP Risk Level',
            'Score', 'Base Score', 'Temporal Score', 'Environmental Score', 'Risk Level', 'Risk Vector',
            'DA Domains', 'Controlled Object Count', 'Days Out of Compliance', 'Last Password Set',
            'Password Set to Expire', 'Enabled', 'When Created', 'Last Logon', 'Last Logon Timestamp',
            'Password Cant Change'
        ]
    else:
        fieldnames = [
            'Domain', 'Username', 'Password', 'Password Length', 'Complexity Label', 'Contains Unicode',
            'Meets Policy', 'Policy Violations', 'Forbidden Words', 'Keyboard Patterns',
            'Common Password', 'Is Exactly Dictionary Word', 'Similar Passwords', 'Shared With',
            'HIBP Breached', 'HIBP Breach Count', 'HIBP Risk Level',
            'Risk Level', 'Score', 'Base Score', 'Temporal Score', 'Environmental Score', 'Risk Vector',
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
                # Extract score breakdown values if they exist
                score_breakdown = row.get('Score Breakdown', {})
                base_score = score_breakdown.get('base_score', 'N/A') if isinstance(score_breakdown, dict) else 'N/A'
                temporal_score = score_breakdown.get('temporal_score', 'N/A') if isinstance(score_breakdown, dict) else 'N/A'
                environmental_score = score_breakdown.get('environmental_score', 'N/A') if isinstance(score_breakdown, dict) else 'N/A'

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
                    'HIBP Breached': 'No',
                    'HIBP Breach Count': '0',
                    'HIBP Risk Level': 'None',
                    'Risk Level': 'N/A',
                    'Score': 'N/A',
                    'Base Score': base_score,
                    'Temporal Score': temporal_score,
                    'Environmental Score': environmental_score,
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