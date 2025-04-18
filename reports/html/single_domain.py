# reports/html/single_domain.py
"""
Single domain report generation module.
"""

import os
from pathlib import Path
from reports.html.components import (
    html_head, get_export_button, create_error_message, create_visualization_container,
    get_risk_distribution_html, get_accounts_table_html, RISK_VECTOR_EXPLANATION,
    RISK_SCORE_EXPLANATION
)
from reports.html.scripts import TABLE_SORT_JS
from utils.visualization_helper import add_visualization_to_html

def generate_html_report(domain, data, visuals, logger=None):
    """
    Generate HTML report for a domain with improved error handling and visualizations.
    
    Args:
        domain (str): Domain name
        data (dict): Domain analysis data
        visuals (dict): Dictionary of visualization paths
        logger (Logger, optional): Logger instance
    """
    try:
        # Create HTML head
        html = html_head(f"Password Security Report - {domain}")
        
        html += """
        <body>
            <div id="reportContent">
                <h1>Password Security Report for {domain}</h1>
                <p><a href="./main.html">Back to Main</a> | <a href="./search.html">Search Accounts</a></p>
        """
        
        # Add export button
        html += get_export_button('reportContent', f'{domain}_report.pdf')

        try:
            # Get consistent data counts
            cracked_rows = [row for row in data['output_rows'] if row.get('Password Length', 'N/A') != 'N/A']
            total_accounts = len(data['output_rows'])
            cracked = len(cracked_rows)
            uncracked = total_accounts - cracked
            
            # Calculate compliance and expiration stats
            out_of_compliance = sum(1 for row in data['output_rows'] 
                                   if row.get('Days Out of Compliance', 'Unknown') not in ('Unknown', 'N/A') 
                                   and int(row.get('Days Out of Compliance', 0)) > 0)
            
            non_expiring = sum(1 for row in data['output_rows'] 
                              if row.get('Password Set to Expire', 'Unknown') == 'No')
        except (KeyError, TypeError) as e:
            if logger:
                logger.error(f"Error processing data for domain {domain}: {str(e)}")
            html += create_error_message("Error processing data. Some metrics may be unavailable.")
            total_accounts = 0
            cracked = 0
            uncracked = 0
            out_of_compliance = 0
            non_expiring = 0

        if total_accounts > 0:
            percent_cracked = round(cracked/total_accounts*100, 1)
            percent_uncracked = round(uncracked/total_accounts*100, 1)
            percent_compliance = round(out_of_compliance/total_accounts*100, 1) if total_accounts > 0 else 0
            percent_nonexpiring = round(non_expiring/total_accounts*100, 1) if total_accounts > 0 else 0
        else:
            percent_cracked = 0
            percent_uncracked = 0
            percent_compliance = 0
            percent_nonexpiring = 0

        # Overview section
        html += f"""
        <h2>Overview</h2>
        <ul>
            <li><strong>Total Accounts Analyzed:</strong> {total_accounts}</li>
            <li><strong>Cracked Passwords:</strong> {cracked} ({percent_cracked}%)</li>
            <li><strong>Uncracked Passwords:</strong> {uncracked} ({percent_uncracked}%)</li>
            <li><strong>Out of Compliance Accounts:</strong> {out_of_compliance} ({percent_compliance}%)</li>
            <li><strong>Non-Expiring Passwords:</strong> {non_expiring} ({percent_nonexpiring}%)</li>
        </ul>
        """
        
        # Add risk score explanation
        html += RISK_SCORE_EXPLANATION
        html += RISK_VECTOR_EXPLANATION

        # Domain risk information - Ensure consistent data source
        try:
            # Find most accurate risk distribution source
            if 'domain_risk' in data and 'risk_distribution' in data['domain_risk']:
                risk_distribution = data['domain_risk']['risk_distribution']
                domain_risk = data['domain_risk']
            elif 'risk_counter' in data:
                risk_distribution = data['risk_counter']
                domain_risk = {
                    'risk_score': data.get('domain_risk', {}).get('risk_score', 'N/A'),
                    'overall_risk_level': data.get('domain_risk', {}).get('overall_risk_level', 'Unknown'),
                    'avg_score': data.get('domain_risk', {}).get('avg_score', 'N/A'),
                    'max_score': data.get('domain_risk', {}).get('max_score', 'N/A')
                }
            else:
                # Calculate from output rows as last resort
                risk_distribution = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
                for row in cracked_rows:
                    risk_level = row.get('Risk Level', 'Unknown')
                    if risk_level in risk_distribution:
                        risk_distribution[risk_level] += 1
                
                # Simple domain risk approximation
                if cracked > 0:
                    scores = [row.get('Score', 0) for row in cracked_rows if 'Score' in row]
                    avg_score = sum(scores) / len(scores) if scores else 0
                    max_score = max(scores) if scores else 0
                    
                    # Determine risk level based on average score
                    if avg_score >= 8.0:
                        overall_level = "Critical"
                    elif avg_score >= 6.0:
                        overall_level = "High"
                    elif avg_score >= 4.0:
                        overall_level = "Medium"
                    else:
                        overall_level = "Low"
                    
                    domain_risk = {
                        'risk_score': round(avg_score, 1),
                        'overall_risk_level': overall_level,
                        'avg_score': round(avg_score, 1),
                        'max_score': round(max_score, 1)
                    }
                else:
                    domain_risk = {
                        'risk_score': 'N/A',
                        'overall_risk_level': 'Unknown',
                        'avg_score': 'N/A',
                        'max_score': 'N/A'
                    }
            
            # Calculate total for percentages
            total_risk_accounts = sum(risk_distribution.values())
            
            html += f"""
            <h2>Risk Distribution</h2>
            <p>Risk levels of the {cracked} cracked passwords in {domain}, assessed by length, complexity, and privilege.</p>
            <ul>
                <li><strong>Overall Domain Risk Score:</strong> {domain_risk.get('risk_score', 'N/A')}/10.0 ({domain_risk.get('overall_risk_level', 'Unknown')})</li>
                <li><strong>Average Account Risk Score:</strong> {domain_risk.get('avg_score', 'N/A')}/10.0</li>
                <li><strong>Maximum Account Risk Score:</strong> {domain_risk.get('max_score', 'N/A')}/10.0</li>
                <li><strong>Risk Distribution:</strong>
                    {get_risk_distribution_html(risk_distribution, total_risk_accounts)}
                </li>
            </ul>
            """
        except Exception as e:
            if logger:
                logger.error(f"Error processing risk distribution for domain {domain}: {str(e)}")
            html += """
            <h2>Risk Distribution</h2>
            """ + create_error_message("Error processing risk distribution data.")

        # Add risk level visualization if available
        vis_html = add_visualization_to_html(visuals, 'risk_levels', 'Risk Levels Chart')
        if vis_html:
            html += vis_html

        # BloodHound insights section
        html += f"""
        <h2>BloodHound Insights</h2>
        <p>Accounts with pathways to Domain Admin (DA) privileges in {domain}.</p>
        """

        try:
            cracked_da_accounts = [row for row in data['output_rows'] 
                                  if row['Password Length'] != 'N/A' and 
                                  row.get('DA Domains', 'None') not in ('None', 'Unknown')]
            if cracked_da_accounts:
                # Group accounts by password
                from collections import defaultdict
                cracked_by_password = defaultdict(list)
                for acc in cracked_da_accounts:
                    cracked_by_password[acc['Password']].append(acc)
                
                html += """
                <h3>Cracked Accounts with DA Pathways</h3>
                <p>Cracked accounts with DA pathways, grouped by password:</p>
                """
                
                # Create table with usernames, password, DA domains, and risk level
                table_data = []
                for password, accounts in cracked_by_password.items():
                    usernames = ', '.join(acc['Username'] for acc in accounts)
                    da_domains = next(acc['DA Domains'] for acc in accounts if 'DA Domains' in acc)
                    risk_level = next(acc['Risk Level'] for acc in accounts if 'Risk Level' in acc)
                    table_data.append({
                        'Usernames': usernames,
                        'Password': password,
                        'DA Domains': da_domains,
                        'Risk Level': risk_level
                    })
                
                html += get_accounts_table_html(
                    table_data, 
                    ['Usernames', 'Password', 'DA Domains', 'Risk Level']
                )
            else:
                html += """
                <h3>Cracked Accounts with DA Pathways</h3>
                <p>No cracked accounts with DA pathways found.</p>
                """
        except Exception as e:
            if logger:
                logger.error(f"Error processing DA accounts for domain {domain}: {str(e)}")
            html += """
            <h3>Cracked Accounts with DA Pathways</h3>
            """ + create_error_message("Error processing DA accounts data.")

        # Add all standard visualizations
        html += add_standard_visualizations_html(visuals, domain)

        # Add table sorting JavaScript and close HTML
        html += f"""
        {TABLE_SORT_JS}
        </div>
        </body>
        </html>
        """

        # Write to file
        output_path = Path(os.path.join('output', 'html_report', f'{domain}_report.html'))
        os.makedirs(output_path.parent, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
        if logger:
            logger.info(f"Generated HTML report: {output_path}")
            
    except Exception as e:
        if logger:
            logger.error(f"Error generating HTML report for domain {domain}: {str(e)}")
        else:
            print(f"Error generating HTML report for domain {domain}: {str(e)}")

def add_standard_visualizations_html(visuals, domain):
    """Add standard set of visualizations to HTML report."""
    html = ""
    visualization_sets = {
        'risk_overview': [
            ('risk_levels', 'Risk Level Distribution'),
            ('score_breakdown', 'Risk Score Breakdown'),
            ('risk_factors', 'Risk Factor Contribution')
        ],
        'password_characteristics': [
            ('length_distribution', 'Password Length Distribution'),
            ('complexity_distribution', 'Password Complexity Distribution'),
            ('password_issues', 'Password Issues'),
            ('top_banned_words', 'Top Banned Words')
        ],
        'temporal_factors': [
            ('last_password_set', 'Last Password Set Distribution'),
            ('expiration_status', 'Password Expiration Status'),
            ('compliance_distribution', 'Compliance Status'),
            ('password_age', 'Password Age vs. Risk')
        ],
        'privilege_analysis': [
            ('da_risk', 'Domain Admin Pathways'),
            ('similarity_network', 'Password Similarity Network'),
        ]
    }
    
    for section, vis_items in visualization_sets.items():
        section_html = f"<h2>{section.replace('_', ' ').title()}</h2>\n<div class='visualization-grid'>\n"
        section_has_content = False
        
        for vis_type, title in vis_items:
            vis_html = add_visualization_to_html(visuals, vis_type, title)
            if vis_html:
                section_html += vis_html
                section_has_content = True
        
        section_html += "</div>\n"
        if section_has_content:
            html += section_html
    
    return html