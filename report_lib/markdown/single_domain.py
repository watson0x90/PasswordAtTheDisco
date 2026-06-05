# reports/markdown/single_domain.py
"""
Single domain Markdown report generation module.
"""

import os
from collections import defaultdict

from core.config import markdown_folder
from report_lib.markdown.components import (
    format_risk_distribution,
    get_domain_overview,
    get_executive_summary,
    get_markdown_header,
    get_markdown_table,
    get_risk_score_explanation,
    get_risk_vector_explanation,
)
from report_lib.markdown.utils import extract_basic_stats, get_password_length_stats, get_risk_distribution
from utils.visualization_helper import add_standard_visualizations_markdown, add_visualization_to_markdown


def generate_markdown_report(domain, data, visuals, logger=None):
    """
    Generate main Markdown report for a domain with improved error handling and visualization consistency.
    
    Args:
        domain (str): Domain name
        data (dict): Domain analysis data
        visuals (dict): Visualization paths
        logger (Logger, optional): Logger instance
    """
    try:
        os.makedirs(markdown_folder, exist_ok=True)
        
        # Generate header
        markdown = get_markdown_header(f"Password Security Report - {domain}")
        
        # Extract basic statistics
        basic_stats = extract_basic_stats(data)
        total_accounts = basic_stats['total_accounts']
        cracked = basic_stats['cracked']
        uncracked = basic_stats['uncracked']
        out_of_compliance = basic_stats['out_of_compliance']
        non_expiring = basic_stats['non_expiring']

        # Calculate HIBP statistics
        hibp_breached = sum(1 for row in data.get('output_rows', [])
                           if row.get('HIBP Breached', 'No') == 'Yes')
        hibp_total_exposures = sum(int(row.get('HIBP Breach Count', 0))
                                  for row in data.get('output_rows', [])
                                  if row.get('HIBP Breached', 'No') == 'Yes')

        # Executive Summary
        markdown += get_executive_summary(domain, total_accounts, cracked, data.get('domain_risk', {}))

        # Overview section
        markdown += get_domain_overview(total_accounts, cracked, uncracked, out_of_compliance, non_expiring,
                                       hibp_breached, hibp_total_exposures)

        # HIBP Breach Statistics section
        if hibp_breached > 0:
            markdown += "## HIBP Breach Statistics\n\n"
            markdown += f"**{hibp_breached}** passwords ({(hibp_breached/total_accounts*100):.1f}% of all accounts) have been found in data breaches tracked by HaveIBeenPwned (HIBP).\n\n"

            # Top breached passwords
            breached_passwords = [(row.get('Password', 'N/A'), int(row.get('HIBP Breach Count', 0)), row.get('Shared With', 0))
                                 for row in data.get('output_rows', [])
                                 if row.get('HIBP Breached', 'No') == 'Yes' and row.get('Password Length', 'N/A') != 'N/A']
            breached_passwords.sort(key=lambda x: x[1], reverse=True)

            if breached_passwords:
                markdown += "### Top 10 Most Breached Passwords\n\n"
                markdown += "| Password | Breach Count | Accounts Using |\n"
                markdown += "|----------|--------------|----------------|\n"
                for pwd, count, shared in breached_passwords[:10]:
                    markdown += f"| `{pwd}` | {count:,} | {int(shared) + 1} |\n"
                markdown += "\n"

            # Breach count distribution
            breach_levels = {'Extreme (100K+)': 0, 'Very High (10K-99K)': 0, 'High (1K-9.9K)': 0,
                           'Medium (100-999)': 0, 'Low (10-99)': 0, 'Minimal (1-9)': 0}
            for row in data.get('output_rows', []):
                if row.get('HIBP Breached', 'No') == 'Yes':
                    count = int(row.get('HIBP Breach Count', 0))
                    if count >= 100000:
                        breach_levels['Extreme (100K+)'] += 1
                    elif count >= 10000:
                        breach_levels['Very High (10K-99K)'] += 1
                    elif count >= 1000:
                        breach_levels['High (1K-9.9K)'] += 1
                    elif count >= 100:
                        breach_levels['Medium (100-999)'] += 1
                    elif count >= 10:
                        breach_levels['Low (10-99)'] += 1
                    else:
                        breach_levels['Minimal (1-9)'] += 1

            markdown += "### Breach Severity Distribution\n\n"
            for level, count in breach_levels.items():
                if count > 0:
                    percentage = (count/hibp_breached*100)
                    markdown += f"- **{level}**: {count} accounts ({percentage:.1f}%)\n"
            markdown += "\n"

        # Add risk score explanation section
        markdown += get_risk_score_explanation()
        markdown += get_risk_vector_explanation()

        # Add domain risk section with combined risk distribution
        try:
            domain_risk = data.get('domain_risk', {})
            if domain_risk:
                markdown += "## Risk Distribution\n\n"
                markdown += f"Risk levels of the {cracked} cracked passwords in {domain}, assessed by length, complexity, and privilege.\n\n"
                markdown += f"- **Overall Domain Risk Score:** {domain_risk.get('risk_score', 'N/A')}/10.0 ({domain_risk.get('overall_risk_level', 'Unknown')})\n"
                markdown += f"- **Average Account Risk Score:** {domain_risk.get('avg_score', 'N/A')}/10.0\n"
                markdown += f"- **Maximum Account Risk Score:** {domain_risk.get('max_score', 'N/A')}/10.0\n"
                markdown += "- **Risk Distribution:**\n"
                
                # Use get_risk_distribution helper to ensure consistency
                risk_distribution = get_risk_distribution(data)
                total_risk_accounts = sum(risk_distribution.values())
                
                markdown += format_risk_distribution(risk_distribution, total_risk_accounts)
        except Exception as e:
            if logger:
                logger.error(f"Error processing risk distribution for domain {domain}: {str(e)}")
            markdown += "## Risk Distribution\n\n*Error processing risk distribution data.*\n\n"

        # Include risk visualization if available
        markdown = add_visualization_to_markdown(visuals, 'risk_levels', 'Risk Levels Chart', markdown)
        
        # BloodHound insights section
        markdown += "## BloodHound Insights\n\n"
        markdown += f"Accounts with pathways to Domain Admin (DA) privileges in {domain}.\n\n"
        
        try:
            cracked_da_accounts = [row for row in data['output_rows'] 
                                  if row['Password Length'] != 'N/A' and 
                                  row.get('DA Domains', 'None') not in ('None', 'Unknown')]
            if cracked_da_accounts:
                cracked_by_password = defaultdict(list)
                for acc in cracked_da_accounts:
                    cracked_by_password[acc['Password']].append(acc)
                markdown += "### Cracked Accounts with DA Pathways\n\n"
                markdown += "Cracked accounts with DA pathways, grouped by password:\n\n"
                
                # Create table data
                table_headers = ['Usernames', 'Password', 'DA Domains', 'Risk Level']
                table_rows = []
                
                for password, accounts in cracked_by_password.items():
                    usernames = ', '.join(acc['Username'] for acc in accounts)
                    da_domains = next(acc['DA Domains'] for acc in accounts)
                    risk_level = next(acc['Risk Level'] for acc in accounts)
                    table_rows.append({
                        'Usernames': usernames,
                        'Password': password,
                        'DA Domains': da_domains,
                        'Risk Level': risk_level
                    })
                
                markdown += get_markdown_table(table_headers, table_rows)
            else:
                markdown += "### Cracked Accounts with DA Pathways\n\nNo cracked accounts with DA pathways found.\n\n"
        except Exception as e:
            if logger:
                logger.error(f"Error processing DA accounts for domain {domain}: {str(e)}")
            markdown += "### Cracked Accounts with DA Pathways\n\n*Error processing DA accounts data.*\n\n"
        
        try:
            uncracked_da_accounts = [row for row in data['output_rows'] 
                                    if row['Password Length'] == 'N/A' and 
                                    row['Shared With'] > 0 and 
                                    row.get('DA Domains', 'None') not in ('None', 'Unknown')]
            if uncracked_da_accounts:
                uncracked_by_hash = defaultdict(list)
                for acc in uncracked_da_accounts:
                    uncracked_by_hash[acc['Password']].append(acc)
                markdown += "### Uncracked Accounts with Shared Hashes and DA Pathways\n\n"
                markdown += "Uncracked accounts with shared hashes and DA pathways, grouped by hash:\n\n"
                
                # Create table data
                table_headers = ['Usernames', 'Password Hash', 'DA Domains', 'Risk Level']
                table_rows = []
                
                for hash_, accounts in uncracked_by_hash.items():
                    usernames = ', '.join(acc['Username'] for acc in accounts)
                    da_domains = next(acc['DA Domains'] for acc in accounts)
                    risk_level = next(acc['Risk Level'] for acc in accounts)
                    table_rows.append({
                        'Usernames': usernames,
                        'Password Hash': hash_,
                        'DA Domains': da_domains,
                        'Risk Level': risk_level
                    })
                
                markdown += get_markdown_table(table_headers, table_rows)
            else:
                markdown += "### Uncracked Accounts with Shared Hashes and DA Pathways\n\nNo uncracked accounts with shared hashes and DA pathways found.\n\n"
        except Exception as e:
            if logger:
                logger.error(f"Error processing uncracked DA accounts for domain {domain}: {str(e)}")
            markdown += "### Uncracked Accounts with Shared Hashes and DA Pathways\n\n*Error processing uncracked DA accounts data.*\n\n"
        
        try:
            # Find accounts sharing passwords with DA accounts
            da_passwords = {row['Password'] for row in data['output_rows'] 
                          if row['Password Length'] != 'N/A' and 
                          row.get('DA Domains', 'None') not in ('None', 'Unknown')}
            shared_with_da = [row for row in data['output_rows'] 
                             if row['Password'] in da_passwords and 
                             row['Password Length'] != 'N/A' and 
                             row.get('DA Domains', 'None') in ('None', 'Unknown')]
            
            if shared_with_da:
                shared_by_password = defaultdict(list)
                for acc in shared_with_da:
                    shared_by_password[acc['Password']].append(acc)
                markdown += "### Accounts Sharing Cracked Passwords with DA Accounts\n\n"
                markdown += "Cracked accounts sharing passwords with DA-privileged accounts, grouped by password:\n\n"
                
                # Create table data
                table_headers = ['Usernames', 'Password', 'Shared With', 'Risk Level']
                table_rows = []
                
                for password, accounts in shared_by_password.items():
                    usernames = ', '.join(acc['Username'] for acc in accounts)
                    shared_with = next(acc['Shared With'] for acc in accounts)
                    risk_level = next(acc['Risk Level'] for acc in accounts)
                    table_rows.append({
                        'Usernames': usernames,
                        'Password': password,
                        'Shared With': shared_with,
                        'Risk Level': risk_level
                    })
                
                markdown += get_markdown_table(table_headers, table_rows)
            else:
                markdown += "### Accounts Sharing Cracked Passwords with DA Accounts\n\nNo accounts share cracked passwords with DA-privileged accounts.\n\n"
        except Exception as e:
            if logger:
                logger.error(f"Error processing accounts sharing passwords with DA accounts for domain {domain}: {str(e)}")
            markdown += "### Accounts Sharing Cracked Passwords with DA Accounts\n\n*Error processing shared passwords data.*\n\n"
        
        # Key Findings section
        try:
            length_stats = get_password_length_stats(data)
            avg_length = length_stats['avg']
            
            risk_counts = get_risk_distribution(data)
            high_risk = risk_counts.get('High', 0) + risk_counts.get('Critical', 0)
            total_risk = sum(risk_counts.values())
            high_risk_percentage = (high_risk / total_risk * 100) if total_risk > 0 else 0
            
            top_issues = sorted(data.get('issues_counter', {}).items(), key=lambda x: x[1], reverse=True)[:3]
            
            markdown += "## Key Findings\n\n"
            markdown += f"- **Average Password Length:** {avg_length:.1f} characters\n"
            markdown += f"- **High/Critical Risk Accounts:** {high_risk} ({high_risk_percentage:.1f}% of cracked)\n"
            
            if top_issues:
                markdown += "- **Top Issues:**\n"
                for issue, count in top_issues:
                    markdown += f"  - {issue}: {count} accounts\n"
            markdown += "\n"
        except Exception as e:
            if logger:
                logger.error(f"Error processing key findings for domain {domain}: {str(e)}")
            markdown += "## Key Findings\n\n*Error processing key findings data.*\n\n"
        
        # Add visualizations using the helper
        markdown += add_standard_visualizations_markdown(visuals, domain)
        
        output_path = markdown_folder / f'{domain}_report.md'
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(markdown)
        
        if logger:
            logger.info(f"Generated Markdown report: {output_path}")
    
    except Exception as e:
        if logger:
            logger.error(f"Error generating markdown report for domain {domain}: {str(e)}")
        else:
            print(f"Error generating markdown report for domain {domain}: {str(e)}")