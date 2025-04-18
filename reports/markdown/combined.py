"""
Combined/cross-domain Markdown report generation module.
"""

import os
import base64
from pathlib import Path
from collections import Counter, defaultdict
from datetime import datetime
from core.config import markdown_folder
from utils.visualization_helper import add_visualization_to_markdown
from reports.markdown.components import (
    get_markdown_header, get_risk_vector_explanation, get_markdown_table
)

def generate_combined_report(combined_rows, global_password_to_users, global_hash_to_users, visuals, logger=None):
    """
    Generate combined Markdown report for cross-domain analysis.
    
    Args:
        combined_rows (list): Combined account rows across domains
        global_password_to_users (dict): Mapping of passwords to users across domains
        global_hash_to_users (dict): Mapping of hashes to users across domains
        visuals (dict): Visualization paths
        logger (Logger, optional): Logger instance
    """
    try:
        os.makedirs(markdown_folder, exist_ok=True)
        
        # Generate header
        markdown = get_markdown_header("Cross-Domain Password Security Report")
        
        try:
            total_shared = len(combined_rows)
            shared_da = sum(1 for row in combined_rows if row.get('DA Domains', 'None') not in ('None', 'Unknown') and row['Shared With'] > 0)
        except Exception as e:
            if logger:
                logger.error(f"Error computing basic metrics for combined report: {str(e)}")
            total_shared = 0
            shared_da = 0
            markdown += "*Error computing basic metrics.*\n\n"
        
        # Executive Summary
        markdown += "## Executive Summary\n\n"
        markdown += f"This report analyzes credential sharing across domains, identifying {total_shared} accounts with shared passwords or hashes. "
        markdown += f"Of particular concern are **{shared_da}** accounts with Domain Admin (DA) privileges that share credentials across domains.\n\n"
        
        # Key Recommendations for cross-domain issues
        markdown += "### Key Recommendations\n\n"
        markdown += "1. **Establish unique password policies** across domains to prevent credential reuse\n"
        markdown += "2. **Implement Multi-Factor Authentication (MFA)** for cross-domain authentication\n"
        markdown += "3. **Monitor privilege escalation paths** that span multiple domains\n"
        markdown += "4. **Reset shared passwords** identified in this report, especially those with DA pathways\n\n"
        
        # Overview section
        markdown += "## Overview\n\n"
        markdown += f"- **Accounts Sharing Credentials Across Domains:** {total_shared}\n"
        markdown += f"- **Shared DA Pathway Accounts:** {shared_da}\n\n"
        
        if total_shared == 0:
            markdown += "No cross-domain sharing detected.\n\n"
            
        # Risk Vector Explanation
        markdown += get_risk_vector_explanation()
        
        # Process password counts
        try:
            # Calculate password sharing across domains
            password_counts = Counter()
            for pw, users in global_password_to_users.items():
                if len(users) > 1:
                    # Extract domains from tuples if possible
                    domains = set()
                    for user in users:
                        if isinstance(user, tuple) and len(user) > 1:
                            domains.add(user[1])
                        elif isinstance(user, str) and '@' in user:
                            domains.add(user.split('@')[1])
                    
                    # Only count if shared across domains
                    if len(domains) > 1:
                        password_counts[pw] = len(users)
            
            top_passwords = password_counts.most_common(5)
            
            markdown += "## Top Shared Passwords\n\n"
            if top_passwords:
                # Create table data
                table_headers = ['Password', 'Total Accounts', 'Instances per Domain']
                table_rows = []
                
                for pw, _ in top_passwords:
                    domain_counts = Counter()
                    for user in global_password_to_users[pw]:
                        domain = None
                        if isinstance(user, tuple) and len(user) > 1:
                            domain = user[1]
                        elif isinstance(user, str) and '@' in user:
                            domain = user.split('@')[1]
                        
                        if domain:
                            domain_counts[domain] += 1
                    
                    instances = ', '.join(f"{d}: {c}" for d, c in domain_counts.items())
                    total = sum(domain_counts.values())
                    
                    table_rows.append({
                        'Password': pw,
                        'Total Accounts': total,
                        'Instances per Domain': instances
                    })
                
                markdown += get_markdown_table(table_headers, table_rows)
            else:
                markdown += "No passwords shared across domains.\n\n"
        except Exception as e:
            if logger:
                logger.error(f"Error processing top shared passwords: {str(e)}")
            markdown += "*Error processing top shared passwords data.*\n\n"
        
        # Process hash counts
        try:
            # Calculate hash sharing across domains
            hash_counts = Counter()
            for h, users in global_hash_to_users.items():
                if len(users) > 1:
                    # Extract domains from tuples if possible
                    domains = set()
                    for user in users:
                        if isinstance(user, tuple) and len(user) > 1:
                            domains.add(user[1])
                        elif isinstance(user, str) and '@' in user:
                            domains.add(user.split('@')[1])
                    
                    # Only count if shared across domains
                    if len(domains) > 1:
                        hash_counts[h] = len(users)
            
            top_hashes = hash_counts.most_common(5)
            
            markdown += "## Top Shared Hashes\n\n"
            if top_hashes:
                # Create table data
                table_headers = ['Hash', 'Total Accounts', 'Instances per Domain']
                table_rows = []
                
                for h, _ in top_hashes:
                    domain_counts = Counter()
                    for user in global_hash_to_users[h]:
                        domain = None
                        if isinstance(user, tuple) and len(user) > 1:
                            domain = user[1]
                        elif isinstance(user, str) and '@' in user:
                            domain = user.split('@')[1]
                        
                        if domain:
                            domain_counts[domain] += 1
                    
                    instances = ', '.join(f"{d}: {c}" for d, c in domain_counts.items())
                    total = sum(domain_counts.values())
                    
                    table_rows.append({
                        'Hash': f"{h[:8]}...",
                        'Total Accounts': total,
                        'Instances per Domain': instances
                    })
                
                markdown += get_markdown_table(table_headers, table_rows)
            else:
                markdown += "No hashes shared across domains.\n\n"
        except Exception as e:
            if logger:
                logger.error(f"Error processing top shared hashes: {str(e)}")
            markdown += "*Error processing top shared hashes data.*\n\n"
        
        # BloodHound insights section
        markdown += "## BloodHound Insights\n\n"
        markdown += "Accounts with DA pathways across domains, risking multi-domain compromise.\n\n"
        
        try:
            cracked_da_accounts = [row for row in combined_rows 
                                 if row['Password'] not in global_hash_to_users and 
                                 row.get('DA Domains', 'None') not in ('None', 'Unknown')]
            
            if cracked_da_accounts:
                cracked_by_password = defaultdict(list)
                for acc in cracked_da_accounts:
                    cracked_by_password[acc['Password']].append(acc)
                    
                markdown += "### Cracked Accounts with DA Pathways\n\n"
                markdown += "Cracked accounts with DA pathways, grouped by password:\n\n"
                
                # Create table data
                table_headers = ['Usernames', 'Password', 'DA Domains', 'Domains Shared', 'Risk Level']
                table_rows = []
                
                for password, accounts in cracked_by_password.items():
                    usernames = ', '.join(acc['Username'] for acc in accounts)
                    da_domains = next(acc['DA Domains'] for acc in accounts)
                    domains_shared = next(acc['Domains Shared'] for acc in accounts)
                    risk_level = next(acc['Risk Level'] for acc in accounts)
                    
                    table_rows.append({
                        'Usernames': usernames,
                        'Password': password,
                        'DA Domains': da_domains,
                        'Domains Shared': domains_shared,
                        'Risk Level': risk_level
                    })
                
                markdown += get_markdown_table(table_headers, table_rows)
            else:
                markdown += "### Cracked Accounts with DA Pathways\n\nNo cracked accounts with DA pathways found.\n\n"
        except Exception as e:
            if logger:
                logger.error(f"Error processing DA accounts for combined report: {str(e)}")
            markdown += "### Cracked Accounts with DA Pathways\n\n*Error processing DA accounts data.*\n\n"
        
        try:
            uncracked_da_accounts = [row for row in combined_rows 
                                  if row['Password'] in global_hash_to_users and 
                                  row['Shared With'] > 0 and 
                                  row.get('DA Domains', 'None') not in ('None', 'Unknown')]
            
            if uncracked_da_accounts:
                uncracked_by_hash = defaultdict(list)
                for acc in uncracked_da_accounts:
                    uncracked_by_hash[acc['Password']].append(acc)
                    
                markdown += "### Uncracked Accounts with Shared Hashes and DA Pathways\n\n"
                markdown += "Uncracked accounts with shared hashes and DA pathways, grouped by hash:\n\n"
                
                # Create table data
                table_headers = ['Usernames', 'Password Hash', 'DA Domains', 'Domains Shared', 'Risk Level', 'Risk Vector']
                table_rows = []
                
                for hash_, accounts in uncracked_by_hash.items():
                    usernames = ', '.join(acc['Username'] for acc in accounts)
                    da_domains = next(acc['DA Domains'] for acc in accounts)
                    domains_shared = next(acc['Domains Shared'] for acc in accounts)
                    risk_level = next(acc['Risk Level'] for acc in accounts)
                    risk_vector = next(acc.get('Risk Vector', 'N/A') for acc in accounts)
                    
                    table_rows.append({
                        'Usernames': usernames,
                        'Password Hash': f"{hash_[:8]}...",
                        'DA Domains': da_domains,
                        'Domains Shared': domains_shared,
                        'Risk Level': risk_level,
                        'Risk Vector': risk_vector
                    })
                
                markdown += get_markdown_table(table_headers, table_rows)
            else:
                markdown += "### Uncracked Accounts with Shared Hashes and DA Pathways\n\nNo uncracked accounts with shared hashes and DA pathways found.\n\n"
        except Exception as e:
            if logger:
                logger.error(f"Error processing uncracked DA accounts for combined report: {str(e)}")
            markdown += "### Uncracked Accounts with Shared Hashes and DA Pathways\n\n*Error processing uncracked accounts data.*\n\n"
        
        try:
            # Find cracked DA passwords
            da_passwords = {row['Password'] for row in combined_rows 
                         if row['Password'] not in global_hash_to_users and 
                         row.get('DA Domains', 'None') not in ('None', 'Unknown')}
            
            # Find accounts sharing passwords with DA accounts
            shared_with_da = [row for row in combined_rows 
                             if row['Password'] in da_passwords and 
                             row['Password'] not in global_hash_to_users and 
                             row.get('DA Domains', 'None') in ('None', 'Unknown')]
            
            if shared_with_da:
                shared_by_password = defaultdict(list)
                for acc in shared_with_da:
                    shared_by_password[acc['Password']].append(acc)
                    
                markdown += "### Accounts Sharing Cracked Passwords with DA Accounts\n\n"
                markdown += "Accounts sharing passwords with DA-privileged accounts, grouped by password:\n\n"
                
                # Create table data
                table_headers = ['Usernames', 'Password', 'Shared With', 'Domains Shared', 'Risk Level', 'Risk Vector']
                table_rows = []
                
                for password, accounts in shared_by_password.items():
                    usernames = ', '.join(acc['Username'] for acc in accounts)
                    shared_with = next(acc['Shared With'] for acc in accounts)
                    domains_shared = next(acc['Domains Shared'] for acc in accounts)
                    risk_level = next(acc['Risk Level'] for acc in accounts)
                    risk_vector = next(acc.get('Risk Vector', 'N/A') for acc in accounts)
                    
                    table_rows.append({
                        'Usernames': usernames,
                        'Password': password,
                        'Shared With': shared_with,
                        'Domains Shared': domains_shared,
                        'Risk Level': risk_level,
                        'Risk Vector': risk_vector
                    })
                
                markdown += get_markdown_table(table_headers, table_rows)
            else:
                markdown += "### Accounts Sharing Cracked Passwords with DA Accounts\n\nNo accounts share cracked passwords with DA-privileged accounts.\n\n"
        except Exception as e:
            if logger:
                logger.error(f"Error processing accounts sharing passwords with DA accounts for combined report: {str(e)}")
            markdown += "### Accounts Sharing Cracked Passwords with DA Accounts\n\n*Error processing shared passwords data.*\n\n"
        
        # Key findings
        try:
            max_shared = max(max(password_counts.values(), default=0), max(hash_counts.values(), default=0))
            markdown += "## Key Findings\n\n"
            markdown += f"- **Total Cross-Domain Sharing Incidents:** {total_shared}\n"
            markdown += f"- **Maximum Accounts Sharing a Credential:** {max_shared}\n"
            markdown += "- **Recommendations:**\n"
            markdown += "  - Enforce unique passwords across domains.\n"
            markdown += "  - Implement MFA for high-risk accounts.\n"
            markdown += "  - Educate users on strong password practices.\n\n"
        except Exception as e:
            if logger:
                logger.error(f"Error processing key findings for combined report: {str(e)}")
            markdown += "## Key Findings\n\n*Error processing key findings data.*\n\n"
        
        # Add visualizations using the helper
        for vis_type, title in [
            ('combined_sharing', 'Cross-Domain Sharing'),
            ('last_password_set', 'Last Password Set'),
            ('expiration_status', 'Expiration Status'),
            ('sharing_heatmap', 'Sharing Heatmap'),
            ('da_exposure', 'DA Exposure'),
            ('shared_network', 'Shared Network')
        ]:
            vis_markdown = add_visualization_to_markdown(visuals, vis_type, title)
            if vis_markdown:
                markdown += vis_markdown
        
        output_path = markdown_folder / 'combined_report.md'
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(markdown)
        
        if logger:
            logger.info(f"Generated combined Markdown report: {output_path}")
            
    except Exception as e:
        if logger:
            logger.error(f"Error generating combined markdown report: {str(e)}")
        else:
            print(f"Error generating combined markdown report: {str(e)}")