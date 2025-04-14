from core.config import reports_folder, markdown_folder
import os
from datetime import datetime
from collections import Counter, defaultdict
import base64
import hashlib


markdown_reports_folder = markdown_folder

def generate_markdown_report(domain, data, visuals):
    os.makedirs(markdown_reports_folder, exist_ok=True)
    markdown = f"# Password Security Report - {domain}\n\n"
    markdown += f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
    
    total_accounts = len(data['output_rows'])
    cracked = sum(1 for row in data['output_rows'] if row['Password Length'] != 'N/A')
    uncracked = total_accounts - cracked
    out_of_compliance = sum(1 for row in data['output_rows'] if row['Days Out of Compliance'] not in ('Unknown', 'N/A') and row['Days Out of Compliance'] > 0)
    non_expiring = sum(1 for row in data['output_rows'] if row['Password Set to Expire'] == 'No')
    
    markdown += "## Overview\n\n"
    markdown += f"- **Total Accounts Analyzed:** {total_accounts}\n"
    markdown += f"- **Cracked Passwords:** {cracked} ({cracked/total_accounts:.1%})\n"
    markdown += f"- **Uncracked Passwords:** {uncracked} ({uncracked/total_accounts:.1%})\n"
    markdown += f"- **Out of Compliance Accounts:** {out_of_compliance} ({out_of_compliance/total_accounts:.1%})\n"
    markdown += f"- **Non-Expiring Passwords:** {non_expiring} ({non_expiring/total_accounts:.1%})\n\n"
    
    cracked_rows = [row for row in data['output_rows'] if row['Password Length'] != 'N/A']
    total_cracked = len(cracked_rows)
    risk_counts = {label: data['risk_counter'].get(label, 0) for label in ['Low', 'Medium', 'High', 'Critical']}
    
    markdown += "## Risk Distribution\n\n"
    markdown += f"Risk levels of cracked accounts in {domain}, assessed by length, complexity, and reuse.\n\n"
    for risk, count in risk_counts.items():
        percentage = count / total_cracked * 100 if total_cracked > 0 else 0
        markdown += f"- **{risk} Risk:** {count} accounts ({percentage:.1f}% of cracked)\n"
    if 'risk_levels' in visuals:
        with open(visuals['risk_levels'], 'rb') as f:
            img_data = base64.b64encode(f.read()).decode('utf-8')
        markdown += f"\n![Risk Levels](data:image/png;base64,{img_data})\n\n"
    
    markdown += "## BloodHound Insights\n\n"
    markdown += f"Accounts with pathways to Domain Admin (DA) privileges in {domain}.\n\n"
    
    cracked_da_accounts = [row for row in data['output_rows'] if row['Password Length'] != 'N/A' and row.get('DA Domains', 'None') not in ('None', 'Unknown')]
    if cracked_da_accounts:
        cracked_by_password = defaultdict(list)
        for acc in cracked_da_accounts:
            cracked_by_password[acc['Password']].append(acc)
        markdown += "### Cracked Accounts with DA Pathways\n\n"
        markdown += "Cracked accounts with DA pathways, grouped by password:\n\n"
        markdown += "| Usernames | Password | DA Domains |\n"
        markdown += "|-----------|----------|------------|\n"
        for password, accounts in cracked_by_password.items():
            usernames = ', '.join(acc['Username'] for acc in accounts)
            da_domains = next(acc['DA Domains'] for acc in accounts)
            markdown += f"| {usernames} | {password} | {da_domains} |\n"
        markdown += "\n"
    else:
        markdown += "### Cracked Accounts with DA Pathways\n\nNo cracked accounts with DA pathways found.\n\n"
    
    uncracked_da_accounts = [row for row in data['output_rows'] if row['Password Length'] == 'N/A' and row['Shared With'] > 0 and row.get('DA Domains', 'None') not in ('None', 'Unknown')]
    if uncracked_da_accounts:
        uncracked_by_hash = defaultdict(list)
        for acc in uncracked_da_accounts:
            uncracked_by_hash[acc['Password']].append(acc)
        markdown += "### Uncracked Accounts with Shared Hashes and DA Pathways\n\n"
        markdown += "Uncracked accounts with shared hashes and DA pathways, grouped by hash:\n\n"
        markdown += "| Usernames | Password Hash | DA Domains |\n"
        markdown += "|-----------|---------------|------------|\n"
        for hash_, accounts in uncracked_by_hash.items():
            usernames = ', '.join(acc['Username'] for acc in accounts)
            da_domains = next(acc['DA Domains'] for acc in accounts)
            markdown += f"| {usernames} | {hash_} | {da_domains} |\n"
        markdown += "\n"
    else:
        markdown += "### Uncracked Accounts with Shared Hashes and DA Pathways\n\nNo uncracked accounts with shared hashes and DA pathways found.\n\n"
    
    da_passwords = {row['Password'] for row in cracked_da_accounts}
    shared_with_da = [row for row in data['output_rows'] if row['Password'] in da_passwords and row['Password Length'] != 'N/A' and row.get('DA Domains', 'None') in ('None', 'Unknown')]
    if shared_with_da:
        shared_by_password = defaultdict(list)
        for acc in shared_with_da:
            shared_by_password[acc['Password']].append(acc)
        markdown += "### Accounts Sharing Cracked Passwords with DA Accounts\n\n"
        markdown += "Cracked accounts sharing passwords with DA-privileged accounts, grouped by password:\n\n"
        markdown += "| Usernames | Password | Shared With |\n"
        markdown += "|-----------|----------|-------------|\n"
        for password, accounts in shared_by_password.items():
            usernames = ', '.join(acc['Username'] for acc in accounts)
            shared_with = next(acc['Shared With'] for acc in accounts)
            markdown += f"| {usernames} | {password} | {shared_with} |\n"
        markdown += "\n"
    else:
        markdown += "### Accounts Sharing Cracked Passwords with DA Accounts\n\nNo accounts share cracked passwords with DA-privileged accounts.\n\n"
    
    avg_length = sum(data['password_lengths']) / len(data['password_lengths']) if data['password_lengths'] else 0
    high_risk = risk_counts['High'] + risk_counts['Critical']
    top_issues = sorted(data['issues_counter'].items(), key=lambda x: x[1], reverse=True)[:3]
    markdown += "## Key Findings\n\n"
    markdown += f"- **Average Password Length:** {avg_length:.1f} characters\n"
    markdown += f"- **High/Critical Risk Accounts:** {high_risk} ({high_risk/total_cracked:.1%} of cracked)\n"
    markdown += "- **Top Issues:**\n"
    for issue, count in top_issues:
        markdown += f"  - {issue}: {count} accounts\n"
    markdown += "\n"
    
    if 'password_issues' in visuals:
        with open(visuals['password_issues'], 'rb') as f:
            img_data = base64.b64encode(f.read()).decode('utf-8')
        markdown += f"![Password Issues](data:image/png;base64,{img_data})\n\n"
    
    if 'length_distribution' in visuals:
        with open(visuals['length_distribution'], 'rb') as f:
            img_data = base64.b64encode(f.read()).decode('utf-8')
        markdown += f"![Length Distribution](data:image/png;base64,{img_data})\n\n"
    
    if 'complexity_distribution' in visuals:
        with open(visuals['complexity_distribution'], 'rb') as f:
            img_data = base64.b64encode(f.read()).decode('utf-8')
        markdown += f"![Complexity Distribution](data:image/png;base64,{img_data})\n\n"
    
    if 'top_banned_words' in visuals:
        with open(visuals['top_banned_words'], 'rb') as f:
            img_data = base64.b64encode(f.read()).decode('utf-8')
        markdown += f"![Top Banned Words](data:image/png;base64,{img_data})\n\n"
    
    if 'last_password_set' in visuals:
        with open(visuals['last_password_set'], 'rb') as f:
            img_data = base64.b64encode(f.read()).decode('utf-8')
        markdown += f"![Last Password Set](data:image/png;base64,{img_data})\n\n"
    
    if 'expiration_status' in visuals:
        with open(visuals['expiration_status'], 'rb') as f:
            img_data = base64.b64encode(f.read()).decode('utf-8')
        markdown += f"![Expiration Status](data:image/png;base64,{img_data})\n\n"
    
    if 'compliance_distribution' in visuals:
        with open(visuals['compliance_distribution'], 'rb') as f:
            img_data = base64.b64encode(f.read()).decode('utf-8')
        markdown += f"![Compliance Distribution](data:image/png;base64,{img_data})\n\n"
    
    if 'da_risk' in visuals:
        with open(visuals['da_risk'], 'rb') as f:
            img_data = base64.b64encode(f.read()).decode('utf-8')
        markdown += f"![DA Pathways by Risk](data:image/png;base64,{img_data})\n\n"
    
    if 'password_age' in visuals:
        with open(visuals['password_age'], 'rb') as f:
            img_data = base64.b64encode(f.read()).decode('utf-8')
        markdown += f"![Password Age Distribution](data:image/png;base64,{img_data})\n\n"
    
    output_path = markdown_reports_folder / f'{domain}_report.md'
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(markdown)

def generate_actionable_report(domain, data, seed, logger=None):
    os.makedirs(markdown_reports_folder, exist_ok=True)
    markdown = f"# Actionable Password Security Report - {domain}\n\n"
    markdown += f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
    markdown += "Actionable items for cracked passwords with critical issues.\n\n"
    
    cracked_rows = [row for row in data['output_rows'] if row['Password Length'] != 'N/A']
    risk_order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Unknown": 0}
    
    da_accounts = [row for row in cracked_rows if row.get('DA Domains', 'None') not in ('None', 'Unknown')]
    if da_accounts:
        da_accounts.sort(key=lambda x: (not (x.get('Enabled', 'Unknown') == 'Yes'), -risk_order.get(x['Risk Level'], 0)))
        markdown += "## Riskiest Cracked Accounts with DA Pathway\n\n"
        markdown += "Cracked accounts with DA pathways, posing severe risk. Sorted by enabled status (True first) and risk level.\n\n"
        markdown += "| Username | Password Placeholder | Risk Level | Shared With | Enabled | Last Logon | When Created | Action |\n"
        markdown += "|----------|----------------------|------------|-------------|---------|------------|--------------|--------|\n"
        for acc in da_accounts:
            placeholder = hashlib.md5((seed + acc['Password']).encode()).hexdigest()
            action = "Reset Immediately" if acc.get('Enabled', 'No') == 'Yes' and acc['Risk Level'] in ('High', 'Critical') else "Review and Secure"
            markdown += f"| {acc['Username']} | {placeholder} | {acc['Risk Level']} | {acc.get('Shared With', 'N/A')} | {acc.get('Enabled', 'Unknown')} | {acc.get('Last Logon', 'Unknown')} | {acc.get('When Created', 'Unknown')} | {action} |\n"
        markdown += "\n"
    else:
        markdown += "## Riskiest Cracked Accounts with DA Pathway\n\nNo cracked accounts with DA pathways identified.\n\n"
    
    controllables_accounts = sorted(
        cracked_rows,
        key=lambda x: (
            not (x.get('Enabled', 'Unknown') == 'Yes'),
            -int(x.get('Controlled Object Count', 0) if x.get('Controlled Object Count', 'Unknown') != 'Unknown' else 0)
        )
    )[:100]
    if controllables_accounts:
        markdown += "## Top 100 Accounts by Controllables\n\n"
        markdown += "Cracked accounts controlling the most objects, sorted by enabled status (True first) and controllable count.\n\n"
        markdown += "| Username | Password Placeholder | Risk Level | Shared With | Enabled | Controllables | Last Logon | When Created | Action |\n"
        markdown += "|----------|----------------------|------------|-------------|---------|---------------|------------|--------------|--------|\n"
        for acc in controllables_accounts:
            placeholder = hashlib.md5((seed + acc['Password']).encode()).hexdigest()
            action = "Reset Immediately" if acc.get('Enabled', 'No') == 'Yes' and acc['Risk Level'] in ('High', 'Critical') else "Review and Secure"
            controllables = acc.get('Controlled Object Count', 'Unknown')
            markdown += f"| {acc['Username']} | {placeholder} | {acc['Risk Level']} | {acc.get('Shared With', 'N/A')} | {acc.get('Enabled', 'Unknown')} | {controllables} | {acc.get('Last Logon', 'Unknown')} | {acc.get('When Created', 'Unknown')} | {action} |\n"
        markdown += "\n"
    else:
        markdown += "## Top 100 Accounts by Controllables\n\nNo cracked accounts with controlled objects identified.\n\n"
    
    non_expiring_accounts = [row for row in cracked_rows if row.get('Password Set to Expire', 'Yes') == 'No']
    if non_expiring_accounts:
        non_expiring_accounts.sort(key=lambda x: not (x.get('Enabled', 'Unknown') == 'Yes'))
        markdown += "## Accounts with Non-Expiring Passwords\n\n"
        markdown += "Cracked accounts with non-expiring passwords, sorted by enabled status (True first).\n\n"
        markdown += "| Username | Password Placeholder | Enabled | Last Logon | When Created | Action |\n"
        markdown += "|----------|----------------------|---------|------------|--------------|--------|\n"
        for acc in non_expiring_accounts:
            placeholder = hashlib.md5((seed + acc['Password']).encode()).hexdigest()
            action = "Set to Expire and Reset" if acc.get('Enabled', 'No') == 'Yes' else "Review and Update"
            markdown += f"| {acc['Username']} | {placeholder} | {acc.get('Enabled', 'Unknown')} | {acc.get('Last Logon', 'Unknown')} | {acc.get('When Created', 'Unknown')} | {action} |\n"
        markdown += "\n"
    else:
        markdown += "## Accounts with Non-Expiring Passwords\n\nNo cracked accounts with non-expiring passwords identified.\n\n"
    
    out_of_compliance_accounts = [row for row in cracked_rows if row.get('Days Out of Compliance', 'N/A') not in ('N/A', 'Unknown') and int(row['Days Out of Compliance']) > 0]
    if out_of_compliance_accounts:
        out_of_compliance_accounts.sort(key=lambda x: (
            not (x.get('Enabled', 'Unknown') == 'Yes'),
            int(x['Password Length']),
            -int(x.get('Days Out of Compliance', 0))
        ))
        markdown += "## Out-of-Compliance Accounts\n\n"
        markdown += "Cracked accounts out of compliance, sorted by enabled status (True first), length, and days.\n\n"
        markdown += "| Username | Password Length | Days Out of Compliance | Enabled | Last Logon | When Created | Risk Level | Action |\n"
        markdown += "|----------|-----------------|------------------------|---------|------------|--------------|------------|--------|\n"
        for acc in out_of_compliance_accounts:
            action = "Reset Immediately" if acc['Risk Level'] in ('High', 'Critical') and acc.get('Enabled', 'No') == 'Yes' else "Enforce Compliance"
            markdown += f"| {acc['Username']} | {acc['Password Length']} | {acc.get('Days Out of Compliance', 'N/A')} | {acc.get('Enabled', 'Unknown')} | {acc.get('Last Logon', 'Unknown')} | {acc.get('When Created', 'Unknown')} | {acc['Risk Level']} | {action} |\n"
        markdown += "\n"
    else:
        markdown += "## Out-of-Compliance Accounts\n\nNo cracked accounts out of compliance identified.\n\n"
    
    if not any([da_accounts, controllables_accounts, non_expiring_accounts, out_of_compliance_accounts]):
        markdown += "**No actionable items identified for this domain.**\n"
    
    output_path = markdown_reports_folder / f'{domain}_actionable_report.md'
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(markdown)
    if logger:
        logger.info(f"Generated actionable report: {output_path}")

def generate_combined_report(combined_rows, global_password_to_users, global_hash_to_users, visuals):
    os.makedirs(markdown_reports_folder, exist_ok=True)
    markdown = f"# Cross-Domain Password Security Report\n\n"
    markdown += f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
    
    total_shared = len(combined_rows)
    shared_da = sum(1 for row in combined_rows if row.get('DA Domains', 'None') not in ('None', 'Unknown') and row['Shared With'] > 0)
    markdown += "## Overview\n\n"
    markdown += f"- **Accounts Sharing Credentials Across Domains:** {total_shared}\n"
    markdown += f"- **Shared DA Pathway Accounts:** {shared_da}\n\n"
    if total_shared == 0:
        markdown += "No cross-domain sharing detected.\n\n"
    
    # Updated to handle usernames as strings
    password_counts = Counter({pw: len(users) for pw, users in global_password_to_users.items() if len(set(u.split('@')[1] if '@' in u else u for u in users)) > 1})
    top_passwords = password_counts.most_common(5)
    markdown += "## Top Shared Passwords\n\n"
    if top_passwords:
        markdown += "| Password | Total Accounts | Instances per Domain |\n"
        markdown += "|----------|----------------|----------------------|\n"
        for pw, _ in top_passwords:
            domain_counts = Counter(u.split('@')[1] if '@' in u else u for u in global_password_to_users[pw])
            instances = ', '.join(f"{d}: {c}" for d, c in domain_counts.items())
            total = sum(domain_counts.values())
            markdown += f"| {pw} | {total} | {instances} |\n"
        markdown += "\n"
    else:
        markdown += "No passwords shared across domains.\n\n"
    
    hash_counts = Counter({h: len(users) for h, users in global_hash_to_users.items() if len(set(u.split('@')[1] if '@' in u else u for u in users)) > 1})
    top_hashes = hash_counts.most_common(5)
    markdown += "## Top Shared Hashes\n\n"
    if top_hashes:
        markdown += "| Hash | Total Accounts | Instances per Domain |\n"
        markdown += "|------|----------------|----------------------|\n"
        for h, _ in top_hashes:
            domain_counts = Counter(u.split('@')[1] if '@' in u else u for u in global_hash_to_users[h])
            instances = ', '.join(f"{d}: {c}" for d, c in domain_counts.items())
            total = sum(domain_counts.values())
            markdown += f"| {h[:8]}... | {total} | {instances} |\n"
        markdown += "\n"
    else:
        markdown += "No hashes shared across domains.\n\n"
    
    markdown += "## BloodHound Insights\n\n"
    markdown += "Accounts with DA pathways across domains, risking multi-domain compromise.\n\n"
    
    cracked_da_accounts = [row for row in combined_rows if row['Password'] not in global_hash_to_users and row.get('DA Domains', 'None') not in ('None', 'Unknown')]
    if cracked_da_accounts:
        cracked_by_password = defaultdict(list)
        for acc in cracked_da_accounts:
            cracked_by_password[acc['Password']].append(acc)
        markdown += "### Cracked Accounts with DA Pathways\n\n"
        markdown += "Cracked accounts with DA pathways, grouped by password:\n\n"
        markdown += "| Usernames | Password | DA Domains | Domains Shared |\n"
        markdown += "|-----------|----------|------------|----------------|\n"
        for password, accounts in cracked_by_password.items():
            usernames = ', '.join(acc['Username'] for acc in accounts)
            da_domains = next(acc['DA Domains'] for acc in accounts)
            domains_shared = next(acc['Domains Shared'] for acc in accounts)
            markdown += f"| {usernames} | {password} | {da_domains} | {domains_shared} |\n"
        markdown += "\n"
    else:
        markdown += "### Cracked Accounts with DA Pathways\n\nNo cracked accounts with DA pathways found.\n\n"
    
    uncracked_da_accounts = [row for row in combined_rows if row['Password'] in global_hash_to_users and row['Shared With'] > 0 and row.get('DA Domains', 'None') not in ('None', 'Unknown')]
    if uncracked_da_accounts:
        uncracked_by_hash = defaultdict(list)
        for acc in uncracked_da_accounts:
            uncracked_by_hash[acc['Password']].append(acc)
        markdown += "### Uncracked Accounts with Shared Hashes and DA Pathways\n\n"
        markdown += "Uncracked accounts with shared hashes and DA pathways, grouped by hash:\n\n"
        markdown += "| Usernames | Password Hash | DA Domains | Domains Shared |\n"
        markdown += "|-----------|---------------|------------|----------------|\n"
        for hash_, accounts in uncracked_by_hash.items():
            usernames = ', '.join(acc['Username'] for acc in accounts)
            da_domains = next(acc['DA Domains'] for acc in accounts)
            domains_shared = next(acc['Domains Shared'] for acc in accounts)
            markdown += f"| {usernames} | {hash_[:8]}... | {da_domains} | {domains_shared} |\n"
        markdown += "\n"
    else:
        markdown += "### Uncracked Accounts with Shared Hashes and DA Pathways\n\nNo uncracked accounts with shared hashes and DA pathways found.\n\n"
    
    da_passwords = {row['Password'] for row in cracked_da_accounts}
    shared_with_da = [row for row in combined_rows if row['Password'] in da_passwords and row['Password'] not in global_hash_to_users and row.get('DA Domains', 'None') in ('None', 'Unknown')]
    if shared_with_da:
        shared_by_password = defaultdict(list)
        for acc in shared_with_da:
            shared_by_password[acc['Password']].append(acc)
        markdown += "### Accounts Sharing Cracked Passwords with DA Accounts\n\n"
        markdown += "Accounts sharing passwords with DA-privileged accounts, grouped by password:\n\n"
        markdown += "| Usernames | Password | Shared With | Domains Shared |\n"
        markdown += "|-----------|----------|-------------|----------------|\n"
        for password, accounts in shared_by_password.items():
            usernames = ', '.join(acc['Username'] for acc in accounts)
            shared_with = next(acc['Shared With'] for acc in accounts)
            domains_shared = next(acc['Domains Shared'] for acc in accounts)
            markdown += f"| {usernames} | {password} | {shared_with} | {domains_shared} |\n"
        markdown += "\n"
    else:
        markdown += "### Accounts Sharing Cracked Passwords with DA Accounts\n\nNo accounts share cracked passwords with DA-privileged accounts.\n\n"
    
    max_shared = max(max(password_counts.values(), default=0), max(hash_counts.values(), default=0))
    markdown += "## Key Findings\n\n"
    markdown += f"- **Total Cross-Domain Sharing Incidents:** {total_shared}\n"
    markdown += f"- **Maximum Accounts Sharing a Credential:** {max_shared}\n"
    markdown += "- **Recommendations:**\n"
    markdown += "  - Enforce unique passwords across domains.\n"
    markdown += "  - Implement MFA for high-risk accounts.\n"
    markdown += "  - Educate users on strong password practices.\n\n"
    
    if 'combined_sharing' in visuals:
        with open(visuals['combined_sharing'], 'rb') as f:
            img_data = base64.b64encode(f.read()).decode('utf-8')
        markdown += f"![Cross-Domain Sharing](data:image/png;base64,{img_data})\n\n"
    
    if 'last_password_set' in visuals:
        with open(visuals['last_password_set'], 'rb') as f:
            img_data = base64.b64encode(f.read()).decode('utf-8')
        markdown += f"![Last Password Set](data:image/png;base64,{img_data})\n\n"
    
    if 'expiration_status' in visuals:
        with open(visuals['expiration_status'], 'rb') as f:
            img_data = base64.b64encode(f.read()).decode('utf-8')
        markdown += f"![Expiration Status](data:image/png;base64,{img_data})\n\n"
    
    if 'sharing_heatmap' in visuals:
        with open(visuals['sharing_heatmap'], 'rb') as f:
            img_data = base64.b64encode(f.read()).decode('utf-8')
        markdown += f"![Sharing Heatmap](data:image/png;base64,{img_data})\n\n"
    
    if 'da_exposure' in visuals:
        with open(visuals['da_exposure'], 'rb') as f:
            img_data = base64.b64encode(f.read()).decode('utf-8')
        markdown += f"![DA Exposure](data:image/png;base64,{img_data})\n\n"
    
    if 'shared_network' in visuals:
        with open(visuals['shared_network'], 'rb') as f:
            img_data = base64.b64encode(f.read()).decode('utf-8')
        markdown += f"![Shared Network](data:image/png;base64,{img_data})\n\n"
    
    output_path = markdown_reports_folder / 'combined_report.md'
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(markdown)


def generate_explained_actionable_report(domain, data, seed, logger=None):
    os.makedirs(markdown_reports_folder, exist_ok=True)
    markdown = f"# Explained Actionable Password Security Report - {domain}\n\n"
    markdown += f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
    markdown += f"This report explains the sections of the actionable Excel report (`{domain}_actionable_report.xlsx`) and provides guidance on remediation. Each section identifies critical password security issues, why they matter, and what actions are expected to mitigate risks.\n\n"

    # Define cracked_rows and risk_order
    cracked_rows = [row for row in data['output_rows'] if row['Password Length'] != 'N/A']
    risk_order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Unknown": 0}

    # Calculate counts for each section
    da_accounts = [row for row in cracked_rows if row.get('DA Domains', 'None') not in ('None', 'Unknown')]
    da_count = len(da_accounts)
    controllables_accounts = sorted(
        cracked_rows,
        key=lambda x: (
            not (x.get('Enabled', 'Unknown') == 'Yes'),
            -int(x.get('Controlled Object Count', 0) if x.get('Controlled Object Count', 'Unknown') != 'Unknown' else 0)
        )
    )[:100]
    controllables_count = len(controllables_accounts)
    non_expiring_accounts = [row for row in cracked_rows if row.get('Password Set to Expire', 'Yes') == 'No']
    non_expiring_count = len(non_expiring_accounts)
    out_of_compliance_accounts = [row for row in cracked_rows if row.get('Days Out of Compliance', 'N/A') not in ('N/A', 'Unknown') and int(row['Days Out of Compliance']) > 0]
    out_of_compliance_count = len(out_of_compliance_accounts)

    # DA Pathways Section
    markdown += "## Riskiest Cracked Accounts with DA Pathway\n\n"
    markdown += f"**Count in this Domain**: {da_count} accounts\n\n"
    markdown += "### Explanation\n"
    markdown += "This section lists accounts with cracked passwords that have pathways to Domain Admin (DA) privileges, identified via BloodHound analysis. These accounts are critical because they can be exploited to gain full control over the domain.\n\n"
    markdown += "### Why It’s Important\n"
    markdown += f"Compromised accounts with DA pathways enable attackers to escalate privileges rapidly. According to the 2023 Verizon Data Breach Investigations Report (DBIR), 86% of breaches involved misuse of privileged credentials. With {da_count} such accounts in {domain}, immediate action is critical to prevent a domain-wide compromise.\n\n"
    markdown += "### Expected Actions\n"
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

    # Top Controllables Section
    markdown += "## Top 100 Accounts by Controllables\n\n"
    markdown += f"**Count in this Domain**: {controllables_count} accounts (top 100 shown)\n\n"
    markdown += "### Explanation\n"
    markdown += "This section identifies the top 100 cracked accounts controlling the most objects (e.g., users, groups, computers) in the domain. High controllables increase the impact of a compromise.\n\n"
    markdown += "### Why It’s Important\n"
    markdown += f"Accounts with many controllables can manipulate multiple resources, amplifying damage. NIST SP 800-53 highlights that excessive privileges contribute to 80% of insider threat incidents. With {controllables_count} high-control accounts in {domain}, securing them reduces systemic risk.\n\n"
    markdown += "### Expected Actions\n"
    markdown += "- **Reset Passwords Immediately**: For enabled accounts with High/Critical risk:\n"
    markdown += "  1. Follow the ADUC password reset steps above.\n"
    markdown += "  2. Use a unique, complex password.\n"
    markdown += "- **Review and Secure**: For other accounts:\n"
    markdown += "  1. Assess if the account needs such extensive control.\n"
    markdown += "  2. Reduce permissions via ADUC or PowerShell (e.g., `Remove-ADGroupMember`).\n"
    markdown += "  3. Reset passwords if still active.\n"
    markdown += "- **Monitor Usage**: Implement logging to detect abuse of these accounts.\n\n"

    # Non-Expiring Passwords Section
    markdown += "## Accounts with Non-Expiring Passwords\n\n"
    markdown += f"**Count in this Domain**: {non_expiring_count} accounts\n\n"
    markdown += "### Explanation\n"
    markdown += "This section lists cracked accounts with passwords set to never expire, bypassing standard rotation policies.\n\n"
    markdown += "### Why It’s Important\n"
    markdown += f"Non-expiring passwords increase exposure over time. The 2022 Ponemon Institute report found that 60% of breaches involved credentials unchanged for over a year. With {non_expiring_count} accounts in {domain}, these are prime targets for persistence attacks.\n\n"
    markdown += "### Expected Actions\n"
    markdown += "- **Set to Expire and Reset**: For enabled accounts:\n"
    markdown += "  1. In ADUC, locate the user.\n"
    markdown += "  2. Reset the password (as above).\n"
    markdown += "  3. Uncheck 'Password never expires' in Account properties.\n"
    markdown += "  4. Set a policy-compliant expiration (e.g., 90 days).\n"
    markdown += "- **Review and Update**: For disabled/unused accounts:\n"
    markdown += "  1. Confirm necessity.\n"
    markdown += "  2. Disable or delete if obsolete.\n"
    markdown += "- **Enforce Policy**: Update domain policy to prevent future non-expiring settings (e.g., via Group Policy).\n\n"

    # Out-of-Compliance Accounts Section
    markdown += "## Out-of-Compliance Accounts\n\n"
    markdown += f"**Count in this Domain**: {out_of_compliance_count} accounts\n\n"
    markdown += "### Explanation\n"
    markdown += "This section highlights cracked accounts with passwords exceeding the maximum age (e.g., >90 days), violating compliance policies.\n\n"
    markdown += "### Why It’s Important\n"
    markdown += f"Stale passwords are more likely to be compromised. IBM’s 2023 Cost of a Data Breach report notes that outdated credentials contribute to 19% of breaches, with an average cost of $4.37M. With {out_of_compliance_count} non-compliant accounts in {domain}, updating them reduces breach risk.\n\n"
    markdown += "### Expected Actions\n"
    markdown += "- **Reset Immediately**: For High/Critical risk enabled accounts:\n"
    markdown += "  1. Reset passwords via ADUC (as above).\n"
    markdown += "  2. Enforce immediate user change.\n"
    markdown += "- **Enforce Compliance**: For other accounts:\n"
    markdown += "  1. Reset passwords.\n"
    markdown += "  2. Verify last set date aligns with policy (e.g., <90 days).\n"
    markdown += "- **Automate Rotation**: Implement password expiration policies via Group Policy (e.g., `Set-ADDefaultDomainPasswordPolicy -MaxPasswordAge 90`).\n\n"

    output_path = markdown_reports_folder / f'{domain}_explained_actionable_report.md'
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(markdown)
    if logger:
        logger.info(f"Generated explained actionable report: {output_path}")
