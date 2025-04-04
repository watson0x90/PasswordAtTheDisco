from core.config import reports_folder
from collections import defaultdict, Counter
import hashlib
import os

html_reports_folder = reports_folder / 'html_report'

BASE_CSS = """
body { font-family: Arial, Helvetica, sans-serif; margin: 20px; color: #000000; }
h1 { font-size: 24px; font-weight: bold; color: #000000; margin-bottom: 20px; }
h2 { font-size: 20px; font-weight: bold; color: #000000; margin-top: 20px; margin-bottom: 10px; }
h3 { font-size: 16px; font-weight: bold; color: #000000; margin-top: 15px; margin-bottom: 10px; }
p { margin: 10px 0; }
table { border-collapse: collapse; width: 100%; margin: 20px 0; }
th, td { border: 1px solid #000000; padding: 8px; text-align: left; }
th { background-color: #f2f2f2; font-weight: bold; cursor: pointer; }
th:hover { background-color: #e0e0e0; }
ul { list-style-type: disc; margin: 10px 0 10px 20px; }
li { margin: 5px 0; }
a { color: #0066cc; text-decoration: none; }
a:hover { text-decoration: underline; }
input[type="text"] { padding: 8px; width: 300px; margin-bottom: 20px; }
"""

IFRAME_CSS = """
iframe { width: 100%; height: 500px; border: none; margin: 20px 0; }
"""

TABLE_SORT_JS = """
<script>
function sortTable(table, colIndex, ascending) {
    const tbody = table.querySelector('tbody');
    const rows = Array.from(tbody.querySelectorAll('tr'));
    rows.sort((a, b) => {
        const aValue = a.cells[colIndex].textContent.trim();
        const bValue = b.cells[colIndex].textContent.trim();
        const aNum = parseFloat(aValue);
        const bNum = parseFloat(bValue);
        if (!isNaN(aNum) && !isNaN(bNum)) {
            return ascending ? aNum - bNum : bNum - aNum;
        }
        return ascending ? aValue.localeCompare(bValue) : bValue.localeCompare(aValue);
    });
    rows.forEach(row => tbody.appendChild(row));
}

document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('table').forEach(table => {
        const headers = table.querySelectorAll('th');
        headers.forEach((th, index) => {
            let ascending = true;
            th.addEventListener('click', () => {
                sortTable(table, index, ascending);
                ascending = !ascending;
                headers.forEach(h => h.classList.remove('sorted-asc', 'sorted-desc'));
                th.classList.add(ascending ? 'sorted-desc' : 'sorted-asc');
            });
        });
    });
});
</script>
"""

SEARCH_JS = """
<script src="https://cdn.jsdelivr.net/npm/choices.js/public/assets/scripts/choices.min.js"></script>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/choices.js/public/assets/styles/choices.min.css" />
<script>
document.addEventListener('DOMContentLoaded', () => {
    const searchInput = document.getElementById('searchInput');
    const resultsTable = document.getElementById('resultsTable');
    const tbody = resultsTable.querySelector('tbody');
    let allAccounts = [];
    let filters = {};

    fetch('/password_data.json')
        .then(response => {
            if (!response.ok) throw new Error('Failed to load password_data.json');
            return response.json();
        })
        .then(data => {
            allAccounts = [
                ...data.combined.all_cracked.map(acc => ({ ...acc, Type: 'Cracked' })),
                ...data.combined.all_uncracked.map(acc => ({ ...acc, Type: 'Uncracked' }))
            ];
            initializeFilters();
            updateTable();
        })
        .catch(error => console.error('Error loading JSON:', error));

    searchInput.addEventListener('input', () => updateTable());

    function initializeFilters() {
        const headers = ['username', 'Domain', 'password', 'Type', 'Risk Level', 'Enabled', 'Last Logon Timestamp', 'Password Set to Expire', 'Controlled Object Count', 'DA Domains', 'Shared With', 'Last Password Set', 'Days Out of Compliance'];
        headers.forEach(header => {
            const selectId = `filter-${header.replace(/[^a-zA-Z0-9]/g, '')}`;
            const th = document.querySelector(`th[data-column="${header}"]`);
            th.innerHTML += `<select multiple id="${selectId}" class="filter-select"></select>`;
            
            const uniqueValues = [...new Set(allAccounts.map(acc => acc[header] || (header === 'DA Domains' ? (acc[header] ? 'Yes' : 'No') : 'N/A')))].sort();
            const choicesOptions = uniqueValues.map(value => ({ value: value, label: value }));
            
            const select = document.getElementById(selectId);
            new Choices(select, {
                removeItemButton: true,
                choices: choicesOptions,
                placeholderValue: 'Filter ' + header,
                maxItemCount: -1
            });
            
            select.addEventListener('change', () => {
                filters[header] = Array.from(select.selectedOptions).map(opt => opt.value);
                updateTable();
            });
        });
    }

    function updateTable() {
        const searchTerm = searchInput.value.trim().toLowerCase();
        tbody.innerHTML = '';
        
        const filtered = allAccounts.filter(acc => {
            const matchesSearch = (acc.username || '').toLowerCase().includes(searchTerm);
            const matchesFilters = Object.keys(filters).every(header => {
                if (!filters[header] || filters[header].length === 0) return true;
                const value = header === 'DA Domains' ? (acc[header] ? 'Yes' : 'No') : (acc[header] || 'N/A');
                return filters[header].includes(value);
            });
            return matchesSearch && matchesFilters;
        });
        
        filtered.forEach(acc => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${acc.username || 'N/A'}</td>
                <td>${acc.Domain || 'N/A'}</td>
                <td>${acc.password || 'N/A'}</td>
                <td>${acc.Type || 'N/A'}</td>
                <td>${acc['Risk Level'] || 'N/A'}</td>
                <td>${acc['Enabled'] || 'Unknown'}</td>
                <td>${acc['Last Logon Timestamp'] || 'Unknown'}</td>
                <td>${acc['Password Set to Expire'] || 'Unknown'}</td>
                <td>${acc['Controlled Object Count'] || 'N/A'}</td>
                <td>${acc['DA Domains'] ? 'Yes' : 'No'}</td>
                <td>${acc['Shared With'] || '0'}</td>
                <td>${acc['Last Password Set'] || 'Unknown'}</td>
                <td>${acc['Days Out of Compliance'] || 'N/A'}</td>
            `;
            tbody.appendChild(row);
        });
    }
});
</script>
"""

# JavaScript for redacted search functionality
SEARCH_REDACTED_JS = """
<script src="https://cdn.jsdelivr.net/npm/choices.js/public/assets/scripts/choices.min.js"></script>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/choices.js/public/assets/styles/choices.min.css" />
<script>
document.addEventListener('DOMContentLoaded', () => {
    const searchInput = document.getElementById('searchInput');
    const resultsTable = document.getElementById('resultsTable');
    const tbody = resultsTable.querySelector('tbody');
    let allAccounts = [];
    let filters = {};

    fetch('/password_data_with_placeholders.json')
        .then(response => {
            if (!response.ok) throw new Error('Failed to load password_data_with_placeholders.json');
            return response.json();
        })
        .then(data => {
            allAccounts = [
                ...data.combined.all_cracked.map(acc => ({ ...acc, Type: 'Cracked' })),
                ...data.combined.all_uncracked.map(acc => ({ ...acc, Type: 'Uncracked' }))
            ];
            initializeFilters();
            updateTable();
        })
        .catch(error => console.error('Error loading JSON:', error));

    searchInput.addEventListener('input', () => updateTable());

    function initializeFilters() {
        const headers = ['username', 'Domain', 'password', 'Type', 'Risk Level', 'Enabled', 'Last Logon Timestamp', 'Password Set to Expire', 'Controlled Object Count', 'DA Domains', 'Shared With', 'Last Password Set', 'Days Out of Compliance'];
        headers.forEach(header => {
            const selectId = `filter-${header.replace(/[^a-zA-Z0-9]/g, '')}`;
            const th = document.querySelector(`th[data-column="${header}"]`);
            th.innerHTML += `<select multiple id="${selectId}" class="filter-select"></select>`;
            
            const uniqueValues = [...new Set(allAccounts.map(acc => acc[header] || (header === 'DA Domains' ? (acc[header] ? 'Yes' : 'No') : 'N/A')))].sort();
            const choicesOptions = uniqueValues.map(value => ({ value: value, label: value }));
            
            const select = document.getElementById(selectId);
            new Choices(select, {
                removeItemButton: true,
                choices: choicesOptions,
                placeholderValue: 'Filter ' + header,
                maxItemCount: -1
            });
            
            select.addEventListener('change', () => {
                filters[header] = Array.from(select.selectedOptions).map(opt => opt.value);
                updateTable();
            });
        });
    }

    function updateTable() {
        const searchTerm = searchInput.value.trim().toLowerCase();
        tbody.innerHTML = '';
        
        const filtered = allAccounts.filter(acc => {
            const matchesSearch = (acc.username || '').toLowerCase().includes(searchTerm);
            const matchesFilters = Object.keys(filters).every(header => {
                if (!filters[header] || filters[header].length === 0) return true;
                const value = header === 'DA Domains' ? (acc[header] ? 'Yes' : 'No') : (acc[header] || 'N/A');
                return filters[header].includes(value);
            });
            return matchesSearch && matchesFilters;
        });
        
        filtered.forEach(acc => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${acc.username || 'N/A'}</td>
                <td>${acc.Domain || 'N/A'}</td>
                <td>${acc.password || 'N/A'}</td>
                <td>${acc.Type || 'N/A'}</td>
                <td>${acc['Risk Level'] || 'N/A'}</td>
                <td>${acc['Enabled'] || 'Unknown'}</td>
                <td>${acc['Last Logon Timestamp'] || 'Unknown'}</td>
                <td>${acc['Password Set to Expire'] || 'Unknown'}</td>
                <td>${acc['Controlled Object Count'] || 'N/A'}</td>
                <td>${acc['DA Domains'] ? 'Yes' : 'No'}</td>
                <td>${acc['Shared With'] || '0'}</td>
                <td>${acc['Last Password Set'] || 'Unknown'}</td>
                <td>${acc['Days Out of Compliance'] || 'N/A'}</td>
            `;
            tbody.appendChild(row);
        });
    }
});
</script>
"""

def generate_html_report(domain, data, visuals, logger=None):
    os.makedirs(html_reports_folder, exist_ok=True)
    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
    <title>Password Security Report - {domain}</title>
    <style>
    {BASE_CSS}
    {IFRAME_CSS}
    .sorted-asc::after {{ content: " ↑"; }}
    .sorted-desc::after {{ content: " ↓"; }}
    </style>
</head>
<body>
    <h1>Password Security Report for {domain}</h1>
    <p><a href="./main.html">Back to Main</a> | <a href="./search.html">Search Accounts</a></p>
"""
    total_accounts = len(data['output_rows'])
    cracked = sum(1 for row in data['output_rows'] if row['Password Length'] != 'N/A')
    uncracked = total_accounts - cracked
    out_of_compliance = sum(1 for row in data['output_rows'] if row['Days Out of Compliance'] not in ('Unknown', 'N/A') and row['Days Out of Compliance'] > 0)
    non_expiring = sum(1 for row in data['output_rows'] if row['Password Set to Expire'] == 'No')
    html += f"""
    <h2>Overview</h2>
    <ul>
        <li><strong>Total Accounts Analyzed:</strong> {total_accounts}</li>
        <li><strong>Cracked Passwords:</strong> {cracked} ({cracked/total_accounts:.1%})</li>
        <li><strong>Uncracked Passwords:</strong> {uncracked} ({uncracked/total_accounts:.1%})</li>
        <li><strong>Out of Compliance Accounts:</strong> {out_of_compliance} ({out_of_compliance/total_accounts:.1%})</li>
        <li><strong>Non-Expiring Passwords:</strong> {non_expiring} ({non_expiring/total_accounts:.1%})</li>
    </ul>
"""

    cracked_rows = [row for row in data['output_rows'] if row['Password Length'] != 'N/A']
    total_cracked = len(cracked_rows)
    risk_counts = {label: data['risk_counter'].get(label, 0) for label in ['Low', 'Medium', 'High', 'Critical']}
    html += f"""
    <h2>Risk Distribution</h2>
    <p>Risk levels of cracked accounts in {domain}, assessed by length, complexity, and reuse.</p>
    <ul>
"""
    for risk, count in risk_counts.items():
        percentage = count / total_cracked * 100 if total_cracked > 0 else 0
        html += f"            <li><strong>{risk} Risk:</strong> {count} accounts ({percentage:.1f}% of cracked)</li>\n"
    html += "        </ul>\n"
    if 'risk_levels' in visuals:
        html += f"""
    <p><strong>Risk Levels Chart:</strong> Green (Low), Yellow (Medium), Orange (High), Red (Critical).</p>
    <iframe src="./{os.path.basename(visuals['risk_levels'])}" width="100%" height="500" frameborder="0"></iframe>
"""

    html += f"""
    <h2>BloodHound Insights</h2>
    <p>Accounts with pathways to Domain Admin (DA) privileges in {domain}.</p>
"""

    cracked_da_accounts = [row for row in data['output_rows'] if row['Password Length'] != 'N/A' and row.get('DA Domains', 'None') not in ('None', 'Unknown')]
    if cracked_da_accounts:
        cracked_by_password = defaultdict(list)
        for acc in cracked_da_accounts:
            cracked_by_password[acc['Password']].append(acc)
        html += """
    <h3>Cracked Accounts with DA Pathways</h3>
    <p>Cracked accounts with DA pathways, grouped by password:</p>
    <table>
        <thead>
            <tr><th>Usernames</th><th>Password</th><th>DA Domains</th></tr>
        </thead>
        <tbody>
"""
        for password, accounts in cracked_by_password.items():
            usernames = ', '.join(acc['Username'] for acc in accounts)
            da_domains = next(acc['DA Domains'] for acc in accounts)
            html += f"                <tr><td>{usernames}</td><td>{password}</td><td>{da_domains}</td></tr>\n"
        html += "            </tbody>\n        </table>\n"
    else:
        html += """
    <h3>Cracked Accounts with DA Pathways</h3>
    <p>No cracked accounts with DA pathways found.</p>
"""

    uncracked_da_accounts = [row for row in data['output_rows'] if row['Password Length'] == 'N/A' and row['Shared With'] > 0 and row.get('DA Domains', 'None') not in ('None', 'Unknown')]
    if uncracked_da_accounts:
        uncracked_by_hash = defaultdict(list)
        for acc in uncracked_da_accounts:
            uncracked_by_hash[acc['Password']].append(acc)
        html += """
    <h3>Uncracked Accounts with Shared Hashes and DA Pathways</h3>
    <p>Uncracked accounts with shared hashes and DA pathways, grouped by hash:</p>
    <table>
        <thead>
            <tr><th>Usernames</th><th>Password Hash</th><th>DA Domains</th></tr>
        </thead>
        <tbody>
"""
        for hash_, accounts in uncracked_by_hash.items():
            usernames = ', '.join(acc['Username'] for acc in accounts)
            da_domains = next(acc['DA Domains'] for acc in accounts)
            html += f"                <tr><td>{usernames}</td><td>{hash_}</td><td>{da_domains}</td></tr>\n"
        html += "            </tbody>\n        </table>\n"
    else:
        html += """
    <h3>Uncracked Accounts with Shared Hashes and DA Pathways</h3>
    <p>No uncracked accounts with shared hashes and DA pathways found.</p>
"""

    da_passwords = {row['Password'] for row in cracked_da_accounts}
    shared_with_da = [row for row in data['output_rows'] if row['Password'] in da_passwords and row['Password Length'] != 'N/A' and row.get('DA Domains', 'None') in ('None', 'Unknown')]
    if shared_with_da:
        shared_by_password = defaultdict(list)
        for acc in shared_with_da:
            shared_by_password[acc['Password']].append(acc)
        html += """
    <h3>Accounts Sharing Cracked Passwords with DA Accounts</h3>
    <p>Cracked accounts sharing passwords with DA-privileged accounts, grouped by password:</p>
    <table>
        <thead>
            <tr><th>Usernames</th><th>Password</th><th>Shared With</th></tr>
        </thead>
        <tbody>
"""
        for password, accounts in shared_by_password.items():
            usernames = ', '.join(acc['Username'] for acc in accounts)
            shared_with = next(acc['Shared With'] for acc in accounts)
            html += f"                <tr><td>{usernames}</td><td>{password}</td><td>{shared_with}</td></tr>\n"
        html += "            </tbody>\n        </table>\n"
    else:
        html += """
    <h3>Accounts Sharing Cracked Passwords with DA Accounts</h3>
    <p>No accounts share cracked passwords with DA-privileged accounts.</p>
"""

    avg_length = sum(data['password_lengths']) / len(data['password_lengths']) if data['password_lengths'] else 0
    high_risk = risk_counts['High'] + risk_counts['Critical']
    top_issues = sorted(data['issues_counter'].items(), key=lambda x: x[1], reverse=True)[:3]
    html += f"""
    <h2>Key Findings</h2>
    <ul>
        <li><strong>Average Password Length:</strong> {avg_length:.1f} characters</li>
        <li><strong>High/Critical Risk Accounts:</strong> {high_risk} ({high_risk/total_cracked:.1%} of cracked)</li>
        <li><strong>Top Issues:</strong>
            <ul>
"""
    for issue, count in top_issues:
        html += f"                    <li>{issue}: {count} accounts</li>\n"
    html += "                </ul>\n            </li>\n        </ul>\n"

    for vis_type in ['password_issues', 'length_distribution', 'complexity_distribution', 'top_banned_words', 'last_password_set', 'expiration_status', 'compliance_distribution', 'da_risk', 'password_age']:
        if vis_type in visuals:
            title = vis_type.replace('_', ' ').title()
            html += f"""
    <p><strong>{title}:</strong></p>
    <iframe src="./{os.path.basename(visuals[vis_type])}" width="100%" height="500" frameborder="0"></iframe>
"""

    html += f"""
{TABLE_SORT_JS}
</body>
</html>
"""

    output_path = html_reports_folder / f'{domain}_report.html'
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)
    if logger:
        logger.info(f"Generated HTML report: {output_path}")

def generate_html_actionable_report(domain, data, seed, visuals, logger=None):
    os.makedirs(html_reports_folder, exist_ok=True)
    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
    <title>Actionable Password Security Report - {domain}</title>
    <style>
    {BASE_CSS}
    .sorted-asc::after {{ content: " ↑"; }}
    .sorted-desc::after {{ content: " ↓"; }}
    </style>
</head>
<body>
    <h1>Actionable Password Security Report for {domain}</h1>
    <p><a href="./main.html">Back to Main</a> | <a href="./search.html">Search Accounts</a></p>
    <p>Actionable items for cracked passwords with critical issues.</p>
"""
    cracked_rows = [row for row in data['output_rows'] if row['Password Length'] != 'N/A']
    risk_order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Unknown": 0}

    da_accounts = [row for row in cracked_rows if row.get('DA Domains', 'None') not in ('None', 'Unknown')]
    if da_accounts:
        da_accounts.sort(key=lambda x: (not (x.get('Enabled', 'Unknown') == 'Yes'), -risk_order.get(x['Risk Level'], 0)))
        html += """
    <h2>Riskiest Cracked Accounts with DA Pathway</h2>
    <p>Cracked accounts with DA pathways, posing severe risk. Sorted by enabled status (True first) and risk level.</p>
    <table>
        <thead>
            <tr><th>Username</th><th>Password Placeholder</th><th>Risk Level</th><th>Shared With</th><th>Enabled</th><th>Last Logon</th><th>When Created</th><th>Action</th></tr>
        </thead>
        <tbody>
"""
        for acc in da_accounts:
            placeholder = hashlib.md5((seed + acc['Password']).encode()).hexdigest()
            action = "Reset Immediately" if acc.get('Enabled', 'No') == 'Yes' and acc['Risk Level'] in ('High', 'Critical') else "Review and Secure"
            html += f"                <tr><td>{acc['Username']}</td><td>{placeholder}</td><td>{acc['Risk Level']}</td><td>{acc.get('Shared With', 'N/A')}</td><td>{acc.get('Enabled', 'Unknown')}</td><td>{acc.get('Last Logon', 'Unknown')}</td><td>{acc.get('When Created', 'Unknown')}</td><td>{action}</td></tr>\n"
        html += "            </tbody>\n        </table>\n"
    else:
        html += """
    <h2>Riskiest Cracked Accounts with DA Pathway</h2>
    <p>No cracked accounts with DA pathways identified.</p>
"""

    controllables_accounts = sorted(
        cracked_rows,
        key=lambda x: (
            not (x.get('Enabled', 'Unknown') == 'Yes'),
            -int(x.get('Controlled Object Count', 0) if x.get('Controlled Object Count', 'Unknown') != 'Unknown' else 0)
        )
    )[:100]
    if controllables_accounts:
        html += """
    <h2>Top 100 Accounts by Controllables</h2>
    <p>Cracked accounts controlling the most objects, sorted by enabled status (True first) and controllable count.</p>
    <table>
        <thead>
            <tr><th>Username</th><th>Password Placeholder</th><th>Risk Level</th><th>Shared With</th><th>Enabled</th><th>Controllables</th><th>Last Logon</th><th>When Created</th><th>Action</th></tr>
        </thead>
        <tbody>
"""
        for acc in controllables_accounts:
            placeholder = hashlib.md5((seed + acc['Password']).encode()).hexdigest()
            action = "Reset Immediately" if acc.get('Enabled', 'No') == 'Yes' and acc['Risk Level'] in ('High', 'Critical') else "Review and Secure"
            controllables = acc.get('Controlled Object Count', 'Unknown')
            html += f"                <tr><td>{acc['Username']}</td><td>{placeholder}</td><td>{acc['Risk Level']}</td><td>{acc.get('Shared With', 'N/A')}</td><td>{acc.get('Enabled', 'Unknown')}</td><td>{controllables}</td><td>{acc.get('Last Logon', 'Unknown')}</td><td>{acc.get('When Created', 'Unknown')}</td><td>{action}</td></tr>\n"
        html += "            </tbody>\n        </table>\n"
    else:
        html += """
    <h2>Top 100 Accounts by Controllables</h2>
    <p>No cracked accounts with controlled objects identified.</p>
"""

    non_expiring_accounts = [row for row in cracked_rows if row.get('Password Set to Expire', 'Yes') == 'No']
    if non_expiring_accounts:
        non_expiring_accounts.sort(key=lambda x: not (x.get('Enabled', 'Unknown') == 'Yes'))
        html += """
    <h2>Accounts with Non-Expiring Passwords</h2>
    <p>Cracked accounts with non-expiring passwords, sorted by enabled status (True first).</p>
    <table>
        <thead>
            <tr><th>Username</th><th>Password Placeholder</th><th>Enabled</th><th>Last Logon</th><th>When Created</th><th>Action</th></tr>
        </thead>
        <tbody>
"""
        for acc in non_expiring_accounts:
            placeholder = hashlib.md5((seed + acc['Password']).encode()).hexdigest()
            action = "Set to Expire and Reset" if acc.get('Enabled', 'No') == 'Yes' else "Review and Update"
            html += f"                <tr><td>{acc['Username']}</td><td>{placeholder}</td><td>{acc.get('Enabled', 'Unknown')}</td><td>{acc.get('Last Logon', 'Unknown')}</td><td>{acc.get('When Created', 'Unknown')}</td><td>{action}</td></tr>\n"
        html += "            </tbody>\n        </table>\n"
    else:
        html += """
    <h2>Accounts with Non-Expiring Passwords</h2>
    <p>No cracked accounts with non-expiring passwords identified.</p>
"""

    out_of_compliance_accounts = [row for row in cracked_rows if row.get('Days Out of Compliance', 'N/A') not in ('N/A', 'Unknown') and int(row['Days Out of Compliance']) > 0]
    if out_of_compliance_accounts:
        out_of_compliance_accounts.sort(key=lambda x: (
            not (x.get('Enabled', 'Unknown') == 'Yes'),
            int(x['Password Length']),
            -int(x.get('Days Out of Compliance', 0))
        ))
        html += """
    <h2>Out-of-Compliance Accounts</h2>
    <p>Cracked accounts out of compliance, sorted by enabled status (True first), length, and days.</p>
    <table>
        <thead>
            <tr><th>Username</th><th>Password Length</th><th>Days Out of Compliance</th><th>Enabled</th><th>Last Logon</th><th>When Created</th><th>Risk Level</th><th>Action</th></tr>
        </thead>
        <tbody>
"""
        for acc in out_of_compliance_accounts:
            action = "Reset Immediately" if acc['Risk Level'] in ('High', 'Critical') and acc.get('Enabled', 'No') == 'Yes' else "Enforce Compliance"
            html += f"                <tr><td>{acc['Username']}</td><td>{acc['Password Length']}</td><td>{acc.get('Days Out of Compliance', 'N/A')}</td><td>{acc.get('Enabled', 'Unknown')}</td><td>{acc.get('Last Logon', 'Unknown')}</td><td>{acc.get('When Created', 'Unknown')}</td><td>{acc['Risk Level']}</td><td>{action}</td></tr>\n"
        html += "            </tbody>\n        </table>\n"
    else:
        html += """
    <h2>Out-of-Compliance Accounts</h2>
    <p>No cracked accounts out of compliance identified.</p>
"""

    if not any([da_accounts, controllables_accounts, non_expiring_accounts, out_of_compliance_accounts]):
        html += "<p><strong>No actionable items identified for this domain.</strong></p>\n"

    html += f"""
{TABLE_SORT_JS}
</body>
</html>
"""

    output_path = html_reports_folder / f'{domain}_actionable_report.html'
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)
    if logger:
        logger.info(f"Generated HTML actionable report: {output_path}")

def generate_combined_html_report(combined_rows, global_password_to_users, global_hash_to_users, visuals, logger=None):
    os.makedirs(html_reports_folder, exist_ok=True)
    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
    <title>Cross-Domain Password Security Report</title>
    <style>
    {BASE_CSS}
    {IFRAME_CSS}
    .sorted-asc::after {{ content: " ↑"; }}
    .sorted-desc::after {{ content: " ↓"; }}
    </style>
</head>
<body>
    <h1>Cross-Domain Password Security Report</h1>
    <p><a href="./main.html">Back to Main</a> | <a href="./search.html">Search Accounts</a></p>
"""
    total_shared = len(combined_rows)
    shared_da = sum(1 for row in combined_rows if row.get('DA Domains', 'None') not in ('None', 'Unknown') and row['Shared With'] > 0)
    html += f"""
    <h2>Overview</h2>
    <ul>
        <li><strong>Accounts Sharing Credentials Across Domains:</strong> {total_shared}</li>
        <li><strong>Shared DA Pathway Accounts:</strong> {shared_da}</li>
    </ul>
"""
    if total_shared == 0:
        html += "<p>No cross-domain sharing detected.</p>\n"

    password_counts = Counter({pw: len(users) for pw, users in global_password_to_users.items() if len(users) > 1})
    top_passwords = password_counts.most_common(5)
    html += """
    <h2>Top Shared Passwords</h2>
"""
    if top_passwords:
        html += """
    <table>
        <thead>
            <tr><th>Password</th><th>Total Accounts</th><th>Instances per Domain</th></tr>
        </thead>
        <tbody>
"""
        for pw, _ in top_passwords:
            domain_counts = Counter(u.split('@')[1] if '@' in u else u for u in global_password_to_users[pw])
            instances = ', '.join(f"{d}: {c}" for d, c in domain_counts.items())
            total = sum(domain_counts.values())
            html += f"                <tr><td>{pw}</td><td>{total}</td><td>{instances}</td></tr>\n"
        html += "            </tbody>\n        </table>\n"
    else:
        html += "<p>No passwords shared across domains.</p>\n"

    hash_counts = Counter({h: len(users) for h, users in global_hash_to_users.items() if len(users) > 1})
    top_hashes = hash_counts.most_common(5)
    html += """
    <h2>Top Shared Hashes</h2>
"""
    if top_hashes:
        html += """
    <table>
        <thead>
            <tr><th>Hash</th><th>Total Accounts</th><th>Instances per Domain</th></tr>
        </thead>
        <tbody>
"""
        for h, _ in top_hashes:
            domain_counts = Counter(u.split('@')[1] if '@' in u else u for u in global_hash_to_users[h])
            instances = ', '.join(f"{d}: {c}" for d, c in domain_counts.items())
            total = sum(domain_counts.values())
            html += f"                <tr><td>{h[:8]}...</td><td>{total}</td><td>{instances}</td></tr>\n"
        html += "            </tbody>\n        </table>\n"
    else:
        html += "<p>No hashes shared across domains.</p>\n"

    html += """
    <h2>BloodHound Insights</h2>
    <p>Accounts with DA pathways across domains, risking multi-domain compromise.</p>
"""

    cracked_da_accounts = [row for row in combined_rows if row['Password'] not in global_hash_to_users and row.get('DA Domains', 'None') not in ('None', 'Unknown')]
    if cracked_da_accounts:
        cracked_by_password = defaultdict(list)
        for acc in cracked_da_accounts:
            cracked_by_password[acc['Password']].append(acc)
        html += """
    <h3>Cracked Accounts with DA Pathways</h3>
    <p>Cracked accounts with DA pathways, grouped by password:</p>
    <table>
        <thead>
            <tr><th>Usernames</th><th>Password</th><th>DA Domains</th><th>Domains Shared</th></tr>
        </thead>
        <tbody>
"""
        for password, accounts in cracked_by_password.items():
            usernames = ', '.join(acc['Username'] for acc in accounts)
            da_domains = next(acc['DA Domains'] for acc in accounts)
            domains_shared = next(acc['Domains Shared'] for acc in accounts)
            html += f"                <tr><td>{usernames}</td><td>{password}</td><td>{da_domains}</td><td>{domains_shared}</td></tr>\n"
        html += "            </tbody>\n        </table>\n"
    else:
        html += """
    <h3>Cracked Accounts with DA Pathways</h3>
    <p>No cracked accounts with DA pathways found.</p>
"""

    uncracked_da_accounts = [row for row in combined_rows if row['Password'] in global_hash_to_users and row['Shared With'] > 0 and row.get('DA Domains', 'None') not in ('None', 'Unknown')]
    if uncracked_da_accounts:
        uncracked_by_hash = defaultdict(list)
        for acc in uncracked_da_accounts:
            uncracked_by_hash[acc['Password']].append(acc)
        html += """
    <h3>Uncracked Accounts with Shared Hashes and DA Pathways</h3>
    <p>Uncracked accounts with shared hashes and DA pathways, grouped by hash:</p>
    <table>
        <thead>
            <tr><th>Usernames</th><th>Password Hash</th><th>DA Domains</th><th>Domains Shared</th></tr>
        </thead>
        <tbody>
"""
        for hash_, accounts in uncracked_by_hash.items():
            usernames = ', '.join(acc['Username'] for acc in accounts)
            da_domains = next(acc['DA Domains'] for acc in accounts)
            domains_shared = next(acc['Domains Shared'] for acc in accounts)
            html += f"                <tr><td>{usernames}</td><td>{hash_[:8]}...</td><td>{da_domains}</td><td>{domains_shared}</td></tr>\n"
        html += "            </tbody>\n        </table>\n"
    else:
        html += """
    <h3>Uncracked Accounts with Shared Hashes and DA Pathways</h3>
    <p>No uncracked accounts with shared hashes and DA pathways found.</p>
"""

    da_passwords = {row['Password'] for row in cracked_da_accounts}
    shared_with_da = [row for row in combined_rows if row['Password'] in da_passwords and row['Password'] not in global_hash_to_users and row.get('DA Domains', 'None') in ('None', 'Unknown')]
    if shared_with_da:
        shared_by_password = defaultdict(list)
        for acc in shared_with_da:
            shared_by_password[acc['Password']].append(acc)
        html += """
    <h3>Accounts Sharing Cracked Passwords with DA Accounts</h3>
    <p>Accounts sharing passwords with DA-privileged accounts, grouped by password:</p>
    <table>
        <thead>
            <tr><th>Usernames</th><th>Password</th><th>Shared With</th><th>Domains Shared</th></tr>
        </thead>
        <tbody>
"""
        for password, accounts in shared_by_password.items():
            usernames = ', '.join(acc['Username'] for acc in accounts)
            shared_with = next(acc['Shared With'] for acc in accounts)
            domains_shared = next(acc['Domains Shared'] for acc in accounts)
            html += f"                <tr><td>{usernames}</td><td>{password}</td><td>{shared_with}</td><td>{domains_shared}</td></tr>\n"
        html += "            </tbody>\n        </table>\n"
    else:
        html += """
    <h3>Accounts Sharing Cracked Passwords with DA Accounts</h3>
    <p>No accounts share cracked passwords with DA-privileged accounts.</p>
"""

    max_shared = max(max(password_counts.values(), default=0), max(hash_counts.values(), default=0))
    html += f"""
    <h2>Key Findings</h2>
    <ul>
        <li><strong>Total Cross-Domain Sharing Incidents:</strong> {total_shared}</li>
        <li><strong>Maximum Accounts Sharing a Credential:</strong> {max_shared}</li>
        <li><strong>Recommendations:</strong>
            <ul>
                <li>Enforce unique passwords across domains.</li>
                <li>Implement MFA for high-risk accounts.</li>
                <li>Educate users on strong password practices.</li>
            </ul>
        </li>
    </ul>
"""

    for vis_type in ['combined_sharing', 'last_password_set', 'expiration_status', 'sharing_heatmap', 'da_exposure', 'shared_network']:
        if vis_type in visuals:
            title = vis_type.replace('_', ' ').title()
            html += f"""
    <p><strong>{title}:</strong></p>
    <iframe src="./{os.path.basename(visuals[vis_type])}" width="100%" height="500" frameborder="0"></iframe>
"""

    html += f"""
{TABLE_SORT_JS}
</body>
</html>
"""

    output_path = html_reports_folder / 'combined_report.html'
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)
    if logger:
        logger.info(f"Generated combined HTML report: {output_path}")

def generate_main_html(domains, logger=None):
    os.makedirs(html_reports_folder, exist_ok=True)
    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
    <title>Password Security Audit - Main Report</title>
    <style>
    {BASE_CSS}
    </style>
</head>
<body>
    <h1>Password Security Audit Reports</h1>
    <h2>Available Reports</h2>
    <ul>
        <li><a href="./combined_report.html">Combined Cross-Domain Report</a></li>
        <li><a href="./search.html">Search Accounts</a></li>
        <li><a href="./search_redacted.html">Search Accounts (Redacted)</a></li>
"""
    for domain in domains:
        html += f"        <li><a href=\"./{domain}_report.html\">{domain} - Single Domain Report</a></li>\n"
        html += f"        <li><a href=\"./{domain}_actionable_report.html\">{domain} - Actionable Report</a></li>\n"
    html += """
    </ul>
</body>
</html>
"""

    output_path = html_reports_folder / 'main.html'
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)
    if logger:
        logger.info(f"Generated main HTML report: {output_path}")

def generate_search_html(json_file, logger=None):
    os.makedirs(html_reports_folder, exist_ok=True)
    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
    <title>Account Search</title>
    <style>
    {BASE_CSS}
    .sorted-asc::after {{ content: " ↑"; }}
    .sorted-desc::after {{ content: " ↓"; }}
    .filter-select {{ width: 100%; max-width: 200px; margin-top: 5px; }}
    </style>
</head>
<body>
    <h1>Account Search</h1>
    <p><a href="./main.html">Back to Main</a></p>
    <input type="text" id="searchInput" placeholder="Search by Username...">
    <table id="resultsTable">
        <thead>
            <tr>
                <th data-column="username">Username</th>
                <th data-column="Domain">Domain</th>
                <th data-column="password">Password</th>
                <th data-column="Type">Type</th>
                <th data-column="Risk Level">Risk Level</th>
                <th data-column="Enabled">Enabled</th>
                <th data-column="Last Logon Timestamp">Last Logon Timestamp</th>
                <th data-column="Password Set to Expire">Password Set to Expire</th>
                <th data-column="Controlled Object Count">Controllables Count</th>
                <th data-column="DA Domains">DA Pathway</th>
                <th data-column="Shared With">Shared With</th>
                <th data-column="Last Password Set">Last Password Set</th>
                <th data-column="Days Out of Compliance">Days Out of Compliance</th>
            </tr>
        </thead>
        <tbody>
        </tbody>
    </table>
    {TABLE_SORT_JS}
    {SEARCH_JS}
</body>
</html>
"""

    output_path = html_reports_folder / 'search.html'
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)
    if logger:
        logger.info(f"Generated search HTML report: {output_path}")


def generate_search_redacted_html(json_file_with_placeholders, logger=None):
    os.makedirs(html_reports_folder, exist_ok=True)
    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
    <title>Account Search (Redacted)</title>
    <style>
    {BASE_CSS}
    .sorted-asc::after {{ content: " ↑"; }}
    .sorted-desc::after {{ content: " ↓"; }}
    .filter-select {{ width: 100%; max-width: 200px; margin-top: 5px; }}
    </style>
</head>
<body>
    <h1>Account Search (Redacted)</h1>
    <p><a href="./main.html">Back to Main</a></p>
    <input type="text" id="searchInput" placeholder="Search by Username...">
    <table id="resultsTable">
        <thead>
            <tr>
                <th data-column="username">Username</th>
                <th data-column="Domain">Domain</th>
                <th data-column="password">Password Placeholder</th>
                <th data-column="Type">Type</th>
                <th data-column="Risk Level">Risk Level</th>
                <th data-column="Enabled">Enabled</th>
                <th data-column="Last Logon Timestamp">Last Logon Timestamp</th>
                <th data-column="Password Set to Expire">Password Set to Expire</th>
                <th data-column="Controlled Object Count">Controllables Count</th>
                <th data-column="DA Domains">DA Pathway</th>
                <th data-column="Shared With">Shared With</th>
                <th data-column="Last Password Set">Last Password Set</th>
                <th data-column="Days Out of Compliance">Days Out of Compliance</th>
            </tr>
        </thead>
        <tbody>
        </tbody>
    </table>
    {TABLE_SORT_JS}
    {SEARCH_REDACTED_JS}
</body>
</html>
"""

    output_path = html_reports_folder / 'search_redacted.html'
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)
    if logger:
        logger.info(f"Generated redacted search HTML report: {output_path}")        