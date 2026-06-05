# reports/html/combined.py
"""
Combined domain report generation module.
"""

import os
import json
from pathlib import Path
from collections import Counter
from report_lib.standalone_html.components import (
    html_head, create_error_message,
    create_breadcrumb, create_metric_card, create_user_detail_offcanvas,
    create_navbar, create_sidebar, create_page_wrapper
)
from report_lib.standalone_html.modern_components import (
    create_stat_grid, create_callout, create_progress_card,
    create_metric_border_card
)
from report_lib.standalone_html.scripts import TABLE_SORT_JS, USER_DETAIL_JS
from utils.visualization_helper import add_visualization_to_html

def generate_user_details_json_combined(combined_rows):
    """
    Generate comprehensive JSON data for user details offcanvas in combined report.

    Args:
        combined_rows: List of account dictionaries from cross-domain analysis

    Returns:
        Dictionary keyed by username with all user detail fields
    """
    user_details = {}

    for row in combined_rows:
        username = row.get('Username', 'Unknown')

        # Extract score breakdown components
        score_breakdown = row.get('Score Breakdown', {})
        base_components = score_breakdown.get('base_components', {})
        temporal_components = score_breakdown.get('temporal_components', {})
        environmental_components = score_breakdown.get('environmental_components', {})

        # Build comprehensive user detail object
        user_details[username] = {
            # Basic Info
            'username': username,
            'domain': row.get('Domain', 'Unknown'),
            'enabled': row.get('Enabled', 'Unknown') == 'Yes',
            'when_created': row.get('When Created', 'Unknown'),
            'last_logon': row.get('Last Logon', 'Unknown'),

            # Password Info
            'password': row.get('Password', None),
            'password_hash': row.get('Password Hash', 'Unknown'),
            'password_length': row.get('Password Length', 'N/A'),
            'complexity_label': row.get('Complexity Label', 'Unknown'),
            'cracked': row.get('Password Length', 'N/A') != 'N/A',

            # Risk Scores
            'risk_score': row.get('Score', 0.0),
            'risk_level': row.get('Risk Level', 'Unknown'),
            'risk_vector': row.get('Risk Vector', 'N/A'),
            'base_score': score_breakdown.get('base_score', 'N/A'),
            'temporal_score': score_breakdown.get('temporal_score', 'N/A'),
            'environmental_score': score_breakdown.get('environmental_score', 'N/A'),

            # Risk Factor Components (10 factors)
            'complexity_factor': base_components.get('complexity_factor', 'N/A'),
            'length_factor': base_components.get('length_factor', 'N/A'),
            'dictionary_factor': base_components.get('dictionary_factor', 'N/A'),
            'similarity_factor': base_components.get('similarity_factor', 'N/A'),
            'compliance_factor': temporal_components.get('compliance_factor', 'N/A'),
            'expiration_factor': temporal_components.get('expiration_factor', 'N/A'),
            'privilege_factor': environmental_components.get('privilege_factor', 'N/A'),
            'share_factor': environmental_components.get('share_factor', 'N/A'),
            'domain_factor': environmental_components.get('domain_factor', 'N/A'),
            'hibp_factor': environmental_components.get('hibp_factor', 'N/A'),

            # HIBP Data
            'hibp_breached': row.get('HIBP Breached', 'No') == 'Yes',
            'hibp_breach_count': row.get('HIBP Breach Count', 0),
            'hibp_risk_level': row.get('HIBP Risk Level', 'None'),

            # BloodHound Data
            'da_domains': row.get('DA Domains', 'None'),
            'controlled_object_count': row.get('Controlled Object Count', 0),

            # Password Analysis
            'forbidden_words': row.get('Forbidden Words', ''),
            'keyboard_patterns': row.get('Keyboard Patterns', ''),
            'is_common': row.get('Common Password', 'No') == 'Yes',
            'is_dictionary_word': row.get('Is Exactly Dictionary Word', 'No') == 'Yes',
            'similar_passwords': row.get('Similar Passwords', ''),

            # Policy Compliance
            'password_set_to_expire': row.get('Password Set to Expire', 'Unknown'),
            'days_out_of_compliance': row.get('Days Out of Compliance', 'N/A'),
            'password_last_set': row.get('Last Password Set', 'Unknown'),

            # Sharing (specific to combined report)
            'share_count': row.get('Shared With', 0),
            'shared_with': row.get('Shared With', 'N/A'),
            'domains_shared': row.get('Domains Shared', ''),
        }

    return user_details

def generate_combined_html_report(combined_rows, global_password_to_users, global_hash_to_users, visuals, logger=None):
    """
    Generate combined HTML report for cross-domain analysis with improved error handling.

    Args:
        combined_rows (list): Combined account rows across domains
        global_password_to_users (dict): Mapping of passwords to users across domains
        global_hash_to_users (dict): Mapping of hashes to users across domains
        visuals (dict): Dictionary of visualization paths
        logger (Logger, optional): Logger instance
    """
    try:
        # Get list of unique domains from combined rows for sidebar
        domains = list(set(row.get('Domain', 'Unknown') for row in combined_rows if row.get('Domain')))

        # Create navbar and sidebar
        navbar = create_navbar(current_page='cross-domain', include_search=True, include_export=True)
        sidebar = create_sidebar(current_page='cross-domain', domains=domains)

        # Start building content (without body tag - that's in page_wrapper)
        content = f"""
                {create_breadcrumb([
                    ('Main Report', './main.html'),
                    ('Search', './search.html'),
                    ('Cross-Domain Analysis', None)
                ])}

                <div class="mb-4">
                    <h1 class="display-4"><i class="bi bi-diagram-3 me-3"></i>Cross-Domain Analysis</h1>
                    <p class="lead text-muted">Shared credentials and lateral movement risks</p>
                </div>
        """

        try:
            total_shared = len(combined_rows)
            shared_da = sum(1 for row in combined_rows if row.get('DA Domains', 'None') not in ('None', 'Unknown') and row['Shared With'] > 0)
        except Exception as e:
            if logger:
                logger.error(f"Error computing basic metrics for combined report: {str(e)}")
            total_shared = 0
            shared_da = 0
            content += create_error_message(f"Error computing basic metrics: {str(e)}")

        # Overview section with metric cards
        content += '<h2 class="mb-4"><i class="bi bi-bar-chart me-2"></i>Overview</h2>'
        content += '<div class="row g-4 mb-4">'
        content += f'''
            <div class="col-12 col-md-6">
                {create_metric_card(
                    "Shared Credentials",
                    total_shared,
                    icon="share-fill",
                    bg_class="bg-warning" if total_shared > 0 else "bg-success",
                    text_class="text-dark" if total_shared > 0 else "text-white",
                    subtitle="Accounts sharing across domains"
                )}
            </div>
            <div class="col-12 col-md-6">
                {create_metric_card(
                    "DA Pathway Risks",
                    shared_da,
                    icon="exclamation-triangle-fill",
                    bg_class="bg-danger" if shared_da > 0 else "bg-success",
                    subtitle="Shared accounts with DA paths"
                )}
            </div>
        '''
        content += '</div>'

        if total_shared == 0:
            content += '<div class="alert alert-success"><i class="bi bi-check-circle me-2"></i>No cross-domain sharing detected.</div>'

        # Top shared passwords section with error handling
        try:
            password_counts = Counter({pw: len(users) for pw, users in global_password_to_users.items() if len(users) > 1})
            top_passwords = password_counts.most_common(5)
            content += '<h2 class="mb-3"><i class="bi bi-key-fill me-2"></i>Top Shared Passwords</h2>'

            if top_passwords:
                content += '''
                <div class="table-responsive">
                    <table class="table table-hover table-striped table-bordered">
                        <thead class="table-dark">
                            <tr>
                                <th>Password</th>
                                <th>Total Accounts</th>
                                <th>Instances per Domain</th>
                            </tr>
                        </thead>
                        <tbody>
                '''
                for pw, _ in top_passwords:
                    domain_counts = Counter()
                    for u in global_password_to_users[pw]:
                        domain = None
                        if isinstance(u, tuple) and len(u) > 1:
                            domain = u[1]
                        elif isinstance(u, str) and '@' in u:
                            domain = u.split('@')[1]

                        if domain:
                            domain_counts[domain] += 1

                    instances = ', '.join(f"<span class='badge bg-info'>{d}: {c}</span>" for d, c in domain_counts.items())
                    total = sum(domain_counts.values())
                    content += f'''
                        <tr>
                            <td><code>{pw}</code></td>
                            <td><span class="badge bg-danger">{total}</span></td>
                            <td>{instances}</td>
                        </tr>
                    '''
                content += "</tbody>\n</table>\n</div>\n"
            else:
                content += '<div class="alert alert-success"><i class="bi bi-check-circle me-2"></i>No passwords shared across domains.</div>'
        except Exception as e:
            if logger:
                logger.error(f"Error processing top shared passwords: {str(e)}")
            content += create_error_message(f"Error processing top shared passwords: {str(e)}")

        # Add cross-domain visualizations
        for vis_type, title in [
            ('combined_sharing', 'Cross-Domain Sharing'),
            ('sharing_heatmap', 'Sharing Heatmap'),
            ('da_exposure', 'DA Exposure by Domain'),
            ('shared_network', 'Password Sharing Network')
        ]:
            vis_html = add_visualization_to_html(visuals, vis_type, title)
            if vis_html:
                content += vis_html

        # Generate password sharing details table
        try:
            content += build_password_sharing_section(combined_rows, global_password_to_users, global_hash_to_users)
        except Exception as e:
            if logger:
                logger.error(f"Error generating password sharing details: {str(e)}")
            content += create_error_message(f"Error generating password sharing details: {str(e)}")

        # Generate user details JSON for offcanvas
        try:
            user_details_json = generate_user_details_json_combined(combined_rows)
            user_details_json_str = json.dumps(user_details_json, indent=2)
        except Exception as e:
            if logger:
                logger.error(f"Error generating user details JSON: {str(e)}")
            user_details_json_str = '{}'

        # Add offcanvas HTML structure
        content += create_user_detail_offcanvas()

        # Add JavaScript (table sorting and user detail)
        user_detail_script = USER_DETAIL_JS.replace('{USER_DATA_JSON}', user_details_json_str)

        content += f"""
                {TABLE_SORT_JS}
                {user_detail_script}
        """

        # Wrap content with navbar and sidebar using page wrapper
        html = html_head("Cross-Domain Password Security Report", enable_sidebar=True)
        html += create_page_wrapper(content, navbar, sidebar)
        html += """
</body>
</html>
        """

        # Write to file
        from core import config as config_module
        html_dir = getattr(config_module, 'html_reports_folder', Path('output/html_report'))
        output_path = html_dir / 'combined_report.html'
        os.makedirs(output_path.parent, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
        if logger:
            logger.info(f"Generated combined HTML report: {output_path}")
            
    except Exception as e:
        if logger:
            logger.error(f"Error generating combined HTML report: {str(e)}")
        else:
            print(f"Error generating combined HTML report: {str(e)}")


def build_password_sharing_section(combined_rows, global_password_to_users, global_hash_to_users):
    """
    Build the password sharing details section.

    Args:
        combined_rows (list): Combined account rows across domains
        global_password_to_users (dict): Mapping of passwords to users across domains
        global_hash_to_users (dict): Mapping of hashes to users across domains

    Returns:
        str: HTML string for the section
    """
    from collections import defaultdict
    from report_lib.standalone_html.components import create_risk_badge

    # Prepare DA sharing analysis
    html = '<h2 class="mb-4 mt-5"><i class="bi bi-shield-exclamation me-2"></i>Cross-Domain Privilege Exposure</h2>'

    # Group DA accounts by password
    da_accounts = [row for row in combined_rows
                  if row.get('DA Domains', 'None') not in ('None', 'Unknown')]

    if da_accounts:
        cracked_by_password = defaultdict(list)
        for acc in da_accounts:
            if isinstance(acc.get('Password', ''), str):
                # Only include cracked passwords, not hashes
                if acc['Password'] not in global_hash_to_users:
                    cracked_by_password[acc['Password']].append(acc)

        if cracked_by_password:
            html += '''
            <div class="card mb-4 shadow-sm">
                <div class="card-header bg-danger text-white">
                    <h4 class="mb-0"><i class="bi bi-exclamation-triangle-fill me-2"></i>Cracked Accounts with DA Pathways</h4>
                </div>
                <div class="card-body">
                    <p class="lead">Cracked accounts with Domain Admin privileges that share passwords across domains:</p>
                    <div class="table-responsive">
                        <table class="table table-hover table-striped table-bordered">
                            <thead class="table-dark">
                                <tr>
                                    <th>Username</th>
                                    <th>Domain</th>
                                    <th>Password</th>
                                    <th>DA Domains</th>
                                    <th>Domains Shared</th>
                                    <th>Risk Level</th>
                                    <th>Risk Vector</th>
                                </tr>
                            </thead>
                            <tbody>
            '''

            for password, accounts in cracked_by_password.items():
                for acc in accounts:
                    da_domains = acc.get('DA Domains', 'None')
                    domains_shared = acc.get('Domains Shared', '')
                    risk_level = acc.get('Risk Level', 'Unknown')
                    risk_vector = acc.get('Risk Vector', 'N/A')
                    domain = acc.get('Domain', 'Unknown')

                    html += f'''
                    <tr>
                        <td>
                            <a href="#" class="user-detail-link text-decoration-none"
                               data-username="{acc['Username']}"
                               data-coreui-toggle="offcanvas"
                               data-coreui-target="#userDetailOffcanvas">
                                <code>{acc['Username']}</code>
                            </a>
                        </td>
                        <td><span class="badge bg-primary">{domain}</span></td>
                        <td><code>{password}</code></td>
                        <td><span class="badge bg-warning text-dark">{da_domains}</span></td>
                        <td><small>{domains_shared}</small></td>
                        <td>{create_risk_badge(risk_level)}</td>
                        <td><small class="font-monospace">{risk_vector}</small></td>
                    </tr>
                    '''

            html += '''
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
            '''
        else:
            html += '<div class="alert alert-success"><i class="bi bi-check-circle me-2"></i>No cracked accounts with DA pathways found sharing passwords across domains.</div>'
    else:
        html += '<div class="alert alert-info"><i class="bi bi-info-circle me-2"></i>No accounts with DA pathways detected.</div>'

    # Analyze accounts sharing passwords with DA accounts
    html += '<h3 class="mb-3 mt-4"><i class="bi bi-people-fill me-2"></i>Accounts Sharing Passwords with DA Accounts</h3>'

    # Find passwords used by DA accounts
    da_passwords = set()
    for row in combined_rows:
        if row.get('DA Domains', 'None') not in ('None', 'Unknown'):
            if isinstance(row.get('Password', ''), str) and row['Password'] not in global_hash_to_users:
                da_passwords.add(row['Password'])

    # Find non-DA accounts using those passwords
    shared_with_da = [row for row in combined_rows
                     if row.get('Password', '') in da_passwords and
                     row.get('DA Domains', 'None') in ('None', 'Unknown')]

    if shared_with_da:
        html += f'''
        <div class="card mb-4 shadow-sm">
            <div class="card-header bg-warning text-dark">
                <h5 class="mb-0"><i class="bi bi-exclamation-diamond-fill me-2"></i>Non-Privileged Accounts ({len(shared_with_da)})</h5>
            </div>
            <div class="card-body">
                <p class="mb-3">Non-privileged accounts sharing passwords with Domain Admin accounts:</p>
                <div class="table-responsive">
                    <table class="table table-hover table-striped table-bordered">
                        <thead class="table-dark">
                            <tr>
                                <th>Username</th>
                                <th>Domain</th>
                                <th>Password</th>
                                <th>Shared With</th>
                                <th>Domains Shared</th>
                                <th>Risk Level</th>
                            </tr>
                        </thead>
                        <tbody>
        '''

        for acc in shared_with_da:
            html += f'''
            <tr>
                <td>
                    <a href="#" class="user-detail-link text-decoration-none"
                       data-username="{acc['Username']}"
                       data-coreui-toggle="offcanvas"
                       data-coreui-target="#userDetailOffcanvas">
                        <code>{acc['Username']}</code>
                    </a>
                </td>
                <td><span class="badge bg-primary">{acc.get('Domain', 'Unknown')}</span></td>
                <td><code>{acc['Password']}</code></td>
                <td><span class="badge bg-info">{acc.get('Shared With', 0)}</span></td>
                <td><small>{acc.get('Domains Shared', '')}</small></td>
                <td>{create_risk_badge(acc.get('Risk Level', 'Unknown'))}</td>
            </tr>
            '''

        html += '''
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        '''
    else:
        html += '<div class="alert alert-success"><i class="bi bi-check-circle me-2"></i>No non-privileged accounts found sharing passwords with DA accounts.</div>'

    return html


def generate_main_html(domains, domain_data, logger=None):
    """
    Generate stunning main HTML dashboard with real insights using modern CoreUI components.

    Args:
        domains (list): List of domain names
        domain_data (dict): Dictionary mapping domain names to their analysis data
        logger (Logger, optional): Logger instance
    """
    try:
        # Calculate aggregate statistics across all domains
        total_accounts = 0
        total_cracked = 0
        total_critical_risk = 0
        total_da_pathways = 0
        total_hibp_breached = 0
        risk_distribution = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}

        for domain in domains:
            if domain in domain_data:
                data = domain_data[domain]
                rows = data.get('output_rows', [])
                total_accounts += len(rows)

                for row in rows:
                    # Count cracked
                    if row.get('Password Length', 'N/A') != 'N/A':
                        total_cracked += 1

                    # Count critical risks
                    if row.get('Risk Level') == 'Critical':
                        total_critical_risk += 1

                    # Count DA pathways
                    if row.get('DA Domains', 'None') not in ('None', 'Unknown'):
                        total_da_pathways += 1

                    # Count HIBP breached
                    if row.get('HIBP Breached') == 'Yes':
                        total_hibp_breached += 1

                    # Risk distribution
                    risk_level = row.get('Risk Level', 'Unknown')
                    if risk_level in risk_distribution:
                        risk_distribution[risk_level] += 1

        total_uncracked = total_accounts - total_cracked
        crack_rate = round((total_cracked / total_accounts * 100), 1) if total_accounts > 0 else 0
        critical_rate = round((total_critical_risk / total_cracked * 100), 1) if total_cracked > 0 else 0
        hibp_rate = round((total_hibp_breached / total_accounts * 100), 1) if total_accounts > 0 else 0

        # Create navbar and sidebar
        navbar = create_navbar(current_page='dashboard', include_search=True, include_export=False)
        sidebar = create_sidebar(current_page='dashboard', domains=domains)

        # Start building content (without body tag - that's in page_wrapper)
        content = """
                <div class="mb-4">
                    <h1 class="display-4"><i class="bi bi-shield-lock-fill me-3"></i>Password Security Audit</h1>
                    <p class="lead text-muted">Executive Dashboard - Real-time insights across all domains</p>
                </div>
        """

        # Critical alerts callout
        if total_critical_risk > 0 or total_da_pathways > 0:
            critical_message = f"""
            <ul class="mb-2">
                <li><strong>{total_critical_risk:,} accounts</strong> have Critical risk level requiring immediate attention</li>
                <li><strong>{total_da_pathways:,} cracked accounts</strong> have pathways to Domain Admin privileges</li>
                <li><strong>{total_hibp_breached:,} accounts ({hibp_rate}%)</strong> have passwords exposed in data breaches</li>
            </ul>
            <p class="mb-0"><strong>Action Required:</strong> Review actionable reports for immediate remediation steps.</p>
            """

            content += create_callout(
                title="Critical Security Findings",
                message=critical_message,
                color="danger",
                icon="exclamation-triangle-fill",
                dismissible=False
            )

        # Key Metrics - Stat Widget Grid
        stats = [
            {
                'value': f'{total_accounts:,}',
                'label': 'Total Accounts',
                'icon': 'people-fill',
                'color': 'primary',
                'subtitle': f'Across {len(domains)} domains'
            },
            {
                'value': f'{total_cracked:,}',
                'label': 'Cracked Passwords',
                'icon': 'unlock-fill',
                'color': 'danger',
                'trend': 'down' if crack_rate < 50 else 'up',
                'trend_value': f'{crack_rate}%',
                'subtitle': f'{total_uncracked:,} uncracked'
            },
            {
                'value': f'{total_critical_risk:,}',
                'label': 'Critical Risk',
                'icon': 'exclamation-circle-fill',
                'color': 'danger',
                'trend_value': f'{critical_rate}%',
                'subtitle': 'of cracked passwords'
            },
            {
                'value': f'{total_da_pathways:,}',
                'label': 'DA Pathways',
                'icon': 'diagram-3-fill',
                'color': 'warning',
                'subtitle': 'Cracked accounts with DA access'
            }
        ]

        content += '<h2 class="mb-3"><i class="bi bi-speedometer me-2"></i>Key Metrics</h2>'
        content += create_stat_grid(stats, cols=4)

        # Risk Distribution Progress Card
        if total_cracked > 0:
            risk_items = []
            for level, count in [('Critical', risk_distribution['Critical']),
                                ('High', risk_distribution['High']),
                                ('Medium', risk_distribution['Medium']),
                                ('Low', risk_distribution['Low'])]:
                if count > 0:
                    percentage = round((count / total_cracked) * 100, 1)
                    color_map = {'Critical': 'danger', 'High': 'warning', 'Medium': 'info', 'Low': 'success'}
                    risk_items.append({
                        'label': f'{level} Risk',
                        'value': percentage,
                        'color': color_map.get(level, 'secondary'),
                        'count': count
                    })

            content += '<div class="row g-4 mb-4"><div class="col-12 col-lg-6">'
            content += create_progress_card('Risk Distribution', risk_items, icon='speedometer2')
            content += '</div>'

            # Domain Breakdown Card
            domain_metrics = []
            for domain in domains:
                if domain in domain_data:
                    data = domain_data[domain]
                    rows = data.get('output_rows', [])
                    domain_cracked = sum(1 for row in rows if row.get('Password Length', 'N/A') != 'N/A')
                    domain_metrics.append({
                        'label': domain,
                        'value': f'{domain_cracked:,}'
                    })

            metrics_for_border_card = []
            for metric in domain_metrics[:4]:  # Limit to 4 for display
                metrics_for_border_card.append({
                    'label': metric['label'],
                    'value': metric['value'],
                    'color': 'primary'
                })

            content += '<div class="col-12 col-lg-6">'
            content += create_metric_border_card(metrics_for_border_card)
            content += '</div></div>'

        # Domain Cards Grid
        content += '<h2 class="mb-4 mt-5"><i class="bi bi-building me-2"></i>Domain Reports</h2>'
        content += '<div class="row g-4 mb-5">'

        for domain in domains:
            account_count = 0
            cracked_count = 0
            critical_count = 0
            hibp_count = 0

            if domain in domain_data:
                data = domain_data[domain]
                rows = data.get('output_rows', [])
                account_count = len(rows)
                cracked_count = sum(1 for row in rows if row.get('Password Length', 'N/A') != 'N/A')
                critical_count = sum(1 for row in rows if row.get('Risk Level') == 'Critical')
                hibp_count = sum(1 for row in rows if row.get('HIBP Breached') == 'Yes')

            crack_pct = round((cracked_count / account_count * 100), 1) if account_count > 0 else 0

            content += f"""
                <div class="col-12 col-md-6 col-xl-4">
                    <div class="card shadow-sm h-100">
                        <div class="card-header bg-primary text-white d-flex justify-content-between align-items-center">
                            <h5 class="mb-0"><i class="bi bi-server me-2"></i>{domain}</h5>
                            <span class="badge bg-light text-dark">{crack_pct}% cracked</span>
                        </div>
                        <div class="card-body">
                            <div class="row text-center mb-3">
                                <div class="col-6">
                                    <div class="border-start border-start-4 border-start-success px-2">
                                        <div class="fs-5 fw-semibold">{cracked_count:,}</div>
                                        <div class="small text-body-secondary">Cracked</div>
                                    </div>
                                </div>
                                <div class="col-6">
                                    <div class="border-start border-start-4 border-start-info px-2">
                                        <div class="fs-5 fw-semibold">{account_count - cracked_count:,}</div>
                                        <div class="small text-body-secondary">Uncracked</div>
                                    </div>
                                </div>
                            </div>
                            <div class="d-flex justify-content-between mb-2">
                                <span class="text-danger"><i class="bi bi-exclamation-circle"></i> Critical:</span>
                                <strong>{critical_count:,}</strong>
                            </div>
                            <div class="d-flex justify-content-between mb-3">
                                <span class="text-warning"><i class="bi bi-shield-exclamation"></i> HIBP Breached:</span>
                                <strong>{hibp_count:,}</strong>
                            </div>
                            <div class="d-grid gap-2">
                                <a href="./{domain}_report.html" class="btn btn-outline-primary btn-sm">
                                    <i class="bi bi-file-earmark-text me-1"></i>Full Report
                                </a>
                                <a href="./{domain}_actionable_report.html" class="btn btn-outline-success btn-sm">
                                    <i class="bi bi-list-check me-1"></i>Actionable Items
                                </a>
                            </div>
                        </div>
                    </div>
                </div>
            """

        content += '</div>'

        # Quick Links Section
        content += """
                <h2 class="mb-4"><i class="bi bi-lightning me-2"></i>Quick Access</h2>
                <div class="row g-4 mb-4">
                    <div class="col-12 col-md-4">
                        <div class="card shadow-sm">
                            <div class="card-body d-flex align-items-center">
                                <i class="bi bi-diagram-3 fs-1 text-warning me-3"></i>
                                <div class="flex-grow-1">
                                    <h6 class="mb-1">Cross-Domain Analysis</h6>
                                    <p class="small text-muted mb-2">Shared credentials & lateral movement risks</p>
                                    <a href="./combined_report.html" class="btn btn-sm btn-warning">View Report</a>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="col-12 col-md-4">
                        <div class="card shadow-sm">
                            <div class="card-body d-flex align-items-center">
                                <i class="bi bi-search fs-1 text-info me-3"></i>
                                <div class="flex-grow-1">
                                    <h6 class="mb-1">Search Interface</h6>
                                    <p class="small text-muted mb-2">Filter & export account data</p>
                                    <a href="./search.html" class="btn btn-sm btn-info">Search Accounts</a>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="col-12 col-md-4">
                        <div class="card shadow-sm">
                            <div class="card-body d-flex align-items-center">
                                <i class="bi bi-eye-slash fs-1 text-secondary me-3"></i>
                                <div class="flex-grow-1">
                                    <h6 class="mb-1">Redacted Search</h6>
                                    <p class="small text-muted mb-2">Search without password visibility</p>
                                    <a href="./search_redacted.html" class="btn btn-sm btn-outline-secondary">Search Redacted</a>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
        """

        # Wrap content with navbar and sidebar using page wrapper
        html = html_head("Password Security Audit - Executive Dashboard", enable_sidebar=True)
        html += create_page_wrapper(content, navbar, sidebar)
        html += """
</body>
</html>
        """

        # Write to file
        from core import config as config_module
        html_dir = getattr(config_module, 'html_reports_folder', Path('output/html_report'))
        output_path = html_dir / 'main.html'
        os.makedirs(output_path.parent, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
        if logger:
            logger.info(f"Generated enhanced main HTML dashboard: {output_path}")

    except Exception as e:
        if logger:
            logger.error(f"Error generating main HTML dashboard: {str(e)}")
        else:
            print(f"Error generating main HTML dashboard: {str(e)}")