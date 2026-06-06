# reports/html/actionable.py
"""
Actionable report generation module.
"""

import hashlib
import json
import os
from pathlib import Path

from markupsafe import escape as escape_html

from report_lib.standalone_html.components import (
    COMPLIANCE_EXPLANATION,
    CONTROLLABLES_EXPLANATION,
    DA_EXPLANATION,
    NONEXPIRING_EXPLANATION,
    create_breadcrumb,
    create_error_message,
    create_navbar,
    create_page_wrapper,
    create_risk_badge,
    create_sidebar,
    create_user_detail_offcanvas,
    html_head,
)
from report_lib.standalone_html.scripts import ACTIONABLE_REPORT_JS, render_user_detail_js
from report_lib.templating import render


def generate_html_actionable_report(domain, data, seed, visuals, logger=None):
    """
    Generate HTML actionable report for a domain.
    
    Args:
        domain (str): Domain name
        data (dict): Domain analysis data
        seed (str): Seed for password placeholders
        visuals (dict): Dictionary of visualization paths
        logger (Logger, optional): Logger instance
    """
    # Call the combined implementation for consistency
    return generate_combined_actionable_report(domain, data, seed, visuals, logger)


def generate_combined_actionable_report(domain, data, seed, visuals, logger=None):
    """
    Generate a combined actionable and explanatory HTML report.

    Args:
        domain (str): Domain name
        data (dict): Domain analysis data
        seed (str): Seed for password placeholders
        visuals (dict): Dictionary of visualization paths
        logger (Logger, optional): Logger instance
    """
    try:
        domains = [domain]
        navbar = create_navbar(current_page=f'actionable_{domain}', include_search=True, include_export=True)
        sidebar = create_sidebar(current_page=f'actionable_{domain}', domains=domains)
        breadcrumb_html = create_breadcrumb([
            ('Main Report', './main.html'),
            ('Search', './search.html'),
            (f'{domain} Actionable Report', None)
        ])

        try:
            cracked_rows = [row for row in data['output_rows'] if row.get('Password Length', 'N/A') != 'N/A']

            da_accounts = [row for row in cracked_rows if row.get('DA Domains', 'None') not in ('None', 'Unknown')]
            da_count = len(da_accounts)
            sections_html = build_section_with_tabs(
                "Riskiest Cracked Accounts with DA Pathway",
                f"**Count in this Domain**: {da_count} accounts",
                DA_EXPLANATION,
                build_da_accounts_table(da_accounts, seed),
                "tab-action",
                "tab-explanation"
            )

            controllables_accounts = sorted(
                cracked_rows,
                key=lambda x: (
                    not (x.get('Enabled', 'Unknown') == 'Yes'),
                    -int(x.get('Controlled Object Count', 0) if x.get('Controlled Object Count', 'Unknown') != 'Unknown' else 0)
                )
            )[:100]
            controllables_count = len(controllables_accounts)
            sections_html += build_section_with_tabs(
                "Top 100 Accounts by Controllables",
                f"**Count in this Domain**: {controllables_count} accounts (top 100 shown)",
                CONTROLLABLES_EXPLANATION,
                build_controllables_table(controllables_accounts, seed),
                "tab-action-controllables",
                "tab-explanation-controllables"
            )

            non_expiring_accounts = [row for row in cracked_rows if row.get('Password Set to Expire', 'Yes') == 'No']
            non_expiring_count = len(non_expiring_accounts)
            sections_html += build_section_with_tabs(
                "Accounts with Non-Expiring Passwords",
                f"**Count in this Domain**: {non_expiring_count} accounts",
                NONEXPIRING_EXPLANATION,
                build_nonexpiring_table(non_expiring_accounts, seed),
                "tab-action-nonexpiring",
                "tab-explanation-nonexpiring"
            )

            out_of_compliance_accounts = [row for row in cracked_rows
                                        if row.get('Days Out of Compliance', 'N/A') not in ('N/A', 'Unknown')
                                        and int(row.get('Days Out of Compliance', 0)) > 0]
            sections_html += build_section_with_tabs(
                "Out-of-Compliance Accounts",
                f"**Count in this Domain**: {len(out_of_compliance_accounts)} accounts",
                COMPLIANCE_EXPLANATION,
                build_compliance_table(out_of_compliance_accounts),
                "tab-action-compliance",
                "tab-explanation-compliance"
            )

            if not any([da_accounts, controllables_accounts, non_expiring_accounts, out_of_compliance_accounts]):
                sections_html += "<p><strong>No actionable items identified for this domain.</strong></p>\n"

        except Exception as e:
            if logger:
                logger.error(f"Error processing data for actionable report for domain {domain}: {str(e)}")
            sections_html = create_error_message(f"Error processing actionable data: {str(e)}")

        try:
            user_details_json = generate_user_details_json(data['output_rows'])
            user_details_json_str = json.dumps(user_details_json, indent=2)
        except Exception as e:
            if logger:
                logger.error(f"Error generating user details JSON: {str(e)}")
            user_details_json_str = '{}'

        offcanvas_html = create_user_detail_offcanvas()
        user_detail_script = render_user_detail_js(user_details_json_str)
        scripts_html = f"""
                {ACTIONABLE_REPORT_JS}
                {user_detail_script}
        """

        content = render(
            "partials/actionable_content.html.j2",
            domain=domain,
            breadcrumb_html=breadcrumb_html,
            sections_html=sections_html,
            offcanvas_html=offcanvas_html,
            scripts_html=scripts_html,
        )

        html = html_head(f"Actionable Password Security Report - {domain}", enable_sidebar=True)
        html += create_page_wrapper(content, navbar, sidebar)
        html += """
</body>
</html>
        """

        from core import config as config_module
        html_dir = getattr(config_module, 'html_reports_folder', Path('output/html_report'))
        output_path = html_dir / f'{domain}_actionable_report.html'
        os.makedirs(output_path.parent, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
        if logger:
            logger.info(f"Generated actionable HTML report: {output_path}")

    except Exception as e:
        if logger:
            logger.error(f"Error generating actionable HTML report for domain {domain}: {str(e)}")
        else:
            print(f"Error generating actionable HTML report for domain {domain}: {str(e)}")


def build_score_breakdown_html(account, row_id):
    """Build HTML for collapsible score breakdown."""
    score_breakdown = account.get('Score Breakdown', {})

    if not score_breakdown or not isinstance(score_breakdown, dict):
        return ""

    base_score = score_breakdown.get('base_score', 'N/A')
    temporal_score = score_breakdown.get('temporal_score', 'N/A')
    environmental_score = score_breakdown.get('environmental_score', 'N/A')

    base_components = score_breakdown.get('base_components', {})
    temporal_components = score_breakdown.get('temporal_components', {})
    environmental_components = score_breakdown.get('environmental_components', {})

    html = f"""
    <tr class="collapse" id="{row_id}">
        <td colspan="100%" class="p-0">
            <div class="card card-body bg-dark m-2">
                <h6 class="text-primary mb-3"><i class="bi bi-calculator me-2"></i>Score Breakdown</h6>
                <div class="row g-3">
                    <div class="col-md-4">
                        <div class="card bg-secondary">
                            <div class="card-body">
                                <h6 class="card-title text-info">Base Score: {base_score}</h6>
                                <small class="text-muted">Password intrinsic qualities</small>
                                <hr class="my-2">
                                <dl class="row mb-0 small">
                                    <dt class="col-7">Complexity:</dt><dd class="col-5">{base_components.get('complexity_factor', 'N/A')}</dd>
                                    <dt class="col-7">Length:</dt><dd class="col-5">{base_components.get('length_factor', 'N/A')}</dd>
                                    <dt class="col-7">Dictionary:</dt><dd class="col-5">{base_components.get('dictionary_factor', 'N/A')}</dd>
                                    <dt class="col-7">Similarity:</dt><dd class="col-5">{base_components.get('similarity_factor', 'N/A')}</dd>
                                </dl>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="card bg-secondary">
                            <div class="card-body">
                                <h6 class="card-title text-warning">Temporal Score: {temporal_score}</h6>
                                <small class="text-muted">Time-based factors</small>
                                <hr class="my-2">
                                <dl class="row mb-0 small">
                                    <dt class="col-7">Compliance:</dt><dd class="col-5">{temporal_components.get('compliance_factor', 'N/A')}</dd>
                                    <dt class="col-7">Expiration:</dt><dd class="col-5">{temporal_components.get('expiration_factor', 'N/A')}</dd>
                                </dl>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="card bg-secondary">
                            <div class="card-body">
                                <h6 class="card-title text-danger">Environmental Score: {environmental_score}</h6>
                                <small class="text-muted">Organizational context</small>
                                <hr class="my-2">
                                <dl class="row mb-0 small">
                                    <dt class="col-7">Privilege:</dt><dd class="col-5">{environmental_components.get('privilege_factor', 'N/A')}</dd>
                                    <dt class="col-7">Sharing:</dt><dd class="col-5">{environmental_components.get('share_factor', 'N/A')}</dd>
                                    <dt class="col-7">Domain:</dt><dd class="col-5">{environmental_components.get('domain_factor', 'N/A')}</dd>
                                    <dt class="col-7">HIBP:</dt><dd class="col-5">{environmental_components.get('hibp_factor', 'N/A')}</dd>
                                </dl>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </td>
    </tr>
    """

    return html


def generate_user_details_json(output_rows):
    """
    Generate comprehensive JSON data for user details offcanvas.

    Args:
        output_rows: List of account dictionaries from domain analysis

    Returns:
        Dictionary keyed by username with all user detail fields
    """
    user_details = {}

    for row in output_rows:
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
            'password': row.get('Password', None),  # Only if cracked
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

            # Risk Factor Components
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

            # Sharing
            'share_count': row.get('Share Count', 0),
            'shared_with': row.get('Shared With', 'N/A'),
        }

    return user_details


def build_section_with_tabs(title, subtitle, explanation, table_html, action_tab_id, explanation_tab_id):
    """Build a section with Bootstrap Nav Tabs."""
    return f"""
    <div class="card mb-4 shadow-sm">
        <div class="card-header">
            <h4 class="mb-0"><i class="bi bi-list-task me-2"></i>{title}</h4>
        </div>
        <div class="card-body">
            <p class="lead">{subtitle}</p>

            <ul class="nav nav-tabs mb-3" id="{action_tab_id}-tabs" role="tablist">
                <li class="nav-item" role="presentation">
                    <button class="nav-link active" id="{action_tab_id}-tab" data-bs-toggle="tab"
                            data-bs-target="#{action_tab_id}" type="button" role="tab"
                            aria-controls="{action_tab_id}" aria-selected="true">
                        <i class="bi bi-clipboard-data me-2"></i>Actions
                    </button>
                </li>
                <li class="nav-item" role="presentation">
                    <button class="nav-link" id="{explanation_tab_id}-tab" data-bs-toggle="tab"
                            data-bs-target="#{explanation_tab_id}" type="button" role="tab"
                            aria-controls="{explanation_tab_id}" aria-selected="false">
                        <i class="bi bi-info-circle me-2"></i>Explanation
                    </button>
                </li>
            </ul>

            <div class="tab-content" id="{action_tab_id}-tabContent">
                <div class="tab-pane fade show active" id="{action_tab_id}" role="tabpanel"
                     aria-labelledby="{action_tab_id}-tab">
                    {table_html}
                </div>
                <div class="tab-pane fade" id="{explanation_tab_id}" role="tabpanel"
                     aria-labelledby="{explanation_tab_id}-tab">
                    {explanation}
                </div>
            </div>
        </div>
    </div>
    """


def build_da_accounts_table(accounts, seed):
    """Build the DA accounts table using Bootstrap with enhanced features."""
    if not accounts:
        return '<div class="alert alert-success"><i class="bi bi-check-circle me-2"></i>No cracked accounts with DA pathways identified.</div>'

    # Sort by enabled status and risk level
    risk_order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Unknown": 0}
    accounts.sort(key=lambda x: (not (x.get('Enabled', 'Unknown') == 'Yes'), -risk_order.get(x['Risk Level'], 0)))

    # Build the table with Bootstrap classes
    table_html = """
    <div class="mb-3 d-flex align-items-center gap-2">
        <span class="text-muted"><i class="bi bi-funnel me-1"></i>Filter by risk:</span>
        <div class="btn-group" role="group" aria-label="Risk filter">
            <button type="button" class="btn btn-sm btn-outline-secondary active" onclick="filterByRisk('all', this)">All</button>
            <button type="button" class="btn btn-sm btn-outline-danger" onclick="filterByRisk('Critical', this)">Critical</button>
            <button type="button"="btn btn-sm btn-outline-warning" onclick="filterByRisk('High', this)">High</button>
            <button type="button" class="btn btn-sm btn-outline-info" onclick="filterByRisk('Medium', this)">Medium</button>
            <button type="button" class="btn btn-sm btn-outline-success" onclick="filterByRisk('Low', this)">Low</button>
        </div>
    </div>

    <div class="table-responsive">
        <table class="table table-hover table-striped table-bordered table-sm">
            <thead class="table-dark">
                <tr>
                    <th>Username</th>
                    <th>Password Placeholder</th>
                    <th>Risk Level</th>
                    <th>HIBP</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>
    """

    for idx, acc in enumerate(accounts):
        placeholder = hashlib.md5((seed + acc['Password']).encode()).hexdigest()
        action = "Reset Immediately" if acc.get('Enabled', 'No') == 'Yes' and acc.get('Risk Level', '') in ('High', 'Critical') else "Review and Secure"
        risk_level = acc.get('Risk Level', 'Unknown')

        hibp_breached = acc.get('HIBP Breached', 'No')
        hibp_count = acc.get('HIBP Breach Count', 0)
        hibp_cell = (f'<span class="badge bg-danger">Breached ({hibp_count:,})</span>'
                     if hibp_breached == 'Yes'
                     else '<span class="badge bg-secondary">Clean</span>')

        action_badge = 'bg-danger' if action == "Reset Immediately" else 'bg-warning text-dark'

        table_html += f"""
        <tr class="risk-row risk-{risk_level.lower()}" data-risk="{risk_level}">
            <td>
                <a href="#" class="user-detail-link text-decoration-none"
                   data-username="{escape_html(acc['Username'])}"
                   data-coreui-toggle="offcanvas"
                   data-coreui-target="#userDetailOffcanvas">
                    <code>{escape_html(acc['Username'])}</code>
                </a>
            </td>
            <td><small class="font-monospace">{placeholder}</small></td>
            <td>{create_risk_badge(risk_level)}</td>
            <td>{hibp_cell}</td>
            <td><span class="badge {action_badge}">{action}</span></td>
        </tr>
        """

    table_html += """
            </tbody>
        </table>
    </div>
    """

    return table_html


def build_controllables_table(accounts, seed):
    """Build the controllables accounts table using Bootstrap."""
    if not accounts:
        return '<div class="alert alert-success"><i class="bi bi-check-circle me-2"></i>No cracked accounts with controlled objects identified.</div>'

    # Build the table with Bootstrap classes
    table_html = """
    <div class="mb-3 d-flex align-items-center gap-2">
        <span class="text-muted"><i class="bi bi-funnel me-1"></i>Filter by risk:</span>
        <div class="btn-group" role="group" aria-label="Risk filter">
            <button type="button" class="btn btn-sm btn-outline-secondary active" onclick="filterByRisk('all', this)">All</button>
            <button type="button" class="btn btn-sm btn-outline-danger" onclick="filterByRisk('Critical', this)">Critical</button>
            <button type="button" class="btn btn-sm btn-outline-warning" onclick="filterByRisk('High', this)">High</button>
            <button type="button" class="btn btn-sm btn-outline-info" onclick="filterByRisk('Medium', this)">Medium</button>
            <button type="button" class="btn btn-sm btn-outline-success" onclick="filterByRisk('Low', this)">Low</button>
        </div>
    </div>

    <div class="table-responsive">
        <table class="table table-hover table-striped table-bordered table-sm">
            <thead class="table-dark">
                <tr>
                    <th>Username</th>
                    <th>Password Placeholder</th>
                    <th>Risk Level</th>
                    <th>Controllables</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>
    """

    for acc in accounts:
        placeholder = hashlib.md5((seed + acc['Password']).encode()).hexdigest()
        action = "Reset Immediately" if acc.get('Enabled', 'No') == 'Yes' and acc.get('Risk Level', '') in ('High', 'Critical') else "Review and Secure"
        controllables = acc.get('Controlled Object Count', 'Unknown')
        risk_level = acc.get('Risk Level', 'Unknown')

        action_badge = 'bg-danger' if action == "Reset Immediately" else 'bg-warning text-dark'

        table_html += f"""
        <tr class="risk-row risk-{risk_level.lower()}" data-risk="{risk_level}">
            <td>
                <a href="#" class="user-detail-link text-decoration-none"
                   data-username="{escape_html(acc['Username'])}"
                   data-coreui-toggle="offcanvas"
                   data-coreui-target="#userDetailOffcanvas">
                    <code>{escape_html(acc['Username'])}</code>
                </a>
            </td>
            <td><small class="font-monospace">{placeholder}</small></td>
            <td>{create_risk_badge(risk_level)}</td>
            <td><span class="badge bg-primary">{controllables}</span></td>
            <td><span class="badge {action_badge}">{action}</span></td>
        </tr>
        """

    table_html += """
            </tbody>
        </table>
    </div>
    """

    return table_html


def build_nonexpiring_table(accounts, seed):
    """Build the non-expiring accounts table using Bootstrap."""
    if not accounts:
        return '<div class="alert alert-success"><i class="bi bi-check-circle me-2"></i>No cracked accounts with non-expiring passwords identified.</div>'

    # Sort by enabled status
    accounts.sort(key=lambda x: not (x.get('Enabled', 'Unknown') == 'Yes'))

    # Build the table with Bootstrap classes
    table_html = """
    <div class="mb-3 d-flex align-items-center gap-2">
        <span class="text-muted"><i class="bi bi-funnel me-1"></i>Filter by risk:</span>
        <div class="btn-group" role="group" aria-label="Risk filter">
            <button type="button" class="btn btn-sm btn-outline-secondary active" onclick="filterByRisk('all', this)">All</button>
            <button type="button" class="btn btn-sm btn-outline-danger" onclick="filterByRisk('Critical', this)">Critical</button>
            <button type="button" class="btn btn-sm btn-outline-warning" onclick="filterByRisk('High', this)">High</button>
            <button type="button" class="btn btn-sm btn-outline-info" onclick="filterByRisk('Medium', this)">Medium</button>
            <button type="button" class="btn btn-sm btn-outline-success" onclick="filterByRisk('Low', this)">Low</button>
        </div>
    </div>

    <div class="table-responsive">
        <table class="table table-hover table-striped table-bordered table-sm">
            <thead class="table-dark">
                <tr>
                    <th>Username</th>
                    <th>Password Placeholder</th>
                    <th>Risk Level</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>
    """

    for acc in accounts:
        placeholder = hashlib.md5((seed + acc['Password']).encode()).hexdigest()
        action = "Set to Expire and Reset" if acc.get('Enabled', 'No') == 'Yes' else "Review and Update"
        risk_level = acc.get('Risk Level', 'Unknown')

        action_badge = 'bg-warning text-dark' if action == "Set to Expire and Reset" else 'bg-info'

        table_html += f"""
        <tr class="risk-row risk-{risk_level.lower()}" data-risk="{risk_level}">
            <td>
                <a href="#" class="user-detail-link text-decoration-none"
                   data-username="{escape_html(acc['Username'])}"
                   data-coreui-toggle="offcanvas"
                   data-coreui-target="#userDetailOffcanvas">
                    <code>{escape_html(acc['Username'])}</code>
                </a>
            </td>
            <td><small class="font-monospace">{placeholder}</small></td>
            <td>{create_risk_badge(risk_level)}</td>
            <td><span class="badge {action_badge}">{action}</span></td>
        </tr>
        """

    table_html += """
            </tbody>
        </table>
    </div>
    """

    return table_html


def build_compliance_table(accounts):
    """Build the out-of-compliance accounts table using Bootstrap."""
    if not accounts:
        return '<div class="alert alert-success"><i class="bi bi-check-circle me-2"></i>No cracked accounts out of compliance identified.</div>'

    # Sort by enabled status, password length, and days out of compliance
    accounts.sort(key=lambda x: (
        not (x.get('Enabled', 'Unknown') == 'Yes'),
        int(x['Password Length']),
        -int(x.get('Days Out of Compliance', 0))
    ))
    
    # Build the table with Bootstrap classes
    table_html = """
    <div class="mb-3 d-flex align-items-center gap-2">
        <span class="text-muted"><i class="bi bi-funnel me-1"></i>Filter by risk:</span>
        <div class="btn-group" role="group" aria-label="Risk filter">
            <button type="button" class="btn btn-sm btn-outline-secondary active" onclick="filterByRisk('all', this)">All</button>
            <button type="button" class="btn btn-sm btn-outline-danger" onclick="filterByRisk('Critical', this)">Critical</button>
            <button type="button" class="btn btn-sm btn-outline-warning" onclick="filterByRisk('High', this)">High</button>
            <button type="button" class="btn btn-sm btn-outline-info" onclick="filterByRisk('Medium', this)">Medium</button>
            <button type="button" class="btn btn-sm btn-outline-success" onclick="filterByRisk('Low', this)">Low</button>
        </div>
    </div>

    <div class="table-responsive">
        <table class="table table-hover table-striped table-bordered table-sm">
            <thead class="table-dark">
                <tr>
                    <th>Username</th>
                    <th>Password Length</th>
                    <th>Days Out of Compliance</th>
                    <th>Risk Level</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>
    """

    for acc in accounts:
        action = "Reset Immediately" if acc['Risk Level'] in ('High', 'Critical') and acc.get('Enabled', 'No') == 'Yes' else "Enforce Compliance"
        risk_level = acc.get('Risk Level', 'Unknown')

        action_badge = 'bg-danger' if action == "Reset Immediately" else 'bg-warning text-dark'

        table_html += f"""
        <tr class="risk-row risk-{risk_level.lower()}" data-risk="{risk_level}">
            <td>
                <a href="#" class="user-detail-link text-decoration-none"
                   data-username="{escape_html(acc['Username'])}"
                   data-coreui-toggle="offcanvas"
                   data-coreui-target="#userDetailOffcanvas">
                    <code>{escape_html(acc['Username'])}</code>
                </a>
            </td>
            <td><span class="badge bg-secondary">{acc['Password Length']}</span></td>
            <td><span class="badge bg-danger">{acc.get('Days Out of Compliance', 'N/A')}</span></td>
            <td>{create_risk_badge(risk_level)}</td>
            <td><span class="badge {action_badge}">{action}</span></td>
        </tr>
        """

    table_html += """
            </tbody>
        </table>
    </div>
    """

    return table_html