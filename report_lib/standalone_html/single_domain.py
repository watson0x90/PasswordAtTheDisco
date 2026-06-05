# reports/html/single_domain.py
"""
Single domain report generation module.
"""

import os
import json
from pathlib import Path
from report_lib.standalone_html.components import (
    html_head, create_error_message, get_risk_distribution_html, RISK_SCORE_EXPLANATION, create_breadcrumb, create_overview_section,
    create_bootstrap_card, create_risk_badge, create_user_detail_offcanvas,
    create_navbar, create_sidebar, create_page_wrapper
)
from report_lib.standalone_html.scripts import TABLE_SORT_JS, USER_DETAIL_JS
from utils.visualization_helper import add_visualization_to_html

def generate_user_details_json_single(output_rows):
    """
    Generate comprehensive JSON data for user details offcanvas in single domain report.

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

            # Sharing
            'share_count': row.get('Share Count', 0),
            'shared_with': row.get('Shared With', 'N/A'),
        }

    return user_details

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
        # Get all domains from data for sidebar (for now, just use single domain)
        domains = [domain]

        # Create navbar and sidebar
        navbar = create_navbar(current_page=f'domain_{domain}', include_search=True, include_export=True)
        sidebar = create_sidebar(current_page=f'domain_{domain}', domains=domains)

        # Start building content (without body tag - that's in page_wrapper)
        content = f"""
                {create_breadcrumb([
                    ('Main Report', './main.html'),
                    ('Search', './search.html'),
                    (f'{domain} Report', None)
                ])}

                <div class="mb-4">
                    <h1 class="display-4"><i class="bi bi-shield-lock me-3"></i>Password Security Report</h1>
                    <p class="lead text-muted">{domain}</p>
                </div>
        """

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

            # Calculate HIBP breach statistics
            hibp_breached = sum(1 for row in data['output_rows']
                               if row.get('HIBP Breached', 'No') == 'Yes')
            hibp_total_exposures = sum(int(row.get('HIBP Breach Count', 0))
                                      for row in data['output_rows']
                                      if row.get('HIBP Breached', 'No') == 'Yes')
        except (KeyError, TypeError) as e:
            if logger:
                logger.error(f"Error processing data for domain {domain}: {str(e)}")
            content += create_error_message("Error processing data. Some metrics may be unavailable.")
            total_accounts = 0
            cracked = 0
            uncracked = 0
            out_of_compliance = 0
            non_expiring = 0
            hibp_breached = 0
            hibp_total_exposures = 0

        if total_accounts > 0:
            percent_cracked = round(cracked/total_accounts*100, 1)
            round(uncracked/total_accounts*100, 1)
            percent_compliance = round(out_of_compliance/total_accounts*100, 1) if total_accounts > 0 else 0
            percent_nonexpiring = round(non_expiring/total_accounts*100, 1) if total_accounts > 0 else 0
            percent_hibp = round(hibp_breached/total_accounts*100, 1) if total_accounts > 0 else 0
        else:
            percent_cracked = 0
            percent_compliance = 0
            percent_nonexpiring = 0
            percent_hibp = 0

        # Overview section with Bootstrap metric cards
        content += '<h2 class="mb-4"><i class="bi bi-bar-chart me-2"></i>Overview</h2>'

        content += create_overview_section({
            'Total Accounts': {
                'value': total_accounts,
                'icon': 'people-fill',
                'bg_class': 'bg-primary',
                'subtitle': f'{domain}'
            },
            'Cracked Passwords': {
                'value': f'{cracked} ({percent_cracked}%)',
                'icon': 'key-fill',
                'bg_class': 'bg-danger',
                'subtitle': f'{uncracked} uncracked'
            },
            'Out of Compliance': {
                'value': f'{out_of_compliance} ({percent_compliance}%)',
                'icon': 'shield-exclamation',
                'bg_class': 'bg-warning',
                'text_class': 'text-dark',
                'subtitle': 'Policy violations'
            },
            'Non-Expiring': {
                'value': f'{non_expiring} ({percent_nonexpiring}%)',
                'icon': 'clock-history',
                'bg_class': 'bg-info',
                'text_class': 'text-dark',
                'subtitle': 'Never expires'
            }
        })

        # HIBP stats card
        if hibp_breached > 0:
            content += f"""
            <div class="alert alert-danger" role="alert">
                <h5 class="alert-heading"><i class="bi bi-exclamation-triangle-fill me-2"></i>Have I Been Pwned (HIBP) Breach Exposure</h5>
                <p class="mb-0"><strong>{hibp_breached} accounts ({percent_hibp}%)</strong> have passwords found in <strong>{hibp_total_exposures:,}</strong> data breaches.</p>
            </div>
            """

        # Add risk score explanation
        content += RISK_SCORE_EXPLANATION

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

            # Risk Distribution Card
            risk_content = f"""
            <p class="lead">Risk levels of the {cracked} cracked passwords in {domain}, assessed by length, complexity, and privilege.</p>

            <div class="row g-3 mb-4">
                <div class="col-md-4">
                    <div class="card">
                        <div class="card-body text-center">
                            <h6 class="text-muted">Overall Risk</h6>
                            <p class="display-6 mb-0">{domain_risk.get('risk_score', 'N/A')}<small>/10.0</small></p>
                            <p class="mb-0">{create_risk_badge(domain_risk.get('overall_risk_level', 'Unknown'))}</p>
                        </div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card">
                        <div class="card-body text-center">
                            <h6 class="text-muted">Average Score</h6>
                            <p class="display-6 mb-0">{domain_risk.get('avg_score', 'N/A')}<small>/10.0</small></p>
                        </div>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card">
                        <div class="card-body text-center">
                            <h6 class="text-muted">Maximum Score</h6>
                            <p class="display-6 mb-0">{domain_risk.get('max_score', 'N/A')}<small>/10.0</small></p>
                        </div>
                    </div>
                </div>
            </div>

            <h5 class="mb-3">Distribution by Risk Level</h5>
            {get_risk_distribution_html(risk_distribution, total_risk_accounts)}
            """

            content += create_bootstrap_card('Risk Distribution', risk_content, icon='speedometer')

        except Exception as e:
            if logger:
                logger.error(f"Error processing risk distribution for domain {domain}: {str(e)}")
            content += create_bootstrap_card(
                'Risk Distribution',
                create_error_message("Error processing risk distribution data."),
                header_bg='bg-danger',
                icon='exclamation-triangle'
            )

        # Add risk level visualization if available
        vis_html = add_visualization_to_html(visuals, 'risk_levels', 'Risk Levels Chart')
        if vis_html:
            content += vis_html

        # BloodHound insights section
        try:
            cracked_da_accounts = [row for row in data['output_rows']
                                  if row['Password Length'] != 'N/A' and
                                  row.get('DA Domains', 'None') not in ('None', 'Unknown')]

            if cracked_da_accounts:
                da_content = f"""
                <div class="alert alert-danger" role="alert">
                    <i class="bi bi-exclamation-triangle-fill me-2"></i>
                    <strong>{len(cracked_da_accounts)} cracked accounts</strong> have pathways to Domain Admin privileges in {domain}.
                </div>
                <div class="table-responsive">
                    <table class="table table-hover table-striped table-bordered">
                        <thead class="table-dark">
                            <tr>
                                <th>Username</th>
                                <th>Password</th>
                                <th>DA Domains</th>
                                <th>Risk Level</th>
                                <th>Risk Vector</th>
                            </tr>
                        </thead>
                        <tbody>
                """

                # Create individual rows for each account with clickable usernames
                for acc in cracked_da_accounts:
                    username = acc.get('Username', 'Unknown')
                    password = acc.get('Password', 'N/A')
                    da_domains = acc.get('DA Domains', 'None')
                    risk_level = acc.get('Risk Level', 'Unknown')
                    risk_vector = acc.get('Risk Vector', 'N/A')

                    da_content += f"""
                        <tr>
                            <td>
                                <a href="#" class="user-detail-link text-decoration-none"
                                   data-username="{username}"
                                   data-coreui-toggle="offcanvas"
                                   data-coreui-target="#userDetailOffcanvas">
                                    <code>{username}</code>
                                </a>
                            </td>
                            <td><code>{password}</code></td>
                            <td><span class="badge bg-warning text-dark">{da_domains}</span></td>
                            <td>{create_risk_badge(risk_level)}</td>
                            <td><small class="font-monospace">{risk_vector}</small></td>
                        </tr>
                    """

                da_content += """
                        </tbody>
                    </table>
                </div>
                """

                content += create_bootstrap_card(
                    'BloodHound Insights - Domain Admin Pathways',
                    da_content,
                    header_bg='bg-danger',
                    icon='diagram-3'
                )
            else:
                content += create_bootstrap_card(
                    'BloodHound Insights - Domain Admin Pathways',
                    '<div class="alert alert-success"><i class="bi bi-check-circle me-2"></i>No cracked accounts with DA pathways found.</div>',
                    header_bg='bg-success',
                    icon='shield-check'
                )
        except Exception as e:
            if logger:
                logger.error(f"Error processing DA accounts for domain {domain}: {str(e)}")
            content += create_bootstrap_card(
                'BloodHound Insights',
                create_error_message("Error processing DA accounts data."),
                header_bg='bg-danger',
                icon='exclamation-triangle'
            )

        # Add all standard visualizations
        content += add_standard_visualizations_html(visuals, domain)

        # Generate user details JSON for offcanvas
        try:
            user_details_json = generate_user_details_json_single(data['output_rows'])
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
        html = html_head(f"Password Security Report - {domain}", enable_sidebar=True)
        html += create_page_wrapper(content, navbar, sidebar)
        html += """
</body>
</html>
        """

        # Write to file
        from core import config as config_module
        html_dir = getattr(config_module, 'html_reports_folder', Path('output/html_report'))
        output_path = html_dir / f'{domain}_report.html'
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
    """Add standard set of visualizations to HTML report using Bootstrap cards."""
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
        ],
        'hibp_analysis': [
            ('hibp_breach_distribution', 'HIBP Breach Distribution'),
            ('hibp_top_breached', 'Top Breached Passwords'),
            ('hibp_vs_risk', 'HIBP Breach Count vs Risk Score')
        ]
    }

    for section, vis_items in visualization_sets.items():
        section_title = section.replace('_', ' ').title()
        section_html = f'<h2 class="mb-4 mt-5"><i class="bi bi-graph-up me-2"></i>{section_title}</h2>\n<div class="row g-4">\n'
        section_has_content = False

        for vis_type, title in vis_items:
            vis_html = add_visualization_to_html(visuals, vis_type, title)
            if vis_html:
                # Wrap in Bootstrap column
                section_html += f'<div class="col-12 col-lg-6">\n{vis_html}\n</div>\n'
                section_has_content = True

        section_html += "</div>\n"
        if section_has_content:
            html += section_html

    return html