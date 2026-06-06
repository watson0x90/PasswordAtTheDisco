# reports/html/single_domain.py
"""
Single domain report generation module.
"""

import json
import os
from pathlib import Path

from report_lib.standalone_html.components import (
    RISK_SCORE_EXPLANATION,
    create_breadcrumb,
    create_error_message,
    create_navbar,
    create_overview_section,
    create_page_wrapper,
    create_risk_badge,
    create_sidebar,
    create_user_detail_offcanvas,
    get_risk_distribution_html,
    html_head,
)
from report_lib.standalone_html.scripts import USER_DETAIL_JS
from report_lib.templating import render, render_macro
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
        domains = [domain]
        navbar = create_navbar(current_page=f'domain_{domain}', include_search=True, include_export=True)
        sidebar = create_sidebar(current_page=f'domain_{domain}', domains=domains)
        breadcrumb_html = create_breadcrumb([
            ('Main Report', './main.html'),
            ('Search', './search.html'),
            (f'{domain} Report', None)
        ])

        counts_error_html = ''
        try:
            cracked_rows = [row for row in data['output_rows'] if row.get('Password Length', 'N/A') != 'N/A']
            total_accounts = len(data['output_rows'])
            cracked = len(cracked_rows)
            uncracked = total_accounts - cracked
            out_of_compliance = sum(1 for row in data['output_rows']
                                   if row.get('Days Out of Compliance', 'Unknown') not in ('Unknown', 'N/A')
                                   and int(row.get('Days Out of Compliance', 0)) > 0)
            non_expiring = sum(1 for row in data['output_rows']
                              if row.get('Password Set to Expire', 'Unknown') == 'No')
            hibp_breached = sum(1 for row in data['output_rows']
                               if row.get('HIBP Breached', 'No') == 'Yes')
            hibp_total_exposures = sum(int(row.get('HIBP Breach Count', 0))
                                      for row in data['output_rows']
                                      if row.get('HIBP Breached', 'No') == 'Yes')
        except (KeyError, TypeError) as e:
            if logger:
                logger.error(f"Error processing data for domain {domain}: {str(e)}")
            counts_error_html = create_error_message("Error processing data. Some metrics may be unavailable.")
            total_accounts = 0
            cracked = 0
            uncracked = 0
            out_of_compliance = 0
            non_expiring = 0
            hibp_breached = 0
            hibp_total_exposures = 0
            cracked_rows = []

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

        overview_html = create_overview_section({
            'Total Accounts': {'value': total_accounts, 'icon': 'people-fill', 'bg_class': 'bg-primary', 'subtitle': f'{domain}'},
            'Cracked Passwords': {'value': f'{cracked} ({percent_cracked}%)', 'icon': 'key-fill', 'bg_class': 'bg-danger', 'subtitle': f'{uncracked} uncracked'},
            'Out of Compliance': {'value': f'{out_of_compliance} ({percent_compliance}%)', 'icon': 'shield-exclamation', 'bg_class': 'bg-warning', 'text_class': 'text-dark', 'subtitle': 'Policy violations'},
            'Non-Expiring': {'value': f'{non_expiring} ({percent_nonexpiring}%)', 'icon': 'clock-history', 'bg_class': 'bg-info', 'text_class': 'text-dark', 'subtitle': 'Never expires'}
        })

        risk_error = False
        risk_error_html = ''
        risk_distribution_list_html = ''
        overall_risk_badge = ''
        risk_score_disp = avg_score_disp = max_score_disp = 'N/A'
        try:
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
                risk_distribution = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
                for row in cracked_rows:
                    risk_level = row.get('Risk Level', 'Unknown')
                    if risk_level in risk_distribution:
                        risk_distribution[risk_level] += 1
                if cracked > 0:
                    scores = [row.get('Score', 0) for row in cracked_rows if 'Score' in row]
                    avg_score = sum(scores) / len(scores) if scores else 0
                    max_score = max(scores) if scores else 0
                    if avg_score >= 8.0:
                        overall_level = "Critical"
                    elif avg_score >= 6.0:
                        overall_level = "High"
                    elif avg_score >= 4.0:
                        overall_level = "Medium"
                    else:
                        overall_level = "Low"
                    domain_risk = {'risk_score': round(avg_score, 1), 'overall_risk_level': overall_level, 'avg_score': round(avg_score, 1), 'max_score': round(max_score, 1)}
                else:
                    domain_risk = {'risk_score': 'N/A', 'overall_risk_level': 'Unknown', 'avg_score': 'N/A', 'max_score': 'N/A'}

            total_risk_accounts = sum(risk_distribution.values())
            risk_score_disp = domain_risk.get('risk_score', 'N/A')
            avg_score_disp = domain_risk.get('avg_score', 'N/A')
            max_score_disp = domain_risk.get('max_score', 'N/A')
            overall_risk_badge = create_risk_badge(domain_risk.get('overall_risk_level', 'Unknown'))
            risk_distribution_list_html = get_risk_distribution_html(risk_distribution, total_risk_accounts)
        except Exception as e:
            if logger:
                logger.error(f"Error processing risk distribution for domain {domain}: {str(e)}")
            risk_error = True
            risk_error_html = create_error_message("Error processing risk distribution data.")

        risk_viz_html = add_visualization_to_html(visuals, 'risk_levels', 'Risk Levels Chart') or ''

        da_error = False
        da_present = False
        da_error_html = ''
        da_table_html = ''
        da_count = 0
        try:
            cracked_da_accounts = [row for row in data['output_rows']
                                  if row['Password Length'] != 'N/A' and
                                  row.get('DA Domains', 'None') not in ('None', 'Unknown')]
            if cracked_da_accounts:
                da_present = True
                da_count = len(cracked_da_accounts)
                da_columns = [
                    {"header": "Username", "field": "Username", "kind": "user_link"},
                    {"header": "Password", "field": "Password", "kind": "code"},
                    {"header": "DA Domains", "field": "DA Domains", "kind": "badge_warn"},
                    {"header": "Risk Level", "field": "Risk Level", "kind": "risk_badge"},
                    {"header": "Risk Vector", "field": "Risk Vector", "kind": "small_mono"},
                ]
                da_table_html = render_macro("partials/tables.html.j2", "account_table", da_columns, cracked_da_accounts)
        except Exception as e:
            if logger:
                logger.error(f"Error processing DA accounts for domain {domain}: {str(e)}")
            da_error = True
            da_error_html = create_error_message("Error processing DA accounts data.")

        standard_viz_html = add_standard_visualizations_html(visuals, domain)

        try:
            user_details_json = generate_user_details_json_single(data['output_rows'])
            user_details_json_str = json.dumps(user_details_json, indent=2)
        except Exception as e:
            if logger:
                logger.error(f"Error generating user details JSON: {str(e)}")
            user_details_json_str = '{}'

        offcanvas_html = create_user_detail_offcanvas()
        user_detail_script = USER_DETAIL_JS.replace('{USER_DATA_JSON}', user_details_json_str)

        content = render(
            "partials/single_domain_content.html.j2",
            domain=domain, breadcrumb_html=breadcrumb_html, counts_error_html=counts_error_html,
            overview_html=overview_html, has_hibp=hibp_breached > 0, hibp_breached=hibp_breached,
            percent_hibp=percent_hibp, hibp_total_exposures=hibp_total_exposures,
            risk_explanation=RISK_SCORE_EXPLANATION, risk_error=risk_error, risk_error_html=risk_error_html,
            cracked=cracked, risk_score_disp=risk_score_disp, avg_score_disp=avg_score_disp,
            max_score_disp=max_score_disp, overall_risk_badge=overall_risk_badge,
            risk_distribution_list_html=risk_distribution_list_html, risk_viz_html=risk_viz_html,
            da_error=da_error, da_present=da_present, da_count=da_count, da_error_html=da_error_html,
            da_table_html=da_table_html, standard_viz_html=standard_viz_html,
            offcanvas_html=offcanvas_html, user_detail_script=user_detail_script,
        )

        html = html_head(f"Password Security Report - {domain}", enable_sidebar=True)
        html += create_page_wrapper(content, navbar, sidebar)
        html += """
</body>
</html>
        """

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