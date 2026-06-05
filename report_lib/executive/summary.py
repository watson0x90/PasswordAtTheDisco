"""
Executive summary generation for Password!AtTheDisco.

Provides high-level business-focused security assessments including:
- Security posture scoring (0-100)
- Business impact analysis
- Top risk summaries
- Remediation roadmap
"""

import os
from pathlib import Path
from datetime import datetime
from report_lib.standalone_html.components import (
    html_head, create_navbar, create_sidebar, create_page_wrapper, create_breadcrumb
)


def calculate_security_posture_score(all_domain_results):
    """
    Calculate overall security posture score (0-100) based on password audit results.

    Score breakdown:
    - 100-85: GREEN (Strong) - Minimal risk, strong password practices
    - 84-70: YELLOW (Fair) - Moderate risk, improvement needed
    - 69-0: RED (Weak) - Significant risk, immediate action required

    Args:
        all_domain_results: Dictionary of domain results from analysis

    Returns:
        tuple: (score, rating, color, breakdown)
    """
    total_accounts = 0
    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0

    cracked_count = 0
    uncracked_count = 0

    da_pathway_count = 0
    shared_password_count = 0
    policy_violation_count = 0

    for domain, result in all_domain_results.items():
        output_rows = result.get('output_rows', [])
        total_accounts += len(output_rows)

        for row in output_rows:
            risk_level = row.get('Risk Level', 'Unknown')
            if risk_level == 'Critical':
                critical_count += 1
            elif risk_level == 'High':
                high_count += 1
            elif risk_level == 'Medium':
                medium_count += 1
            elif risk_level == 'Low':
                low_count += 1

            # Track cracked vs uncracked
            account_type = row.get('Type')

            # Fallback: Infer type from Password Length if Type is not set (backward compatibility)
            if account_type is None:
                pw_length = row.get('Password Length', '')
                if pw_length == 'N/A':
                    account_type = 'Uncracked'
                else:
                    account_type = 'Cracked'

            if account_type == 'Cracked':
                cracked_count += 1
            elif account_type == 'Uncracked':
                uncracked_count += 1

            # Track DA pathways
            da_domains = row.get('DA Domains', 'None')
            if da_domains not in ('None', 'Unknown', []):
                da_pathway_count += 1

            # Track shared passwords
            shared_with = row.get('Shared With', 0)
            if isinstance(shared_with, int) and shared_with > 0:
                shared_password_count += 1

            # Track policy violations
            meets_policy = row.get('Meets Policy', 'Unknown')
            if meets_policy == 'No':
                policy_violation_count += 1

    if total_accounts == 0:
        # Return empty breakdown structure with all expected keys
        empty_breakdown = {
            'risk_distribution_score': 0,
            'password_strength_score': 0,
            'privilege_risk_score': 0,
            'policy_compliance_score': 0,
            'total_accounts': 0,
            'critical_count': 0,
            'high_count': 0,
            'medium_count': 0,
            'low_count': 0,
            'cracked_count': 0,
            'uncracked_count': 0,
            'da_pathway_count': 0,
            'policy_violation_count': 0
        }
        return 0, "No Data", "secondary", empty_breakdown

    # Calculate component scores (each 0-100)

    # 1. Risk Distribution Score (40 points max)
    # Penalize critical and high risk accounts heavily
    risk_score = 100
    if total_accounts > 0:
        critical_penalty = (critical_count / total_accounts) * 100 * 2.0  # 2x weight
        high_penalty = (high_count / total_accounts) * 100 * 1.5  # 1.5x weight
        medium_penalty = (medium_count / total_accounts) * 100 * 0.5  # 0.5x weight
        risk_score = max(0, 100 - critical_penalty - high_penalty - medium_penalty)
    risk_score = (risk_score / 100) * 40  # Scale to 40 points

    # 2. Password Strength Score (30 points max)
    # Based on cracked vs uncracked ratio
    strength_score = 0
    if (cracked_count + uncracked_count) > 0:
        uncracked_ratio = uncracked_count / (cracked_count + uncracked_count)
        strength_score = uncracked_ratio * 30

    # 3. Privilege Risk Score (15 points max)
    # Penalize DA pathways with weak passwords
    privilege_score = 15
    if total_accounts > 0:
        da_ratio = da_pathway_count / total_accounts
        privilege_score = max(0, 15 - (da_ratio * 100))

    # 4. Policy Compliance Score (15 points max)
    # Reward policy compliance
    compliance_score = 0
    if total_accounts > 0:
        compliant_ratio = (total_accounts - policy_violation_count) / total_accounts
        compliance_score = compliant_ratio * 15

    # Total score
    final_score = round(risk_score + strength_score + privilege_score + compliance_score, 1)

    # Determine rating and color
    if final_score >= 85:
        rating = "Strong"
        color = "success"
    elif final_score >= 70:
        rating = "Fair"
        color = "warning"
    else:
        rating = "Weak"
        color = "danger"

    breakdown = {
        'risk_distribution_score': round(risk_score, 1),
        'password_strength_score': round(strength_score, 1),
        'privilege_risk_score': round(privilege_score, 1),
        'policy_compliance_score': round(compliance_score, 1),
        'total_accounts': total_accounts,
        'critical_count': critical_count,
        'high_count': high_count,
        'medium_count': medium_count,
        'low_count': low_count,
        'cracked_count': cracked_count,
        'uncracked_count': uncracked_count,
        'da_pathway_count': da_pathway_count,
        'shared_password_count': shared_password_count,
        'policy_violation_count': policy_violation_count
    }

    return final_score, rating, color, breakdown


def estimate_breach_impact(all_domain_results):
    """
    Estimate potential business impact of a breach.

    Returns:
        dict: Impact estimation with cost ranges and probability
    """
    total_critical = 0
    total_high = 0
    total_da_paths = 0

    for domain, result in all_domain_results.items():
        output_rows = result.get('output_rows', [])
        for row in output_rows:
            risk_level = row.get('Risk Level', 'Unknown')
            if risk_level == 'Critical':
                total_critical += 1
            elif risk_level == 'High':
                total_high += 1

            da_domains = row.get('DA Domains', 'None')
            if da_domains not in ('None', 'Unknown', []):
                total_da_paths += 1

    # Estimate breach probability (simplified model)
    if total_critical > 50 or total_da_paths > 20:
        probability = "Very High"
        probability_pct = ">75%"
    elif total_critical > 20 or total_da_paths > 10:
        probability = "High"
        probability_pct = "50-75%"
    elif total_critical > 5 or total_da_paths > 3:
        probability = "Medium"
        probability_pct = "25-50%"
    else:
        probability = "Low"
        probability_pct = "<25%"

    # Cost estimates (industry averages)
    # Source: IBM Cost of Data Breach Report
    if total_critical > 50:
        cost_range = "$1M - $5M+"
        recovery_time = "6-12 months"
    elif total_critical > 20:
        cost_range = "$500K - $1M"
        recovery_time = "3-6 months"
    elif total_critical > 5:
        cost_range = "$100K - $500K"
        recovery_time = "1-3 months"
    else:
        cost_range = "$50K - $100K"
        recovery_time = "2-4 weeks"

    return {
        'probability': probability,
        'probability_percentage': probability_pct,
        'estimated_cost': cost_range,
        'recovery_time': recovery_time,
        'critical_accounts': total_critical,
        'high_risk_accounts': total_high,
        'da_pathways': total_da_paths
    }


def get_top_risks(all_domain_results, limit=10):
    """
    Get top N riskiest accounts across all domains.

    Args:
        all_domain_results: Dictionary of domain results
        limit: Maximum number of top risks to return

    Returns:
        list: Top risk accounts with details
    """
    all_accounts = []

    for domain, result in all_domain_results.items():
        output_rows = result.get('output_rows', [])
        for row in output_rows:
            all_accounts.append({
                'domain': domain,
                'username': row.get('Username', 'Unknown'),
                'risk_level': row.get('Risk Level', 'Unknown'),
                'score': row.get('Score', 0),
                'type': row.get('Type', 'Unknown'),
                'da_domains': row.get('DA Domains', 'None'),
                'controlled_objects': row.get('Controlled Object Count', 0),
                'shared_with': row.get('Shared With', 0),
                'complexity': row.get('Complexity Label', 'Unknown'),
                'policy_violations': row.get('Policy Violations', [])
            })

    # Sort by score (descending), then by risk level priority
    risk_priority = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1, 'Unknown': 0}
    sorted_accounts = sorted(
        all_accounts,
        key=lambda x: (risk_priority.get(x['risk_level'], 0), x['score']),
        reverse=True
    )

    return sorted_accounts[:limit]


def generate_remediation_roadmap(all_domain_results):
    """
    Generate a prioritized remediation roadmap.

    Returns:
        list: Remediation phases with timelines and effort estimates
    """
    breakdown = calculate_security_posture_score(all_domain_results)[3]

    critical_count = breakdown.get('critical_count', 0)
    high_count = breakdown.get('high_count', 0)
    da_pathway_count = breakdown.get('da_pathway_count', 0)
    policy_violation_count = breakdown.get('policy_violation_count', 0)

    roadmap = []

    # Phase 1: Critical Immediate Actions
    if critical_count > 0 or da_pathway_count > 0:
        roadmap.append({
            'phase': 'Phase 1: Critical Immediate Actions',
            'timeline': '0-2 weeks',
            'priority': 'Critical',
            'tasks': [
                f'Reset {critical_count} critical risk passwords immediately',
                f'Review and secure {da_pathway_count} accounts with Domain Admin pathways',
                'Enable MFA for all privileged accounts',
                'Audit and revoke excessive permissions'
            ],
            'effort': 'High',
            'resources': 'Security team + IT operations'
        })

    # Phase 2: High Risk Mitigation
    if high_count > 0:
        roadmap.append({
            'phase': 'Phase 2: High Risk Mitigation',
            'timeline': '2-6 weeks',
            'priority': 'High',
            'tasks': [
                f'Reset {high_count} high-risk passwords',
                'Implement password complexity monitoring',
                'Deploy password manager enterprise-wide',
                'Conduct security awareness training'
            ],
            'effort': 'Medium',
            'resources': 'Security team + HR'
        })

    # Phase 3: Policy Enforcement
    if policy_violation_count > 0:
        roadmap.append({
            'phase': 'Phase 3: Policy Enforcement',
            'timeline': '1-3 months',
            'priority': 'Medium',
            'tasks': [
                f'Address {policy_violation_count} policy violations',
                'Update Group Policy Objects (GPO) for password policies',
                'Implement automated compliance checks',
                'Regular password audits (quarterly)'
            ],
            'effort': 'Medium',
            'resources': 'IT operations + Compliance'
        })

    # Phase 4: Long-term Improvements
    roadmap.append({
        'phase': 'Phase 4: Long-term Improvements',
        'timeline': '3-6 months',
        'priority': 'Low',
        'tasks': [
            'Implement passwordless authentication where possible',
            'Deploy FIDO2/WebAuthn for critical systems',
            'Integrate with SIEM for anomaly detection',
            'Establish continuous password monitoring'
        ],
        'effort': 'Low',
        'resources': 'Security architecture team'
    })

    return roadmap


def calculate_domain_scores(all_domain_results):
    """
    Calculate individual security posture scores for each domain.

    Args:
        all_domain_results: Dictionary of domain results from analysis

    Returns:
        dict: Dictionary mapping domain names to their scores and breakdowns
    """
    domain_scores = {}

    for domain, result in all_domain_results.items():
        # Create a single-domain dict to pass to scoring function
        single_domain = {domain: result}
        score, rating, color, breakdown = calculate_security_posture_score(single_domain)

        domain_scores[domain] = {
            'score': score,
            'rating': rating,
            'color': color,
            'breakdown': breakdown
        }

    # Sort by score (lowest to highest - worst domains first)
    sorted_domains = sorted(domain_scores.items(), key=lambda x: x[1]['score'])

    return dict(sorted_domains)


def identify_quick_wins(all_domain_results, limit=5):
    """
    Identify quick win opportunities - high impact, low effort improvements.

    Args:
        all_domain_results: Dictionary of domain results
        limit: Maximum number of quick wins to return

    Returns:
        list: Quick win opportunities with impact and effort estimates
    """
    quick_wins = []

    # Collect all accounts across domains
    all_accounts = []
    for domain, result in all_domain_results.items():
        for row in result.get('output_rows', []):
            all_accounts.append({
                'domain': domain,
                'username': row.get('Username'),
                'password': row.get('Password'),
                'risk_level': row.get('Risk Level'),
                'da_domains': row.get('DA Domains'),
                'controlled_objects': row.get('Controlled Object Count'),
                'enabled': row.get('Enabled'),
                'meets_policy': row.get('Meets Policy'),
                'policy_violations': row.get('Policy Violations', ''),
                'type': row.get('Type')
            })

    # Quick Win 1: Common weak passwords
    common_passwords = {}
    for acc in all_accounts:
        if acc['type'] == 'Cracked' and acc['risk_level'] in ('Critical', 'High'):
            pw = acc['password']
            if pw and len(pw) < 12:  # Short password
                if pw not in common_passwords:
                    common_passwords[pw] = []
                common_passwords[pw].append(acc['username'])

    # Find most common weak passwords
    if common_passwords:
        most_common = sorted(common_passwords.items(), key=lambda x: len(x[1]), reverse=True)[0]
        if len(most_common[1]) >= 3:  # At least 3 accounts with same weak password
            quick_wins.append({
                'category': 'Common Weak Passwords',
                'description': f'{len(most_common[1])} accounts use the same weak password variant (length < 12 characters). These accounts are high-risk due to password reuse and weak complexity.',
                'action': f'Force password reset for {len(most_common[1])} accounts using bulk password reset',
                'expected_outcome': f'Eliminates {len(most_common[1])} critical/high risk accounts immediately',
                'impact': 'High',
                'effort': 'Low'
            })

    # Quick Win 2: DA pathway accounts
    da_accounts = [acc for acc in all_accounts if acc['da_domains'] not in ('None', 'Unknown', [])
                   and acc['risk_level'] in ('Critical', 'High')]
    if da_accounts and len(da_accounts) >= 5:
        quick_wins.append({
            'category': 'Domain Admin Pathway Protection',
            'description': f'{len(da_accounts)} accounts with paths to Domain Admin lack adequate protection. These accounts are prime targets for privilege escalation attacks.',
            'action': f'Enable MFA for {len(da_accounts)} Domain Admin pathway accounts via Group Policy',
            'expected_outcome': 'Protects all domain admin escalation paths from credential-based compromise',
            'impact': 'High',
            'effort': 'Low'
        })

    # Quick Win 3: Disabled accounts with high privileges
    disabled_high_priv = [acc for acc in all_accounts if acc['enabled'] == 'False'
                          and acc['controlled_objects'] != 'Unknown'
                          and isinstance(acc['controlled_objects'], (int, str))
                          and (int(acc['controlled_objects']) if str(acc['controlled_objects']).isdigit() else 0) > 10]
    if disabled_high_priv and len(disabled_high_priv) >= 3:
        quick_wins.append({
            'category': 'Disabled Account Cleanup',
            'description': f'{len(disabled_high_priv)} disabled accounts still retain excessive permissions (>10 controlled objects). These represent dormant backdoors that could be re-enabled.',
            'action': f'Revoke permissions from {len(disabled_high_priv)} disabled accounts using automated PowerShell script',
            'expected_outcome': f'Reduces attack surface by eliminating {len(disabled_high_priv)} potential privilege escalation backdoors',
            'impact': 'Medium',
            'effort': 'Low'
        })

    # Quick Win 4: Policy violations - easy fixes
    simple_violations = [acc for acc in all_accounts if acc['meets_policy'] == 'No'
                        and 'Length' in str(acc['policy_violations'])]
    if simple_violations and len(simple_violations) >= 10:
        quick_wins.append({
            'category': 'Password Policy Compliance',
            'description': f'{len(simple_violations)} passwords violate only the minimum length requirement. These are simple fixes with high compliance impact.',
            'action': f'Enforce minimum password length for {len(simple_violations)} accounts via automated Group Policy',
            'expected_outcome': f'Brings {len(simple_violations)} accounts into full policy compliance',
            'impact': 'Medium',
            'effort': 'Low'
        })

    # Quick Win 5: Uncracked but HIBP exposed accounts
    exposed_accounts = [acc for acc in all_accounts if acc['type'] == 'Uncracked'
                       and acc['risk_level'] in ('Critical', 'High')]
    if exposed_accounts and len(exposed_accounts) >= 5:
        quick_wins.append({
            'category': 'Preemptive Password Reset',
            'description': f'{len(exposed_accounts)} uncracked accounts show high-risk indicators (HIBP exposure or DA pathways). While passwords are not yet compromised, they represent significant future risk.',
            'action': f'Schedule forced password reset for {len(exposed_accounts)} high-risk uncracked accounts',
            'expected_outcome': 'Preemptively secures vulnerable accounts before they can be compromised',
            'impact': 'Medium',
            'effort': 'Low'
        })

    # Return top N quick wins (no sorting needed - already prioritized)
    return quick_wins[:limit]


def calculate_cost_risk_matrix(all_domain_results):
    """
    Calculate cost vs. risk analysis and ROI for remediation.

    Args:
        all_domain_results: Dictionary of domain results

    Returns:
        dict: Cost/risk analysis with ROI calculations
    """
    # Get breakdown from overall scoring
    _, _, _, breakdown = calculate_security_posture_score(all_domain_results)

    critical_count = breakdown.get('critical_count', 0)
    breakdown.get('high_count', 0)
    da_pathway_count = breakdown.get('da_pathway_count', 0)
    breakdown.get('total_accounts', 0)

    # Breach cost estimation (industry averages from IBM Cost of Data Breach Report)
    # Average cost per compromised record: ~$150
    # Domain compromise multiplier: 100x
    critical_exposure = critical_count * 50000  # $50K per critical account
    da_exposure = da_pathway_count * 100000  # $100K per DA pathway
    total_exposure = critical_exposure + da_exposure

    # Remediation cost estimation
    phase1_cost = 15000  # Password resets + MFA deployment
    phase2_cost = 30000  # Training + password manager
    phase3_cost = 20000  # GPO updates + monitoring tools
    total_remediation = phase1_cost + phase2_cost + phase3_cost

    # ROI calculation
    roi_ratio = total_exposure / total_remediation if total_remediation > 0 else 0

    # Priority matrix categorization
    priority_matrix = {
        'high_impact_low_cost': [],
        'high_impact_high_cost': [],
        'low_impact_low_cost': [],
        'low_impact_high_cost': []
    }

    # Categorize actions
    if critical_count > 0:
        priority_matrix['high_impact_low_cost'].append('Reset common weak passwords')
        priority_matrix['high_impact_low_cost'].append('Force password expiry for critical accounts')

    if da_pathway_count > 0:
        priority_matrix['high_impact_low_cost'].append('Enable MFA for DA pathway accounts')
        priority_matrix['high_impact_low_cost'].append('Audit and reduce DA group membership')

    priority_matrix['high_impact_high_cost'].append('Deploy enterprise password manager')
    priority_matrix['high_impact_high_cost'].append('Implement FIDO2/WebAuthn')
    priority_matrix['high_impact_high_cost'].append('Security awareness training program')

    priority_matrix['low_impact_low_cost'].append('Enable password complexity GPO')
    priority_matrix['low_impact_low_cost'].append('Set up password expiration alerts')

    return {
        'total_exposure': total_exposure,
        'critical_exposure': critical_exposure,
        'da_exposure': da_exposure,
        'total_remediation_cost': total_remediation,
        'phase1_cost': phase1_cost,
        'phase2_cost': phase2_cost,
        'phase3_cost': phase3_cost,
        'roi_ratio': roi_ratio,
        'priority_matrix': priority_matrix
    }


def generate_executive_summary(all_domain_results, metadata, logger=None):
    """
    Generate executive summary HTML report.

    Args:
        all_domain_results: Dictionary of domain analysis results
        metadata: Report metadata (run_id, timestamp, domains, etc.)
        logger: Optional logger instance

    Returns:
        Path: Path to generated HTML file
    """
    try:
        # Calculate security posture
        score, rating, color, breakdown = calculate_security_posture_score(all_domain_results)

        # Estimate business impact
        estimate_breach_impact(all_domain_results)

        # Get top risks
        top_risks = get_top_risks(all_domain_results, limit=10)

        # Generate remediation roadmap
        roadmap = generate_remediation_roadmap(all_domain_results)

        # Calculate domain-level scores
        domain_scores = calculate_domain_scores(all_domain_results)

        # Identify quick wins
        quick_wins = identify_quick_wins(all_domain_results)

        # Calculate cost vs. risk matrix
        cost_risk_matrix = calculate_cost_risk_matrix(all_domain_results)

        # Create navbar and sidebar
        domains = list(all_domain_results.keys())
        navbar = create_navbar(current_page='executive', include_search=True, include_export=True)
        sidebar = create_sidebar(current_page='executive', domains=domains)

        # Build content
        content = f"""
                {create_breadcrumb([
                    ('Main Report', './main.html'),
                    ('Executive Summary', None)
                ])}

                <div class="mb-4">
                    <h1 class="display-4"><i class="bi bi-clipboard-data me-3"></i>Executive Summary</h1>
                    <p class="lead text-muted">High-level security posture assessment for leadership</p>
                    <p class="text-muted"><small>Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</small></p>
                </div>

                <!-- Security Posture Score -->
                <div class="card mb-4 shadow">
                    <div class="card-header bg-{color} text-white">
                        <h3 class="mb-0"><i class="bi bi-shield-check me-2"></i>Security Posture Score</h3>
                    </div>
                    <div class="card-body">
                        <div class="row align-items-center">
                            <div class="col-md-4 text-center">
                                <h1 class="display-1 text-{color} mb-0">{score}</h1>
                                <p class="lead">/ 100</p>
                                <h4 class="text-{color}">{rating}</h4>
                            </div>
                            <div class="col-md-8">
                                <h5>Score Breakdown:</h5>
                                <div class="mb-2">
                                    <div class="d-flex justify-content-between">
                                        <span>Risk Distribution</span>
                                        <span>{breakdown['risk_distribution_score']}/40</span>
                                    </div>
                                    <div class="progress" style="height: 20px;">
                                        <div class="progress-bar bg-info" style="width: {max(2, (breakdown['risk_distribution_score']/40)*100)}%"></div>
                                    </div>
                                </div>
                                <div class="mb-2">
                                    <div class="d-flex justify-content-between">
                                        <span>Password Strength</span>
                                        <span>{breakdown['password_strength_score']}/30</span>
                                    </div>
                                    <div class="progress" style="height: 20px;">
                                        <div class="progress-bar bg-primary" style="width: {max(2, (breakdown['password_strength_score']/30)*100)}%"></div>
                                    </div>
                                </div>
                                <div class="mb-2">
                                    <div class="d-flex justify-content-between">
                                        <span>Privilege Risk</span>
                                        <span>{breakdown['privilege_risk_score']}/15</span>
                                    </div>
                                    <div class="progress" style="height: 20px;">
                                        <div class="progress-bar bg-warning" style="width: {max(2, (breakdown['privilege_risk_score']/15)*100)}%"></div>
                                    </div>
                                </div>
                                <div class="mb-2">
                                    <div class="d-flex justify-content-between">
                                        <span>Policy Compliance</span>
                                        <span>{breakdown['policy_compliance_score']}/15</span>
                                    </div>
                                    <div class="progress" style="height: 20px;">
                                        <div class="progress-bar bg-success" style="width: {max(2, (breakdown['policy_compliance_score']/15)*100)}%"></div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Domain-Level Breakdown -->
                <div class="card mb-4 shadow">
                    <div class="card-header bg-secondary text-white">
                        <h3 class="mb-0"><i class="bi bi-building me-2"></i>Domain-Level Breakdown</h3>
                    </div>
                    <div class="card-body">
                        <p class="text-muted mb-3">Security posture comparison across all analyzed domains</p>

                        <!-- Domain Summary Cards -->
                        <div class="row mb-4">
        """

        # Add domain summary cards (3 per row)
        for idx, (domain, domain_info) in enumerate(domain_scores.items()):
            breakdown_data = domain_info['breakdown']

            content += f"""
                            <div class="col-md-4 mb-3">
                                <div class="card h-100 border-{domain_info['color']}">
                                    <div class="card-header bg-{domain_info['color']} text-white">
                                        <h5 class="mb-0">{domain}</h5>
                                    </div>
                                    <div class="card-body">
                                        <div class="text-center mb-3">
                                            <h2 class="display-4 text-{domain_info['color']} mb-0">{domain_info['score']}</h2>
                                            <p class="text-muted">/ 100</p>
                                            <span class="badge bg-{domain_info['color']}">{domain_info['rating']}</span>
                                        </div>
                                        <hr>
                                        <div class="small">
                                            <div class="d-flex justify-content-between mb-1">
                                                <span>Total Accounts:</span>
                                                <strong>{breakdown_data['total_accounts']}</strong>
                                            </div>
                                            <div class="d-flex justify-content-between mb-1">
                                                <span>Critical:</span>
                                                <strong class="text-danger">{breakdown_data['critical_count']}</strong>
                                            </div>
                                            <div class="d-flex justify-content-between mb-1">
                                                <span>High:</span>
                                                <strong class="text-warning">{breakdown_data['high_count']}</strong>
                                            </div>
                                            <div class="d-flex justify-content-between mb-1">
                                                <span>DA Pathways:</span>
                                                <strong class="text-warning">{breakdown_data['da_pathway_count']}</strong>
                                            </div>
                                            <div class="d-flex justify-content-between">
                                                <span>Cracked:</span>
                                                <strong class="text-info">{breakdown_data['cracked_count']}</strong>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
            """

        content += """
                        </div>

                        <!-- Domain Comparison Table -->
                        <h5 class="mt-4 mb-3">Domain Comparison Table</h5>
                        <div class="table-responsive">
                            <table class="table table-hover table-striped">
                                <thead class="table-dark">
                                    <tr>
                                        <th>Rank</th>
                                        <th>Domain</th>
                                        <th>Score</th>
                                        <th>Rating</th>
                                        <th>Total Accounts</th>
                                        <th>Critical</th>
                                        <th>High</th>
                                        <th>DA Pathways</th>
                                        <th>Cracked</th>
                                        <th>Policy Violations</th>
                                    </tr>
                                </thead>
                                <tbody>
        """

        # Add domain comparison rows
        for idx, (domain, domain_info) in enumerate(domain_scores.items(), 1):
            breakdown_data = domain_info['breakdown']

            content += f"""
                                    <tr>
                                        <td><strong>#{idx}</strong></td>
                                        <td><strong>{domain}</strong></td>
                                        <td><span class="badge bg-{domain_info['color']}">{domain_info['score']}</span></td>
                                        <td>{domain_info['rating']}</td>
                                        <td>{breakdown_data['total_accounts']}</td>
                                        <td><span class="text-danger">{breakdown_data['critical_count']}</span></td>
                                        <td><span class="text-warning">{breakdown_data['high_count']}</span></td>
                                        <td><span class="text-warning">{breakdown_data['da_pathway_count']}</span></td>
                                        <td><span class="text-info">{breakdown_data['cracked_count']}</span></td>
                                        <td>{breakdown_data['policy_violation_count']}</td>
                                    </tr>
            """

        content += """
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <!-- Quick Wins -->
                <div class="card mb-4 shadow">
                    <div class="card-header bg-success text-white">
                        <h3 class="mb-0"><i class="bi bi-check2-circle me-2"></i>Quick Wins - High Impact, Low Effort</h3>
                    </div>
                    <div class="card-body">
                        <p class="text-muted mb-4">Prioritized actions that deliver maximum security improvement with minimal effort</p>
        """

        # Add quick wins
        if quick_wins:
            for idx, win in enumerate(quick_wins, 1):
                # Determine badge colors
                impact_color = 'danger' if win['impact'] == 'High' else 'warning' if win['impact'] == 'Medium' else 'info'
                effort_color = 'success' if win['effort'] == 'Low' else 'warning' if win['effort'] == 'Medium' else 'danger'

                content += f"""
                        <div class="mb-4 p-3 border-start border-success border-5 bg-light">
                            <div class="d-flex justify-content-between align-items-start mb-2">
                                <h5 class="mb-0">
                                    <span class="badge bg-secondary me-2">{idx}</span>
                                    {win['category']}
                                </h5>
                                <div>
                                    <span class="badge bg-{impact_color} me-1">Impact: {win['impact']}</span>
                                    <span class="badge bg-{effort_color}">Effort: {win['effort']}</span>
                                </div>
                            </div>
                            <p class="mb-2">{win['description']}</p>
                            <div class="alert alert-success mb-2">
                                <strong><i class="bi bi-lightbulb me-2"></i>Action:</strong> {win['action']}
                            </div>
                            <div class="small text-muted">
                                <i class="bi bi-graph-up me-1"></i>
                                <strong>Expected Outcome:</strong> {win['expected_outcome']}
                            </div>
                        </div>
                """
        else:
            content += """
                        <div class="alert alert-info">
                            <i class="bi bi-info-circle me-2"></i>
                            No quick win opportunities identified at this time.
                        </div>
            """

        content += """
                    </div>
                </div>

                <!-- Cost vs. Risk Prioritization Matrix -->
                <div class="card mb-4 shadow">
                    <div class="card-header bg-info text-white">
                        <h3 class="mb-0"><i class="bi bi-coin me-2"></i>Cost vs. Risk Prioritization</h3>
                    </div>
                    <div class="card-body">
                        <p class="text-muted mb-4">Return on investment analysis for password security remediation</p>

                        <!-- ROI Summary -->
                        <div class="row mb-4">
                            <div class="col-md-4">
                                <div class="card bg-danger text-white">
                                    <div class="card-body text-center">
                                        <h6>Breach Cost Exposure</h6>
                                        <h3>{cost_risk_matrix['breach_cost_exposure']}</h3>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-4">
                                <div class="card bg-warning text-dark">
                                    <div class="card-body text-center">
                                        <h6>Total Remediation Cost</h6>
                                        <h3>{cost_risk_matrix['total_remediation_cost']}</h3>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-4">
                                <div class="card bg-success text-white">
                                    <div class="card-body text-center">
                                        <h6>ROI Ratio</h6>
                                        <h3>{cost_risk_matrix['roi_ratio']}</h3>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <div class="alert alert-success mb-4">
                            <i class="bi bi-check-circle me-2"></i>
                            <strong>Investment Justification:</strong> For every $1 spent on remediation, you reduce breach risk exposure by ${cost_risk_matrix['roi_ratio'].replace('x', '')} -
                            a strong return on security investment.
                        </div>

                        <!-- Priority Matrix -->
                        <h5 class="mb-3">Priority Matrix</h5>
                        <div class="row">
                            <div class="col-md-6">
                                <div class="card border-danger mb-3">
                                    <div class="card-header bg-danger text-white">
                                        <strong>High Impact, Low Cost</strong>
                                        <span class="badge bg-white text-danger float-end">DO FIRST</span>
                                    </div>
                                    <div class="card-body">
        """

        # Add high impact, low cost items
        hi_lc = cost_risk_matrix['priority_matrix']['high_impact_low_cost']
        if hi_lc:
            content += "<ul class='mb-0'>"
            for item in hi_lc:
                content += f"<li>{item}</li>"
            content += "</ul>"
        else:
            content += "<p class='text-muted mb-0'>No items in this category</p>"

        content += """
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="card border-warning mb-3">
                                    <div class="card-header bg-warning text-dark">
                                        <strong>High Impact, High Cost</strong>
                                        <span class="badge bg-dark float-end">PLAN & BUDGET</span>
                                    </div>
                                    <div class="card-body">
        """

        # Add high impact, high cost items
        hi_hc = cost_risk_matrix['priority_matrix']['high_impact_high_cost']
        if hi_hc:
            content += "<ul class='mb-0'>"
            for item in hi_hc:
                content += f"<li>{item}</li>"
            content += "</ul>"
        else:
            content += "<p class='text-muted mb-0'>No items in this category</p>"

        content += """
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div class="row">
                            <div class="col-md-6">
                                <div class="card border-info mb-3">
                                    <div class="card-header bg-info text-white">
                                        <strong>Low Impact, Low Cost</strong>
                                        <span class="badge bg-white text-info float-end">FILL GAPS</span>
                                    </div>
                                    <div class="card-body">
        """

        # Add low impact, low cost items
        li_lc = cost_risk_matrix['priority_matrix']['low_impact_low_cost']
        if li_lc:
            content += "<ul class='mb-0'>"
            for item in li_lc:
                content += f"<li>{item}</li>"
            content += "</ul>"
        else:
            content += "<p class='text-muted mb-0'>No items in this category</p>"

        content += """
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="card border-secondary mb-3">
                                    <div class="card-header bg-secondary text-white">
                                        <strong>Low Impact, High Cost</strong>
                                        <span class="badge bg-white text-secondary float-end">DEFER</span>
                                    </div>
                                    <div class="card-body">
        """

        # Add low impact, high cost items
        li_hc = cost_risk_matrix['priority_matrix']['low_impact_high_cost']
        if li_hc:
            content += "<ul class='mb-0'>"
            for item in li_hc:
                content += f"<li>{item}</li>"
            content += "</ul>"
        else:
            content += "<p class='text-muted mb-0'>No items in this category</p>"

        content += """
                                    </div>
                                </div>
                            </div>
                        </div>

                        <!-- Cost Breakdown -->
                        <h5 class="mt-4 mb-3">Remediation Cost Breakdown</h5>
                        <div class="table-responsive">
                            <table class="table table-bordered">
                                <thead class="table-light">
                                    <tr>
                                        <th>Phase</th>
                                        <th>Description</th>
                                        <th class="text-end">Estimated Cost</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <tr>
                                        <td><strong>Immediate (0-30 days)</strong></td>
                                        <td>Critical risk remediation, forced password resets, MFA enablement</td>
                                        <td class="text-end">{cost_risk_matrix['cost_breakdown']['immediate']}</td>
                                    </tr>
                                    <tr>
                                        <td><strong>Short-term (1-3 months)</strong></td>
                                        <td>High-risk account remediation, policy enforcement automation</td>
                                        <td class="text-end">{cost_risk_matrix['cost_breakdown']['short_term']}</td>
                                    </tr>
                                    <tr>
                                        <td><strong>Medium-term (3-6 months)</strong></td>
                                        <td>Medium-risk remediation, password manager deployment, training</td>
                                        <td class="text-end">{cost_risk_matrix['cost_breakdown']['medium_term']}</td>
                                    </tr>
                                    <tr class="table-secondary">
                                        <td colspan="2"><strong>Total Remediation Investment</strong></td>
                                        <td class="text-end"><strong>{cost_risk_matrix['total_remediation_cost']}</strong></td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <!-- Key Metrics -->
                <div class="row mb-4">
                    <div class="col-md-3">
                        <div class="card shadow-sm">
                            <div class="card-body text-center">
                                <h6 class="text-muted">Total Accounts</h6>
                                <h2 class="text-primary">{breakdown['total_accounts']:,}</h2>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card shadow-sm">
                            <div class="card-body text-center">
                                <h6 class="text-muted">Critical Risk</h6>
                                <h2 class="text-danger">{breakdown['critical_count']:,}</h2>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card shadow-sm">
                            <div class="card-body text-center">
                                <h6 class="text-muted">DA Pathways</h6>
                                <h2 class="text-warning">{breakdown['da_pathway_count']:,}</h2>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card shadow-sm">
                            <div class="card-body text-center">
                                <h6 class="text-muted">Passwords Cracked</h6>
                                <h2 class="text-info">{breakdown['cracked_count']:,}</h2>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Business Impact Analysis -->
                <div class="card mb-4 shadow">
                    <div class="card-header bg-danger text-white">
                        <h3 class="mb-0"><i class="bi bi-exclamation-triangle me-2"></i>Business Impact Assessment</h3>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-6">
                                <h5>Breach Probability</h5>
                                <p class="lead text-danger"><strong>{impact['probability']}</strong> ({impact['probability_percentage']})</p>
                                <h5 class="mt-3">Estimated Cost of Breach</h5>
                                <p class="lead"><strong>{impact['estimated_cost']}</strong></p>
                            </div>
                            <div class="col-md-6">
                                <h5>Recovery Time</h5>
                                <p class="lead"><strong>{impact['recovery_time']}</strong></p>
                                <h5 class="mt-3">Critical Exposure</h5>
                                <ul>
                                    <li>{impact['critical_accounts']} critical risk accounts</li>
                                    <li>{impact['da_pathways']} Domain Admin pathways exposed</li>
                                    <li>{impact['high_risk_accounts']} high-risk accounts</li>
                                </ul>
                            </div>
                        </div>
                        <div class="alert alert-warning mt-3" role="alert">
                            <i class="bi bi-info-circle me-2"></i>
                            <strong>Note:</strong> Cost estimates based on industry averages (IBM Cost of Data Breach Report).
                            Actual costs may vary based on organization size, industry, and breach scope.
                        </div>
                    </div>
                </div>

                <!-- Top Risks -->
                <div class="card mb-4 shadow">
                    <div class="card-header bg-warning text-dark">
                        <h3 class="mb-0"><i class="bi bi-lightning me-2"></i>Top 10 Riskiest Accounts</h3>
                    </div>
                    <div class="card-body p-0">
                        <div class="table-responsive">
                            <table class="table table-hover table-striped mb-0">
                                <thead class="table-dark">
                                    <tr>
                                        <th>#</th>
                                        <th>Username</th>
                                        <th>Domain</th>
                                        <th>Risk Level</th>
                                        <th>Score</th>
                                        <th>DA Pathway</th>
                                        <th>Controlled Objects</th>
                                    </tr>
                                </thead>
                                <tbody>
        """

        for idx, risk in enumerate(top_risks, 1):
            risk_badge = "<span class='badge bg-danger'>Critical</span>" if risk['risk_level'] == 'Critical' else \
                        "<span class='badge bg-warning text-dark'>High</span>" if risk['risk_level'] == 'High' else \
                        "<span class='badge bg-info'>Medium</span>" if risk['risk_level'] == 'Medium' else \
                        "<span class='badge bg-success'>Low</span>"

            has_da = "Yes" if risk['da_domains'] not in ('None', 'Unknown', []) else "No"
            da_badge = "<span class='badge bg-danger'>Yes</span>" if has_da == "Yes" else "<span class='badge bg-secondary'>No</span>"

            content += f"""
                                    <tr>
                                        <td>{idx}</td>
                                        <td><code>{risk['username']}</code></td>
                                        <td>{risk['domain']}</td>
                                        <td>{risk_badge}</td>
                                        <td><strong>{risk['score']}</strong></td>
                                        <td>{da_badge}</td>
                                        <td>{risk['controlled_objects']}</td>
                                    </tr>
            """

        content += """
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <!-- Remediation Roadmap -->
                <div class="card mb-4 shadow">
                    <div class="card-header bg-primary text-white">
                        <h3 class="mb-0"><i class="bi bi-map me-2"></i>Remediation Roadmap</h3>
                    </div>
                    <div class="card-body">
        """

        for phase in roadmap:
            priority_color = 'danger' if phase['priority'] == 'Critical' else \
                           'warning' if phase['priority'] == 'High' else \
                           'info' if phase['priority'] == 'Medium' else 'success'

            content += f"""
                        <div class="mb-4">
                            <h4>{phase['phase']} <span class="badge bg-{priority_color}">{phase['priority']}</span></h4>
                            <p><strong>Timeline:</strong> {phase['timeline']} | <strong>Effort:</strong> {phase['effort']} | <strong>Resources:</strong> {phase['resources']}</p>
                            <ul>
            """
            for task in phase['tasks']:
                content += f"<li>{task}</li>\n"

            content += """
                            </ul>
                        </div>
            """

        content += """
                    </div>
                </div>

                <!-- Recommendations -->
                <div class="card mb-4 shadow">
                    <div class="card-header bg-success text-white">
                        <h3 class="mb-0"><i class="bi bi-check-circle me-2"></i>Executive Recommendations</h3>
                    </div>
                    <div class="card-body">
                        <ol>
                            <li><strong>Immediate Action:</strong> Reset all critical risk passwords within 48 hours and enable MFA for privileged accounts.</li>
                            <li><strong>Short-term (1-3 months):</strong> Deploy enterprise password manager, conduct security awareness training, and enforce password policies via GPO.</li>
                            <li><strong>Medium-term (3-6 months):</strong> Implement automated password monitoring, integrate with SIEM, and establish quarterly audit cadence.</li>
                            <li><strong>Long-term (6-12 months):</strong> Transition to passwordless authentication (FIDO2/WebAuthn) for critical systems and establish continuous monitoring.</li>
                            <li><strong>Budget Allocation:</strong> Allocate resources for password management tools, security training, and potential incident response based on impact assessment.</li>
                        </ol>
                    </div>
                </div>
        """

        # Wrap with page structure
        html = html_head("Executive Summary", include_pdf_export=True, include_search=False, enable_sidebar=True)
        html += create_page_wrapper(content, navbar, sidebar)
        html += """
</body>
</html>
        """

        # Write to file
        from core import config as config_module
        html_dir = getattr(config_module, 'html_reports_folder', Path('output/html_report'))

        # Try to use latest report directory
        latest_dir = config_module.get_latest_report_dir()
        if latest_dir:
            html_dir = latest_dir / 'html'

        output_path = html_dir / 'executive_summary.html'
        os.makedirs(output_path.parent, exist_ok=True)

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)

        if logger:
            logger.info(f"Generated executive summary report: {output_path}")

        return output_path

    except Exception as e:
        if logger:
            logger.error(f"Error generating executive summary: {str(e)}")
        raise
