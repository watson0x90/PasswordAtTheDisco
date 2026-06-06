# reports/html/components.py
"""
Reusable HTML components for reports.
"""

# Risk vector explanation component
RISK_VECTOR_EXPLANATION = """
<div class="alert alert-info" role="alert">
    <h4 class="alert-heading"><i class="bi bi-info-circle me-2"></i>Risk Vector Format</h4>
    <p class="mb-3">Risk vectors provide a compact representation of risk factors in the format: <code>C:X/L:Y/D:Z/...</code></p>
    <div class="row g-3">
        <div class="col-md-6 col-lg-4">
            <strong>C: Complexity (C1-C10)</strong>
            <ul class="small mb-0">
                <li>C1: Excellent complexity</li>
                <li>C5: Moderate complexity</li>
                <li>C10: Very poor complexity</li>
            </ul>
        </div>
        <div class="col-md-6 col-lg-4">
            <strong>L: Length</strong>
            <ul class="small mb-0">
                <li>VL: Very Long (16+ chars)</li>
                <li>L: Long (12-15 chars)</li>
                <li>M: Medium (8-11 chars)</li>
                <li>S: Short (6-7 chars)</li>
                <li>VS: Very Short (<6 chars)</li>
            </ul>
        </div>
        <div class="col-md-6 col-lg-4">
            <strong>D: Dictionary Issues</strong>
            <ul class="small mb-0">
                <li>N: None</li>
                <li>CO: Common password</li>
                <li>DW: Dictionary word</li>
                <li>BW: Banned words</li>
                <li>KP: Keyboard pattern</li>
            </ul>
        </div>
        <div class="col-md-6 col-lg-4">
            <strong>SM: Similarity</strong>
            <ul class="small mb-0">
                <li>N: No significant similarity</li>
                <li>M: Medium (70-79%)</li>
                <li>H: High (80-89%)</li>
                <li>VH: Very High (90%+)</li>
            </ul>
        </div>
        <div class="col-md-6 col-lg-4">
            <strong>CM: Compliance</strong>
            <ul class="small mb-0">
                <li>N: Compliant</li>
                <li>L: Low (<1 month)</li>
                <li>M: Medium (1-3 months)</li>
                <li>H: High (3-12 months)</li>
                <li>VH: Very High (1-2 years)</li>
                <li>E: Extreme (>2 years)</li>
            </ul>
        </div>
        <div class="col-md-6 col-lg-4">
            <strong>EX: Expiration</strong>
            <ul class="small mb-0">
                <li>Y: Password set to expire</li>
                <li>N: Never expires</li>
                <li>U: Unknown</li>
            </ul>
        </div>
        <div class="col-md-6 col-lg-4">
            <strong>DA: Domain Admin Pathway</strong>
            <ul class="small mb-0">
                <li>N: No pathway</li>
                <li>Y: Has pathway</li>
                <li>M: Multiple pathways</li>
                <li>S: Shared with DA account</li>
            </ul>
        </div>
        <div class="col-md-6 col-lg-4">
            <strong>CO: Controlled Objects</strong>
            <ul class="small mb-0">
                <li>L: Low (1-10)</li>
                <li>M: Medium (11-50)</li>
                <li>M+: Medium-High (51-100)</li>
                <li>H: High (101-500)</li>
                <li>VH: Very High (501-1000)</li>
                <li>E: Extreme (>1000)</li>
            </ul>
        </div>
        <div class="col-md-6 col-lg-4">
            <strong>S: Sharing</strong>
            <ul class="small mb-0">
                <li>0: Not shared</li>
                <li>1: 1-9 accounts</li>
                <li>2: 10-99 accounts</li>
                <li>3: 100-999 accounts</li>
                <li>4: 1000+ accounts</li>
            </ul>
        </div>
        <div class="col-md-6 col-lg-4">
            <strong>DR: Domain Risk</strong>
            <ul class="small mb-0">
                <li>L: Low risk domain</li>
                <li>M: Medium risk domain</li>
                <li>H: High risk domain</li>
                <li>C: Critical risk domain</li>
                <li>U: Unknown</li>
            </ul>
        </div>
        <div class="col-md-6 col-lg-4">
            <strong>HIBP: Breach Exposure</strong>
            <ul class="small mb-0">
                <li>N: Not breached</li>
                <li>L: Low (1-9 breaches)</li>
                <li>M: Medium (10-99)</li>
                <li>H: High (100-999)</li>
                <li>VH: Very High (1K-9.9K)</li>
                <li>E: Extreme (10K-99.9K)</li>
                <li>C: Critical (100K+)</li>
            </ul>
        </div>
    </div>
</div>
"""

# Domain Admin explanation component
DA_EXPLANATION = """
<div class="alert alert-warning" role="alert">
    <h4 class="alert-heading"><i class="bi bi-exclamation-triangle me-2"></i>Domain Admin Pathways</h4>
    <p>This section lists accounts with cracked passwords that have pathways to Domain Admin (DA) privileges, identified via BloodHound analysis. These accounts are critical because they can be exploited to gain full control over the domain.</p>

    <h5 class="mt-3">Why It's Important</h5>
    <p>Compromised accounts with DA pathways enable attackers to escalate privileges rapidly. According to the 2023 Verizon Data Breach Investigations Report (DBIR), 86% of breaches involved misuse of privileged credentials.</p>

    <h5 class="mt-3">Expected Actions</h5>
    <ul>
        <li><strong>Reset Passwords Immediately</strong>: For accounts marked 'Reset Immediately' (Enabled = Yes, Risk Level = High/Critical):
            <ol>
                <li>Log into Active Directory Users and Computers (ADUC).</li>
                <li>Locate the user (e.g., `Username`).</li>
                <li>Right-click > Reset Password, enforce a strong, unique password (e.g., 16+ characters, mixed case, numbers, special characters).</li>
                <li>Check 'User must change password at next logon' to ensure immediate update.</li>
            </ol>
        </li>
        <li><strong>Review and Secure</strong>: For accounts marked 'Review and Secure' (Disabled or lower risk):
            <ol>
                <li>Verify if the account is still needed.</li>
                <li>If active, reset the password as above.</li>
                <li>If unused, disable or delete the account to reduce attack surface.</li>
            </ol>
        </li>
        <li><strong>Audit DA Pathways</strong>: Use BloodHound to review and restrict these pathways (e.g., remove unnecessary privileges).</li>
    </ul>
</div>
"""

# Controllables explanation component
CONTROLLABLES_EXPLANATION = """
<div class="alert alert-warning" role="alert">
    <h4 class="alert-heading"><i class="bi bi-diagram-3 me-2"></i>Controlled Objects</h4>
    <p>This section identifies the top 100 cracked accounts controlling the most objects (e.g., users, groups, computers) in the domain. High controllables increase the impact of a compromise.</p>

    <h5 class="mt-3">Why It's Important</h5>
    <p>Accounts with many controllables can manipulate multiple resources, amplifying damage. NIST SP 800-53 highlights that excessive privileges contribute to 80% of insider threat incidents.</p>

    <h5 class="mt-3">Expected Actions</h5>
    <ul>
        <li><strong>Reset Passwords Immediately</strong>: For enabled accounts with High/Critical risk:
            <ol>
                <li>Follow the ADUC password reset steps above.</li>
                <li>Use a unique, complex password.</li>
            </ol>
        </li>
        <li><strong>Review and Secure</strong>: For other accounts:
            <ol>
                <li>Assess if the account needs such extensive control.</li>
                <li>Reduce permissions via ADUC or PowerShell (e.g., `Remove-ADGroupMember`).</li>
                <li>Reset passwords if still active.</li>
            </ol>
        </li>
        <li><strong>Monitor Usage</strong>: Implement logging to detect abuse of these accounts.</li>
    </ul>
</div>
"""

# Non-expiring passwords explanation component
NONEXPIRING_EXPLANATION = """
<div class="alert alert-warning" role="alert">
    <h4 class="alert-heading"><i class="bi bi-clock-history me-2"></i>Non-Expiring Passwords</h4>
    <p>This section lists cracked accounts with passwords set to never expire, bypassing standard rotation policies.</p>

    <h5 class="mt-3">Why It's Important</h5>
    <p>Non-expiring passwords increase exposure over time. The 2022 Ponemon Institute report found that 60% of breaches involved credentials unchanged for over a year.</p>

    <h5 class="mt-3">Expected Actions</h5>
    <ul>
        <li><strong>Set to Expire and Reset</strong>: For enabled accounts:
            <ol>
                <li>In ADUC, locate the user.</li>
                <li>Reset the password (as above).</li>
                <li>Uncheck 'Password never expires' in Account properties.</li>
                <li>Set a policy-compliant expiration (e.g., 90 days).</li>
            </ol>
        </li>
        <li><strong>Review and Update</strong>: For disabled/unused accounts:
            <ol>
                <li>Confirm necessity.</li>
                <li>Disable or delete if obsolete.</li>
            </ol>
        </li>
        <li><strong>Enforce Policy</strong>: Update domain policy to prevent future non-expiring settings (e.g., via Group Policy).</li>
    </ul>
</div>
"""

# Out-of-compliance explanation component
COMPLIANCE_EXPLANATION = """
<div class="alert alert-danger" role="alert">
    <h4 class="alert-heading"><i class="bi bi-shield-exclamation me-2"></i>Out of Compliance</h4>
    <p>This section highlights cracked accounts with passwords exceeding the maximum age (e.g., >90 days), violating compliance policies.</p>

    <h5 class="mt-3">Why It's Important</h5>
    <p>Stale passwords are more likely to be compromised. IBM's 2023 Cost of a Data Breach report notes that outdated credentials contribute to 19% of breaches, with an average cost of $4.37M.</p>

    <h5 class="mt-3">Expected Actions</h5>
    <ul>
        <li><strong>Reset Immediately</strong>: For High/Critical risk enabled accounts:
            <ol>
                <li>Reset passwords via ADUC (as above).</li>
                <li>Enforce immediate user change.</li>
            </ol>
        </li>
        <li><strong>Enforce Compliance</strong>: For other accounts:
            <ol>
                <li>Reset passwords.</li>
                <li>Verify last set date aligns with policy (e.g., <90 days).</li>
            </ol>
        </li>
        <li><strong>Automate Rotation</strong>: Implement password expiration policies via Group Policy (e.g., `Set-ADDefaultDomainPasswordPolicy -MaxPasswordAge 90`).</li>
    </ul>
</div>
"""

# Risk score explanation component
RISK_SCORE_EXPLANATION = """
<div class="alert alert-info" role="alert">
    <h4 class="alert-heading"><i class="bi bi-speedometer me-2"></i>Risk Scoring System</h4>
    <p class="mb-2">This report uses a CVSS-style 0-10 risk scoring system:</p>
    <ul class="mb-3">
        <li><strong><span class="badge bg-danger">Critical</span> (8.0-10.0)</strong>: Severe security threat requiring immediate action</li>
        <li><strong><span class="badge bg-warning text-dark">High</span> (6.0-7.9)</strong>: Significant vulnerability requiring prompt attention</li>
        <li><strong><span class="badge bg-info text-dark">Medium</span> (4.0-5.9)</strong>: Moderate vulnerability for regular security maintenance</li>
        <li><strong><span class="badge bg-success">Low</span> (0.0-3.9)</strong>: Minor issue with limited security impact</li>
    </ul>

    <h5 class="mt-3">Score Components</h5>
    <ul>
        <li><strong>Base Score</strong>: Evaluates password complexity, length, and dictionary factors</li>
        <li><strong>Temporal Score</strong>: Adjusts for password age and expiration policy</li>
        <li><strong>Environmental Score</strong>: Incorporates account privileges and password sharing</li>
    </ul>
</div>
"""

def html_head(title, include_pdf_export=False, include_search=False, include_redacted_search=False, enable_sidebar=False):
    """Generate standard HTML head section with CoreUI 5 dark theme."""
    from report_lib.standalone_html.styles import COREUI_CSS, COREUI_JS

    # COREUI_CSS includes CoreUI CDN + Custom Dark Theme CSS
    scripts = COREUI_JS  # Add CoreUI JavaScript

    # Sidebar-specific CSS
    sidebar_css = ''
    if enable_sidebar:
        sidebar_css = """
        <style>
        /* ============================================
           Sidebar and Layout Styles
           ============================================ */

        /* Wrapper for entire page */
        .wrapper {
            display: flex;
            flex-direction: column;
            min-height: 100vh;
        }

        .body {
            display: flex;
            flex: 1;
            padding-top: 88px; /* Account for sticky header height */
        }

        /* Sidebar base styles */
        .sidebar {
            position: fixed;
            top: 88px; /* Below header (header is 88px with CoreUI) */
            bottom: 0;
            left: 0;
            z-index: 1020;
            width: 256px;
            background: #212529;
            border-right: 1px solid #374151;
            overflow-y: auto;
            overflow-x: hidden;
            transition: all 0.3s ease;
        }

        .sidebar-narrow {
            width: 56px !important;
        }

        /* Sidebar navigation */
        .sidebar-nav {
            padding: 0;
            padding-top: 1rem; /* Top spacing */
            margin: 0;
            list-style: none;
        }

        .sidebar .nav-icon {
            min-width: 20px;
            margin-right: 0.5rem;
        }

        .sidebar-narrow .nav-icon {
            margin-right: 0 !important;
        }

        /* Hide text in narrow sidebar */
        .sidebar-narrow .sidebar-nav .nav-link > span:not(.nav-icon),
        .sidebar-narrow .nav-title {
            display: none !important;
        }

        /* Hide chevron in narrow mode */
        .sidebar-narrow .nav-group-toggle::after {
            display: none !important;
        }

        /* Reduce padding and center icons in narrow mode */
        .sidebar-narrow .nav-link {
            padding-left: 1rem !important;
            padding-right: 1rem !important;
            justify-content: center;
        }

        /* Main content area */
        .main-content {
            margin-left: 256px;
            padding: 0;
            width: 100%;
            transition: margin-left 0.3s ease;
        }

        .sidebar-narrow ~ .main-content {
            margin-left: 56px;
        }

        /* Responsive: Mobile */
        @media (max-width: 992px) {
            .sidebar {
                transform: translateX(-100%);
            }

            .sidebar.show {
                transform: translateX(0);
            }

            .main-content {
                margin-left: 0 !important;
            }

            /* Backdrop for mobile */
            .sidebar.show::before {
                content: '';
                position: fixed;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                background: rgba(0, 0, 0, 0.5);
                z-index: -1;
            }
        }

        /* Nav items */
        .sidebar .nav-link {
            display: flex;
            align-items: center;
            padding: 0.625rem 1.5rem;
            color: #d1d5db;
            text-decoration: none;
            border-left: 3px solid transparent;
            transition: all 0.2s ease;
            font-size: 0.9375rem;
            font-weight: 400;
        }

        .sidebar .nav-link:hover {
            background: rgba(59, 130, 246, 0.1);
            color: #60a5fa;
        }

        .sidebar .nav-link.active {
            background: rgba(59, 130, 246, 0.2);
            color: #60a5fa;
            border-left-color: #3b82f6;
            font-weight: 500;
        }

        /* Highlight parent nav-group when child is active */
        .nav-group:has(.nav-link.active) > .nav-group-toggle {
            color: #60a5fa;
            background: rgba(59, 130, 246, 0.05);
        }

        /* Auto-expand parent groups with active children - handled by JavaScript */

        /* Nav groups (collapsible) */
        .nav-group-items {
            display: none;
            list-style: none;
            padding-left: 0;
            margin: 0;
            overflow: hidden;
            max-height: 0;
            transition: max-height 0.3s ease-in-out;
        }

        .nav-group-toggle.show ~ .nav-group-items,
        .nav-group.show > .nav-group-items {
            display: block;
            max-height: 2000px;
        }

        /* Chevron indicators for collapsible nav groups */
        .nav-group-toggle {
            position: relative;
            cursor: pointer;
        }

        .nav-group-toggle::after {
            content: "";
            display: inline-block;
            width: 0.5rem;
            height: 0.5rem;
            margin-left: auto;
            margin-right: 0.5rem;
            border-right: 2px solid currentColor;
            border-bottom: 2px solid currentColor;
            transform: rotate(-45deg);
            transition: transform 0.3s ease;
            flex-shrink: 0;
        }

        .nav-group.show > .nav-group-toggle::after {
            transform: rotate(45deg);
        }

        /* Ensure toggle link uses flexbox for proper chevron placement */
        .nav-group-toggle {
            display: flex;
            align-items: center;
        }

        .nav-group-items .nav-link {
            padding-left: 2.25rem;
            font-size: 0.875rem;
            font-weight: 400;
        }

        .nav-group-items.compact .nav-link {
            padding-top: 0.5rem;
            padding-bottom: 0.5rem;
        }

        .nav-group-items .nav-group-items .nav-link {
            padding-left: 3.25rem;
            font-size: 0.8125rem;
            color: #9ca3af;
        }

        .nav-group-items .nav-group-items .nav-link:hover {
            color: #60a5fa;
        }

        /* Nav divider */
        .nav-divider {
            height: 1px;
            margin: 0.5rem 0;
            overflow: hidden;
            background-color: #374151;
        }

        /* Nav title */
        .nav-title {
            padding: 0.75rem 1rem 0.25rem;
            margin-top: 1rem;
            font-size: 0.75rem;
            font-weight: 700;
            color: #9ca3af;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        /* Header/Navbar adjustments */
        .header,
        .navbar {
            z-index: 1030;
            min-height: 56px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);
        }

        /* Sidebar toggle button */
        .sidebar-toggle-btn {
            padding: 0.5rem;
            border-radius: 0.25rem;
            transition: background-color 0.2s;
        }

        .sidebar-toggle-btn:hover {
            background-color: rgba(255, 255, 255, 0.1);
        }

        /* Sidebar toggle button (inside sidebar, top right) */
        .sidebar-toggler {
            position: absolute;
            top: 12px;
            right: 12px;
            background: none;
            border: none;
            color: #9ca3af;
            padding: 0.5rem;
            transition: all 0.2s ease;
            border-radius: 0.25rem;
            cursor: pointer;
            z-index: 10;
            width: 32px;
            height: 32px;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .sidebar-toggler i {
            font-size: 1.125rem;
            line-height: 1;
            transition: transform 0.3s ease;
        }

        /* Rotate icon when sidebar is narrow (collapsed) */
        .sidebar-narrow .sidebar-toggler i {
            transform: rotate(180deg);
        }

        .sidebar-toggler:hover {
            background: rgba(255, 255, 255, 0.1);
            color: #60a5fa;
        }

        .sidebar-toggler:active {
            background: rgba(255, 255, 255, 0.2);
        }

        /* Navbar brand */
        .navbar-brand {
            font-family: var(--pd-mono);
            font-size: 1.25rem;
            font-weight: 400;
            white-space: nowrap;
        }

        .navbar-brand i {
            font-size: 1.125rem;
        }

        /* Hide brand text on very small screens */
        @media (max-width: 576px) {
            .navbar-brand .brand-text {
                display: none;
            }
        }

        /* Navbar search form */
        .navbar form .form-control-sm {
            height: 32px;
            font-size: 0.875rem;
        }

        .navbar form .btn-sm {
            height: 32px;
            padding: 0.25rem 0.75rem;
            font-size: 0.875rem;
        }

        /* Theme toggle button styling */
        .navbar-nav .btn-link {
            text-decoration: none;
            padding: 0.5rem;
        }

        .navbar-nav .btn-link:hover {
            background: rgba(255, 255, 255, 0.1);
            border-radius: 0.25rem;
        }

        /* Scrollbar styling for sidebar */
        .sidebar::-webkit-scrollbar {
            width: 8px;
        }

        .sidebar::-webkit-scrollbar-track {
            background: #1f2937;
        }

        .sidebar::-webkit-scrollbar-thumb {
            background: #4b5563;
            border-radius: 4px;
        }

        .sidebar::-webkit-scrollbar-thumb:hover {
            background: #6b7280;
        }

        /* Focus states for accessibility */
        .sidebar .nav-link:focus,
        .nav-group-toggle:focus {
            outline: 2px solid #60a5fa;
            outline-offset: -2px;
        }

        .sidebar-toggler:focus {
            outline: 2px solid rgba(255, 255, 255, 0.5);
            outline-offset: 2px;
        }

        /* Smooth animations for nav items */
        .nav-group-items .nav-link {
            animation: fadeInLeft 0.2s ease-in-out;
        }

        @keyframes fadeInLeft {
            from {
                opacity: 0;
                transform: translateX(-10px);
            }
            to {
                opacity: 1;
                transform: translateX(0);
            }
        }

        /* Theme toggle button improvements */
        .navbar .nav-link[onclick*="toggleTheme"] {
            transition: all 0.2s ease;
        }

        .navbar .nav-link[onclick*="toggleTheme"]:hover {
            transform: rotate(15deg);
        }
        </style>
        """

    return f"""
    <!DOCTYPE html>
    <html lang="en" data-coreui-theme="dark">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0, shrink-to-fit=no">
        <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
        <meta name="description" content="Password!AtTheDisco - Enterprise Password Security Audit Report">
        <title>{title}</title>

        {COREUI_CSS}
        {sidebar_css}
        {scripts}
    </head>
    """

def create_error_message(message="An error occurred while processing the data."):
    """Create an error message div using Bootstrap alert."""
    return f"""
    <div class="alert alert-danger alert-dismissible fade show" role="alert">
        <i class="bi bi-exclamation-circle me-2"></i><strong>Error:</strong> {message}
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
    </div>
    """


def get_risk_distribution_html(distribution, total=None):
    """Generate HTML for risk distribution using Bootstrap badges and list group."""
    if not distribution:
        return '<div class="alert alert-info">No risk distribution data available.</div>'

    if total is None:
        total = sum(distribution.values())

    risk_config = {
        'Critical': {'badge': 'bg-danger', 'icon': 'exclamation-triangle-fill'},
        'High': {'badge': 'bg-warning text-dark', 'icon': 'exclamation-circle-fill'},
        'Medium': {'badge': 'bg-info text-dark', 'icon': 'info-circle-fill'},
        'Low': {'badge': 'bg-success', 'icon': 'check-circle-fill'}
    }

    html = '<ul class="list-group">'
    for level in ['Critical', 'High', 'Medium', 'Low']:
        count = distribution.get(level, 0)
        percentage = round((count/total)*100, 1) if total > 0 else 0
        config = risk_config.get(level, {'badge': 'bg-secondary', 'icon': 'circle-fill'})

        html += f'''
        <li class="list-group-item d-flex justify-content-between align-items-center">
            <span><i class="bi bi-{config["icon"]} me-2"></i>{level}</span>
            <div>
                <span class="badge {config["badge"]} rounded-pill me-2">{count}</span>
                <small class="text-muted">({percentage}%)</small>
            </div>
        </li>
        '''
    html += "</ul>"

    return html


def create_metric_card(title, value, icon=None, bg_class="bg-primary", text_class="text-white", subtitle=None):
    """Create a Bootstrap metric card for displaying statistics."""
    icon_html = f'<i class="bi bi-{icon} fa-2x mb-3"></i>' if icon else ''
    subtitle_html = f'<p class="mb-0 small opacity-75">{subtitle}</p>' if subtitle else ''

    return f"""
    <div class="card {bg_class} {text_class} shadow-sm h-100">
        <div class="card-body text-center">
            {icon_html}
            <h5 class="card-title mb-2">{title}</h5>
            <p class="display-6 fw-bold mb-2">{value}</p>
            {subtitle_html}
        </div>
    </div>
    """


def create_risk_badge(risk_level):
    """Create a Bootstrap badge for risk level."""
    if not risk_level or risk_level == "N/A":
        return '<span class="badge bg-secondary">Unknown</span>'

    risk_mapping = {
        'critical': 'badge-risk-critical',
        'high': 'badge-risk-high',
        'medium': 'badge-risk-medium',
        'low': 'badge-risk-low'
    }

    badge_class = risk_mapping.get(risk_level.lower(), 'bg-secondary')
    return f'<span class="badge {badge_class}">{risk_level.title()}</span>'


def create_breadcrumb(items):
    """
    Create a Bootstrap breadcrumb navigation.

    Args:
        items: List of tuples (name, url) where url=None for active item

    Example:
        create_breadcrumb([('Dashboard', './main.html'), ('Domain Report', None)])
    """
    if not items:
        return ''

    breadcrumb_items = ''
    for i, (name, url) in enumerate(items):
        is_active = (url is None) or (i == len(items) - 1)

        if is_active:
            breadcrumb_items += f'<li class="breadcrumb-item active" aria-current="page">{name}</li>'
        else:
            breadcrumb_items += f'<li class="breadcrumb-item"><a href="{url}">{name}</a></li>'

    return f"""
    <nav aria-label="breadcrumb">
        <ol class="breadcrumb">
            {breadcrumb_items}
        </ol>
    </nav>
    """


def create_bootstrap_card(title, content, header_bg="bg-primary", header_text="text-white", icon=None):
    """Create a generic Bootstrap card with custom header."""
    icon_html = f'<i class="bi bi-{icon} me-2"></i>' if icon else ''

    return f"""
    <div class="card shadow-sm mb-4">
        <div class="card-header {header_bg} {header_text}">
            <h5 class="mb-0">{icon_html}{title}</h5>
        </div>
        <div class="card-body">
            {content}
        </div>
    </div>
    """


def create_overview_section(stats_dict):
    """
    Create an overview section with metric cards in a responsive grid.

    Args:
        stats_dict: Dict of {title: {value, icon, subtitle?}}

    Example:
        create_overview_section({
            'Total Accounts': {'value': 100, 'icon': 'people', 'subtitle': '3 domains'},
            'Cracked': {'value': 50, 'icon': 'key'}
        })
    """
    cards_html = ''
    for title, data in stats_dict.items():
        cards_html += f'''
        <div class="col-12 col-md-6 col-lg-3">
            {create_metric_card(
                title=title,
                value=data.get('value', 'N/A'),
                icon=data.get('icon'),
                bg_class=data.get('bg_class', 'bg-primary'),
                text_class=data.get('text_class', 'text-white'),
                subtitle=data.get('subtitle')
            )}
        </div>
        '''

    return f"""
    <div class="row g-4 mb-4">
        {cards_html}
    </div>
    """


def create_user_detail_offcanvas():
    """Create the user-detail offcanvas shell (rendered from the Jinja partial).

    Returns:
        HTML string for the offcanvas panel structure.
    """
    from report_lib.templating import render
    return render("partials/offcanvas.html.j2")



def create_navbar(current_page='dashboard', include_search=True, include_export=False):
    """Create the CoreUI navbar (rendered from the Jinja partial).

    Args:
        current_page (str): Current page identifier (kept for API compatibility).
        include_search (bool): Show the quick-search box.
        include_export (bool): Show the export dropdown menu.

    Returns:
        HTML string for the navbar.
    """
    from report_lib.templating import render
    return render("partials/navbar.html.j2", current_page=current_page,
                  include_search=include_search, include_export=include_export)



def create_sidebar(current_page='dashboard', domains=None):
    """Create the collapsible sidebar navigation (rendered from the Jinja
    partial; domain names are autoescaped).

    Args:
        current_page (str): Current page identifier for the active item.
        domains (list): Domain names for the per-domain submenus.

    Returns:
        HTML string for the sidebar.
    """
    from report_lib.templating import render
    return render("partials/sidebar.html.j2", current_page=current_page,
                  domains=domains or [])



def create_page_wrapper(content, navbar, sidebar):
    """
    Wrap page content with navbar and sidebar in CoreUI layout structure.

    Args:
        content (str): Main page content HTML
        navbar (str): Navbar HTML from create_navbar()
        sidebar (str): Sidebar HTML from create_sidebar()

    Returns:
        Complete page body HTML with navigation
    """
    from report_lib.standalone_html.scripts import SIDEBAR_NAV_JS

    return f'''
<body>
    <a class="visually-hidden-focusable position-absolute top-0 start-0 m-2 btn btn-primary" href="#main-content">Skip to main content</a>
    <div class="wrapper">
        {navbar}

        <div class="body flex-grow-1">
            {sidebar}

            <!-- Main Content Area -->
            <main class="main-content" id="main-content">
                <div class="container-fluid p-4">
                    {content}
                </div>
            </main>
        </div>
    </div>

    {SIDEBAR_NAV_JS}
'''


def create_about_content(report_metadata=None):
    """Render the About page content from the Jinja template.

    Args:
        report_metadata (dict): timestamp, domains, version, total_accounts,
            cracked_accounts, uncracked_accounts, tool_name.

    Returns:
        HTML string for the about page content (metadata autoescaped).
    """
    from report_lib.templating import render
    report_metadata = report_metadata or {}
    total = report_metadata.get("total_accounts", 0) or 0
    cracked = report_metadata.get("cracked_accounts", 0) or 0
    crack_pct = (cracked / total * 100) if total > 0 else 0
    return render(
        "partials/about_content.html.j2",
        timestamp=report_metadata.get("timestamp", "Unknown"),
        version=report_metadata.get("version", "1.0.0"),
        domains=report_metadata.get("domains", []) or [],
        total=total,
        cracked=cracked,
        uncracked=report_metadata.get("uncracked_accounts", 0) or 0,
        crack_pct=crack_pct,
        risk_vector_explanation=RISK_VECTOR_EXPLANATION,
    )
