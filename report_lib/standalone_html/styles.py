# report_lib/standalone_html/styles.py
"""
CSS and CDN links for standalone HTML reports.
Using CoreUI 5 Dark Theme for consistency with Flask UI.
"""

# CoreUI 5 CDN Links (for standalone HTML files)
COREUI_CDN = """
<!-- Vendored offline assets (copied into each report's vendor/ dir so reports
     render with no internet access -- important for air-gapped review). -->
<!-- CoreUI 5.2.0 CSS -->
<link href="vendor/coreui/coreui.min.css" rel="stylesheet">

<!-- Bootstrap Icons 1.13.1 (the only icon set used: bi bi-*) -->
<link href="vendor/bootstrap-icons/bootstrap-icons.min.css" rel="stylesheet">
"""

# CoreUI 5 JavaScript Bundle
COREUI_JS = """
<!-- CoreUI 5.2.0 JS Bundle (includes Popper) -->
<script src="vendor/coreui/coreui.bundle.min.js"></script>

<!-- Plotly.js 2.32.0 for interactive charts -->
<script src="vendor/plotly/plotly.min.js"></script>

<!-- Custom theme initialization -->
<script>
// Initialize dark theme
document.addEventListener('DOMContentLoaded', function() {
    // Ensure dark theme is applied
    document.documentElement.setAttribute('data-coreui-theme', 'dark');

    // Initialize CoreUI components
    const tooltipTriggerList = document.querySelectorAll('[data-coreui-toggle="tooltip"]')
    const tooltipList = [...tooltipTriggerList].map(tooltipTriggerEl => new coreui.Tooltip(tooltipTriggerEl))

    // Initialize sidebar navigation for collapsible nav-groups
    const sidebarNav = document.querySelector('[data-coreui="navigation"]');
    if (sidebarNav) {
        console.log('CoreUI sidebar navigation initialized');

        // Add manual click handlers for nav-group-toggle elements
        const navGroupToggles = document.querySelectorAll('.nav-group-toggle');
        navGroupToggles.forEach(toggle => {
            toggle.addEventListener('click', function(e) {
                e.preventDefault();

                // Get the parent nav-group
                const navGroup = this.closest('.nav-group');

                if (navGroup) {
                    // Toggle the 'show' class on the nav-group
                    navGroup.classList.toggle('show');

                    // Update aria-expanded attribute
                    const isExpanded = navGroup.classList.contains('show');
                    this.setAttribute('aria-expanded', isExpanded);
                }
            });
        });
    }
});
</script>
"""

# Custom Dark Theme CSS (ported from Flask app)
CUSTOM_DARK_CSS = """
<style>
/* ============================================
   Dark theme color variables (from Flask app)
   ============================================ */
[data-coreui-theme="dark"] {
    --cui-body-bg: #1a1d23;
    --cui-body-color: #d1d5db;
    --cui-card-bg: #212529;
    --cui-border-color: #374151;
    --cui-primary: #3b82f6;
    --cui-success: #10b981;
    --cui-danger: #ef4444;
    --cui-warning: #f59e0b;
    --cui-info: #06b6d4;
}

/* ============================================
   Body and base styling
   ============================================ */
body {
    background-color: var(--cui-body-bg);
    color: var(--cui-body-color);
}

.container-fluid {
    max-width: 1600px;
    margin: 0 auto;
    padding: 20px;
}

/* ============================================
   Cards and panels
   ============================================ */
[data-coreui-theme="dark"] .card {
    background: #212529;
    border: 1px solid #374151;
}

[data-coreui-theme="dark"] .card-header {
    background: rgba(0, 0, 0, 0.2);
    border-bottom: 1px solid #374151;
}

/* ============================================
   Risk badges (consistent with Flask UI)
   ============================================ */
.badge-risk-critical {
    background-color: #ef4444;
    color: #fff;
}

.badge-risk-high {
    background-color: #f97316;
    color: #fff;
}

.badge-risk-medium {
    background-color: #eab308;
    color: #000;
}

.badge-risk-low {
    background-color: #22c55e;
    color: #fff;
}

/* Text colors for risk levels */
.text-risk-critical { color: #ef4444 !important; }
.text-risk-high { color: #f97316 !important; }
.text-risk-medium { color: #eab308 !important; }
.text-risk-low { color: #22c55e !important; }

/* ============================================
   Stat cards (from Flask UI)
   ============================================ */
.stat-card {
    transition: transform 0.2s ease-in-out;
}

.stat-card:hover {
    transform: translateY(-5px);
    box-shadow: 0 8px 16px rgba(0, 0, 0, 0.3);
}

.stat-card .stat-value {
    font-size: 2.5rem;
    font-weight: 700;
}

.stat-card .stat-label {
    color: #9ca3af;
    text-transform: uppercase;
    font-size: 0.875rem;
    letter-spacing: 0.05em;
}

/* ============================================
   Tables
   ============================================ */
[data-coreui-theme="dark"] .table {
    color: var(--cui-body-color);
    border-color: #374151;
}

[data-coreui-theme="dark"] .table-dark {
    background-color: rgba(0, 0, 0, 0.2);
}

[data-coreui-theme="dark"] .table-striped > tbody > tr:nth-of-type(odd) > * {
    background-color: rgba(255, 255, 255, 0.02);
}

[data-coreui-theme="dark"] .table-hover > tbody > tr:hover > * {
    background-color: rgba(255, 255, 255, 0.05);
}

table.table-sortable thead th {
    cursor: pointer;
    user-select: none;
}

table.table-sortable thead th:hover {
    background-color: rgba(255, 255, 255, 0.1);
}

table.table-sortable thead th.sorted-asc::after {
    content: " ↑";
    font-weight: bold;
    color: var(--cui-primary);
}

table.table-sortable thead th.sorted-desc::after {
    content: " ↓";
    font-weight: bold;
    color: var(--cui-primary);
}

/* ============================================
   Alerts (dark theme)
   ============================================ */
[data-coreui-theme="dark"] .alert-info {
    background: rgba(6, 182, 212, 0.1);
    border-color: rgba(6, 182, 212, 0.2);
    color: #06b6d4;
}

[data-coreui-theme="dark"] .alert-success {
    background: rgba(16, 185, 129, 0.1);
    border-color: rgba(16, 185, 129, 0.2);
    color: #10b981;
}

[data-coreui-theme="dark"] .alert-warning {
    background: rgba(245, 158, 11, 0.1);
    border-color: rgba(245, 158, 11, 0.2);
    color: #f59e0b;
}

[data-coreui-theme="dark"] .alert-danger {
    background: rgba(239, 68, 68, 0.1);
    border-color: rgba(239, 68, 68, 0.2);
    color: #ef4444;
}

/* ============================================
   Forms and inputs
   ============================================ */
[data-coreui-theme="dark"] .form-control,
[data-coreui-theme="dark"] .form-select {
    background: #1f2937;
    border: 1px solid #374151;
    color: #d1d5db;
}

[data-coreui-theme="dark"] .form-control:focus,
[data-coreui-theme="dark"] .form-select:focus {
    background: #1f2937;
    border-color: var(--cui-primary);
    color: #d1d5db;
    box-shadow: 0 0 0 0.25rem rgba(59, 130, 246, 0.25);
}

/* ============================================
   Buttons
   ============================================ */
[data-coreui-theme="dark"] .btn-primary {
    background-color: var(--cui-primary);
    border-color: var(--cui-primary);
}

[data-coreui-theme="dark"] .btn-outline-primary {
    color: var(--cui-primary);
    border-color: var(--cui-primary);
}

[data-coreui-theme="dark"] .btn-outline-primary:hover {
    background-color: var(--cui-primary);
    border-color: var(--cui-primary);
    color: #fff;
}

/* ============================================
   Breadcrumb
   ============================================ */
[data-coreui-theme="dark"] .breadcrumb {
    background: transparent;
}

[data-coreui-theme="dark"] .breadcrumb-item a {
    color: var(--cui-primary);
    text-decoration: none;
}

[data-coreui-theme="dark"] .breadcrumb-item.active {
    color: #9ca3af;
}

/* ============================================
   Custom gradient backgrounds
   ============================================ */
.bg-gradient-primary {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
}

.bg-gradient-success {
    background: linear-gradient(135deg, #10b981 0%, #059669 100%);
}

.bg-gradient-danger {
    background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
}

.bg-gradient-info {
    background: linear-gradient(135deg, #06b6d4 0%, #0891b2 100%);
}

/* ============================================
   Visualization containers
   ============================================ */
.visualization-container {
    margin: 20px 0;
    padding: 15px;
    border: 1px solid #374151;
    border-radius: 8px;
    background-color: #212529;
}

.plotly-dark-bg {
    background-color: #1a1d23;
}

/* ============================================
   Report header styling
   ============================================ */
.report-header {
    background: linear-gradient(135deg, #1a1d23 0%, #212529 100%);
    padding: 30px 0;
    border-bottom: 2px solid var(--cui-primary);
    margin-bottom: 30px;
}

.report-title {
    font-family: 'Iceland', sans-serif;
    font-size: 2.5rem;
    color: #fff;
    letter-spacing: 0.1em;
    text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.5);
}

/* ============================================
   Metric cards
   ============================================ */
.metric-card {
    text-align: center;
    padding: 20px;
    border-radius: 8px;
    background: #212529;
    border: 1px solid #374151;
    transition: transform 0.2s;
}

.metric-card:hover {
    transform: translateY(-2px);
    box-shadow: 0 8px 16px rgba(0, 0, 0, 0.3);
}

.metric-value {
    font-size: 2.5rem;
    font-weight: bold;
    margin: 10px 0;
    color: var(--cui-primary);
}

.metric-label {
    font-size: 0.9rem;
    color: #9ca3af;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

/* ============================================
   Scrollbar styling (webkit browsers)
   ============================================ */
[data-coreui-theme="dark"] ::-webkit-scrollbar {
    width: 8px;
    height: 8px;
}

[data-coreui-theme="dark"] ::-webkit-scrollbar-track {
    background: #1f2937;
}

[data-coreui-theme="dark"] ::-webkit-scrollbar-thumb {
    background: #4b5563;
    border-radius: 4px;
}

[data-coreui-theme="dark"] ::-webkit-scrollbar-thumb:hover {
    background: #6b7280;
}

/* ============================================
   Text readability in dark mode
   ============================================ */
[data-coreui-theme="dark"] h1,
[data-coreui-theme="dark"] h2,
[data-coreui-theme="dark"] h3,
[data-coreui-theme="dark"] h4,
[data-coreui-theme="dark"] h5,
[data-coreui-theme="dark"] h6 {
    color: #f9fafb;
}

[data-coreui-theme="dark"] .text-body {
    color: #d1d5db !important;
}

[data-coreui-theme="dark"] .text-body-secondary {
    color: #9ca3af !important;
}

/* ============================================
   Animation utilities
   ============================================ */
.fade-in {
    animation: fadeIn 0.3s ease-in-out;
}

@keyframes fadeIn {
    from {
        opacity: 0;
        transform: translateY(10px);
    }
    to {
        opacity: 1;
        transform: translateY(0);
    }
}

/* ============================================
   Print Optimization
   ============================================ */
@media print {
    .no-print {
        display: none !important;
    }

    .card {
        break-inside: avoid;
    }

    table {
        break-inside: auto;
    }

    tr {
        break-inside: avoid;
        break-after: auto;
    }
}

/* ============================================
   Responsive Adjustments
   ============================================ */
@media (max-width: 768px) {
    .metric-value {
        font-size: 1.8rem;
    }

    .container-fluid {
        padding: 10px;
    }

    .report-title {
        font-size: 1.8rem;
    }
}

/* ============================================
   User Detail Offcanvas Styling
   ============================================ */
.user-detail-link {
    color: var(--cui-primary);
    text-decoration: none;
    cursor: pointer;
    transition: all 0.2s ease;
}

.user-detail-link:hover {
    color: var(--cui-info);
    text-decoration: underline;
}

.user-detail-link:active {
    color: var(--cui-warning);
}

/* Offcanvas customization */
#userDetailOffcanvas {
    width: 800px;
    max-width: 90vw;
}

[data-coreui-theme="dark"] #userDetailOffcanvas {
    background-color: var(--cui-card-bg);
    color: var(--cui-body-color);
}

[data-coreui-theme="dark"] #userDetailOffcanvas .offcanvas-header {
    border-bottom: 1px solid var(--cui-border-color);
}

/* Summary cards in offcanvas */
.offcanvas-summary-card {
    border-radius: 8px;
    padding: 1rem;
    text-align: center;
    transition: transform 0.2s ease;
}

.offcanvas-summary-card:hover {
    transform: translateY(-2px);
}

/* Risk factor items */
.risk-factor-item {
    margin-bottom: 1.5rem;
}

.risk-factor-label {
    display: flex;
    justify-content: space-between;
    margin-bottom: 0.5rem;
    font-weight: 500;
}

/* Progress bars in offcanvas */
#riskBreakdownContent .progress {
    height: 8px;
    border-radius: 4px;
}

#riskBreakdownContent .progress-bar {
    transition: width 0.5s ease;
}

/* Controlled objects list */
.controlled-object-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 0.75rem;
    border-bottom: 1px solid var(--cui-border-color);
    transition: background-color 0.2s ease;
}

.controlled-object-item:hover {
    background-color: rgba(var(--cui-primary-rgb), 0.1);
}

.controlled-object-item:last-child {
    border-bottom: none;
}

/* Ensure tabs are visible in dark mode */
[data-coreui-theme="dark"] .nav-tabs .nav-link {
    color: var(--cui-body-color);
    border-color: transparent;
}

[data-coreui-theme="dark"] .nav-tabs .nav-link:hover {
    color: var(--cui-primary);
    border-color: var(--cui-border-color);
}

[data-coreui-theme="dark"] .nav-tabs .nav-link.active {
    color: var(--cui-primary);
    background-color: var(--cui-card-bg);
    border-color: var(--cui-border-color) var(--cui-border-color) transparent;
}

/* Alert styling in offcanvas */
#userDetailOffcanvas .alert {
    border-radius: 6px;
}

/* Definition list styling */
#accountPropsContent dt {
    font-weight: 600;
    color: var(--cui-body-color);
}

#accountPropsContent dd {
    color: var(--cui-body-color);
}

/* Small badge adjustments */
#userDetailOffcanvas .badge {
    font-size: 0.875rem;
    padding: 0.35em 0.65em;
}

/* Card spacing in offcanvas */
#userDetailOffcanvas .card {
    margin-bottom: 1rem;
    border-radius: 8px;
}

#userDetailOffcanvas .card:last-child {
    margin-bottom: 0;
}

/* ============================================
   Accessibility: WCAG AA colour-contrast fixes
   ============================================ */

/* Sidebar section titles were #75787a on #212529 (3.47:1). */
.sidebar .nav-title {
    color: #adb5bd !important;   /* ~7:1 on the sidebar background */
}

/* Light "bg-light" cards inherited near-white text in the dark theme, giving
   ~1:1 contrast (effectively invisible). Force readable dark text on them. */
[data-coreui-theme="dark"] .bg-light,
[data-coreui-theme="dark"] .bg-light .mt-3,
[data-coreui-theme="dark"] .bg-light h1,
[data-coreui-theme="dark"] .bg-light h2,
[data-coreui-theme="dark"] .bg-light h3,
[data-coreui-theme="dark"] .bg-light h4,
[data-coreui-theme="dark"] .bg-light h5,
[data-coreui-theme="dark"] .bg-light h6,
[data-coreui-theme="dark"] .bg-light p {
    color: #1a1d23 !important;
}
[data-coreui-theme="dark"] .bg-light .text-muted {
    color: #495057 !important;   /* ~8:1 on #f3f4f7 */
}

/* "text-dark" headers on bg-info/bg-warning rendered light (2.84 / 1.89:1).
   Force dark text against the light header background. */
.card-header.bg-info.text-dark, .card-header.bg-warning.text-dark,
.card-header.bg-info.text-dark :is(h1, h2, h3, h4, h5, h6),
.card-header.bg-warning.text-dark :is(h1, h2, h3, h4, h5, h6) {
    color: #0a2540 !important;   /* dark navy on the light header */
}

/* White text on the lighter danger/success badge backgrounds was 3.66/3.85:1.
   Darken the badge backgrounds to clear 4.5:1 (does not affect the custom
   badge-risk-* classes used for risk levels). */
.badge.bg-danger { background-color: #b02a37 !important; }
.badge.bg-success { background-color: #15703a !important; }
</style>
"""

# Combined CSS for easy import
COREUI_CSS = COREUI_CDN + CUSTOM_DARK_CSS

# Legacy support - maintain old variable names for backward compatibility
BASE_CSS = COREUI_CSS  # For old imports
BOOTSTRAP_JS = COREUI_JS  # For old imports
BOOTSTRAP_CDN = COREUI_CDN  # For old imports
CUSTOM_CSS = CUSTOM_DARK_CSS  # For old imports