# visualizations/core.py
"""
Core visualization module for password security analysis.
Coordinates generation of various visualization types.
"""

import importlib.util
import os

from core.config import ENABLE_STATIC_CHARTS, html_reports_folder
from utils.logging import get_logger

logger = get_logger('visualizations')

# Plotly is an optional dependency (not required for basic functionality).
PLOTLY_AVAILABLE = importlib.util.find_spec("plotly") is not None

def save_plot(fig, filename, static=None):
    """
    Save a Plotly figure for embedding in reports.

    Always produces the interactive forms (a standalone HTML file and the inline
    JSON used by the HTML reports). The static PNG (via kaleido) is only needed
    for Markdown/PDF and is the most fragile step -- kaleido 0.2.1 can hang on
    some platforms -- so it is opt-in (config ``reports.enable_static_charts``)
    and guarded; on failure the chart degrades to HTML-only.

    Args:
        fig (Figure): Plotly figure object
        filename (str): Base filename without extension
        static (bool|None): Force static PNG export on/off; defaults to the
            ENABLE_STATIC_CHARTS config flag.

    Returns:
        dict: Paths to saved files and inline JSON data ('png' is '' if skipped)
    """
    if not PLOTLY_AVAILABLE:
        # Return empty paths if plotly not available
        return {'png': '', 'html': '', 'json': '', 'plotly': None}

    os.makedirs(html_reports_folder, exist_ok=True)
    png_path = html_reports_folder / f'{filename}.png'
    html_path = html_reports_folder / f'{filename}.html'
    json_path = html_reports_folder / f'{filename}.json'

    # Static PNG export -- opt-in and guarded (see docstring).
    png_str = ''
    if ENABLE_STATIC_CHARTS if static is None else static:
        try:
            fig.write_image(png_path, width=800, height=500)
            png_str = str(png_path)
        except Exception as e:
            logger.warning(f"Static chart export failed for {filename}; "
                           f"chart will be HTML-only: {e}")

    fig.write_html(html_path)

    # Get Plotly figure as JSON for inline embedding
    import json as json_module
    fig_json = fig.to_json()

    # Save JSON file
    with open(json_path, 'w', encoding='utf-8') as f:
        f.write(fig_json)

    # Parse JSON string to dict for proper serialization across processes
    # This ensures it survives pickle/unpickle in multiprocessing and json.dump()
    fig_dict = json_module.loads(fig_json)

    return {
        'png': png_str,  # '' when static export is disabled/failed (HTML-only)
        'html': str(html_path),  # Convert PosixPath to string for JSON serialization
        'json': str(json_path),  # Convert PosixPath to string for JSON serialization
        'plotly': fig_dict  # Store as dict (not string) for proper serialization
    }

def generate_visualizations(domain, data):
    """
    Generate all visualizations for a domain.

    Args:
        domain (str): Domain name
        data (dict): Domain analysis data

    Returns:
        dict: Dictionary of visualization paths by type
    """
    if not PLOTLY_AVAILABLE:
        # Return empty visualizations if plotly not available
        return {}

    from visualizations.charts import (
        create_complexity_distribution_chart,
        create_compliance_distribution_chart,
        create_da_risk_chart,
        create_expiration_status_chart,
        create_last_password_set_chart,
        create_length_distribution_chart,
        create_password_age_chart,
        create_password_issues_chart,
        create_risk_factors_chart,
        create_risk_levels_chart,
        create_score_breakdown_chart,
        create_top_banned_words_chart,
    )
    from visualizations.networks import create_password_similarity_graph
    
    visuals = {}
    os.makedirs(html_reports_folder, exist_ok=True)

    # Risk Levels Chart
    fig = create_risk_levels_chart(domain, data)
    visuals['risk_levels'] = save_plot(fig, f'{domain}_risk_levels')
    
    # Score Components Breakdown
    fig = create_score_breakdown_chart(domain, data)
    visuals['score_breakdown'] = save_plot(fig, f'{domain}_score_breakdown')
    
    # Risk Factor Contribution Chart
    fig = create_risk_factors_chart(domain, data)
    visuals['risk_factors'] = save_plot(fig, f'{domain}_risk_factors')
    
    # Password Similarity Network
    fig = create_password_similarity_graph(domain, data)
    visuals['similarity_network'] = save_plot(fig, f'{domain}_similarity_network')

    # Password Issues Chart
    if data['issues_counter']:
        fig = create_password_issues_chart(domain, data)
        visuals['password_issues'] = save_plot(fig, f'{domain}_password_issues')

    # Password Length Distribution
    if data['password_lengths']:
        fig = create_length_distribution_chart(domain, data)
        visuals['length_distribution'] = save_plot(fig, f'{domain}_length_distribution')

    # Password Complexity Distribution
    if data['complexity_counter']:
        fig = create_complexity_distribution_chart(domain, data)
        visuals['complexity_distribution'] = save_plot(fig, f'{domain}_complexity_distribution')

    # Top Banned Words
    if data['banned_word_counter']:
        fig = create_top_banned_words_chart(domain, data)
        visuals['top_banned_words'] = save_plot(fig, f'{domain}_top_banned_words')

    # Last Password Set Distribution
    fig = create_last_password_set_chart(domain, data)
    if fig:
        visuals['last_password_set'] = save_plot(fig, f'{domain}_last_password_set')

    # Password Expiration Status
    fig = create_expiration_status_chart(domain, data)
    if fig:
        visuals['expiration_status'] = save_plot(fig, f'{domain}_expiration_status')

    # Out-of-Compliance Distribution
    fig = create_compliance_distribution_chart(domain, data)
    if fig:
        visuals['compliance_distribution'] = save_plot(fig, f'{domain}_compliance_distribution')

    # DA Pathways by Risk Level
    fig = create_da_risk_chart(domain, data)
    if fig:
        visuals['da_risk'] = save_plot(fig, f'{domain}_da_risk')

    # Password Age vs Risk Score
    fig = create_password_age_chart(domain, data)
    if fig:
        visuals['password_age'] = save_plot(fig, f'{domain}_password_age')

    # HIBP Breach Analysis - Adding missing visualizations
    from visualizations.charts import (
        create_hibp_breach_distribution_chart,
        create_hibp_top_breached_chart,
        create_hibp_vs_risk_chart,
    )

    # HIBP Breach Distribution
    fig = create_hibp_breach_distribution_chart(domain, data)
    if fig:
        visuals['hibp_breach_distribution'] = save_plot(fig, f'{domain}_hibp_breach_distribution')

    # HIBP Top Breached Passwords
    fig = create_hibp_top_breached_chart(domain, data)
    if fig:
        visuals['hibp_top_breached'] = save_plot(fig, f'{domain}_hibp_top_breached')

    # HIBP Breach Count vs Risk Score Correlation
    fig = create_hibp_vs_risk_chart(domain, data)
    if fig:
        visuals['hibp_vs_risk'] = save_plot(fig, f'{domain}_hibp_vs_risk')

    return visuals

def generate_combined_visualizations(combined_rows, global_password_to_users, global_hash_to_users):
    """
    Generate visualizations for combined cross-domain analysis.

    Args:
        combined_rows (list): Combined account rows across domains
        global_password_to_users (dict): Mapping of passwords to users across domains
        global_hash_to_users (dict): Mapping of hashes to users across domains

    Returns:
        dict: Dictionary of visualization paths by type
    """
    if not PLOTLY_AVAILABLE:
        # Return empty visualizations if plotly not available
        return {}

    from visualizations.charts import (
        create_combined_sharing_chart,
        create_da_exposure_chart,
        create_expiration_status_chart,
        create_last_password_set_chart,
        create_top_shared_hashes_chart,
        create_top_shared_passwords_chart,
    )
    from visualizations.networks import create_shared_network, create_sharing_heatmap
    
    visuals = {}
    os.makedirs(html_reports_folder, exist_ok=True)

    # Cross-Domain Sharing Chart
    fig = create_combined_sharing_chart(combined_rows, global_password_to_users, global_hash_to_users)
    if fig:
        visuals['combined_sharing'] = save_plot(fig, 'combined_sharing')

    # Sharing Heatmap
    fig = create_sharing_heatmap(combined_rows)
    if fig:
        visuals['sharing_heatmap'] = save_plot(fig, 'combined_sharing_heatmap')
    
    # Shared Network Visualization
    fig = create_shared_network(combined_rows)
    if fig:
        visuals['shared_network'] = save_plot(fig, 'combined_shared_network')

    # Top Shared Passwords
    fig = create_top_shared_passwords_chart(global_password_to_users)
    if fig:
        visuals['top_shared_passwords'] = save_plot(fig, 'combined_top_shared_passwords')

    # Top Shared Hashes
    fig = create_top_shared_hashes_chart(global_hash_to_users)
    if fig:
        visuals['top_shared_hashes'] = save_plot(fig, 'combined_top_shared_hashes')

    # Last Password Set Distribution
    fig = create_last_password_set_chart('Combined', {'output_rows': combined_rows})
    if fig:
        visuals['last_password_set'] = save_plot(fig, 'combined_last_password_set')

    # Password Expiration Status
    fig = create_expiration_status_chart('Combined', {'output_rows': combined_rows})
    if fig:
        visuals['expiration_status'] = save_plot(fig, 'combined_expiration_status')

    # DA Exposure by Domain
    fig = create_da_exposure_chart(combined_rows)
    if fig:
        visuals['da_exposure'] = save_plot(fig, 'combined_da_exposure')

    return visuals