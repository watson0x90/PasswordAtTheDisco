# visualizations/core.py
"""
Core visualization module for password security analysis.
Coordinates generation of various visualization types.
"""

import os
import plotly.graph_objects as go
import plotly.express as px
from core.config import html_reports_folder

def save_plot(fig, filename):
    """
    Save Plotly figure as PNG and HTML in html_report folder.
    
    Args:
        fig (Figure): Plotly figure object
        filename (str): Base filename without extension
        
    Returns:
        dict: Paths to saved PNG and HTML files
    """
    os.makedirs(html_reports_folder, exist_ok=True)
    png_path = html_reports_folder / f'{filename}.png'
    html_path = html_reports_folder / f'{filename}.html'
    
    fig.write_image(png_path, width=800, height=500)
    fig.write_html(html_path)
    
    return {'png': png_path, 'html': html_path}

def generate_visualizations(domain, data):
    """
    Generate all visualizations for a domain.
    
    Args:
        domain (str): Domain name
        data (dict): Domain analysis data
        
    Returns:
        dict: Dictionary of visualization paths by type
    """
    from visualizations.charts import (
        create_risk_levels_chart, create_password_issues_chart,
        create_length_distribution_chart, create_complexity_distribution_chart,
        create_top_banned_words_chart, create_last_password_set_chart,
        create_expiration_status_chart, create_compliance_distribution_chart,
        create_da_risk_chart, create_password_age_chart,
        create_score_breakdown_chart, create_risk_factors_chart
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
    from visualizations.charts import (
        create_combined_sharing_chart, create_last_password_set_chart,
        create_expiration_status_chart, create_da_exposure_chart,
        create_top_shared_passwords_chart, create_top_shared_hashes_chart
    )
    from visualizations.networks import (
        create_sharing_heatmap, create_shared_network
    )
    
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