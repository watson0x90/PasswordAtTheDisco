# visualizations/charts.py
"""
Charts visualization module for password security analysis.
Provides functions to create various chart types.
"""

import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import numpy as np
from datetime import datetime
from collections import Counter, defaultdict
import math

def create_risk_levels_chart(domain, data):
    """
    Create a pie chart showing risk level distribution.
    
    Args:
        domain (str): Domain name
        data (dict): Domain analysis data
        
    Returns:
        Figure: Plotly figure object
    """
    risk_labels = ['Low (0.0-3.9)', 'Medium (4.0-5.9)', 'High (6.0-7.9)', 'Critical (8.0-10.0)']
    risk_counts = [
        data['risk_counter'].get('Low', 0),
        data['risk_counter'].get('Medium', 0),
        data['risk_counter'].get('High', 0),
        data['risk_counter'].get('Critical', 0)
    ]
    total = sum(risk_counts)
    
    if total == 0:
        # Create empty figure with message
        fig = go.Figure()
        fig.update_layout(
            title=dict(text=f"{domain} - No Risk Data Available", font_size=20, x=0.5, xanchor='center'),
            annotations=[dict(text="No risk data available", x=0.5, y=0.5, font_size=14, showarrow=False)]
        )
        return fig
    
    fig = go.Figure(data=[go.Pie(
        labels=risk_labels,
        values=risk_counts,
        marker_colors=['#66BB6A', '#FFEB3B', '#FFA726', '#D32F2F'],
        textinfo='label+percent',
        hoverinfo='label+value+percent',
        hole=0.3
    )])
    
    fig.update_layout(
        title=dict(text=f"{domain} - Password Risk Distribution (0-10 scale)", font_size=20, x=0.5, xanchor='center'),
        margin=dict(t=60, b=20, l=20, r=20),
        annotations=[dict(text=f'Total: {total}', x=0.5, y=0.5, font_size=14, showarrow=False)]
    )
    
    return fig

def create_score_breakdown_chart(domain, data):
    """
    Create a chart visualizing the score breakdown for different risk levels.
    
    Args:
        domain (str): Domain name
        data (dict): Domain analysis data
        
    Returns:
        Figure: Plotly figure object
    """
    # Group accounts by risk level
    risk_levels = ['Critical', 'High', 'Medium', 'Low']
    
    # Sample accounts for each risk level (max 5 per level for clarity)
    samples = {}
    for level in risk_levels:
        samples[level] = [row for row in data['output_rows'] 
                         if row.get('Risk Level') == level and 
                            row.get('Password Length', 'N/A') != 'N/A'][:5]
    
    # Create subplot grid (1 row per risk level)
    rows = sum(1 for level in risk_levels if samples[level])
    if rows == 0:
        # No data, create empty figure
        fig = go.Figure()
        fig.update_layout(
            title=dict(text=f"{domain} - No Score Breakdown Available", font_size=20, x=0.5, xanchor='center'),
            annotations=[dict(text="No score data available", x=0.5, y=0.5, font_size=14, showarrow=False)]
        )
        return fig
    
    # Create subplots
    fig = make_subplots(
        rows=rows, cols=1,
        subplot_titles=[f"{level} Risk Accounts - Score Breakdown" for level in risk_levels if samples[level]],
        vertical_spacing=0.1
    )
    
    # Color maps for different components
    color_map = {
        'base_score': '#1F77B4',  # Blue
        'temporal_score': '#FF7F0E',  # Orange
        'environmental_score': '#2CA02C'  # Green
    }
    
    # Add traces for each risk level
    current_row = 1
    for level in risk_levels:
        if not samples[level]:
            continue
        
        # Extract usernames and scores
        usernames = []
        base_scores = []
        temporal_scores = []
        environmental_scores = []
        
        for acc in samples[level]:
            usernames.append(acc['Username'])
            
            # Get score breakdown (or default values)
            breakdown = acc.get('Score Breakdown', {})
            base = breakdown.get('base_score', 0)
            temporal = breakdown.get('temporal_score', 0)
            environmental = breakdown.get('environmental_score', 0)
            
            base_scores.append(base)
            temporal_scores.append(temporal)
            environmental_scores.append(environmental)
        
        # Add base score bars
        fig.add_trace(
            go.Bar(
                x=usernames,
                y=base_scores,
                name=f'Base Score',
                marker_color=color_map['base_score'],
                text=base_scores,
                textposition='auto',
                hovertemplate='Username: %{x}<br>Base Score: %{y:.1f}<extra></extra>'
            ),
            row=current_row, col=1
        )
        
        # Add temporal score bars
        fig.add_trace(
            go.Bar(
                x=usernames,
                y=temporal_scores,
                name=f'Temporal Score',
                marker_color=color_map['temporal_score'],
                text=temporal_scores,
                textposition='auto',
                hovertemplate='Username: %{x}<br>Temporal Score: %{y:.1f}<extra></extra>'
            ),
            row=current_row, col=1
        )
        
        # Add environmental score bars
        fig.add_trace(
            go.Bar(
                x=usernames,
                y=environmental_scores,
                name=f'Environmental Score',
                marker_color=color_map['environmental_score'],
                text=environmental_scores,
                textposition='auto',
                hovertemplate='Username: %{x}<br>Environmental Score: %{y:.1f}<extra></extra>'
            ),
            row=current_row, col=1
        )
        
        # Add reference line at score threshold for this risk level
        threshold = 8.0 if level == 'Critical' else 6.0 if level == 'High' else 4.0 if level == 'Medium' else 0.0
        fig.add_shape(
            type="line",
            x0=-0.5,
            y0=threshold,
            x1=len(usernames) - 0.5,
            y1=threshold,
            line=dict(color="red", width=2, dash="dash"),
            row=current_row, col=1
        )
        
        # Increment row counter
        current_row += 1
    
    # Update layout
    fig.update_layout(
        title=dict(text=f"{domain} - Risk Score Breakdown by Account", font_size=20, x=0.5, xanchor='center'),
        barmode='group',
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="center", x=0.5),
        height=200 * rows + 100,
        showlegend=(rows == 1),  # Only show legend on the first subplot
        margin=dict(t=100, b=50)
    )
    
    # Update y-axis range for each subplot
    for i in range(1, rows + 1):
        fig.update_yaxes(title_text="Score (0-10)", range=[0, 10.5], row=i, col=1)
    
    return fig

def create_risk_factors_chart(domain, data):
    """
    Generate a radar chart showing the contribution of different risk factors.
    
    Args:
        domain (str): Domain name
        data (dict): Domain analysis data
        
    Returns:
        Figure: Plotly figure object
    """
    # Extract data from accounts by risk level
    risk_levels = ['Critical', 'High', 'Medium', 'Low']
    
    # Risk factor categories to analyze
    categories = [
        'complexity_factor',
        'length_factor',
        'dictionary_factor',
        'similarity_factor',
        'compliance_factor',
        'expiration_factor',
        'privilege_factor',
        'share_factor',
        'domain_factor'
    ]
    
    # Label mapping for display
    label_map = {
        'complexity_factor': 'Complexity',
        'length_factor': 'Length',
        'dictionary_factor': 'Dictionary',
        'similarity_factor': 'Similarity',
        'compliance_factor': 'Compliance',
        'expiration_factor': 'Expiration',
        'privilege_factor': 'Privilege',
        'share_factor': 'Sharing',
        'domain_factor': 'Domain Risk'
    }
    
    # Collect average factors by risk level
    factor_data = {}
    for level in risk_levels:
        accounts = [row for row in data['output_rows'] 
                   if row.get('Risk Level') == level and 
                      row.get('Password Length', 'N/A') != 'N/A']
        
        if not accounts:
            continue
            
        factor_data[level] = {'count': len(accounts)}
        
        # Calculate average for each factor
        for category in categories:
            if category in ['complexity_factor', 'length_factor', 'dictionary_factor', 'similarity_factor']:
                # Base score components
                values = []
                for acc in accounts:
                    breakdown = acc.get('Score Breakdown', {}).get('base_components', {})
                    if category in breakdown:
                        values.append(breakdown[category])
            elif category in ['compliance_factor', 'expiration_factor']:
                # Temporal score components
                values = []
                for acc in accounts:
                    breakdown = acc.get('Score Breakdown', {}).get('temporal_components', {})
                    if category in breakdown:
                        values.append(breakdown[category])
            elif category in ['privilege_factor', 'share_factor', 'domain_factor']:
                # Environmental score components
                values = []
                for acc in accounts:
                    breakdown = acc.get('Score Breakdown', {}).get('environmental_components', {})
                    if category in breakdown:
                        values.append(breakdown[category])
            
            factor_data[level][category] = sum(values) / len(values) if values else 0
    
    # Create radar chart
    if not factor_data:
        # No data, create empty figure
        fig = go.Figure()
        fig.update_layout(
            title=dict(text=f"{domain} - No Risk Factor Data Available", font_size=20, x=0.5, xanchor='center'),
            annotations=[dict(text="No risk factor data available", x=0.5, y=0.5, font_size=14, showarrow=False)]
        )
        return fig
    
    fig = go.Figure()
    
    # Color map for risk levels
    colors = {
        'Critical': '#D32F2F',  # Red
        'High': '#FFA726',     # Orange
        'Medium': '#FFEB3B',   # Yellow
        'Low': '#66BB6A'       # Green
    }
    
    # Add traces for each risk level
    for level, data in factor_data.items():
        # Scale factors to 0-10 for better visualization
        values = []
        for category in categories:
            # Different scaling for different factor types:
            if category in ['complexity_factor', 'length_factor']:
                # These are better when lower (0.0-1.0 scale), so invert and scale
                values.append((1.0 - data.get(category, 0)) * 10)
            else:
                # These are worse when higher (various scales), so scale to 0-10
                if category == 'dictionary_factor' or category == 'similarity_factor':
                    values.append(data.get(category, 0) * 10)  # Already 0-1 scale
                else:
                    # Map 1.0-1.5 scale to 0-10
                    factor_val = data.get(category, 1.0)
                    if category in ['privilege_factor', 'share_factor', 'domain_factor']:
                        normalized = (factor_val - 1.0) * 20  # 1.0-1.5 becomes 0-10
                    else:
                        normalized = (factor_val - 0.6) * 25  # 0.6-1.0 becomes 0-10
                    values.append(min(10, max(0, normalized)))
        
        # Add radar trace
        fig.add_trace(go.Scatterpolar(
            r=values,
            theta=[label_map[cat] for cat in categories],
            fill='toself',
            name=f"{level} Risk ({data['count']} accounts)",
            line_color=colors[level]
        ))
    
    # Update layout
    fig.update_layout(
        title=dict(text=f"{domain} - Risk Factor Contribution by Risk Level", font_size=20, x=0.5, xanchor='center'),
        polar=dict(
            radialaxis=dict(
                visible=True,
                range=[0, 10]
            )
        ),
        showlegend=True,
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="center", x=0.5)
    )
    
    return fig

def create_password_issues_chart(domain, data):
    """
    Create a bar chart showing common password issues.
    
    Args:
        domain (str): Domain name
        data (dict): Domain analysis data
        
    Returns:
        Figure: Plotly figure object
    """
    sorted_issues = sorted(data['issues_counter'].items(), key=lambda x: x[1], reverse=True)
    if not sorted_issues:
        return None
        
    issue_labels, issue_counts = zip(*sorted_issues)
    
    fig = go.Figure(data=[go.Bar(
        x=issue_labels,
        y=issue_counts,
        text=issue_counts,
        textposition='auto',
        marker=dict(color=issue_counts, colorscale='Blues', showscale=True)
    )])
    
    fig.update_layout(
        title=dict(text=f"{domain} - Common Password Issues", font_size=20, x=0.5, xanchor='center'),
        xaxis_title="Issue Type",
        yaxis_title="Number of Passwords",
        xaxis_tickangle=-45,
        margin=dict(t=60, b=40)
    )
    
    return fig

def create_length_distribution_chart(domain, data):
    """
    Create a histogram showing password length distribution.
    
    Args:
        domain (str): Domain name
        data (dict): Domain analysis data
        
    Returns:
        Figure: Plotly figure object
    """
    from core.config import policy
    
    if not data['password_lengths']:
        return None
        
    min_length = policy.get('min_length', 8)
    max_length = max(data['password_lengths']) if data['password_lengths'] else min_length + 10
    bin_size = 1
    
    fig = px.histogram(
        x=data['password_lengths'],
        nbins=int((max_length - min(data['password_lengths']) + 1) / bin_size),
        color_discrete_sequence=['#A5D6A7']
    )
    
    fig.add_vline(
        x=min_length, 
        line_dash="dash", 
        line_color="red", 
        annotation_text=f"Min: {min_length}", 
        annotation_position="top right"
    )
    
    fig.update_layout(
        title=dict(text=f"{domain} - Password Length Distribution", font_size=20, x=0.5, xanchor='center'),
        xaxis_title="Password Length",
        yaxis_title="Count",
        margin=dict(t=60, b=40, l=40, r=40)
    )
    
    return fig

def create_complexity_distribution_chart(domain, data):
    """
    Create a bar chart showing password complexity distribution.
    
    Args:
        domain (str): Domain name
        data (dict): Domain analysis data
        
    Returns:
        Figure: Plotly figure object
    """
    if not data['complexity_counter']:
        return None
        
    complexity_labels = [
        'loweralpha', 'upperalpha', 'numeric', 'special', 'loweralphanum', 'upperalphanum', 'mixedalpha',
        'loweralphaspecial', 'upperalphaspecial', 'specialnum', 'mixedalphanum', 'loweralphaspecialnum',
        'mixedalphaspecial', 'upperalphaspecialnum', 'mixedalphaspecialnum', 'none'
    ]
    
    filtered_labels = [label for label in complexity_labels if label in data['complexity_counter']]
    
    if not filtered_labels:
        return None
        
    complexity_counts = [data['complexity_counter'].get(label, 0) for label in filtered_labels]
    
    fig = go.Figure(data=[go.Bar(
        x=filtered_labels,
        y=complexity_counts,
        text=complexity_counts,
        textposition='auto',
        marker_color='#1F77B4'
    )])
    
    fig.update_layout(
        title=dict(text=f"{domain} - Password Complexity Distribution", font_size=20, x=0.5, xanchor='center'),
        xaxis_title="Complexity Category",
        yaxis_title="Number of Passwords",
        xaxis_tickangle=-45,
        margin=dict(t=60, b=40)
    )
    
    return fig

def create_top_banned_words_chart(domain, data):
    """
    Create a bar chart showing top banned words found in passwords.
    
    Args:
        domain (str): Domain name
        data (dict): Domain analysis data
        
    Returns:
        Figure: Plotly figure object
    """
    top_10 = data['banned_word_counter'].most_common(10)
    if not top_10:
        return None
        
    words, counts = zip(*top_10)
    
    fig = go.Figure(data=[go.Bar(
        x=words,
        y=counts,
        text=counts,
        textposition='auto',
        marker=dict(color=counts, colorscale='Reds', showscale=True)
    )])
    
    fig.update_layout(
        title=dict(text=f"{domain} - Top 10 Banned Words", font_size=20, x=0.5, xanchor='center'),
        xaxis_title="Banned Word",
        yaxis_title="Occurrences",
        xaxis_tickangle=-45,
        margin=dict(t=60, b=40)
    )
    
    return fig

def create_last_password_set_chart(domain, data):
    """
    Create a scatter chart showing last password set distribution.
    
    Args:
        domain (str): Domain name
        data (dict): Domain analysis data
        
    Returns:
        Figure: Plotly figure object or None if no data
    """
    valid_dates = []
    y_values = []
    
    for row in data['output_rows']:
        if row['Last Password Set'] not in ('Unknown', 'N/A'):
            try:
                date = datetime.strptime(row['Last Password Set'], '%Y-%m-%d')
                valid_dates.append(date.date())
                y_values.append(row['Score'])
            except (ValueError, TypeError):
                continue
    
    if not valid_dates:
        return None
    
    fig = go.Figure(data=[go.Scatter(
        x=valid_dates,
        y=y_values,
        mode='markers',
        marker=dict(color='blue', opacity=0.5, size=8),
        hovertemplate='Date: %{x}<br>Score: %{y}'
    )])
    
    fig.update_layout(
        title=dict(text=f"{domain} - Last Password Set vs. Risk Score", font_size=20, x=0.5, xanchor='center'),
        xaxis_title="Date Set",
        yaxis_title="Risk Score",
        xaxis_tickangle=-45,
        margin=dict(t=60, b=40)
    )
    
    return fig

def create_expiration_status_chart(domain, data):
    """
    Create a pie chart showing password expiration status.
    
    Args:
        domain (str): Domain name
        data (dict): Domain analysis data
        
    Returns:
        Figure: Plotly figure object or None if no data
    """
    expiration_counts = Counter()
    
    for row in data['output_rows']:
        if row['Password Set to Expire'] != 'Unknown':
            expiration_counts[row['Password Set to Expire']] += 1
    
    if not expiration_counts:
        return None
    
    labels = ['Expires', 'Does Not Expire']
    counts = [expiration_counts.get('Yes', 0), expiration_counts.get('No', 0)]
    
    if sum(counts) == 0:
        return None
    
    fig = go.Figure(data=[go.Pie(
        labels=labels,
        values=counts,
        marker_colors=['#4CAF50', '#F44336'],
        textinfo='label+percent',
        hoverinfo='label+value+percent',
        hole=0.3
    )])
    
    fig.update_layout(
        title=dict(text=f"{domain} - Password Expiration Status", font_size=20, x=0.5, xanchor='center'),
        margin=dict(t=60, b=20)
    )
    
    return fig

def create_compliance_distribution_chart(domain, data):
    """
    Create a bar chart showing out-of-compliance distribution.
    
    Args:
        domain (str): Domain name
        data (dict): Domain analysis data
        
    Returns:
        Figure: Plotly figure object or None if no data
    """
    compliance_counts = Counter()
    
    for row in data['output_rows']:
        days = row['Days Out of Compliance']
        if days != 'Unknown' and days != 'N/A':
            try:
                days_value = int(days)
                if days_value <= 30:
                    compliance_counts['0-30'] += 1
                elif days_value <= 90:
                    compliance_counts['31-90'] += 1
                elif days_value <= 180:
                    compliance_counts['91-180'] += 1
                else:
                    compliance_counts['181+'] += 1
            except (ValueError, TypeError):
                continue
    
    if not compliance_counts:
        return None
    
    # Sort by age categories
    categories = ['0-30', '31-90', '91-180', '181+']
    labels = [cat for cat in categories if cat in compliance_counts]
    counts = [compliance_counts.get(cat, 0) for cat in labels]
    
    if sum(counts) == 0:
        return None
    
    fig = go.Figure(data=[go.Bar(
        x=labels,
        y=counts,
        text=counts,
        textposition='auto',
        marker_color='#FF4136'
    )])
    
    fig.update_layout(
        title=dict(text=f"{domain} - Days Out of Compliance", font_size=20, x=0.5, xanchor='center'),
        xaxis_title="Days",
        yaxis_title="Accounts",
        margin=dict(t=60, b=40)
    )
    
    return fig

def create_da_risk_chart(domain, data):
    """
    Create a stacked bar chart showing DA pathways by risk level.
    
    Args:
        domain (str): Domain name
        data (dict): Domain analysis data
        
    Returns:
        Figure: Plotly figure object or None if no data
    """
    da_risk_counts = {'Low': 0, 'Medium': 0, 'High': 0, 'Critical': 0}
    
    for row in data['output_rows']:
        if row.get('DA Domains', 'None') not in ('None', 'Unknown'):
            da_risk_counts[row['Risk Level']] += 1
    
    if sum(da_risk_counts.values()) == 0:
        return None
    
    fig = go.Figure()
    colors = {'Low': '#66BB6A', 'Medium': '#FFEB3B', 'High': '#FFA726', 'Critical': '#D32F2F'}
    
    for risk, count in da_risk_counts.items():
        if count > 0:
            fig.add_trace(go.Bar(
                x=['DA Pathways'],
                y=[count],
                name=risk,
                marker_color=colors[risk],
                text=[count] if count > 0 else None,
                textposition='auto'
            ))
    
    fig.update_layout(
        title=dict(text=f"{domain} - DA Pathways by Risk", font_size=20, x=0.5, xanchor='center'),
        yaxis_title="Number of Accounts",
        barmode='stack',
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="center", x=0.5),
        margin=dict(t=60, b=40)
    )
    
    return fig

def create_password_age_chart(domain, data):
    """
    Create a scatter plot showing password age vs risk score.
    
    Args:
        domain (str): Domain name
        data (dict): Domain analysis data
        
    Returns:
        Figure: Plotly figure object or None if no data
    """
    valid_ages = []
    y_values = []
    
    for row in data['output_rows']:
        if row['Days Out of Compliance'] not in ('Unknown', 'N/A'):
            try:
                days = int(row['Days Out of Compliance'])
                valid_ages.append(days)
                y_values.append(row['Score'])
            except (ValueError, TypeError):
                continue
    
    if not valid_ages:
        return None
    
    fig = go.Figure(data=[go.Scatter(
        x=valid_ages,
        y=y_values,
        mode='markers',
        marker=dict(color='purple', opacity=0.5, size=8),
        hovertemplate='Days: %{x}<br>Score: %{y}'
    )])
    
    fig.update_layout(
        title=dict(text=f"{domain} - Password Age vs. Risk Score", font_size=20, x=0.5, xanchor='center'),
        xaxis_title="Days Out of Compliance",
        yaxis_title="Risk Score",
        margin=dict(t=60, b=40)
    )
    
    return fig

def create_combined_sharing_chart(combined_rows, global_password_to_users, global_hash_to_users):
    """
    Create a bar chart showing cross-domain password/hash sharing.
    
    Args:
        combined_rows (list): Combined account rows across domains
        global_password_to_users (dict): Mapping of passwords to users across domains
        global_hash_to_users (dict): Mapping of hashes to users across domains
        
    Returns:
        Figure: Plotly figure object or None if no data
    """
    password_sharing = Counter()
    hash_sharing = Counter()
    
    for row in combined_rows:
        if isinstance(row.get('Password', None), str) and len(row.get('Password', '')) > 0:
            password_or_hash = row['Password']
            if password_or_hash in global_password_to_users:
                password_sharing[row['Shared With']] += 1
            elif password_or_hash in global_hash_to_users:
                hash_sharing[row['Shared With']] += 1
    
    if not password_sharing and not hash_sharing:
        return None
    
    max_shared = max(max(password_sharing.keys(), default=0), max(hash_sharing.keys(), default=0))
    bin_size = max(1, (max_shared // 10) + 1)
    bins = [(i, min(i + bin_size - 1, max_shared)) for i in range(1, max_shared + 1, bin_size)]
    sharing_bins = [f"{lower}-{upper}" for lower, upper in bins]
    
    password_counts = [sum(password_sharing.get(i, 0) for i in range(lower, upper + 1)) for lower, upper in bins]
    hash_counts = [sum(hash_sharing.get(i, 0) for i in range(lower, upper + 1)) for lower, upper in bins]
    
    fig = go.Figure()
    fig.add_trace(go.Bar(
        x=sharing_bins, 
        y=password_counts, 
        name='Passwords', 
        marker_color='#1F77B4', 
        text=password_counts, 
        textposition='auto'
    ))
    fig.add_trace(go.Bar(
        x=sharing_bins, 
        y=hash_counts, 
        name='Hashes', 
        marker_color='#FF7F0E', 
        text=hash_counts, 
        textposition='auto'
    ))
    
    fig.update_layout(
        title=dict(text="Cross-Domain Password/Hash Sharing", font_size=20, x=0.5, xanchor='center'),
        xaxis_title="Number of Accounts Sharing",
        yaxis_title="Count",
        barmode='group',
        xaxis_tickangle=-45,
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="center", x=0.5),
        margin=dict(t=60, b=40)
    )
    
    return fig

def create_top_shared_passwords_chart(global_password_to_users):
    """
    Create a bar chart showing top shared passwords across domains.
    
    Args:
        global_password_to_users (dict): Mapping of passwords to users across domains
        
    Returns:
        Figure: Plotly figure object or None if no data
    """
    password_counts = Counter({pw: len(users) for pw, users in global_password_to_users.items() if len(users) > 1})
    top_passwords = password_counts.most_common(5)
    
    if not top_passwords:
        return None
    
    passwords, counts = zip(*top_passwords)
    
    # Truncate or mask passwords for display
    display_passwords = [f"{pw[:3]}***" if len(pw) > 6 else pw for pw in passwords]
    
    fig = go.Figure(data=[go.Bar(
        x=display_passwords,
        y=counts,
        text=counts,
        textposition='auto',
        marker_color='#1F77B4'
    )])
    
    fig.update_layout(
        title=dict(text="Top 5 Shared Passwords Across Domains", font_size=20, x=0.5, xanchor='center'),
        xaxis_title="Password",
        yaxis_title="Number of Accounts",
        xaxis_tickangle=-45,
        margin=dict(t=60, b=40)
    )
    
    return fig

def create_top_shared_hashes_chart(global_hash_to_users):
    """
    Create a bar chart showing top shared hashes across domains.
    
    Args:
        global_hash_to_users (dict): Mapping of hashes to users across domains
        
    Returns:
        Figure: Plotly figure object or None if no data
    """
    hash_counts = Counter({h: len(users) for h, users in global_hash_to_users.items() if len(users) > 1})
    top_hashes = hash_counts.most_common(5)
    
    if not top_hashes:
        return None
    
    hashes, counts = zip(*top_hashes)
    
    # Truncate hashes for display
    display_hashes = [f"{h[:8]}..." for h in hashes]
    
    fig = go.Figure(data=[go.Bar(
        x=display_hashes,
        y=counts,
        text=counts,
        textposition='auto',
        marker_color='#FF7F0E'
    )])
    
    fig.update_layout(
        title=dict(text="Top 5 Shared Hashes Across Domains", font_size=20, x=0.5, xanchor='center'),
        xaxis_title="Hash",
        yaxis_title="Number of Accounts",
        xaxis_tickangle=-45,
        margin=dict(t=60, b=40)
    )
    
    return fig

def create_da_exposure_chart(combined_rows):
    """
    Create a bar chart showing DA exposure by domain.
    
    Args:
        combined_rows (list): Combined account rows across domains
        
    Returns:
        Figure: Plotly figure object or None if no data
    """
    da_by_domain = defaultdict(lambda: {'total': 0, 'shared': 0})
    
    for row in combined_rows:
        domain = row.get('Domain', 'Unknown')
        if row.get('DA Domains', 'None') not in ('None', 'Unknown'):
            da_by_domain[domain]['total'] += 1
            if row['Shared With'] > 0:
                da_by_domain[domain]['shared'] += 1
    
    if not da_by_domain:
        return None
    
    domains = list(da_by_domain.keys())
    total_counts = [da_by_domain[d]['total'] for d in domains]
    shared_counts = [da_by_domain[d]['shared'] for d in domains]
    
    fig = go.Figure()
    fig.add_trace(go.Bar(
        x=domains, 
        y=total_counts, 
        name='Total DA', 
        marker_color='#1F77B4', 
        text=total_counts, 
        textposition='auto'
    ))
    fig.add_trace(go.Bar(
        x=domains, 
        y=shared_counts, 
        name='Shared DA', 
        marker_color='#FF4136', 
        text=shared_counts, 
        textposition='auto'
    ))
    
    fig.update_layout(
        title=dict(text="DA Exposure by Domain", font_size=20, x=0.5, xanchor='center'),
        xaxis_title="Domain",
        yaxis_title="Accounts",
        barmode='group',
        xaxis_tickangle=-45,
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="center", x=0.5),
        margin=dict(t=60, b=40)
    )
    
    return fig