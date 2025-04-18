# visualizations/risk.py
"""
Risk visualizations module for password security analysis.
Provides functions to create risk-related visualizations.
"""

import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import numpy as np
from datetime import datetime
from collections import Counter
import math

def create_risk_distribution_chart(domain, data):
    """
    Create a bar chart showing risk level distribution.
    
    Args:
        domain (str): Domain name
        data (dict): Domain analysis data or domain_risk data
        
    Returns:
        Figure: Plotly figure object
    """
    if 'domain_risk' in data:
        # Use domain risk data if available
        domain_risk = data['domain_risk']
        risk_distribution = domain_risk.get('risk_distribution', {})
    else:
        # Use risk counter
        risk_distribution = data.get('risk_counter', {})
    
    risk_levels = ['Critical', 'High', 'Medium', 'Low']
    counts = [risk_distribution.get(level, 0) for level in risk_levels]
    
    if sum(counts) == 0:
        fig = go.Figure()
        fig.update_layout(
            title=dict(text=f"{domain} - No Risk Data Available", font_size=20, x=0.5, xanchor='center'),
            annotations=[dict(text="No risk data available", x=0.5, y=0.5, font_size=14, showarrow=False)]
        )
        return fig
    
    colors = ['#D32F2F', '#FFA726', '#FFEB3B', '#66BB6A']  # Red, Orange, Yellow, Green
    
    fig = go.Figure(data=[go.Bar(
        x=risk_levels,
        y=counts,
        text=counts,
        textposition='auto',
        marker_color=colors
    )])
    
    fig.update_layout(
        title=dict(text=f"{domain} - Risk Level Distribution", font_size=20, x=0.5, xanchor='center'),
        xaxis_title="Risk Level",
        yaxis_title="Number of Accounts",
        margin=dict(t=60, b=40)
    )
    
    return fig

def create_risk_heatmap(domain, data):
    """
    Create a heatmap showing risk factors correlation.
    
    Args:
        domain (str): Domain analysis data
        data (dict): Domain analysis data
        
    Returns:
        Figure: Plotly figure object
    """
    # Extract score breakdown components
    risk_factors = {
        'Complexity': [],
        'Length': [],
        'Dictionary': [],
        'Similarity': [],
        'Compliance': [],
        'Expiration': [],
        'Privilege': [],
        'Sharing': [],
        'Domain Risk': []
    }
    
    # Collect factor values for cracked accounts
    for row in data['output_rows']:
        if row['Password Length'] == 'N/A':  # Skip uncracked accounts
            continue
            
        breakdown = row.get('Score Breakdown', {})
        
        # Base score components
        if 'base_components' in breakdown:
            base = breakdown['base_components']
            risk_factors['Complexity'].append(base.get('complexity_factor', 0))
            risk_factors['Length'].append(base.get('length_factor', 0))
            risk_factors['Dictionary'].append(base.get('dictionary_factor', 0))
            risk_factors['Similarity'].append(base.get('similarity_factor', 0))
        
        # Temporal score components
        if 'temporal_components' in breakdown:
            temporal = breakdown['temporal_components']
            risk_factors['Compliance'].append(temporal.get('compliance_factor', 0))
            risk_factors['Expiration'].append(temporal.get('expiration_factor', 0))
        
        # Environmental score components
        if 'environmental_components' in breakdown:
            env = breakdown['environmental_components']
            risk_factors['Privilege'].append(env.get('privilege_factor', 0))
            risk_factors['Sharing'].append(env.get('share_factor', 0))
            risk_factors['Domain Risk'].append(env.get('domain_factor', 0))
    
    # Check if we have enough data
    factor_names = list(risk_factors.keys())
    min_samples = min(len(values) for values in risk_factors.values())
    
    if min_samples < 5:  # Not enough data for meaningful correlation
        fig = go.Figure()
        fig.update_layout(
            title=dict(text=f"{domain} - Insufficient Data for Risk Correlation", font_size=20, x=0.5, xanchor='center'),
            annotations=[dict(text="Not enough data for risk factor correlation analysis", 
                            x=0.5, y=0.5, font_size=14, showarrow=False)]
        )
        return fig
    
    # Calculate correlation matrix
    corr_matrix = np.zeros((len(factor_names), len(factor_names)))
    
    for i, factor1 in enumerate(factor_names):
        for j, factor2 in enumerate(factor_names):
            values1 = risk_factors[factor1]
            values2 = risk_factors[factor2]
            
            # Calculate correlation (handle potential division by zero)
            if np.std(values1) == 0 or np.std(values2) == 0:
                corr = 0
            else:
                corr = np.corrcoef(values1, values2)[0, 1]
            
            corr_matrix[i, j] = corr
    
    # Create heatmap
    fig = go.Figure(data=go.Heatmap(
        z=corr_matrix,
        x=factor_names,
        y=factor_names,
        colorscale='RdBu_r',  # Red-White-Blue scale, red for positive correlation
        zmid=0,               # White at zero correlation
        text=[[f"{corr:.2f}" for corr in row] for row in corr_matrix],
        texttemplate="%{text}",
        hoverongaps=False
    ))
    
    fig.update_layout(
        title=dict(text=f"{domain} - Risk Factor Correlation", font_size=20, x=0.5, xanchor='center'),
        xaxis_title="Risk Factor",
        yaxis_title="Risk Factor",
        xaxis_tickangle=-45,
        margin=dict(t=60, b=40, l=40, r=40)
    )
    
    return fig

def create_risk_boxplot(domain, data):
    """
    Create boxplots showing risk score distribution by attribute.
    
    Args:
        domain (str): Domain name
        data (dict): Domain analysis data
        
    Returns:
        Figure: Plotly figure object
    """
    # Extract scores and attributes for cracked accounts
    scores = []
    attributes = {
        'Risk Level': [],
        'Sharing': [],
        'Password Length': [],
        'Complexity': [],
        'DA Pathway': [],
        'Password Expires': []
    }
    
    for row in data['output_rows']:
        if row['Password Length'] == 'N/A':  # Skip uncracked accounts
            continue
            
        # Get score and risk level
        score = row.get('Score', 0)
        scores.append(score)
        
        # Collect attribute values
        attributes['Risk Level'].append(row.get('Risk Level', 'Unknown'))
        
        # Categorize sharing
        shared_with = row.get('Shared With', 0)
        if shared_with == 0:
            sharing_cat = 'None'
        elif shared_with < 10:
            sharing_cat = 'Low (1-9)'
        elif shared_with < 100:
            sharing_cat = 'Medium (10-99)'
        else:
            sharing_cat = 'High (100+)'
        attributes['Sharing'].append(sharing_cat)
        
        # Categorize length
        length = row.get('Password Length', 0)
        if length < 8:
            length_cat = 'Very Short (<8)'
        elif length < 12:
            length_cat = 'Short (8-11)'
        elif length < 16:
            length_cat = 'Medium (12-15)'
        else:
            length_cat = 'Long (16+)'
        attributes['Password Length'].append(length_cat)
        
        # Categorize complexity
        complexity = row.get('Complexity Label', 'none')
        if complexity in ['mixedalphaspecialnum']:
            complexity_cat = 'Very High'
        elif complexity in ['mixedalphaspecial', 'upperalphaspecialnum', 'loweralphaspecialnum']:
            complexity_cat = 'High'
        elif complexity in ['mixedalphanum', 'upperalphaspecial', 'loweralphaspecial']:
            complexity_cat = 'Medium'
        else:
            complexity_cat = 'Low'
        attributes['Complexity'].append(complexity_cat)
        
        # DA Pathway
        has_da = row.get('DA Domains', 'None') not in ('None', 'Unknown', [])
        attributes['DA Pathway'].append('Yes' if has_da else 'No')
        
        # Password Expiration
        expires = row.get('Password Set to Expire', 'Unknown')
        attributes['Password Expires'].append(expires)
    
    if not scores:  # No data available
        fig = go.Figure()
        fig.update_layout(
            title=dict(text=f"{domain} - No Risk Score Data Available", font_size=20, x=0.5, xanchor='center'),
            annotations=[dict(text="No risk score data available", x=0.5, y=0.5, font_size=14, showarrow=False)]
        )
        return fig
    
    # Create subplot grid
    fig = make_subplots(
        rows=3, cols=2,
        subplot_titles=[f"Risk Score by {attr}" for attr in attributes.keys()],
        vertical_spacing=0.1,
        horizontal_spacing=0.1
    )
    
    # Add boxplots for each attribute
    row, col = 1, 1
    for attr, values in attributes.items():
        # Create categorical boxplot
        categories = sorted(set(values))
        
        if attr == 'Risk Level':
            # Custom sort order for risk levels
            categories = [c for c in ['Critical', 'High', 'Medium', 'Low'] if c in categories]
            colors = [
                'rgba(211, 47, 47, 0.7)',   # Red for Critical
                'rgba(255, 167, 38, 0.7)',  # Orange for High
                'rgba(255, 235, 59, 0.7)',  # Yellow for Medium
                'rgba(102, 187, 106, 0.7)'  # Green for Low
            ]
        else:
            colors = [
                'rgba(31, 119, 180, 0.7)',  # Blue
                'rgba(255, 127, 14, 0.7)',  # Orange
                'rgba(44, 160, 44, 0.7)',   # Green
                'rgba(214, 39, 40, 0.7)'    # Red
            ]
        
        for i, category in enumerate(categories):
            # Get scores for this category
            cat_scores = [score for score, val in zip(scores, values) if val == category]
            
            if cat_scores:
                color_idx = i % len(colors)
                fig.add_trace(
                    go.Box(
                        y=cat_scores,
                        name=category,
                        marker_color=colors[color_idx],
                        boxmean=True,  # Show mean as dashed line
                        showlegend=False
                    ),
                    row=row, col=col
                )
        
        # Update subplot layout
        fig.update_yaxes(title_text="Risk Score", range=[0, 10], row=row, col=col)
        
        # Move to next subplot position
        col += 1
        if col > 2:
            col = 1
            row += 1
    
    # Update overall layout
    fig.update_layout(
        title=dict(text=f"{domain} - Risk Score Distribution by Attribute", font_size=20, x=0.5, xanchor='center'),
        height=800,
        margin=dict(t=80, b=40),
        boxmode='group'
    )
    
    return fig

def create_risk_scatter_matrix(domain, data):
    """
    Create a scatter matrix showing relationships between risk factors.
    
    Args:
        domain (str): Domain name
        data (dict): Domain analysis data
        
    Returns:
        Figure: Plotly figure object
    """
    # Extract risk factors for cracked accounts
    factors = {
        'Score': [],
        'Length': [],
        'Complexity': [],
        'Dictionary': [],
        'Sharing': [],
        'Compliance': []
    }
    
    risk_levels = []
    
    for row in data['output_rows']:
        if row['Password Length'] == 'N/A':  # Skip uncracked accounts
            continue
            
        # Get score and risk level
        score = row.get('Score', 0)
        factors['Score'].append(score)
        risk_levels.append(row.get('Risk Level', 'Unknown'))
        
        # Get basic factors
        factors['Length'].append(row.get('Password Length', 0))
        factors['Sharing'].append(row.get('Shared With', 0))
        
        # Get complexity (convert to numeric: 0=low, 1=medium, 2=high)
        complexity = row.get('Complexity Label', 'none')
        if complexity in ['mixedalphaspecialnum', 'mixedalphaspecial', 'upperalphaspecialnum']:
            complexity_score = 2  # High
        elif complexity in ['loweralphaspecialnum', 'mixedalphanum', 'upperalphaspecial']:
            complexity_score = 1  # Medium
        else:
            complexity_score = 0  # Low
        factors['Complexity'].append(complexity_score)
        
        # Get dictionary status (0=none, 1=some issues, 2=major issues)
        dictionary_score = 0
        if row.get('Common Password', 'No') == 'Yes':
            dictionary_score = 2
        elif row.get('Is Exactly Dictionary Word', 'No') == 'Yes':
            dictionary_score = 2
        elif row.get('Forbidden Words', 'None') != 'None':
            dictionary_score = 1
        factors['Dictionary'].append(dictionary_score)
        
        # Get compliance days
        days = row.get('Days Out of Compliance', 0)
        if days == 'Unknown' or days == 'N/A':
            days = 0
        factors['Compliance'].append(int(days))
    
    if not factors['Score']:  # No data available
        fig = go.Figure()
        fig.update_layout(
            title=dict(text=f"{domain} - No Risk Factor Data Available", font_size=20, x=0.5, xanchor='center'),
            annotations=[dict(text="No risk factor data available", x=0.5, y=0.5, font_size=14, showarrow=False)]
        )
        return fig
    
    # Create scatter matrix
    # Convert to DataFrame structure expected by px.scatter_matrix
    import pandas as pd
    df = pd.DataFrame(factors)
    df['Risk Level'] = risk_levels
    
    # Define color map for risk levels
    color_map = {
        'Critical': '#D32F2F',  # Red
        'High': '#FFA726',     # Orange
        'Medium': '#FFEB3B',   # Yellow
        'Low': '#66BB6A'       # Green
    }
    
    fig = px.scatter_matrix(
        df,
        dimensions=['Score', 'Length', 'Complexity', 'Dictionary', 'Sharing', 'Compliance'],
        color='Risk Level',
        color_discrete_map=color_map,
        opacity=0.7
    )
    
    # Update layout
    fig.update_layout(
        title=dict(text=f"{domain} - Risk Factor Relationships", font_size=20, x=0.5, xanchor='center'),
        height=800,
        margin=dict(t=80, b=40)
    )
    
    # Update axis titles
    for axis in fig.layout:
        if axis.startswith('xaxis') or axis.startswith('yaxis'):
            fig.layout[axis].title.font.size = 10
    
    return fig