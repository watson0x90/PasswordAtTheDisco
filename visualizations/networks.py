# visualizations/networks.py
"""
Networks visualization module for password security analysis.
Provides functions to create network graph visualizations.
"""

import plotly.graph_objects as go
import networkx as nx
import math
import re
from collections import defaultdict
import numpy as np

# Import CoreUI dark theme
from visualizations.theme import (
    get_dark_layout,
    get_risk_colors_list,
    get_legend_config,
    COREUI_COLORS
)


def rgb_string_to_tuple(rgb_str):
    """Convert 'rgb(r, g, b)' string to (r, g, b) tuple."""
    match = re.match(r'rgb\((\d+),\s*(\d+),\s*(\d+)\)', rgb_str)
    if match:
        return tuple(int(x) for x in match.groups())
    # Fallback for hex colors like '#6b7785'
    if rgb_str.startswith('#'):
        return (int(rgb_str[1:3], 16), int(rgb_str[3:5], 16), int(rgb_str[5:7], 16))
    return (128, 128, 128)  # Default gray

def get_password_similarity_network(data):
    """
    Extract password similarity data to build a network visualization.
    
    Args:
        data (dict): Domain analysis data
        
    Returns:
        list: Network data with nodes and edges
    """
    similarity_data = []
    
    # For each row with similar passwords, extract the similarity info
    for row in data['output_rows']:
        if row['Password Length'] == 'N/A':  # Skip uncracked accounts
            continue
            
        password = row['Password']
        similar_passwords_text = row.get('Similar Passwords', 'None')
        
        if similar_passwords_text == 'None':
            continue
            
        # Parse the similar passwords text
        # Format is: "password1 (90%), password2 (85%), ..."
        matches = re.findall(r'(.*?) \((\d+)%\)', similar_passwords_text)
        
        for similar_pw, similarity in matches:
            if int(similarity) >= 70:  # Only include matches with 70%+ similarity
                similarity_data.append({
                    'source': password,
                    'target': similar_pw.strip(),
                    'weight': int(similarity) / 100,
                    'count': 1
                })
    
    # Combine duplicate edges and sum their counts
    combined_data = defaultdict(int)
    for item in similarity_data:
        key = tuple(sorted([item['source'], item['target']]))
        combined_data[key] += 1
    
    # Convert back to list format
    network_data = []
    for (source, target), count in combined_data.items():
        # Find the original weight
        weight = next((item['weight'] for item in similarity_data 
                     if (item['source'] == source and item['target'] == target) or 
                        (item['source'] == target and item['target'] == source)), 0.7)
        
        network_data.append({
            'source': source,
            'target': target,
            'weight': weight,
            'count': count
        })
    
    return network_data

def create_password_similarity_graph(domain, data):
    """
    Generate a network graph showing password similarity relationships.
    
    Args:
        domain (str): Domain name
        data (dict): Domain analysis data
        
    Returns:
        Figure: Plotly figure object
    """
    similarity_data = get_password_similarity_network(data)
    
    if not similarity_data:
        # No similarity data, create empty figure
        fig = go.Figure()
        fig.update_layout(
            **get_dark_layout(title=f"{domain} - No Similar Passwords Detected"),
            annotations=[dict(
                text="No passwords with significant similarity were found",
                x=0.5, y=0.5,
                font=dict(size=14, color=COREUI_COLORS['body_color']),
                showarrow=False
            )]
        )
        return fig
    
    # Create networkx graph
    G = nx.Graph()
    
    # Add edges with weights
    for item in similarity_data:
        G.add_edge(item['source'], item['target'], weight=item['weight'], count=item['count'])
    
    # Calculate node sizes based on degree centrality
    centrality = nx.degree_centrality(G)
    max_centrality = max(centrality.values()) if centrality else 0.1
    for node in G.nodes():
        G.nodes[node]['size'] = 5 + (centrality[node] / max_centrality) * 25
    
    # Calculate positions using a force-directed layout
    pos = nx.spring_layout(G, weight='weight', k=0.3, iterations=50, seed=42)
    
    # Create edge trace
    edge_trace = []
    for edge in G.edges(data=True):
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        weight = edge[2]['weight']
        count = edge[2]['count']
        
        # Set color based on weight (similarity) - using CoreUI danger/warning/info colors
        # Convert rgb() format to rgba() by adding alpha channel
        if weight >= 0.9:
            color = COREUI_COLORS["danger"].replace('rgb(', 'rgba(').replace(')', ', 0.7)')  # Red for high similarity
        elif weight >= 0.8:
            color = COREUI_COLORS["warning"].replace('rgb(', 'rgba(').replace(')', ', 0.7)')  # Orange for medium-high
        else:
            color = COREUI_COLORS["info"].replace('rgb(', 'rgba(').replace(')', ', 0.7)')  # Blue for lower similarity
            
        # Line width based on count and weight
        width = math.log(count + 1) * weight * 3
        
        # Create edge trace
        edge_trace.append(go.Scatter(
            x=[x0, x1, None],
            y=[y0, y1, None],
            mode='lines',
            line=dict(color=color, width=width),
            hoverinfo='text',
            text=f"Similarity: {weight*100:.0f}%, Count: {count}",
            showlegend=False
        ))
    
    # Create node trace
    node_x = []
    node_y = []
    node_text = []
    node_size = []
    node_color = []
    
    for node in G.nodes(data=True):
        x, y = pos[node[0]]
        node_x.append(x)
        node_y.append(y)
        centrality_value = centrality[node[0]]
        connections = len(list(G.neighbors(node[0])))
        node_text.append(f"Password: {node[0]}<br>Connected to: {connections} other passwords<br>Centrality: {centrality_value:.3f}")
        node_size.append(node[1].get('size', 10))
        
        # Color nodes based on connectivity - using CoreUI colors
        if connections >= 5:
            node_color.append(COREUI_COLORS['danger'])  # Highly connected passwords
        elif connections >= 3:
            node_color.append(COREUI_COLORS['warning'])  # Moderately connected
        else:
            node_color.append(COREUI_COLORS['info'])  # Less connected
    
    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode='markers',
        hoverinfo='text',
        text=node_text,
        marker=dict(
            color=node_color,
            size=node_size,
            line=dict(width=1, color=COREUI_COLORS['border_color'])
        ),
        showlegend=False
    )
    
    # Create figure
    fig = go.Figure(data=edge_trace + [node_trace])
    
    # Add legend for edge colors - using CoreUI theme colors
    fig.add_trace(go.Scatter(
        x=[None], y=[None],
        mode='lines',
        line=dict(color=COREUI_COLORS["info"].replace('rgb(', 'rgba(').replace(')', ', 0.7)'), width=4),
        name='70-79% Similar'
    ))

    fig.add_trace(go.Scatter(
        x=[None], y=[None],
        mode='lines',
        line=dict(color=COREUI_COLORS["warning"].replace('rgb(', 'rgba(').replace(')', ', 0.7)'), width=4),
        name='80-89% Similar'
    ))

    fig.add_trace(go.Scatter(
        x=[None], y=[None],
        mode='lines',
        line=dict(color=COREUI_COLORS["danger"].replace('rgb(', 'rgba(').replace(')', ', 0.7)'), width=4),
        name='90-100% Similar'
    ))

    # Add legend for node colors - using CoreUI theme colors
    fig.add_trace(go.Scatter(
        x=[None], y=[None],
        mode='markers',
        marker=dict(color=COREUI_COLORS['danger'], size=15),
        name='5+ Similar Passwords'
    ))

    fig.add_trace(go.Scatter(
        x=[None], y=[None],
        mode='markers',
        marker=dict(color=COREUI_COLORS['warning'], size=15),
        name='3-4 Similar Passwords'
    ))

    fig.add_trace(go.Scatter(
        x=[None], y=[None],
        mode='markers',
        marker=dict(color=COREUI_COLORS['info'], size=15),
        name='1-2 Similar Passwords'
    ))
    
    # Update layout with dark theme
    # Note: get_dark_layout already includes xaxis/yaxis, so we merge with update()
    layout = get_dark_layout(title=f"{domain} - Password Similarity Network")
    layout.update({
        'showlegend': True,
        'legend': get_legend_config(orientation="h", position="top"),
        'hovermode': 'closest',
        'height': 600
    })
    # Update xaxis/yaxis separately to hide grid for network graph
    layout['xaxis'].update(dict(showgrid=False, zeroline=False, showticklabels=False))
    layout['yaxis'].update(dict(showgrid=False, zeroline=False, showticklabels=False))
    fig.update_layout(**layout)
    
    return fig

def create_sharing_heatmap(combined_rows):
    """
    Create a cross-domain sharing matrix heatmap.
    
    Args:
        combined_rows (list): Combined account rows across domains
        
    Returns:
        Figure: Plotly figure object or None if no data
    """
    if not combined_rows:
        return None
        
    # Extract all domains
    all_domains = set()
    domain_pairs = defaultdict(int)
    
    for row in combined_rows:
        if 'Domains Shared' in row and row['Domains Shared']:
            domains = row['Domains Shared'].split(', ')
            this_domain = row.get('Domain', 'Unknown')
            all_domains.add(this_domain)
            
            for d in domains:
                all_domains.add(d)
                if d != this_domain:
                    # Sort domains alphabetically to avoid duplicates
                    key = tuple(sorted([this_domain, d]))
                    domain_pairs[key] += 1
    
    if not domain_pairs:
        return None
        
    # Create matrix
    domains_list = sorted(all_domains)
    matrix = np.zeros((len(domains_list), len(domains_list)))
    
    # Fill the matrix
    for (d1, d2), count in domain_pairs.items():
        try:
            i = domains_list.index(d1)
            j = domains_list.index(d2)
            matrix[i][j] = count
            matrix[j][i] = count  # Mirror for the heatmap
        except ValueError:
            continue  # Skip if domain not found
    
    # Create heatmap with dark-friendly colorscale
    fig = go.Figure(data=go.Heatmap(
        z=matrix,
        x=domains_list,
        y=domains_list,
        colorscale='Reds',  # Dark-friendly colorscale
        text=matrix.astype(int),
        texttemplate="%{text}",
        textfont=dict(color=COREUI_COLORS['body_color']),
        hoverongaps=False
    ))

    fig.update_layout(
        **get_dark_layout(title="Cross-Domain Password Sharing Matrix")
    )
    
    return fig

def create_shared_network(combined_rows):
    """
    Create a network visualization of cross-domain sharing.
    
    Args:
        combined_rows (list): Combined account rows across domains
        
    Returns:
        Figure: Plotly figure object or None if no data
    """
    if not combined_rows:
        return None
        
    # Extract domains and sharing relationships
    all_domains = set()
    domain_pairs = defaultdict(int)
    
    for row in combined_rows:
        if 'Domains Shared' in row and row['Domains Shared']:
            domains = row['Domains Shared'].split(', ')
            this_domain = row.get('Domain', 'Unknown')
            all_domains.add(this_domain)
            
            for d in domains:
                all_domains.add(d)
                if d != this_domain:
                    # Sort domains alphabetically to avoid duplicates
                    key = tuple(sorted([this_domain, d]))
                    domain_pairs[key] += 1
    
    if len(all_domains) <= 1 or not domain_pairs:
        return None
        
    # Create networkx graph
    G = nx.Graph()
    
    # Add nodes
    for domain in all_domains:
        G.add_node(domain)
    
    # Add edges with weights
    for (d1, d2), count in domain_pairs.items():
        G.add_edge(d1, d2, weight=count)
    
    # Calculate node sizes based on degree
    degree = dict(G.degree())
    max_degree = max(degree.values()) if degree else 1
    node_sizes = {node: 20 + (deg / max_degree) * 30 for node, deg in degree.items()}
    
    # Calculate positions using a force-directed layout
    pos = nx.spring_layout(G, weight='weight', k=0.3, iterations=50, seed=42)
    
    # Create edge traces
    edge_traces = []
    for (d1, d2, weight) in G.edges(data='weight'):
        x0, y0 = pos[d1]
        x1, y1 = pos[d2]
        
        width = 1 + math.log(weight + 1)
        # Use CoreUI warning color with varying opacity based on weight
        warning_rgb = rgb_string_to_tuple(COREUI_COLORS["warning"])
        opacity = min(0.4 + (weight * 0.05), 0.8)
        color = f'rgba({warning_rgb[0]}, {warning_rgb[1]}, {warning_rgb[2]}, {opacity})'

        edge_traces.append(go.Scatter(
            x=[x0, x1, None],
            y=[y0, y1, None],
            mode='lines',
            line=dict(width=width, color=color),
            hoverinfo='text',
            text=f"{d1} ↔ {d2}: {weight} shared passwords",
            showlegend=False
        ))
    
    # Create node trace
    node_x = []
    node_y = []
    node_text = []
    node_size = []
    
    for node in G.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)
        connected_to = ", ".join(neighbor for neighbor in G.neighbors(node))
        shared_count = sum(G[node][neighbor]['weight'] for neighbor in G.neighbors(node))
        node_text.append(f"Domain: {node}<br>Connected to: {connected_to}<br>Total shared: {shared_count}")
        node_size.append(node_sizes[node])
    
    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode='markers+text',
        marker=dict(
            size=node_size,
            color=COREUI_COLORS['primary'],
            line=dict(width=1, color=COREUI_COLORS['border_color'])
        ),
        text=list(G.nodes()),
        textposition="top center",
        textfont=dict(color=COREUI_COLORS['body_color']),
        hoverinfo='text',
        hovertext=node_text,
        showlegend=False
    )
    
    # Create figure
    fig = go.Figure(data=edge_traces + [node_trace])
    
    layout = get_dark_layout(title="Cross-Domain Password Sharing Network")
    layout.update({
        'showlegend': False,
        'hovermode': 'closest',
        'height': 600
    })
    layout['xaxis'].update(dict(showgrid=False, zeroline=False, showticklabels=False))
    layout['yaxis'].update(dict(showgrid=False, zeroline=False, showticklabels=False))
    fig.update_layout(**layout)
    
    return fig

def create_risk_network(data):
    """
    Create a network visualization of password risk relationships.
    
    Args:
        data (dict): Domain analysis data
        
    Returns:
        Figure: Plotly figure object
    """
    # Extract accounts by risk level
    risk_levels = ['Critical', 'High', 'Medium', 'Low']
    
    # Track accounts by risk level for node coloring
    risk_to_accounts = {level: [] for level in risk_levels}
    
    # Create networkx graph
    G = nx.Graph()
    
    # Add nodes (accounts) and track by risk level
    for row in data['output_rows']:
        if row['Password Length'] == 'N/A':  # Skip uncracked accounts
            continue
            
        username = row['Username']
        risk_level = row.get('Risk Level', 'Unknown')
        
        if risk_level in risk_levels:
            G.add_node(username, risk=risk_level, score=row.get('Score', 0))
            risk_to_accounts[risk_level].append(username)
    
    # Add edges for:
    # 1. Shared passwords
    password_to_accounts = defaultdict(list)
    for row in data['output_rows']:
        if row['Password Length'] != 'N/A':
            password_to_accounts[row['Password']].append(row['Username'])
            
    for password, accounts in password_to_accounts.items():
        if len(accounts) > 1:
            for i in range(len(accounts)):
                for j in range(i+1, len(accounts)):
                    G.add_edge(accounts[i], accounts[j], type='shared_password')
    
    # 2. Similar passwords (based on Similar Passwords field)
    for row in data['output_rows']:
        if row['Password Length'] == 'N/A':
            continue
            
        username = row['Username']
        similar_passwords_text = row.get('Similar Passwords', 'None')
        
        if similar_passwords_text == 'None':
            continue
            
        # Find usernames with similar passwords
        matches = re.findall(r'(.*?) \((\d+)%\)', similar_passwords_text)
        for similar_pw, similarity in matches:
            similar_accounts = password_to_accounts.get(similar_pw.strip(), [])
            for similar_account in similar_accounts:
                if similar_account != username:
                    G.add_edge(username, similar_account, type='similar_password', 
                              similarity=int(similarity) / 100)
    
    # No edges, create simple visualization
    if not G.edges():
        fig = go.Figure()
        fig.update_layout(
            **get_dark_layout(title="No Password Risk Relationships Found"),
            annotations=[dict(
                text="No shared or similar password relationships detected",
                x=0.5, y=0.5,
                font=dict(size=14, color=COREUI_COLORS['body_color']),
                showarrow=False
            )]
        )
        return fig
    
    # Calculate positions using a force-directed layout
    pos = nx.spring_layout(G, k=0.3, iterations=50, seed=42)
    
    # Create edge traces
    edge_trace_shared = []
    edge_trace_similar = []
    
    for edge in G.edges(data=True):
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        
        if edge[2].get('type') == 'shared_password':
            # Use CoreUI info color for shared passwords
            info_rgb = rgb_string_to_tuple(COREUI_COLORS["info"])
            edge_trace_shared.append(go.Scatter(
                x=[x0, x1, None],
                y=[y0, y1, None],
                mode='lines',
                line=dict(width=2, color=f'rgba({info_rgb[0]}, {info_rgb[1]}, {info_rgb[2]}, 0.7)'),
                hoverinfo='text',
                text=f"Shared password: {edge[0]} and {edge[1]}",
                showlegend=False
            ))
        else:  # similar_password
            similarity = edge[2].get('similarity', 0.7)
            width = 1 + similarity * 3
            # Use CoreUI danger color for similar passwords
            danger_rgb = rgb_string_to_tuple(COREUI_COLORS["danger"])
            edge_trace_similar.append(go.Scatter(
                x=[x0, x1, None],
                y=[y0, y1, None],
                mode='lines',
                line=dict(width=width, color=f'rgba({danger_rgb[0]}, {danger_rgb[1]}, {danger_rgb[2]}, 0.7)'),
                hoverinfo='text',
                text=f"Similar passwords: {edge[0]} and {edge[1]} ({similarity*100:.0f}% similar)",
                showlegend=False
            ))
    
    # Create node traces by risk level using CoreUI risk colors
    node_traces = []
    risk_colors = get_risk_colors_list()
    colors = {
        'Critical': risk_colors[0],  # Critical red
        'High': risk_colors[1],      # High orange
        'Medium': risk_colors[2],    # Medium yellow
        'Low': risk_colors[3]        # Low green
    }
    
    for risk, accounts in risk_to_accounts.items():
        if not accounts:
            continue
            
        node_x = []
        node_y = []
        node_text = []
        
        for account in accounts:
            x, y = pos[account]
            node_x.append(x)
            node_y.append(y)
            score = G.nodes[account].get('score', 0)
            node_text.append(f"Account: {account}<br>Risk: {risk}<br>Score: {score}")
        
        node_traces.append(go.Scatter(
            x=node_x, y=node_y,
            mode='markers',
            marker=dict(
                size=10,
                color=colors[risk],
                line=dict(width=1, color=COREUI_COLORS['border_color'])
            ),
            hoverinfo='text',
            text=node_text,
            name=f"{risk} Risk"
        ))
    
    # Create figure
    fig = go.Figure(data=edge_trace_shared + edge_trace_similar + node_traces)
    
    # Add legend for edge types using CoreUI colors
    info_rgb = rgb_string_to_tuple(COREUI_COLORS["info"])
    danger_rgb = rgb_string_to_tuple(COREUI_COLORS["danger"])

    fig.add_trace(go.Scatter(
        x=[None], y=[None],
        mode='lines',
        line=dict(color=f'rgba({info_rgb[0]}, {info_rgb[1]}, {info_rgb[2]}, 0.7)', width=4),
        name='Shared Password'
    ))

    fig.add_trace(go.Scatter(
        x=[None], y=[None],
        mode='lines',
        line=dict(color=f'rgba({danger_rgb[0]}, {danger_rgb[1]}, {danger_rgb[2]}, 0.7)', width=4),
        name='Similar Password'
    ))
    
    # Update layout with dark theme
    layout = get_dark_layout(title="Password Risk Relationship Network")
    layout.update({
        'showlegend': True,
        'legend': get_legend_config(orientation="h", position="top"),
        'hovermode': 'closest',
        'height': 600
    })
    layout['xaxis'].update(dict(showgrid=False, zeroline=False, showticklabels=False))
    layout['yaxis'].update(dict(showgrid=False, zeroline=False, showticklabels=False))
    fig.update_layout(**layout)
    
    return fig