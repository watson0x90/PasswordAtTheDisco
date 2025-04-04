import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import numpy as np
from core.config import reports_folder, policy
from datetime import datetime
from collections import Counter, defaultdict
import os

html_reports_folder = reports_folder / 'html_report'

def save_plot(fig, filename):
    """Save Plotly figure as PNG and HTML in html_report folder."""
    os.makedirs(html_reports_folder, exist_ok=True)
    png_path = html_reports_folder / f'{filename}.png'
    html_path = html_reports_folder / f'{filename}.html'
    fig.write_image(png_path, width=800, height=500)
    fig.write_html(html_path)
    return {'png': png_path, 'html': html_path}

def generate_visualizations(domain, data):
    visuals = {}
    os.makedirs(html_reports_folder, exist_ok=True)

    # Pie Chart: Risk Levels
    risk_labels = ['Low', 'Medium', 'High', 'Critical']
    risk_counts = [data['risk_counter'].get(label, 0) for label in risk_labels]
    total = sum(risk_counts)
    if total > 0:
        fig = go.Figure(data=[go.Pie(
            labels=risk_labels,
            values=risk_counts,
            marker_colors=['#66BB6A', '#FFEB3B', '#FFA726', '#D32F2F'],
            textinfo='label+percent',
            hoverinfo='label+value+percent',
            hole=0.3
        )])
        fig.update_layout(
            title=dict(text=f"{domain} - Password Risk Distribution", font_size=20, x=0.5, xanchor='center'),
            margin=dict(t=60, b=20, l=20, r=20),
            annotations=[dict(text=f'Total: {total}', x=0.5, y=0.5, font_size=14, showarrow=False)]
        )
        visuals['risk_levels'] = save_plot(fig, f'{domain}_risk_levels')

    # Bar Graph: Common Password Issues
    if data['issues_counter']:
        sorted_issues = sorted(data['issues_counter'].items(), key=lambda x: x[1], reverse=True)
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
        visuals['password_issues'] = save_plot(fig, f'{domain}_password_issues')

    # Histogram: Password Length Distribution
    if data['password_lengths']:
        min_length = policy.get('min_length', 8)
        fig = px.histogram(
            x=data['password_lengths'],
            nbins=max(data['password_lengths']) - min(data['password_lengths']) + 1,
            color_discrete_sequence=['#A5D6A7']
        )
        fig.add_vline(x=min_length, line_dash="dash", line_color="red", annotation_text=f"Min: {min_length}", annotation_position="top right")
        fig.update_layout(
            title=dict(text=f"{domain} - Password Length Distribution", font_size=20, x=0.5, xanchor='center'),
            xaxis_title="Password Length",
            yaxis_title="Count",
            margin=dict(t=60, b=40, l=40, r=40)
        )
        visuals['length_distribution'] = save_plot(fig, f'{domain}_length_distribution')

    # Bar Graph: Password Complexity Distribution
    if data['complexity_counter']:
        complexity_labels = [
            'loweralpha', 'upperalpha', 'numeric', 'special', 'loweralphanum', 'upperalphanum', 'mixedalpha',
            'loweralphaspecial', 'upperalphaspecial', 'specialnum', 'mixedalphanum', 'loweralphaspecialnum',
            'mixedalphaspecial', 'upperalphaspecialnum', 'mixedalphaspecialnum', 'none'
        ]
        complexity_counts = [data['complexity_counter'].get(label, 0) for label in complexity_labels]
        fig = go.Figure(data=[go.Bar(
            x=complexity_labels,
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
        visuals['complexity_distribution'] = save_plot(fig, f'{domain}_complexity_distribution')

    # Bar Chart: Top 10 Most Common Banned Words
    if data['banned_word_counter']:
        top_10 = data['banned_word_counter'].most_common(10)
        if top_10:
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
            visuals['top_banned_words'] = save_plot(fig, f'{domain}_top_banned_words')

    # Scatter Chart: Last Password Set Distribution
    valid_dates = [datetime.strptime(row['Last Password Set'], '%Y-%m-%d') for row in data['output_rows'] if row['Last Password Set'] not in ('Unknown', 'N/A')]
    if valid_dates:
        dates = [d.date() for d in valid_dates]
        y_values = [row['Score'] for row in data['output_rows'] if row['Last Password Set'] not in ('Unknown', 'N/A')]
        fig = go.Figure(data=[go.Scatter(
            x=dates,
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
        visuals['last_password_set'] = save_plot(fig, f'{domain}_last_password_set')

    # Pie Chart: Password Expiration Status
    expiration_counts = Counter(row['Password Set to Expire'] for row in data['output_rows'] if row['Password Set to Expire'] != 'Unknown')
    if expiration_counts:
        labels = ['Expires', 'Does Not Expire']
        counts = [expiration_counts.get('Yes', 0), expiration_counts.get('No', 0)]
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
        visuals['expiration_status'] = save_plot(fig, f'{domain}_expiration_status')

    # Bar Chart: Out-of-Compliance Distribution
    compliance_counts = Counter()
    for row in data['output_rows']:
        days = row['Days Out of Compliance']
        if days != 'Unknown' and days != 'N/A':
            if days <= 30:
                compliance_counts['0-30'] += 1
            elif days <= 90:
                compliance_counts['31-90'] += 1
            elif days <= 180:
                compliance_counts['91-180'] += 1
            else:
                compliance_counts['181+'] += 1
    if compliance_counts:
        labels = list(compliance_counts.keys())
        counts = list(compliance_counts.values())
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
        visuals['compliance_distribution'] = save_plot(fig, f'{domain}_compliance_distribution')

    # Stacked Bar Chart: DA Pathways by Risk Level
    da_risk_counts = {'Low': 0, 'Medium': 0, 'High': 0, 'Critical': 0}
    for row in data['output_rows']:
        if row.get('DA Domains', 'None') not in ('None', 'Unknown'):
            da_risk_counts[row['Risk Level']] += 1
    if any(da_risk_counts.values()):
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
        visuals['da_risk'] = save_plot(fig, f'{domain}_da_risk')

    # Scatter Plot: Password Age Distribution
    valid_ages = [row['Days Out of Compliance'] for row in data['output_rows'] if row['Days Out of Compliance'] not in ('Unknown', 'N/A')]
    if valid_ages:
        y_values = [row['Score'] for row in data['output_rows'] if row['Days Out of Compliance'] not in ('Unknown', 'N/A')]
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
        visuals['password_age'] = save_plot(fig, f'{domain}_password_age')

    return visuals

def generate_combined_visualizations(combined_rows, global_password_to_users, global_hash_to_users):
    visuals = {}
    os.makedirs(html_reports_folder, exist_ok=True)

    # Bar Chart: Cross-Domain Sharing
    password_sharing = Counter()
    hash_sharing = Counter()
    for row in combined_rows:
        if row['Password'] in global_password_to_users:
            password_sharing[row['Shared With']] += 1
        elif row['Password'] in global_hash_to_users:
            hash_sharing[row['Shared With']] += 1
    if password_sharing or hash_sharing:
        max_shared = max(max(password_sharing.keys(), default=0), max(hash_sharing.keys(), default=0))
        bin_size = max(1, (max_shared // 10) + 1)
        bins = [(i, min(i + bin_size - 1, max_shared)) for i in range(1, max_shared + 1, bin_size)]
        sharing_bins = [f"{lower}-{upper}" for lower, upper in bins]
        password_counts = [sum(password_sharing.get(i, 0) for i in range(lower, upper + 1)) for lower, upper in bins]
        hash_counts = [sum(hash_sharing.get(i, 0) for i in range(lower, upper + 1)) for lower, upper in bins]
        
        fig = go.Figure()
        fig.add_trace(go.Bar(x=sharing_bins, y=password_counts, name='Passwords', marker_color='#1F77B4', text=password_counts, textposition='auto'))
        fig.add_trace(go.Bar(x=sharing_bins, y=hash_counts, name='Hashes', marker_color='#FF7F0E', text=hash_counts, textposition='auto'))
        fig.update_layout(
            title=dict(text="Cross-Domain Password/Hash Sharing", font_size=20, x=0.5, xanchor='center'),
            xaxis_title="Number of Accounts Sharing",
            yaxis_title="Count",
            barmode='group',
            xaxis_tickangle=-45,
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="center", x=0.5),
            margin=dict(t=60, b=40)
        )
        visuals['combined_sharing'] = save_plot(fig, 'combined_sharing')

    # Bar Chart: Top Shared Passwords
    password_counts = Counter({pw: len(users) for pw, users in global_password_to_users.items() if len(users) > 1})
    top_passwords = password_counts.most_common(5)
    if top_passwords:
        passwords, counts = zip(*top_passwords)
        fig = go.Figure(data=[go.Bar(
            x=passwords,
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
        visuals['top_shared_passwords'] = save_plot(fig, 'combined_top_shared_passwords')

    # Bar Chart: Top Shared Hashes
    hash_counts = Counter({h: len(users) for h, users in global_hash_to_users.items() if len(users) > 1})
    top_hashes = hash_counts.most_common(5)
    if top_hashes:
        hashes, counts = zip(*top_hashes)
        fig = go.Figure(data=[go.Bar(
            x=[h[:8] + '...' for h in hashes],
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
        visuals['top_shared_hashes'] = save_plot(fig, 'combined_top_shared_hashes')

    # Scatter Chart: Last Password Set Distribution
    valid_dates = [row['Last Password Set'] for row in combined_rows if row['Last Password Set'] not in ('Unknown', 'N/A') and isinstance(row['Last Password Set'], str)]
    if valid_dates:
        try:
            dates = [datetime.strptime(d, '%Y-%m-%d').date() for d in valid_dates]
            y_values = [row['Score'] for row in combined_rows if row['Last Password Set'] not in ('Unknown', 'N/A') and isinstance(row['Last Password Set'], str)]
            fig = go.Figure(data=[go.Scatter(
                x=dates,
                y=y_values,
                mode='markers',
                marker=dict(color='purple', opacity=0.5, size=8),
                hovertemplate='Date: %{x}<br>Score: %{y}'
            )])
            fig.update_layout(
                title=dict(text="Cross-Domain Last Password Set vs. Risk", font_size=20, x=0.5, xanchor='center'),
                xaxis_title="Date Set",
                yaxis_title="Risk Score",
                xaxis_tickangle=-45,
                margin=dict(t=60, b=40)
            )
            visuals['last_password_set'] = save_plot(fig, 'combined_last_password_set')
        except ValueError:
            pass  # Skip if date parsing fails

    # Pie Chart: Password Expiration Status
    expiration_counts = Counter(row['Password Set to Expire'] for row in combined_rows if row['Password Set to Expire'] != 'Unknown')
    if expiration_counts:
        labels = ['Expires', 'Does Not Expire']
        counts = [expiration_counts.get('Yes', 0), expiration_counts.get('No', 0)]
        fig = go.Figure(data=[go.Pie(
            labels=labels,
            values=counts,
            marker_colors=['#4CAF50', '#F44336'],
            textinfo='label+percent',
            hoverinfo='label+value+percent',
            hole=0.3
        )])
        fig.update_layout(
            title=dict(text="Cross-Domain Password Expiration", font_size=20, x=0.5, xanchor='center'),
            margin=dict(t=60, b=20)
        )
        visuals['expiration_status'] = save_plot(fig, 'combined_expiration_status')

    # Heatmap: Cross-Domain Sharing by Domain Pair
    domain_pairs = defaultdict(int)
    for row in combined_rows:
        domains = row['Domains Shared'].split(', ')
        if len(domains) > 1:
            for i in range(len(domains)):
                for j in range(i + 1, len(domains)):
                    pair = tuple(sorted([domains[i], domains[j]]))
                    domain_pairs[pair] += 1
    if domain_pairs:
        unique_domains = sorted(set(d for pair in domain_pairs for d in pair))
        z = np.zeros((len(unique_domains), len(unique_domains)))
        for (d1, d2), count in domain_pairs.items():
            i, j = unique_domains.index(d1), unique_domains.index(d2)
            z[i][j] = count
            z[j][i] = count
        fig = go.Figure(data=go.Heatmap(
            z=z,
            x=unique_domains,
            y=unique_domains,
            colorscale='YlOrRd',
            text=[[f"{int(val)}" if val > 0 else "" for val in row] for row in z],
            texttemplate="%{text}",
            hoverongaps=False
        ))
        fig.update_layout(
            title=dict(text="Cross-Domain Sharing Heatmap", font_size=20, x=0.5, xanchor='center'),
            xaxis_title="Domain",
            yaxis_title="Domain",
            xaxis_tickangle=-45,
            margin=dict(t=60, b=40)
        )
        visuals['sharing_heatmap'] = save_plot(fig, 'combined_sharing_heatmap')

    # Bar Chart: DA Exposure by Domain
    da_by_domain = defaultdict(lambda: {'total': 0, 'shared': 0})
    for row in combined_rows:
        domain = row['Domain']
        if row.get('DA Domains', 'None') not in ('None', 'Unknown'):
            da_by_domain[domain]['total'] += 1
            if row['Shared With'] > 0:
                da_by_domain[domain]['shared'] += 1
    if da_by_domain:
        domains = list(da_by_domain.keys())
        total_counts = [da_by_domain[d]['total'] for d in domains]
        shared_counts = [da_by_domain[d]['shared'] for d in domains]
        fig = go.Figure()
        fig.add_trace(go.Bar(x=domains, y=total_counts, name='Total DA', marker_color='#1F77B4', text=total_counts, textposition='auto'))
        fig.add_trace(go.Bar(x=domains, y=shared_counts, name='Shared DA', marker_color='#FF4136', text=shared_counts, textposition='auto'))
        fig.update_layout(
            title=dict(text="DA Exposure by Domain", font_size=20, x=0.5, xanchor='center'),
            xaxis_title="Domain",
            yaxis_title="Accounts",
            barmode='group',
            xaxis_tickangle=-45,
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="center", x=0.5),
            margin=dict(t=60, b=40)
        )
        visuals['da_exposure'] = save_plot(fig, 'combined_da_exposure')

    # Sankey Diagram: Shared Credentials Network
    if combined_rows:
        nodes = set()
        edges = defaultdict(int)
        for row in combined_rows:
            if row['Shared With'] > 0:
                domains = row['Domains Shared'].split(', ')
                nodes.update(domains)
                for i in range(len(domains)):
                    for j in range(i + 1, len(domains)):
                        edges[(domains[i], domains[j])] += 1
        if nodes and edges:
            node_list = list(nodes)
            node_indices = {node: i for i, node in enumerate(node_list)}
            source = [node_indices[src] for src, _ in edges.keys()]
            target = [node_indices[tgt] for _, tgt in edges.keys()]
            value = list(edges.values())
            fig = go.Figure(data=[go.Sankey(
                node=dict(
                    pad=15,
                    thickness=20,
                    line=dict(color="black", width=0.5),
                    label=node_list,
                    color="#1F77B4"
                ),
                link=dict(
                    source=source,
                    target=target,
                    value=value,
                    color="#FFDD89"
                )
            )])
            fig.update_layout(
                title=dict(text="Cross-Domain Shared Credentials Network", font_size=20, x=0.5, xanchor='center'),
                font_size=10,
                margin=dict(t=60, b=40)
            )
            visuals['shared_network'] = save_plot(fig, 'combined_shared_network')

    return visuals