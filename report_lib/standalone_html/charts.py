# report_lib/standalone_html/charts.py
"""
Plotly chart generation for static HTML reports.
Generates interactive charts that can be embedded directly in HTML.
"""

import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots


def generate_chart_html(fig, div_id="chart", height=500):
    """
    Convert a Plotly figure to HTML div that can be embedded in static HTML.

    Args:
        fig: Plotly figure object
        div_id: HTML div ID for the chart
        height: Chart height in pixels

    Returns:
        HTML string with the chart
    """
    # Apply dark theme
    fig.update_layout(
        template="plotly_dark",
        height=height,
        paper_bgcolor='#1a1d23',
        plot_bgcolor='#212529',
        font=dict(color='#d1d5db')
    )

    # Convert to JSON for embedding
    graph_json = fig.to_json()

    # Create HTML div with inline Plotly rendering
    html = f"""
    <div id="{div_id}" class="plotly-chart"></div>
    <script>
        (function() {{
            var figure = {graph_json};
            Plotly.newPlot('{div_id}', figure.data, figure.layout, {{responsive: true}});
        }})();
    </script>
    """

    return html


def create_risk_distribution_chart(risk_counts, title="Risk Level Distribution"):
    """Create a donut chart for risk level distribution."""

    # Define colors matching CoreUI dark theme
    colors = {
        'Critical': '#ef4444',
        'High': '#f97316',
        'Medium': '#eab308',
        'Low': '#22c55e'
    }

    labels = []
    values = []
    chart_colors = []

    for level in ['Critical', 'High', 'Medium', 'Low']:
        if level in risk_counts and risk_counts[level] > 0:
            labels.append(level)
            values.append(risk_counts[level])
            chart_colors.append(colors[level])

    fig = go.Figure(data=[go.Pie(
        labels=labels,
        values=values,
        hole=0.4,
        marker=dict(colors=chart_colors),
        textinfo='label+percent',
        textposition='auto'
    )])

    fig.update_layout(
        title=dict(text=title, font=dict(size=20)),
        showlegend=True,
        legend=dict(
            orientation="v",
            yanchor="middle",
            y=0.5,
            xanchor="left",
            x=1.05
        )
    )

    return fig


def create_password_complexity_chart(complexity_data, title="Password Complexity Distribution"):
    """Create a bar chart for password complexity distribution."""

    complexity_order = ['digit', 'lower', 'upper', 'mixedalpha', 'mixedalphanumeric', 'special']
    complexity_labels = {
        'digit': 'Digits Only',
        'lower': 'Lowercase Only',
        'upper': 'Uppercase Only',
        'mixedalpha': 'Mixed Alpha',
        'mixedalphanumeric': 'Alphanumeric',
        'special': 'Special Characters'
    }

    x_values = []
    y_values = []
    colors = []

    # Color gradient from weak to strong
    color_scale = ['#ef4444', '#f97316', '#eab308', '#06b6d4', '#10b981', '#3b82f6']

    for i, comp in enumerate(complexity_order):
        if comp in complexity_data:
            x_values.append(complexity_labels.get(comp, comp))
            y_values.append(complexity_data[comp])
            colors.append(color_scale[i % len(color_scale)])

    fig = go.Figure(data=[go.Bar(
        x=x_values,
        y=y_values,
        marker=dict(color=colors),
        text=y_values,
        textposition='auto'
    )])

    fig.update_layout(
        title=dict(text=title, font=dict(size=20)),
        xaxis_title="Complexity Type",
        yaxis_title="Number of Passwords",
        showlegend=False
    )

    return fig


def create_password_length_chart(length_data, title="Password Length Distribution"):
    """Create a histogram for password length distribution."""

    # Convert length data to lists for histogram
    lengths = []
    for length_str, count in length_data.items():
        try:
            length = int(length_str)
            lengths.extend([length] * count)
        except ValueError:
            continue

    if not lengths:
        # No data, create empty chart
        fig = go.Figure()
        fig.add_annotation(
            text="No password length data available",
            xref="paper", yref="paper",
            x=0.5, y=0.5, showarrow=False,
            font=dict(size=16, color='#9ca3af')
        )
    else:
        fig = go.Figure(data=[go.Histogram(
            x=lengths,
            nbinsx=30,
            marker=dict(color='#3b82f6', line=dict(color='#1a1d23', width=1))
        )])

        fig.update_layout(
            title=dict(text=title, font=dict(size=20)),
            xaxis_title="Password Length (characters)",
            yaxis_title="Number of Passwords",
            showlegend=False,
            bargap=0.1
        )

    return fig


def create_hibp_breach_chart(hibp_data, title="HIBP Breach Status"):
    """Create a pie chart for HIBP breach status."""

    breached = hibp_data.get('breached', 0)
    clean = hibp_data.get('clean', 0)

    fig = go.Figure(data=[go.Pie(
        labels=['Breached', 'Clean'],
        values=[breached, clean],
        hole=0.4,
        marker=dict(colors=['#ef4444', '#22c55e']),
        textinfo='label+value+percent',
        textposition='auto'
    )])

    fig.update_layout(
        title=dict(text=title, font=dict(size=20)),
        showlegend=True
    )

    return fig


def create_compliance_chart(compliance_data, title="Password Age Compliance"):
    """Create a bar chart for compliance status."""

    categories = []
    values = []
    colors = []

    if 'compliant' in compliance_data:
        categories.append('Compliant')
        values.append(compliance_data['compliant'])
        colors.append('#22c55e')

    if 'non_compliant' in compliance_data:
        categories.append('Non-Compliant')
        values.append(compliance_data['non_compliant'])
        colors.append('#ef4444')

    if 'unknown' in compliance_data:
        categories.append('Unknown')
        values.append(compliance_data['unknown'])
        colors.append('#6b7280')

    fig = go.Figure(data=[go.Bar(
        x=categories,
        y=values,
        marker=dict(color=colors),
        text=values,
        textposition='auto'
    )])

    fig.update_layout(
        title=dict(text=title, font=dict(size=20)),
        xaxis_title="Compliance Status",
        yaxis_title="Number of Accounts",
        showlegend=False
    )

    return fig


def create_top_passwords_chart(password_counts, top_n=10, title="Top Shared Passwords"):
    """Create a horizontal bar chart for most common passwords."""

    # Sort and get top N
    sorted_passwords = sorted(password_counts.items(), key=lambda x: x[1], reverse=True)[:top_n]

    if not sorted_passwords:
        fig = go.Figure()
        fig.add_annotation(
            text="No shared passwords found",
            xref="paper", yref="paper",
            x=0.5, y=0.5, showarrow=False,
            font=dict(size=16, color='#9ca3af')
        )
    else:
        passwords = [p[0][:20] + '...' if len(p[0]) > 20 else p[0] for p in sorted_passwords]
        counts = [p[1] for p in sorted_passwords]

        # Create gradient colors
        colors = px.colors.sequential.Reds_r[:len(passwords)]

        fig = go.Figure(data=[go.Bar(
            y=passwords,
            x=counts,
            orientation='h',
            marker=dict(color=colors),
            text=counts,
            textposition='auto'
        )])

        fig.update_layout(
            title=dict(text=title, font=dict(size=20)),
            xaxis_title="Number of Accounts",
            yaxis_title="Password",
            showlegend=False,
            height=max(400, len(passwords) * 40)
        )

    return fig


def create_da_path_chart(da_data, title="Domain Admin Pathways"):
    """Create a donut chart for DA pathway distribution."""

    has_path = da_data.get('has_path', 0)
    no_path = da_data.get('no_path', 0)

    fig = go.Figure(data=[go.Pie(
        labels=['Has DA Path', 'No DA Path'],
        values=[has_path, no_path],
        hole=0.4,
        marker=dict(colors=['#f97316', '#3b82f6']),
        textinfo='label+value+percent',
        textposition='auto'
    )])

    fig.update_layout(
        title=dict(text=title, font=dict(size=20)),
        showlegend=True
    )

    return fig


def create_multi_chart_dashboard(domain_data, title="Domain Security Dashboard"):
    """Create a multi-chart dashboard for domain overview."""

    # Create subplots
    fig = make_subplots(
        rows=2, cols=3,
        subplot_titles=(
            'Risk Distribution', 'Password Complexity', 'Length Distribution',
            'HIBP Status', 'Compliance', 'DA Pathways'
        ),
        specs=[
            [{'type': 'pie'}, {'type': 'bar'}, {'type': 'histogram'}],
            [{'type': 'pie'}, {'type': 'bar'}, {'type': 'pie'}]
        ]
    )

    # Add charts
    # ... (implement based on data structure)

    fig.update_layout(
        title=dict(text=title, font=dict(size=24)),
        showlegend=False,
        height=800
    )

    return fig


def embed_all_charts(domain_data):
    """
    Generate all charts for a domain and return as embedded HTML.

    Args:
        domain_data: Dictionary containing domain statistics

    Returns:
        Dictionary of chart HTML strings
    """
    charts = {}

    # Risk distribution
    if 'risk_distribution' in domain_data:
        fig = create_risk_distribution_chart(domain_data['risk_distribution'])
        charts['risk_distribution'] = generate_chart_html(fig, 'risk-chart')

    # Password complexity
    if 'complexity_distribution' in domain_data:
        fig = create_password_complexity_chart(domain_data['complexity_distribution'])
        charts['complexity'] = generate_chart_html(fig, 'complexity-chart')

    # Password length
    if 'length_distribution' in domain_data:
        fig = create_password_length_chart(domain_data['length_distribution'])
        charts['length'] = generate_chart_html(fig, 'length-chart')

    # HIBP status
    if 'hibp_stats' in domain_data:
        fig = create_hibp_breach_chart(domain_data['hibp_stats'])
        charts['hibp'] = generate_chart_html(fig, 'hibp-chart')

    # Compliance
    if 'compliance_stats' in domain_data:
        fig = create_compliance_chart(domain_data['compliance_stats'])
        charts['compliance'] = generate_chart_html(fig, 'compliance-chart')

    # DA pathways
    if 'da_path_stats' in domain_data:
        fig = create_da_path_chart(domain_data['da_path_stats'])
        charts['da_paths'] = generate_chart_html(fig, 'da-chart')

    # Top shared passwords
    if 'shared_passwords' in domain_data:
        fig = create_top_passwords_chart(domain_data['shared_passwords'])
        charts['top_passwords'] = generate_chart_html(fig, 'passwords-chart')

    return charts


# Example usage in report generation:
"""
from report_lib.standalone_html.charts import embed_all_charts

# In your report generation function:
def generate_domain_report(domain_data):
    charts = embed_all_charts(domain_data)

    html = f'''
    <div class="container-fluid">
        <div class="row">
            <div class="col-md-6">
                {charts.get('risk_distribution', '')}
            </div>
            <div class="col-md-6">
                {charts.get('complexity', '')}
            </div>
        </div>
        <div class="row">
            <div class="col-md-4">
                {charts.get('hibp', '')}
            </div>
            <div class="col-md-4">
                {charts.get('compliance', '')}
            </div>
            <div class="col-md-4">
                {charts.get('da_paths', '')}
            </div>
        </div>
    </div>
    '''
"""