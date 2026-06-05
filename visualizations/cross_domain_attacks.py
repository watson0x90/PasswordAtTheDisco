"""
Cross-Domain Attack Path Visualization Module

This module creates visualizations for cross-domain attack scenarios:
- Network graphs showing lateral movement paths
- Domain relationship diagrams
- Shared credential visualizations
- Attack path flow charts

Usage:
    from visualizations.cross_domain_attacks import CrossDomainVisualizer

    visualizer = CrossDomainVisualizer()
    visualizer.create_lateral_movement_graph(shared_passwords)
"""

import networkx as nx
import matplotlib.pyplot as plt
import plotly.graph_objects as go
from pathlib import Path
from typing import Dict, List
from collections import defaultdict

# Import CoreUI dark theme
from visualizations.theme import (
    get_dark_layout,
    COREUI_COLORS
)


class CrossDomainVisualizer:
    """Create visualizations for cross-domain attack scenarios."""

    def __init__(self, output_dir: Path = None):
        """
        Initialize visualizer.

        Args:
            output_dir: Directory for output files
        """
        self.output_dir = output_dir or Path('output/visualizations')
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def create_lateral_movement_graph(self, shared_passwords: List[Dict],
                                     output_file: str = 'lateral_movement_graph') -> Dict[str, Path]:
        """
        Create network graph showing lateral movement opportunities via shared passwords.

        Args:
            shared_passwords: List of shared password dictionaries
            output_file: Base name for output files

        Returns:
            Dictionary mapping format types to file paths
        """
        # Create directed graph
        G = nx.DiGraph()

        # Track edges and their weights (number of shared passwords)
        edge_weights = defaultdict(int)

        # Add nodes and edges
        for shared_pwd in shared_passwords:
            if shared_pwd['type'] != 'cross_domain_password_reuse':
                continue

            domains = shared_pwd['domains']
            accounts = shared_pwd['accounts']

            # Add domain nodes
            for domain in domains:
                if domain not in G.nodes():
                    G.add_node(domain, node_type='domain', color='#3498db')

            # Create edges between domains (representing lateral movement opportunity)
            for i, domain1 in enumerate(domains):
                for domain2 in domains[i+1:]:
                    edge_weights[(domain1, domain2)] += len([
                        acc for acc in accounts
                        if acc['domain'] in [domain1, domain2]
                    ])

        # Add weighted edges
        for (src, dst), weight in edge_weights.items():
            G.add_edge(src, dst, weight=weight, label=f"{weight} accounts")

        # Create static matplotlib visualization
        fig_static = self._create_static_graph(G, edge_weights)
        static_path = self.output_dir / f"{output_file}.png"
        fig_static.savefig(static_path, dpi=300, bbox_inches='tight')
        plt.close(fig_static)

        # Create interactive plotly visualization
        fig_interactive = self._create_interactive_graph(G, edge_weights)
        interactive_path = self.output_dir / f"{output_file}.html"
        fig_interactive.write_html(str(interactive_path))

        print("✓ Lateral movement graph created:")
        print(f"  Static: {static_path}")
        print(f"  Interactive: {interactive_path}")

        return {
            'png': static_path,
            'html': interactive_path
        }

    def _create_static_graph(self, G: nx.DiGraph, edge_weights: Dict) -> plt.Figure:
        """Create static matplotlib graph."""
        plt.style.use('dark_background')
        fig, ax = plt.subplots(figsize=(14, 10))
        fig.patch.set_facecolor(COREUI_COLORS['body_bg'])
        ax.set_facecolor(COREUI_COLORS['body_bg'])

        # Layout
        pos = nx.spring_layout(G, k=2, iterations=50)

        # Draw nodes using CoreUI primary color
        node_colors = [COREUI_COLORS['primary'] for node in G.nodes()]
        nx.draw_networkx_nodes(G, pos, node_color=node_colors,
                              node_size=3000, alpha=0.9, ax=ax)

        # Draw edges with varying thickness using CoreUI danger color
        if edge_weights:
            max_weight = max(edge_weights.values())

            for (src, dst), weight in edge_weights.items():
                if G.has_edge(src, dst):
                    edge_width = 1 + (weight / max_weight) * 5
                    nx.draw_networkx_edges(G, pos, [(src, dst)],
                                          width=edge_width, alpha=0.6,
                                          edge_color=COREUI_COLORS['danger'],
                                          arrows=True, arrowsize=20,
                                          connectionstyle='arc3,rad=0.1',
                                          ax=ax)

        # Draw labels with CoreUI body color
        nx.draw_networkx_labels(G, pos, font_size=11, font_weight='bold',
                               font_color=COREUI_COLORS['body_color'], ax=ax)

        # Edge labels
        edge_labels = nx.get_edge_attributes(G, 'label')
        nx.draw_networkx_edge_labels(G, pos, edge_labels, font_size=9,
                                     font_color=COREUI_COLORS['body_color'], ax=ax)

        ax.set_title('Cross-Domain Lateral Movement Opportunities',
                    fontsize=16, fontweight='bold', pad=20,
                    color=COREUI_COLORS['body_color'])
        ax.text(0.5, -0.1, 'Red edges indicate shared credentials enabling lateral movement',
               transform=ax.transAxes, ha='center', fontsize=10, style='italic',
               color=COREUI_COLORS['body_color'])
        ax.axis('off')

        return fig

    def _create_interactive_graph(self, G: nx.DiGraph, edge_weights: Dict) -> go.Figure:
        """Create interactive plotly graph."""
        # Layout
        pos = nx.spring_layout(G, k=2, iterations=50)

        # Edge traces using CoreUI danger color
        edge_traces = []

        for (src, dst), weight in edge_weights.items():
            if G.has_edge(src, dst):
                x0, y0 = pos[src]
                x1, y1 = pos[dst]

                edge_trace = go.Scatter(
                    x=[x0, x1, None],
                    y=[y0, y1, None],
                    mode='lines',
                    line=dict(width=1 + weight/2, color=COREUI_COLORS['danger']),
                    hoverinfo='text',
                    text=f'{src} → {dst}<br>{weight} shared accounts',
                    showlegend=False
                )
                edge_traces.append(edge_trace)

        # Node trace
        node_x = []
        node_y = []
        node_text = []

        for node in G.nodes():
            x, y = pos[node]
            node_x.append(x)
            node_y.append(y)

            # Count connected edges
            in_edges = list(G.in_edges(node))
            out_edges = list(G.out_edges(node))

            node_text.append(
                f'<b>{node}</b><br>'
                f'Incoming paths: {len(in_edges)}<br>'
                f'Outgoing paths: {len(out_edges)}'
            )

        node_trace = go.Scatter(
            x=node_x,
            y=node_y,
            mode='markers+text',
            hoverinfo='text',
            text=list(G.nodes()),
            hovertext=node_text,
            textposition='top center',
            marker=dict(
                size=30,
                color=COREUI_COLORS['primary'],
                line=dict(width=2, color=COREUI_COLORS['border_color'])
            ),
            textfont=dict(color=COREUI_COLORS['body_color']),
            showlegend=False
        )

        # Create figure
        fig = go.Figure(data=edge_traces + [node_trace])

        fig.update_layout(
            **get_dark_layout(title='Cross-Domain Lateral Movement Opportunities<br><sub>Hover over nodes and edges for details</sub>'),
            showlegend=False,
            hovermode='closest',
            margin=dict(b=0, l=0, r=0, t=80),
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
        )

        return fig

    def create_shared_password_heatmap(self, domain_data: Dict[str, List[Dict]],
                                       output_file: str = 'shared_password_heatmap') -> Path:
        """
        Create heatmap showing password sharing intensity between domains.

        Args:
            domain_data: Dictionary mapping domain names to account lists
            output_file: Base name for output file

        Returns:
            Path to output file
        """
        # Build password hash to domains mapping
        hash_to_domains = defaultdict(set)

        for domain, accounts in domain_data.items():
            for account in accounts:
                ntlm_hash = account.get('hash') or account.get('ntlm_hash', '')
                if ntlm_hash:
                    hash_to_domains[ntlm_hash].add(domain)

        # Build sharing matrix
        domains = sorted(domain_data.keys())
        matrix = [[0 for _ in domains] for _ in domains]

        for ntlm_hash, shared_domains in hash_to_domains.items():
            if len(shared_domains) > 1:
                domain_list = list(shared_domains)
                for i, dom1 in enumerate(domain_list):
                    for dom2 in domain_list[i+1:]:
                        idx1 = domains.index(dom1)
                        idx2 = domains.index(dom2)
                        matrix[idx1][idx2] += 1
                        matrix[idx2][idx1] += 1

        # Create heatmap with CoreUI dark theme
        fig = go.Figure(data=go.Heatmap(
            z=matrix,
            x=domains,
            y=domains,
            colorscale='Reds',
            hoverongaps=False,
            hovertemplate='%{y} → %{x}<br>Shared passwords: %{z}<extra></extra>'
        ))

        fig.update_layout(
            **get_dark_layout(title='Password Sharing Intensity Between Domains'),
            xaxis_title='Target Domain',
            yaxis_title='Source Domain',
            width=800,
            height=800
        )

        output_path = self.output_dir / f"{output_file}.html"
        fig.write_html(str(output_path))

        print(f"✓ Shared password heatmap created: {output_path}")

        return output_path

    def create_attack_path_flowchart(self, attack_scenario: Dict,
                                     output_file: str = 'attack_path_flow') -> Path:
        """
        Create flowchart visualization of an attack path.

        Args:
            attack_scenario: Attack scenario dictionary
            output_file: Base name for output file

        Returns:
            Path to output file
        """
        # Create directed graph for flowchart
        G = nx.DiGraph()

        attack_steps = attack_scenario.get('attack_steps', [])

        # Add nodes for each step
        for i, step in enumerate(attack_steps):
            G.add_node(i, label=step, step_number=i+1)

        # Add edges connecting steps
        for i in range(len(attack_steps) - 1):
            G.add_edge(i, i+1)

        # Hierarchical layout
        pos = {}
        for i in range(len(attack_steps)):
            pos[i] = (0, -i)

        # Create figure with dark theme
        plt.style.use('dark_background')
        fig, ax = plt.subplots(figsize=(14, max(8, len(attack_steps) * 1.5)))
        fig.patch.set_facecolor(COREUI_COLORS['body_bg'])
        ax.set_facecolor(COREUI_COLORS['body_bg'])

        # Draw nodes using CoreUI colors
        node_colors = [COREUI_COLORS['danger'] if i == 0 else COREUI_COLORS['success'] if i == len(attack_steps)-1
                      else COREUI_COLORS['primary'] for i in range(len(attack_steps))]

        nx.draw_networkx_nodes(G, pos, node_color=node_colors,
                              node_size=8000, node_shape='s', alpha=0.9, ax=ax)

        # Draw edges using CoreUI border color
        nx.draw_networkx_edges(G, pos, width=2, alpha=0.6,
                              edge_color=COREUI_COLORS['border_color'], arrows=True,
                              arrowsize=20, arrowstyle='->', ax=ax)

        # Draw step labels with CoreUI body color
        labels = {i: f"Step {i+1}" for i in range(len(attack_steps))}
        nx.draw_networkx_labels(G, pos, labels, font_size=10,
                               font_weight='bold', font_color=COREUI_COLORS['body_color'], ax=ax)

        # Add step descriptions
        for i, step in enumerate(attack_steps):
            x, y = pos[i]
            # Wrap text
            max_width = 60
            words = step.split()
            lines = []
            current_line = []

            for word in words:
                if len(' '.join(current_line + [word])) <= max_width:
                    current_line.append(word)
                else:
                    if current_line:
                        lines.append(' '.join(current_line))
                    current_line = [word]

            if current_line:
                lines.append(' '.join(current_line))

            # Remove step number from description
            description = '\n'.join(lines)
            if '. ' in description:
                description = '. '.join(description.split('. ')[1:])

            ax.text(x + 1.5, y, description, fontsize=9,
                   va='center', ha='left', wrap=True, color=COREUI_COLORS['body_color'])

        ax.set_title(f"Attack Path: {attack_scenario.get('title', 'Unknown')}",
                    fontsize=16, fontweight='bold', pad=20, color=COREUI_COLORS['body_color'])
        ax.text(0.5, 1.02, f"Severity: {attack_scenario.get('severity', 'N/A')} | "
                           f"Type: {attack_scenario.get('type', 'N/A')}",
               transform=ax.transAxes, ha='center', fontsize=11, color=COREUI_COLORS['body_color'])
        ax.axis('off')

        output_path = self.output_dir / f"{output_file}.png"
        fig.savefig(output_path, dpi=300, bbox_inches='tight', facecolor=COREUI_COLORS['body_bg'])
        plt.close(fig)

        print(f"✓ Attack path flowchart created: {output_path}")

        return output_path

    def create_domain_risk_dashboard(self, domain_stats: Dict[str, Dict],
                                     output_file: str = 'domain_risk_dashboard') -> Path:
        """
        Create comprehensive dashboard showing risk across domains.

        Args:
            domain_stats: Dictionary mapping domains to their statistics
            output_file: Base name for output file

        Returns:
            Path to output file
        """
        from plotly.subplots import make_subplots

        domains = list(domain_stats.keys())

        # Create subplots
        fig = make_subplots(
            rows=2, cols=2,
            subplot_titles=('Crack Rate by Domain', 'Password Types Distribution',
                          'HIBP Breach Exposure', 'Risk Score Distribution'),
            specs=[[{'type': 'bar'}, {'type': 'bar'}],
                   [{'type': 'bar'}, {'type': 'box'}]]
        )

        # 1. Crack Rate using CoreUI danger color
        crack_rates = [stats.get('crack_rate', 0) * 100 for stats in domain_stats.values()]
        fig.add_trace(
            go.Bar(x=domains, y=crack_rates, name='Crack Rate (%)',
                  marker_color=COREUI_COLORS['danger']),
            row=1, col=1
        )

        # 2. Password Types using CoreUI colors
        if domain_stats:
            first_domain_stats = list(domain_stats.values())[0]
            if 'password_types' in first_domain_stats:
                hibp_counts = [stats.get('password_types', {}).get('hibp', 0) for stats in domain_stats.values()]
                rockyou_counts = [stats.get('password_types', {}).get('rockyou', 0) for stats in domain_stats.values()]
                random_counts = [stats.get('password_types', {}).get('random', 0) for stats in domain_stats.values()]

                fig.add_trace(go.Bar(x=domains, y=hibp_counts, name='HIBP', marker_color=COREUI_COLORS['danger']), row=1, col=2)
                fig.add_trace(go.Bar(x=domains, y=rockyou_counts, name='Rockyou', marker_color=COREUI_COLORS['warning']), row=1, col=2)
                fig.add_trace(go.Bar(x=domains, y=random_counts, name='Random', marker_color=COREUI_COLORS['success']), row=1, col=2)

        # 3. HIBP Breach Exposure using CoreUI info color
        breach_counts = [stats.get('breached_count', 0) for stats in domain_stats.values()]
        fig.add_trace(
            go.Bar(x=domains, y=breach_counts, name='Breached Accounts',
                  marker_color=COREUI_COLORS['info']),
            row=2, col=1
        )

        # 4. Risk Score Distribution (box plot) using CoreUI primary color
        # Placeholder - would need actual risk scores
        fig.add_trace(
            go.Box(y=[5, 6, 7, 8, 9], name='Domain 1', marker_color=COREUI_COLORS['primary']),
            row=2, col=2
        )

        fig.update_layout(
            **get_dark_layout(title=f'Domain Security Dashboard - {len(domains)} Domains'),
            height=800,
            showlegend=True
        )

        output_path = self.output_dir / f"{output_file}.html"
        fig.write_html(str(output_path))

        print(f"✓ Domain risk dashboard created: {output_path}")

        return output_path


def demo_visualizations():
    """Demonstrate cross-domain attack visualizations."""
    print("="*70)
    print("Cross-Domain Attack Visualization Demo")
    print("="*70 + "\n")

    visualizer = CrossDomainVisualizer()

    # Sample data
    shared_passwords = [
        {
            'type': 'cross_domain_password_reuse',
            'password': 'Summer2023!',
            'domains': ['DOMAIN1.INT', 'DOMAIN2.COM', 'DOMAIN3.LOCAL'],
            'accounts': [
                {'username': 'alice', 'domain': 'DOMAIN1.INT'},
                {'username': 'alice', 'domain': 'DOMAIN2.COM'},
                {'username': 'bob', 'domain': 'DOMAIN3.LOCAL'},
            ]
        },
        {
            'type': 'cross_domain_password_reuse',
            'password': 'Password123!',
            'domains': ['DOMAIN1.INT', 'DOMAIN2.COM'],
            'accounts': [
                {'username': 'admin', 'domain': 'DOMAIN1.INT'},
                {'username': 'svc_web', 'domain': 'DOMAIN2.COM'},
            ]
        }
    ]

    attack_scenario = {
        'id': 'SCENARIO-001',
        'title': 'Cross-Domain Password Reuse Attack',
        'severity': 'CRITICAL',
        'type': 'Lateral Movement',
        'attack_steps': [
            '1. Identify weak password "Summer2023!" on user alice@DOMAIN1.INT',
            '2. Crack password using hashcat with rockyou.txt',
            '3. Test password across all discovered domains',
            '4. Successfully authenticate to DOMAIN2.COM as alice',
            '5. Enumerate privileges in DOMAIN2.COM',
            '6. Identify path to Domain Admin',
            '7. Escalate privileges using discovered attack path'
        ]
    }

    # Create visualizations
    print("Creating lateral movement graph...")
    visualizer.create_lateral_movement_graph(shared_passwords)

    print("\nCreating attack path flowchart...")
    visualizer.create_attack_path_flowchart(attack_scenario)

    print("\n" + "="*70)
    print("Visualization demo complete!")
    print(f"Output directory: {visualizer.output_dir.absolute()}")
    print("="*70)


if __name__ == '__main__':
    demo_visualizations()
