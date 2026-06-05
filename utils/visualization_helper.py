# utils/visualization_helper.py
"""
Visualization helper utility for password security audit reports.
Provides functions to consistently add visualizations to reports.
"""

import base64
import os


def get_vis_path(visuals, vis_type, format_type='html'):
    """Helper function to safely get visualization path regardless of format"""
    if not visuals or vis_type not in visuals:
        return None
        
    vis_data = visuals[vis_type]
    # Case 1: If it's a dict with key matching format_type
    if isinstance(vis_data, dict) and format_type in vis_data:
        return vis_data[format_type]
    # Case 2: If it's a PosixPath object directly
    elif hasattr(vis_data, 'name'):
        return vis_data
    # Case 3: If it's a string
    elif isinstance(vis_data, str):
        return vis_data
    # Default case
    return None

def add_visualization_to_html(visuals, vis_type, title, fallback_text="Visualization not available"):
    """Add visualization to HTML report with inline Plotly (no iframes)"""
    import json

    if not visuals or vis_type not in visuals:
        return ""

    vis_data = visuals[vis_type]

    # Try to get Plotly JSON for inline rendering (preferred)
    if isinstance(vis_data, dict) and 'plotly' in vis_data and vis_data['plotly']:
        try:
            import uuid
            chart_id = f"chart_{vis_type}_{uuid.uuid4().hex[:8]}"
            # vis_data['plotly'] is now a dict, so we need to serialize it to JSON string
            plotly_dict = vis_data['plotly']
            plotly_json = json.dumps(plotly_dict)
            return f"""
            <div id="{chart_id}" class="plotly-chart-container" style="width:100%; height:500px;"></div>
            <script>
                var plotlyData = {plotly_json};
                Plotly.newPlot('{chart_id}', plotlyData.data, plotlyData.layout, {{responsive: true}});
            </script>
            """
        except Exception:
            # Fall back to iframe if inline fails
            pass

    # Fallback to iframe method if Plotly JSON not available
    vis_path = get_vis_path(visuals, vis_type, 'html')
    if vis_path:
        try:
            return f"""
            <div class="visualization-container">
                <iframe src="./{os.path.basename(vis_path)}" width="100%" height="500" frameborder="0"
                        loading="lazy" class="visualization-frame" title="{title}"></iframe>
            </div>
            """
        except Exception:
            return f"""
            <div class="visualization-container error">
                <p class="error-message">{fallback_text}</p>
            </div>
            """
    return ""

def add_visualization_to_markdown(visuals, vis_type, title, fallback_text="Visualization not available"):
    """Add visualization to Markdown report with error handling"""
    vis_path = get_vis_path(visuals, vis_type, 'png')
    if vis_path:
        try:
            with open(vis_path, 'rb') as f:
                img_data = base64.b64encode(f.read()).decode('utf-8')
            return f"## {title}\n\n![{title}](data:image/png;base64,{img_data})\n\n"
        except Exception:
            return f"## {title}\n\n*{fallback_text}*\n\n"
    return ""

def add_standard_visualizations_html(visuals, domain):
    """Add standard set of visualizations to HTML report"""
    html = ""
    visualization_sets = {
        'risk_overview': [
            ('risk_levels', 'Risk Level Distribution'),
            ('score_breakdown', 'Risk Score Breakdown'),
            ('risk_factors', 'Risk Factor Contribution')
        ],
        'password_characteristics': [
            ('length_distribution', 'Password Length Distribution'),
            ('complexity_distribution', 'Password Complexity Distribution'),
            ('password_issues', 'Password Issues'),
            ('top_banned_words', 'Top Banned Words')
        ],
        'temporal_factors': [
            ('last_password_set', 'Last Password Set Distribution'),
            ('expiration_status', 'Password Expiration Status'),
            ('compliance_distribution', 'Compliance Status'),
            ('password_age', 'Password Age vs. Risk')
        ],
        'privilege_analysis': [
            ('da_risk', 'Domain Admin Pathways'),
            ('similarity_network', 'Password Similarity Network'),
        ]
    }
    
    for section, vis_items in visualization_sets.items():
        section_html = f"<h2>{section.replace('_', ' ').title()}</h2>\n<div class='visualization-grid'>\n"
        section_has_content = False
        
        for vis_type, title in vis_items:
            vis_html = add_visualization_to_html(visuals, vis_type, title)
            if vis_html:
                section_html += vis_html
                section_has_content = True
        
        section_html += "</div>\n"
        if section_has_content:
            html += section_html
    
    return html

def add_standard_visualizations_markdown(visuals, domain):
    """Add standard set of visualizations to Markdown report"""
    markdown = ""
    visualization_sets = {
        'Risk Overview': [
            ('risk_levels', 'Risk Level Distribution'),
            ('score_breakdown', 'Risk Score Breakdown'),
            ('risk_factors', 'Risk Factor Contribution')
        ],
        'Password Characteristics': [
            ('length_distribution', 'Password Length Distribution'),
            ('complexity_distribution', 'Password Complexity Distribution'),
            ('password_issues', 'Password Issues'),
            ('top_banned_words', 'Top Banned Words')
        ],
        'Temporal Factors': [
            ('last_password_set', 'Last Password Set Distribution'),
            ('expiration_status', 'Password Expiration Status'),
            ('compliance_distribution', 'Compliance Status'),
            ('password_age', 'Password Age vs. Risk')
        ],
        'Privilege Analysis': [
            ('da_risk', 'Domain Admin Pathways'),
            ('similarity_network', 'Password Similarity Network'),
        ]
    }
    
    for section, vis_items in visualization_sets.items():
        section_markdown = f"# {section}\n\n"
        section_has_content = False
        
        for vis_type, title in vis_items:
            vis_markdown = add_visualization_to_markdown(visuals, vis_type, title)
            if vis_markdown:
                section_markdown += vis_markdown
                section_has_content = True
        
        if section_has_content:
            markdown += section_markdown
    
    return markdown