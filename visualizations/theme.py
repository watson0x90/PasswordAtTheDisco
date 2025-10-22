# visualizations/theme.py
"""
CoreUI 5 Dark Theme for Plotly Visualizations

Provides consistent dark theme styling for all Plotly charts to match
the CoreUI dashboard interface. Color palette extracted from CoreUI demo analysis.
"""

# CoreUI Color Palette (from puppetter_helper/analysis_output/color_palette.json)
COREUI_COLORS = {
    'primary': 'rgb(94, 92, 208)',      # Purple/blue
    'secondary': '#6b7785',             # Gray
    'success': 'rgb(34, 151, 65)',      # Green
    'danger': 'rgb(222, 90, 90)',       # Red
    'warning': 'rgb(238, 173, 32)',     # Yellow/orange
    'info': 'rgb(61, 153, 245)',        # Blue
    'dark': '#212631',                  # Dark background
    'light': '#f3f4f7',                 # Light text (for light theme)
    'body_bg': '#212631',               # Background color
    'body_color': 'rgba(255, 255, 255, 0.87)',  # Main text color
    'border_color': '#323a49',          # Border color
}

# Risk level color mapping
RISK_COLORS = {
    'Critical': COREUI_COLORS['danger'],
    'High': 'rgb(255, 152, 0)',  # Darker orange between danger and warning
    'Medium': COREUI_COLORS['warning'],
    'Low': COREUI_COLORS['success'],
}

# Score component color mapping
SCORE_COMPONENT_COLORS = {
    'base_score': COREUI_COLORS['info'],
    'temporal_score': COREUI_COLORS['warning'],
    'environmental_score': COREUI_COLORS['danger'],
}

# General categorical color palette (for charts with multiple categories)
CATEGORICAL_COLORS = [
    COREUI_COLORS['primary'],
    COREUI_COLORS['info'],
    COREUI_COLORS['success'],
    COREUI_COLORS['warning'],
    COREUI_COLORS['danger'],
    COREUI_COLORS['secondary'],
    'rgb(156, 39, 176)',  # Purple
    'rgb(0, 150, 136)',   # Teal
]

# Sequential color scales (for heatmaps and gradients)
# Light to dark progression for dark backgrounds
SEQUENTIAL_COLORS = {
    'danger': ['rgb(100, 40, 40)', 'rgb(222, 90, 90)', 'rgb(255, 120, 120)'],
    'warning': ['rgb(100, 70, 20)', 'rgb(238, 173, 32)', 'rgb(255, 200, 80)'],
    'success': ['rgb(20, 70, 30)', 'rgb(34, 151, 65)', 'rgb(80, 200, 100)'],
    'info': ['rgb(30, 70, 120)', 'rgb(61, 153, 245)', 'rgb(100, 180, 255)'],
    'primary': ['rgb(50, 48, 100)', 'rgb(94, 92, 208)', 'rgb(130, 128, 255)'],
}


def get_dark_layout(title=None, **kwargs):
    """
    Get base dark layout configuration for Plotly charts.

    Args:
        title (str): Chart title
        **kwargs: Additional layout parameters to override defaults

    Returns:
        dict: Layout configuration dictionary
    """
    layout = {
        'template': 'plotly_dark',  # Use Plotly's dark template as base
        'paper_bgcolor': COREUI_COLORS['body_bg'],  # Outer background
        'plot_bgcolor': 'rgba(0, 0, 0, 0.1)',  # Slightly darker plot area
        'font': {
            'family': '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif',
            'size': 12,
            'color': COREUI_COLORS['body_color']
        },
        'title': {
            'font': {
                'size': 18,
                'color': COREUI_COLORS['body_color'],
                'family': '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif'
            },
            'x': 0.5,
            'xanchor': 'center'
        },
        'xaxis': {
            'gridcolor': COREUI_COLORS['border_color'],
            'zerolinecolor': COREUI_COLORS['border_color'],
            'color': COREUI_COLORS['body_color'],
        },
        'yaxis': {
            'gridcolor': COREUI_COLORS['border_color'],
            'zerolinecolor': COREUI_COLORS['border_color'],
            'color': COREUI_COLORS['body_color'],
        },
        # Note: legend positioning is left to individual charts, but we provide the styled defaults
        # Charts can override with their own legend dict(orientation="h", ...) without conflicts
        'colorway': CATEGORICAL_COLORS,  # Default color sequence for traces
        'hoverlabel': {
            'bgcolor': COREUI_COLORS['dark'],
            'bordercolor': COREUI_COLORS['border_color'],
            'font': {
                'color': COREUI_COLORS['body_color'],
                'family': '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif'
            }
        },
    }

    # Add title if provided
    if title:
        layout['title']['text'] = title

    # Override with any custom parameters
    layout.update(kwargs)

    return layout


def get_risk_color(risk_level):
    """
    Get color for a specific risk level.

    Args:
        risk_level (str): Risk level (Critical, High, Medium, Low)

    Returns:
        str: RGB color string
    """
    return RISK_COLORS.get(risk_level, COREUI_COLORS['secondary'])


def get_risk_colors_list():
    """
    Get list of risk colors in order: Low, Medium, High, Critical.

    Returns:
        list: List of RGB color strings
    """
    return [
        RISK_COLORS['Low'],
        RISK_COLORS['Medium'],
        RISK_COLORS['High'],
        RISK_COLORS['Critical']
    ]


def get_score_component_color(component):
    """
    Get color for a score component.

    Args:
        component (str): Component name (base_score, temporal_score, environmental_score)

    Returns:
        str: RGB color string
    """
    return SCORE_COMPONENT_COLORS.get(component, COREUI_COLORS['info'])


def get_legend_config(orientation="v", position="right", **kwargs):
    """
    Get styled legend configuration for dark theme.

    Args:
        orientation (str): "v" for vertical or "h" for horizontal
        position (str): "right", "top", "bottom", "left"
        **kwargs: Additional legend parameters to override defaults

    Returns:
        dict: Legend configuration dictionary
    """
    config = {
        'bgcolor': 'rgba(33, 38, 49, 0.8)',
        'bordercolor': COREUI_COLORS['border_color'],
        'borderwidth': 1,
        'font': {
            'color': COREUI_COLORS['body_color']
        },
        'orientation': orientation
    }

    # Add common position presets
    if orientation == "h":
        if position == "top":
            config.update({'yanchor': 'bottom', 'y': 1.02, 'xanchor': 'center', 'x': 0.5})
        elif position == "bottom":
            config.update({'yanchor': 'top', 'y': -0.1, 'xanchor': 'center', 'x': 0.5})

    # Override with any custom parameters
    config.update(kwargs)

    return config


def apply_dark_theme_to_figure(fig):
    """
    Apply dark theme to an existing Plotly figure.

    Args:
        fig (plotly.graph_objects.Figure): Plotly figure object

    Returns:
        plotly.graph_objects.Figure: Figure with dark theme applied
    """
    fig.update_layout(**get_dark_layout())
    return fig


# Export commonly used items
__all__ = [
    'COREUI_COLORS',
    'RISK_COLORS',
    'SCORE_COMPONENT_COLORS',
    'CATEGORICAL_COLORS',
    'SEQUENTIAL_COLORS',
    'get_dark_layout',
    'get_risk_color',
    'get_risk_colors_list',
    'get_score_component_color',
    'get_legend_config',
    'apply_dark_theme_to_figure',
]
