# report_lib/standalone_html/modern_components.py
"""
Modern CoreUI 5 Component Library
Provides advanced components for stunning dashboards with real insights.
Based on CoreUI demo analysis from Puppeteer script.
"""


def create_stat_widget(value, label, icon, color="primary", trend=None, trend_value=None, subtitle=None):
    """
    Create a modern stat widget card with gradient background.

    Args:
        value (str): Main metric value (e.g., "26K", "9.8/10", "$6,200")
        label (str): Metric label (e.g., "Critical Accounts", "Avg Risk Score")
        icon (str): Bootstrap icon name (without 'bi-' prefix)
        color (str): Color theme - primary, info, warning, danger, success
        trend (str): Optional trend direction - "up" or "down"
        trend_value (str): Optional trend percentage (e.g., "+12.4%")
        subtitle (str): Optional subtitle text

    Returns:
        str: HTML for stat widget
    """
    # Trend icon and styling
    trend_html = ""
    if trend and trend_value:
        trend_icon = "arrow-up" if trend == "up" else "arrow-down"
        trend_html = f"""
        <span class="fs-6 fw-normal">
            ({trend_value} <i class="bi bi-{trend_icon}"></i>)
        </span>
        """

    subtitle_html = f'<div class="small mt-1 opacity-75">{subtitle}</div>' if subtitle else ""

    return f"""
    <div class="card text-white bg-{color}-gradient">
        <div class="card-body pb-0 d-flex justify-content-between align-items-start">
            <div>
                <div class="fs-4 fw-semibold">{value} {trend_html}</div>
                <div>{label}</div>
                {subtitle_html}
            </div>
            <div>
                <i class="bi bi-{icon} fs-1 opacity-75"></i>
            </div>
        </div>
        <div class="card-body pt-2">
            <div class="progress progress-thin mt-2">
                <div class="progress-bar bg-white opacity-50" role="progressbar" style="width: 100%" aria-valuenow="100" aria-valuemin="0" aria-valuemax="100"></div>
            </div>
        </div>
    </div>
    """


def create_callout(title, message, color="info", icon=None, dismissible=False):
    """
    Create a prominent callout/alert box for critical information.

    Args:
        title (str): Callout title
        message (str): Callout message (supports HTML)
        color (str): Color theme - primary, secondary, success, danger, warning, info
        icon (str): Optional Bootstrap icon name
        dismissible (bool): Whether callout can be dismissed

    Returns:
        str: HTML for callout
    """
    icon_html = f'<i class="bi bi-{icon} me-2"></i>' if icon else ""
    dismiss_button = """
    <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
    """ if dismissible else ""

    fade_show = " fade show" if dismissible else ""

    return f"""
    <div class="alert alert-{color} alert-dismissible{fade_show}" role="alert">
        <h5 class="alert-heading">{icon_html}{title}</h5>
        <p class="mb-0">{message}</p>
        {dismiss_button}
    </div>
    """


def create_progress_card(title, items, icon="graph-up-arrow"):
    """
    Create a card with multiple progress indicators.

    Args:
        title (str): Card title
        items (list): List of dicts with keys: label, value (0-100), color, count
        icon (str): Bootstrap icon name

    Returns:
        str: HTML for progress card
    """
    items_html = ""
    for item in items:
        label = item.get('label', 'Item')
        value = item.get('value', 0)
        color = item.get('color', 'primary')
        count = item.get('count', 0)

        items_html += f"""
        <div class="mb-3">
            <div class="d-flex justify-content-between mb-1">
                <span class="text-body-secondary">{label}</span>
                <strong>{count:,}</strong>
            </div>
            <div class="progress progress-thin">
                <div class="progress-bar bg-{color}" role="progressbar"
                     style="width: {value}%" aria-valuenow="{value}"
                     aria-valuemin="0" aria-valuemax="100"></div>
            </div>
        </div>
        """

    return f"""
    <div class="card">
        <div class="card-header">
            <i class="bi bi-{icon} me-2"></i>{title}
        </div>
        <div class="card-body">
            {items_html}
        </div>
    </div>
    """


def create_metric_border_card(metrics, border_width=4):
    """
    Create a card with colored border indicators for multiple metrics.

    Args:
        metrics (list): List of dicts with keys: label, value, color
        border_width (int): Border width in pixels

    Returns:
        str: HTML for metric border card
    """
    metrics_html = ""
    for metric in metrics:
        label = metric.get('label', 'Metric')
        value = metric.get('value', 'N/A')
        color = metric.get('color', 'info')

        metrics_html += f"""
        <div class="col-6 col-lg-3">
            <div class="border-start border-start-{border_width} border-start-{color} px-3 mb-3">
                <div class="small text-body-secondary text-truncate">{label}</div>
                <div class="fs-5 fw-semibold">{value}</div>
            </div>
        </div>
        """

    return f"""
    <div class="card">
        <div class="card-body">
            <div class="row">
                {metrics_html}
            </div>
        </div>
    </div>
    """


def create_stat_grid(stats, cols=4):
    """
    Create a responsive grid of stat widgets.

    Args:
        stats (list): List of stat widget configs (dicts with keys: value, label, icon, color, trend, trend_value)
        cols (int): Number of columns in grid (default: 4)

    Returns:
        str: HTML for stat grid
    """
    col_class = f"col-12 col-sm-6 col-lg-{12//cols}"

    widgets_html = ""
    for stat in stats:
        widget = create_stat_widget(
            value=stat.get('value', 'N/A'),
            label=stat.get('label', 'Metric'),
            icon=stat.get('icon', 'graph-up'),
            color=stat.get('color', 'primary'),
            trend=stat.get('trend'),
            trend_value=stat.get('trend_value'),
            subtitle=stat.get('subtitle')
        )
        widgets_html += f"""
        <div class="{col_class} mb-4">
            {widget}
        </div>
        """

    return f"""
    <div class="row g-3">
        {widgets_html}
    </div>
    """






