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


def create_accordion_item(item_id, title, content, parent_id, collapsed=True, icon=None):
    """
    Create a single accordion item.

    Args:
        item_id (str): Unique ID for this accordion item
        title (str): Accordion header title
        content (str): Accordion body content (HTML)
        parent_id (str): ID of parent accordion container
        collapsed (bool): Whether item starts collapsed
        icon (str): Optional Bootstrap icon name

    Returns:
        str: HTML for accordion item
    """
    icon_html = f'<i class="bi bi-{icon} me-2"></i>' if icon else ""
    collapsed_class = "" if not collapsed else "collapsed"
    show_class = "show" if not collapsed else ""
    expanded = "true" if not collapsed else "false"

    return f"""
    <div class="accordion-item">
        <h2 class="accordion-header" id="heading-{item_id}">
            <button class="accordion-button {collapsed_class}" type="button"
                    data-bs-toggle="collapse" data-bs-target="#collapse-{item_id}"
                    aria-expanded="{expanded}" aria-controls="collapse-{item_id}">
                {icon_html}{title}
            </button>
        </h2>
        <div id="collapse-{item_id}" class="accordion-collapse collapse {show_class}"
             aria-labelledby="heading-{item_id}" data-bs-parent="#{parent_id}">
            <div class="accordion-body">
                {content}
            </div>
        </div>
    </div>
    """


def create_accordion(items, accordion_id="accordion", flush=False):
    """
    Create a complete accordion from multiple items.

    Args:
        items (list): List of dicts with keys: id, title, content, icon (optional)
        accordion_id (str): Unique ID for accordion container
        flush (bool): Whether to use flush style (no borders/background)

    Returns:
        str: HTML for complete accordion
    """
    flush_class = " accordion-flush" if flush else ""

    items_html = ""
    for idx, item in enumerate(items):
        items_html += create_accordion_item(
            item_id=item.get('id', f'item{idx}'),
            title=item.get('title', f'Item {idx+1}'),
            content=item.get('content', ''),
            parent_id=accordion_id,
            collapsed=(idx != 0),  # First item open by default
            icon=item.get('icon')
        )

    return f"""
    <div class="accordion{flush_class}" id="{accordion_id}">
        {items_html}
    </div>
    """


def create_info_modal(modal_id, title, content, size="lg", footer_buttons=None):
    """
    Create a Bootstrap modal dialog.

    Args:
        modal_id (str): Unique ID for modal
        title (str): Modal title
        content (str): Modal body content (HTML)
        size (str): Modal size - "sm", "lg", "xl"
        footer_buttons (list): Optional list of button HTML strings

    Returns:
        str: HTML for modal (hidden by default, shown via JavaScript)
    """
    size_class = f" modal-{size}" if size != "md" else ""

    footer_html = ""
    if footer_buttons:
        buttons_html = "".join(footer_buttons)
        footer_html = f"""
        <div class="modal-footer">
            {buttons_html}
        </div>
        """
    else:
        footer_html = """
        <div class="modal-footer">
            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
        </div>
        """

    return f"""
    <div class="modal fade" id="{modal_id}" tabindex="-1" aria-labelledby="{modal_id}Label" aria-hidden="true">
        <div class="modal-dialog{size_class} modal-dialog-scrollable">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="{modal_id}Label">{title}</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    {content}
                </div>
                {footer_html}
            </div>
        </div>
    </div>
    """


def create_chart_card_with_actions(title, chart_html, actions=None, subtitle=None):
    """
    Create a card for visualizations with action buttons (download, expand, etc).

    Args:
        title (str): Chart title
        chart_html (str): Chart HTML content (Plotly div or iframe)
        actions (list): Optional list of action button HTML strings
        subtitle (str): Optional subtitle/date range

    Returns:
        str: HTML for chart card with toolbar
    """
    subtitle_html = f'<div class="small text-body-secondary">{subtitle}</div>' if subtitle else ""

    actions_html = ""
    if actions:
        actions_html = f"""
        <div class="btn-toolbar" role="toolbar">
            <div class="btn-group btn-group-sm me-2" role="group">
                {"".join(actions)}
            </div>
        </div>
        """

    return f"""
    <div class="card mb-4">
        <div class="card-header d-flex justify-content-between align-items-center">
            <div>
                <h5 class="card-title mb-0">{title}</h5>
                {subtitle_html}
            </div>
            {actions_html}
        </div>
        <div class="card-body">
            {chart_html}
        </div>
    </div>
    """


def create_table_card_with_filter(title, table_html, filter_options=None, export_buttons=True):
    """
    Create a card for tables with filtering and export options.

    Args:
        title (str): Table title
        table_html (str): Table HTML content
        filter_options (list): Optional list of filter button configs
        export_buttons (bool): Whether to include CSV/JSON export buttons

    Returns:
        str: HTML for table card with controls
    """
    filter_html = ""
    if filter_options:
        buttons_html = ""
        for option in filter_options:
            label = option.get('label', 'Filter')
            value = option.get('value', 'all')
            btn_class = option.get('class', 'btn-outline-secondary')
            active = ' active' if option.get('active', False) else ''

            buttons_html += f"""
            <button type="button" class="btn btn-sm {btn_class}{active}"
                    onclick="filterTable('{value}', this)">{label}</button>
            """

        filter_html = f"""
        <div class="d-flex align-items-center gap-2 mb-3">
            <span class="text-muted"><i class="bi bi-funnel me-1"></i>Filter:</span>
            <div class="btn-group" role="group">
                {buttons_html}
            </div>
        </div>
        """

    export_html = ""
    if export_buttons:
        export_html = """
        <div class="btn-group btn-group-sm" role="group">
            <button type="button" class="btn btn-outline-secondary" onclick="exportTableToCSV()" title="Export to CSV">
                <i class="bi bi-file-earmark-spreadsheet"></i>
            </button>
            <button type="button" class="btn btn-outline-secondary" onclick="exportTableToJSON()" title="Export to JSON">
                <i class="bi bi-filetype-json"></i>
            </button>
        </div>
        """

    return f"""
    <div class="card mb-4">
        <div class="card-header d-flex justify-content-between align-items-center">
            <h5 class="card-title mb-0"><i class="bi bi-table me-2"></i>{title}</h5>
            {export_html}
        </div>
        <div class="card-body">
            {filter_html}
            {table_html}
        </div>
    </div>
    """
