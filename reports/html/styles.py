# reports/html/styles.py
"""
CSS styles for HTML reports.
"""

# Base CSS for all reports
BASE_CSS = """
body { font-family: Arial, Helvetica, sans-serif; margin: 20px; color: #000000; }
h1 { font-size: 24px; font-weight: bold; color: #000000; margin-bottom: 20px; }
h2 { font-size: 20px; font-weight: bold; color: #000000; margin-top: 20px; margin-bottom: 10px; }
h3 { font-size: 16px; font-weight: bold; color: #000000; margin-top: 15px; margin-bottom: 10px; }
p { margin: 10px 0; }
table { border-collapse: collapse; width: 100%; margin: 20px 0; }
th, td { border: 1px solid #000000; padding: 8px; text-align: left; }
th { background-color: #f2f2f2; font-weight: bold; cursor: pointer; }
th:hover { background-color: #e0e0e0; }
ul { list-style-type: disc; margin: 10px 0 10px 20px; }
li { margin: 5px 0; }
a { color: #0066cc; text-decoration: none; }
a:hover { text-decoration: underline; }
input[type="text"] { padding: 8px; width: 300px; margin-bottom: 20px; }
.tooltip { position: relative; display: inline-block; cursor: help; text-decoration: underline dotted; }
.tooltip .tooltiptext { visibility: hidden; width: 400px; background-color: #555; color: #fff; text-align: left; border-radius: 6px; padding: 8px; position: absolute; z-index: 1; bottom: 125%; left: 50%; margin-left: -200px; opacity: 0; transition: opacity 0.3s; }
.tooltip:hover .tooltiptext { visibility: visible; opacity: 1; }
.risk-critical { background-color: #ffdddd; }
.risk-high { background-color: #ffffcc; }
.risk-medium { background-color: #e6f2ff; }
.risk-low { background-color: #e6ffe6; }
.visualization-container { margin: 20px 0; padding: 10px; border: 1px solid #e0e0e0; border-radius: 5px; }
.visualization-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 20px; }
.error-message { color: #f44336; font-style: italic; }
.pagination { display: flex; justify-content: center; padding: 20px 0; }
.pagination button { margin: 0 5px; padding: 5px 10px; cursor: pointer; }
.current-page { font-weight: bold; background-color: #e0e0e0; }
.explanation-block { background-color: #f8f9fa; border-left: 4px solid #4CAF50; padding: 10px 15px; margin: 15px 0; }
.action-item { background-color: #FFF3E0; border-left: 4px solid #FF9800; padding: 10px 15px; margin: 15px 0; }
.tab-container { margin: 20px 0; }
.tab-buttons { overflow: hidden; border: 1px solid #ccc; background-color: #f1f1f1; }
.tab-buttons button { background-color: inherit; float: left; border: none; outline: none; cursor: pointer; padding: 14px 16px; }
.tab-buttons button:hover { background-color: #ddd; }
.tab-buttons button.active { background-color: #ccc; }
.tab-content { display: none; padding: 20px; border: 1px solid #ccc; border-top: none; }
.filter-container { margin-bottom: 15px; }
.filter-container button { padding: 5px 10px; margin-right: 5px; cursor: pointer; }
.filter-container button.active { background-color: #0066cc; color: white; }
"""

# CSS for iframe content
IFRAME_CSS = """
iframe { width: 100%; height: 500px; border: none; margin: 20px 0; }
"""

# Additional styles for sorting
TABLE_SORT_CSS = """
.sorted-asc::after { content: " ↑"; }
.sorted-desc::after { content: " ↓"; }
"""

# Styles for dashboard
DASHBOARD_CSS = """
.dashboard-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
    gap: 20px;
    margin-top: 20px;
}
.domain-card {
    border: 1px solid #ddd;
    border-radius: 8px;
    padding: 15px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}
.domain-card h3 {
    margin-top: 0;
    border-bottom: 1px solid #eee;
    padding-bottom: 10px;
}
.metric {
    margin: 10px 0;
    font-size: 24px;
    font-weight: bold;
}
.metric-label {
    font-size: 14px;
    color: #555;
}
.card-links {
    margin-top: 15px;
    padding-top: 10px;
    border-top: 1px solid #eee;
}
.risk-critical { color: #D32F2F; }
.risk-high { color: #FFA726; }
.risk-medium { color: #FFEB3B; }
.risk-low { color: #66BB6A; }
"""