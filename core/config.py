# core/config.py
from pathlib import Path
import json

reports_folder = Path('output')
lists_folder = Path('lists')
markdown_folder = reports_folder / 'markdown_report'
html_reports_folder = reports_folder / 'html_report'
pdf_folder = reports_folder / 'pdf_report'

# Load password policy
with open(lists_folder / 'password_policy.json', 'r', encoding='utf-8') as f:
    policy = json.load(f)


# Animation configuration
ENABLE_ANIMATION = True  # Set to False to disable terminal animation