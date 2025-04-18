# core/config.py
"""
Configuration module for the password audit tool.
Defines paths, settings, and loads policy configuration.
"""

from pathlib import Path
import json
import os

# Ensure core directories exist
BASE_DIR = Path(__file__).resolve().parent.parent
reports_folder = BASE_DIR / 'output'
lists_folder = BASE_DIR / 'lists'
markdown_folder = reports_folder / 'markdown_report'
html_reports_folder = reports_folder / 'html_report'
pdf_folder = reports_folder / 'pdf_report'
csv_folder = reports_folder / 'csv_report'
excel_folder = reports_folder / 'excel_report'

# Create directories if they don't exist
os.makedirs(reports_folder, exist_ok=True)
os.makedirs(markdown_folder, exist_ok=True)
os.makedirs(html_reports_folder, exist_ok=True)
os.makedirs(pdf_folder, exist_ok=True)
os.makedirs(csv_folder, exist_ok=True)
os.makedirs(excel_folder, exist_ok=True)

# Load password policy
policy_file = lists_folder / 'password_policy.json'
policy = {}

if policy_file.exists():
    with open(policy_file, 'r', encoding='utf-8') as f:
        policy = json.load(f)
else:
    # Default policy if file doesn't exist
    policy = {
        "min_length": 8,
        "require_lowercase": True,
        "require_uppercase": True,
        "require_digits": True,
        "require_special": True,
        "max_password_age_days": 90
    }
    
    # Create policy file with default values
    os.makedirs(lists_folder, exist_ok=True)
    with open(policy_file, 'w', encoding='utf-8') as f:
        json.dump(policy, f, indent=4)

# Animation configuration
ENABLE_ANIMATION = True  # Set to False to disable terminal animation

# BloodHound Enterprise configuration
BHE_CONFIG = {
    "DOMAIN": "10.0.5.218",
    "PORT": 8080,
    "SCHEME": "http",
    "TOKEN_ID": "854233a7-a33d-4bee-a610-6e5ba50cacea",
    "TOKEN_KEY": "2/ug1h4/G0wzTJQHEkCM8PJzo6MjMdSz1sknzZGVSD8Ws8DURBTI8g=="
}