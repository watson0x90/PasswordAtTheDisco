# core/config.py
"""
Configuration module for the password audit tool.
Defines paths, settings, and loads policy configuration.
"""

from pathlib import Path
import json
import os
import sys

# Ensure core directories exist
BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_DIR = BASE_DIR / 'config'
lists_folder = BASE_DIR / 'lists'

# DEPRECATED: Old folder variables (kept for backward compatibility)
# These are being phased out in favor of timestamped report directories
# New reports go to: reports/DOMAIN-TIMESTAMP/ (see create_report_directory())
# Logs go to: logs/ (see utils/logging.py)
reports_folder = BASE_DIR / 'output'  # DEPRECATED - used only by legacy code
markdown_folder = reports_folder / 'markdown_report'  # DEPRECATED
html_reports_folder = reports_folder / 'html_report'  # DEPRECATED
pdf_folder = reports_folder / 'pdf_report'  # DEPRECATED
csv_folder = reports_folder / 'csv_report'  # DEPRECATED
excel_folder = reports_folder / 'excel_report'  # DEPRECATED

# NOTE: Old output/ directories are no longer created by default
# Reports now go to timestamped directories in reports/
# See create_report_directory() function below

# Load password policies (domain-specific)
policy_file = lists_folder / 'password_policy.json'
_domain_policies = {}

if policy_file.exists():
    with open(policy_file, 'r', encoding='utf-8') as f:
        _domain_policies = json.load(f)
else:
    # Default policy structure if file doesn't exist
    _domain_policies = {
        "default": {
            "policy": {
                "min_length": 8,
                "require_lowercase": True,
                "require_uppercase": True,
                "require_digits": True,
                "require_special": True,
                "max_password_age_days": 90
            }
        }
    }

    # Create policy file with default values
    os.makedirs(lists_folder, exist_ok=True)
    with open(policy_file, 'w', encoding='utf-8') as f:
        json.dump(_domain_policies, f, indent=4)

# Legacy global policy for backward compatibility
# This uses the "default" domain policy
policy = _domain_policies.get("default", {}).get("policy", {})


def get_policy_for_domain(domain_name: str) -> dict:
    """
    Get the password policy for a specific domain.

    Args:
        domain_name: The domain name (e.g., "PRODUCTION.CORP")

    Returns:
        Dictionary with policy configuration
    """
    # Check if domain has specific policy
    if domain_name in _domain_policies and "policy" in _domain_policies[domain_name]:
        return _domain_policies[domain_name]["policy"]

    # Fall back to default policy
    if "default" in _domain_policies and "policy" in _domain_policies["default"]:
        return _domain_policies["default"]["policy"]

    # Ultimate fallback - hardcoded defaults
    return {
        "min_length": 8,
        "require_lowercase": True,
        "require_uppercase": True,
        "require_digits": True,
        "require_special": True,
        "max_password_age_days": 90
    }

# Animation configuration (legacy variable for backward compatibility)
# Now loaded from APP_CONFIG["UI"]["ENABLE_ANIMATION"]
# This will be set after APP_CONFIG is loaded below


def load_json_config(config_file: Path, config_name: str) -> dict:
    """
    Load configuration from a JSON file with error handling.

    Args:
        config_file: Path to the JSON config file
        config_name: Name of the configuration (for error messages)

    Returns:
        Dictionary with configuration values

    Raises:
        SystemExit: If file doesn't exist or is invalid
    """
    if not config_file.exists():
        print(f"\n{'='*70}")
        print(f"ERROR: {config_name} configuration file not found!")
        print(f"{'='*70}")
        print(f"Expected location: {config_file}")
        print(f"\nPlease create the configuration file with your settings.")
        print(f"See README.md for configuration instructions.")
        print(f"{'='*70}\n")
        sys.exit(1)

    try:
        with open(config_file, 'r', encoding='utf-8') as f:
            config = json.load(f)
        return config
    except json.JSONDecodeError as e:
        print(f"\n{'='*70}")
        print(f"ERROR: Invalid JSON in {config_name} configuration file!")
        print(f"{'='*70}")
        print(f"File: {config_file}")
        print(f"Error: {e}")
        print(f"\nPlease fix the JSON syntax in your configuration file.")
        print(f"{'='*70}\n")
        sys.exit(1)
    except Exception as e:
        print(f"\n{'='*70}")
        print(f"ERROR: Failed to load {config_name} configuration!")
        print(f"{'='*70}")
        print(f"File: {config_file}")
        print(f"Error: {e}")
        print(f"{'='*70}\n")
        sys.exit(1)


# BloodHound Enterprise configuration
_bhe_json = load_json_config(CONFIG_DIR / 'bloodhound.json', 'BloodHound')
BHE_CONFIG = {
    "DOMAIN": _bhe_json.get("domain", "127.0.0.1"),
    "PORT": _bhe_json.get("port", 8080),
    "SCHEME": _bhe_json.get("scheme", "http"),
    "TOKEN_ID": _bhe_json.get("token_id", ""),
    "TOKEN_KEY": _bhe_json.get("token_key", ""),
    "SEARCH_LIMIT": _bhe_json.get("search_limit", 1),
    "CONTROLLABLES_LIMIT": _bhe_json.get("controllables_limit", 10)
}

# Hashcat 7.1.2 configuration
_hashcat_json = load_json_config(CONFIG_DIR / 'hashcat.json', 'Hashcat')

# Convert relative paths to absolute
def _resolve_path(path_str: str, relative_to: Path = BASE_DIR) -> Path:
    """Convert a path string to an absolute Path object."""
    path = Path(path_str)
    if not path.is_absolute():
        path = relative_to / path
    return path.resolve()

HASHCAT_CONFIG = {
    "BINARY_PATH": _resolve_path(_hashcat_json.get("binary_path", "../../../hashcat/hashcat")),
    "WORDLISTS_DIR": _resolve_path(_hashcat_json.get("wordlists_dir", "../../../hashcat/wordlists")),
    "RULES_DIR": _resolve_path(_hashcat_json.get("rules_dir", "../../../hashcat/rules")),
    "POTFILE_DIR": _resolve_path(_hashcat_json.get("potfile_dir", "hashcat_potfiles")),
    "ENABLE_JSON_STATUS": _hashcat_json.get("enable_json_status", True),
    "ENABLE_BRAIN_MODE": _hashcat_json.get("enable_brain_mode", False),
    "BRAIN_HOST": _hashcat_json.get("brain_host", "127.0.0.1"),
    "BRAIN_PORT": _hashcat_json.get("brain_port", 6863),
    "BRAIN_PASSWORD": _hashcat_json.get("brain_password", "changeme"),
    "DEFAULT_WORKLOAD_PROFILE": _hashcat_json.get("default_workload_profile", 3),
    "ENABLE_OPTIMIZED_KERNEL": _hashcat_json.get("enable_optimized_kernel", True),
    "STATUS_TIMER": _hashcat_json.get("status_timer", 10)
}

# Create hashcat potfile directory
os.makedirs(HASHCAT_CONFIG["POTFILE_DIR"], exist_ok=True)

# HaveIBeenPwned configuration
_hibp_json = load_json_config(CONFIG_DIR / 'hibp.json', 'HIBP')
HIBP_CONFIG = {
    "NTLM_HASH_FILE": _resolve_path(_hibp_json.get("ntlm_hash_file", "PwnedPasswordsDownloader/pwnedpasswords_ntlm.txt")),
    "ENABLE_LOOKUP": _hibp_json.get("enable_lookup", True),
    "CACHE_SIZE": _hibp_json.get("cache_size", 1000000),
    "PREFIX_LENGTH": _hibp_json.get("prefix_length", 5)
}

# Application configuration (UI, server, etc.)
_app_config_file = CONFIG_DIR / 'application.json'
if _app_config_file.exists():
    try:
        with open(_app_config_file, 'r', encoding='utf-8') as f:
            _app_json = json.load(f)
    except Exception as e:
        print(f"Warning: Failed to load application.json, using defaults: {e}")
        _app_json = {}
else:
    # Use defaults if file doesn't exist
    _app_json = {}

APP_CONFIG = {
    "SERVER": {
        "PORT": _app_json.get("server", {}).get("port", 8008),
        "HOST": _app_json.get("server", {}).get("host", "localhost")
    },
    "UI": {
        "ENABLE_ANIMATION": _app_json.get("ui", {}).get("enable_animation", True)
    }
}

# Set legacy ENABLE_ANIMATION variable for backward compatibility
ENABLE_ANIMATION = APP_CONFIG["UI"]["ENABLE_ANIMATION"]

# Demo data configuration
DEMO_CONFIG = {
    "DATA_DIR": BASE_DIR / 'demo_data',
    "SCRIPTS_DIR": BASE_DIR / 'scripts',
    "ATTACK_PATHS_FILE": BASE_DIR / 'demo_data' / 'attack_paths.md',
    "DEFAULT_USER_COUNT": 100,
    "DEFAULT_HIBP_RATIO": 0.3,
    "DEFAULT_ROCKYOU_RATIO": 0.4,
}

# Create demo data directory
os.makedirs(DEMO_CONFIG["DATA_DIR"], exist_ok=True)

# Reports base directory
REPORTS_BASE_DIR = BASE_DIR / 'reports'
os.makedirs(REPORTS_BASE_DIR, exist_ok=True)


def create_report_directory(domains: list) -> dict:
    """
    Create a timestamped report directory for the audit run.

    Args:
        domains: List of domain names being audited

    Returns:
        Dictionary with all output paths:
            - base_dir: Base report directory
            - csv_dir: CSV reports directory
            - excel_dir: Excel reports directory
            - html_dir: HTML reports directory
            - markdown_dir: Markdown reports directory
            - pdf_dir: PDF reports directory
            - run_id: Unique run identifier
            - timestamp: ISO timestamp string
    """
    from datetime import datetime

    # Generate timestamp
    now = datetime.now()
    timestamp = now.strftime("%Y-%m-%d-%H%M%S")
    timestamp_iso = now.isoformat()

    # Generate run ID from domain names
    domain_parts = []
    for domain in domains:
        # Extract just the domain name (before .COM, .INT, etc.)
        domain_name = domain.split('.')[0].upper()
        domain_parts.append(domain_name)

    # Limit to first 3 domains to keep directory names manageable
    if len(domain_parts) > 3:
        domain_str = '-'.join(domain_parts[:3]) + f'-and-{len(domain_parts)-3}-more'
    else:
        domain_str = '-'.join(domain_parts)

    # Create run ID
    run_id = f"{domain_str}-{timestamp}"

    # Create base directory
    base_dir = REPORTS_BASE_DIR / run_id
    os.makedirs(base_dir, exist_ok=True)

    # Create subdirectories
    csv_dir = base_dir / 'csv'
    excel_dir = base_dir / 'excel'
    html_dir = base_dir / 'html'
    markdown_dir = base_dir / 'markdown'
    pdf_dir = base_dir / 'pdf'

    for directory in [csv_dir, excel_dir, html_dir, markdown_dir, pdf_dir]:
        os.makedirs(directory, exist_ok=True)

    # Create/update 'latest' symlink
    latest_link = REPORTS_BASE_DIR / 'latest'

    # Remove existing symlink if it exists
    if latest_link.exists() or latest_link.is_symlink():
        latest_link.unlink()

    # Create new symlink (relative path for portability)
    try:
        latest_link.symlink_to(run_id, target_is_directory=True)
    except (OSError, NotImplementedError):
        # On Windows or systems without symlink support, just skip
        pass

    return {
        'base_dir': base_dir,
        'csv_dir': csv_dir,
        'excel_dir': excel_dir,
        'html_dir': html_dir,
        'markdown_dir': markdown_dir,
        'pdf_dir': pdf_dir,
        'run_id': run_id,
        'timestamp': timestamp_iso,
        'timestamp_str': timestamp
    }


def get_latest_report_dir() -> Path:
    """
    Get the latest report directory.

    Returns:
        Path to latest report directory, or None if no reports exist
    """
    latest_link = REPORTS_BASE_DIR / 'latest'

    # If symlink exists, use it
    if latest_link.is_symlink() and latest_link.exists():
        return latest_link.resolve()

    # Otherwise, find most recent directory
    report_dirs = []
    for item in REPORTS_BASE_DIR.iterdir():
        if item.is_dir() and item.name != 'latest':
            report_dirs.append(item)

    if not report_dirs:
        return None

    # Sort by modification time, most recent first
    report_dirs.sort(key=lambda x: x.stat().st_mtime, reverse=True)
    return report_dirs[0]


def list_report_directories() -> list:
    """
    List all report directories with metadata.

    Returns:
        List of dictionaries with report information
    """
    import json

    reports = []

    for item in REPORTS_BASE_DIR.iterdir():
        if item.is_dir() and item.name != 'latest':
            metadata_file = item / 'metadata.json'

            # Try to load metadata
            if metadata_file.exists():
                try:
                    with open(metadata_file, 'r') as f:
                        metadata = json.load(f)
                    reports.append(metadata)
                except Exception:
                    # If metadata can't be loaded, create basic info
                    reports.append({
                        'run_id': item.name,
                        'base_dir': str(item),
                        'timestamp': None
                    })
            else:
                # No metadata, create basic info
                reports.append({
                    'run_id': item.name,
                    'base_dir': str(item),
                    'timestamp': None
                })

    # Sort by timestamp (most recent first)
    reports.sort(key=lambda x: x.get('timestamp', ''), reverse=True)

    return reports