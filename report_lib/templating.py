"""
Jinja2 templating for HTML reports.

A single autoescaping environment renders the report pages. Autoescaping is ON
for every template, so any value interpolated with ``{{ value }}`` (account
usernames, domains, cracked passwords, etc.) is HTML-escaped by default --
preventing the injection that the previous f-string concatenation allowed.
Trusted, pre-built HTML fragments (CSS/JS bundles, plotly chart markup,
chrome rendered elsewhere) are passed through explicitly with the ``| safe``
filter.
"""
import shutil
from functools import lru_cache
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

_TEMPLATES_DIR = Path(__file__).parent / "templates"
_VENDOR_DIR = Path(__file__).parent / "vendor"


def copy_vendor_assets(html_dir) -> None:
    """Copy the vendored front-end assets (CoreUI, Bootstrap Icons, Plotly) into
    a report's html directory as ``vendor/``, so the HTML reports render without
    any internet access (air-gapped review). No-op if already present."""
    dest = Path(html_dir) / "vendor"
    if dest.exists():
        return
    if _VENDOR_DIR.exists():
        shutil.copytree(_VENDOR_DIR, dest)


@lru_cache(maxsize=1)
def get_environment() -> Environment:
    """Return the shared, autoescaping Jinja2 environment."""
    return Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        autoescape=True,          # escape everything by default; opt out with | safe
        trim_blocks=True,
        lstrip_blocks=True,
    )


def render(template_name: str, **context) -> str:
    """Render a template from report_lib/templates with the given context."""
    return get_environment().get_template(template_name).render(**context)


def render_macro(template_name: str, macro_name: str, *args, **kwargs) -> str:
    """Render a single macro from a template (its values are autoescaped)."""
    template = get_environment().get_template(template_name)
    macro = getattr(template.module, macro_name)
    return str(macro(*args, **kwargs))
