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
from functools import lru_cache
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

_TEMPLATES_DIR = Path(__file__).parent / "templates"


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
