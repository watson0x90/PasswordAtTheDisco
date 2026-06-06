"""
Tests for the Jinja2 report templating environment (report_lib/templating.py).

The security-critical property is autoescaping: any value interpolated with
{{ ... }} must be HTML-escaped, so untrusted account data cannot inject markup.
"""

from report_lib.templating import get_environment


def test_autoescape_is_enabled():
    assert get_environment().autoescape is True


def test_interpolated_values_are_escaped():
    env = get_environment()
    tmpl = env.from_string("<td>{{ value }}</td>")
    rendered = tmpl.render(value='<img src=x onerror="alert(1)">')
    assert "<img" not in rendered
    assert "&lt;img src=x onerror=&#34;alert(1)&#34;&gt;" in rendered


def test_safe_filter_passes_trusted_html_through():
    env = get_environment()
    tmpl = env.from_string("<div>{{ chrome | safe }}</div>")
    assert tmpl.render(chrome="<span>ok</span>") == "<div><span>ok</span></div>"


def test_base_template_loads():
    # The base layout must be resolvable from the templates dir.
    assert get_environment().get_template("base.html.j2") is not None
