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


from report_lib.templating import render_macro  # noqa: E402


class TestTableMacros:
    def test_account_table_escapes_user_data(self):
        rows = [{"Username": '<img src=x onerror=alert(1)>', "Password": '<script>x</script>',
                 "DA Domains": "C<b>", "Risk Level": "Critical", "Risk Vector": "V"}]
        cols = [{"header": "User", "field": "Username", "kind": "user_link"},
                {"header": "PW", "field": "Password", "kind": "code"},
                {"header": "DA", "field": "DA Domains", "kind": "badge_warn"},
                {"header": "Risk", "field": "Risk Level", "kind": "risk_badge"}]
        out = render_macro("partials/tables.html.j2", "account_table", cols, rows)
        assert "<img" not in out and "&lt;img" in out
        assert "<script>x" not in out and "&lt;script&gt;x" in out
        assert 'data-username="&lt;img' in out          # attribute context escaped
        assert "badge-risk-critical" in out             # trusted badge still rendered

    def test_top_shared_table_escapes(self):
        out = render_macro("partials/tables.html.j2", "top_shared_passwords_table",
                           [{"password": "<svg onload=x>", "total": 2, "domain_counts": [("D<b>", 1)]}])
        assert "<svg" not in out and "&lt;svg" in out
        assert "D&lt;b&gt;" in out
