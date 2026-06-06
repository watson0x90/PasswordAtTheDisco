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


class TestOfflineAssets:
    def test_no_cdn_urls_remain(self):
        from report_lib.standalone_html.styles import COREUI_CDN, COREUI_JS
        blob = COREUI_CDN + COREUI_JS
        for cdn in ("cdn.jsdelivr.net", "cdn.plot.ly", "cdnjs.cloudflare", "unpkg.com", "fonts.googleapis"):
            assert cdn not in blob, f"CDN reference still present: {cdn}"
        assert "vendor/coreui/coreui.min.css" in COREUI_CDN
        assert "vendor/plotly/plotly.min.js" in COREUI_JS

    def test_copy_vendor_assets(self, tmp_path):
        from report_lib.templating import copy_vendor_assets
        copy_vendor_assets(tmp_path)
        v = tmp_path / "vendor"
        for rel in ("coreui/coreui.min.css", "coreui/coreui.bundle.min.js",
                    "bootstrap-icons/bootstrap-icons.min.css",
                    "bootstrap-icons/fonts/bootstrap-icons.woff2",
                    "plotly/plotly.min.js"):
            assert (v / rel).exists(), f"missing vendored asset: {rel}"
        copy_vendor_assets(tmp_path)  # idempotent, no error


class TestChromePartials:
    def test_sidebar_escapes_domain_names(self):
        from report_lib.standalone_html.components import create_sidebar
        sb = create_sidebar(current_page='about', domains=['EVIL<img src=x onerror=alert(1)>'])
        assert '<img src=x onerror' not in sb      # not raw markup
        assert '&lt;img' in sb                     # escaped

    def test_sidebar_active_state_and_fallback(self):
        from report_lib.standalone_html.components import create_sidebar
        sb = create_sidebar(current_page='about')
        assert 'class="nav-link active"' in sb
        assert 'aria-current="page" href="about.html"' in sb   # active item marked for AT
        assert 'No domains loaded' in create_sidebar(domains=[])

    def test_navbar_conditionals(self):
        from report_lib.standalone_html.components import create_navbar
        assert 'id="navbarSearch"' in create_navbar(include_search=True)
        assert 'id="navbarSearch"' not in create_navbar(include_search=False)
        assert 'exportPDF()' in create_navbar(include_export=True)
        assert 'exportPDF()' not in create_navbar(include_export=False)

    def test_offcanvas_shell(self):
        from report_lib.standalone_html.components import create_user_detail_offcanvas
        oc = create_user_detail_offcanvas()
        assert 'id="userDetailOffcanvas"' in oc and 'id="riskBreakdownContent"' in oc
        assert 'role="tab"' in oc and 'aria-controls="riskBreakdownTab"' in oc
        assert 'role="tabpanel" aria-labelledby="riskBreakdownTabBtn"' in oc


    def test_base_layout_has_landmarks_and_skip_link(self):
        from report_lib.templating import render
        html = render("base.html.j2", head="<head></head>", navbar="", sidebar="",
                      sidebar_nav_js="")
        assert 'href="#main-content"' in html and "Skip to main content" in html
        assert '<main class="main-content" id="main-content">' in html
