"""
Smoke tests for the HTML report generators.

Each test generates a report from a small fixture and asserts the output is
valid, complete HTML with no error markers. This locks in the Jinja templating
migration so a future change can't silently break report generation (e.g. the
local-variable shadowing bug that only surfaced in a live audit).
"""
import pytest

from core import config


def _account(username, domain="CORP.INT", pw_len=9, da="None", risk="High",
             score=7.0, breached="No", breach_count=0, ooc=0, expire="No", coc=0):
    return {
        "Username": username, "Domain": domain, "Password": "Passw0rd!",
        "Password Length": pw_len, "DA Domains": da, "Risk Level": risk, "Score": score,
        "Risk Vector": "C:5/L:M/D:N", "HIBP Breached": breached, "HIBP Breach Count": breach_count,
        "Days Out of Compliance": ooc, "Password Set to Expire": expire, "Enabled": "Yes",
        "Controlled Object Count": coc, "Shared With": 0, "Last Logon": "2024-01-01",
        "Last Password Set": "2020-01-01", "When Created": "2019-01-01", "Complexity Label": "Weak",
    }


def _rows():
    return [
        _account("ALICE@CORP.INT", da="CORP.INT", risk="Critical", score=9.0,
                 breached="Yes", breach_count=1000, ooc=100, coc=50),
        _account("BOB@CORP.INT", risk="Medium", score=5.0),
        _account("CAROL@CORP.INT", risk="High", score=7.0, breached="Yes", breach_count=50, ooc=50),
        _account("DAVE@CORP.INT", pw_len="N/A", risk="Unknown"),
    ]


@pytest.fixture
def html_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "html_reports_folder", tmp_path)
    return tmp_path


def _assert_valid_report(path, *must_contain):
    assert path.exists(), f"{path.name} was not generated"
    html = path.read_text(encoding="utf-8")
    assert html.lstrip().startswith("<!DOCTYPE html>"), f"{path.name} is not valid HTML"
    assert html.rstrip().endswith("</html>"), f"{path.name} is truncated"
    for marker in ("Error processing", "Error generating", "not associated", "Traceback"):
        assert marker not in html, f"error marker '{marker}' present in {path.name}"
    for snippet in must_contain:
        assert snippet in html, f"expected '{snippet}' in {path.name}"


def test_about_report(html_dir):
    from report_lib.standalone_html.about import generate_about_html
    generate_about_html(
        {"timestamp": "2026-01-01", "domains": ["CORP.INT"], "version": "1.0.0",
         "total_accounts": 4, "cracked_accounts": 3, "uncracked_accounts": 1,
         "tool_name": "Password!AtTheDisco"},
        domains=["CORP.INT"],
    )
    _assert_valid_report(html_dir / "about.html", "About Password!AtTheDisco", "CORP.INT")


def test_single_domain_report(html_dir):
    from report_lib.standalone_html.single_domain import generate_html_report
    data = {
        "output_rows": _rows(),
        "domain_risk": {"risk_distribution": {"Critical": 1, "High": 1, "Medium": 1, "Low": 0},
                        "risk_score": 7.0, "overall_risk_level": "High",
                        "avg_score": 7.0, "max_score": 9.0},
    }
    generate_html_report("CORP.INT", data, {})
    _assert_valid_report(html_dir / "CORP.INT_report.html",
                         "Password Security Report", "Risk Distribution", "ALICE@CORP.INT")


def test_actionable_report(html_dir):
    from report_lib.standalone_html.actionable import generate_html_actionable_report
    generate_html_actionable_report("CORP.INT", {"output_rows": _rows()}, "seed123", {})
    _assert_valid_report(html_dir / "CORP.INT_actionable_report.html",
                         "Actionable Report", "Count in this Domain")


def test_combined_report(html_dir):
    from report_lib.standalone_html.combined import generate_combined_html_report
    global_password_to_users = {"Passw0rd!": [("ALICE", "CORP.INT"), ("BOB", "CORP.INT")]}
    generate_combined_html_report(_rows(), global_password_to_users, {}, {})
    _assert_valid_report(html_dir / "combined_report.html",
                         "Cross-Domain Analysis", "Top Shared Passwords")


def test_main_dashboard(html_dir):
    from report_lib.standalone_html.combined import generate_main_html
    generate_main_html(["CORP.INT"], {"CORP.INT": {"output_rows": _rows()}})
    _assert_valid_report(html_dir / "main.html",
                         "Password Security Audit", "Key Metrics", "Domain Reports")
