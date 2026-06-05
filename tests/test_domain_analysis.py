"""
Tests for risk re-scoring helpers in domain analysis (core/domain_analysis.py).
"""

from collections import Counter

from core.domain_analysis import _risk_after_boost, apply_shared_password_risk


class TestRiskAfterBoost:
    """The shared-password privilege boost must never downgrade a DA-path account."""

    def test_da_path_account_stays_critical_below_threshold(self):
        # Regression: GMANAGER-style account -- has a DA pathway but a boosted
        # score of 5.7 (< 8). Must remain Critical, not be downgraded to Medium.
        row = {"DA Domains": "PHANTOM.CORP, GHOST.CORP, WRAITH.CORP"}
        assert _risk_after_boost(5.7, row) == "Critical"

    def test_non_da_account_uses_numeric_threshold(self):
        row = {"DA Domains": "None"}
        assert _risk_after_boost(5.7, row) == "Medium"
        assert _risk_after_boost(8.5, row) == "Critical"
        assert _risk_after_boost(3.0, row) == "Low"

    def test_unknown_da_domains_is_not_a_pathway(self):
        assert _risk_after_boost(5.7, {"DA Domains": "Unknown"}) == "Medium"

    def test_missing_da_domains_defaults_to_no_pathway(self):
        assert _risk_after_boost(3.0, {}) == "Low"


def _row(overrides=None):
    base = {
        "Password": "pw", "Password Length": 8, "Risk Level": "Medium", "Score": 5.0,
        "Risk Vector": "BASE/DA:N/CO:0", "DA Domains": "None", "Controlled Object Count": 0,
    }
    if overrides:
        base.update(overrides)
    return base


class TestApplySharedPasswordRisk:
    def test_da_path_account_not_downgraded_by_boost(self):
        # Regression: a DA-path account (Critical) sharing a password with a much
        # higher-privilege account gets boosted but must STAY Critical.
        rows = [
            _row({"Password": "shared", "Risk Level": "Critical", "Score": 3.7,
                  "DA Domains": "CORP.INT", "Controlled Object Count": 38}),
            _row({"Password": "shared", "Risk Level": "Critical", "Score": 3.7,
                  "DA Domains": "CORP.INT", "Controlled Object Count": 469}),
        ]
        apply_shared_password_risk(rows, Counter({"Critical": 2}))
        assert rows[0]["Risk Level"] == "Critical"

    def test_sharing_password_with_da_account_becomes_critical(self):
        rows = [
            _row({"Password": "reused", "Risk Level": "Medium", "Score": 5.0,
                  "DA Domains": "CORP.INT", "Controlled Object Count": 100}),
            _row({"Password": "reused", "Risk Level": "Low", "Score": 2.0,
                  "DA Domains": "None", "Controlled Object Count": 0}),
        ]
        apply_shared_password_risk(rows, Counter({"Medium": 1, "Low": 1}))
        assert rows[1]["Risk Level"] == "Critical"
        assert rows[1]["Score"] >= 8.0

    def test_privilege_boost_escalates_score(self):
        rows = [
            _row({"Password": "p", "Risk Level": "Low", "Score": 3.0,
                  "DA Domains": "None", "Controlled Object Count": 10}),
            _row({"Password": "p", "Risk Level": "Medium", "Score": 5.0,
                  "DA Domains": "None", "Controlled Object Count": 500}),
        ]
        apply_shared_password_risk(rows, Counter({"Low": 1, "Medium": 1}))
        assert rows[0]["Score"] > 3.0

    def test_unshared_account_unchanged(self):
        rows = [_row({"Password": "unique", "Risk Level": "Medium", "Score": 5.0,
                      "Controlled Object Count": 5})]
        apply_shared_password_risk(rows, Counter({"Medium": 1}))
        assert rows[0]["Risk Level"] == "Medium" and rows[0]["Score"] == 5.0

    def test_risk_counter_kept_in_sync(self):
        rows = [
            _row({"Password": "reused", "Risk Level": "Medium",
                  "DA Domains": "CORP.INT", "Controlled Object Count": 100}),
            _row({"Password": "reused", "Risk Level": "Low", "Score": 2.0,
                  "DA Domains": "None", "Controlled Object Count": 0}),
        ]
        rc = Counter({"Medium": 1, "Low": 1})
        apply_shared_password_risk(rows, rc)
        assert rc["Critical"] >= 1 and rc["Low"] == 0

    def test_uncracked_rows_skipped(self):
        rows = [_row({"Password Length": "N/A", "Risk Level": "Medium"})]
        apply_shared_password_risk(rows, Counter({"Medium": 1}))
        assert rows[0]["Risk Level"] == "Medium"
