"""
Tests for risk re-scoring helpers in domain analysis (core/domain_analysis.py).
"""

from core.domain_analysis import _risk_after_boost


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
