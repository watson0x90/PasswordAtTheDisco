"""
Characterization tests for the CVSS-style risk scoring engine (core/scoring.py).

These lock down the current, intended behavior of the scoring math so it can be
refactored safely. The scoring engine is pure and deterministic, so every value
here is reproducible.
"""

import math

import pytest

from core.scoring import (
    calculate_base_score,
    calculate_environmental_score,
    calculate_password_risk_score,
    calculate_temporal_score,
    compute_risk_level,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_analysis(**overrides):
    """Build a password_analysis dict with neutral defaults for a strong password."""
    analysis = {
        "complexity_label": "mixedalphaspecialnum",  # strongest -> lowest factor
        "password_length": 20,                        # long -> tiny length factor
        "is_common": False,
        "is_exactly_dictionary_word": False,
        "banned_words": [],
        "keyboard_patterns": [],
        "days_out_of_compliance": "Unknown",
        "password_set_to_expire": "Unknown",
    }
    analysis.update(overrides)
    return analysis


# ---------------------------------------------------------------------------
# compute_risk_level
# ---------------------------------------------------------------------------

class TestComputeRiskLevel:
    @pytest.mark.parametrize("score,expected", [
        (10.0, "Critical"),
        (8.0, "Critical"),    # boundary
        (7.9, "High"),
        (6.0, "High"),        # boundary
        (5.9, "Medium"),
        (4.0, "Medium"),      # boundary
        (3.9, "Low"),
        (0.0, "Low"),
    ])
    def test_thresholds(self, score, expected):
        assert compute_risk_level(score) == expected

    def test_da_path_forces_critical_regardless_of_score(self):
        # A Domain Admin pathway is always Critical, even at score 0.
        assert compute_risk_level(0.0, has_da_path=True) == "Critical"
        assert compute_risk_level(3.9, has_da_path=True) == "Critical"


# ---------------------------------------------------------------------------
# calculate_base_score
# ---------------------------------------------------------------------------

class TestBaseScore:
    def test_returns_five_tuple(self):
        result = calculate_base_score("mixedalphaspecialnum", 20, False, False, 0, 0, [])
        assert len(result) == 5

    def test_strong_long_password_scores_low(self):
        base, *_ = calculate_base_score("mixedalphaspecialnum", 20, False, False, 0, 0, [])
        assert base < 1.0

    def test_complexity_factor_mapping(self):
        # Strongest complexity yields the smallest complexity factor (0.2).
        _, complexity_factor, *_ = calculate_base_score(
            "mixedalphaspecialnum", 20, False, False, 0, 0, [])
        assert complexity_factor == 0.2

    def test_unknown_complexity_label_defaults_to_worst(self):
        _, complexity_factor, *_ = calculate_base_score(
            "not-a-real-label", 20, False, False, 0, 0, [])
        assert complexity_factor == 1.0

    def test_length_factor_is_sigmoid(self):
        # length_factor = 1 / (1 + exp((L - 10) / 2))
        _, _, length_factor, _, _ = calculate_base_score(
            "numeric", 10, False, False, 0, 0, [])
        assert length_factor == pytest.approx(1.0 / (1.0 + math.exp(0.0)))  # == 0.5

    def test_dictionary_factor_caps_at_one(self):
        _, _, _, dictionary_factor, _ = calculate_base_score(
            "loweralpha", 4, True, True, 10, 10, [])
        assert dictionary_factor == 1.0

    @pytest.mark.parametrize("similarity,expected", [
        (0.95, 0.6),
        (0.85, 0.4),
        (0.75, 0.2),
        (0.5, 0.0),
    ])
    def test_similarity_factor_tiers(self, similarity, expected):
        _, _, _, _, similarity_factor = calculate_base_score(
            "mixedalphaspecialnum", 20, False, False, 0, 0, [("other", similarity)])
        assert similarity_factor == expected

    def test_base_score_capped_at_ten(self):
        base, *_ = calculate_base_score(
            "none", 1, True, True, 50, 50, [("x", 1.0)])
        assert base <= 10.0


# ---------------------------------------------------------------------------
# calculate_temporal_score
# ---------------------------------------------------------------------------

class TestTemporalScore:
    def test_unknown_compliance_uses_mid_factor(self):
        _, compliance_factor, _ = calculate_temporal_score(10.0, "Unknown", "No")
        assert compliance_factor == 0.8

    def test_expiration_no_is_full_weight(self):
        _, _, expiration_factor = calculate_temporal_score(10.0, 0, "No")
        assert expiration_factor == 1.0

    def test_expiration_yes_reduces(self):
        _, _, expiration_factor = calculate_temporal_score(10.0, 0, "Yes")
        assert expiration_factor == 0.85

    def test_expiration_unknown_is_mid(self):
        _, _, expiration_factor = calculate_temporal_score(10.0, 0, "Unknown")
        assert expiration_factor == 0.925

    def test_temporal_is_product_of_factors(self):
        temporal, comp, exp = calculate_temporal_score(10.0, "Unknown", "Unknown")
        assert temporal == pytest.approx(min(10.0, 10.0 * comp * exp))

    def test_more_days_out_of_compliance_increases_risk(self):
        low, *_ = calculate_temporal_score(10.0, 10, "No")
        high, *_ = calculate_temporal_score(10.0, 180, "No")
        assert high > low


# ---------------------------------------------------------------------------
# calculate_environmental_score
# ---------------------------------------------------------------------------

class TestEnvironmentalScore:
    def test_da_path_raises_privilege_factor(self):
        _, privilege_factor, *_ = calculate_environmental_score(
            5.0, has_da_path=True, controlled_object_count=0, shared_with=0)
        assert privilege_factor == pytest.approx(1.5)

    @pytest.mark.parametrize("count,expected_priv", [
        (5, 1.0),
        (50, 1.1),
        (100, 1.2),
        (500, 1.3),
        (1000, 1.4),
        (2000, 1.5),
    ])
    def test_controlled_object_tiers(self, count, expected_priv):
        _, privilege_factor, *_ = calculate_environmental_score(
            5.0, has_da_path=False, controlled_object_count=count, shared_with=0)
        assert privilege_factor == pytest.approx(expected_priv)

    @pytest.mark.parametrize("shared,expected_share", [
        (0, 1.0),
        (5, 1.2),
        (10, 1.3),
        (100, 1.4),
        (1000, 1.5),
    ])
    def test_share_tiers(self, shared, expected_share):
        _, _, share_factor, *_ = calculate_environmental_score(
            5.0, has_da_path=False, controlled_object_count=0, shared_with=shared)
        assert share_factor == pytest.approx(expected_share)

    @pytest.mark.parametrize("level,expected", [
        ("Critical", 1.3),
        ("High", 1.2),
        ("Medium", 1.1),
        ("Low", 1.0),
        ("Unknown", 1.0),
        (None, 1.0),
    ])
    def test_domain_risk_factor(self, level, expected):
        _, _, _, domain_factor, _ = calculate_environmental_score(
            5.0, False, 0, 0, domain_risk_level=level)
        assert domain_factor == pytest.approx(expected)

    @pytest.mark.parametrize("breaches,expected", [
        (0, 1.0),
        (50, 1.1),
        (100, 1.2),
        (1000, 1.3),
        (10000, 1.4),
        (100000, 1.5),
    ])
    def test_hibp_factor_tiers(self, breaches, expected):
        _, _, _, _, hibp_factor = calculate_environmental_score(
            5.0, False, 0, 0, hibp_breach_count=breaches)
        assert hibp_factor == pytest.approx(expected)

    def test_environmental_capped_at_ten(self):
        score, *_ = calculate_environmental_score(
            10.0, has_da_path=True, controlled_object_count=2000,
            shared_with=1000, domain_risk_level="Critical", hibp_breach_count=100000)
        assert score <= 10.0


# ---------------------------------------------------------------------------
# calculate_password_risk_score  (cracked-password tier flooring)
# ---------------------------------------------------------------------------

class TestCrackedPasswordFlooring:
    """A cracked password always carries baseline risk regardless of strength."""

    def _base(self, **overrides):
        _, breakdown, _ = calculate_password_risk_score(
            make_analysis(**overrides),
            shared_with=0, da_domains="None", controlled_object_count=0,
            hibp_breach_count=overrides.pop("hibp_breach_count", 0),
        )
        return breakdown["base_score"]

    def test_ultra_extreme_breach_floor(self):
        _, breakdown, _ = calculate_password_risk_score(
            make_analysis(), 0, "None", 0, hibp_breach_count=1_000_000)
        assert breakdown["base_score"] >= 8.0

    def test_extreme_breach_floor(self):
        _, breakdown, _ = calculate_password_risk_score(
            make_analysis(), 0, "None", 0, hibp_breach_count=100_000)
        assert breakdown["base_score"] >= 7.5

    def test_common_password_floor(self):
        _, breakdown, _ = calculate_password_risk_score(
            make_analysis(is_common=True), 0, "None", 0)
        assert breakdown["base_score"] >= 7.0

    def test_dictionary_word_floor(self):
        _, breakdown, _ = calculate_password_risk_score(
            make_analysis(is_exactly_dictionary_word=True), 0, "None", 0)
        assert breakdown["base_score"] >= 6.0

    def test_strong_cracked_password_still_has_minimum_risk(self):
        # Long, complex, not in HIBP -- but it WAS cracked, so floor is 2.0.
        _, breakdown, _ = calculate_password_risk_score(
            make_analysis(), 0, "None", 0, hibp_breach_count=0)
        assert breakdown["base_score"] >= 2.0


class TestRiskScoreIntegration:
    def test_breakdown_structure(self):
        _, breakdown, _ = calculate_password_risk_score(
            make_analysis(), 0, "None", 0)
        assert set(breakdown) == {
            "base_score", "base_components",
            "temporal_score", "temporal_components",
            "environmental_score", "environmental_components",
        }

    def test_da_domains_list_sets_da_path(self):
        _, _, has_da_path = calculate_password_risk_score(
            make_analysis(), 0, ["CORP.INT"], 0)
        assert bool(has_da_path) is True

    @pytest.mark.parametrize("da_domains", ["None", "Unknown", []])
    def test_no_da_path_values(self, da_domains):
        _, _, has_da_path = calculate_password_risk_score(
            make_analysis(), 0, da_domains, 0)
        assert bool(has_da_path) is False

    def test_final_score_in_range(self):
        final, _, _ = calculate_password_risk_score(
            make_analysis(is_common=True), shared_with=1000,
            da_domains=["CORP.INT"], controlled_object_count=2000,
            domain_risk_level="Critical", hibp_breach_count=100000)
        assert 0.0 <= final <= 10.0
