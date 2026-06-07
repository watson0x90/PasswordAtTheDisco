"""
Characterization tests for password analysis (core/password_analysis.py).

Covers the character-class predicates, the 16-way complexity classifier,
policy checking, and the wordlist/pattern matchers.
"""

import pytest

from core.password_analysis import (
    analyze_password,
    check_forbidden_words,
    check_keyboard_patterns,
    check_password_complexity,
    check_policy,
    has_digit,
    has_lower,
    has_special,
    has_unicode,
    has_upper,
    is_common_password,
    is_dictionary_word,
)


class TestCharacterPredicates:
    @pytest.mark.parametrize("fn,pw,expected", [
        (has_lower, "abc", True), (has_lower, "ABC123!", False),
        (has_upper, "ABC", True), (has_upper, "abc123!", False),
        (has_digit, "123", True), (has_digit, "abcABC!", False),
        (has_special, "!@#", True), (has_special, "abcABC123", False),
        (has_unicode, "café", True), (has_unicode, "cafe", False),
    ])
    def test_predicates(self, fn, pw, expected):
        assert fn(pw) is expected


class TestComplexityClassifier:
    @pytest.mark.parametrize("pw,expected", [
        ("abc", "loweralpha"),
        ("ABC", "upperalpha"),
        ("123", "numeric"),
        ("!!!", "special"),
        ("abc123", "loweralphanum"),
        ("ABC123", "upperalphanum"),
        ("abcABC", "mixedalpha"),
        ("abc!!!", "loweralphaspecial"),
        ("ABC!!!", "upperalphaspecial"),
        ("123!!!", "specialnum"),
        ("abcABC123", "mixedalphanum"),
        ("abc123!!!", "loweralphaspecialnum"),
        ("abcABC!!!", "mixedalphaspecial"),
        ("ABC123!!!", "upperalphaspecialnum"),
        ("abcABC123!!!", "mixedalphaspecialnum"),
        ("", "none"),
    ])
    def test_all_categories(self, pw, expected):
        assert check_password_complexity(pw) == expected


class TestPolicy:
    POLICY = {
        "min_length": 14,
        "require_lowercase": True,
        "require_uppercase": True,
        "require_digits": True,
        "require_special": True,
    }

    def test_compliant_password(self):
        meets, violations = check_policy("Abcdefghij123!", custom_policy=self.POLICY)
        assert meets is True
        assert violations == []

    def test_too_short_reports_length_violation(self):
        meets, violations = check_policy("Ab1!", custom_policy=self.POLICY)
        assert meets is False
        assert any("Length" in v for v in violations)

    def test_missing_classes_each_reported(self):
        meets, violations = check_policy("abcdefghijklmn", custom_policy=self.POLICY)
        assert meets is False
        assert "No uppercase" in violations
        assert "No digits" in violations
        assert "No special character" in violations


class TestWordlistMatchers:
    def test_forbidden_words_substring_case_insensitive(self):
        found = check_forbidden_words("MyAcmeCorp2024", {"acme", "corp"})
        assert set(found) == {"acme", "corp"}

    def test_forbidden_words_none_found(self):
        assert check_forbidden_words("xyz123", {"acme"}) == []

    def test_keyboard_patterns_substring(self):
        found = check_keyboard_patterns("qwerty123", {"qwerty", "asdf"})
        assert found == ["qwerty"]

    def test_is_common_password_case_insensitive(self):
        assert is_common_password("Password", {"password"}) is True
        assert is_common_password("unique-xyz", {"password"}) is False

    def test_is_dictionary_word_exact_match(self):
        assert is_dictionary_word("Hello", {"hello"}) is True
        assert is_dictionary_word("hello123", {"hello"}) is False


class TestAnalyzePassword:
    def test_empty_password_returns_none(self):
        assert analyze_password("", set(), set(), set(), set()) is None

    def test_full_analysis_shape(self):
        result = analyze_password(
            "Acme123!", forbidden_words={"acme"}, keyboard_patterns=set(),
            common_passwords=set(), dictionary_words=set(),
            policy={"min_length": 8, "require_lowercase": True,
                    "require_uppercase": True, "require_digits": True,
                    "require_special": True},
        )
        assert result["password_length"] == 8
        assert result["complexity_label"] == "mixedalphaspecialnum"
        assert result["banned_words"] == ["acme"]
        assert result["meets_policy"] is True
