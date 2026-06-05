"""
Tests for BloodHound integration (core/bloodhound_integration.py).

Covers the pure data-extraction helpers, credential/client construction, and
URL formatting -- none of which touch the network.
"""

from core.bloodhound_integration import (
    Client,
    Credentials,
    extract_controllable_count,
    extract_da_domains,
    handle_bhe_data,
)


def _client():
    creds = Credentials(token_id="id", token_key="key")
    return Client(scheme="https", host="bh.example.com", port=443, credentials=creds)


class TestCredentials:
    def test_stores_token_pair(self):
        creds = Credentials(token_id="abc", token_key="xyz")
        assert creds.token_id == "abc"
        assert creds.token_key == "xyz"


class TestFormatUrl:
    def test_strips_leading_slash(self):
        assert _client()._format_url("/api/version") == "https://bh.example.com:443/api/version"

    def test_without_leading_slash(self):
        assert _client()._format_url("api/version") == "https://bh.example.com:443/api/version"


class TestHandleBheData:
    def test_list_form(self):
        data = [{"props": [{"enabled": True}]}]
        assert handle_bhe_data(data) == {"enabled": True}

    def test_dict_form(self):
        data = {"props": [{"enabled": False}]}
        assert handle_bhe_data(data) == {"enabled": False}

    def test_empty_inputs(self):
        assert handle_bhe_data([]) == {}
        assert handle_bhe_data({}) == {}


class TestExtractDaDomains:
    def test_extracts_domains_with_da_path(self):
        data = [{
            "controllables": [
                {"domain": "CORP.INT", "labels": {"has_da_path": True}},
                {"domain": "DEV.INT", "labels": {"has_da_path": False}},
            ]
        }]
        assert extract_da_domains(data) == ["CORP.INT"]

    def test_no_da_path_returns_none_string(self):
        data = [{"controllables": [{"domain": "DEV.INT", "labels": {"has_da_path": False}}]}]
        assert extract_da_domains(data) == "None"

    def test_empty_returns_none_string(self):
        assert extract_da_domains([]) == "None"
        assert extract_da_domains({}) == "None"


class TestExtractControllableCount:
    def test_sums_numeric_labels_excluding_da_path(self):
        data = [{
            "controllables": [
                {"domain": "CORP.INT", "labels": {"has_da_path": True, "computers": "5", "users": "10"}},
                {"domain": "CORP.INT", "labels": {"has_da_path": False, "groups": "2"}},
            ]
        }]
        assert extract_controllable_count(data) == 17

    def test_non_numeric_labels_ignored(self):
        data = {"controllables": [{"labels": {"has_da_path": True, "note": "abc"}}]}
        assert extract_controllable_count(data) == 0

    def test_empty_returns_zero(self):
        assert extract_controllable_count([]) == 0
        assert extract_controllable_count({}) == 0
