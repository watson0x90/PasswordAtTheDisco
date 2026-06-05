"""
Tests for BloodHound integration (core/bloodhound_integration.py).

Covers the pure data-extraction helpers, credential/client construction, and
URL formatting -- none of which touch the network.
"""

from unittest.mock import MagicMock

import core.bloodhound_integration as bhi
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


class TestRequestTimeout:
    """Requests must carry a timeout so an unreachable host can't hang the audit."""

    def test_client_has_default_timeout_tuple(self):
        c = _client()
        assert isinstance(c._timeout, tuple) and len(c._timeout) == 2

    def test_explicit_timeout_override(self):
        c = Client("https", "h", 443, Credentials("id", "key"), timeout=(1, 2))
        assert c._timeout == (1, 2)

    def test_request_passes_timeout_to_requests(self, monkeypatch):
        captured = {}

        def fake_request(**kwargs):
            captured.update(kwargs)
            return MagicMock(status_code=200)

        monkeypatch.setattr(bhi.requests, "request", fake_request)
        c = Client("https", "h", 443, Credentials("id", "key"), timeout=(3, 7))
        c._request("GET", "/api/version")
        assert captured.get("timeout") == (3, 7)


class TestGetBloodhoundClientStatus:
    """get_bloodhound_client must report failure honestly, not always 'connected'."""

    def test_returns_none_when_version_is_none(self, monkeypatch):
        # get_version returns None on a failed connection (it swallows its own
        # exception); the client must then be treated as unavailable.
        monkeypatch.setattr(bhi.Client, "get_version", lambda self, logger=None: None)
        assert bhi.get_bloodhound_client() is None

    def test_returns_client_when_version_present(self, monkeypatch):
        fake_version = type("V", (), {"server_version": "5.0", "api_version": "2"})()
        monkeypatch.setattr(bhi.Client, "get_version", lambda self, logger=None: fake_version)
        assert bhi.get_bloodhound_client() is not None


class TestShortestPathAttackOnly:
    """DA-path detection must scope to traversable (attack) edges, not all edges."""

    @staticmethod
    def _resp(status):
        m = MagicMock()
        m.status_code = status
        m.json.return_value = {"data": {}}
        return m

    def test_only_traversable_sent_by_default(self, monkeypatch):
        c = _client()
        captured = {}

        def fake(method, uri, **kw):
            captured["uri"] = uri
            return self._resp(200)

        monkeypatch.setattr(c, "_request", fake)
        c.get_shortest_path("S-1-start", "S-1-end")
        assert "only_traversable=true" in captured["uri"]

    def test_only_traversable_omitted_when_disabled(self, monkeypatch):
        c = _client()
        captured = {}

        def fake(method, uri, **kw):
            captured["uri"] = uri
            return self._resp(200)

        monkeypatch.setattr(c, "_request", fake)
        c.get_shortest_path("S-1-start", "S-1-end", only_traversable=False)
        assert "only_traversable" not in captured["uri"]

    def test_path_presence_status_mapping(self, monkeypatch):
        c = _client()
        monkeypatch.setattr(c, "_request", lambda *a, **k: self._resp(200))
        assert c.get_shortest_path("a", "b")["has_path"] is True
        monkeypatch.setattr(c, "_request", lambda *a, **k: self._resp(404))
        assert c.get_shortest_path("a", "b")["has_path"] is False
