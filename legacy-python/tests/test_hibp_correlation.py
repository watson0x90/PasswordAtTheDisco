"""
Tests for HIBP correlation (core/hibp_correlation.py).

Covers the pure helpers (NTLM hashing, risk categorisation, factor tiers),
report aggregation, and small end-to-end fixtures for the cache lookup and the
prefix indexer -- all without the real 43GB HIBP database.
"""

import pytest

from core.hibp_correlation import (
    HIBPChecker,
    HIBPPrefixSearcher,
    calculate_hibp_factor,
    categorize_hibp_risk,
    plaintext_to_ntlm,
)

# Well-known NTLM test vectors.
NTLM_EMPTY = "31D6CFE0D16AE931B73C59D7E0C089C0"
NTLM_PASSWORD = "8846F7EAEE8FB117AD06BDD830B7586C"


def _write_hibp_file(tmp_path, rows, newline="\n"):
    """Write a HIBP 'HASH:COUNT' fixture with the given line ending."""
    path = tmp_path / "hibp.txt"
    body = "".join(f"{h}:{c}{newline}" for h, c in rows)
    path.write_bytes(body.encode("utf-8"))
    return path


class TestPlaintextToNtlm:
    def test_empty_password(self):
        assert plaintext_to_ntlm("") == NTLM_EMPTY

    def test_known_vector(self):
        assert plaintext_to_ntlm("password") == NTLM_PASSWORD

    def test_output_is_uppercase_hex_32(self):
        h = plaintext_to_ntlm("Whatever123!")
        assert len(h) == 32
        assert h == h.upper()


class TestCategorizeHibpRisk:
    @pytest.mark.parametrize("count,expected", [
        (0, "None"),
        (5, "Low"),
        (50, "Medium"),
        (500, "High"),
        (5000, "Very High"),
        (50000, "Extreme"),
    ])
    def test_tiers(self, count, expected):
        assert categorize_hibp_risk(count) == expected


class TestCalculateHibpFactor:
    @pytest.mark.parametrize("count,expected", [
        (0, 1.0),
        (50, 1.1),
        (500, 1.2),
        (5000, 1.3),
        (50000, 1.4),
        (500000, 1.5),
    ])
    def test_tiers(self, count, expected):
        assert calculate_hibp_factor(count) == expected


class TestDisabledChecker:
    def test_missing_file_disables_checker(self, tmp_path):
        checker = HIBPChecker(hibp_file=tmp_path / "does_not_exist.txt")
        assert checker.enabled is False
        assert checker.check_ntlm_hash(NTLM_PASSWORD) == (False, 0)

    def test_disabled_batch_returns_accounts_unchanged(self, tmp_path):
        checker = HIBPChecker(hibp_file=tmp_path / "nope.txt")
        accounts = [{"hash": NTLM_PASSWORD}]
        assert checker.check_password_batch(accounts) is accounts


class TestCacheLookup:
    def test_cached_hash_is_found(self, tmp_path):
        path = _write_hibp_file(tmp_path, [(NTLM_EMPTY, 5), (NTLM_PASSWORD, 1000)])
        checker = HIBPChecker(hibp_file=path, enable_index=False)
        assert checker.enabled is True
        assert checker.check_ntlm_hash(NTLM_PASSWORD) == (True, 1000)
        assert checker.check_ntlm_hash(NTLM_EMPTY) == (True, 5)

    def test_case_insensitive_lookup(self, tmp_path):
        path = _write_hibp_file(tmp_path, [(NTLM_PASSWORD, 1000)])
        checker = HIBPChecker(hibp_file=path, enable_index=False)
        assert checker.check_ntlm_hash(NTLM_PASSWORD.lower()) == (True, 1000)

    def test_absent_hash_without_index(self, tmp_path):
        path = _write_hibp_file(tmp_path, [(NTLM_PASSWORD, 1000)])
        checker = HIBPChecker(hibp_file=path, enable_index=False)
        assert checker.check_ntlm_hash(NTLM_EMPTY) == (False, 0)

    def test_statistics_track_hits_and_misses(self, tmp_path):
        path = _write_hibp_file(tmp_path, [(NTLM_PASSWORD, 1000)])
        checker = HIBPChecker(hibp_file=path, enable_index=False)
        checker.check_ntlm_hash(NTLM_PASSWORD)   # hit
        checker.check_ntlm_hash(NTLM_EMPTY)       # miss
        stats = checker.get_statistics()
        assert stats["cache_hits"] == 1
        assert stats["cache_misses"] == 1
        assert stats["cache_hit_rate"] == 0.5


class TestBreachReport:
    def test_report_aggregates_breached_accounts(self, tmp_path):
        checker = HIBPChecker(hibp_file=tmp_path / "nope.txt")  # disabled is fine
        accounts = [
            {"username": "a", "hibp_breached": True, "hibp_count": 15000},
            {"username": "b", "hibp_breached": True, "hibp_count": 50},
            {"username": "c", "hibp_breached": False, "hibp_count": 0},
        ]
        report = checker.generate_breach_report(accounts)
        assert report["total_accounts"] == 3
        assert report["breached_accounts"] == 2
        assert report["breach_rate"] == pytest.approx(2 / 3)
        assert report["total_breach_exposure"] == 15050
        assert report["breach_count_distribution"]["10,000+"] == 1
        assert report["breach_count_distribution"]["10-99"] == 1
        # Highest-count account sorts first in top_breached.
        assert report["top_breached"][0]["username"] == "a"


class TestPrefixSearcher:
    def test_build_and_load_index(self, tmp_path):
        path = _write_hibp_file(tmp_path, [(NTLM_EMPTY, 5), (NTLM_PASSWORD, 1000)])
        searcher = HIBPPrefixSearcher(path, prefix_length=5)
        searcher.build_index()
        index = searcher.load_index()
        assert index[NTLM_EMPTY[:5]] == 0                       # first line, offset 0
        assert index[NTLM_PASSWORD[:5]] == len(f"{NTLM_EMPTY}:5\n")

    def test_lookup_found_via_seek(self, tmp_path):
        path = _write_hibp_file(tmp_path, [(NTLM_EMPTY, 5), (NTLM_PASSWORD, 1000)])
        searcher = HIBPPrefixSearcher(path, prefix_length=5)
        searcher.build_index()
        searcher.load_index()
        assert searcher.lookup_hash(NTLM_PASSWORD) == (True, 1000)
        assert searcher.lookup_hash(NTLM_EMPTY) == (True, 5)

    @pytest.mark.parametrize("newline", ["\n", "\r\n"])
    def test_lookup_works_with_either_line_ending(self, tmp_path, newline):
        path = _write_hibp_file(
            tmp_path, [(NTLM_EMPTY, 5), (NTLM_PASSWORD, 1000)], newline=newline)
        searcher = HIBPPrefixSearcher(path, prefix_length=5)
        searcher.build_index()
        searcher.load_index()
        assert searcher.lookup_hash(NTLM_PASSWORD) == (True, 1000)
        assert searcher.lookup_hash(NTLM_EMPTY) == (True, 5)

    @pytest.mark.parametrize("newline", ["\n", "\r\n"])
    def test_index_offsets_are_byte_accurate(self, tmp_path, newline):
        # The recorded prefix offset must equal the TRUE byte position of that
        # prefix's first line. With CRLF this drifts under text-mode counting
        # and accumulates over a 1.3B-line file until every seek misses (HIBP
        # silently returns 0). The offset must be byte-exact for any ending.
        path = _write_hibp_file(
            tmp_path, [(NTLM_EMPTY, 5), (NTLM_PASSWORD, 1000)], newline=newline)
        searcher = HIBPPrefixSearcher(path, prefix_length=5)
        searcher.build_index()
        idx = searcher.load_index()
        expected = len(f"{NTLM_EMPTY}:5{newline}".encode("utf-8"))  # true start of line 2
        assert idx[NTLM_PASSWORD[:5]] == expected

    def test_lookup_invalid_length_returns_not_found(self, tmp_path):
        path = _write_hibp_file(tmp_path, [(NTLM_PASSWORD, 1000)])
        searcher = HIBPPrefixSearcher(path, prefix_length=5)
        searcher.build_index()
        searcher.load_index()
        assert searcher.lookup_hash("TOOSHORT") == (False, 0)

    def test_lookup_unknown_prefix_returns_not_found(self, tmp_path):
        path = _write_hibp_file(tmp_path, [(NTLM_PASSWORD, 1000)])
        searcher = HIBPPrefixSearcher(path, prefix_length=5)
        searcher.build_index()
        searcher.load_index()
        # A valid 32-hex hash whose prefix is not in the index.
        assert searcher.lookup_hash("00000000000000000000000000000000") == (False, 0)
