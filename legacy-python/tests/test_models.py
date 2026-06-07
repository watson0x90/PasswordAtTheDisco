"""
Characterization tests for the domain models (models/account.py, models/password.py).

These exercise pure, stdlib-only logic: BloodHound data parsing, compliance
calculation, and password analysis/serialization.
"""

from datetime import datetime, timedelta

from models.account import Account
from models.password import Password

# ---------------------------------------------------------------------------
# Password
# ---------------------------------------------------------------------------

class TestPasswordConstruction:
    def test_length_from_value(self):
        assert Password("abcdef").length == 6

    def test_none_value_has_zero_length(self):
        assert Password(None).length == 0

    def test_defaults(self):
        pw = Password("x")
        assert pw.is_cracked is False
        assert pw.complexity_label == "N/A"
        assert pw.shared_with_count == 0


class TestPasswordPredicates:
    def test_predicates_on_none_value_are_false(self):
        pw = Password(None)
        assert pw.has_lower() is False
        assert pw.has_upper() is False
        assert pw.has_digit() is False
        assert pw.has_special() is False

    def test_predicates_detect_classes(self):
        pw = Password("aB3!")
        assert pw.has_lower() and pw.has_upper() and pw.has_digit() and pw.has_special()


class TestPasswordToString:
    def test_returns_value_when_present(self):
        assert Password("hunter2", hash_value="HASH").to_string() == "hunter2"

    def test_falls_back_to_hash_when_no_value(self):
        # Uncracked passwords have no clear-text value; to_string yields the hash.
        assert Password(None, hash_value="ABC123").to_string() == "ABC123"


class TestPasswordToDict:
    def test_uncracked_returns_minimal_dict(self):
        result = Password(None, is_cracked=False, hash_value="DEAD").to_dict()
        assert result == {"hash": "DEAD", "is_cracked": False}

    def test_cracked_returns_full_dict(self):
        pw = Password("Acme123!", is_cracked=True, hash_value="HASH")
        pw.analyze(forbidden_words={"acme"}, keyboard_patterns=set(),
                   common_passwords=set(), dictionary_words=set())
        result = pw.to_dict()
        assert result["Password"] == "Acme123!"
        assert result["Password Length"] == 8
        assert result["Complexity Label"] == "mixedalphaspecialnum"
        assert result["Forbidden Words"] == "acme"


class TestPasswordAnalyze:
    def test_uncracked_password_is_not_analyzed(self):
        pw = Password("whatever", is_cracked=False)
        pw.analyze(set(), set(), set(), set())
        assert pw.complexity_label == "N/A"  # untouched

    def test_cracked_password_sets_flags(self):
        pw = Password("password", is_cracked=True)
        pw.analyze(forbidden_words=set(), keyboard_patterns=set(),
                   common_passwords={"password"}, dictionary_words={"password"})
        assert pw.is_common is True
        assert pw.is_dictionary_word is True
        assert pw.complexity_label == "loweralpha"


class TestPasswordSimilarity:
    def test_empty_comparison_list_is_noop(self):
        pw = Password("hunter2")
        pw.calculate_similarity([])
        assert pw.similar_passwords == []

    def test_dissimilar_password_excluded(self):
        # "hunter2" vs "ZZZZZZZ" is far below the 0.7 threshold; excluded in both
        # the Levenshtein and the exact-match fallback paths.
        pw = Password("hunter2")
        pw.calculate_similarity(["ZZZZZZZ"])
        assert pw.similar_passwords == []


# ---------------------------------------------------------------------------
# Account
# ---------------------------------------------------------------------------

class TestAccountConstruction:
    def test_defaults(self):
        acc = Account("alice", "CORP.INT")
        assert acc.username == "alice"
        assert acc.domain == "CORP.INT"
        assert acc.da_domains is None
        assert acc.has_da_pathway() is False


class TestSetBloodhoundData:
    def test_pwdneverexpires_maps_to_set_to_expire_no(self):
        acc = Account("alice", "CORP.INT")
        acc.set_bloodhound_data({"props": [{"pwdneverexpires": True}]})
        # "never expires" == True -> NOT set to expire.
        assert acc.password_set_to_expire == "No"

    def test_pwd_expires_maps_to_set_to_expire_yes(self):
        acc = Account("alice", "CORP.INT")
        acc.set_bloodhound_data({"props": [{"pwdneverexpires": False}]})
        assert acc.password_set_to_expire == "Yes"

    def test_da_domains_extracted_only_when_has_da_path_true(self):
        acc = Account("alice", "CORP.INT")
        acc.set_bloodhound_data({
            "props": [{}],
            "controllables": [
                {"domain": "CORP.INT", "labels": {"has_da_path": True}},
                {"domain": "DEV.INT", "labels": {"has_da_path": False}},
            ],
        })
        assert acc.da_domains == ["CORP.INT"]
        assert acc.has_da_pathway() is True

    def test_controlled_object_count_sums_numeric_labels(self):
        acc = Account("alice", "CORP.INT")
        acc.set_bloodhound_data({
            "props": [{}],
            "controllables": [
                {"domain": "CORP.INT",
                 "labels": {"has_da_path": True, "computers": "5", "users": "10"}},
                {"domain": "CORP.INT",
                 "labels": {"has_da_path": False, "groups": "2"}},
            ],
        })
        # has_da_path is excluded; 5 + 10 + 2 = 17.
        assert acc.controlled_object_count == 17

    def test_timestamp_parsing(self):
        acc = Account("alice", "CORP.INT")
        ts = datetime(2024, 1, 15, 12, 0, 0).timestamp()
        acc.set_bloodhound_data({"props": [{"pwdlastset": ts}]})
        assert acc.last_password_set == datetime.fromtimestamp(ts)


class TestComplianceCalculation:
    def test_no_password_set_returns_zero(self):
        acc = Account("alice", "CORP.INT")
        assert acc.calculate_days_out_of_compliance(90) == 0

    def test_recent_password_is_compliant(self):
        acc = Account("alice", "CORP.INT")
        acc.last_password_set = datetime.now()
        assert acc.calculate_days_out_of_compliance(90) == 0

    def test_old_password_is_out_of_compliance(self):
        acc = Account("alice", "CORP.INT")
        acc.last_password_set = datetime.now() - timedelta(days=200)
        days_out = acc.calculate_days_out_of_compliance(90)
        assert days_out > 0
        # ~200 days old, 90-day policy -> ~110 days out.
        assert days_out == acc.days_out_of_compliance


class TestAccountToDict:
    def test_to_dict_handles_unset_fields(self):
        acc = Account("alice", "CORP.INT", password=Password("Secret1!", is_cracked=True))
        result = acc.to_dict()
        assert result["Username"] == "alice"
        assert result["Domain"] == "CORP.INT"
        assert result["Last Password Set"] == "Unknown"
        assert result["DA Domains"] == "None"
