"""
Characterization tests for file parsing (core/data.py) and hex decoding
(utils/file_utils.decode_hex).

process_domain parses two on-disk formats; these tests write small fixture
files with tmp_path and assert the parsed structures, including known edge
cases (colon-in-password truncation, $HEX[] decoding).
"""

from core.data import map_accounts_to_models, process_domain
from utils.file_utils import decode_hex

# ---------------------------------------------------------------------------
# decode_hex
# ---------------------------------------------------------------------------

class TestDecodeHex:
    def test_plain_password_unchanged(self):
        assert decode_hex("Sup3rSecret!") == "Sup3rSecret!"

    def test_hex_block_decoded(self):
        # $HEX[48656c6c6f] -> "Hello"
        assert decode_hex("$HEX[48656c6c6f]") == "Hello"

    def test_password_without_hex_marker_passthrough(self):
        assert decode_hex("contains$dollar") == "contains$dollar"


# ---------------------------------------------------------------------------
# process_domain
# ---------------------------------------------------------------------------

def _write(tmp_path, name, lines):
    path = tmp_path / name
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(path)


class TestProcessDomainSecretsDump:
    # The cracked parser keys off field roles (username=0, NTLM=3, password =
    # everything after the trailing empty placeholder fields), so it accepts
    # both the README's 7-field form (`nt:::password`) and the 8-field form
    # (`nt::::password`), and preserves passwords containing colons.
    def test_parses_secretsdump_cracked_line_7_fields(self, tmp_path):
        # README-documented format: username:rid:lm:nt:::password
        cracked = _write(tmp_path, "cracked.txt", [
            "alice:1001:aad3b435b51404eeaad3b435b51404ee:ntlmhashvalue:::Summer2024!",
        ])
        uncracked = _write(tmp_path, "uncracked.txt", [])
        cracked_accounts, _ = process_domain("CORP.INT", cracked, uncracked)
        assert len(cracked_accounts) == 1
        acc = cracked_accounts[0]
        assert acc["username"] == "alice"
        assert acc["hash"] == "ntlmhashvalue"   # NTLM hash is field index 3
        assert acc["password"] == "Summer2024!"
        assert acc["domain"] == "CORP.INT"

    def test_parses_secretsdump_cracked_line_8_fields(self, tmp_path):
        cracked = _write(tmp_path, "cracked.txt", [
            "alice:1001:aad3b435b51404eeaad3b435b51404ee:ntlmhashvalue::::Summer2024!",
        ])
        uncracked = _write(tmp_path, "uncracked.txt", [])
        cracked_accounts, _ = process_domain("CORP.INT", cracked, uncracked)
        assert cracked_accounts[0]["password"] == "Summer2024!"

    def test_empty_password_field_skipped(self, tmp_path):
        cracked = _write(tmp_path, "cracked.txt", [
            "bob:1002:aad3b435b51404eeaad3b435b51404ee:ntlm::::",
        ])
        uncracked = _write(tmp_path, "uncracked.txt", [])
        cracked_accounts, _ = process_domain("CORP.INT", cracked, uncracked)
        assert cracked_accounts == []

    def test_colon_in_password_is_preserved(self, tmp_path):
        # A password containing colons must survive intact (split on ':' and
        # taking only the last field would have truncated it to "word").
        cracked = _write(tmp_path, "cracked.txt", [
            "carol:1003:aad3b435b51404eeaad3b435b51404ee:ntlm::::pa:ss:word",
        ])
        uncracked = _write(tmp_path, "uncracked.txt", [])
        cracked_accounts, _ = process_domain("CORP.INT", cracked, uncracked)
        assert cracked_accounts[0]["password"] == "pa:ss:word"

    def test_parses_secretsdump_uncracked_line(self, tmp_path):
        cracked = _write(tmp_path, "cracked.txt", [])
        uncracked = _write(tmp_path, "uncracked.txt", [
            "dave:1004:aad3b435b51404eeaad3b435b51404ee:uncrackedntlm:::",
        ])
        _, uncracked_accounts = process_domain("CORP.INT", cracked, uncracked)
        assert len(uncracked_accounts) == 1
        assert uncracked_accounts[0]["username"] == "dave"
        assert uncracked_accounts[0]["hash"] == "uncrackedntlm"
        assert uncracked_accounts[0]["password"] is None


class TestProcessDomainSimpleFormat:
    def test_parses_simple_cracked_line(self, tmp_path):
        cracked = _write(tmp_path, "cracked.txt", ["eve:abc123hash:Winter2024!"])
        uncracked = _write(tmp_path, "uncracked.txt", [])
        cracked_accounts, _ = process_domain("CORP.INT", cracked, uncracked)
        assert cracked_accounts[0] == {
            "username": "eve", "hash": "abc123hash",
            "password": "Winter2024!", "domain": "CORP.INT",
        }

    def test_parses_simple_uncracked_line(self, tmp_path):
        cracked = _write(tmp_path, "cracked.txt", [])
        uncracked = _write(tmp_path, "uncracked.txt", ["frank:defhash"])
        _, uncracked_accounts = process_domain("CORP.INT", cracked, uncracked)
        assert uncracked_accounts[0]["username"] == "frank"
        assert uncracked_accounts[0]["hash"] == "defhash"

    def test_hex_encoded_password_decoded(self, tmp_path):
        cracked = _write(tmp_path, "cracked.txt", ["grace:hash:$HEX[48656c6c6f]"])
        uncracked = _write(tmp_path, "uncracked.txt", [])
        cracked_accounts, _ = process_domain("CORP.INT", cracked, uncracked)
        assert cracked_accounts[0]["password"] == "Hello"


# ---------------------------------------------------------------------------
# map_accounts_to_models
# ---------------------------------------------------------------------------

class TestMapAccountsToModels:
    def test_maps_cracked_and_uncracked(self):
        cracked = [{"username": "alice", "hash": "H1", "password": "Secret1!", "domain": "CORP.INT"}]
        uncracked = [{"username": "bob", "hash": "H2", "password": None, "domain": "CORP.INT"}]
        cracked_models, uncracked_models = map_accounts_to_models(cracked, uncracked)

        assert len(cracked_models) == 1 and len(uncracked_models) == 1
        assert cracked_models[0].username == "alice"
        assert cracked_models[0].password.is_cracked is True
        assert cracked_models[0].password.value == "Secret1!"
        assert uncracked_models[0].password.is_cracked is False
        assert uncracked_models[0].password.value is None
        assert uncracked_models[0].password.hash_value == "H2"
