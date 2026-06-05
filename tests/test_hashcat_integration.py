"""
Tests for hashcat integration (core/hashcat_integration.py).

Covers JSON status parsing, the runner's binary-existence guard, and the
command builder -- without invoking hashcat. Command assertions check for the
presence of key tokens so they stay robust to config-driven flags
(workload profile, optimized kernel, JSON status).
"""

import pytest

from core.hashcat_integration import HashcatRunner, HashcatStatus


@pytest.fixture
def runner(tmp_path):
    """A runner backed by a fake (but existing) hashcat binary."""
    fake_binary = tmp_path / "hashcat"
    fake_binary.write_text("#!/bin/sh\n")
    return HashcatRunner(hashcat_binary=fake_binary)


class TestHashcatStatusFromJson:
    def test_parses_fields(self):
        status = HashcatStatus.from_json({
            "session": "patd_1",
            "progress": 500,
            "progress_percent": 42.5,
            "recovered": 7,
            "guess": {"guess_base": "rockyou.txt"},
            "devices": [{"device_id": 1}],
        })
        assert status.session == "patd_1"
        assert status.progress == 500
        assert status.progress_percent == 42.5
        assert status.recovered == 7
        assert status.guess_base == "rockyou.txt"
        assert status.device_status == [{"device_id": 1}]

    def test_defaults_for_missing_fields(self):
        status = HashcatStatus.from_json({})
        assert status.session == "unknown"
        assert status.progress == 0
        assert status.guess_base == ""
        assert status.device_status == []


class TestRunnerInit:
    def test_missing_binary_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            HashcatRunner(hashcat_binary=tmp_path / "no_such_hashcat")


class TestBuildCommand:
    def test_defaults_to_ntlm_dictionary(self, runner, tmp_path):
        hash_file = tmp_path / "hashes.txt"
        cmd = runner.build_command(hash_file, {"wordlist": tmp_path / "wl.txt"})
        # NTLM mode (-m 1000), dictionary attack (-a 0), hash file and wordlist present.
        assert "-m" in cmd and "1000" in cmd
        assert "-a" in cmd and "0" in cmd
        assert str(hash_file) in cmd
        assert str(tmp_path / "wl.txt") in cmd

    def test_binary_is_first_token(self, runner, tmp_path):
        cmd = runner.build_command(tmp_path / "h.txt", {})
        assert cmd[0] == str(runner.hashcat_binary)

    def test_username_flag_added_by_default(self, runner, tmp_path):
        cmd = runner.build_command(tmp_path / "h.txt", {"username": True})
        assert "--username" in cmd

    def test_show_mode_adds_show_flag(self, runner, tmp_path):
        cmd = runner.build_command(tmp_path / "h.txt", {"show_mode": True})
        assert "--show" in cmd

    def test_left_mode_adds_left_flag(self, runner, tmp_path):
        cmd = runner.build_command(tmp_path / "h.txt", {"left_mode": True})
        assert "--left" in cmd

    def test_rules_expand_to_dash_r(self, runner, tmp_path):
        rule = tmp_path / "best64.rule"
        cmd = runner.build_command(tmp_path / "h.txt", {"rules": [rule]})
        assert "-r" in cmd
        assert str(rule) in cmd

    def test_custom_hash_mode(self, runner, tmp_path):
        cmd = runner.build_command(tmp_path / "h.txt", {"hash_mode": 1800})
        assert "1800" in cmd

    def test_mask_used_when_no_wordlist(self, runner, tmp_path):
        cmd = runner.build_command(tmp_path / "h.txt", {"mask": "?a?a?a?a"})
        assert "?a?a?a?a" in cmd
