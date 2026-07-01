package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
)

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("mustJSON: %v", err)
	}
	return string(b)
}

func TestBundleAccounts(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	accts := []model.Account{
		{Username: "alice", Domain: "CORP", Cracked: true, Password: "Hunter2", NTHash: "AAAA1111AAAA1111AAAA1111AAAA1111",
			BannedWords: []string{"zzbanzz"}, KeyboardPatterns: []string{"zzkbzz"},
			RiskLevel: "Critical", RiskScore: 8.1, DADomains: "CORP", PasswordLength: 7},
		{Username: "bob", Domain: "CORP", Cracked: false, RiskLevel: "Low"},
	}
	// sanitized: identities present, no password/hash/wordlist.
	san := bundleAccounts(accts, false, now)
	if len(san) != 2 || san[0].Username != "alice" || san[0].Domain != "CORP" {
		t.Fatalf("identities missing: %+v", san)
	}
	if san[0].Password != "" {
		t.Error("sanitized bundle must not carry a password")
	}
	if san[0].DADomains != "CORP" || !san[0].HasDAPath {
		t.Error("da_domains / has_da_path should be identified, not stripped")
	}
	// cleartext: password present for cracked, empty for uncracked; still no hash/wordlist.
	ct := bundleAccounts(accts, true, now)
	if ct[0].Password != "Hunter2" {
		t.Errorf("cleartext bundle: cracked account missing password, got %q", ct[0].Password)
	}
	if ct[1].Password != "" {
		t.Error("uncracked account must have empty password")
	}
	// The struct must have no NTHash/BannedWords/KeyboardPatterns fields at all —
	// assert via JSON that those never appear.
	raw := mustJSON(t, ct)
	for _, bad := range []string{"AAAA1111", "zzbanzz", "zzkbzz", "nt_hash"} {
		if strings.Contains(raw, bad) {
			t.Errorf("bundle account leaked %q", bad)
		}
	}
}
