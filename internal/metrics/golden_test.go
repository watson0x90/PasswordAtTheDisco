// internal/metrics/golden_test.go
package metrics

import (
	"encoding/json"
	"flag"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
)

var update = flag.Bool("update", false, "regenerate golden files")

func TestMetricsGolden(t *testing.T) {
	raw, err := os.ReadFile("testdata/accounts.json")
	if err != nil {
		t.Fatalf("read accounts fixture: %v", err)
	}
	var accts []model.Account
	if err := json.Unmarshal(raw, &accts); err != nil {
		t.Fatalf("unmarshal accounts: %v", err)
	}
	now := time.Date(2026, 6, 30, 0, 0, 0, 0, time.UTC)
	got, err := json.MarshalIndent(Compute(accts, now), "", "  ")
	if err != nil {
		t.Fatalf("marshal metrics: %v", err)
	}
	got = append(got, '\n')
	const goldenPath = "testdata/metrics_golden.json"
	if *update {
		if err := os.WriteFile(goldenPath, got, 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		return
	}
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden (run with -update first): %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("metrics bundle changed vs golden.\nRe-run: go test ./internal/metrics/ -run TestMetricsGolden -update\nthen review the diff before committing.")
	}
}

func TestBundleHasNoSensitiveFields(t *testing.T) {
	now := time.Date(2026, 6, 30, 0, 0, 0, 0, time.UTC)
	// Feed accounts that DO carry secrets — the bundle must strip every one.
	// Fixture is deliberately cross-domain (alice in A, bob in B) + HIBP-breached
	// so the canary exercises the AccountRef and ReportAccount projections AND the
	// new per-domain DomainReports (reuse_clusters, da_paths, exposure_headline).
	// alice+bob share the same NTHash → they form a cross-domain reuse group that
	// appears in BOTH domains' reports.reuse_clusters.cracked. Members are
	// ReportAccount (no password/NTHash) so the check must pass.
	secret := "SuperSecretCleartextPassword!"
	ntHash := "ABCDEF0123456789ABCDEF0123456789"
	accts := []model.Account{
		{Username: "alice", Domain: "A", Cracked: true, RiskLevel: "Critical", DADomains: "A",
			Password: secret, NTHash: ntHash, BannedWords: []string{"forbiddenword"},
			KeyboardPatterns: []string{"qwerty"}, HIBPBreached: true, HIBPBreachCount: 5},
		{Username: "bob", Domain: "B", Cracked: true, RiskLevel: "High",
			Password: secret, NTHash: ntHash},
	}
	raw, err := json.Marshal(Compute(accts, now))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	low := strings.ToLower(string(raw))
	for _, bad := range []string{strings.ToLower(secret), strings.ToLower(ntHash), "forbiddenword", "qwerty", "\"password\"", "\"nt_hash\"", "banned_words", "keyboard_patterns"} {
		if strings.Contains(low, bad) {
			t.Errorf("bundle leaked sensitive content %q", bad)
		}
	}
}
