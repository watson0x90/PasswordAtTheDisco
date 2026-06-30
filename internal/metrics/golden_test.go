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
	raw, err := os.ReadFile("testdata/accounts.json")
	if err != nil {
		t.Fatalf("read accounts fixture: %v", err)
	}
	var accts []model.Account
	if err := json.Unmarshal(raw, &accts); err != nil {
		t.Fatalf("unmarshal accounts: %v", err)
	}
	now := time.Date(2026, 6, 30, 0, 0, 0, 0, time.UTC)
	jsonBytes, err := json.Marshal(Compute(accts, now))
	if err != nil {
		t.Fatalf("marshal metrics: %v", err)
	}
	jsonLower := strings.ToLower(string(jsonBytes))

	forbiddenSubstrings := []string{`"password"`, `"nt_hash"`, `"banned"`, `"keyboard"`}
	for _, sub := range forbiddenSubstrings {
		if strings.Contains(jsonLower, sub) {
			t.Errorf("forbidden substring found in metrics bundle JSON: %s", sub)
		}
	}
}
