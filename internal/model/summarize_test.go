// internal/model/summarize_test.go
package model

import (
	"testing"
	"time"
)

func bp(b bool) *bool { return &b }

func TestSummarizeCounts(t *testing.T) {
	gen := time.Date(2026, 6, 30, 0, 0, 0, 0, time.UTC)
	accts := []Account{
		{Domain: "A", Enabled: true, Cracked: true, MeetsPolicy: false, RiskLevel: "Critical", HIBPBreached: true},
		{Domain: "A", Enabled: true, Cracked: false, MeetsPolicy: true, RiskLevel: "Low"},
		{Domain: "B", Enabled: false, Cracked: true, MeetsPolicy: true, RiskLevel: "High",
			ControlsTier0: true}, // disabled + privileged + obtainable -> dormant_privileged
		{Domain: "B", Enabled: true, Cracked: false, RiskLevel: "Medium", PwdNeverExpires: bp(true),
			DaysOutOfCompliance: 10, Controlled: 200},
	}
	s := Summarize(accts, gen)
	if s.TotalAccounts != 4 {
		t.Fatalf("total = %d, want 4", s.TotalAccounts)
	}
	if s.Cracked != 2 {
		t.Errorf("cracked = %d, want 2", s.Cracked)
	}
	if s.HIBPBreached != 1 {
		t.Errorf("hibp = %d, want 1", s.HIBPBreached)
	}
	if s.DisabledAccounts != 1 {
		t.Errorf("disabled = %d, want 1", s.DisabledAccounts)
	}
	if s.NeverExpires != 1 {
		t.Errorf("never_expires = %d, want 1", s.NeverExpires)
	}
	if s.StalePasswords != 1 {
		t.Errorf("stale = %d, want 1", s.StalePasswords)
	}
	if s.PolicyViolations != 1 { // only the enabled cracked !meets_policy
		t.Errorf("violations = %d, want 1", s.PolicyViolations)
	}
	if s.HighControlled != 1 {
		t.Errorf("high_controlled = %d, want 1", s.HighControlled)
	}
	if s.DormantPrivileged != 1 {
		t.Errorf("dormant = %d, want 1", s.DormantPrivileged)
	}
	if s.RiskCounts["Critical"] != 1 || s.RiskCounts["Low"] != 1 {
		t.Errorf("risk_counts = %v", s.RiskCounts)
	}
	if !s.GeneratedAt.Equal(gen) {
		t.Errorf("generated_at = %v, want %v", s.GeneratedAt, gen)
	}
	if s.Posture.Rating == "" {
		t.Error("posture not populated")
	}
}
