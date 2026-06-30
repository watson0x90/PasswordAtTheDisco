// internal/metrics/metrics_test.go
package metrics

import (
	"testing"
	"time"

	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
)

func TestComputeOrgSummary(t *testing.T) {
	now := time.Date(2026, 6, 30, 0, 0, 0, 0, time.UTC)
	accts := []model.Account{
		{Domain: "A", Enabled: true, Cracked: true, RiskLevel: "High"},
		{Domain: "B", Enabled: true, Cracked: false, RiskLevel: "Low"},
	}
	m := Compute(accts, now)
	if m.Summary.TotalAccounts != 2 {
		t.Fatalf("total = %d, want 2", m.Summary.TotalAccounts)
	}
	if m.Summary.Cracked != 1 {
		t.Errorf("cracked = %d, want 1", m.Summary.Cracked)
	}
	if !m.Summary.GeneratedAt.Equal(now) {
		t.Errorf("generated_at = %v, want %v", m.Summary.GeneratedAt, now)
	}
}
