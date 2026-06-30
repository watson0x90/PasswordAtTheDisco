// internal/metrics/domain_test.go
package metrics

import (
	"testing"
	"time"

	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
)

func TestComputeByDomainSplitsAndMatchesSummarize(t *testing.T) {
	now := time.Date(2026, 6, 30, 0, 0, 0, 0, time.UTC)
	accts := []model.Account{
		{Domain: "B.LOCAL", Enabled: true, Cracked: true, RiskLevel: "High"},
		{Domain: "A.LOCAL", Enabled: true, Cracked: false, RiskLevel: "Low"},
		{Domain: "A.LOCAL", Enabled: true, Cracked: true, RiskLevel: "Critical"},
	}
	doms := ComputeByDomain(accts, now)
	if len(doms) != 2 {
		t.Fatalf("domains = %d, want 2", len(doms))
	}
	// deterministic alphabetical order
	if doms[0].Domain != "A.LOCAL" || doms[1].Domain != "B.LOCAL" {
		t.Fatalf("order = %q,%q want A.LOCAL,B.LOCAL", doms[0].Domain, doms[1].Domain)
	}
	if doms[0].Summary.TotalAccounts != 2 || doms[1].Summary.TotalAccounts != 1 {
		t.Errorf("totals = %d,%d want 2,1", doms[0].Summary.TotalAccounts, doms[1].Summary.TotalAccounts)
	}
	// per-domain summary must equal Summarize over that subset (single source)
	want := model.Summarize([]model.Account{
		{Domain: "A.LOCAL", Enabled: true, Cracked: false, RiskLevel: "Low"},
		{Domain: "A.LOCAL", Enabled: true, Cracked: true, RiskLevel: "Critical"},
	}, now)
	if doms[0].Summary.Cracked != want.Cracked || doms[0].Summary.Posture.Score != want.Posture.Score {
		t.Errorf("A.LOCAL summary diverges from Summarize")
	}
}
