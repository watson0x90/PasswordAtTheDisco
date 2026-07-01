// internal/metrics/domain_test.go
package metrics

import (
	"testing"
	"time"

	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
)

// TestComputeByDomainReports verifies per-domain report-derived surfaces in DomainReports:
//   - Cross-domain reuse group appears in BOTH member domains (not just one)
//   - DA paths are scoped to each domain
//   - Exposure headline counts match the domain's accounts
//   - Semantics match what domainReuseClusters / domainDAPaths / exposureHeadline on
//     the client would produce for the same fixture
func TestComputeByDomainReports(t *testing.T) {
	now := time.Date(2026, 6, 30, 0, 0, 0, 0, time.UTC)
	// alice (A): cracked DA account, HIBP-breached
	// bob (B): cracked, shares alice's hash → cross-domain reuse group
	// carol (B): uncracked, no reuse → not in any group
	const sharedHash = "AABBCC1122334455AABBCC1122334455"
	accts := []model.Account{
		{Username: "alice", Domain: "A", NTHash: sharedHash, Cracked: true,
			RiskLevel: "High", DADomains: "A", Enabled: true,
			HIBPBreached: true, HIBPBreachCount: 5},
		{Username: "bob", Domain: "B", NTHash: sharedHash, Cracked: true,
			RiskLevel: "High", Enabled: true},
		{Username: "carol", Domain: "B", Cracked: false, RiskLevel: "Low", Enabled: true},
	}

	doms := ComputeByDomain(accts, now)
	if len(doms) != 2 {
		t.Fatalf("domains = %d, want 2", len(doms))
	}
	a, b := doms[0], doms[1] // alphabetical: A < B
	if a.Domain != "A" || b.Domain != "B" {
		t.Fatalf("order %q,%q want A,B", a.Domain, b.Domain)
	}

	// --- ReuseClusters: cross-domain group must appear in BOTH domains ---
	if len(a.Reports.ReuseClusters.Cracked) != 1 {
		t.Errorf("A cracked reuse clusters = %d, want 1", len(a.Reports.ReuseClusters.Cracked))
	}
	if len(b.Reports.ReuseClusters.Cracked) != 1 {
		t.Errorf("B cracked reuse clusters = %d, want 1", len(b.Reports.ReuseClusters.Cracked))
	}
	if len(a.Reports.ReuseClusters.Uncracked) != 0 {
		t.Errorf("A uncracked reuse clusters = %d, want 0", len(a.Reports.ReuseClusters.Uncracked))
	}
	if len(b.Reports.ReuseClusters.Uncracked) != 0 {
		t.Errorf("B uncracked reuse clusters = %d, want 0", len(b.Reports.ReuseClusters.Uncracked))
	}
	// The same group appears in both: size=2, spans A and B
	if len(a.Reports.ReuseClusters.Cracked) == 1 {
		g := a.Reports.ReuseClusters.Cracked[0]
		if g.Size != 2 {
			t.Errorf("A reuse cluster size = %d, want 2", g.Size)
		}
		if !g.Cracked {
			t.Error("A reuse cluster: want Cracked=true")
		}
	}

	// --- DAPaths: alice (domain A, cracked, HasDAPathway) → A has 1; B has 0 ---
	if len(a.Reports.DAPaths) != 1 {
		t.Errorf("A da_paths = %d, want 1", len(a.Reports.DAPaths))
	} else if a.Reports.DAPaths[0].Username != "alice" {
		t.Errorf("A da_paths[0].username = %q, want alice", a.Reports.DAPaths[0].Username)
	}
	if len(b.Reports.DAPaths) != 0 {
		t.Errorf("B da_paths = %d, want 0", len(b.Reports.DAPaths))
	}

	// --- ExposureHeadline for domain A ---
	// crackedDA=1 (alice: cracked && DADomains="A")
	// crackedHIBP=1 (alice: cracked && HIBPBreached)
	// crossDomainGroups=1 (the alice+bob group spans A and B)
	// domainsSpanned=2 ({A,B})
	ah := a.Reports.ExposureHeadline
	if ah.CrackedDA != 1 {
		t.Errorf("A crackedDA = %d, want 1", ah.CrackedDA)
	}
	if ah.CrackedHIBP != 1 {
		t.Errorf("A crackedHIBP = %d, want 1", ah.CrackedHIBP)
	}
	if ah.CrossDomainGroups != 1 {
		t.Errorf("A crossDomainGroups = %d, want 1", ah.CrossDomainGroups)
	}
	if ah.DomainsSpanned != 2 {
		t.Errorf("A domainsSpanned = %d, want 2", ah.DomainsSpanned)
	}

	// --- ExposureHeadline for domain B ---
	// crackedDA=0 (bob: cracked but no DADomains)
	// crackedHIBP=0 (bob: cracked but not HIBPBreached; carol: not cracked)
	// crossDomainGroups=1 (same cross-domain group touches B)
	// domainsSpanned=2
	bh := b.Reports.ExposureHeadline
	if bh.CrackedDA != 0 {
		t.Errorf("B crackedDA = %d, want 0", bh.CrackedDA)
	}
	if bh.CrackedHIBP != 0 {
		t.Errorf("B crackedHIBP = %d, want 0", bh.CrackedHIBP)
	}
	if bh.CrossDomainGroups != 1 {
		t.Errorf("B crossDomainGroups = %d, want 1", bh.CrossDomainGroups)
	}
	if bh.DomainsSpanned != 2 {
		t.Errorf("B domainsSpanned = %d, want 2", bh.DomainsSpanned)
	}
}

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
