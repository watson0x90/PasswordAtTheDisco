package metrics

import (
	"testing"

	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
)

func TestExposureHeadline(t *testing.T) {
	accts := []model.Account{
		{Cracked: true, DADomains: "A"},                        // crackedDA + (not hibp)
		{Cracked: true, HIBPBreached: true, DADomains: "None"}, // crackedHibp
		{Cracked: false, DADomains: "A"},                       // neither (uncracked)
	}
	rep := model.Report{
		CrackedReuse: []model.ReuseGroup{
			{Members: []model.ReportAccount{{Domain: "A"}, {Domain: "B"}}}, // cross-domain (2)
			{Members: []model.ReportAccount{{Domain: "A"}, {Domain: "A"}}}, // single-domain (skip)
		},
		UncrackedReuse: []model.ReuseGroup{
			{Members: []model.ReportAccount{{Domain: "B"}, {Domain: "C"}}}, // cross-domain (2)
		},
	}
	h := ExposureHeadlineOf(accts, rep)
	if h.CrackedDA != 1 {
		t.Errorf("crackedDA = %d, want 1", h.CrackedDA)
	}
	if h.CrackedHIBP != 1 {
		t.Errorf("crackedHibp = %d, want 1", h.CrackedHIBP)
	}
	if h.CrossDomainGroups != 2 {
		t.Errorf("crossDomainGroups = %d, want 2", h.CrossDomainGroups)
	}
	if h.DomainsSpanned != 3 { // A,B from first + B,C from third = {A,B,C}
		t.Errorf("domainsSpanned = %d, want 3", h.DomainsSpanned)
	}
}

func TestCrossDomainBridgesRanking(t *testing.T) {
	rep := model.Report{
		CrackedReuse: []model.ReuseGroup{
			{Size: 3, Cracked: true, HasDAPathway: false, Members: []model.ReportAccount{{Domain: "A"}, {Domain: "B"}}},
		},
		UncrackedReuse: []model.ReuseGroup{
			{Size: 2, Cracked: false, HasDAPathway: true, Members: []model.ReportAccount{{Domain: "B"}, {Domain: "C"}}},
			{Size: 9, Cracked: false, Members: []model.ReportAccount{{Domain: "A"}, {Domain: "A"}}}, // single-domain -> skip
		},
	}
	cd := CrossDomainBridges(rep)
	if len(cd.Clusters) != 2 {
		t.Fatalf("clusters = %d, want 2", len(cd.Clusters))
	}
	if !cd.Clusters[0].HasDA { // DA cluster ranks first
		t.Errorf("expected DA cluster first, got %+v", cd.Clusters[0])
	}
	if len(cd.Domains) != 3 { // A,B,C
		t.Errorf("domains = %v, want 3", cd.Domains)
	}
}

func TestHIBPTriageTiers(t *testing.T) {
	rep := model.Report{HIBPExposed: []model.ReportAccount{
		{Username: "a", Cracked: true, HIBPBreachCount: 10, RiskScore: 5},
		{Username: "b", Cracked: true, HIBPBreachCount: 99, RiskScore: 5},
		{Username: "c", Cracked: false, HIBPBreachCount: 3, RiskScore: 9},
	}}
	tr := HIBPTriageOf(rep)
	if len(tr.Tier1) != 2 || tr.Tier1[0].Username != "b" { // sorted by breach desc
		t.Fatalf("tier1 = %+v", tr.Tier1)
	}
	if len(tr.Tier2) != 1 || tr.Tier2[0].Username != "c" {
		t.Fatalf("tier2 = %+v", tr.Tier2)
	}
}

func TestBlastRadiusPriorityAndReasons(t *testing.T) {
	accts := []model.Account{
		{Username: "danger", DADomains: "A", HIBPBreached: true, HIBPBreachCount: 5, Cracked: true, SharedWith: 2, Enabled: true, RiskScore: 9}, // 3+2+1+1=7
		{Username: "mild", Cracked: true, Enabled: true, RiskScore: 3},                                                                          // 1
		{Username: "clean", Enabled: true, RiskScore: 2},                                                                                        // priority 0 -> excluded
	}
	rows := BlastRadius(accts)
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2", len(rows))
	}
	if rows[0].Account.Username != "danger" || rows[0].Priority != 7 {
		t.Fatalf("row0 = %+v", rows[0])
	}
	if len(rows[0].Reasons) != 4 { // DA, HIBP n, Cracked, Shared n
		t.Errorf("reasons = %v, want 4", rows[0].Reasons)
	}
	if rows[0].Reasons[1] != "HIBP 5" {
		t.Errorf("HIBP reason = %q, want \"HIBP 5\"", rows[0].Reasons[1])
	}
	if rows[1].Account.Username != "mild" || rows[1].Priority != 1 {
		t.Errorf("row1 = %+v", rows[1])
	}
}

func TestGroupThousands(t *testing.T) {
	tests := []struct {
		n    int
		want string
	}{
		{0, "0"},
		{999, "999"},
		{1200, "1,200"},
		{1234567, "1,234,567"},
	}
	for _, tt := range tests {
		got := groupThousands(tt.n)
		if got != tt.want {
			t.Errorf("groupThousands(%d) = %q, want %q", tt.n, got, tt.want)
		}
	}
}
