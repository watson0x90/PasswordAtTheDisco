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
		t.Errorf("domains = %v, want 3", len(cd.Domains))
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
