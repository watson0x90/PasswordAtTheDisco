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
