package metrics

import (
	"testing"
	"time"

	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
)

func TestRiskDistributionOrderAndColors(t *testing.T) {
	accts := []model.Account{
		{RiskLevel: "Low"}, {RiskLevel: "Critical"}, {RiskLevel: "Low"}, {RiskLevel: "High"},
	}
	got := RiskDistribution(accts)
	// order Critical, High, Medium(absent->skipped), Low
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3", len(got))
	}
	if got[0].Name != "Critical" || got[0].Value != 1 || got[0].Color != "#fb7185" {
		t.Errorf("slot0 = %+v", got[0])
	}
	if got[1].Name != "High" || got[1].Value != 1 {
		t.Errorf("slot1 = %+v", got[1])
	}
	if got[2].Name != "Low" || got[2].Value != 2 || got[2].Color != "#22d3ee" {
		t.Errorf("slot2 = %+v", got[2])
	}
}

func TestHIBPSplitFiltersZero(t *testing.T) {
	accts := []model.Account{{HIBPBreached: true}, {HIBPBreached: true}}
	got := HIBPSplit(accts) // all breached -> "Not in HIBP" slice (value 0) dropped
	if len(got) != 1 || got[0].Name != "Breached" || got[0].Value != 2 {
		t.Fatalf("got = %+v, want single Breached=2", got)
	}
}

func TestExpirationSplitThreeWay(t *testing.T) {
	tr, fa := true, false
	accts := []model.Account{
		{PwdNeverExpires: &tr}, {PwdNeverExpires: &fa}, {PwdNeverExpires: &fa}, {},
	}
	got := ExpirationSplit(accts)
	m := map[string]int{}
	for _, s := range got {
		m[s.Name] = s.Value
	}
	if m["Expires"] != 2 || m["Never expires"] != 1 || m["Unknown"] != 1 {
		t.Fatalf("got = %+v", got)
	}
}

func TestBuildChartSeriesAttachedToBundle(t *testing.T) {
	now := time.Date(2026, 6, 30, 0, 0, 0, 0, time.UTC)
	m := Compute([]model.Account{{RiskLevel: "Low"}, {RiskLevel: "Critical"}}, now)
	if len(m.Charts.RiskDistribution) != 2 {
		t.Fatalf("org charts not populated: %+v", m.Charts.RiskDistribution)
	}
}
