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

func TestLengthBucketsCrackedOnlyAllSix(t *testing.T) {
	accts := []model.Account{
		{Cracked: true, PasswordLength: 7}, {Cracked: true, PasswordLength: 16},
		{Cracked: false, PasswordLength: 3}, // uncracked excluded
	}
	got := LengthBuckets(accts)
	if len(got) != 6 {
		t.Fatalf("want 6 bars, got %d", len(got))
	}
	if got[0].Name != "1–7" || got[0].Value != 1 {
		t.Errorf("bucket0 = %+v", got[0])
	}
	if got[5].Name != "16+" || got[5].Value != 1 {
		t.Errorf("bucket5 = %+v", got[5])
	}
}

func TestScoreBucketsBoundaries(t *testing.T) {
	accts := []model.Account{{RiskScore: 8}, {RiskScore: 6}, {RiskScore: 4}, {RiskScore: 2}, {RiskScore: 0}}
	got := ScoreBuckets(accts)
	want := []int{1, 1, 1, 1, 1} // 0–2,2–4,4–6,6–8,8–10
	for i, b := range got {
		if b.Value != want[i] {
			t.Errorf("bucket %d (%s) = %d, want %d", i, b.Name, b.Value, want[i])
		}
	}
}

func TestControlledObjectsBucketsFiltersZero(t *testing.T) {
	accts := []model.Account{{Controlled: 0}, {Controlled: 600}}
	got := ControlledObjectsBuckets(accts)
	// "0" bucket has 1 but is value>0 so KEPT; "500+" has 1; the empty middle buckets dropped
	names := map[string]int{}
	for _, b := range got {
		names[b.Name] = b.Value
	}
	if names["0"] != 1 || names["500+"] != 1 {
		t.Fatalf("got = %+v", got)
	}
	if _, ok := names["11–50"]; ok {
		t.Errorf("empty bucket 11–50 should be filtered out")
	}
}

func TestSimilarityBucketsSkipsZeroScores(t *testing.T) {
	accts := []model.Account{{SimilarityScore: 0}, {SimilarityScore: 0.95}, {SimilarityScore: 0.75}}
	got := SimilarityBuckets(accts)
	names := map[string]int{}
	for _, b := range got {
		names[b.Name] = b.Value
	}
	if names["0.9+"] != 1 || names["0.7–0.8"] != 1 {
		t.Fatalf("got = %+v", got)
	}
}

func TestDAExposureByDomainSortedDesc(t *testing.T) {
	da := "CORP.LOCAL"
	none := "None"
	accts := []model.Account{
		{Domain: "A", DADomains: da}, {Domain: "B", DADomains: da}, {Domain: "B", DADomains: da},
		{Domain: "C", DADomains: none},
	}
	got := DAExposureByDomain(accts)
	if len(got) != 2 || got[0].Name != "B" || got[0].Value != 2 || got[1].Name != "A" {
		t.Fatalf("got = %+v", got)
	}
}

func TestComplexityCountsLabelsAndSort(t *testing.T) {
	accts := []model.Account{
		{Cracked: true, Complexity: "mixedalphaspecialnum"},
		{Cracked: true, Complexity: "loweralpha"},
		{Cracked: true, Complexity: "loweralpha"},
		{Cracked: false, Complexity: "numeric"}, // excluded
	}
	got := ComplexityCounts(accts)
	if got[0].Name != "a–z" || got[0].Value != 2 {
		t.Fatalf("top = %+v", got)
	}
	if got[1].Name != "a–z A–Z 0–9 !@#" || got[1].Value != 1 {
		t.Errorf("second = %+v", got[1])
	}
}

func TestComplexityLabelUnknownPassThrough(t *testing.T) {
	if ComplexityLabel("weirdkey") != "weirdkey" {
		t.Error("unknown key should pass through")
	}
	if ComplexityLabel("numeric") != "0–9" {
		t.Error("numeric -> 0–9")
	}
}

func TestHIBPVsRiskDropsEmptyLevels(t *testing.T) {
	accts := []model.Account{
		{RiskLevel: "Critical", HIBPBreachCount: 9, RiskScore: 8.5},
		{RiskLevel: "Low", HIBPBreachCount: 0, RiskScore: 1},
	}
	got := HIBPVsRisk(accts)
	if len(got) != 2 {
		t.Fatalf("want Critical+Low series, got %d", len(got))
	}
	if got[0].Name != "Critical" || len(got[0].Points) != 1 {
		t.Fatalf("crit = %+v", got[0])
	}
	// x = log10(9+1) = 1
	if got[0].Points[0].X < 0.999 || got[0].Points[0].X > 1.001 {
		t.Errorf("x = %v, want ~1", got[0].Points[0].X)
	}
}

func TestPasswordAgeBucketsUsesNow(t *testing.T) {
	now := time.Date(2026, 6, 30, 0, 0, 0, 0, time.UTC)
	day := int64(86400)
	accts := []model.Account{
		{PwdLastSet: now.Unix() - 10*day},  // < 30d
		{PwdLastSet: now.Unix() - 800*day}, // 2y+
		{PwdLastSet: 0},                    // skipped
	}
	got := PasswordAgeBuckets(accts, now)
	names := map[string]int{}
	for _, b := range got {
		names[b.Name] = b.Value
	}
	if names["< 30d"] != 1 || names["2y+"] != 1 {
		t.Fatalf("got = %+v", got)
	}
}

func TestAxisFactorBarsAveragesAndImpactFlag(t *testing.T) {
	sb := func(weak, priv float64) *model.ScoreBreakdown {
		return &model.ScoreBreakdown{WeaknessScore: weak, PrivilegeSubScore: priv}
	}
	fp := func(f float64) *float64 { return &f }
	accts := []model.Account{
		{RiskLevel: "Critical", ScoreBreakdown: sb(8, 10), ImpactKnown: true, ImpactScore: fp(9)},
		{RiskLevel: "Critical", ScoreBreakdown: sb(6, 0), ImpactKnown: false}, // not enriched
	}
	got := AxisFactorBars(accts)
	if len(got) != 1 || got[0].Tier != "Critical" {
		t.Fatalf("got = %+v", got)
	}
	// Weakness avg over the whole group (8+6)/2 = 7
	var weak float64
	for _, f := range got[0].Exposure {
		if f.Name == "Weakness" {
			weak = f.Value
		}
	}
	if weak != 7 {
		t.Errorf("weakness avg = %v, want 7", weak)
	}
	// Privilege avg over ENRICHED only = 10/1 = 10
	var priv float64
	for _, f := range got[0].Impact {
		if f.Name == "Privilege" {
			priv = f.Value
		}
	}
	if priv != 10 {
		t.Errorf("privilege avg (enriched) = %v, want 10", priv)
	}
	if !got[0].ImpactKnown {
		t.Error("impact_known should be true (one enriched account in tier)")
	}
}
