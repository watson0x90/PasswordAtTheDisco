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

func TestTopRiskiestSortedSliced(t *testing.T) {
	accts := []model.Account{
		{Username: "a", RiskScore: 3}, {Username: "b", RiskScore: 9}, {Username: "c", RiskScore: 6},
	}
	got := TopRiskiest(accts, 2)
	if len(got) != 2 || got[0].Username != "b" || got[1].Username != "c" {
		t.Fatalf("got = %+v", got)
	}
}

func TestTopControllersSortAndMoreOver100(t *testing.T) {
	accts := []model.Account{
		{Username: "z", Controlled: 200}, {Username: "y", Controlled: 500},
		{Username: "x", Controlled: 150}, {Username: "w", Controlled: 0},
	}
	rows, more := TopControllers(accts, 2)
	if len(rows) != 2 || rows[0].Username != "y" || rows[1].Username != "z" {
		t.Fatalf("rows = %+v", rows)
	}
	// remaining controllers beyond top-2 with >100: x(150) -> 1
	if more != 1 {
		t.Errorf("more = %d, want 1", more)
	}
}

func TestEscalatedBySharedDAFilteredSorted(t *testing.T) {
	accts := []model.Account{
		{Username: "a", EscalatedBySharedDA: true, RiskScore: 5},
		{Username: "b", EscalatedBySharedDA: false, RiskScore: 9},
		{Username: "c", EscalatedBySharedDA: true, RiskScore: 8},
	}
	got := EscalatedBySharedDA(accts)
	if len(got) != 2 || got[0].Username != "c" || got[1].Username != "a" {
		t.Fatalf("got = %+v", got)
	}
}

func TestPasswordAgeScatterUsesNow(t *testing.T) {
	now := time.Date(2026, 6, 30, 0, 0, 0, 0, time.UTC)
	nowUnix := now.Unix()
	day := int64(86400)

	accts := []model.Account{
		{RiskLevel: "Critical", RiskScore: 9, PwdLastSet: nowUnix - 100*day},
		{RiskLevel: "Low", RiskScore: 1, PwdLastSet: nowUnix - 5*day},
		{RiskLevel: "Low", RiskScore: 2, PwdLastSet: 0}, // skipped (pwd_last_set <= 0)
	}
	got := PasswordAgeScatter(accts, now)

	// Should have exactly 2 series: Critical and Low (in that order per levelColors)
	if len(got) != 2 {
		t.Fatalf("want 2 series, got %d: %+v", len(got), got)
	}

	// Check Critical series
	if got[0].Name != "Critical" || got[0].Color != "#fb7185" {
		t.Errorf("crit series header = %+v, want Critical/#fb7185", got[0])
	}
	if len(got[0].Points) != 1 {
		t.Errorf("crit series points = %d, want 1", len(got[0].Points))
	}
	if len(got[0].Points) > 0 {
		if got[0].Points[0].X != 100 || got[0].Points[0].Y != 9 {
			t.Errorf("crit point = X:%v Y:%v, want X:100 Y:9", got[0].Points[0].X, got[0].Points[0].Y)
		}
	}

	// Check Low series
	if got[1].Name != "Low" || got[1].Color != "#22d3ee" {
		t.Errorf("low series header = %+v, want Low/#22d3ee", got[1])
	}
	if len(got[1].Points) != 1 {
		t.Errorf("low series points = %d, want 1", len(got[1].Points))
	}
	if len(got[1].Points) > 0 {
		if got[1].Points[0].X != 5 || got[1].Points[0].Y != 1 {
			t.Errorf("low point = X:%v Y:%v, want X:5 Y:1", got[1].Points[0].X, got[1].Points[0].Y)
		}
	}
}

func TestToRefCopiesAllDisplayFields(t *testing.T) {
	a := model.Account{
		Username:             "alice",
		Domain:               "CORP.LOCAL",
		RiskLevel:            "Critical",
		RiskScore:            9.5,
		HIBPBreachCount:      3,
		Controlled:           42,
		Enabled:              true,
		Cracked:              true,
		HIBPBreached:         true,
		DADomains:            "CORP.LOCAL",
		ControlsTier0:        true,
		EscalatedBySharedDA:  true,
		EscalatedByMassReuse: false,
		MeetsPolicy:          false,
	}
	ref := toRef(a)

	// Check all fields are copied correctly
	if ref.Username != "alice" || ref.Domain != "CORP.LOCAL" {
		t.Errorf("basic fields: username=%q, domain=%q", ref.Username, ref.Domain)
	}
	if ref.Enabled != true {
		t.Errorf("Enabled = %v, want true", ref.Enabled)
	}
	if ref.Cracked != true {
		t.Errorf("Cracked = %v, want true", ref.Cracked)
	}
	if ref.HIBPBreached != true {
		t.Errorf("HIBPBreached = %v, want true", ref.HIBPBreached)
	}
	if ref.DADomains != "CORP.LOCAL" {
		t.Errorf("DADomains = %q, want CORP.LOCAL", ref.DADomains)
	}
	if ref.ControlsTier0 != true {
		t.Errorf("ControlsTier0 = %v, want true", ref.ControlsTier0)
	}
	if ref.EscalatedBySharedDA != true {
		t.Errorf("EscalatedBySharedDA = %v, want true", ref.EscalatedBySharedDA)
	}
	if ref.EscalatedByMassReuse != false {
		t.Errorf("EscalatedByMassReuse = %v, want false", ref.EscalatedByMassReuse)
	}
	if ref.MeetsPolicy != false {
		t.Errorf("MeetsPolicy = %v, want false", ref.MeetsPolicy)
	}
}
