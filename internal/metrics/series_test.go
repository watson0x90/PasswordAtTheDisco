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
