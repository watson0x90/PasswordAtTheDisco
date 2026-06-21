package model

import (
	"strings"
	"testing"
)

func TestPostureScoreGolden(t *testing.T) {
	// Pins the formula; web/src/insights.ts:posture() must match. 2 accounts:
	// 1 Critical cracked+breached non-compliant, 1 Low cracked compliant.
	p := PostureScore([]Account{
		{RiskLevel: "Critical", Cracked: true, HIBPBreached: true, MeetsPolicy: false},
		{RiskLevel: "Low", Cracked: true, MeetsPolicy: true},
	})
	// risk: max(0,100-(1/2)*200)=0 ; strength 0 ; priv 15 ; compliance (2-1)/2*15=7.5
	if p.Score != 22.5 || p.Rating != "Weak" {
		t.Fatalf("posture = %.1f %s, want 22.5 Weak", p.Score, p.Rating)
	}
	if p.Breakdown != (PostureBreakdown{Risk: 0, Strength: 0, Privilege: 15, Compliance: 7.5}) {
		t.Fatalf("breakdown = %+v, want {0 0 15 7.5}", p.Breakdown)
	}

	// Second golden with NON-ZERO risk + strength, so coefficient drift in either
	// (which the all-zero fixture above would miss) is caught. 5 accounts: 1 Crit
	// cracked non-compliant, 1 High cracked compliant, 3 Low uncracked.
	//   risk = (100 - 1/5*200 - 1/5*150)/100*40 = 12 ; strength = 3/5*30 = 18 ;
	//   privilege 15 ; compliance = (5-1)/5*15 = 12  -> score 57 Weak
	p2 := PostureScore([]Account{
		{RiskLevel: "Critical", Cracked: true, MeetsPolicy: false},
		{RiskLevel: "High", Cracked: true, MeetsPolicy: true},
		{RiskLevel: "Low", Cracked: false},
		{RiskLevel: "Low", Cracked: false},
		{RiskLevel: "Low", Cracked: false},
	})
	if p2.Score != 57 || p2.Rating != "Weak" {
		t.Fatalf("posture2 = %.1f %s, want 57 Weak", p2.Score, p2.Rating)
	}
	if p2.Breakdown != (PostureBreakdown{Risk: 12, Strength: 18, Privilege: 15, Compliance: 12}) {
		t.Fatalf("breakdown2 = %+v, want {12 18 15 12}", p2.Breakdown)
	}
}

// Sharing is keyed on the NT hash (NTLM is unsalted), so it spans domains AND covers
// uncracked accounts -- and ignores the empty-password hash.
func TestRecomputeSharingByHash(t *testing.T) {
	const reused = "1122334455667788AABBCCDDEEFF0011"
	accts := []Account{
		{Username: "a", Domain: "CORP", NTHash: reused, Cracked: true, Password: "Reused1"},
		{Username: "b", Domain: "LEGACY", NTHash: reused, Cracked: false}, // UNCRACKED, same hash, other domain
		{Username: "c", Domain: "CORP", NTHash: "FFEEDDCCBBAA99887766554433221100", Cracked: true, Password: "Unique1"},
		{Username: "svc", Domain: "CORP", NTHash: emptyNTHash, Cracked: false},  // no password set
		{Username: "svc2", Domain: "CORP", NTHash: emptyNTHash, Cracked: false}, // no password set
	}
	RecomputeSharing(accts)
	if accts[0].SharedWith != 1 || accts[1].SharedWith != 1 {
		t.Fatalf("cracked+uncracked sharing one NT hash should each be 1: a=%d b=%d", accts[0].SharedWith, accts[1].SharedWith)
	}
	if accts[2].SharedWith != 0 {
		t.Fatalf("unique hash should have 0 shared, got %d", accts[2].SharedWith)
	}
	if accts[3].SharedWith != 0 || accts[4].SharedWith != 0 {
		t.Fatal("empty-password (no-password) accounts must not count as password reuse")
	}
}

func TestEscalateSharedWithDAByHash(t *testing.T) {
	const shared = "AABBCCDDEEFF00112233445566778899"
	accts := []Account{
		{Username: "da", Domain: "PARENT", NTHash: shared, Cracked: true, Password: "Shared1", DADomains: "PARENT", RiskLevel: "Critical"},
		{Username: "helpdesk", Domain: "SUB", NTHash: shared, Cracked: false, RiskLevel: "Low"}, // UNCRACKED, shares the DA's hash
		{Username: "alice", Domain: "SUB", NTHash: "00000000000000000000000000000001", Cracked: false, RiskLevel: "Low"},
	}
	EscalateSharedWithDA(accts)
	if accts[1].RiskLevel != "Critical" || !strings.Contains(accts[1].RiskVector, "SHARED-DA") {
		t.Fatalf("uncracked account sharing a DA's NT hash must escalate: %+v", accts[1])
	}
	if accts[2].RiskLevel == "Critical" {
		t.Fatal("unrelated account must not be escalated")
	}
	// idempotent: a second pass must not duplicate the marker
	before := accts[1].RiskVector
	EscalateSharedWithDA(accts)
	if accts[1].RiskVector != before {
		t.Fatalf("escalation not idempotent: %q -> %q", before, accts[1].RiskVector)
	}
}

func TestRedactedStripsMatchedWords(t *testing.T) {
	a := Account{
		Username: "alice", Domain: "CORP",
		Password: "Summer2021!", NTHash: "ABC",
		BannedWords:      []string{"summer", "2021"},
		KeyboardPatterns: []string{"qwerty"},
		BannedWordCount:  2, KeyboardPatternCount: 1, IsCommon: true,
	}
	r := a.Redacted()
	if r.BannedWords != nil || r.KeyboardPatterns != nil {
		t.Fatalf("Redacted leaked matched words: %+v / %+v", r.BannedWords, r.KeyboardPatterns)
	}
	if r.Password != "" || r.NTHash != "" {
		t.Fatalf("Redacted leaked credential")
	}
	// redacted-safe metadata is preserved
	if r.BannedWordCount != 2 || !r.IsCommon {
		t.Fatalf("Redacted dropped safe metadata: %+v", r)
	}
}

func TestCoverageSurvivesRedaction(t *testing.T) {
	a := Account{Username: "alice", Domain: "CORP", Password: "secret", NTHash: "ABC", Coverage: "full"}
	red := a.Redacted()
	if red.Coverage != "full" {
		t.Errorf("Coverage = %q after Redacted(), want full (descriptive, not a credential)", red.Coverage)
	}
	if red.Password != "" || red.NTHash != "" {
		t.Errorf("credentials not cleared: pw=%q hash=%q", red.Password, red.NTHash)
	}
}

func TestAxisFieldsRedactionSafe(t *testing.T) {
	imp := 7.0
	a := Account{ExposureScore: 5.0, ImpactScore: &imp, ImpactKnown: true, Percentile: 0.9, Password: "secret"}
	r := a.Redacted()
	if r.Password != "" {
		t.Fatal("password must be redacted")
	}
	if r.ExposureScore != 5.0 || r.ImpactScore == nil || *r.ImpactScore != 7.0 || !r.ImpactKnown || r.Percentile != 0.9 {
		t.Fatalf("axis fields must survive Redacted(): %+v", r)
	}
}

func TestEscalateSharedWithDAImpact(t *testing.T) {
	imp9 := 9.0
	accts := []Account{
		{Username: "da", NTHash: "AAA", DADomains: "CORP.INT", RiskLevel: "Critical",
			ImpactScore: &imp9, ImpactKnown: true, ExposureScore: 6.0},
		{Username: "helpdesk", NTHash: "AAA", DADomains: "None", RiskLevel: "Low",
			ImpactScore: nil, ImpactKnown: false, ExposureScore: 7.0}, // shares DA hash, unenriched
	}
	EscalateSharedWithDA(accts)
	hd := accts[1]
	if hd.RiskLevel != "Critical" {
		t.Fatalf("shared-DA helpdesk level = %q, want Critical", hd.RiskLevel)
	}
	if !hd.ImpactKnown || hd.ImpactScore == nil || *hd.ImpactScore != 10.0 {
		t.Fatalf("shared-DA helpdesk must inherit max Impact 10: known=%v ptr=%v", hd.ImpactKnown, hd.ImpactScore)
	}
	if !hd.EscalatedBySharedDA {
		t.Fatal("EscalatedBySharedDA flag not set")
	}
}

func TestComputePercentiles(t *testing.T) {
	mk := func(score float64) Account { return Account{RiskScore: score} }
	accts := []Account{mk(2), mk(5), mk(8), mk(8)} // ties share rank
	ComputePercentiles(accts)
	// Lowest score -> lowest percentile; highest -> ~1.0. Strictly ordered, [0,1].
	for i := range accts {
		if accts[i].Percentile < 0 || accts[i].Percentile > 1 {
			t.Fatalf("percentile out of range: %v", accts[i].Percentile)
		}
	}
	if !(accts[0].Percentile < accts[1].Percentile && accts[1].Percentile < accts[2].Percentile) {
		t.Fatalf("percentiles must be monotonic with score: %v", []float64{
			accts[0].Percentile, accts[1].Percentile, accts[2].Percentile})
	}
	if accts[2].Percentile != accts[3].Percentile {
		t.Fatalf("ties must share a percentile: %v vs %v", accts[2].Percentile, accts[3].Percentile)
	}
	// Idempotent: running twice yields identical results.
	first := accts[2].Percentile
	ComputePercentiles(accts)
	if accts[2].Percentile != first {
		t.Fatal("ComputePercentiles must be idempotent")
	}
}
