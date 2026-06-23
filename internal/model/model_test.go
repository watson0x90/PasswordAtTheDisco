package model

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPostureScoreGolden(t *testing.T) {
	// Pins the new Hygiene×Reachability formula over ENABLED accounts.
	// Weights: risk=45, strength=35, compliance=20 (privilege term removed).
	// 2 enabled accounts: 1 Critical cracked+breached non-compliant, 1 Low cracked compliant.
	// active=2: risk=max(0,100-1/2*200)/100*45=0; strength=0/2*35=0; compliance=(2-1)/2*20=10 -> 10.0
	p := PostureScore([]Account{
		{Enabled: true, RiskLevel: "Critical", Cracked: true, HIBPBreached: true, MeetsPolicy: false},
		{Enabled: true, RiskLevel: "Low", Cracked: true, MeetsPolicy: true},
	})
	if p.Score != 10.0 || p.Rating != "Weak" {
		t.Fatalf("posture = %.1f %s, want 10.0 Weak", p.Score, p.Rating)
	}
	if p.Breakdown.Risk != 0 || p.Breakdown.Strength != 0 || p.Breakdown.Privilege != 0 || p.Breakdown.Compliance != 10.0 {
		t.Fatalf("breakdown = %+v, want {Risk:0 Strength:0 Privilege:0 Compliance:10}", p.Breakdown)
	}

	// Second golden with NON-ZERO risk + strength. 5 enabled accounts:
	// 1 Crit cracked non-compliant, 1 High cracked compliant, 3 Low uncracked.
	// active=5: risk=max(0,100-1/5*200-1/5*150)/100*45 = (100-40-30)/100*45 = 30/100*45 = 13.5
	// strength = 3/5*35 = 21; compliance = (5-1)/5*20 = 16 -> 50.5 Weak
	p2 := PostureScore([]Account{
		{Enabled: true, RiskLevel: "Critical", Cracked: true, MeetsPolicy: false},
		{Enabled: true, RiskLevel: "High", Cracked: true, MeetsPolicy: true},
		{Enabled: true, RiskLevel: "Low", Cracked: false},
		{Enabled: true, RiskLevel: "Low", Cracked: false},
		{Enabled: true, RiskLevel: "Low", Cracked: false},
	})
	if p2.Score != 50.5 || p2.Rating != "Weak" {
		t.Fatalf("posture2 = %.1f %s, want 50.5 Weak", p2.Score, p2.Rating)
	}
	if p2.Breakdown.Risk != 13.5 || p2.Breakdown.Strength != 21.0 || p2.Breakdown.Privilege != 0 || p2.Breakdown.Compliance != 16.0 {
		t.Fatalf("breakdown2 = %+v, want {Risk:13.5 Strength:21 Privilege:0 Compliance:16}", p2.Breakdown)
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
	// The DA account that seeded its own hash must NOT be flagged as escalated-by-
	// shared-DA -- it has its own DA pathway; flagging it inflates the lateral-
	// movement report with false positives.
	if accts[0].EscalatedBySharedDA {
		t.Fatal("the DA account itself must not be flagged EscalatedBySharedDA")
	}
}

func TestControlsTier0RoundTripsAndSurvivesRedaction(t *testing.T) {
	a := Account{Username: "svc", Domain: "CORP", ControlsTier0: true, Password: "s3cret"}
	b, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	var got Account
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if !got.ControlsTier0 {
		t.Fatalf("ControlsTier0 lost on JSON round-trip: %+v", got)
	}
	red := a.Redacted()
	if !red.ControlsTier0 {
		t.Fatalf("ControlsTier0 must survive Redacted() (boolean signal, not a credential)")
	}
	if red.Password != "" {
		t.Fatalf("Redacted() must still strip Password")
	}
	// false must round-trip silently: omitempty suppresses the key, and the default
	// false is semantically "does not control a Tier-0 asset" (no three-state needed).
	bFalse, err := json.Marshal(Account{Username: "svc2", Domain: "CORP", ControlsTier0: false})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(bFalse), "controls_tier0") {
		t.Fatalf("ControlsTier0:false must be omitted by omitempty, got %s", bFalse)
	}
}

func ptr10() *float64 { v := 10.0; return &v }

func TestEscalateSharedWithDASyncsBreakdownImpact(t *testing.T) {
	da := Account{Username: "admin", Domain: "CORP", NTHash: "AA", DADomains: "CORP.LOCAL",
		Cracked: true, ImpactScore: ptr10(), ImpactKnown: true}
	victim := Account{Username: "bob", Domain: "CORP", NTHash: "AA", Cracked: true,
		ScoreBreakdown: &ScoreBreakdown{ImpactScore: 3.0, PrivilegeSubScore: 1.0}}
	accts := []Account{da, victim}
	EscalateSharedWithDA(accts)
	var bob Account
	for _, a := range accts {
		if a.Username == "bob" {
			bob = a
		}
	}
	if bob.ImpactScore == nil || *bob.ImpactScore != 10 {
		t.Fatalf("victim ImpactScore = %v, want 10", bob.ImpactScore)
	}
	if bob.ScoreBreakdown == nil || bob.ScoreBreakdown.ImpactScore != 10 {
		t.Fatalf("breakdown ImpactScore must be synced to 10, got %v", bob.ScoreBreakdown)
	}
}

func TestComputePercentiles(t *testing.T) {
	// Fixtures now carry RiskLevel + ExposureScore so the composite triage key is
	// meaningful (level-first, then Exposure as the scalar when ImpactKnown=false).
	// RiskScore is kept for display/back-compat but no longer drives triage rank.
	//   accts[0]: Low   / Exposure 2  -> levelRank 1, scalar 2  -> lowest
	//   accts[1]: Medium/ Exposure 5  -> levelRank 2, scalar 5  -> middle
	//   accts[2]: High  / Exposure 8  -> levelRank 3, scalar 8  -> tied-highest
	//   accts[3]: High  / Exposure 8  -> levelRank 3, scalar 8  -> tied-highest
	mk := func(level string, exp float64) Account {
		return Account{RiskLevel: level, ExposureScore: exp}
	}
	accts := []Account{mk("Low", 2), mk("Medium", 5), mk("High", 8), mk("High", 8)}
	ComputePercentiles(accts)
	// All percentiles in [0,1].
	for i := range accts {
		if accts[i].Percentile < 0 || accts[i].Percentile > 1 {
			t.Fatalf("percentile out of range: %v", accts[i].Percentile)
		}
	}
	// Level-first order: Low < Medium < High (strictly).
	if !(accts[0].Percentile < accts[1].Percentile && accts[1].Percentile < accts[2].Percentile) {
		t.Fatalf("percentiles must be monotonic with composite key: %v", []float64{
			accts[0].Percentile, accts[1].Percentile, accts[2].Percentile})
	}
	// Ties share a percentile (both High/Exposure=8).
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

func TestComputePercentilesLevelFirst(t *testing.T) {
	f := func(v float64) *float64 { return &v }
	high := Account{Username: "svc", RiskLevel: "High", ExposureScore: 5, ImpactScore: f(9), ImpactKnown: true}
	lowNoise := Account{Username: "dis", RiskLevel: "Low", ExposureScore: 9, ImpactScore: f(2), ImpactKnown: true}
	esc := Account{Username: "esc", RiskLevel: "Critical", ExposureScore: 1, ImpactScore: f(10), ImpactKnown: true, EscalatedBySharedDA: true}
	accts := []Account{lowNoise, high, esc}
	ComputePercentiles(accts)
	p := map[string]float64{}
	for _, a := range accts {
		p[a.Username] = a.Percentile
	}
	if !(p["esc"] > p["svc"] && p["svc"] > p["dis"]) {
		t.Fatalf("level-first violated: esc=%v svc=%v dis=%v", p["esc"], p["svc"], p["dis"])
	}
	if p["dis"] != 0 {
		t.Fatalf("disabled-noise should rank lowest, got %v", p["dis"])
	}
	if p["esc"] != 1 {
		t.Fatalf("escalated Critical should rank highest, got %v", p["esc"])
	}
}

func TestMassReuseTarget(t *testing.T) {
	cases := []struct {
		n, total int
		want     string
	}{
		{100, 10000, "High"},
		{25, 10000, "Medium"},
		{24, 10000, ""},
		{20, 30, "High"},   // hybrid: 20 >= 0.25*30=7.5 and >=5
		{8, 100, "Medium"}, // hybrid: 8 >= 0.05*100=5 and >=5
		{2, 4, ""},         // below the N>=5 fraction guard
		{4, 5, ""},         // 4 < 5 guard even though 80% of audit
	}
	for _, c := range cases {
		if got := massReuseTarget(c.n, c.total); got != c.want {
			t.Errorf("massReuseTarget(%d,%d)=%q want %q", c.n, c.total, got, c.want)
		}
	}
}

func TestEscalateLargeCrackedReuse(t *testing.T) {
	accts := make([]Account, 0, 102)
	for i := 0; i < 100; i++ {
		accts = append(accts, Account{Username: fmt.Sprintf("u%d", i), Domain: "CORP", NTHash: "SHARED", Cracked: true, RiskLevel: "Low", RiskScore: 0.8})
	}
	accts = append(accts, Account{Username: "x", Domain: "CORP", NTHash: "OTHER", Cracked: false, RiskLevel: "Low"})
	accts = append(accts, Account{Username: "crit", Domain: "CORP", NTHash: "SHARED", Cracked: true, RiskLevel: "Critical", RiskScore: 9.0, EscalatedBySharedDA: true})

	EscalateLargeCrackedReuse(accts)

	for i := 0; i < 100; i++ {
		a := accts[i]
		if a.RiskLevel != "High" {
			t.Fatalf("u%d level=%q want High", i, a.RiskLevel)
		}
		if !a.EscalatedByMassReuse || !strings.Contains(a.RiskVector, "MASS-REUSE") {
			t.Fatalf("u%d not flagged/tagged: %+v", i, a)
		}
		if a.RiskScore < 6.0 {
			t.Fatalf("u%d score=%v want >=6.0 (High floor)", i, a.RiskScore)
		}
		if a.ImpactKnown || a.ImpactScore != nil {
			t.Fatalf("u%d Impact must stay untouched", i)
		}
	}
	if accts[100].EscalatedByMassReuse || accts[100].RiskLevel != "Low" {
		t.Errorf("uncracked account wrongly escalated: %+v", accts[100])
	}
	if accts[101].RiskLevel != "Critical" || !accts[101].EscalatedByMassReuse {
		t.Errorf("already-Critical member must stay Critical AND be flagged: %+v", accts[101])
	}
}

func TestUnicodeAndPolicyViolationsRoundTripAndSurviveRedaction(t *testing.T) {
	a := Account{
		Username: "u", Domain: "CORP",
		Password: "s3cret", NTHash: "ABCD",
		ContainsUnicode:  true,
		PolicyViolations: []string{"No uppercase", "Length < 14"},
	}
	b, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	var got Account
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if !got.ContainsUnicode || len(got.PolicyViolations) != 2 || got.PolicyViolations[0] != "No uppercase" {
		t.Fatalf("lost on round-trip: %+v", got)
	}
	red := a.Redacted()
	if !red.ContainsUnicode || len(red.PolicyViolations) != 2 {
		t.Fatalf("ContainsUnicode/PolicyViolations must survive Redacted() (non-secret descriptors)")
	}
	if red.Password != "" || red.NTHash != "" {
		t.Fatalf("Redacted() must still strip Password/NTHash")
	}
}

func TestBreachImpactReachabilityDriven(t *testing.T) {
	t0 := Posture{Verdict: "Critical", VerdictReason: "Tier-0 Reachable", Reachability: "Very High"}
	if bi := EstimateBreachImpact(t0); bi.EstimatedCost != "$1M – $5M+" || bi.RecoveryTime != "6–12 months" {
		t.Fatalf("tier-0 reachable -> want $1M-$5M+/6-12mo, got %q/%q", bi.EstimatedCost, bi.RecoveryTime)
	}
	vh := Posture{Verdict: "Critical", VerdictReason: "multiple reachable domain-control paths", Reachability: "Very High"}
	if bi := EstimateBreachImpact(vh); bi.EstimatedCost != "$500K – $1M" {
		t.Fatalf("very-high (no tier0) -> want $500K-$1M, got %q", bi.EstimatedCost)
	}
	low := Posture{Verdict: "Sound", Reachability: "Low"}
	if bi := EstimateBreachImpact(low); bi.Probability != "Low" || bi.EstimatedCost != "$50K – $100K" {
		t.Fatalf("low -> want Low/$50K-$100K, got %q/%q", bi.Probability, bi.EstimatedCost)
	}
}

func TestGateVerdict(t *testing.T) {
	cases := []struct {
		name, rating, band string
		t0, active         int
		verdict, reason    string
	}{
		{"tier0 caps to critical even if hygiene strong", "Strong", "Low", 1, 100, "Critical", "Tier-0 Reachable"},
		{"very-high L -> critical", "Strong", "Very High", 0, 100, "Critical", "multiple reachable domain-control paths"},
		{"high L -> high risk", "Strong", "High", 0, 100, "High Risk", "a reachable path to domain-control exists"},
		{"strong hygiene, low L -> sound", "Strong", "Low", 0, 100, "Sound", ""},
		{"fair hygiene -> guarded", "Fair", "Low", 0, 100, "Guarded", ""},
		{"weak hygiene -> elevated", "Weak", "Medium", 0, 100, "Elevated", ""},
		{"all disabled, no t0 -> no data", "No Data", "Low", 0, 0, "No Data", ""},
		{"all disabled but reachable tier0 -> critical", "No Data", "Low", 1, 0, "Critical", "Tier-0 Reachable"},
	}
	for _, c := range cases {
		v, r := gateVerdict(c.rating, c.band, c.t0, c.active)
		if v != c.verdict || r != c.reason {
			t.Errorf("%s: got %q/%q want %q/%q", c.name, v, r, c.verdict, c.reason)
		}
	}
}

func TestReachabilityBandsAndReachable(t *testing.T) {
	mk := func(da, t0 bool, cracked, enabled bool) Account {
		a := Account{Enabled: enabled, Cracked: cracked, ControlsTier0: t0}
		if da {
			a.DADomains = "CORP.LOCAL" // makes HasDAPathway() true
		}
		return a
	}
	// 0 enablers -> Low
	if b := reachBand(0); b != "Low" {
		t.Fatalf("reachBand(0) = %q, want Low", b)
	}
	// 1 reachable DA path -> L=0.55 exactly -> High
	one := []Account{mk(true, false, true, true)}
	L, da, _, _, _ := breachReachability(one)
	if da != 1 || reachBand(L) != "High" {
		t.Fatalf("1 reachable DA: da=%d band=%s L=%.4f, want da=1 High L=0.55", da, reachBand(L), L)
	}
	if L != 0.55 {
		t.Fatalf("1 reachable DA: L = %.17g, want exactly 0.55", L)
	}
	// 2 reachable DA paths -> L=0.7975 exactly -> Very High
	two := []Account{mk(true, false, true, true), mk(true, false, true, true)}
	L2, _, _, _, _ := breachReachability(two)
	if reachBand(L2) != "Very High" {
		t.Fatalf("2 reachable DA: band=%s L=%.4f, want Very High", reachBand(L2), L2)
	}
	if L2 != 0.7975 {
		t.Fatalf("2 reachable DA: L2 = %.17g, want exactly 0.7975", L2)
	}
	// DA path through a DISABLED account is NOT reachable -> contributes 0, +1 dormant
	dis := []Account{mk(true, false, true, false)}
	Ld, dad, _, _, dorm := breachReachability(dis)
	if dad != 0 || reachBand(Ld) != "Low" || dorm != 1 {
		t.Fatalf("disabled DA: da=%d band=%s dormant=%d, want da=0 Low dormant=1", dad, reachBand(Ld), dorm)
	}
}

func TestBreachImpactNoData(t *testing.T) {
	// A Posture with Verdict "No Data" must produce all-"—" BreachImpact fields.
	p := Posture{Verdict: "No Data", Reachability: "—", ReachabilityPct: ""}
	bi := EstimateBreachImpact(p)
	if bi.Probability != "—" || bi.ProbabilityPct != "" || bi.EstimatedCost != "—" || bi.RecoveryTime != "—" {
		t.Fatalf("no-data posture: want Probability=—, ProbabilityPct=, Cost=—, Recovery=—; got %+v", bi)
	}

	// PostureScore(all-disabled) must yield Verdict "No Data" with no dollar estimate.
	p2 := PostureScore([]Account{{Enabled: false}})
	if p2.Verdict != "No Data" {
		t.Fatalf("all-disabled PostureScore: want Verdict=No Data, got %q", p2.Verdict)
	}
	if p2.Reachability != "—" || p2.ReachabilityPct != "" || p2.Likelihood != "—" {
		t.Fatalf("all-disabled PostureScore: want Reachability=—, ReachabilityPct=, Likelihood=—; got Reachability=%q ReachabilityPct=%q Likelihood=%q",
			p2.Reachability, p2.ReachabilityPct, p2.Likelihood)
	}
	bi2 := EstimateBreachImpact(p2)
	if bi2.EstimatedCost != "—" || bi2.RecoveryTime != "—" || bi2.Probability != "—" {
		t.Fatalf("EstimateBreachImpact(no-data PostureScore): want all-—, got %+v", bi2)
	}
}

func TestHygieneExcludesDisabledAndDropsPrivilege(t *testing.T) {
	// 2 enabled (1 cracked-violator), 8 disabled -> hygiene computed over the 2 enabled only.
	accts := []Account{
		{Enabled: true, RiskLevel: "Low", Cracked: true, MeetsPolicy: false}, // enabled cracked violator
		{Enabled: true, RiskLevel: "Low", Cracked: false, MeetsPolicy: true}, // enabled clean
	}
	for i := 0; i < 8; i++ { // disabled padding must NOT inflate hygiene
		accts = append(accts, Account{Enabled: false, RiskLevel: "Critical", Cracked: true, MeetsPolicy: false})
	}
	p := PostureScore(accts)
	// active=2: risk=45 (no crit/high/med among enabled), strength=(1/2)*35=17.5,
	// compliance=((2-1)/2)*20=10 -> 72.5
	if p.Score < 72.0 || p.Score > 73.0 {
		t.Fatalf("hygiene = %v, want ~72.5 (disabled excluded, privilege dropped)", p.Score)
	}
	if p.Breakdown.Privilege != 0 {
		t.Errorf("privilege breakdown must be 0 (term removed), got %v", p.Breakdown.Privilege)
	}
}

func TestHygieneActiveZero(t *testing.T) {
	accts := []Account{{Enabled: false, RiskLevel: "Low"}}
	p := PostureScore(accts)
	if p.Verdict != "No Data" || p.Score != 0 {
		t.Fatalf("all-disabled -> want No Data/0, got %q/%v", p.Verdict, p.Score)
	}
}

func TestEscalateLargeCrackedReuseMediumIdempotentAndSubThreshold(t *testing.T) {
	// 25 cracked share a hash in a large audit -> Medium (absolute N>=25, but <5% of 1000).
	// Plus a sub-threshold cluster of 3 cracked -> untouched.
	accts := make([]Account, 0, 1003)
	for i := 0; i < 25; i++ {
		accts = append(accts, Account{Username: fmt.Sprintf("m%d", i), Domain: "CORP", NTHash: "MEDIUM", Cracked: true, RiskLevel: "Low", RiskScore: 0.5})
	}
	for i := 0; i < 3; i++ {
		accts = append(accts, Account{Username: fmt.Sprintf("s%d", i), Domain: "CORP", NTHash: "SMALL", Cracked: true, RiskLevel: "Low", RiskScore: 0.5})
	}
	for i := 0; i < 975; i++ { // padding so total=1003 -> 25 is < 5% (=50.15)
		accts = append(accts, Account{Username: fmt.Sprintf("p%d", i), Domain: "CORP", NTHash: fmt.Sprintf("UNIQ%d", i), Cracked: true, RiskLevel: "Low"})
	}

	EscalateLargeCrackedReuse(accts)

	for i := 0; i < 25; i++ { // Medium tier exercises the 4.0 floor branch
		a := accts[i]
		if a.RiskLevel != "Medium" || !a.EscalatedByMassReuse || a.RiskScore < 4.0 {
			t.Fatalf("m%d: level=%q flagged=%v score=%v, want Medium+flagged+>=4.0", i, a.RiskLevel, a.EscalatedByMassReuse, a.RiskScore)
		}
	}
	for i := 25; i < 28; i++ { // sub-threshold cluster of 3 -> untouched
		a := accts[i]
		if a.EscalatedByMassReuse || a.RiskLevel != "Low" || strings.Contains(a.RiskVector, "MASS-REUSE") {
			t.Fatalf("s%d sub-threshold escalated: %+v", i-25, a)
		}
	}

	// Idempotent: a second run leaves state identical (no double tag, no further score change).
	before := accts[0]
	EscalateLargeCrackedReuse(accts)
	after := accts[0]
	if after.RiskLevel != before.RiskLevel || after.RiskScore != before.RiskScore ||
		after.RiskVector != before.RiskVector || strings.Count(after.RiskVector, "MASS-REUSE") != 1 {
		t.Errorf("not idempotent: before=%+v after=%+v", before, after)
	}
}

// TestPostureGolden loads the shared Go⇄TS fixture and pins the Go PostureScore output.
// Any change to either the fixture or the Go formula that diverges from the TS mirror
// will fail here; the companion web/src/insights.golden.test.ts asserts the same fixture.
func TestPostureGolden(t *testing.T) {
	type goldenAccount struct {
		Enabled              bool   `json:"enabled"`
		Cracked              bool   `json:"cracked"`
		RiskLevel            string `json:"risk_level"`
		MeetsPolicy          bool   `json:"meets_policy"`
		DADomains            string `json:"da_domains"`
		ControlsTier0        bool   `json:"controls_tier0"`
		EscalatedBySharedDA  bool   `json:"escalated_by_shared_da"`
		EscalatedByMassReuse bool   `json:"escalated_by_mass_reuse"`
	}
	type goldenExpect struct {
		Score           float64 `json:"score"`
		Rating          string  `json:"rating"`
		Reachability    string  `json:"reachability"`
		ReachabilityPct string  `json:"reachability_pct"`
		Overall         float64 `json:"overall"`
		Verdict         string  `json:"verdict"`
		VerdictReason   string  `json:"verdict_reason"`
		Likelihood      string  `json:"likelihood"`
	}
	type goldenCase struct {
		Name     string          `json:"name"`
		Accounts []goldenAccount `json:"accounts"`
		Expect   goldenExpect    `json:"expect"`
	}

	raw, err := os.ReadFile("testdata/posture_golden.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var cases []goldenCase
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}

	for _, c := range cases {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			accts := make([]Account, len(c.Accounts))
			for i, ga := range c.Accounts {
				accts[i] = Account{
					Enabled:              ga.Enabled,
					Cracked:              ga.Cracked,
					RiskLevel:            ga.RiskLevel,
					MeetsPolicy:          ga.MeetsPolicy,
					DADomains:            ga.DADomains,
					ControlsTier0:        ga.ControlsTier0,
					EscalatedBySharedDA:  ga.EscalatedBySharedDA,
					EscalatedByMassReuse: ga.EscalatedByMassReuse,
				}
			}
			p := PostureScore(accts)
			e := c.Expect
			if p.Score != e.Score {
				t.Errorf("score: got %v want %v", p.Score, e.Score)
			}
			if p.Rating != e.Rating {
				t.Errorf("rating: got %q want %q", p.Rating, e.Rating)
			}
			if p.Reachability != e.Reachability {
				t.Errorf("reachability: got %q want %q", p.Reachability, e.Reachability)
			}
			if p.ReachabilityPct != e.ReachabilityPct {
				t.Errorf("reachability_pct: got %q want %q", p.ReachabilityPct, e.ReachabilityPct)
			}
			if p.Overall != e.Overall {
				t.Errorf("overall: got %v want %v", p.Overall, e.Overall)
			}
			if p.Verdict != e.Verdict {
				t.Errorf("verdict: got %q want %q", p.Verdict, e.Verdict)
			}
			if p.VerdictReason != e.VerdictReason {
				t.Errorf("verdict_reason: got %q want %q", p.VerdictReason, e.VerdictReason)
			}
			if p.Likelihood != e.Likelihood {
				t.Errorf("likelihood: got %q want %q", p.Likelihood, e.Likelihood)
			}
		})
	}
}

// TestPostureGoldenFixtureInSync asserts that the two fixture copies are byte-identical.
// If they drift, copy internal/model/testdata/posture_golden.json to web/src/__fixtures__/posture_golden.json.
func TestPostureGoldenFixtureInSync(t *testing.T) {
	// Resolve both paths relative to this test file's location (internal/model/).
	goFixture := filepath.Join("testdata", "posture_golden.json")
	// Two levels up from internal/model/ -> repo root, then into web/src/__fixtures__/.
	webFixture := filepath.Join("..", "..", "web", "src", "__fixtures__", "posture_golden.json")

	goBuf, err := os.ReadFile(goFixture)
	if err != nil {
		t.Fatalf("read Go fixture: %v", err)
	}
	webBuf, err := os.ReadFile(webFixture)
	if err != nil {
		t.Fatalf("read web fixture: %v", err)
	}
	if !bytes.Equal(goBuf, webBuf) {
		t.Fatalf("fixture files are out of sync:\n  Go:  internal/model/testdata/posture_golden.json\n  Web: web/src/__fixtures__/posture_golden.json\nRe-copy the Go fixture to the web path to fix this.")
	}
}
