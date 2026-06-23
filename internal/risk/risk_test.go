package risk

import (
	"math"
	"testing"
)

func almost(a, b float64) bool { return math.Abs(a-b) < 1e-9 }
func ip(n int) *int            { return &n }

// strong: a long, complex password (lowest intrinsic risk).
func strong() Analysis { return Analysis{ComplexityLabel: "mixedalphaspecialnum", PasswordLength: 20} }

func TestSimilarityTiers(t *testing.T) {
	cases := []struct {
		sim, want float64
	}{{0.95, 0.6}, {0.85, 0.4}, {0.75, 0.2}, {0.5, 0.0}}
	for _, c := range cases {
		if sf := similarityFactor(c.sim); !almost(sf, c.want) {
			t.Errorf("similarity %.2f -> factor %v, want %v", c.sim, sf, c.want)
		}
	}
}

func TestScoreV2Range(t *testing.T) {
	r := Score(
		Analysis{ComplexityLabel: "numeric", PasswordLength: 4, IsCommon: true, IsDictionaryWord: true,
			BannedWordsCount: 1, KeyboardPatternsCount: 1, SimilarMax: 0.95},
		Context{Cracked: true, Coverage: "full", Enabled: true, SharedWith: 1000,
			DADomains: []string{"A"}, ControlledObjects: ip(2000), DomainRiskLevel: "Critical",
			HIBPBreachCount: 200000},
	)
	if r.Exposure < 0 || r.Exposure > 10 || r.Impact < 0 || r.Impact > 10 || r.Score < 0 || r.Score > 10 {
		t.Fatalf("axes out of range: %+v", r)
	}
	if r.Level != "Critical" { // cracked + DA hard override
		t.Fatalf("level = %q, want Critical", r.Level)
	}
}

func TestExposureComplexityIndependentOfLength(t *testing.T) {
	// Two 16-char passwords, identical length, differing ONLY in complexity.
	// In v1 the base multiplied complexityF*lengthF, so a long password collapsed
	// complexity's contribution and these scored identically. In v2 complexity is an
	// independent weighted term, so the mixed-special password must score strictly
	// LOWER exposure than the all-lowercase one.
	// Length 8 (not 16): both weakness scores must clear the crackedFloor (3.0) for the
	// complexity difference to be observable through exposureScore; at length 16 both fall
	// below the floor and exposure collapses to 3.0 for both (deviation from plan's literal
	// length 16 — the floor masked the difference there). The point — complexity is an
	// independent term, not nullified by length — holds.
	lower := Analysis{ComplexityLabel: "loweralpha", PasswordLength: 8}
	mixed := Analysis{ComplexityLabel: "mixedalphaspecialnum", PasswordLength: 8}
	c := Context{Cracked: true, Coverage: "none"}
	eLow := exposureScore(lower, c)
	eMixed := exposureScore(mixed, c)
	if !(eLow > eMixed) {
		t.Fatalf("complexity must matter independent of length: lower=%v mixed=%v", eLow, eMixed)
	}
}

func TestExposureHIBPCountedOnce(t *testing.T) {
	// A strong, long, unique password whose hash matches HIBP at exactly the 1e5
	// tier. v1 multiplied/floored HIBP three times; v2 uses a single floor of 8.5.
	// Exposure must equal exactly the floor (no weakness signal beats it, no bumps).
	a := strong()
	got := exposureScore(a, Context{Cracked: true, Coverage: "none", HIBPBreachCount: 100000})
	if !almost(got, 8.5) {
		t.Fatalf("HIBP 1e5 exposure = %v, want exactly 8.5 (single channel)", got)
	}
	// One breach hit floors at 4.5, not higher.
	if got := exposureScore(a, Context{Cracked: true, Coverage: "none", HIBPBreachCount: 1}); !almost(got, 4.5) {
		t.Fatalf("HIBP 1 exposure = %v, want 4.5", got)
	}
}

func TestExposureWeakness(t *testing.T) {
	// Worst-case weakness: shortest, least complex ("numeric" cf=1.0 -> max penalty),
	// every dict signal, max similarity. complexity/dict/sim penalties saturate to 1.0;
	// lengthPenalty is a sigmoid that ASYMPTOTES to 1.0 but never reaches it (lengthPenalty(1)
	// = 0.989), so the locked "= 10.0" is the cf=1.0/len=0 idealization. The achievable
	// saturated weakness is ~9.97; assert it is essentially maxed (>= 9.9) rather than the
	// unreachable exact 10.0 (deviation from plan's literal almost(10.0)).
	a := Analysis{ComplexityLabel: "numeric", PasswordLength: 1, IsCommon: true,
		IsDictionaryWord: true, BannedWordsCount: 50, KeyboardPatternsCount: 50, SimilarMax: 1.0}
	if got := weaknessScore(a); got < 9.9 {
		t.Fatalf("saturated weakness = %v, want ~10.0 (>= 9.9)", got)
	}
	// A perfectly strong long password: lengthPenalty~0, complexityPenalty=0,
	// dict=0, sim=0 -> weaknessScore ~ 0.
	if got := weaknessScore(strong()); got > 0.1 {
		t.Fatalf("strong weakness = %v, want ~0", got)
	}
}

func TestExposureBumps(t *testing.T) {
	a := strong()
	base := exposureScore(a, Context{Cracked: true, Coverage: "none"}) // crackedFloor 3.0
	if !almost(base, 3.0) {
		t.Fatalf("strong cracked floor = %v, want 3.0", base)
	}
	reuse := exposureScore(a, Context{Cracked: true, Coverage: "none", SharedWith: 2})
	if !almost(reuse, 3.75) { // crackedFloor 3.0 + reuseBump(2)=0.75
		t.Fatalf("reuse bump = %v, want 3.75", reuse)
	}
	roast := exposureScore(a, Context{Cracked: true, Coverage: "full", HasSPN: true})
	if !almost(roast, 3.5) {
		t.Fatalf("roastable bump = %v, want 3.5", roast)
	}
	short := exposureScore(Analysis{ComplexityLabel: "loweralpha", PasswordLength: 5},
		Context{Cracked: true, Coverage: "none"})
	if short < 4.0 {
		t.Fatalf("short cracked floor = %v, want >= 4.0", short)
	}
}

func TestExposureUncracked(t *testing.T) {
	// Uncracked: no weakness signals (password unknown). Exposure from HIBP floor + bumps only.
	c := Context{Cracked: false, Coverage: "none", HIBPBreachCount: 1000}
	if got := exposureScore(Analysis{}, c); !almost(got, 7.0) {
		t.Fatalf("uncracked HIBP 1e3 = %v, want 7.0", got)
	}
	// Uncracked, no HIBP, no bumps -> 0 exposure (unknown password, no signal).
	if got := exposureScore(Analysis{}, Context{Cracked: false, Coverage: "none"}); !almost(got, 0.0) {
		t.Fatalf("uncracked no-signal exposure = %v, want 0.0", got)
	}
	// Uncracked + AS-REP floor(3.0) + reuse(3)=0.75 bump + AS-REP roastable(0.75) bump.
	c2 := Context{Cracked: false, Coverage: "full", SharedWith: 3, DontReqPreauth: true}
	if got := exposureScore(Analysis{}, c2); !almost(got, 4.5) {
		t.Fatalf("uncracked AS-REP+reuse exposure = %v, want 4.5", got)
	}
}

func TestReuseFloorAppliesUncracked(t *testing.T) {
	// A strong, uncracked, zero-HIBP password in a 200-account reuse cluster must still
	// floor to >= Medium on the back of reuseFloor alone -- the panel's whole point.
	// Components: floor = max(0, reuseFloor(200)=4.0) = 4.0; bump = reuseBump(200)=1.0 (>=10 tier).
	// Exposure = min(10, 4.0 + 1.0) = 5.0.
	got := exposureScore(strong(), Context{Cracked: false, Coverage: "full", SharedWith: 200})
	if !almost(got, 5.0) {
		t.Fatalf("uncracked 200-cluster exposure = %v, want 5.0", got)
	}
}

func TestShareCode(t *testing.T) {
	for _, c := range []struct {
		n    int
		want string
	}{{0, "0"}, {5, "1"}, {9, "1"}, {10, "2"}, {99, "2"}, {100, "3"}, {999, "3"}, {1000, "4"}, {50000, "4"}} {
		if got := shareCode(c.n); got != c.want {
			t.Errorf("shareCode(%d) = %q, want %q", c.n, got, c.want)
		}
	}
}

func TestImpactPrivilege(t *testing.T) {
	for _, tc := range []struct {
		n    int
		want float64
	}{{0, 0}, {5, 3}, {11, 5}, {51, 6}, {101, 7}, {501, 8}, {1001, 9}} {
		got, known := impactScore(Context{Coverage: "full", Enabled: true, ControlledObjects: ip(tc.n)})
		if !known || !almost(got, tc.want) {
			t.Errorf("controlled=%d -> impact %v (known=%v), want %v", tc.n, got, known, tc.want)
		}
	}
}

func TestImpactDAandTier0(t *testing.T) {
	// Own DA path -> 10.
	got, _ := impactScore(Context{Coverage: "full", Enabled: true, DADomains: []string{"CORP"}})
	if !almost(got, 10.0) {
		t.Fatalf("own DA path impact = %v, want 10", got)
	}
	// ControlsTier0 (DA-equivalent) -> privilege 10 even with a tiny controlled count.
	got, _ = impactScore(Context{Coverage: "full", Enabled: true, ControlsTier0: true, ControlledObjects: ip(1)})
	if !almost(got, 10.0) {
		t.Fatalf("Tier-0 control impact = %v, want 10", got)
	}
}

func TestImpactDisabledGate(t *testing.T) {
	// A DA-pathed but DISABLED account cannot authenticate -> Impact capped at 2.0.
	got, known := impactScore(Context{Coverage: "full", Enabled: false, DADomains: []string{"CORP"}})
	if !known || !almost(got, 2.0) {
		t.Fatalf("disabled DA impact = %v (known=%v), want 2.0", got, known)
	}
}

func TestImpactUnknown(t *testing.T) {
	// coverage "none" -> Impact Unknown (number is meaningless; known=false).
	_, known := impactScore(Context{Coverage: "none", Enabled: true, ControlledObjects: ip(500)})
	if known {
		t.Fatalf("coverage none must yield Unknown impact (known=false)")
	}
}

func TestImpactDomainModifier(t *testing.T) {
	// privilege 5 (count 11..50) * Critical factor (1.3) = 6.5.
	got, _ := impactScore(Context{Coverage: "full", Enabled: true, ControlledObjects: ip(20), DomainRiskLevel: "Critical"})
	if !almost(got, 6.5) {
		t.Fatalf("priv5 * Critical domain = %v, want 6.5", got)
	}
	// High factor (1.2): 5 * 1.2 = 6.0.
	got, _ = impactScore(Context{Coverage: "full", Enabled: true, ControlledObjects: ip(20), DomainRiskLevel: "High"})
	if !almost(got, 6.0) {
		t.Fatalf("priv5 * High domain = %v, want 6.0", got)
	}
	// Medium factor (1.1): 5 * 1.1 = 5.5.
	got, _ = impactScore(Context{Coverage: "full", Enabled: true, ControlledObjects: ip(20), DomainRiskLevel: "Medium"})
	if !almost(got, 5.5) {
		t.Fatalf("priv5 * Medium domain = %v, want 5.5", got)
	}
	// Normal/other factor (1.0): 5 * 1.0 = 5.0.
	got, _ = impactScore(Context{Coverage: "full", Enabled: true, ControlledObjects: ip(20)})
	if !almost(got, 5.0) {
		t.Fatalf("priv5 * Normal domain = %v, want 5.0", got)
	}
	// DA path 10 * Critical factor (1.3) saturates at 10 (not 13).
	got, _ = impactScore(Context{Coverage: "full", Enabled: true, DADomains: []string{"CORP"}, DomainRiskLevel: "Critical"})
	if !almost(got, 10.0) {
		t.Fatalf("DA * domain clamp = %v, want 10", got)
	}
	// Unenriched (Coverage "none") -> Impact still Unknown.
	if _, known := impactScore(Context{Coverage: "none", DomainRiskLevel: "Critical"}); known {
		t.Fatalf("unenriched impact must be Unknown, got known=true")
	}
}

func TestLevelMatrix(t *testing.T) {
	cases := []struct {
		exp, imp float64
		want     string
	}{
		{9, 9, "Critical"}, {6.5, 9, "Critical"}, {4.5, 9, "Critical"}, {2, 9, "High"}, // Impact Critical row
		{9, 6.5, "Critical"}, {6.5, 6.5, "High"}, {4.5, 6.5, "High"}, {2, 6.5, "Medium"}, // Impact High row
		{9, 4.5, "High"}, {6.5, 4.5, "High"}, {4.5, 4.5, "Medium"}, {2, 4.5, "Medium"}, // Impact Medium row
		{9, 2, "Medium"}, {6.5, 2, "Medium"}, {4.5, 2, "Low"}, {2, 2, "Low"}, // Impact Low row
	}
	for _, c := range cases {
		if got := LevelFromAxes(c.exp, c.imp, true, false); got != c.want {
			t.Errorf("matrix(exp=%v,imp=%v) = %q, want %q", c.exp, c.imp, got, c.want)
		}
	}
	// Unknown impact -> level from Exposure tier alone.
	if got := LevelFromAxes(6.5, 0, false, false); got != "High" {
		t.Errorf("unknown-impact level from exposure(6.5) = %q, want High", got)
	}
	if got := LevelFromAxes(2, 0, false, false); got != "Low" {
		t.Errorf("unknown-impact level from exposure(2) = %q, want Low", got)
	}
	// Hard override: cracked + DA -> Critical even with low exposure/impact.
	if got := LevelFromAxes(2, 2, true, true); got != "Critical" {
		t.Errorf("DA hard override = %q, want Critical", got)
	}
}

func TestScoreV2Result(t *testing.T) {
	// Strong cracked, no enrichment: Exposure=crackedFloor 3.0 (Low), Impact Unknown,
	// Level from Exposure alone (Low), Provisional=true, RiskScore=Exposure (legacy blend).
	r := Score(strong(), Context{Cracked: true, Coverage: "none"})
	if !almost(r.Exposure, 3.0) || r.ImpactKnown {
		t.Fatalf("strong/none: exposure=%v impactKnown=%v, want 3.0/false", r.Exposure, r.ImpactKnown)
	}
	if r.Level != "Low" || !r.Provisional {
		t.Fatalf("strong/none: level=%q provisional=%v, want Low/true", r.Level, r.Provisional)
	}
	if !almost(r.Score, 3.0) {
		t.Fatalf("legacy blend (unknown impact) = %v, want exposure 3.0", r.Score)
	}
	// Enriched, privileged: exposure 3.0, impact 7 (count 101), known.
	// RiskScore = round1(0.5*3.0 + 0.5*7.0) = 5.0.
	r2 := Score(strong(), Context{Cracked: true, Coverage: "full", Enabled: true, ControlledObjects: ip(101)})
	if !r2.ImpactKnown || !almost(r2.Impact, 7.0) || r2.Provisional {
		t.Fatalf("enriched: impact=%v known=%v provisional=%v", r2.Impact, r2.ImpactKnown, r2.Provisional)
	}
	if !almost(r2.Score, 5.0) {
		t.Fatalf("legacy blend = %v, want 5.0", r2.Score)
	}
	// Breakdown carries radar inputs (each factor's raw value).
	if !almost(r2.Breakdown.LengthPenalty, round2(lengthPenalty(20))) {
		t.Fatalf("breakdown LengthPenalty = %v", r2.Breakdown.LengthPenalty)
	}
	if !almost(r2.Breakdown.PrivilegeSubScore, 7.0) {
		t.Fatalf("breakdown PrivilegeSubScore = %v, want 7.0", r2.Breakdown.PrivilegeSubScore)
	}
}

func TestScoreDAHardOverride(t *testing.T) {
	// Cracked + own DA path: hard override -> Critical, HasDAPath true.
	r := Score(strong(), Context{Cracked: true, Coverage: "full", Enabled: true, DADomains: []string{"CORP"}})
	if !r.HasDAPath || r.Level != "Critical" {
		t.Fatalf("cracked+DA: hasDA=%v level=%q, want true/Critical", r.HasDAPath, r.Level)
	}
}

func TestRoastableBump(t *testing.T) {
	cases := []struct {
		name string
		c    Context
		want float64
	}{
		{"neither", Context{}, 0},
		{"spn only", Context{HasSPN: true}, 0.5},
		{"asrep only", Context{DontReqPreauth: true}, 0.75},
		{"both", Context{HasSPN: true, DontReqPreauth: true}, 1.25},
	}
	for _, tc := range cases {
		if got := roastableBump(tc.c); !almost(got, tc.want) {
			t.Errorf("roastableBump(%s) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestReuseBump(t *testing.T) {
	// boundaries: 0->0, 1->0.5, 2->0.75, 9->0.75, 10->1.0, 100->1.0 (ceiling 1.0; no higher bump tier)
	cases := []struct {
		shared int
		want   float64
	}{{0, 0}, {1, 0.5}, {2, 0.75}, {9, 0.75}, {10, 1.0}, {100, 1.0}, {5000, 1.0}}
	prev := -1.0
	for _, tc := range cases {
		got := reuseBump(tc.shared)
		if !almost(got, tc.want) {
			t.Errorf("reuseBump(%d) = %v, want %v", tc.shared, got, tc.want)
		}
		if got < prev {
			t.Errorf("reuseBump not monotone at %d: %v < %v", tc.shared, got, prev)
		}
		prev = got
	}
}

func TestReuseFloor(t *testing.T) {
	// floor is 0 below 100, 4.0 at 100-999, 5.0 at 1000+
	cases := []struct {
		shared int
		want   float64
	}{{0, 0}, {99, 0}, {100, 4.0}, {999, 4.0}, {1000, 5.0}, {50000, 5.0}}
	prev := -1.0
	for _, tc := range cases {
		got := reuseFloor(tc.shared)
		if !almost(got, tc.want) {
			t.Errorf("reuseFloor(%d) = %v, want %v", tc.shared, got, tc.want)
		}
		if got < prev {
			t.Errorf("reuseFloor not monotone at %d: %v < %v", tc.shared, got, prev)
		}
		prev = got
	}
}

func TestAgeBump(t *testing.T) {
	mk := func(d int) *int { return &d }
	cases := []struct {
		name string
		days *int
		want float64
	}{
		{"nil", nil, 0},
		{"0d_never_set", mk(0), 0}, // PwdLastSet=0 (never set / pre-Win2k): below 1yr -> 0
		{"364d", mk(364), 0},
		{"365d", mk(365), 0.25},
		{"729d", mk(729), 0.25},
		{"730d", mk(730), 0.5},
		{"1824d", mk(1824), 0.5},
		{"1825d", mk(1825), 0.75},
		{"6000d", mk(6000), 0.75},
	}
	for _, tc := range cases {
		if got := ageBump(tc.days); !almost(got, tc.want) {
			t.Errorf("ageBump(%s) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestRoastableFloor(t *testing.T) {
	cases := []struct {
		name string
		c    Context
		want float64
	}{
		{"neither", Context{}, 0},
		{"spn only (no floor; needs foothold)", Context{HasSPN: true}, 0},
		{"asrep only", Context{DontReqPreauth: true}, 3.0},
		{"both (asrep floors)", Context{HasSPN: true, DontReqPreauth: true}, 3.0},
	}
	for _, tc := range cases {
		if got := roastableFloor(tc.c); !almost(got, tc.want) {
			t.Errorf("roastableFloor(%s) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestExposureASREPFloor(t *testing.T) {
	// A strong, uncracked, zero-HIBP, no-reuse, AS-REP-roastable account must floor to 3.0 on the
	// roastable floor, plus the retained +0.75 AS-REP bump => 3.75 (the low/Medium border). Before
	// this change it was only the +0.75 bump => 0.75 (bottom-of-Low), which mis-triaged a foothold-
	// independent offline-crackable account as harmless.
	got := exposureScore(strong(), Context{Cracked: false, Coverage: "full", DontReqPreauth: true})
	if !almost(got, 3.75) {
		t.Fatalf("uncracked AS-REP exposure = %v, want 3.75", got)
	}
	// SPN-only (Kerberoast needs a foothold) gets NO floor: just the +0.5 bump => 0.5.
	gotSPN := exposureScore(strong(), Context{Cracked: false, Coverage: "full", HasSPN: true})
	if !almost(gotSPN, 0.5) {
		t.Fatalf("uncracked SPN-only exposure = %v, want 0.5", gotSPN)
	}
}

func TestVectorV2(t *testing.T) {
	got := Vector(strong(), Context{Cracked: true, Coverage: "none", PasswordExpires: "Unknown"})
	// EXP: strong cracked exposure=3.0 -> Low tier 'L'; IMP:U (unknown).
	// DR:U because Coverage=="none" -> domain risk does nothing while Impact is Unknown.
	if want := "C:C1/L:VL/D:N/SM:N/CM:U/EX:U/DA:N/CO:U/T0:N/S:0/RO:N/DR:U/HIBP:N/EXP:L/IMP:U"; got != want {
		t.Errorf("v2 strong vector = %q, want %q", got, want)
	}
	// Enriched privileged: CO from real count, IMP tier present.
	// count 101 -> privilegeSubScore 7, * Critical domain factor (1.3) = Impact min(10,9.1)=9.1
	// -> tier Critical 'C' (>=8). DR:C because Coverage is "full".
	got = Vector(strong(), Context{Cracked: true, Coverage: "full", Enabled: true, ControlledObjects: ip(101),
		DomainRiskLevel: "Critical", PasswordExpires: "Unknown"})
	if want := "C:C1/L:VL/D:N/SM:N/CM:U/EX:U/DA:N/CO:H/T0:N/S:0/RO:N/DR:C/HIBP:N/EXP:L/IMP:C"; got != want {
		t.Errorf("v2 enriched vector = %q, want %q", got, want)
	}
}
