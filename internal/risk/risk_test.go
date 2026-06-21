package risk

import (
	"math"
	"testing"
)

func almost(a, b float64) bool { return math.Abs(a-b) < 1e-9 }
func ip(n int) *int            { return &n }

// strong: a long, complex password (lowest intrinsic risk).
func strong() Analysis { return Analysis{ComplexityLabel: "mixedalphaspecialnum", PasswordLength: 20} }

func TestComputeLevel(t *testing.T) {
	cases := []struct {
		score float64
		want  string
	}{
		{10.0, "Critical"}, {8.0, "Critical"}, {7.9, "High"}, {6.0, "High"},
		{5.9, "Medium"}, {4.0, "Medium"}, {3.9, "Low"}, {0.0, "Low"},
	}
	for _, c := range cases {
		if got := ComputeLevel(c.score, false); got != c.want {
			t.Errorf("ComputeLevel(%v) = %q, want %q", c.score, got, c.want)
		}
	}
	if ComputeLevel(0.0, true) != "Critical" || ComputeLevel(3.9, true) != "Critical" {
		t.Error("a DA pathway must force Critical regardless of score")
	}
}

func TestBaseScore(t *testing.T) {
	base, cf, _, _, _ := baseScore(strong())
	if base >= 1.0 {
		t.Errorf("strong long password base = %v, want < 1.0", base)
	}
	if !almost(cf, 0.2) {
		t.Errorf("strongest complexity factor = %v, want 0.2", cf)
	}
	if _, cf, _, _, _ := baseScore(Analysis{ComplexityLabel: "not-real", PasswordLength: 20}); !almost(cf, 1.0) {
		t.Errorf("unknown complexity factor = %v, want 1.0", cf)
	}
	// length factor is a sigmoid: L=10 -> 1/(1+e^0) = 0.5
	if _, _, lf, _, _ := baseScore(Analysis{ComplexityLabel: "numeric", PasswordLength: 10}); !almost(lf, 0.5) {
		t.Errorf("length factor at L=10 = %v, want 0.5", lf)
	}
	// dictionary factor caps at 1.0
	if _, _, _, df, _ := baseScore(Analysis{ComplexityLabel: "loweralpha", PasswordLength: 4,
		IsCommon: true, IsDictionaryWord: true, BannedWordsCount: 10, KeyboardPatternsCount: 10}); !almost(df, 1.0) {
		t.Errorf("dictionary factor = %v, want 1.0 (capped)", df)
	}
	// base score capped at 10
	if base, _, _, _, _ := baseScore(Analysis{ComplexityLabel: "none", PasswordLength: 1,
		IsCommon: true, IsDictionaryWord: true, BannedWordsCount: 50, KeyboardPatternsCount: 50, SimilarMax: 1.0}); base > 10.0 {
		t.Errorf("base score = %v, want <= 10", base)
	}
}

func TestSimilarityTiers(t *testing.T) {
	cases := []struct {
		sim, want float64
	}{{0.95, 0.6}, {0.85, 0.4}, {0.75, 0.2}, {0.5, 0.0}}
	for _, c := range cases {
		_, _, _, _, sf := baseScore(Analysis{ComplexityLabel: "mixedalphaspecialnum", PasswordLength: 20, SimilarMax: c.sim})
		if !almost(sf, c.want) {
			t.Errorf("similarity %.2f -> factor %v, want %v", c.sim, sf, c.want)
		}
	}
}

func TestTemporalScore(t *testing.T) {
	if _, cf, _ := temporalScore(10.0, nil, "No"); !almost(cf, 0.8) {
		t.Errorf("unknown compliance factor = %v, want 0.8", cf)
	}
	for expires, want := range map[string]float64{"No": 1.0, "Yes": 0.85, "Unknown": 0.925} {
		if _, _, ef := temporalScore(10.0, ip(0), expires); !almost(ef, want) {
			t.Errorf("expiration %q -> %v, want %v", expires, ef, want)
		}
	}
	temporal, comp, exp := temporalScore(10.0, nil, "Unknown")
	if !almost(temporal, math.Min(10.0, 10.0*comp*exp)) {
		t.Errorf("temporal not product of factors: %v", temporal)
	}
	low, _, _ := temporalScore(10.0, ip(10), "No")
	high, _, _ := temporalScore(10.0, ip(180), "No")
	if !(high > low) {
		t.Errorf("more days out of compliance should increase risk: %v !> %v", high, low)
	}
}

func TestEnvironmentalScore(t *testing.T) {
	if _, p, _, _, _ := environmentalScore(5.0, true, nil, 0, "", 0); !almost(p, 1.5) {
		t.Errorf("DA privilege factor = %v, want 1.5", p)
	}
	for _, c := range []struct {
		n    int
		want float64
	}{{5, 1.0}, {50, 1.1}, {100, 1.2}, {500, 1.3}, {1000, 1.4}, {2000, 1.5}} {
		if _, p, _, _, _ := environmentalScore(5.0, false, ip(c.n), 0, "", 0); !almost(p, c.want) {
			t.Errorf("controlled=%d -> priv %v, want %v", c.n, p, c.want)
		}
	}
	for _, c := range []struct {
		n    int
		want float64
	}{{0, 1.0}, {5, 1.2}, {10, 1.3}, {100, 1.4}, {1000, 1.5}} {
		if _, _, s, _, _ := environmentalScore(5.0, false, nil, c.n, "", 0); !almost(s, c.want) {
			t.Errorf("shared=%d -> share %v, want %v", c.n, s, c.want)
		}
	}
	for _, c := range []struct {
		lvl  string
		want float64
	}{{"Critical", 1.3}, {"High", 1.2}, {"Medium", 1.1}, {"Low", 1.0}, {"Unknown", 1.0}, {"", 1.0}} {
		if _, _, _, d, _ := environmentalScore(5.0, false, nil, 0, c.lvl, 0); !almost(d, c.want) {
			t.Errorf("domain=%q -> %v, want %v", c.lvl, d, c.want)
		}
	}
	for _, c := range []struct {
		n    int
		want float64
	}{{0, 1.0}, {50, 1.1}, {100, 1.2}, {1000, 1.3}, {10000, 1.4}, {100000, 1.5}} {
		if _, _, _, _, h := environmentalScore(5.0, false, nil, 0, "", c.n); !almost(h, c.want) {
			t.Errorf("hibp=%d -> %v, want %v", c.n, h, c.want)
		}
	}
	if env, _, _, _, _ := environmentalScore(10.0, true, ip(2000), 1000, "Critical", 100000); env > 10.0 {
		t.Errorf("environmental score = %v, want <= 10", env)
	}
}

func TestScoreFlooring(t *testing.T) {
	cases := []struct {
		name      string
		a         Analysis
		hibp      int
		wantFloor float64
	}{
		{"ultra-extreme", strong(), 1000000, 8.0},
		{"extreme", strong(), 100000, 7.5},
		{"common", Analysis{ComplexityLabel: "mixedalphaspecialnum", PasswordLength: 20, IsCommon: true}, 0, 7.0},
		{"dictionary", Analysis{ComplexityLabel: "mixedalphaspecialnum", PasswordLength: 20, IsDictionaryWord: true}, 0, 6.0},
		{"strong-cracked", strong(), 0, 2.0},
	}
	for _, c := range cases {
		r := Score(c.a, Context{HIBPBreachCount: c.hibp, PasswordExpires: "Unknown"})
		if r.Breakdown.BaseScore < c.wantFloor {
			t.Errorf("%s: base = %v, want >= %v", c.name, r.Breakdown.BaseScore, c.wantFloor)
		}
	}
}

func TestScoreDAPathAndRange(t *testing.T) {
	// v2: a CRACKED account with a confirmed DA path is the hard-override -> Critical.
	r := Score(strong(), Context{Cracked: true, Coverage: "full", Enabled: true,
		DADomains: []string{"CORP.INT"}, PasswordExpires: "Unknown"})
	if !r.HasDAPath || r.Level != "Critical" {
		t.Errorf("cracked + DA path should be Critical: %+v", r)
	}
	if Score(strong(), Context{Cracked: true, Coverage: "none", PasswordExpires: "Unknown"}).HasDAPath {
		t.Error("no DADomains should mean no DA path")
	}
	r2 := Score(
		Analysis{ComplexityLabel: "mixedalphaspecialnum", PasswordLength: 20, IsCommon: true},
		Context{Cracked: true, Coverage: "full", Enabled: true, SharedWith: 1000,
			DADomains: []string{"CORP.INT"}, ControlledObjects: ip(2000),
			DomainRiskLevel: "Critical", HIBPBreachCount: 100000, PasswordExpires: "Unknown"},
	)
	if r2.Score < 0.0 || r2.Score > 10.0 {
		t.Errorf("legacy score out of range: %v", r2.Score)
	}
	if r2.Exposure < 0.0 || r2.Exposure > 10.0 || r2.Impact < 0.0 || r2.Impact > 10.0 {
		t.Errorf("axes out of range: exposure=%v impact=%v", r2.Exposure, r2.Impact)
	}
}

func TestVector(t *testing.T) {
	// v2 vector now carries EXP:/IMP: trailers. Strong, uncracked, unenriched
	// (Coverage "none" -> Impact Unknown -> IMP:U; Exposure 0 -> EXP:L).
	if got := Vector(strong(), Context{Coverage: "none", PasswordExpires: "Unknown"}); got != "C:C1/L:VL/D:N/SM:N/CM:U/EX:U/DA:N/CO:U/S:0/DR:U/HIBP:N/EXP:L/IMP:U" {
		t.Errorf("strong vector = %q", got)
	}
	// High-risk cracked + enriched: every code maxed; Exposure 9.0 (HIBP 2e5) -> EXP:C,
	// Impact 10 (DA path, clamped with Critical modifier) -> IMP:C.
	high := Vector(
		Analysis{ComplexityLabel: "numeric", PasswordLength: 4, IsCommon: true, IsDictionaryWord: true,
			BannedWordsCount: 1, KeyboardPatternsCount: 1, SimilarMax: 0.95},
		Context{Cracked: true, Coverage: "full", Enabled: true, SharedWith: 1500,
			DADomains: []string{"A", "B", "C"}, ControlledObjects: ip(2000),
			DaysOutOfCompliance: ip(800), PasswordExpires: "No", DomainRiskLevel: "Critical", HIBPBreachCount: 200000},
	)
	if high != "C:C10/L:VS/D:CO+DW+BW+KP/SM:VH/CM:E/EX:N/DA:M/CO:E/S:4/DR:C/HIBP:C/EXP:C/IMP:C" {
		t.Errorf("high-risk vector = %q", high)
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
	if !almost(reuse, 3.5) {
		t.Fatalf("reuse bump = %v, want 3.5", reuse)
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
	// Uncracked + reuse + roastable bump still applies.
	c2 := Context{Cracked: false, Coverage: "full", SharedWith: 3, DontReqPreauth: true}
	if got := exposureScore(Analysis{}, c2); !almost(got, 1.0) {
		t.Fatalf("uncracked bumps-only exposure = %v, want 1.0", got)
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
	// privilege 5 (count 11..50) + Critical domain (+1.0) = 6.0.
	got, _ := impactScore(Context{Coverage: "full", Enabled: true, ControlledObjects: ip(20), DomainRiskLevel: "Critical"})
	if !almost(got, 6.0) {
		t.Fatalf("priv5 + Critical domain = %v, want 6.0", got)
	}
	// DA path 10 + Critical modifier clamps at 10 (not 11).
	got, _ = impactScore(Context{Coverage: "full", Enabled: true, DADomains: []string{"CORP"}, DomainRiskLevel: "Critical"})
	if !almost(got, 10.0) {
		t.Fatalf("DA + domain clamp = %v, want 10", got)
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

func TestVectorV2(t *testing.T) {
	got := Vector(strong(), Context{Cracked: true, Coverage: "none", PasswordExpires: "Unknown"})
	// EXP: strong cracked exposure=3.0 -> Low tier 'L'; IMP:U (unknown).
	if want := "C:C1/L:VL/D:N/SM:N/CM:U/EX:U/DA:N/CO:U/S:0/DR:U/HIBP:N/EXP:L/IMP:U"; got != want {
		t.Errorf("v2 strong vector = %q, want %q", got, want)
	}
	// Enriched privileged: CO from real count, IMP tier present.
	// count 101 -> privilegeSubScore 7, + Critical domain modifier (+1.0) = Impact 8.0
	// -> tier Critical 'C' (the plan's literal "IMP:H" predated the domain modifier;
	// derived from the real impactScore here).
	got = Vector(strong(), Context{Cracked: true, Coverage: "full", Enabled: true, ControlledObjects: ip(101),
		DomainRiskLevel: "Critical", PasswordExpires: "Unknown"})
	if want := "C:C1/L:VL/D:N/SM:N/CM:U/EX:U/DA:N/CO:H/S:0/DR:C/HIBP:N/EXP:L/IMP:C"; got != want {
		t.Errorf("v2 enriched vector = %q, want %q", got, want)
	}
}
