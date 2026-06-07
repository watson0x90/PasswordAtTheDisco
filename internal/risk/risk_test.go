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
	r := Score(strong(), Context{DADomains: []string{"CORP.INT"}, PasswordExpires: "Unknown"})
	if !r.HasDAPath || r.Level != "Critical" {
		t.Errorf("DA path should be Critical: %+v", r)
	}
	if Score(strong(), Context{PasswordExpires: "Unknown"}).HasDAPath {
		t.Error("no DADomains should mean no DA path")
	}
	r2 := Score(
		Analysis{ComplexityLabel: "mixedalphaspecialnum", PasswordLength: 20, IsCommon: true},
		Context{SharedWith: 1000, DADomains: []string{"CORP.INT"}, ControlledObjects: ip(2000),
			DomainRiskLevel: "Critical", HIBPBreachCount: 100000, PasswordExpires: "Unknown"},
	)
	if r2.Score < 0.0 || r2.Score > 10.0 {
		t.Errorf("final score out of range: %v", r2.Score)
	}
}

func TestVector(t *testing.T) {
	if got := Vector(strong(), Context{PasswordExpires: "Unknown"}); got != "C:C1/L:VL/D:N/SM:N/CM:U/EX:U/DA:N/CO:U/S:0/DR:U/HIBP:N" {
		t.Errorf("strong vector = %q", got)
	}
	high := Vector(
		Analysis{ComplexityLabel: "numeric", PasswordLength: 4, IsCommon: true, IsDictionaryWord: true,
			BannedWordsCount: 1, KeyboardPatternsCount: 1, SimilarMax: 0.95},
		Context{SharedWith: 1500, DADomains: []string{"A", "B", "C"}, ControlledObjects: ip(2000),
			DaysOutOfCompliance: ip(800), PasswordExpires: "No", DomainRiskLevel: "Critical", HIBPBreachCount: 200000},
	)
	if high != "C:C10/L:VS/D:CO+DW+BW+KP/SM:VH/CM:E/EX:N/DA:M/CO:E/S:4/DR:C/HIBP:C" {
		t.Errorf("high-risk vector = %q", high)
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
