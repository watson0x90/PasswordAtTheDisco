// Package risk implements the v2 two-axis password risk scoring engine: an
// Exposure axis ("how easily is this credential compromised?") and an Impact axis
// ("blast radius if it is?"), a derived Level from a 2D matrix, an extended
// per-factor Breakdown, and a CVSS-like vector string.
//
// Numeric fields that the source data represented as int-or-"Unknown" are modeled
// here as *int (nil = unknown); DA pathways are a []string (empty = none).
package risk

import (
	"math"
	"strconv"
	"strings"
)

// Analysis holds intrinsic password characteristics (from the password-analysis
// stage) consumed by scoring.
type Analysis struct {
	ComplexityLabel       string
	PasswordLength        int
	IsCommon              bool
	IsDictionaryWord      bool // is_exactly_dictionary_word
	BannedWordsCount      int
	KeyboardPatternsCount int
	SimilarMax            float64 // highest similarity to another password (0 if none)
}

// Context holds account/environment signals consumed by scoring. v2: Exposure is
// always computed; Impact needs Enabled/ControlsTier0/Coverage and is Unknown when
// coverage == "none". Cracked distinguishes the weakness-bearing path from uncracked.
type Context struct {
	Cracked           bool     // true = password known (weakness penalties apply)
	SharedWith        int      // accounts sharing this password (>0 => reuse bump)
	DADomains         []string // domains with a Domain Admin pathway (empty = none)
	ControlledObjects *int     // TRUE controlled-object count (env.Count); nil = unknown
	ControlsTier0     bool     // controls a Tier-0/DA-equivalent object (DCSync/DA group/AdminSDHolder/KRBTGT)
	Enabled           bool     // false => Impact capped at 2.0 (can't authenticate)
	HasSPN            bool     // Kerberoastable (Exposure roastable bump)
	DontReqPreauth    bool     // AS-REP roastable (Exposure roastable bump)
	Coverage          string   // "full" | "none"; "none" => Impact Unknown
	DomainRiskLevel   string   // "Critical"|"High"|"Medium"|"Low"; else unknown
	HIBPBreachCount   int
	// Retained for the vector string only (no longer scored); see Vector().
	DaysOutOfCompliance *int
	PasswordExpires     string
}

// Breakdown is the per-axis score detail plus every raw per-factor input the
// sub-project C leave-one-out radar needs (Δ_k = Score(all) − Score(factor k neutralized)).
type Breakdown struct {
	// Exposure axis (v2)
	ExposureScore     float64 `json:"exposure_score"`
	WeaknessScore     float64 `json:"weakness_score"`
	LengthPenalty     float64 `json:"length_penalty"`
	ComplexityPenalty float64 `json:"complexity_penalty"`
	DictPenalty       float64 `json:"dict_penalty"`
	SimPenalty        float64 `json:"sim_penalty"`
	HIBPFloor         float64 `json:"hibp_floor"`
	CrackedFloor      float64 `json:"cracked_floor"`
	ReuseBump         float64 `json:"reuse_bump"`
	RoastableBump     float64 `json:"roastable_bump"`
	// Impact axis (v2)
	ImpactScore       float64 `json:"impact_score"`
	PrivilegeSubScore float64 `json:"privilege_sub_score"`
	DAComponent       float64 `json:"da_component"`
	DomainModifier    float64 `json:"domain_modifier"`
	EnabledGated      bool    `json:"enabled_gated"`
}

// Result is the full v2 scoring output for one account.
type Result struct {
	Exposure    float64 // 0-10, one decimal
	Impact      float64 // 0-10, one decimal; meaningless when !ImpactKnown
	ImpactKnown bool
	Score       float64 // legacy back-compat blend (de-emphasized)
	Level       string  // from the 2D matrix
	Provisional bool    // true when ImpactKnown is false (level from Exposure alone)
	Vector      string
	HasDAPath   bool
	Breakdown   Breakdown
}

// Score computes the full v2 risk result. Per-account only: it does NOT compute
// shared-hash-to-DA (an audit-level pass in internal/store).
func Score(a Analysis, c Context) Result {
	exp := round1(exposureScore(a, c))
	impRaw, known := impactScore(c)
	imp := round1(impRaw)
	hasDA := len(c.DADomains) > 0
	daOverride := c.Cracked && hasDA
	level := LevelFromAxes(exp, imp, known, daOverride)

	var legacy float64
	if known {
		legacy = round1(0.5*exp + 0.5*imp)
	} else {
		legacy = exp
	}

	var reuse, roast float64
	if c.SharedWith > 0 {
		reuse = 0.5
	}
	if c.HasSPN || c.DontReqPreauth {
		roast = 0.5
	}

	return Result{
		Exposure:    exp,
		Impact:      imp,
		ImpactKnown: known,
		Score:       legacy,
		Level:       level,
		Provisional: !known,
		Vector:      Vector(a, c),
		HasDAPath:   hasDA,
		Breakdown: Breakdown{
			ExposureScore:     exp,
			WeaknessScore:     round2(weaknessScore(a)),
			LengthPenalty:     round2(lengthPenalty(a.PasswordLength)),
			ComplexityPenalty: round2(complexityPenalty(a.ComplexityLabel)),
			DictPenalty:       round2(dictPenalty(a)),
			SimPenalty:        round2(simPenalty(a.SimilarMax)),
			HIBPFloor:         hibpExposureFloor(c.HIBPBreachCount),
			CrackedFloor:      crackedFloor(a, c.Cracked),
			ReuseBump:         reuse,
			RoastableBump:     roast,
			ImpactScore:       imp,
			PrivilegeSubScore: privilegeSubScore(c.ControlledObjects, c.ControlsTier0),
			DAComponent:       daComponent(c.DADomains),
			DomainModifier:    domainModifier(c.DomainRiskLevel),
			EnabledGated:      known && !c.Enabled,
		},
	}
}

// tierOf maps an axis value [0,10] to its tier index: 0=Critical,1=High,2=Medium,3=Low.
func tierOf(v float64) int {
	switch {
	case v >= 8.0:
		return 0
	case v >= 6.0:
		return 1
	case v >= 4.0:
		return 2
	default:
		return 3
	}
}

// levelMatrix[impactTier][exposureTier] -> Level. Rows = Impact, cols = Exposure,
// each Critical(0)/High(1)/Medium(2)/Low(3). Mirrors the design spec table.
var levelMatrix = [4][4]string{
	{"Critical", "Critical", "Critical", "High"}, // Impact Critical
	{"Critical", "High", "High", "Medium"},       // Impact High
	{"High", "High", "Medium", "Medium"},         // Impact Medium
	{"Medium", "Medium", "Low", "Low"},           // Impact Low
}

// LevelFromAxes derives the overall Level. When impactKnown is false the level is
// taken from the Exposure tier alone (the caller flags it provisional). A cracked
// account with a confirmed DA path (daOverride) is always Critical.
func LevelFromAxes(exposure, impact float64, impactKnown, daOverride bool) string {
	if daOverride {
		return "Critical"
	}
	if !impactKnown {
		switch tierOf(exposure) {
		case 0:
			return "Critical"
		case 1:
			return "High"
		case 2:
			return "Medium"
		default:
			return "Low"
		}
	}
	return levelMatrix[tierOf(impact)][tierOf(exposure)]
}

var complexityFactors = map[string]float64{
	"mixedalphaspecialnum": 0.2,
	"mixedalphaspecial":    0.3,
	"upperalphaspecialnum": 0.4,
	"loweralphaspecialnum": 0.5,
	"mixedalphanum":        0.6,
	"specialnum":           0.7,
	"mixedalpha":           0.7,
	"upperalphaspecial":    0.7,
	"loweralphaspecial":    0.8,
	"upperalphanum":        0.8,
	"loweralphanum":        0.9,
	"special":              0.9,
	"upperalpha":           0.95,
	"loweralpha":           0.95,
	"numeric":              1.0,
	"none":                 1.0,
}

func similarityFactor(max float64) float64 {
	switch {
	case max >= 0.9:
		return 0.6
	case max >= 0.8:
		return 0.4
	case max >= 0.7:
		return 0.2
	default:
		return 0
	}
}

// --- Exposure axis (v2): "how easily is this credential compromised?" ---

// exposureWeights sum to 1.0; each penalty is an INDEPENDENT [0,1] term, so
// complexity is no longer nullified by length (the v1 product bug).
const (
	wLen  = 0.30
	wCx   = 0.20
	wDict = 0.35
	wSim  = 0.15
)

// lengthPenalty is the v1 logistic, kept verbatim (higher = shorter = worse), [0,1].
func lengthPenalty(length int) float64 {
	return 1.0 / (1.0 + math.Exp(float64(length-10)/2.0))
}

// complexityPenalty maps complexityF in [0.2,1.0] -> [0,1] (higher = less complex = worse).
// In complexityFactors a LOWER factor means a STRONGER password (mixedalphaspecialnum=0.2
// is strongest, numeric=1.0 weakest), so risk rises WITH the factor. The penalty therefore
// scales directly with cf: (cf-0.2)/0.8.
func complexityPenalty(label string) float64 {
	cf := 1.0
	if v, ok := complexityFactors[label]; ok {
		cf = v
	}
	p := (cf - 0.2) / 0.8
	return clamp01(p)
}

// dictPenalty is the v1 additive dictionary/common/banned/keyboard term, clamped [0,1].
func dictPenalty(a Analysis) float64 {
	var d float64
	if a.IsCommon {
		d += 0.7
	}
	if a.IsDictionaryWord {
		d += 0.5
	}
	d += math.Min(0.8, 0.2*float64(a.BannedWordsCount))
	d += math.Min(0.5, 0.1*float64(a.KeyboardPatternsCount))
	return clamp01(d)
}

// simPenalty normalizes the v1 similarity term (raw max 0.6) to [0,1].
func simPenalty(simMax float64) float64 {
	return clamp01(similarityFactor(simMax) / 0.6)
}

// weaknessScore is the cracked-only weighted sum of bounded penalties, scaled x10.
func weaknessScore(a Analysis) float64 {
	return 10.0 * (wLen*lengthPenalty(a.PasswordLength) +
		wCx*complexityPenalty(a.ComplexityLabel) +
		wDict*dictPenalty(a) +
		wSim*simPenalty(a.SimilarMax))
}

// hibpExposureFloor is the SINGLE HIBP channel (kills the v1 triple-count).
func hibpExposureFloor(count int) float64 {
	switch {
	case count >= 1000000:
		return 9.0
	case count >= 100000:
		return 8.5
	case count >= 10000:
		return 8.0
	case count >= 1000:
		return 7.0
	case count >= 100:
		return 6.0
	case count >= 10:
		return 5.0
	case count >= 1:
		return 4.5
	default:
		return 0
	}
}

// crackedFloor: cracking is itself exposure, applied ONCE.
func crackedFloor(a Analysis, cracked bool) float64 {
	switch {
	case cracked && a.PasswordLength < 8:
		return 4.0
	case cracked:
		return 3.0
	default:
		return 0
	}
}

// exposureScore is the per-account Exposure axis [0,10].
func exposureScore(a Analysis, c Context) float64 {
	var floor float64
	if c.Cracked {
		floor = math.Max(weaknessScore(a), math.Max(hibpExposureFloor(c.HIBPBreachCount), crackedFloor(a, true)))
	} else {
		// Uncracked: password unknown, no weakness signals.
		floor = hibpExposureFloor(c.HIBPBreachCount)
	}
	var bump float64
	if c.SharedWith > 0 {
		bump += 0.5
	}
	if c.HasSPN || c.DontReqPreauth {
		bump += 0.5
	}
	return math.Min(10.0, floor+bump)
}

func clamp01(x float64) float64 {
	if x < 0 {
		return 0
	}
	if x > 1 {
		return 1
	}
	return x
}

// --- Impact axis (v2): "blast radius if this credential is compromised?" ---

// privilegeSubScore maps the TRUE controlled-objects count to [0,10]. Control of a
// Tier-0/DA-equivalent object is the maximum regardless of count.
func privilegeSubScore(controlled *int, controlsTier0 bool) float64 {
	if controlsTier0 {
		return 10
	}
	if controlled == nil {
		return 0
	}
	switch oc := *controlled; {
	case oc > 1000:
		return 9
	case oc > 500:
		return 8
	case oc > 100:
		return 7
	case oc > 50:
		return 6
	case oc > 10:
		return 5
	case oc > 0:
		return 3
	default:
		return 0
	}
}

// daComponent is 10 when THIS account has its own confirmed DA path, else 0.
// (Shared-hash-to-DA inheritance is an audit-level pass, not here.)
func daComponent(daDomains []string) float64 {
	if len(daDomains) > 0 {
		return 10
	}
	return 0
}

func domainModifier(level string) float64 {
	switch level {
	case "Critical":
		return 1.0
	case "High":
		return 0.6
	case "Medium":
		return 0.3
	default:
		return 0
	}
}

// impactScore returns the per-account Impact axis and whether it is known. When
// coverage == "none" (not BloodHound-enriched) Impact is Unknown (known=false) and
// the returned number is meaningless.
func impactScore(c Context) (score float64, known bool) {
	if c.Coverage == "none" {
		return 0, false
	}
	priv := privilegeSubScore(c.ControlledObjects, c.ControlsTier0)
	da := daComponent(c.DADomains)
	imp := math.Min(10.0, math.Max(priv, da)+domainModifier(c.DomainRiskLevel))
	if !c.Enabled {
		imp = math.Min(imp, 2.0) // disabled can't authenticate
	}
	return imp, true
}

// Vector returns the CVSS-like risk vector string:
// "C:.../L:.../D:.../SM:.../CM:.../EX:.../DA:.../CO:.../S:.../DR:.../HIBP:...".
func Vector(a Analysis, c Context) string {
	parts := []string{
		"C:" + complexityCode(a.ComplexityLabel),
		"L:" + lengthCode(a.PasswordLength),
		"D:" + dictCode(a),
		"SM:" + similarityCode(a.SimilarMax),
		"CM:" + complianceCode(c.DaysOutOfCompliance),
		"EX:" + expireCode(c.PasswordExpires),
		"DA:" + daCode(c.DADomains),
		"CO:" + controlledCode(c.ControlledObjects),
		"S:" + shareCode(c.SharedWith),
		"DR:" + domainCode(c.DomainRiskLevel),
		"HIBP:" + hibpCode(c.HIBPBreachCount),
		"EXP:" + axisCode(exposureScore(a, c)),
		"IMP:" + impactCode(c),
	}
	return strings.Join(parts, "/")
}

// axisCode maps an axis value to its tier letter (C/H/M/L).
func axisCode(v float64) string {
	switch tierOf(v) {
	case 0:
		return "C"
	case 1:
		return "H"
	case 2:
		return "M"
	default:
		return "L"
	}
}

// impactCode is the Impact tier letter, or "U" when Impact is Unknown.
func impactCode(c Context) string {
	v, known := impactScore(c)
	if !known {
		return "U"
	}
	return axisCode(v)
}

var complexityCodes = map[string]string{
	"mixedalphaspecialnum": "C1",
	"mixedalphaspecial":    "C2",
	"upperalphaspecialnum": "C3",
	"loweralphaspecialnum": "C4",
	"mixedalphanum":        "C5",
	"specialnum":           "C6",
	"mixedalpha":           "C6",
	"upperalphaspecial":    "C6",
	"loweralphaspecial":    "C7",
	"upperalphanum":        "C7",
	"loweralphanum":        "C8",
	"special":              "C8",
	"upperalpha":           "C9",
	"loweralpha":           "C9",
	"numeric":              "C10",
	"none":                 "C10",
}

func complexityCode(label string) string {
	if v, ok := complexityCodes[label]; ok {
		return v
	}
	return "C10"
}

func lengthCode(n int) string {
	switch {
	case n >= 16:
		return "VL"
	case n >= 12:
		return "L"
	case n >= 8:
		return "M"
	case n >= 6:
		return "S"
	default:
		return "VS"
	}
}

func dictCode(a Analysis) string {
	var issues []string
	if a.IsCommon {
		issues = append(issues, "CO")
	}
	if a.IsDictionaryWord {
		issues = append(issues, "DW")
	}
	if a.BannedWordsCount > 0 {
		issues = append(issues, "BW")
	}
	if a.KeyboardPatternsCount > 0 {
		issues = append(issues, "KP")
	}
	if len(issues) == 0 {
		return "N"
	}
	return strings.Join(issues, "+")
}

func similarityCode(max float64) string {
	switch {
	case max >= 0.9:
		return "VH"
	case max >= 0.8:
		return "H"
	case max >= 0.7:
		return "M"
	default:
		return "N"
	}
}

func complianceCode(days *int) string {
	if days == nil {
		return "U"
	}
	switch d := *days; {
	case d <= 0:
		return "N"
	case d <= 30:
		return "L"
	case d <= 90:
		return "M"
	case d <= 365:
		return "H"
	case d <= 730:
		return "VH"
	default:
		return "E"
	}
}

func expireCode(expires string) string {
	switch expires {
	case "No":
		return "N"
	case "Yes":
		return "Y"
	default:
		return "U"
	}
}

func daCode(daDomains []string) string {
	switch {
	case len(daDomains) > 2:
		return "M"
	case len(daDomains) >= 1:
		return "Y"
	default:
		return "N"
	}
}

func controlledCode(controlled *int) string {
	if controlled == nil {
		return "U"
	}
	switch oc := *controlled; {
	case oc > 1000:
		return "E"
	case oc > 500:
		return "VH"
	case oc > 100:
		return "H"
	case oc > 50:
		return "M+"
	case oc > 10:
		return "M"
	default:
		return "L"
	}
}

func shareCode(n int) string {
	if n <= 0 {
		return "0"
	}
	scale := 1 + int(math.Log10(float64(n)))
	if scale > 4 {
		scale = 4
	}
	return strconv.Itoa(scale)
}

func domainCode(level string) string {
	switch level {
	case "Critical":
		return "C"
	case "High":
		return "H"
	case "Medium":
		return "M"
	case "Low":
		return "L"
	default:
		return "U"
	}
}

func hibpCode(n int) string {
	switch {
	case n == 0:
		return "N"
	case n < 10:
		return "L"
	case n < 100:
		return "M"
	case n < 1000:
		return "H"
	case n < 10000:
		return "VH"
	case n < 100000:
		return "E"
	default:
		return "C"
	}
}

func round1(x float64) float64 { return math.Round(x*10) / 10 }
func round2(x float64) float64 { return math.Round(x*100) / 100 }
