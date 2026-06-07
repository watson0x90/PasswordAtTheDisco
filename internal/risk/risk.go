// Package risk implements the CVSS-style password risk scoring engine: base,
// temporal, and environmental components, a cracked-password risk floor, the
// 0-10 score -> level mapping, and a CVSS-like vector string.
//
// Ported from legacy-python/core/scoring.py and core/vector.py. Numeric fields
// that the Python represented as int-or-"Unknown" are modeled here as *int
// (nil = unknown); DA pathways are a []string (empty = none).
package risk

import (
	"math"
	"strconv"
	"strings"

	"github.com/watson0x90/PasswordAtTheDisco/internal/hibp"
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

// Context holds account/environment signals consumed by scoring.
type Context struct {
	SharedWith          int      // accounts sharing this password (<=0 treated as none)
	DADomains           []string // domains with a Domain Admin pathway (empty = none)
	ControlledObjects   *int     // controlled object count; nil = unknown
	DaysOutOfCompliance *int     // nil = unknown
	PasswordExpires     string   // "No" | "Yes"; anything else = unknown
	DomainRiskLevel     string   // "Critical"|"High"|"Medium"|"Low"; else unknown
	HIBPBreachCount     int
}

// Breakdown is the per-component score detail (mirrors score_breakdown).
type Breakdown struct {
	BaseScore          float64
	ComplexityFactor   float64
	LengthFactor       float64
	DictionaryFactor   float64
	SimilarityFactor   float64
	TemporalScore      float64
	ComplianceFactor   float64
	ExpirationFactor   float64
	EnvironmentalScore float64
	PrivilegeFactor    float64
	ShareFactor        float64
	DomainFactor       float64
	HIBPFactor         float64
}

// Result is the full scoring output for one (cracked) account.
type Result struct {
	Score     float64 // 0-10, one decimal
	Level     string  // Critical | High | Medium | Low
	Vector    string  // CVSS-like vector string
	HasDAPath bool
	Breakdown Breakdown
}

// Score computes the full risk result for a cracked password.
func Score(a Analysis, c Context) Result {
	base, cf, lf, df, sf := baseScore(a)
	base = floorBase(base, a, c.HIBPBreachCount)
	temporal, compF, expF := temporalScore(base, c.DaysOutOfCompliance, c.PasswordExpires)
	hasDA := len(c.DADomains) > 0
	env, privF, shareF, domF, hibpF := environmentalScore(
		temporal, hasDA, c.ControlledObjects, c.SharedWith, c.DomainRiskLevel, c.HIBPBreachCount)
	final := round1(env)
	return Result{
		Score:     final,
		Level:     ComputeLevel(final, hasDA),
		Vector:    Vector(a, c),
		HasDAPath: hasDA,
		Breakdown: Breakdown{
			BaseScore:          round1(base),
			ComplexityFactor:   round2(cf),
			LengthFactor:       round2(lf),
			DictionaryFactor:   round2(df),
			SimilarityFactor:   round2(sf),
			TemporalScore:      round1(temporal),
			ComplianceFactor:   round2(compF),
			ExpirationFactor:   round2(expF),
			EnvironmentalScore: round1(env),
			PrivilegeFactor:    round2(privF),
			ShareFactor:        round2(shareF),
			DomainFactor:       round2(domF),
			HIBPFactor:         round2(hibpF),
		},
	}
}

// ComputeLevel maps a 0-10 score to a risk level. A Domain Admin pathway is
// always Critical regardless of score.
func ComputeLevel(score float64, hasDAPath bool) string {
	switch {
	case hasDAPath:
		return "Critical"
	case score >= 8.0:
		return "Critical"
	case score >= 6.0:
		return "High"
	case score >= 4.0:
		return "Medium"
	default:
		return "Low"
	}
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

func baseScore(a Analysis) (base, complexityF, lengthF, dictionaryF, similarityF float64) {
	complexityF = 1.0
	if v, ok := complexityFactors[a.ComplexityLabel]; ok {
		complexityF = v
	}
	lengthF = 1.0 / (1.0 + math.Exp(float64(a.PasswordLength-10)/2.0))

	if a.IsCommon {
		dictionaryF += 0.7
	}
	if a.IsDictionaryWord {
		dictionaryF += 0.5
	}
	dictionaryF += math.Min(0.8, 0.2*float64(a.BannedWordsCount))
	dictionaryF += math.Min(0.5, 0.1*float64(a.KeyboardPatternsCount))
	dictionaryF = math.Min(1.0, dictionaryF)

	similarityF = similarityFactor(a.SimilarMax)

	combined := complexityF*lengthF + dictionaryF + similarityF
	base = math.Min(10.0, combined*(10.0/4.0))
	return
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

// floorBase applies the evidence-based cracked-password risk floor: a cracked
// password always carries baseline risk, tiered by HIBP exposure / weakness.
func floorBase(base float64, a Analysis, hibpCount int) float64 {
	switch {
	case hibpCount >= 1000000:
		return math.Max(base, 8.0)
	case hibpCount >= 100000:
		return math.Max(base, 7.5)
	case hibpCount >= 10000 || a.IsCommon:
		return math.Max(base, 7.0)
	case hibpCount >= 1000 || a.IsDictionaryWord:
		return math.Max(base, 6.0)
	case hibpCount >= 100:
		return math.Max(base, 5.0)
	case hibpCount >= 10 || a.BannedWordsCount > 0 || a.KeyboardPatternsCount > 0:
		return math.Max(base, 4.0)
	case hibpCount > 0 || a.PasswordLength < 12:
		return math.Max(base, 3.0)
	default:
		return math.Max(base, 2.0)
	}
}

func temporalScore(base float64, days *int, expires string) (temporal, complianceF, expirationF float64) {
	if days == nil {
		complianceF = 0.8
	} else {
		complianceF = math.Min(1.0, 0.6+0.4*math.Min(1.0, float64(*days)/180.0))
	}
	switch expires {
	case "No":
		expirationF = 1.0
	case "Yes":
		expirationF = 0.85
	default: // Unknown / unset
		expirationF = 0.925
	}
	temporal = math.Min(10.0, base*complianceF*expirationF)
	return
}

func environmentalScore(temporal float64, hasDA bool, controlled *int, shared int, domainRisk string, hibpCount int) (env, privF, shareF, domF, hibpF float64) {
	privF = 1.0
	if hasDA {
		privF += 0.5
	}
	if controlled != nil {
		switch oc := *controlled; {
		case oc > 1000:
			privF += 0.5
		case oc > 500:
			privF += 0.4
		case oc > 100:
			privF += 0.3
		case oc > 50:
			privF += 0.2
		case oc > 10:
			privF += 0.1
		}
	}

	shareF = 1.0
	if shared > 0 {
		switch {
		case shared >= 1000:
			shareF += 0.5
		case shared >= 100:
			shareF += 0.4
		case shared >= 10:
			shareF += 0.3
		default:
			shareF += 0.2
		}
	}

	domF = domainFactor(domainRisk)
	hibpF = hibp.Factor(hibpCount) // identical tiers to the Python environmental hibp_factor

	env = math.Min(10.0, temporal*privF*shareF*domF*hibpF)
	return
}

func domainFactor(level string) float64 {
	switch level {
	case "Critical":
		return 1.3
	case "High":
		return 1.2
	case "Medium":
		return 1.1
	default: // Low, Unknown, "", anything else
		return 1.0
	}
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
	}
	return strings.Join(parts, "/")
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
