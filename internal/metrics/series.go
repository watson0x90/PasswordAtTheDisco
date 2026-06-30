package metrics

import (
	"math"
	"sort"
	"time"

	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
)

// Slice is a labeled, colored count for pie/donut charts.
type Slice struct {
	Name  string `json:"name"`
	Value int    `json:"value"`
	Color string `json:"color"`
}

// Bar is a labeled count for bar charts.
type Bar struct {
	Name  string `json:"name"`
	Value int    `json:"value"`
}

// Point is one (x,y) sample for scatter series.
type Point struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
}

// Series is a named, colored set of scatter points.
type Series struct {
	Name   string  `json:"name"`
	Color  string  `json:"color"`
	Points []Point `json:"points"`
}

// AxisFactor is a single exposure or impact breakdown factor with name, value, and color.
type AxisFactor struct {
	Name  string  `json:"name"`
	Value float64 `json:"value"`
	Color string  `json:"color"`
}

// TierFactorBars holds per-tier averaged exposure and impact factors.
type TierFactorBars struct {
	Tier        string       `json:"tier"`
	Color       string       `json:"color"`
	Exposure    []AxisFactor `json:"exposure"`
	Impact      []AxisFactor `json:"impact"`
	ImpactKnown bool         `json:"impact_known"`
}

// ChartSeries holds the account-derived chart data the dashboards render.
// Ported verbatim from web/src/insights.ts so the SPA and the exporters show
// the same numbers. (Later tasks add more fields.)
type ChartSeries struct {
	RiskDistribution         []Slice          `json:"risk_distribution"`
	HIBPSplit                []Slice          `json:"hibp_split"`
	ExpirationSplit          []Slice          `json:"expiration_split"`
	LengthBuckets            []Bar            `json:"length_buckets"`
	ScoreBuckets             []Bar            `json:"score_buckets"`
	SharingDistribution      []Bar            `json:"sharing_distribution"`
	ControlledObjectsBuckets []Bar            `json:"controlled_objects_buckets"`
	SimilarityBuckets        []Bar            `json:"similarity_buckets"`
	DAExposureByDomain       []Bar            `json:"da_exposure_by_domain"`
	ComplexityCounts         []Bar            `json:"complexity_counts"`
	HIBPVsRisk               []Series         `json:"hibp_vs_risk"`
	PasswordAgeBuckets       []Bar            `json:"password_age_buckets"`
	PasswordAgeScatter       []Series         `json:"password_age_scatter"`
	AxisFactorBars           []TierFactorBars `json:"axis_factor_bars"`
}

var riskHex = map[string]string{"Critical": "#fb7185", "High": "#fbbf24", "Medium": "#a3e635", "Low": "#22d3ee"}
var riskOrder = []string{"Critical", "High", "Medium", "Low"}

var levelColors = []struct{ name, color string }{
	{"Critical", "#fb7185"}, {"High", "#fbbf24"}, {"Medium", "#a3e635"}, {"Low", "#22d3ee"},
}

var complexityLabels = map[string]string{
	"loweralpha": "a–z", "upperalpha": "A–Z", "numeric": "0–9", "special": "!@#",
	"loweralphanum": "a–z 0–9", "upperalphanum": "A–Z 0–9", "mixedalpha": "a–z A–Z",
	"loweralphaspecial": "a–z !@#", "upperalphaspecial": "A–Z !@#", "specialnum": "0–9 !@#",
	"mixedalphanum": "a–z A–Z 0–9", "loweralphaspecialnum": "a–z 0–9 !@#",
	"mixedalphaspecial": "a–z A–Z !@#", "upperalphaspecialnum": "A–Z 0–9 !@#",
	"mixedalphaspecialnum": "a–z A–Z 0–9 !@#", "none": "(none)",
}

// RiskDistribution mirrors insights.ts riskDistribution: counts by risk level in
// fixed order, dropping absent levels; default color for unknown levels.
func RiskDistribution(accts []model.Account) []Slice {
	counts := map[string]int{}
	for i := range accts {
		if accts[i].RiskLevel != "" {
			counts[accts[i].RiskLevel]++
		}
	}
	out := []Slice{}
	for _, r := range riskOrder {
		if counts[r] == 0 {
			continue
		}
		c := riskHex[r]
		if c == "" {
			c = "#818cf8"
		}
		out = append(out, Slice{Name: r, Value: counts[r], Color: c})
	}
	return out
}

// HIBPSplit mirrors insights.ts hibpSplit: breached vs not, zero slices dropped.
func HIBPSplit(accts []model.Account) []Slice {
	breached := 0
	for i := range accts {
		if accts[i].HIBPBreached {
			breached++
		}
	}
	cand := []Slice{
		{Name: "Breached", Value: breached, Color: "#fb7185"},
		{Name: "Not in HIBP", Value: len(accts) - breached, Color: "#22d3ee"},
	}
	return dropZeroSlices(cand)
}

// ExpirationSplit mirrors insights.ts expirationSplit: expires / never / unknown,
// zero slices dropped.
func ExpirationSplit(accts []model.Account) []Slice {
	var expires, never, unknown int
	for i := range accts {
		switch {
		case accts[i].PwdNeverExpires != nil && *accts[i].PwdNeverExpires:
			never++
		case accts[i].PwdNeverExpires != nil && !*accts[i].PwdNeverExpires:
			expires++
		default:
			unknown++
		}
	}
	cand := []Slice{
		{Name: "Expires", Value: expires, Color: "#34d399"},
		{Name: "Never expires", Value: never, Color: "#fb7185"},
		{Name: "Unknown", Value: unknown, Color: "#475569"},
	}
	return dropZeroSlices(cand)
}

func dropZeroSlices(in []Slice) []Slice {
	out := []Slice{}
	for _, s := range in {
		if s.Value > 0 {
			out = append(out, s)
		}
	}
	return out
}

func LengthBuckets(accts []model.Account) []Bar {
	labels := []string{"1–7", "8–9", "10–11", "12–13", "14–15", "16+"}
	c := make([]int, 6)
	for i := range accts {
		if !accts[i].Cracked {
			continue
		}
		switch n := accts[i].PasswordLength; {
		case n <= 7:
			c[0]++
		case n <= 9:
			c[1]++
		case n <= 11:
			c[2]++
		case n <= 13:
			c[3]++
		case n <= 15:
			c[4]++
		default:
			c[5]++
		}
	}
	return labeledBars(labels, c, false)
}

func ScoreBuckets(accts []model.Account) []Bar {
	labels := []string{"0–2", "2–4", "4–6", "6–8", "8–10"}
	c := make([]int, 5)
	for i := range accts {
		s := accts[i].RiskScore
		switch {
		case s >= 8:
			c[4]++
		case s >= 6:
			c[3]++
		case s >= 4:
			c[2]++
		case s >= 2:
			c[1]++
		default:
			c[0]++
		}
	}
	return labeledBars(labels, c, false)
}

func SharingDistribution(accts []model.Account) []Bar {
	labels := []string{"0", "1", "2", "3–5", "6+"}
	c := make([]int, 5)
	for i := range accts {
		switch n := accts[i].SharedWith; {
		case n <= 0:
			c[0]++
		case n == 1:
			c[1]++
		case n == 2:
			c[2]++
		case n <= 5:
			c[3]++
		default:
			c[4]++
		}
	}
	return labeledBars(labels, c, false)
}

func ControlledObjectsBuckets(accts []model.Account) []Bar {
	labels := []string{"0", "1–10", "11–50", "51–100", "101–500", "500+"}
	c := make([]int, 6)
	for i := range accts {
		switch n := accts[i].Controlled; {
		case n <= 0:
			c[0]++
		case n <= 10:
			c[1]++
		case n <= 50:
			c[2]++
		case n <= 100:
			c[3]++
		case n <= 500:
			c[4]++
		default:
			c[5]++
		}
	}
	return labeledBars(labels, c, true)
}

func SimilarityBuckets(accts []model.Account) []Bar {
	labels := []string{"< 0.5", "0.5–0.7", "0.7–0.8", "0.8–0.9", "0.9+"}
	c := make([]int, 5)
	for i := range accts {
		s := accts[i].SimilarityScore
		if s <= 0 {
			continue
		}
		switch {
		case s < 0.5:
			c[0]++
		case s < 0.7:
			c[1]++
		case s < 0.8:
			c[2]++
		case s < 0.9:
			c[3]++
		default:
			c[4]++
		}
	}
	return labeledBars(labels, c, true)
}

// labeledBars zips labels+counts into Bars; when filterZero is true, drops bars
// whose value is 0 (mirrors the .filter(b=>b.value>0) on the relevant TS series).
func labeledBars(labels []string, counts []int, filterZero bool) []Bar {
	out := make([]Bar, 0, len(labels))
	for i, name := range labels {
		if filterZero && counts[i] == 0 {
			continue
		}
		out = append(out, Bar{Name: name, Value: counts[i]})
	}
	return out
}

// ComplexityLabel maps the engine complexity enum to character-class notation;
// unknown keys pass through unchanged (mirrors insights.ts complexityLabel).
func ComplexityLabel(key string) string {
	if v, ok := complexityLabels[key]; ok {
		return v
	}
	return key
}

// DAExposureByDomain counts DA-pathway accounts per domain, sorted by count desc
// then domain name asc (the name tie-break stabilizes Go's random map order; the
// TS relied on JS object insertion order for ties).
func DAExposureByDomain(accts []model.Account) []Bar {
	m := map[string]int{}
	for i := range accts {
		if accts[i].HasDAPathway() {
			m[accts[i].Domain]++
		}
	}
	return sortedBarsFromMap(m)
}

// ComplexityCounts counts cracked accounts per complexity class (labeled), sorted
// by count desc then label asc.
func ComplexityCounts(accts []model.Account) []Bar {
	m := map[string]int{}
	for i := range accts {
		if accts[i].Cracked && accts[i].Complexity != "" {
			m[ComplexityLabel(accts[i].Complexity)]++
		}
	}
	return sortedBarsFromMap(m)
}

func sortedBarsFromMap(m map[string]int) []Bar {
	out := make([]Bar, 0, len(m))
	for name, v := range m {
		out = append(out, Bar{Name: name, Value: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Value != out[j].Value {
			return out[i].Value > out[j].Value
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// HIBPVsRisk: per-level scatter of log10(hibp_breach_count+1) vs risk_score.
func HIBPVsRisk(accts []model.Account) []Series {
	out := []Series{}
	for _, lc := range levelColors {
		pts := []Point{}
		for i := range accts {
			if accts[i].RiskLevel != lc.name {
				continue
			}
			pts = append(pts, Point{X: math.Log10(float64(accts[i].HIBPBreachCount) + 1), Y: accts[i].RiskScore})
		}
		if len(pts) > 0 {
			out = append(out, Series{Name: lc.name, Color: lc.color, Points: pts})
		}
	}
	return out
}

// PasswordAgeBuckets: days since pwd_last_set bucketed; skips unset; filters empties.
func PasswordAgeBuckets(accts []model.Account, now time.Time) []Bar {
	labels := []string{"< 30d", "30–90d", "90–180d", "180–365d", "1–2y", "2y+"}
	c := make([]int, 6)
	nowUnix := now.Unix()
	for i := range accts {
		pls := accts[i].PwdLastSet
		if pls <= 0 {
			continue
		}
		days := float64(nowUnix-pls) / 86400.0
		switch {
		case days < 30:
			c[0]++
		case days < 90:
			c[1]++
		case days < 180:
			c[2]++
		case days < 365:
			c[3]++
		case days < 730:
			c[4]++
		default:
			c[5]++
		}
	}
	return labeledBars(labels, c, true)
}

// PasswordAgeScatter: per-level scatter of integer days-ago vs risk_score.
func PasswordAgeScatter(accts []model.Account, now time.Time) []Series {
	nowUnix := now.Unix()
	out := []Series{}
	for _, lc := range levelColors {
		pts := []Point{}
		for i := range accts {
			if accts[i].RiskLevel != lc.name || accts[i].PwdLastSet <= 0 {
				continue
			}
			pts = append(pts, Point{X: float64((nowUnix - accts[i].PwdLastSet) / 86400), Y: accts[i].RiskScore})
		}
		if len(pts) > 0 {
			out = append(out, Series{Name: lc.name, Color: lc.color, Points: pts})
		}
	}
	return out
}

// bdAvg averages a score breakdown field over a set of accounts, with 2-decimal rounding.
// Returns 0 if the set is empty.
func bdAvg(rows []model.Account, get func(*model.ScoreBreakdown) float64) float64 {
	if len(rows) == 0 {
		return 0
	}
	var sum float64
	for i := range rows {
		if rows[i].ScoreBreakdown != nil {
			sum += get(rows[i].ScoreBreakdown)
		}
	}
	return math.Round(sum/float64(len(rows))*100) / 100
}

type factorDef struct {
	name  string
	color string
	get   func(*model.ScoreBreakdown) float64
}

var expFactors = []factorDef{
	{"Weakness", "#fbbf24", func(b *model.ScoreBreakdown) float64 { return b.WeaknessScore }},
	{"HIBP floor", "#fb7185", func(b *model.ScoreBreakdown) float64 { return b.HIBPFloor }},
	{"Cracked floor", "#f472b6", func(b *model.ScoreBreakdown) float64 { return b.CrackedFloor }},
	{"Reuse", "#a78bfa", func(b *model.ScoreBreakdown) float64 { return b.ReuseBump }},
	{"Roastable", "#38bdf8", func(b *model.ScoreBreakdown) float64 { return b.RoastableBump }},
	{"Age", "#2dd4bf", func(b *model.ScoreBreakdown) float64 { return b.AgePenalty }},
}

var impFactors = []factorDef{
	{"Privilege", "#22d3ee", func(b *model.ScoreBreakdown) float64 { return b.PrivilegeSubScore }},
	{"DA path", "#fb7185", func(b *model.ScoreBreakdown) float64 { return b.DAComponent }},
	{"Domain", "#a3e635", func(b *model.ScoreBreakdown) float64 { return b.DomainModifier }},
}

// AxisFactorBars: per-tier averaged breakdown sub-scores. Impact group averages
// over enriched accounts only; impact_known=false when none in the tier is enriched.
func AxisFactorBars(accts []model.Account) []TierFactorBars {
	out := []TierFactorBars{}
	for _, lc := range levelColors {
		var group, enriched []model.Account
		for i := range accts {
			if accts[i].RiskLevel == lc.name && accts[i].ScoreBreakdown != nil {
				group = append(group, accts[i])
				if accts[i].ImpactKnown && accts[i].ImpactScore != nil {
					enriched = append(enriched, accts[i])
				}
			}
		}
		if len(group) == 0 {
			continue
		}
		exp := make([]AxisFactor, len(expFactors))
		for i, f := range expFactors {
			exp[i] = AxisFactor{Name: f.name, Value: bdAvg(group, f.get), Color: f.color}
		}
		imp := make([]AxisFactor, len(impFactors))
		for i, f := range impFactors {
			imp[i] = AxisFactor{Name: f.name, Value: bdAvg(enriched, f.get), Color: f.color}
		}
		out = append(out, TierFactorBars{Tier: lc.name, Color: lc.color, Exposure: exp, Impact: imp, ImpactKnown: len(enriched) > 0})
	}
	return out
}

// buildChartSeries assembles the account-derived chart series. now is threaded for
// age-based series added in later tasks.
func buildChartSeries(accounts []model.Account, now time.Time) ChartSeries {
	return ChartSeries{
		RiskDistribution:         RiskDistribution(accounts),
		HIBPSplit:                HIBPSplit(accounts),
		ExpirationSplit:          ExpirationSplit(accounts),
		LengthBuckets:            LengthBuckets(accounts),
		ScoreBuckets:             ScoreBuckets(accounts),
		SharingDistribution:      SharingDistribution(accounts),
		ControlledObjectsBuckets: ControlledObjectsBuckets(accounts),
		SimilarityBuckets:        SimilarityBuckets(accounts),
		DAExposureByDomain:       DAExposureByDomain(accounts),
		ComplexityCounts:         ComplexityCounts(accounts),
		HIBPVsRisk:               HIBPVsRisk(accounts),
		PasswordAgeBuckets:       PasswordAgeBuckets(accounts, now),
		PasswordAgeScatter:       PasswordAgeScatter(accounts, now),
		AxisFactorBars:           AxisFactorBars(accounts),
	}
}
