package metrics

import (
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

// ChartSeries holds the account-derived chart data the dashboards render.
// Ported verbatim from web/src/insights.ts so the SPA and the exporters show
// the same numbers. (Later tasks add more fields.)
type ChartSeries struct {
	RiskDistribution []Slice `json:"risk_distribution"`
	HIBPSplit        []Slice `json:"hibp_split"`
	ExpirationSplit  []Slice `json:"expiration_split"`
}

var riskHex = map[string]string{"Critical": "#fb7185", "High": "#fbbf24", "Medium": "#a3e635", "Low": "#22d3ee"}
var riskOrder = []string{"Critical", "High", "Medium", "Low"}

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

// buildChartSeries assembles the account-derived chart series. now is threaded for
// age-based series added in later tasks.
func buildChartSeries(accounts []model.Account, now time.Time) ChartSeries {
	_ = now // used by later tasks (age buckets/scatter)
	return ChartSeries{
		RiskDistribution: RiskDistribution(accounts),
		HIBPSplit:        HIBPSplit(accounts),
		ExpirationSplit:  ExpirationSplit(accounts),
	}
}
