package metrics

import (
	"sort"
	"time"

	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
)

// DomainMetrics is the per-domain bundle: the same Summary + Matrix as the org
// bundle, computed over the domain's account subset. Replaces the frontend
// domainScope.ts / domainData.ts recompute so the dashboard, the in-report section,
// and the standalone per-domain export all share one calculation.
type DomainMetrics struct {
	Domain  string        `json:"domain"`
	Summary model.Summary `json:"summary"`
	Matrix  Matrix        `json:"matrix"`
	Charts  ChartSeries   `json:"charts"`
}

// ComputeByDomain groups accounts by Domain and builds one DomainMetrics per domain,
// in deterministic alphabetical domain order.
func ComputeByDomain(accounts []model.Account, now time.Time) []DomainMetrics {
	byDomain := map[string][]model.Account{}
	for i := range accounts {
		d := accounts[i].Domain
		byDomain[d] = append(byDomain[d], accounts[i])
	}
	names := make([]string, 0, len(byDomain))
	for d := range byDomain {
		names = append(names, d)
	}
	sort.Strings(names)
	out := make([]DomainMetrics, 0, len(names))
	for _, d := range names {
		sub := byDomain[d]
		out = append(out, DomainMetrics{
			Domain:  d,
			Summary: model.Summarize(sub, now),
			Matrix:  BuildMatrix(sub),
			Charts:  buildChartSeries(sub, now),
		})
	}
	return out
}
