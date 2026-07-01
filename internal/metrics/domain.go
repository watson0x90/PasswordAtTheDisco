package metrics

import (
	"sort"
	"time"

	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
)

// DomainMetrics is the per-domain bundle: the same Summary + Matrix as the org
// bundle, computed over the domain's account subset, plus report-derived surfaces
// (exposure headline, similarity graph, reuse clusters, DA paths) so the SPA can
// render per-domain views without client-side recomputation.
type DomainMetrics struct {
	Domain  string        `json:"domain"`
	Summary model.Summary `json:"summary"`
	Matrix  Matrix        `json:"matrix"`
	Charts  ChartSeries   `json:"charts"`
	Reports DomainReports `json:"reports"`
}

// ComputeByDomain groups accounts by Domain and builds one DomainMetrics per domain,
// in deterministic alphabetical domain order. The org-level report is built once and
// filtered per domain for report-derived surfaces (reuse clusters, DA paths, exposure
// headline) so that cross-domain reuse groups appear in each member domain's view.
func ComputeByDomain(accounts []model.Account, now time.Time) []DomainMetrics {
	// Build the org report once; per-domain report surfaces filter from it.
	rep := model.BuildReport(accounts)
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
			Reports: buildDomainReports(rep, d, sub),
		})
	}
	return out
}
