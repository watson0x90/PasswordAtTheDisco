// Package metrics computes the redacted aggregate "dashboard bundle" — org-level
// and per-domain — from a plain []model.Account. It is the single producer of
// derived numbers consumed by the API, the SPA, and the report/CSV/JSON exporters.
// It emits no cleartext, no NT hashes, and no matched wordlist fragments.
package metrics

import (
	"time"

	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
)

// Metrics is the org-level dashboard bundle. (Phase 1: Summary + Matrix + Domains.
// Later plans add chart series and graph data as additional fields.)
type Metrics struct {
	Summary model.Summary   `json:"summary"`
	Matrix  Matrix          `json:"matrix"`
	Charts  ChartSeries     `json:"charts"`
	Reports ReportSeries    `json:"reports"`
	Domains []DomainMetrics `json:"domains"`
}

// Compute builds the org bundle over the full account set. now is injected (no
// time.Now here) for reproducible output.
func Compute(accounts []model.Account, now time.Time) Metrics {
	rep := model.BuildReport(accounts)
	return Metrics{
		Summary: model.Summarize(accounts, now),
		Matrix:  BuildMatrix(accounts),
		Charts:  buildChartSeries(accounts, now),
		Reports: buildReportSeries(rep, accounts),
		Domains: ComputeByDomain(accounts, now),
	}
}
