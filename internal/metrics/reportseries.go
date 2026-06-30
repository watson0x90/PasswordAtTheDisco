package metrics

import "github.com/watson0x90/PasswordAtTheDisco/internal/model"

// ExposureHeadline holds the three executive "blast radius" numbers (cracked&DA,
// cracked&breached, cross-domain reuse) mirroring web/src/exposure.ts exposureHeadline.
type ExposureHeadline struct {
	CrackedDA         int `json:"cracked_da"`
	CrackedHIBP       int `json:"cracked_hibp"`
	CrossDomainGroups int `json:"cross_domain_groups"`
	DomainsSpanned    int `json:"domains_spanned"`
}

// ReportSeries holds the dashboard surfaces derived from the reuse-grouped report.
// (Later tasks add bridges, HIBP triage, worklist, and the two graphs.)
type ReportSeries struct {
	ExposureHeadline ExposureHeadline `json:"exposure_headline"`
}

// groupDomains returns the distinct, member-derived domains of a reuse group.
// Mirrors the TS `new Set(g.members.map(m => m.domain))` (member-derived, so a
// truncated huge group counts only its retained members' domains — same as the API).
func groupDomains(g model.ReuseGroup) map[string]bool {
	doms := map[string]bool{}
	for i := range g.Members {
		doms[g.Members[i].Domain] = true
	}
	return doms
}

// ExposureHeadlineOf computes the exposure headline. accounts gives the cracked&DA
// / cracked&breached counts; rep gives the cross-domain reuse spread.
func ExposureHeadlineOf(accounts []model.Account, rep model.Report) ExposureHeadline {
	var h ExposureHeadline
	for i := range accounts {
		a := accounts[i]
		if a.Cracked && a.HasDAPathway() {
			h.CrackedDA++
		}
		if a.Cracked && a.HIBPBreached {
			h.CrackedHIBP++
		}
	}
	spanned := map[string]bool{}
	groups := append(append([]model.ReuseGroup{}, rep.CrackedReuse...), rep.UncrackedReuse...)
	for _, g := range groups {
		doms := groupDomains(g)
		if len(doms) >= 2 {
			h.CrossDomainGroups++
			for d := range doms {
				spanned[d] = true
			}
		}
	}
	h.DomainsSpanned = len(spanned)
	return h
}

// buildReportSeries assembles the report-derived bundle. (Grows in later tasks.)
func buildReportSeries(rep model.Report, accounts []model.Account) ReportSeries {
	return ReportSeries{
		ExposureHeadline: ExposureHeadlineOf(accounts, rep),
	}
}
