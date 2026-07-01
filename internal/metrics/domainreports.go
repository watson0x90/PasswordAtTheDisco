package metrics

import (
	"sort"

	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
)

// DomainReuseClusters holds the org reuse groups (cracked and uncracked) that touch
// a given domain. A cross-domain group appears in EACH member domain's view so that
// the per-domain UI can show the full blast radius of a shared credential.
// Members are model.ReportAccount (no cleartext password, no NT hash).
// Mirrors web/src/domainData.ts domainReuseClusters.
type DomainReuseClusters struct {
	Cracked   []model.ReuseGroup `json:"cracked"`
	Uncracked []model.ReuseGroup `json:"uncracked"`
}

// DomainReports holds the report-derived per-domain surfaces computed server-side so
// the SPA can render them directly from the bundle without client-side recomputation.
// Completely redaction-safe: no cleartext passwords, no NT hashes, no matched
// wordlist strings. Mirrors the four per-domain UI functions:
//   - web/src/exposure.ts         exposureHeadline
//   - web/src/domainData.ts       domainReuseClusters / domainDAPaths
//   - web/src/insights.ts         similarityNetwork
type DomainReports struct {
	ExposureHeadline ExposureHeadline      `json:"exposure_headline"`
	SimilarityGraph  Graph                 `json:"similarity_graph"`
	ReuseClusters    DomainReuseClusters   `json:"reuse_clusters"`
	DAPaths          []model.ReportAccount `json:"da_paths"`
}

// groupTouchesDomain reports whether any stored member of g is in domain.
// Mirrors the TS groupTouchesDomain predicate in domainScope.ts.
// Note: if a group is truncated at maxGroupMembers the check is limited to retained
// members — the same limitation applies on the client side, so this maintains parity.
func groupTouchesDomain(g model.ReuseGroup, domain string) bool {
	for _, m := range g.Members {
		if m.Domain == domain {
			return true
		}
	}
	return false
}

// domainReuseClustersOf returns the org reuse groups touching domain, sorted by size
// desc (matching the client's bySize comparator). Cross-domain groups appear in each
// member domain's view. Mirrors domainData.ts domainReuseClusters.
func domainReuseClustersOf(rep model.Report, domain string) DomainReuseClusters {
	filter := func(groups []model.ReuseGroup) []model.ReuseGroup {
		out := []model.ReuseGroup{}
		for _, g := range groups {
			if groupTouchesDomain(g, domain) {
				out = append(out, g)
			}
		}
		sort.SliceStable(out, func(i, j int) bool {
			return out[i].Size > out[j].Size
		})
		return out
	}
	return DomainReuseClusters{
		Cracked:   filter(rep.CrackedReuse),
		Uncracked: filter(rep.UncrackedReuse),
	}
}

// domainDAPathsOf returns the org DA-pathway accounts in domain, highest risk first.
// Mirrors domainData.ts domainDAPaths.
func domainDAPathsOf(rep model.Report, domain string) []model.ReportAccount {
	out := []model.ReportAccount{}
	for _, a := range rep.DAPathways {
		if a.Domain == domain {
			out = append(out, a)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].RiskScore > out[j].RiskScore
	})
	return out
}

// domainExposureHeadlineOf computes the per-domain exposure headline:
//   - crackedDA and crackedHIBP are counted from the domain's own accounts.
//   - crossDomainGroups and domainsSpanned are derived from org reuse groups that
//     TOUCH the domain (at least one member in it) AND span >=2 distinct member
//     domains — exactly matching how the client calls
//     exposureHeadline(domainAccounts, domainReport(orgReport, domain)).
func domainExposureHeadlineOf(domAccounts []model.Account, rep model.Report, domain string) ExposureHeadline {
	var h ExposureHeadline
	for i := range domAccounts {
		a := domAccounts[i]
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
		if !groupTouchesDomain(g, domain) {
			continue
		}
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

// buildDomainReports assembles the per-domain report-derived bundle for one domain.
// rep is the ORG-level report (built once in ComputeByDomain); reuse clusters and
// DA paths are filtered from it so cross-domain groups appear in each member domain.
func buildDomainReports(rep model.Report, domain string, domAccounts []model.Account) DomainReports {
	return DomainReports{
		ExposureHeadline: domainExposureHeadlineOf(domAccounts, rep, domain),
		SimilarityGraph:  SimilarityNetwork(domAccounts, 60),
		ReuseClusters:    domainReuseClustersOf(rep, domain),
		DAPaths:          domainDAPathsOf(rep, domain),
	}
}
