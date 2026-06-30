package metrics

import (
	"sort"
	"strconv"

	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
)

// ExposureHeadline holds the three executive "blast radius" numbers (cracked&DA,
// cracked&breached, cross-domain reuse) mirroring web/src/exposure.ts exposureHeadline.
type ExposureHeadline struct {
	CrackedDA         int `json:"cracked_da"`
	CrackedHIBP       int `json:"cracked_hibp"`
	CrossDomainGroups int `json:"cross_domain_groups"`
	DomainsSpanned    int `json:"domains_spanned"`
}

// BridgeCluster represents a cross-domain reuse group with ranked metadata.
type BridgeCluster struct {
	Domains []string              `json:"domains"`
	Size    int                   `json:"size"`
	Cracked bool                  `json:"cracked"`
	HasDA   bool                  `json:"has_da"`
	HIBPMax int                   `json:"hibp_max"`
	Members []model.ReportAccount `json:"members"`
}

// CrossDomain groups cross-domain reuse clusters (>=2 distinct member domains)
// ranked by DA-first, then blast radius (size * distinct-domain-count), then
// first-member username for deterministic tie-breaking.
type CrossDomain struct {
	Clusters []BridgeCluster `json:"clusters"`
	Domains  []string        `json:"domains"`
}

// HIBPTriage splits HIBP-exposed accounts into tier1 (cracked) and tier2
// (not cracked), each sorted by breach count desc, then risk score desc,
// then username asc for deterministic tie-breaking.
type HIBPTriage struct {
	Tier1 []model.ReportAccount `json:"tier1"`
	Tier2 []model.ReportAccount `json:"tier2"`
}

// WorklistRow is one ranked remediation account with reason badges.
type WorklistRow struct {
	Account  AccountRef `json:"account"`
	Priority int        `json:"priority"`
	Reasons  []string   `json:"reasons"`
}

// ReportSeries holds the dashboard surfaces derived from the reuse-grouped report.
// (Later tasks add bridges, HIBP triage, worklist, and the two graphs.)
type ReportSeries struct {
	ExposureHeadline ExposureHeadline `json:"exposure_headline"`
	CrossDomain      CrossDomain      `json:"cross_domain"`
	HIBPTriage       HIBPTriage       `json:"hibp_triage"`
	Worklist         []WorklistRow    `json:"worklist"`
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
		CrossDomain:      CrossDomainBridges(rep),
		HIBPTriage:       HIBPTriageOf(rep),
		Worklist:         BlastRadius(accounts),
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// CrossDomainBridges ranks cross-domain (>=2 domain) reuse clusters: DA-first, then
// blast radius = size * distinct-domain-count, then first-member username for a
// deterministic tie-break (the TS relied on input order for ties).
func CrossDomainBridges(rep model.Report) CrossDomain {
	clusters := []BridgeCluster{}
	domains := map[string]bool{}
	groups := append(append([]model.ReuseGroup{}, rep.CrackedReuse...), rep.UncrackedReuse...)
	for _, g := range groups {
		doms := sortedKeys(groupDomains(g))
		if len(doms) < 2 {
			continue
		}
		for _, d := range doms {
			domains[d] = true
		}
		clusters = append(clusters, BridgeCluster{
			Domains: doms, Size: g.Size, Cracked: g.Cracked, HasDA: g.HasDAPathway,
			HIBPMax: g.HIBPBreachCount, Members: g.Members,
		})
	}
	sort.SliceStable(clusters, func(i, j int) bool {
		di, dj := boolInt(clusters[i].HasDA), boolInt(clusters[j].HasDA)
		if di != dj {
			return di > dj
		}
		bi := clusters[i].Size * len(clusters[i].Domains)
		bj := clusters[j].Size * len(clusters[j].Domains)
		if bi != bj {
			return bi > bj
		}
		return firstMemberName(clusters[i]) < firstMemberName(clusters[j])
	})
	return CrossDomain{Clusters: clusters, Domains: sortedKeys(domains)}
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func firstMemberName(c BridgeCluster) string {
	if len(c.Members) > 0 {
		return c.Members[0].Username
	}
	return ""
}

// HIBPTriageOf splits HIBP-exposed accounts into tier1 (cracked) and tier2
// (not cracked), each sorted by breach count desc, then risk score desc, then
// username asc (deterministic tie-break).
func HIBPTriageOf(rep model.Report) HIBPTriage {
	bySeverity := func(rows []model.ReportAccount) {
		sort.SliceStable(rows, func(i, j int) bool {
			if rows[i].HIBPBreachCount != rows[j].HIBPBreachCount {
				return rows[i].HIBPBreachCount > rows[j].HIBPBreachCount
			}
			if rows[i].RiskScore != rows[j].RiskScore {
				return rows[i].RiskScore > rows[j].RiskScore
			}
			return rows[i].Username < rows[j].Username
		})
	}
	var t HIBPTriage
	t.Tier1 = []model.ReportAccount{}
	t.Tier2 = []model.ReportAccount{}
	for i := range rep.HIBPExposed {
		a := rep.HIBPExposed[i]
		if a.Cracked {
			t.Tier1 = append(t.Tier1, a)
		} else {
			t.Tier2 = append(t.Tier2, a)
		}
	}
	bySeverity(t.Tier1)
	bySeverity(t.Tier2)
	return t
}

// BlastRadius is the ranked remediation worklist (mirrors exposure.ts blastRadius):
// DA +3, HIBP +2, Cracked +1, Shared +1; rows with priority>0 only; sorted by
// priority desc, then risk score desc, then username asc (deterministic).
func BlastRadius(accounts []model.Account) []WorklistRow {
	rows := []WorklistRow{}
	for i := range accounts {
		a := accounts[i]
		reasons := []string{}
		priority := 0
		if a.HasDAPathway() {
			priority += 3
			reasons = append(reasons, "DA")
		}
		if a.HIBPBreached {
			priority += 2
			reasons = append(reasons, "HIBP "+strconv.Itoa(a.HIBPBreachCount))
		}
		if a.Cracked {
			priority++
			reasons = append(reasons, "Cracked")
		}
		if a.SharedWith > 0 {
			priority++
			reasons = append(reasons, "Shared "+strconv.Itoa(a.SharedWith))
		}
		if !a.Enabled {
			reasons = append(reasons, "disabled")
		}
		if priority > 0 {
			rows = append(rows, WorklistRow{Account: toRef(a), Priority: priority, Reasons: reasons})
		}
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Priority != rows[j].Priority {
			return rows[i].Priority > rows[j].Priority
		}
		if rows[i].Account.RiskScore != rows[j].Account.RiskScore {
			return rows[i].Account.RiskScore > rows[j].Account.RiskScore
		}
		return rows[i].Account.Username < rows[j].Account.Username
	})
	return rows
}
