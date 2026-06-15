package model

import "sort"

// maxGroupMembers caps the members listed per reuse group, so one pathologically
// large group can't bloat the report. The full Size is still reported.
const maxGroupMembers = 200

// ReportAccount is a redacted account row for the Actionable reports -- no cleartext
// password, no NT hash (both are credentials that never leave the process).
type ReportAccount struct {
	Username        string  `json:"username"`
	Domain          string  `json:"domain"`
	Cracked         bool    `json:"cracked"`
	PasswordLength  int     `json:"password_length,omitempty"`
	RiskLevel       string  `json:"risk_level"`
	RiskScore       float64 `json:"risk_score"`
	HIBPBreachCount int     `json:"hibp_breach_count"`
	SharedWith      int     `json:"shared_with"`
	DADomains       string  `json:"da_domains,omitempty"`
}

func toReportAccount(a Account) ReportAccount {
	return ReportAccount{
		Username:        a.Username,
		Domain:          a.Domain,
		Cracked:         a.Cracked,
		PasswordLength:  a.PasswordLength,
		RiskLevel:       a.RiskLevel,
		RiskScore:       a.RiskScore,
		HIBPBreachCount: a.HIBPBreachCount,
		SharedWith:      a.SharedWith,
		DADomains:       a.DADomains,
	}
}

// ReuseGroup is a set of accounts sharing one NT hash -- i.e. the same password,
// known (cracked) or not. The hash itself is never exposed; GroupID is opaque.
type ReuseGroup struct {
	GroupID         int             `json:"group_id"`
	Size            int             `json:"size"`    // total accounts sharing the password
	Cracked         bool            `json:"cracked"` // is the shared password known?
	PasswordLength  int             `json:"password_length,omitempty"`
	HIBPBreachCount int             `json:"hibp_breach_count"` // times this password appears in HIBP breaches
	HasDAPathway    bool            `json:"has_da_pathway"`    // a member can reach Domain Admin (lateral path to DA)
	Domains         int             `json:"domains"`           // distinct domains -> cross-domain reuse
	Truncated       bool            `json:"truncated,omitempty"`
	Members         []ReportAccount `json:"members"`
}

// Report is the Actionable section's set of redacted reports.
type Report struct {
	TotalAccounts  int             `json:"total_accounts"`
	CrackedCount   int             `json:"cracked_count"`
	UncrackedCount int             `json:"uncracked_count"`
	DAPathways     []ReportAccount `json:"da_pathways"`
	Cracked        []ReportAccount `json:"cracked"`         // whose password has been cracked
	CrackedReuse   []ReuseGroup    `json:"cracked_reuse"`   // groups sharing a cracked password
	UncrackedReuse []ReuseGroup    `json:"uncracked_reuse"` // groups sharing an uncracked NT hash
	HIBPExposed    []ReportAccount `json:"hibp_exposed"`    // accounts whose hash is in HIBP + the count
}

// BuildReport groups accounts by NT hash and produces the redacted Actionable
// reports. Grouping is done here (server-side) because the NT hash is not exposed.
func BuildReport(accts []Account) Report {
	rep := Report{
		TotalAccounts:  len(accts),
		DAPathways:     []ReportAccount{},
		Cracked:        []ReportAccount{},
		CrackedReuse:   []ReuseGroup{},
		UncrackedReuse: []ReuseGroup{},
		HIBPExposed:    []ReportAccount{},
	}

	byHash := map[string][]Account{}
	var hashOrder []string
	for _, a := range accts {
		if a.Cracked {
			rep.CrackedCount++
			rep.Cracked = append(rep.Cracked, toReportAccount(a))
		} else {
			rep.UncrackedCount++
		}
		if a.HIBPBreachCount > 0 {
			rep.HIBPExposed = append(rep.HIBPExposed, toReportAccount(a))
		}
		if a.HasDAPathway() {
			rep.DAPathways = append(rep.DAPathways, toReportAccount(a))
		}
		if k := reuseKey(a.NTHash); k != "" {
			if _, ok := byHash[k]; !ok {
				hashOrder = append(hashOrder, k)
			}
			byHash[k] = append(byHash[k], a)
		}
	}

	gid := 0
	for _, k := range hashOrder {
		members := byHash[k]
		if len(members) < 2 {
			continue
		}
		gid++
		g := ReuseGroup{GroupID: gid, Size: len(members), HIBPBreachCount: members[0].HIBPBreachCount}
		domains := map[string]bool{}
		for i, m := range members {
			if m.Cracked {
				g.Cracked = true
				g.PasswordLength = m.PasswordLength
			}
			if m.HasDAPathway() {
				g.HasDAPathway = true
			}
			domains[m.Domain] = true
			if i < maxGroupMembers {
				g.Members = append(g.Members, toReportAccount(m))
			}
		}
		g.Domains = len(domains)
		if len(members) > maxGroupMembers {
			g.Truncated = true
		}
		if g.Cracked {
			rep.CrackedReuse = append(rep.CrackedReuse, g)
		} else {
			rep.UncrackedReuse = append(rep.UncrackedReuse, g)
		}
	}

	sort.SliceStable(rep.Cracked, func(i, j int) bool { return rep.Cracked[i].RiskScore > rep.Cracked[j].RiskScore })
	sort.SliceStable(rep.DAPathways, func(i, j int) bool { return rep.DAPathways[i].RiskScore > rep.DAPathways[j].RiskScore })
	sort.SliceStable(rep.HIBPExposed, func(i, j int) bool { return rep.HIBPExposed[i].HIBPBreachCount > rep.HIBPExposed[j].HIBPBreachCount })
	sortGroups := func(g []ReuseGroup) {
		sort.SliceStable(g, func(i, j int) bool {
			if g[i].Size != g[j].Size {
				return g[i].Size > g[j].Size
			}
			return g[i].HIBPBreachCount > g[j].HIBPBreachCount
		})
	}
	sortGroups(rep.CrackedReuse)
	sortGroups(rep.UncrackedReuse)
	return rep
}
