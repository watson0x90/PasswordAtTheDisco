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
	Controlled      int     `json:"controlled_object_count"`
	Enabled         bool    `json:"enabled"`
	// wordlist weakness signals (booleans/counts only -- never the matched word)
	IsCommon             bool `json:"is_common,omitempty"`
	IsDictionaryWord     bool `json:"is_dictionary_word,omitempty"`
	BannedWordCount      int  `json:"banned_word_count,omitempty"`
	KeyboardPatternCount int  `json:"keyboard_pattern_count,omitempty"`
}

func toReportAccount(a Account) ReportAccount {
	return ReportAccount{
		Username:             a.Username,
		Domain:               a.Domain,
		Cracked:              a.Cracked,
		PasswordLength:       a.PasswordLength,
		RiskLevel:            a.RiskLevel,
		RiskScore:            a.RiskScore,
		HIBPBreachCount:      a.HIBPBreachCount,
		SharedWith:           a.SharedWith,
		DADomains:            a.DADomains,
		Controlled:           a.Controlled,
		Enabled:              a.Enabled,
		IsCommon:             a.IsCommon,
		IsDictionaryWord:     a.IsDictionaryWord,
		BannedWordCount:      a.BannedWordCount,
		KeyboardPatternCount: a.KeyboardPatternCount,
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

// ViolationCounts is the number of accounts tripping each wordlist category.
type ViolationCounts struct {
	Common     int `json:"common"`
	Dictionary int `json:"dictionary"`
	Forbidden  int `json:"forbidden"`
	Keyboard   int `json:"keyboard"`
}

// Report is the Actionable section's set of redacted reports.
type Report struct {
	TotalAccounts   int             `json:"total_accounts"`
	CrackedCount    int             `json:"cracked_count"`
	UncrackedCount  int             `json:"uncracked_count"`
	DAPathways      []ReportAccount `json:"da_pathways"`
	Cracked         []ReportAccount `json:"cracked"`         // whose password has been cracked
	CrackedReuse    []ReuseGroup    `json:"cracked_reuse"`   // groups sharing a cracked password
	UncrackedReuse  []ReuseGroup    `json:"uncracked_reuse"` // groups sharing an uncracked NT hash
	HIBPExposed     []ReportAccount `json:"hibp_exposed"`    // accounts whose hash is in HIBP + the count
	WeakPasswords   []ReportAccount `json:"weak_passwords"`  // cracked pw matched a wordlist (common/dictionary/forbidden/keyboard)
	ViolationCounts ViolationCounts `json:"violation_counts"`
	// Lateral-movement escalation: accounts sharing a hash with a DA-pathway account.
	EscalatedBySharedDA []ReportAccount `json:"escalated_by_shared_da"`
	// Privilege hotspots: accounts controlling > 100 AD objects.
	HighControlled []ReportAccount `json:"high_controlled"`
	// Password age / never-expires accounts (from BloodHound enrichment).
	NeverExpires   []ReportAccount `json:"never_expires"`
	StalePasswords []ReportAccount `json:"stale_passwords"`
	// Kerberos attack surface.
	Kerberoastable []ReportAccount `json:"kerberoastable"`
	ASREPRoastable []ReportAccount `json:"asrep_roastable"`
}

// Term is one recurring wordlist match and how many accounts' passwords contain it.
type Term struct {
	Term  string `json:"term"`
	Count int    `json:"count"`
}

// Terms is the recurring forbidden words + keyboard patterns. The matched strings
// are cleartext fragments -- this is only ever returned by the lead-gated, audited
// terms endpoint, never persisted or exported. Common/dictionary are deliberately
// excluded: their "term" is the whole password.
type Terms struct {
	Forbidden []Term `json:"forbidden"`
	Keyboard  []Term `json:"keyboard"`
}

// AggregateTerms counts each distinct matched term once per account and returns the
// top-N of each kind, sorted by count (desc), then term (asc) for stability.
func AggregateTerms(accts []Account, topN int) Terms {
	tally := func(get func(Account) []string) []Term {
		counts := map[string]int{}
		for _, a := range accts {
			seen := map[string]bool{}
			for _, t := range get(a) {
				if t == "" || seen[t] {
					continue
				}
				seen[t] = true
				counts[t]++
			}
		}
		out := make([]Term, 0, len(counts))
		for t, c := range counts {
			out = append(out, Term{Term: t, Count: c})
		}
		sort.SliceStable(out, func(i, j int) bool {
			if out[i].Count != out[j].Count {
				return out[i].Count > out[j].Count
			}
			return out[i].Term < out[j].Term
		})
		if topN > 0 && len(out) > topN {
			out = out[:topN]
		}
		return out
	}
	return Terms{
		Forbidden: tally(func(a Account) []string { return a.BannedWords }),
		Keyboard:  tally(func(a Account) []string { return a.KeyboardPatterns }),
	}
}

// BuildReport groups accounts by NT hash and produces the redacted Actionable
// reports. Grouping is done here (server-side) because the NT hash is not exposed.
func BuildReport(accts []Account) Report {
	rep := Report{
		TotalAccounts:       len(accts),
		DAPathways:          []ReportAccount{},
		Cracked:             []ReportAccount{},
		CrackedReuse:        []ReuseGroup{},
		UncrackedReuse:      []ReuseGroup{},
		HIBPExposed:         []ReportAccount{},
		WeakPasswords:       []ReportAccount{},
		EscalatedBySharedDA: []ReportAccount{},
		HighControlled:      []ReportAccount{},
		NeverExpires:        []ReportAccount{},
		StalePasswords:      []ReportAccount{},
		Kerberoastable:      []ReportAccount{},
		ASREPRoastable:      []ReportAccount{},
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
		if a.HasObtainableDAPathway() {
			rep.DAPathways = append(rep.DAPathways, toReportAccount(a))
		}
		if a.IsWeak() {
			rep.WeakPasswords = append(rep.WeakPasswords, toReportAccount(a))
		}
		if a.IsCommon {
			rep.ViolationCounts.Common++
		}
		if a.IsDictionaryWord {
			rep.ViolationCounts.Dictionary++
		}
		if a.BannedWordCount > 0 {
			rep.ViolationCounts.Forbidden++
		}
		if a.KeyboardPatternCount > 0 {
			rep.ViolationCounts.Keyboard++
		}
		if a.EscalatedBySharedDA {
			rep.EscalatedBySharedDA = append(rep.EscalatedBySharedDA, toReportAccount(a))
		}
		if a.Controlled > 100 {
			rep.HighControlled = append(rep.HighControlled, toReportAccount(a))
		}
		if a.PwdNeverExpires != nil && *a.PwdNeverExpires {
			rep.NeverExpires = append(rep.NeverExpires, toReportAccount(a))
		}
		if a.DaysOutOfCompliance > 0 {
			rep.StalePasswords = append(rep.StalePasswords, toReportAccount(a))
		}
		if a.HasSPN != nil && *a.HasSPN {
			rep.Kerberoastable = append(rep.Kerberoastable, toReportAccount(a))
		}
		if a.DontReqPreauth != nil && *a.DontReqPreauth {
			rep.ASREPRoastable = append(rep.ASREPRoastable, toReportAccount(a))
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
	sort.SliceStable(rep.WeakPasswords, func(i, j int) bool { return rep.WeakPasswords[i].RiskScore > rep.WeakPasswords[j].RiskScore })
	sort.SliceStable(rep.EscalatedBySharedDA, func(i, j int) bool {
		return rep.EscalatedBySharedDA[i].RiskScore > rep.EscalatedBySharedDA[j].RiskScore
	})
	sort.SliceStable(rep.HighControlled, func(i, j int) bool { return rep.HighControlled[i].RiskScore > rep.HighControlled[j].RiskScore })
	sort.SliceStable(rep.NeverExpires, func(i, j int) bool { return rep.NeverExpires[i].RiskScore > rep.NeverExpires[j].RiskScore })
	sort.SliceStable(rep.StalePasswords, func(i, j int) bool { return rep.StalePasswords[i].RiskScore > rep.StalePasswords[j].RiskScore })
	sort.SliceStable(rep.Kerberoastable, func(i, j int) bool { return rep.Kerberoastable[i].RiskScore > rep.Kerberoastable[j].RiskScore })
	sort.SliceStable(rep.ASREPRoastable, func(i, j int) bool { return rep.ASREPRoastable[i].RiskScore > rep.ASREPRoastable[j].RiskScore })
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
