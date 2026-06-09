// Package model defines the audit data types served by the API.
package model

import (
	"math"
	"strings"
	"time"
)

// Posture is the executive Security Posture Score and its components.
type Posture struct {
	Score      float64          `json:"score"`
	Rating     string           `json:"rating"`
	Likelihood string           `json:"likelihood"`
	Breakdown  PostureBreakdown `json:"breakdown"`
}

// PostureBreakdown is each posture component's weighted contribution.
type PostureBreakdown struct {
	Risk       float64 `json:"risk"`       // /40
	Strength   float64 `json:"strength"`   // /30
	Privilege  float64 `json:"privilege"`  // /15
	Compliance float64 `json:"compliance"` // /15
}

func round1(f float64) float64 { return math.Round(f*10) / 10 }

// PostureScore is the executive Security Posture Score (0-100) from the redacted
// account set: risk distribution (40) + password strength (30) + privilege
// exposure (15) + policy compliance (15). THIS IS THE SINGLE SOURCE OF TRUTH --
// the HTML report, audit diff, and the /api/summary the dashboard renders all use
// it, so the on-screen gauge can never drift from the exported report.
func PostureScore(accounts []Account) Posture {
	total := len(accounts)
	if total == 0 {
		return Posture{Rating: "No Data", Likelihood: "—"}
	}
	var crit, high, med, cracked, uncracked, da, viol int
	for _, a := range accounts {
		switch a.RiskLevel {
		case "Critical":
			crit++
		case "High":
			high++
		case "Medium":
			med++
		}
		if a.Cracked {
			cracked++
		} else {
			uncracked++
		}
		if a.HasDAPathway() {
			da++
		}
		if a.Cracked && !a.MeetsPolicy {
			viol++
		}
	}
	ft := float64(total)
	risk := math.Max(0, 100-float64(crit)/ft*200-float64(high)/ft*150-float64(med)/ft*50) / 100 * 40
	strength := 0.0
	if cracked+uncracked > 0 {
		strength = float64(uncracked) / float64(cracked+uncracked) * 30
	}
	priv := math.Max(0, 15-float64(da)/ft*100)
	comp := float64(total-viol) / ft * 15
	p := Posture{
		Score:     round1(risk + strength + priv + comp),
		Rating:    "Weak",
		Breakdown: PostureBreakdown{Risk: round1(risk), Strength: round1(strength), Privilege: round1(priv), Compliance: round1(comp)},
	}
	if p.Score >= 85 {
		p.Rating = "Strong"
	} else if p.Score >= 70 {
		p.Rating = "Fair"
	}
	p.Likelihood = "Low"
	if crit > 50 || da > 20 {
		p.Likelihood = "Very High"
	} else if crit > 20 || da > 10 {
		p.Likelihood = "High"
	} else if crit > 5 || da > 3 {
		p.Likelihood = "Medium"
	}
	return p
}

// Account is a single audited AD account. Password holds the cracked cleartext
// -- the sensitive field that must never leave the process unredacted without
// authorization.
type Account struct {
	Username        string  `json:"username"`
	Domain          string  `json:"domain"`
	Password        string  `json:"password,omitempty"`
	Cracked         bool    `json:"cracked"`
	PasswordLength  int     `json:"password_length"`
	RiskLevel       string  `json:"risk_level"`
	RiskScore       float64 `json:"risk_score"`
	RiskVector      string  `json:"risk_vector"`
	HIBPBreached    bool    `json:"hibp_breached"`
	HIBPBreachCount int     `json:"hibp_breach_count"`
	DADomains       string  `json:"da_domains"`
	Controlled      int     `json:"controlled_object_count"`
	SharedWith      int     `json:"shared_with"`
	Enabled         bool    `json:"enabled"`
	MeetsPolicy     bool    `json:"meets_policy"`
	Complexity      string  `json:"complexity,omitempty"`
}

// Redacted returns a copy with the cleartext password removed.
func (a Account) Redacted() Account {
	a.Password = ""
	return a
}

// HasDAPathway reports whether the account has a Domain Admin pathway.
func (a Account) HasDAPathway() bool {
	return a.DADomains != "" && a.DADomains != "None" && a.DADomains != "Unknown"
}

// RecomputeSharing sets each cracked account's SharedWith to the number of OTHER
// accounts in the set that use the same cleartext password. Run over a whole
// audit, this captures cross-domain reuse (the per-domain engine pass cannot).
func RecomputeSharing(accts []Account) {
	byPw := make(map[string]int)
	for _, a := range accts {
		if a.Cracked && a.Password != "" {
			byPw[a.Password]++
		}
	}
	for i := range accts {
		if a := &accts[i]; a.Cracked && a.Password != "" {
			a.SharedWith = byPw[a.Password] - 1
		}
	}
}

// EscalateSharedWithDA raises any account to Critical when it shares a cracked
// password with an account that has a Domain Admin pathway (e.g. a helpdesk
// account reusing a DA's password) -- the flagship lateral-movement signal. Run
// over a whole audit it catches cross-domain reuse. Idempotent: safe to re-run.
func EscalateSharedWithDA(accts []Account) {
	daPasswords := make(map[string]bool)
	for _, a := range accts {
		if a.Cracked && a.Password != "" && a.HasDAPathway() {
			daPasswords[a.Password] = true
		}
	}
	if len(daPasswords) == 0 {
		return
	}
	for i := range accts {
		a := &accts[i]
		if !a.Cracked || a.Password == "" || !daPasswords[a.Password] {
			continue
		}
		if a.RiskLevel != "Critical" {
			a.RiskLevel = "Critical"
		}
		if a.RiskScore < 9.0 {
			a.RiskScore = 9.0
		}
		if !strings.Contains(a.RiskVector, "SHARED-DA") {
			a.RiskVector += "/SHARED-DA"
		}
	}
}

// Dataset is a full audit result ingested from the analysis engine. Name lets a
// CLI ingest label the audit it creates.
type Dataset struct {
	Name        string    `json:"name,omitempty"`
	GeneratedAt time.Time `json:"generated_at"`
	Accounts    []Account `json:"accounts"`
}

// Summary is non-sensitive aggregate stats for the dashboard.
type Summary struct {
	TotalAccounts int            `json:"total_accounts"`
	Cracked       int            `json:"cracked"`
	HIBPBreached  int            `json:"hibp_breached"`
	DAPathways    int            `json:"da_pathways"`
	RiskCounts    map[string]int `json:"risk_counts"`
	Posture       Posture        `json:"posture"`
	GeneratedAt   time.Time      `json:"generated_at"`
}
