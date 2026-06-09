// Package model defines the audit data types served by the API.
package model

import (
	"strings"
	"time"
)

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
	GeneratedAt   time.Time      `json:"generated_at"`
}
