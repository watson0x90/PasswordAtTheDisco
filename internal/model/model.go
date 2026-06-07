// Package model defines the audit data types served by the API.
package model

import "time"

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

// Dataset is a full audit result ingested from the analysis engine.
type Dataset struct {
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
