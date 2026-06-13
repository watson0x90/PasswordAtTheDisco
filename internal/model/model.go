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
	Username string `json:"username"`
	Domain   string `json:"domain"`
	Password string `json:"password,omitempty"`
	// NTHash is the account's NT hash, retained to detect password REUSE across
	// accounts -- including uncracked ones, since NTLM is unsalted (identical hash =
	// identical password). It is a pass-the-hash credential, so it is persisted only
	// in the encrypted store and stripped by Redacted() before any API response.
	NTHash          string  `json:"nt_hash,omitempty"`
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

// Redacted returns a copy with the cleartext password AND the NT hash removed --
// both are credentials (the hash enables pass-the-hash) and never leave the process.
func (a Account) Redacted() Account {
	a.Password = ""
	a.NTHash = ""
	return a
}

// HasDAPathway reports whether the account has a Domain Admin pathway.
func (a Account) HasDAPathway() bool {
	return a.DADomains != "" && a.DADomains != "None" && a.DADomains != "Unknown"
}

// emptyNTHash is the NT hash of an empty password. Every account with no password
// set shares it, which is "no password", not meaningful reuse -- so it is excluded.
const emptyNTHash = "31D6CFE0D16AE931B73C59D7E0C089C0"

// reuseKey normalizes an account's NT hash for reuse grouping. NTLM is unsalted, so
// the hash is the password-equality key -- this works for UNCRACKED accounts too.
// Returns "" (don't count) for a missing or empty-password hash.
func reuseKey(ntHash string) string {
	h := strings.ToUpper(strings.TrimSpace(ntHash))
	if h == "" || h == emptyNTHash {
		return ""
	}
	return h
}

// RecomputeSharing sets each account's SharedWith to the number of OTHER accounts in
// the set with the same NT hash -- cracked or not, across all domains. Because NTLM
// is unsalted, an identical hash means an identical password even when neither was
// cracked, so this catches reuse the cleartext-only pass would miss.
func RecomputeSharing(accts []Account) {
	byHash := make(map[string]int)
	for _, a := range accts {
		if k := reuseKey(a.NTHash); k != "" {
			byHash[k]++
		}
	}
	for i := range accts {
		if k := reuseKey(accts[i].NTHash); k != "" {
			accts[i].SharedWith = byHash[k] - 1
		} else {
			accts[i].SharedWith = 0
		}
	}
}

// EscalateSharedWithDA raises any account to Critical when it shares an NT hash with
// an account that has a Domain Admin pathway (e.g. a helpdesk account reusing a DA's
// password -- detected even if neither was cracked). The flagship lateral-movement
// signal. Run over a whole audit it catches cross-domain reuse. Idempotent.
func EscalateSharedWithDA(accts []Account) {
	daHashes := make(map[string]bool)
	for _, a := range accts {
		if a.HasDAPathway() {
			if k := reuseKey(a.NTHash); k != "" {
				daHashes[k] = true
			}
		}
	}
	if len(daHashes) == 0 {
		return
	}
	for i := range accts {
		a := &accts[i]
		k := reuseKey(a.NTHash)
		if k == "" || !daHashes[k] {
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
