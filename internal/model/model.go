// Package model defines the audit data types served by the API.
package model

import (
	"math"
	"sort"
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

// EstimateBreachImpact produces a simplified breach-impact estimate for the
// executive summary, mirroring the legacy Python report's approach.
func EstimateBreachImpact(crit, da int) BreachImpact {
	var bi BreachImpact
	switch {
	case crit > 50 || da > 20:
		bi.Probability = "Very High"
		bi.ProbabilityPct = ">75%"
	case crit > 20 || da > 10:
		bi.Probability = "High"
		bi.ProbabilityPct = "50-75%"
	case crit > 5 || da > 3:
		bi.Probability = "Medium"
		bi.ProbabilityPct = "25-50%"
	default:
		bi.Probability = "Low"
		bi.ProbabilityPct = "<25%"
	}
	switch {
	case crit > 50:
		bi.EstimatedCost = "$1M – $5M+"
		bi.RecoveryTime = "6–12 months"
	case crit > 20:
		bi.EstimatedCost = "$500K – $1M"
		bi.RecoveryTime = "3–6 months"
	case crit > 5:
		bi.EstimatedCost = "$100K – $500K"
		bi.RecoveryTime = "1–3 months"
	default:
		bi.EstimatedCost = "$50K – $100K"
		bi.RecoveryTime = "2–4 weeks"
	}
	return bi
}

// SimilarPeer is another account whose cracked password is a near-duplicate of
// this account's (Levenshtein ratio). Username/Domain/Score only — never the
// password — so it is safe to expose and survives Redacted().
type SimilarPeer struct {
	Username string  `json:"username"`
	Domain   string  `json:"domain"`
	Score    float64 `json:"score"`
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
	// Coverage is the per-account BloodHound coverage state: "full" (enriched) or
	// "none" (not enriched). Drives the Unknown-Impact state and the coverage
	// banner. Descriptive, not a credential — survives Redacted().
	Coverage string `json:"coverage,omitempty"`
	// v2 two-axis scoring. ExposureScore (always computed). ImpactScore is nil when
	// Impact is Unknown (no BloodHound enrichment); ImpactKnown mirrors that. Percentile
	// is the within-audit triage rank [0,1] assigned by ComputePercentiles; it is
	// always computed for every account in a loaded audit, so 0.0 is a valid lowest
	// rank and must serialize (no omitempty). All are descriptive, not credentials —
	// they survive Redacted().
	ExposureScore float64  `json:"exposure_score"`
	ImpactScore   *float64 `json:"impact_score"`
	ImpactKnown   bool     `json:"impact_known"`
	Percentile    float64  `json:"percentile"`
	MeetsPolicy   bool     `json:"meets_policy"`
	Complexity    string   `json:"complexity,omitempty"`
	// Wordlist weakness signals (cracked accounts only). Counts/booleans are
	// redacted-safe; the matched substrings live in BannedWords / KeyboardPatterns
	// below (see their comment) and are stripped by Redacted().
	IsCommon             bool `json:"is_common,omitempty"`              // exact match in the common-password list
	IsDictionaryWord     bool `json:"is_dictionary_word,omitempty"`     // exactly a dictionary word
	BannedWordCount      int  `json:"banned_word_count,omitempty"`      // forbidden words found as substrings
	KeyboardPatternCount int  `json:"keyboard_pattern_count,omitempty"` // keyboard patterns found as substrings
	// BannedWords / KeyboardPatterns are the ACTUAL matched substrings -- cleartext
	// fragments. Like Password/NTHash they are persisted only in the encrypted store
	// and stripped by Redacted(); they leave the process only via the lead-gated,
	// audited terms endpoint.
	BannedWords      []string `json:"banned_words,omitempty"`
	KeyboardPatterns []string `json:"keyboard_patterns,omitempty"`

	// Enrichment-derived temporal/privilege signals. Stored so the UI can surface
	// them without decoding the risk vector. PwdLastSet is Unix epoch seconds (or 0
	// if unknown); PwdNeverExpires and DaysOutOfCompliance are from BloodHound.
	PwdLastSet          int64 `json:"pwd_last_set,omitempty"`
	PwdNeverExpires     *bool `json:"pwd_never_expires,omitempty"`
	DaysOutOfCompliance int   `json:"days_out_of_compliance,omitempty"`

	// Kerberos attack surface (from BloodHound).
	HasSPN         *bool `json:"has_spn,omitempty"`          // Kerberoastable — SPN set
	DontReqPreauth *bool `json:"dont_req_preauth,omitempty"` // AS-REP roastable

	// SimilarityScore is the max Levenshtein similarity (0–1) to another cracked
	// password in the same domain. Zero means not computed or no similarity.
	SimilarityScore float64 `json:"similarity_score,omitempty"`

	// SimilarPeers are the accounts (same domain) whose cracked passwords are
	// near-duplicates of this one — username/domain/score only, never the
	// password — so it survives Redacted().
	SimilarPeers []SimilarPeer `json:"similar_peers,omitempty"`

	// EscalatedBySharedDA is true when this account was escalated to Critical by
	// EscalateSharedWithDA (shares an NT hash with a DA account).
	EscalatedBySharedDA bool `json:"escalated_by_shared_da,omitempty"`

	// ScoreBreakdown holds the numeric risk-factor components that produced the
	// final RiskScore. Stored so the UI can explain *why* an account scored high
	// without operators having to decode the vector string manually.
	ScoreBreakdown *ScoreBreakdown `json:"score_breakdown,omitempty"`
}

// ScoreBreakdown is the per-component detail of a CVSS-style risk score. Only
// populated for cracked accounts (uncracked accounts are scored through the same
// risk.Score path but do not carry a stored breakdown).
type ScoreBreakdown struct {
	// v2 two-axis sub-scores + raw per-factor inputs for the leave-one-out radar.
	ExposureScore     float64 `json:"exposure_score,omitempty"`
	WeaknessScore     float64 `json:"weakness_score,omitempty"`
	LengthPenalty     float64 `json:"length_penalty,omitempty"`
	ComplexityPenalty float64 `json:"complexity_penalty,omitempty"`
	DictPenalty       float64 `json:"dict_penalty,omitempty"`
	SimPenalty        float64 `json:"sim_penalty,omitempty"`
	HIBPFloor         float64 `json:"hibp_floor,omitempty"`
	CrackedFloor      float64 `json:"cracked_floor,omitempty"`
	ReuseBump         float64 `json:"reuse_bump,omitempty"`
	RoastableBump     float64 `json:"roastable_bump,omitempty"`
	ImpactScore       float64 `json:"impact_score,omitempty"`
	PrivilegeSubScore float64 `json:"privilege_sub_score,omitempty"`
	DAComponent       float64 `json:"da_component,omitempty"`
	DomainModifier    float64 `json:"domain_modifier,omitempty"`
	EnabledGated      bool    `json:"enabled_gated,omitempty"`
}

// IsWeak reports whether the password matched any wordlist signal (common,
// dictionary, forbidden word, or keyboard pattern).
func (a Account) IsWeak() bool {
	return a.IsCommon || a.IsDictionaryWord || a.BannedWordCount > 0 || a.KeyboardPatternCount > 0
}

// Redacted returns a copy with every cleartext fragment removed: the password, the
// NT hash (a pass-the-hash credential), and the matched wordlist substrings
// (BannedWords / KeyboardPatterns). None of these ever leave the process unredacted.
func (a Account) Redacted() Account {
	a.Password = ""
	a.NTHash = ""
	a.BannedWords = nil
	a.KeyboardPatterns = nil
	// PwdNeverExpires is safe to expose (boolean, not a credential).
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
		a.EscalatedBySharedDA = true
		// v2: inherit MAX Impact — cracking a hash shared with a DA-reachable account
		// IS a DA compromise. Force Impact known + 10 (a fresh local per iteration, no
		// aliasing); Level stays Critical (set above; the matrix at Impact=10 over any
		// Exposure is at least High, and the shared-DA signal is the flagship
		// lateral-movement escalation -> Critical).
		max := 10.0
		a.ImpactScore = &max
		a.ImpactKnown = true
	}
}

// ComputePercentiles assigns each account a within-audit triage percentile in [0,1]
// from its RiskScore (ties share a rank), so a large block of same-Level accounts
// still yields a strict order. A SORT KEY, not a displayed score. Idempotent: it
// depends only on RiskScore, never on a prior Percentile. Empty/one-account sets get 0.
//
// O(n log n): collect (score, index), sort by score, then walk assigning each run of
// equal scores a rank = number of accounts with a strictly lower score, advancing the
// rank past each run so ties share it. Percentile = rank/(n-1).
func ComputePercentiles(accts []Account) {
	n := len(accts)
	if n == 0 {
		return
	}
	if n == 1 {
		accts[0].Percentile = 0
		return
	}
	type sc struct {
		score float64
		idx   int
	}
	order := make([]sc, n)
	for i := range accts {
		order[i] = sc{score: accts[i].RiskScore, idx: i}
	}
	sort.SliceStable(order, func(i, j int) bool {
		return order[i].score < order[j].score
	})
	denom := float64(n - 1)
	// Walk ascending: each run of equal scores shares rank = #strictly-lower scores,
	// which equals the index of the first element in the run.
	for i := 0; i < n; {
		j := i
		for j < n && order[j].score == order[i].score {
			j++
		}
		rank := float64(i) // count of strictly-lower scores
		p := rank / denom
		for k := i; k < j; k++ {
			accts[order[k].idx].Percentile = p
		}
		i = j
	}
}

// IngestEvent records one upload into an audit (a dump load or a crack-apply).
// Metadata only -- no password or NT hash. Stored in the audit's encrypted dataset.
type IngestEvent struct {
	Filename       string    `json:"filename"`
	Kind           string    `json:"kind"` // "dump" | "cracks" | "domain_delete" | "enrich"
	Domain         string    `json:"domain,omitempty"`
	AccountsLoaded int       `json:"accounts_loaded,omitempty"` // dump
	HashesMatched  int       `json:"hashes_matched,omitempty"`  // cracks
	NewlyCracked   int       `json:"newly_cracked,omitempty"`   // cracks
	At             time.Time `json:"at"`
	By             string    `json:"by"` // operator username
}

// Dataset is a full audit result ingested from the analysis engine. Name lets a
// CLI ingest label the audit it creates.
type Dataset struct {
	Name        string        `json:"name,omitempty"`
	GeneratedAt time.Time     `json:"generated_at"`
	Accounts    []Account     `json:"accounts"`
	Ingests     []IngestEvent `json:"ingests,omitempty"`
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

	// Extended stats for the dashboard gap-fills.
	DisabledAccounts    int `json:"disabled_accounts"`
	NeverExpires        int `json:"never_expires"`
	StalePasswords      int `json:"stale_passwords"`        // days_out_of_compliance > 0
	EscalatedBySharedDA int `json:"escalated_by_shared_da"` // escalated via hash-sharing with a DA
	PolicyViolations    int `json:"policy_violations"`      // cracked && !meets_policy
	HighControlled      int `json:"high_controlled"`        // controlled_object_count > 100

	// Executive breach impact estimate.
	BreachImpact BreachImpact `json:"breach_impact"`
}

// BreachImpact is a simplified breach-impact estimate for the executive summary.
type BreachImpact struct {
	Probability    string `json:"probability"`     // Very High | High | Medium | Low
	ProbabilityPct string `json:"probability_pct"` // >75% | 50-75% | 25-50% | <25%
	EstimatedCost  string `json:"estimated_cost"`  // $1M-$5M+ etc.
	RecoveryTime   string `json:"recovery_time"`   // 6-12 months etc.
}
