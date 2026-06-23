// Package model defines the audit data types served by the API.
package model

import (
	"math"
	"sort"
	"strings"
	"time"
)

const (
	// Credential Hygiene component weights (sum 100); privilege term removed.
	hygieneRiskWeight       = 45.0
	hygieneStrengthWeight   = 35.0
	hygieneComplianceWeight = 20.0
	hygieneStrongMin        = 85.0
	hygieneFairMin          = 70.0

	// Breach Reachability: per-enabler "exploitable" probabilities and caps.
	reachPDA     = 0.55 // one reachable DA path -> L=0.55 (High); two -> 0.7975 (Very High)
	reachPT0     = 0.70
	reachPCrit   = 0.15
	reachCapCrit = 5 // cap supporting-evidence count so estate SIZE can't auto-pin Very High
	// reuseN deferred (v1): redacted /api/accounts has no reuse-group token -> TS parity; see spec §2.2.

	// Reachability bands on integer-scaled L (L*reachScale), parity-safe.
	reachScale      = 1_000_000
	reachBandMedium = 250_000 // >= -> Medium  (>=25%)
	reachBandHigh   = 500_000 // >= -> High     (>=50%)
	reachBandVeryHi = 750_000 // >= -> Very High (>=75%)
)

// Posture is the executive Security Posture Score and its components.
type Posture struct {
	Score             float64          `json:"score"`      // = Credential Hygiene (0-100)
	Rating            string           `json:"rating"`     // Strong|Fair|Weak|No Data (hygiene)
	Likelihood        string           `json:"likelihood"` // back-compat alias = Reachability band
	Breakdown         PostureBreakdown `json:"breakdown"`
	Reachability      string           `json:"reachability"`       // Low|Medium|High|Very High|—
	ReachabilityScore float64          `json:"reachability_score"` // L in [0,1)
	ReachabilityPct   string           `json:"reachability_pct"`   // band range, e.g. ">75%" (never a point %)
	Overall           float64          `json:"overall"`            // Hygiene*(1-L); trend/sort key only
	Verdict           string           `json:"verdict"`            // Sound|Guarded|Elevated|High Risk|Critical|No Data
	VerdictReason     string           `json:"verdict_reason,omitempty"`
}

// PostureBreakdown is each posture component's weighted contribution.
type PostureBreakdown struct {
	Risk       float64 `json:"risk"`       // /40
	Strength   float64 `json:"strength"`   // /30
	Privilege  float64 `json:"privilege"`  // /15
	Compliance float64 `json:"compliance"` // /15
}

func round1(f float64) float64 { return math.Round(f*10) / 10 }

// reachable: a privileged object the auditor can actually obtain/authenticate as.
func reachable(a Account) bool {
	return a.Enabled && (a.Cracked || a.EscalatedBySharedDA || a.EscalatedByMassReuse)
}

// powi: integer power by repeated multiply — IDENTICAL in Go and JS (avoids math.Pow/Math.pow
// cross-libm last-ULP drift). Keep web/src/insights.ts powi in lockstep.
func powi(base float64, n int) float64 {
	r := 1.0
	for i := 0; i < n; i++ {
		r *= base
	}
	return r
}

// breachReachability returns L plus the component counts (da, t0Reachable, critN, dormant).
func breachReachability(accts []Account) (L float64, da, t0, critN, dormant int) {
	for i := range accts {
		a := accts[i]
		if reachable(a) {
			if a.HasDAPathway() {
				da++
			}
			if a.ControlsTier0 {
				t0++
			}
		} else if !a.Enabled && (a.ControlsTier0 || a.HasDAPathway()) &&
			(a.Cracked || a.EscalatedBySharedDA || a.EscalatedByMassReuse) {
			dormant++ // disabled landmine
		}
		if a.RiskLevel == "Critical" && !a.HasDAPathway() && !a.ControlsTier0 {
			critN++ // Critical that is not ALREADY the catastrophe (de-dup vs da/t0)
		}
	}
	if critN > reachCapCrit {
		critN = reachCapCrit
	}
	// reuseN deferred (v1) — see spec §2.2.
	L = 1 - powi(1-reachPDA, da)*powi(1-reachPT0, t0)*powi(1-reachPCrit, critN)
	return
}

func reachBand(L float64) string {
	ls := int(L*reachScale + 0.5) // floor(L*scale+0.5); identical to Math.floor(L*scale+0.5) in TS
	switch {
	case ls >= reachBandVeryHi:
		return "Very High"
	case ls >= reachBandHigh:
		return "High"
	case ls >= reachBandMedium:
		return "Medium"
	default:
		return "Low"
	}
}

func reachPct(band string) string {
	switch band {
	case "Very High":
		return ">75%"
	case "High":
		return "50-75%"
	case "Medium":
		return "25-50%"
	default:
		return "<25%"
	}
}

// STUB: Task 4 — replaced by real implementation in Task 4.
func gateVerdict(hygieneRating, band string, t0, active int) (verdict, reason string) {
	return "No Data", ""
}

func hygieneRating(h float64) string {
	switch {
	case h >= hygieneStrongMin:
		return "Strong"
	case h >= hygieneFairMin:
		return "Fair"
	default:
		return "Weak"
	}
}

// PostureScore computes the executive Credential Hygiene (0–100) over ENABLED accounts
// plus Breach Reachability (L) over the full account set, and a gated Verdict.
// THIS IS THE SINGLE SOURCE OF TRUTH — the HTML report, audit diff, and the /api/summary
// the dashboard renders all use it, so the on-screen gauge can never drift from the exported report.
func PostureScore(accounts []Account) Posture {
	var active, crit, high, med, uncracked, viol int
	for _, a := range accounts {
		if !a.Enabled {
			continue // disabled excluded from hygiene (they padded "Strong")
		}
		active++
		switch a.RiskLevel {
		case "Critical":
			crit++
		case "High":
			high++
		case "Medium":
			med++
		}
		if !a.Cracked {
			uncracked++
		}
		if a.Cracked && !a.MeetsPolicy {
			viol++
		}
	}
	// Reachability is computed over the FULL set so the Tier-0 gate can fire even when active==0.
	L, _, t0, _, _ := breachReachability(accounts)
	band := reachBand(L)

	if active == 0 {
		p := Posture{Score: 0, Rating: "No Data", Reachability: band,
			ReachabilityScore: L, ReachabilityPct: reachPct(band), Likelihood: band}
		p.Verdict, p.VerdictReason = gateVerdict("No Data", band, t0, active)
		return p
	}
	af := float64(active)
	risk := math.Max(0, 100-float64(crit)/af*200-float64(high)/af*150-float64(med)/af*50) / 100 * hygieneRiskWeight
	strength := float64(uncracked) / af * hygieneStrengthWeight
	compliance := float64(active-viol) / af * hygieneComplianceWeight
	hygiene := round1(risk + strength + compliance)
	rating := hygieneRating(hygiene)

	p := Posture{
		Score:             hygiene,
		Rating:            rating,
		Breakdown:         PostureBreakdown{Risk: round1(risk), Strength: round1(strength), Privilege: 0, Compliance: round1(compliance)},
		Reachability:      band,
		ReachabilityScore: L,
		ReachabilityPct:   reachPct(band),
		Likelihood:        band,
	}
	p.Overall = round1(hygiene * (1 - L))
	p.Verdict, p.VerdictReason = gateVerdict(rating, band, t0, active)
	return p
}

// EstimateBreachImpact: reachability-driven (single-source with Posture so $ and verdict agree).
func EstimateBreachImpact(p Posture) BreachImpact {
	var bi BreachImpact
	bi.Probability = p.Reachability
	bi.ProbabilityPct = p.ReachabilityPct
	switch {
	case p.VerdictReason == "Tier-0 Reachable":
		bi.EstimatedCost, bi.RecoveryTime = "$1M – $5M+", "6–12 months"
	case p.Reachability == "Very High":
		bi.EstimatedCost, bi.RecoveryTime = "$500K – $1M", "3–6 months"
	case p.Reachability == "High":
		bi.EstimatedCost, bi.RecoveryTime = "$100K – $500K", "1–3 months"
	default:
		bi.EstimatedCost, bi.RecoveryTime = "$50K – $100K", "2–4 weeks"
	}
	if p.Reachability == "" || p.Reachability == "—" { // No-Data guard
		bi.Probability, bi.ProbabilityPct = "—", ""
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
	// ContainsUnicode flags a cracked password containing non-ASCII runes; PolicyViolations
	// is the list of failed policy rules ("No uppercase", "Length < 14"). Both are descriptive
	// (reveal nothing beyond the already-exposed length/complexity) -- not credentials -- so
	// they survive Redacted().
	ContainsUnicode  bool     `json:"contains_unicode,omitempty"`
	PolicyViolations []string `json:"policy_violations,omitempty"`

	// Enrichment-derived temporal/privilege signals. Stored so the UI can surface
	// them without decoding the risk vector. PwdLastSet is Unix epoch seconds (or 0
	// if unknown); PwdNeverExpires and DaysOutOfCompliance are from BloodHound.
	PwdLastSet          int64 `json:"pwd_last_set,omitempty"`
	PwdNeverExpires     *bool `json:"pwd_never_expires,omitempty"`
	DaysOutOfCompliance int   `json:"days_out_of_compliance,omitempty"`

	// Kerberos attack surface (from BloodHound).
	HasSPN         *bool `json:"has_spn,omitempty"`          // Kerberoastable — SPN set
	DontReqPreauth *bool `json:"dont_req_preauth,omitempty"` // AS-REP roastable

	// ControlsTier0 marks an account with a BloodHound control edge onto a Tier-0
	// asset (a high-Impact privilege signal consumed by risk scoring). Persisted so
	// it survives store reloads and can be re-derived without re-running BloodHound.
	// Descriptive boolean, not a credential -- survives Redacted().
	ControlsTier0 bool `json:"controls_tier0,omitempty"`

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

	// EscalatedByMassReuse is true when this account was escalated by
	// EscalateLargeCrackedReuse (member of a large CRACKED reuse cluster).
	EscalatedByMassReuse bool `json:"escalated_by_mass_reuse,omitempty"`

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
	AgePenalty        float64 `json:"age_penalty,omitempty"`
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
		// Skip accounts that already have their own DA pathway: a DA-reachable
		// account seeded its hash into daHashes, so it matches itself here. The
		// shared-DA signal means "inherited Critical by reusing a DA's password",
		// which doesn't apply to the DA account itself -- flagging it would inflate
		// the lateral-movement report with false positives.
		if a.HasDAPathway() {
			continue
		}
		if a.RiskLevel != "Critical" {
			a.RiskLevel = "Critical"
		}
		if a.RiskScore < 9.0 {
			a.RiskScore = 9.0 // display/back-compat floor; triage percentile is driven by the composite key, not RiskScore
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
		if a.ScoreBreakdown != nil {
			a.ScoreBreakdown.ImpactScore = max
		}
	}
}

// Mass-reuse Level escalation (Finding 1). A large CRACKED reuse cluster is collectively
// high-risk ("crack one, own N") even though each member's blast radius is low; the
// Exposure x Impact matrix caps low-Impact accounts at Medium, so without this pass a
// 402-account cracked cluster reads as 402x "Low". Hybrid + scale-aware so it isn't locked
// to one audit size. Tune the five knobs here.
const (
	massReuseHighN             = 100
	massReuseMediumN           = 25
	massReuseHighFrac          = 0.25
	massReuseMediumFrac        = 0.05
	massReuseMinClusterForFrac = 5 // the fraction path requires at least this many accounts
)

// massReuseTarget returns the Level a cracked cluster of n members (in an audit of total
// accounts) escalates to: "High", "Medium", or "" (none). Cap: High.
func massReuseTarget(n, total int) string {
	if n >= massReuseHighN || (n >= massReuseMinClusterForFrac && float64(n) >= massReuseHighFrac*float64(total)) {
		return "High"
	}
	if n >= massReuseMediumN || (n >= massReuseMinClusterForFrac && float64(n) >= massReuseMediumFrac*float64(total)) {
		return "Medium"
	}
	return ""
}

// levelRank maps a Level to a severity rank (higher = worse); mirrors triageKey.
func levelRank(level string) int {
	switch level {
	case "Critical":
		return 4
	case "High":
		return 3
	case "Medium":
		return 2
	case "Low":
		return 1
	default:
		return 0
	}
}

// moreSevereLevel returns whichever of cur/target is higher severity.
func moreSevereLevel(cur, target string) string {
	if levelRank(target) > levelRank(cur) {
		return target
	}
	return cur
}

// levelFloorScore is the display RiskScore floor for an escalated level (the tier minimum),
// so a Medium/High level doesn't show next to a near-zero RiskScore.
func levelFloorScore(level string) float64 {
	switch level {
	case "High":
		return 6.0
	case "Medium":
		return 4.0
	default:
		return 0
	}
}

// EscalateLargeCrackedReuse raises the Level of members of a large CRACKED reuse cluster
// (see massReuseTarget). It changes Level / RiskScore / vector / flag ONLY -- Impact stays
// honest (these accounts genuinely have low blast radius; the /MASS-REUSE tag + flag explain
// the override). Run AFTER EscalateSharedWithDA, BEFORE ComputePercentiles.
func EscalateLargeCrackedReuse(accts []Account) {
	total := len(accts)
	crackedN := map[string]int{}
	for i := range accts {
		if accts[i].Cracked {
			if k := reuseKey(accts[i].NTHash); k != "" {
				crackedN[k]++
			}
		}
	}
	for i := range accts {
		a := &accts[i]
		if !a.Cracked {
			continue
		}
		k := reuseKey(a.NTHash)
		if k == "" {
			continue
		}
		target := massReuseTarget(crackedN[k], total)
		if target == "" {
			continue
		}
		a.RiskLevel = moreSevereLevel(a.RiskLevel, target)
		if f := levelFloorScore(target); a.RiskScore < f {
			a.RiskScore = f
		}
		if !strings.Contains(a.RiskVector, "MASS-REUSE") {
			a.RiskVector += "/MASS-REUSE"
		}
		a.EscalatedByMassReuse = true
	}
}

// triageKey is the level-first sort key for the triage percentile: rank by Level
// severity first (Critical>High>Medium>Low), then an Impact-weighted scalar within a
// level. Guarantees the percentile never contradicts the Level badge.
func triageKey(a Account) (rank int, scalar float64) {
	rank = levelRank(a.RiskLevel) // shared severity ordering (also used by EscalateLargeCrackedReuse)
	if a.ImpactKnown && a.ImpactScore != nil {
		scalar = 0.4*a.ExposureScore + 0.6*(*a.ImpactScore)
	} else {
		scalar = a.ExposureScore
	}
	return rank, scalar
}

func triageLess(a, b Account) bool {
	la, sa := triageKey(a)
	lb, sb := triageKey(b)
	if la != lb {
		return la < lb
	}
	return sa < sb
}

func triageEqual(a, b Account) bool {
	la, sa := triageKey(a)
	lb, sb := triageKey(b)
	return la == lb && sa == sb
}

// ComputePercentiles assigns each account a within-audit triage percentile in [0,1]
// ranked level-first (Critical>High>Medium>Low) then by an Impact-weighted scalar
// within each level (ties share a rank), so the percentile can never contradict the
// Level badge. A SORT KEY, not a displayed score. RiskScore is display/back-compat
// only and no longer drives triage. Idempotent: depends only on RiskLevel,
// ExposureScore, ImpactScore/ImpactKnown, never on a prior Percentile.
// Empty/one-account sets get 0.
//
// O(n log n): sort by composite key, then walk assigning each run of equal keys a
// rank = number of accounts with a strictly lower key, advancing the rank past each
// run so ties share it. Percentile = rank/(n-1).
func ComputePercentiles(accts []Account) {
	n := len(accts)
	if n == 0 {
		return
	}
	if n == 1 {
		accts[0].Percentile = 0
		return
	}
	order := make([]int, n)
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(i, j int) bool {
		return triageLess(accts[order[i]], accts[order[j]])
	})
	denom := float64(n - 1)
	for i := 0; i < n; {
		j := i
		for j < n && triageEqual(accts[order[j]], accts[order[i]]) {
			j++
		}
		p := float64(i) / denom
		for k := i; k < j; k++ {
			accts[order[k]].Percentile = p
		}
		i = j
	}
}

// IngestEvent records one upload into an audit (a dump load or a crack-apply).
// Metadata only -- no password or NT hash. Stored in the audit's encrypted dataset.
type IngestEvent struct {
	Filename       string    `json:"filename"`
	Kind           string    `json:"kind"` // "dump" | "cracks" | "domain_delete" | "enrich" | "rescore"
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
	DisabledAccounts     int `json:"disabled_accounts"`
	NeverExpires         int `json:"never_expires"`
	StalePasswords       int `json:"stale_passwords"`         // days_out_of_compliance > 0
	EscalatedBySharedDA  int `json:"escalated_by_shared_da"`  // escalated via hash-sharing with a DA
	EscalatedByMassReuse int `json:"escalated_by_mass_reuse"` // escalated via a large cracked-reuse cluster
	PolicyViolations     int `json:"policy_violations"`       // cracked && !meets_policy
	HighControlled       int `json:"high_controlled"`         // controlled_object_count > 100
	DormantPrivileged    int `json:"dormant_privileged"`      // disabled but privileged & credential-compromisable

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
