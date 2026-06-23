package report

import (
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
)

// emptyNTHash is the NT hash of an empty password (a public constant) -- accounts
// with it are "no password", not real reuse, so they are not grouped. Mirrors the
// exclusion in model.reuseKey (which is unexported).
const emptyNTHash = "31D6CFE0D16AE931B73C59D7E0C089C0"

// SanitizedReport is the top-level review export. It is an ALLOWLIST structure:
// nothing is copied from model.Account except the explicitly-named safe fields
// below, so any future field on model.Account is excluded by default.
type SanitizedReport struct {
	SchemaVersion int                `json:"schema_version"`
	GeneratedAt   time.Time          `json:"generated_at"`
	ToolVersion   string             `json:"tool_version"`
	Summary       model.Summary      `json:"summary"`
	Domains       []SanitizedDomain  `json:"domains"`
	Accounts      []SanitizedAccount `json:"accounts"`
}

// SanitizedDomain is a per-domain rollup with no domain name.
type SanitizedDomain struct {
	Label        string `json:"label"`
	AccountCount int    `json:"account_count"`
	RiskLevel    string `json:"risk_level,omitempty"`
}

// SanitizedPeer references another account in this report by its opaque id.
type SanitizedPeer struct {
	ID    string  `json:"id"`
	Score float64 `json:"score"`
}

// SanitizedAccount carries every per-account SCORING/STRUCTURAL signal with no
// identifying or secret data. Sensitive raw fields are transformed: domain ->
// DomainLabel, DA domain names -> HasDAPath, raw pwdLastSet -> PasswordAgeDays,
// peer usernames -> opaque ids.
type SanitizedAccount struct {
	ID          string `json:"id"`
	DomainLabel string `json:"domain_label"`
	ReuseGroup  string `json:"reuse_group,omitempty"`

	Cracked        bool   `json:"cracked"`
	PasswordLength int    `json:"password_length"`
	Complexity     string `json:"complexity,omitempty"`

	RiskLevel     string   `json:"risk_level"`
	RiskScore     float64  `json:"risk_score"`
	RiskVector    string   `json:"risk_vector"`
	ExposureScore float64  `json:"exposure_score"`
	ImpactScore   *float64 `json:"impact_score"`
	ImpactKnown   bool     `json:"impact_known"`
	Percentile    float64  `json:"percentile"`

	HIBPBreached    bool `json:"hibp_breached"`
	HIBPBreachCount int  `json:"hibp_breach_count"`

	SharedWith           int  `json:"shared_with"`
	EscalatedBySharedDA  bool `json:"escalated_by_shared_da,omitempty"`
	EscalatedByMassReuse bool `json:"escalated_by_mass_reuse,omitempty"`
	HasDAPath            bool `json:"has_da_path"`
	ControlledObjects    int  `json:"controlled_object_count"`
	ControlsTier0        bool `json:"controls_tier0,omitempty"`

	Enabled  bool   `json:"enabled"`
	Coverage string `json:"coverage,omitempty"`

	MeetsPolicy          bool     `json:"meets_policy"`
	PolicyViolations     []string `json:"policy_violations,omitempty"`
	IsCommon             bool     `json:"is_common,omitempty"`
	IsDictionaryWord     bool     `json:"is_dictionary_word,omitempty"`
	BannedWordCount      int      `json:"banned_word_count,omitempty"`
	KeyboardPatternCount int      `json:"keyboard_pattern_count,omitempty"`
	ContainsUnicode      bool     `json:"contains_unicode,omitempty"`

	PasswordAgeDays     int   `json:"password_age_days"`
	PwdNeverExpires     *bool `json:"pwd_never_expires,omitempty"`
	DaysOutOfCompliance int   `json:"days_out_of_compliance,omitempty"`

	HasSPN         *bool `json:"has_spn,omitempty"`
	DontReqPreauth *bool `json:"dont_req_preauth,omitempty"`

	SimilarityScore float64               `json:"similarity_score,omitempty"`
	SimilarPeers    []SanitizedPeer       `json:"similar_peers,omitempty"`
	ScoreBreakdown  *model.ScoreBreakdown `json:"score_breakdown,omitempty"`
}

// peerKey normalizes a (username, domain) into the lookup key used to resolve
// similar-peer references to opaque account ids.
func peerKey(username, domain string) string {
	return strings.ToLower(strings.TrimSpace(username)) + "@" + strings.ToUpper(strings.TrimSpace(domain))
}

// reuseGroupKey mirrors model.reuseKey: uppercased NT hash, excluding empty/absent
// and the empty-password hash (those are not real reuse).
func reuseGroupKey(ntHash string) string {
	h := strings.ToUpper(strings.TrimSpace(ntHash))
	if h == "" || h == emptyNTHash {
		return ""
	}
	return h
}

func ageDays(pwdLastSet int64, now time.Time) int {
	if pwdLastSet <= 0 {
		return 0
	}
	d := int(now.Sub(time.Unix(pwdLastSet, 0).UTC()).Hours() / 24)
	if d < 0 {
		d = 0
	}
	return d
}

// Sanitize builds the allowlist report from the (unredacted) accounts. NT hashes
// and identities are used only to compute opaque structure; none are emitted.
func Sanitize(accounts []model.Account, summary model.Summary, now time.Time, version string) SanitizedReport {
	n := len(accounts)
	ids := make([]string, n)
	idByPeerKey := make(map[string]string, n)
	for i, a := range accounts {
		ids[i] = "a" + strconv.Itoa(i+1)
		// First account with a given (user,domain) key wins, so peer resolution is
		// deterministic even if two accounts collide on the key (it never affects
		// privacy -- only an opaque id is ever emitted).
		if k := peerKey(a.Username, a.Domain); k != "" {
			if _, ok := idByPeerKey[k]; !ok {
				idByPeerKey[k] = ids[i]
			}
		}
	}

	domainLabel := make(map[string]string)
	var domainOrder []string
	domAccts := make(map[string][]model.Account)
	for _, a := range accounts {
		if _, ok := domainLabel[a.Domain]; !ok {
			domainLabel[a.Domain] = "D" + strconv.Itoa(len(domainOrder)+1)
			domainOrder = append(domainOrder, a.Domain)
		}
		domAccts[a.Domain] = append(domAccts[a.Domain], a)
	}
	domains := make([]SanitizedDomain, 0, len(domainOrder))
	for _, d := range domainOrder {
		domains = append(domains, SanitizedDomain{
			Label: domainLabel[d], AccountCount: len(domAccts[d]), RiskLevel: modeRiskLevel(domAccts[d]),
		})
	}

	hashCount := make(map[string]int)
	for _, a := range accounts {
		if k := reuseGroupKey(a.NTHash); k != "" {
			hashCount[k]++
		}
	}
	reuseGroup := make(map[string]string)
	for _, a := range accounts {
		k := reuseGroupKey(a.NTHash)
		if k == "" || hashCount[k] < 2 {
			continue
		}
		if _, ok := reuseGroup[k]; !ok {
			reuseGroup[k] = "g" + strconv.Itoa(len(reuseGroup)+1)
		}
	}

	out := make([]SanitizedAccount, 0, n)
	for i, a := range accounts {
		var peers []SanitizedPeer
		for _, p := range a.SimilarPeers {
			if pid, ok := idByPeerKey[peerKey(p.Username, p.Domain)]; ok {
				peers = append(peers, SanitizedPeer{ID: pid, Score: p.Score})
			}
		}
		out = append(out, SanitizedAccount{
			ID:          ids[i],
			DomainLabel: domainLabel[a.Domain],
			ReuseGroup:  reuseGroup[reuseGroupKey(a.NTHash)],

			Cracked:        a.Cracked,
			PasswordLength: a.PasswordLength,
			Complexity:     a.Complexity,

			RiskLevel:     a.RiskLevel,
			RiskScore:     a.RiskScore,
			RiskVector:    a.RiskVector,
			ExposureScore: a.ExposureScore,
			ImpactScore:   a.ImpactScore,
			ImpactKnown:   a.ImpactKnown,
			Percentile:    a.Percentile,

			HIBPBreached:    a.HIBPBreached,
			HIBPBreachCount: a.HIBPBreachCount,

			SharedWith:           a.SharedWith,
			EscalatedBySharedDA:  a.EscalatedBySharedDA,
			EscalatedByMassReuse: a.EscalatedByMassReuse,
			HasDAPath:            a.HasDAPathway(),
			ControlledObjects:    a.Controlled,
			ControlsTier0:        a.ControlsTier0,

			Enabled:  a.Enabled,
			Coverage: a.Coverage,

			MeetsPolicy:          a.MeetsPolicy,
			PolicyViolations:     a.PolicyViolations,
			IsCommon:             a.IsCommon,
			IsDictionaryWord:     a.IsDictionaryWord,
			BannedWordCount:      a.BannedWordCount,
			KeyboardPatternCount: a.KeyboardPatternCount,
			ContainsUnicode:      a.ContainsUnicode,

			PasswordAgeDays:     ageDays(a.PwdLastSet, now),
			PwdNeverExpires:     a.PwdNeverExpires,
			DaysOutOfCompliance: a.DaysOutOfCompliance,

			HasSPN:         a.HasSPN,
			DontReqPreauth: a.DontReqPreauth,

			SimilarityScore: a.SimilarityScore,
			SimilarPeers:    peers,
			ScoreBreakdown:  a.ScoreBreakdown,
		})
	}

	return SanitizedReport{
		SchemaVersion: 1,
		GeneratedAt:   now.UTC(),
		ToolVersion:   version,
		Summary:       summary,
		Domains:       domains,
		Accounts:      out,
	}
}

// modeRiskLevel returns the most common RiskLevel among the accounts (ties broken
// by severity Critical>High>Medium>Low). "" if none.
func modeRiskLevel(accts []model.Account) string {
	counts := make(map[string]int)
	for _, a := range accts {
		if a.RiskLevel != "" {
			counts[a.RiskLevel]++
		}
	}
	order := []string{"Critical", "High", "Medium", "Low"}
	best, bestN := "", 0
	for _, lvl := range order {
		if counts[lvl] > bestN {
			best, bestN = lvl, counts[lvl]
		}
	}
	return best
}

// SanitizedJSON builds and writes the sanitized report as indented JSON.
func SanitizedJSON(w io.Writer, accounts []model.Account, summary model.Summary, now time.Time, version string) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(Sanitize(accounts, summary, now, version))
}
