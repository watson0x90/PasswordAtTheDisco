package report

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/watson0x90/PasswordAtTheDisco/internal/metrics"
	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
)

// bundleReport is the top-level JSON document written to report.json inside the
// BundleZip archive. It is an allowlist structure.
type bundleReport struct {
	SchemaVersion int               `json:"schema_version"`
	GeneratedAt   time.Time         `json:"generated_at"`
	ToolVersion   string            `json:"tool_version"`
	Name          string            `json:"name"`
	Scope         string            `json:"scope"`
	Cleartext     bool              `json:"cleartext"`
	Metrics       metrics.Metrics   `json:"metrics"`
	Accounts      []BundleAccount   `json:"accounts"`
	Images        map[string]string `json:"images"`
}

// BundleZip writes a self-contained ZIP archive to w. The archive contains:
//   - report.json — indented JSON of bundleReport (accounts via bundleAccounts,
//     images manifest mapping chart name -> "images/<name>.svg").
//   - images/<name>.svg — one entry per ChartSVGs(m) result.
//
// Binding constraints:
//   - stdlib only (archive/zip, encoding/json).
//   - Sanitized bundle (cleartext=false): no cleartext password, no NTHash anywhere.
//   - Cleartext bundle: password only in report.json accounts, never in SVG images.
//   - NTHash is NEVER emitted in any output path.
func BundleZip(w io.Writer, name, scope string, cleartext bool, m metrics.Metrics, accounts []model.Account, now time.Time, version string) error {
	zw := zip.NewWriter(w)
	if err := writeBundleInto(zw, "", name, scope, cleartext, m, accounts, now, version); err != nil {
		return err
	}
	return zw.Close()
}

// writeBundleInto writes the bundle contents into an existing zip.Writer, prefixing
// every entry path with prefix. The zip.Writer is neither created nor closed by this
// function — the caller owns both operations.
//
// The images manifest inside report.json always uses relative paths ("images/<name>.svg")
// regardless of prefix; only the zip entry paths are prefixed. When prefix=="" the
// output is identical to the previous single-function behaviour.
func writeBundleInto(zw *zip.Writer, prefix, name, scope string, cleartext bool, m metrics.Metrics, accounts []model.Account, now time.Time, version string) error {
	charts := ChartSVGs(m)

	// Build the images manifest with paths relative to the bundle root (no prefix).
	images := make(map[string]string, len(charts))
	for _, c := range charts {
		images[c.Name] = fmt.Sprintf("images/%s.svg", c.Name)
	}

	rep := bundleReport{
		SchemaVersion: 1,
		GeneratedAt:   now,
		ToolVersion:   version,
		Name:          name,
		Scope:         scope,
		Cleartext:     cleartext,
		Metrics:       m,
		Accounts:      bundleAccounts(accounts, cleartext, now),
		Images:        images,
	}

	// Write report.json under the prefix.
	rjBytes, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return fmt.Errorf("bundle: marshal report: %w", err)
	}
	rjf, err := zw.Create(prefix + "report.json")
	if err != nil {
		return fmt.Errorf("bundle: create report.json: %w", err)
	}
	if _, err := rjf.Write(rjBytes); err != nil {
		return fmt.Errorf("bundle: write report.json: %w", err)
	}

	// Write each chart SVG into <prefix>images/.
	for _, c := range charts {
		entryPath := fmt.Sprintf("%simages/%s.svg", prefix, c.Name)
		cf, err := zw.Create(entryPath)
		if err != nil {
			return fmt.Errorf("bundle: create %s: %w", entryPath, err)
		}
		if _, err := io.WriteString(cf, c.SVG); err != nil {
			return fmt.Errorf("bundle: write %s: %w", entryPath, err)
		}
	}

	return nil
}

// BundlePeer is an identified similar-peer reference for the model export bundle.
// Unlike SanitizedPeer (which uses an opaque id), BundlePeer carries the real
// username and domain — safe to include in the identified export tier.
type BundlePeer struct {
	Username string  `json:"username"`
	Domain   string  `json:"domain"`
	Score    float64 `json:"score"`
}

// BundleAccount is the per-account projection for the model-export bundle. It is an
// ALLOWLIST structure: only the fields explicitly listed here are copied from
// model.Account. Future fields on model.Account are excluded by default.
//
// Unlike SanitizedAccount, identities are real: username, domain, da_domains, and
// similar_peers all carry actual values. Password is set only when the caller holds
// cleartext authority (cleartext=true) AND the account was cracked.
//
// The struct must never contain NTHash, BannedWords, or KeyboardPatterns. Only the
// safe derivative counts (banned_word_count / keyboard_pattern_count) are included.
type BundleAccount struct {
	Username string `json:"username"`
	Domain   string `json:"domain"`
	// Password is set only when cleartext && a.Cracked.
	Password string `json:"password,omitempty"`

	ReuseGroup string `json:"reuse_group,omitempty"`

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

	HasDAPath bool   `json:"has_da_path"`
	DADomains string `json:"da_domains,omitempty"`

	ControlledObjects int  `json:"controlled_object_count"`
	ControlsTier0     bool `json:"controls_tier0,omitempty"`

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
	SimilarPeers    []BundlePeer          `json:"similar_peers,omitempty"`
	ScoreBreakdown  *model.ScoreBreakdown `json:"score_breakdown,omitempty"`
}

// bundleAccounts projects a slice of model.Account into the identified bundle
// representation. If cleartext is false, Password is always empty. If cleartext is
// true, Password is set only for cracked accounts.
//
// NTHash is used only internally to compute reuse-group ids; it is never emitted.
func bundleAccounts(accounts []model.Account, cleartext bool, now time.Time) []BundleAccount {
	// Build reuse-group map: same logic as sanitize.go but applied to the bundle.
	// reuseGroupKey and the emptyNTHash constant are defined in sanitize.go (same package).
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

	out := make([]BundleAccount, 0, len(accounts))
	for _, a := range accounts {
		var pwd string
		if cleartext && a.Cracked {
			pwd = a.Password
		}

		var peers []BundlePeer
		for _, p := range a.SimilarPeers {
			peers = append(peers, BundlePeer{
				Username: p.Username,
				Domain:   p.Domain,
				Score:    p.Score,
			})
		}

		out = append(out, BundleAccount{
			Username:   a.Username,
			Domain:     a.Domain,
			Password:   pwd,
			ReuseGroup: reuseGroup[reuseGroupKey(a.NTHash)],

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

			HasDAPath: a.HasDAPathway(),
			DADomains: a.DADomains,

			ControlledObjects: a.Controlled,
			ControlsTier0:     a.ControlsTier0,

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
	return out
}
