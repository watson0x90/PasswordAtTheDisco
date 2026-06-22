// Package rescore re-scores a stored audit against the current policy, wordlists,
// and HIBP index WITHOUT re-fetching BloodHound: a stored enricher rebuilds each
// account's BloodHound-derived Enrichment from its already-persisted fields, so
// engine.RescoreWith re-derives the same Impact while Exposure/Level/percentile
// refresh from current config. Mirrors internal/enrich's job manager.
package rescore

import (
	"strings"

	"github.com/watson0x90/PasswordAtTheDisco/internal/engine"
	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
)

// StoredEnricher serves engine.Enrichment rebuilt from persisted account fields,
// keyed by engine.NormalizeUsername(username, domain) -- the same key the live
// scoring path uses (see engine.enrichVia). A lookup miss returns the zero
// Enrichment (Enriched:false => Impact-Unknown), matching an unenriched account.
type StoredEnricher map[string]engine.Enrichment

// NewStoredEnricher builds the lookup from the audit's accounts. For an enriched
// account (Coverage=="full") it reconstructs the full Enrichment from persisted
// fields; otherwise it stores the zero value so Impact stays Unknown.
func NewStoredEnricher(accts []model.Account) StoredEnricher {
	m := make(StoredEnricher, len(accts))
	for _, a := range accts {
		key := engine.NormalizeUsername(a.Username, a.Domain)
		if a.Coverage != "full" {
			m[key] = engine.Enrichment{Enriched: false}
			continue
		}
		m[key] = enrichmentFromAccount(a)
	}
	return m
}

// Enrich implements engine.Enricher. Returns the stored Enrichment for the
// normalized username, or a zero Enrichment (Enriched:false) if not found.
func (s StoredEnricher) Enrich(username string) engine.Enrichment { return s[username] }

// enrichmentFromAccount mirrors engine.BulkBloodhoundEnricher.Enrich, but reads
// the persisted model.Account fields instead of a fresh BloodHound prefetch.
//
// Note: HasSPN/DontReqPreauth/PwdNeverExpires are passed through as the stored
// *bool (which may be nil if BloodHound never populated that field). The live
// BulkBloodhoundEnricher always yields non-nil pointers; a nil here maps to the
// same "unknown" treatment downstream (boolOrFalse -> false, passwordExpires ->
// "Unknown"), so Impact is conservative, never falsely inflated.
func enrichmentFromAccount(a model.Account) engine.Enrichment {
	enabled := a.Enabled
	enr := engine.Enrichment{
		DADomains:       splitDA(a.DADomains),
		Enabled:         &enabled,
		ControlsTier0:   a.ControlsTier0,
		HasSPN:          a.HasSPN,
		DontReqPreauth:  a.DontReqPreauth,
		PwdNeverExpires: a.PwdNeverExpires,
		Enriched:        true,
	}
	// Controlled==0 means "not in the controllables map" = unknown; leave the
	// pointer nil so the vector encodes CO:U (unknown), matching the live path.
	if a.Controlled > 0 {
		c := a.Controlled
		enr.ControlledObjects = &c
	}
	if a.PwdLastSet > 0 {
		v := a.PwdLastSet
		enr.PwdLastSet = &v
	}
	return enr
}

// splitDA inverts engine.joinDA: the stored string is "None" when empty, else a
// ", "-joined list of DA-reachable domains.
func splitDA(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" || s == "None" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
