// Package engine is the audit orchestration: for each parsed account it runs
// password analysis, HIBP correlation, BloodHound enrichment, and CVSS-style
// scoring, producing model.Account records ready for the API store.
//
// Ported from the per-account flow of legacy-python/core/domain_analysis.py
// (analyze_domain) + core/processor.py. HIBP and BloodHound are optional,
// injected behind small interfaces so the pipeline is testable without the 74GB
// dump or a live BHE server.
package engine

import (
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/watson0x90/PasswordAtTheDisco/internal/bloodhound"
	"github.com/watson0x90/PasswordAtTheDisco/internal/hibp"
	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
	"github.com/watson0x90/PasswordAtTheDisco/internal/policy"
	"github.com/watson0x90/PasswordAtTheDisco/internal/pwanalysis"
	"github.com/watson0x90/PasswordAtTheDisco/internal/risk"
	"github.com/watson0x90/PasswordAtTheDisco/internal/secretsdump"
)

// HIBPLookup checks an NTLM hash against the breach corpus (*hibp.Searcher
// satisfies this).
type HIBPLookup interface {
	LookupHash(ntlm string) (found bool, count int, err error)
}

// Enrichment is the BloodHound-derived signal set for one account. A zero value
// (nil pointers / empty slice) means "unknown".
type Enrichment struct {
	DADomains         []string
	ControlledObjects *int
	PwdLastSet        *int64 // epoch seconds
	PwdNeverExpires   *bool
	Enabled           *bool
}

// Enricher supplies BloodHound enrichment for a normalized username.
type Enricher interface {
	Enrich(username string) Enrichment
}

// Engine holds the pipeline's dependencies. HIBP and Enricher are optional.
type Engine struct {
	HIBP     HIBPLookup // guarded by hibpMu for hot-swap; read via hibpCount
	hibpMu   sync.RWMutex
	Enricher Enricher // guarded by encMu for hot-swap; read via enrich
	encMu    sync.RWMutex
	Lists    pwanalysis.Lists
	Policies *policy.Set // per-domain password policies (length/classes + max age)
	Now      func() time.Time
}

// SwapHIBP atomically replaces the HIBP searcher (h may be nil to disable lookups)
// and returns the previous one so the caller can Close it. Lets the breach corpus
// be refreshed (re-downloaded + re-indexed) and hot-swapped without a restart.
func (e *Engine) SwapHIBP(h HIBPLookup) HIBPLookup {
	e.hibpMu.Lock()
	defer e.hibpMu.Unlock()
	old := e.HIBP
	e.HIBP = h
	return old
}

// SwapEnricher atomically replaces the BloodHound enricher (nil to disable), so the
// connection can be (re)configured from the UI and take effect without a restart.
func (e *Engine) SwapEnricher(enr Enricher) {
	e.encMu.Lock()
	defer e.encMu.Unlock()
	e.Enricher = enr
}

// HasEnricher reports whether BloodHound enrichment is currently active.
func (e *Engine) HasEnricher() bool {
	e.encMu.RLock()
	defer e.encMu.RUnlock()
	return e.Enricher != nil
}

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

// ProcessDomain scores all cracked and uncracked accounts for a domain and
// returns the resulting model.Account records.
func (e *Engine) ProcessDomain(domain string, cracked, uncracked []secretsdump.ParsedAccount) []model.Account {
	now := e.now()

	pwUsers := map[string]int{}
	for _, a := range cracked {
		pwUsers[a.Password]++
	}
	hashUsers := map[string]int{}
	for _, a := range uncracked {
		hashUsers[a.Hash]++
	}

	// Similarity is an O(n^2) Levenshtein pass; above a cap, skip it (nil disables
	// the per-account comparison) so a large domain doesn't blow up wall-clock.
	const similarityCap = 5000
	var allPasswords []string
	if len(cracked) <= similarityCap {
		allPasswords = make([]string, 0, len(cracked))
		for _, a := range cracked {
			allPasswords = append(allPasswords, a.Password)
		}
	}

	analysisCache := map[string]*pwanalysis.Analysis{}
	simCache := map[string]float64{}

	out := make([]model.Account, 0, len(cracked)+len(uncracked))
	for _, a := range cracked {
		out = append(out, e.scoreCracked(domain, a, pwUsers[a.Password]-1, allPasswords, analysisCache, simCache, now))
	}
	for _, a := range uncracked {
		out = append(out, e.scoreUncracked(domain, a, hashUsers[a.Hash]-1, now))
	}
	// Cross-domain password-reuse + DA-share escalation is applied at the audit
	// level (model.EscalateSharedWithDA / RecomputeSharing) by the store, since it
	// must see every domain -- not just this one.
	return out
}

func (e *Engine) scoreCracked(domain string, a secretsdump.ParsedAccount, sharedWith int, allPasswords []string, analysisCache map[string]*pwanalysis.Analysis, simCache map[string]float64, now time.Time) model.Account {
	pw := a.Password
	pol := e.Policies.For(domain) // ProcessDomain is per-domain, so one policy here

	an, ok := analysisCache[pw]
	if !ok {
		an = pwanalysis.Analyze(pw, e.Lists, nil, pol.Analysis())
		analysisCache[pw] = an
	}
	simMax, ok := simCache[pw]
	if !ok {
		if sims := pwanalysis.Similar(pw, allPasswords); len(sims) > 0 {
			simMax = sims[0].Score
		}
		simCache[pw] = simMax
	}

	count := e.hibpCount(a.Hash)
	enr := e.enrich(a.Username, domain, true)

	rctx := risk.Context{
		SharedWith:          sharedWith,
		DADomains:           enr.DADomains,
		ControlledObjects:   enr.ControlledObjects,
		DaysOutOfCompliance: daysOutOfCompliance(enr.PwdLastSet, now, pol.MaxPasswordAgeDays),
		PasswordExpires:     passwordExpires(enr.PwdNeverExpires),
		HIBPBreachCount:     count,
	}
	ran := risk.Analysis{
		ComplexityLabel:       an.ComplexityLabel,
		PasswordLength:        an.PasswordLength,
		IsCommon:              an.IsCommon,
		IsDictionaryWord:      an.IsDictionaryWord,
		BannedWordsCount:      len(an.BannedWords),
		KeyboardPatternsCount: len(an.KeyboardPatterns),
		SimilarMax:            simMax,
	}
	res := risk.Score(ran, rctx)

	return model.Account{
		Username:        a.Username,
		Domain:          domain,
		Password:        pw,
		Cracked:         true,
		PasswordLength:  an.PasswordLength,
		RiskLevel:       res.Level,
		RiskScore:       res.Score,
		RiskVector:      res.Vector,
		HIBPBreached:    count > 0,
		HIBPBreachCount: count,
		DADomains:       joinDA(enr.DADomains),
		Controlled:      derefInt(enr.ControlledObjects),
		SharedWith:      sharedWith,
		Enabled:         derefBool(enr.Enabled),
		MeetsPolicy:     an.MeetsPolicy,
		Complexity:      an.ComplexityLabel,
	}
}

// scoreUncracked applies the simplified uncracked-hash scoring (base 5.0 scaled
// by privilege/share/HIBP factors). BHE is consulted only for shared hashes.
func (e *Engine) scoreUncracked(domain string, a secretsdump.ParsedAccount, sharedWith int, now time.Time) model.Account {
	count := e.hibpCount(a.Hash)
	var enr Enrichment
	if sharedWith > 0 {
		enr = e.enrich(a.Username, domain, true)
	}
	hasDA := len(enr.DADomains) > 0
	score := uncrackedScore(hasDA, sharedWith, count)

	return model.Account{
		Username:        a.Username,
		Domain:          domain,
		Cracked:         false,
		RiskLevel:       risk.ComputeLevel(score, hasDA),
		RiskScore:       score,
		RiskVector:      uncrackedVector(hasDA, enr.ControlledObjects, sharedWith, count),
		HIBPBreached:    count > 0,
		HIBPBreachCount: count,
		DADomains:       joinDA(enr.DADomains),
		Controlled:      derefInt(enr.ControlledObjects),
		SharedWith:      sharedWith,
		Enabled:         derefBool(enr.Enabled),
	}
}

func (e *Engine) hibpCount(ntlm string) int {
	e.hibpMu.RLock()
	h := e.HIBP
	e.hibpMu.RUnlock()
	if h == nil {
		return 0
	}
	if _, c, err := h.LookupHash(ntlm); err == nil {
		return c
	}
	return 0
}

func (e *Engine) enrich(username, domain string, wanted bool) Enrichment {
	if !wanted {
		return Enrichment{}
	}
	e.encMu.RLock()
	enr := e.Enricher
	e.encMu.RUnlock()
	if enr == nil {
		return Enrichment{}
	}
	return enr.Enrich(normalizeUsername(username, domain))
}

func daysOutOfCompliance(pwdLastSet *int64, now time.Time, maxAge int) *int {
	if pwdLastSet == nil {
		return nil
	}
	daysSince := int(now.Sub(time.Unix(*pwdLastSet, 0).UTC()).Hours() / 24)
	d := daysSince - maxAge
	if d < 0 {
		d = 0
	}
	return &d
}

// passwordExpires maps pwdneverexpires to risk's PasswordExpires field:
// neverExpires=true -> "No" (won't expire), false -> "Yes", nil -> "Unknown".
func passwordExpires(neverExpires *bool) string {
	if neverExpires == nil {
		return "Unknown"
	}
	if *neverExpires {
		return "No"
	}
	return "Yes"
}

func uncrackedScore(hasDA bool, sharedWith, breach int) float64 {
	priv := 1.0
	if hasDA {
		priv += 0.5
	}
	share := 1.0
	if sharedWith > 0 {
		switch {
		case sharedWith >= 1000:
			share += 0.5
		case sharedWith >= 100:
			share += 0.4
		case sharedWith >= 10:
			share += 0.3
		default:
			share += 0.2
		}
	}
	score := 5.0 * priv * share * hibp.Factor(breach)
	return math.Round(math.Min(10.0, score)*10) / 10
}

func uncrackedVector(hasDA bool, controlled *int, sharedWith, breach int) string {
	da := "N"
	if hasDA {
		da = "Y"
	}
	co := "L"
	if controlled != nil {
		if *controlled > 50 {
			co = "H"
		} else if *controlled > 10 {
			co = "M"
		}
	}
	s := sharedWith
	if s > 9 {
		s = 9
	}
	if s < 0 {
		s = 0
	}
	return fmt.Sprintf("UNCRACKED/DA:%s/CO:%s/S:%d/HIBP:%s", da, co, s, uncrackedHIBPLevel(breach))
}

func uncrackedHIBPLevel(n int) string {
	switch {
	case n >= 100000:
		return "C"
	case n >= 10000:
		return "E"
	case n >= 1000:
		return "VH"
	case n >= 100:
		return "H"
	case n >= 10:
		return "M"
	case n > 0:
		return "L"
	default:
		return "N"
	}
}

func normalizeUsername(username, domain string) string {
	if strings.Contains(username, "@") {
		return username
	}
	return username + "@" + domain
}

func joinDA(da []string) string {
	if len(da) == 0 {
		return "None"
	}
	return strings.Join(da, ", ")
}

func derefInt(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}

func derefBool(p *bool) bool { return p != nil && *p }

// BloodhoundEnricher adapts a *bloodhound.Client to the Enricher interface.
type BloodhoundEnricher struct {
	Client *bloodhound.Client
}

// Enrich fetches and flattens a user's BloodHound enrichment.
func (b BloodhoundEnricher) Enrich(username string) Enrichment {
	ud, err := b.Client.GetUserData(username)
	if err != nil || ud == nil {
		return Enrichment{}
	}
	count := bloodhound.ExtractControllableCount(ud)
	enabled := ud.Props.Enabled
	never := ud.Props.PwdNeverExpires
	enr := Enrichment{
		DADomains:         bloodhound.ExtractDADomains(ud),
		ControlledObjects: &count,
		PwdNeverExpires:   &never,
		Enabled:           &enabled,
	}
	if v, err := ud.Props.PwdLastSet.Int64(); err == nil && v > 0 {
		enr.PwdLastSet = &v
	}
	return enr
}
