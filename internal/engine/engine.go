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
	HasSPN            *bool // Kerberoastable
	DontReqPreauth    *bool // AS-REP roastable
	// Enriched is true when the enricher actually returned BloodHound data for the
	// user (per-account coverage). False on the zero Enrichment{} (user not found,
	// BHE off, or an error) — drives model.Account.Coverage and the Unknown Impact.
	Enriched bool
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
	listsMu  sync.RWMutex // guards Lists.ForbiddenWords for hot-swap
	Policies *policy.Set  // per-domain password policies (length/classes + max age)
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

// SwapForbiddenWords atomically replaces the analysis forbidden-words set so the
// list can be edited from the UI and take effect for the next analysis without a
// restart.
func (e *Engine) SwapForbiddenWords(set pwanalysis.Set) {
	e.listsMu.Lock()
	defer e.listsMu.Unlock()
	e.Lists.ForbiddenWords = set
}

// ForbiddenWords returns the current forbidden-words set under the read lock.
func (e *Engine) ForbiddenWords() pwanalysis.Set {
	e.listsMu.RLock()
	defer e.listsMu.RUnlock()
	return e.Lists.ForbiddenWords
}

// snapshotLists returns a copy of the wordlists read entirely under the read
// lock, so the analysis path never reads the swappable ForbiddenWords field
// lock-free (which would race SwapForbiddenWords).
func (e *Engine) snapshotLists() pwanalysis.Lists {
	e.listsMu.RLock()
	defer e.listsMu.RUnlock()
	return e.Lists
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

// CurrentEnricher returns the configured enricher (nil if BHE is off).
func (e *Engine) CurrentEnricher() Enricher {
	e.encMu.RLock()
	defer e.encMu.RUnlock()
	return e.Enricher
}

// BuildBulkEnricher attempts to create a BulkBloodhoundEnricher by running 3
// Cypher queries against BHE. Returns nil if BHE is not configured or if the
// bulk prefetch fails (caller should fall back to per-user enrichment).
func (e *Engine) BuildBulkEnricher() Enricher {
	e.encMu.RLock()
	enr := e.Enricher
	e.encMu.RUnlock()
	if enr == nil {
		return nil
	}
	// Only works if the enricher wraps a *bloodhound.Client (the normal case).
	bhe, ok := enr.(BloodhoundEnricher)
	if !ok {
		return nil
	}
	bulk := bloodhound.NewBulkEnricher(bhe.Client)
	if err := bulk.Prefetch(); err != nil {
		return nil // fall back to per-user
	}
	return BulkBloodhoundEnricher{Bulk: bulk}
}

// ProcessDomain scores all cracked and uncracked accounts for a domain and
// returns the resulting model.Account records. BloodHound enrichment is applied
// via the currently configured Enricher (if any).
func (e *Engine) ProcessDomain(domain string, cracked, uncracked []secretsdump.ParsedAccount) []model.Account {
	return e.processDomainWith(domain, cracked, uncracked, e.CurrentEnricher())
}

// ProcessDomainNoEnrich scores all cracked and uncracked accounts for a domain
// without any BloodHound enrichment, even if an Enricher is configured. Use
// this for fast upload-time scoring where BHE is applied later by a background job.
func (e *Engine) ProcessDomainNoEnrich(domain string, cracked, uncracked []secretsdump.ParsedAccount) []model.Account {
	return e.processDomainWith(domain, cracked, uncracked, nil)
}

func (e *Engine) processDomainWith(domain string, cracked, uncracked []secretsdump.ParsedAccount, enr Enricher) []model.Account {
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
	pwAccounts := map[string][]model.SimilarPeer{} // password -> accounts using it (username/domain)
	if len(cracked) <= similarityCap {
		allPasswords = make([]string, 0, len(cracked))
		for _, a := range cracked {
			allPasswords = append(allPasswords, a.Password)
			pwAccounts[a.Password] = append(pwAccounts[a.Password], model.SimilarPeer{Username: a.Username, Domain: domain})
		}
	}

	analysisCache := map[string]*pwanalysis.Analysis{}
	simCache := map[string]float64{}
	peersCache := map[string][]model.SimilarPeer{}

	out := make([]model.Account, 0, len(cracked)+len(uncracked))
	for _, a := range cracked {
		out = append(out, e.scoreCracked(domain, a, pwUsers[a.Password]-1, allPasswords, pwAccounts, analysisCache, simCache, peersCache, now, enr))
	}
	for _, a := range uncracked {
		out = append(out, e.scoreUncracked(domain, a, hashUsers[a.Hash]-1, now, enr))
	}
	// Cross-domain password-reuse + DA-share escalation is applied at the audit
	// level (model.EscalateSharedWithDA / RecomputeSharing) by the store, since it
	// must see every domain -- not just this one.
	return out
}

// Rescore re-runs scoring over an existing account set, grouped by domain. An account
// whose Password is non-empty is scored as cracked, the rest as uncracked. Used after
// applying newly cracked passwords (by NT hash) to a stored audit, so the formerly
// uncracked accounts get full cracked scoring. (Re-runs BHE enrichment via the
// currently configured Enricher.)
func (e *Engine) Rescore(accts []model.Account) []model.Account {
	return e.rescoreWith(accts, e.CurrentEnricher())
}

// RescoreWith re-runs scoring over an existing account set using an explicit enricher.
// Pass nil to score without any BloodHound enrichment.
func (e *Engine) RescoreWith(accts []model.Account, enr Enricher) []model.Account {
	return e.rescoreWith(accts, enr)
}

func (e *Engine) rescoreWith(accts []model.Account, enr Enricher) []model.Account {
	order := []string{}
	byDomain := map[string][]model.Account{}
	for _, a := range accts {
		if _, ok := byDomain[a.Domain]; !ok {
			order = append(order, a.Domain)
		}
		byDomain[a.Domain] = append(byDomain[a.Domain], a)
	}
	out := make([]model.Account, 0, len(accts))
	for _, dom := range order {
		var cracked, uncracked []secretsdump.ParsedAccount
		for _, a := range byDomain[dom] {
			pa := secretsdump.ParsedAccount{Username: a.Username, Domain: a.Domain, Hash: a.NTHash, Password: a.Password, Cracked: a.Password != ""}
			if pa.Cracked {
				cracked = append(cracked, pa)
			} else {
				uncracked = append(uncracked, pa)
			}
		}
		out = append(out, e.processDomainWith(dom, cracked, uncracked, enr)...)
	}
	return out
}

func (e *Engine) scoreCracked(domain string, a secretsdump.ParsedAccount, sharedWith int, allPasswords []string, pwAccounts map[string][]model.SimilarPeer, analysisCache map[string]*pwanalysis.Analysis, simCache map[string]float64, peersCache map[string][]model.SimilarPeer, now time.Time, enr Enricher) model.Account {
	pw := a.Password
	pol := e.Policies.For(domain) // ProcessDomain is per-domain, so one policy here

	an, ok := analysisCache[pw]
	if !ok {
		an = pwanalysis.Analyze(pw, e.snapshotLists(), nil, pol.Analysis())
		analysisCache[pw] = an
	}
	simMax, ok := simCache[pw]
	if !ok {
		sims := pwanalysis.Similar(pw, allPasswords)
		if len(sims) > 0 {
			simMax = sims[0].Score
		}
		simCache[pw] = simMax
		// Map the similar passwords back to the accounts using them (same domain),
		// top 5 by score. Self never appears: Similar() excludes exact matches, so
		// s.Password != pw and pwAccounts[s.Password] cannot contain this account.
		peers := make([]model.SimilarPeer, 0, 5)
		seen := map[string]bool{}
		for _, s := range sims {
			for _, acct := range pwAccounts[s.Password] {
				key := acct.Domain + "/" + acct.Username
				if seen[key] {
					continue
				}
				seen[key] = true
				peers = append(peers, model.SimilarPeer{Username: acct.Username, Domain: acct.Domain, Score: s.Score})
			}
			if len(peers) >= 5 {
				break
			}
		}
		if len(peers) > 5 {
			peers = peers[:5]
		}
		peersCache[pw] = peers
	}

	count := e.hibpCount(a.Hash)
	enrData := enrichVia(enr, a.Username, domain)

	daysOOC := daysOutOfCompliance(enrData.PwdLastSet, now, pol.MaxPasswordAgeDays)
	rctx := risk.Context{
		SharedWith:          sharedWith,
		DADomains:           enrData.DADomains,
		ControlledObjects:   enrData.ControlledObjects,
		DaysOutOfCompliance: daysOOC,
		PasswordExpires:     passwordExpires(enrData.PwdNeverExpires),
		HIBPBreachCount:     count,
		DomainRiskLevel:     pol.DomainRiskLevel,
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

	var pwdLastSet int64
	if enrData.PwdLastSet != nil {
		pwdLastSet = *enrData.PwdLastSet
	}
	var daysOOCVal int
	if daysOOC != nil {
		daysOOCVal = *daysOOC
	}

	return model.Account{
		Username:        a.Username,
		Domain:          domain,
		Password:        pw,
		NTHash:          strings.ToUpper(a.Hash),
		Cracked:         true,
		PasswordLength:  an.PasswordLength,
		RiskLevel:       res.Level,
		RiskScore:       res.Score,
		RiskVector:      res.Vector,
		HIBPBreached:    count > 0,
		HIBPBreachCount: count,
		DADomains:       joinDA(enrData.DADomains),
		Controlled:      derefInt(enrData.ControlledObjects),
		SharedWith:      sharedWith,
		Enabled:         enabledOrUnknown(enrData.Enabled),
		Coverage:        coverageState(enrData.Enriched),
		MeetsPolicy:     an.MeetsPolicy,
		Complexity:      an.ComplexityLabel,
		// wordlist weakness signals (counts/booleans + matched substrings; see Redacted())
		IsCommon:             an.IsCommon,
		IsDictionaryWord:     an.IsDictionaryWord,
		BannedWordCount:      len(an.BannedWords),
		KeyboardPatternCount: len(an.KeyboardPatterns),
		BannedWords:          an.BannedWords,
		KeyboardPatterns:     an.KeyboardPatterns,
		// Temporal/privilege signals for the UI
		PwdLastSet:          pwdLastSet,
		PwdNeverExpires:     enrData.PwdNeverExpires,
		DaysOutOfCompliance: daysOOCVal,
		SimilarityScore:     simMax,
		SimilarPeers:        peersCache[pw],
		HasSPN:              enrData.HasSPN,
		DontReqPreauth:      enrData.DontReqPreauth,
		// Score breakdown for per-account factor visibility
		ScoreBreakdown: &model.ScoreBreakdown{
			BaseScore:          res.Breakdown.BaseScore,
			ComplexityFactor:   res.Breakdown.ComplexityFactor,
			LengthFactor:       res.Breakdown.LengthFactor,
			DictionaryFactor:   res.Breakdown.DictionaryFactor,
			SimilarityFactor:   res.Breakdown.SimilarityFactor,
			TemporalScore:      res.Breakdown.TemporalScore,
			ComplianceFactor:   res.Breakdown.ComplianceFactor,
			ExpirationFactor:   res.Breakdown.ExpirationFactor,
			EnvironmentalScore: res.Breakdown.EnvironmentalScore,
			PrivilegeFactor:    res.Breakdown.PrivilegeFactor,
			ShareFactor:        res.Breakdown.ShareFactor,
			DomainFactor:       res.Breakdown.DomainFactor,
			HIBPFactor:         res.Breakdown.HIBPFactor,
		},
	}
}

// scoreUncracked applies the simplified uncracked-hash scoring (base 5.0 scaled
// by privilege/share/HIBP factors). BHE is always consulted when available so
// DA pathways, controlled objects, and account properties are captured even for
// uncracked accounts (their hash may be in HIBP or shared with a DA).
func (e *Engine) scoreUncracked(domain string, a secretsdump.ParsedAccount, sharedWith int, now time.Time, enr Enricher) model.Account {
	count := e.hibpCount(a.Hash)
	enrData := enrichVia(enr, a.Username, domain)
	hasDA := len(enrData.DADomains) > 0
	score := uncrackedScore(hasDA, sharedWith, count)

	var pwdLastSet int64
	if enrData.PwdLastSet != nil {
		pwdLastSet = *enrData.PwdLastSet
	}

	return model.Account{
		Username:        a.Username,
		Domain:          domain,
		NTHash:          strings.ToUpper(a.Hash),
		Cracked:         false,
		RiskLevel:       risk.ComputeLevel(score, hasDA),
		RiskScore:       score,
		RiskVector:      uncrackedVector(hasDA, enrData.ControlledObjects, sharedWith, count),
		HIBPBreached:    count > 0,
		HIBPBreachCount: count,
		DADomains:       joinDA(enrData.DADomains),
		Controlled:      derefInt(enrData.ControlledObjects),
		SharedWith:      sharedWith,
		Enabled:         enabledOrUnknown(enrData.Enabled),
		Coverage:        coverageState(enrData.Enriched),
		PwdLastSet:      pwdLastSet,
		PwdNeverExpires: enrData.PwdNeverExpires,
		HasSPN:          enrData.HasSPN,
		DontReqPreauth:  enrData.DontReqPreauth,
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

// enrichVia fetches enrichment from enr; returns an empty Enrichment if enr is nil.
func enrichVia(enr Enricher, username, domain string) Enrichment {
	if enr == nil {
		return Enrichment{}
	}
	return enr.Enrich(NormalizeUsername(username, domain))
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

// NormalizeUsername returns "user@DOMAIN". If username already contains "@" it
// is returned unchanged; otherwise domain is appended. Used to build the key
// that BloodHound enrichers expect.
func NormalizeUsername(username, domain string) string {
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

// enabledOrUnknown treats a missing enabled-status (no BloodHound data) as enabled,
// so a "disabled" flag fires only on an explicit disabled signal -- not on absent data.
func enabledOrUnknown(p *bool) bool { return p == nil || *p }

// coverageState maps the per-account Enriched bit to the model coverage string.
func coverageState(enriched bool) string {
	if enriched {
		return "full"
	}
	return "none"
}

// BloodhoundEnricher adapts a *bloodhound.Client to the Enricher interface.
// This is the per-user REST version (slow, used for single-user lookups).
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
	hasSPN := ud.Props.HasSPN
	dontReqPreauth := ud.Props.DontReqPreauth
	enr := Enrichment{
		DADomains:         bloodhound.ExtractDADomains(ud),
		ControlledObjects: &count,
		PwdNeverExpires:   &never,
		Enabled:           &enabled,
		HasSPN:            &hasSPN,
		DontReqPreauth:    &dontReqPreauth,
		Enriched:          true,
	}
	if v, err := ud.Props.PwdLastSet.Int64(); err == nil && v > 0 {
		enr.PwdLastSet = &v
	}
	return enr
}

// BulkBloodhoundEnricher satisfies the Enricher interface using pre-fetched bulk
// Cypher data. Instantiate with NewBulkEnricher, call Prefetch once, then use as
// an Enricher for re-scoring. O(1) per lookup — no network calls during scoring.
type BulkBloodhoundEnricher struct {
	Bulk *bloodhound.BulkEnricher
}

// Enrich returns enrichment data from the pre-fetched bulk cache.
func (b BulkBloodhoundEnricher) Enrich(username string) Enrichment {
	props, daDomains, ctrl := b.Bulk.Lookup(username)
	enabled := props.Enabled
	never := props.PwdNeverExpires
	hasSPN := props.HasSPN
	dontReqPreauth := props.DontReqPreauth
	var pwdLastSet *int64
	if props.PwdLastSet > 0 {
		v := props.PwdLastSet
		pwdLastSet = &v
	}
	return Enrichment{
		DADomains:         daDomains,
		ControlledObjects: &ctrl,
		PwdNeverExpires:   &never,
		Enabled:           &enabled,
		PwdLastSet:        pwdLastSet,
		HasSPN:            &hasSPN,
		DontReqPreauth:    &dontReqPreauth,
		// A bulk miss returns the zero BulkUserProps{} (empty ObjectID). A hit is
		// populated from a real Cypher row, so ObjectID is non-empty.
		Enriched: props.ObjectID != "",
	}
}
