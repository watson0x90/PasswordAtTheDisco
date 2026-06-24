package bloodhound

import (
	"log"
	"strings"
	"sync"
)

// BulkEnrichment holds the pre-fetched BHE data for all users, loaded via Cypher.
type BulkEnrichment struct {
	Props         map[string]BulkUserProps // key: "user@DOMAIN"
	DAUsers       map[string][]string      // key -> DA domains
	Controllables map[string]int           // key -> controlled object count
	Tier0         map[string]bool          // key -> controls a Tier-0/DA-equivalent object
}

// BulkEnricher pre-fetches ALL user data from BHE in 4 Cypher queries, then
// serves enrichment lookups from memory. This replaces the per-user REST approach
// (which made ~10 HTTP calls per user) with 4 total queries regardless of user count.
type BulkEnricher struct {
	client candidateClient
	once   sync.Once
	data   BulkEnrichment
	err    error
}

// NewBulkEnricher creates an enricher backed by bulk Cypher queries.
func NewBulkEnricher(c *Client) *BulkEnricher {
	return &BulkEnricher{client: c}
}

// newBulkEnricherWithClient creates an enricher with an arbitrary candidateClient.
// Intended for tests that inject a fake client; not for production use.
func newBulkEnricherWithClient(c candidateClient) *BulkEnricher {
	return &BulkEnricher{client: c}
}

// Prefetch loads all data from BHE. Safe to call multiple times (idempotent).
// Call this before Enrich() to ensure data is loaded.
func (b *BulkEnricher) Prefetch() error {
	b.once.Do(func() {
		log.Printf("bloodhound: bulk prefetch starting (Cypher + REST DA checks)...")

		props, err := b.client.FetchAllUserProps()
		if err != nil {
			log.Printf("bloodhound: FetchAllUserProps failed: %v", err)
			b.err = err
			return
		}
		log.Printf("bloodhound: fetched properties for %d users", len(props))

		da, err := b.client.FetchDAUsers()
		if err != nil {
			log.Printf("bloodhound: FetchDAUsers failed: %v (DA paths will be empty)", err)
			da = map[string][]string{}
		}

		ctrl, err := b.client.FetchControllableCounts()
		if err != nil {
			log.Printf("bloodhound: FetchControllableCounts failed: %v (controllables will be zero)", err)
			ctrl = map[string]int{}
		} else {
			log.Printf("bloodhound: fetched controllable counts for %d users", len(ctrl))
		}

		t0, err := b.client.FetchTier0Controllers()
		if err != nil {
			log.Printf("bloodhound: FetchTier0Controllers failed: %v (Tier-0 control will be empty)", err)
			t0 = map[string]bool{}
		} else {
			log.Printf("bloodhound: fetched Tier-0 controllers: %d users", len(t0))
		}

		b.data = BulkEnrichment{Props: props, DAUsers: da, Controllables: ctrl, Tier0: t0}
		log.Printf("bloodhound: bulk prefetch complete (DA paths will be checked per credential-relevant accounts at rescore time)")
	})
	return b.err
}

// NewBulkEnricherFromData builds an enricher whose cache is pre-populated, without a
// Cypher prefetch. Used for seeding/tests; Prefetch is not required (Lookup/Tier0 read data directly).
func NewBulkEnricherFromData(data BulkEnrichment) *BulkEnricher {
	return &BulkEnricher{data: data}
}

// normKey normalizes a "user@DOMAIN" key to "lowercase@UPPER" so lookups are
// consistent regardless of how the caller constructed the key.
// Keys are stored as "lowercasesam@UPPERDOMAIN" by the Cypher parsers.
func normKey(key string) string {
	if idx := strings.LastIndex(key, "@"); idx >= 0 {
		return strings.ToLower(key[:idx]) + "@" + strings.ToUpper(key[idx+1:])
	}
	return strings.ToLower(key)
}

// collectedDomains returns the names of all Collected==true domains from BHE.
// Called once per EnrichCandidates invocation and cached in a local slice.
func (b *BulkEnricher) collectedDomains() []string {
	ds, err := b.client.GetDomains()
	if err != nil {
		log.Printf("bloodhound: collectedDomains: GetDomains failed: %v", err)
		return nil
	}
	var out []string
	for _, d := range ds {
		if d.Collected {
			out = append(out, d.Name)
		}
	}
	return out
}

// appendUnique appends each element of extra to dst only if it is not already
// present. Used to merge DA-domain slices without introducing duplicates.
func appendUnique(dst []string, extra ...string) []string {
	seen := make(map[string]struct{}, len(dst))
	for _, v := range dst {
		seen[v] = struct{}{}
	}
	for _, v := range extra {
		if _, ok := seen[v]; !ok {
			dst = append(dst, v)
			seen[v] = struct{}{}
		}
	}
	return dst
}

// Tier0 reports whether the user controls a Tier-0 / DA-equivalent object, from the
// bulk Tier-0 prefetch set. Same key normalization as Lookup.
func (b *BulkEnricher) Tier0(key string) bool {
	return b.data.Tier0[normKey(key)]
}

// Lookup returns the enrichment for a normalized "user@DOMAIN" key.
func (b *BulkEnricher) Lookup(key string) (BulkUserProps, []string, int) {
	k := normKey(key)
	props := b.data.Props[k]
	da := b.data.DAUsers[k]
	ctrl := b.data.Controllables[k]
	return props, da, ctrl
}

// EnrichCandidates corrects the credential-obtainable subset of accounts with true
// transitive control counts (env.Count) and reachable Tier-0/DA paths (per user).
//
// Candidate gate: Cracked OR HIBPHit OR roastable (HasSPN or DontReqPreauth).
// Accounts are deduped by normalized key so each unique account is enriched once.
// For each candidate the bulk cache is overridden:
//   - Controllables[k] = env.Count (when > 0)
//   - DAUsers[k]       += newly-discovered DA domains (appendUnique)
//   - Tier0[k]         = true (when any reachable Tier-0 anchor found)
//
// This replaces CheckDAForAccounts and its first-degree Controllables gate, which
// incorrectly excluded cracked users whose bulk first-degree count was 0.
func (b *BulkEnricher) EnrichCandidates(accounts []struct {
	Key              string
	Cracked, HIBPHit bool
}) {
	domains := b.collectedDomains()

	seen := map[string]struct{}{}
	for _, a := range accounts {
		k := normKey(a.Key)
		if _, dup := seen[k]; dup {
			continue
		}
		p, ok := b.data.Props[k]
		if !ok || p.ObjectID == "" {
			continue
		}
		roastable := p.HasSPN || p.DontReqPreauth
		if !a.Cracked && !a.HIBPHit && !roastable {
			continue // not a candidate
		}
		seen[k] = struct{}{}

		total, da, t0 := enrichCandidate(b.client, p.ObjectID, domains)
		if total > 0 {
			b.data.Controllables[k] = total
		}
		if len(da) > 0 {
			b.data.DAUsers[k] = appendUnique(b.data.DAUsers[k], da...)
		}
		if t0 {
			b.data.Tier0[k] = true
		}
	}

	log.Printf("bloodhound: EnrichCandidates enriched %d credential-obtainable candidates (true transitive control + reachable Tier-0/DA)", len(seen))
}
