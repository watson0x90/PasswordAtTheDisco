package bloodhound

import (
	"log"
	"strings"
	"sync"
)

// BulkEnrichment holds the pre-fetched BHE data for all users, loaded via Cypher.
type BulkEnrichment struct {
	Props         map[string]BulkUserProps // key: "user@DOMAIN"
	DAUsers       map[string][]string     // key -> DA domains
	Controllables map[string]int          // key -> controlled object count
}

// BulkEnricher pre-fetches ALL user data from BHE in 3 Cypher queries, then
// serves enrichment lookups from memory. This replaces the per-user REST approach
// (which made ~10 HTTP calls per user) with 3 total queries regardless of user count.
type BulkEnricher struct {
	client *Client
	once   sync.Once
	data   BulkEnrichment
	err    error
}

// NewBulkEnricher creates an enricher backed by bulk Cypher queries.
func NewBulkEnricher(c *Client) *BulkEnricher {
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

		b.data = BulkEnrichment{Props: props, DAUsers: da, Controllables: ctrl}
		log.Printf("bloodhound: bulk prefetch complete (DA paths will be checked per credential-relevant accounts at rescore time)")
	})
	return b.err
}

// CheckDAForAccounts runs REST shortest-path DA checks for the credential-relevant
// subset of accounts that also have elevated privilege indicators (controllables).
// The logic: only accounts that are (cracked OR shared OR HIBP-exposed) AND have
// controllable objects are realistic DA escalation candidates worth checking.
// Additionally, Kerberoastable (hasSPN) and AS-REP roastable (dontReqPreauth)
// accounts are always checked — they're offline-crackable attack targets.
func (b *BulkEnricher) CheckDAForAccounts(accounts []struct {
	Key      string
	Cracked  bool
	Shared   bool
	HIBPHit  bool
}) {
	// Build the set: credential-relevant AND privileged, OR Kerberoastable/AS-REP roastable.
	candidates := map[string]string{} // key -> objectID
	for _, a := range accounts {
		if _, already := b.data.DAUsers[a.Key]; already {
			continue
		}
		p, hasProps := b.data.Props[a.Key]
		if !hasProps || p.ObjectID == "" {
			continue
		}

		// Always check Kerberoastable and AS-REP roastable accounts (offline crack targets)
		if p.HasSPN || p.DontReqPreauth {
			candidates[a.Key] = p.ObjectID
			continue
		}

		// Check credential-relevant accounts that have controllables
		if !a.Cracked && !a.Shared && !a.HIBPHit {
			continue
		}
		if _, hasCtrl := b.data.Controllables[a.Key]; !hasCtrl {
			continue
		}
		candidates[a.Key] = p.ObjectID
	}
	if len(candidates) == 0 {
		log.Printf("bloodhound: no credential-relevant privileged accounts need DA path checks")
		return
	}
	log.Printf("bloodhound: checking DA paths for %d accounts (privileged credential-relevant + Kerberoastable/AS-REP)...", len(candidates))
	additional := b.client.CheckDAPathsREST(candidates, b.data.DAUsers)
	for k, domains := range additional {
		b.data.DAUsers[k] = append(b.data.DAUsers[k], domains...)
	}
	log.Printf("bloodhound: total DA pathways: %d users", len(b.data.DAUsers))
}

// Lookup returns the enrichment for a normalized "user@DOMAIN" key.
func (b *BulkEnricher) Lookup(key string) (BulkUserProps, []string, int) {
	// Keys are stored as "lowercasesam@UPPERDOMAIN" by the Cypher parsers.
	// NormalizeUsername builds "user@DOMAIN" (username as-is, domain as-is from account).
	// Normalize to match: lowercase the username part, uppercase the domain part.
	k := key
	if idx := strings.LastIndex(k, "@"); idx >= 0 {
		k = strings.ToLower(k[:idx]) + "@" + strings.ToUpper(k[idx+1:])
	} else {
		k = strings.ToLower(k)
	}
	props := b.data.Props[k]
	da := b.data.DAUsers[k]
	ctrl := b.data.Controllables[k]
	return props, da, ctrl
}
