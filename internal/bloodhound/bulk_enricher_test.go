package bloodhound

import "testing"

func TestBulkEnricherTier0(t *testing.T) {
	b := NewBulkEnricherFromData(BulkEnrichment{
		Props: map[string]BulkUserProps{"svc@CORP": {ObjectID: "S-1-5-21-1"}},
		Tier0: map[string]bool{"svc@CORP": true},
	})
	if !b.Tier0("svc@CORP") {
		t.Errorf("Tier0(svc@CORP) = false, want true")
	}
	// Key normalization: mixed-case input must still resolve.
	if !b.Tier0("SVC@corp") {
		t.Errorf("Tier0(SVC@corp) = false, want true (case-normalized)")
	}
	if b.Tier0("other@CORP") {
		t.Errorf("Tier0(other@CORP) = true, want false (not in set)")
	}
}

// TestEnrichCandidatesGateFixed is the primary regression test for the bug where a
// cracked user with first-degree Controllables==0 (baseline) but 4k transitive control
// was not enriched. After EnrichCandidates the bulk cache must reflect the true counts.
func TestEnrichCandidatesGateFixed(t *testing.T) {
	const (
		corp   = "CORP.LOCAL"
		uKey   = "alice@CORP.LOCAL"
		uObjID = "S-1-5-21-1111-1001"
		daSID  = "S-1-5-21-1111-512"
	)

	fc := newFakeCandidateClient()
	fc.seedDomain(Domain{Name: corp, Collected: true})
	fc.seedControllables(uObjID, 4000)
	fc.seedGroup("DOMAIN ADMINS@"+corp, daSID)
	fc.seedPath(uObjID, daSID)

	// Seed Props with the user; first-degree Controllables stays 0 (the bug state).
	b := newBulkEnricherWithClient(fc)
	b.data = BulkEnrichment{
		Props: map[string]BulkUserProps{
			uKey: {ObjectID: uObjID, Enabled: true},
		},
		DAUsers:       map[string][]string{},
		Controllables: map[string]int{}, // first-degree = 0 (would gate out old code)
		Tier0:         map[string]bool{},
	}

	accounts := []struct {
		Key              string
		Cracked, HIBPHit bool
	}{
		{Key: uKey, Cracked: true, HIBPHit: false},
	}
	b.EnrichCandidates(accounts)

	if got := b.data.Controllables[uKey]; got != 4000 {
		t.Errorf("Controllables[%q] = %d, want 4000 (gate bug fixed)", uKey, got)
	}
	if len(b.data.DAUsers[uKey]) == 0 {
		t.Errorf("DAUsers[%q] = %v, want [%s]", uKey, b.data.DAUsers[uKey], corp)
	}
	if !b.data.Tier0[uKey] {
		t.Errorf("Tier0[%q] = false, want true", uKey)
	}
}

// TestEnrichCandidatesDedup asserts that an account matching both Cracked AND
// HIBPHit is enriched exactly once (GetUserControllables called once).
func TestEnrichCandidatesDedup(t *testing.T) {
	const (
		corp   = "CORP.LOCAL"
		uKey   = "bob@CORP.LOCAL"
		uObjID = "S-1-5-21-1111-1002"
		daSID  = "S-1-5-21-1111-512"
	)

	fc := newFakeCandidateClient()
	fc.seedDomain(Domain{Name: corp, Collected: true})
	fc.seedControllables(uObjID, 500)
	fc.seedGroup("DOMAIN ADMINS@"+corp, daSID)

	b := newBulkEnricherWithClient(fc)
	b.data = BulkEnrichment{
		Props:         map[string]BulkUserProps{uKey: {ObjectID: uObjID}},
		DAUsers:       map[string][]string{},
		Controllables: map[string]int{},
		Tier0:         map[string]bool{},
	}

	// Same key appears twice (cracked AND HIBP hit) — must be processed only once.
	accounts := []struct {
		Key              string
		Cracked, HIBPHit bool
	}{
		{Key: uKey, Cracked: true, HIBPHit: false},
		{Key: uKey, Cracked: false, HIBPHit: true},
	}
	b.EnrichCandidates(accounts)

	if fc.getUserControllablesCalls != 1 {
		t.Errorf("GetUserControllables called %d times, want 1 (dedup)", fc.getUserControllablesCalls)
	}
}

// TestEnrichCandidatesRoastable asserts that an account that is NOT cracked and NOT
// HIBP-hit but IS Kerberoastable (HasSPN) is included as a candidate.
func TestEnrichCandidatesRoastable(t *testing.T) {
	const (
		corp   = "CORP.LOCAL"
		uKey   = "svc@CORP.LOCAL"
		uObjID = "S-1-5-21-1111-1003"
		daSID  = "S-1-5-21-1111-512"
	)

	fc := newFakeCandidateClient()
	fc.seedDomain(Domain{Name: corp, Collected: true})
	fc.seedControllables(uObjID, 200)
	fc.seedGroup("DOMAIN ADMINS@"+corp, daSID)
	fc.seedPath(uObjID, daSID)

	b := newBulkEnricherWithClient(fc)
	b.data = BulkEnrichment{
		Props:         map[string]BulkUserProps{uKey: {ObjectID: uObjID, HasSPN: true}},
		DAUsers:       map[string][]string{},
		Controllables: map[string]int{},
		Tier0:         map[string]bool{},
	}

	// Not cracked, not HIBP — but HasSPN => roastable => candidate.
	accounts := []struct {
		Key              string
		Cracked, HIBPHit bool
	}{
		{Key: uKey, Cracked: false, HIBPHit: false},
	}
	b.EnrichCandidates(accounts)

	if fc.getUserControllablesCalls != 1 {
		t.Errorf("GetUserControllables called %d times, want 1 (roastable is a candidate)", fc.getUserControllablesCalls)
	}
	if got := b.data.Controllables[uKey]; got != 200 {
		t.Errorf("Controllables[%q] = %d, want 200", uKey, got)
	}
}

// TestEnrichCandidatesNonCandidateSkipped asserts that an account that is neither
// cracked, HIBP-hit, nor roastable is NOT enriched.
func TestEnrichCandidatesNonCandidateSkipped(t *testing.T) {
	const (
		corp   = "CORP.LOCAL"
		uKey   = "plain@CORP.LOCAL"
		uObjID = "S-1-5-21-1111-1004"
	)

	fc := newFakeCandidateClient()
	fc.seedDomain(Domain{Name: corp, Collected: true})
	fc.seedControllables(uObjID, 999)

	b := newBulkEnricherWithClient(fc)
	b.data = BulkEnrichment{
		Props:         map[string]BulkUserProps{uKey: {ObjectID: uObjID}}, // no HasSPN, no DontReqPreauth
		DAUsers:       map[string][]string{},
		Controllables: map[string]int{},
		Tier0:         map[string]bool{},
	}

	// Not cracked, not HIBP, not roastable — must be skipped entirely.
	accounts := []struct {
		Key              string
		Cracked, HIBPHit bool
	}{
		{Key: uKey, Cracked: false, HIBPHit: false},
	}
	b.EnrichCandidates(accounts)

	if fc.getUserControllablesCalls != 0 {
		t.Errorf("GetUserControllables called %d times, want 0 (non-candidate must be skipped)", fc.getUserControllablesCalls)
	}
	if _, ok := b.data.Controllables[uKey]; ok {
		t.Errorf("Controllables[%q] must not be set for a non-candidate", uKey)
	}
}
