package bloodhound

// fakeCandidateClient is an in-package test double implementing the full
// candidateClient interface. It is seeded so tests control what each method returns
// without a live BloodHound server. Reused by Tasks 5-6 test suites.
//
// Seedable fields:
//   - controllablesByID: objectID -> env.Count returned by GetUserControllables
//   - paths:             (src,dst) -> hasPath returned by GetShortestPath
//   - groups:            group name -> searchHit (for GetGroup)
//   - domains:           slice returned by GetDomains
//   - anchorSIDCache:    (domain,anchorName) cache
//
// Call counts are tracked in getShortestPathCalls and getUserControllablesCalls for
// assertions on expensive-call gating.

import (
	"sync"
	"testing"
)

type pathKey struct{ src, dst string }

type fakeCandidateClient struct {
	mu sync.Mutex

	// Seed data
	controllablesByID map[string]int       // objectID -> total
	paths             map[pathKey]bool     // (src,dst) -> hasPath (known=true always)
	groups            map[string]searchHit // group name -> hit (found=true)
	domains           []Domain

	// Anchor SID cache (mirrors Client behaviour)
	anchorSIDCache map[string]string // "domain|anchorName" -> sid

	// Call counters
	getUserControllablesCalls int
	getShortestPathCalls      int
}

func newFakeCandidateClient() *fakeCandidateClient {
	return &fakeCandidateClient{
		controllablesByID: map[string]int{},
		paths:             map[pathKey]bool{},
		groups:            map[string]searchHit{},
		anchorSIDCache:    map[string]string{},
	}
}

// seedControllables sets the env.Count that GetUserControllables returns for objectID.
func (f *fakeCandidateClient) seedControllables(objectID string, total int) {
	f.controllablesByID[objectID] = total
}

// seedPath marks a shortest-path result (hasPath=true) from src to dst.
func (f *fakeCandidateClient) seedPath(src, dst string) {
	f.paths[pathKey{src, dst}] = true
}

// seedGroup registers a group name -> objectID mapping for GetGroup.
func (f *fakeCandidateClient) seedGroup(name, objectID string) {
	f.groups[name] = searchHit{Name: name, ObjectID: objectID}
}

// seedDomain appends a Domain to the list returned by GetDomains.
func (f *fakeCandidateClient) seedDomain(d Domain) {
	f.domains = append(f.domains, d)
}

// --- candidateClient implementation ---

func (f *fakeCandidateClient) GetUserControllables(objectID string) (map[string]map[string]int, map[string][]ControllableItem, int, error) {
	f.mu.Lock()
	f.getUserControllablesCalls++
	total := f.controllablesByID[objectID]
	f.mu.Unlock()
	return nil, nil, total, nil
}

func (f *fakeCandidateClient) GetShortestPath(src, dst string) (hasPath, known bool, err error) {
	f.mu.Lock()
	f.getShortestPathCalls++
	hp := f.paths[pathKey{src, dst}]
	f.mu.Unlock()
	return hp, true, nil
}

func (f *fakeCandidateClient) GetGroup(name string) (searchHit, bool, error) {
	f.mu.Lock()
	hit, ok := f.groups[name]
	f.mu.Unlock()
	return hit, ok, nil
}

func (f *fakeCandidateClient) GetDomains() ([]Domain, error) {
	f.mu.Lock()
	ds := f.domains
	f.mu.Unlock()
	return ds, nil
}

func (f *fakeCandidateClient) anchorSID(domain, anchorName string) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	sid, ok := f.anchorSIDCache[domain+"|"+anchorName]
	return sid, ok
}

func (f *fakeCandidateClient) setAnchorSID(domain, anchorName, sid string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.anchorSIDCache[domain+"|"+anchorName] = sid
}

// Bulk prefetch methods — not used by enrichCandidate; return zero/nil.

func (f *fakeCandidateClient) FetchAllUserProps() (map[string]BulkUserProps, error) {
	return map[string]BulkUserProps{}, nil
}

func (f *fakeCandidateClient) FetchDAUsers() (map[string][]string, error) {
	return map[string][]string{}, nil
}

func (f *fakeCandidateClient) FetchControllableCounts() (map[string]int, error) {
	return map[string]int{}, nil
}

func (f *fakeCandidateClient) FetchTier0Controllers() (map[string]bool, error) {
	return map[string]bool{}, nil
}

func (f *fakeCandidateClient) CheckDAPathsREST(objectIDs map[string]string, existing map[string][]string) map[string][]string {
	return map[string][]string{}
}

// --- Tests ---

// TestEnrichCandidateTransitive covers three cases:
//
//  1. High-controller (env.Count=4000): path to DA group + a Tier-0 anchor → total=4000,
//     daDomains=[CORP.LOCAL], controlsTier0=true.
//
//  2. Zero-controller (env.Count=0): no reachability calls at all — GetShortestPath
//     must NOT be called (asserted via call count).
//
//  3. Mid-controller (1 ≤ env.Count < tier0SweepMin): DA path → daDomains set +
//     controlsTier0=true; but the extra Tier-0 anchors (EA/KRBTGT/etc.) must NOT be
//     swept (getShortestPathCalls == 1, exactly the DA check).
func TestEnrichCandidateTransitive(t *testing.T) {
	const (
		corp      = "CORP.LOCAL"
		uSID      = "u-sid"
		noCtrlSID = "no-control-sid"
		midSID    = "mid-sid"

		daSID   = "S-1-5-21-1111-512" // DA group SID
		krbtSID = "S-1-5-21-1111-502" // KRBTGT SID
	)

	// ---- Case 1: high-controller (env.Count = 4000) ----
	t.Run("high_controller", func(t *testing.T) {
		fc := newFakeCandidateClient()
		fc.seedControllables(uSID, 4000)

		// DA group
		fc.seedGroup("DOMAIN ADMINS@"+corp, daSID)
		fc.seedPath(uSID, daSID) // traversable path to DA

		// KRBTGT (a Tier-0 anchor in tier0AnchorNames()[1:])
		fc.seedGroup("KRBTGT@"+corp, krbtSID)
		fc.seedPath(uSID, krbtSID)

		total, daDomains, t0 := enrichCandidate(fc, uSID, []string{corp})

		if total != 4000 {
			t.Errorf("total = %d, want 4000", total)
		}
		if len(daDomains) != 1 || daDomains[0] != corp {
			t.Errorf("daDomains = %v, want [%s]", daDomains, corp)
		}
		if !t0 {
			t.Error("controlsTier0 = false, want true (path to Tier-0 anchor)")
		}
		if fc.getUserControllablesCalls != 1 {
			t.Errorf("GetUserControllables called %d times, want 1", fc.getUserControllablesCalls)
		}
		// At minimum 1 GetShortestPath call (DA group) must have been made.
		if fc.getShortestPathCalls < 1 {
			t.Errorf("GetShortestPath called %d times, want ≥1", fc.getShortestPathCalls)
		}
	})

	// ---- Case 2: zero-controller (env.Count = 0) ----
	t.Run("zero_controller", func(t *testing.T) {
		fc := newFakeCandidateClient()
		fc.seedControllables(noCtrlSID, 0)

		total, daDomains, t0 := enrichCandidate(fc, noCtrlSID, []string{corp})

		if total != 0 {
			t.Errorf("total = %d, want 0", total)
		}
		if len(daDomains) != 0 {
			t.Errorf("daDomains = %v, want nil/empty", daDomains)
		}
		if t0 {
			t.Error("controlsTier0 = true, want false for zero-controller")
		}
		if fc.getShortestPathCalls != 0 {
			t.Errorf("GetShortestPath called %d times, want 0 (gated out by env.Count=0)", fc.getShortestPathCalls)
		}
	})

	// ---- Case 3: mid-controller (1 ≤ env.Count < tier0SweepMin) ----
	// DA path → daDomains set + controlsTier0=true, but extra Tier-0 anchors NOT swept.
	t.Run("mid_controller_da_only_sweep", func(t *testing.T) {
		// Use a count just below the sweep threshold.
		midCount := tier0SweepMin - 1

		fc := newFakeCandidateClient()
		fc.seedControllables(midSID, midCount)

		// DA group resolvable and has a path.
		fc.seedGroup("DOMAIN ADMINS@"+corp, daSID)
		fc.seedPath(midSID, daSID)

		// Seed KRBTGT too — but it must NOT be queried (below tier0SweepMin).
		fc.seedGroup("KRBTGT@"+corp, krbtSID)
		fc.seedPath(midSID, krbtSID)

		total, daDomains, t0 := enrichCandidate(fc, midSID, []string{corp})

		if total != midCount {
			t.Errorf("total = %d, want %d", total, midCount)
		}
		if len(daDomains) != 1 || daDomains[0] != corp {
			t.Errorf("daDomains = %v, want [%s]", daDomains, corp)
		}
		if !t0 {
			t.Error("controlsTier0 = false, want true (DA path counts as Tier-0)")
		}
		// Only the DA anchor check should have been made — exactly 1 GetShortestPath call.
		if fc.getShortestPathCalls != 1 {
			t.Errorf("GetShortestPath called %d times, want exactly 1 (DA only; no extra anchor sweep below tier0SweepMin=%d)", fc.getShortestPathCalls, tier0SweepMin)
		}
	})
}
