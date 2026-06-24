package bloodhound

// candidateClient is the subset of *Client used by per-candidate enrichment and
// the bulk prefetch, so tests can inject a fake without a live BloodHound server.
// *Client satisfies this interface (compile-time assertion below).
type candidateClient interface {
	// Bulk prefetch methods (used by BulkEnricher.Prefetch and CheckDAForAccounts).
	FetchAllUserProps() (map[string]BulkUserProps, error)
	FetchDAUsers() (map[string][]string, error)
	FetchControllableCounts() (map[string]int, error)
	FetchTier0Controllers() (map[string]bool, error)
	CheckDAPathsREST(objectIDs map[string]string, existing map[string][]string) map[string][]string

	// Per-candidate enrichment methods (used by EnrichCandidate in Task 4+).
	GetUserControllables(objectID string) (map[string]map[string]int, map[string][]ControllableItem, int, error)
	GetShortestPath(src, dst string) (hasPath, known bool, err error)
	GetGroup(name string) (searchHit, bool, error)
	GetDomains() ([]Domain, error)
	anchorSID(domain, anchorName string) (string, bool)
	setAnchorSID(domain, anchorName, sid string)
}

// Compile-time assertion: *Client must satisfy candidateClient.
var _ candidateClient = (*Client)(nil)
