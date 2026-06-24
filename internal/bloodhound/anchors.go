package bloodhound

// tier0SweepMin is the minimum true transitive-control count (env.Count) required
// to trigger the non-DA Tier-0 anchor sweep in EnrichCandidate.  If a user's
// env.Count is at least this value they are checked against all Tier-0 anchors;
// below it only the DA group path is checked (cheap fast-path).
const tier0SweepMin = 100

// tier0AnchorNames returns the Tier-0 / DA-equivalent group names that a candidate's
// traversable control path is checked against (per collected domain).
// DOMAIN ADMINS is the DA anchor (-> DADomains); any anchor hit -> ControlsTier0.
// NOTE: The Domain object (DCSync) anchor is a Domain node, not a Group — it is
// resolved separately in EnrichCandidate (Task 4) via GetDomains, not via GetGroup.
func tier0AnchorNames() []string {
	return []string{
		"DOMAIN ADMINS",
		"ENTERPRISE ADMINS",
		"KRBTGT",
		"ADMINSDHOLDER",
		"ADMINISTRATORS",
	}
}

// anchorSID looks up the cached SID for the given (domain, anchorName) pair.
// Returns ("", false) on a cache miss.
func (c *Client) anchorSID(domain, anchorName string) (string, bool) {
	c.domMu.Lock()
	defer c.domMu.Unlock()
	if c.anchorSIDs == nil {
		return "", false
	}
	sid, ok := c.anchorSIDs[domain+"|"+anchorName]
	return sid, ok
}

// setAnchorSID stores sid for the (domain, anchorName) pair in the anchor SID cache.
// An empty sid stores a negative (miss) entry so the same resolution is not retried.
func (c *Client) setAnchorSID(domain, anchorName, sid string) {
	c.domMu.Lock()
	defer c.domMu.Unlock()
	if c.anchorSIDs == nil {
		c.anchorSIDs = map[string]string{}
	}
	c.anchorSIDs[domain+"|"+anchorName] = sid
}
