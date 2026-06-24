package bloodhound

import "strings"

// tier0SweepMin is the minimum true transitive-control count (env.Count) required
// to trigger the non-DA Tier-0 anchor sweep in EnrichCandidate.  If a user's
// env.Count is at least this value they are checked against all Tier-0 anchors;
// below it only the DA group path is checked (cheap fast-path).
const tier0SweepMin = 100

// tier0AnchorNames returns the Tier-0 / DA-equivalent group names that a candidate's
// traversable control path is checked against (per collected domain).
// DOMAIN ADMINS is the DA anchor (-> DADomains); any anchor hit -> ControlsTier0.
// NOTE: The Domain object (DCSync) anchor is a Domain node, not a Group — it is
// resolved separately in enrichCandidate via GetDomains, not via GetGroup.
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

// enrichCandidate performs true per-user transitive enrichment for one candidate:
//
//  1. Calls GetUserControllables(objectID) → env.Count (true transitive total).
//     If total == 0 or an error occurs, returns (total, nil, false) immediately —
//     no reachability calls are made (env.Count > 0 gate).
//
//  2. For each domain, resolves the DA-group SID (via anchor cache or GetGroup),
//     then calls GetShortestPath. A traversable path appends the domain to daDomains
//     and sets controlsTier0 = true.
//
//  3. If total >= tier0SweepMin, also sweeps the remaining Tier-0 anchors
//     (tier0AnchorNames()[1:] = EA/KRBTGT/AdminSDHolder/Administrators, resolved via
//     GetGroup) plus the Domain object (DCSync, resolved via GetDomains and matched
//     by name). Any traversable path sets controlsTier0 = true.
//     Short-circuit: once controlsTier0 is true the remaining Tier-0-only anchor
//     checks are skipped (DA-domain checks for ALL domains always complete).
//
// Anchor SIDs are cached across calls via the candidateClient cache methods so
// repeated candidates do not re-resolve. An indeterminate path (known == false) is
// treated as "no path" (best-effort, matching ProcessUserDAPath behaviour).
func enrichCandidate(c candidateClient, objectID string, domains []string) (total int, daDomains []string, controlsTier0 bool) {
	// Step 1: get true transitive count.
	_, _, total, err := c.GetUserControllables(objectID)
	if err != nil || total == 0 {
		return total, nil, false
	}

	// resolveGroupSID resolves a group name within a domain via the anchor cache,
	// falling back to GetGroup on a miss. Returns "" when not resolvable.
	resolveGroupSID := func(domain, anchorName string) string {
		if sid, ok := c.anchorSID(domain, anchorName); ok {
			return sid // cache hit (may be "" for a previously-recorded miss)
		}
		hit, found, err := c.GetGroup(anchorName + "@" + domain)
		if err != nil || !found {
			c.setAnchorSID(domain, anchorName, "") // cache the miss
			return ""
		}
		c.setAnchorSID(domain, anchorName, hit.ObjectID)
		return hit.ObjectID
	}

	// resolveShortestPath wraps GetShortestPath, treating indeterminate (known=false)
	// as "no path" per spec (best-effort, matching ProcessUserDAPath).
	resolveShortestPath := func(src, dst string) bool {
		if dst == "" {
			return false
		}
		hasPath, known, err := c.GetShortestPath(src, dst)
		if err != nil || !known {
			return false
		}
		return hasPath
	}

	// Step 2: DA-group sweep for all domains (populates daDomains).
	const daAnchor = "DOMAIN ADMINS"
	for _, domain := range domains {
		daSID := resolveGroupSID(domain, daAnchor)
		if resolveShortestPath(objectID, daSID) {
			daDomains = append(daDomains, domain)
			controlsTier0 = true
		}
	}

	// Step 3: additional Tier-0 anchor sweep (only when total >= tier0SweepMin).
	if total < tier0SweepMin {
		return total, daDomains, controlsTier0
	}

	// For each domain sweep remaining group anchors and the Domain object.
	extraAnchors := tier0AnchorNames()[1:] // EA, KRBTGT, ADMINSDHOLDER, ADMINISTRATORS

	// Lazily fetch and cache Domain node SIDs by name (for DCSync anchor).
	domainNodeSIDCache := map[string]string{} // domain name -> domain node objectID
	resolveDomainNodeSID := func(domain string) string {
		if sid, ok := domainNodeSIDCache[domain]; ok {
			return sid
		}
		const domainNodeAnchor = "_DOMAIN_NODE_"
		if sid, ok := c.anchorSID(domain, domainNodeAnchor); ok {
			domainNodeSIDCache[domain] = sid
			return sid
		}
		ds, err := c.GetDomains()
		if err != nil {
			c.setAnchorSID(domain, domainNodeAnchor, "")
			domainNodeSIDCache[domain] = ""
			return ""
		}
		for _, d := range ds {
			if strings.EqualFold(d.Name, domain) {
				c.setAnchorSID(domain, domainNodeAnchor, d.ID)
				domainNodeSIDCache[domain] = d.ID
				return d.ID
			}
		}
		c.setAnchorSID(domain, domainNodeAnchor, "")
		domainNodeSIDCache[domain] = ""
		return ""
	}

	for _, domain := range domains {
		if controlsTier0 {
			// Short-circuit: already confirmed Tier-0 control; no need to sweep more.
			break
		}

		// Extra group anchors (EA, KRBTGT, AdminSDHolder, Administrators).
		for _, anchorName := range extraAnchors {
			if controlsTier0 {
				break
			}
			sid := resolveGroupSID(domain, anchorName)
			if resolveShortestPath(objectID, sid) {
				controlsTier0 = true
			}
		}

		// Domain object anchor (DCSync).
		if !controlsTier0 {
			domSID := resolveDomainNodeSID(domain)
			if resolveShortestPath(objectID, domSID) {
				controlsTier0 = true
			}
		}
	}

	return total, daDomains, controlsTier0
}
