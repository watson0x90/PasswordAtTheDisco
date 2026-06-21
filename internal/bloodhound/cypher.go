package bloodhound

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
)

// CypherResult is the response from POST /api/v2/graphs/cypher.
type CypherResult struct {
	Nodes map[string]cypherNode `json:"nodes"`
}

type cypherNode struct {
	Label      string                 `json:"label"`
	Kind       string                 `json:"kind"`
	ObjectID   string                 `json:"objectId"`
	Properties map[string]interface{} `json:"properties"`
}

// cypherResponse wraps the raw BHE cypher response envelope.
type cypherResponse struct {
	Data json.RawMessage `json:"data"`
}

// RunCypher executes a Cypher query against BHE and returns the raw JSON data.
func (c *Client) RunCypher(query string) (json.RawMessage, error) {
	body, err := json.Marshal(map[string]string{"query": query})
	if err != nil {
		return nil, err
	}
	resp, err := c.doRequest("POST", "/api/v2/graphs/cypher", body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var cr cypherResponse
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
		return nil, fmt.Errorf("cypher decode: %w", err)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("cypher query returned %d", resp.StatusCode)
	}
	return cr.Data, nil
}

// BulkUserProps holds the properties we extract for each user from a bulk Cypher query.
type BulkUserProps struct {
	ObjectID        string
	Enabled         bool
	PwdLastSet      int64
	PwdNeverExpires bool
	HasSPN          bool // Kerberoastable — has a Service Principal Name set
	DontReqPreauth  bool // AS-REP roastable — pre-authentication not required
}

// FetchAllUserProps fetches properties for all users in the BHE database using a
// single Cypher query. Returns a map keyed by lowercase "samaccountname@DOMAIN".
func (c *Client) FetchAllUserProps() (map[string]BulkUserProps, error) {
	query := `MATCH (u:User) RETURN u.samaccountname, u.domain, u.objectid, u.enabled, u.pwdlastset, u.pwdneverexpires, u.hasspn, u.dontreqpreauth`
	data, err := c.RunCypher(query)
	if err != nil {
		return nil, fmt.Errorf("FetchAllUserProps: %w", err)
	}

	// BHE cypher returns {"nodes":{...}} for graph results or tabular rows.
	// For RETURN with property projections, it returns tabular data as:
	// {"data": [{"row": [val1, val2, ...], "meta": [...]}, ...]}
	// Try tabular format first.
	var tabular struct {
		Nodes   map[string]json.RawMessage `json:"nodes"`
		Results []struct {
			Columns []string          `json:"columns"`
			Data    []json.RawMessage `json:"data"`
		} `json:"results"`
	}
	// BHE CE returns {"nodes":{},"edges":[],"literals":[{value,key},{value,key},...]}
	// where literals is a flat array of field objects, grouped by the RETURN columns.
	var literalsResult struct {
		Literals []literal `json:"literals"`
	}
	if json.Unmarshal(data, &literalsResult) == nil && len(literalsResult.Literals) > 0 {
		return parseUserPropsLiterals(literalsResult.Literals), nil
	}

	// Try direct array of rows
	var rows [][]interface{}
	if json.Unmarshal(data, &rows) == nil && len(rows) > 0 {
		return parseUserPropsRows(rows), nil
	}
	// Try {"results":[{"columns":[...],"data":[{"row":[...]}]}]} (neo4j-compat)
	if json.Unmarshal(data, &tabular) == nil && len(tabular.Results) > 0 {
		return parseUserPropsFromResults(tabular.Results[0].Columns, tabular.Results[0].Data), nil
	}
	// Try {"nodes":{id: {...}}} format (graph result) and extract from node properties
	var graphResult struct {
		Nodes map[string]struct {
			Properties map[string]interface{} `json:"properties"`
		} `json:"nodes"`
	}
	if json.Unmarshal(data, &graphResult) == nil && len(graphResult.Nodes) > 0 {
		return parseUserPropsFromNodes(graphResult.Nodes), nil
	}
	log.Printf("bloodhound: FetchAllUserProps: unrecognized response format, got %d bytes; first 500: %s", len(data), truncate(data, 500))
	return map[string]BulkUserProps{}, nil
}

// parseLiterals is the BHE CE "literals" format: a flat array of {key, value} pairs
// where each group of N items (matching the RETURN columns) represents one row.
type literal struct {
	Key   string      `json:"key"`
	Value interface{} `json:"value"`
}

func parseUserPropsLiterals(lits []literal) map[string]BulkUserProps {
	// 8 columns: u.samaccountname, u.domain, u.objectid, u.enabled, u.pwdlastset, u.pwdneverexpires, u.hasspn, u.dontreqpreauth
	const cols = 8
	out := make(map[string]BulkUserProps, len(lits)/cols)
	for i := 0; i+cols-1 < len(lits); i += cols {
		sam := toString(lits[i].Value)
		domain := toString(lits[i+1].Value)
		objectID := toString(lits[i+2].Value)
		enabled := toBool(lits[i+3].Value)
		pwdLastSet := toInt64(lits[i+4].Value)
		pwdNeverExpires := toBool(lits[i+5].Value)
		hasSPN := toBool(lits[i+6].Value)
		dontReqPreauth := toBool(lits[i+7].Value)
		if sam == "" {
			continue
		}
		key := strings.ToLower(sam) + "@" + strings.ToUpper(domain)
		out[key] = BulkUserProps{
			ObjectID:        objectID,
			Enabled:         enabled,
			PwdLastSet:      windowsEpochToUnix(pwdLastSet),
			PwdNeverExpires: pwdNeverExpires,
			HasSPN:          hasSPN,
			DontReqPreauth:  dontReqPreauth,
		}
	}
	return out
}

func parseDAPathsLiterals(lits []literal) map[string][]string {
	// 3 columns: u.samaccountname, u.domain, g.domain
	const cols = 3
	out := map[string][]string{}
	for i := 0; i+cols-1 < len(lits); i += cols {
		sam := toString(lits[i].Value)
		userDomain := toString(lits[i+1].Value)
		daDomain := toString(lits[i+2].Value)
		if sam == "" {
			continue
		}
		key := strings.ToLower(sam) + "@" + strings.ToUpper(userDomain)
		out[key] = append(out[key], daDomain)
	}
	return out
}

func parseControllablesLiterals(lits []literal) map[string]int {
	// 3 columns: u.samaccountname, u.domain, cnt
	const cols = 3
	out := map[string]int{}
	for i := 0; i+cols-1 < len(lits); i += cols {
		sam := toString(lits[i].Value)
		domain := toString(lits[i+1].Value)
		cnt := int(toInt64(lits[i+2].Value))
		if sam == "" || cnt == 0 {
			continue
		}
		key := strings.ToLower(sam) + "@" + strings.ToUpper(domain)
		out[key] = cnt
	}
	return out
}

func toString(v interface{}) string {
	s, _ := v.(string)
	return s
}

func parseUserPropsRows(rows [][]interface{}) map[string]BulkUserProps {
	out := make(map[string]BulkUserProps, len(rows))
	for _, row := range rows {
		if len(row) < 6 {
			continue
		}
		sam, _ := row[0].(string)
		domain, _ := row[1].(string)
		objectID, _ := row[2].(string)
		enabled := toBool(row[3])
		pwdLastSet := toInt64(row[4])
		pwdNeverExpires := toBool(row[5])
		// hasspn / dontreqpreauth are the roastable signals (cols 6,7). Guarded so a
		// short (legacy 6-col) row still parses the core fields rather than being dropped.
		var hasSPN, dontReqPreauth bool
		if len(row) >= 8 {
			hasSPN = toBool(row[6])
			dontReqPreauth = toBool(row[7])
		}
		if sam == "" {
			continue
		}
		key := strings.ToLower(sam) + "@" + strings.ToUpper(domain)
		out[key] = BulkUserProps{
			ObjectID:        objectID,
			Enabled:         enabled,
			PwdLastSet:      windowsEpochToUnix(pwdLastSet),
			PwdNeverExpires: pwdNeverExpires,
			HasSPN:          hasSPN,
			DontReqPreauth:  dontReqPreauth,
		}
	}
	return out
}

func parseUserPropsFromResults(columns []string, data []json.RawMessage) map[string]BulkUserProps {
	out := make(map[string]BulkUserProps, len(data))
	for _, raw := range data {
		var item struct {
			Row []interface{} `json:"row"`
		}
		if json.Unmarshal(raw, &item) != nil || len(item.Row) < 6 {
			continue
		}
		sam, _ := item.Row[0].(string)
		domain, _ := item.Row[1].(string)
		objectID, _ := item.Row[2].(string)
		enabled := toBool(item.Row[3])
		pwdLastSet := toInt64(item.Row[4])
		pwdNeverExpires := toBool(item.Row[5])
		var hasSPN, dontReqPreauth bool
		if len(item.Row) >= 8 {
			hasSPN = toBool(item.Row[6])
			dontReqPreauth = toBool(item.Row[7])
		}
		if sam == "" {
			continue
		}
		key := strings.ToLower(sam) + "@" + strings.ToUpper(domain)
		out[key] = BulkUserProps{
			ObjectID:        objectID,
			Enabled:         enabled,
			PwdLastSet:      windowsEpochToUnix(pwdLastSet),
			PwdNeverExpires: pwdNeverExpires,
			HasSPN:          hasSPN,
			DontReqPreauth:  dontReqPreauth,
		}
	}
	return out
}

func parseUserPropsFromNodes(nodes map[string]struct {
	Properties map[string]interface{} `json:"properties"`
}) map[string]BulkUserProps {
	out := make(map[string]BulkUserProps, len(nodes))
	for _, n := range nodes {
		sam, _ := n.Properties["samaccountname"].(string)
		domain, _ := n.Properties["domain"].(string)
		objectID, _ := n.Properties["objectid"].(string)
		enabled := toBool(n.Properties["enabled"])
		pwdLastSet := toInt64(n.Properties["pwdlastset"])
		pwdNeverExpires := toBool(n.Properties["pwdneverexpires"])
		hasSPN := toBool(n.Properties["hasspn"])
		dontReqPreauth := toBool(n.Properties["dontreqpreauth"])
		if sam == "" {
			continue
		}
		key := strings.ToLower(sam) + "@" + strings.ToUpper(domain)
		out[key] = BulkUserProps{
			ObjectID:        objectID,
			Enabled:         enabled,
			PwdLastSet:      windowsEpochToUnix(pwdLastSet),
			PwdNeverExpires: pwdNeverExpires,
			HasSPN:          hasSPN,
			DontReqPreauth:  dontReqPreauth,
		}
	}
	return out
}

// FetchDAUsers returns a set of "samaccountname@DOMAIN" keys for users that have
// a path to Domain Admins in any collected domain. Single Cypher query.
func (c *Client) FetchDAUsers() (map[string][]string, error) {
	// BHE CE's Cypher doesn't support shortestPath with typed edge lists, and a
	// plain MemberOf traversal only finds actual DA members (missing exploitable
	// attack paths). Use a two-step approach:
	//
	// 1. Cypher: find users who ARE Domain Admins (direct/nested MemberOf).
	// 2. REST: for users with controllables (the realistic attack-path candidates),
	//    call the per-user shortest-path endpoint with only_traversable=true.
	//
	// Step 1: DA group membership via Cypher (fast, single query).
	memberQuery := `MATCH (u:User)-[:MemberOf*1..]->(g:Group) WHERE g.name STARTS WITH 'DOMAIN ADMINS@' RETURN u.samaccountname, u.domain, g.domain`
	data, err := c.RunCypher(memberQuery)
	if err != nil {
		log.Printf("bloodhound: FetchDAUsers Cypher failed: %v (will try REST)", err)
		return map[string][]string{}, nil
	}
	var result map[string][]string
	// Try literals format (BHE CE)
	var literalsResult struct {
		Literals []literal `json:"literals"`
	}
	if json.Unmarshal(data, &literalsResult) == nil && len(literalsResult.Literals) > 0 {
		result = parseDAPathsLiterals(literalsResult.Literals)
	} else {
		var rows [][]interface{}
		if json.Unmarshal(data, &rows) == nil {
			result = parseDAPaths(rows)
		} else {
			result = map[string][]string{}
		}
	}
	log.Printf("bloodhound: DA group members: %d", len(result))

	// Step 2: For users with controllables who AREN'T already DA members, check
	// the traversable shortest-path via REST (the only way BHE CE supports it).
	// This catches the "exploitable attack path" users the Cypher query misses.
	return result, nil
}

// CheckDAPathsREST checks DA paths for a batch of users using the per-user REST
// endpoint. Called after bulk prefetch for users with controllables who aren't
// already identified as DA members. Returns additional DA users found.
func (c *Client) CheckDAPathsREST(objectIDs map[string]string, existing map[string][]string) map[string][]string {
	additional := map[string][]string{}
	domains, err := c.GetDomains()
	if err != nil || len(domains) == 0 {
		return additional
	}
	var collected []string
	for _, d := range domains {
		if d.Collected {
			collected = append(collected, d.Name)
		}
	}
	if len(collected) == 0 {
		return additional
	}

	checked := 0
	for key, sid := range objectIDs {
		if _, already := existing[key]; already {
			continue // already known DA member
		}
		if sid == "" {
			continue
		}
		for _, domainName := range collected {
			hp := c.ProcessUserDAPath(domainName, sid)
			if hp != nil && *hp {
				additional[key] = append(additional[key], domainName)
			}
		}
		checked++
	}
	if checked > 0 {
		log.Printf("bloodhound: REST DA path checks: %d users checked, %d additional paths found", checked, len(additional))
	}
	return additional
}

func parseDAPaths(rows [][]interface{}) map[string][]string {
	out := map[string][]string{}
	for _, row := range rows {
		if len(row) < 3 {
			continue
		}
		sam, _ := row[0].(string)
		userDomain, _ := row[1].(string)
		daDomain, _ := row[2].(string)
		if sam == "" {
			continue
		}
		key := strings.ToLower(sam) + "@" + strings.ToUpper(userDomain)
		out[key] = append(out[key], daDomain)
	}
	return out
}

func parseDAPathsFromResults(data []json.RawMessage) map[string][]string {
	out := map[string][]string{}
	for _, raw := range data {
		var item struct {
			Row []interface{} `json:"row"`
		}
		if json.Unmarshal(raw, &item) != nil || len(item.Row) < 3 {
			continue
		}
		sam, _ := item.Row[0].(string)
		userDomain, _ := item.Row[1].(string)
		daDomain, _ := item.Row[2].(string)
		if sam == "" {
			continue
		}
		key := strings.ToLower(sam) + "@" + strings.ToUpper(userDomain)
		out[key] = append(out[key], daDomain)
	}
	return out
}

// FetchControllableCounts returns the number of objects each user controls.
// Single Cypher query: count outbound control edges per user.
func (c *Client) FetchControllableCounts() (map[string]int, error) {
	query := `MATCH (u:User)-[r]->(n) WHERE type(r) IN ['GenericAll','GenericWrite','WriteOwner','WriteDacl','Owns','ForceChangePassword','AddMember'] WITH u, count(n) as cnt WHERE cnt > 0 RETURN u.samaccountname, u.domain, cnt`
	data, err := c.RunCypher(query)
	if err != nil {
		return nil, fmt.Errorf("FetchControllableCounts: %w", err)
	}
	// Try literals format first (BHE CE)
	var literalsResult struct {
		Literals []literal `json:"literals"`
	}
	if json.Unmarshal(data, &literalsResult) == nil && len(literalsResult.Literals) > 0 {
		return parseControllablesLiterals(literalsResult.Literals), nil
	}
	var rows [][]interface{}
	if json.Unmarshal(data, &rows) == nil {
		return parseControllables(rows), nil
	}
	var tabular struct {
		Results []struct {
			Data []json.RawMessage `json:"data"`
		} `json:"results"`
	}
	if json.Unmarshal(data, &tabular) == nil && len(tabular.Results) > 0 {
		return parseControllablesFromResults(tabular.Results[0].Data), nil
	}
	log.Printf("bloodhound: FetchControllableCounts: unrecognized response format")
	return map[string]int{}, nil
}

func parseControllables(rows [][]interface{}) map[string]int {
	out := map[string]int{}
	for _, row := range rows {
		if len(row) < 3 {
			continue
		}
		sam, _ := row[0].(string)
		domain, _ := row[1].(string)
		cnt := int(toInt64(row[2]))
		if sam == "" || cnt == 0 {
			continue
		}
		key := strings.ToLower(sam) + "@" + strings.ToUpper(domain)
		out[key] = cnt
	}
	return out
}

func parseControllablesFromResults(data []json.RawMessage) map[string]int {
	out := map[string]int{}
	for _, raw := range data {
		var item struct {
			Row []interface{} `json:"row"`
		}
		if json.Unmarshal(raw, &item) != nil || len(item.Row) < 3 {
			continue
		}
		sam, _ := item.Row[0].(string)
		domain, _ := item.Row[1].(string)
		cnt := int(toInt64(item.Row[2]))
		if sam == "" || cnt == 0 {
			continue
		}
		key := strings.ToLower(sam) + "@" + strings.ToUpper(domain)
		out[key] = cnt
	}
	return out
}

func truncate(data json.RawMessage, n int) string {
	if len(data) <= n {
		return string(data)
	}
	return string(data[:n])
}

// helper converters
func toBool(v interface{}) bool {
	switch b := v.(type) {
	case bool:
		return b
	case float64:
		return b != 0
	default:
		return false
	}
}

func toInt64(v interface{}) int64 {
	switch n := v.(type) {
	case float64:
		return int64(n)
	case json.Number:
		i, _ := n.Int64()
		return i
	case string:
		var jn json.Number = json.Number(n)
		i, _ := jn.Int64()
		return i
	default:
		return 0
	}
}

// windowsEpochToUnix converts a Windows FILETIME or already-unix timestamp.
func windowsEpochToUnix(v int64) int64 {
	if v <= 0 {
		return 0
	}
	if v < 10_000_000_000 { // already Unix seconds
		return v
	}
	const epochDiff = 116444736000000000
	if v < epochDiff {
		return 0
	}
	return (v - epochDiff) / 10_000_000
}
