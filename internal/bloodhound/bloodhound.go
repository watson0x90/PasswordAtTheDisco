// Package bloodhound is a minimal BloodHound Enterprise API client plus the
// per-user enrichment the audit needs: Domain Admin pathways and controlled-
// object counts. Ported from legacy-python/core/bloodhound_integration.py.
//
// Requests are authenticated with BHE's 3-stage HMAC-SHA256 signature:
//
//	d1 = HMAC(token_key, method+uri)
//	d2 = HMAC(d1,        requestDate[:13])   // date+hour, e.g. "2006-01-02T15"
//	d3 = HMAC(d2,        body)               // body omitted when nil
//	Signature: base64(d3)
package bloodhound

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/watson0x90/PasswordAtTheDisco/internal/fsutil"
)

// Credentials is a BHE API token pair.
type Credentials struct {
	TokenID  string
	TokenKey string
}

// Config mirrors config/bloodhound.json.
type Config struct {
	Scheme             string `json:"scheme"`
	Host               string `json:"domain"`
	Port               int    `json:"port"`
	TokenID            string `json:"token_id"`
	TokenKey           string `json:"token_key"`
	SearchLimit        int    `json:"search_limit"`
	ControllablesLimit int    `json:"controllables_limit"`
	ConnectTimeout     int    `json:"connect_timeout"`
	ReadTimeout        int    `json:"read_timeout"`
	EnrichConcurrency  int    `json:"enrich_concurrency"` // max concurrent BHE requests (default 8)
}

// LoadConfig reads a bloodhound.json config file.
func LoadConfig(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return Config{}, fmt.Errorf("parse bloodhound config: %w", err)
	}
	return c, nil
}

// SaveConfig writes the config to path atomically (0600 -- it holds an API token).
func SaveConfig(path string, c Config) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(path, b, 0o600)
}

// Client is a BloodHound Enterprise API client.
type Client struct {
	scheme, host       string
	port               int
	creds              Credentials
	http               *http.Client
	searchLimit        int
	controllablesLimit int

	sem chan struct{} // counting semaphore: send to acquire a slot, receive to release; cap = max concurrent BHE requests

	domMu       sync.Mutex
	domCache    []Domain
	domCachedAt time.Time
	domTTL      time.Duration
	daGroups    map[string]string // cached DA group SID per domain
}

// New builds a Client from a Config.
func New(cfg Config) *Client {
	scheme := cfg.Scheme
	if scheme == "" {
		scheme = "http"
	}
	readTimeout := cfg.ReadTimeout
	if readTimeout == 0 {
		readTimeout = 30
	}
	searchLimit := cfg.SearchLimit
	if searchLimit == 0 {
		searchLimit = 1
	}
	controllablesLimit := cfg.ControllablesLimit
	if controllablesLimit == 0 {
		controllablesLimit = 100 // wider sample for Tier-0/sensitivity; env.Count gives true magnitude
	}
	concurrency := cfg.EnrichConcurrency
	if concurrency <= 0 {
		concurrency = 8
	}
	if concurrency > 32 {
		concurrency = 32
	}
	// The semaphore bounds in-flight HTTP requests. Since each enrichment worker
	// makes ~10 sequential HTTP calls per user, the semaphore must be larger than
	// the worker pool count to avoid self-contention. Size it at workers × 4 so
	// workers rarely block on each other's sequential calls.
	semSize := concurrency * 4
	return &Client{
		scheme:             scheme,
		host:               cfg.Host,
		port:               cfg.Port,
		creds:              Credentials{cfg.TokenID, cfg.TokenKey},
		http:               &http.Client{Timeout: time.Duration(readTimeout) * time.Second},
		searchLimit:        searchLimit,
		controllablesLimit: controllablesLimit,
		sem:                make(chan struct{}, semSize),
		domTTL:             60 * time.Second,
	}
}

// sign computes the BHE request signature (see package doc).
func sign(tokenKey, method, uri, datePrefix string, body []byte) string {
	m := hmac.New(sha256.New, []byte(tokenKey))
	m.Write([]byte(method + uri))
	m = hmac.New(sha256.New, m.Sum(nil))
	m.Write([]byte(datePrefix))
	m = hmac.New(sha256.New, m.Sum(nil))
	if body != nil {
		m.Write(body)
	}
	return base64.StdEncoding.EncodeToString(m.Sum(nil))
}

func (c *Client) formatURL(uri string) string {
	return fmt.Sprintf("%s://%s:%d/%s", c.scheme, c.host, c.port, strings.TrimPrefix(uri, "/"))
}

// acquire/release bracket a single HTTP round-trip; the slot is held only until
// doRequest returns (callers drain the response body after the semaphore is freed).
func (c *Client) acquire() { c.sem <- struct{}{} }
func (c *Client) release() { <-c.sem }

func (c *Client) doRequest(method, uri string, body []byte) (*http.Response, error) {
	c.acquire()
	defer c.release()
	requestDate := time.Now().Format("2006-01-02T15:04:05.000000-07:00")
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, c.formatURL(uri), rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "bhe-go-sdk 0001")
	req.Header.Set("Authorization", "bhesignature "+c.creds.TokenID)
	req.Header.Set("RequestDate", requestDate)
	req.Header.Set("Signature", sign(c.creds.TokenKey, method, uri, requestDate[:13], body))
	req.Header.Set("Content-Type", "application/json")
	return c.http.Do(req)
}

type envelope struct {
	Data  json.RawMessage `json:"data"`
	Count int             `json:"count"`
}

// getRetries is the max attempts for a transient (429/5xx) BHE response.
const getRetries = 3

// get issues a GET and returns the decoded {"data","count"} envelope and status.
// Transient errors (429 / 5xx) are retried up to getRetries times with linear
// back-off; a WARN is logged on each retry and on any non-200 final status.
func (c *Client) get(uri string) (envelope, int, error) {
	var lastStatus int
	for attempt := 0; attempt < getRetries; attempt++ {
		env, status, err := c.getOnce(uri)
		if err != nil {
			return env, status, err
		}
		lastStatus = status
		if status == http.StatusTooManyRequests || status >= 500 {
			log.Printf("bloodhound: %s -> %d (attempt %d/%d), backing off", uri, status, attempt+1, getRetries)
			time.Sleep(time.Duration(150*(attempt+1)) * time.Millisecond)
			continue
		}
		if status != http.StatusOK {
			log.Printf("bloodhound: %s -> %d", uri, status)
		}
		return env, status, nil
	}
	return envelope{}, lastStatus, nil
}

// getOnce issues a single GET and returns the decoded envelope and status code.
func (c *Client) getOnce(uri string) (envelope, int, error) {
	resp, err := c.doRequest("GET", uri, nil)
	if err != nil {
		return envelope{}, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return envelope{}, resp.StatusCode, err
	}
	if resp.StatusCode != http.StatusOK {
		return envelope{}, resp.StatusCode, nil
	}
	var env envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return envelope{}, resp.StatusCode, err
	}
	return env, resp.StatusCode, nil
}

// encode percent-encodes a query value the way the Python client did
// (urllib.parse.quote(safe=”) -> space as %20, not '+').
func encode(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

// APIVersion is the BHE version payload.
type APIVersion struct {
	API    string
	Server string
}

// GetVersion returns the API/server version (connectivity check).
func (c *Client) GetVersion() (APIVersion, error) {
	env, status, err := c.get("/api/version")
	if err != nil {
		return APIVersion{}, err
	}
	if status != http.StatusOK {
		return APIVersion{}, fmt.Errorf("version: status %d", status)
	}
	var v struct {
		API struct {
			CurrentVersion string `json:"current_version"`
		} `json:"API"`
		ServerVersion string `json:"server_version"`
	}
	if err := json.Unmarshal(env.Data, &v); err != nil {
		return APIVersion{}, err
	}
	return APIVersion{API: v.API.CurrentVersion, Server: v.ServerVersion}, nil
}

// Domain is an available domain.
type Domain struct {
	Name      string `json:"name"`
	ID        string `json:"id"`
	Collected bool   `json:"collected"`
	Type      string `json:"type"`
}

// GetDomains returns all available domains. Results are cached for domTTL to
// avoid redundant BHE round-trips when called per-account in GetUserData.
func (c *Client) GetDomains() ([]Domain, error) {
	c.domMu.Lock()
	// Lock is released across the network call below; concurrent cold callers may
	// both fetch once — benign, second write wins.
	if !c.domCachedAt.IsZero() && time.Since(c.domCachedAt) < c.domTTL {
		ds := c.domCache
		c.domMu.Unlock()
		return ds, nil
	}
	c.domMu.Unlock()

	env, status, err := c.get("/api/v2/available-domains")
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("available-domains: status %d", status)
	}
	var ds []Domain
	if err := json.Unmarshal(env.Data, &ds); err != nil {
		return nil, err
	}
	c.domMu.Lock()
	c.domCache = ds
	c.domCachedAt = time.Now()
	c.domMu.Unlock()
	return ds, nil
}

type searchHit struct {
	Name     string `json:"name"`
	ObjectID string `json:"objectid"`
}

func (c *Client) search(q, typ string) (searchHit, bool, error) {
	uri := fmt.Sprintf("/api/v2/search?q=%s&type=%s&limit=%d", encode(q), typ, c.searchLimit)
	env, status, err := c.get(uri)
	if err != nil {
		return searchHit{}, false, err
	}
	if status != http.StatusOK {
		return searchHit{}, false, nil
	}
	var hits []searchHit
	if err := json.Unmarshal(env.Data, &hits); err != nil {
		return searchHit{}, false, err
	}
	if len(hits) == 0 {
		return searchHit{}, false, nil
	}
	return hits[0], true, nil
}

// GetUser resolves a username to its object (name + SID) via search.
func (c *Client) GetUser(username string) (searchHit, bool, error) { return c.search(username, "User") }

// GetGroup resolves a group name to its object via search.
func (c *Client) GetGroup(groupname string) (searchHit, bool, error) {
	return c.search(groupname, "Group")
}

// GetComputer resolves a computer name to its object via search.
func (c *Client) GetComputer(name string) (searchHit, bool, error) { return c.search(name, "Computer") }

// UserProps holds the user properties relevant to the audit.
type UserProps struct {
	PwdLastSet         json.Number `json:"pwdlastset"`
	PwdNeverExpires    bool        `json:"pwdneverexpires"`
	Enabled            bool        `json:"enabled"`
	WhenCreated        json.Number `json:"whencreated"`
	DistinguishedName  string      `json:"distinguishedname"`
	LastLogon          json.Number `json:"lastlogon"`
	LastLogonTimestamp json.Number `json:"lastlogontimestamp"`
	PasswordCantChange bool        `json:"passwordcantchange"`
}

// GetUserFull returns the detailed user properties for an object ID.
func (c *Client) GetUserFull(objectID string) (UserProps, bool, error) {
	env, status, err := c.get("/api/v2/users/" + objectID)
	if err != nil {
		return UserProps{}, false, err
	}
	if status != http.StatusOK || len(env.Data) == 0 {
		return UserProps{}, false, nil
	}
	var full struct {
		Props UserProps `json:"props"`
	}
	if err := json.Unmarshal(env.Data, &full); err != nil {
		return UserProps{}, false, err
	}
	return full.Props, true, nil
}

// computerDomain resolves a computer object's domain (props.domain).
func (c *Client) computerDomain(objectID string) string {
	env, status, err := c.get("/api/v2/base/" + objectID)
	if err != nil || status != http.StatusOK || len(env.Data) == 0 {
		return ""
	}
	var full struct {
		Props struct {
			Domain string `json:"domain"`
		} `json:"props"`
	}
	if err := json.Unmarshal(env.Data, &full); err != nil {
		return ""
	}
	return full.Props.Domain
}

// GetUserControllables returns the objects controllable by a user, grouped as
// domain -> (controllable label -> count) plus domain -> sampled items, plus the
// API's TRUE total (env.Count). The label/item sample is bounded by
// controllablesLimit; total is the real magnitude and is not capped.
func (c *Client) GetUserControllables(objectID string) (byDomain map[string]map[string]int, items map[string][]ControllableItem, total int, err error) {
	out := map[string]map[string]int{}
	itemsOut := map[string][]ControllableItem{}

	// Single call with the configured limit (avoids double round-trip). limit now
	// bounds only the display/label sample; env.Count carries the true total.
	env, status, err := c.get(fmt.Sprintf("/api/v2/base/%s/controllables?skip=0&limit=%d&type=list", objectID, c.controllablesLimit))
	if err != nil {
		return nil, nil, 0, err
	}
	if status != http.StatusOK || env.Count == 0 {
		return out, itemsOut, 0, nil
	}

	var rawItems []struct {
		Label string `json:"label"`
		Name  string `json:"name"`
	}
	if err := json.Unmarshal(env.Data, &rawItems); err != nil {
		return nil, nil, 0, err
	}
	for _, it := range rawItems {
		domain := domainFromName(it.Name)
		if domain == "LOCALDOMAIN" || domain == "Unknown" || domain == "INT" {
			if comp, ok, _ := c.GetComputer(it.Name); ok {
				if d := c.computerDomain(comp.ObjectID); d != "" {
					domain = d
				}
			}
		}
		if out[domain] == nil {
			out[domain] = map[string]int{}
		}
		label := it.Label
		if label == "" {
			label = "Unknown"
		}
		out[domain][label]++
		itemsOut[domain] = append(itemsOut[domain], ControllableItem{Label: label, Name: it.Name})
	}
	return out, itemsOut, env.Count, nil
}

// domainFromName extracts a domain from an object name: "user@DOMAIN" -> DOMAIN,
// else "host.domain.tld" -> "domain.tld" (everything after the first dot).
func domainFromName(name string) string {
	if i := strings.LastIndex(name, "@"); i >= 0 {
		return name[i+1:]
	}
	if i := strings.Index(name, "."); i >= 0 {
		return name[i+1:]
	}
	return "Unknown"
}

// GetShortestPath reports whether a traversable attack path exists from src to
// dst. known is false when the result is indeterminate (non-200/404 response).
func (c *Client) GetShortestPath(src, dst string) (hasPath, known bool, err error) {
	uri := fmt.Sprintf("/api/v2/graphs/shortest-path?start_node=%s&end_node=%s&only_traversable=true", encode(src), encode(dst))
	resp, err := c.doRequest("GET", uri, nil)
	if err != nil {
		return false, false, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	switch resp.StatusCode {
	case http.StatusOK:
		return true, true, nil
	case http.StatusNotFound:
		return false, true, nil
	default:
		return false, false, nil
	}
}

// ProcessUserDAPath reports whether the user (by SID) has a Domain Admin pathway
// in domainName. Returns nil when indeterminate (group not found / path unknown).
// The DA group SID is cached per domain so repeated lookups skip the search call.
func (c *Client) ProcessUserDAPath(domainName, userSID string) *bool {
	grpSID, ok := c.cachedDAGroup(domainName)
	if !ok {
		grp, found, err := c.GetGroup("DOMAIN ADMINS@" + domainName)
		if err != nil || !found {
			c.setDAGroup(domainName, "") // cache the miss
			return nil
		}
		grpSID = grp.ObjectID
		c.setDAGroup(domainName, grpSID)
	}
	if grpSID == "" {
		return nil // cached miss
	}
	hasPath, known, err := c.GetShortestPath(userSID, grpSID)
	if err != nil || !known {
		return nil
	}
	return &hasPath
}

func (c *Client) cachedDAGroup(domain string) (string, bool) {
	c.domMu.Lock()
	defer c.domMu.Unlock()
	if c.daGroups == nil {
		return "", false
	}
	sid, ok := c.daGroups[domain]
	return sid, ok
}

func (c *Client) setDAGroup(domain, sid string) {
	c.domMu.Lock()
	defer c.domMu.Unlock()
	if c.daGroups == nil {
		c.daGroups = map[string]string{}
	}
	c.daGroups[domain] = sid
}

// ControllableItem is one sampled controllable object (label + name). Retained so
// Tier-0 / DA-equivalent control can be detected by name heuristic. The sample is
// bounded by controllablesLimit; env.Count (ControllableTotal) gives the true count.
type ControllableItem struct {
	Label string
	Name  string
}

// DomainControllables holds, for one domain, the user's controllable-object
// label counts and whether they have a Domain Admin pathway there.
type DomainControllables struct {
	Domain    string
	Labels    map[string]int
	Items     []ControllableItem // the sampled controllable objects (bounded by controllablesLimit)
	HasDAPath *bool              // nil = unknown
}

// UserData is the aggregated BHE enrichment for a single user.
type UserData struct {
	Username      string
	ObjectID      string
	Props         UserProps
	Controllables []DomainControllables
	// ControllableTotal is the API's TRUE count of controlled objects (env.Count),
	// independent of the sampled label map. 0 means absent/unknown.
	ControllableTotal int
}

// GetUserData fetches and aggregates a user's BHE enrichment: properties,
// controllable objects by domain, and DA pathways for each collected domain.
// Returns (nil, nil) if the user is not found.
func (c *Client) GetUserData(username string) (*UserData, error) {
	domains, err := c.GetDomains()
	if err != nil {
		return nil, err
	}
	var collected []string
	for _, d := range domains {
		if d.Collected {
			collected = append(collected, d.Name)
		}
	}

	user, ok, err := c.GetUser(username)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	sid := user.ObjectID

	byCount, ctrlItems, total, err := c.GetUserControllables(sid)
	if err != nil {
		return nil, err
	}
	props, ok, err := c.GetUserFull(sid)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}

	ud := &UserData{Username: user.Name, ObjectID: sid, Props: props}
	ud.ControllableTotal = total

	// Controllables, in deterministic (sorted) domain order.
	domainsSorted := make([]string, 0, len(byCount))
	for d := range byCount {
		domainsSorted = append(domainsSorted, d)
	}
	sort.Strings(domainsSorted)
	idx := map[string]int{}
	for _, d := range domainsSorted {
		idx[d] = len(ud.Controllables)
		ud.Controllables = append(ud.Controllables, DomainControllables{Domain: d, Labels: byCount[d], Items: ctrlItems[d]})
	}

	// DA pathways per collected domain (attach to existing entry or append).
	for _, dn := range collected {
		hp := c.ProcessUserDAPath(dn, sid)
		if i, found := idx[dn]; found {
			ud.Controllables[i].HasDAPath = hp
		} else {
			idx[dn] = len(ud.Controllables)
			ud.Controllables = append(ud.Controllables, DomainControllables{Domain: dn, HasDAPath: hp})
		}
	}
	return ud, nil
}

// ExtractDADomains returns the domains where the user has a confirmed DA pathway.
func ExtractDADomains(ud *UserData) []string {
	if ud == nil {
		return nil
	}
	var out []string
	for _, dc := range ud.Controllables {
		if dc.HasDAPath != nil && *dc.HasDAPath {
			out = append(out, dc.Domain)
		}
	}
	return out
}

// tier0Names are case-insensitive name fragments whose control is DA-equivalent.
// Substring matching is intentional here: each fragment is a unique, well-known
// AD token, so substring favors recall and this is only an additive Impact signal
// (never a gate). NOTE: "ADMINISTRATORS" is deliberately NOT in this slice —
// substring-matching it over-matches benign delegated groups (e.g. "Backup
// Administrators", "SQL Administrators"), so isTier0Name handles the built-in
// Administrators group as an exact local-part match instead.
var tier0Names = []string{
	"DOMAIN ADMINS",
	"ENTERPRISE ADMINS",
	"DOMAIN CONTROLLERS",
	"KRBTGT",
	"ADMINSDHOLDER",
}

// isTier0Name reports whether an object name matches a Tier-0 / DA-equivalent
// object. The tier0Names fragments are matched as case-insensitive substrings
// (unique tokens, recall-favoring). The built-in "Administrators" group is
// matched as an EXACT local part (the portion before '@', or the whole name when
// there is no '@') to avoid over-matching delegated "* Administrators" groups.
func isTier0Name(name string) bool {
	// Built-in Administrators: exact local-part match only.
	localPart := name
	if i := strings.IndexByte(name, '@'); i >= 0 {
		localPart = name[:i]
	}
	if strings.EqualFold(strings.TrimSpace(localPart), "Administrators") {
		return true
	}
	u := strings.ToUpper(name)
	for _, t := range tier0Names {
		if strings.Contains(u, t) {
			return true
		}
	}
	return false
}

// ExtractControlsTier0 reports whether the user controls a Tier-0 / DA-equivalent
// object (Domain Admins, Enterprise Admins, Administrators, Domain Controllers,
// KRBTGT, AdminSDHolder, or the domain object — DCSync). Best-effort over the
// SAMPLED controllables page (bounded by controllablesLimit); a true magnitude
// still comes from ExtractControllableCount and the literal DA path from
// ExtractDADomains. Never a gate — an additive Impact signal.
func ExtractControlsTier0(ud *UserData) bool {
	if ud == nil {
		return false
	}
	for _, dc := range ud.Controllables {
		for _, it := range dc.Items {
			if isTier0Name(it.Name) {
				return true
			}
			// Control of the domain object itself implies DCSync (DA-equivalent).
			if it.Label == "Domain" {
				return true
			}
		}
	}
	return false
}

// ExtractControllableCount returns the TRUE number of controlled objects: the
// API's env.Count (ControllableTotal) when present, falling back to the summed
// sampled label map only when the total is 0/absent.
func ExtractControllableCount(ud *UserData) int {
	if ud == nil {
		return 0
	}
	if ud.ControllableTotal > 0 {
		return ud.ControllableTotal
	}
	total := 0
	for _, dc := range ud.Controllables {
		for _, n := range dc.Labels {
			total += n
		}
	}
	return total
}
