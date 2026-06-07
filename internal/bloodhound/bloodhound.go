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
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
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

// Client is a BloodHound Enterprise API client.
type Client struct {
	scheme, host       string
	port               int
	creds              Credentials
	http               *http.Client
	searchLimit        int
	controllablesLimit int

	mu          sync.Mutex
	lastRequest time.Time
	minInterval time.Duration
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
		controllablesLimit = 10
	}
	return &Client{
		scheme:             scheme,
		host:               cfg.Host,
		port:               cfg.Port,
		creds:              Credentials{cfg.TokenID, cfg.TokenKey},
		http:               &http.Client{Timeout: time.Duration(readTimeout) * time.Second},
		searchLimit:        searchLimit,
		controllablesLimit: controllablesLimit,
		minInterval:        100 * time.Millisecond,
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

// throttle enforces a minimum interval between requests (with jitter).
func (c *Client) throttle() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.minInterval > 0 {
		if elapsed := time.Since(c.lastRequest); elapsed < c.minInterval {
			time.Sleep(c.minInterval - elapsed + time.Duration(rand.Int63n(int64(50*time.Millisecond))))
		}
	}
	c.lastRequest = time.Now()
}

func (c *Client) doRequest(method, uri string, body []byte) (*http.Response, error) {
	c.throttle()
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

// get issues a GET and returns the decoded {"data","count"} envelope and status.
func (c *Client) get(uri string) (envelope, int, error) {
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

// GetDomains returns all available domains.
func (c *Client) GetDomains() ([]Domain, error) {
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
// domain -> (controllable label -> count).
func (c *Client) GetUserControllables(objectID string) (map[string]map[string]int, error) {
	out := map[string]map[string]int{}

	// First call discovers the total count, the second fetches them all.
	env, status, err := c.get(fmt.Sprintf("/api/v2/base/%s/controllables?skip=0&limit=%d&type=list", objectID, c.controllablesLimit))
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return out, nil
	}
	env, status, err = c.get(fmt.Sprintf("/api/v2/base/%s/controllables?skip=0&limit=%d&type=list", objectID, env.Count))
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return out, nil
	}

	var items []struct {
		Label string `json:"label"`
		Name  string `json:"name"`
	}
	if err := json.Unmarshal(env.Data, &items); err != nil {
		return nil, err
	}
	for _, it := range items {
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
	}
	return out, nil
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
func (c *Client) ProcessUserDAPath(domainName, userSID string) *bool {
	grp, ok, err := c.GetGroup("DOMAIN ADMINS@" + domainName)
	if err != nil || !ok {
		return nil
	}
	hasPath, known, err := c.GetShortestPath(userSID, grp.ObjectID)
	if err != nil || !known {
		return nil
	}
	return &hasPath
}

// DomainControllables holds, for one domain, the user's controllable-object
// label counts and whether they have a Domain Admin pathway there.
type DomainControllables struct {
	Domain    string
	Labels    map[string]int
	HasDAPath *bool // nil = unknown
}

// UserData is the aggregated BHE enrichment for a single user.
type UserData struct {
	Username      string
	ObjectID      string
	Props         UserProps
	Controllables []DomainControllables
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

	byCount, err := c.GetUserControllables(sid)
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

	// Controllables, in deterministic (sorted) domain order.
	domainsSorted := make([]string, 0, len(byCount))
	for d := range byCount {
		domainsSorted = append(domainsSorted, d)
	}
	sort.Strings(domainsSorted)
	idx := map[string]int{}
	for _, d := range domainsSorted {
		idx[d] = len(ud.Controllables)
		ud.Controllables = append(ud.Controllables, DomainControllables{Domain: d, Labels: byCount[d]})
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

// ExtractControllableCount returns the total number of controlled objects.
func ExtractControllableCount(ud *UserData) int {
	if ud == nil {
		return 0
	}
	total := 0
	for _, dc := range ud.Controllables {
		for _, n := range dc.Labels {
			total += n
		}
	}
	return total
}
