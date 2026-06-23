package bloodhound

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// ImportedUser is a user's AD properties parsed from an uploaded BloodHound JSON
// export (the users_*.json from SharpHound collection or a BHE export). These
// properties are applied to accounts at upload time, eliminating the need to query
// BHE for anything except DA-pathway graph checks.
type ImportedUser struct {
	Username        string `json:"username"`        // SAMAccountName or user@domain
	Domain          string `json:"domain"`          // AD domain (uppercase)
	Enabled         *bool  `json:"enabled"`         // UAC enabled; nil means absent/unknown
	PwdLastSet      int64  `json:"pwdlastset"`      // Unix epoch seconds
	PwdNeverExpires bool   `json:"pwdneverexpires"` // UAC flag
	LastLogon       int64  `json:"lastlogon"`       // Unix epoch seconds
	HasSPN          bool   `json:"hasspn"`          // Kerberoastable (SPN set)
	DontReqPreauth  bool   `json:"dontreqpreauth"`  // AS-REP roastable (no pre-auth)
	Controllables   int    `json:"controllables"`   // total controlled object count (optional)
	ObjectID        string `json:"objectid"`        // SID (optional, for DA path lookups)
}

// ParseUsersExport parses a BloodHound users JSON export. It accepts several
// shapes common in the ecosystem:
//
//   - SharpHound collection format: {"data":[{"Properties":{...},"ObjectIdentifier":"S-1-..."},...]}
//   - BHE flat export: [{"props":{"samaccountname":"...","domain":"...","pwdlastset":...,"enabled":true,...},"objectid":"S-1-..."},...]
//   - Simplified array: [{"username":"user@DOMAIN","domain":"DOMAIN","enabled":true,"pwdlastset":1234,...},...]
//
// Returns the parsed users keyed by normalized "user@DOMAIN" for fast lookup.
func ParseUsersExport(r io.Reader) (map[string]ImportedUser, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	// Try SharpHound format: {"data":[...], "meta":{...}}
	var sharpHound struct {
		Data []json.RawMessage `json:"data"`
	}
	if json.Unmarshal(raw, &sharpHound) == nil && len(sharpHound.Data) > 0 {
		return parseSharpHound(sharpHound.Data)
	}

	// Try plain array
	var arr []json.RawMessage
	if json.Unmarshal(raw, &arr) == nil && len(arr) > 0 {
		return parseArray(arr)
	}

	return nil, fmt.Errorf("unrecognized BloodHound export format")
}

func parseSharpHound(data []json.RawMessage) (map[string]ImportedUser, error) {
	out := make(map[string]ImportedUser, len(data))
	for _, raw := range data {
		var item struct {
			Properties struct {
				SAMAccountName  string      `json:"samaccountname"`
				Domain          string      `json:"domain"`
				Enabled         *bool       `json:"enabled"`
				PwdLastSet      json.Number `json:"pwdlastset"`
				PwdNeverExpires bool        `json:"pwdneverexpires"`
				LastLogon       json.Number `json:"lastlogon"`
				HasSPN          bool        `json:"hasspn"`
				DontReqPreauth  bool        `json:"dontreqpreauth"`
			} `json:"Properties"`
			ObjectIdentifier string `json:"ObjectIdentifier"`
		}
		if err := json.Unmarshal(raw, &item); err != nil {
			continue
		}
		if item.Properties.SAMAccountName == "" {
			continue
		}
		domain := strings.ToUpper(item.Properties.Domain)
		pwdLastSet, _ := item.Properties.PwdLastSet.Int64()
		lastLogon, _ := item.Properties.LastLogon.Int64()
		u := ImportedUser{
			Username:        item.Properties.SAMAccountName,
			Domain:          domain,
			Enabled:         item.Properties.Enabled,
			PwdLastSet:      windowsEpochToUnix(pwdLastSet),
			PwdNeverExpires: item.Properties.PwdNeverExpires,
			LastLogon:       windowsEpochToUnix(lastLogon),
			HasSPN:          item.Properties.HasSPN,
			DontReqPreauth:  item.Properties.DontReqPreauth,
			ObjectID:        item.ObjectIdentifier,
		}
		key := normalizeKey(u.Username, u.Domain)
		out[key] = u
	}
	return out, nil
}

func parseArray(data []json.RawMessage) (map[string]ImportedUser, error) {
	out := make(map[string]ImportedUser, len(data))
	for _, raw := range data {
		// Try BHE format: {"props":{...}, "objectid":"..."}
		var bhe struct {
			Props struct {
				SAMAccountName  string      `json:"samaccountname"`
				Domain          string      `json:"domain"`
				Enabled         *bool       `json:"enabled"`
				PwdLastSet      json.Number `json:"pwdlastset"`
				PwdNeverExpires bool        `json:"pwdneverexpires"`
				LastLogon       json.Number `json:"lastlogon"`
				HasSPN          bool        `json:"hasspn"`
				DontReqPreauth  bool        `json:"dontreqpreauth"`
			} `json:"props"`
			ObjectID string `json:"objectid"`
		}
		if json.Unmarshal(raw, &bhe) == nil && bhe.Props.SAMAccountName != "" {
			domain := strings.ToUpper(bhe.Props.Domain)
			pwdLastSet, _ := bhe.Props.PwdLastSet.Int64()
			lastLogon, _ := bhe.Props.LastLogon.Int64()
			u := ImportedUser{
				Username:        bhe.Props.SAMAccountName,
				Domain:          domain,
				Enabled:         bhe.Props.Enabled,
				PwdLastSet:      windowsEpochToUnix(pwdLastSet),
				PwdNeverExpires: bhe.Props.PwdNeverExpires,
				LastLogon:       windowsEpochToUnix(lastLogon),
				HasSPN:          bhe.Props.HasSPN,
				DontReqPreauth:  bhe.Props.DontReqPreauth,
				ObjectID:        bhe.ObjectID,
			}
			out[normalizeKey(u.Username, u.Domain)] = u
			continue
		}

		// Try simplified format
		var simple ImportedUser
		if json.Unmarshal(raw, &simple) == nil && simple.Username != "" {
			simple.Domain = strings.ToUpper(simple.Domain)
			out[normalizeKey(simple.Username, simple.Domain)] = simple
		}
	}
	return out, nil
}

// normalizeKey builds the lookup key matching engine.NormalizeUsername: "user@DOMAIN".
func normalizeKey(username, domain string) string {
	u := strings.ToLower(username)
	if strings.Contains(u, "@") {
		return u
	}
	return u + "@" + strings.ToUpper(domain)
}

// LookupKey normalizes a username+domain for looking up in the import map.
func LookupKey(username, domain string) string {
	return normalizeKey(username, domain)
}
