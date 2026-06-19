// Command bhdump enumerates all users (+ key AD properties, DA reachability, and
// controlled-object counts) from the configured BloodHound database, using the
// project's existing signed BHE client. It emits a JSON array to stdout and a
// summary to stderr. Read-only. Used to seed realistic synthetic sample data —
// real usernames, but synthetic credentials are generated separately.
//
//	go run ./tools/bhdump > sample_data/bloodhound/users.json
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/watson0x90/PasswordAtTheDisco/internal/bloodhound"
)

type userRec struct {
	Username        string   `json:"username"`
	Domain          string   `json:"domain"`
	Enabled         bool     `json:"enabled"`
	PwdLastSet      int64    `json:"pwdlastset"`
	PwdNeverExpires bool     `json:"pwdneverexpires"`
	HasSPN          bool     `json:"hasspn"`
	DontReqPreauth  bool     `json:"dontreqpreauth"`
	Controlled      int      `json:"controlled"`
	DADomains       []string `json:"da_domains"`
	ObjectID        string   `json:"objectid"`
}

func main() {
	cfgPath := "config/bloodhound.json"
	if len(os.Args) > 1 {
		cfgPath = os.Args[1]
	}
	cfg, err := bloodhound.LoadConfig(cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load config:", err)
		os.Exit(1)
	}
	c := bloodhound.New(cfg)

	props, err := c.FetchAllUserProps()
	if err != nil {
		fmt.Fprintln(os.Stderr, "FetchAllUserProps:", err)
		os.Exit(1)
	}
	da, err := c.FetchDAUsers()
	if err != nil {
		fmt.Fprintln(os.Stderr, "FetchDAUsers (continuing):", err)
		da = map[string][]string{}
	}
	ctrl, err := c.FetchControllableCounts()
	if err != nil {
		fmt.Fprintln(os.Stderr, "FetchControllableCounts (continuing):", err)
		ctrl = map[string]int{}
	}

	recs := make([]userRec, 0, len(props))
	domains := map[string]int{}
	var nSPN, nAsrep, nNever, nDA, nCtrl int
	for key, p := range props {
		at := strings.LastIndex(key, "@")
		if at < 0 {
			continue
		}
		sam, dom := key[:at], key[at+1:]
		r := userRec{
			Username: sam, Domain: dom, Enabled: p.Enabled,
			PwdLastSet: p.PwdLastSet, PwdNeverExpires: p.PwdNeverExpires,
			HasSPN: p.HasSPN, DontReqPreauth: p.DontReqPreauth,
			Controlled: ctrl[key], DADomains: da[key], ObjectID: p.ObjectID,
		}
		recs = append(recs, r)
		domains[dom]++
		if r.HasSPN {
			nSPN++
		}
		if r.DontReqPreauth {
			nAsrep++
		}
		if r.PwdNeverExpires {
			nNever++
		}
		if len(r.DADomains) > 0 {
			nDA++
		}
		if r.Controlled > 0 {
			nCtrl++
		}
	}
	sort.Slice(recs, func(i, j int) bool {
		if recs[i].Domain != recs[j].Domain {
			return recs[i].Domain < recs[j].Domain
		}
		return recs[i].Username < recs[j].Username
	})

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", " ")
	if err := enc.Encode(recs); err != nil {
		fmt.Fprintln(os.Stderr, "encode:", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "users=%d  domains=%d  kerberoastable(SPN)=%d  asrep=%d  never-expires=%d  DA-reachable=%d  with-controlled=%d\n",
		len(recs), len(domains), nSPN, nAsrep, nNever, nDA, nCtrl)
	doms := make([]string, 0, len(domains))
	for d := range domains {
		doms = append(doms, d)
	}
	sort.Strings(doms)
	for _, d := range doms {
		fmt.Fprintf(os.Stderr, "  %s: %d users\n", d, domains[d])
	}
}
