package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/watson0x90/PasswordAtTheDisco/internal/bloodhound"
	"github.com/watson0x90/PasswordAtTheDisco/internal/engine"
	"github.com/watson0x90/PasswordAtTheDisco/internal/hibp"
	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
	"github.com/watson0x90/PasswordAtTheDisco/internal/policy"
	"github.com/watson0x90/PasswordAtTheDisco/internal/pwanalysis"
	"github.com/watson0x90/PasswordAtTheDisco/internal/secretsdump"
)

// runAudit parses credential dumps, scores them through the engine, and pushes
// the resulting dataset to the API's /api/ingest endpoint (and/or a JSON file).
//
// Usage: patd audit [flags] DOMAIN cracked-file uncracked-file [DOMAIN ...]
func runAudit(args []string) {
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	api := fs.String("api", env("PATD_API", "http://127.0.0.1:8443"), "API base URL to POST the dataset to (empty to skip)")
	token := fs.String("token", os.Getenv("PATD_INGEST_TOKEN"), "ingest bearer token (or PATD_INGEST_TOKEN)")
	hibpPath := fs.String("hibp", "PwnedPasswordsDownloader/pwnedpasswords_ntlm.txt", "HIBP NTLM dump path (optional)")
	listsDir := fs.String("lists", "lists", "wordlists directory")
	bhePath := fs.String("bhe", "config/bloodhound.json", "BloodHound config path (optional)")
	policyPath := fs.String("policy", "lists/password_policy.json", "per-domain password policy file (optional)")
	name := fs.String("name", "CLI import", "name for the audit this ingest creates")
	out := fs.String("out", "", "also write the dataset JSON to this file")
	insecure := fs.Bool("insecure", false, "skip TLS verification when POSTing (self-signed dev certs)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: patd audit [flags] DOMAIN cracked-file uncracked-file [DOMAIN cracked-file uncracked-file ...]")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)

	entries, err := parseEntries(fs.Args())
	if err != nil {
		fs.Usage()
		log.Fatalf("audit: %v", err)
	}

	eng, _, cleanup := buildEngine(*hibpPath, *listsDir, *bhePath, *policyPath)
	defer cleanup()

	var all []model.Account
	for _, e := range entries {
		cracked, uncracked, err := secretsdump.ParseDomain(e.Domain, e.Cracked, e.Uncracked)
		if err != nil {
			log.Printf("skip %s: %v", e.Domain, err)
			continue
		}
		accts := eng.ProcessDomain(e.Domain, cracked, uncracked)
		all = append(all, accts...)
		log.Printf("%s: %d cracked + %d uncracked -> %d accounts", e.Domain, len(cracked), len(uncracked), len(accts))
	}

	data, err := json.Marshal(model.Dataset{Name: *name, GeneratedAt: time.Now().UTC(), Accounts: all})
	if err != nil {
		log.Fatalf("encode dataset: %v", err)
	}
	if *out != "" {
		if err := os.WriteFile(*out, data, 0o600); err != nil {
			log.Fatalf("write %s: %v", *out, err)
		}
		log.Printf("wrote %d accounts to %s", len(all), *out)
	}
	if *api != "" {
		if err := postDataset(*api, *token, data, *insecure); err != nil {
			log.Fatalf("ingest: %v", err)
		}
		log.Printf("ingested %d accounts to %s", len(all), *api)
	}
}

type domainEntry struct{ Domain, Cracked, Uncracked string }

// parseEntries reads positional args as (domain, cracked, uncracked) triples.
// Triples avoid the ':' delimiter ambiguity with Windows paths.
func parseEntries(args []string) ([]domainEntry, error) {
	if len(args) == 0 || len(args)%3 != 0 {
		return nil, fmt.Errorf("expected DOMAIN cracked-file uncracked-file triples, got %d argument(s)", len(args))
	}
	var out []domainEntry
	for i := 0; i < len(args); i += 3 {
		out = append(out, domainEntry{Domain: args[i], Cracked: args[i+1], Uncracked: args[i+2]})
	}
	return out, nil
}

// configured reports whether a BHE config has real (non-placeholder) credentials.
func configured(c bloodhound.Config) bool {
	return c.TokenID != "" && c.TokenID != "your-token-id-here" && c.TokenKey != "" && c.TokenKey != "your-token-key-here"
}

// buildEngine constructs the audit engine from on-disk inputs (shared by the
// `audit` CLI and the server's web-upload endpoint). It also returns the loaded
// policy Set so the server can expose/edit it. The returned cleanup closes the
// HIBP searcher; call it on shutdown.
func buildEngine(hibpPath, listsDir, bhePath, policyPath string) (*engine.Engine, *policy.Set, func()) {
	policies, err := policy.Load(policyPath)
	if err != nil {
		log.Printf("password policy load failed (%v); using built-in default", err)
		policies = policy.DefaultSet()
	} else {
		def, dom := policies.Snapshot()
		log.Printf("password policy loaded (%s): default min-len %d / max-age %dd, %d domain override(s)", policyPath, def.MinLength, def.MaxPasswordAgeDays, len(dom))
	}
	eng := &engine.Engine{
		Lists:    loadLists(listsDir),
		Policies: policies,
	}
	cleanup := func() {}
	if s, err := hibp.Open(hibpPath, hibp.DefaultPrefixLen); err == nil {
		eng.HIBP = s
		cleanup = func() { _ = s.Close() }
		log.Printf("HIBP correlation enabled (%s)", hibpPath)
	} else {
		log.Printf("HIBP correlation disabled (%v)", err)
	}
	if cfg, err := bloodhound.LoadConfig(bhePath); err == nil && configured(cfg) {
		eng.Enricher = engine.BloodhoundEnricher{Client: bloodhound.New(cfg)}
		log.Printf("BloodHound enrichment enabled (%s:%d)", cfg.Host, cfg.Port)
	} else {
		log.Printf("BloodHound enrichment disabled")
	}
	return eng, policies, cleanup
}

func loadLists(dir string) pwanalysis.Lists {
	load := func(name string) pwanalysis.Set {
		s, err := pwanalysis.LoadSet(filepath.Join(dir, name))
		if err != nil {
			log.Printf("wordlist %s unavailable (%v); using empty set", name, err)
			return pwanalysis.Set{}
		}
		return s
	}
	return pwanalysis.Lists{
		ForbiddenWords:   load("forbidden_words.txt"),
		KeyboardPatterns: load("keyboard_patterns.txt"),
		CommonPasswords:  load("common_passwords.txt"),
		DictionaryWords:  load("dictionary_words.txt"),
	}
}

func postDataset(apiBase, token string, body []byte, insecure bool) error {
	if token == "" {
		return fmt.Errorf("no ingest token (set -token or PATD_INGEST_TOKEN)")
	}
	req, err := http.NewRequest("POST", strings.TrimRight(apiBase, "/")+"/api/ingest", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 60 * time.Second}
	if insecure {
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec // opt-in dev flag
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}
