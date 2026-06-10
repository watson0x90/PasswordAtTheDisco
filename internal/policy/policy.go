// Package policy holds per-domain password policies (minimum length, required
// character classes, and maximum password age) loaded from password_policy.json
// and applied by the scoring engine. A Set is safe for concurrent use, so the
// live engine and the policy-management endpoints can share one instance.
package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/watson0x90/PasswordAtTheDisco/internal/pwanalysis"
)

// Policy is one domain's password policy.
type Policy struct {
	MinLength          int  `json:"min_length"`
	RequireLowercase   bool `json:"require_lowercase"`
	RequireUppercase   bool `json:"require_uppercase"`
	RequireDigits      bool `json:"require_digits"`
	RequireSpecial     bool `json:"require_special"`
	MaxPasswordAgeDays int  `json:"max_password_age_days"`
}

// Default is the built-in fallback when no file/default policy is present.
func Default() Policy {
	return Policy{
		MinLength:          14,
		RequireLowercase:   true,
		RequireUppercase:   true,
		RequireDigits:      true,
		RequireSpecial:     true,
		MaxPasswordAgeDays: 90,
	}
}

// Analysis returns the password-analysis subset (length + required classes).
func (p Policy) Analysis() pwanalysis.Policy {
	return pwanalysis.Policy{
		MinLength:        p.MinLength,
		RequireLowercase: p.RequireLowercase,
		RequireUppercase: p.RequireUppercase,
		RequireDigits:    p.RequireDigits,
		RequireSpecial:   p.RequireSpecial,
	}
}

// Set is a thread-safe default policy plus per-domain overrides.
type Set struct {
	mu      sync.RWMutex
	def     Policy
	domains map[string]Policy
}

// DefaultSet returns a Set with the built-in default and no overrides.
func DefaultSet() *Set {
	return &Set{def: Default(), domains: map[string]Policy{}}
}

// For returns the policy for a domain: its override if present, else the default.
func (s *Set) For(domain string) Policy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if p, ok := s.domains[domain]; ok {
		return p
	}
	return s.def
}

// Snapshot returns a copy of the default and the per-domain overrides.
func (s *Set) Snapshot() (def Policy, domains map[string]Policy) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]Policy, len(s.domains))
	for k, v := range s.domains {
		out[k] = v
	}
	return s.def, out
}

// Replace swaps in a new default and per-domain set.
func (s *Set) Replace(def Policy, domains map[string]Policy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.def = def
	s.domains = make(map[string]Policy, len(domains))
	for k, v := range domains {
		s.domains[k] = v
	}
}

// fileEntry matches the on-disk password_policy.json shape:
//
//	{"default": {"policy": {...}}, "CORP.LOCAL": {"policy": {...}}}
type fileEntry struct {
	Policy Policy `json:"policy"`
}

// Load reads password_policy.json. A missing file yields DefaultSet (no error).
func Load(path string) (*Set, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return DefaultSet(), nil
		}
		return nil, err
	}
	var raw map[string]fileEntry
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	s := DefaultSet()
	domains := map[string]Policy{}
	for k, v := range raw {
		if k == "default" {
			s.def = v.Policy
		} else {
			domains[k] = v.Policy
		}
	}
	s.domains = domains
	return s, nil
}

// Save writes the set to path in the password_policy.json format (0600).
func (s *Set) Save(path string) error {
	def, domains := s.Snapshot()
	raw := map[string]fileEntry{"default": {Policy: def}}
	for k, v := range domains {
		raw[k] = fileEntry{Policy: v}
	}
	b, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, b)
}

// writeFileAtomic writes b durably: a temp file in the same directory is written +
// fsync'd, then renamed over path (then the dir is fsync'd, best-effort). A crash
// leaves either the old policy file or the complete new one, never a truncated one.
func writeFileAtomic(path string, b []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".policy-*.tmp") // 0600 by default
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }() // no-op once renamed
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil { // dir fsync; not supported everywhere
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
