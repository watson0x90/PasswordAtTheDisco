// Package store holds audits in memory. Each audit owns its own dataset of
// accounts. Cleartext passwords live only in process memory -- the API never
// writes them to disk in the clear (Phase 2 adds encrypted-at-rest persistence).
package store

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
)

// ErrNotFound is returned when an audit id does not exist.
var ErrNotFound = errors.New("audit not found")

// AuditMeta describes one audit (no account data).
type AuditMeta struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Notes     string    `json:"notes,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// AuditListItem is an audit's metadata plus headline counts (for the picker).
type AuditListItem struct {
	AuditMeta
	TotalAccounts int `json:"total_accounts"`
	Cracked       int `json:"cracked"`
}

type audit struct {
	meta AuditMeta
	ds   model.Dataset
}

// Store is a thread-safe, in-memory collection of audits.
type Store struct {
	mu     sync.RWMutex
	audits map[string]*audit
	now    func() time.Time
	newID  func() string
}

// New returns an empty Store.
func New() *Store {
	return &Store{
		audits: map[string]*audit{},
		now:    func() time.Time { return time.Now().UTC() },
		newID:  randomID,
	}
}

func randomID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// CreateAudit adds a new, empty audit and returns its metadata.
func (s *Store) CreateAudit(name, notes string) AuditMeta {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	m := AuditMeta{ID: s.newID(), Name: name, Notes: notes, CreatedAt: now, UpdatedAt: now}
	s.audits[m.ID] = &audit{meta: m, ds: model.Dataset{GeneratedAt: now}}
	return m
}

// List returns all audits' metadata + counts, newest first.
func (s *Store) List() []AuditListItem {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]AuditListItem, 0, len(s.audits))
	for _, a := range s.audits {
		item := AuditListItem{AuditMeta: a.meta}
		for _, acc := range a.ds.Accounts {
			item.TotalAccounts++
			if acc.Cracked {
				item.Cracked++
			}
		}
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// Has reports whether an audit exists.
func (s *Store) Has(id string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.audits[id]
	return ok
}

// Delete removes an audit. Returns false if it did not exist.
func (s *Store) Delete(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.audits[id]; !ok {
		return false
	}
	delete(s.audits, id)
	return true
}

// ReplaceDomain replaces all accounts for one domain within an audit, leaving
// other domains intact (per-domain web upload).
func (s *Store) ReplaceDomain(id, domain string, accounts []model.Account) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.audits[id]
	if !ok {
		return ErrNotFound
	}
	kept := make([]model.Account, 0, len(a.ds.Accounts))
	for _, acc := range a.ds.Accounts {
		if acc.Domain != domain {
			kept = append(kept, acc)
		}
	}
	a.ds.Accounts = append(kept, accounts...)
	a.ds.GeneratedAt = s.now()
	a.meta.UpdatedAt = a.ds.GeneratedAt
	return nil
}

// Replace swaps an audit's entire dataset (CLI ingest).
func (s *Store) Replace(id string, ds model.Dataset) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.audits[id]
	if !ok {
		return ErrNotFound
	}
	if ds.GeneratedAt.IsZero() {
		ds.GeneratedAt = s.now()
	}
	a.ds = ds
	a.meta.UpdatedAt = ds.GeneratedAt
	return nil
}

// Accounts returns an audit's accounts. Passwords are stripped unless
// includeSecrets is true (callers must gate that behind authz + audit logging).
func (s *Store) Accounts(id string, includeSecrets bool) ([]model.Account, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.audits[id]
	if !ok {
		return nil, ErrNotFound
	}
	out := make([]model.Account, len(a.ds.Accounts))
	for i, acc := range a.ds.Accounts {
		if includeSecrets {
			out[i] = acc
		} else {
			out[i] = acc.Redacted()
		}
	}
	return out, nil
}

// Find returns the full (unredacted) account for username within an audit.
// Callers must gate this behind authorization + audit logging.
func (s *Store) Find(id, username string) (model.Account, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.audits[id]
	if !ok {
		return model.Account{}, false
	}
	for _, acc := range a.ds.Accounts {
		if acc.Username == username {
			return acc, true
		}
	}
	return model.Account{}, false
}

// Summary returns an audit's non-sensitive aggregate stats.
func (s *Store) Summary(id string) (model.Summary, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.audits[id]
	if !ok {
		return model.Summary{}, ErrNotFound
	}
	sum := model.Summary{RiskCounts: map[string]int{}, GeneratedAt: a.ds.GeneratedAt}
	for _, acc := range a.ds.Accounts {
		sum.TotalAccounts++
		if acc.Cracked {
			sum.Cracked++
		}
		if acc.HIBPBreached {
			sum.HIBPBreached++
		}
		if acc.HasDAPathway() {
			sum.DAPathways++
		}
		if acc.RiskLevel != "" {
			sum.RiskCounts[acc.RiskLevel]++
		}
	}
	return sum, nil
}
