// Package store holds the ingested audit dataset in memory. Cleartext passwords
// live only in process memory -- the API never writes them to disk. Ingestion
// is full-replace, not append.
package store

import (
	"sync"

	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
)

// Store is a thread-safe, in-memory holder for the current audit dataset.
type Store struct {
	mu sync.RWMutex
	ds model.Dataset
}

// New returns an empty Store.
func New() *Store { return &Store{} }

// Replace swaps in a new dataset.
func (s *Store) Replace(ds model.Dataset) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ds = ds
}

// Accounts returns the accounts. Passwords are stripped unless includeSecrets is
// true (which callers must only set after an authorization + audit check).
func (s *Store) Accounts(includeSecrets bool) []model.Account {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.Account, len(s.ds.Accounts))
	for i, a := range s.ds.Accounts {
		if includeSecrets {
			out[i] = a
		} else {
			out[i] = a.Redacted()
		}
	}
	return out
}

// Find returns the full (unredacted) account for username. Callers must gate
// this behind authorization + audit logging.
func (s *Store) Find(username string) (model.Account, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, a := range s.ds.Accounts {
		if a.Username == username {
			return a, true
		}
	}
	return model.Account{}, false
}

// Summary returns non-sensitive aggregate stats.
func (s *Store) Summary() model.Summary {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sum := model.Summary{RiskCounts: map[string]int{}, GeneratedAt: s.ds.GeneratedAt}
	for _, a := range s.ds.Accounts {
		sum.TotalAccounts++
		if a.Cracked {
			sum.Cracked++
		}
		if a.HIBPBreached {
			sum.HIBPBreached++
		}
		if a.HasDAPathway() {
			sum.DAPathways++
		}
		if a.RiskLevel != "" {
			sum.RiskCounts[a.RiskLevel]++
		}
	}
	return sum
}
