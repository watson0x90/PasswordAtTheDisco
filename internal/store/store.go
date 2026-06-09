// Package store holds audits in memory. Each audit owns its own dataset of
// accounts. Cleartext passwords live only in process memory -- the API never
// writes them to disk in the clear (Phase 2 adds encrypted-at-rest persistence).
package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
	"github.com/watson0x90/PasswordAtTheDisco/internal/vault"
)

// currentSchemaVersion versions the on-disk (pre-encryption) audit payload so a
// future model change can migrate old blobs instead of silently zero-filling.
const currentSchemaVersion = 1

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

// persisted is the on-disk (pre-encryption) shape of one audit.
type persisted struct {
	SchemaVersion int           `json:"schema_version"`
	Meta          AuditMeta     `json:"meta"`
	Dataset       model.Dataset `json:"dataset"`
}

// Store is a thread-safe collection of audits, optionally persisted to an
// encrypted vault. With no vault it is purely in-memory and always "unlocked".
type Store struct {
	mu     sync.RWMutex
	audits map[string]*audit
	now    func() time.Time
	newID  func() string
	vault  *vault.Vault // nil = in-memory only
}

// New returns an empty in-memory Store (no persistence).
func New() *Store {
	return &Store{
		audits: map[string]*audit{},
		now:    func() time.Time { return time.Now().UTC() },
		newID:  randomID,
	}
}

// NewPersistent returns a Store backed by an encrypted vault. It starts locked
// (and empty) until Unlock loads the decrypted audits into memory.
func NewPersistent(v *vault.Vault) *Store {
	s := New()
	s.vault = v
	return s
}

// Initialized reports whether the backing vault has a passphrase set (always
// true for an in-memory store).
func (s *Store) Initialized() bool {
	if s.vault == nil {
		return true
	}
	return s.vault.Initialized()
}

// Unlocked reports whether the store is usable (always true in-memory).
func (s *Store) Unlocked() bool {
	if s.vault == nil {
		return true
	}
	return s.vault.Unlocked()
}

// Initialize sets the store passphrase on first run (no-op in-memory).
func (s *Store) Initialize(passphrase string) error {
	if s.vault == nil {
		return nil
	}
	return s.vault.Initialize(passphrase)
}

// Unlock decrypts the vault with the passphrase and loads the audits into memory.
func (s *Store) Unlock(passphrase string) error {
	if s.vault == nil {
		return nil
	}
	if err := s.vault.Unlock(passphrase); err != nil {
		return err
	}
	return s.load()
}

// Lock drops the encryption key AND clears the decrypted audits from memory, so
// cleartext no longer resides in the process. No-op for an in-memory store.
func (s *Store) Lock() {
	if s.vault == nil {
		return
	}
	s.vault.Lock()
	s.mu.Lock()
	s.audits = map[string]*audit{}
	s.mu.Unlock()
}

// ChangePassphrase re-wraps the data key under a new passphrase (no-op in-memory).
func (s *Store) ChangePassphrase(oldPass, newPass string) error {
	if s.vault == nil {
		return nil
	}
	return s.vault.ChangePassphrase(oldPass, newPass)
}

func (s *Store) load() error {
	blobs, err := s.vault.LoadAll()
	if err != nil {
		return err
	}
	loaded := make(map[string]*audit, len(blobs))
	for id, b := range blobs {
		var p persisted
		if err := json.Unmarshal(b, &p); err != nil {
			return err
		}
		if p.SchemaVersion > currentSchemaVersion {
			return fmt.Errorf("audit %s was written by a newer version (schema %d > %d)", id, p.SchemaVersion, currentSchemaVersion)
		}
		// schema 0 (pre-versioning) and 1 share the current shape; add migrations here.
		loaded[id] = &audit{meta: p.Meta, ds: p.Dataset}
	}
	s.mu.Lock()
	s.audits = loaded
	s.mu.Unlock()
	return nil
}

// persist writes one audit to the vault (caller holds s.mu). No-op in-memory.
func (s *Store) persist(a *audit) error {
	if s.vault == nil {
		return nil
	}
	b, err := json.Marshal(persisted{SchemaVersion: currentSchemaVersion, Meta: a.meta, Dataset: a.ds})
	if err != nil {
		return err
	}
	return s.vault.SaveAudit(a.meta.ID, b)
}

func randomID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// CreateAudit adds a new, empty audit and returns its metadata.
func (s *Store) CreateAudit(name, notes string) (AuditMeta, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	a := &audit{meta: AuditMeta{ID: s.newID(), Name: name, Notes: notes, CreatedAt: now, UpdatedAt: now}, ds: model.Dataset{GeneratedAt: now}}
	s.audits[a.meta.ID] = a
	if err := s.persist(a); err != nil {
		delete(s.audits, a.meta.ID) // roll back if it can't be saved
		return AuditMeta{}, err
	}
	return a.meta, nil
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

// Meta returns an audit's metadata.
func (s *Store) Meta(id string) (AuditMeta, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.audits[id]
	if !ok {
		return AuditMeta{}, false
	}
	return a.meta, true
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
	if s.vault != nil {
		_ = s.vault.DeleteAudit(id) // best-effort; file may already be gone
	}
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
	return s.persist(a)
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
	return s.persist(a)
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
