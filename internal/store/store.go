// Package store holds audits, optionally persisted to an encrypted vault. When
// persisted, only a small metadata index is decrypted at unlock; each audit's
// dataset is decrypted lazily on first access and held in a bounded LRU cache, so
// unlock latency and steady memory don't scale with all audits ever created.
// Cache entries are immutable (copy-on-write on mutation), so reads are lock-free.
package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
	"github.com/watson0x90/PasswordAtTheDisco/internal/vault"
)

// ErrNotFound is returned when an audit id does not exist.
var ErrNotFound = errors.New("audit not found")

// currentSchemaVersion versions the on-disk (pre-encryption) audit payload.
const currentSchemaVersion = 1

// defaultCacheCap bounds how many audit datasets are held decrypted at once.
const defaultCacheCap = 8

// AuditMeta describes one audit (no account data).
type AuditMeta struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Notes     string    `json:"notes,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// AuditListItem is an audit's metadata plus headline counts (for the picker). It
// is also the per-audit entry of the on-disk index, so List works without
// decrypting any dataset.
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

// keyedMutex serializes read-modify-write per audit id (so a load-build-swap on
// one audit can't lose another's concurrent write) without blocking readers.
type keyedMutex struct {
	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

func (k *keyedMutex) lock(id string) func() {
	k.mu.Lock()
	if k.locks == nil {
		k.locks = map[string]*sync.Mutex{}
	}
	m := k.locks[id]
	if m == nil {
		m = &sync.Mutex{}
		k.locks[id] = m
	}
	k.mu.Unlock()
	m.Lock()
	return m.Unlock
}

// Store is a thread-safe collection of audits.
type Store struct {
	mu      sync.Mutex
	writeMu sync.Mutex // serializes vault writes without blocking readers
	mutate  keyedMutex // serializes per-audit read-modify-write
	index   map[string]AuditListItem
	cache   map[string]*audit // lazily decrypted datasets (immutable entries)
	lru     []string          // cache ids, oldest first
	cap     int               // cache cap (0 = unlimited, for in-memory)
	now     func() time.Time
	newID   func() string
	vault   *vault.Vault // nil = in-memory only
}

// New returns an empty in-memory Store (no persistence, no eviction).
func New() *Store {
	return &Store{
		index: map[string]AuditListItem{},
		cache: map[string]*audit{},
		now:   func() time.Time { return time.Now().UTC() },
		newID: randomID,
		cap:   0,
	}
}

// NewPersistent returns a Store backed by an encrypted vault. It starts locked;
// Unlock loads the metadata index and datasets load lazily.
func NewPersistent(v *vault.Vault) *Store {
	s := New()
	s.vault = v
	s.cap = defaultCacheCap
	return s
}

func randomID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func listItem(m AuditMeta, ds model.Dataset) AuditListItem {
	it := AuditListItem{AuditMeta: m}
	for _, a := range ds.Accounts {
		it.TotalAccounts++
		if a.Cracked {
			it.Cracked++
		}
	}
	return it
}

// --- lock state ---

func (s *Store) Initialized() bool {
	if s.vault == nil {
		return true
	}
	return s.vault.Initialized()
}

func (s *Store) Unlocked() bool {
	if s.vault == nil {
		return true
	}
	return s.vault.Unlocked()
}

func (s *Store) Initialize(passphrase string) error {
	if s.vault == nil {
		return nil
	}
	return s.vault.Initialize(passphrase)
}

// Unlock decrypts the vault and loads the metadata index into memory.
func (s *Store) Unlock(passphrase string) error {
	if s.vault == nil {
		return nil
	}
	if err := s.vault.Unlock(passphrase); err != nil {
		return err
	}
	return s.loadIndex()
}

// Lock drops the key and clears the index + decrypted cache from memory.
func (s *Store) Lock() {
	if s.vault == nil {
		return
	}
	s.vault.Lock()
	s.mu.Lock()
	s.index = map[string]AuditListItem{}
	s.cache = map[string]*audit{}
	s.lru = nil
	s.mu.Unlock()
}

func (s *Store) ChangePassphrase(oldPass, newPass string) error {
	if s.vault == nil {
		return nil
	}
	// Serialize against in-flight vault writes (load-bearing once the DEK rotates).
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.vault.ChangePassphrase(oldPass, newPass)
}

// Rekey rotates the data-encryption key, re-encrypting every audit under a fresh
// DEK (the passphrase is unchanged). In-memory plaintext is unaffected. No-op
// in-memory.
//
// It MUST hold writeMu for the whole operation: otherwise a SaveAudit that
// captured the old DEK and has a still-pending writeFileAtomic could land AFTER
// rekey drops the old key, leaving that blob sealed under a key no longer on disk
// -- permanently undecryptable (and, via reconcile->rebuild, bricking unlock).
func (s *Store) Rekey(passphrase string) error {
	if s.vault == nil {
		return nil
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.vault.Rekey(passphrase)
}

// loadIndex populates the metadata index. The index is a derived cache, so on
// ANY failure to read it (absent, corrupt, or unparseable) it is rebuilt from the
// still-authentic audit blobs and re-persisted -- a corrupt index never bricks
// intact data. After loading it reconciles against the blobs on disk (drops index
// entries with no blob; adopts blobs with no entry).
func (s *Store) loadIndex() error {
	idx, ok := s.tryLoadIndex()
	if !ok {
		return s.rebuildIndex()
	}
	if err := s.reconcile(idx); err != nil {
		if errors.Is(err, errRebuild) {
			return s.rebuildIndex()
		}
		return err
	}
	s.mu.Lock()
	s.index, s.cache, s.lru = idx, map[string]*audit{}, nil
	s.mu.Unlock()
	return nil
}

// tryLoadIndex returns the decrypted+parsed index, or ok=false if it is absent or
// unusable (so the caller rebuilds).
func (s *Store) tryLoadIndex() (map[string]AuditListItem, bool) {
	b, err := s.vault.LoadIndex()
	if err != nil {
		if !errors.Is(err, vault.ErrNoIndex) {
			log.Printf("index unreadable (%v); rebuilding from blobs", err)
		}
		return nil, false
	}
	var idx map[string]AuditListItem
	if err := json.Unmarshal(b, &idx); err != nil {
		log.Printf("index corrupt (%v); rebuilding from blobs", err)
		return nil, false
	}
	return idx, true
}

// reconcile drops index entries whose blob is gone (ghosts). Adopting orphan
// blobs (entry missing) is handled by a full rebuild, which reconcile triggers.
func (s *Store) reconcile(idx map[string]AuditListItem) error {
	ids, err := s.vault.ListAudits()
	if err != nil {
		return err
	}
	have := make(map[string]bool, len(ids))
	for _, id := range ids {
		have[id] = true
	}
	changed := false
	for id := range idx {
		if !have[id] {
			delete(idx, id) // ghost: index lists an audit with no blob
			changed = true
		}
	}
	if len(idx) != len(have) || changed { // an orphan blob exists, or we pruned: rebuild for accuracy
		return errRebuild
	}
	return nil
}

var errRebuild = errors.New("index needs rebuild")

// rebuildIndex decrypts every blob once to rebuild + persist the index.
func (s *Store) rebuildIndex() error {
	blobs, err := s.vault.LoadAll()
	if err != nil {
		return err
	}
	idx := make(map[string]AuditListItem, len(blobs))
	for id, bb := range blobs {
		var p persisted
		if err := json.Unmarshal(bb, &p); err != nil {
			log.Printf("skipping unreadable audit blob %s during reindex: %v", id, err)
			continue // a single bad blob must not abort the whole unlock
		}
		if p.SchemaVersion > currentSchemaVersion {
			return fmt.Errorf("audit %s was written by a newer version (schema %d > %d)", id, p.SchemaVersion, currentSchemaVersion)
		}
		idx[id] = listItem(p.Meta, p.Dataset)
	}
	s.mu.Lock()
	s.index, s.cache, s.lru = idx, map[string]*audit{}, nil
	ib, mErr := json.Marshal(idx)
	s.mu.Unlock()
	if mErr != nil {
		return mErr
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.vault.SaveIndex(ib)
}

// Reindex forces a rebuild of the index from the audit blobs (admin recovery).
func (s *Store) Reindex() error {
	if s.vault == nil {
		return nil
	}
	return s.rebuildIndex()
}

// --- cache (caller holds s.mu) ---

func (s *Store) bumpLRU(id string) {
	for i, x := range s.lru {
		if x == id {
			s.lru = append(s.lru[:i], s.lru[i+1:]...)
			break
		}
	}
	s.lru = append(s.lru, id)
}

func (s *Store) removeLRU(id string) {
	for i, x := range s.lru {
		if x == id {
			s.lru = append(s.lru[:i], s.lru[i+1:]...)
			return
		}
	}
}

func (s *Store) evict() {
	if s.cap <= 0 {
		return
	}
	for len(s.cache) > s.cap && len(s.lru) > 0 {
		oldest := s.lru[0]
		s.lru = s.lru[1:]
		delete(s.cache, oldest)
	}
}

// ensureLoaded returns the (immutable) audit, decrypting it on demand. The
// decrypt happens outside the lock; a double-check avoids a duplicate load.
func (s *Store) ensureLoaded(id string) (*audit, error) {
	s.mu.Lock()
	if a, ok := s.cache[id]; ok {
		s.bumpLRU(id)
		s.mu.Unlock()
		return a, nil
	}
	_, known := s.index[id]
	s.mu.Unlock()
	if !known || s.vault == nil {
		return nil, ErrNotFound
	}
	b, err := s.vault.LoadOne(id)
	if err != nil {
		return nil, err
	}
	var p persisted
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, err
	}
	a := &audit{meta: p.Meta, ds: p.Dataset}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.cache[id]; ok {
		s.bumpLRU(id)
		return existing, nil
	}
	s.cache[id] = a
	s.bumpLRU(id)
	s.evict()
	return a, nil
}

// marshalAudit serializes an audit for persistence.
func marshalAudit(a *audit) ([]byte, error) {
	return json.Marshal(persisted{SchemaVersion: currentSchemaVersion, Meta: a.meta, Dataset: a.ds})
}

// persist writes an audit blob + the index, serialized and outside the store lock.
func (s *Store) persist(id string, auditBytes, indexBytes []byte) error {
	if s.vault == nil {
		return nil
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := s.vault.SaveAudit(id, auditBytes); err != nil {
		return err
	}
	return s.vault.SaveIndex(indexBytes)
}

// marshalIndex serializes the index (caller holds s.mu).
func (s *Store) marshalIndex() ([]byte, error) { return json.Marshal(s.index) }

// --- audits ---

// CreateAudit adds a new, empty audit and returns its metadata.
func (s *Store) CreateAudit(name, notes string) (AuditMeta, error) {
	now := s.now()
	a := &audit{meta: AuditMeta{ID: s.newID(), Name: name, Notes: notes, CreatedAt: now, UpdatedAt: now}, ds: model.Dataset{GeneratedAt: now}}
	s.mu.Lock()
	s.index[a.meta.ID] = listItem(a.meta, a.ds)
	s.cache[a.meta.ID] = a
	s.bumpLRU(a.meta.ID)
	s.evict()
	ab, err := marshalAudit(a)
	ib, ierr := s.marshalIndex()
	s.mu.Unlock()
	if err == nil && ierr == nil {
		err = s.persist(a.meta.ID, ab, ib)
	} else if ierr != nil {
		err = ierr
	}
	if err != nil {
		s.mu.Lock()
		delete(s.index, a.meta.ID)
		delete(s.cache, a.meta.ID)
		s.removeLRU(a.meta.ID)
		s.mu.Unlock()
		return AuditMeta{}, err
	}
	return a.meta, nil
}

// ReplaceDomain replaces all accounts for one domain (per-domain upload),
// copy-on-write so concurrent readers keep a consistent snapshot.
func (s *Store) ReplaceDomain(id, domain string, accounts []model.Account) error {
	unlock := s.mutate.lock(id) // serialize the whole read-modify-write for this audit
	defer unlock()
	cur, err := s.ensureLoaded(id)
	if err != nil {
		return err
	}
	kept := make([]model.Account, 0, len(cur.ds.Accounts))
	for _, acc := range cur.ds.Accounts {
		if acc.Domain != domain {
			kept = append(kept, acc)
		}
	}
	merged := append(kept, accounts...)
	model.RecomputeSharing(merged)     // cross-domain reuse counts over the whole audit
	model.EscalateSharedWithDA(merged) // cross-domain DA-share escalation
	now := s.now()
	meta := cur.meta
	meta.UpdatedAt = now
	return s.swap(id, &audit{meta: meta, ds: model.Dataset{Name: cur.ds.Name, GeneratedAt: now, Accounts: merged}})
}

// Replace swaps an audit's entire dataset (CLI ingest).
func (s *Store) Replace(id string, ds model.Dataset) error {
	unlock := s.mutate.lock(id)
	defer unlock()
	cur, err := s.ensureLoaded(id)
	if err != nil {
		return err
	}
	if ds.GeneratedAt.IsZero() {
		ds.GeneratedAt = s.now()
	}
	model.RecomputeSharing(ds.Accounts)
	model.EscalateSharedWithDA(ds.Accounts)
	meta := cur.meta
	meta.UpdatedAt = ds.GeneratedAt
	return s.swap(id, &audit{meta: meta, ds: ds})
}

// swap replaces the cached audit + index entry and persists (copy-on-write).
func (s *Store) swap(id string, next *audit) error {
	s.mu.Lock()
	if _, ok := s.index[id]; !ok {
		s.mu.Unlock()
		return ErrNotFound
	}
	s.cache[id] = next
	s.bumpLRU(id)
	s.index[id] = listItem(next.meta, next.ds)
	ab, err := marshalAudit(next)
	ib, ierr := s.marshalIndex()
	s.mu.Unlock()
	if err != nil {
		return err
	}
	if ierr != nil {
		return ierr
	}
	return s.persist(id, ab, ib)
}

// List returns all audits' metadata + counts, newest first (from the index).
func (s *Store) List() []AuditListItem {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]AuditListItem, 0, len(s.index))
	for _, it := range s.index {
		out = append(out, it)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// Meta returns an audit's metadata (from the index).
func (s *Store) Meta(id string) (AuditMeta, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	it, ok := s.index[id]
	return it.AuditMeta, ok
}

// Has reports whether an audit exists (from the index).
func (s *Store) Has(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.index[id]
	return ok
}

// Delete removes an audit. Returns ErrNotFound if it did not exist. The index is
// persisted BEFORE the blob is removed, so a crash leaves a harmless reapable
// orphan blob rather than a ghost index entry; the SaveIndex error is propagated.
func (s *Store) Delete(id string) error {
	unlock := s.mutate.lock(id)
	defer unlock()
	s.mu.Lock()
	if _, ok := s.index[id]; !ok {
		s.mu.Unlock()
		return ErrNotFound
	}
	delete(s.index, id)
	delete(s.cache, id)
	s.removeLRU(id)
	ib, err := s.marshalIndex()
	s.mu.Unlock()
	if s.vault == nil || err != nil {
		return err
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := s.vault.SaveIndex(ib); err != nil { // index first
		return err
	}
	return s.vault.DeleteAudit(id) // then the blob
}

// Accounts returns an audit's accounts, redacted unless includeSecrets. The
// cached audit is immutable, so the read needs no lock.
func (s *Store) Accounts(id string, includeSecrets bool) ([]model.Account, error) {
	a, err := s.ensureLoaded(id)
	if err != nil {
		return nil, err
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
	a, err := s.ensureLoaded(id)
	if err != nil {
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
	a, err := s.ensureLoaded(id)
	if err != nil {
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
	sum.Posture = model.PostureScore(a.ds.Accounts) // single source for the dashboard gauge
	return sum, nil
}
