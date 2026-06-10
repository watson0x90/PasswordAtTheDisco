package store

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
	"github.com/watson0x90/PasswordAtTheDisco/internal/vault"
)

// Deterministic guard for the data-loss fix: a write that starts during a rekey
// MUST block until the rekey finishes (store.Rekey holds writeMu), then land
// durably under the new key. Unlike the probabilistic concurrent-hammer test, this
// FAILS if store.Rekey stops holding writeMu.
func TestRekeySerializesConcurrentWrite(t *testing.T) {
	dir := t.TempDir()
	v, _ := vault.Open(dir)
	s := NewPersistent(v)
	if err := s.Initialize("serialize-passphrase"); err != nil {
		t.Fatal(err)
	}
	m, _ := s.CreateAudit("A", "")
	if err := s.Replace(m.ID, model.Dataset{Accounts: []model.Account{{Username: "orig", Domain: "D", Cracked: true}}}); err != nil {
		t.Fatal(err)
	}

	writeDone := make(chan error, 1)
	s.testHookInRekey = func() { // runs inside Rekey holding writeMu
		started := make(chan struct{})
		go func() {
			close(started)
			writeDone <- s.ReplaceDomain(m.ID, "D", []model.Account{{Username: "after-rekey", Domain: "D", Cracked: true}})
		}()
		<-started
		select {
		case <-writeDone:
			t.Error("ReplaceDomain completed DURING rekey -- store.Rekey is not holding writeMu")
		case <-time.After(200 * time.Millisecond):
			// expected: the write is blocked on writeMu
		}
	}
	if err := s.Rekey("serialize-passphrase"); err != nil {
		t.Fatalf("rekey: %v", err)
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("post-rekey write failed: %v", err)
	}

	// The write landed after the rotation (under the new DEK); reopen proves it's
	// durable + decryptable, not silently lost.
	s2 := NewPersistent(mustReopen(t, dir))
	if err := s2.Unlock("serialize-passphrase"); err != nil {
		t.Fatal(err)
	}
	accts, err := s2.Accounts(m.ID, true)
	if err != nil {
		t.Fatalf("audit unreadable after rekey+write: %v", err)
	}
	if len(accts) != 1 || accts[0].Username != "after-rekey" {
		t.Fatalf("post-rekey write not durable: %+v", accts)
	}
}

// Logical regression test for the lost-update race: two concurrent per-domain
// uploads to the same audit must BOTH survive. (go test -race cannot catch this
// -- the copy-on-write design has no memory race, only last-writer-wins.)
func TestConcurrentReplaceDomainNoLostUpdate(t *testing.T) {
	for trial := 0; trial < 50; trial++ {
		s := New()
		m, _ := s.CreateAudit("x", "")
		var wg sync.WaitGroup
		for i := 0; i < 2; i++ {
			dom := fmt.Sprintf("D%d", i)
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = s.ReplaceDomain(m.ID, dom, []model.Account{{Username: "u" + dom, Domain: dom, Cracked: true}})
			}()
		}
		wg.Wait()
		accts, _ := s.Accounts(m.ID, false)
		if len(accts) != 2 {
			t.Fatalf("trial %d: both domains should survive concurrent upload, got %d", trial, len(accts))
		}
	}
}

// Regression for the panel-3 data-loss race: writes hammering the store while a
// rekey runs must not lose or brick any audit. (-race also checks memory safety;
// the assertion that every audit still decrypts after reopen is the logical guard
// that store.Rekey holds writeMu.)
func TestRekeyConcurrentWritesNoLoss(t *testing.T) {
	dir := t.TempDir()
	v, _ := vault.Open(dir)
	s := NewPersistent(v)
	if err := s.Initialize("rekey-race-passphrase"); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for i := 0; i < 6; i++ {
		m, _ := s.CreateAudit(fmt.Sprintf("A%d", i), "")
		if err := s.Replace(m.ID, model.Dataset{Accounts: []model.Account{{Username: fmt.Sprintf("u%d", i), Domain: "D", Cracked: true}}}); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, m.ID)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); _ = s.Rekey("rekey-race-passphrase") }()
	for _, id := range ids {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			_ = s.ReplaceDomain(id, "D", []model.Account{{Username: "x", Domain: "D", Cracked: true}})
		}(id)
	}
	wg.Wait()

	// Reopen as on restart: every audit must still decrypt under the (rotated) key.
	s2 := NewPersistent(mustReopen(t, dir))
	if err := s2.Unlock("rekey-race-passphrase"); err != nil {
		t.Fatalf("unlock after concurrent rekey: %v", err)
	}
	if len(s2.List()) != len(ids) {
		t.Fatalf("audits lost across rekey race: %d/%d", len(s2.List()), len(ids))
	}
	for _, id := range ids {
		if _, err := s2.Accounts(id, true); err != nil {
			t.Fatalf("audit %s undecryptable after rekey race: %v", id, err)
		}
	}
}

// An undecryptable blob (e.g. sealed under a lost key) must be quarantined, not
// repeatedly re-skipped: unlock recovers + drops it, and a second unlock does not
// re-trigger the rebuild loop (index now matches the on-disk .enc count).
func TestUndecryptableBlobQuarantined(t *testing.T) {
	dir := t.TempDir()
	v, _ := vault.Open(dir)
	s := NewPersistent(v)
	if err := s.Initialize("quarantine-passphrase"); err != nil {
		t.Fatal(err)
	}
	var badID string
	for i := 0; i < 3; i++ {
		m, _ := s.CreateAudit(fmt.Sprintf("A%d", i), "")
		if err := s.Replace(m.ID, sample()); err != nil {
			t.Fatal(err)
		}
		if i == 1 {
			badID = m.ID
		}
	}
	blob := filepath.Join(dir, "audits", badID+".enc")
	if err := os.WriteFile(blob, []byte("not-valid-gcm-ciphertext-garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Invalidate the index so unlock must rebuild from blobs (the path that reaches
	// LoadAll + the quarantine), as it would after a reconcile mismatch.
	if err := os.WriteFile(filepath.Join(dir, "index.enc"), []byte("garbage-index"), 0o600); err != nil {
		t.Fatal(err)
	}

	// First unlock recovers, drops + quarantines the corrupt audit.
	s2 := NewPersistent(mustReopen(t, dir))
	if err := s2.Unlock("quarantine-passphrase"); err != nil {
		t.Fatalf("unlock with one corrupt blob should recover, not brick: %v", err)
	}
	if len(s2.List()) != 2 {
		t.Fatalf("corrupt audit should be dropped: List=%d, want 2", len(s2.List()))
	}
	if _, err := os.Stat(blob + ".corrupt"); err != nil {
		t.Fatalf("corrupt blob should be quarantined to .corrupt: %v", err)
	}
	if _, err := os.Stat(blob); !os.IsNotExist(err) {
		t.Fatal("original .enc should be gone after quarantine")
	}

	// Second unlock must converge (index 2 == .enc count 2), no rebuild loop.
	s3 := NewPersistent(mustReopen(t, dir))
	if err := s3.Unlock("quarantine-passphrase"); err != nil {
		t.Fatal(err)
	}
	if len(s3.List()) != 2 {
		t.Fatalf("second unlock List=%d, want 2", len(s3.List()))
	}
}

func TestCorruptIndexRecovers(t *testing.T) {
	dir := t.TempDir()
	v, _ := vault.Open(dir)
	s := NewPersistent(v)
	if err := s.Initialize("a-strong-passphrase"); err != nil {
		t.Fatal(err)
	}
	m, _ := s.CreateAudit("Eng", "")
	if err := s.Replace(m.ID, sample()); err != nil {
		t.Fatal(err)
	}
	// Corrupt the index file; the audit blob stays intact.
	if err := os.WriteFile(filepath.Join(dir, "index.enc"), []byte("garbage-not-gcm"), 0o600); err != nil {
		t.Fatal(err)
	}
	s2 := NewPersistent(mustReopen(t, dir))
	if err := s2.Unlock("a-strong-passphrase"); err != nil {
		t.Fatalf("unlock should recover from a corrupt index, not brick: %v", err)
	}
	if len(s2.List()) != 1 {
		t.Fatalf("rebuilt index should list the audit, got %d", len(s2.List()))
	}
	if sum, err := s2.Summary(m.ID); err != nil || sum.TotalAccounts != 2 {
		t.Fatalf("data must be intact after rebuild: %v %+v", err, sum)
	}
}

func TestLazyLoadAndEviction(t *testing.T) {
	dir := t.TempDir()
	v, _ := vault.Open(dir)
	s := NewPersistent(v)
	s.cap = 2 // tiny cache to force eviction
	if err := s.Initialize("a-strong-passphrase"); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for i := 0; i < 5; i++ {
		m, err := s.CreateAudit(fmt.Sprintf("Audit %d", i), "")
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Replace(m.ID, model.Dataset{Accounts: []model.Account{{Username: fmt.Sprintf("u%d", i), Domain: "D", Cracked: true}}}); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, m.ID)
	}
	// cache is bounded; index holds all
	s.mu.Lock()
	cached, indexed := len(s.cache), len(s.index)
	s.mu.Unlock()
	if cached > s.cap {
		t.Fatalf("cache should be bounded to %d, got %d", s.cap, cached)
	}
	if indexed != 5 {
		t.Fatalf("index should hold all 5, got %d", indexed)
	}
	// every audit is still readable (evicted ones lazily re-decrypt)
	for i, id := range ids {
		accts, err := s.Accounts(id, true)
		if err != nil || len(accts) != 1 || accts[0].Username != fmt.Sprintf("u%d", i) {
			t.Fatalf("audit %d not readable after eviction: %v %+v", i, err, accts)
		}
	}
	// reopen: the persisted index means List works WITHOUT a full migration
	s2 := NewPersistent(mustReopen(t, dir))
	if err := s2.Unlock("a-strong-passphrase"); err != nil {
		t.Fatal(err)
	}
	if len(s2.List()) != 5 {
		t.Fatalf("reopened List = %d, want 5", len(s2.List()))
	}
	if accts, err := s2.Accounts(ids[2], true); err != nil || accts[0].Username != "u2" {
		t.Fatalf("reopen lazy read: %v %+v", err, accts)
	}
}

func sample() model.Dataset {
	return model.Dataset{Accounts: []model.Account{
		{Username: "alice", Domain: "CORP", Password: "Welcome1", Cracked: true,
			RiskLevel: "Critical", HIBPBreached: true, DADomains: "CORP"},
		{Username: "bob", Domain: "CORP", Cracked: false, RiskLevel: "Low", DADomains: "None"},
	}}
}

// seed creates an audit and loads the sample dataset into it, returning its id.
func seed(t *testing.T, s *Store) string {
	t.Helper()
	m, err := s.CreateAudit("test", "")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := s.Replace(m.ID, sample()); err != nil {
		t.Fatalf("seed: %v", err)
	}
	return m.ID
}

func TestAccountsRedactedByDefault(t *testing.T) {
	s := New()
	id := seed(t, s)
	accts, _ := s.Accounts(id, false)
	for _, a := range accts {
		if a.Password != "" {
			t.Fatalf("redacted account leaked a password: %q", a.Password)
		}
	}
}

func TestAccountsWithSecrets(t *testing.T) {
	s := New()
	id := seed(t, s)
	accts, _ := s.Accounts(id, true)
	if accts[0].Password != "Welcome1" {
		t.Fatalf("includeSecrets should keep password, got %q", accts[0].Password)
	}
}

func TestRedactedReadDoesNotMutateStore(t *testing.T) {
	s := New()
	id := seed(t, s)
	_, _ = s.Accounts(id, false) // a redacted read must not zero the stored value
	accts, _ := s.Accounts(id, true)
	if accts[0].Password != "Welcome1" {
		t.Fatalf("redacted read mutated stored password: %q", accts[0].Password)
	}
}

func TestSummary(t *testing.T) {
	s := New()
	id := seed(t, s)
	sum, err := s.Summary(id)
	if err != nil {
		t.Fatal(err)
	}
	if sum.TotalAccounts != 2 || sum.Cracked != 1 || sum.HIBPBreached != 1 || sum.DAPathways != 1 {
		t.Fatalf("unexpected summary: %+v", sum)
	}
	if sum.RiskCounts["Critical"] != 1 || sum.RiskCounts["Low"] != 1 {
		t.Fatalf("unexpected risk counts: %+v", sum.RiskCounts)
	}
}

func TestAuditsIsolatedAndListed(t *testing.T) {
	s := New()
	a, _ := s.CreateAudit("Engagement A", "client A")
	b, _ := s.CreateAudit("Engagement B", "")
	if err := s.Replace(a.ID, sample()); err != nil {
		t.Fatal(err)
	}
	// b stays empty; a has 2 accounts -- isolation
	sa, _ := s.Summary(a.ID)
	sb, _ := s.Summary(b.ID)
	if sa.TotalAccounts != 2 || sb.TotalAccounts != 0 {
		t.Fatalf("audits not isolated: a=%d b=%d", sa.TotalAccounts, sb.TotalAccounts)
	}
	if len(s.List()) != 2 {
		t.Fatalf("List should return 2 audits, got %d", len(s.List()))
	}
	// delete + missing-id errors
	if err := s.Delete(b.ID); err != nil || s.Has(b.ID) {
		t.Fatalf("delete failed: %v", err)
	}
	if err := s.Delete(b.ID); err != ErrNotFound {
		t.Fatalf("deleting a missing audit should be ErrNotFound, got %v", err)
	}
	if _, err := s.Summary(b.ID); err != ErrNotFound {
		t.Fatalf("deleted audit should be ErrNotFound, got %v", err)
	}
}

func TestPersistentRoundTrip(t *testing.T) {
	dir := t.TempDir()
	v, _ := vault.Open(dir)
	s := NewPersistent(v)
	if s.Unlocked() {
		t.Fatal("persistent store should start locked")
	}
	if err := s.Initialize("a-strong-passphrase"); err != nil { // first run, unlocks
		t.Fatalf("initialize: %v", err)
	}
	m, err := s.CreateAudit("Engagement", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Replace(m.ID, sample()); err != nil {
		t.Fatal(err)
	}

	// Reopen from disk: locked until the correct passphrase, then data is back.
	s2 := NewPersistent(mustReopen(t, dir))
	if s2.Unlocked() {
		t.Fatal("reopened store should be locked")
	}
	if err := s2.Unlock("wrong"); err == nil {
		t.Fatal("wrong passphrase should fail")
	}
	if err := s2.Unlock("a-strong-passphrase"); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	sum, err := s2.Summary(m.ID)
	if err != nil || sum.TotalAccounts != 2 {
		t.Fatalf("data not persisted across reopen: %v %+v", err, sum)
	}
}

func mustReopen(t *testing.T, dir string) *vault.Vault {
	t.Helper()
	v, err := vault.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestReplaceDomainScoped(t *testing.T) {
	s := New()
	idm, _ := s.CreateAudit("x", "")
	id := idm.ID
	_ = s.Replace(id, sample()) // CORP: alice, bob
	// upsert CORP -> replaces both CORP accounts with one
	if err := s.ReplaceDomain(id, "CORP", []model.Account{{Username: "carol", Domain: "CORP", Cracked: true, RiskLevel: "High"}}); err != nil {
		t.Fatal(err)
	}
	accts, _ := s.Accounts(id, false)
	if len(accts) != 1 || accts[0].Username != "carol" {
		t.Fatalf("ReplaceDomain did not replace CORP set: %+v", accts)
	}
	if err := s.ReplaceDomain("nope", "CORP", nil); err != ErrNotFound {
		t.Fatalf("ReplaceDomain on missing audit should error, got %v", err)
	}
}
