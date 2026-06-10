package vault

import (
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A corrupt wrapped_prev_dek (interrupted-rekey marker that won't unwrap) must be
// surfaced, not swallowed into a confusing per-blob "cannot decrypt" error.
// Unlock must FAIL (not silently unlock with prevDEK=nil) when an interrupted
// rekey left a corrupt wrapped_prev_dek -- otherwise a later rebuild would
// quarantine the still-recoverable prev-sealed blobs as "corrupt".
func TestUnlockRejectsCorruptPrevDEK(t *testing.T) {
	dir := t.TempDir()
	v, _ := Open(dir)
	if err := v.Initialize("unlock-prevdek-pass"); err != nil {
		t.Fatal(err)
	}
	_ = v.SaveAudit("a", []byte("data"))
	// Forge an interrupted-rekey keyfile with a garbage wrapped_prev_dek, then lock.
	v.mu.Lock()
	kf, _ := v.readKeyfile()
	kf.WrappedPrevDEK = b64([]byte("garbage-not-a-wrapped-dek"))
	b, _ := json.MarshalIndent(kf, "", "  ")
	_ = writeFileAtomic(v.keyfilePath(), b)
	v.mu.Unlock()
	v.Lock()

	v2, _ := Open(dir)
	err := v2.Unlock("unlock-prevdek-pass")
	if err == nil || !strings.Contains(err.Error(), "previous DEK") {
		t.Fatalf("unlock with corrupt wrapped_prev_dek must fail loud, got %v", err)
	}
	if v2.Unlocked() {
		t.Fatal("vault must stay locked after a failed prev-DEK unwrap (no half-unlocked state)")
	}
	// the blob is NOT quarantined (still .enc), so it remains recoverable
	if _, err := os.Stat(filepath.Join(dir, auditsSubdir, "a.enc")); err != nil {
		t.Fatalf("blob should remain (not quarantined) after a failed unlock: %v", err)
	}
}

func TestRekeyRejectsCorruptPrevDEK(t *testing.T) {
	dir := t.TempDir()
	v, _ := Open(dir)
	if err := v.Initialize("prevdek-passphrase"); err != nil {
		t.Fatal(err)
	}
	_ = v.SaveAudit("a", []byte("data"))
	// Forge a mid-rekey keyfile whose wrapped_prev_dek is garbage (valid b64, but
	// not a real wrapped key).
	v.mu.Lock()
	kf, _ := v.readKeyfile()
	kf.WrappedPrevDEK = b64([]byte("not-a-valid-wrapped-dek"))
	b, _ := json.MarshalIndent(kf, "", "  ")
	_ = writeFileAtomic(v.keyfilePath(), b)
	v.mu.Unlock()

	err := v.Rekey("prevdek-passphrase")
	if err == nil || !strings.Contains(err.Error(), "previous DEK") {
		t.Fatalf("rekey with corrupt wrapped_prev_dek should surface the error, got %v", err)
	}
}

func TestInitializeUnlockRoundTrip(t *testing.T) {
	dir := t.TempDir()
	v, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if v.Initialized() {
		t.Fatal("fresh vault should not be initialized")
	}
	if err := v.Initialize("correct horse battery staple"); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if !v.Initialized() || !v.Unlocked() {
		t.Fatal("after Initialize, vault should be initialized + unlocked")
	}

	// store + read back an audit
	if err := v.SaveAudit("abc123", []byte(`{"secret":"Welcome1"}`)); err != nil {
		t.Fatalf("SaveAudit: %v", err)
	}

	// the on-disk file must NOT contain the cleartext
	raw, _ := os.ReadFile(filepath.Join(dir, auditsSubdir, "abc123.enc"))
	if len(raw) == 0 {
		t.Fatal("audit file not written")
	}
	if string(raw) == `{"secret":"Welcome1"}` || containsSub(raw, "Welcome1") {
		t.Fatalf("CLEARTEXT ON DISK: %q", raw)
	}

	// lock, then a fresh handle must require the passphrase
	v.Lock()
	if v.Unlocked() {
		t.Fatal("Lock did not lock")
	}

	v2, _ := Open(dir)
	if err := v2.Unlock("wrong passphrase"); err != ErrBadPassphrase {
		t.Fatalf("wrong passphrase should be ErrBadPassphrase, got %v", err)
	}
	if v2.Unlocked() {
		t.Fatal("vault unlocked after a wrong passphrase")
	}
	if err := v2.Unlock("correct horse battery staple"); err != nil {
		t.Fatalf("Unlock with correct passphrase: %v", err)
	}
	all, err := v2.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if string(all["abc123"]) != `{"secret":"Welcome1"}` {
		t.Fatalf("round-trip mismatch: %q", all["abc123"])
	}
}

func TestLockedOpsFail(t *testing.T) {
	v, _ := Open(t.TempDir())
	if err := v.Unlock("x"); err != ErrNotInitialized {
		t.Fatalf("unlock before init should be ErrNotInitialized, got %v", err)
	}
	if err := v.SaveAudit("x", []byte("y")); err != ErrLocked {
		t.Fatalf("SaveAudit locked should be ErrLocked, got %v", err)
	}
	if _, err := v.LoadAll(); err != ErrLocked {
		t.Fatalf("LoadAll locked should be ErrLocked, got %v", err)
	}
}

func TestDeleteAudit(t *testing.T) {
	v, _ := Open(t.TempDir())
	_ = v.Initialize("pw")
	_ = v.SaveAudit("gone", []byte("data"))
	if err := v.DeleteAudit("gone"); err != nil {
		t.Fatal(err)
	}
	if err := v.DeleteAudit("gone"); err != nil {
		t.Fatalf("deleting a missing audit should be a no-op, got %v", err)
	}
	all, _ := v.LoadAll()
	if _, ok := all["gone"]; ok {
		t.Fatal("deleted audit still present")
	}
}

func TestChangePassphrase(t *testing.T) {
	dir := t.TempDir()
	v, _ := Open(dir)
	if err := v.Initialize("first-passphrase-xyz"); err != nil {
		t.Fatal(err)
	}
	_ = v.SaveAudit("a1", []byte("data1"))

	if err := v.ChangePassphrase("wrong-old", "second-passphrase-xyz"); err != ErrBadPassphrase {
		t.Fatalf("wrong old passphrase should be ErrBadPassphrase, got %v", err)
	}
	if err := v.ChangePassphrase("first-passphrase-xyz", "second-passphrase-xyz"); err != nil {
		t.Fatalf("ChangePassphrase: %v", err)
	}
	// keyfile.json.bak must NOT survive a rotation -- it still wraps the DEK under
	// the old passphrase, which would defeat the rotation.
	if _, err := os.Stat(filepath.Join(dir, "keyfile.json.bak")); !os.IsNotExist(err) {
		t.Fatal("keyfile.json.bak must be removed after a passphrase change")
	}
	// reopen: old fails, new works, data intact
	v2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := v2.Unlock("first-passphrase-xyz"); err != ErrBadPassphrase {
		t.Fatalf("old passphrase should no longer unlock, got %v", err)
	}
	if err := v2.Unlock("second-passphrase-xyz"); err != nil {
		t.Fatalf("new passphrase should unlock: %v", err)
	}
	all, _ := v2.LoadAll()
	if string(all["a1"]) != "data1" {
		t.Fatal("data lost across passphrase change")
	}
}

func TestRekeyRotatesDataKey(t *testing.T) {
	dir := t.TempDir()
	v, _ := Open(dir)
	if err := v.Initialize("the-current-passphrase"); err != nil {
		t.Fatal(err)
	}
	_ = v.SaveAudit("aud1", []byte("audit-one-plaintext"))
	_ = v.SaveIndex([]byte(`{"aud1":{}}`))

	// capture the old ciphertext so we can prove the key actually changed
	oldCT, _ := os.ReadFile(filepath.Join(dir, auditsSubdir, "aud1.enc"))

	if err := v.Rekey("wrong-passphrase"); err != ErrBadPassphrase {
		t.Fatalf("rekey with wrong passphrase should be ErrBadPassphrase, got %v", err)
	}
	if err := v.Rekey("the-current-passphrase"); err != nil {
		t.Fatalf("Rekey: %v", err)
	}

	// data still readable + intact under the new key
	if got, err := v.LoadOne("aud1"); err != nil || string(got) != "audit-one-plaintext" {
		t.Fatalf("audit unreadable after rekey: %v %q", err, got)
	}
	// ciphertext actually changed (new DEK / nonce)
	newCT, _ := os.ReadFile(filepath.Join(dir, auditsSubdir, "aud1.enc"))
	if string(oldCT) == string(newCT) {
		t.Fatal("ciphertext unchanged after rekey -- key did not rotate")
	}
	// keyfile no longer carries a previous DEK
	if kf, _ := v.readKeyfile(); kf.WrappedPrevDEK != "" {
		t.Fatal("wrapped_prev_dek should be cleared after a completed rekey")
	}
	// lock + reopen + unlock: still works under the same passphrase, new key on disk
	v.Lock()
	v2, _ := Open(dir)
	if err := v2.Unlock("the-current-passphrase"); err != nil {
		t.Fatalf("unlock after rekey: %v", err)
	}
	if got, err := v2.LoadOne("aud1"); err != nil || string(got) != "audit-one-plaintext" {
		t.Fatalf("audit unreadable after rekey+reopen: %v %q", err, got)
	}
}

// TestRekeyResumesAfterInterruption simulates a crash mid-rekey: the keyfile holds
// BOTH keys and blobs are split across the old and new DEK. A re-run must resume,
// re-seal everything under the (new) primary, drop the prev, and keep all data.
func TestRekeyResumesAfterInterruption(t *testing.T) {
	dir := t.TempDir()
	v, _ := Open(dir)
	if err := v.Initialize("pp-resume-test"); err != nil {
		t.Fatal(err)
	}
	// "done" blob already sealed under the (new) primary; "pending" still under old.
	_ = v.SaveAudit("done", []byte("done-plaintext"))
	_ = v.SaveAudit("pending", []byte("pending-plaintext"))

	// Forge a mid-rekey keyfile: primary = a fresh DEK, prev = the current DEK.
	v.mu.Lock()
	oldDEK := append([]byte(nil), v.dek...)
	newDEK := make([]byte, dekLen)
	_, _ = rand.Read(newDEK)
	// re-seal only "done" under the new DEK (as a partial rekey would have)
	doneCT, _ := gcmSeal(newDEK, []byte("done-plaintext"), blobAAD("done"))
	_ = writeFileAtomic(v.auditPath("done"), doneCT)
	if err := v.wrapAndWriteBoth(newDEK, oldDEK, "pp-resume-test"); err != nil {
		v.mu.Unlock()
		t.Fatal(err)
	}
	v.mu.Unlock()

	// Reopen fresh (as on restart) and unlock: prev DEK must load so both read.
	v2, _ := Open(dir)
	if err := v2.Unlock("pp-resume-test"); err != nil {
		t.Fatalf("unlock interrupted-rekey store: %v", err)
	}
	if got, err := v2.LoadOne("pending"); err != nil || string(got) != "pending-plaintext" {
		t.Fatalf("pending blob (old DEK) unreadable mid-rekey: %v %q", err, got)
	}
	// Resume: re-run Rekey; it must finish under the existing primary.
	if err := v2.Rekey("pp-resume-test"); err != nil {
		t.Fatalf("resume rekey: %v", err)
	}
	for id, want := range map[string]string{"done": "done-plaintext", "pending": "pending-plaintext"} {
		if got, err := v2.LoadOne(id); err != nil || string(got) != want {
			t.Fatalf("after resume, %s = %v %q", id, err, got)
		}
	}
	if kf, _ := v2.readKeyfile(); kf.WrappedPrevDEK != "" {
		t.Fatal("wrapped_prev_dek should be cleared after resume completes")
	}
}

func TestCorruptKeyfileRejected(t *testing.T) {
	dir := t.TempDir()
	v, _ := Open(dir)
	if err := v.Initialize("passphrase-aaaa-bbbb"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "keyfile.json"), []byte("{ not valid json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); err == nil {
		t.Fatal("Open should reject a corrupt keyfile instead of treating it as initialized")
	}
}

func containsSub(b []byte, sub string) bool {
	s, n := string(b), len(sub)
	for i := 0; i+n <= len(s); i++ {
		if s[i:i+n] == sub {
			return true
		}
	}
	return false
}
