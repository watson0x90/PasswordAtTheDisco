package vault

import (
	"os"
	"path/filepath"
	"testing"
)

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
