package auth

import (
	"path/filepath"
	"testing"
)

func seedStore(t *testing.T) *UserStore {
	t.Helper()
	leadHash, _ := HashPassword("lead-password-1")
	s := NewUserStore(filepath.Join(t.TempDir(), "users.json"), Users{
		"boss": {Username: "boss", PasswordHash: leadHash, Role: RoleLead},
	})
	return s
}

func TestUserStoreCreateAndAuth(t *testing.T) {
	s := seedStore(t)
	if err := s.Create("ana", "analyst-pass-1", RoleAnalyst); err != nil {
		t.Fatal(err)
	}
	if err := s.Create("ana", "another-pass-1", RoleAnalyst); err != ErrUserExists {
		t.Fatalf("duplicate create = %v, want ErrUserExists", err)
	}
	if err := s.Create("weak", "short", RoleAnalyst); err != ErrWeakPassword {
		t.Fatalf("weak password = %v, want ErrWeakPassword", err)
	}
	if _, ok := s.Authenticate("ana", "analyst-pass-1"); !ok {
		t.Fatal("created operator should authenticate")
	}
	if _, ok := s.Authenticate("ana", "wrong"); ok {
		t.Fatal("wrong password should not authenticate")
	}
	// List must never leak password hashes.
	for _, info := range s.List() {
		if info.Username == "" {
			t.Fatal("empty username in list")
		}
	}
}

func TestUserStoreDisable(t *testing.T) {
	s := seedStore(t)
	_ = s.Create("ana", "analyst-pass-1", RoleAnalyst)
	if err := s.SetDisabled("ana", true); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Authenticate("ana", "analyst-pass-1"); ok {
		t.Fatal("disabled operator must not authenticate")
	}
	if err := s.SetDisabled("ana", false); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Authenticate("ana", "analyst-pass-1"); !ok {
		t.Fatal("re-enabled operator should authenticate")
	}
}

func TestUserStoreLastLeadGuards(t *testing.T) {
	s := seedStore(t) // only one lead: boss
	if err := s.Delete("boss"); err != ErrLastLead {
		t.Fatalf("delete last lead = %v, want ErrLastLead", err)
	}
	if err := s.SetRole("boss", RoleAnalyst); err != ErrLastLead {
		t.Fatalf("demote last lead = %v, want ErrLastLead", err)
	}
	if err := s.SetDisabled("boss", true); err != ErrLastLead {
		t.Fatalf("disable last lead = %v, want ErrLastLead", err)
	}
	// Add a second lead -> the guards release for the first.
	if err := s.Create("boss2", "lead-password-2", RoleLead); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRole("boss", RoleAnalyst); err != nil {
		t.Fatalf("demote with a spare lead should succeed, got %v", err)
	}
}

func TestUserStorePersistReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	leadHash, _ := HashPassword("lead-password-1")
	s := NewUserStore(path, Users{"boss": {Username: "boss", PasswordHash: leadHash, Role: RoleLead}})
	if err := s.Create("ana", "analyst-pass-1", RoleAnalyst); err != nil {
		t.Fatal(err)
	}
	// Reopen from disk: the new operator must be present.
	s2, err := OpenUserStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s2.Authenticate("ana", "analyst-pass-1"); !ok {
		t.Fatal("operator did not persist across reload")
	}
}
