package main

import (
	"net"
	"path/filepath"
	"testing"

	"github.com/watson0x90/PasswordAtTheDisco/internal/auth"
)

func tempUsersFile(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "users.json")
}

func TestAddUser_CreatesOperator(t *testing.T) {
	f := tempUsersFile(t)
	if err := addUser(f, "alice", "longpassword", "lead"); err != nil {
		t.Fatalf("addUser: %v", err)
	}
	st, err := auth.OpenUserStore(f)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if _, ok := st.Authenticate("alice", "longpassword"); !ok {
		t.Fatal("alice cannot authenticate with the set password")
	}
	got := st.List()
	if len(got) != 1 || got[0].Username != "alice" || got[0].Role != auth.RoleLead {
		t.Fatalf("List = %+v, want one alice/lead", got)
	}
}

func TestAddUser_DuplicateAndWeak(t *testing.T) {
	f := tempUsersFile(t)
	if err := addUser(f, "ana", "longpassword", "analyst"); err != nil {
		t.Fatalf("first add: %v", err)
	}
	if err := addUser(f, "ana", "longpassword", "analyst"); err != auth.ErrUserExists {
		t.Fatalf("duplicate = %v, want ErrUserExists", err)
	}
	if err := addUser(f, "bob", "short", "analyst"); err != auth.ErrWeakPassword {
		t.Fatalf("weak = %v, want ErrWeakPassword", err)
	}
	if err := addUser(f, "bad", "longpassword", "wizard"); err == nil {
		t.Fatal("invalid role: want error, got nil")
	}
}

func TestSetUserPassword(t *testing.T) {
	f := tempUsersFile(t)
	if err := addUser(f, "alice", "oldpassword", "lead"); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := setUserPassword(f, "alice", "newpassword"); err != nil {
		t.Fatalf("setUserPassword: %v", err)
	}
	st, err := auth.OpenUserStore(f)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if _, ok := st.Authenticate("alice", "newpassword"); !ok {
		t.Fatal("new password does not authenticate")
	}
	if _, ok := st.Authenticate("alice", "oldpassword"); ok {
		t.Fatal("old password still authenticates")
	}
	if err := setUserPassword(f, "ghost", "longpassword"); err != auth.ErrUserNotFound {
		t.Fatalf("unknown user = %v, want ErrUserNotFound", err)
	}
}

func TestListUsers(t *testing.T) {
	f := tempUsersFile(t)
	_ = addUser(f, "alice", "longpassword", "lead")
	_ = addUser(f, "bob", "longpassword", "analyst")
	got, err := listUsers(f)
	if err != nil {
		t.Fatalf("listUsers: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("listUsers len = %d, want 2", len(got))
	}
	if got[0].Username != "alice" || got[0].Role != auth.RoleLead {
		t.Errorf("got[0] = %+v, want alice/lead", got[0])
	}
	if got[1].Username != "bob" || got[1].Role != auth.RoleAnalyst {
		t.Errorf("got[1] = %+v, want bob/analyst", got[1])
	}
}

func TestServerIsRunning(t *testing.T) {
	if serverIsRunning("127.0.0.1:1") {
		t.Error("127.0.0.1:1 should not be reachable")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	if !serverIsRunning(ln.Addr().String()) {
		t.Errorf("live listener %s should be detected", ln.Addr())
	}
}

func TestSplitUserArgs(t *testing.T) {
	// username first, then flags (the documented form)
	u, f, ok := splitUserArgs([]string{"alice", "--role", "lead"})
	if !ok || u != "alice" || len(f) != 2 || f[0] != "--role" || f[1] != "lead" {
		t.Fatalf("got (%q, %v, %v), want (alice, [--role lead], true)", u, f, ok)
	}
	// username with no flags
	u, f, ok = splitUserArgs([]string{"bob"})
	if !ok || u != "bob" || len(f) != 0 {
		t.Fatalf("got (%q, %v, %v), want (bob, [], true)", u, f, ok)
	}
	// no args, or a flag where the username should be -> not ok
	if _, _, ok := splitUserArgs(nil); ok {
		t.Error("empty args should not be ok")
	}
	if _, _, ok := splitUserArgs([]string{"--role", "lead"}); ok {
		t.Error("flag-first (no username) should not be ok")
	}
}
