package auth

import (
	"testing"
	"time"
)

func TestArgon2RoundTrip(t *testing.T) {
	h, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword("correct horse battery staple", h) {
		t.Fatal("correct password failed to verify")
	}
	if VerifyPassword("wrong password", h) {
		t.Fatal("wrong password verified")
	}
}

func TestVerifyRejectsGarbage(t *testing.T) {
	for _, bad := range []string{"", "not-phc", "$argon2id$bad", "$bcrypt$v=19$..."} {
		if VerifyPassword("x", bad) {
			t.Fatalf("garbage hash %q verified", bad)
		}
	}
}

func TestAuthenticate(t *testing.T) {
	hash, _ := HashPassword("s3cret")
	users := Users{"alice": {Username: "alice", PasswordHash: hash, Role: RoleLead}}

	if u, ok := users.Authenticate("alice", "s3cret"); !ok || u.Role != RoleLead {
		t.Fatalf("valid login failed: %v %+v", ok, u)
	}
	if _, ok := users.Authenticate("alice", "wrong"); ok {
		t.Fatal("wrong password authenticated")
	}
	if _, ok := users.Authenticate("nobody", "s3cret"); ok {
		t.Fatal("unknown user authenticated")
	}
}

func TestSessionLifecycle(t *testing.T) {
	s := NewSessionStore(time.Hour)
	id, err := s.Create(User{Username: "alice", Role: RoleLead})
	if err != nil {
		t.Fatal(err)
	}
	if sess, ok := s.Get(id); !ok || sess.Username != "alice" || sess.Role != RoleLead {
		t.Fatalf("session not retrievable: %v %+v", ok, sess)
	}
	s.Delete(id)
	if _, ok := s.Get(id); ok {
		t.Fatal("deleted session still valid")
	}
}

func TestSessionExpiry(t *testing.T) {
	s := NewSessionStore(-time.Second) // already expired
	id, _ := s.Create(User{Username: "bob", Role: RoleAnalyst})
	if _, ok := s.Get(id); ok {
		t.Fatal("expired session returned as valid")
	}
}

func TestSessionIDsAreUnique(t *testing.T) {
	s := NewSessionStore(time.Hour)
	id1, _ := s.Create(User{Username: "a"})
	id2, _ := s.Create(User{Username: "a"})
	if id1 == id2 || id1 == "" {
		t.Fatalf("session IDs not unique/random: %q %q", id1, id2)
	}
}
