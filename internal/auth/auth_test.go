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
	s := NewSessionStore(time.Hour, time.Hour)
	id, csrf, err := s.Create(User{Username: "alice", Role: RoleLead})
	if err != nil {
		t.Fatal(err)
	}
	if csrf == "" {
		t.Fatal("session created without a CSRF token")
	}
	if sess, ok := s.Get(id); !ok || sess.Username != "alice" || sess.Role != RoleLead || sess.CSRF != csrf {
		t.Fatalf("session not retrievable: %v %+v", ok, sess)
	}
	s.Delete(id)
	if _, ok := s.Get(id); ok {
		t.Fatal("deleted session still valid")
	}
}

func TestSessionIDsAndCSRFAreUnique(t *testing.T) {
	s := NewSessionStore(time.Hour, time.Hour)
	id1, c1, _ := s.Create(User{Username: "a"})
	id2, c2, _ := s.Create(User{Username: "a"})
	if id1 == id2 || id1 == "" || c1 == c2 || c1 == "" {
		t.Fatalf("ids/csrf not unique: ids %q/%q csrf %q/%q", id1, id2, c1, c2)
	}
}

func TestSessionIdleAndAbsoluteExpiry(t *testing.T) {
	now := time.Unix(0, 0)
	s := NewSessionStore(30*time.Minute, 2*time.Hour)
	s.now = func() time.Time { return now }

	id, _, _ := s.Create(User{Username: "alice", Role: RoleAnalyst})
	// Activity within the idle window slides the session forward.
	for i := 0; i < 3; i++ {
		now = now.Add(20 * time.Minute) // < 30m idle
		if _, ok := s.Get(id); !ok {
			t.Fatalf("session expired prematurely at step %d", i)
		}
	}
	// Idle past the timeout -> expires.
	now = now.Add(31 * time.Minute)
	if _, ok := s.Get(id); ok {
		t.Fatal("session survived past idle timeout")
	}

	// Absolute cap fires even with continuous activity.
	now = time.Unix(0, 0)
	id2, _, _ := s.Create(User{Username: "bob"})
	for i := 0; i < 10; i++ {
		now = now.Add(15 * time.Minute)
		s.Get(id2)
	}
	if _, ok := s.Get(id2); ok { // t = 150m > 2h absolute
		t.Fatal("session survived past absolute lifetime")
	}
}
