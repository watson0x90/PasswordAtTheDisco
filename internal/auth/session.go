package auth

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// Session is a server-side authenticated session (revocable; lost on restart).
type Session struct {
	Username    string
	Role        Role
	CSRF        string // per-session CSRF token (synchronizer pattern)
	Created     time.Time
	LastSeen    time.Time
	ActiveAudit string // id of the audit this session is currently viewing
}

// SessionStore is an in-memory, thread-safe session store with sliding idle
// expiry bounded by an absolute lifetime.
type SessionStore struct {
	mu          sync.Mutex
	sessions    map[string]Session
	idleTTL     time.Duration
	absoluteTTL time.Duration
	now         func() time.Time
}

// NewSessionStore returns a store where sessions expire after idleTTL of
// inactivity, or absoluteTTL after creation regardless of activity.
func NewSessionStore(idleTTL, absoluteTTL time.Duration) *SessionStore {
	return &SessionStore{
		sessions:    make(map[string]Session),
		idleTTL:     idleTTL,
		absoluteTTL: absoluteTTL,
		now:         time.Now,
	}
}

func randToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Create starts a session for u, returning the opaque session ID and its CSRF
// token.
func (s *SessionStore) Create(u User) (id, csrf string, err error) {
	if id, err = randToken(32); err != nil {
		return "", "", err
	}
	if csrf, err = randToken(32); err != nil {
		return "", "", err
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[id] = Session{Username: u.Username, Role: u.Role, CSRF: csrf, Created: now, LastSeen: now}
	return id, csrf, nil
}

// Get returns the session for id if it is within both the idle and absolute
// timeouts, refreshing LastSeen (sliding idle expiry).
func (s *SessionStore) Get(id string) (Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return Session{}, false
	}
	now := s.now()
	if now.Sub(sess.Created) >= s.absoluteTTL || now.Sub(sess.LastSeen) >= s.idleTTL {
		delete(s.sessions, id)
		return Session{}, false
	}
	sess.LastSeen = now
	s.sessions[id] = sess
	return sess, true
}

// SetActiveAudit records which audit a session is viewing. Returns false if the
// session no longer exists.
func (s *SessionStore) SetActiveAudit(id, auditID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return false
	}
	sess.ActiveAudit = auditID
	s.sessions[id] = sess
	return true
}

// Delete revokes a session (logout).
func (s *SessionStore) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
}
