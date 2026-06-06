package auth

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// Session is a server-side authenticated session (revocable; lost on restart).
type Session struct {
	Username string
	Role     Role
	Expires  time.Time
}

// SessionStore is an in-memory, thread-safe session store.
type SessionStore struct {
	mu       sync.Mutex
	sessions map[string]Session
	ttl      time.Duration
}

// NewSessionStore returns a store whose sessions expire after ttl.
func NewSessionStore(ttl time.Duration) *SessionStore {
	return &SessionStore{sessions: make(map[string]Session), ttl: ttl}
}

// Create starts a session for u and returns an opaque, random session ID.
func (s *SessionStore) Create(u User) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	id := base64.RawURLEncoding.EncodeToString(b)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[id] = Session{Username: u.Username, Role: u.Role, Expires: time.Now().Add(s.ttl)}
	return id, nil
}

// Get returns the session for id if it exists and has not expired.
func (s *SessionStore) Get(id string) (Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return Session{}, false
	}
	if time.Now().After(sess.Expires) {
		delete(s.sessions, id)
		return Session{}, false
	}
	return sess, true
}

// Delete revokes a session (logout).
func (s *SessionStore) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
}
