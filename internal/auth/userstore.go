package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/watson0x90/PasswordAtTheDisco/internal/fsutil"
)

// minOperatorPassword is the floor for an operator's login password. (The store
// passphrase, which is offline-attackable, has a higher floor of its own.)
const minOperatorPassword = 8

var (
	// ErrUserExists is returned when creating a duplicate username.
	ErrUserExists = errors.New("an operator with that username already exists")
	// ErrUserNotFound is returned when the target operator does not exist.
	ErrUserNotFound = errors.New("no such operator")
	// ErrLastLead guards against locking everyone out: at least one enabled lead
	// must always remain.
	ErrLastLead = errors.New("that would leave no enabled lead -- promote or enable another lead first")
	// ErrWeakPassword is returned when a password is below the minimum length.
	ErrWeakPassword = fmt.Errorf("password must be at least %d characters", minOperatorPassword)
)

// UserStore is a thread-safe, JSON-backed operator store. Mutations persist
// atomically and update the in-memory set, so changes take effect live -- no
// restart needed to add/disable/remove an operator.
type UserStore struct {
	mu    sync.RWMutex
	path  string // persisted JSON file; "" means in-memory only (tests)
	users Users
}

// OpenUserStore loads operators from a JSON file.
func OpenUserStore(path string) (*UserStore, error) {
	users, err := LoadUsers(path)
	if err != nil {
		return nil, err
	}
	return &UserStore{path: path, users: users}, nil
}

// NewUserStore builds a store from an in-memory set. If path is non-empty,
// mutations persist there; if empty, the store is memory-only (used in tests).
func NewUserStore(path string, users Users) *UserStore {
	if users == nil {
		users = Users{}
	}
	return &UserStore{path: path, users: users}
}

// Authenticate verifies credentials live against the current set.
func (s *UserStore) Authenticate(username, password string) (User, bool) {
	s.mu.RLock()
	user, ok := s.users[username]
	s.mu.RUnlock()
	if !ok || user.Disabled {
		VerifyPassword(password, dummyHash) // equalize timing
		return User{}, false
	}
	if !VerifyPassword(password, user.PasswordHash) {
		return User{}, false
	}
	return user, true
}

// Count returns the number of configured operators.
func (s *UserStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.users)
}

// Info is a redacted operator view (no password hash) for the admin UI.
type Info struct {
	Username string `json:"username"`
	Role     Role   `json:"role"`
	Disabled bool   `json:"disabled"`
}

// List returns all operators sorted by username, without password hashes.
func (s *UserStore) List() []Info {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Info, 0, len(s.users))
	for _, u := range s.users {
		out = append(out, Info{Username: u.Username, Role: u.Role, Disabled: u.Disabled})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out
}

// Create adds a new operator. Errors on a duplicate username, invalid role, or a
// too-short password.
func (s *UserStore) Create(username, password string, role Role) error {
	username = strings.TrimSpace(username)
	if username == "" {
		return errors.New("username is required")
	}
	if !validRole(role) {
		return fmt.Errorf("invalid role %q", role)
	}
	if len(password) < minOperatorPassword {
		return ErrWeakPassword
	}
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.users[username]; exists {
		return ErrUserExists
	}
	s.users[username] = User{Username: username, PasswordHash: hash, Role: role}
	return s.persistLocked()
}

// SetRole changes an operator's role, refusing to demote the last enabled lead.
func (s *UserStore) SetRole(username string, role Role) error {
	if !validRole(role) {
		return fmt.Errorf("invalid role %q", role)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[username]
	if !ok {
		return ErrUserNotFound
	}
	if role != RoleLead && s.isOnlyEnabledLeadLocked(username) {
		return ErrLastLead
	}
	u.Role = role
	s.users[username] = u
	return s.persistLocked()
}

// SetPassword resets an operator's login password.
func (s *UserStore) SetPassword(username, password string) error {
	if len(password) < minOperatorPassword {
		return ErrWeakPassword
	}
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[username]
	if !ok {
		return ErrUserNotFound
	}
	u.PasswordHash = hash
	s.users[username] = u
	return s.persistLocked()
}

// SetDisabled enables/disables an operator, refusing to disable the last enabled lead.
func (s *UserStore) SetDisabled(username string, disabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[username]
	if !ok {
		return ErrUserNotFound
	}
	if disabled && s.isOnlyEnabledLeadLocked(username) {
		return ErrLastLead
	}
	u.Disabled = disabled
	s.users[username] = u
	return s.persistLocked()
}

// Delete removes an operator, refusing to remove the last enabled lead.
func (s *UserStore) Delete(username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[username]; !ok {
		return ErrUserNotFound
	}
	if s.isOnlyEnabledLeadLocked(username) {
		return ErrLastLead
	}
	delete(s.users, username)
	return s.persistLocked()
}

// isOnlyEnabledLeadLocked reports whether username is the single remaining enabled
// lead. Caller must hold the lock.
func (s *UserStore) isOnlyEnabledLeadLocked(username string) bool {
	u, ok := s.users[username]
	if !ok || u.Role != RoleLead || u.Disabled {
		return false
	}
	n := 0
	for _, x := range s.users {
		if x.Role == RoleLead && !x.Disabled {
			n++
		}
	}
	return n == 1
}

// persistLocked writes the set to disk atomically. Caller must hold the lock.
func (s *UserStore) persistLocked() error {
	if s.path == "" {
		return nil
	}
	list := make([]User, 0, len(s.users))
	for _, u := range s.users {
		list = append(list, u)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Username < list[j].Username })
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(s.path, b, 0o600)
}
