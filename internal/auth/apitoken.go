package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/watson0x90/PasswordAtTheDisco/internal/fsutil"
)

// tokenPrefix self-identifies an MCP API token (secret-scanner friendly; cheap reject).
const tokenPrefix = "patdmcp_"

// b32 is lowercase, unpadded base32: charset [a-z2-7], so a token never contains '_'
// and splits cleanly on '_'. The id/secret are opaque strings (the secret is hashed
// as-is, the id is a lookup key) — never base32-decoded — so lowercasing is free.
var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func randBase32(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return strings.ToLower(b32.EncodeToString(b)), nil
}

// newToken returns (id, secret, fullToken). id is 10 random bytes, secret is 32
// (~256-bit). fullToken is the only place the secret appears in clear.
func newToken() (id, secret, full string, err error) {
	if id, err = randBase32(10); err != nil {
		return "", "", "", err
	}
	if secret, err = randBase32(32); err != nil {
		return "", "", "", err
	}
	return id, secret, tokenPrefix + id + "_" + secret, nil
}

// parseToken splits "patdmcp_<id>_<secret>" into its parts.
func parseToken(s string) (id, secret string, ok bool) {
	rest, found := strings.CutPrefix(s, tokenPrefix)
	if !found {
		return "", "", false
	}
	id, secret, found = strings.Cut(rest, "_")
	if !found || id == "" || secret == "" {
		return "", "", false
	}
	return id, secret, true
}

// hashSecret is sha256(secret) as hex. SHA-256 (not argon2) is correct here: the
// secret is 256-bit random, so a fast hash is safe and avoids per-request argon2 cost.
func hashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// verifySecret reports whether secret hashes to storedHash, using a constant-time
// comparison to avoid a timing oracle on the hash bytes. This is the single point
// where a presented secret is checked against a stored hash.
func verifySecret(secret, storedHash string) bool {
	return subtle.ConstantTimeCompare([]byte(hashSecret(secret)), []byte(storedHash)) == 1
}

// APIToken is one stored credential. The secret itself is never stored.
type APIToken struct {
	ID         string     `json:"id"`
	SecretHash string     `json:"secret_hash"`
	Role       Role       `json:"role"`
	Label      string     `json:"label"`
	Created    time.Time  `json:"created"`
	Expires    *time.Time `json:"expires,omitempty"`
	Disabled   bool       `json:"disabled,omitempty"`
	LastUsed   *time.Time `json:"last_used,omitempty"`
}

// dummyTokenHash equalises Verify timing on unknown-id / malformed paths, mirroring
// the dummyHash trick in users.go. It is a var (not const) because hashSecret computes
// its value at runtime.
var dummyTokenHash = hashSecret("not-a-real-token-secret-0000000000")

// TokenInfo is a redacted token view (no secret hash) for the admin UI / CLI list.
type TokenInfo struct {
	ID       string     `json:"id"`
	Role     Role       `json:"role"`
	Label    string     `json:"label"`
	Created  time.Time  `json:"created"`
	Expires  *time.Time `json:"expires,omitempty"`
	Disabled bool       `json:"disabled"`
	LastUsed *time.Time `json:"last_used,omitempty"`
}

// TokenStore is a thread-safe, JSON-backed API-token store. Mirrors UserStore:
// mutations persist atomically and take effect live.
type TokenStore struct {
	mu        sync.RWMutex
	path      string
	tokens    map[string]APIToken  // keyed by id
	lastFlush map[string]time.Time // throttles last_used persistence
}

// LoadTokens reads a JSON array of APIToken from path.
func LoadTokens(path string) (map[string]APIToken, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var list []APIToken
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("parse mcp tokens: %w", err)
	}
	m := make(map[string]APIToken, len(list))
	for _, tk := range list {
		if tk.ID == "" || tk.SecretHash == "" || !validRole(tk.Role) {
			return nil, fmt.Errorf("token entry %q is malformed", tk.ID)
		}
		m[tk.ID] = tk
	}
	return m, nil
}

// OpenTokenStore loads tokens from a JSON file.
func OpenTokenStore(path string) (*TokenStore, error) {
	m, err := LoadTokens(path)
	if err != nil {
		return nil, err
	}
	return &TokenStore{path: path, tokens: m, lastFlush: map[string]time.Time{}}, nil
}

// NewTokenStore builds a store from an in-memory map. Empty path = memory-only (tests).
func NewTokenStore(path string, tokens map[string]APIToken) *TokenStore {
	if tokens == nil {
		tokens = map[string]APIToken{}
	}
	return &TokenStore{path: path, tokens: tokens, lastFlush: map[string]time.Time{}}
}

// Issue mints a token, persists it, and returns the full token string ONCE.
func (s *TokenStore) Issue(role Role, label string, expires *time.Time) (string, APIToken, error) {
	label = strings.TrimSpace(label)
	if label == "" {
		return "", APIToken{}, errors.New("label is required")
	}
	if !validRole(role) {
		return "", APIToken{}, fmt.Errorf("invalid role %q", role)
	}
	id, secret, full, err := newToken()
	if err != nil {
		return "", APIToken{}, err
	}
	rec := APIToken{ID: id, SecretHash: hashSecret(secret), Role: role, Label: label, Created: time.Now().UTC(), Expires: expires}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.tokens[id]; exists {
		return "", APIToken{}, errors.New("token id collision; retry")
	}
	s.tokens[id] = rec
	if err := s.persistLocked(); err != nil {
		delete(s.tokens, id)
		return "", APIToken{}, err
	}
	return full, rec, nil
}

// Verify authenticates a full token string. Constant-time on every path (incl. a
// dummy compare on unknown id / malformed input) to blunt timing enumeration.
func (s *TokenStore) Verify(full string) (APIToken, bool) {
	id, secret, ok := parseToken(full)
	if !ok {
		_ = verifySecret("invalid", dummyTokenHash) // equalize timing on malformed input
		return APIToken{}, false
	}
	s.mu.RLock()
	rec, found := s.tokens[id]
	s.mu.RUnlock()
	want := dummyTokenHash
	if found {
		want = rec.SecretHash
	}
	match := verifySecret(secret, want)
	if !found || !match || rec.Disabled || (rec.Expires != nil && rec.Expires.Before(time.Now())) {
		return APIToken{}, false
	}
	return s.touchLastUsed(id), true
}

// List returns redacted token views sorted by Created (newest first).
func (s *TokenStore) List() []TokenInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]TokenInfo, 0, len(s.tokens))
	for _, tk := range s.tokens {
		out = append(out, TokenInfo{ID: tk.ID, Role: tk.Role, Label: tk.Label, Created: tk.Created, Expires: tk.Expires, Disabled: tk.Disabled, LastUsed: tk.LastUsed})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.After(out[j].Created) })
	return out
}

// Revoke removes a token. Returns false if the id is unknown.
func (s *TokenStore) Revoke(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.tokens[id]; !ok {
		return false
	}
	delete(s.tokens, id)
	delete(s.lastFlush, id)
	_ = s.persistLocked()
	return true
}

// touchLastUsed updates last_used in memory, persists it at most once/min/token, and
// returns the updated record (so Verify's returned APIToken reflects the new LastUsed).
func (s *TokenStore) touchLastUsed(id string) APIToken {
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.tokens[id]
	if !ok {
		return APIToken{}
	}
	rec.LastUsed = &now
	s.tokens[id] = rec
	if last := s.lastFlush[id]; last.IsZero() || now.Sub(last) >= time.Minute {
		s.lastFlush[id] = now
		// Persist under the lock: low frequency (<=1/min/token) makes this acceptable.
		// If token volume grows, decouple persist to a background goroutine.
		_ = s.persistLocked() // best-effort; last_used is non-critical
	}
	return rec
}

// persistLocked writes the token set atomically. Caller must hold the write lock.
func (s *TokenStore) persistLocked() error {
	if s.path == "" {
		return nil
	}
	list := make([]APIToken, 0, len(s.tokens))
	for _, tk := range s.tokens {
		list = append(list, tk)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Created.Before(list[j].Created) })
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(s.path, b, 0o600)
}

// setDisabledForTest is a test seam (no production caller).
func (s *TokenStore) setDisabledForTest(id string, disabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rec, ok := s.tokens[id]; ok {
		rec.Disabled = disabled
		s.tokens[id] = rec
	}
}
