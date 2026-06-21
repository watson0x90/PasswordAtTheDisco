# MCP Token / Credential System (sub-project A) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add role-scoped API tokens (`patdmcp_<id>_<secret>`) as a new credential type so external agents can authenticate to patd programmatically, with lead-gated issue/revoke (Admin UI + CLI), audit, and a `GET /api/mcp/whoami` proof endpoint.

**Architecture:** A new `auth.TokenStore` mirrors the existing `auth.UserStore` (thread-safe, JSON-backed, atomic persist, live mutations). A `requireMCPToken` middleware authenticates a bearer token and attaches its role to the request context, exactly like `requireIngestToken` but multi-token and role-bearing. Token management handlers are lead-gated and audited. A `patd token` CLI bootstraps the first token. An Admin UI panel mirrors `Operators.tsx`.

**Tech Stack:** Go stdlib only (`crypto/rand`, `crypto/sha256`, `crypto/subtle`, `encoding/base32`, `net/http`); React + TypeScript + Vite SPA.

**Spec:** `docs/superpowers/specs/2026-06-21-mcp-token-system-design.md`

**Conventions (read before starting):**
- Gates that MUST stay green: `gofmt -l cmd internal` (empty), `go build ./... && go vet ./... && go test ./...`, `govulncheck ./...`; in `web/`: `npx tsc --noEmit`, `npx vitest run`, `npm run build`. **Never** run `npm install` — deps are vetted/pinned; use the committed lockfile only.
- **Do NOT use `git commit --no-verify`.** Use the Grep/Read tools, not `npx rg`.
- Mirror existing patterns: `internal/auth/userstore.go` (store), `internal/httpapi/server.go` (`requireIngestToken` ~line 2304, `requireAuth` ~2259, `requireCSRF` ~2278, `writeJSON` ~2319, `sessionFrom`, `okOr` ~759, `clientIP`, `handleCreateUser` ~1056), `internal/audit/audit.go` (`Event`/`Log`), `internal/auth/ratelimit.go` (`Limiter`), `cmd/patd/main.go` (subcommand dispatch ~line 57, `env` helper, server wiring ~169), `web/src/components/Operators.tsx` (admin panel), `web/src/api.ts` (client).

---

## File Structure

**Create:**
- `internal/auth/apitoken.go` — `APIToken`, `TokenInfo`, token generation/hashing/parse, `TokenStore` (Open/New/Issue/Verify/List/Revoke/touchLastUsed/persist).
- `internal/auth/apitoken_test.go` — token + store unit tests.
- `internal/httpapi/mcp.go` — `requireMCPToken`, `mcpTokenFrom`, and the `whoami` + token-management handlers.
- `internal/httpapi/mcp_test.go` — middleware + handler tests.
- `cmd/patd/token.go` — `runToken` CLI (`create`/`list`/`revoke`).
- `cmd/patd/token_test.go` — CLI tests.
- `mcp_tokens.example.json` — tracked example (empty array).
- `web/src/components/McpTokens.tsx` — Admin Tokens panel.

**Modify:**
- `internal/httpapi/server.go` — add `MCPTokens`/`MCPLimiter` Server fields; register 4 routes; add `mcpTokenKey` ctx const.
- `cmd/patd/main.go` — add `token` subcommand dispatch; load + wire the token store and limiter.
- `.gitignore` — add `mcp_tokens.json`.
- `web/src/api.ts` — `McpToken`/`McpTokenCreated` types + `listMcpTokens`/`createMcpToken`/`revokeMcpToken`.
- `web/src/components/AppShell.tsx` — add a "Tokens" entry to the Admin nav + route to `<McpTokens/>`.

---

## Task 1: Token type, generation, hashing, parsing

**Files:**
- Create: `internal/auth/apitoken.go`
- Test: `internal/auth/apitoken_test.go`

- [ ] **Step 1: Write the failing test**

```go
package auth

import (
	"strings"
	"testing"
)

func TestNewTokenFormatAndParse(t *testing.T) {
	id, secret, full, err := newToken()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(full, "patdmcp_") {
		t.Fatalf("token missing prefix: %q", full)
	}
	if full != "patdmcp_"+id+"_"+secret {
		t.Fatalf("token assembly mismatch: %q", full)
	}
	// id and secret are base32-lower: only [a-z2-7], no underscore, so parse is clean.
	if strings.ContainsAny(id, "_") || strings.ContainsAny(secret, "_") {
		t.Fatalf("id/secret must not contain '_': id=%q secret=%q", id, secret)
	}
	gotID, gotSecret, ok := parseToken(full)
	if !ok || gotID != id || gotSecret != secret {
		t.Fatalf("parseToken round-trip failed: %q %q %v", gotID, gotSecret, ok)
	}
	if len(secret) < 40 { // 32 bytes base32 (no pad) ≈ 52 chars
		t.Fatalf("secret too short (%d), want >=40 chars of entropy", len(secret))
	}
}

func TestParseTokenRejectsMalformed(t *testing.T) {
	for _, bad := range []string{"", "nope", "patdmcp_", "patdmcp_onlyid", "Bearer x", "patdmcp__nosecret"} {
		if _, _, ok := parseToken(bad); ok {
			t.Errorf("parseToken(%q) accepted a malformed token", bad)
		}
	}
}

func TestHashSecretDeterministic(t *testing.T) {
	if hashSecret("abc") != hashSecret("abc") {
		t.Fatal("hashSecret not deterministic")
	}
	if hashSecret("abc") == hashSecret("abd") {
		t.Fatal("hashSecret collision on different inputs")
	}
	if len(hashSecret("abc")) != 64 { // sha256 hex
		t.Fatal("hashSecret not 64 hex chars")
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/auth/ -run 'TestNewToken|TestParseToken|TestHashSecret' -v`
Expected: FAIL — `undefined: newToken`, `parseToken`, `hashSecret`.

- [ ] **Step 3: Write the minimal implementation**

Create `internal/auth/apitoken.go`:

```go
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"strings"
	"time"
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
```

- [ ] **Step 4: Run it to verify it passes**

Run: `go test ./internal/auth/ -run 'TestNewToken|TestParseToken|TestHashSecret' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/auth/apitoken.go internal/auth/apitoken_test.go
git commit -m "feat(auth): MCP API token type, generation, hashing, parsing"
```

---

## Task 2: TokenStore — load/save/Issue/Verify/List/Revoke

**Files:**
- Modify: `internal/auth/apitoken.go`
- Test: `internal/auth/apitoken_test.go`

- [ ] **Step 1: Write the failing test** (append to `apitoken_test.go`)

```go
import (
	"path/filepath"
	"testing"
	"time"
)

func TestTokenStoreIssueVerify(t *testing.T) {
	s := NewTokenStore("", nil)
	full, rec, err := s.Issue(RoleAnalyst, "gemini", nil)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Role != RoleAnalyst || rec.Label != "gemini" || rec.SecretHash == "" {
		t.Fatalf("bad record: %+v", rec)
	}
	got, ok := s.Verify(full)
	if !ok || got.ID != rec.ID || got.Role != RoleAnalyst {
		t.Fatalf("verify failed: %+v ok=%v", got, ok)
	}
	if _, ok := s.Verify(full + "x"); ok {
		t.Fatal("verify accepted a tampered secret")
	}
	if _, ok := s.Verify("patdmcp_unknown_secret"); ok {
		t.Fatal("verify accepted an unknown id")
	}
}

func TestTokenStoreExpiredAndDisabled(t *testing.T) {
	s := NewTokenStore("", nil)
	past := time.Now().Add(-time.Hour)
	full, rec, _ := s.Issue(RoleLead, "expired", &past)
	if _, ok := s.Verify(full); ok {
		t.Fatal("expired token verified")
	}
	full2, rec2, _ := s.Issue(RoleLead, "live", nil)
	_ = rec
	s.setDisabledForTest(rec2.ID, true)
	if _, ok := s.Verify(full2); ok {
		t.Fatal("disabled token verified")
	}
}

func TestTokenStoreListRedactedAndRevoke(t *testing.T) {
	s := NewTokenStore("", nil)
	_, rec, _ := s.Issue(RoleAnalyst, "a", nil)
	for _, info := range s.List() {
		// TokenInfo has no SecretHash field at all — compile-time guarantee it can't leak.
		if info.ID == rec.ID && info.Label != "a" {
			t.Fatal("list label mismatch")
		}
	}
	if !s.Revoke(rec.ID) {
		t.Fatal("revoke of existing token returned false")
	}
	if s.Revoke(rec.ID) {
		t.Fatal("revoke of missing token returned true")
	}
}

func TestTokenStorePersistReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mcp_tokens.json")
	s := NewTokenStore(path, nil)
	full, _, _ := s.Issue(RoleLead, "persisted", nil)
	s2, err := OpenTokenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s2.Verify(full); !ok {
		t.Fatal("token did not survive persist+reload")
	}
}
```

Add a tiny test helper to `apitoken.go` so tests can flip Disabled without a public setter:

```go
// setDisabledForTest is a test seam (no production caller).
func (s *TokenStore) setDisabledForTest(id string, disabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rec, ok := s.tokens[id]; ok {
		rec.Disabled = disabled
		s.tokens[id] = rec
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/auth/ -run TestTokenStore -v`
Expected: FAIL — `undefined: NewTokenStore`, `OpenTokenStore`, `TokenInfo`, etc.

- [ ] **Step 3: Write the minimal implementation** (append to `apitoken.go`)

```go
import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"

	"github.com/watson0x90/PasswordAtTheDisco/internal/fsutil"
)

// dummyTokenHash equalises Verify timing on unknown-id / malformed paths, mirroring
// the dummyHash trick in users.go.
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
// dummy compare on unknown id / bad secret) to blunt timing enumeration.
func (s *TokenStore) Verify(full string) (APIToken, bool) {
	id, secret, ok := parseToken(full)
	if !ok {
		subtle.ConstantTimeCompare([]byte(dummyTokenHash), []byte(dummyTokenHash))
		return APIToken{}, false
	}
	s.mu.RLock()
	rec, found := s.tokens[id]
	s.mu.RUnlock()
	want := dummyTokenHash
	if found {
		want = rec.SecretHash
	}
	match := subtle.ConstantTimeCompare([]byte(hashSecret(secret)), []byte(want)) == 1
	if !found || !match || rec.Disabled || (rec.Expires != nil && rec.Expires.Before(time.Now())) {
		return APIToken{}, false
	}
	s.touchLastUsed(id)
	return rec, true
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

// touchLastUsed updates last_used in memory and persists it at most once/min/token.
func (s *TokenStore) touchLastUsed(id string) {
	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.tokens[id]
	if !ok {
		return
	}
	rec.LastUsed = &now
	s.tokens[id] = rec
	if last := s.lastFlush[id]; last.IsZero() || now.Sub(last) >= time.Minute {
		s.lastFlush[id] = now
		_ = s.persistLocked() // best-effort; last_used is non-critical
	}
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
```

Add `"crypto/subtle"` to the import block at the top of `apitoken.go`.

- [ ] **Step 4: Run it to verify it passes**

Run: `go test ./internal/auth/ -run 'TestToken|TestNewToken|TestParseToken|TestHashSecret' -v`
Expected: PASS. Then `gofmt -w internal/auth/apitoken.go internal/auth/apitoken_test.go`.

- [ ] **Step 5: Commit**

```bash
git add internal/auth/apitoken.go internal/auth/apitoken_test.go
git commit -m "feat(auth): TokenStore (issue/verify/list/revoke) with atomic persist + last-used throttle"
```

---

## Task 3: requireMCPToken middleware + whoami probe

**Files:**
- Create: `internal/httpapi/mcp.go`
- Modify: `internal/httpapi/server.go` (Server fields, `mcpTokenKey`, routes)
- Test: `internal/httpapi/mcp_test.go`

- [ ] **Step 1: Add Server fields + ctx key** in `internal/httpapi/server.go`

In the `Server` struct (after `IngestToken string`), add:
```go
	MCPTokens *auth.TokenStore // role-scoped API tokens for MCP/programmatic access (may be nil)
	MCPLimiter *auth.Limiter   // per-IP failed-MCP-auth throttle (may be nil)
```
Below `const sessionKey ctxKey = 0`, add:
```go
const mcpTokenKey ctxKey = 1
```

- [ ] **Step 2: Write the failing test** — create `internal/httpapi/mcp_test.go`

```go
package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/watson0x90/PasswordAtTheDisco/internal/auth"
)

func mcpTestServer(t *testing.T) (*Server, string, string) {
	t.Helper()
	ts := auth.NewTokenStore("", nil)
	analystTok, _, _ := ts.Issue(auth.RoleAnalyst, "analyst-agent", nil)
	leadTok, _, _ := ts.Issue(auth.RoleLead, "lead-agent", nil)
	s := &Server{MCPTokens: ts, MCPLimiter: auth.NewLimiter(20, time.Minute)}
	return s, analystTok, leadTok
}

func TestWhoamiValidToken(t *testing.T) {
	s, analystTok, _ := mcpTestServer(t)
	h := s.requireMCPToken(http.HandlerFunc(s.handleMCPWhoami))
	req := httptest.NewRequest("GET", "/api/mcp/whoami", nil)
	req.Header.Set("Authorization", "Bearer "+analystTok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["role"] != "analyst" || body["token_id"] == "" {
		t.Fatalf("whoami body = %v", body)
	}
}

func TestWhoamiRejectsBadToken(t *testing.T) {
	s, _, _ := mcpTestServer(t)
	h := s.requireMCPToken(http.HandlerFunc(s.handleMCPWhoami))
	for _, hdr := range []string{"", "Bearer nonsense", "Bearer patdmcp_x_y"} {
		req := httptest.NewRequest("GET", "/api/mcp/whoami", nil)
		if hdr != "" {
			req.Header.Set("Authorization", hdr)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("header %q: status = %d, want 401", hdr, rec.Code)
		}
	}
}
```

Add `"time"` to the test imports.

- [ ] **Step 3: Run it to verify it fails**

Run: `go test ./internal/httpapi/ -run TestWhoami -v`
Expected: FAIL — `undefined: (*Server).requireMCPToken`, `handleMCPWhoami`.

- [ ] **Step 4: Write the implementation** — create `internal/httpapi/mcp.go`

```go
package httpapi

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/watson0x90/PasswordAtTheDisco/internal/auth"
)

// mcpTokenFrom returns the authenticated MCP token from the request context.
func mcpTokenFrom(ctx context.Context) (auth.APIToken, bool) {
	t, ok := ctx.Value(mcpTokenKey).(auth.APIToken)
	return t, ok
}

// requireMCPToken authenticates a bearer API token and attaches it to the context.
// Like requireIngestToken, but multi-token and role-bearing. Rate-limited per IP.
func (s *Server) requireMCPToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.MCPTokens == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "mcp access disabled"})
			return
		}
		ip := clientIP(r)
		if s.MCPLimiter != nil {
			if ok, retry := s.MCPLimiter.Allowed(ip); !ok {
				w.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds())))
				writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many failed attempts"})
				return
			}
		}
		raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		tok, ok := s.MCPTokens.Verify(raw)
		if !ok {
			if s.MCPLimiter != nil {
				s.MCPLimiter.RecordFailure(ip)
			}
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		if s.MCPLimiter != nil {
			s.MCPLimiter.Reset(ip)
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), mcpTokenKey, tok)))
	})
}

// handleMCPWhoami returns the calling token's id + role. Proves the bearer auth path
// end-to-end. Does NOT require the data store to be unlocked.
func (s *Server) handleMCPWhoami(w http.ResponseWriter, r *http.Request) {
	tok, _ := mcpTokenFrom(r.Context())
	writeJSON(w, http.StatusOK, map[string]string{"token_id": tok.ID, "role": string(tok.Role)})
}
```

- [ ] **Step 5: Register the route** in `server.go` (near the other `/api/...` routes, e.g. after the ingest line):
```go
	mux.Handle("GET /api/mcp/whoami", s.requireMCPToken(http.HandlerFunc(s.handleMCPWhoami)))
```

- [ ] **Step 6: Run it to verify it passes**

Run: `go test ./internal/httpapi/ -run TestWhoami -v && go build ./...`
Expected: PASS + build OK.

- [ ] **Step 7: Commit**

```bash
git add internal/httpapi/mcp.go internal/httpapi/mcp_test.go internal/httpapi/server.go
git commit -m "feat(httpapi): requireMCPToken middleware + GET /api/mcp/whoami probe"
```

---

## Task 4: Token management handlers (lead-gated, CSRF, audited)

**Files:**
- Modify: `internal/httpapi/mcp.go`, `internal/httpapi/server.go` (routes)
- Test: `internal/httpapi/mcp_test.go`

- [ ] **Step 1: Write the failing test** (append to `mcp_test.go`)

These call the handlers directly with a session in context (mirroring how the user-management tests inject a session). Build a small helper that wraps a request with an `auth.Session`:

```go
import "context"

func withSession(req *http.Request, role auth.Role) *http.Request {
	sess := auth.Session{Username: "boss", Role: role, CSRF: "x"}
	return req.WithContext(context.WithValue(req.Context(), sessionKey, sess))
}

func TestCreateTokenLeadOnlyReturnsOnce(t *testing.T) {
	s, _, _ := mcpTestServer(t)
	// analyst session -> 403
	req := withSession(httptest.NewRequest("POST", "/api/mcp/tokens", strings.NewReader(`{"label":"x","role":"analyst"}`)), auth.RoleAnalyst)
	rec := httptest.NewRecorder()
	s.handleCreateMCPToken(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("analyst create status = %d, want 403", rec.Code)
	}
	// lead session -> 201 + token shown once
	req = withSession(httptest.NewRequest("POST", "/api/mcp/tokens", strings.NewReader(`{"label":"gemini","role":"analyst"}`)), auth.RoleLead)
	rec = httptest.NewRecorder()
	s.handleCreateMCPToken(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("lead create status = %d, want 201", rec.Code)
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if tok, _ := body["token"].(string); !strings.HasPrefix(tok, "patdmcp_") {
		t.Fatalf("create did not return the full token: %v", body)
	}
}

func TestListTokensNeverLeaksHash(t *testing.T) {
	s, _, _ := mcpTestServer(t)
	req := withSession(httptest.NewRequest("GET", "/api/mcp/tokens", nil), auth.RoleLead)
	rec := httptest.NewRecorder()
	s.handleListMCPTokens(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "secret_hash") {
		t.Fatal("token list leaked secret_hash")
	}
}

func TestRevokeToken(t *testing.T) {
	s, _, _ := mcpTestServer(t)
	_, rec0, _ := s.MCPTokens.Issue(auth.RoleAnalyst, "doomed", nil)
	req := withSession(httptest.NewRequest("DELETE", "/api/mcp/tokens/"+rec0.ID, nil), auth.RoleLead)
	req.SetPathValue("id", rec0.ID)
	rec := httptest.NewRecorder()
	s.handleRevokeMCPToken(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("revoke status = %d, want 204", rec.Code)
	}
}
```

The handlers call `s.Audit.Log(...)`, so give the test server a no-op audit logger. Update `mcpTestServer` to set `Audit: audit.New(io.Discard)` (add imports `io` and the audit package).

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/httpapi/ -run 'TestCreateToken|TestListTokens|TestRevokeToken' -v`
Expected: FAIL — handlers undefined.

- [ ] **Step 3: Implement the handlers** (append to `internal/httpapi/mcp.go`; add imports `encoding/json`, `time`, and the `audit` package)

```go
// requireLeadSession returns the session and true iff the caller is an authenticated
// lead. On failure it writes 403/401 and returns false.
func requireLeadSession(w http.ResponseWriter, r *http.Request) (auth.Session, bool) {
	sess, ok := sessionFrom(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return auth.Session{}, false
	}
	if sess.Role != auth.RoleLead {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "requires lead role"})
		return auth.Session{}, false
	}
	return sess, true
}

func (s *Server) handleListMCPTokens(w http.ResponseWriter, r *http.Request) {
	if _, ok := requireLeadSession(w, r); !ok {
		return
	}
	writeJSON(w, http.StatusOK, s.MCPTokens.List())
}

func (s *Server) handleCreateMCPToken(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireLeadSession(w, r)
	if !ok {
		return
	}
	var body struct {
		Label   string     `json:"label"`
		Role    auth.Role  `json:"role"`
		Expires *time.Time `json:"expires"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	full, rec, err := s.MCPTokens.Issue(body.Role, body.Label, body.Expires)
	s.Audit.Log(audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: "token_create", Target: rec.ID, Source: r.RemoteAddr, Result: okOr(err)})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"token": full, "id": rec.ID, "role": string(rec.Role),
		"label": rec.Label, "created": rec.Created, "expires": rec.Expires,
	})
}

func (s *Server) handleRevokeMCPToken(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireLeadSession(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	revoked := s.MCPTokens.Revoke(id)
	result := "ok"
	if !revoked {
		result = "denied"
	}
	s.Audit.Log(audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: "token_revoke", Target: id, Source: r.RemoteAddr, Result: result})
	if !revoked {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such token"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
```

- [ ] **Step 4: Register routes** in `server.go`:
```go
	mux.Handle("GET /api/mcp/tokens", s.requireAuth(http.HandlerFunc(s.handleListMCPTokens)))
	mux.Handle("POST /api/mcp/tokens", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.handleCreateMCPToken))))
	mux.Handle("DELETE /api/mcp/tokens/{id}", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.handleRevokeMCPToken))))
```

- [ ] **Step 5: Run it to verify it passes**

Run: `go test ./internal/httpapi/ -run 'Token' -v && go vet ./...`
Expected: PASS + vet clean. Then `gofmt -w internal/httpapi/mcp.go internal/httpapi/mcp_test.go`.

- [ ] **Step 6: Commit**

```bash
git add internal/httpapi/mcp.go internal/httpapi/mcp_test.go internal/httpapi/server.go
git commit -m "feat(httpapi): lead-gated MCP token management (list/create/revoke) + audit"
```

---

## Task 5: `patd token` CLI

**Files:**
- Create: `cmd/patd/token.go`, `cmd/patd/token_test.go`
- Modify: `cmd/patd/main.go` (dispatch)

- [ ] **Step 1: Write the failing test** — `cmd/patd/token_test.go`

```go
package main

import (
	"path/filepath"
	"testing"

	"github.com/watson0x90/PasswordAtTheDisco/internal/auth"
)

func TestTokenCreateThenVerify(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mcp_tokens.json")
	full, err := createToken(path, "analyst", "cli-agent", "")
	if err != nil {
		t.Fatal(err)
	}
	store, err := auth.OpenTokenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store.Verify(full); !ok {
		t.Fatal("CLI-created token did not verify")
	}
}

func TestTokenRevokeViaHelper(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mcp_tokens.json")
	full, _ := createToken(path, "lead", "doomed", "")
	store, _ := auth.OpenTokenStore(path)
	got, _ := store.Verify(full)
	if !revokeToken(path, got.ID) {
		t.Fatal("revoke returned false for an existing token")
	}
	store2, _ := auth.OpenTokenStore(path)
	if _, ok := store2.Verify(full); ok {
		t.Fatal("token still verifies after revoke")
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./cmd/patd/ -run TestToken -v`
Expected: FAIL — `undefined: createToken`, `revokeToken`.

- [ ] **Step 3: Implement** — `cmd/patd/token.go`

```go
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/watson0x90/PasswordAtTheDisco/internal/auth"
)

// openOrNewTokenStore loads the tokens file, or starts an empty store if absent.
func openOrNewTokenStore(path string) (*auth.TokenStore, error) {
	if st, err := auth.OpenTokenStore(path); err == nil {
		return st, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return auth.NewTokenStore(path, nil), nil
}

// createToken mints a token in the file and returns the full secret string (once).
func createToken(path, role, label, expires string) (string, error) {
	st, err := openOrNewTokenStore(path)
	if err != nil {
		return "", err
	}
	var exp *time.Time
	if expires != "" {
		if d, derr := time.ParseDuration(expires); derr == nil {
			t := time.Now().Add(d).UTC()
			exp = &t
		} else if t, terr := time.Parse(time.RFC3339, expires); terr == nil {
			tu := t.UTC()
			exp = &tu
		} else {
			return "", fmt.Errorf("--expires %q: want a duration (e.g. 720h) or RFC3339 timestamp", expires)
		}
	}
	full, _, err := st.Issue(auth.Role(role), label, exp)
	return full, err
}

func revokeToken(path, id string) bool {
	st, err := auth.OpenTokenStore(path)
	if err != nil {
		return false
	}
	return st.Revoke(id)
}

// runToken implements `patd token <create|list|revoke> ...`.
func runToken(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: patd token <create|list|revoke> [flags]")
		os.Exit(2)
	}
	path := env("PATD_MCP_TOKENS_FILE", "mcp_tokens.json")
	switch args[0] {
	case "create":
		fs := flag.NewFlagSet("token create", flag.ExitOnError)
		role := fs.String("role", "analyst", "token role: analyst|lead")
		label := fs.String("label", "", "human label (required)")
		expires := fs.String("expires", "", "optional expiry: duration (720h) or RFC3339")
		file := fs.String("file", path, "tokens file")
		_ = fs.Parse(args[1:])
		if *label == "" {
			fmt.Fprintln(os.Stderr, "--label is required")
			os.Exit(2)
		}
		full, err := createToken(*file, *role, *label, *expires)
		if err != nil {
			fmt.Fprintln(os.Stderr, "create failed:", err)
			os.Exit(1)
		}
		if *role == "lead" {
			fmt.Fprintln(os.Stderr, "WARNING: a lead token can reveal AD cleartext via the MCP reveal tool.")
		}
		fmt.Println(full)
		fmt.Fprintln(os.Stderr, "^ copy this now — it will not be shown again.")
	case "list":
		fs := flag.NewFlagSet("token list", flag.ExitOnError)
		file := fs.String("file", path, "tokens file")
		_ = fs.Parse(args[1:])
		st, err := auth.OpenTokenStore(*file)
		if err != nil {
			fmt.Fprintln(os.Stderr, "no tokens:", err)
			return
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tROLE\tLABEL\tCREATED\tLAST USED\tSTATUS")
		for _, tk := range st.List() {
			status := "active"
			if tk.Disabled {
				status = "disabled"
			} else if tk.Expires != nil && tk.Expires.Before(time.Now()) {
				status = "expired"
			}
			last := "never"
			if tk.LastUsed != nil {
				last = tk.LastUsed.Format("2006-01-02 15:04")
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", tk.ID, tk.Role, tk.Label, tk.Created.Format("2006-01-02"), last, status)
		}
		_ = tw.Flush()
	case "revoke":
		fs := flag.NewFlagSet("token revoke", flag.ExitOnError)
		file := fs.String("file", path, "tokens file")
		_ = fs.Parse(args[1:])
		rest := fs.Args()
		if len(rest) != 1 {
			fmt.Fprintln(os.Stderr, "usage: patd token revoke <id>")
			os.Exit(2)
		}
		if !revokeToken(*file, rest[0]) {
			fmt.Fprintln(os.Stderr, "no such token:", rest[0])
			os.Exit(1)
		}
		fmt.Println("revoked", rest[0])
	default:
		fmt.Fprintln(os.Stderr, "unknown subcommand:", args[0])
		os.Exit(2)
	}
	_ = errors.New // keep imports stable if create path unused in a build
}
```

(If `errors` ends up unused after gofmt, delete its import and the trailing `_ = errors.New` line.)

- [ ] **Step 4: Wire dispatch** in `cmd/patd/main.go` — add to the `switch os.Args[1]` block:
```go
		case "token":
			runToken(os.Args[2:])
			return
```

- [ ] **Step 5: Run it to verify it passes**

Run: `go test ./cmd/patd/ -run TestToken -v && go build ./...`
Expected: PASS + build OK. Then `gofmt -w cmd/patd/token.go cmd/patd/token_test.go cmd/patd/main.go`.

- [ ] **Step 6: Commit**

```bash
git add cmd/patd/token.go cmd/patd/token_test.go cmd/patd/main.go
git commit -m "feat(cli): patd token create/list/revoke (bootstrap MCP tokens)"
```

---

## Task 6: Server wiring + gitignore + example file

**Files:**
- Modify: `cmd/patd/main.go`, `.gitignore`
- Create: `mcp_tokens.example.json`

- [ ] **Step 1: Load + wire the token store** in `cmd/patd/main.go`. After the user-store block (~line 81), add:
```go
	mcpFile := env("PATD_MCP_TOKENS_FILE", "mcp_tokens.json")
	mcpTokens, err := auth.OpenTokenStore(mcpFile)
	if err != nil {
		log.Printf("no MCP tokens loaded (%v) -- mint one with `patd token create --role analyst --label <name>`", err)
		mcpTokens = auth.NewTokenStore(mcpFile, nil)
	} else {
		log.Printf("loaded %d MCP token(s) from %s", len(mcpTokens.List()), mcpFile)
	}
```
Then in the `&httpapi.Server{...}` literal (~line 169), add:
```go
		MCPTokens:    mcpTokens,
		MCPLimiter:   auth.NewLimiter(20, 15*time.Minute),
```

- [ ] **Step 2: Create `mcp_tokens.example.json`**
```json
[]
```

- [ ] **Step 3: gitignore the real file.** Append to `.gitignore`:
```
# MCP API tokens (hashed secrets — never commit)
mcp_tokens.json
```

- [ ] **Step 4: Verify build + full Go suite**

Run: `go build ./... && go vet ./... && go test ./... && gofmt -l cmd internal`
Expected: all pass; gofmt prints nothing.

- [ ] **Step 5: Manual smoke (real end-to-end auth)**

```bash
go build -o patd ./cmd/patd
PATD_MCP_TOKENS_FILE=/tmp/mcp_tokens.json ./patd token create --role analyst --label smoke
# copy the printed patdmcp_... token
```
Start the server with `PATD_MCP_TOKENS_FILE=/tmp/mcp_tokens.json` and:
```bash
curl -s -H "Authorization: Bearer patdmcp_..." http://127.0.0.1:8443/api/mcp/whoami
# expect: {"role":"analyst","token_id":"..."}
curl -s http://127.0.0.1:8443/api/mcp/whoami   # no token
# expect: 401 {"error":"unauthorized"}
```

- [ ] **Step 6: Commit**

```bash
git add cmd/patd/main.go .gitignore mcp_tokens.example.json
git commit -m "feat(server): wire MCP token store + per-IP limiter; gitignore mcp_tokens.json"
```

---

## Task 7: Web API client + types

**Files:**
- Modify: `web/src/api.ts`

- [ ] **Step 1: Add types** near the other interfaces in `web/src/api.ts`:
```ts
export interface McpToken {
  id: string
  role: Role
  label: string
  created: string
  expires?: string
  disabled: boolean
  last_used?: string
}
export interface McpTokenCreated extends McpToken {
  token: string // full secret, shown exactly once
}
```

- [ ] **Step 2: Add client methods** (mirror the existing `listUsers`/`createUser`/`deleteUser` methods — same fetch wrapper, CSRF header on mutations):
```ts
  listMcpTokens: () => request<McpToken[]>("GET", "/api/mcp/tokens"),
  createMcpToken: (label: string, role: Role, expires: string | undefined, csrf: string) =>
    request<McpTokenCreated>("POST", "/api/mcp/tokens", { label, role, expires }, csrf),
  revokeMcpToken: (id: string, csrf: string) =>
    request<void>("DELETE", `/api/mcp/tokens/${encodeURIComponent(id)}`, undefined, csrf),
```
Match the exact signature of `request(...)` already used by `createUser`/`deleteUser` in this file (read those two first and mirror argument order, CSRF placement, and return-type handling — including how a 204/empty body is handled).

- [ ] **Step 3: Typecheck**

Run (in `web/`): `npx tsc --noEmit`
Expected: no errors.

- [ ] **Step 4: Commit**

```bash
git add web/src/api.ts
git commit -m "feat(web): api client for MCP token management"
```

---

## Task 8: Admin Tokens UI panel

**Files:**
- Create: `web/src/components/McpTokens.tsx`
- Modify: `web/src/components/AppShell.tsx`

> Use the `frontend-design` skill for the panel and verify live with Playwright. Mirror `web/src/components/Operators.tsx` exactly for structure, styling classes (`ops-page`, `panel`, `section-label`, `search`, `btn btn-primary`, `link-btn`, `error`, `ingest-ok`), the `useAuth()` + `csrf` pattern, the lead-gate guard, and load/flash/fail helpers. Web tests are node-env pure-logic; the styleguard bans literal inline spacing styles in `.tsx`.

- [ ] **Step 1: Build the panel** — `web/src/components/McpTokens.tsx`. Required behaviour:
  - Guard: `if (me?.role !== "lead") return <div className="center-state">MCP token management requires the lead role.</div>`
  - Load `api.listMcpTokens()`; show a table (Label, Role, Created, Last used, Status, Revoke action).
  - "Issue token" form: label input, role `<select>` (analyst/lead) **with a visible warning when `lead` is selected** — e.g. `{role === "lead" && <p className="error">A lead token can reveal AD cleartext via the MCP reveal tool.</p>}`, optional expiry input (text, e.g. `720h`).
  - On create success, render the returned `token` once in a copy box with a "you will not see this again" notice (store it in component state; clear on next create or navigate). Never refetch it.
  - Revoke uses `confirm(...)` like `Operators.remove`, then `api.revokeMcpToken(id, csrf)` and reload.

  Skeleton (fill in following `Operators.tsx`):
```tsx
import { useCallback, useEffect, useState } from "react"
import { api, ApiError, type McpToken, type Role } from "../api"
import { useAuth } from "../auth"
import { fmtWhen } from "../format"

export function McpTokens() {
  const { me } = useAuth()
  const csrf = me?.csrf_token ?? ""
  const [tokens, setTokens] = useState<McpToken[]>([])
  const [error, setError] = useState("")
  const [ok, setOk] = useState("")
  const [label, setLabel] = useState("")
  const [role, setRole] = useState<Role>("analyst")
  const [expires, setExpires] = useState("")
  const [created, setCreated] = useState("") // the one-time full token

  const load = useCallback(async () => {
    try { setTokens(await api.listMcpTokens()) }
    catch (e) { setError(e instanceof ApiError ? e.message : "failed to load tokens") }
  }, [])
  useEffect(() => { void load() }, [load])

  async function issue() {
    if (!label.trim()) return
    try {
      const res = await api.createMcpToken(label.trim(), role, expires.trim() || undefined, csrf)
      setCreated(res.token)
      setLabel(""); setExpires(""); setRole("analyst")
      setOk(`Issued token "${res.label}".`); setError("")
      await load()
    } catch (e) { setError(e instanceof ApiError ? e.message : "failed to issue token") }
  }

  async function revoke(t: McpToken) {
    if (!confirm(`Revoke token "${t.label}"? Agents using it stop working immediately.`)) return
    try { await api.revokeMcpToken(t.id, csrf); setOk(`Revoked "${t.label}".`); await load() }
    catch (e) { setError(e instanceof ApiError ? e.message : "failed to revoke") }
  }

  if (me?.role !== "lead") return <div className="center-state">MCP token management requires the lead role.</div>
  // ...render: section-label "MCP Tokens", panel with table over `tokens`,
  // the one-time `created` copy box when set, the issue form with the lead warning,
  // and {error && <div className="error">{error}</div>} / {ok && <div className="ingest-ok">✓ {ok}</div>}.
  return <div className="ops-page">{/* mirror Operators.tsx layout */}</div>
}
```

- [ ] **Step 2: Wire into the Admin nav** in `web/src/components/AppShell.tsx`. Find where `Operators` is added to the Admin dropdown and routed (search for `Operators`), and add a sibling "Tokens" entry that renders `<McpTokens/>`, gated to leads the same way Operators is.

- [ ] **Step 3: Gates**

Run (in `web/`): `npx tsc --noEmit && npx vitest run && npm run build`
Expected: tsc clean, all vitest pass (incl. styleguard), build OK.

- [ ] **Step 4: Live verify** (build embed, restart, Playwright)

```bash
# repo root, via Bash:
cd /c/base/dev/PasswordAtTheDisco && bash .claude/skills/build-and-run/scripts/build.sh
```
Then restart (`.claude/skills/build-and-run/scripts/restart.ps1`) and via the Playwright MCP at `http://127.0.0.1:8443`: log in as a lead (watson/discotime, unlock disco-vault-2026), open Admin → Tokens, issue an analyst token, confirm the one-time secret box shows a `patdmcp_…` string, confirm it appears in the list, revoke it, and assert the browser console has **no 4xx/error noise**. Screenshot the panel.

- [ ] **Step 5: Commit**

```bash
git add web/src/components/McpTokens.tsx web/src/components/AppShell.tsx
git commit -m "feat(web): Admin MCP Tokens panel (issue with one-time secret, revoke, lead-gated)"
```

---

## Task 9: Whole-of-A verification

**Files:** none (verification only).

- [ ] **Step 1: Full gate sweep**

Run: `gofmt -l cmd internal` (empty) · `go build ./... && go vet ./... && go test ./...` · `govulncheck ./...` · in `web/`: `npx tsc --noEmit && npx vitest run && npm run build`.
Expected: all green.

- [ ] **Step 2: End-to-end auth proof against the running embed build**

With the restarted server (Task 8): mint a token via the CLI **and** via the UI; `curl` `/api/mcp/whoami` with each and confirm the role; revoke one and confirm the next call is `401`; confirm an analyst **operator** session is `403` on `GET /api/mcp/tokens`; confirm `token_create`/`token_revoke` lines appear in the audit log (`PATD_AUDIT_LOG`).

- [ ] **Step 3: Confirm secret hygiene**

`git status` shows no `mcp_tokens.json` staged/tracked; the audit log contains **no** `patdmcp_…` secret; the `GET /api/mcp/tokens` response contains no `secret_hash`.

- [ ] **Step 4: Hand off to sub-project B**

A is done: `requireMCPToken` authenticates role-scoped tokens, leads manage them via UI + CLI, everything is audited, gates are green. **B** builds the Streamable-HTTP MCP endpoint and tool registry on top of `requireMCPToken` + `requireUnlocked`, mapping tools to existing capabilities and gating the reveal tool to `lead` tokens.

---

## Self-Review (completed by plan author)

**Spec coverage:** §4 token format/crypto → Tasks 1–2; §5 store/last-used → Task 2; §6 authz → Tasks 3–4; §7 HTTP (whoami + management) → Tasks 3–4; §8 CLI → Task 5; §9 Admin UI → Tasks 7–8; §10 audit/errors/rate-limit → Tasks 3–4; §11 testing → embedded per task + Task 9; §12 config/gitignore/example → Task 6. All covered.

**Type consistency:** `APIToken`/`TokenInfo`/`TokenStore` and methods (`Issue`/`Verify`/`List`/`Revoke`/`touchLastUsed`) are defined in Task 2 and used identically in Tasks 3–6; `requireMCPToken`/`mcpTokenFrom`/`mcpTokenKey` defined in Task 3 and reused in Task 4; `handleCreate/List/RevokeMCPToken` consistent across handler + route tasks; web `McpToken`/`McpTokenCreated` + `listMcpTokens`/`createMcpToken`/`revokeMcpToken` consistent across Tasks 7–8.

**Placeholder scan:** no TBD/"add error handling"/"similar to" — every code step is concrete. Two explicit "mirror the existing X" instructions (the `request(...)` wrapper in Task 7, the `Operators.tsx` layout in Task 8) intentionally defer to read-and-match because reproducing those large existing files verbatim would be error-prone; the required behaviour and skeleton are fully specified.
