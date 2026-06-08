package httpapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/watson0x90/PasswordAtTheDisco/internal/audit"
	"github.com/watson0x90/PasswordAtTheDisco/internal/auth"
	"github.com/watson0x90/PasswordAtTheDisco/internal/engine"
	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
	"github.com/watson0x90/PasswordAtTheDisco/internal/pwanalysis"
	"github.com/watson0x90/PasswordAtTheDisco/internal/store"
)

const oneAccount = `{"accounts":[{"username":"alice","domain":"CORP","password":"Welcome1",` +
	`"cracked":true,"risk_level":"Critical","hibp_breached":true,"da_domains":"CORP"}]}`

func newServerAudit(token string, auditW io.Writer) *Server {
	leadHash, _ := auth.HashPassword("leadpw")
	analystHash, _ := auth.HashPassword("analystpw")
	return &Server{
		Store:       store.New(),
		IngestToken: token,
		Users: auth.Users{
			"lead":    {Username: "lead", PasswordHash: leadHash, Role: auth.RoleLead},
			"analyst": {Username: "analyst", PasswordHash: analystHash, Role: auth.RoleAnalyst},
		},
		Sessions:     auth.NewSessionStore(time.Hour, time.Hour),
		Audit:        audit.New(auditW),
		LoginLimiter: auth.NewLimiter(50, time.Minute),
	}
}

func loginCSRF(t *testing.T, srv *Server, user, pass string) (*http.Cookie, string) {
	t.Helper()
	rec := loginAttempt(srv, user, pass)
	if rec.Code != http.StatusOK {
		t.Fatalf("login failed: %d %s", rec.Code, rec.Body.String())
	}
	var body struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("bad login body: %v", err)
	}
	var cookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie {
			cookie = c
		}
	}
	if cookie == nil || body.CSRFToken == "" {
		t.Fatalf("missing session cookie or csrf token (csrf=%q)", body.CSRFToken)
	}
	return cookie, body.CSRFToken
}

func loginAttempt(srv *Server, user, pass string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "/api/login", strings.NewReader(fmt.Sprintf(`{"username":%q,"password":%q}`, user, pass)))
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	return rec
}

func newServer(token string) *Server { return newServerAudit(token, io.Discard) }

func login(t *testing.T, srv *Server, user, pass string) *http.Cookie {
	t.Helper()
	req := httptest.NewRequest("POST", "/api/login", strings.NewReader(fmt.Sprintf(`{"username":%q,"password":%q}`, user, pass)))
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("login failed: %d %s", rec.Code, rec.Body.String())
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie {
			return c
		}
	}
	t.Fatal("no session cookie set")
	return nil
}

func do(srv *Server, method, path string, cookie *http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	return rec
}

func seed(t *testing.T, srv *Server) {
	t.Helper()
	req := httptest.NewRequest("POST", "/api/ingest", strings.NewReader(oneAccount))
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("seed ingest failed: %d %s", rec.Code, rec.Body.String())
	}
}

func TestIngestRejectsMissingToken(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/ingest", strings.NewReader(oneAccount))
	rec := httptest.NewRecorder()
	newServer("secret").Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", rec.Code)
	}
}

func TestAccountsRequireAuth(t *testing.T) {
	srv := newServer("secret")
	seed(t, srv)
	if rec := do(srv, "GET", "/api/accounts", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without session, got %d", rec.Code)
	}
}

func TestAccountsRedactedForAnalyst(t *testing.T) {
	srv := newServer("secret")
	seed(t, srv)
	rec := do(srv, "GET", "/api/accounts", login(t, srv, "analyst", "analystpw"))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if bytes.Contains(rec.Body.Bytes(), []byte("Welcome1")) {
		t.Fatal("cleartext leaked in /api/accounts")
	}
	var accts []model.Account
	if err := json.Unmarshal(rec.Body.Bytes(), &accts); err != nil || len(accts) != 1 || accts[0].Password != "" {
		t.Fatalf("unexpected payload: %v %+v", err, accts)
	}
}

func TestRevealRequiresLeadRole(t *testing.T) {
	srv := newServer("secret")
	seed(t, srv)
	// analyst is forbidden
	if rec := do(srv, "GET", "/api/accounts/alice/secret", login(t, srv, "analyst", "analystpw")); rec.Code != http.StatusForbidden {
		t.Fatalf("analyst should be 403, got %d", rec.Code)
	}
	// lead may reveal
	rec := do(srv, "GET", "/api/accounts/alice/secret", login(t, srv, "lead", "leadpw"))
	if rec.Code != http.StatusOK || !bytes.Contains(rec.Body.Bytes(), []byte("Welcome1")) {
		t.Fatalf("lead reveal failed: %d %s", rec.Code, rec.Body.String())
	}
}

func TestRevealIsAuditedWithoutCleartext(t *testing.T) {
	var buf bytes.Buffer
	srv := newServerAudit("secret", &buf)
	seed(t, srv)
	do(srv, "GET", "/api/accounts/alice/secret", login(t, srv, "lead", "leadpw"))

	logs := buf.String()
	if !strings.Contains(logs, "reveal_secret") || !strings.Contains(logs, `"target":"alice"`) || !strings.Contains(logs, `"actor":"lead"`) {
		t.Fatalf("reveal not audited: %s", logs)
	}
	if strings.Contains(logs, "Welcome1") {
		t.Fatalf("AUDIT LOG LEAKED CLEARTEXT: %s", logs)
	}
}

func TestSummaryRequiresAuth(t *testing.T) {
	srv := newServer("secret")
	seed(t, srv)
	if rec := do(srv, "GET", "/api/summary", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	rec := do(srv, "GET", "/api/summary", login(t, srv, "analyst", "analystpw"))
	var sum model.Summary
	if err := json.Unmarshal(rec.Body.Bytes(), &sum); err != nil || sum.TotalAccounts != 1 || sum.DAPathways != 1 {
		t.Fatalf("unexpected summary: %v %+v", err, sum)
	}
}

func TestLogoutRequiresCSRF(t *testing.T) {
	srv := newServer("secret")
	cookie, csrf := loginCSRF(t, srv, "analyst", "analystpw")

	// Without the CSRF header -> 403.
	req := httptest.NewRequest("POST", "/api/logout", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("logout without CSRF should be 403, got %d", rec.Code)
	}

	// With the CSRF header -> 200, and the session is then invalid.
	req = httptest.NewRequest("POST", "/api/logout", nil)
	req.AddCookie(cookie)
	req.Header.Set("X-CSRF-Token", csrf)
	rec = httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("logout with CSRF should be 200, got %d", rec.Code)
	}
	if rec := do(srv, "GET", "/api/accounts", cookie); rec.Code != http.StatusUnauthorized {
		t.Fatalf("session should be invalid after logout, got %d", rec.Code)
	}
}

func auditReq(t *testing.T, cookie *http.Cookie, csrf, domain, crackedBody string) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("domain", domain)
	fw, _ := mw.CreateFormFile("cracked", "cracked.txt")
	_, _ = io.WriteString(fw, crackedBody)
	_ = mw.Close()
	req := httptest.NewRequest("POST", "/api/audit", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	if cookie != nil {
		req.AddCookie(cookie)
	}
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	return req
}

func TestAuditUpload(t *testing.T) {
	body := "alice:1001:aad3b435b51404eeaad3b435b51404ee:NTLMHASHVALUE:::Welcome1\n"

	// lead with an engine configured -> ingests and the data is queryable (redacted)
	srv := newServer("secret")
	srv.Engine = &engine.Engine{Policy: pwanalysis.DefaultPolicy(), MaxPasswordAgeDays: 90}
	cookie, csrf := loginCSRF(t, srv, "lead", "leadpw")
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, auditReq(t, cookie, csrf, "CORP", body))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"accounts":1`) {
		t.Fatalf("lead upload = %d %s", rec.Code, rec.Body.String())
	}
	ar := do(srv, "GET", "/api/accounts", cookie)
	if !strings.Contains(ar.Body.String(), "alice") || strings.Contains(ar.Body.String(), "Welcome1") {
		t.Fatalf("accounts after upload (must include alice, NOT cleartext): %s", ar.Body.String())
	}

	// analyst -> 403
	ac, acsrf := loginCSRF(t, srv, "analyst", "analystpw")
	rec = httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, auditReq(t, ac, acsrf, "CORP", body))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("analyst audit should be 403, got %d", rec.Code)
	}

	// no engine configured -> 503
	srv2 := newServer("secret")
	c2, csrf2 := loginCSRF(t, srv2, "lead", "leadpw")
	rec = httptest.NewRecorder()
	srv2.Routes().ServeHTTP(rec, auditReq(t, c2, csrf2, "CORP", body))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("audit without engine should be 503, got %d", rec.Code)
	}
}

func TestLoginRateLimited(t *testing.T) {
	srv := newServer("secret")
	srv.LoginLimiter = auth.NewLimiter(5, time.Minute)
	for i := 0; i < 5; i++ {
		if rec := loginAttempt(srv, "analyst", "wrong"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401, got %d", i, rec.Code)
		}
	}
	if rec := loginAttempt(srv, "analyst", "wrong"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after threshold, got %d", rec.Code)
	}
	// Correct creds are still blocked while locked out.
	if rec := loginAttempt(srv, "analyst", "analystpw"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 even with correct creds while locked, got %d", rec.Code)
	}
}
