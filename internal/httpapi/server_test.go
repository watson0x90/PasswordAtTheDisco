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
	"github.com/watson0x90/PasswordAtTheDisco/internal/policy"
	"github.com/watson0x90/PasswordAtTheDisco/internal/store"
	"github.com/watson0x90/PasswordAtTheDisco/internal/vault"
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

// seed ingests the sample dataset (creating an audit) and returns its id.
func seed(t *testing.T, srv *Server) string {
	t.Helper()
	req := httptest.NewRequest("POST", "/api/ingest", strings.NewReader(oneAccount))
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("seed ingest failed: %d %s", rec.Code, rec.Body.String())
	}
	var body struct {
		AuditID string `json:"audit_id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return body.AuditID
}

// openAudit points a session (cookie+csrf) at an audit.
func openAudit(t *testing.T, srv *Server, cookie *http.Cookie, csrf, id string) {
	t.Helper()
	req := httptest.NewRequest("POST", "/api/audits/"+id+"/open", nil)
	req.AddCookie(cookie)
	req.Header.Set("X-CSRF-Token", csrf)
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("open audit %s: %d %s", id, rec.Code, rec.Body.String())
	}
}

// createAudit creates a named audit (auto-opens it for the creator) and returns its id.
func createAudit(t *testing.T, srv *Server, cookie *http.Cookie, csrf, name string) string {
	t.Helper()
	req := httptest.NewRequest("POST", "/api/audits", strings.NewReader(fmt.Sprintf(`{"name":%q}`, name)))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	req.Header.Set("X-CSRF-Token", csrf)
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("create audit: %d %s", rec.Code, rec.Body.String())
	}
	var m struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &m)
	return m.ID
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
	id := seed(t, srv)
	cookie, csrf := loginCSRF(t, srv, "analyst", "analystpw")
	openAudit(t, srv, cookie, csrf, id)
	rec := do(srv, "GET", "/api/accounts", cookie)
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
	id := seed(t, srv)
	// analyst is forbidden (role checked before the active-audit check)
	if rec := do(srv, "GET", "/api/accounts/alice/secret", login(t, srv, "analyst", "analystpw")); rec.Code != http.StatusForbidden {
		t.Fatalf("analyst should be 403, got %d", rec.Code)
	}
	// lead may reveal (after opening the audit)
	lc, lcsrf := loginCSRF(t, srv, "lead", "leadpw")
	openAudit(t, srv, lc, lcsrf, id)
	rec := do(srv, "GET", "/api/accounts/alice/secret", lc)
	if rec.Code != http.StatusOK || !bytes.Contains(rec.Body.Bytes(), []byte("Welcome1")) {
		t.Fatalf("lead reveal failed: %d %s", rec.Code, rec.Body.String())
	}
}

func TestRevealIsAuditedWithoutCleartext(t *testing.T) {
	var buf bytes.Buffer
	srv := newServerAudit("secret", &buf)
	id := seed(t, srv)
	lc, lcsrf := loginCSRF(t, srv, "lead", "leadpw")
	openAudit(t, srv, lc, lcsrf, id)
	do(srv, "GET", "/api/accounts/alice/secret", lc)

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
	id := seed(t, srv)
	if rec := do(srv, "GET", "/api/summary", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	ac, acsrf := loginCSRF(t, srv, "analyst", "analystpw")
	openAudit(t, srv, ac, acsrf, id)
	rec := do(srv, "GET", "/api/summary", ac)
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
	req := httptest.NewRequest("POST", "/api/upload", &buf)
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
	srv.Engine = &engine.Engine{Policies: policy.DefaultSet()}
	cookie, csrf := loginCSRF(t, srv, "lead", "leadpw")
	createAudit(t, srv, cookie, csrf, "Engagement") // auto-opens for the lead
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

func sendJSON(srv *Server, method, path string, cookie *http.Cookie, csrf, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	return rec
}

func TestPolicies(t *testing.T) {
	srv := newServer("secret")
	srv.Policies = policy.DefaultSet()
	body := `{"default":{"min_length":15,"require_lowercase":true,"require_uppercase":true,"require_digits":true,"require_special":true,"max_password_age_days":120},"domains":{"CORP.LOCAL":{"min_length":20,"require_lowercase":true,"require_uppercase":true,"require_digits":true,"require_special":true,"max_password_age_days":45}}}`

	// any operator can read
	ac, acsrf := loginCSRF(t, srv, "analyst", "analystpw")
	if g := do(srv, "GET", "/api/policies", ac); g.Code != http.StatusOK || !strings.Contains(g.Body.String(), `"min_length":14`) {
		t.Fatalf("GET policies = %d %s", g.Code, g.Body.String())
	}
	// analyst cannot edit
	if r := sendJSON(srv, "PUT", "/api/policies", ac, acsrf, body); r.Code != http.StatusForbidden {
		t.Fatalf("analyst PUT should be 403, got %d", r.Code)
	}
	// lead can edit; the shared Set (used by the engine) reflects it
	lc, lcsrf := loginCSRF(t, srv, "lead", "leadpw")
	if r := sendJSON(srv, "PUT", "/api/policies", lc, lcsrf, body); r.Code != http.StatusOK {
		t.Fatalf("lead PUT = %d %s", r.Code, r.Body.String())
	}
	if got := srv.Policies.For("CORP.LOCAL"); got.MinLength != 20 || got.MaxPasswordAgeDays != 45 {
		t.Errorf("override not applied: %+v", got)
	}
	if got := srv.Policies.For("other"); got.MinLength != 15 {
		t.Errorf("default not updated: %+v", got)
	}
	// invalid (min_length 0) rejected
	if r := sendJSON(srv, "PUT", "/api/policies", lc, lcsrf, `{"default":{"min_length":0,"max_password_age_days":90},"domains":{}}`); r.Code != http.StatusBadRequest {
		t.Fatalf("invalid policy should be 400, got %d", r.Code)
	}
}

func TestStoreLockAndUnlock(t *testing.T) {
	srv := newServer("secret")
	v, err := vault.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv.Store = store.NewPersistent(v)

	lc, lcsrf := loginCSRF(t, srv, "lead", "leadpw")
	// locked -> data endpoints return 423
	if rec := do(srv, "GET", "/api/audits", lc); rec.Code != http.StatusLocked {
		t.Fatalf("locked store should be 423, got %d", rec.Code)
	}
	// analyst cannot unlock
	ac, acsrf := loginCSRF(t, srv, "analyst", "analystpw")
	if rec := sendJSON(srv, "POST", "/api/unlock", ac, acsrf, `{"passphrase":"a-strong-passphrase"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("analyst unlock should be 403, got %d", rec.Code)
	}
	// too-short passphrase on first run -> 400
	if rec := sendJSON(srv, "POST", "/api/unlock", lc, lcsrf, `{"passphrase":"short"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("short passphrase should be 400, got %d", rec.Code)
	}
	// lead first-run sets the passphrase + unlocks
	if rec := sendJSON(srv, "POST", "/api/unlock", lc, lcsrf, `{"passphrase":"a-strong-passphrase"}`); rec.Code != http.StatusOK {
		t.Fatalf("lead unlock = %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(srv, "GET", "/api/audits", lc); rec.Code != http.StatusOK {
		t.Fatalf("after unlock, audits should be 200, got %d", rec.Code)
	}
}

type failWriter struct{}

func (failWriter) Write(p []byte) (int, error) { return 0, fmt.Errorf("disk full") }

func persistentServer(t *testing.T) *Server {
	t.Helper()
	v, err := vault.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv := newServer("secret")
	srv.Store = store.NewPersistent(v)
	return srv
}

func TestUnlockRateLimited(t *testing.T) {
	srv := persistentServer(t)
	srv.UnlockLimiter = auth.NewLimiter(3, time.Minute)
	lc, lcsrf := loginCSRF(t, srv, "lead", "leadpw")
	if r := sendJSON(srv, "POST", "/api/unlock", lc, lcsrf, `{"passphrase":"correct-horse-staple"}`); r.Code != http.StatusOK {
		t.Fatalf("init+unlock: %d %s", r.Code, r.Body.String())
	}
	if r := sendJSON(srv, "POST", "/api/lock", lc, lcsrf, ""); r.Code != http.StatusOK {
		t.Fatalf("lock: %d", r.Code)
	}
	got429 := false
	for i := 0; i < 6; i++ {
		if r := sendJSON(srv, "POST", "/api/unlock", lc, lcsrf, `{"passphrase":"wrong-passphrase-x"}`); r.Code == http.StatusTooManyRequests {
			got429 = true
			break
		}
	}
	if !got429 {
		t.Fatal("expected /api/unlock to rate-limit repeated wrong passphrases")
	}
}

func TestChangePassphraseEndpoint(t *testing.T) {
	srv := persistentServer(t)
	lc, lcsrf := loginCSRF(t, srv, "lead", "leadpw")
	sendJSON(srv, "POST", "/api/unlock", lc, lcsrf, `{"passphrase":"initial-passphrase"}`) // init + unlock

	ac, acsrf := loginCSRF(t, srv, "analyst", "analystpw")
	if r := sendJSON(srv, "POST", "/api/passphrase", ac, acsrf, `{"old":"initial-passphrase","new":"another-passphrase"}`); r.Code != http.StatusForbidden {
		t.Fatalf("analyst change should be 403, got %d", r.Code)
	}
	if r := sendJSON(srv, "POST", "/api/passphrase", lc, lcsrf, `{"old":"initial-passphrase","new":"short"}`); r.Code != http.StatusBadRequest {
		t.Fatalf("short new passphrase should be 400, got %d", r.Code)
	}
	if r := sendJSON(srv, "POST", "/api/passphrase", lc, lcsrf, `{"old":"nope","new":"another-passphrase"}`); r.Code != http.StatusUnauthorized {
		t.Fatalf("wrong old passphrase should be 401, got %d", r.Code)
	}
	if r := sendJSON(srv, "POST", "/api/passphrase", lc, lcsrf, `{"old":"initial-passphrase","new":"another-passphrase"}`); r.Code != http.StatusOK {
		t.Fatalf("valid change should be 200, got %d %s", r.Code, r.Body.String())
	}
}

func TestHealthzReadiness(t *testing.T) {
	if r := do(persistentServer(t), "GET", "/healthz", nil); r.Code != http.StatusServiceUnavailable {
		t.Fatalf("locked store healthz should be 503, got %d", r.Code)
	}
	if r := do(newServer("secret"), "GET", "/healthz", nil); r.Code != http.StatusOK {
		t.Fatalf("usable store healthz should be 200, got %d", r.Code)
	}
}

func TestRevealFailsClosedOnAuditError(t *testing.T) {
	srv := newServerAudit("secret", failWriter{})
	id := seed(t, srv)
	lc, lcsrf := loginCSRF(t, srv, "lead", "leadpw")
	openAudit(t, srv, lc, lcsrf, id)
	r := do(srv, "GET", "/api/accounts/alice/secret", lc)
	if r.Code != http.StatusInternalServerError {
		t.Fatalf("reveal with a failing audit log should be 500, got %d", r.Code)
	}
	if strings.Contains(r.Body.String(), "Welcome1") {
		t.Fatal("CLEARTEXT revealed despite the audit write failing")
	}
}

func TestShouldAutoLock(t *testing.T) {
	now := time.Now()
	idle := 30 * time.Minute
	stale := now.Add(-31 * time.Minute)
	fresh := now.Add(-5 * time.Minute)
	if !shouldAutoLock(true, 0, stale, idle, now) {
		t.Fatal("idle + unlocked + no in-flight should auto-lock")
	}
	if shouldAutoLock(true, 1, stale, idle, now) {
		t.Fatal("must not lock while a data request is in flight")
	}
	if shouldAutoLock(false, 0, stale, idle, now) {
		t.Fatal("must not lock when already locked")
	}
	if shouldAutoLock(true, 0, fresh, idle, now) {
		t.Fatal("must not lock before the idle window elapses")
	}
}

func TestExportEndpoints(t *testing.T) {
	srv := newServer("secret")
	id := seed(t, srv)
	lc, lcsrf := loginCSRF(t, srv, "lead", "leadpw")
	openAudit(t, srv, lc, lcsrf, id)
	for _, path := range []string{"/api/export/csv", "/api/export/html"} {
		r := do(srv, "GET", path, lc)
		if r.Code != http.StatusOK {
			t.Fatalf("%s = %d", path, r.Code)
		}
		body := r.Body.String()
		if strings.Contains(body, "Welcome1") {
			t.Fatalf("%s LEAKED cleartext", path)
		}
		if !strings.Contains(body, "alice") {
			t.Fatalf("%s missing data", path)
		}
		if !strings.Contains(r.Header().Get("Content-Disposition"), "attachment") {
			t.Fatalf("%s missing attachment disposition", path)
		}
	}
	if r := do(srv, "GET", "/api/export/csv", nil); r.Code != http.StatusUnauthorized {
		t.Fatalf("export without auth should be 401, got %d", r.Code)
	}
}

func TestDiffEndpoint(t *testing.T) {
	srv := newServer("secret")
	lc, lcsrf := loginCSRF(t, srv, "lead", "leadpw")
	a := createAudit(t, srv, lc, lcsrf, "Engagement A")
	b := createAudit(t, srv, lc, lcsrf, "Engagement B")
	if r := do(srv, "GET", "/api/audits/"+a+"/diff/"+b, lc); r.Code != http.StatusOK || !strings.Contains(r.Body.String(), "posture_a") {
		t.Fatalf("diff = %d %s", r.Code, r.Body.String())
	}
	if r := do(srv, "GET", "/api/audits/nope/diff/"+b, lc); r.Code != http.StatusNotFound {
		t.Fatalf("diff with a missing audit should be 404, got %d", r.Code)
	}
}

func TestAuditsLifecycle(t *testing.T) {
	srv := newServer("secret")

	// no audit selected -> summary/accounts 409
	ac, acsrf := loginCSRF(t, srv, "analyst", "analystpw")
	if rec := do(srv, "GET", "/api/summary", ac); rec.Code != http.StatusConflict {
		t.Fatalf("summary with no audit should be 409, got %d", rec.Code)
	}

	// analyst cannot create
	if rec := sendJSON(srv, "POST", "/api/audits", ac, acsrf, `{"name":"X"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("analyst create should be 403, got %d", rec.Code)
	}

	// lead creates two audits (creating auto-opens the latter for the lead)
	lc, lcsrf := loginCSRF(t, srv, "lead", "leadpw")
	a := createAudit(t, srv, lc, lcsrf, "Engagement A")
	createAudit(t, srv, lc, lcsrf, "Engagement B")
	if rec := do(srv, "GET", "/api/audits", lc); rec.Code != http.StatusOK || strings.Count(rec.Body.String(), `"id"`) != 2 {
		t.Fatalf("list audits = %d %s", rec.Code, rec.Body.String())
	}

	// open A, confirm /me reflects it
	openAudit(t, srv, lc, lcsrf, a)
	if rec := do(srv, "GET", "/api/me", lc); !strings.Contains(rec.Body.String(), `"active_audit":"`+a+`"`) {
		t.Fatalf("/me should show active audit %s: %s", a, rec.Body.String())
	}

	// delete A; the session's active audit is now gone -> summary 409
	if rec := sendJSON(srv, "DELETE", "/api/audits/"+a, lc, lcsrf, ""); rec.Code != http.StatusOK {
		t.Fatalf("delete = %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(srv, "GET", "/api/summary", lc); rec.Code != http.StatusConflict {
		t.Fatalf("summary after deleting active audit should be 409, got %d", rec.Code)
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
