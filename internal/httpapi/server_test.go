package httpapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/watson0x90/PasswordAtTheDisco/internal/audit"
	"github.com/watson0x90/PasswordAtTheDisco/internal/auth"
	"github.com/watson0x90/PasswordAtTheDisco/internal/bloodhound"
	"github.com/watson0x90/PasswordAtTheDisco/internal/engine"
	"github.com/watson0x90/PasswordAtTheDisco/internal/enrich"
	"github.com/watson0x90/PasswordAtTheDisco/internal/hibp"
	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
	"github.com/watson0x90/PasswordAtTheDisco/internal/policy"
	"github.com/watson0x90/PasswordAtTheDisco/internal/pwanalysis"
	"github.com/watson0x90/PasswordAtTheDisco/internal/rescore"
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
		Users: auth.NewUserStore("", auth.Users{
			"lead":    {Username: "lead", PasswordHash: leadHash, Role: auth.RoleLead},
			"analyst": {Username: "analyst", PasswordHash: analystHash, Role: auth.RoleAnalyst},
		}),
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

func TestMeAnonymousIs200(t *testing.T) {
	srv := newServer("secret")
	rr := do(srv, "GET", "/api/me", nil) // no cookie
	if rr.Code != http.StatusOK {
		t.Fatalf("anon /api/me = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"authenticated":false`) {
		t.Fatalf("missing authenticated:false: %s", rr.Body.String())
	}
}

func TestMeAuthenticatedIs200(t *testing.T) {
	srv := newServer("secret")
	cookie, _ := loginCSRF(t, srv, "lead", "leadpw")
	rr := do(srv, "GET", "/api/me", cookie)
	if rr.Code != http.StatusOK {
		t.Fatalf("auth /api/me = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, `"authenticated":true`) {
		t.Fatalf("missing authenticated:true: %s", body)
	}
	if !strings.Contains(body, `"role":"lead"`) {
		t.Fatalf("missing role:lead: %s", body)
	}
}

func TestForbiddenWordsPutGet(t *testing.T) {
	var buf bytes.Buffer
	srv := newServerAudit("secret", &buf)
	srv.Engine = &engine.Engine{Lists: pwanalysis.Lists{ForbiddenWords: pwanalysis.NewSet()}}
	srv.ForbiddenWordsPath = filepath.Join(t.TempDir(), "forbidden_words.txt")

	body := `{"words":["Acme"," summer ","summer",""]}`

	// analyst cannot edit
	ac, acsrf := loginCSRF(t, srv, "analyst", "analystpw")
	if r := sendJSON(srv, "PUT", "/api/forbidden-words", ac, acsrf, body); r.Code != http.StatusForbidden {
		t.Fatalf("analyst PUT should be 403, got %d", r.Code)
	}

	// lead can edit; engine + disk reflect the normalized set
	lc, lcsrf := loginCSRF(t, srv, "lead", "leadpw")
	if r := sendJSON(srv, "PUT", "/api/forbidden-words", lc, lcsrf, body); r.Code != http.StatusOK {
		t.Fatalf("lead PUT = %d %s", r.Code, r.Body.String())
	}
	if got := srv.Engine.ForbiddenWords(); len(got) != 2 { // acme, summer
		t.Fatalf("engine set size = %d (%v)", len(got), got)
	}

	// GET returns sorted, normalized words (lead-only)
	g := do(srv, "GET", "/api/forbidden-words", lc)
	if g.Code != http.StatusOK || !strings.Contains(g.Body.String(), `"acme"`) || !strings.Contains(g.Body.String(), `"summer"`) {
		t.Fatalf("GET = %d body=%s", g.Code, g.Body.String())
	}
	// analyst cannot read
	if g := do(srv, "GET", "/api/forbidden-words", ac); g.Code != http.StatusForbidden {
		t.Fatalf("analyst GET should be 403, got %d", g.Code)
	}

	// Audit log records the update (count only) and never the cleartext words.
	logs := buf.String()
	if !strings.Contains(logs, "forbidden_words_update") || !strings.Contains(logs, "2 word(s)") {
		t.Fatalf("forbidden-words update not audited: %s", logs)
	}
	if strings.Contains(logs, "acme") || strings.Contains(logs, "summer") {
		t.Fatalf("AUDIT LOG LEAKED FORBIDDEN WORDS: %s", logs)
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

func TestRecoverPanic(t *testing.T) {
	// Panic before any write -> clean 500 + inner defer still ran during unwind.
	deferRan := false
	h := recoverPanic(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		defer func() { deferRan = true }()
		panic("boom")
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/x", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("panic-before-write: want 500, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "internal error") {
		t.Fatalf("want error body, got %q", rec.Body.String())
	}
	if !deferRan {
		t.Fatal("inner defer must run during the panic unwind")
	}

	// Write a 200 body THEN panic -> must NOT clobber it with a second body/header.
	h2 := recoverPanic(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
		panic("late")
	}))
	rec2 := httptest.NewRecorder()
	h2.ServeHTTP(rec2, httptest.NewRequest("GET", "/y", nil))
	if rec2.Code != http.StatusOK {
		t.Fatalf("already-written status should stay 200, got %d", rec2.Code)
	}
	if strings.Contains(rec2.Body.String(), "internal error") {
		t.Fatalf("must not append an error body after a write, got %q", rec2.Body.String())
	}
}

func TestRekeyRateLimited(t *testing.T) {
	dir := t.TempDir()
	v, _ := vault.Open(dir)
	st := store.NewPersistent(v)
	if err := st.Initialize("the-real-passphrase-xyz"); err != nil {
		t.Fatal(err)
	}
	srv := newServer("secret")
	srv.Store = st
	srv.RekeyLimiter = auth.NewLimiter(2, time.Minute)
	srv.UnlockLimiter = auth.NewLimiter(2, time.Minute)
	lc, lcsrf := loginCSRF(t, srv, "lead", "leadpw")

	// Happy path returns 200 (and resets the rekey limiter).
	if r := postJSON(srv, "/api/rekey", lc, lcsrf, `{"passphrase":"the-real-passphrase-xyz"}`); r.Code != http.StatusOK {
		t.Fatalf("valid rekey: want 200, got %d (%s)", r.Code, r.Body.String())
	}
	// Two wrong-passphrase attempts -> 401 each (and count against the rekey limiter).
	for i := 0; i < 2; i++ {
		if r := postJSON(srv, "/api/rekey", lc, lcsrf, `{"passphrase":"wrong"}`); r.Code != http.StatusUnauthorized {
			t.Fatalf("wrong-pass attempt %d: want 401, got %d", i, r.Code)
		}
	}
	// Limit reached -> 429.
	if r := postJSON(srv, "/api/rekey", lc, lcsrf, `{"passphrase":"wrong"}`); r.Code != http.StatusTooManyRequests {
		t.Fatalf("want 429 after the rekey limit, got %d", r.Code)
	}
	// The dedicated rekey limiter did NOT consume the unlock budget for the same IP.
	if ok, _ := srv.UnlockLimiter.Allowed("192.0.2.1"); !ok {
		t.Fatal("rekey failures must not lock out unlock (separate limiter)")
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

// The HTML export must render the cross-domain credential-reuse graph — the same
// surface the dashboard shows. The reuse graph is derived from NT-hash reuse
// grouping, so the export handler must feed report.HTML full (non-redacted)
// accounts; report.HTML redacts its own output, so no cleartext or NT hash leaks.
func TestExportHTMLIncludesReuseGraph(t *testing.T) {
	const reusePayload = `{"accounts":[` +
		`{"username":"alice","domain":"CORP","password":"Welcome1","cracked":true,"risk_level":"High","nt_hash":"SHAREDHASH0000000000000000000000"},` +
		`{"username":"bob","domain":"SUB","password":"Welcome1","cracked":true,"risk_level":"High","nt_hash":"SHAREDHASH0000000000000000000000"}]}`

	srv := newServer("secret")
	req := httptest.NewRequest("POST", "/api/ingest", strings.NewReader(reusePayload))
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("ingest failed: %d %s", rec.Code, rec.Body.String())
	}
	var body struct {
		AuditID string `json:"audit_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.AuditID == "" {
		t.Fatalf("ingest response missing audit_id: err=%v body=%s", err, rec.Body.String())
	}

	lc, lcsrf := loginCSRF(t, srv, "lead", "leadpw")
	openAudit(t, srv, lc, lcsrf, body.AuditID)

	r := do(srv, "GET", "/api/export/html", lc)
	if r.Code != http.StatusOK {
		t.Fatalf("export = %d", r.Code)
	}
	out := r.Body.String()

	// Parity: the cross-domain reuse graph card must render (two domains share an NT hash).
	if !strings.Contains(out, "Cross-domain credential reuse") {
		t.Error("HTML export missing cross-domain reuse graph — export must match the dashboard")
	}
	if !strings.Contains(out, "<line ") {
		t.Error("HTML export reuse graph should contain <line> edge elements")
	}
	// Redaction: full accounts flow into report.HTML, but neither the cleartext
	// password nor the NT hash may reach the downloaded file.
	if strings.Contains(out, "Welcome1") {
		t.Error("HTML export LEAKED cleartext password")
	}
	if strings.Contains(out, "SHAREDHASH") {
		t.Error("HTML export LEAKED NT hash")
	}
}

func postJSON(srv *Server, path string, cookie *http.Cookie, csrf, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
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

// TestRekeyEndpoint checks route wiring/role/CSRF (the passphrase + actual key
// rotation are covered by vault.TestRekeyRotatesDataKey; the in-memory test store
// has no vault, so Rekey is a no-op here).
func TestRekeyEndpoint(t *testing.T) {
	srv := newServer("secret")
	id := seed(t, srv)
	lc, lcsrf := loginCSRF(t, srv, "lead", "leadpw")
	openAudit(t, srv, lc, lcsrf, id)

	ac, acsrf := loginCSRF(t, srv, "analyst", "analystpw")
	if r := postJSON(srv, "/api/rekey", ac, acsrf, `{"passphrase":"x"}`); r.Code != http.StatusForbidden {
		t.Fatalf("analyst rekey should be 403, got %d", r.Code)
	}
	if r := postJSON(srv, "/api/rekey", lc, "", `{"passphrase":"x"}`); r.Code != http.StatusForbidden {
		t.Fatalf("rekey without CSRF should be 403, got %d", r.Code)
	}
	if r := postJSON(srv, "/api/rekey", lc, lcsrf, `{"passphrase":"x"}`); r.Code != http.StatusOK {
		t.Fatalf("lead rekey = %d %s", r.Code, r.Body.String())
	}
	if r := do(srv, "GET", "/api/accounts", lc); r.Code != http.StatusOK || !strings.Contains(r.Body.String(), "alice") {
		t.Fatalf("accounts unreadable after rekey: %d %s", r.Code, r.Body.String())
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

	// no audit selected -> summary is an empty 200 (a normal not-yet-started state)
	ac, acsrf := loginCSRF(t, srv, "analyst", "analystpw")
	if rec := do(srv, "GET", "/api/summary", ac); rec.Code != http.StatusOK {
		t.Fatalf("summary with no audit should be 200, got %d", rec.Code)
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

	// delete A; the session's active audit is now gone -> summary is an empty 200
	if rec := sendJSON(srv, "DELETE", "/api/audits/"+a, lc, lcsrf, ""); rec.Code != http.StatusOK {
		t.Fatalf("delete = %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(srv, "GET", "/api/summary", lc); rec.Code != http.StatusOK {
		t.Fatalf("summary after deleting active audit should be 200, got %d", rec.Code)
	}
}

func TestReadEndpointsEmptyWhenNoAudit(t *testing.T) {
	srv := newServer("secret")
	cookie, _ := loginCSRF(t, srv, "lead", "leadpw") // logged in, but no audit opened
	for _, path := range []string{"/api/accounts", "/api/report", "/api/summary"} {
		rr := do(srv, "GET", path, cookie)
		if rr.Code != http.StatusOK {
			t.Errorf("%s status = %d, want 200 (body=%s)", path, rr.Code, rr.Body.String())
		}
		if strings.Contains(rr.Body.String(), "no audit selected") {
			t.Errorf("%s leaked 409 error body: %s", path, rr.Body.String())
		}
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

func authedReq(method, path, body string, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	r.AddCookie(cookie)
	if csrf != "" {
		r.Header.Set("X-CSRF-Token", csrf)
	}
	return r2rec(r)
}

func r2rec(r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	srvForReq.Routes().ServeHTTP(rec, r)
	return rec
}

var srvForReq *Server

func TestUserManagement(t *testing.T) {
	srv := newServer("tok")
	srvForReq = srv
	cookie, csrf := loginCSRF(t, srv, "lead", "leadpw")

	// create a new analyst -> takes effect live (no restart)
	rec := authedReq("POST", "/api/users", `{"username":"newby","password":"newby-pass-1","role":"analyst"}`, cookie, csrf)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create user = %d, want 201 (%s)", rec.Code, rec.Body.String())
	}
	if _, ok := srv.Users.Authenticate("newby", "newby-pass-1"); !ok {
		t.Fatal("new operator cannot authenticate (not live)")
	}

	// self-delete is blocked
	if rec := authedReq("DELETE", "/api/users/lead", "", cookie, csrf); rec.Code != http.StatusBadRequest {
		t.Fatalf("self-delete = %d, want 400", rec.Code)
	}

	// deleting the only lead would be blocked too (409); delete the analyst instead
	if rec := authedReq("DELETE", "/api/users/newby", "", cookie, csrf); rec.Code != http.StatusOK {
		t.Fatalf("delete analyst = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}

	// an analyst may not manage operators
	acookie, acsrf := loginCSRF(t, srv, "analyst", "analystpw")
	if rec := authedReq("GET", "/api/users", "", acookie, acsrf); rec.Code != http.StatusForbidden {
		t.Fatalf("analyst list users = %d, want 403", rec.Code)
	}
}

func TestLoginLockout(t *testing.T) {
	srv := newServer("tok")
	srv.Logins = auth.NewLoginTracker(3, time.Minute, time.Hour)
	srvForReq = srv

	// 3 bad attempts lock the analyst account
	for i := 0; i < 3; i++ {
		if rec := loginAttempt(srv, "analyst", "wrong"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("bad attempt %d = %d, want 401", i, rec.Code)
		}
	}
	// even the correct password is now rejected (locked) -> 429
	if rec := loginAttempt(srv, "analyst", "analystpw"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("locked login = %d, want 429", rec.Code)
	}

	// a lead clears the lockout
	cookie, csrf := loginCSRF(t, srv, "lead", "leadpw")
	if rec := authedReq("POST", "/api/users/analyst/unlock", "", cookie, csrf); rec.Code != http.StatusOK {
		t.Fatalf("unlock = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	// analyst can log in again
	if rec := loginAttempt(srv, "analyst", "analystpw"); rec.Code != http.StatusOK {
		t.Fatalf("post-unlock login = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	// the lead's successful login shows up in recent activity
	rec := authedReq("GET", "/api/login-activity", "", cookie, csrf)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"username":"analyst"`) {
		t.Fatalf("login-activity = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestReportTermsLeadGatedAndAudited(t *testing.T) {
	var buf bytes.Buffer
	srv := newServerAudit("secret", &buf)

	// Create an audit and plant an account with a known BannedWord via the store directly.
	lc, lcsrf := loginCSRF(t, srv, "lead", "leadpw")
	id := createAudit(t, srv, lc, lcsrf, "Terms Test Audit")
	if err := srv.Store.Replace(id, model.Dataset{
		Name: "Terms Test Audit",
		Accounts: []model.Account{
			{
				Username:        "alice",
				Domain:          "CORP",
				Password:        "plantedword123",
				Cracked:         true,
				BannedWords:     []string{"plantedword"},
				BannedWordCount: 1,
				RiskLevel:       "Critical",
			},
		},
	}); err != nil {
		t.Fatalf("seed account: %v", err)
	}

	// 1. Non-lead (analyst) gets 403 and a denied audit event.
	// buf is NOT reset so the denied event accumulates alongside later events.
	ac, acsrf := loginCSRF(t, srv, "analyst", "analystpw")
	openAudit(t, srv, ac, acsrf, id)
	buf.Reset()
	rec := do(srv, "GET", "/api/report/terms", ac)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("analyst /api/report/terms: want 403, got %d (%s)", rec.Code, rec.Body.String())
	}
	// 403 body must not expose the planted term (cleartext-free denied response).
	if strings.Contains(rec.Body.String(), "plantedword") {
		t.Fatalf("403 response body LEAKED cleartext fragment 'plantedword': %s", rec.Body.String())
	}
	deniedLog := buf.String()
	if !strings.Contains(deniedLog, "reveal_violation_terms") {
		t.Fatalf("denied call not audit-logged (want reveal_violation_terms): %s", deniedLog)
	}
	if !strings.Contains(deniedLog, `"result":"denied"`) {
		t.Fatalf("denied audit event missing result=denied: %s", deniedLog)
	}

	// 2. Lead gets 200 with plantedword in the body and an ok audit event.
	// Do NOT reset buf — accumulate denied + ok events so assertion 4 covers both.
	rec = do(srv, "GET", "/api/report/terms", lc)
	if rec.Code != http.StatusOK {
		t.Fatalf("lead /api/report/terms: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "plantedword") {
		t.Fatalf("/api/report/terms body should contain plantedword, got: %s", body)
	}
	allLogs := buf.String()
	if !strings.Contains(allLogs, "reveal_violation_terms") {
		t.Fatalf("ok call not audit-logged (want reveal_violation_terms): %s", allLogs)
	}
	if !strings.Contains(allLogs, `"result":"ok"`) {
		t.Fatalf("ok audit event missing result=ok: %s", allLogs)
	}

	// 3. GET /api/report (as lead) must NOT expose plantedword.
	reportRec := do(srv, "GET", "/api/report", lc)
	if reportRec.Code != http.StatusOK {
		t.Fatalf("/api/report: want 200, got %d", reportRec.Code)
	}
	if strings.Contains(reportRec.Body.String(), "plantedword") {
		t.Fatalf("/api/report LEAKED matched word 'plantedword' — must be redacted")
	}

	// 4. The audit log (covering both denied and ok paths) must never contain the
	// matched word — plantedword is a cleartext fragment and must never be logged.
	if strings.Contains(allLogs, "plantedword") {
		t.Fatalf("AUDIT LOG LEAKED cleartext fragment 'plantedword': %s", allLogs)
	}
}

func TestBHEConfig(t *testing.T) {
	srv := newServer("tok")
	srvForReq = srv
	srv.BHEPath = filepath.Join(t.TempDir(), "bloodhound.json")
	if err := bloodhound.SaveConfig(srv.BHEPath, bloodhound.Config{Scheme: "http", Host: "10.0.0.1", Port: 8080, TokenID: "tid-xyz", TokenKey: "tkey-secret"}); err != nil {
		t.Fatal(err)
	}
	cookie, csrf := loginCSRF(t, srv, "lead", "leadpw")

	// status must not leak the token, but reports it's configured
	rec := authedReq("GET", "/api/bhe/status", "", cookie, csrf)
	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if strings.Contains(body, "tkey-secret") || strings.Contains(body, "tid-xyz") {
		t.Fatalf("status leaked the token: %s", body)
	}
	if !strings.Contains(body, `"token_configured":true`) {
		t.Fatalf("status should report token configured: %s", body)
	}

	// saving with a new host + BLANK token preserves the stored token
	rec = authedReq("PUT", "/api/bhe/config", `{"scheme":"https","host":"10.0.0.9","port":443}`, cookie, csrf)
	if rec.Code != http.StatusOK {
		t.Fatalf("config save = %d (%s)", rec.Code, rec.Body.String())
	}
	saved, _ := bloodhound.LoadConfig(srv.BHEPath)
	if saved.Host != "10.0.0.9" || saved.TokenID != "tid-xyz" || saved.TokenKey != "tkey-secret" {
		t.Fatalf("save should update host but keep the token, got %+v", saved)
	}

	// analyst is forbidden
	acook, acsrf := loginCSRF(t, srv, "analyst", "analystpw")
	if rec := authedReq("GET", "/api/bhe/status", "", acook, acsrf); rec.Code != http.StatusForbidden {
		t.Fatalf("analyst status = %d, want 403", rec.Code)
	}
}

func TestIngestsEndpoint(t *testing.T) {
	srv := newServer("secret")

	// Create an audit via the lead session, then seed an ingest event directly into
	// the store (mirrors how TestReportTermsLeadGatedAndAudited seeds data).
	lc, lcsrf := loginCSRF(t, srv, "lead", "leadpw")
	id := createAudit(t, srv, lc, lcsrf, "Ingest History Test")
	if err := srv.Store.RecordIngest(id, model.IngestEvent{
		Filename:       "x.pwdump",
		Kind:           "dump",
		Domain:         "CORP",
		AccountsLoaded: 3,
		By:             "watson",
	}); err != nil {
		t.Fatalf("seed RecordIngest: %v", err)
	}

	// 1. Lead GET /api/ingests with the audit open -> 200 containing the filename.
	rec := do(srv, "GET", "/api/ingests", lc)
	if rec.Code != http.StatusOK {
		t.Fatalf("lead /api/ingests: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "x.pwdump") {
		t.Fatalf("/api/ingests body should contain x.pwdump, got: %s", body)
	}

	// 2. Non-lead (analyst) GET /api/ingests -> 403.
	ac, acsrf := loginCSRF(t, srv, "analyst", "analystpw")
	openAudit(t, srv, ac, acsrf, id)
	if rec := do(srv, "GET", "/api/ingests", ac); rec.Code != http.StatusForbidden {
		t.Fatalf("analyst /api/ingests: want 403, got %d", rec.Code)
	}

	// 3. Lead response body must not contain password or nt_hash fields.
	if strings.Contains(body, "password") || strings.Contains(body, "nt_hash") {
		t.Fatalf("/api/ingests LEAKED secret fields: %s", body)
	}
}

// uploadReq builds a multipart POST to /api/upload. domainFirst controls whether
// the domain field is written before or after the file part (the streaming handler
// requires domain-first).
func uploadReq(t *testing.T, cookie *http.Cookie, csrf string, domainFirst bool) *http.Request {
	t.Helper()
	const line = "WALTER@CORP:1119:aad3b435b51404eeaad3b435b51404ee:0011CA32824670FF94EF25961895BE37:::\n"
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if domainFirst {
		_ = mw.WriteField("domain", "CORP")
	}
	fw, _ := mw.CreateFormFile("uncracked", "ntds.pwdump")
	_, _ = io.WriteString(fw, line)
	if !domainFirst {
		_ = mw.WriteField("domain", "CORP")
	}
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

// cracksReq builds a multipart POST to /api/upload/cracks with a single
// "crackfile" part named filename containing body.
func cracksReq(t *testing.T, cookie *http.Cookie, csrf, filename, body string) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("crackfile", filename)
	_, _ = io.WriteString(fw, body)
	_ = mw.Close()
	req := httptest.NewRequest("POST", "/api/upload/cracks", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	if cookie != nil {
		req.AddCookie(cookie)
	}
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	return req
}

func TestApplyCracksRecordsIngest(t *testing.T) {
	const ntHash = "0011CA32824670FF94EF25961895BE37"
	const crackLine = "WALTER@CORP:1119:aad3b435b51404eeaad3b435b51404ee:" + ntHash + ":::Hannah2021!\n"

	srv := newServer("secret")
	srv.Engine = &engine.Engine{Policies: policy.DefaultSet()}
	lc, lcsrf := loginCSRF(t, srv, "lead", "leadpw")
	id := createAudit(t, srv, lc, lcsrf, "Crack Test") // auto-opens for the lead

	// Seed the audit with an uncracked account that carries the NT hash we'll crack.
	if err := srv.Store.Replace(id, model.Dataset{
		Name: "Crack Test",
		Accounts: []model.Account{
			{Username: "WALTER", Domain: "CORP", NTHash: ntHash},
		},
	}); err != nil {
		t.Fatalf("seed Replace: %v", err)
	}

	// POST the crackfile.
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, cracksReq(t, lc, lcsrf, "crack.potfile", crackLine))
	if rec.Code != http.StatusOK {
		t.Fatalf("apply cracks: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	var result struct {
		NewlyCracked int `json:"newly_cracked"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil || result.NewlyCracked < 1 {
		t.Fatalf("apply cracks body: %v / %s", err, rec.Body.String())
	}

	// Verify a "cracks" ingest event was recorded with the correct filename.
	ingestsRec := do(srv, "GET", "/api/ingests", lc)
	if ingestsRec.Code != http.StatusOK {
		t.Fatalf("GET /api/ingests: want 200, got %d (%s)", ingestsRec.Code, ingestsRec.Body.String())
	}
	ingestsBody := ingestsRec.Body.String()
	if !strings.Contains(ingestsBody, `"kind":"cracks"`) {
		t.Fatalf("/api/ingests should contain kind=cracks, got: %s", ingestsBody)
	}
	if !strings.Contains(ingestsBody, "crack.potfile") {
		t.Fatalf("/api/ingests should contain filename crack.potfile, got: %s", ingestsBody)
	}
}

func TestUploadStreamsAndRecordsIngest(t *testing.T) {
	// Case 1: domain field BEFORE the file part -> 200 + ingest event recorded.
	srv := newServer("secret")
	srv.Engine = &engine.Engine{Policies: policy.DefaultSet()}
	lc, lcsrf := loginCSRF(t, srv, "lead", "leadpw")
	createAudit(t, srv, lc, lcsrf, "Stream Test") // auto-opens for the lead

	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, uploadReq(t, lc, lcsrf, true))
	if rec.Code != http.StatusOK {
		t.Fatalf("domain-first upload: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	var result struct {
		Accounts int `json:"accounts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil || result.Accounts < 1 {
		t.Fatalf("domain-first upload body: %v / %s", err, rec.Body.String())
	}

	// Verify an ingest event was recorded with kind=="dump" and the correct filename.
	ingestsRec := do(srv, "GET", "/api/ingests", lc)
	if ingestsRec.Code != http.StatusOK {
		t.Fatalf("GET /api/ingests: want 200, got %d (%s)", ingestsRec.Code, ingestsRec.Body.String())
	}
	ingestsBody := ingestsRec.Body.String()
	if !strings.Contains(ingestsBody, `"kind":"dump"`) {
		t.Fatalf("/api/ingests should contain kind=dump, got: %s", ingestsBody)
	}
	if !strings.Contains(ingestsBody, "ntds.pwdump") {
		t.Fatalf("/api/ingests should contain filename ntds.pwdump, got: %s", ingestsBody)
	}

	// Case 2: file part BEFORE the domain field -> 400 (streaming contract violation).
	srv2 := newServer("secret")
	srv2.Engine = &engine.Engine{Policies: policy.DefaultSet()}
	lc2, lcsrf2 := loginCSRF(t, srv2, "lead", "leadpw")
	createAudit(t, srv2, lc2, lcsrf2, "Stream Test 2")

	rec2 := httptest.NewRecorder()
	srv2.Routes().ServeHTTP(rec2, uploadReq(t, lc2, lcsrf2, false))
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("file-before-domain upload: want 400, got %d (%s)", rec2.Code, rec2.Body.String())
	}
	if !strings.Contains(rec2.Body.String(), "domain field must be sent before") {
		t.Fatalf("expected domain-ordering error, got: %s", rec2.Body.String())
	}
}

// fakeTestEnricher is a trivial engine.Enricher for httpapi tests.
type fakeTestEnricher struct{}

func (fakeTestEnricher) Enrich(username string) engine.Enrichment {
	return engine.Enrichment{DADomains: []string{"CORP"}}
}

// countingTestEnricher counts how many times Enrich has been called across all goroutines.
type countingTestEnricher struct {
	mu    sync.Mutex
	calls int
}

func (c *countingTestEnricher) Enrich(username string) engine.Enrichment {
	c.mu.Lock()
	c.calls++
	c.mu.Unlock()
	return engine.Enrichment{DADomains: []string{"CORP"}}
}

func (c *countingTestEnricher) Calls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

func TestAutoEnrichOnlyOnFirstData(t *testing.T) {
	// Build an engine with a counting enricher so we can verify call counts.
	eng := &engine.Engine{Policies: policy.DefaultSet()}
	counter := &countingTestEnricher{}
	eng.SwapEnricher(counter)
	st := store.New()
	srv := &Server{
		Store:        st,
		IngestToken:  "secret",
		Engine:       eng,
		Enrich:       enrich.NewManager(eng, st),
		Users:        newServer("secret").Users,
		Sessions:     auth.NewSessionStore(time.Hour, time.Hour),
		Audit:        audit.New(io.Discard),
		LoginLimiter: auth.NewLimiter(50, time.Minute),
	}

	lc, lcsrf := loginCSRF(t, srv, "lead", "leadpw")
	// Create an empty audit (auto-opens for the lead session).
	createAudit(t, srv, lc, lcsrf, "AutoEnrich Test")

	const crackBody = "alice:1001:aad3b435b51404eeaad3b435b51404ee:NTLMHASHVALUE:::Welcome1\n"

	// First upload to the EMPTY audit — should auto-kick enrichment.
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, auditReq(t, lc, lcsrf, "CORP", crackBody))
	if rec.Code != http.StatusOK {
		t.Fatalf("first upload: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	srv.Enrich.Wait()
	callsAfterFirst := counter.Calls()
	if callsAfterFirst == 0 {
		t.Fatal("enricher should have been called after the first (empty-audit) upload")
	}

	// Second upload (different domain) — the audit is non-empty now; should NOT auto-kick.
	rec2 := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec2, auditReq(t, lc, lcsrf, "EU", crackBody))
	if rec2.Code != http.StatusOK {
		t.Fatalf("second upload: want 200, got %d (%s)", rec2.Code, rec2.Body.String())
	}
	srv.Enrich.Wait()
	callsAfterSecond := counter.Calls()
	if callsAfterSecond != callsAfterFirst {
		t.Fatalf("enricher should NOT be called again after a second upload; calls before=%d after=%d",
			callsAfterFirst, callsAfterSecond)
	}
}

func TestEnrichEndpoints(t *testing.T) {
	// Build a server with an engine that has an enricher and an enrich.Manager.
	eng := &engine.Engine{Policies: policy.DefaultSet()}
	eng.SwapEnricher(fakeTestEnricher{})
	st := store.New()
	srv := &Server{
		Store:        st,
		IngestToken:  "secret",
		Engine:       eng,
		Enrich:       enrich.NewManager(eng, st),
		Users:        newServer("secret").Users,
		Sessions:     auth.NewSessionStore(time.Hour, time.Hour),
		Audit:        audit.New(io.Discard),
		LoginLimiter: auth.NewLimiter(50, time.Minute),
	}

	// Seed an audit with at least one account so the job has work.
	lc, lcsrf := loginCSRF(t, srv, "lead", "leadpw")
	id := createAudit(t, srv, lc, lcsrf, "Enrich Test")
	if err := srv.Store.Replace(id, model.Dataset{
		Name: "Enrich Test",
		Accounts: []model.Account{
			{Username: "alice", Domain: "CORP", NTHash: "AAAA", Cracked: true, Password: "Welcome1"},
		},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	ac, acsrf := loginCSRF(t, srv, "analyst", "analystpw")
	openAudit(t, srv, ac, acsrf, id)

	// (a) POST /api/enrich as analyst -> 403.
	if r := postJSON(srv, "/api/enrich", ac, acsrf, ""); r.Code != http.StatusForbidden {
		t.Fatalf("analyst POST /api/enrich: want 403, got %d (%s)", r.Code, r.Body.String())
	}

	// (b) POST /api/enrich as lead -> 200, response contains "phase".
	r := postJSON(srv, "/api/enrich", lc, lcsrf, "")
	if r.Code != http.StatusOK {
		t.Fatalf("lead POST /api/enrich: want 200, got %d (%s)", r.Code, r.Body.String())
	}
	if !strings.Contains(r.Body.String(), `"phase"`) {
		t.Fatalf("POST /api/enrich response should contain phase, got: %s", r.Body.String())
	}

	// Wait for the async job to finish before checking GET.
	srv.Enrich.Wait()

	// (c) GET /api/enrich/job -> 200 with "phase".
	gr := do(srv, "GET", "/api/enrich/job", lc)
	if gr.Code != http.StatusOK {
		t.Fatalf("GET /api/enrich/job: want 200, got %d (%s)", gr.Code, gr.Body.String())
	}
	if !strings.Contains(gr.Body.String(), `"phase"`) {
		t.Fatalf("GET /api/enrich/job response should contain phase, got: %s", gr.Body.String())
	}
}

func TestEnrichJobAnalystForbidden(t *testing.T) {
	srv := newServer("secret")
	srv.Engine = &engine.Engine{Policies: policy.DefaultSet()}
	srv.Engine.SwapEnricher(fakeTestEnricher{})
	srv.Enrich = enrich.NewManager(srv.Engine, srv.Store)

	lc, lcsrf := loginCSRF(t, srv, "lead", "leadpw")
	id := createAudit(t, srv, lc, lcsrf, "Enrich Test 2")
	ac, acsrf := loginCSRF(t, srv, "analyst", "analystpw")
	openAudit(t, srv, ac, acsrf, id)

	if r := do(srv, "GET", "/api/enrich/job", ac); r.Code != http.StatusForbidden {
		t.Fatalf("analyst GET /api/enrich/job: want 403, got %d", r.Code)
	}
	if r := postJSON(srv, "/api/enrich/cancel", ac, acsrf, ""); r.Code != http.StatusForbidden {
		t.Fatalf("analyst POST /api/enrich/cancel: want 403, got %d", r.Code)
	}
}

// gatedEnricher blocks each Enrich call until the gate channel is closed,
// allowing tests to hold a job in-flight before cancelling it.
type gatedEnricher struct {
	gate  chan struct{}
	inner engine.Enricher
}

func (g gatedEnricher) Enrich(username string) engine.Enrichment {
	<-g.gate
	return g.inner.Enrich(username)
}

func newEnrichServer(t *testing.T) (*Server, *http.Cookie, string, string) {
	t.Helper()
	eng := &engine.Engine{Policies: policy.DefaultSet()}
	eng.SwapEnricher(fakeTestEnricher{})
	st := store.New()
	srv := &Server{
		Store:        st,
		IngestToken:  "secret",
		Engine:       eng,
		Enrich:       enrich.NewManager(eng, st),
		Users:        newServer("secret").Users,
		Sessions:     auth.NewSessionStore(time.Hour, time.Hour),
		Audit:        audit.New(io.Discard),
		LoginLimiter: auth.NewLimiter(50, time.Minute),
	}
	lc, lcsrf := loginCSRF(t, srv, "lead", "leadpw")
	id := createAudit(t, srv, lc, lcsrf, "Cancel Test")
	if err := srv.Store.Replace(id, model.Dataset{
		Name: "Cancel Test",
		Accounts: []model.Account{
			{Username: "alice", Domain: "CORP", NTHash: "AAAA", Cracked: true, Password: "Welcome1"},
		},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	return srv, lc, lcsrf, id
}

func TestEnrichCancelNoJob(t *testing.T) {
	// Cancel when no job is running -> 409.
	srv, lc, lcsrf, _ := newEnrichServer(t)
	r := postJSON(srv, "/api/enrich/cancel", lc, lcsrf, "")
	if r.Code != http.StatusConflict {
		t.Fatalf("cancel with no job: want 409, got %d (%s)", r.Code, r.Body.String())
	}
	if !strings.Contains(r.Body.String(), `"phase"`) && !strings.Contains(r.Body.String(), "error") {
		t.Fatalf("cancel 409 response should contain error, got: %s", r.Body.String())
	}
}

func TestEnrichCancelRunningJob(t *testing.T) {
	// Start a gated enricher so the job is definitely still running when we cancel.
	gate := make(chan struct{})
	eng := &engine.Engine{Policies: policy.DefaultSet()}
	eng.SwapEnricher(gatedEnricher{gate: gate, inner: fakeTestEnricher{}})
	st := store.New()
	srv := &Server{
		Store:        st,
		IngestToken:  "secret",
		Engine:       eng,
		Enrich:       enrich.NewManager(eng, st),
		Users:        newServer("secret").Users,
		Sessions:     auth.NewSessionStore(time.Hour, time.Hour),
		Audit:        audit.New(io.Discard),
		LoginLimiter: auth.NewLimiter(50, time.Minute),
	}
	lc, lcsrf := loginCSRF(t, srv, "lead", "leadpw")
	id := createAudit(t, srv, lc, lcsrf, "Cancel Running Test")
	if err := srv.Store.Replace(id, model.Dataset{
		Name: "Cancel Running Test",
		Accounts: []model.Account{
			{Username: "alice", Domain: "CORP", NTHash: "AAAA", Cracked: true, Password: "Welcome1"},
		},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Start the job (gate blocks the enricher so it stays in PhaseRunning).
	startR := postJSON(srv, "/api/enrich", lc, lcsrf, "")
	if startR.Code != http.StatusOK {
		t.Fatalf("POST /api/enrich: want 200, got %d (%s)", startR.Code, startR.Body.String())
	}

	// Cancel while the job is still gated — must get 200 (deterministic).
	cancelR := postJSON(srv, "/api/enrich/cancel", lc, lcsrf, "")
	if cancelR.Code != http.StatusOK {
		t.Fatalf("cancel running job: want 200, got %d (%s)", cancelR.Code, cancelR.Body.String())
	}
	if !strings.Contains(cancelR.Body.String(), `"phase"`) {
		t.Fatalf("cancel 200 response should contain phase, got: %s", cancelR.Body.String())
	}

	// Release the gate and drain the goroutine to avoid a leak into other tests.
	close(gate)
	srv.Enrich.Wait()
}

func TestHoldReleaseActivity(t *testing.T) {
	srv := newServer("secret")
	now := time.Now()
	idle := 30 * time.Minute
	stale := now.Add(-31 * time.Minute)

	// Before HoldActivity: stale + unlocked + no in-flight -> should auto-lock.
	if !shouldAutoLock(true, srv.inFlight.Load(), stale, idle, now) {
		t.Fatal("before hold: should auto-lock with stale activity")
	}

	// After HoldActivity: inFlight > 0 -> must NOT auto-lock.
	srv.HoldActivity()
	if shouldAutoLock(true, srv.inFlight.Load(), stale, idle, now) {
		t.Fatal("after HoldActivity: must not auto-lock while held")
	}

	// After ReleaseActivity: inFlight back to 0 -> should auto-lock again.
	srv.ReleaseActivity()
	if !shouldAutoLock(true, srv.inFlight.Load(), stale, idle, now) {
		t.Fatal("after ReleaseActivity: should auto-lock again")
	}
}

func TestHandleVersionReportsBuild(t *testing.T) {
	s := &Server{Build: BuildInfo{Version: "v9.9.9", Commit: "abc1234", BuildDate: "2026-06-17T12:00:00Z"}}
	rec := httptest.NewRecorder()
	s.handleVersion(rec, httptest.NewRequest("GET", "/api/version", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"passwordatthedisco-api", "v9.9.9", "abc1234", "2026-06-17T12:00:00Z"} {
		if !strings.Contains(body, want) {
			t.Fatalf("version body %q missing %q", body, want)
		}
	}
}

func TestHandleVersionDefaultsWhenUnstamped(t *testing.T) {
	s := &Server{} // no Build injected (e.g. `go run`)
	rec := httptest.NewRecorder()
	s.handleVersion(rec, httptest.NewRequest("GET", "/api/version", nil))
	if !strings.Contains(rec.Body.String(), `"version":"dev"`) {
		t.Fatalf("expected dev default, got %s", rec.Body.String())
	}
}

func TestDeleteDomain(t *testing.T) {
	srv := newServer("secret")
	lc, lcsrf := loginCSRF(t, srv, "lead", "leadpw")
	id := createAudit(t, srv, lc, lcsrf, "Delete Domain Test")

	// Seed domain A (3 accounts) and domain B (2 accounts) directly into the store.
	if err := srv.Store.ReplaceDomain(id, "CORP_A", []model.Account{
		{Username: "alice", Domain: "CORP_A"},
		{Username: "bob", Domain: "CORP_A"},
		{Username: "carol", Domain: "CORP_A"},
	}); err != nil {
		t.Fatalf("seed CORP_A: %v", err)
	}
	if err := srv.Store.ReplaceDomain(id, "CORP_B", []model.Account{
		{Username: "dave", Domain: "CORP_B"},
		{Username: "eve", Domain: "CORP_B"},
	}); err != nil {
		t.Fatalf("seed CORP_B: %v", err)
	}

	// Analyst DELETE /api/domains/CORP_A -> 403.
	ac, acsrf := loginCSRF(t, srv, "analyst", "analystpw")
	openAudit(t, srv, ac, acsrf, id)
	req := httptest.NewRequest("DELETE", "/api/domains/CORP_A", nil)
	req.AddCookie(ac)
	req.Header.Set("X-CSRF-Token", acsrf)
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("analyst DELETE /api/domains/CORP_A: want 403, got %d (%s)", rec.Code, rec.Body.String())
	}

	// Lead DELETE /api/domains/CORP_A -> 200.
	req2 := httptest.NewRequest("DELETE", "/api/domains/CORP_A", nil)
	req2.AddCookie(lc)
	req2.Header.Set("X-CSRF-Token", lcsrf)
	rec2 := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("lead DELETE /api/domains/CORP_A: want 200, got %d (%s)", rec2.Code, rec2.Body.String())
	}
	var result struct {
		Removed int `json:"removed"`
	}
	if err := json.Unmarshal(rec2.Body.Bytes(), &result); err != nil || result.Removed != 3 {
		t.Fatalf("delete response: err=%v body=%s (want removed=3)", err, rec2.Body.String())
	}

	// CORP_A accounts are gone; CORP_B's 2 remain.
	accts, err := srv.Store.Accounts(id, false)
	if err != nil {
		t.Fatalf("Accounts after delete: %v", err)
	}
	for _, a := range accts {
		if a.Domain == "CORP_A" {
			t.Fatalf("CORP_A account %s still present after delete", a.Username)
		}
	}
	if len(accts) != 2 {
		t.Fatalf("expected 2 CORP_B accounts remaining, got %d", len(accts))
	}

	// A domain_delete ingest event for "CORP_A" was recorded.
	ingests, err := srv.Store.Ingests(id)
	if err != nil {
		t.Fatalf("Ingests: %v", err)
	}
	found := false
	for _, ev := range ingests {
		if ev.Kind == "domain_delete" && ev.Domain == "CORP_A" {
			found = true
			if ev.AccountsLoaded != 3 {
				t.Fatalf("domain_delete ingest event: want accounts_loaded=3, got %d", ev.AccountsLoaded)
			}
			break
		}
	}
	if !found {
		t.Fatalf("no domain_delete ingest event for CORP_A found in: %+v", ingests)
	}
}

func TestAuditAccountsEndpoint(t *testing.T) {
	srv := newServer("secret")
	id := seed(t, srv)
	lc, lcsrf := loginCSRF(t, srv, "lead", "leadpw")
	openAudit(t, srv, lc, lcsrf, id) // unlocks the store for this session
	rr := do(srv, "GET", "/api/audits/"+id+"/accounts", lc)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rr.Code, rr.Body.String())
	}
	// the seeded account username must be present (redacted), no cleartext
	if !strings.Contains(rr.Body.String(), "alice") {
		t.Fatalf("expected seeded account in body: %s", rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "Welcome1") {
		t.Fatalf("LEAKED cleartext in audit-accounts body")
	}
	rr2 := do(srv, "GET", "/api/audits/nope/accounts", lc)
	if rr2.Code != http.StatusOK || strings.TrimSpace(rr2.Body.String()) != "[]" {
		t.Fatalf("unknown id = %d %q, want 200 []", rr2.Code, rr2.Body.String())
	}
}

func TestProbeEndpoint(t *testing.T) {
	var auditBuf bytes.Buffer
	srv := newServerAudit("secret", &auditBuf)

	want := hibp.NTLMHash("Welcome1")
	payload := `{"accounts":[{"username":"alice","domain":"CORP","password":"Welcome1",` +
		`"cracked":true,"risk_level":"Critical","nt_hash":"` + want + `"}]}`
	ireq := httptest.NewRequest("POST", "/api/ingest", strings.NewReader(payload))
	ireq.Header.Set("Authorization", "Bearer secret")
	irec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(irec, ireq)
	if irec.Code != http.StatusOK {
		t.Fatalf("ingest: %d %s", irec.Code, irec.Body.String())
	}
	var ing struct {
		AuditID string `json:"audit_id"`
	}
	_ = json.Unmarshal(irec.Body.Bytes(), &ing)

	cookie, csrf := loginCSRF(t, srv, "lead", "leadpw")
	openAudit(t, srv, cookie, csrf, ing.AuditID)

	probe := func(pw string) *httptest.ResponseRecorder {
		body := `{"password":` + strconv.Quote(pw) + `}`
		req := httptest.NewRequest("POST", "/api/probe", strings.NewReader(body))
		req.AddCookie(cookie)
		req.Header.Set("X-CSRF-Token", csrf)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		srv.Routes().ServeHTTP(rec, req)
		return rec
	}

	rec := probe("Welcome1")
	if rec.Code != http.StatusOK {
		t.Fatalf("probe match: %d %s", rec.Code, rec.Body.String())
	}
	bodyStr := rec.Body.String()
	if !strings.Contains(bodyStr, `"count":1`) || !strings.Contains(bodyStr, "alice") {
		t.Errorf("expected one match for alice, got %s", bodyStr)
	}
	if strings.Contains(bodyStr, "Welcome1") || strings.Contains(strings.ToLower(bodyStr), "nt_hash") {
		t.Errorf("probe response leaked a secret: %s", bodyStr)
	}

	rec = probe("nope-not-it")
	if !strings.Contains(rec.Body.String(), `"count":0`) {
		t.Errorf("expected count 0, got %s", rec.Body.String())
	}

	if rec := probe(""); rec.Code != http.StatusBadRequest {
		t.Errorf("empty probe: want 400, got %d", rec.Code)
	}

	al := auditBuf.String()
	if !strings.Contains(al, "password_probe") {
		t.Errorf("audit log missing password_probe: %s", al)
	}
	if strings.Contains(al, "Welcome1") {
		t.Errorf("audit log leaked the candidate password: %s", al)
	}
}

func TestRevealDomainAware(t *testing.T) {
	var auditBuf bytes.Buffer
	srv := newServerAudit("secret", &auditBuf)

	payload := `{"accounts":[` +
		`{"username":"svc","domain":"CORP","password":"AlphaPass1","cracked":true,"nt_hash":"AAAA","risk_level":"High"},` +
		`{"username":"svc","domain":"GHOST","password":"BetaPass2","cracked":true,"nt_hash":"BBBB","risk_level":"High"},` +
		`{"username":"u@CORP","domain":"CORP","password":"GammaPass3","cracked":true,"nt_hash":"CCCC","risk_level":"High"}]}`
	ireq := httptest.NewRequest("POST", "/api/ingest", strings.NewReader(payload))
	ireq.Header.Set("Authorization", "Bearer secret")
	irec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(irec, ireq)
	if irec.Code != http.StatusOK {
		t.Fatalf("ingest: %d %s", irec.Code, irec.Body.String())
	}
	var ing struct {
		AuditID string `json:"audit_id"`
	}
	_ = json.Unmarshal(irec.Body.Bytes(), &ing)

	lc, lcsrf := loginCSRF(t, srv, "lead", "leadpw")
	openAudit(t, srv, lc, lcsrf, ing.AuditID)

	get := func(path string, cookie *http.Cookie) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", path, nil)
		if cookie != nil {
			req.AddCookie(cookie)
		}
		rec := httptest.NewRecorder()
		srv.Routes().ServeHTTP(rec, req)
		return rec
	}

	if rec := get("/api/accounts/svc/secret?domain=GHOST", lc); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "BetaPass2") || strings.Contains(rec.Body.String(), "AlphaPass1") {
		t.Errorf("reveal GHOST: %d %s", rec.Code, rec.Body.String())
	}
	if rec := get("/api/accounts/svc/secret?domain=CORP", lc); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "AlphaPass1") {
		t.Errorf("reveal CORP: %d %s", rec.Code, rec.Body.String())
	}
	if rec := get("/api/accounts/svc/secret", lc); rec.Code != http.StatusOK {
		t.Errorf("reveal no-domain: %d %s", rec.Code, rec.Body.String())
	}

	ac, acsrf := loginCSRF(t, srv, "analyst", "analystpw")
	openAudit(t, srv, ac, acsrf, ing.AuditID)
	if rec := get("/api/accounts/svc/secret?domain=GHOST", ac); rec.Code != http.StatusForbidden {
		t.Errorf("non-lead reveal: want 403, got %d", rec.Code)
	}

	al := auditBuf.String()
	if !strings.Contains(al, "reveal_secret") || !strings.Contains(al, "svc@GHOST") {
		t.Errorf("audit missing reveal_secret svc@GHOST: %s", al)
	}
	if strings.Contains(al, "BetaPass2") || strings.Contains(al, "AlphaPass1") {
		t.Errorf("audit leaked a password: %s", al)
	}
	if !strings.Contains(al, `"target":"svc@CORP"`) {
		t.Errorf("CORP reveal not audited: %s", al)
	}
	if !strings.Contains(al, `"result":"denied"`) || !strings.Contains(al, `"result":"ok"`) {
		t.Errorf("expected both ok and denied reveal results in audit: %s", al)
	}

	if rec := get("/api/accounts/"+url.PathEscape("u@CORP")+"/secret?domain=CORP", lc); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "GammaPass3") {
		t.Errorf("reveal u@CORP: %d %s", rec.Code, rec.Body.String())
	}
	al2 := auditBuf.String()
	if !strings.Contains(al2, `"target":"u@CORP"`) {
		t.Errorf("at-username target should be u@CORP (not doubled): %s", al2)
	}
	if strings.Contains(al2, "u@CORP@CORP") {
		t.Errorf("audit target double-appended domain: %s", al2)
	}
}

// --- Re-scoring job endpoints (Task 5) ---

func TestRescoreStartRequiresLead(t *testing.T) {
	srv := newServer("secret")
	srv.Engine = &engine.Engine{Policies: policy.DefaultSet()}
	srv.Rescore = rescore.NewManager(srv.Engine, srv.Store)
	// Lead creates+opens an audit; analyst then attempts to start a rescore.
	lc, lcsrf := loginCSRF(t, srv, "lead", "leadpw")
	createAudit(t, srv, lc, lcsrf, "Rescore Lead Gate")
	ac, acsrf := loginCSRF(t, srv, "analyst", "analystpw")
	r := postJSON(srv, "/api/rescore", ac, acsrf, "")
	if r.Code != http.StatusForbidden {
		t.Fatalf("analyst POST /api/rescore: want 403, got %d (%s)", r.Code, r.Body.String())
	}
}

func TestRescoreStartNoAudit(t *testing.T) {
	srv := newServer("secret")
	srv.Engine = &engine.Engine{Policies: policy.DefaultSet()}
	srv.Rescore = rescore.NewManager(srv.Engine, srv.Store)
	// Lead logged in but no audit created/opened -> activeAudit writes 409.
	lc, lcsrf := loginCSRF(t, srv, "lead", "leadpw")
	r := postJSON(srv, "/api/rescore", lc, lcsrf, "")
	if r.Code != http.StatusConflict {
		t.Fatalf("no audit POST /api/rescore: want 409, got %d (%s)", r.Code, r.Body.String())
	}
	if !strings.Contains(r.Body.String(), "no audit selected") {
		t.Fatalf("expected 'no audit selected', got: %s", r.Body.String())
	}
}

func TestRescoreStart409WhenEnrichRunning(t *testing.T) {
	srv := newServer("secret")
	srv.Engine = &engine.Engine{Policies: policy.DefaultSet()}
	srv.Rescore = rescore.NewManager(srv.Engine, srv.Store)
	srv.Enrich = enrich.NewManager(srv.Engine, srv.Store)
	gate := make(chan struct{})
	srv.Enrich.ActivityHook = func() func() {
		<-gate
		return func() {}
	}
	lc, lcsrf := loginCSRF(t, srv, "lead", "leadpw")
	auditID := createAudit(t, srv, lc, lcsrf, "Rescore vs Enrich")

	// Start enrich; its ActivityHook blocks on the gate so Running() stays true.
	if err := srv.Enrich.Start(auditID); err != nil {
		t.Fatalf("enrich start: %v", err)
	}
	if !srv.Enrich.Running() {
		t.Fatal("expected enrich to be running after Start")
	}

	r := postJSON(srv, "/api/rescore", lc, lcsrf, "")
	if r.Code != http.StatusConflict {
		t.Fatalf("rescore while enrich running: want 409, got %d (%s)", r.Code, r.Body.String())
	}
	if !strings.Contains(r.Body.String(), "enrichment in progress") {
		t.Fatalf("expected 'enrichment in progress' error, got: %s", r.Body.String())
	}

	// Release the gate and drain the enrich goroutine to avoid a leak.
	close(gate)
	srv.Enrich.Wait()
}

func TestEnrichStart409WhenRescoreRunning(t *testing.T) {
	srv := newServer("secret")
	srv.Engine = &engine.Engine{Policies: policy.DefaultSet()}
	// handleEnrichStart bails with 503 unless an enricher is configured; swap in a
	// stub so the handler gets PAST the "not configured" check and reaches the new
	// rescore guard.
	srv.Engine.SwapEnricher(fakeTestEnricher{})
	srv.Rescore = rescore.NewManager(srv.Engine, srv.Store)
	srv.Enrich = enrich.NewManager(srv.Engine, srv.Store)
	gate := make(chan struct{})
	srv.Rescore.ActivityHook = func() func() {
		<-gate
		return func() {}
	}
	lc, lcsrf := loginCSRF(t, srv, "lead", "leadpw")
	auditID := createAudit(t, srv, lc, lcsrf, "Enrich vs Rescore")

	// Start rescore; its ActivityHook blocks on the gate so Running() stays true.
	if err := srv.Rescore.Start(auditID); err != nil {
		t.Fatalf("rescore start: %v", err)
	}
	if !srv.Rescore.Running() {
		t.Fatal("expected rescore to be running after Start")
	}

	r := postJSON(srv, "/api/enrich", lc, lcsrf, "")
	if r.Code != http.StatusConflict {
		t.Fatalf("enrich while rescore running: want 409, got %d (%s)", r.Code, r.Body.String())
	}
	if !strings.Contains(r.Body.String(), "re-scoring in progress") {
		t.Fatalf("expected 're-scoring in progress' error, got: %s", r.Body.String())
	}

	// Release the gate and drain the rescore goroutine to avoid a leak.
	close(gate)
	srv.Rescore.Wait()
}

func TestRescoreStartHappyPath(t *testing.T) {
	srv := newServer("secret")
	srv.Engine = &engine.Engine{Policies: policy.DefaultSet()}
	srv.Rescore = rescore.NewManager(srv.Engine, srv.Store)
	lc, lcsrf := loginCSRF(t, srv, "lead", "leadpw")
	auditID := createAudit(t, srv, lc, lcsrf, "Rescore Happy")
	if err := srv.Store.ReplaceDomain(auditID, "CORP", []model.Account{
		{Username: "a", Domain: "CORP", Coverage: "none"},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	r := postJSON(srv, "/api/rescore", lc, lcsrf, "")
	if r.Code != http.StatusOK {
		t.Fatalf("POST /api/rescore: want 200, got %d (%s)", r.Code, r.Body.String())
	}
	srv.Rescore.Wait()

	job := sendJSON(srv, "GET", "/api/rescore/job", lc, lcsrf, "")
	if job.Code != http.StatusOK {
		t.Fatalf("GET /api/rescore/job: want 200, got %d (%s)", job.Code, job.Body.String())
	}
	if !strings.Contains(job.Body.String(), `"phase":"done"`) {
		t.Fatalf("expected phase done, got: %s", job.Body.String())
	}
}

func TestRescoreJobRequiresLead(t *testing.T) {
	srv := newServer("secret")
	srv.Engine = &engine.Engine{Policies: policy.DefaultSet()}
	srv.Rescore = rescore.NewManager(srv.Engine, srv.Store)
	ac, _ := loginCSRF(t, srv, "analyst", "analystpw")
	r := sendJSON(srv, "GET", "/api/rescore/job", ac, "", "")
	if r.Code != http.StatusForbidden {
		t.Fatalf("analyst GET /api/rescore/job: want 403, got %d (%s)", r.Code, r.Body.String())
	}
}

func TestUploadBHEUsersPreservesEnabledWhenAbsent(t *testing.T) {
	srv := newServer("secret")
	srv.Engine = &engine.Engine{Policies: policy.DefaultSet()}
	lc, lcsrf := loginCSRF(t, srv, "lead", "leadpw")
	id := createAudit(t, srv, lc, lcsrf, "BHE Enabled Test")

	// Seed a KNOWN-ENABLED account.
	if err := srv.Store.Replace(id, model.Dataset{
		Name:     "BHE Enabled Test",
		Accounts: []model.Account{{Username: "svc", Domain: "CORP", NTHash: "ABC", Enabled: true}},
	}); err != nil {
		t.Fatalf("seed Replace: %v", err)
	}

	// Upload a users entry that OMITS "enabled".
	body := `[{"username":"svc","domain":"CORP","hasspn":true}]`
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("bheusers", "users.json")
	_, _ = io.WriteString(fw, body)
	_ = mw.Close()
	req := httptest.NewRequest("POST", "/api/upload/bheusers", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.AddCookie(lc)
	req.Header.Set("X-CSRF-Token", lcsrf)

	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("bheusers upload: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	accts, err := srv.Store.Accounts(id, false)
	if err != nil {
		t.Fatalf("read accounts: %v", err)
	}
	if !accts[0].Enabled {
		t.Errorf("Enabled was flipped to false by an export that omitted 'enabled' — must stay true")
	}
}

func TestUploadBHEUsersExplicitFalseDisables(t *testing.T) {
	// The counterpart to the absent case: an explicit "enabled":false MUST disable
	// the account (the merge guard's *imp.Enabled deref flows the real value).
	srv := newServer("secret")
	srv.Engine = &engine.Engine{Policies: policy.DefaultSet()}
	lc, lcsrf := loginCSRF(t, srv, "lead", "leadpw")
	id := createAudit(t, srv, lc, lcsrf, "BHE Disable Test")

	if err := srv.Store.Replace(id, model.Dataset{
		Name:     "BHE Disable Test",
		Accounts: []model.Account{{Username: "svc", Domain: "CORP", NTHash: "ABC", Enabled: true}},
	}); err != nil {
		t.Fatalf("seed Replace: %v", err)
	}

	body := `[{"username":"svc","domain":"CORP","enabled":false}]`
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("bheusers", "users.json")
	_, _ = io.WriteString(fw, body)
	_ = mw.Close()
	req := httptest.NewRequest("POST", "/api/upload/bheusers", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.AddCookie(lc)
	req.Header.Set("X-CSRF-Token", lcsrf)

	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("bheusers upload: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	accts, err := srv.Store.Accounts(id, false)
	if err != nil {
		t.Fatalf("read accounts: %v", err)
	}
	if accts[0].Enabled {
		t.Errorf("explicit enabled=false must disable the account, but Enabled stayed true")
	}
}

func TestUploadBHEUsersMergesRoastable(t *testing.T) {
	srv := newServer("secret")
	srv.Engine = &engine.Engine{Policies: policy.DefaultSet()}
	lc, lcsrf := loginCSRF(t, srv, "lead", "leadpw")
	id := createAudit(t, srv, lc, lcsrf, "BHE Test")

	if err := srv.Store.Replace(id, model.Dataset{
		Name:     "BHE Test",
		Accounts: []model.Account{{Username: "svc", Domain: "CORP", NTHash: "ABC"}},
	}); err != nil {
		t.Fatalf("seed Replace: %v", err)
	}

	body := `[{"username":"svc","domain":"CORP","enabled":true,"hasspn":true,"dontreqpreauth":true}]`
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("bheusers", "users.json")
	_, _ = io.WriteString(fw, body)
	_ = mw.Close()
	req := httptest.NewRequest("POST", "/api/upload/bheusers", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.AddCookie(lc)
	req.Header.Set("X-CSRF-Token", lcsrf)

	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("bheusers upload: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}

	accts, err := srv.Store.Accounts(id, false)
	if err != nil {
		t.Fatalf("read accounts: %v", err)
	}
	if len(accts) != 1 {
		t.Fatalf("want 1 account, got %d", len(accts))
	}
	a := accts[0]
	if a.HasSPN == nil || !*a.HasSPN {
		t.Errorf("HasSPN = %v, want &true", a.HasSPN)
	}
	if a.DontReqPreauth == nil || !*a.DontReqPreauth {
		t.Errorf("DontReqPreauth = %v, want &true", a.DontReqPreauth)
	}
}

func TestExportSanitizedJSON(t *testing.T) {
	srv := newServer("secret")
	srv.Engine = &engine.Engine{Policies: policy.DefaultSet()}
	lc, lcsrf := loginCSRF(t, srv, "lead", "leadpw")
	id := createAudit(t, srv, lc, lcsrf, "Acme Customer Audit") // name carries a "customer"

	if err := srv.Store.Replace(id, model.Dataset{
		Name: "Acme Customer Audit",
		Accounts: []model.Account{
			{Username: "SECRETUSER", Domain: "SECRET.CORP", NTHash: "SECRETHASH", Cracked: true, ExposureScore: 4.3},
		},
	}); err != nil {
		t.Fatalf("seed Replace: %v", err)
	}

	req := httptest.NewRequest("GET", "/api/export/sanitized.json", nil)
	req.AddCookie(lc)
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("sanitized export: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	body := rec.Body.String()
	for _, canary := range []string{"SECRETUSER", "SECRET.CORP", "SECRETHASH", "Acme Customer Audit"} {
		if strings.Contains(body, canary) {
			t.Errorf("LEAK in handler output: %q", canary)
		}
	}
	var rep map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	if _, ok := rep["accounts"]; !ok {
		t.Errorf("missing accounts in output")
	}
}

func TestExportCSVByDomain(t *testing.T) {
	const twoDomainPayload = `{"accounts":[` +
		`{"username":"alice","domain":"CORP","password":"Welcome1","cracked":true,"nt_hash":"AAAA00000000000000000000000000000001"},` +
		`{"username":"bob","domain":"SUB","password":"Spring2024!","cracked":true,"nt_hash":"BBBB00000000000000000000000000000001"}]}`

	srv := newServer("secret")
	req := httptest.NewRequest("POST", "/api/ingest", strings.NewReader(twoDomainPayload))
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("ingest failed: %d %s", rec.Code, rec.Body.String())
	}
	var body struct {
		AuditID string `json:"audit_id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)

	lc, lcsrf := loginCSRF(t, srv, "lead", "leadpw")
	openAudit(t, srv, lc, lcsrf, body.AuditID)

	// CORP-scoped export: alice present, bob absent, header row present, Content-Disposition contains "CORP".
	r := do(srv, "GET", "/api/export/csv?domain=CORP", lc)
	if r.Code != http.StatusOK {
		t.Fatalf("csv domain=CORP = %d %s", r.Code, r.Body.String())
	}
	out := r.Body.String()
	if !strings.Contains(out, "alice") {
		t.Error("CORP CSV should contain alice")
	}
	if strings.Contains(out, "bob") {
		t.Error("CORP CSV should NOT contain bob (SUB user)")
	}
	if !strings.HasPrefix(out, "domain,username,") { // header row check
		t.Error("CORP CSV should start with header row 'domain,username,...'")
	}
	cd := r.Result().Header.Get("Content-Disposition")
	if !strings.Contains(cd, "CORP") {
		t.Errorf("Content-Disposition should contain CORP, got: %s", cd)
	}

	// Unknown domain → 404.
	r2 := do(srv, "GET", "/api/export/csv?domain=NOPE", lc)
	if r2.Code != http.StatusNotFound {
		t.Fatalf("csv domain=NOPE = %d, want 404", r2.Code)
	}

	// No domain param → org-wide: both alice and bob present.
	r3 := do(srv, "GET", "/api/export/csv", lc)
	if r3.Code != http.StatusOK {
		t.Fatalf("csv no domain = %d %s", r3.Code, r3.Body.String())
	}
	out3 := r3.Body.String()
	if !strings.Contains(out3, "alice") || !strings.Contains(out3, "bob") {
		t.Error("org-wide CSV should contain both alice (CORP) and bob (SUB)")
	}
}

func TestExportHTMLByDomain(t *testing.T) {
	const twoDomainPayload = `{"accounts":[` +
		`{"username":"alice","domain":"CORP","password":"Welcome1","cracked":true,"nt_hash":"CCCC00000000000000000000000000000001"},` +
		`{"username":"bob","domain":"SUB","password":"Spring2024!","cracked":true,"nt_hash":"DDDD00000000000000000000000000000001"}]}`

	srv := newServer("secret")
	req := httptest.NewRequest("POST", "/api/ingest", strings.NewReader(twoDomainPayload))
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("ingest failed: %d %s", rec.Code, rec.Body.String())
	}
	var body struct {
		AuditID string `json:"audit_id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)

	lc, lcsrf := loginCSRF(t, srv, "lead", "leadpw")
	openAudit(t, srv, lc, lcsrf, body.AuditID)

	// CORP-scoped HTML: alice present, domain in title, bob absent, Content-Disposition contains "CORP".
	r := do(srv, "GET", "/api/export/html?domain=CORP", lc)
	if r.Code != http.StatusOK {
		t.Fatalf("html domain=CORP = %d %s", r.Code, r.Body.String())
	}
	out := r.Body.String()
	if !strings.Contains(out, "alice") {
		t.Error("CORP HTML should contain alice")
	}
	if !strings.Contains(out, "CORP") {
		t.Error("CORP HTML title/content should reference CORP domain")
	}
	if strings.Contains(out, "bob") {
		t.Error("CORP HTML should NOT contain bob (SUB user)")
	}
	cd := r.Result().Header.Get("Content-Disposition")
	if !strings.Contains(cd, "CORP") {
		t.Errorf("Content-Disposition should contain CORP, got: %s", cd)
	}
	// Redaction: cleartext password and NT hash must never reach the file.
	if strings.Contains(out, "Welcome1") {
		t.Error("HTML export LEAKED cleartext password")
	}
	if strings.Contains(out, "CCCC") {
		t.Error("HTML export LEAKED NT hash")
	}

	// Unknown domain → 404.
	r2 := do(srv, "GET", "/api/export/html?domain=NOPE", lc)
	if r2.Code != http.StatusNotFound {
		t.Fatalf("html domain=NOPE = %d, want 404", r2.Code)
	}

	// No domain param → org-wide: both alice and bob present, no cleartext/NT-hash leak.
	r3 := do(srv, "GET", "/api/export/html", lc)
	if r3.Code != http.StatusOK {
		t.Fatalf("html no domain = %d %s", r3.Code, r3.Body.String())
	}
	out3 := r3.Body.String()
	if !strings.Contains(out3, "alice") || !strings.Contains(out3, "bob") {
		t.Error("org-wide HTML should contain both alice (CORP) and bob (SUB)")
	}
	if strings.Contains(out3, "Welcome1") {
		t.Error("org-wide HTML export LEAKED cleartext password")
	}
	if strings.Contains(out3, "CCCC") {
		t.Error("org-wide HTML export LEAKED NT hash")
	}
}

// cleartextFixture has two domains and a cracked account with a distinctive
// cleartext (Welcome1) and an NT hash, to verify both inclusion and exclusion.
const cleartextFixture = `{"accounts":[` +
	`{"username":"alice","domain":"CORP","password":"Welcome1","cracked":true,"nt_hash":"AAAA0000000000000000000000000077"},` +
	`{"username":"bob","domain":"SUB","password":"Spring2024!","cracked":true,"nt_hash":"BBBB0000000000000000000000000077"}]}`

// ingestAndOpen ingests payload (via the bearer token), opens the resulting audit
// for the given session, and returns the audit ID.
func ingestAndOpen(t *testing.T, srv *Server, payload string, cookie *http.Cookie, csrf string) string {
	t.Helper()
	req := httptest.NewRequest("POST", "/api/ingest", strings.NewReader(payload))
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("ingest: %d %s", rec.Code, rec.Body.String())
	}
	var body struct {
		AuditID string `json:"audit_id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	openAudit(t, srv, cookie, csrf, body.AuditID)
	return body.AuditID
}

// TestExportCleartextCSV covers all gate assertions for POST /api/export/cleartext.csv.
func TestExportCleartextCSV(t *testing.T) {
	var buf bytes.Buffer
	srv := newServerAudit("secret", &buf)
	lc, lcsrf := loginCSRF(t, srv, "lead", "leadpw")
	ingestAndOpen(t, srv, cleartextFixture, lc, lcsrf)

	ac, acsrf := loginCSRF(t, srv, "analyst", "analystpw")
	// analyst needs the audit open so the role check (not no-audit) is hit.
	openAudit(t, srv, ac, acsrf, func() string {
		// read the active audit id from lead's /api/me
		r := do(srv, "GET", "/api/me", lc)
		var m struct {
			ActiveAudit string `json:"active_audit"`
		}
		_ = json.Unmarshal(r.Body.Bytes(), &m)
		return m.ActiveAudit
	}())

	// (1) Analyst → 403, denied audit event, no cleartext in body.
	r := postJSON(srv, "/api/export/cleartext.csv", ac, acsrf, `{"acknowledge":true}`)
	if r.Code != http.StatusForbidden {
		t.Fatalf("analyst should be 403, got %d %s", r.Code, r.Body.String())
	}
	if strings.Contains(r.Body.String(), "Welcome1") {
		t.Fatal("cleartext leaked in denied response body")
	}
	logs := buf.String()
	if !strings.Contains(logs, "export_cleartext") || !strings.Contains(logs, `"result":"denied"`) {
		t.Fatalf("denied audit event missing (want export_cleartext/denied): %s", logs)
	}
	if strings.Contains(logs, "Welcome1") {
		t.Fatalf("AUDIT LOG LEAKED CLEARTEXT after denied: %s", logs)
	}
	// No export_cleartext ok event should exist yet; check per JSON line so
	// unrelated "ok" results (e.g. logins) don't cause a false positive.
	for _, line := range strings.Split(logs, "\n") {
		if strings.Contains(line, "export_cleartext") && strings.Contains(line, `"result":"ok"`) {
			t.Fatalf("export_cleartext ok event must NOT exist after analyst denial: %s", line)
		}
	}

	// (2) Lead without CSRF → 403 (middleware).
	r = postJSON(srv, "/api/export/cleartext.csv", lc, "", `{"acknowledge":true}`)
	if r.Code != http.StatusForbidden {
		t.Fatalf("no CSRF should be 403, got %d", r.Code)
	}

	// (3) Lead with CSRF + no acknowledge → 400.
	r = postJSON(srv, "/api/export/cleartext.csv", lc, lcsrf, `{"acknowledge":false}`)
	if r.Code != http.StatusBadRequest {
		t.Fatalf("no acknowledge should be 400, got %d", r.Code)
	}
	if strings.Contains(r.Body.String(), "Welcome1") {
		t.Fatal("cleartext leaked in 400 response body")
	}

	// (4) Happy path: lead + CSRF + acknowledge → 200.
	buf.Reset()
	r = postJSON(srv, "/api/export/cleartext.csv", lc, lcsrf, `{"acknowledge":true}`)
	if r.Code != http.StatusOK {
		t.Fatalf("happy path should be 200, got %d %s", r.Code, r.Body.String())
	}
	csvBody := r.Body.String()
	if !strings.Contains(csvBody, "Welcome1") {
		t.Fatal("CSV should contain cracked password Welcome1 in password column")
	}
	if strings.Contains(csvBody, "AAAA0000000000000000000000000077") {
		t.Fatal("CSV must NOT contain NT hash")
	}
	cd := r.Result().Header.Get("Content-Disposition")
	if !strings.Contains(cd, "CLEARTEXT") {
		t.Errorf("Content-Disposition should contain CLEARTEXT, got: %s", cd)
	}
	// Audit log: export_cleartext ok + no cleartext.
	logs = buf.String()
	if !strings.Contains(logs, "export_cleartext") || !strings.Contains(logs, `"result":"ok"`) {
		t.Fatalf("export_cleartext ok audit event missing: %s", logs)
	}
	if strings.Contains(logs, "Welcome1") {
		t.Fatalf("AUDIT LOG LEAKED CLEARTEXT PASSWORD: %s", logs)
	}

	// (5) Domain scoping via body: CORP → alice only; unknown domain → 404.
	r = postJSON(srv, "/api/export/cleartext.csv", lc, lcsrf, `{"acknowledge":true,"domain":"CORP"}`)
	if r.Code != http.StatusOK {
		t.Fatalf("domain=CORP should be 200, got %d %s", r.Code, r.Body.String())
	}
	out := r.Body.String()
	if !strings.Contains(out, "alice") {
		t.Error("CORP CSV should contain alice")
	}
	if strings.Contains(out, "bob") {
		t.Error("CORP CSV should NOT contain bob (SUB user)")
	}
	cd = r.Result().Header.Get("Content-Disposition")
	if !strings.Contains(cd, "CLEARTEXT") || !strings.Contains(cd, "CORP") {
		t.Errorf("domain CSV Content-Disposition should contain CLEARTEXT and CORP, got: %s", cd)
	}
	r = postJSON(srv, "/api/export/cleartext.csv", lc, lcsrf, `{"acknowledge":true,"domain":"GHOST"}`)
	if r.Code != http.StatusNotFound {
		t.Fatalf("unknown domain should be 404, got %d", r.Code)
	}
}

// TestExportCleartextHTML covers gate assertions and HTML-specific checks for
// POST /api/export/cleartext.html.
func TestExportCleartextHTML(t *testing.T) {
	var buf bytes.Buffer
	srv := newServerAudit("secret", &buf)
	lc, lcsrf := loginCSRF(t, srv, "lead", "leadpw")
	ingestAndOpen(t, srv, cleartextFixture, lc, lcsrf)

	// (1) Lead + CSRF + acknowledge → 200, HTML has Welcome1 + banner, no NT hash.
	r := postJSON(srv, "/api/export/cleartext.html", lc, lcsrf, `{"acknowledge":true}`)
	if r.Code != http.StatusOK {
		t.Fatalf("html happy path should be 200, got %d %s", r.Code, r.Body.String())
	}
	out := r.Body.String()
	if !strings.Contains(out, "Welcome1") {
		t.Fatal("HTML should contain cracked password Welcome1")
	}
	if strings.Contains(out, "AAAA0000000000000000000000000077") {
		t.Fatal("HTML must NOT contain NT hash")
	}
	if !strings.Contains(out, "CONTAINS CLEARTEXT") {
		t.Fatal("HTML must contain the cleartext warning banner")
	}
	cd := r.Result().Header.Get("Content-Disposition")
	if !strings.Contains(cd, "CLEARTEXT") {
		t.Errorf("Content-Disposition should contain CLEARTEXT, got: %s", cd)
	}
	// Audit log: export_cleartext ok, no cleartext password.
	logs := buf.String()
	if !strings.Contains(logs, "export_cleartext") || !strings.Contains(logs, `"result":"ok"`) {
		t.Fatalf("export_cleartext ok audit event missing: %s", logs)
	}
	if strings.Contains(logs, "Welcome1") {
		t.Fatalf("AUDIT LOG LEAKED CLEARTEXT PASSWORD: %s", logs)
	}

	// (2) Analyst → 403.
	ac, acsrf := loginCSRF(t, srv, "analyst", "analystpw")
	r = postJSON(srv, "/api/export/cleartext.html", ac, acsrf, `{"acknowledge":true}`)
	if r.Code != http.StatusForbidden {
		t.Fatalf("analyst should be 403, got %d", r.Code)
	}

	// (3) No CSRF → 403 (middleware).
	r = postJSON(srv, "/api/export/cleartext.html", lc, "", `{"acknowledge":true}`)
	if r.Code != http.StatusForbidden {
		t.Fatalf("no CSRF should be 403, got %d", r.Code)
	}

	// (4) No acknowledge → 400.
	r = postJSON(srv, "/api/export/cleartext.html", lc, lcsrf, `{"acknowledge":false}`)
	if r.Code != http.StatusBadRequest {
		t.Fatalf("no acknowledge should be 400, got %d", r.Code)
	}
	if strings.Contains(r.Body.String(), "Welcome1") {
		t.Fatal("cleartext leaked in 400 response body")
	}

	// (5) Domain scoping via body.
	r = postJSON(srv, "/api/export/cleartext.html", lc, lcsrf, `{"acknowledge":true,"domain":"CORP"}`)
	if r.Code != http.StatusOK {
		t.Fatalf("domain=CORP HTML should be 200, got %d", r.Code)
	}
	domOut := r.Body.String()
	if !strings.Contains(domOut, "alice") {
		t.Error("CORP HTML should contain alice")
	}
	if strings.Contains(domOut, "bob") {
		t.Error("CORP HTML should NOT contain bob (SUB user)")
	}
	// Unknown domain → 404.
	r = postJSON(srv, "/api/export/cleartext.html", lc, lcsrf, `{"acknowledge":true,"domain":"GHOST"}`)
	if r.Code != http.StatusNotFound {
		t.Fatalf("unknown domain HTML should be 404, got %d", r.Code)
	}
}

// TestExportCleartextFailClosed verifies that a failing audit sink prevents cleartext
// from being emitted for the cleartext CSV endpoint.
func TestExportCleartextFailClosed(t *testing.T) {
	srv := newServerAudit("secret", failWriter{})
	lc, lcsrf := loginCSRF(t, srv, "lead", "leadpw")
	ingestAndOpen(t, srv, cleartextFixture, lc, lcsrf)

	r := postJSON(srv, "/api/export/cleartext.csv", lc, lcsrf, `{"acknowledge":true}`)
	if r.Code != http.StatusInternalServerError {
		t.Fatalf("failing audit sink should yield 500, got %d", r.Code)
	}
	if strings.Contains(r.Body.String(), "Welcome1") {
		t.Fatal("CLEARTEXT emitted despite audit write failure")
	}
}
