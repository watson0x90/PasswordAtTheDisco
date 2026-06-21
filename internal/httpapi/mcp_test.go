package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/watson0x90/PasswordAtTheDisco/internal/audit"
	"github.com/watson0x90/PasswordAtTheDisco/internal/auth"
)

func mcpTestServer(t *testing.T) (*Server, string, string) {
	t.Helper()
	ts := auth.NewTokenStore("", nil)
	analystTok, _, _ := ts.Issue(auth.RoleAnalyst, "analyst-agent", nil)
	leadTok, _, _ := ts.Issue(auth.RoleLead, "lead-agent", nil)
	s := &Server{MCPTokens: ts, MCPLimiter: auth.NewLimiter(20, time.Minute), Audit: audit.New(io.Discard)}
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

func TestWhoamiDisabledWhenNilStore(t *testing.T) {
	s := &Server{} // MCPTokens is nil
	h := s.requireMCPToken(http.HandlerFunc(s.handleMCPWhoami))
	req := httptest.NewRequest("GET", "/api/mcp/whoami", nil)
	req.Header.Set("Authorization", "Bearer patdmcp_anything_here")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestWhoamiRateLimited(t *testing.T) {
	s, _, _ := mcpTestServer(t)
	s.MCPLimiter = auth.NewLimiter(1, time.Minute) // 1 failure allowed
	h := s.requireMCPToken(http.HandlerFunc(s.handleMCPWhoami))
	bad := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/api/mcp/whoami", nil)
		req.Header.Set("Authorization", "Bearer patdmcp_bad_bad")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	bad() // consumes the single allowed failure (401)
	rec := bad()
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("want Retry-After header on 429")
	}
}

func withSession(req *http.Request, role auth.Role) *http.Request {
	sess := auth.Session{Username: "boss", Role: role, CSRF: "x"}
	return req.WithContext(context.WithValue(req.Context(), sessionKey, sess))
}

func TestCreateTokenLeadOnlyReturnsOnce(t *testing.T) {
	s, _, _ := mcpTestServer(t)
	req := withSession(httptest.NewRequest("POST", "/api/mcp/tokens", strings.NewReader(`{"label":"x","role":"analyst"}`)), auth.RoleAnalyst)
	rec := httptest.NewRecorder()
	s.handleCreateMCPToken(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("analyst create status = %d, want 403", rec.Code)
	}
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
	if strings.Contains(rec.Body.String(), `"token"`) {
		t.Fatal("token list leaked the full token field")
	}
}

func TestListTokensAnalystForbidden(t *testing.T) {
	s, _, _ := mcpTestServer(t)
	req := withSession(httptest.NewRequest("GET", "/api/mcp/tokens", nil), auth.RoleAnalyst)
	rec := httptest.NewRecorder()
	s.handleListMCPTokens(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("analyst list status = %d, want 403", rec.Code)
	}
}

func TestCreateTokenWithDurationExpiry(t *testing.T) {
	s, _, _ := mcpTestServer(t)
	req := withSession(httptest.NewRequest("POST", "/api/mcp/tokens", strings.NewReader(`{"label":"exp","role":"analyst","expires":"720h"}`)), auth.RoleLead)
	rec := httptest.NewRecorder()
	s.handleCreateMCPToken(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create with 720h expiry status = %d, want 201", rec.Code)
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["expires"] == nil {
		t.Fatal("expected a non-null expires in the response")
	}
}

func TestCreateTokenBadExpiry(t *testing.T) {
	s, _, _ := mcpTestServer(t)
	req := withSession(httptest.NewRequest("POST", "/api/mcp/tokens", strings.NewReader(`{"label":"x","role":"analyst","expires":"nonsense"}`)), auth.RoleLead)
	rec := httptest.NewRecorder()
	s.handleCreateMCPToken(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("create with bad expiry status = %d, want 400", rec.Code)
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
