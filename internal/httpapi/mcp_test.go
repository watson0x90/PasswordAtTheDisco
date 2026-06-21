package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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
