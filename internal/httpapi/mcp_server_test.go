package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/watson0x90/PasswordAtTheDisco/internal/auth"
)

func mcpServer(t *testing.T) (*Server, string) {
	t.Helper()
	ts := auth.NewTokenStore("", nil)
	tok, _, _ := ts.Issue(auth.RoleAnalyst, "agent", nil)
	return &Server{MCPTokens: ts, MCPLimiter: auth.NewLimiter(50, time.Minute)}, tok
}

// rpc sends one JSON-RPC request through the full requireMCPToken+handleMCP chain.
func rpc(t *testing.T, s *Server, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	h := s.requireMCPToken(http.HandlerFunc(s.handleMCP))
	req := httptest.NewRequest("POST", "/api/mcp", strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestMCPInitialize(t *testing.T) {
	s, tok := mcpServer(t)
	rec := rpc(t, s, tok, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{}}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	result, _ := resp["result"].(map[string]any)
	if result == nil || result["protocolVersion"] == nil || result["serverInfo"] == nil {
		t.Fatalf("bad initialize result: %v", resp)
	}
	caps, _ := result["capabilities"].(map[string]any)
	if _, ok := caps["tools"]; !ok {
		t.Fatalf("initialize must advertise tools capability: %v", result)
	}
}

func TestMCPPing(t *testing.T) {
	s, tok := mcpServer(t)
	rec := rpc(t, s, tok, `{"jsonrpc":"2.0","id":2,"method":"ping"}`)
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if _, ok := resp["result"]; !ok {
		t.Fatalf("ping must return a result: %v", resp)
	}
}

func TestMCPNotificationNoBody(t *testing.T) {
	s, tok := mcpServer(t)
	rec := rpc(t, s, tok, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	if rec.Code != http.StatusAccepted && rec.Body.Len() != 0 {
		t.Fatalf("a notification must get an empty/202 response, got %d %q", rec.Code, rec.Body.String())
	}
}

func TestMCPParseAndMethodErrors(t *testing.T) {
	s, tok := mcpServer(t)
	if rec := rpc(t, s, tok, `not json`); !strings.Contains(rec.Body.String(), "-32700") {
		t.Fatalf("malformed JSON must yield -32700: %s", rec.Body.String())
	}
	if rec := rpc(t, s, tok, `{"jsonrpc":"2.0","id":9,"method":"no/such"}`); !strings.Contains(rec.Body.String(), "-32601") {
		t.Fatalf("unknown method must yield -32601: %s", rec.Body.String())
	}
}
