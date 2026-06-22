package httpapi

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/watson0x90/PasswordAtTheDisco/internal/audit"
	"github.com/watson0x90/PasswordAtTheDisco/internal/auth"
	"github.com/watson0x90/PasswordAtTheDisco/internal/hibp"
	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
	"github.com/watson0x90/PasswordAtTheDisco/internal/store"
)

// TestToolsCallAuditsDenied confirms a role-denied tool call emits an audit event
// (the audit guarantee for MCP tokens — every executed/denied call is recorded).
func TestToolsCallAuditsDenied(t *testing.T) {
	var buf bytes.Buffer
	ts := auth.NewTokenStore("", nil)
	analyst, _, _ := ts.Issue(auth.RoleAnalyst, "a", nil)
	s := &Server{MCPTokens: ts, MCPLimiter: auth.NewLimiter(50, time.Minute), Audit: audit.New(&buf)}
	rpc(t, s, analyst, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"reveal_password","arguments":{"username":"x","domain":"Y"}}}`)
	if !strings.Contains(buf.String(), "mcp_tool:reveal_password") || !strings.Contains(buf.String(), "denied") {
		t.Fatalf("denied reveal must be audited: %q", buf.String())
	}
}

func mcpToolServer(t *testing.T) (*Server, string, string) {
	t.Helper()
	ts := auth.NewTokenStore("", nil)
	analyst, _, _ := ts.Issue(auth.RoleAnalyst, "analyst-agent", nil)
	lead, _, _ := ts.Issue(auth.RoleLead, "lead-agent", nil)
	s := &Server{MCPTokens: ts, MCPLimiter: auth.NewLimiter(50, time.Minute), Audit: audit.New(io.Discard)}
	return s, analyst, lead
}

func TestToolsListRoleFiltered(t *testing.T) {
	s, analyst, lead := mcpToolServer(t)
	names := func(tok string) map[string]bool {
		rec := rpc(t, s, tok, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
		var resp struct {
			Result struct {
				Tools []struct {
					Name string `json:"name"`
				} `json:"tools"`
			} `json:"result"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		m := map[string]bool{}
		for _, tl := range resp.Result.Tools {
			m[tl.Name] = true
		}
		return m
	}
	an := names(analyst)
	if !an["list_audits"] || an["reveal_password"] {
		t.Fatalf("analyst tools wrong: %v", an)
	}
	ld := names(lead)
	if !ld["reveal_password"] || !ld["list_audits"] {
		t.Fatalf("lead must see reveal_password: %v", ld)
	}
}

func TestToolsCallUnknownAndRole(t *testing.T) {
	s, analyst, _ := mcpToolServer(t)
	rec := rpc(t, s, analyst, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nope","arguments":{}}}`)
	if !strings.Contains(rec.Body.String(), "isError") {
		t.Fatalf("unknown tool must be a tool error: %s", rec.Body.String())
	}
	rec = rpc(t, s, analyst, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"reveal_password","arguments":{"username":"x","domain":"Y"}}}`)
	if !strings.Contains(rec.Body.String(), "lead") {
		t.Fatalf("analyst reveal must be denied: %s", rec.Body.String())
	}
}

// seedMCPStore attaches an unlocked in-memory store with one audit, two domains, and a
// known cracked account (alice@CORP / "Summer2024!") for the data-tool tests.
func seedMCPStore(t *testing.T, s *Server) {
	t.Helper()
	st := store.New()
	meta, err := st.CreateAudit("MCP Test", "")
	if err != nil {
		t.Fatal(err)
	}
	pw := "Summer2024!"
	if err := st.ReplaceDomain(meta.ID, "CORP", []model.Account{
		{Username: "alice", Domain: "CORP", Cracked: true, Password: pw, NTHash: hibp.NTLMHash(pw), RiskLevel: "Critical", HIBPBreached: true},
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.ReplaceDomain(meta.ID, "GHOST", []model.Account{
		{Username: "bob", Domain: "GHOST", Cracked: false, RiskLevel: "Low", DADomains: "GHOST"},
	}); err != nil {
		t.Fatal(err)
	}
	s.Store = st
}

// toolText extracts the inner JSON text of a successful tools/call result so tests
// can assert on actual values (the result.content[0].text block).
func toolText(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var resp struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || len(resp.Result.Content) == 0 {
		t.Fatalf("no tool content: %s", rec.Body.String())
	}
	return resp.Result.Content[0].Text
}

func TestGetPostureAndDomainBreakdown(t *testing.T) {
	s, analyst, _ := mcpToolServer(t)
	seedMCPStore(t, s)
	post := rpc(t, s, analyst, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_posture","arguments":{}}}`)
	if strings.Contains(post.Body.String(), "isError") {
		t.Fatalf("get_posture errored: %s", post.Body.String())
	}
	if pt := toolText(t, post); !strings.Contains(pt, `"total_accounts":2`) {
		t.Fatalf("posture total wrong: %s", pt)
	}
	dom := rpc(t, s, analyst, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"domain_breakdown","arguments":{}}}`)
	if strings.Contains(dom.Body.String(), "isError") {
		t.Fatalf("domain_breakdown errored: %s", dom.Body.String())
	}
	// CORP: cracked+critical+breached account; GHOST: a DA-pathway account.
	dt := toolText(t, dom)
	if !strings.Contains(dt, `"critical":1`) || !strings.Contains(dt, `"da_paths":1`) || !strings.Contains(dt, `"hibp_breached":1`) {
		t.Fatalf("domain_breakdown counts wrong: %s", dt)
	}
	// unknown audit_id -> tool error
	bad := rpc(t, s, analyst, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_posture","arguments":{"audit_id":"nope"}}}`)
	if !strings.Contains(bad.Body.String(), "isError") {
		t.Fatalf("unknown audit_id must be a tool error: %s", bad.Body.String())
	}
}

func TestEmptyStoreNoAudits(t *testing.T) {
	s, analyst, _ := mcpToolServer(t)
	s.Store = store.New() // unlocked, zero audits
	rec := rpc(t, s, analyst, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_posture","arguments":{}}}`)
	if !strings.Contains(rec.Body.String(), "isError") || !strings.Contains(rec.Body.String(), "no audits") {
		t.Fatalf("empty store must yield a 'no audits' tool error: %s", rec.Body.String())
	}
}
