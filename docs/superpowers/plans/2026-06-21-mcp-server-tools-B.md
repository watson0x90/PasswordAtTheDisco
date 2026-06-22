# MCP Server + Tools (sub-project B) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A stateless Streamable-HTTP MCP server at `POST /api/mcp` with a role-filtered tool registry exposing patd's read capabilities (and a lead-only cleartext reveal) to MCP clients, authenticated by the API tokens from sub-project A.

**Architecture:** Stdlib JSON-RPC 2.0 over a single authenticated POST endpoint. `handleMCP` (wrapped in A's `requireMCPToken`) dispatches `initialize`/`notifications/initialized`/`ping`/`tools/list`/`tools/call`. A `mcpTool` registry declares each tool's name/description/input-schema/required-role/needs-unlock/handler; `tools/call` enforces role + unlock, resolves an optional `audit_id` (default = most-recently-updated audit), runs the handler against existing `store`/`report`/`model` methods, and audit-logs every call. Tools return redacted shapes; cleartext flows only through `reveal_password`.

**Tech Stack:** Go stdlib only (`encoding/json`, `net/http`); reuses `internal/store`, `internal/report`, `internal/model`, `internal/hibp`, `internal/audit`, and A's `requireMCPToken`/`mcpTokenFrom`.

**Spec:** `docs/superpowers/specs/2026-06-21-mcp-server-tools-design.md`

**Conventions (read first):**
- Gates: `gofmt -l cmd internal` empty; `go build ./... && go vet ./... && go test ./...`; `govulncheck ./...`. No web changes in B.
- **No `git commit --no-verify`.** Use Read/Grep tools, not `npx rg`.
- Reuse, don't reinvent: `internal/httpapi/server.go` patterns — `writeJSON`, `mcpTokenFrom` (A, returns `auth.APIToken`), `requireMCPToken` (A), `clientIP`, the audit pattern `s.Audit.Log(audit.Event{...})`, `auditOrFail` (~1448), and `handleReveal` (~1401, the lead-gated reveal to mirror).
- Store/data methods (confirm exact field names by reading the files): `s.Store.Unlocked() bool`; `s.Store.List() []store.AuditListItem`; `s.Store.Meta(id) (store.AuditMeta, bool)`; `s.Store.Has(id) bool`; `s.Store.Accounts(id string, includeSecrets bool) ([]model.Account, error)`; `s.Store.Find(id, username) (model.Account, bool)`; `s.Store.FindByDomain(id, username, domain) (model.Account, bool)`; `s.Store.Summary(id) (model.Summary, error)`; `model.BuildReport(accts []model.Account) model.Report`; `report.ComputeDiff(a, b []model.Account)` (see `handleDiff` ~1808 for the exact call + return type); `hibp.NTLMHash(s string) string`; `model.Account.Redacted() model.Account`.

---

## File Structure

**Create:**
- `internal/httpapi/mcp_server.go` — JSON-RPC 2.0 types + error codes, `handleMCP`, method dispatch (`initialize`/`initialized`/`ping`/`tools/list`/`tools/call`), MCP result helpers.
- `internal/httpapi/mcp_tools.go` — `mcpTool` type, `mcpCall`, the registry `mcpToolset()`, the role/unlock/audit dispatch in `callTool`, `audit_id` resolution + `latestAuditID`, and the nine tool handlers + a per-domain helper.
- `internal/httpapi/mcp_server_test.go`, `internal/httpapi/mcp_tools_test.go`.

**Modify:**
- `internal/httpapi/server.go` — register `POST /api/mcp`.

These sit beside A's `internal/httpapi/mcp.go`. Tools call store/report/model methods directly — never the session-coupled HTTP handlers.

---

## Task 1: JSON-RPC envelope + `/api/mcp` endpoint (initialize / ping / initialized)

**Files:** Create `internal/httpapi/mcp_server.go`, `internal/httpapi/mcp_server_test.go`; Modify `server.go` (route).

- [ ] **Step 1: Failing test** — `internal/httpapi/mcp_server_test.go`
```go
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
```
Run `go test ./internal/httpapi/ -run TestMCP -v` → FAIL (undefined `handleMCP`).

- [ ] **Step 2: Implement** — `internal/httpapi/mcp_server.go`
```go
package httpapi

import (
	"encoding/json"
	"net/http"
)

// mcpProtocolVersion is the MCP revision this server implements.
const mcpProtocolVersion = "2025-06-18"

// JSON-RPC 2.0 envelope types.
type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"` // absent => notification
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

const (
	rpcParseError     = -32700
	rpcInvalidRequest = -32600
	rpcMethodNotFound = -32601
	rpcInvalidParams  = -32602
	rpcInternal       = -32603
)

func rpcErr(id json.RawMessage, code int, msg string) rpcResponse {
	return rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: msg}}
}
func rpcOK(id json.RawMessage, result any) rpcResponse {
	return rpcResponse{JSONRPC: "2.0", ID: id, Result: result}
}

// handleMCP is the single MCP endpoint. Auth (requireMCPToken) ran already; the token
// is in context. It decodes one JSON-RPC request and dispatches. Stateless, JSON
// response (no SSE). Notifications (no id) get 202 with no body.
func (s *Server) handleMCP(w http.ResponseWriter, r *http.Request) {
	var req rpcRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusOK, rpcErr(nil, rpcParseError, "parse error"))
		return
	}
	if req.JSONRPC != "2.0" || req.Method == "" {
		writeJSON(w, http.StatusOK, rpcErr(req.ID, rpcInvalidRequest, "invalid request"))
		return
	}
	// Notification (no id): act, return no body.
	if len(req.ID) == 0 {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	switch req.Method {
	case "initialize":
		writeJSON(w, http.StatusOK, rpcOK(req.ID, map[string]any{
			"protocolVersion": mcpProtocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "passwordatthedisco-mcp", "version": s.Build.Version},
		}))
	case "ping":
		writeJSON(w, http.StatusOK, rpcOK(req.ID, map[string]any{}))
	case "tools/list":
		writeJSON(w, http.StatusOK, s.mcpToolsList(req))
	case "tools/call":
		writeJSON(w, http.StatusOK, s.mcpToolsCall(r, req))
	default:
		writeJSON(w, http.StatusOK, rpcErr(req.ID, rpcMethodNotFound, "method not found: "+req.Method))
	}
}
```
`s.mcpToolsList` and `s.mcpToolsCall` are added in Task 2. To compile Task 1 alone, add temporary stubs at the bottom of `mcp_server.go` (they will be REPLACED in Task 2 — do not leave them):
```go
func (s *Server) mcpToolsList(req rpcRequest) rpcResponse { return rpcOK(req.ID, map[string]any{"tools": []any{}}) }
func (s *Server) mcpToolsCall(r *http.Request, req rpcRequest) rpcResponse { return rpcErr(req.ID, rpcMethodNotFound, "tools not wired yet") }
```
`s.Build.Version` is the existing build-info field (see the `Server.Build BuildInfo` field and `handleVersion`).

- [ ] **Step 3: Register the route** in `server.go` (next to A's `GET /api/mcp/whoami`):
```go
	mux.Handle("POST /api/mcp", s.requireMCPToken(http.HandlerFunc(s.handleMCP)))
```

- [ ] **Step 4: Run** `go test ./internal/httpapi/ -run TestMCP -v && go build ./... && go vet ./...` → PASS. `gofmt -w internal/httpapi/mcp_server.go internal/httpapi/mcp_server_test.go internal/httpapi/server.go`.

- [ ] **Step 5: Commit**
```bash
git add internal/httpapi/mcp_server.go internal/httpapi/mcp_server_test.go internal/httpapi/server.go
git commit -m "feat(mcp): JSON-RPC endpoint POST /api/mcp (initialize/ping/notifications)"
```

---

## Task 2: Tool registry + `tools/list` (role-filtered) + `tools/call` dispatch + `list_audits`

**Files:** Create `internal/httpapi/mcp_tools.go`, `internal/httpapi/mcp_tools_test.go`; Modify `mcp_server.go` (remove the Task-1 stubs).

- [ ] **Step 1: Failing test** — `internal/httpapi/mcp_tools_test.go`
```go
package httpapi

import (
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
	// unknown tool -> tool error (isError result, not a protocol error)
	rec := rpc(t, s, analyst, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nope","arguments":{}}}`)
	if !strings.Contains(rec.Body.String(), "isError") {
		t.Fatalf("unknown tool must be a tool error: %s", rec.Body.String())
	}
	// analyst calling reveal_password -> denied tool error
	rec = rpc(t, s, analyst, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"reveal_password","arguments":{"username":"x","domain":"Y"}}}`)
	if !strings.Contains(rec.Body.String(), "lead") {
		t.Fatalf("analyst reveal must be denied: %s", rec.Body.String())
	}
}

func mcpHelper(t *testing.T) {} // placeholder to keep imports tidy if needed
var _ = httptest.NewRequest
```

Run `go test ./internal/httpapi/ -run 'TestToolsList|TestToolsCall' -v` → FAIL.

- [ ] **Step 2: Implement** — `internal/httpapi/mcp_tools.go`
```go
package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"

	"github.com/watson0x90/PasswordAtTheDisco/internal/audit"
	"github.com/watson0x90/PasswordAtTheDisco/internal/auth"
)

// mcpTool is one registered MCP tool.
type mcpTool struct {
	Name        string
	Description string
	InputSchema map[string]any
	Role        auth.Role // minimum role: RoleAnalyst (any) or RoleLead
	NeedsUnlock bool
	// Handler runs the tool. It returns the JSON-able result, an audit target string
	// (a SAFE summary — never a secret), and an error (nil => ok; non-nil => tool error).
	Handler func(s *Server, c *mcpCall) (result any, auditTarget string, err error)
}

// mcpCall carries the per-call context handed to a tool handler.
type mcpCall struct {
	Token      auth.APIToken
	Args       json.RawMessage
	RemoteAddr string
}

// roleAtLeast reports whether `have` satisfies the minimum `need` (lead >= analyst).
func roleAtLeast(have, need auth.Role) bool {
	if need == auth.RoleLead {
		return have == auth.RoleLead
	}
	return have == auth.RoleAnalyst || have == auth.RoleLead
}

// mcpToolset returns the full registry. Handlers are added across Tasks 2–6.
func (s *Server) mcpToolset() []mcpTool {
	return []mcpTool{
		{
			Name:        "list_audits",
			Description: "List the available audits (id, name, account counts). Use an id as audit_id in other tools; omit audit_id to use the most recently updated audit.",
			InputSchema: map[string]any{"type": "object", "properties": map[string]any{}},
			Role:        auth.RoleAnalyst, NeedsUnlock: true,
			Handler: func(s *Server, c *mcpCall) (any, string, error) {
				return map[string]any{"audits": s.Store.List()}, "", nil
			},
		},
		// get_posture, list_accounts, search_accounts, domain_breakdown,
		// password_in_use, get_report, diff_audits, reveal_password added in later tasks.
	}
}

// mcpToolsList answers tools/list, filtered to the calling token's role.
func (s *Server) mcpToolsList(req rpcRequest) rpcResponse {
	// The token is not on rpcRequest; tools/list is role-filtered using the request
	// context, so this is handled in handleMCP via a context-aware variant. To keep the
	// signature simple, we re-resolve the role from a field set on the request — see note.
	return rpcOK(req.ID, map[string]any{"tools": []any{}}) // replaced below by the context-aware version
}
```
**Important wiring note:** `tools/list` and `tools/call` need the authenticated token (role). `handleMCP` has the `*http.Request` (with the token in context via A's `mcpTokenFrom`). Change the two dispatch calls in `mcp_server.go` to pass the request, and implement the real methods here:

Replace the `mcpToolsList` stub above and the Task-1 `mcpToolsCall` stub with these (and update `handleMCP` to call `s.mcpToolsList(r, req)`):
```go
func (s *Server) mcpToolsList(r *http.Request, req rpcRequest) rpcResponse {
	tok, _ := mcpTokenFrom(r.Context())
	out := []map[string]any{}
	for _, tl := range s.mcpToolset() {
		if !roleAtLeast(tok.Role, tl.Role) {
			continue
		}
		out = append(out, map[string]any{"name": tl.Name, "description": tl.Description, "inputSchema": tl.InputSchema})
	}
	return rpcOK(req.ID, map[string]any{"tools": out})
}

func (s *Server) mcpToolsCall(r *http.Request, req rpcRequest) rpcResponse {
	tok, _ := mcpTokenFrom(r.Context())
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return rpcErr(req.ID, rpcInvalidParams, "invalid params")
	}
	var tool *mcpTool
	for i := range s.mcpToolsetCached() {
		if s.mcpToolsetCached()[i].Name == p.Name {
			tool = &s.mcpToolsetCached()[i]
			break
		}
	}
	call := &mcpCall{Token: tok, Args: p.Arguments, RemoteAddr: clientIP(r)}
	logCall := func(target, result string) {
		s.Audit.Log(audit.Event{Actor: mcpActor(tok), Role: string(tok.Role), Action: "mcp_tool:" + p.Name, Target: target, Source: call.RemoteAddr, Result: result})
	}
	if tool == nil {
		return rpcOK(req.ID, mcpToolError("unknown tool: "+p.Name))
	}
	if !roleAtLeast(tok.Role, tool.Role) {
		logCall("", "denied")
		return rpcOK(req.ID, mcpToolError("this tool requires a lead token"))
	}
	if tool.NeedsUnlock && !s.Store.Unlocked() {
		return rpcOK(req.ID, mcpToolError("data store is locked"))
	}
	result, target, err := tool.Handler(s, call)
	if err != nil {
		logCall(target, "error")
		return rpcOK(req.ID, mcpToolError(err.Error()))
	}
	logCall(target, "ok")
	return rpcOK(req.ID, mcpToolResult(result))
}

// mcpActor labels an MCP token in the audit log (id + label, never the secret).
func mcpActor(t auth.APIToken) string { return "mcp:" + t.ID + " (" + t.Label + ")" }

// mcpToolResult wraps a JSON-able value as an MCP tool result (text content block).
func mcpToolResult(v any) map[string]any {
	b, err := json.Marshal(v)
	if err != nil {
		return mcpToolError("failed to encode result")
	}
	return map[string]any{"content": []map[string]any{{"type": "text", "text": string(b)}}}
}

// mcpToolError is an MCP tool error result (isError:true) so the model sees the message.
func mcpToolError(msg string) map[string]any {
	return map[string]any{"isError": true, "content": []map[string]any{{"type": "text", "text": msg}}}
}
```
Also delete the placeholder `mcpToolset` duplication: keep ONE `mcpToolset()` (the registry) and add a tiny cache wrapper so `mcpToolsCall` doesn't rebuild it three times:
```go
func (s *Server) mcpToolsetCached() []mcpTool { return s.mcpToolset() }
```
(Building the slice per call is fine — it's small and stateless. The `mcpToolsetCached` name documents intent; do not add real caching/state.)

Finally, in `mcp_server.go` remove the Task-1 stubs and change the dispatch:
```go
	case "tools/list":
		writeJSON(w, http.StatusOK, s.mcpToolsList(r, req))
	case "tools/call":
		writeJSON(w, http.StatusOK, s.mcpToolsCall(r, req))
```

- [ ] **Step 3: Run** `go test ./internal/httpapi/ -run 'TestMCP|TestTools' -v && go build ./... && go vet ./...` → PASS. Note: `TestToolsListRoleFiltered` checks `reveal_password` is lead-only; it must already be in the registry as a declaration even before its handler exists — add a registry entry for `reveal_password` with `Role: auth.RoleLead` and a handler that returns `nil, "", fmt.Errorf("not implemented")` for now (Task 6 implements it). Do the same minimal stub-entries are NOT needed for the other tools (the role test only asserts list_audits present + reveal_password lead-only). gofmt the new files.

- [ ] **Step 4: Commit**
```bash
git add internal/httpapi/mcp_tools.go internal/httpapi/mcp_tools_test.go internal/httpapi/mcp_server.go
git commit -m "feat(mcp): tool registry, role-filtered tools/list, tools/call dispatch + list_audits"
```

---

## Task 3: `audit_id` resolution + `get_posture` + `domain_breakdown`

**Files:** Modify `internal/httpapi/mcp_tools.go`, `internal/httpapi/mcp_tools_test.go`.

- [ ] **Step 1: Add the resolution helpers** to `mcp_tools.go`
```go
// latestAuditID returns the id of the most-recently-updated audit, or ("",false) if none.
func (s *Server) latestAuditID() (string, bool) {
	list := s.Store.List()
	if len(list) == 0 {
		return "", false
	}
	sort.Slice(list, func(i, j int) bool { return list[i].UpdatedAt.After(list[j].UpdatedAt) })
	return list[0].ID, true
}

// resolveAuditID returns the requested audit id (validated) or the latest when blank.
func (s *Server) resolveAuditID(want string) (string, error) {
	if want != "" {
		if !s.Store.Has(want) {
			return "", fmt.Errorf("unknown audit_id %q", want)
		}
		return want, nil
	}
	if id, ok := s.latestAuditID(); ok {
		return id, nil
	}
	return "", fmt.Errorf("no audits exist yet")
}
```
(Confirm `store.AuditListItem` has `ID` and `UpdatedAt time.Time` — read `internal/store/store.go` near `List()`; adjust field names if they differ.)

- [ ] **Step 2: Failing test** (append to `mcp_tools_test.go`) — seed a store and assert posture + domains. Use the existing store test seam to build an unlocked in-memory store with accounts. Read `internal/store/store_test.go` for the helper that constructs a `*store.Store` with data, and `internal/httpapi/server_test.go` for how `Server` is built with a `Store`. Then:
```go
func TestGetPostureAndDomainBreakdown(t *testing.T) {
	s, analyst, _ := mcpToolServer(t)
	seedMCPStore(t, s) // helper you add: an unlocked store with a couple domains/accounts
	post := rpc(t, s, analyst, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_posture","arguments":{}}}`)
	if strings.Contains(post.Body.String(), "isError") {
		t.Fatalf("get_posture errored: %s", post.Body.String())
	}
	dom := rpc(t, s, analyst, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"domain_breakdown","arguments":{}}}`)
	if strings.Contains(dom.Body.String(), "isError") || !strings.Contains(dom.Body.String(), "domains") {
		t.Fatalf("domain_breakdown wrong: %s", dom.Body.String())
	}
}
```
Write `seedMCPStore(t, s)` to attach an unlocked `*store.Store` containing at least two accounts in two domains (one cracked/HIBP-breached, one critical with a DA pathway), mirroring the construction in `internal/store/store_test.go` + `server_test.go`. Run → FAIL (tools undefined).

- [ ] **Step 3: Implement the two tools** — add to the `mcpToolset()` slice:
```go
		{
			Name:        "get_posture",
			Description: "Org-wide posture for an audit: account/cracked/breached counts, risk-level distribution, posture score, breach-impact, and BloodHound coverage. Optional audit_id (defaults to the latest).",
			InputSchema: auditIDSchema("Audit id; omit for the most recently updated audit."),
			Role:        auth.RoleAnalyst, NeedsUnlock: true,
			Handler: func(s *Server, c *mcpCall) (any, string, error) {
				id, err := s.resolveAuditID(argAuditID(c.Args))
				if err != nil {
					return nil, "", err
				}
				sum, err := s.Store.Summary(id)
				if err != nil {
					return nil, id, fmt.Errorf("summary unavailable: %w", err)
				}
				return sum, id, nil
			},
		},
		{
			Name:        "domain_breakdown",
			Description: "Per-domain stats for an audit: accounts, cracked, HIBP-breached, critical, and DA-pathway counts. Optional audit_id.",
			InputSchema: auditIDSchema("Audit id; omit for the most recently updated audit."),
			Role:        auth.RoleAnalyst, NeedsUnlock: true,
			Handler: func(s *Server, c *mcpCall) (any, string, error) {
				id, err := s.resolveAuditID(argAuditID(c.Args))
				if err != nil {
					return nil, "", err
				}
				accts, err := s.Store.Accounts(id, false)
				if err != nil {
					return nil, id, fmt.Errorf("accounts unavailable: %w", err)
				}
				return map[string]any{"domains": domainBreakdown(accts)}, id, nil
			},
		},
```
Add these helpers to `mcp_tools.go`:
```go
// auditIDSchema is the shared JSON Schema for tools that take an optional audit_id.
func auditIDSchema(desc string) map[string]any {
	return map[string]any{"type": "object", "properties": map[string]any{
		"audit_id": map[string]any{"type": "string", "description": desc},
	}}
}

// argAuditID extracts an optional "audit_id" from a tool's raw arguments.
func argAuditID(raw json.RawMessage) string {
	var a struct {
		AuditID string `json:"audit_id"`
	}
	_ = json.Unmarshal(raw, &a)
	return a.AuditID
}

type domainStat struct {
	Domain   string `json:"domain"`
	Accounts int    `json:"accounts"`
	Cracked  int    `json:"cracked"`
	Breached int    `json:"hibp_breached"`
	Critical int    `json:"critical"`
	DAPaths  int    `json:"da_paths"`
}

// domainBreakdown groups REDACTED accounts into per-domain stats, sorted by account count desc.
func domainBreakdown(accts []model.Account) []domainStat {
	by := map[string]*domainStat{}
	for _, a := range accts {
		d := by[a.Domain]
		if d == nil {
			d = &domainStat{Domain: a.Domain}
			by[a.Domain] = d
		}
		d.Accounts++
		if a.Cracked {
			d.Cracked++
		}
		if a.HIBPBreached {
			d.Breached++
		}
		if a.RiskLevel == "Critical" {
			d.Critical++
		}
		if a.HasDAPathway() {
			d.DAPaths++
		}
	}
	out := make([]domainStat, 0, len(by))
	for _, d := range by {
		out = append(out, *d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Accounts > out[j].Accounts })
	return out
}
```
Add `"github.com/watson0x90/PasswordAtTheDisco/internal/model"` to `mcp_tools.go` imports. Confirm `model.Account` has `HIBPBreached`, `RiskLevel`, `HasDAPathway()` (it does — used in `internal/model`).

- [ ] **Step 4: Run** `go test ./internal/httpapi/ -run 'TestMCP|TestTools|TestGetPosture' -v` → PASS. gofmt.

- [ ] **Step 5: Commit**
```bash
git add internal/httpapi/mcp_tools.go internal/httpapi/mcp_tools_test.go
git commit -m "feat(mcp): audit_id resolution + get_posture + domain_breakdown tools"
```

---

## Task 4: `list_accounts` (filter/sort/pagination) + `search_accounts`

**Files:** Modify `internal/httpapi/mcp_tools.go`, `internal/httpapi/mcp_tools_test.go`.

- [ ] **Step 1: Failing test** (append) — assert pagination cap + filter:
```go
func TestListAndSearchAccounts(t *testing.T) {
	s, analyst, _ := mcpToolServer(t)
	seedMCPStore(t, s)
	// limit cap: ask for 9999, must be capped to <=200 and echo a total
	rec := rpc(t, s, analyst, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_accounts","arguments":{"limit":9999}}}`)
	body := rec.Body.String()
	if strings.Contains(body, "isError") || !strings.Contains(body, "\"total\"") {
		t.Fatalf("list_accounts wrong: %s", body)
	}
	// search
	se := rpc(t, s, analyst, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"search_accounts","arguments":{"query":"a"}}}`)
	if strings.Contains(se.Body.String(), "isError") {
		t.Fatalf("search errored: %s", se.Body.String())
	}
}
```
Run → FAIL.

- [ ] **Step 2: Implement** — add to `mcpToolset()`:
```go
		{
			Name:        "list_accounts",
			Description: "List redacted accounts in an audit with optional filtering, sorting, and cursor pagination (max 200 per page). Filters: risk_level, cracked, domain, hibp_breached, has_da. Sort: risk_score (default, desc) or username.",
			InputSchema: map[string]any{"type": "object", "properties": map[string]any{
				"audit_id":      map[string]any{"type": "string"},
				"risk_level":    map[string]any{"type": "string", "enum": []string{"Critical", "High", "Medium", "Low"}},
				"cracked":       map[string]any{"type": "boolean"},
				"domain":        map[string]any{"type": "string"},
				"hibp_breached": map[string]any{"type": "boolean"},
				"has_da":        map[string]any{"type": "boolean"},
				"sort":          map[string]any{"type": "string", "enum": []string{"risk_score", "username"}},
				"limit":         map[string]any{"type": "integer", "description": "1–200 (default 50)"},
				"cursor":        map[string]any{"type": "string", "description": "next_cursor from a prior page"},
			}},
			Role: auth.RoleAnalyst, NeedsUnlock: true,
			Handler: mcpListAccounts,
		},
		{
			Name:        "search_accounts",
			Description: "Find redacted accounts whose username or domain contains the query (case-insensitive), capped at 200 results.",
			InputSchema: map[string]any{"type": "object", "properties": map[string]any{
				"audit_id": map[string]any{"type": "string"},
				"query":    map[string]any{"type": "string"},
			}, "required": []string{"query"}},
			Role: auth.RoleAnalyst, NeedsUnlock: true,
			Handler: mcpSearchAccounts,
		},
```
Add the handlers + a constant to `mcp_tools.go`:
```go
const mcpMaxPage = 200

func mcpListAccounts(s *Server, c *mcpCall) (any, string, error) {
	var a struct {
		AuditID      string `json:"audit_id"`
		RiskLevel    string `json:"risk_level"`
		Cracked      *bool  `json:"cracked"`
		Domain       string `json:"domain"`
		HIBPBreached *bool  `json:"hibp_breached"`
		HasDA        *bool  `json:"has_da"`
		Sort         string `json:"sort"`
		Limit        int    `json:"limit"`
		Cursor       string `json:"cursor"`
	}
	_ = json.Unmarshal(c.Args, &a)
	id, err := s.resolveAuditID(a.AuditID)
	if err != nil {
		return nil, "", err
	}
	accts, err := s.Store.Accounts(id, false)
	if err != nil {
		return nil, id, fmt.Errorf("accounts unavailable: %w", err)
	}
	// filter
	out := accts[:0:0]
	for _, x := range accts {
		if a.RiskLevel != "" && !strings.EqualFold(x.RiskLevel, a.RiskLevel) {
			continue
		}
		if a.Cracked != nil && x.Cracked != *a.Cracked {
			continue
		}
		if a.Domain != "" && !strings.EqualFold(x.Domain, a.Domain) {
			continue
		}
		if a.HIBPBreached != nil && x.HIBPBreached != *a.HIBPBreached {
			continue
		}
		if a.HasDA != nil && x.HasDAPathway() != *a.HasDA {
			continue
		}
		out = append(out, x)
	}
	// sort
	switch a.Sort {
	case "username":
		sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	default:
		sort.Slice(out, func(i, j int) bool { return out[i].RiskScore > out[j].RiskScore })
	}
	total := len(out)
	// paginate (offset cursor)
	limit := a.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > mcpMaxPage {
		limit = mcpMaxPage
	}
	offset := 0
	if a.Cursor != "" {
		fmt.Sscanf(a.Cursor, "%d", &offset)
	}
	if offset < 0 || offset > total {
		offset = total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	page := out[offset:end]
	res := map[string]any{"accounts": page, "total": total}
	if end < total {
		res["next_cursor"] = fmt.Sprintf("%d", end)
	}
	return res, id, nil
}

func mcpSearchAccounts(s *Server, c *mcpCall) (any, string, error) {
	var a struct {
		AuditID string `json:"audit_id"`
		Query   string `json:"query"`
	}
	_ = json.Unmarshal(c.Args, &a)
	if strings.TrimSpace(a.Query) == "" {
		return nil, "", fmt.Errorf("query is required")
	}
	id, err := s.resolveAuditID(a.AuditID)
	if err != nil {
		return nil, "", err
	}
	accts, err := s.Store.Accounts(id, false)
	if err != nil {
		return nil, id, fmt.Errorf("accounts unavailable: %w", err)
	}
	q := strings.ToLower(a.Query)
	matches := []model.Account{}
	for _, x := range accts {
		if strings.Contains(strings.ToLower(x.Username), q) || strings.Contains(strings.ToLower(x.Domain), q) {
			matches = append(matches, x)
			if len(matches) >= mcpMaxPage {
				break
			}
		}
	}
	return map[string]any{"matches": matches, "count": len(matches), "truncated": len(matches) >= mcpMaxPage}, id, nil
}
```
Confirm `model.Account` has `RiskScore float64` and `Username`/`Domain`/`Cracked`/`RiskLevel`/`HIBPBreached` (it does).

- [ ] **Step 3: Run** `go test ./internal/httpapi/ -run 'TestTools|TestList' -v` → PASS. gofmt.

- [ ] **Step 4: Commit**
```bash
git add internal/httpapi/mcp_tools.go internal/httpapi/mcp_tools_test.go
git commit -m "feat(mcp): list_accounts (filter/sort/paginate, cap 200) + search_accounts"
```

---

## Task 5: `password_in_use` + `get_report` + `diff_audits`

**Files:** Modify `internal/httpapi/mcp_tools.go`, `internal/httpapi/mcp_tools_test.go`.

- [ ] **Step 1: Failing test** (append):
```go
func TestProbeReportDiff(t *testing.T) {
	s, analyst, _ := mcpToolServer(t)
	seedMCPStore(t, s)
	// password_in_use with a known seeded cracked password (set in seedMCPStore)
	pr := rpc(t, s, analyst, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"password_in_use","arguments":{"password":"Summer2024!"}}}`)
	if strings.Contains(pr.Body.String(), "isError") || !strings.Contains(pr.Body.String(), "count") {
		t.Fatalf("password_in_use wrong: %s", pr.Body.String())
	}
	rp := rpc(t, s, analyst, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_report","arguments":{}}}`)
	if strings.Contains(rp.Body.String(), "isError") {
		t.Fatalf("get_report errored: %s", rp.Body.String())
	}
}
```
(Make `seedMCPStore` give one cracked account the password `Summer2024!` so the probe matches by NTLM hash.) Run → FAIL.

- [ ] **Step 2: Implement** — add to `mcpToolset()`:
```go
		{
			Name:        "password_in_use",
			Description: "Check which accounts in an audit use a specific password (matched by NTLM hash server-side, including uncracked accounts). The candidate is never stored or logged; only redacted matches and a count are returned.",
			InputSchema: map[string]any{"type": "object", "properties": map[string]any{
				"audit_id": map[string]any{"type": "string"},
				"password": map[string]any{"type": "string"},
			}, "required": []string{"password"}},
			Role: auth.RoleAnalyst, NeedsUnlock: true,
			Handler: mcpPasswordInUse,
		},
		{
			Name:        "get_report",
			Description: "The actionable report for an audit (cracked accounts, password-reuse groups, HIBP-exposed, DA pathways, escalations, weak/never-expires/stale, roastable). Redacted — no cleartext. Optional audit_id.",
			InputSchema: auditIDSchema("Audit id; omit for the latest."),
			Role:        auth.RoleAnalyst, NeedsUnlock: true,
			Handler: func(s *Server, c *mcpCall) (any, string, error) {
				id, err := s.resolveAuditID(argAuditID(c.Args))
				if err != nil {
					return nil, "", err
				}
				accts, err := s.Store.Accounts(id, true) // unredacted to group by NT hash; BuildReport redacts
				if err != nil {
					return nil, id, fmt.Errorf("accounts unavailable: %w", err)
				}
				return model.BuildReport(accts), id, nil
			},
		},
		{
			Name:        "diff_audits",
			Description: "Compare two audits: accounts newly cracked, remediated, regressed, and newly breached. Requires audit_id_a and audit_id_b.",
			InputSchema: map[string]any{"type": "object", "properties": map[string]any{
				"audit_id_a": map[string]any{"type": "string"},
				"audit_id_b": map[string]any{"type": "string"},
			}, "required": []string{"audit_id_a", "audit_id_b"}},
			Role: auth.RoleAnalyst, NeedsUnlock: true,
			Handler: mcpDiffAudits,
		},
```
Add the handlers (and `"github.com/watson0x90/PasswordAtTheDisco/internal/hibp"` + `"github.com/watson0x90/PasswordAtTheDisco/internal/report"` imports):
```go
func mcpPasswordInUse(s *Server, c *mcpCall) (any, string, error) {
	var a struct {
		AuditID  string `json:"audit_id"`
		Password string `json:"password"`
	}
	_ = json.Unmarshal(c.Args, &a)
	if a.Password == "" {
		return nil, "", fmt.Errorf("password is required")
	}
	id, err := s.resolveAuditID(a.AuditID)
	if err != nil {
		return nil, "", err
	}
	full, err := s.Store.Accounts(id, true) // includeSecrets to read NTHash
	if err != nil {
		return nil, id, fmt.Errorf("accounts unavailable: %w", err)
	}
	candidate := hibp.NTLMHash(a.Password)
	matches := []model.Account{}
	for _, x := range full {
		if x.NTHash != "" && strings.EqualFold(x.NTHash, candidate) {
			matches = append(matches, x.Redacted())
		}
	}
	// audit target is the COUNT only — never the candidate password.
	return map[string]any{"count": len(matches), "matches": matches}, fmt.Sprintf("matches=%d", len(matches)), nil
}

func mcpDiffAudits(s *Server, c *mcpCall) (any, string, error) {
	var a struct {
		A string `json:"audit_id_a"`
		B string `json:"audit_id_b"`
	}
	_ = json.Unmarshal(c.Args, &a)
	if a.A == "" || a.B == "" {
		return nil, "", fmt.Errorf("audit_id_a and audit_id_b are required")
	}
	if !s.Store.Has(a.A) || !s.Store.Has(a.B) {
		return nil, "", fmt.Errorf("unknown audit_id_a or audit_id_b")
	}
	accA, err := s.Store.Accounts(a.A, false)
	if err != nil {
		return nil, a.A + ".." + a.B, fmt.Errorf("accounts A unavailable: %w", err)
	}
	accB, err := s.Store.Accounts(a.B, false)
	if err != nil {
		return nil, a.A + ".." + a.B, fmt.Errorf("accounts B unavailable: %w", err)
	}
	metaA, _ := s.Store.Meta(a.A)
	metaB, _ := s.Store.Meta(a.B)
	return map[string]any{"a": metaA, "b": metaB, "diff": report.ComputeDiff(accA, accB)}, a.A + ".." + a.B, nil
}
```
**Confirm** `report.ComputeDiff` signature and that `handleDiff` (server.go ~1808) reads accounts the same way (`s.Store.Accounts(id, false)`); match it exactly.

- [ ] **Step 3: Run** `go test ./internal/httpapi/ -run 'TestTools|TestProbe' -v` → PASS. gofmt.

- [ ] **Step 4: Commit**
```bash
git add internal/httpapi/mcp_tools.go internal/httpapi/mcp_tools_test.go
git commit -m "feat(mcp): password_in_use + get_report + diff_audits tools"
```

---

## Task 6: `reveal_password` (lead-gated, audited)

**Files:** Modify `internal/httpapi/mcp_tools.go`, `internal/httpapi/mcp_tools_test.go`.

- [ ] **Step 1: Failing test** (append):
```go
func TestRevealPasswordLeadOnly(t *testing.T) {
	s, analyst, lead := mcpToolServer(t)
	seedMCPStore(t, s) // seeds account alice@CORP cracked with password "Summer2024!"
	// analyst -> denied
	an := rpc(t, s, analyst, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"reveal_password","arguments":{"username":"alice","domain":"CORP"}}}`)
	if !strings.Contains(an.Body.String(), "lead") {
		t.Fatalf("analyst reveal must be denied: %s", an.Body.String())
	}
	// lead -> cleartext
	ld := rpc(t, s, lead, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"reveal_password","arguments":{"username":"alice","domain":"CORP"}}}`)
	if strings.Contains(ld.Body.String(), "isError") || !strings.Contains(ld.Body.String(), "Summer2024!") {
		t.Fatalf("lead reveal must return cleartext: %s", ld.Body.String())
	}
	// unknown account -> tool error
	nf := rpc(t, s, lead, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"reveal_password","arguments":{"username":"ghost","domain":"CORP"}}}`)
	if !strings.Contains(nf.Body.String(), "isError") {
		t.Fatalf("missing account must be a tool error: %s", nf.Body.String())
	}
}
```
Run → FAIL (handler is the not-implemented stub from Task 2).

- [ ] **Step 2: Implement** — replace the `reveal_password` registry entry's stub handler with the real one. The entry (already declared `Role: auth.RoleLead, NeedsUnlock: true`):
```go
		{
			Name:        "reveal_password",
			Description: "Reveal the cleartext password for ONE account (username + domain) in an audit. Lead token only; every reveal is audit-logged (the account, never the password).",
			InputSchema: map[string]any{"type": "object", "properties": map[string]any{
				"audit_id": map[string]any{"type": "string"},
				"username": map[string]any{"type": "string"},
				"domain":   map[string]any{"type": "string"},
			}, "required": []string{"username", "domain"}},
			Role: auth.RoleLead, NeedsUnlock: true,
			Handler: mcpRevealPassword,
		},
```
Add the handler:
```go
func mcpRevealPassword(s *Server, c *mcpCall) (any, string, error) {
	var a struct {
		AuditID  string `json:"audit_id"`
		Username string `json:"username"`
		Domain   string `json:"domain"`
	}
	_ = json.Unmarshal(c.Args, &a)
	if a.Username == "" || a.Domain == "" {
		return nil, "", fmt.Errorf("username and domain are required")
	}
	id, err := s.resolveAuditID(a.AuditID)
	if err != nil {
		return nil, "", err
	}
	target := a.Username + "@" + a.Domain
	acct, found := s.Store.FindByDomain(id, a.Username, a.Domain)
	if !found {
		return nil, target, fmt.Errorf("account not found: %s", target)
	}
	// Cleartext leaves the process here — the one audited reveal path. Mirrors handleReveal.
	return map[string]any{"username": acct.Username, "domain": acct.Domain, "password": acct.Password}, target, nil
}
```
**Security re-check (already enforced by dispatch, keep it):** `tools/call` checks `roleAtLeast(tok.Role, RoleLead)` for this tool BEFORE the handler runs and audits `denied`. The handler itself only runs for a lead token. The dispatch's success audit logs `action: mcp_tool:reveal_password`, `target: alice@CORP`, `result: ok` — never the password. Confirm by reading the `logCall` in `mcpToolsCall`.

- [ ] **Step 3: Run** `go test ./internal/httpapi/ -run 'TestTools|TestReveal' -v && go test ./...` → PASS. gofmt.

- [ ] **Step 4: Commit**
```bash
git add internal/httpapi/mcp_tools.go internal/httpapi/mcp_tools_test.go
git commit -m "feat(mcp): reveal_password tool (lead-gated, one account, audit-logged)"
```

---

## Task 7: Whole-of-B verification (gates + live JSON-RPC e2e)

**Files:** none (verification only). Run by the controller.

- [ ] **Step 1: Full gate sweep**

`gofmt -l cmd internal` (empty) · `go build ./... && go vet ./... && go test ./...` · `govulncheck ./...`. (No web changes in B.)

- [ ] **Step 2: Live JSON-RPC e2e** (embed build + restart; the running store already holds a seeded audit, or create/open one). Mint tokens via the CLI, then:
```bash
A=$(./patd.exe token create --role analyst --label e2e-a --file mcp_tokens.json 2>/dev/null)
L=$(./patd.exe token create --role lead    --label e2e-l --file mcp_tokens.json 2>/dev/null)
# initialize + tools/list (analyst sees 8, no reveal_password)
curl -s -H "Authorization: Bearer $A" -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' http://127.0.0.1:8443/api/mcp
# a data tool
curl -s -H "Authorization: Bearer $A" -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_posture","arguments":{}}}' http://127.0.0.1:8443/api/mcp
# analyst reveal -> denied; lead reveal -> cleartext (pick a known cracked account)
curl -s -H "Authorization: Bearer $A" -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"reveal_password","arguments":{"username":"<u>","domain":"<d>"}}}' http://127.0.0.1:8443/api/mcp
curl -s -H "Authorization: Bearer $L" -d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"reveal_password","arguments":{"username":"<u>","domain":"<d>"}}}' http://127.0.0.1:8443/api/mcp
```
Confirm: analyst `tools/list` omits `reveal_password`; `get_posture` returns a summary; analyst reveal → `isError` "lead token"; lead reveal → cleartext; the audit log shows `mcp_tool:*` events and a `mcp_tool:reveal_password` with the account but **no password**; `grep patdmcp_ audit.log` is empty. Revoke the e2e tokens afterward.

- [ ] **Step 3: Hand-off.** B is complete: an MCP client can connect to `/api/mcp` with a token and use the tools; reveal is lead-gated and audited. Together with A this completes the MCP feature — proceed to finishing-a-development-branch (merge to main) and tag the release.

---

## Self-Review (completed by plan author)

**Spec coverage:** §1 transport/protocol → Task 1; §3 endpoint/methods → Task 1–2; §4 tool set → Tasks 2 (list_audits) / 3 (posture, domain) / 4 (list, search) / 5 (probe, report, diff) / 6 (reveal); §5 dispatch+authz+audit → Task 2; §6 reveal → Task 6; §7 result/pagination/redaction → Task 4 (caps) + handlers return redacted shapes; §8 errors → Tasks 1–2 (JSON-RPC vs tool error); §9 testing → per-task + Task 7. Covered.

**Type consistency:** `mcpTool`/`mcpCall`/`mcpToolset`/`mcpToolsList(r,req)`/`mcpToolsCall(r,req)`/`mcpToolResult`/`mcpToolError`/`roleAtLeast`/`resolveAuditID`/`latestAuditID`/`argAuditID`/`auditIDSchema`/`domainBreakdown` are defined in Tasks 2–3 and used consistently after; handler signature `func(s *Server, c *mcpCall) (any, string, error)` is uniform across all tools.

**Placeholder scan:** no TBD/"add error handling"/"similar to". The Task-1 `mcpToolsList`/`mcpToolsCall` stubs are explicitly flagged "REPLACED in Task 2 — do not leave them." Several "confirm exact field names / signatures against the store/report packages" notes are deliberate: the store struct field names (e.g. `AuditListItem.UpdatedAt`) and `report.ComputeDiff`'s exact signature must be read from source, but every store CALL the handlers make is named and grounded in an existing handler (`handleProbe`/`handleReport`/`handleDiff`/`handleReveal`).
