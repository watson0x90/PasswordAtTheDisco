package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"

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
	// Handler returns the JSON-able result, a SAFE audit target (never a secret), and an
	// error (nil => ok; non-nil => tool error).
	Handler func(s *Server, c *mcpCall) (result any, auditTarget string, err error)
}

// mcpCall is the per-call context handed to a tool handler.
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

// mcpToolset is the full registry. Handlers for most tools are added in later tasks;
// reveal_password is declared lead-only now (handler implemented in Task 6).
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
		{
			Name:        "reveal_password",
			Description: "Reveal the cleartext password for ONE account (username + domain) in an audit. Lead token only; every reveal is audit-logged (the account, never the password).",
			InputSchema: map[string]any{"type": "object", "properties": map[string]any{
				"audit_id": map[string]any{"type": "string"},
				"username": map[string]any{"type": "string"},
				"domain":   map[string]any{"type": "string"},
			}, "required": []string{"username", "domain"}},
			Role: auth.RoleLead, NeedsUnlock: true,
			Handler: func(s *Server, c *mcpCall) (any, string, error) {
				return nil, "", fmt.Errorf("not implemented") // Task 6
			},
		},
	}
}

// mcpToolsList answers tools/list, filtered to the calling token's role.
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

// mcpToolsCall dispatches tools/call: role check, unlock check, run handler, audit.
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
	tools := s.mcpToolset()
	for i := range tools {
		if tools[i].Name == p.Name {
			tool = &tools[i]
			break
		}
	}
	remote := clientIP(r)
	logCall := func(target, result string) {
		s.Audit.Log(audit.Event{Actor: mcpActor(tok), Role: string(tok.Role), Action: "mcp_tool:" + p.Name, Target: target, Source: remote, Result: result})
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
	result, target, err := tool.Handler(s, &mcpCall{Token: tok, Args: p.Arguments, RemoteAddr: remote})
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
