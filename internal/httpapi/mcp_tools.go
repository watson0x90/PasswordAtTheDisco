package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/watson0x90/PasswordAtTheDisco/internal/audit"
	"github.com/watson0x90/PasswordAtTheDisco/internal/auth"
	"github.com/watson0x90/PasswordAtTheDisco/internal/hibp"
	"github.com/watson0x90/PasswordAtTheDisco/internal/model"
	"github.com/watson0x90/PasswordAtTheDisco/internal/report"
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

// auditIDSchema is the shared JSON Schema for tools taking an optional audit_id.
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

// domainBreakdown groups REDACTED accounts into per-domain stats, sorted by count desc.
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
	sort.Slice(out, func(i, j int) bool {
		if out[i].Accounts != out[j].Accounts {
			return out[i].Accounts > out[j].Accounts
		}
		return out[i].Domain < out[j].Domain // deterministic tiebreaker
	})
	return out
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
				"limit":         map[string]any{"type": "integer", "description": "1-200 (default 50)"},
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
			Description: "The actionable report for an audit (cracked accounts, password-reuse groups, HIBP-exposed, DA pathways, escalations, weak/never-expires/stale, roastable). Redacted - no cleartext. Optional audit_id.",
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
		logCall("", "locked")
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
	var out []model.Account
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
	switch a.Sort {
	case "username":
		sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	default:
		// username tiebreaker keeps pagination stable across pages when scores tie.
		sort.Slice(out, func(i, j int) bool {
			if out[i].RiskScore != out[j].RiskScore {
				return out[i].RiskScore > out[j].RiskScore
			}
			return out[i].Username < out[j].Username
		})
	}
	total := len(out)
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
	res := map[string]any{"accounts": out[offset:end], "total": total}
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
	// audit target is the COUNT only - never the candidate password.
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
