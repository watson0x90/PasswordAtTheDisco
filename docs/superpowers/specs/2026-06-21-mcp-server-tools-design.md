# MCP Server + Tools (sub-project B) — Design

> **Part 2 of 2.** Builds on sub-project A (the API-token credential system —
> `docs/superpowers/specs/2026-06-21-mcp-token-system-design.md`, merged to `main`).
> A delivered `requireMCPToken` (bearer auth attaching an `analyst|lead` role) and a
> `GET /api/mcp/whoami` probe. B delivers the actual MCP server: a Streamable-HTTP
> JSON-RPC endpoint and a tool registry that lets external agents (Gemini, Kiro, …)
> query the audit data — and, for lead tokens, reveal cleartext — through their tokens.

**Goal:** Expose patd's existing read capabilities (and the lead-gated cleartext
reveal) to MCP clients over a single authenticated HTTP endpoint, so an agent with a
valid token can list audits, inspect posture, query/search redacted accounts, probe a
candidate password, diff audits, and (lead only) reveal one account's cleartext — every
call role-checked and audit-logged.

---

## 1. Decisions locked during brainstorming

- **Transport:** remote, served by patd at **`POST /api/mcp`**, wrapped in
  `requireMCPToken`. **Stateless, JSON-response Streamable HTTP** — each POST returns
  `application/json`; no SSE stream, no `Mcp-Session-Id` (our tools are request/response
  with no server-initiated messages). The simplest spec-compliant form.
- **Protocol:** stdlib JSON-RPC 2.0; minimal MCP surface (`initialize`,
  `notifications/initialized`, `tools/list`, `tools/call`, `ping`). No new dependencies.
- **Audit selection:** every data/reveal tool takes an **optional `audit_id`**;
  when omitted it resolves to the **most-recently-updated** audit.
- **Tool set:** **Read + lead-gated reveal** (nine tools, §4). No write/mutation tools.
- **Authorization:** `tools/list` is filtered by the calling token's role; `tools/call`
  re-checks role and store-unlocked state. Every call is audit-logged.

---

## 2. Scope

**In scope (B):**
- The `POST /api/mcp` JSON-RPC endpoint + the five MCP methods.
- A tool registry (name, description, JSON-Schema input, required role, needs-unlock,
  handler) with role-filtered listing and dispatch.
- The nine read+reveal tools, reusing existing store/engine methods.
- `audit_id` resolution (param → latest), pagination caps, per-call audit, and the
  lead-gated `reveal_password`.

**Out of scope:**
- Write/mutation tools (ingest, enrichment, HIBP build, admin).
- SSE streaming / stateful MCP sessions / MCP resources & prompts (tools only).
- OAuth authorization framework (bearer tokens from A are the auth).
- Changes to the token system (A is done) beyond consuming `requireMCPToken`.

---

## 3. Architecture

### Endpoint & transport
`mux.Handle("POST /api/mcp", s.requireMCPToken(http.HandlerFunc(s.handleMCP)))`.
The handler reads the token (and its role) from context (A's `mcpTokenFrom`), decodes a
single JSON-RPC request (or a batch), dispatches, and writes a JSON-RPC response with
`Content-Type: application/json`. No `requireUnlocked` at the endpoint level — locked
state is reported per-tool (so `initialize`/`tools/list`/`ping` work while locked).

### MCP methods
- **`initialize`** → `{protocolVersion, capabilities:{tools:{}}, serverInfo:{name,version}}`.
  Echo the client's requested `protocolVersion` when supported, else return the server's
  supported version. `serverInfo` uses the build name/version.
- **`notifications/initialized`** → no response (it's a notification; id absent).
- **`ping`** → `{}`.
- **`tools/list`** → `{tools:[{name, description, inputSchema}]}`, **filtered to the
  tools the calling token's role may use** (analyst never sees `reveal_password`).
- **`tools/call`** → `{name, arguments}` → dispatch (§5). Returns MCP tool result
  `{content:[{type:"text", text:"<json>"}], isError?:bool}`.

### Files
- `internal/httpapi/mcp_server.go` — JSON-RPC 2.0 types, `handleMCP`, method dispatch
  (initialize/initialized/ping/tools-list/tools-call), JSON-RPC error helpers.
- `internal/httpapi/mcp_tools.go` — the `Tool` type, the registry (`mcpTools()`), the
  nine tool handlers (closing over `s.Store`/`s.Engine`), `audit_id` resolution, the
  pagination cap, and per-call audit.
- Tests: `internal/httpapi/mcp_server_test.go`, `internal/httpapi/mcp_tools_test.go`.

This mirrors where A's `mcp.go` lives; the tools call the same store/engine methods the
existing REST handlers use (NOT the session-coupled HTTP handlers).

---

## 4. The tool set (Read + lead-gated reveal)

Each tool: **role** (minimum), **needs-unlock** (data tools yes), inputs, output. All
outputs are the same **redacted** shapes the REST API already returns; cleartext flows
ONLY through `reveal_password`.

| Tool | Role | Unlock | Inputs | Output |
|---|---|---|---|---|
| `list_audits` | analyst | no | — | `[{id,name,created,updated,total_accounts,cracked}]` |
| `get_posture` | analyst | yes | `audit_id?` | summary: totals, risk counts, posture score, breach-impact, coverage |
| `list_accounts` | analyst | yes | `audit_id?, filter?, sort?, limit?(≤200, default 50), cursor?` | `{accounts:[redacted], total, next_cursor?}` |
| `search_accounts` | analyst | yes | `audit_id?, query` | redacted accounts matching username/domain (capped) |
| `domain_breakdown` | analyst | yes | `audit_id?` | per-domain stats (accounts, cracked, breached, critical, DA paths) |
| `password_in_use` | analyst | yes | `audit_id?, password` | `{count, matches:[redacted]}` — candidate matched by NT hash server-side, **never stored/logged** |
| `get_report` | analyst | yes | `audit_id?, section?` | the actionable report, or one named section; large sub-lists capped with counts |
| `diff_audits` | analyst | yes | `audit_id_a, audit_id_b` | the audit diff (newly cracked / remediated / regressed / newly breached) |
| `reveal_password` | **lead** | yes | `audit_id?, username, domain` | `{username, domain, password}` — cleartext for ONE account |

**`audit_id` resolution:** a tool that accepts `audit_id` uses it when present (404-style
tool error if unknown), else the most-recently-updated audit (tool error if no audits
exist). `list_audits` needs none; `diff_audits` requires both ids.

**`filter`/`sort` for `list_accounts`:** a small, documented set mirroring the REST
accounts query (e.g. filter by `risk_level`, `cracked`, `domain`, `has_da`,
`hibp_breached`; sort by `risk_score`/`username`). Anything unspecified is rejected with
a clear tool error rather than silently ignored.

---

## 5. `tools/call` dispatch & authorization

1. Look up the tool by `name`; unknown → JSON-RPC "method not found"-class tool error.
2. **Role check:** if the token's role is below the tool's required role → tool error
   `{isError:true}` "this tool requires a lead token" (and audit `result:"denied"`).
   (Analyst tokens can't even see `reveal_password` via `tools/list`, but the call path
   re-checks — defense in depth.)
3. **Unlock check:** if the tool needs unlock and `!s.Store.Unlocked()` → tool error
   "data store is locked".
4. **Resolve `audit_id`** (param → latest); unknown/none → tool error.
5. **Validate arguments** against the tool's input schema (required fields present, types
   correct); invalid → tool error naming the bad field.
6. Run the handler; map a handler error to `{isError:true, content:[text:msg]}`.
7. **Audit** (always, success or failure): actor = token id (+label), role,
   `action = "mcp_tool:"+name`, target = a safe summary (audit_id; `username@domain`
   for reveal; for `password_in_use` the **match count only**, never the candidate),
   `source` = remote addr, `result` = ok/denied/error.

A tool error is returned as a normal JSON-RPC *result* with `isError:true` (MCP's
convention so the model sees the error), NOT a JSON-RPC protocol error — protocol errors
are reserved for malformed requests / unknown methods / auth failures.

---

## 6. `reveal_password` (the dangerous tool)

- **Lead token only**, enforced in the registry (hidden from analyst `tools/list`) AND
  re-checked in the handler.
- **One account per call** (`username` + `domain` required; no bulk reveal).
- Reuses the **exact store decrypt path** that the REST `handleReveal` uses, so the
  cleartext is produced the same vetted way and never cached.
- **Audit-logged with the existing reveal semantics:** actor = token id+label, action
  `mcp_tool:reveal_password`, target = `username@domain`, result — **never the password**.
  Mirrors the REST reveal audit so the Activity view shows MCP reveals alongside UI ones.
- Returns `{username, domain, password}` as the tool's JSON text content. This is the one
  path by which cleartext leaves the process to an MCP client — by design, gated and
  audited.

---

## 7. Result shape, size & safety

- Tool results are MCP `content` arrays with a single `{type:"text", text:"<json>"}`
  block whose text is the JSON-encoded result (broadly client-compatible; Gemini/Kiro/
  Claude all read text content).
- **Hard caps:** `list_accounts` `limit` ≤ 200 (default 50) with opaque cursor
  pagination returning `next_cursor`; `search_accounts` capped (e.g. 200) with a
  `truncated` flag; `get_report` sub-lists capped with their true counts so an agent
  can drill down via `list_accounts` rather than pulling everything at once.
- **Redaction at the tool layer:** every non-reveal tool returns the same redacted
  account shape the REST API emits (no NT hash, no cleartext). The redaction is applied
  in the tool handler, not trusted from callers.

---

## 8. Error handling

- **JSON-RPC protocol errors** (`-32700` parse, `-32600` invalid request, `-32601`
  method not found, `-32602` invalid params, `-32603` internal) for malformed
  envelopes / unknown JSON-RPC methods.
- **Auth** is the transport's job: a bad/expired/disabled token never reaches dispatch
  (A's `requireMCPToken` returns HTTP 401 before any JSON-RPC parsing).
- **Tool-level failures** (unknown tool name, role denied, locked store, bad arguments,
  unknown audit, handler error) are returned as `tools/call` *results* with
  `isError:true`, so the agent gets an actionable message.
- The store-locked and rekey-in-progress states surface as tool errors, not 5xx.

---

## 9. Testing

- **Protocol** (`mcp_server_test.go`): `initialize` returns version+capabilities;
  `ping`→`{}`; `notifications/initialized` yields no body; malformed JSON →`-32700`;
  unknown method →`-32601`; bad params →`-32602`. Auth is exercised via A's middleware.
- **Registry/dispatch** (`mcp_tools_test.go`): `tools/list` lists the 8 read tools for an
  analyst token and all 9 for a lead token (reveal hidden from analyst); `tools/call`
  enforces role (analyst→`reveal_password` denied), unlock (locked store → tool error),
  `audit_id` defaulting to latest, argument validation, and pagination caps.
- **Each tool handler** against a seeded in-memory store: correct redacted shapes, the
  probe matches by hash without storing the candidate, diff requires both ids,
  `reveal_password` returns cleartext for a lead and is audit-logged with no password in
  the event.
- **Audit:** every `tools/call` emits an `mcp_tool:<name>` event; the reveal event
  contains `username@domain` but never the password; `password_in_use` logs only a count.
- **Live e2e:** point `curl` (JSON-RPC) — and ideally a real MCP client — at `/api/mcp`
  with an analyst token (list/posture/accounts/search/probe/report/diff) and a lead token
  (reveal one account); confirm `tools/list` role-filtering and that reveals land in the
  audit log. All gates green (`gofmt`, `go build/vet/test`, `govulncheck`; web unaffected).

---

## 10. Definition of done (B)

An agent configured with an analyst token can `initialize`, `tools/list` (8 tools), and
call them to explore an audit's posture/accounts/domains/search/probe/report/diff with
redacted results and paginated account lists; a lead token additionally sees and can call
`reveal_password` to get one account's cleartext; an analyst token calling
`reveal_password` is denied; every tool call is in the audit log (reveal with the account,
never the password); and a real MCP client (Gemini/Kiro) can connect to `/api/mcp` with a
bearer token. Together with A, this completes the MCP feature → tag the release.
