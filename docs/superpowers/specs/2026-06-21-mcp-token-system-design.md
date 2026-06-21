# MCP Token / Credential System (sub-project A) — Design

> **Part 1 of 2.** This sub-project builds the API-token credential system that the
> MCP server will use for authentication. **Sub-project B** (the Streamable-HTTP MCP
> endpoint + tool registry, including the lead-gated reveal tool) is specified
> separately and **depends on A**. A must produce working, independently testable
> software on its own.

**Goal:** Add a new credential type — role-scoped **API tokens** — distinct from
operator sessions, so external agents (Gemini, Kiro, …) can authenticate to patd
programmatically with an **ID + secret** bearer credential that leads can issue,
scope, audit, and revoke.

**Owner:** watson0x90 · single CGO-free static binary · Go stdlib-first.

---

## 1. Context & rationale

patd already has one non-session bearer path: `PATD_INGEST_TOKEN` (a single shared
secret validated by `requireIngestToken` for `POST /api/ingest`). That is the
precedent, but it is one global secret with no identity, scope, expiry, or
revocation. This sub-project generalises it into a managed, multi-consumer credential
set so each external agent gets its own auditable, revocable, role-scoped token.

Roles reuse the existing `auth.Role`: **`analyst`** (redacted data only) and
**`lead`** (may reveal cleartext — exercised in B). A token's role is therefore the
single lever that decides whether an agent can ever reach cleartext.

---

## 2. Decisions locked during brainstorming

- **Transport (B):** remote MCP over HTTP, served by the patd binary; A provides the
  bearer auth it will consume.
- **Capability ceiling (B):** may include lead-scoped, audit-logged cleartext reveal.
  Therefore A's token role is security-critical and lead is a deliberate grant.
- **Scoping:** **role only** (`analyst` | `lead`). No per-tool or per-data scoping in
  v1 (YAGNI).
- **Management:** **lead-gated Admin UI + a CLI bootstrap.** Analyst operators can
  neither issue nor view tokens.
- **Hashing:** store **`sha256(secret)`**, not argon2 — approved. Rationale in §4.
- **Expiry:** optional per token.
- **Implementation:** Go stdlib only; no new dependencies.

---

## 3. Scope

**In scope (A):**
- Token data model + flat-file store with hot-reload (mirrors the operator store).
- Token generation, hashing, and constant-time verification.
- `requireMCPToken` HTTP middleware that authenticates a bearer token and attaches
  its role to the request context.
- A minimal `GET /api/mcp/whoami` probe (token-authenticated) that returns the
  calling token's id + role — the end-to-end proof that A works before B exists.
- Lead-gated token management: HTTP handlers, `patd token` CLI, and an Admin UI panel.
- Audit events for issuance and revocation.

**Out of scope (deferred to B):**
- The MCP protocol (JSON-RPC, `initialize` / `tools/list` / `tools/call`), the
  Streamable-HTTP transport, the tool registry, per-tool authorization, per-tool-call
  audit, and the reveal tool.

---

## 4. Token format & crypto

### Format
A single opaque string, GitHub-style, self-identifying:

```
patdmcp_<id>_<secret>
```

- **`id`** — 10 random bytes, **base32** (`encoding/base32`, RawStdEncoding,
  lowercased → `[a-z2-7]`, ~16 chars), public. Used for lookup, display, "last used",
  and revocation.
- **`secret`** — 32 random bytes (~256-bit), **base32** (lowercased, ~52 chars), shown
  **exactly once** at creation.
- base32 is chosen because it is **stdlib** (no custom encoder), contains **no `_`**,
  and is URL/header-safe — so the credential splits unambiguously into exactly three
  parts on `_`. The id and secret are treated as **opaque strings** (the secret is
  hashed as-is; the id is a lookup key) — neither is ever base32-decoded, so lowercasing
  is free.
- The `patdmcp_` prefix lets secret scanners flag leaks and lets the server reject
  non-tokens cheaply.

`crypto/rand` is the only entropy source; `crypto/sha256`, `crypto/subtle`, and
`encoding/base32` complete the crypto surface — all stdlib.

### Storage
Never store the secret. Store the public `id` plus **`sha256(secret)`** as hex.

**Why SHA-256, not argon2 (a deliberate departure from the project's argon2-only
stance — approved):** argon2's slowness exists to defend *low-entropy human
passwords* against offline brute-force. These secrets are 256-bit random, infeasible
to brute-force regardless of hash speed, so a fast cryptographic hash is the correct,
standard tool (GitHub/Stripe/etc. do exactly this) and avoids paying tens of
milliseconds of argon2 on every MCP request. **Operator passwords remain argon2id;**
only high-entropy machine tokens use SHA-256.

### Verification
`Verify(tokenString) (APIToken, bool)`:
1. Reject anything not matching `patdmcp_<id>_<secret>` (3 base62 parts).
2. Look up the record by `id`.
3. Compute `sha256(secret)` and **constant-time compare** (`crypto/subtle`) against
   the stored hash.
4. Reject if `disabled` or (`expires` set and in the past).
5. On any miss (unknown id, bad secret), still run a constant-time compare against a
   fixed dummy hash to equalise timing — mirrors the `dummyHash` trick in
   `internal/auth/users.go`.

---

## 5. Data model & storage

### Record (`internal/auth/apitoken.go`)
```go
type APIToken struct {
    ID         string     `json:"id"`                   // public
    SecretHash string     `json:"secret_hash"`          // hex sha256(secret)
    Role       Role       `json:"role"`                 // "analyst" | "lead"
    Label      string     `json:"label"`                // human description
    Created    time.Time  `json:"created"`
    Expires    *time.Time `json:"expires,omitempty"`    // nil = never
    Disabled   bool       `json:"disabled,omitempty"`
    LastUsed   *time.Time `json:"last_used,omitempty"`
}
```

### Store
- Flat JSON file **`mcp_tokens.json`** (a JSON array of records). Path from
  **`PATD_MCP_TOKENS_FILE`** (default sits beside `users.json`). Gitignored; a
  tracked **`mcp_tokens.example.json`** documents the shape.
- A `TokenStore` type owns load / atomic-save / **hot-reload**, reusing the same
  watching/reload mechanism as the operator store (`internal/auth/userstore.go`).
- Validation **does not require the encrypted store to be unlocked** — tokens are
  their own flat file, exactly like `users.json` — so the MCP endpoint can
  authenticate while the data store is locked, and B's data tools then return a clean
  "store locked" error (the same way login works before unlock).

### `last_used`
Updated **in memory** on every successful verify; persisted **throttled** to ≤ once
per minute per token (dirty-flag + periodic/at-shutdown flush) to avoid a disk write
on every request. `last_used` precision of ~1 minute is acceptable.

### Store API (interface level)
```go
func (s *TokenStore) Issue(role Role, label string, expires *time.Time) (full string, rec APIToken, err error)
func (s *TokenStore) Verify(tokenString string) (APIToken, bool)
func (s *TokenStore) List() []APIToken          // redacted: SecretHash zeroed/omitted for callers
func (s *TokenStore) Revoke(id string) bool     // removes the record
func (s *TokenStore) touchLastUsed(id string)   // in-memory + throttled flush
```
`Issue` is the only place the full token string exists; it is returned to the caller
once and never persisted.

---

## 6. Authorization

- The token's `Role` is attached to the request context by `requireMCPToken`.
- `analyst` → B's redacted tools only; `lead` → also B's reveal tool. (A only carries
  the role; B enforces per-tool.)
- **Token management is lead-only.** Reuse the lead-role gating pattern already used
  by the reveal handler: management handlers require an authenticated operator with
  `role == lead`, else **403**. Analysts cannot list or issue tokens.

---

## 7. HTTP surface

### Token-authenticated probe (proves A end-to-end)
| Method & path | Auth | Behaviour |
|---|---|---|
| `GET /api/mcp/whoami` | `requireMCPToken` | `200 {"token_id","role"}`. No CSRF (bearer, not cookie). `401` on any bad/expired/disabled token. |

### Management (operator session; **lead-gated**)
All `requireAuth` + `requireCSRF` (for mutations) + lead check.

| Method & path | Behaviour |
|---|---|
| `GET /api/mcp/tokens` | List, **redacted** — never returns `secret_hash`. Fields: id, label, role, created, last_used, expires, disabled. |
| `POST /api/mcp/tokens` | Body `{label, role, expires?}`. `201` returning the **full token once** plus the record. Validates role ∈ {analyst,lead} and non-empty label, else `400`. Audited `token_create`. |
| `DELETE /api/mcp/tokens/{id}` | Revoke (remove the record). `204`. `404` if unknown. Audited `token_revoke`. |

Non-lead operator on any management route → `403`.

---

## 8. CLI bootstrap (`cmd/patd`)

A `token` subcommand operating **directly on the tokens file** (no running server
needed — for first-boot bootstrap), resolving the path from `PATD_MCP_TOKENS_FILE` or
a `--file` flag:

- `patd token create --role <analyst|lead> --label <text> [--expires <duration|RFC3339>]`
  → writes the record, **prints the full token once** + its id.
- `patd token list [--file <path>]` → table: id, label, role, created, last-used,
  expires, status. Never prints secrets/hashes.
- `patd token revoke <id>` → removes the record.

Mirrors the existing `hashpw` subcommand's structure.

---

## 9. Admin UI (lead-gated)

A **Tokens** panel in the existing Admin area (next to operator management), built
with the `frontend-design` skill and Playwright-verified:
- **List**: id, label, role badge, created, last-used, expiry, status; Revoke action
  (with confirm).
- **Issue token**: form (label; role `<select>` with an explicit **warning when
  `lead` is chosen** — a lead token can surface AD cleartext via the MCP reveal tool;
  optional expiry). On success, show the **full token once** in a copy box with a
  "you will not see this again" notice.
- API-client methods added to `web/src/api.ts`; panel hidden/disabled for analyst
  operators (backend still enforces).
- Web tests are node-env pure-logic; styleguard applies (no literal inline spacing).

---

## 10. Audit, errors, rate limiting

- **Audit** (`internal/audit`): add `token_create` (actor operator, token id, role,
  label) and `token_revoke` (actor operator, token id). **Never** record the secret.
- **Errors**: `401` for any bad MCP token (no hint which part failed); `403` for a
  non-lead operator on management routes; `400` for an invalid create body. Consistent
  JSON `{"error": "..."}`.
- **Rate limiting**: apply the existing per-IP limiter (`internal/auth/ratelimit.go`)
  to `requireMCPToken` failures — defense-in-depth + auth-failure log-noise control.

---

## 11. Testing

- **Token core** (`apitoken_test.go`): format/entropy of generated tokens; `Verify`
  for valid / wrong-secret / unknown-id / expired / disabled, and that the
  timing-equalisation path runs on misses; `sha256` round-trip.
- **Store**: load/save round-trip, hot-reload picks up external edits, `last_used`
  throttle persists at most once/min, atomic save.
- **Middleware**: `requireMCPToken` attaches the correct role; rejects
  malformed/unknown/expired/disabled with `401`; rate-limit kicks in on repeated
  failures.
- **Handlers**: `whoami` returns id+role; `POST` returns the token exactly once and
  `201`; `GET` list never leaks `secret_hash`; `DELETE` revokes; **analyst operator →
  403** on all management routes; CSRF enforced on mutations.
- **CLI**: create/list/revoke against a temp file; secret printed once; list never
  prints secrets.
- **Web**: pure-logic tests for the Tokens panel data; styleguard.
- All existing gates stay green: `gofmt -l cmd internal`, `go build/vet/test ./...`,
  `govulncheck`, `tsc`, `vitest`, web build.

---

## 12. Config & housekeeping

- New env: **`PATD_MCP_TOKENS_FILE`** (path to `mcp_tokens.json`).
- `.gitignore`: add `mcp_tokens.json`; track `mcp_tokens.example.json`.
- Server startup wires a `TokenStore` alongside the user store; the deploy
  scripts/docs note the new env var (documented when B ships the user-facing feature).

---

## 13. Definition of done (A)

A lead can mint a token via CLI or the Admin UI, an external caller can
`curl -H "Authorization: Bearer patdmcp_…" /api/mcp/whoami` and get back its id+role,
an analyst operator is 403'd from token management, revocation takes effect on the
next call, and every issue/revoke is in the audit log — all with the gates green.
**B then builds the MCP protocol and tools on top of `requireMCPToken`.**
