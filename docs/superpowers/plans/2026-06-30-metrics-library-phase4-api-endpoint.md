# Metrics Library (Phase 4: /api/metrics endpoint) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Serve the computed bundle over HTTP at `GET /api/metrics` (org bundle; `?domain=<d>` returns one domain's bundle), so the SPA can render server-computed metrics instead of recomputing them.

**Architecture:** A new `handleMetrics` mirrors `handleReport`: resolve the session's active audit, read accounts **with NT hashes** (`includeSecrets=true`) so `metrics.Compute` can build the reuse-grouped report-series/graphs, then `metrics.Compute(accts, time.Now())` and write the redacted bundle as JSON. The bundle output carries no secrets (its structs have no password/hash fields) — verified by a handler-level no-secrets test and a hardened redaction guard that feeds secret-bearing accounts in.

**Tech Stack:** Go stdlib `net/http`, `encoding/json`, `httptest`.

## Global Constraints

- **Go: stdlib-first.** `gofmt -l` empty, `go vet ./...` clean, `go test ./...` green.
- **Redaction (hard rule).** The response must contain NO cleartext (`password`), NT hash (`nt_hash`), or wordlist fragments (`banned_words`/`keyboard_patterns`). Accounts are read with secrets ONLY to feed `BuildReport`'s hash grouping; the emitted bundle is redacted by construction.
- **Auth/gating.** `GET /api/metrics` requires `requireAuth` + `requireUnlocked` (read-only, no CSRF — same as `/api/summary`, `/api/report`). Empty/no active audit → `200` with the empty bundle `metrics.Compute(nil, now)` (mirrors `/api/summary` returning `{}` and `/api/report` returning `BuildReport(nil)`).
- **Determinism not required at the endpoint** — `time.Now()` is correct for live data; the golden/unit tests inject a fixed `now`.
- **Commit messages** end with: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.
- **Run from worktree root** `C:\base\dev\PasswordAtTheDisco\.claude\worktrees\nav-and-pagination-fixes`. Do not `cd` to the primary checkout.

**Scope note:** Part of spec `docs/superpowers/specs/2026-06-30-exports-dashboard-parity-design.md`. This serves the bundle. The SPA refactor to CONSUME it (replacing the TS recompute), export parity, per-domain report-series, and the unredacted tier are later phases. `/api/summary` stays as-is for back-compat.

**Reference (existing code, do not change):** `internal/httpapi/server.go` `handleReport` (line ~1431) and `handleSummary` (~1412) show the `sessionFrom` / `activeAuditRead` / `Store.Accounts(id, includeSecrets)` / `writeJSON` pattern. Routes are registered in `Routes()` (~line 161). Test helpers in `internal/httpapi/server_test.go`: `newServer(token)`, `seed(t, srv)` (ingests `oneAccount`, returns auditID), `loginCSRF(t, srv, user, pw)`, `openAudit(t, srv, cookie, csrf, id)`, `do(srv, method, path, cookie)`.

---

### Task 1: `GET /api/metrics` handler + route

**Files:**
- Modify: `internal/httpapi/server.go` (add `handleMetrics`; register route; add imports if needed)
- Test: `internal/httpapi/metrics_endpoint_test.go` (create)

**Interfaces:**
- Consumes: `s.activeAuditRead`, `s.Store.Accounts(id, true)`, `metrics.Compute`, `writeJSON`.
- Produces: route `GET /api/metrics` → JSON `metrics.Metrics`.

- [ ] **Step 1: Write the failing test**

```go
// internal/httpapi/metrics_endpoint_test.go
package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestMetricsEndpoint(t *testing.T) {
	srv := newServer("secret")
	id := seed(t, srv)
	ac, acsrf := loginCSRF(t, srv, "analyst", "analystpw")
	openAudit(t, srv, ac, acsrf, id)

	rec := do(srv, "GET", "/api/metrics", ac)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	// the seeded fixture has one cracked account (alice) -> summary.total 1
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := body["summary"]; !ok {
		t.Error("response missing summary")
	}
	if _, ok := body["matrix"]; !ok {
		t.Error("response missing matrix")
	}
	if _, ok := body["charts"]; !ok {
		t.Error("response missing charts")
	}
	if _, ok := body["reports"]; !ok {
		t.Error("response missing reports")
	}
	// redaction: the raw JSON must not contain the seeded cleartext or any secret key
	raw := strings.ToLower(rec.Body.String())
	for _, bad := range []string{"welcome1", "nt_hash", "\"password\"", "banned_words", "keyboard_patterns"} {
		if strings.Contains(raw, bad) {
			t.Errorf("metrics response leaked %q", bad)
		}
	}
}

func TestMetricsRequiresAuth(t *testing.T) {
	srv := newServer("secret")
	if rec := do(srv, "GET", "/api/metrics", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauth status = %d, want 401", rec.Code)
	}
}
```

(`oneAccount` is `alice` with `password:"Welcome1"`, cracked, hibp_breached, da_domains "CORP" — so the bundle is non-empty and the cleartext "welcome1" must NOT appear in the redacted response.)

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/httpapi/ -run 'TestMetricsEndpoint|TestMetricsRequiresAuth' -v`
Expected: FAIL — route not registered (404, not 200/401).

- [ ] **Step 3: Add the handler**

In `internal/httpapi/server.go`, add (next to `handleReport`):

```go
// handleMetrics serves the computed dashboard bundle (summary, matrix, chart
// series, report-derived series, network graphs, and per-domain bundles) for the
// session's active audit. Like handleReport it reads accounts WITH NT hashes so the
// reuse-grouped report-series/graphs can be built; metrics.Compute emits only
// redacted, descriptive numbers -- no cleartext, no NT hash ever leaves here.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	now := time.Now()
	id, ok := s.activeAuditRead(sess)
	if !ok {
		writeJSON(w, http.StatusOK, metrics.Compute(nil, now))
		return
	}
	accts, err := s.Store.Accounts(id, true) // need NT hashes to group; bundle is redacted
	if err != nil {
		writeJSON(w, http.StatusOK, metrics.Compute(nil, now))
		return
	}
	writeJSON(w, http.StatusOK, metrics.Compute(accts, now))
}
```

Ensure imports include `"time"` and `"github.com/watson0x90/PasswordAtTheDisco/internal/metrics"` (add if missing).

- [ ] **Step 4: Register the route**

In `Routes()`, next to the `/api/summary` registration (~line 161), add:
```go
	mux.Handle("GET /api/metrics", s.requireAuth(s.requireUnlocked(http.HandlerFunc(s.handleMetrics))))
```

- [ ] **Step 5: Run tests** — `go test ./internal/httpapi/ -run 'TestMetricsEndpoint|TestMetricsRequiresAuth' -v` → PASS.

- [ ] **Step 6: Full gate + commit**

Run: `gofmt -l internal/httpapi` (empty), `go vet ./...`, `go test ./...`
```bash
git add internal/httpapi/server.go internal/httpapi/metrics_endpoint_test.go
git commit -m "$(printf 'feat(api): GET /api/metrics serves the computed bundle\n\nCo-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>')"
```

---

### Task 2: `?domain=<d>` selector + hardened redaction guard

Add the per-domain selector to the endpoint, and harden the bundle redaction guard to feed secret-bearing accounts (since the endpoint now passes secrets into `Compute`).

**Files:**
- Modify: `internal/httpapi/server.go` (`handleMetrics` honors `?domain=`)
- Modify: `internal/httpapi/metrics_endpoint_test.go` (add `?domain=` test)
- Modify: `internal/metrics/golden_test.go` (harden `TestBundleHasNoSensitiveFields` to feed secrets)

**Interfaces:**
- Produces: `GET /api/metrics?domain=<d>` → JSON `metrics.DomainMetrics` for that domain; `404` if the domain isn't in the active audit.

- [ ] **Step 1: Write the failing tests**

Add to `internal/httpapi/metrics_endpoint_test.go`:
```go
func TestMetricsDomainSelector(t *testing.T) {
	srv := newServer("secret")
	id := seed(t, srv)
	ac, acsrf := loginCSRF(t, srv, "analyst", "analystpw")
	openAudit(t, srv, ac, acsrf, id)

	// the seeded account is in domain CORP
	rec := do(srv, "GET", "/api/metrics?domain=CORP", ac)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var dm map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &dm); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if dm["domain"] != "CORP" {
		t.Errorf("domain = %v, want CORP", dm["domain"])
	}
	if _, ok := dm["summary"]; !ok {
		t.Error("domain bundle missing summary")
	}

	// unknown domain -> 404
	if rec := do(srv, "GET", "/api/metrics?domain=NOPE", ac); rec.Code != http.StatusNotFound {
		t.Errorf("unknown domain status = %d, want 404", rec.Code)
	}
}
```

Harden `internal/metrics/golden_test.go` `TestBundleHasNoSensitiveFields` (replace its body to feed secret-bearing accounts) — change the accounts it marshals so they carry secrets that MUST be stripped:
```go
func TestBundleHasNoSensitiveFields(t *testing.T) {
	now := time.Date(2026, 6, 30, 0, 0, 0, 0, time.UTC)
	// Feed accounts that DO carry secrets — the bundle must strip every one.
	secret := "SuperSecretCleartextPassword!"
	ntHash := "ABCDEF0123456789ABCDEF0123456789"
	accts := []model.Account{
		{Username: "alice", Domain: "A", Cracked: true, RiskLevel: "Critical", DADomains: "A",
			Password: secret, NTHash: ntHash, BannedWords: []string{"forbiddenword"},
			KeyboardPatterns: []string{"qwerty"}},
		{Username: "bob", Domain: "A", Cracked: true, RiskLevel: "High",
			Password: secret, NTHash: ntHash},
	}
	raw, err := json.Marshal(Compute(accts, now))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	low := strings.ToLower(string(raw))
	for _, bad := range []string{strings.ToLower(secret), strings.ToLower(ntHash), "forbiddenword", "qwerty", "\"password\"", "\"nt_hash\"", "banned_words", "keyboard_patterns"} {
		if strings.Contains(low, bad) {
			t.Errorf("bundle leaked sensitive content %q", bad)
		}
	}
}
```
(If `golden_test.go` lacks `strings`, add the import.)

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/httpapi/ -run TestMetricsDomainSelector -v` (FAIL — `?domain=` ignored, returns org bundle so `domain` key absent / 404 not produced) and `go test ./internal/metrics/ -run TestBundleHasNoSensitiveFields -v` (should still PASS — the bundle is already redacted; this strengthens the guard. If it FAILS, a real leak exists — STOP and report).

- [ ] **Step 3: Implement the selector**

In `handleMetrics`, after computing `m := metrics.Compute(accts, now)` (restructure to a named var), honor the query param:
```go
	m := metrics.Compute(accts, now)
	if d := r.URL.Query().Get("domain"); d != "" {
		for i := range m.Domains {
			if m.Domains[i].Domain == d {
				writeJSON(w, http.StatusOK, m.Domains[i])
				return
			}
		}
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "domain not found"})
		return
	}
	writeJSON(w, http.StatusOK, m)
```
(Apply the same `?domain=` handling in the no-active-audit / error branches is unnecessary — those return the empty org bundle; a `?domain=` against an empty audit yields 404, which is fine. To keep it simple, move the `?domain=` check to operate on whatever `m` was computed; for the empty-audit branch, `metrics.Compute(nil, now).Domains` is empty so `?domain=` → 404, which is acceptable. Ensure the empty/error branches still return before the selector OR also run the selector — pick one and keep it consistent; simplest: compute `m` once at the end from `accts` (nil on the empty/error paths) and run the selector once.)

Suggested clean restructure of the whole handler:
```go
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	now := time.Now()
	var accts []model.Account
	if id, ok := s.activeAuditRead(sess); ok {
		if a, err := s.Store.Accounts(id, true); err == nil {
			accts = a
		}
	}
	m := metrics.Compute(accts, now)
	if d := r.URL.Query().Get("domain"); d != "" {
		for i := range m.Domains {
			if m.Domains[i].Domain == d {
				writeJSON(w, http.StatusOK, m.Domains[i])
				return
			}
		}
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "domain not found"})
		return
	}
	writeJSON(w, http.StatusOK, m)
}
```

- [ ] **Step 4: Run tests** — `go test ./internal/httpapi/ -run 'TestMetrics' -v` and `go test ./internal/metrics/ -run TestBundleHasNoSensitiveFields -v` → PASS.

- [ ] **Step 5: Full gate + commit**

Run: `gofmt -l internal/httpapi internal/metrics` (empty), `go vet ./...`, `go test ./...`
```bash
git add internal/httpapi/server.go internal/httpapi/metrics_endpoint_test.go internal/metrics/golden_test.go
git commit -m "$(printf 'feat(api): /api/metrics?domain selector + harden bundle redaction guard\n\nCo-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>')"
```

---

## Self-Review

**Spec coverage (Phase 4 slice):** `GET /api/metrics` serves the org bundle; `?domain=<d>` serves one domain's bundle (404 unknown); auth+unlock gated; empty audit → empty bundle. The redaction guard is hardened to feed secret-bearing accounts (covering the endpoint's `includeSecrets=true` read). SPA consumption, exports, and the unredacted tier remain later phases.

**Placeholder scan:** No TBD/TODO; complete Go in every step. The Task 2 restructure shows the full final handler.

**Type consistency:** `handleMetrics` uses `metrics.Compute(...) metrics.Metrics` (Phase 1) with `.Domains []metrics.DomainMetrics` each having `.Domain`/`.Summary` (Phase 1). `writeJSON`, `sessionFrom`, `activeAuditRead`, `Store.Accounts(id, true)` are existing server methods (see `handleReport`). Test helpers (`newServer`/`seed`/`loginCSRF`/`openAudit`/`do`) exist in `server_test.go`. The seeded `oneAccount` is domain `CORP`, cleartext `Welcome1` — used by the redaction assertion and the `?domain=CORP` test.
