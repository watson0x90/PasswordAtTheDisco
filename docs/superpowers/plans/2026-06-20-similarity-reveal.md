# Similarity-Breakdown Password Reveal (Lead-Gated) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a lead reveal the cleartext of the selected account and its similar peers from the Password Similarity Clusters breakdown — through the existing lead-gated, audit-logged reveal, made domain-aware so the exact account is revealed.

**Architecture:** Add an optional `?domain=` to the reveal endpoint (exact account match), thread it through the client, and add a self-contained lead-gated reveal (reusing the `.secret`/`.mono-pw` UX) to the similarity breakdown. The Accounts table also keys its reveal by domain+username, fixing a latent same-username-across-domains collision.

**Tech Stack:** Go 1.26 stdlib. React 18 + TS + Vite. Gates: `gofmt -l cmd internal`, `go build/vet/test ./...`, `govulncheck ./...`; in `web/` (NEVER `npm install`): `npx tsc --noEmit`, `npx vitest run` (incl. styleguard), `npm run build`.

**Spec:** `docs/superpowers/specs/2026-06-20-similarity-reveal-design.md`

**Conventions that bite:** `styleguard.test.ts` fails on inline spacing styles in `.tsx` (CSS classes only). vitest is node-env (pure logic only). Hooks unconditional, above early returns. The reveal is lead-only + audit-logged; the password is NEVER written to the audit log.

---

## File Structure
- **Modify** `internal/store/store.go` — add `FindByDomain`.
- **Modify** `internal/httpapi/server.go` — `handleReveal` honors `?domain=`.
- **Modify** `internal/httpapi/server_test.go` — `TestRevealDomainAware`.
- **Modify** `web/src/api.ts` — `revealSecret(username, domain?)`.
- **Modify** `web/src/components/AccountsTable.tsx` — domain+username-keyed reveal.
- **Modify** `web/src/components/SimilarityClusters.tsx` — lead-gated reveal in the breakdown.
- **Modify** `web/src/styles.css` — small breakdown-reveal rules.

---

## Task 1: Backend — domain-aware reveal

**Files:** `internal/store/store.go`, `internal/httpapi/server.go`, `internal/httpapi/server_test.go`

**Context:** `Store.Find(id, username)` (store.go:649) iterates `a.ds.Accounts` and returns the first `acc.Username == username` (exact). `handleReveal` (server.go:1393) is lead-gated, fail-closed on audit, resolves via `Find`, returns `{username, password}`, and logs `reveal_secret` with `Target: username` (never the password). Test users: `lead`/`leadpw` (RoleLead), `analyst`/`analystpw` (RoleAnalyst). Ingest one audit via `POST /api/ingest` with `Authorization: Bearer secret`.

- [ ] **Step 1: Write the failing test**

Add to `internal/httpapi/server_test.go`:

```go
func TestRevealDomainAware(t *testing.T) {
	var auditBuf bytes.Buffer
	srv := newServerAudit("secret", &auditBuf)

	payload := `{"accounts":[` +
		`{"username":"svc","domain":"CORP","password":"AlphaPass1","cracked":true,"nt_hash":"AAAA","risk_level":"High"},` +
		`{"username":"svc","domain":"GHOST","password":"BetaPass2","cracked":true,"nt_hash":"BBBB","risk_level":"High"}]}`
	ireq := httptest.NewRequest("POST", "/api/ingest", strings.NewReader(payload))
	ireq.Header.Set("Authorization", "Bearer secret")
	irec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(irec, ireq)
	if irec.Code != http.StatusOK {
		t.Fatalf("ingest: %d %s", irec.Code, irec.Body.String())
	}
	var ing struct{ AuditID string `json:"audit_id"` }
	_ = json.Unmarshal(irec.Body.Bytes(), &ing)

	lc, lcsrf := loginCSRF(t, srv, "lead", "leadpw")
	openAudit(t, srv, lc, lcsrf, ing.AuditID)

	get := func(path string, cookie *http.Cookie) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", path, nil)
		if cookie != nil {
			req.AddCookie(cookie)
		}
		rec := httptest.NewRecorder()
		srv.Routes().ServeHTTP(rec, req)
		return rec
	}

	if rec := get("/api/accounts/svc/secret?domain=GHOST", lc); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "BetaPass2") || strings.Contains(rec.Body.String(), "AlphaPass1") {
		t.Errorf("reveal GHOST: %d %s", rec.Code, rec.Body.String())
	}
	if rec := get("/api/accounts/svc/secret?domain=CORP", lc); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "AlphaPass1") {
		t.Errorf("reveal CORP: %d %s", rec.Code, rec.Body.String())
	}
	// back-compat: no domain still works (returns one of them)
	if rec := get("/api/accounts/svc/secret", lc); rec.Code != http.StatusOK {
		t.Errorf("reveal no-domain: %d %s", rec.Code, rec.Body.String())
	}

	// non-lead denied
	ac, acsrf := loginCSRF(t, srv, "analyst", "analystpw")
	openAudit(t, srv, ac, acsrf, ing.AuditID)
	if rec := get("/api/accounts/svc/secret?domain=GHOST", ac); rec.Code != http.StatusForbidden {
		t.Errorf("non-lead reveal: want 403, got %d", rec.Code)
	}

	// audit log: reveal_secret target svc@GHOST, no password
	al := auditBuf.String()
	if !strings.Contains(al, "reveal_secret") || !strings.Contains(al, "svc@GHOST") {
		t.Errorf("audit missing reveal_secret svc@GHOST: %s", al)
	}
	if strings.Contains(al, "BetaPass2") || strings.Contains(al, "AlphaPass1") {
		t.Errorf("audit leaked a password: %s", al)
	}
}
```

Ensure `bytes` is imported in the test file (for `auditBuf`).

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/httpapi/ -run TestRevealDomainAware`
Expected: FAIL — `?domain=GHOST` returns the wrong/first account (or domain ignored), and the audit target is `svc` not `svc@GHOST`.

- [ ] **Step 3: Add `Store.FindByDomain`**

In `internal/store/store.go`, after `Find`:
```go
// FindByDomain returns the full (unredacted) account for username+domain within an
// audit. The exact domain match disambiguates a username that repeats across domains
// (e.g. "administrator" in every domain), which Find cannot.
func (s *Store) FindByDomain(id, username, domain string) (model.Account, bool) {
	a, err := s.ensureLoaded(id)
	if err != nil {
		return model.Account{}, false
	}
	for _, acc := range a.ds.Accounts {
		if acc.Username == username && acc.Domain == domain {
			return acc, true
		}
	}
	return model.Account{}, false
}
```

- [ ] **Step 4: Honor `?domain=` in `handleReveal`**

In `internal/httpapi/server.go` `handleReveal`, replace the top (the `username :=` line and the `ev` closure) and the `Find` lookup:
```go
	username := r.PathValue("username")
	domain := r.URL.Query().Get("domain")
	target := username
	if domain != "" {
		target = username + "@" + domain
	}
	ev := func(result string) audit.Event {
		return audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: "reveal_secret", Target: target, Source: r.RemoteAddr, Result: result}
	}
```
Then, replacing `acct, ok := s.Store.Find(id, username)`:
```go
	var acct model.Account
	var found bool
	if domain != "" {
		acct, found = s.Store.FindByDomain(id, username, domain)
	} else {
		acct, found = s.Store.Find(id, username)
	}
	if !found {
		if !s.auditOrFail(w, ev("not_found")) {
			return
		}
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "account not found"})
		return
	}
```
(Leave the lead check, `activeAudit`, the `ok` audit branch, and the `{username, password}` response unchanged. Note `id, ok := s.activeAudit(...)` already declares `ok`; the lookup now uses `found`, so no clash.)

- [ ] **Step 5: Run to verify it passes**

Run: `go test ./internal/httpapi/ -run TestRevealDomainAware -v`
Expected: PASS.

- [ ] **Step 6: Full Go gate**

Run: `gofmt -l cmd internal` (empty); `go build ./... && go vet ./... && go test ./...` (all ok); `govulncheck ./...`.

- [ ] **Step 7: Commit**

```bash
git add internal/store/store.go internal/httpapi/server.go internal/httpapi/server_test.go
git commit -m "feat(api): domain-aware reveal (?domain=) — resolve the exact account; audit username@domain"
```

---

## Task 2: Client + Accounts table — domain-keyed reveal

**Files:** `web/src/api.ts`, `web/src/components/AccountsTable.tsx`

**Context:** `api.revealSecret(username)` → `GET /accounts/{username}/secret`. AccountsTable keys its reveal state by `username`: `reveal(username)` (line 45) calls `api.revealSecret(username)` and stores `revealed[username]`; the Secret cell (lines 114-134) uses `a.username in revealed`, `revealed[a.username]`, `revealing === a.username`, `reveal(a.username)`, `hide(a.username)`. Same username in two domains collides in this state.

- [ ] **Step 1: `revealSecret` takes an optional domain**

In `web/src/api.ts`:
```ts
  revealSecret: (username: string, domain?: string) =>
    request<{ username: string; password: string }>(
      `/accounts/${encodeURIComponent(username)}/secret${domain ? `?domain=${encodeURIComponent(domain)}` : ""}`,
    ),
```

- [ ] **Step 2: Re-key AccountsTable reveal by `${domain}/${username}`**

Change `reveal` (lines 45-57) to take `(username, domain)` and key by the composite:
```tsx
  async function reveal(username: string, domain: string) {
    const key = `${domain}/${username}`
    setRevealing(key)
    setRevealError("")
    try {
      const r = await api.revealSecret(username, domain)
      setRevealed((prev) => ({ ...prev, [key]: r.password }))
      timers.current.push(window.setTimeout(() => hide(key), 45000)) // auto-hide after 45s
    } catch (e) {
      setRevealError(e instanceof ApiError ? `reveal failed: ${e.message}` : "reveal failed")
    } finally {
      setRevealing("")
    }
  }
```
Change `hide` to take the composite key (the body is unchanged — it just deletes `next[key]`):
```tsx
  function hide(key: string) {
    setRevealed((prev) => {
      const next = { ...prev }
      delete next[key]
      return next
    })
  }
```
In the Secret cell (lines 114-134), compute the key once and use it everywhere. Replace the cell's body with:
```tsx
                {isLead && (
                  <td>
                    {(() => {
                      const key = `${a.domain}/${a.username}`
                      if (!a.cracked) return <span className="muted">uncracked</span>
                      if (key in revealed) {
                        return (
                          <span className="secret">
                            <span className="mono-pw">{revealed[key]}</span>
                            <button className="link-btn" onClick={() => copy(revealed[key])} title="Copy">copy</button>
                            <button className="link-btn" onClick={() => hide(key)}>hide</button>
                          </span>
                        )
                      }
                      return (
                        <button className="reveal-btn" disabled={revealing === key} onClick={() => reveal(a.username, a.domain)}>
                          {revealing === key ? "…" : "reveal"}
                        </button>
                      )
                    })()}
                  </td>
                )}
```

- [ ] **Step 3: Typecheck, test, build**

Run: `cd web && npx tsc --noEmit && npx vitest run && npm run build`
Expected: all green (incl. styleguard — no inline styles).

- [ ] **Step 4: Commit**

```bash
git add web/src/api.ts web/src/components/AccountsTable.tsx
git commit -m "feat(web): revealSecret domain param; Accounts-table reveal keyed by domain/username"
```

---

## Task 3: Reveal in the similarity breakdown

**Files:** `web/src/components/SimilarityClusters.tsx`, `web/src/styles.css`

**Context:** `SimilarityBreakdown({ account, accounts })` early-returns when `!account`, then renders the header (username/domain/risk badge), the peer list (`<AccountLink>` + score per row), and the note. SimilarityClusters.tsx currently imports: `{ useEffect, useMemo, useState }` from react; `type Account` from `../api`; `RISK_CLASS` from `../util`; `similarityNetwork`; `NetworkGraph`; `AccountLink`. The `.secret`/`.mono-pw`/`.reveal-btn`/`.link-btn` classes exist globally (used by AccountsTable).

- [ ] **Step 1: Add imports**

In `web/src/components/SimilarityClusters.tsx`, update the react import to include `useRef`, and add:
```ts
import { useEffect, useMemo, useRef, useState } from "react"
import { api, ApiError, type Account } from "../api"
import { useAuth } from "../auth"
```
(Keep the existing `RISK_CLASS`, `similarityNetwork`, `NetworkGraph`, `AccountLink` imports. `Account` was a type-only import — merge it into the `api`/`ApiError` import as shown.)

- [ ] **Step 2: Add lead-gated reveal to `SimilarityBreakdown`**

Replace the whole `SimilarityBreakdown` function with:
```tsx
function SimilarityBreakdown({ account, accounts }: { account: Account | null; accounts: Account[] }) {
  const { me } = useAuth()
  const isLead = me?.role === "lead"
  const [revealed, setRevealed] = useState<Record<string, string>>({})
  const [revealing, setRevealing] = useState("")
  const [revealErr, setRevealErr] = useState("")
  const timers = useRef<number[]>([])
  useEffect(() => () => { timers.current.forEach(clearTimeout) }, [])

  async function reveal(username: string, domain: string) {
    const key = `${domain}/${username}`
    setRevealing(key)
    setRevealErr("")
    try {
      const r = await api.revealSecret(username, domain)
      setRevealed((prev) => ({ ...prev, [key]: r.password }))
      timers.current.push(window.setTimeout(() => hide(key), 45000))
    } catch (e) {
      setRevealErr(e instanceof ApiError ? `reveal failed: ${e.message}` : "reveal failed")
    } finally {
      setRevealing("")
    }
  }
  function hide(key: string) {
    setRevealed((prev) => {
      const next = { ...prev }
      delete next[key]
      return next
    })
  }
  async function copy(text: string) {
    try {
      await navigator.clipboard.writeText(text)
    } catch {
      /* clipboard may be unavailable; ignore */
    }
  }
  function revealCell(username: string, domain: string) {
    if (!isLead) return null
    const key = `${domain}/${username}`
    if (key in revealed) {
      return (
        <span className="secret">
          <span className="mono-pw">{revealed[key]}</span>
          <button className="link-btn" onClick={() => copy(revealed[key])} title="Copy">copy</button>
          <button className="link-btn" onClick={() => hide(key)}>hide</button>
        </span>
      )
    }
    return (
      <button className="reveal-btn" disabled={revealing === key} onClick={() => reveal(username, domain)}>
        {revealing === key ? "…" : "reveal"}
      </button>
    )
  }

  if (!account) {
    return <div className="simbreak-empty">Click an account in the graph to see its closest password matches.</div>
  }
  const peers = account.similar_peers ?? []
  return (
    <div className="simbreak">
      <div className="simbreak-head">
        <span className="simbreak-user">{account.username}</span>
        <span className="muted">{account.domain}</span>
        <span className={`badge ${RISK_CLASS[account.risk_level] || ""}`}>{account.risk_level}</span>
      </div>
      {isLead && <div className="simbreak-reveal">{revealCell(account.username, account.domain)}</div>}
      <div className="simbreak-label">Most similar passwords in this audit</div>
      {peers.length === 0 ? (
        <div className="muted fs-12">No close matches recorded for this account.</div>
      ) : (
        <div className="simbreak-list">
          {peers.map((p, i) => (
            <div className="simbreak-row" key={`${p.domain}/${p.username}/${i}`}>
              <AccountLink username={p.username} domain={p.domain} accounts={accounts} />
              <span className="simbreak-score">{Math.round(p.score * 100)}%</span>
              {revealCell(p.username, p.domain)}
            </div>
          ))}
        </div>
      )}
      {revealErr && <div className="error">{revealErr}</div>}
      <p className="muted fs-12 simbreak-note">
        Revealing a password is lead-only and recorded in the audit log — never the password itself.
      </p>
    </div>
  )
}
```
(The `SimilarityClusters` parent component is unchanged. All new hooks are above the `if (!account)` early return — rules-of-hooks safe.)

- [ ] **Step 3: CSS for the reveal placement**

In `web/src/styles.css`, modify the existing `.simbreak-row` rule to allow wrapping (the narrow 320px side panel must wrap a revealed password), and add the header-reveal spacing:
```css
.simbreak-row { display: flex; align-items: center; justify-content: space-between; gap: 10px; flex-wrap: wrap; }
.simbreak-reveal { margin: 8px 0 4px; }
```
(`.simbreak-row` already exists — add `flex-wrap: wrap;` to it. `.secret`/`.mono-pw`/`.reveal-btn`/`.link-btn` are reused as-is, including the existing `.secret { flex-wrap: wrap }` + `.mono-pw { word-break: break-all }` so a revealed password wraps within the panel.)

- [ ] **Step 4: Typecheck, test, build**

Run: `cd web && npx tsc --noEmit && npx vitest run && npm run build`
Expected: all green (incl. styleguard; confirm no unused imports — `useRef`, `api`, `ApiError`, `useAuth` are all used).

- [ ] **Step 5: Commit**

```bash
git add web/src/components/SimilarityClusters.tsx web/src/styles.css
git commit -m "feat(web): lead-gated reveal in the similarity breakdown (selected account + peers)"
```

---

## Task 4: Full gate + live verification + finish

**Files:** none (verification + release)

- [ ] **Step 1: Full gates**

```bash
cd /c/base/dev/PasswordAtTheDisco
gofmt -l cmd internal                                    # empty
go build ./... && go vet ./... && go test ./...           # all ok
govulncheck ./...                                         # No vulnerabilities found.
( cd web && npx tsc --noEmit && npx vitest run && npm run build )   # all green incl. styleguard
```

- [ ] **Step 2: Rebuild embedded binary + restart on :8443**

Stop the running patd first (binary lock), then `bash .claude/skills/build-and-run/scripts/build.sh`, then restart via PowerShell `& .claude\skills\build-and-run\scripts\restart.ps1`; confirm the version stamp matches the new commit. (The synthetic audit loaded earlier — "Sample data (synthetic)" — has populated `similar_peers`, so the breakdown shows peers there.)

- [ ] **Step 3: Live Playwright verification (as lead `watson`)**

Login (`watson`/`discotime`), unlock (`disco-vault-2026`), switch to the **Sample data (synthetic)** audit, open **Overview** → Password Similarity Clusters:
- Click a node → breakdown shows; as lead, a **reveal** control appears on the selected account and on each peer row.
- Reveal the selected account → cleartext shows (mono); reveal a peer → its cleartext shows; the two are visibly similar; **copy** and **hide** work.
- Open **Admin → Activity** → confirm `reveal_secret` rows with `username@domain` targets and **no** password in the row.
- (Optional) confirm the Accounts table reveal still works and is correct for a duplicated username (e.g. `administrator`) across domains.
- Assert the browser console has no 4xx/error noise.

- [ ] **Step 4: Finish the branch**

Use **superpowers:finishing-a-development-branch**: verify tests pass, merge to `main`, tag **v2.17.0**, rebuild + restart on :8443. (Pushing stays deferred per the user's standing preference unless they say otherwise.)

---

## Self-Review notes (for the controller)
- **Spec coverage:** domain-aware backend + audit `username@domain` + test (T1); `revealSecret(domain?)` + Accounts-table domain-keyed reveal (T2); lead-gated breakdown reveal on selected + peers + note copy (T3); gate+Playwright+v2.17.0 (T4). ✓
- **Type consistency:** `revealSecret(username, domain?)` used identically in AccountsTable + breakdown; reveal state keyed by `${domain}/${username}` in both; `FindByDomain(id, username, domain)` matches the handler call. ✓
- **Security:** reveal stays lead-only + audited (T1 asserts target `svc@GHOST`, no password; non-lead 403); breakdown reveal gated on `isLead`; cleartext transient (45s auto-hide + unmount cleanup). ✓
