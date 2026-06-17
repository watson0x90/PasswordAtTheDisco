# UX Hardening + Forbidden-Words Editor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the password-analysis forbidden-words list editable from the UI (lead-only), fix tables overflowing their panels, introduce a CSS spacing-token system with a dependency-free guard, and turn the "no audit selected" 409 into a graceful 200-empty so the browser console stops logging 409s.

**Architecture:** Backend changes mirror the existing Policies GET/PUT pattern (lead-gated, CSRF, audit-logged, disk-persisted, engine hot-swap). Frontend folds a textarea editor into the existing `Policies.tsx`, converts ad-hoc inline styles to `:root` tokens, and adds a vitest scan that fails on regressions. Read endpoints stop returning 409 for "no audit selected"; they return 200 + empty so pages render calm empty states.

**Tech Stack:** Go 1.26 (stdlib + golang.org/x/crypto), `net/http` ServeMux, React 18 + TypeScript + Vite, vitest (node-env, no jsdom), single embedded static binary.

**Spec:** `docs/superpowers/specs/2026-06-17-ux-hardening-design.md`

**Branch:** `feature/ux-hardening` (already created off `main`, post-`v2.8.0`).

**Gates (run from repo root unless noted):**
- Go: `gofmt -l cmd internal` (empty) ; `go build ./... && go vet ./... && go test ./...`
- Web (in `web/`): `npx tsc --noEmit` ; `npx vitest run` ; `npm run build`  — never `npm install`.
- `govulncheck ./...` clean.

---

## File Structure

**Backend (Go):**
- `internal/pwanalysis/pwanalysis.go` — add `SaveSet` (Task 1).
- `internal/pwanalysis/pwanalysis_test.go` — `SaveSet` round-trip test (Task 1).
- `internal/engine/engine.go` — `listsMu`, `SwapForbiddenWords`, `ForbiddenWords`, guarded read at the analysis call (Task 2).
- `internal/engine/engine_test.go` — swap-changes-analysis test (Task 2).
- `internal/httpapi/server.go` — `ForbiddenWordsPath` field, two handlers, two routes (Task 3); `activeAuditRead` + read-endpoint empties (Task 6).
- `internal/httpapi/server_test.go` (or the existing httpapi test file) — handler tests (Tasks 3, 6).
- `cmd/patd/main.go` — wire `ForbiddenWordsPath` (Task 3).

**Frontend (TS/React/CSS):**
- `web/src/api.ts` — `getForbiddenWords` / `setForbiddenWords` (Task 4).
- `web/src/components/Policies.tsx` — forbidden-words section (Task 5).
- `web/src/components/{Exposure,Operators,Activity}.tsx` — wrap tables (Task 9).
- `web/src/components/{AuditData,Exposure,…}.tsx` — convert inline styles (Task 9).
- `web/src/styles.css` — spacing/radius tokens + utility classes + repointed magic numbers (Tasks 8, 9).
- `web/src/components/{Actionable,Exposure,Domains}.tsx`, `web/src/accountsData.tsx` — calm empty states (Task 7).
- `web/src/styleguard.test.ts` — inline-style guard (Task 10).

**Docs:**
- `README.md` — "What's new" bullet (Task 11).

---

## Task 1: `pwanalysis.SaveSet` (persist a wordlist)

**Files:**
- Modify: `internal/pwanalysis/pwanalysis.go` (after `LoadSet`, ~line 50)
- Test: `internal/pwanalysis/pwanalysis_test.go`

- [ ] **Step 1: Write the failing test**

Add to `internal/pwanalysis/pwanalysis_test.go`:

```go
func TestSaveSetRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "words.txt")
	in := NewSet("Acme", "summer", "summer", " Winter ", "")
	if err := SaveSet(path, in); err != nil {
		t.Fatalf("SaveSet: %v", err)
	}
	got, err := LoadSet(path)
	if err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	want := NewSet("acme", "summer", "winter")
	if len(got) != len(want) {
		t.Fatalf("len got=%d want=%d (%v)", len(got), len(want), got)
	}
	for w := range want {
		if _, ok := got[w]; !ok {
			t.Errorf("missing %q", w)
		}
	}
	// File must be sorted, one per line, lowercased.
	b, _ := os.ReadFile(path)
	if string(b) != "acme\nsummer\nwinter\n" {
		t.Errorf("file body = %q", string(b))
	}
}
```

Ensure the test file imports `os`, `path/filepath` (add if missing).

- [ ] **Step 2: Run it, expect FAIL**

Run: `go test ./internal/pwanalysis/ -run TestSaveSetRoundTrip -v`
Expected: FAIL — `undefined: SaveSet`.

- [ ] **Step 3: Implement `SaveSet`**

Add after `LoadSet` in `internal/pwanalysis/pwanalysis.go` (the file already imports `bufio`, `os`, `strings`; add `sort` and `path/filepath` to the import block):

```go
// SaveSet writes the set to path, one lowercased entry per line, sorted, with a
// trailing newline. Atomic (temp file + rename) and 0600 so a partial write can
// never corrupt the live list.
func SaveSet(path string, s Set) error {
	words := make([]string, 0, len(s))
	for w := range s {
		words = append(words, w)
	}
	sort.Strings(words)
	var b strings.Builder
	for _, w := range words {
		b.WriteString(w)
		b.WriteByte('\n')
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
```

(`filepath` is not strictly needed by this function; only add imports you actually use — if `gofmt`/`vet` complains, drop `path/filepath` from the source import. The test file uses `filepath`, not the source.)

- [ ] **Step 4: Run it, expect PASS**

Run: `go test ./internal/pwanalysis/ -run TestSaveSetRoundTrip -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/pwanalysis/pwanalysis.go internal/pwanalysis/pwanalysis_test.go
git add internal/pwanalysis/pwanalysis.go internal/pwanalysis/pwanalysis_test.go
git commit -m "feat(pwanalysis): SaveSet — atomic, sorted wordlist persistence"
```

---

## Task 2: Engine hot-swap for forbidden words

**Files:**
- Modify: `internal/engine/engine.go` (struct ~line 49-57; analysis call at line 198)
- Test: `internal/engine/engine_test.go`

- [ ] **Step 1: Write the failing test**

Add to `internal/engine/engine_test.go`:

```go
func TestSwapForbiddenWords(t *testing.T) {
	eng := &Engine{
		Lists:    pwanalysis.Lists{ForbiddenWords: pwanalysis.NewSet("acme")},
		Policies: policy.NewSet(policy.Policy{MinLength: 8}, nil),
	}
	if got := eng.ForbiddenWords(); len(got) != 1 {
		t.Fatalf("initial size = %d", len(got))
	}
	eng.SwapForbiddenWords(pwanalysis.NewSet("acme", "summer"))
	if got := eng.ForbiddenWords(); len(got) != 2 {
		t.Fatalf("after swap size = %d", len(got))
	}
	if _, ok := eng.ForbiddenWords()["summer"]; !ok {
		t.Error("swapped set missing 'summer'")
	}
}
```

If `policy.NewSet`'s signature differs, mirror an existing engine test's `Engine{}` construction (see `engine_test.go:182-201`) — the point is only to exercise `ForbiddenWords()`/`SwapForbiddenWords`, so a minimal `Engine{Lists: pwanalysis.Lists{ForbiddenWords: pwanalysis.NewSet("acme")}}` without Policies is acceptable if the accessors don't touch Policies.

- [ ] **Step 2: Run it, expect FAIL**

Run: `go test ./internal/engine/ -run TestSwapForbiddenWords -v`
Expected: FAIL — `eng.ForbiddenWords undefined`.

- [ ] **Step 3: Implement the swap + guarded read**

In `internal/engine/engine.go`, add a mutex field to the `Engine` struct (after the `Lists` field at line 54):

```go
	Lists    pwanalysis.Lists
	listsMu  sync.RWMutex // guards Lists.ForbiddenWords for hot-swap
```

Add these methods next to `SwapEnricher` (after line 76):

```go
// SwapForbiddenWords atomically replaces the analysis forbidden-words set so the
// list can be edited from the UI and take effect for the next analysis without a
// restart.
func (e *Engine) SwapForbiddenWords(set pwanalysis.Set) {
	e.listsMu.Lock()
	defer e.listsMu.Unlock()
	e.Lists.ForbiddenWords = set
}

// ForbiddenWords returns the current forbidden-words set under the read lock.
func (e *Engine) ForbiddenWords() pwanalysis.Set {
	e.listsMu.RLock()
	defer e.listsMu.RUnlock()
	return e.Lists.ForbiddenWords
}
```

Make the analysis read use the lock. At `internal/engine/engine.go:198`, replace:

```go
		an = pwanalysis.Analyze(pw, e.Lists, nil, pol.Analysis())
```

with a snapshot that swaps in the lock-guarded set:

```go
		lists := e.Lists
		lists.ForbiddenWords = e.ForbiddenWords()
		an = pwanalysis.Analyze(pw, lists, nil, pol.Analysis())
```

(`sync` is already imported in `engine.go` — the struct uses `sync.RWMutex` for `hibpMu`.)

- [ ] **Step 4: Run it, expect PASS**

Run: `go test ./internal/engine/ -run TestSwapForbiddenWords -v`
Then the package: `go test ./internal/engine/ -v` (ensure nothing else broke).
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/engine/engine.go internal/engine/engine_test.go
git add internal/engine/engine.go internal/engine/engine_test.go
git commit -m "feat(engine): hot-swappable forbidden-words set (SwapForbiddenWords/ForbiddenWords)"
```

---

## Task 3: `GET`/`PUT /api/forbidden-words` endpoints + wiring

**Files:**
- Modify: `internal/httpapi/server.go` (Server struct ~line 57; routes ~line 166-167; handlers near `handleGetPolicies` ~line 1884)
- Modify: `cmd/patd/main.go` (Server construction ~line 175)
- Test: the existing httpapi test file (e.g. `internal/httpapi/server_test.go`)

- [ ] **Step 1: Write the failing test**

Use the existing harness in `internal/httpapi/server_test.go`: `newServer("secret")` builds a Server with `lead`/`leadpw` (RoleLead) and `analyst`/`analystpw` (RoleAnalyst); `loginCSRF(t, srv, user, pass)` returns `(cookie, csrf)`; `sendJSON(srv, method, path, cookie, csrf, body)` does a JSON request with the CSRF header; `do(srv, method, path, cookie)` does a GET. The default test server has **no** Engine, so set one. Mirror `TestPolicies` (line 335):

```go
func TestForbiddenWordsPutGet(t *testing.T) {
	srv := newServer("secret")
	srv.Engine = &engine.Engine{Lists: pwanalysis.Lists{ForbiddenWords: pwanalysis.NewSet()}}
	srv.ForbiddenWordsPath = filepath.Join(t.TempDir(), "forbidden_words.txt")

	body := `{"words":["Acme"," summer ","summer",""]}`

	// analyst cannot edit
	ac, acsrf := loginCSRF(t, srv, "analyst", "analystpw")
	if r := sendJSON(srv, "PUT", "/api/forbidden-words", ac, acsrf, body); r.Code != http.StatusForbidden {
		t.Fatalf("analyst PUT should be 403, got %d", r.Code)
	}

	// lead can edit; engine + disk reflect the normalized set
	lc, lcsrf := loginCSRF(t, srv, "lead", "leadpw")
	if r := sendJSON(srv, "PUT", "/api/forbidden-words", lc, lcsrf, body); r.Code != http.StatusOK {
		t.Fatalf("lead PUT = %d %s", r.Code, r.Body.String())
	}
	if got := srv.Engine.ForbiddenWords(); len(got) != 2 { // acme, summer
		t.Fatalf("engine set size = %d (%v)", len(got), got)
	}

	// GET returns sorted, normalized words (lead-only)
	g := do(srv, "GET", "/api/forbidden-words", lc)
	if g.Code != http.StatusOK || !strings.Contains(g.Body.String(), `"acme"`) || !strings.Contains(g.Body.String(), `"summer"`) {
		t.Fatalf("GET = %d body=%s", g.Code, g.Body.String())
	}
	// analyst cannot read (words are cleartext fragments)
	if g := do(srv, "GET", "/api/forbidden-words", ac); g.Code != http.StatusForbidden {
		t.Fatalf("analyst GET should be 403, got %d", g.Code)
	}
}
```

Add the imports `engine`, `pwanalysis`, and `path/filepath` to the test file if missing. (`engine` = `github.com/watson0x90/PasswordAtTheDisco/internal/engine`, `pwanalysis` = `.../internal/pwanalysis`.)

- [ ] **Step 2: Run it, expect FAIL**

Run: `go test ./internal/httpapi/ -run TestForbiddenWordsPutGet -v`
Expected: FAIL — 404 (route not registered) or compile error (`ForbiddenWordsPath` undefined).

- [ ] **Step 3a: Add the Server field**

In `internal/httpapi/server.go`, after `PolicyPath` (line 57):

```go
	PolicyPath        string          // where to persist policy edits (empty = in-memory only)
	ForbiddenWordsPath string         // where to persist forbidden-words edits (empty = in-memory only)
```

- [ ] **Step 3b: Add the handlers**

Add near `handleSetPolicies` (after line 1941) in `internal/httpapi/server.go`:

```go
// forbiddenWordsPayload is the wire shape for GET/PUT /api/forbidden-words.
type forbiddenWordsPayload struct {
	Words []string `json:"words"`
}

// handleGetForbiddenWords returns the current forbidden-words list (sorted).
// Lead-only: the words are cleartext fragments (same sensitivity as
// /api/report/terms).
func (s *Server) handleGetForbiddenWords(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	if sess.Role != auth.RoleLead {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "requires lead role"})
		return
	}
	if s.Engine == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "engine not configured"})
		return
	}
	set := s.Engine.ForbiddenWords()
	words := make([]string, 0, len(set))
	for word := range set {
		words = append(words, word)
	}
	sort.Strings(words)
	writeJSON(w, http.StatusOK, forbiddenWordsPayload{Words: words})
}

// handleSetForbiddenWords replaces the forbidden-words list (lead only), persists
// it to disk if a path is configured, and hot-swaps it into the engine so it
// applies to the next analysis. Audit-logged (count only, never the words).
func (s *Server) handleSetForbiddenWords(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	if sess.Role != auth.RoleLead {
		s.Audit.Log(audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: "forbidden_words_update", Source: r.RemoteAddr, Result: "denied"})
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "requires lead role"})
		return
	}
	if s.Engine == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "engine not configured"})
		return
	}
	defer r.Body.Close()
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	var p forbiddenWordsPayload
	if err := dec.Decode(&p); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request: " + err.Error()})
		return
	}
	if len(p.Words) > 5000 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "too many words (max 5000)"})
		return
	}
	set := pwanalysis.Set{}
	for _, raw := range p.Words {
		word := strings.ToLower(strings.TrimSpace(raw))
		if word == "" {
			continue
		}
		if len(word) > 64 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "word too long (max 64 chars): " + word[:64] + "…"})
			return
		}
		if strings.ContainsAny(word, "\n\r\x00") {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "word contains a control character"})
			return
		}
		set[word] = struct{}{}
	}
	s.Engine.SwapForbiddenWords(set)
	saved := "memory"
	if s.ForbiddenWordsPath != "" {
		if err := pwanalysis.SaveSet(s.ForbiddenWordsPath, set); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "saved in memory but failed to persist: " + err.Error()})
			return
		}
		saved = s.ForbiddenWordsPath
	}
	s.Audit.Log(audit.Event{Actor: sess.Username, Role: string(sess.Role), Action: "forbidden_words_update", Target: strconv.Itoa(len(set)) + " word(s)", Source: r.RemoteAddr, Result: "ok"})
	writeJSON(w, http.StatusOK, map[string]any{"count": len(set), "persisted": saved})
}
```

Ensure `internal/httpapi/server.go` imports `sort` and `github.com/watson0x90/PasswordAtTheDisco/internal/pwanalysis` (add to the import block if missing; `auth`, `audit`, `strconv`, `json`, `strings` are already imported).

- [ ] **Step 3c: Register the routes**

In `internal/httpapi/server.go`, next to the policies routes (after line 167):

```go
	mux.Handle("GET /api/forbidden-words", s.requireAuth(http.HandlerFunc(s.handleGetForbiddenWords)))
	mux.Handle("PUT /api/forbidden-words", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.handleSetForbiddenWords))))
```

- [ ] **Step 3d: Wire the persistence path**

In `cmd/patd/main.go`, find where `listsDir` is resolved (it's passed to `loadLists(listsDir)` in `cmd/patd/audit.go:175`; the server is built in `main.go`). Set the field on the Server struct (near `PolicyPath: policyPath`, line 175):

```go
		ForbiddenWordsPath: filepath.Join(listsDir, "forbidden_words.txt"),
```

If `listsDir` is not in scope at the Server construction in `main.go`, resolve it the same way `policyPath` is resolved (check the lines just above 175) and reuse that directory. `path/filepath` is already imported by `main.go`.

- [ ] **Step 4: Run it, expect PASS**

Run: `go test ./internal/httpapi/ -run TestForbiddenWordsPutGet -v`
Then: `go build ./... && go vet ./...`
Expected: PASS, clean build.

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/httpapi/server.go cmd/patd/main.go
git add internal/httpapi/server.go cmd/patd/main.go internal/httpapi/*_test.go
git commit -m "feat(api): GET/PUT /api/forbidden-words — lead-gated, CSRF, audit-logged, hot-swap+persist"
```

---

## Task 4: API client methods

**Files:**
- Modify: `web/src/api.ts` (near `getPolicies`/`savePolicies`, ~line 346-353)

- [ ] **Step 1: Add the client methods**

In `web/src/api.ts`, in the `api` object next to `savePolicies`:

```ts
  getForbiddenWords: () => request<{ words: string[] }>("/forbidden-words"),
  setForbiddenWords: (words: string[], csrf: string) =>
    request<{ count: number; persisted: string }>("/forbidden-words", {
      method: "PUT",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
      body: JSON.stringify({ words }),
    }),
```

- [ ] **Step 2: Type-check**

Run (in `web/`): `npx tsc --noEmit`
Expected: clean (no usage yet, just the methods).

- [ ] **Step 3: Commit**

```bash
git add web/src/api.ts
git commit -m "feat(web): api.getForbiddenWords/setForbiddenWords"
```

---

## Task 5: Forbidden-words editor in `Policies.tsx`

**Files:**
- Modify: `web/src/components/Policies.tsx` (add a section + a child component)

- [ ] **Step 1: Add the `ForbiddenWords` component**

In `web/src/components/Policies.tsx`, add this component (place it next to `ChangePassphrase`/`RotateDataKey`, after the `Policies` function). It loads on mount, edits as a newline-joined textarea, and saves the split/trimmed list:

```tsx
function ForbiddenWords({ csrf }: { csrf: string }) {
  const [text, setText] = useState("")
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState("")
  const [okMsg, setOkMsg] = useState("")

  useEffect(() => {
    api
      .getForbiddenWords()
      .then((r) => setText(r.words.join("\n")))
      .catch((e) => setErr(e instanceof ApiError ? e.message : "failed to load forbidden words"))
      .finally(() => setLoading(false))
  }, [])

  const words = text
    .split("\n")
    .map((w) => w.trim())
    .filter(Boolean)

  async function save() {
    setBusy(true)
    setErr("")
    setOkMsg("")
    try {
      const r = await api.setForbiddenWords(words, csrf)
      setOkMsg(`saved — ${r.count} word(s), persisted to ${r.persisted}`)
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : "save failed")
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="panel ingest-form">
      <p className="ingest-note">
        Words that should never appear in a password (company name, product names, local slang). Each
        match adds to the dictionary penalty in scoring. One word per line; case-insensitive substring
        match. Changes apply to newly ingested or re-analyzed data — existing account scores are unchanged.
      </p>
      {loading ? (
        <div className="spinner">loading words</div>
      ) : (
        <>
          <textarea
            className="search forbidden-words-area"
            rows={10}
            spellCheck={false}
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder={"acme\nsummer\nwinter"}
          />
          <div className="field-hint">{words.length} word(s)</div>
          {err && <div className="error">{err}</div>}
          {okMsg && <div className="ingest-ok">✓ {okMsg}</div>}
          <button type="button" className="btn btn-primary" onClick={save} disabled={busy}>
            {busy ? "Saving…" : "Save forbidden words"}
          </button>
        </>
      )}
    </div>
  )
}
```

- [ ] **Step 2: Render it inside the lead-gated page**

In the `Policies` function's returned JSX, add a section before "Store passphrase" (after the policies `</div>` panel, around line 157):

```tsx
      <div className="section-label">Forbidden words</div>
      <ForbiddenWords csrf={me.csrf_token} />
```

(The whole `Policies` page already returns early unless `me?.role === "lead"`, so this is lead-gated for free.)

- [ ] **Step 3: Add the textarea style**

In `web/src/styles.css`, add (uses tokens introduced in Task 8; if Task 8 not yet merged, use `12px`/`var(--mono)` literally and let Task 9's guard conversion catch it — but prefer doing Task 8 first):

```css
.forbidden-words-area {
  width: 100%;
  min-height: 220px;
  font-family: var(--mono);
  font-size: 13px;
  line-height: 1.6;
  resize: vertical;
}
```

- [ ] **Step 4: Verify**

Run (in `web/`): `npx tsc --noEmit && npm run build`
Expected: clean compile + build.

- [ ] **Step 5: Commit**

```bash
git add web/src/components/Policies.tsx web/src/styles.css
git commit -m "feat(web): forbidden-words editor folded into Policies (lead-only)"
```

---

## Task 6: Graceful read endpoints (no 409 for "no audit selected")

**Files:**
- Modify: `internal/httpapi/server.go` (`activeAudit` ~1181; read handlers `handleAccounts` 1217, `handleSummary` 1231, `handleReport` 1249, `handleReportTerms` 1267, ingests ~1608, exports ~1667/1741/1784)
- Test: httpapi test file

- [ ] **Step 1: Write the failing test**

Add a test asserting a logged-in session that has **not** called `openAudit` (so `ActiveAudit == ""`) gets 200 + empty (not 409) from the read endpoints. Use `loginCSRF` + `do` (GET); do NOT call `openAudit`:

```go
func TestReadEndpointsEmptyWhenNoAudit(t *testing.T) {
	srv := newServer("secret")
	cookie, _ := loginCSRF(t, srv, "lead", "leadpw") // logged in, but no audit opened
	for _, path := range []string{"/api/accounts", "/api/report", "/api/summary"} {
		rr := do(srv, "GET", path, cookie)
		if rr.Code != http.StatusOK {
			t.Errorf("%s status = %d, want 200 (body=%s)", path, rr.Code, rr.Body.String())
		}
		if strings.Contains(rr.Body.String(), "no audit selected") {
			t.Errorf("%s leaked 409 error body: %s", path, rr.Body.String())
		}
	}
}
```

- [ ] **Step 2: Run it, expect FAIL**

Run: `go test ./internal/httpapi/ -run TestReadEndpointsEmptyWhenNoAudit -v`
Expected: FAIL — endpoints return 409.

- [ ] **Step 3a: Add a non-writing resolver**

In `internal/httpapi/server.go`, next to `activeAudit` (after line 1187):

```go
// activeAuditRead resolves the session's selected audit WITHOUT writing a
// response. Read endpoints use this so "no audit selected" yields an empty 200
// (a normal not-yet-started state) instead of a 409 the browser logs as an error.
func (s *Server) activeAuditRead(sess auth.Session) (string, bool) {
	if sess.ActiveAudit == "" || !s.Store.Has(sess.ActiveAudit) {
		return "", false
	}
	return sess.ActiveAudit, true
}
```

- [ ] **Step 3b: Make read handlers return empty 200**

`handleAccounts` (1217-1229) becomes:

```go
func (s *Server) handleAccounts(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	id, ok := s.activeAuditRead(sess)
	if !ok {
		writeJSON(w, http.StatusOK, []model.Account{})
		return
	}
	accts, err := s.Store.Accounts(id, false)
	if err != nil {
		writeJSON(w, http.StatusOK, []model.Account{})
		return
	}
	writeJSON(w, http.StatusOK, accts)
}
```

`handleReport` (1249-1261) becomes (empty report via `model.BuildReport(nil)`):

```go
func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	id, ok := s.activeAuditRead(sess)
	if !ok {
		writeJSON(w, http.StatusOK, model.BuildReport(nil))
		return
	}
	accts, err := s.Store.Accounts(id, true)
	if err != nil {
		writeJSON(w, http.StatusOK, model.BuildReport(nil))
		return
	}
	writeJSON(w, http.StatusOK, model.BuildReport(accts))
}
```

`handleSummary` (1231-1243) becomes (empty summary — use `model.BuildSummary(nil)` if it exists; otherwise return the zero `model.Summary{}`; check which the codebase exposes by grepping `func BuildSummary` / `type Summary`):

```go
func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionFrom(r.Context())
	id, ok := s.activeAuditRead(sess)
	if !ok {
		writeJSON(w, http.StatusOK, emptySummary())
		return
	}
	sum, err := s.Store.Summary(id)
	if err != nil {
		writeJSON(w, http.StatusOK, emptySummary())
		return
	}
	writeJSON(w, http.StatusOK, sum)
}
```

Where `emptySummary()` returns the same type `Store.Summary` returns. Grep for that type first (`grep -n "func.*Summary(" internal/store/*.go internal/model/*.go`) and construct its zero value. If `model.BuildSummary([]model.Account{})` exists, use that instead and skip the helper.

`handleReportTerms` (1267…): apply the same pattern — when `activeAuditRead` is false, return the endpoint's empty shape (e.g. `writeJSON(w, 200, <emptyTerms>)`), preserving the existing lead-role check. Read the handler body first to see its return type.

Ingests handler (~1608) and the CSV/HTML exports (~1667, 1741, 1784): when no audit, return an empty 200 (empty slice / empty CSV / minimal HTML) instead of 409. Read each handler and mirror its success shape with empty data.

- [ ] **Step 3c: Leave write/conflict 409s untouched**

Do **not** change: `activeAudit` itself (writes still call it), rekey (477, 518), job-already-running (608, 628, 662, 694, 729), user conflicts (746, 1051), and upload/cracks/domain-delete (1355, 1436, 1530, 1562, 1576). Verify with `grep -n "no audit selected" internal/httpapi/server.go` that only the read handlers changed.

- [ ] **Step 4: Run it, expect PASS**

Run: `go test ./internal/httpapi/ -run TestReadEndpointsEmptyWhenNoAudit -v`

Then update the two existing assertions in `TestAuditsLifecycle` that expect the **old** 409 read behavior (they will now fail):
- `internal/httpapi/server_test.go:644-647` — "no audit selected -> summary 409": change `!= http.StatusConflict` → `!= http.StatusOK` and the message to "should be 200".
- `internal/httpapi/server_test.go:669-674` — "delete A … summary 409": same change to `http.StatusOK`.

Leave the **real**-conflict 409 assertions untouched: the job-cancel test (`:1274-1281`) and the last-lead-delete (`:737`).

Then full: `go test ./internal/httpapi/ -v`.
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
gofmt -w internal/httpapi/server.go
git add internal/httpapi/server.go internal/httpapi/*_test.go
git commit -m "fix(api): read endpoints return 200+empty for no-audit (kills console 409 noise)"
```

---

## Task 7: Calm empty states in the frontend

**Files:**
- Modify: `web/src/components/Actionable.tsx`, `web/src/components/Exposure.tsx`, `web/src/components/Domains.tsx`, `web/src/accountsData.tsx`

- [ ] **Step 1: Distinguish empty from error**

With the backend now returning empty reports, the `reportErr` paths stop firing for "no audit". Make each report consumer render a calm empty state when the report has zero accounts. For each of `Actionable.tsx`, `Exposure.tsx`, `Domains.tsx`, after the report loads, add an empty check using the report's account-count field (grep the `Report` type in `web/src/api.ts` for the total field, e.g. `total_accounts`):

In `Exposure.tsx`, where it currently shows the `reportErr` hint, also handle the empty case — add near the top of the returned JSX (after loading resolves):

```tsx
  if (report && report.total_accounts === 0)
    return <div className="center-state">No data yet — select or create an audit and upload a dump.</div>
```

Apply the equivalent guard in `Actionable.tsx` (it already returns `null` when `!report`; change the empty-data case to the same friendly message instead of `null`) and `Domains.tsx`.

- [ ] **Step 2: Accounts empty state**

In `web/src/accountsData.tsx`, the fetch now resolves to `[]` for no-audit (no throw). Confirm the consuming view (Accounts) shows its existing empty/`GetStarted` state for `accounts.length === 0` rather than a red error. If `accountsData` still sets `error` on a real failure, leave that — only the empty array should be the calm path (it already is, since empty array is a success).

- [ ] **Step 3: Verify**

Run (in `web/`): `npx tsc --noEmit && npm run build`
Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add web/src/components/Actionable.tsx web/src/components/Exposure.tsx web/src/components/Domains.tsx web/src/accountsData.tsx
git commit -m "feat(web): calm 'no data yet' empty states for report/accounts views"
```

---

## Task 8: CSS spacing/radius token scale

**Files:**
- Modify: `web/src/styles.css` (`:root` block ~line 16-45; `.main` 177; `.table-wrap` 327-332; section spacing)

- [ ] **Step 1: Add tokens to `:root`**

In `web/src/styles.css`, inside the existing `:root { … }` block, add:

```css
  --space-xs: 4px;
  --space-sm: 8px;
  --space-md: 12px;
  --space-lg: 16px;
  --space-xl: 24px;
  --space-2xl: 32px;
  --radius-sm: 8px;
  --radius-md: 12px;
  --radius-lg: 16px;
  --main-max-width: 1200px;
  --table-max-height: calc(100vh - 250px);
```

- [ ] **Step 2: Repoint the magic numbers**

- `.main` (line 177): change `max-width: 1200px` → `max-width: var(--main-max-width)`.
- `.table-wrap` (line ~330): change `max-height: calc(100vh - 250px)` → `max-height: var(--table-max-height)`.
- Section spacing — set these onto the nearest token, keeping the rendered gap visually equivalent: `.section-label` `margin: 0 0 16px` → `0 0 var(--space-lg)`; `.stat-grid` `margin-bottom: 38px` → keep 38px is non-standard, round to `var(--space-2xl)` (32px) **only if it does not visibly crowd** — otherwise leave 38px and note it; `.action-section` `margin-bottom: 34px` → `var(--space-2xl)` if visually fine. When unsure, prefer leaving the exact px and tokenizing only the clean matches (xs/sm/md/lg/xl/2xl == 4/8/12/16/24/32).

- [ ] **Step 3: Verify build**

Run (in `web/`): `npm run build`
Expected: clean (CSS changes don't break the build; visual check happens in the live run, Task 11).

- [ ] **Step 4: Commit**

```bash
git add web/src/styles.css
git commit -m "feat(web): spacing/radius/layout design tokens in :root"
```

---

## Task 9: Wrap overflowing tables + convert inline styles

**Files:**
- Modify: `web/src/components/Exposure.tsx` (bridge matrix ~line 103; badge `marginLeft` inline styles)
- Modify: `web/src/components/Operators.tsx` (`.ops-table`), `web/src/components/Activity.tsx` (`.act-table`)
- Modify: `web/src/components/AuditData.tsx` (9 inline styles), and any other files with static inline spacing
- Modify: `web/src/styles.css` (add utility classes)

- [ ] **Step 1: Add utility classes**

In `web/src/styles.css`:

```css
.font-mono { font-family: var(--mono); }
.mb-lg { margin-bottom: var(--space-lg); }
.mb-xl { margin-bottom: var(--space-xl); }
.py-sm { padding: var(--space-sm) 0; }
.row-gap-xs { display: flex; align-items: center; flex-wrap: wrap; gap: var(--space-xs); }
```

- [ ] **Step 2: Wrap the three overflowing tables**

- `Exposure.tsx` line ~103: wrap the `<table className="bridge-matrix">…</table>` in `<div className="table-wrap">…</div>`.
- `Operators.tsx`: wrap the `<table className="ops-table">…</table>` in `<div className="table-wrap">…</div>`.
- `Activity.tsx`: wrap the `<table className="act-table">…</table>` in `<div className="table-wrap">…</div>`.

- [ ] **Step 3: Convert static inline styles to classes**

Find every static inline style: `grep -rn "style={{" web/src`. For each whose value is a **literal** margin/padding/gap/width/font (NOT a computed expression), replace with a class:
- `AuditData.tsx`: `style={{ marginBottom: 24 }}` → `className="… mb-xl"`; `style={{ padding: "8px 0" }}` → `className="… py-sm"`; `style={{ fontFamily: "var(--mono)", fontWeight: 600 }}` → `className="font-mono"` + keep weight via an existing class or a new `.fw-600 { font-weight: 600; }`; `style={{ fontFamily: "var(--mono)", fontSize: 12 }}` → `className="font-mono"` + a `.fs-12 { font-size: 12px; }` util if needed.
- `Exposure.tsx`: the three `marginLeft: 6` badge spacings — make the parent a `row-gap-xs` flex row and drop the inline `marginLeft`; `marginBottom: 12/16` → `mb-lg`/a `.mb-md` util.
- Any other file surfaced by the grep with literal spacing values.
- **Keep dynamic inline styles** (do NOT convert): `AccountsTable.tsx` `height: start * ROW_H`; `Dashboard.tsx` `animationDelay`; `Charts.tsx` pixel dims computed from data. These have non-literal values and are legitimate.

- [ ] **Step 4: Verify**

Run (in `web/`): `npx tsc --noEmit && npm run build`
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add web/src/components/*.tsx web/src/styles.css
git commit -m "fix(web): wrap overflowing tables; convert static inline styles to tokens"
```

---

## Task 10: Inline-style guard test

**Files:**
- Create: `web/src/styleguard.test.ts`

- [ ] **Step 1: Write the guard**

Create `web/src/styleguard.test.ts`:

```ts
import { readdirSync, readFileSync, statSync } from "node:fs"
import { join } from "node:path"
import { describe, expect, it } from "vitest"

function walk(dir: string): string[] {
  const out: string[] = []
  for (const name of readdirSync(dir)) {
    const p = join(dir, name)
    if (statSync(p).isDirectory()) out.push(...walk(p))
    else if (p.endsWith(".tsx")) out.push(p)
  }
  return out
}

// Flags inline style props whose value is a LITERAL px/number for spacing/size.
// Computed values (start * ROW_H, `${x}px`, animationDelay) do not match.
const BANNED = /\b(margin|marginTop|marginBottom|marginLeft|marginRight|padding|paddingTop|paddingBottom|paddingLeft|paddingRight|gap|width|height)\s*:\s*("?\d+(px)?"?)\s*[,}]/g

describe("no static inline spacing styles", () => {
  const files = walk(join(__dirname))
  for (const file of files) {
    it(`${file} uses tokens, not literal inline spacing`, () => {
      const src = readFileSync(file, "utf8")
      // Only inspect inline style objects.
      const styleBlocks = src.match(/style=\{\{[^}]*\}\}/g) ?? []
      const offenders: string[] = []
      for (const block of styleBlocks) {
        const m = block.match(BANNED)
        if (m) offenders.push(block)
      }
      expect(offenders, `convert to a token class:\n${offenders.join("\n")}`).toHaveLength(0)
    })
  }
})
```

Note: this catches `width: 200` / `margin: 8` style literals. Verified-legitimate dynamic styles (e.g. `height: start * ROW_H`) won't match because their value is not a bare number/px literal. If a legitimately-dynamic style happens to match (e.g. `width: 200` that must stay), refactor it to a class — do not weaken the regex.

- [ ] **Step 2: Run it, expect PASS**

Run (in `web/`): `npx vitest run styleguard`
Expected: PASS (Task 9 already converted the offenders). If it FAILS, the failure lists the remaining offenders — convert them to classes and re-run.

- [ ] **Step 3: Full web gate**

Run (in `web/`): `npx tsc --noEmit && npx vitest run && npm run build`
Expected: all green (42+ tests).

- [ ] **Step 4: Commit**

```bash
git add web/src/styleguard.test.ts
git commit -m "test(web): styleguard — fail on literal inline spacing styles"
```

---

## Task 11: Docs, full gate, rebuild, live verify

**Files:**
- Modify: `README.md` ("What's new in 2.8" section ~line 44)

- [ ] **Step 1: README bullet**

In `README.md`, under "What's new in 2.8", add a bullet:

```markdown
- **Editable forbidden-words list + UI polish.** Manage the password-analysis
  banned-words list from **Setup → Policies** (lead-only, audit-logged; applies to
  new/re-analyzed data). Plus consistent table widths, a spacing-token CSS system,
  and calm "no data yet" empty states (no more console 409s on a fresh session).
```

- [ ] **Step 2: Full gate**

Run from repo root:
```bash
gofmt -l cmd internal
go build ./... && go vet ./... && go test ./...
( cd web && npx tsc --noEmit && npx vitest run && npm run build )
govulncheck ./...
```
Expected: gofmt empty, all Go tests pass, web green, govulncheck clean.

- [ ] **Step 3: Rebuild the embedded binary**

```bash
rm -rf internal/webui/dist && cp -r web/dist internal/webui/dist
VERSION=$(git describe --tags --always); COMMIT=$(git rev-parse --short HEAD); BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
CGO_ENABLED=0 go build -tags embed -trimpath \
  -ldflags="-s -w -X main.version=$VERSION -X main.commit=$COMMIT -X main.buildDate=$BUILD_DATE" \
  -o patd.exe ./cmd/patd
```

- [ ] **Step 4: Restart + live verify** (PowerShell, the operator runs this; server serves PLAIN HTTP on 127.0.0.1:8443)

Restart the server (Stop-Process old PID, Start-Process patd.exe with `$env:PATD_AUDIT_LOG`). Then verify:
- `GET /api/version` shows the new commit.
- On a fresh session with **no audit selected**, the browser console shows **no 409** for `/api/accounts`, `/api/report`, `/api/summary`.
- Setup → Policies shows the Forbidden words editor (lead); saving shows the count + persisted path; `audit.log` gets a `forbidden_words_update` line with a **count only** (no words).
- Exposure bridge matrix, Operators, and Activity tables scroll horizontally within their panels instead of overflowing.
- Spacing looks consistent across Overview / Audit Data / Exposure / Policies.

- [ ] **Step 5: Commit docs**

```bash
git add README.md
git commit -m "docs: note forbidden-words editor + UI hardening in 2.8"
```

---

## Self-Review Notes (filled by plan author)

- **Spec coverage:** §1 forbidden-words → Tasks 1-5; §2 overflow → Task 9 (+ Task 8 tokens); §3 CSS tokens+guard → Tasks 8, 9, 10; §4 graceful 409 → Tasks 6, 7. All four spec sections have tasks.
- **Type consistency:** `SaveSet(path, Set)` (Task 1) used in Task 3; `SwapForbiddenWords(pwanalysis.Set)` / `ForbiddenWords() pwanalysis.Set` (Task 2) used in Task 3; `forbiddenWordsPayload{Words []string}` ↔ `{ words: string[] }` (Tasks 3, 4); `api.getForbiddenWords` returns `{ words }`, `setForbiddenWords` returns `{ count, persisted }` (Tasks 4, 5); `activeAuditRead` (Task 6) only in read handlers.
- **Verify-before-claiming:** every task ends with a build/test gate; Task 11 is a full gate + live run.
- **Open assumptions the implementer must confirm by reading code first:** the httpapi test harness helper names (Task 3/6 use placeholders `newTestServerWithLead`/`doRequest` — match the real ones); the `Summary` empty-construction (`model.BuildSummary` vs zero value, Task 6); the `Report` total-accounts field name (Task 7); that `listsDir` is reachable at the `main.go` Server construction (Task 3d).
