# UX Hardening + Forbidden-Words Editor — Design

**Date:** 2026-06-17
**Branch:** `feature/ux-hardening` (off `main`, post-`v2.8.0`)
**Owner:** watson0x90

## Goal

Four related improvements to the Go+React console, all frontend + a narrow,
well-precedented backend slice. No new runtime dependencies, no store/schema
changes, no new secret surface.

1. **Editable forbidden-words list** — manage the password-analysis banned-words
   list from the UI (lead-only), folded into the existing Policies page.
2. **Fix table/report width overflow** — apply the existing `.table-wrap`
   overflow pattern to the tables that currently overflow their panels.
3. **CSS token system + lint guard** — add a spacing/radius token scale, convert
   ad-hoc inline styles to tokens, and add a dependency-free guard test so it
   does not regress.
4. **Graceful empty states / kill console 409s** — stop returning 409 for the
   normal "no audit selected" read case; return 200 + empty so the browser stops
   logging 409s and pages show a calm empty state.

## Non-goals

- No retroactive re-scoring of existing accounts when the forbidden-words list
  changes. `Engine.RescoreWith` exists, but re-scoring rewrites every audit's
  stored data and is a larger operation; out of scope. The UI states plainly that
  edits apply to **newly ingested / re-analyzed** data.
- No ESLint/Prettier toolchain (would require new npm deps; this box is
  `npm ci --ignore-scripts` only). The lint guard is a vitest test instead.
- No visual redesign — spacing is standardized onto tokens, not restyled.
- The real 409 conflicts stay 409 (see §4).

---

## §1. Editable forbidden-words list

### Current state
- `lists/forbidden_words.txt`, one word per line, loaded **once** at startup:
  `cmd/patd/audit.go:205` → `pwanalysis.LoadSet` (`pwanalysis.go:35`), stored as
  `Engine.Lists.ForbiddenWords` (`engine.go:54`, type `pwanalysis.Set =
  map[string]struct{}`).
- Consumed at analysis time: `engine.go:198`
  `pwanalysis.Analyze(pw, e.Lists, …)` → `BannedWords:
  ForbiddenWordsIn(password, lists.ForbiddenWords)` (`pwanalysis.go:307`) →
  scoring penalty up to +0.8 (`risk.go:148`). Case-insensitive substring match.
- Not editable, not hot-reloadable.

### Backend (mirror the Policies pattern, `server.go:1878-1941`)

**Engine hot-swap** (`internal/engine/engine.go`): `Engine.Lists` is currently
read lock-free at `engine.go:198`. Add a `RWMutex` so the forbidden-words set can
be swapped safely:
- Add `listsMu sync.RWMutex` to the `Engine` struct.
- Add `func (e *Engine) SwapForbiddenWords(set pwanalysis.Set) { e.listsMu.Lock();
  defer e.listsMu.Unlock(); e.Lists.ForbiddenWords = set }`.
- Add `func (e *Engine) ForbiddenWords() pwanalysis.Set { e.listsMu.RLock();
  defer e.listsMu.RUnlock(); return e.Lists.ForbiddenWords }`.
- At `engine.go:198`, read the set under the lock (snapshot `lists` with the
  guarded forbidden-words set) so analysis and swap don't race. Keep the rest of
  `e.Lists` as-is (only ForbiddenWords is swappable in this scope).

**Persistence** (`internal/pwanalysis/pwanalysis.go`): add `func SaveSet(path
string, s Set) error` mirroring `LoadSet` — write the words sorted, one per line,
lowercased, trailing newline, atomic (temp file + rename), 0600.

**Server** (`internal/httpapi/server.go`):
- Add `ForbiddenWordsPath string` to the `Server` struct (next to `PolicyPath`,
  line 57). Empty = in-memory only.
- `forbiddenWordsPayload` wire shape: `{ "words": []string }`.
- `GET /api/forbidden-words` → `handleGetForbiddenWords`: lead-gated read (the
  matched words are cleartext fragments — same sensitivity as `/api/report/terms`,
  which is lead-only); returns the current set sorted. If `s.Engine == nil` →
  503.
- `PUT /api/forbidden-words` → `handleSetForbiddenWords`: **lead-only + CSRF**.
  - Decode with `MaxBytesReader(1<<20)` + `DisallowUnknownFields` (mirror
    `handleSetPolicies`).
  - Normalize: trim each word, `ToLower`, drop empties, dedupe. Validate: each
    word length 1–64 after trim; total count ≤ 5000; reject words containing
    newlines/control chars. On violation → 400 with a clear message.
  - `s.Engine.SwapForbiddenWords(newSet)`.
  - Persist if `s.ForbiddenWordsPath != ""` via `pwanalysis.SaveSet`; on failure →
    500 "saved in memory but failed to persist: …" (mirror policies).
  - Audit-log `action: "forbidden_words_update"`, `Target: strconv.Itoa(len)
    + " word(s)"`, never the words themselves. Denied path logs
    `Result: "denied"` (mirror `handleSetPolicies:1900`).
  - Response: `{ "count": n, "persisted": <path|"memory"> }`.
- Routes (next to policies, `server.go:166-167`):
  ```go
  mux.Handle("GET /api/forbidden-words", s.requireAuth(http.HandlerFunc(s.handleGetForbiddenWords)))
  mux.Handle("PUT /api/forbidden-words", s.requireAuth(s.requireCSRF(http.HandlerFunc(s.handleSetForbiddenWords))))
  ```

**Wiring** (`cmd/patd/main.go`): set `ForbiddenWordsPath: filepath.Join(listsDir,
"forbidden_words.txt")` on the Server (mirror `PolicyPath: policyPath` at
`main.go:175`). Confirm `listsDir` is in scope there; if not, thread it like
`policyPath`.

### Frontend (fold into `web/src/components/Policies.tsx`)
- `web/src/api.ts`: add (mirror `getPolicies`/`savePolicies`, `api.ts:346-353`):
  ```ts
  getForbiddenWords: () => request<{ words: string[] }>("/forbidden-words"),
  setForbiddenWords: (words: string[], csrf: string) =>
    request<{ count: number; persisted: string }>("/forbidden-words", {
      method: "PUT",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
      body: JSON.stringify({ words }),
    }),
  ```
- `Policies.tsx`: add a "Forbidden words" section below the existing policy form.
  - Load on mount alongside policies; store as a `\n`-joined textarea value.
  - Textarea (one word per line), live count, Save button → split on newline,
    trim, drop empties, `setForbiddenWords(words, me.csrf_token)`.
  - Success/error flash reusing the page's existing flash mechanism.
  - A muted caveat line: "Changes apply to newly ingested or re-analyzed data;
    existing account scores are unchanged."
  - Page is already lead-gated; reuse that gate (no reveal, no secret surface).

### Security
- Words are scoring config, not credentials. The audit log records only the
  **count**. Read + write are lead-only (matches `/api/report/terms`). No new
  cleartext-on-disk path beyond the already-existing `lists/forbidden_words.txt`.

---

## §2. Table / report width overflow

### Current state
- Single layout container `.main { max-width:1200px; padding:32px 28px 56px }`
  (`styles.css:177`).
- `.table-wrap { overflow:auto }` exists (`styles.css:327-332`) and works, but is
  **not applied** to three tables, which then overflow their fixed-width panels:
  1. Exposure **bridge matrix** — `table.bridge-matrix` (`Exposure.tsx:103`),
     no wrapper.
  2. **Operators** table — `.ops-table` (`Operators.tsx`), no wrapper.
  3. **Activity** table — `.act-table` (`Activity.tsx`), no wrapper.

### Fix
- Wrap each of the three tables in `<div className="table-wrap">…</div>` (the
  bridge matrix may want a dedicated `.bridge-wrap` if its max-height differs, but
  reuse `.table-wrap` unless it visibly breaks the heatmap).
- Add `text-overflow: ellipsis; overflow: hidden; max-width: <n>` to long
  free-text cells that still overflow (follow the existing `.act-target` pattern,
  `styles.css:935`). Verify in the live run; only add where actually needed.
- No new overflow mechanism — consistent application of the existing one.

---

## §3. CSS token system + lint guard

### Current state
- One master stylesheet `web/src/styles.css` (899 lines), imported once
  (`main.tsx:4`). Color/surface tokens exist at `:root` (`styles.css:16-45`);
  **no spacing/radius scale** → spacing hardcoded ad-hoc (8–56px), plus **26
  inline `style={{}}` overrides across 9 files** (worst: `AuditData.tsx` ×9,
  `Exposure.tsx` ×6).

### Tokens (add to `:root`, `styles.css`)
```css
--space-xs: 4px;  --space-sm: 8px;  --space-md: 12px;
--space-lg: 16px; --space-xl: 24px; --space-2xl: 32px;
--radius-sm: 8px; --radius-md: 12px; --radius-lg: 16px;
--main-max-width: 1200px;
--table-max-height: calc(100vh - 250px);
```
- Repoint the existing magic numbers: `.main` max-width → `var(--main-max-width)`;
  `.table-wrap` max-height → `var(--table-max-height)`; section spacing
  (`.section-label`, `.stat-grid`, `.action-section`) onto the `--space-*` scale.
  Keep the *rendered* spacing visually equivalent (pick the nearest token; do not
  redesign).

### Convert inline styles
- Replace the **static** inline spacing/padding/font overrides with token-based
  utility classes or existing classes. Concretely:
  - `AuditData.tsx` ×9 (e.g. `marginBottom:24`, `padding:"8px 0"`, inline
    `fontFamily:"var(--mono)"`) → classes (`.panel` spacing util, a `.font-mono`
    utility class).
  - `Exposure.tsx` ×6 (`marginLeft:6` badge gaps, `marginBottom:12/16`) → use
    flex `gap` on the parent / section spacing classes. (The badge `marginLeft:6`
    cluster row becomes a flex row with `gap: var(--space-xs)`.)
  - Other files' static ones similarly.
- **Keep dynamic inline styles** — they are computed, not ad-hoc spacing:
  `AccountsTable.tsx` virtualization `height: start*ROW_H`; `Dashboard.tsx`
  `animationDelay`; `Charts.tsx` pixel dims. These must remain inline.

### Lint guard — `web/src/styleguard.test.ts` (vitest, node-env, no deps)
- Reads `web/src/**/*.tsx` via `node:fs`/`fast-glob`-free recursion (use `fs`
  + manual walk; no new dep).
- **Fails** if it finds an inline style object property `margin*`, `padding*`,
  `gap`, or `width`/`height` whose value is a **literal px number/string**
  (e.g. `margin: 8`, `padding: "8px 0"`, `marginLeft: 6`). Regex targets literal
  numeric/`"…px"` values so computed expressions (`start*ROW_H`,
  `` `${x}px` ``, `animationDelay`) pass.
- Emits the offending file + matched snippet so regressions are actionable.
- Runs in the existing `npx vitest run` gate. Seed it green by converting the 26
  offenders first.

---

## §4. Graceful empty states / kill console 409s

### Current state
- `activeAudit(w, sess)` writes **409 "no audit selected"** when no audit is
  selected or it was deleted (`server.go:1181-1187`). Read handlers also emit a
  second 409 on `Store` `ErrNotFound` (`server.go:1225, 1239, 1257`, …).
- The browser DevTools console logs the raw 409 HTTP response regardless of JS
  `.catch()` — that's the console noise.
- Several pages render "no audit selected" as a red error
  (`Accounts`, `Actionable`) or a hint (`Exposure`, `Domains`); `Dashboard`
  silently swallows it. The genuine "audit exists, no data ingested" case already
  returns **200 + empty** and renders fine (`GetStarted`, empty tables).

### Backend — narrow change to READ endpoints only
- Add a non-writing resolver: `func (s *Server) activeAuditRead(sess auth.Session)
  (string, bool)` that returns `(sess.ActiveAudit, true)` only when selected and
  present, else `("", false)` **without writing a response**.
- Update the read handlers to return **200 + empty** when `!ok`:
  - `GET /api/accounts` → `[]model.Account{}` (`handleAccounts:1217`).
  - `GET /api/report` → `model.BuildReport(nil)` (`handleReport:1249`).
  - `GET /api/summary` → empty summary (whatever `Store.Summary` of empty yields;
    construct the zero summary) (`handleSummary:1231`).
  - `GET /api/report/terms` → empty terms (lead path unchanged) (`:1267`).
  - `GET /api/ingests` → `[]` (`:1608` area).
  - CSV/HTML exports → empty document (200), not 409 (`:1667, 1741, 1784`).
  - Also collapse the secondary `ErrNotFound` 409 in these handlers to the same
    empty 200 (the store returning `ErrNotFound` here means the same "no data"
    condition).
- **Unchanged (still 409 — these are real conflicts):** rekey-in-progress
  (`:477,518`), job-already-running (`:608,628,662,694,729`), user create/update
  conflicts (`:746,1051`), and **all write/mutation handlers** (upload, cracks,
  domain delete: `:1355,1436,1530,1562,1576`) — you genuinely cannot mutate
  without a selected audit, so those keep `activeAudit`'s 409.

### Frontend — calm empty states
- With the backend returning empty, the `reportErr`/`error` paths for "no audit
  selected" stop firing. Ensure each page renders a friendly empty state for the
  "no data yet" case rather than a blank/transient error:
  - `Accounts` / `accountsData.tsx`: empty list → existing empty/onboarding view
    (no red error for the empty case).
  - `Actionable`, `Exposure`, `Domains`: when the report is empty (0 accounts),
    show a muted "No data yet — select or create an audit and upload a dump."
    instead of an error hint.
  - `Dashboard`: already shows `GetStarted` on empty; keep.
- Real errors (500, 423-locked, network) still surface as before — only the
  "no audit/no data" case becomes a calm empty state.

---

## Testing & gates

- **Go:** `gofmt -l cmd internal` empty; `go build ./... && go vet ./... && go
  test ./...`. New unit tests: `pwanalysis.SaveSet` round-trips with `LoadSet`;
  `engine.SwapForbiddenWords` changes analysis output; handler tests for
  `forbidden-words` GET/PUT (lead gate, CSRF, validation, audit-count-only) and
  for the read endpoints returning 200+empty when no audit selected (no 409).
- **Web:** `npx tsc --noEmit`; `npx vitest run` (incl. the new
  `styleguard.test.ts`, green after conversion); `npm run build`. No
  jsdom/testing-library added; component correctness via tsc/build + live run.
- **Supply chain:** `go.mod` / `web/package.json` unchanged; `govulncheck ./...`
  clean.
- **Live run:** rebuild the embedded `patd.exe`, restart, verify: edit forbidden
  words (lead) → 200 + audit line with count only; no 409 in console on a
  fresh/no-audit session; the three tables scroll within their panels; spacing
  consistent across pages.

## Out-of-scope / future
- Retroactive re-scoring on wordlist change (via `Engine.RescoreWith`).
- Tokenizing every px in `styles.css` (only the spacing/radius/layout magic
  numbers and the 26 inline overrides are in scope).
