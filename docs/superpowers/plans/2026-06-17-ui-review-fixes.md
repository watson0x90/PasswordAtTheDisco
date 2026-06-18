# UI Review Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`).

**Goal:** Fix the four issues found in the live Playwright e2e review of v2.9.0 — a header that overflows/clips below ~1100px, console-noise 401s on load, run-together chart labels + a stray chart node — and add a one-command dev-seed script so a loaded instance is trivial to stand up.

**Architecture:** Frontend-only except one narrow backend change (`/api/me` → 200 always). Header collapses its tabs into a ☰ menu at a breakpoint, reusing the existing `NavDropdown` pattern. `/api/me` stops 401-ing for anonymous (matches the 409→empty philosophy already adopted). Chart labels get a display mapping reusing the app's existing `a–z / A–Z / 0–9 / !@#` class notation. The dev-seed script automates the exact login→unlock→create→upload→cracks flow against a disposable instance.

**Tech Stack:** Go stdlib `net/http`; React 18 + TS + Vite; recharts; bash + curl for the seed script. No new deps.

**Branch:** `feature/ui-review-fixes` (off `main`, post-`v2.9.0`).

**Gates:** Go: `gofmt -l cmd internal`, `go build/vet/test ./...`. Web (in `web/`, project-local bins, never `npm install`): `npx tsc --noEmit`, `npx vitest run`, `npm run build`. `govulncheck ./...`. Final: Playwright re-verify on a freshly seeded instance.

---

## Task 1: `/api/me` returns 200 for anonymous (kill console 401)

**Files:** `internal/httpapi/server.go` (route ~107, `handleMe` 339-353, `requireAuth` 2097-2111); `internal/httpapi/server_test.go`; `web/src/auth.tsx` (33-56); `web/src/api.ts` (`Me` type, `me()` 262).

- [ ] **Step 1 — failing test.** In `server_test.go`, assert anonymous `GET /api/me` is 200 with `authenticated:false` (use the harness `newServer`, `do`, NO login):
```go
func TestMeAnonymousIs200(t *testing.T) {
	srv := newServer("secret")
	rr := do(srv, "GET", "/api/me", nil) // no cookie
	if rr.Code != http.StatusOK {
		t.Fatalf("anon /api/me = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"authenticated":false`) {
		t.Fatalf("missing authenticated:false: %s", rr.Body.String())
	}
}
```
Check `do`'s signature handles a nil cookie (it takes `*http.Cookie`; pass `nil`). If `do` can't send no-cookie, build the request inline like other tests do.

- [ ] **Step 2 — run, expect FAIL** (currently 401): `go test ./internal/httpapi/ -run TestMeAnonymousIs200 -v`.

- [ ] **Step 3 — backend.** Register `/api/me` WITHOUT `requireAuth` (it must be reachable anonymously). At server.go:107 change to:
```go
	mux.Handle("GET /api/me", http.HandlerFunc(s.handleMe))
```
Rewrite `handleMe` to resolve the session itself and return 200 either way:
```go
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"authenticated": false})
		return
	}
	sess, ok := s.Sessions.Get(c.Value)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"authenticated": false})
		return
	}
	active := sess.ActiveAudit
	if active != "" && (!s.Store.Unlocked() || !s.Store.Has(active)) {
		active = ""
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated":     true,
		"username":          sess.Username,
		"role":              string(sess.Role),
		"csrf_token":        sess.CSRF,
		"active_audit":      active,
		"store_initialized": s.Store.Initialized(),
		"store_unlocked":    s.Store.Unlocked(),
	})
}
```
Confirm `sessionCookie` is the cookie-name constant `requireAuth` uses (server.go:2099). Leave `requireAuth` itself unchanged (every other protected route still uses it).

- [ ] **Step 4 — frontend.** In `web/src/api.ts`, add `authenticated?: boolean` to the `Me` type. In `web/src/auth.tsx` bootstrap (33-56), branch on the flag instead of relying on a thrown 401:
```tsx
    api.me()
      .then((m) => {
        if (!active) return
        if (m.authenticated === false) { setStatus("anonymous"); return }
        setMe(m); setStatus("authenticated")
      })
      .catch(() => { if (active) setStatus("anonymous") })
```
Grep other `api.me()` callers (e.g. a csrf refresh) — authenticated users still get the full payload, so they're unaffected; verify none asserts on a 401.

- [ ] **Step 5 — verify + commit.** `go test ./internal/httpapi/`; `(cd web && npx tsc --noEmit && npm run build)`. Commit:
```
gofmt -w internal/httpapi/server.go internal/httpapi/server_test.go
git add internal/httpapi/server.go internal/httpapi/server_test.go web/src/api.ts web/src/auth.tsx
git commit -m "fix(api): /api/me returns 200 anonymous (authenticated flag) — no console 401 on load"
```

---

## Task 2: Readable complexity-chart labels

**Files:** `web/src/insights.ts` (`complexityCounts` 167-174); a unit test (create `web/src/insights.test.ts` or extend an existing insights test if present — grep first); the chart already reads `name` so no chart change needed.

- [ ] **Step 1 — failing test.** Grep for an existing insights test; if none, create `web/src/insights.test.ts`:
```ts
import { describe, it, expect } from "vitest"
import { complexityLabel } from "./insights"

describe("complexityLabel", () => {
  it("maps the full-class key to class tokens", () => {
    expect(complexityLabel("mixedalphaspecialnum")).toBe("a–z A–Z 0–9 !@#")
  })
  it("maps a partial key", () => {
    expect(complexityLabel("loweralphanum")).toBe("a–z 0–9")
  })
  it("passes through unknown keys unchanged", () => {
    expect(complexityLabel("weird")).toBe("weird")
  })
})
```

- [ ] **Step 2 — run, expect FAIL** (`complexityLabel` undefined): `(cd web && npx vitest run insights)`.

- [ ] **Step 3 — implement.** In `web/src/insights.ts`, add the exported mapper (the 16 backend enum values from `pwanalysis.Complexity`, decomposed into the app's existing `a–z / A–Z / 0–9 / !@#` notation) and apply it in `complexityCounts`:
```ts
// Maps the backend Complexity() enum (internal/pwanalysis) to the app's
// character-class notation (same tokens as the Policies page) so the chart axis
// reads "a–z A–Z 0–9 !@#" instead of "mixedalphaspecialnum".
const COMPLEXITY_LABELS: Record<string, string> = {
  loweralpha: "a–z",
  upperalpha: "A–Z",
  numeric: "0–9",
  special: "!@#",
  loweralphanum: "a–z 0–9",
  upperalphanum: "A–Z 0–9",
  mixedalpha: "a–z A–Z",
  loweralphaspecial: "a–z !@#",
  upperalphaspecial: "A–Z !@#",
  specialnum: "0–9 !@#",
  mixedalphanum: "a–z A–Z 0–9",
  loweralphaspecialnum: "a–z 0–9 !@#",
  mixedalphaspecial: "a–z A–Z !@#",
  upperalphaspecialnum: "A–Z 0–9 !@#",
  mixedalphaspecialnum: "a–z A–Z 0–9 !@#",
  none: "(none)",
}
export function complexityLabel(key: string): string {
  return COMPLEXITY_LABELS[key] ?? key
}
```
Then in `complexityCounts`, map the name: `.map(([name, value]) => ({ name: complexityLabel(name), value }))`.

- [ ] **Step 4 — verify + commit.** `(cd web && npx vitest run insights && npx tsc --noEmit && npm run build)`. Commit:
```
git add web/src/insights.ts web/src/insights.test.ts
git commit -m "fix(web): readable complexity-chart labels (a–z/A–Z/0–9/!@# class tokens)"
```

---

## Task 3: Contain the stray chart node

**Files:** `web/src/components/Charts.tsx` (HBars/Tooltip 22-26, 70-82), `web/src/styles.css` (chart-card container).

Context: on Overview, a detached text node showing a complexity label renders at the document root — a recharts measurement/tooltip artifact. After Task 2 it shows the readable label, but it may still be a stray node.

- [ ] **Step 1 — reproduce + scope.** With a seeded instance running (Task 5) or against the existing build, open the app and inspect: is the node visible (occupies space / shows text) or zero-size/invisible? Use the browser devtools or a Playwright `browser_evaluate` checking for text nodes that are direct children of `<body>` outside the app root. Record the finding.

- [ ] **Step 2 — fix if visible.** If the node is visible/disruptive: ensure each chart card clips its overflow and the recharts tooltip can't leak — in `styles.css` give the chart container `position: relative; overflow: hidden;` (find the `.chart-card`/chart wrapper class actually used by `ChartCard`), and in `Charts.tsx` set the recharts `<Tooltip>` `wrapperStyle={{ pointerEvents: "none" }}` and confirm a single `<ResponsiveContainer>` per chart (no double-mount). If the node is zero-size/invisible (a benign recharts measurement artifact), do NOT chase it — add a one-line code comment in `Charts.tsx` noting it's a known recharts measurement node, and move on.

- [ ] **Step 3 — verify + commit.** `(cd web && npx tsc --noEmit && npm run build)`. Commit:
```
git add web/src/components/Charts.tsx web/src/styles.css
git commit -m "fix(web): contain stray recharts node / document benign measurement artifact"
```

---

## Task 4: Header collapses to a ☰ menu at narrow widths

**Files:** `web/src/components/AppShell.tsx` (header 48-87, `NavDropdown` 113-165), `web/src/styles.css` (`.topbar` 82-93, `.nav` 99-116, `.nav-dd*` 118-149, `.topbar-right` 151-154).

Context: below ~1100px the inline `.nav` + Setup/Admin dropdowns force the page wider than the viewport (671px overflow measured at 820px) and the right cluster clips. Reuse the existing `NavDropdown` open/close/backdrop/Escape pattern for a single ☰ menu holding ALL nav targets.

- [ ] **Step 1 — add a ☰ menu component.** In `AppShell.tsx`, add a `NavMenu` (mirror `NavDropdown`’s state/backdrop/Escape, lines 113-165) whose trigger is a `☰` button (`.topbar-hamburger`) and whose menu lists every destination: the 7 primary tabs (Overview…Reports) plus the Setup items and Admin items, each a `role="menuitem"` `.nav-dd-item` that calls the same view/navigation setter `NavDropdown`/the tabs use. Keep its label/aria: `aria-haspopup="menu"`, `aria-expanded`, `aria-label="Menu"`.

- [ ] **Step 2 — render it in the header** next to the brand (so it sits on the left), e.g. `<NavMenu .../>` right after the brand and before `.nav`.

- [ ] **Step 3 — responsive CSS.** In `styles.css` add a breakpoint (use `900px`; the inline nav + right cluster stop fitting around there):
```css
.topbar-hamburger { display: none; }   /* hidden on wide screens */
@media (max-width: 900px) {
  .nav { display: none; }              /* hide inline tabs */
  .topbar .nav-dd { display: none; }   /* hide inline Setup/Admin dropdowns */
  .topbar-hamburger { display: inline-flex; }
}
```
Style `.topbar-hamburger` to match `.nav-dd-trigger`. Also make the header not overflow: ensure `.topbar`/`.topbar-left` use `min-width: 0` and the right cluster can shrink (e.g. allow the verbose user sublabel to hide under the breakpoint: `@media (max-width: 900px) { .who .operator-sub { display: none } }` — use the real class names from the file). The goal: at 820px the page has NO horizontal scrollbar and every destination is reachable via ☰.

- [ ] **Step 4 — verify (build + live).** `(cd web && npx tsc --noEmit && npm run build)`. Then rebuild+seed (Tasks 5/6) and Playwright-verify at 820px: `document.documentElement.scrollWidth === clientWidth` (no overflow), ☰ opens a menu, every destination navigates, Escape/backdrop closes it. Above 1100px the inline nav is unchanged.

- [ ] **Step 5 — commit.**
```
git add web/src/components/AppShell.tsx web/src/styles.css
git commit -m "fix(web): collapse header nav into a menu below 900px (no overflow/clipping)"
```

---

## Task 5: `tools/dev_seed.sh` — one-command loaded instance

**Files:** create `tools/dev_seed.sh` (tracked; bash + curl). Mirrors the exact flow already proven by hand.

- [ ] **Step 1 — write the script.** It must: (a) generate synthetic data if missing (`python tools/gen_synthetic.py`); (b) mint a throwaway lead via `go run ./cmd/patd hashpw` and write `.devusers.json`; (c) start `patd.exe` backgrounded on `127.0.0.1:8444` with isolated `.devdata`/`.devusers.json`/`.devaudit.log` and BloodHound OFF (`PATD_BHE=.no-bloodhound.json`); (d) wait for `/api/version`; (e) login → unlock(init) → create+open audit → upload the 3 domain dumps → apply cracks (curl with the session cookie + CSRF); (f) print the URL, throwaway creds, store passphrase, and the PID + how to stop it. All creds are clearly-labelled disposable dev values; loopback only; isolated dirs (never touches real `data/`/`config/`). Base it on these exact calls (already verified working):
  - login: `POST /api/login {"username":"dev","password":"devpass123456"}` (-c cookiejar)
  - unlock/init: `POST /api/unlock {"passphrase":"devstorepass123"}` with `X-CSRF-Token`
  - audit: `POST /api/audits {"name":"Dev Seed"}` then `POST /api/audits/<id>/open`
  - upload: `POST /api/upload -F domain=<D> -F uncracked=@sample_data/synthetic/<D>_dump.txt` for CORP.LOCAL, EU.CORP.LOCAL, LAB.LOCAL
  - cracks: `POST /api/upload/cracks -F crackfile=@sample_data/synthetic/cracks.txt`
  Add a `--stop` flag (or a sibling note) to kill the instance and clean `.dev*` artifacts.

- [ ] **Step 2 — run it end-to-end.** Execute `bash tools/dev_seed.sh`, confirm it prints a reachable URL and that `GET /api/summary` (with the cookie) shows `total_accounts:68, cracked:57`. Then stop it and confirm cleanup.

- [ ] **Step 3 — commit.**
```
git add tools/dev_seed.sh
git commit -m "tools: dev_seed.sh — one-command disposable instance + synthetic data load"
```

---

## Task 6: Gate, rebuild, Playwright re-verify, docs

- [ ] **Step 1 — full gate.** `gofmt -l cmd internal`; `go build ./... && go vet ./... && go test ./...`; `(cd web && npx tsc --noEmit && npx vitest run && npm run build)`; `govulncheck ./...`.
- [ ] **Step 2 — rebuild** via the build-and-run skill: `bash .claude/skills/build-and-run/scripts/build.sh`.
- [ ] **Step 3 — seed + Playwright re-verify** on `:8444`: (a) fresh load → **no `/api/me` 401** in console; (b) Overview "Password complexity" axis shows `a–z A–Z 0–9 !@#`; (c) resize to 820px → **no page horizontal scrollbar**, ☰ menu reaches every view; (d) no new console errors across the walk.
- [ ] **Step 4 — README bullet** under "What's new in 2.8" (or a fresh 2.9 note): responsive header, quieter console, readable complexity labels, `tools/dev_seed.sh`. (Note `README.md` is tracked; `CLAUDE.md`/`.claude` are gitignored.)
- [ ] **Step 5 — commit docs**, then final whole-branch review + finishing-a-development-branch.

---

## Self-review
- **Coverage:** #1 header→Task 4; #2 console 401→Task 1; #3 labels→Task 2; #4 stray node→Task 3; dev-friction→Task 5; verify→Task 6. All review findings mapped.
- **Types:** `complexityLabel(string):string` (T2) used in `complexityCounts`; `Me.authenticated?:boolean` (T1) used in `auth.tsx`; `handleMe` 200-always consistent with the route losing `requireAuth`.
- **Confirm-by-reading:** the `do` helper's no-cookie call shape (T1); real class names for the user sublabel + chart-card wrapper (T3/T4); existing insights test file presence (T2).
