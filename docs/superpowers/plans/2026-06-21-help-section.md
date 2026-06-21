# In-App Help / Methodology Section — Implementation Plan

> REQUIRED SUB-SKILL: superpowers:subagent-driven-development

**Date:** 2026-06-21
**Spec:** `docs/superpowers/specs/2026-06-20-help-section-design.md`
**Scoring reference:** `docs/superpowers/specs/2026-06-20-scoring-engine-v2-design.md` (the two-axis model shipped on `main` as v2.18.0)

## Goal

Add a polished, presentation-style **Help / Methodology** surface inside the SPA that
explains *how the tool works* — the security thesis, the two-axis Exposure × Impact
scoring model (matching the SHIPPED v2), the enrichment pipeline, the security/privacy
model, and a glossary/FAQ. It must be:

- **Reachable pre-auth** (from the login screen), **while the store is locked** (from the
  unlock screen), AND **post-auth** (from the app shell).
- A **pure static React surface** — NO authenticated API calls, NO audit/config/operator
  data embedded. The only dynamic value it may show is the already-public version/build
  (which the footer already exposes). A reviewer confirms zero API data.
- **No new npm dependencies** — diagrams are inline SVG/CSS reusing existing house style
  (recharts is already present; we will mostly use plain SVG/CSS for static diagrams).
- **Class-based styles only** (passes `web/src/styleguard.test.ts` — no literal inline
  px/spacing in `.tsx`).

## Architecture

### Routing (LOCKED — resolves the spec's deferred routing detail)

The app has **no hash router**; `App.tsx`'s `Routed()` does STATE-based routing
(`status==="anonymous"` → `<Login/>`; authed-but-locked → `<Unlock/>`; else
`<AppShell>` + `viewFor(view)`). We add Help in two complementary places:

1. **Pre-auth / locked reachability** — a top-level `showHelp` boolean state in
   `Routed()`, checked **BEFORE** the `anonymous`/`locked` branches. When `showHelp` is
   true, render `<Help onClose={() => setShowHelp(false)} />` standalone (no auth
   providers), so Help is reachable while logged out and while locked. `Login.tsx` and
   `Unlock.tsx` each get a "How it works" link that calls a passed `onShowHelp` callback
   which sets `showHelp=true`.
2. **Post-auth reachability** — add a `"help"` member to the `View` union and a
   **header link** ("Help") in `AppShell`'s `topbar-right`, next to Sign Out, plus a
   `viewFor("help")` case rendering `<Help />` (embedded mode, no `onClose`).
   - **Why a header link, not a `TABS` entry:** the primary `TABS` row is the
     analyst worklist (Overview/Actionable/Accounts/…); Help is meta/reference, not part
     of the audit workflow, and belongs with the account-level controls (Lock / Sign
     Out) on the right — same reasoning the spec uses for placing it on login/locked
     screens. A single header link also keeps the (already busy) tab row unchanged. The
     `"help"` View still routes through `viewFor` so the active state and CommandPalette
     can target it for free.

`Help` is **mode-aware**: when given `onClose` it renders standalone with a visible
"← Back" control (pre-auth/locked); without `onClose` it renders embedded in the shell
(post-auth). Either way it is the SAME component, makes NO authenticated calls, and
needs NONE of the authed providers (Audits/Accounts/Jobs/Nav) to render.

### Deep-linking (LOCKED — resolves spec nice-to-have `#/help/scoring`)

**Lightweight hash sync, kept trivially small.** The active chapter is component state
(`useState<ChapterId>`). A small `useChapterHash` hook (its own tested module)
(a) initializes the chapter from `location.hash` (`#help/scoring`) on mount and
(b) writes `location.hash` when the chapter changes — so a chapter is linkable in an
email without introducing a router. This is the ONLY hash handling; it is a pure helper
with a real vitest test (parse/format round-trip + unknown-id fallback). If, during T1,
the hash sync proves to interfere with the state-based `showHelp` toggle, fall back to
**chapter-state-only** and drop deep-linking for v1 (YAGNI) — documented in the task.
Default decision: ship the lightweight hash sync.

### Chapter structure (LOCKED)

A left-rail sub-nav switches 5 chapters. Files are kept focused under a new
`web/src/components/help/` directory: a `Help.tsx` shell (mode handling + sub-nav +
chapter registry + active-chapter render) plus one component per chapter and a couple of
shared inline-SVG diagram components. A pure `chapters.ts` registry (id → label →
component) is unit-tested (stable ids, no dupes, hash ids match).

Diagrams follow the dashboard house style: wrap in a `panel`/`chart-card`-like titled
card, reuse color tokens (`--crit/--high/--med/--low`, `--glass`, `--glass-border`), and
use inline `<svg>`/CSS-grid (mirroring `MatrixHeatmap` in `web/src/components/Charts.tsx`,
which is itself a CSS-grid heatmap). No recharts is required for the static diagrams; do
NOT add deps.

## Tech Stack

- **React 18 + TypeScript (strict)**, Vite SPA in `web/`.
- **Styling:** existing `web/src/styles.css` tokens + new class-based Help styles appended
  there (or a colocated CSS the build already bundles — append to `styles.css` to match
  current convention). NO inline literal spacing (styleguard).
- **Diagrams:** inline SVG + CSS grid (no new deps).
- **Tests:** `vitest` (incl. `styleguard.test.ts`), `tsc --noEmit`, `npm run build`;
  live **Playwright** against `http://127.0.0.1:8443`.
- **Skills:** **frontend-design** for all UI/UX; **build-and-run** for the CGO-free embed
  rebuild before the Playwright sweep.

---

## File Structure

| Path | Status | Purpose |
|---|---|---|
| `web/src/components/help/Help.tsx` | new | Shell: mode (standalone/embedded), sub-nav, active chapter, optional hash sync |
| `web/src/components/help/chapters.ts` | new | Pure chapter registry (id, label, hash slug, component) — unit-tested |
| `web/src/components/help/chapters.test.ts` | new | Tests: stable/unique ids, slug↔id round-trip, registry order |
| `web/src/components/help/useChapterHash.ts` | new | Pure hash parse/format helpers + hook for `#help/<slug>` deep-link |
| `web/src/components/help/useChapterHash.test.ts` | new | Tests: parse known/unknown slug, format, round-trip |
| `web/src/components/help/ChapterThesis.tsx` | new | Chapter 1 — "Why this exists" hero/thesis |
| `web/src/components/help/ChapterScoring.tsx` | new | Chapter 2 — Exposure × Impact model + worked example |
| `web/src/components/help/ChapterPipeline.tsx` | new | Chapter 3 — enrichment pipeline (BloodHound + HIBP) |
| `web/src/components/help/ChapterSecurity.tsx` | new | Chapter 4 — security & privacy model |
| `web/src/components/help/ChapterGlossary.tsx` | new | Chapter 5 — glossary (reuse `glossary.ts`) + FAQ |
| `web/src/components/help/diagrams/ExposureImpactGrid.tsx` | new | Static Exposure × Impact matrix diagram (SVG/CSS grid) |
| `web/src/components/help/diagrams/PipelineFlow.tsx` | new | Static dump→analysis→enrichment→scoring→dashboard flow (SVG) |
| `web/src/components/help/diagrams/RevealFlow.tsx` | new | Small reveal/audit data-flow diagram (SVG) |
| `web/src/App.tsx` | edit | `showHelp` state + pre-auth/locked intercept; pass `onShowHelp` to Login/Unlock; `viewFor("help")` |
| `web/src/components/AppShell.tsx` | edit | `View` union gains `"help"`; header "Help" link in `topbar-right` |
| `web/src/components/Login.tsx` | edit | "How it works" link → `onShowHelp` |
| `web/src/components/Unlock.tsx` | edit | "How it works" link → `onShowHelp` (both lead and non-lead variants) |
| `web/src/styles.css` | edit | Help layout/sub-nav/hero/diagram classes (token-based) |

---

## Task 1 — Routing scaffold + entry points + empty Help shell

Goal: Help is **reachable pre-auth, while locked, and post-auth**, rendering an empty
shell with a working 5-chapter sub-nav and "← Back" (standalone) — tsc/vitest/build green.

**Files:** `web/src/components/help/Help.tsx`, `web/src/components/help/chapters.ts`,
`web/src/components/help/chapters.test.ts`, `web/src/components/help/useChapterHash.ts`,
`web/src/components/help/useChapterHash.test.ts`, `web/src/App.tsx`,
`web/src/components/AppShell.tsx`, `web/src/components/Login.tsx`,
`web/src/components/Unlock.tsx`, `web/src/styles.css`

1. [ ] Create `chapters.ts` — a pure registry array of `{ id, slug, label }` for the 5
   chapters (`thesis`/`why-this-exists`, `scoring`/`how-we-score`, `pipeline`/`enrichment`,
   `security`/`security-privacy`, `glossary`/`glossary-faq`). Export `ChapterId` type,
   `CHAPTERS` array, and a `chapterBySlug(slug): ChapterId | undefined`. Leave component
   wiring as a TODO list (sections added in later tasks). Keep it data-only so it's
   testable without React.
2. [ ] Write `chapters.test.ts` FIRST for the pure registry: ids unique, slugs unique,
   exactly 5 entries in intended order, `chapterBySlug` returns the id for a known slug
   and `undefined` for an unknown one. Run `npx vitest run chapters` — RED, then make it
   pass.
3. [ ] Create `useChapterHash.ts` — pure helpers `parseHelpHash(hash): ChapterId | null`
   (matches `#help/<slug>` only, else null) and `formatHelpHash(id): string`
   (`"#help/<slug>"`), plus a `useChapterHash(initial)` hook returning
   `[chapter, setChapter]` that seeds from `location.hash` on mount and writes
   `location.hash` on change (guarded so it only touches `#help/*` hashes). Keep the
   DOM-touching part minimal; the parse/format functions are pure.
4. [ ] Write `useChapterHash.test.ts` FIRST for `parseHelpHash`/`formatHelpHash`:
   `parseHelpHash("#help/how-we-score")===\"scoring\"`, `parseHelpHash("#nope")===null`,
   `parseHelpHash("")===null`, `formatHelpHash("security")==="#help/security-privacy"`,
   and a round-trip `parse(format(id))===id` for all 5 ids. RED → green.
5. [ ] Create `Help.tsx` shell with the **frontend-design skill**:
   - Props: `{ onClose?: () => void }`. `onClose` present ⇒ standalone mode (render a
     `← Back` button calling `onClose`, wrap in a full-screen `.help-standalone` shell
     with the brand lockup like the login card). Absent ⇒ embedded mode (no Back; render
     inside the shell's `<main>`).
   - Active chapter via `useChapterHash` (default `"thesis"`).
   - Left-rail sub-nav from `CHAPTERS` (`.help-nav` buttons, active class), and a content
     pane that, for now, renders a placeholder `<h2>{label}</h2>` per chapter (real
     sections land in T2–T5).
   - MUST NOT import `useAuth`, `api`, or any data provider. (A later review asserts this.)
6. [ ] Edit `App.tsx`: add `const [showHelp, setShowHelp] = useState(() => location.hash.startsWith("#help"))` in `Routed()` — initializing from the hash so a COLD `#help/<slug>` URL (an emailed chapter link) auto-opens Help on that chapter pre-auth (the deep-link use case), not just chapter-switching within an already-open Help. (If the YAGNI fallback drops hash sync, initialize to `false`.)
   Immediately after the `status === "loading"` guard and BEFORE the `anonymous` branch:
   ```tsx
   if (showHelp) return <Help onClose={() => setShowHelp(false)} />
   if (status === "anonymous") return <Login onShowHelp={() => setShowHelp(true)} />
   if (me && !me.store_unlocked) return <Unlock onShowHelp={() => setShowHelp(true)} />
   ```
   Import `Help` (eager — it is small/static and must load pre-auth; do NOT lazy-load
   behind the recharts chunk). Add `"help"` handling to the post-auth shell by passing it
   through `viewFor` (next step).
7. [ ] Edit `AppShell.tsx`: add `"help"` to the `View` union. Add a header link in
   `topbar-right` (inside the `{me && (...)}` block, before Sign Out):
   `<button className="btn" onClick={() => onNav("help")}>Help</button>`. Do NOT add a
   `TABS` entry (justified in Architecture).
8. [ ] Edit `App.tsx` `viewFor`: add `case "help": return <Help />` (embedded mode, no
   `onClose`).
9. [ ] Edit `Login.tsx`: add an optional `onShowHelp?: () => void` prop; render a
   `link-btn` "How it works" below the Sign In button when provided
   (`{onShowHelp && <button type="button" className="link-btn" onClick={onShowHelp}>How it works</button>}`).
10. [ ] Edit `Unlock.tsx`: add the same optional `onShowHelp` prop and render the "How it
    works" `link-btn` in BOTH the non-lead card and the lead form (near the sign-out
    control).
11. [ ] Append Help layout classes to `styles.css` (token-based, NO literal inline px in
    `.tsx`): `.help-standalone`, `.help-shell`, `.help-nav`, `.help-nav-item(.active)`,
    `.help-content`, `.help-back`. Reuse `--glass`, `--glass-border`, panel radii.
12. [ ] **Frontend gates:** from `web/`:
    `npx tsc --noEmit` && `npx vitest run` (must include `styleguard` + the new
    chapters/hash tests) && `npm run build`. All green.
13. [ ] Quick **Playwright** smoke (controller may batch with T6's full sweep): build the
    embed binary via the **build-and-run** skill, restart `patd.exe`, navigate to
    `http://127.0.0.1:8443`, confirm a "How it works" link on the login screen opens Help
    standalone with a working sub-nav and Back; then (after a lead unlock) confirm the
    header "Help" link opens the embedded Help. Console: 0 errors.

## Task 2 — Chapter 1: "Why this exists" (thesis / hero)

Goal: the security thesis as a confident hero — legacy tool wrote cleartext cracked
passwords to disk; this NEVER does (memory-only; one-at-a-time lead reveal; every reveal
audit-logged, never the password). Includes the small reveal/audit data-flow diagram.

**Files:** `web/src/components/help/ChapterThesis.tsx`,
`web/src/components/help/diagrams/RevealFlow.tsx`, `web/src/components/help/Help.tsx`
(wire the section), `web/src/styles.css`

1. [ ] Build `ChapterThesis.tsx` with the **frontend-design skill**: a hero block
   (`.help-hero`) with confident typography stating the thesis; a before/after contrast
   (legacy "cleartext to disk" vs "cleartext only in memory, revealed one account at a
   time to leads, every reveal audit-logged — never the password"). Executive-credible
   tone, scannable lede + detail. Static copy only.
2. [ ] Build `RevealFlow.tsx` — a small inline-SVG/CSS data-flow: cracked password in
   memory → lead requests reveal → audit log entry (no password) → operator sees
   cleartext once. Reuse token colors; wrap in a titled card (`ChartCard`-style).
3. [ ] Wire `thesis` chapter in `Help.tsx` to render `<ChapterThesis />`.
4. [ ] Add hero/contrast classes to `styles.css` (token-based).
5. [ ] **Frontend gates:** `npx tsc --noEmit` && `npx vitest run` && `npm run build` — green.

## Task 3 — Chapter 2: "How we score risk" (Exposure × Impact centerpiece)

Goal: explain the SHIPPED two-axis model and render the Exposure × Impact matrix diagram
+ a worked example. Must match `matrix.ts`/`glossary.ts` exactly (Critical≥8, High≥6,
Medium≥4, Low<4; Unknown as a distinct column).

**Files:** `web/src/components/help/ChapterScoring.tsx`,
`web/src/components/help/diagrams/ExposureImpactGrid.tsx`,
`web/src/components/help/Help.tsx`, `web/src/styles.css`

1. [ ] Build `ExposureImpactGrid.tsx` — a STATIC Exposure × Impact matrix diagram in the
   visual language of `MatrixHeatmap` (CSS grid; rows = Impact, cols = Exposure
   Critical→Low **plus an Unknown column**), with each cell labeled by the resulting
   Level per the spec's matrix table. This is illustrative (no live data) — hard-code the
   level mapping from the scoring-v2 design's matrix and the Unknown→provisional behavior.
   Reuse `--crit/--high/--med/--low` tokens for cell tinting.
2. [ ] Build `ChapterScoring.tsx` with the **frontend-design skill**, covering, in
   plain language matching `glossary.ts` (`exposure_axis`, `impact_axis`,
   `impact_unknown`, `coverage`, `provisional`, `percentile`):
   - **Exposure (0–10, always):** crackability/weakness, HIBP breach prevalence, password
     reuse, roastability — computed from the dump + HIBP, so always trustworthy.
   - **Impact (0–10 or Unknown):** blast radius — privilege/controlled-object count, DA
     reachability, Tier-0/DA-equivalent, Enabled state — BloodHound-derived; **Unknown
     (never "low")** when not enriched.
   - **Level = 2D matrix** of the two tiers (not max, not two badges); the hard override
     (cracked + confirmed DA path ⇒ Critical); **provisional** badge + needs-enrichment
     routing when Impact is Unknown.
   - **Coverage/confidence:** graceful degradation; per-account Unknown + audit coverage
     banner.
   - **Percentile:** within-audit triage rank (a sort key, not a displayed score).
   - **Worked example:** walk one account from inputs → Exposure, Impact, Level (static,
     illustrative numbers).
3. [ ] Wire `scoring` chapter in `Help.tsx`.
4. [ ] Add scoring-diagram/worked-example classes to `styles.css` (token-based).
5. [ ] **Frontend gates:** `npx tsc --noEmit` && `npx vitest run` && `npm run build` — green.

## Task 4 — Chapter 3: "The enrichment pipeline"

Goal: how BloodHound + HIBP feed the model, with a pipeline flow diagram and the
graceful-degradation story.

**Files:** `web/src/components/help/ChapterPipeline.tsx`,
`web/src/components/help/diagrams/PipelineFlow.tsx`,
`web/src/components/help/Help.tsx`, `web/src/styles.css`

1. [ ] Build `PipelineFlow.tsx` — inline-SVG horizontal flow:
   **dump → analysis → enrichment (BloodHound + HIBP) → scoring → dashboard**, with the
   BloodHound branch annotated as optional and a "graceful degradation" note. House-style
   card wrapper + token colors.
2. [ ] Build `ChapterPipeline.tsx` with the **frontend-design skill**:
   - **BloodHound:** DA attack pathways, controlled-object blast radius (true
     sensitivity-weighted count), Tier-0/DA-equivalent control, Kerberoastable /
     AS-REP-roastable exposure.
   - **HIBP:** local NTLM breach corpus matched offline — **no hash leaves the box**.
   - **Graceful degradation:** without BloodHound, Exposure is still fully valid and
     Impact is honestly Unknown (coverage banner). Tie back to chapter 2's coverage.
3. [ ] Wire `pipeline` chapter in `Help.tsx`.
4. [ ] Add pipeline classes to `styles.css` (token-based).
5. [ ] **Frontend gates:** `npx tsc --noEmit` && `npx vitest run` && `npm run build` — green.

## Task 5 — Chapters 4 (security & privacy) + 5 (glossary & FAQ)

Goal: the CISO data-handling reassurance chapter and the plain-language glossary/FAQ,
reusing `glossary.ts`.

**Files:** `web/src/components/help/ChapterSecurity.tsx`,
`web/src/components/help/ChapterGlossary.tsx`, `web/src/components/help/Help.tsx`,
`web/src/styles.css`

1. [ ] Build `ChapterSecurity.tsx` with the **frontend-design skill**, covering: no
   cleartext on disk; encrypted-at-rest store + DEK re-keying; redacted-by-default APIs;
   lead-only, one-at-a-time, audit-logged reveal (audit never logs the password); RBAC;
   HttpOnly/SameSite=Strict cookies; strict CSP + security headers; TLS fail-closed in
   prod; single static CGO-free binary; supply-chain discipline (vetted, exact-pinned,
   stdlib-first). Present as scannable assurance cards/list.
2. [ ] Build `ChapterGlossary.tsx`: render plain-language terms — **reuse the `GLOSSARY`
   strings from `web/src/glossary.ts`** (import them; do not re-author) for NT hash/NTLM,
   HIBP, DA pathway, controlled objects (blast radius), Kerberoastable, AS-REP-roastable,
   Exposure, Impact, coverage, similarity clusters, password reuse — plus a short FAQ:
   "Do you store cracked passwords?", "What if we don't run BloodHound?", "How is a reveal
   controlled and logged?", "Where does the data live?". (Add any glossary term the
   chapter needs that isn't in `glossary.ts` as local static copy — but prefer reuse.)
3. [ ] Wire `security` and `glossary` chapters in `Help.tsx` (all 5 now live).
4. [ ] Add security-card / glossary / FAQ classes to `styles.css` (token-based).
5. [ ] **Frontend gates:** `npx tsc --noEmit` && `npx vitest run` && `npm run build` — green.

## Task 6 — Responsive polish, security review, final gates + Playwright sweep, finish

Goal: responsive/standalone polish, the static-surface security check, full gate run, and
the live Playwright verification across pre-auth + all chapters with a clean console.

**Files:** `web/src/styles.css`, `web/src/components/help/*` (polish only)

1. [ ] **Responsive pass** (frontend-design skill): the left-rail collapses gracefully on
   narrow viewports (stacked sub-nav); the standalone (pre-auth) shell and the embedded
   shell both look intentional; diagrams scale (SVG `viewBox`, no fixed-px overflow).
2. [ ] **Static-surface security review** (the spec's hard requirement): grep the `help/`
   tree to confirm NO `useAuth`, NO `api.`/`fetch(`, NO import of any data provider, and
   NO audit/config/operator literals. The ONLY permissible dynamic value is the public
   version/build (and the Help component does not even need that). Record the grep
   evidence in the finish notes.
   Commands (from `web/`):
   `npx rg -n "useAuth|from \"\\.\\./\\.\\./(api|auth|accountsData|auditsData|jobs|nav)\"|api\\.|fetch\\(" src/components/help` — expect no matches (other than type-only `GLOSSARY` import from `glossary.ts`, which is static).
3. [ ] **Full frontend gates:** `npx tsc --noEmit` && `npx vitest run` (incl. styleguard,
   chapters, hash) && `npm run build` — all green; `gofmt`/Go gates untouched (no Go
   changes).
4. [ ] **Embed rebuild** via the **build-and-run** skill (CGO-free, stamped ldflags),
   restart `patd.exe`, confirm version.
5. [ ] **Playwright sweep** (controller may batch the live run, as it did for scoring-v2
   sub-project C). Drive `http://127.0.0.1:8443`:
   - PRE-AUTH: from the login screen, "How it works" opens Help standalone; navigate ALL
     5 chapters; "← Back" returns to login. **Network panel: NO API calls** issued by the
     Help view (the security assertion). **Console: 0 errors / 0 warnings.**
   - LOCKED: confirm the "How it works" link is present on the unlock screen and opens
     Help.
   - POST-AUTH (lead unlock): header "Help" link opens embedded Help; all 5 chapters
     render; console clean.
   - Deep-link: navigate directly to `…/#help/how-we-score` and confirm the scoring
     chapter is active (or, if hash sync was dropped in T1 per the YAGNI fallback, skip
     and note it).
   - **Screenshots:** the scoring chapter (Exposure × Impact diagram) and the security
     chapter (per the spec's polish check).
6. [ ] **finishing-a-development-branch:** present merge/PR options; the finish notes
   include the security-review grep evidence + Playwright screenshots + 0-console-error
   confirmation.

---

## Self-Review — spec coverage map

| Spec requirement | Task(s) |
|---|---|
| Chapter 1 — Why this exists (thesis/hero) | T2 |
| Chapter 2 — Exposure × Impact scoring (matches shipped v2) + matrix diagram + worked example | T3 |
| Chapter 3 — Enrichment pipeline (BloodHound + HIBP) + pipeline diagram + graceful degradation | T4 |
| Chapter 4 — Security & privacy model | T5 |
| Chapter 5 — Glossary (reuse `glossary.ts`) & FAQ | T5 |
| Pre-auth access (login screen) | T1 (showHelp intercept + Login link), verified T6 |
| Locked-state access (unlock screen) | T1 (Unlock link), verified T6 |
| Post-auth access (nav entry) | T1 (View "help" + header link + viewFor), verified T6 |
| Pure static surface — no API/audit/config data | T1 (no providers) + T6 (grep review + Playwright network assertion) |
| Diagrams: Exposure×Impact heatmap, pipeline flow, reveal/audit flow (inline SVG/CSS, no deps) | T3 / T4 / T2 |
| Reuse house style (cards, tokens, MatrixHeatmap language) | T1–T5 (frontend-design skill, token classes) |
| Class-based styles only (styleguard) | every task's gate runs `vitest` incl. `styleguard.test.ts` |
| Deep-linking `#help/<slug>` | T1 (lightweight hash sync; YAGNI fallback documented), verified T6 |
| No new npm dependencies | all tasks (inline SVG/CSS; no installs) |
| Testing: tsc / vitest / build per task | gate step in T1–T6 |
| Live Playwright: reachable pre-auth + all chapters + 0 console errors + screenshots | T6 (smoke also in T1) |
| Security check (reviewer confirms no API data) | T6 step 2 |
| Pure logic gets real tests (registry, hash helper) | T1 (`chapters.test.ts`, `useChapterHash.test.ts`) |
