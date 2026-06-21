# In-App Help / Methodology Section — Design

**Date:** 2026-06-20
**Topic:** A polished, presentation-style **Help / Methodology** section inside the SPA that explains *how the tool works* — the security thesis, the risk-scoring model, the enrichment pipeline, the security/privacy model, and a glossary — written to impress CISOs and Blue Team managers during demos and procurement evaluations. Static content only: no audit data, no secrets.

## Decision (keystone choices, approved via brainstorming)

1. **Scoring chapter describes the v2 two-axis (Exposure × Impact) model**, and the Help section **ships after scoring-v2 sub-projects B (engine) and C (dashboard)** so the docs and the live app agree. Roadmap: merge A → build B → build C → ship Help. (Designing the Help now; implementing last.)
2. **In-app presentation pages** (not an exported deck) — a navigable Help section inside the SPA, styled to impress rather than a dry docs dump.
3. **Public / pre-auth access** — reachable from the login screen and while the store is locked (it needs no audit data), so a prospective CISO can browse the methodology before any credentials exist.

## Placement & access

- A **Help** entry in the top nav (visible when authenticated) **and** a **"How it works"** link on the **login screen** and the **locked state**.
- The Help view is a **pure static React surface** — no API calls, no audit data, no config. It renders entirely from the SPA bundle, so it is safe to serve before authentication and while locked.
- A left-rail (or tab) **sub-navigation** switches between chapters; deep-linkable via a hash/route (e.g. `#/help/scoring`) so a specific chapter can be linked in an email.
- **No new dependencies** — diagrams are inline **SVG / CSS** reusing the existing card/chart styling (supply-chain hard rule). Class-based styles only (passes the `styleguard.test.ts` no-inline-spacing check).

## Information architecture — five chapters

### 1. Why this exists — the thesis
The headline for security leaders: the legacy Python tool emitted a self-contained HTML report that wrote **cleartext cracked passwords to disk**; this tool **never** does. Cleartext exists only in process memory and is revealed **one account at a time** to authorized **lead** operators, and **every reveal is audit-logged** (the log never contains the password). Frame the "secure by construction" posture up front.

### 2. How we score risk — the centerpiece
The **two-axis Exposure × Impact** model (per `docs/superpowers/specs/2026-06-20-scoring-engine-v2-design.md`):
- **Exposure (0–10):** how easily the credential is compromised — crackability, HIBP breach prevalence, password reuse, roastability. Computed from the dump (+ HIBP) so it is **always trustworthy**.
- **Impact (0–10 or Unknown):** blast radius if compromised — privilege / controlled-object count, Domain-Admin reachability, Tier-0 / DA-equivalent control, account Enabled state. **BloodHound-derived**; shown as **Unknown** (never "low") when an account was not enriched.
- **Overall level** from the **Exposure × Impact matrix**; **percentile triage** within an audit so even a large block of "Critical" yields a strict worklist order.
- **Coverage / confidence:** explains how the model **degrades gracefully** when BloodHound data is present for some, all, or none of an audit — per-account `Unknown` Impact + an audit coverage banner.
- **Diagram:** an Exposure×Impact heatmap (the 2D level matrix) + one worked example walking a single account from inputs → Exposure, Impact, level.

### 3. The enrichment pipeline
How external intelligence feeds the model and what each source adds:
- **BloodHound:** Domain-Admin attack pathways, controlled-object blast radius (the true count, sensitivity-weighted), Tier-0 / DA-equivalent control, Kerberoastable / AS-REP-roastable exposure.
- **HIBP:** the local NTLM breach corpus — how a hash is matched to public-breach prevalence (offline, no hash leaves the box).
- **Graceful degradation:** with no BloodHound, Exposure is still fully valid and Impact is honestly marked Unknown (the coverage banner). A simple pipeline diagram (dump → analysis → enrichment → scoring → dashboard).

### 4. Security & privacy model
Reassurance for a CISO on data handling:
- No cleartext on disk; **encrypted-at-rest** store with **DEK re-keying**; redacted-by-default APIs; **lead-only, one-at-a-time, audit-logged** reveal (audit never logs the password); **RBAC**; HttpOnly / SameSite=Strict session cookies; strict **CSP** + security headers; **TLS fail-closed** in production; a single **static CGO-free binary**; **supply-chain discipline** (vetted, exact-pinned dependencies; stdlib-first).

### 5. Glossary & FAQ
Plain-language definitions: NT hash / NTLM, HIBP, BloodHound DA pathway, controlled objects (blast radius), Kerberoastable, AS-REP-roastable, Exposure, Impact, coverage, similarity clusters, password reuse. Plus a short FAQ: "Do you store cracked passwords?", "What if we don't run BloodHound?", "How is a password reveal controlled and logged?", "Where does the data live?".

## Visual / presentation treatment

- A **hero** at the top of the Help view stating the thesis (chapter 1's headline) with confident typography.
- Each chapter is a **narrative section** with a clear heading, short executive lede, then the detail — scannable, not a wall of text.
- **Diagrams** (inline SVG/CSS): the Exposure×Impact matrix heatmap, the enrichment pipeline flow, and a small reveal/audit data-flow. Reuse the existing chart palette and card components for visual consistency with the dashboard.
- Tone: executive-credible — confident, precise, no marketing fluff; it should read as the work of a serious security team.

## Components & files

- `web/src/components/Help.tsx` — the Help view shell (sub-nav + chapter routing). Per-chapter content in a small, focused structure (one component or section per chapter; keep files focused).
- A **nav entry** wired into the existing app navigation, plus a **"How it works" link** on the login and locked screens.
- Inline-SVG/CSS diagram components reusing existing styling tokens. Class-based styles only.
- Implementation uses the **`frontend-design`** skill for the UI/UX and **Playwright** for live verification, per project convention.

## Routing & access control

- The Help route renders **before** the auth gate (and while locked), exactly like the login screen — it must not be wrapped by the authenticated/unlocked guards.
- **Security check:** the Help surface must contain **only static methodology copy** — no audit data, no config values, no operator list, nothing beyond what the public login/footer already exposes (product name + version/build, which the footer already shows). A reviewer confirms the Help bundle pulls no API data and embeds no secrets.

## Sequencing

Implement **after** scoring-v2 B (engine) and C (dashboard) land, so the scoring chapter's two-axis description matches the live app. The chapter content is authored against the scoring-v2 design spec; a final pass during the Help implementation reconciles any wording with what B/C actually shipped.

## Testing

- **Web:** `npx tsc --noEmit`, `npx vitest run` (light — the surface is presentational; include `styleguard`), `npm run build`.
- **Live Playwright:** Help is reachable **pre-auth from the login screen** and from the nav when authenticated; all five chapters render; deep-link to a chapter works; **browser console has 0 errors/0 warnings**; screenshot the scoring + security chapters for the polish check.
- **Security:** confirm (network panel) the Help view issues **no API calls** and exposes no audit/config data pre-auth.

## Out of scope (YAGNI)

- A printable / PDF executive brief (a reasonable fast-follow, not now).
- Search-within-help, i18n, light/dark theming work beyond the existing theme.
- Any per-audit or live data in the Help section.
