# Changelog

All notable changes to **Password!AtTheDisco** are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

_Nothing yet._

## [2.20.0] — 2026-06-21 — Colourised Exposure × Impact matrix + audit hardening

### Added
- **Colourised risk matrix** — the Overview's Exposure × Impact cells are now tinted by
  the risk **level** they resolve to (Critical → red, High → amber, Medium → green,
  Low → cyan), with a legend; account count still drives the tint intensity. A single
  shared `cellLevel()` feeds both the live grid and the in-app Help methodology diagram,
  so the two can't drift from the scoring engine.

### Fixed
Post-v2.19 subsystem audit:
- Kerberoastable / AS-REP-roastable signals are captured on **every** BloodHound response
  format (previously only the BHE CE "literals" path; tabular/node formats dropped them).
- Domain-Admin pathway tables now show each account's controlled-object count
  (`ReportAccount` carried none, so the column always rendered "—").
- Uncracked accounts now carry their score breakdown, so they appear in the
  risk-factor-by-tier dashboard rather than being silently excluded.
- A Domain-Admin account no longer self-flags as "escalated by shared-DA" (a false
  positive that inflated the lateral-movement report).
- The risk-factor breakdown uses the shared `impactIsKnown` predicate, so it can't
  diverge from the matrix and accounts table.
- A transient BloodHound outage now surfaces an error instead of being mistaken for
  "account not found", which had silently dropped Impact to Unknown.
- Matrix cell tint was an invalid non-final CSS background layer (so cells rendered
  un-coloured); it is now painted as a valid gradient layer over the glass.

## [2.19.1] — 2026-06-21 — Dead-session 401 console noise

### Fixed
- The console now returns to the login screen on any **401** (mirroring the existing
  423 → lock handling), so a dead server-side session — wiped by a restart or expired by
  the idle / absolute timeout — stops the lead-only job pollers from 401-ing every 5 s.
  While authenticated: zero console errors; on session death: a single bounce to login.

## [2.19.0] — 2026-06-21 — In-app Help / Methodology section

### Added
- **Help / Methodology** — a pre-auth, presentation-style section (reachable from the
  login and unlock screens, deep-linkable via `#help/<slug>`) with five chapters: the
  security thesis, the two-axis Exposure × Impact scoring model, the enrichment pipeline,
  the security / privacy model, and a glossary / FAQ. Inline-SVG diagrams, **pure static —
  no API calls.** Written to explain the model to CISOs and blue-team leads.

## [2.18.0] — 2026-06-21 — Two-axis (Exposure × Impact) risk scoring

### Changed
- **Risk scoring rebuilt around two axes.** **Exposure** (crackability / HIBP / reuse /
  roastable — always computed from the dump) × **Impact** (blast radius — BloodHound-derived,
  and explicitly **Unknown** when an account isn't enriched). The overall level comes from a
  2-D Exposure × Impact matrix, not a single blended number. **Scores change for every
  account — this is intentional.**

### Added
- True BloodHound **controlled-objects count** (uses the API's real total — removes the old
  10-object cap), **Tier-0 / DA-equivalent** control detection, roastable signals on the live
  enrichment path, and per-account **coverage**.
- **Within-audit percentile** triage, **shared-hash → DA** Impact inheritance, and HIBP
  de-duplication.
- Honest dashboard: per-axis sub-score bars (replacing the old radar), the Exposure × Impact
  matrix with an explicit **Unknown** column, a coverage banner, **provisional** badges, a
  needs-enrichment worklist, and two-axis KPIs.

### Removed
- The v1 single-axis CVSS-style scoring path.

## [2.17.0] — 2026-06-20 — Lead-gated reveal in the similarity breakdown

### Added
- Reveal the cleartext of a selected account and its similar peers from the **Password
  Similarity Clusters** breakdown, through the existing lead-only, audit-logged reveal — now
  domain-aware so the exact account is revealed.

### Fixed
- Similar-peer duplication (accounts sharing a password) and a doubled-domain audit target
  for `username@domain` accounts.

## [2.16.0] — 2026-06-20 — Similarity clusters: expand + explain

### Added
- The **Password Similarity Clusters** graph is now expandable into a large modal and
  explainable: clicking a node names its most-similar accounts and similarity scores, backed
  by new server-computed similar-peer references (redacted — username / domain / score, never
  the password).

### Changed
- Graph edges are now real pairwise links from those peers (replacing the prior heuristic
  domain-chain edges).
- **Search** page split into **Accounts** and **Password in use?** sub-tabs.

## [2.15.0] — 2026-06-19 — Global search + password-in-use probe

### Added
- **⌘/Ctrl-K command palette** — from any view, search accounts (opens the shared
  detail drawer) or jump to another view. Account search runs over the already-loaded
  redacted set; no extra round-trips.
- **Search** tab — account search backed by the sortable/paginated accounts table.
- **Password-in-use probe** (`POST /api/probe`) — check whether any account uses a
  specific password, **including uncracked ones**, by matching its NT hash server-side.
  Returns only redacted accounts; available to any operator, CSRF-gated, request body
  size-capped. Every check is audit-logged (`password_probe`) with the operator, time,
  and match count — the candidate is **never stored, logged, or echoed**.

### Fixed
- Revealing a cleartext password no longer forces a horizontal scrollbar on the
  accounts table (the secret cell wraps instead of widening the table).
- Main content width is now responsive (`clamp(1320px, 92vw, 1440px)`) so wide screens
  give tables — and a revealed password — room to stay on one line.

## [2.14.0] — 2026-06-19 — Sortable + paginated tables

### Added
- Column **sorting** (type-aware, severity-ranked risk, stable) and page-based
  **pagination** across Accounts, Activity, Domains detail, Operators, Actionable, and
  Compare cohorts, via a shared hook plus `SortHeader` / `Pager` controls.

### Changed
- The Accounts table's virtualized scroll was replaced by real pagination; the
  Actionable and Domains "top-N" display caps were replaced by paging (no more silently
  truncated lists).

## [2.13.0] — 2026-06-19 — App-wide clickable usernames

### Added
- Every audited-account username across the app (Accounts, Exposure, Actionable,
  Insights, Domains, Compare) is a clickable link that opens the shared account-detail
  drawer.
- `GET /api/audits/{id}/accounts` — redacted per-audit accounts, for opening the drawer
  from the Compare view's two compared audits.

## [2.12.1] — 2026-06-19

### Added
- Exposure cross-domain bridge members render as a clickable table that opens the shared
  account drawer (the drawer was extracted into a shared component for reuse).

## [2.12.0] — 2026-06-18 — Dashboard clarity

### Changed
- A dashboard-clarity pass: health-framed posture score ("higher is better, target ≥ 75"),
  inline ⓘ glossary tooltips, per-view purpose subtitles, a ranked **Priority Worklist** in
  Actionable, and severity-tiered cross-domain bridge cards.

## [2.11.0] — 2026-06-18 — BloodHound graph + exposure analytics

### Added
- BloodHound users import + bulk Cypher enrichment (DA reachability and controlled-object
  counts in one pass).
- Exposure analytics — cross-domain credential reuse, HIBP-vs-risk triage, blast-radius
  buckets, DA exposure by domain, password-age distribution, and a risk-factors radar —
  plus an interactive network graph; rebuilt **Insights** and **Domains** views.
- Editable forbidden-words list (lead-only, logged by count only).

### Fixed
- A fresh load no longer logs a console 401 (`/api/me` returns 200 with an `authenticated`
  flag); report and console polish; Playwright dev dependencies dropped.

## [2.10.0] — 2026-06-17

### Fixed
- UI review fixes: responsive ☰ header, quiet `/api/me`, readable complexity-chart labels;
  added `tools/dev_seed.sh` for a one-command, synthetic-data-loaded instance.

## [2.9.0] — 2026-06-17

### Added
- Editable forbidden-words list (lead-gated, audit-count-only); a CSS token system and a
  styleguard test.

### Fixed
- Graceful no-audit empty states (no console 409s) and overflow fixes.

## [2.8.0] — 2026-06-17 — Exposure dashboards

### Added
- Cross-domain bridges, HIBP triage, and a blast-radius worklist; an audit-data UX overhaul.

## [2.6.0] — 2026-06-16

### Added
- Upload UX improvements, decoupled BloodHound enrichment, domain drill-down, and
  background-job visibility.

## [2.4.1] — 2026-06-16

### Added
- Manage Audits view with secure delete.

## [2.4.0] — 2026-06-16

### Changed
- Console navigation consolidation and report parity.

## [2.3.0] — 2026-06-15

### Added
- Wordlist-violation reporting.

## [2.2.0] — 2026-06-15 — Reporting

### Added
- Redacted report exports as CSV and HTML.

## [2.1.0] — 2026-06-12 — Admin & oversight

### Added
- Runtime operator management with hot-reload, per-account login lockout + history, a
  searchable/CSV-exportable Activity view over the audit log, and an in-app HIBP downloader.

## [2.0.0] — 2026-06-10 — Secure Go + React rewrite

The ground-up Go API + React console that replaced the original Python tool.

### Added
- argon2id auth, revocable sessions, RBAC, append-only audit log, redacted-by-default
  endpoints, and ingest.
- The analysis engine: secretsdump parsing, HIBP NTLM lookup, password analysis, BloodHound
  Enterprise enrichment, and CVSS-style risk scoring.
- Encrypted-at-rest store with DEK re-keying, embedded single-page app, TLS fail-closed, and
  guided deploy scripts.

### Security
- Cleartext never written to disk; cleartext reveal is a lead-only, audit-logged action that
  never records the password value.

[Unreleased]: https://github.com/watson0x90/PasswordAtTheDisco/compare/v2.20.0...HEAD
[2.20.0]: https://github.com/watson0x90/PasswordAtTheDisco/compare/v2.19.1...v2.20.0
[2.19.1]: https://github.com/watson0x90/PasswordAtTheDisco/compare/v2.19.0...v2.19.1
[2.19.0]: https://github.com/watson0x90/PasswordAtTheDisco/compare/v2.18.0...v2.19.0
[2.18.0]: https://github.com/watson0x90/PasswordAtTheDisco/compare/v2.17.0...v2.18.0
[2.17.0]: https://github.com/watson0x90/PasswordAtTheDisco/compare/v2.16.0...v2.17.0
[2.16.0]: https://github.com/watson0x90/PasswordAtTheDisco/compare/v2.15.0...v2.16.0
[2.15.0]: https://github.com/watson0x90/PasswordAtTheDisco/compare/v2.14.0...v2.15.0
[2.14.0]: https://github.com/watson0x90/PasswordAtTheDisco/compare/v2.13.0...v2.14.0
[2.13.0]: https://github.com/watson0x90/PasswordAtTheDisco/compare/v2.12.1...v2.13.0
[2.12.1]: https://github.com/watson0x90/PasswordAtTheDisco/compare/v2.12.0...v2.12.1
[2.12.0]: https://github.com/watson0x90/PasswordAtTheDisco/compare/v2.11.0...v2.12.0
[2.11.0]: https://github.com/watson0x90/PasswordAtTheDisco/compare/v2.10.0...v2.11.0
[2.10.0]: https://github.com/watson0x90/PasswordAtTheDisco/compare/v2.9.0...v2.10.0
[2.9.0]: https://github.com/watson0x90/PasswordAtTheDisco/compare/v2.8.0...v2.9.0
[2.8.0]: https://github.com/watson0x90/PasswordAtTheDisco/compare/v2.6.0...v2.8.0
[2.6.0]: https://github.com/watson0x90/PasswordAtTheDisco/compare/v2.4.1...v2.6.0
[2.4.1]: https://github.com/watson0x90/PasswordAtTheDisco/compare/v2.4.0...v2.4.1
[2.4.0]: https://github.com/watson0x90/PasswordAtTheDisco/compare/v2.3.0...v2.4.0
[2.3.0]: https://github.com/watson0x90/PasswordAtTheDisco/compare/v2.2.0...v2.3.0
[2.2.0]: https://github.com/watson0x90/PasswordAtTheDisco/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/watson0x90/PasswordAtTheDisco/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/watson0x90/PasswordAtTheDisco/releases/tag/v2.0.0
