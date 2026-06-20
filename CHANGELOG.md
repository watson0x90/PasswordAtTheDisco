# Changelog

All notable changes to **Password!AtTheDisco** are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed
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

[Unreleased]: https://github.com/watson0x90/PasswordAtTheDisco/compare/v2.15.0...HEAD
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
