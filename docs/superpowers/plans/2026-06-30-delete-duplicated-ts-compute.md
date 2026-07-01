# Delete Duplicated TS Compute — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development.

**Goal:** Eliminate client↔server metric drift by making the Go `internal/metrics` bundle the single source for ALL dashboard surfaces (org AND per-domain), then deleting the duplicated TypeScript compute.

**Architecture:** Extend the Go bundle's per-domain `DomainMetrics` with report-derived data, migrate the per-domain SPA surfaces to render it, remove every account-compute fallback from the dual-path components (bundle-only, loading-gated), relocate the still-needed non-duplicated helpers/types out of the compute files, then delete the pure-duplication files + their tests.

**Tech Stack:** Go stdlib; React/TS SPA (Vite, vitest).

## Global Constraints (binding)
- NEVER `npm install`/`npm ci`. Frontend build/tests only via existing tooling: `cd web && npm run build`, `cd web && npx vitest run` (vitest binary already in node_modules).
- The Go bundle stays redaction-safe (`metrics.TestBundleHasNoSensitiveFields` must stay green). Per-domain report additions must not emit cleartext/NThash/wordlist.
- Parity, not behavior change: migrated surfaces must render the SAME values users see today. Pin with golden tests (Go) + the existing TS contract test (`metricsBundle.test.ts`).
- The raw `/api/accounts` fetch (`accountsData.tsx`) STAYS — needed for row-drawer full-account lookups. `api.report()` may be dropped from a surface ONLY once that surface reads the bundle instead; `Actionable.tsx` uses `/api/report` directly (NOT via TS compute) and is OUT OF SCOPE — leave it.
- Stage explicit paths. Commit trailer EXACTLY: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.

## Files that are NOT pure duplication (relocate, do NOT delete)
- `matrix.ts`: per-account predicates `impactIsKnown`, `isProvisional`, `coverageState` (used by `AccountsTable.tsx`, `accountFacts.tsx`, `Actionable.tsx`, `worklist.ts`, `coverage.ts`, `insights.ts`) and matrix RENDER helpers + types `cellLevel`, `matrixMaxCount`, `TIERS`, `IMPACT_COLS`, `IMPACT_UNKNOWN`, `Tier`, `ImpactCol`, `ExposureImpactMatrix` (used by `Charts.tsx` MatrixHeatmap over the BUNDLE matrix). These must survive.
- `insights.ts`: shared chart TYPES imported by `Charts.tsx` (`AxisFactor`, `Bar`, `Series`, `Slice`, `TierFactorBars`) and any pure label helper (`complexityLabel`). These must survive (prefer pointing `Charts.tsx` at `metricsBundle.ts` types if equivalent).
- Pure-duplication files to DELETE outright once unused: `exposure.ts`, `domainScope.ts`, `domainData.ts`, and the aggregate-compute functions of `insights.ts`/`matrix.ts`.

---

## Phase 1 (Go): per-domain report-derived in the bundle
**Files:** `internal/metrics/domain.go`, `internal/metrics/reportseries.go` (or a new `domainreports.go`), `internal/metrics/*_test.go`, golden `internal/metrics/testdata/metrics_golden.json`; TS mirror `web/src/metricsBundle.ts`.

- Add a `DomainReports` struct to `DomainMetrics` (`json:"reports"`) carrying exactly what the per-domain UI needs: `ExposureHeadline`, `SimilarityGraph` (over the domain's accounts), `ReuseClusters` (org reuse groups TOUCHING the domain — cracked+uncracked, mirroring client `domainReuseClusters`), and `DAPaths` (org DA-pathway accounts in the domain, mirroring `domainDAPaths`). Do NOT blindly reuse the org `buildReportSeries` over one domain's accounts — reuse clusters/DA paths must be the ORG report FILTERED to the domain (a cross-domain reuse group must still appear in each member domain's view). Read the client functions `web/src/exposure.ts exposureHeadline`, `web/src/domainData.ts domainReuseClusters/domainDAPaths`, `web/src/domainScope.ts domainReport`, and `web/src/insights.ts similarityNetwork` and port their exact semantics.
- `ComputeByDomain` builds the org `rep := model.BuildReport(accounts)` ONCE, then per domain derives the domain-scoped `DomainReports`.
- Update the golden JSON + a Go test asserting per-domain reports match the client semantics on a fixture. Mirror the struct in `metricsBundle.ts` (`DomainMetrics.reports`) and update `metricsBundle.test.ts` if it pins the golden.
- Gate: `gofmt`, `go vet`, `go test ./...`; `cd web && npx vitest run` (contract test). Commit.

## Phase 2 (SPA): migrate per-domain surfaces to `bundle.domains[d].reports`
**Files:** `web/src/components/Domains.tsx` (`DomainDetail`), `ExposureHeadline.tsx`, `SimilarityClusters.tsx`.
- `DomainDetail` passes `dm.reports.exposureHeadline`, `dm.reports.similarityGraph`, and renders reuse-cluster + DA-path tables from `dm.reports.reuseClusters`/`dm.reports.daPaths` instead of `domainReuseClusters`/`domainDAPaths`/`domainReport`/`domainSummary`.
- Pass the per-domain `exposureHeadline`/`similarityGraph`/`reuseGraph` props into the per-domain `OverviewView`/`Insights`/`ExposureHeadline`/`SimilarityClusters` (currently omitted, forcing fallback).
- Drop the per-domain `api.report()`/`api.summary()` usages that these replace (verify nothing else on the page needs them; keep `/api/accounts` for drawers).
- Gate: `npm run build`, `npx vitest run`. Commit.

## Phase 3 (SPA): remove account-compute fallbacks (bundle-only, loading-gated)
**Files:** `Dashboard.tsx` (`OverviewView`), `Insights.tsx`, `ExposureHeadline.tsx`, `SimilarityClusters.tsx`.
- Make each dual-path component render ONLY from bundle props; when the bundle isn't ready, show the existing loading state (mirror `Exposure.tsx`'s `bundleLoading` gate) instead of computing from accounts.
- Remove the now-dead optional-prop fallback branches and their imports from `insights.ts`/`matrix.ts`/`exposure.ts`.
- Gate: `npm run build`, `npx vitest run`. Commit.

## Phase 4 (SPA): relocate survivors, delete duplication + tests
**Files:** new `web/src/accountFlags.ts` (or similar) + `web/src/matrixView.ts`; edits to importers; deletions.
- Relocate the survivors listed above out of `matrix.ts`/`insights.ts` into kept modules; update every importer (`AccountsTable.tsx`, `accountFacts.tsx`, `Actionable.tsx`, `worklist.ts`, `coverage.ts`, `Charts.tsx`). Prefer pointing type-only imports at `metricsBundle.ts` where an equivalent exists.
- Delete `exposure.ts`, `domainScope.ts`, `domainData.ts`, and (once emptied of survivors) `insights.ts`, `matrix.ts`.
- Delete the corresponding test files: `insights.test.ts`, `insights.golden.test.ts`, `exposure.test.ts`, `matrix.test.ts`, `domainScope.test.ts`, `domainData.test.ts`. If a relocated survivor had meaningful test coverage, move those specific cases into a test for the new module rather than dropping them.
- Gate: `npm run build` (tsc proves no dangling imports), `npx vitest run` (green), plus `grep` proving no remaining imports of the deleted files. Commit.

## Verification (controller, after all phases)
Rebuild embed binary + `dev_seed` :8444. Compare org + per-domain dashboard values (Overview KPIs/matrix, Insights charts, ExposureHeadline, SimilarityClusters, per-domain reuse/DA tables) against `/api/metrics` and `/api/metrics?domain=D` JSON — must match exactly. Console clean. Tear down :8444.
