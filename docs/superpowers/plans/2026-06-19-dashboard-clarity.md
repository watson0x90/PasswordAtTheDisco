# Dashboard Clarity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`).

**Goal:** Fix the comprehension gaps a first-time CISO + Blue-Team Manager found in the dashboards/reports — without changing the underlying math — so the tool reads clearly cold.

**Architecture:** Mostly labeling/tooltip/layout work in `web/src` + the Go HTML report (`internal/report/report.go`); one substantive feature (a ranked "Priority worklist" on the Actionable view). No backend math/persistence changes (trend is explicitly deferred). Decisions locked: (1) keep the 0–100 health score but make direction/target explicit and relabel sub-bars so a full bar always = healthy; (2) defer trend; (3) upgrade Actionable into a ranked worklist.

**Tech Stack:** React 18 + TS + Vite + recharts; Go `html/template`. No new deps.

**Branch:** `feature/dashboard-clarity` (off `main`, post-`v2.11.0`).

**Gates:** `gofmt -l cmd internal`, `go build/vet/test ./...`; in `web/` `npx tsc --noEmit`, `npx vitest run`, `npm run build` (never `npm install`); `govulncheck ./...`.

**Verify env:** the loaded `:8444` instance (operator `dev`/`devpass123456`, passphrase `devstorepass123`, audit "BHE Large Sample", ~2,002 accounts) is the Playwright re-verify target. Reload via `PATD_PW=devpass123456 bash tools/load_sample.sh sample_data/bhsample http://127.0.0.1:8444` if needed.

---

## Task 1: Posture score framing (Overview + HTML report)

**Files:** `web/src/components/Dashboard.tsx` (PostureGauge ~100, PostureBar 185-198, the 4 bars 107-110); `internal/report/report.go` (posture block 331-343).

Context: `model.PostureScore` returns a 0–100 **health** score (higher=better) = Risk(/40)+Strength(/30)+Privilege(/15)+Compliance(/15). Each sub-bar is a *health contribution* (full bar = healthy), but the label "Privilege exposure" implies the opposite. No math changes — labels + framing only.

- [ ] **Step 1 — Dashboard gauge framing.** In `Dashboard.tsx`, under the `<PostureGauge>` add a one-line caption making direction + target explicit, e.g. a `<div className="posture-cap">Security health · higher is better · target ≥ 75</div>`. Keep the existing rating ("Weak") + likelihood line. Add the CSS class `.posture-cap { font-size: 12px; color: var(--dim); margin-top: 6px; }` to `styles.css`.

- [ ] **Step 2 — Relabel the 4 sub-bars so a full bar = healthy.** Change the `<PostureBar>` labels (lines 107-110) to health-positive, unambiguous names + keep `value/max`:
  - `"Risk distribution"` → `"Risk profile"`
  - `"Password strength"` → `"Password strength"` (unchanged)
  - `"Privilege exposure"` → `"Privilege control"`
  - `"Policy compliance"` → `"Policy compliance"` (unchanged)
  Also add a small header above the bars clarifying "each bar: more filled = healthier (of N pts)". In `PostureBar` (185-198), append a token hint that the bar fills toward "good" (e.g. keep `.bg-low` green fill — green already reads as good).

- [ ] **Step 3 — Mirror in the HTML report.** In `internal/report/report.go` posture block (339-343), change `Risk distribution` → `Risk profile`, `Privilege exposure` → `Privilege control`; and change the `score`/`rating` area to add a caption line `<div class="meta">security health (higher is better · target ≥ 75)</div>` near the score. Keep the math/values.

- [ ] **Step 4 — Account risk-score direction cue.** The per-account `risk_score` (0–10, higher=worse) runs opposite the posture score. Add a one-time cue: in `AccountsTable.tsx` the Score column header gets an InfoTip (Task 2) "Risk 0–10 · higher = worse"; same on the Actionable tables' score columns + the HTML report's risk-score column header.

- [ ] **Step 5 — Verify + commit.** `(cd web && npx tsc --noEmit && npm run build)`; `go build ./... && go test ./internal/report/`. Commit:
```
git add web/src/components/Dashboard.tsx web/src/styles.css internal/report/report.go
git commit -m "fix(ui): frame posture score as health (direction + target) + health-positive sub-bar labels"
```

---

## Task 2: InfoTip component + shared glossary + apply tooltips

**Files:** create `web/src/components/InfoTip.tsx`, `web/src/glossary.ts`; modify `Dashboard.tsx`, `AccountsTable.tsx`, `Exposure.tsx`; `styles.css`.

- [ ] **Step 1 — InfoTip component.** Create `web/src/components/InfoTip.tsx`:
```tsx
// Small accessible info marker: a hoverable "ⓘ" that shows a definition.
// Uses native title for the tooltip (no deps, screen-reader friendly via aria-label).
export function InfoTip({ text }: { text: string }) {
  return (
    <span className="infotip" title={text} aria-label={text} role="img">ⓘ</span>
  )
}
```
Add CSS: `.infotip { margin-left: 4px; font-size: 11px; color: var(--faint); cursor: help; user-select: none; }`

- [ ] **Step 2 — Shared glossary.** Create `web/src/glossary.ts` with a term→definition map covering the jargon (sourced from the Reports `COLUMNS` + the persona list). Keys are short ids; values are plain-English (≤120 chars). Include at least:
```ts
export const GLOSSARY = {
  da_pathway: "Domain-Admin pathway: this account can reach Domain Admin via an AD attack path (BloodHound).",
  hibp: "Have I Been Pwned: the password's NT hash appears in public breach corpora. The number is how many times it's been seen.",
  hibp_count: "How many times this password has been seen in public breaches. Accounts sharing a password share this count (same hash).",
  shared_with: "How many other accounts use the exact same password (same NT hash).",
  escalated_shared_da: "This account shares its password with a Domain-Admin account — cracking it yields DA.",
  high_controlled: "Controls a large number of AD objects (BloodHound). >100 objects = high blast radius.",
  controlled_objects: "Number of AD objects this account can take over (BloodHound control edges).",
  tier1_hibp: "Tier 1 — cracked AND in public breaches: the exact password is public. Reset now.",
  tier2_hibp: "Tier 2 — the hash is in breach data but not cracked here. Rotate next cycle.",
  weak_categories: "Why a password is weak: Forbidden (banned term), Common (top breached), Dictionary (a dictionary word), Keyboard (a keyboard walk).",
  risk_score: "Per-account risk, 0–10 — higher is worse (opposite of the org health score).",
  bridge_matrix: "Each cell = number of shared-password groups that bridge the two domains. Darker = more bridges.",
} as const
```

- [ ] **Step 3 — Apply tooltips at the cited sites.** Add `<InfoTip text={GLOSSARY.X} />` next to:
  - `Dashboard.tsx`: "DA Pathways" (:80 → da_pathway), "HIBP Breached" (:79 → hibp), "Escalated (Shared-DA)" (:90 → escalated_shared_da), "High Privilege" (:91 → high_controlled).
  - `AccountsTable.tsx` column headers: "HIBP" (:106 → hibp_count), "Weak" (:108 → weak_categories), "SHARED" (→ shared_with), "DA PATHWAY" (:110 → da_pathway), "Score"/"Risk" (→ risk_score).
  - `Exposure.tsx`: the bridge-matrix heading (→ bridge_matrix), "HIBP urgency triage" Tier 1 (:189 → tier1_hibp) + Tier 2 (:199 → tier2_hibp).

- [ ] **Step 4 — Verify + commit.** `(cd web && npx tsc --noEmit && npm run build)`. Commit:
```
git add web/src/components/InfoTip.tsx web/src/glossary.ts web/src/components/Dashboard.tsx web/src/components/AccountsTable.tsx web/src/components/Exposure.tsx web/src/styles.css
git commit -m "feat(ui): InfoTip + shared glossary; define jargon inline on the dashboards"
```

---

## Task 3: Screen-purpose subtitles + de-duplicate the headline strip

**Files:** `Dashboard.tsx`, `Accounts.tsx`, `Actionable.tsx`, `Domains.tsx`, `Exposure.tsx`, `Reports.tsx`; `styles.css`.

- [ ] **Step 1 — One-line "this view answers" subtitle** under each view's `section-label`. Add a `<div className="view-sub">…</div>` with:
  - Overview (Dashboard.tsx:70): "Where do we stand? Org-wide posture at a glance."
  - Accounts (Accounts.tsx:46): "The full, searchable account worklist — filter and drill in."
  - Actionable (Actionable.tsx:70): "What do I fix first? Prioritized remediation."
  - Domains (Domains.tsx:76): "Which domain is worst? Per-domain health."
  - Exposure (Exposure.tsx — add a title before ExposureHeadline at :91): "How do attackers move between domains? Cross-domain credential reuse."
  - Reports (Reports.tsx:65): "Export for tickets and leadership."
  CSS: `.view-sub { font-size: 13px; color: var(--dim); margin: -8px 0 18px; }`

- [ ] **Step 2 — De-dup the headline strip.** The `<ExposureHeadline>` shows on BOTH Overview (Dashboard.tsx:83) and Exposure (Exposure.tsx:91). Keep it on **Overview**; **remove** it from `Exposure.tsx:91` (Exposure already has its own bridge matrix + triage + worklist). Confirm `accounts`/`report` props/imports left unused are cleaned (no TS6133).

- [ ] **Step 3 — Verify + commit.** `(cd web && npx tsc --noEmit && npm run build)`. Commit:
```
git add web/src/components/Dashboard.tsx web/src/components/Accounts.tsx web/src/components/Actionable.tsx web/src/components/Domains.tsx web/src/components/Exposure.tsx web/src/components/Reports.tsx web/src/styles.css
git commit -m "feat(ui): per-view purpose subtitles; drop duplicated headline strip from Exposure"
```

---

## Task 4: Exposure clarity (matrix legend + top-N bridges + HIBP-repeat note)

**Files:** `web/src/components/Exposure.tsx` (matrix 104-136, clusters 138-181, triage 289-317).

- [ ] **Step 1 — Matrix legend.** Add a caption directly under the bridge matrix: a `<div className="matrix-legend muted">Each cell = shared-password groups bridging the two domains · darker = more</div>` (the InfoTip from Task 2 can also sit on the heading).

- [ ] **Step 2 — Lead with top bridges + collapse the long list.** The cluster list (138-181) currently renders every cluster. Add a heading "Top credential bridges (N total)" and default-limit to the **top 10** (they're already sorted DA-first then blast-radius), with a "show all N" toggle button that reveals the rest. Keep the existing per-row expand-members behavior.

- [ ] **Step 3 — HIBP-repeat note.** Under the HIBP triage table (289-317), add a one-line muted note: "Accounts sharing a password share its breach count (same hash) — repetition is expected, not a duplicate." (Resolves the "looks like a bug" trust issue.)

- [ ] **Step 4 — Verify + commit.** `(cd web && npx tsc --noEmit && npm run build)`. Commit:
```
git add web/src/components/Exposure.tsx web/src/styles.css
git commit -m "fix(ui): Exposure — matrix legend, top-N bridges w/ show-all, HIBP-repeat note"
```

---

## Task 5: Surface Breach Impact + methodology note

**Files:** `web/src/components/Dashboard.tsx` (breach panel 118-143; posture panel ~95-116).

- [ ] **Step 1 — Move the Breach Impact panel up** so it sits **immediately after the posture panel** (before the stat charts), not below the fold. Cut the block at 118-143 and re-insert right after the posture-panel close.

- [ ] **Step 2 — Methodology InfoTip.** Add `<InfoTip>` on the "Breach Impact Estimate" heading: "Estimate from critical-risk + Domain-Admin-path counts; cost/recovery from IBM Cost of a Data Breach industry averages — directional, not a quote." (The existing "industry avg (IBM CODB)" sub-line stays.)

- [ ] **Step 3 — Verify + commit.** `(cd web && npx tsc --noEmit && npm run build)`. Commit:
```
git add web/src/components/Dashboard.tsx
git commit -m "feat(ui): surface Breach Impact above the fold + methodology note"
```

---

## Task 6: Actionable → ranked Priority Worklist (the big one)

**Files:** create `web/src/worklist.ts` (+ test `web/src/worklist.test.ts`); modify `web/src/components/Actionable.tsx`; `styles.css`.

Context: Actionable currently shows 12 category tables each sorted by `risk_score` (ties at 10.0, no reason/action). Add a single ranked worklist at the TOP that answers "fix these first, why, and how" — keep the category sections below as detail.

- [ ] **Step 1 — Worklist derivation + test.** Create `web/src/worklist.ts` deriving, from `Account[]` (the `/api/accounts` rows, which carry the needed fields), a ranked list with a composite priority (so ties break), a reason-badge list, and a recommended action:
```ts
import type { Account } from "./api"
import { hasDA } from "./util"
export interface WorklistItem { account: Account; priority: number; reasons: string[]; action: string }
export function priorityWorklist(accounts: Account[]): WorklistItem[] {
  const items: WorklistItem[] = []
  for (const a of accounts) {
    const reasons: string[] = []
    let p = 0
    const da = hasDA(a.da_domains)
    if (da) { p += 100; reasons.push("DA path") }
    if (a.cracked && a.hibp_breached) { p += 40; reasons.push(`HIBP ${a.hibp_breach_count.toLocaleString()}`) }
    else if (a.cracked) { p += 25; reasons.push("Cracked") }
    if (a.shared_with > 0) { p += Math.min(20, a.shared_with); reasons.push(`Shared ${a.shared_with}`) }
    if (a.escalated_by_shared_da) { p += 50; reasons.push("Shares DA hash") }
    // tie-break by raw risk_score (0-10) and shared_with
    p += a.risk_score + Math.min(a.shared_with, 5) / 10
    if (p === 0) continue
    // recommended action (most severe first)
    let action = "Review"
    if (da || a.escalated_by_shared_da) action = "Rotate now + review DA path"
    else if (a.cracked && a.hibp_breached) action = "Rotate now — password is public"
    else if (a.cracked) action = "Rotate password"
    else if (a.pwd_never_expires) action = "Enforce expiry"
    items.push({ account: a, priority: p, reasons, action })
  }
  return items.sort((x, y) => y.priority - x.priority)
}
```
Confirm the real field names on `Account` in `api.ts` (`cracked`, `hibp_breached`, `hibp_breach_count`, `shared_with`, `da_domains`, `escalated_by_shared_da`, `pwd_never_expires`, `risk_score`) and adjust. Add `worklist.test.ts` (vitest, pure) asserting: a DA+cracked+HIBP account outranks a merely-cracked one; reasons + action are correct; ties break by risk_score.

- [ ] **Step 2 — Render the Priority Worklist section** at the TOP of `Actionable.tsx` (after the title/subtitle, before the existing sections). A table: **Account | Domain | Risk (score + level) | Why (reason badges) | Recommended action**. Default-limit to the **top 50** with a "show all" toggle. The Risk column shows `risk_score.toFixed(1)` with the InfoTip "0–10 higher = worse". Reuse existing badge classes. Pull `accounts` from the accounts context/hook the view already uses (it has `report`; add the `accounts` fetch if not present — Exposure/Dashboard already fetch accounts, mirror that).

- [ ] **Step 3 — Verify + commit.** `(cd web && npx tsc --noEmit && npx vitest run worklist && npm run build)`. Commit:
```
git add web/src/worklist.ts web/src/worklist.test.ts web/src/components/Actionable.tsx web/src/styles.css
git commit -m "feat(ui): Actionable Priority Worklist — ranked, with reason badges + recommended action"
```

---

## Task 7: Gate, rebuild, live re-verify, docs

- [ ] **Step 1 — Full gate.** `gofmt -l cmd internal`; `go build/vet/test ./...`; `(cd web && npx tsc --noEmit && npx vitest run && npm run build)`; `govulncheck ./...`.
- [ ] **Step 2 — Rebuild** via `bash .claude/skills/build-and-run/scripts/build.sh`.
- [ ] **Step 3 — Live re-verify on :8444** (reload sample if needed; restart :8444 on the new binary OR rebuild affects :8443 too — verify on whichever has data). Playwright-check: posture caption + relabeled bars read clearly; tooltips appear on the jargon; each view has its subtitle; Exposure has the legend + top-N + no duplicate strip; Breach Impact is above the fold; **Actionable opens with the ranked Priority Worklist** (reasons + actions, not all-10.0). Also confirm the y-axis labels render cleanly live (the CISO's "X0/:0" was likely a screenshot artifact — fix only if real).
- [ ] **Step 4 — README** "What's new" bullet: clarity pass (score framing, glossary tooltips, view subtitles, Exposure legend, ranked Actionable worklist). Commit.
- [ ] **Step 5 — Final whole-branch review + finishing-a-development-branch.**

---

## Self-review
- Persona findings → tasks: posture score → T1; jargon tooltips → T2; START-HERE/overlap → T3; Exposure dump → T4; breach impact → T5; Actionable worklist → T6; HIBP-repeat trust → T2 glossary + T4 note; y-axis → T7 verify. Trend = deferred (per decision).
- No backend math/persistence change (trend deferred). New deps: none.
- Confirm-by-reading: exact `Account` field names (T6); the PostureBar fill color reads as good/green (T1); the accounts fetch pattern in Actionable (T6).
