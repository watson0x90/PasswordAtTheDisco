import type { CSSProperties } from "react"
import { cellLevel } from "../../../matrixView"

// ExposureImpactGrid — a STATIC, illustrative Exposure × Impact matrix diagram
// for the scoring chapter. It mirrors the dashboard's live MatrixHeatmap visual
// language (CSS grid, same row/column/cell classes) but carries NO live data:
// every cell shows the resulting LEVEL, hard-coded to match the shipped scoring
// engine exactly.
//
// SOURCE OF TRUTH — internal/risk/risk.go `levelMatrix[impactTier][exposureTier]`
// (rows = Impact, cols = Exposure Critical→High→Medium→Low):
//
//   Impact ↓ \ Exposure →   Critical   High     Medium   Low
//   Critical                Critical   Critical Critical High
//   High                    Critical   High     High     Medium
//   Medium                  High       High     Medium   Medium
//   Low                     Medium     Medium   Low      Low
//
// The Unknown column is risk.go's `impactKnown == false` branch: the level is
// taken from the Exposure tier ALONE (Critical→Critical, High→High, Medium→Medium,
// Low→Low) and rendered as a provisional cell — a distinct, neutral/dashed
// treatment that never reads as "low/safe". Tier cutoffs on BOTH axes are
// ≥8 Critical, ≥6 High, ≥4 Medium, else Low (matrix.ts `axisTier`).
//
// PURE STATIC: no auth, no api, no data providers. The only inline style is a
// computed `var(--level-color)` token (color, not literal spacing) — allowed by
// the styleguard.

type Level = "Critical" | "High" | "Medium" | "Low"

const LEVEL_TOKEN: Record<Level, string> = {
  Critical: "var(--crit)",
  High: "var(--high)",
  Medium: "var(--med)",
  Low: "var(--low)",
}

// Rows are Exposure tiers (top→down Critical→Low) so each ROW reads "for this
// exposure, here's the level as blast radius grows left→right". Columns are the
// four Impact tiers PLUS the explicit Unknown column.
const EXPOSURE_ROWS: Level[] = ["Critical", "High", "Medium", "Low"]
const IMPACT_COLS: (Level | "Unknown")[] = ["Critical", "High", "Medium", "Low", "Unknown"]

// The cell Level for an (exposure, impact) pair comes from the shared cellLevel()
// in matrix.ts (the single transcription of risk.go's levelMatrix) so this static
// diagram can't drift from the live dashboard. The Unknown column = Exposure tier
// alone (provisional), handled inside cellLevel.

export function ExposureImpactGrid() {
  return (
    <div className="panel chart-card score-grid-card">
      <div className="chart-title">Level = Exposure × Impact</div>
      <p className="score-grid-caption">
        The overall <strong>Level</strong> is the cell where an account&rsquo;s Exposure tier (how easily the credential is
        compromised) meets its Impact tier (blast radius if it is) — not the larger of the two, and not two separate badges.
        Cutoffs on both axes: <span className="score-cut">≥8 Critical</span>, <span className="score-cut">≥6 High</span>,{" "}
        <span className="score-cut">≥4 Medium</span>, <span className="score-cut">&lt;4 Low</span>. This grid is illustrative.
      </p>

      <div className="score-grid" role="table" aria-label="Resulting Level for each Exposure tier by Impact tier">
        <div className="score-grid-head" role="rowgroup">
          <div className="matrix-row matrix-row-head" role="row">
            <div className="score-grid-corner" role="presentation">
              <span className="score-grid-corner-imp">Impact →</span>
              <span className="score-grid-corner-exp">Exposure ↓</span>
            </div>
            {IMPACT_COLS.map((c) => (
              <div
                key={c}
                role="columnheader"
                className={`matrix-col-head${c === "Unknown" ? " matrix-col-unknown" : ""}`}
              >
                {c}
              </div>
            ))}
          </div>
        </div>

        <div className="score-grid-body" role="rowgroup">
          {EXPOSURE_ROWS.map((exp) => (
            <div key={exp} className="matrix-row" role="row">
              <div className="matrix-row-head-cell" role="rowheader">
                {exp}
              </div>
              {IMPACT_COLS.map((imp) => {
                const level = cellLevel(exp, imp)
                const unknown = imp === "Unknown"
                return (
                  <div
                    key={imp}
                    role="cell"
                    className={`score-grid-cell${unknown ? " score-grid-cell-unknown matrix-col-unknown" : ""}`}
                    style={{ "--level-color": LEVEL_TOKEN[level] } as CSSProperties}
                    title={`Exposure ${exp} × Impact ${unknown ? "Unknown (no BloodHound coverage)" : imp} → ${level}${
                      unknown ? " (provisional)" : ""
                    }`}
                  >
                    <span className="score-grid-level">{level}</span>
                    {unknown && <span className="score-grid-prov">provisional</span>}
                  </div>
                )
              })}
            </div>
          ))}
        </div>
      </div>

      <div className="score-grid-notes">
        <p className="score-grid-note">
          <span className="score-grid-note-k unknown">Unknown column</span> — no BloodHound coverage, so blast radius is
          unknown (<em>not</em> low). The Level is computed from Exposure alone and flagged <strong>provisional</strong>;
          the account is routed to the &ldquo;needs enrichment&rdquo; worklist.
        </p>
        <p className="score-grid-note">
          <span className="score-grid-note-k override">Hard override</span> — a cracked account with a confirmed
          Domain-Admin path (or DA-equivalent control) is <strong>Critical</strong> regardless of the cell above.
        </p>
      </div>
    </div>
  )
}
