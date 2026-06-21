// RevealFlow — a small, static inline-SVG data-flow diagram for the thesis
// chapter. It traces the ONE controlled path a cracked password can take:
//
//   in memory  →  lead requests reveal  →  audit log (no password)  →  shown once
//
// Pure presentation: no data, no API, no providers. Reuses the dashboard house
// style (token colours, a ChartCard-like titled panel). The SVG uses a viewBox
// so it scales with no fixed-px overflow; the small amount of inline style is a
// COMPUTED gradient stop (allowed by the styleguard — only literal spacing/px in
// .tsx is banned).

import { wrap } from "./wrap"

// Node captions wrap to this width (chars). Authored to fit in <=3 lines at
// REVEAL_WRAP; wrap() never drops words, so no line cap / .slice is needed.
const REVEAL_WRAP = 22

interface Stage {
  // x is the centre of the node in viewBox units.
  x: number
  title: string
  sub: string
  // token CSS var name for the node accent.
  tone: "low" | "med" | "high" | "crit" | "dim"
}

const TONE_STROKE: Record<Stage["tone"], string> = {
  crit: "var(--crit)",
  high: "var(--high)",
  med: "var(--med)",
  low: "var(--low)",
  dim: "var(--dim)",
}

// Four stages laid out left→right across a 720×220 canvas.
const STAGES: Stage[] = [
  { x: 90, title: "In memory", sub: "Cracked password — process RAM only, never written to disk", tone: "high" },
  { x: 270, title: "Lead requests reveal", sub: "Role-gated: lead operators only, one account at a time", tone: "low" },
  { x: 450, title: "Audit log entry", sub: "Who · what account · when — the password is NEVER logged", tone: "med" },
  { x: 630, title: "Shown once", sub: "Cleartext rendered to the operator, then auto-hidden", tone: "low" },
]

const NODE_W = 150
const NODE_H = 110
const NODE_Y = 56

export function RevealFlow() {
  return (
    <div className="panel chart-card reveal-flow-card">
      <div className="chart-title">How a reveal is controlled</div>
      <div
        role="img"
        aria-label="Reveal data flow: a cracked password stays in memory; a lead operator requests a reveal one account at a time; an audit entry is written without the password; the cleartext is shown once and then auto-hidden."
        className="reveal-flow"
      >
        <svg viewBox="0 0 720 220" preserveAspectRatio="xMidYMid meet" className="reveal-flow-svg">
          <defs>
            <marker id="rf-arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
              <path d="M0 0 L10 5 L0 10 z" fill="var(--accent)" />
            </marker>
          </defs>

          {/* Connectors between consecutive stages. */}
          {STAGES.slice(0, -1).map((s, i) => {
            const from = s.x + NODE_W / 2
            const to = STAGES[i + 1].x - NODE_W / 2
            const midY = NODE_Y + NODE_H / 2
            return (
              <line
                key={`c${i}`}
                x1={from}
                y1={midY}
                x2={to - 2}
                y2={midY}
                className="reveal-flow-link"
                markerEnd="url(#rf-arrow)"
              />
            )
          })}

          {/* Stage nodes. */}
          {STAGES.map((s, i) => {
            const left = s.x - NODE_W / 2
            return (
              <g key={s.title} className="reveal-flow-node">
                <rect
                  x={left}
                  y={NODE_Y}
                  width={NODE_W}
                  height={NODE_H}
                  rx={14}
                  className="reveal-flow-box"
                  style={{ stroke: TONE_STROKE[s.tone] }}
                />
                <circle cx={s.x} cy={NODE_Y + 22} r={11} className="reveal-flow-dot" style={{ fill: TONE_STROKE[s.tone] }} />
                <text x={s.x} y={NODE_Y + 27} textAnchor="middle" className="reveal-flow-step">
                  {i + 1}
                </text>
                <text x={s.x} y={NODE_Y + 52} textAnchor="middle" className="reveal-flow-node-title">
                  {s.title}
                </text>
                {wrap(s.sub, REVEAL_WRAP).map((line, li) => (
                  <text key={li} x={s.x} y={NODE_Y + 70 + li * 13} textAnchor="middle" className="reveal-flow-node-sub">
                    {line}
                  </text>
                ))}
              </g>
            )
          })}

          {/* The guarantee restated under the flow. */}
          <text x={360} y={200} textAnchor="middle" className="reveal-flow-foot">
            Cleartext never touches disk — and never appears in the audit log.
          </text>
        </svg>
      </div>
    </div>
  )
}
