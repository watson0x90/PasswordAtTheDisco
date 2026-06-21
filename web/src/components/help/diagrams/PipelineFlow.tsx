// PipelineFlow — a static inline-SVG horizontal flow diagram for the enrichment
// chapter. It traces how raw inputs become a scored dashboard:
//
//   dump → analysis → enrichment (BloodHound + HIBP) → scoring → dashboard
//
// The enrichment stage forks: HIBP is always available (the local NTLM corpus),
// while BloodHound is OPTIONAL — annotated as such, with a graceful-degradation
// note (without BloodHound, Exposure stays valid and Impact is honestly Unknown).
//
// Pure presentation: no data, no API, no providers. Reuses the dashboard house
// style (token colours + a ChartCard-like titled panel), and mirrors RevealFlow:
// a viewBox-scaled SVG (no fixed-px overflow), with the only inline styles being
// COMPUTED `var(--token)` colours (allowed by the styleguard — only literal
// spacing/px in .tsx is banned). Stage colour is reinforced with text, not
// colour alone (a11y).

interface Stage {
  // x is the centre of the node in viewBox units.
  x: number
  step: string
  title: string
  sub: string
  // token CSS var name for the node accent.
  tone: "low" | "med" | "high" | "crit" | "accent" | "dim"
}

const TONE_STROKE: Record<Stage["tone"], string> = {
  crit: "var(--crit)",
  high: "var(--high)",
  med: "var(--med)",
  low: "var(--low)",
  accent: "var(--accent)",
  dim: "var(--dim)",
}

// The main spine: dump → analysis → … → scoring → dashboard. The enrichment
// stage sits in the centre slot; its two sources (HIBP / BloodHound) branch off
// above/below it.
const SPINE: Stage[] = [
  { x: 95, step: "1", title: "Dump", sub: "NTLM hashes + cracked passwords from the AD secrets dump", tone: "dim" },
  { x: 290, step: "2", title: "Analysis", sub: "Strength, dictionary/keyboard patterns, hash reuse clusters", tone: "low" },
  { x: 500, step: "3", title: "Enrichment", sub: "Inputs joined with the two sources above", tone: "accent" },
  { x: 710, step: "4", title: "Scoring", sub: "Exposure × Impact → Level, provisional when uncovered", tone: "high" },
  { x: 905, step: "5", title: "Dashboard", sub: "Triage worklist, coverage banner, lead-gated reveal", tone: "med" },
]

// The two enrichment sources, branching off the centre (Enrichment) node.
const HIBP_X = 500
const HIBP_Y = 36
const BH_X = 500
const BH_Y = 300

const NODE_W = 168
const NODE_H = 116
const NODE_Y = 150
const SPINE_MID = NODE_Y + NODE_H / 2

export function PipelineFlow() {
  return (
    <div className="panel chart-card pipe-flow-card">
      <div className="chart-title">From dump to dashboard</div>
      <div
        role="img"
        aria-label="Enrichment pipeline: the AD dump is analysed for password weakness and reuse, then enriched by two sources — HIBP breach matching (always available) and BloodHound graph enrichment (optional). The combined signals are scored on the Exposure and Impact axes into a Level, then surfaced on the dashboard. Without BloodHound, Exposure stays fully valid and Impact is reported as Unknown rather than guessed."
        className="pipe-flow"
      >
        <svg viewBox="0 0 1000 470" preserveAspectRatio="xMidYMid meet" className="pipe-flow-svg">
          <defs>
            <marker id="pf-arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
              <path d="M0 0 L10 5 L0 10 z" fill="var(--accent)" />
            </marker>
            <marker
              id="pf-arrow-dim"
              viewBox="0 0 10 10"
              refX="8"
              refY="5"
              markerWidth="7"
              markerHeight="7"
              orient="auto-start-reverse"
            >
              <path d="M0 0 L10 5 L0 10 z" fill="var(--dim)" />
            </marker>
          </defs>

          {/* Spine connectors between consecutive stages. */}
          {SPINE.slice(0, -1).map((s, i) => {
            const from = s.x + NODE_W / 2
            const to = SPINE[i + 1].x - NODE_W / 2
            return (
              <line
                key={`spine${i}`}
                x1={from}
                y1={SPINE_MID}
                x2={to - 2}
                y2={SPINE_MID}
                className="pipe-flow-link"
                markerEnd="url(#pf-arrow)"
              />
            )
          })}

          {/* Source branches feeding the Enrichment node. */}
          <line
            x1={HIBP_X}
            y1={HIBP_Y + NODE_H / 2 + 6}
            x2={500}
            y2={NODE_Y - 2}
            className="pipe-flow-link"
            markerEnd="url(#pf-arrow)"
          />
          <line
            x1={BH_X}
            y1={BH_Y - 6}
            x2={500}
            y2={NODE_Y + NODE_H + 2}
            className="pipe-flow-branch-optional"
            markerEnd="url(#pf-arrow-dim)"
          />

          {/* HIBP source (always available). */}
          <g className="pipe-flow-source">
            <rect
              x={HIBP_X - NODE_W / 2}
              y={HIBP_Y - NODE_H / 2}
              width={NODE_W}
              height={NODE_H}
              rx={14}
              className="pipe-flow-box"
              style={{ stroke: TONE_STROKE.low }}
            />
            <text x={HIBP_X} y={HIBP_Y - 22} textAnchor="middle" className="pipe-flow-source-tag">
              SOURCE · ALWAYS
            </text>
            <text x={HIBP_X} y={HIBP_Y - 2} textAnchor="middle" className="pipe-flow-node-title">
              HIBP corpus
            </text>
            {wrap("Local NTLM breach index, matched offline — no hash leaves the box").map((line, li) => (
              <text key={li} x={HIBP_X} y={HIBP_Y + 16 + li * 13} textAnchor="middle" className="pipe-flow-node-sub">
                {line}
              </text>
            ))}
          </g>

          {/* BloodHound source (optional). */}
          <g className="pipe-flow-source">
            <rect
              x={BH_X - NODE_W / 2}
              y={BH_Y}
              width={NODE_W}
              height={NODE_H}
              rx={14}
              className="pipe-flow-box pipe-flow-box-optional"
              style={{ stroke: TONE_STROKE.dim }}
            />
            <text x={BH_X} y={BH_Y + 20} textAnchor="middle" className="pipe-flow-source-tag optional">
              SOURCE · OPTIONAL
            </text>
            <text x={BH_X} y={BH_Y + 40} textAnchor="middle" className="pipe-flow-node-title">
              BloodHound graph
            </text>
            {wrap("DA pathways, blast radius, Tier-0 control, roastability").map((line, li) => (
              <text key={li} x={BH_X} y={BH_Y + 58 + li * 13} textAnchor="middle" className="pipe-flow-node-sub">
                {line}
              </text>
            ))}
          </g>

          {/* Spine stage nodes. */}
          {SPINE.map((s) => {
            const left = s.x - NODE_W / 2
            return (
              <g key={s.title} className="pipe-flow-node">
                <rect
                  x={left}
                  y={NODE_Y}
                  width={NODE_W}
                  height={NODE_H}
                  rx={14}
                  className="pipe-flow-box"
                  style={{ stroke: TONE_STROKE[s.tone] }}
                />
                <circle cx={s.x} cy={NODE_Y + 24} r={12} className="pipe-flow-dot" style={{ fill: TONE_STROKE[s.tone] }} />
                <text x={s.x} y={NODE_Y + 29} textAnchor="middle" className="pipe-flow-step">
                  {s.step}
                </text>
                <text x={s.x} y={NODE_Y + 56} textAnchor="middle" className="pipe-flow-node-title">
                  {s.title}
                </text>
                {wrap(s.sub).map((line, li) => (
                  <text key={li} x={s.x} y={NODE_Y + 74 + li * 13} textAnchor="middle" className="pipe-flow-node-sub">
                    {line}
                  </text>
                ))}
              </g>
            )
          })}

          {/* Graceful-degradation note pinned under the optional branch. */}
          <text x={500} y={448} textAnchor="middle" className="pipe-flow-foot">
            Without BloodHound: Exposure is still valid — Impact is reported Unknown, never guessed.
          </text>
        </svg>
      </div>
    </div>
  )
}

// wrap splits a short caption into <=3 balanced lines for the fixed node width.
// Pure string layout (no DOM measurement) — deterministic and test-friendly.
function wrap(text: string): string[] {
  const words = text.split(" ")
  const lines: string[] = []
  let cur = ""
  const max = 24
  for (const w of words) {
    if ((cur + " " + w).trim().length > max && cur) {
      lines.push(cur)
      cur = w
    } else {
      cur = (cur + " " + w).trim()
    }
  }
  if (cur) lines.push(cur)
  return lines.slice(0, 3)
}
