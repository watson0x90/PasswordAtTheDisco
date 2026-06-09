import { useEffect, useState } from "react"
import { api, ApiError, type DiffAccount, type DiffResult } from "../api"
import { useAudits } from "../auditsData"

export function Compare() {
  const { audits } = useAudits()
  const [a, setA] = useState("")
  const [b, setB] = useState("")
  const [res, setRes] = useState<DiffResult | null>(null)
  const [err, setErr] = useState("")
  const [busy, setBusy] = useState(false)

  // Default: baseline = second-newest, current = newest.
  useEffect(() => {
    if (audits.length >= 2 && !a && !b) {
      setB(audits[0].id)
      setA(audits[1].id)
    }
  }, [audits, a, b])

  useEffect(() => {
    if (!a || !b || a === b) {
      setRes(null)
      return
    }
    let active = true
    setBusy(true)
    setErr("")
    api
      .diff(a, b)
      .then((r) => active && setRes(r))
      .catch((e) => active && setErr(e instanceof ApiError ? e.message : "compare failed"))
      .finally(() => active && setBusy(false))
    return () => {
      active = false
    }
  }, [a, b])

  if (audits.length < 2) {
    return <div className="center-state">Create at least two audits to compare them over time.</div>
  }

  return (
    <>
      <div className="section-label">Compare audits</div>
      <div className="panel compare-pick">
        <label>
          Baseline
          <select className="search" value={a} onChange={(e) => setA(e.target.value)}>
            {audits.map((x) => (
              <option key={x.id} value={x.id}>
                {x.name}
              </option>
            ))}
          </select>
        </label>
        <span className="compare-arrow">→</span>
        <label>
          Current
          <select className="search" value={b} onChange={(e) => setB(e.target.value)}>
            {audits.map((x) => (
              <option key={x.id} value={x.id}>
                {x.name}
              </option>
            ))}
          </select>
        </label>
      </div>

      {a === b && <div className="chart-empty">Pick two different audits to compare.</div>}
      {err && <div className="error">{err}</div>}
      {busy && <div className="center-state"><div className="spinner">comparing</div></div>}
      {res && a !== b && <DiffView res={res} />}
    </>
  )
}

function DiffView({ res }: { res: DiffResult }) {
  const d = res.diff
  const delta = Math.round((d.posture_b - d.posture_a) * 10) / 10
  return (
    <>
      <div className="panel compare-posture">
        <div className="cp-side">
          <div className="cp-name">{res.a.name}</div>
          <div className="cp-score">{d.posture_a}</div>
        </div>
        <div className="cp-arrow">→</div>
        <div className="cp-side">
          <div className="cp-name">{res.b.name}</div>
          <div className="cp-score">{d.posture_b}</div>
        </div>
        <div className={`cp-delta ${delta >= 0 ? "c-low" : "c-crit"}`}>
          {delta >= 0 ? "+" : ""}
          {delta} posture
        </div>
      </div>

      <div className="chart-grid">
        <CohortCard title="Newly cracked" tone="crit" items={d.newly_cracked} />
        <CohortCard title="Remediated" tone="low" items={d.remediated} />
        <CohortCard title="Risk regressed" tone="high" items={d.regressed} />
        <CohortCard title="Newly breached" tone="crit" items={d.newly_breached} />
      </div>
      <div className="meta-line">{d.still_cracked.toLocaleString()} account(s) still cracked in both.</div>
    </>
  )
}

function CohortCard({ title, tone, items: raw }: { title: string; tone: string; items: DiffAccount[] | null }) {
  const items = raw ?? []
  return (
    <div className="panel chart-card">
      <div className="chart-title">
        {title} <span className={`c-${tone}`}>{items.length}</span>
      </div>
      {items.length === 0 ? (
        <div className="chart-empty">none</div>
      ) : (
        <div className="cohort-list">
          {items.slice(0, 50).map((x, i) => (
            <div className="cohort-row" key={i}>
              <span>{x.username}</span>
              <span className="muted">{x.domain}</span>
            </div>
          ))}
          {items.length > 50 && <div className="meta-line">+{(items.length - 50).toLocaleString()} more</div>}
        </div>
      )}
    </div>
  )
}
