import { useEffect, useState } from "react"
import { api, ApiError, type Account, type DiffAccount, type DiffResult } from "../api"
import { useAudits } from "../auditsData"
import { RISK_CLASS } from "../util"
import { useSortablePaged, type SortColumn } from "../sortPage"
import { AccountLink } from "./AccountLink"
import { Pager } from "./Pager"

const COHORT_PAGE_COLS: SortColumn<DiffAccount>[] = [{ key: "n", get: () => 0 }]

export function Compare() {
  const { audits } = useAudits()
  const [a, setA] = useState("")
  const [b, setB] = useState("")
  const [res, setRes] = useState<DiffResult | null>(null)
  const [err, setErr] = useState("")
  const [busy, setBusy] = useState(false)
  const [acctIndex, setAcctIndex] = useState<Account[]>([])

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

  useEffect(() => {
    if (!a || !b || a === b) {
      setAcctIndex([])
      return
    }
    let active = true
    Promise.all([api.auditAccounts(b), api.auditAccounts(a)])
      .then(([curr, base]) => {
        if (!active) return
        const byKey = new Map<string, Account>()
        // insert baseline first, then current overwrites so current (b) wins
        for (const acc of base) byKey.set(`${acc.username}\t${acc.domain}`, acc)
        for (const acc of curr) byKey.set(`${acc.username}\t${acc.domain}`, acc)
        setAcctIndex([...byKey.values()])
      })
      .catch(() => active && setAcctIndex([])) // links gracefully fall back to plain text
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
      {res && a !== b && <DiffView res={res} accounts={acctIndex} />}
    </>
  )
}

function DiffView({ res, accounts }: { res: DiffResult; accounts: Account[] }) {
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
        <CohortCard title="Newly cracked" tone="crit" items={d.newly_cracked} accounts={accounts} />
        <CohortCard title="Remediated" tone="low" items={d.remediated} accounts={accounts} />
        <CohortCard title="Risk regressed" tone="high" items={d.regressed} accounts={accounts} />
        <CohortCard title="Newly breached" tone="crit" items={d.newly_breached} accounts={accounts} />
      </div>
      <div className="meta-line">{d.still_cracked.toLocaleString()} account(s) still cracked in both.</div>
    </>
  )
}

function CohortCard({
  title,
  tone,
  items: raw,
  accounts,
}: {
  title: string
  tone: string
  items: DiffAccount[] | null
  accounts: Account[]
}) {
  const items = raw ?? []
  const page = useSortablePaged(items, COHORT_PAGE_COLS, { defaultSort: { key: "n", dir: "asc" }, pageSize: 50 })
  return (
    <div className="panel chart-card">
      <div className="chart-title">
        {title} <span className={`c-${tone}`}>{items.length}</span>
      </div>
      {items.length === 0 ? (
        <div className="chart-empty">none</div>
      ) : (
        <div className="cohort-list">
          {page.rows.map((x, i) => (
            <div className="cohort-row" key={i}>
              <AccountLink username={x.username} domain={x.domain} accounts={accounts} />
              <span className="cohort-meta">
                {x.risk_a && x.risk_b && x.risk_a !== x.risk_b ? (
                  <span className="risk-transition">
                    <span className={`badge ${RISK_CLASS[x.risk_a] || ""}`}>{x.risk_a}</span>
                    <span className="arrow">→</span>
                    <span className={`badge ${RISK_CLASS[x.risk_b] || ""}`}>{x.risk_b}</span>
                  </span>
                ) : (
                  <span className="muted">{x.domain}</span>
                )}
              </span>
            </div>
          ))}
          <Pager page={page} />
        </div>
      )}
    </div>
  )
}
