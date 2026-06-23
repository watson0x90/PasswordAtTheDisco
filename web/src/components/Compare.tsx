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
  // posture_a / posture_b are Credential Hygiene (enabled-only average, 0–100).
  // Reachability delta requires backend fields not yet in the diff payload; show "—" when absent.
  const hygieneA = Math.round(d.posture_a * 10) / 10
  const hygieneB = Math.round(d.posture_b * 10) / 10
  const hygieneDelta = Math.round((hygieneB - hygieneA) * 10) / 10
  const reachA: string = (d as unknown as Record<string, unknown>).reachability_a as string | undefined ?? "—"
  const reachB: string = (d as unknown as Record<string, unknown>).reachability_b as string | undefined ?? "—"
  const reachChanged = reachA !== "—" && reachB !== "—" && reachA !== reachB

  return (
    <>
      {/* Two-axis delta — primary headline */}
      <div className="panel cp-twoaxis">
        <div className="cp-twoaxis-head">
          <span className="cp-twoaxis-title">Two-axis change</span>
          <span className="cp-twoaxis-sub">{res.a.name} → {res.b.name}</span>
        </div>
        <div className="cp-twoaxis-row">
          {/* Hygiene axis */}
          <div className="cp-axis-block">
            <div className="cp-axis-label">Credential Hygiene</div>
            <div className="cp-axis-values">
              <span className="cp-axis-score muted">{hygieneA}</span>
              <span className="cp-axis-arrow">→</span>
              <span className="cp-axis-score">{hygieneB}</span>
            </div>
            <div className={`cp-axis-delta ${hygieneDelta >= 0 ? "c-low" : "c-crit"}`}>
              {hygieneDelta >= 0 ? "+" : ""}{hygieneDelta} pts
            </div>
          </div>

          <div className="cp-axis-divider" aria-hidden="true" />

          {/* Reachability axis */}
          <div className="cp-axis-block">
            <div className="cp-axis-label">Breach Reachability</div>
            <div className="cp-axis-values">
              <span className="cp-axis-score muted">{reachA}</span>
              {reachA !== "—" && reachB !== "—" && <span className="cp-axis-arrow">→</span>}
              {reachA !== "—" && reachB !== "—" && <span className="cp-axis-score">{reachB}</span>}
            </div>
            {reachChanged ? (
              <div className="cp-axis-delta c-high">changed — re-check structural exposure</div>
            ) : reachA !== "—" ? (
              <div className="cp-axis-delta muted">unchanged</div>
            ) : (
              <div className="cp-axis-delta muted">— available after backend diff extension</div>
            )}
          </div>
        </div>

        {/* Overall as labeled secondary, not headline */}
        <div className="cp-overall-secondary">
          Overall (Hygiene × (1−L) trend): {hygieneA} → {hygieneB}
          {" "}<span className="muted">— use Hygiene and Reachability separately as primary signals</span>
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
