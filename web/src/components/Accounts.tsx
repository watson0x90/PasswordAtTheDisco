import { useMemo, useState } from "react"
import { useAccountsData } from "../accountsData"
import { RISK_CLASS } from "../util"
import { AccountsTable } from "./AccountsTable"

const FILTERS = ["All", "Critical", "High", "Medium", "Low"] as const

export function Accounts() {
  const { accounts, error: loadError } = useAccountsData()
  const [query, setQuery] = useState("")
  const [risk, setRisk] = useState<string>("All")

  const filtered = useMemo(() => {
    if (!accounts) return []
    const needle = query.trim().toLowerCase()
    return accounts.filter((a) => {
      if (risk !== "All" && a.risk_level !== risk) return false
      if (needle && !`${a.username} ${a.domain}`.toLowerCase().includes(needle)) return false
      return true
    })
  }, [accounts, query, risk])

  if (loadError && !accounts) return <div className="center-state">{loadError}</div>
  if (!accounts) return <div className="center-state"><div className="spinner">loading</div></div>

  return (
    <>
      <div className="section-label">Accounts</div>
      <div className="toolbar">
        <input className="search" placeholder="search username or domain…" value={query}
               spellCheck={false} onChange={(e) => setQuery(e.target.value)} />
        <div className="filter-pills">
          {FILTERS.map((f) => {
            const active = f === risk
            const cls = active ? `pill active ${f !== "All" ? RISK_CLASS[f] : ""}` : "pill"
            return <button key={f} className={cls} onClick={() => setRisk(f)}>{f}</button>
          })}
        </div>
        <div className="toolbar-count">{filtered.length.toLocaleString()} / {accounts.length.toLocaleString()}</div>
      </div>
      <AccountsTable accounts={filtered} />
    </>
  )
}
