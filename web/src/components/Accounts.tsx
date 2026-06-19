import { useMemo, useState } from "react"
import { useAccountsData } from "../accountsData"
import { RISK_CLASS } from "../util"
import { AccountsTable } from "./AccountsTable"

const FILTERS = ["All", "Critical", "High", "Medium", "Low"] as const
const SIGNAL_FILTERS = [
  { key: "all", label: "All" },
  { key: "never_expires", label: "Never Expires" },
  { key: "stale", label: "Stale Password" },
  { key: "shared_da", label: "Escalated (Shared-DA)" },
  { key: "high_priv", label: "High Privilege" },
  { key: "disabled", label: "Disabled" },
  { key: "policy_fail", label: "Policy Violation" },
] as const

type SignalKey = (typeof SIGNAL_FILTERS)[number]["key"]

export function Accounts() {
  const { accounts, error: loadError } = useAccountsData()
  const [query, setQuery] = useState("")
  const [risk, setRisk] = useState<string>("All")
  const [signal, setSignal] = useState<SignalKey>("all")

  const filtered = useMemo(() => {
    if (!accounts) return []
    const needle = query.trim().toLowerCase()
    return accounts.filter((a) => {
      if (risk !== "All" && a.risk_level !== risk) return false
      if (needle && !`${a.username} ${a.domain}`.toLowerCase().includes(needle)) return false
      if (signal === "never_expires" && a.pwd_never_expires !== true) return false
      if (signal === "stale" && !(a.days_out_of_compliance && a.days_out_of_compliance > 0)) return false
      if (signal === "shared_da" && !a.escalated_by_shared_da) return false
      if (signal === "high_priv" && a.controlled_object_count <= 100) return false
      if (signal === "disabled" && a.enabled) return false
      if (signal === "policy_fail" && !(a.cracked && !a.meets_policy)) return false
      return true
    })
  }, [accounts, query, risk, signal])

  if (loadError && !accounts) return <div className="center-state">{loadError}</div>
  if (!accounts) return <div className="center-state"><div className="spinner">loading</div></div>

  return (
    <>
      <div className="section-label">Accounts</div>
      <div className="view-sub">The full, searchable account worklist — filter and drill in.</div>
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
      <div className="toolbar signal-toolbar">
        {SIGNAL_FILTERS.map((sf) => (
          <button key={sf.key} className={signal === sf.key ? "pill active" : "pill"} onClick={() => setSignal(sf.key)}>{sf.label}</button>
        ))}
      </div>
      <AccountsTable accounts={filtered} />
    </>
  )
}
