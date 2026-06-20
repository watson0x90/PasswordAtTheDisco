import { useCallback, useEffect, useState } from "react"
import { api, ApiError, type AuditEvent } from "../api"
import { useAuth } from "../auth"
import { fmtWhen, resultClass } from "../format"
import { useSortablePaged, type SortColumn } from "../sortPage"
import { SortHeader } from "./SortHeader"
import { Pager } from "./Pager"

const ACTIONS = [
  "login", "logout", "reveal_secret", "reveal_violation_terms", "password_probe", "store_unlock", "store_lock", "store_passphrase_change", "store_rekey",
  "audit_create", "audit_delete", "audit_upload", "apply_cracks", "export", "policy_update",
  "user_create", "user_update", "user_delete", "user_unlock",
  "pwned_build", "pwned_probe", "pwned_download", "pwned_index", "pwned_cancel",
]
const RESULTS = ["ok", "denied", "failed", "locked", "not_found", "rate_limited"]

export function Activity() {
  const { me } = useAuth()
  const [events, setEvents] = useState<AuditEvent[]>([])
  const [q, setQ] = useState("")
  const [action, setAction] = useState("")
  const [result, setResult] = useState("")
  const [from, setFrom] = useState("")
  const [to, setTo] = useState("")
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState("")

  const load = useCallback(async () => {
    try {
      setEvents(await api.auditLog({ q, action, result, from, to, limit: 200 }))
      setError("")
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "failed to load activity")
    } finally {
      setLoading(false)
    }
  }, [q, action, result, from, to])

  function downloadCsv() {
    const a = document.createElement("a")
    a.href = api.auditLogCsvUrl({ q, action, result, from, to })
    a.download = "audit-log.csv"
    document.body.appendChild(a)
    a.click()
    a.remove()
  }

  // debounced reload on any filter change (covers typing in the search box)
  useEffect(() => {
    const id = window.setTimeout(() => void load(), 250)
    return () => window.clearTimeout(id)
  }, [load])

  const COLS: SortColumn<AuditEvent>[] = [
    { key: "time", get: (e) => e.time, defaultDir: "desc" },
    { key: "actor", get: (e) => e.actor ?? "" },
    { key: "action", get: (e) => e.action },
    { key: "target", get: (e) => e.target ?? "" },
    { key: "source", get: (e) => e.source ?? "" },
    { key: "result", get: (e) => e.result },
  ]
  const page = useSortablePaged(events, COLS, { defaultSort: { key: "time", dir: "desc" }, pageSize: 50 })

  if (me?.role !== "lead") return <div className="center-state">The activity log requires the lead role.</div>

  return (
    <div className="ops-page">
      <div className="section-label">Activity — audit log</div>
      <div className="panel">
        <p className="ingest-note">
          Every operator action is recorded here — logins, cleartext reveals, operator &amp; policy changes, store
          rotations, HIBP jobs. The audit log <b>never contains cleartext passwords</b>. Showing the most recent 200
          matching events, newest first.
        </p>

        <div className="act-filters">
          <input
            className="search"
            placeholder="search actor / target / source…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
          <select className="search" value={action} onChange={(e) => setAction(e.target.value)}>
            <option value="">all actions</option>
            {ACTIONS.map((a) => (
              <option key={a} value={a}>{a}</option>
            ))}
          </select>
          <select className="search" value={result} onChange={(e) => setResult(e.target.value)}>
            <option value="">any result</option>
            {RESULTS.map((r) => (
              <option key={r} value={r}>{r}</option>
            ))}
          </select>
          <label className="act-date">from<input type="date" className="search" value={from} onChange={(e) => setFrom(e.target.value)} /></label>
          <label className="act-date">to<input type="date" className="search" value={to} onChange={(e) => setTo(e.target.value)} /></label>
          <button className="btn" onClick={() => void load()}>Refresh</button>
          <button className="btn" onClick={downloadCsv} title="Download all matching events as CSV">Download CSV</button>
          <span className="act-count">{events.length}</span>
        </div>

        {error && <div className="error">{error}</div>}

        {loading ? (
          <div className="center-state"><div className="spinner">loading</div></div>
        ) : events.length === 0 ? (
          <p className="ingest-note mb-0">No matching events.</p>
        ) : (
          <>
          <div className="table-wrap">
          <table className="ops-table act-table">
            <thead>
              <tr>
                <SortHeader label="When" colKey="time" sort={page.sort} onSort={page.setSort} />
                <SortHeader label="Operator" colKey="actor" sort={page.sort} onSort={page.setSort} />
                <SortHeader label="Action" colKey="action" sort={page.sort} onSort={page.setSort} />
                <SortHeader label="Target" colKey="target" sort={page.sort} onSort={page.setSort} />
                <SortHeader label="Source" colKey="source" sort={page.sort} onSort={page.setSort} />
                <SortHeader label="Result" colKey="result" sort={page.sort} onSort={page.setSort} />
              </tr>
            </thead>
            <tbody>
              {page.rows.map((e, i) => (
                <tr key={i}>
                  <td className="ops-when">{fmtWhen(e.time)}</td>
                  <td className="ops-user">
                    {e.actor || "—"}
                    {e.role && <span className="act-role">{e.role}</span>}
                  </td>
                  <td className="act-action">{e.action}</td>
                  <td className="act-target" title={e.target || ""}>{e.target || ""}</td>
                  <td className="ops-src">{e.source || ""}</td>
                  <td>
                    <span className={"act-result " + resultClass(e.result)}>{e.result}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          </div>
          <Pager page={page} />
          </>
        )}
      </div>
    </div>
  )
}
