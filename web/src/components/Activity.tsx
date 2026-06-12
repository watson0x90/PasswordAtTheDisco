import { useCallback, useEffect, useState } from "react"
import { api, ApiError, type AuditEvent } from "../api"
import { useAuth } from "../auth"

const ACTIONS = [
  "login", "logout", "reveal_secret", "store_unlock", "store_lock", "store_passphrase_change", "store_rekey",
  "audit_create", "audit_delete", "audit_upload", "export", "policy_update",
  "user_create", "user_update", "user_delete", "user_unlock",
  "pwned_build", "pwned_probe", "pwned_download", "pwned_index", "pwned_cancel",
]
const RESULTS = ["ok", "denied", "failed", "locked", "not_found", "rate_limited"]

function fmtTime(iso: string): string {
  const d = new Date(iso)
  return isNaN(d.getTime()) ? iso : d.toLocaleString()
}
function resultClass(r: string): string {
  if (r === "ok") return "ev-ok"
  if (r === "denied" || r === "failed") return "ev-bad"
  if (r === "locked" || r === "rate_limited") return "ev-warn"
  return "ev-dim"
}

export function Activity() {
  const { me } = useAuth()
  const [events, setEvents] = useState<AuditEvent[]>([])
  const [q, setQ] = useState("")
  const [action, setAction] = useState("")
  const [result, setResult] = useState("")
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState("")

  const load = useCallback(async () => {
    try {
      setEvents(await api.auditLog({ q, action, result, limit: 200 }))
      setError("")
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "failed to load activity")
    } finally {
      setLoading(false)
    }
  }, [q, action, result])

  // debounced reload on any filter change (covers typing in the search box)
  useEffect(() => {
    const id = window.setTimeout(() => void load(), 250)
    return () => window.clearTimeout(id)
  }, [load])

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
          <button className="btn" onClick={() => void load()}>Refresh</button>
          <span className="act-count">{events.length}</span>
        </div>

        {error && <div className="error">{error}</div>}

        {loading ? (
          <div className="center-state"><div className="spinner">loading</div></div>
        ) : events.length === 0 ? (
          <p className="ingest-note" style={{ marginBottom: 0 }}>No matching events.</p>
        ) : (
          <table className="ops-table act-table">
            <thead>
              <tr>
                <th>When</th>
                <th>Operator</th>
                <th>Action</th>
                <th>Target</th>
                <th>Source</th>
                <th>Result</th>
              </tr>
            </thead>
            <tbody>
              {events.map((e, i) => (
                <tr key={i}>
                  <td className="ops-when">{fmtTime(e.time)}</td>
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
        )}
      </div>
    </div>
  )
}
