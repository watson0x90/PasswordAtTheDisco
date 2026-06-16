import { useAudits } from "../auditsData"
import { useAuth } from "../auth"
import { fmtWhen } from "../format"

// ManageAudits is the lead-only Admin → Manage Audits page: a table of every saved
// audit with open + delete. Deleting permanently removes the audit's encrypted data.
export function ManageAudits() {
  const { me } = useAuth()
  const { audits, activeId, open, remove } = useAudits()

  if (me?.role !== "lead") {
    return <div className="center-state">Managing audits requires the lead role.</div>
  }

  function del(id: string, name: string) {
    if (confirm(`Delete audit "${name}"? This permanently removes its encrypted data and cannot be undone.`)) {
      void remove(id)
    }
  }

  return (
    <>
      <div className="section-label">Manage audits</div>
      <div className="panel">
        <p className="ingest-note">
          Open or delete saved audits. Each audit is an independent, encrypted dataset; <b>deleting one permanently
          removes its data</b> and cannot be undone. (Create new audits from the switcher, top right.)
        </p>
        <div className="table-wrap">
          <table className="accounts">
            <thead>
              <tr>
                <th>Name</th>
                <th className="num">Accounts</th>
                <th className="num">Cracked</th>
                <th>Created</th>
                <th>Updated</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {audits.length === 0 && (
                <tr>
                  <td colSpan={6} className="muted">
                    No audits yet — create one from the switcher (top right) and upload a domain.
                  </td>
                </tr>
              )}
              {audits.map((a) => (
                <tr key={a.id}>
                  <td>
                    {a.name}
                    {a.id === activeId && <span className="badge low" style={{ marginLeft: 8 }}>active</span>}
                  </td>
                  <td className="num">{a.total_accounts.toLocaleString()}</td>
                  <td className="num">{a.cracked.toLocaleString()}</td>
                  <td className="muted">{fmtWhen(a.created_at)}</td>
                  <td className="muted">{fmtWhen(a.updated_at)}</td>
                  <td className="audit-actions">
                    {a.id !== activeId && (
                      <button className="link-btn" onClick={() => void open(a.id)}>
                        open
                      </button>
                    )}
                    <button className="link-btn danger" onClick={() => del(a.id, a.name)}>
                      delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  )
}
