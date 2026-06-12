import { useCallback, useEffect, useState } from "react"
import { api, ApiError, type Operator, type Role, type LoginAttempt } from "../api"
import { useAuth } from "../auth"
import { fmtWhen } from "../format"

export function Operators() {
  const { me } = useAuth()
  const csrf = me?.csrf_token ?? ""
  const [ops, setOps] = useState<Operator[]>([])
  const [activity, setActivity] = useState<LoginAttempt[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState("")
  const [ok, setOk] = useState("")

  // add form
  const [addUser, setAddUser] = useState("")
  const [addPass, setAddPass] = useState("")
  const [addRole, setAddRole] = useState<Role>("analyst")
  const [adding, setAdding] = useState(false)

  // inline password reset
  const [resetting, setResetting] = useState<string | null>(null)
  const [resetPass, setResetPass] = useState("")

  const load = useCallback(async () => {
    try {
      const [users, acts] = await Promise.all([api.listUsers(), api.loginActivity().catch(() => [])])
      setOps(users)
      setActivity(acts)
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "failed to load operators")
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  function flash(msg: string) {
    setOk(msg)
    setError("")
    window.setTimeout(() => setOk(""), 3500)
  }
  function fail(e: unknown, fallback: string) {
    setError(e instanceof ApiError ? e.message : fallback)
  }

  async function addOperator() {
    if (!addUser.trim() || !addPass) return
    setAdding(true)
    setError("")
    try {
      await api.createUser(addUser.trim(), addPass, addRole, csrf)
      setAddUser("")
      setAddPass("")
      setAddRole("analyst")
      flash(`Added operator "${addUser.trim()}".`)
      await load()
    } catch (e) {
      fail(e, "failed to add operator")
    } finally {
      setAdding(false)
    }
  }

  async function changeRole(u: Operator, role: Role) {
    setError("")
    try {
      await api.updateUser(u.username, { role }, csrf)
      flash(`${u.username} is now ${role}.`)
      await load()
    } catch (e) {
      fail(e, "failed to change role")
      await load() // resync the select
    }
  }

  async function toggleDisabled(u: Operator) {
    setError("")
    try {
      await api.updateUser(u.username, { disabled: !u.disabled }, csrf)
      flash(`${u.username} ${u.disabled ? "enabled" : "disabled"}.`)
      await load()
    } catch (e) {
      fail(e, "failed to update operator")
    }
  }

  async function saveReset(u: Operator) {
    if (!resetPass) return
    setError("")
    try {
      await api.updateUser(u.username, { password: resetPass }, csrf)
      setResetting(null)
      setResetPass("")
      flash(`Password reset for ${u.username}.`)
    } catch (e) {
      fail(e, "failed to reset password")
    }
  }

  async function unlock(u: Operator) {
    setError("")
    try {
      await api.unlockUser(u.username, csrf)
      flash(`Unlocked ${u.username}.`)
      await load()
    } catch (e) {
      fail(e, "failed to unlock")
    }
  }

  async function remove(u: Operator) {
    if (!confirm(`Remove operator "${u.username}"? This cannot be undone.`)) return
    setError("")
    try {
      await api.deleteUser(u.username, csrf)
      flash(`Removed ${u.username}.`)
      await load()
    } catch (e) {
      fail(e, "failed to remove operator")
    }
  }

  if (me?.role !== "lead") return <div className="center-state">Operator management requires the lead role.</div>
  if (loading)
    return (
      <div className="center-state">
        <div className="spinner">loading</div>
      </div>
    )

  return (
    <div className="ops-page">
      <div className="section-label">Operators</div>
      <div className="panel">
        <p className="ingest-note">
          Add, disable, or remove operators — changes take effect immediately, no restart needed. A <b>lead</b> may
          reveal cleartext and manage operators; an <b>analyst</b> sees redacted data only. At least one enabled lead
          must always remain.
        </p>

        <table className="ops-table">
          <thead>
            <tr>
              <th>Operator</th>
              <th>Role</th>
              <th>Last login</th>
              <th>Status</th>
              <th className="ops-actions-col">Actions</th>
            </tr>
          </thead>
          <tbody>
            {ops.map((u) => (
              <tr key={u.username} className={u.disabled ? "ops-row disabled" : "ops-row"}>
                <td className="ops-user">
                  {u.username}
                  {u.is_self && <span className="ops-self">you</span>}
                </td>
                <td>
                  <select
                    className="search ops-role"
                    value={u.role}
                    onChange={(e) => void changeRole(u, e.target.value as Role)}
                  >
                    <option value="analyst">analyst</option>
                    <option value="lead">lead</option>
                  </select>
                </td>
                <td className="ops-when" title={u.last_login_ip ? `from ${u.last_login_ip}` : ""}>
                  {fmtWhen(u.last_login)}
                </td>
                <td>
                  {u.locked ? (
                    <span className="ops-badge locked">locked</span>
                  ) : (
                    <span className={u.disabled ? "ops-badge off" : "ops-badge on"}>{u.disabled ? "disabled" : "enabled"}</span>
                  )}
                  {u.failed_attempts > 0 && !u.locked && <span className="ops-fails">{u.failed_attempts} failed</span>}
                </td>
                <td className="ops-actions">
                  {resetting === u.username ? (
                    <span className="ops-reset">
                      <input
                        autoFocus
                        type="password"
                        className="search"
                        placeholder="new password"
                        value={resetPass}
                        onChange={(e) => setResetPass(e.target.value)}
                        onKeyDown={(e) => e.key === "Enter" && void saveReset(u)}
                      />
                      <button className="btn btn-primary" onClick={() => void saveReset(u)}>Save</button>
                      <button className="link-btn" onClick={() => { setResetting(null); setResetPass("") }}>cancel</button>
                    </span>
                  ) : (
                    <>
                      {u.locked && (
                        <button className="link-btn" onClick={() => void unlock(u)}>
                          Unlock
                        </button>
                      )}
                      <button className="link-btn" onClick={() => { setResetting(u.username); setResetPass("") }}>
                        Reset password
                      </button>
                      <button
                        className="link-btn"
                        disabled={u.is_self}
                        title={u.is_self ? "You cannot disable your own account" : ""}
                        onClick={() => void toggleDisabled(u)}
                      >
                        {u.disabled ? "Enable" : "Disable"}
                      </button>
                      <button
                        className="link-btn danger"
                        disabled={u.is_self}
                        title={u.is_self ? "You cannot delete your own account" : ""}
                        onClick={() => void remove(u)}
                      >
                        Remove
                      </button>
                    </>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {error && <div className="error">{error}</div>}
        {ok && <div className="ingest-ok">✓ {ok}</div>}
      </div>

      <div className="section-label">Add operator</div>
      <div className="panel">
        <div className="ops-add">
          <input
            className="search"
            placeholder="username"
            value={addUser}
            onChange={(e) => setAddUser(e.target.value)}
          />
          <input
            type="password"
            className="search"
            placeholder="password (min 8)"
            value={addPass}
            onChange={(e) => setAddPass(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && void addOperator()}
          />
          <select className="search ops-role" value={addRole} onChange={(e) => setAddRole(e.target.value as Role)}>
            <option value="analyst">analyst</option>
            <option value="lead">lead</option>
          </select>
          <button className="btn btn-primary" disabled={adding || !addUser.trim() || !addPass} onClick={addOperator}>
            {adding ? "Adding…" : "Add operator"}
          </button>
        </div>
      </div>

      <div className="section-label">Recent login activity</div>
      <div className="panel">
        {activity.length === 0 ? (
          <p className="ingest-note" style={{ margin: 0 }}>No recent login attempts recorded.</p>
        ) : (
          <table className="ops-table ops-activity">
            <tbody>
              {activity.map((a, i) => (
                <tr key={i}>
                  <td className={"ops-result " + a.result}>
                    {a.result === "ok" ? "✓" : a.result === "locked" ? "⊘" : "✕"}
                  </td>
                  <td className="ops-user">{a.username || "—"}</td>
                  <td className="ops-when">{fmtWhen(a.time)}</td>
                  <td className="ops-src">{a.source}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
