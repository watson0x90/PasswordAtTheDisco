import { useCallback, useEffect, useState } from "react"
import { api, ApiError, type McpToken, type McpTokenCreated, type Role } from "../api"
import { useAuth } from "../auth"
import { fmtWhen } from "../format"

export function McpTokens() {
  const { me } = useAuth()
  const csrf = me?.csrf_token ?? ""
  const [tokens, setTokens] = useState<McpToken[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState("")
  const [ok, setOk] = useState("")

  // one-time revealed secret after successful create
  const [revealed, setRevealed] = useState<McpTokenCreated | null>(null)

  // issue form
  const [label, setLabel] = useState("")
  const [role, setRole] = useState<Role>("analyst")
  const [expires, setExpires] = useState("")
  const [issuing, setIssuing] = useState(false)

  const load = useCallback(async () => {
    try {
      const list = await api.listMcpTokens()
      setTokens(list)
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "failed to load MCP tokens")
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

  async function issueToken() {
    if (!label.trim()) return
    setIssuing(true)
    setError("")
    setRevealed(null)
    try {
      const res = await api.createMcpToken(label.trim(), role, expires.trim() || undefined, csrf)
      setLabel("")
      setRole("analyst")
      setExpires("")
      setRevealed(res)
      flash(`Issued token "${res.label}".`)
      await load()
    } catch (e) {
      fail(e, "failed to issue token")
    } finally {
      setIssuing(false)
    }
  }

  async function revoke(t: McpToken) {
    if (!confirm(`Revoke token "${t.label}"? Agents using it stop working immediately.`)) return
    setError("")
    setRevealed(null)
    try {
      await api.revokeMcpToken(t.id, csrf)
      flash(`Revoked token "${t.label}".`)
      await load()
    } catch (e) {
      fail(e, "failed to revoke token")
    }
  }

  function tokenStatus(t: McpToken): string {
    if (t.expires && new Date(t.expires) < new Date()) return "expired"
    if (t.disabled) return "disabled"
    return "active"
  }

  function statusClass(status: string): string {
    if (status === "active") return "ops-badge on"
    if (status === "expired") return "ops-badge off"
    return "ops-badge off"
  }

  if (me?.role !== "lead") return <div className="center-state">MCP token management requires the lead role.</div>
  if (loading)
    return (
      <div className="center-state">
        <div className="spinner">loading</div>
      </div>
    )

  return (
    <div className="ops-page">
      <div className="section-label">MCP Tokens</div>
      <div className="panel">
        <p className="ingest-note">
          MCP tokens grant machine clients (agents, scripts) API access without operator credentials. A{" "}
          <b>lead</b> token can reveal cleartext AD passwords via the MCP reveal tool — issue with care. Tokens
          are revocable at any time; revocation takes effect immediately.
        </p>

        {tokens.length === 0 ? (
          <p className="ingest-note m-0">No MCP tokens issued yet.</p>
        ) : (
          <div className="table-wrap">
            <table className="ops-table">
              <thead>
                <tr>
                  <th>Label</th>
                  <th>Role</th>
                  <th>Created</th>
                  <th>Last used</th>
                  <th>Status</th>
                  <th className="ops-actions-col">Actions</th>
                </tr>
              </thead>
              <tbody>
                {tokens.map((t) => {
                  const status = tokenStatus(t)
                  return (
                    <tr key={t.id} className={t.disabled ? "ops-row disabled" : "ops-row"}>
                      <td className="ops-user">{t.label}</td>
                      <td>
                        <span className={t.role === "lead" ? "ops-badge mcp-role-lead" : "ops-badge mcp-role-analyst"}>
                          {t.role}
                        </span>
                      </td>
                      <td className="ops-when">{fmtWhen(t.created)}</td>
                      <td className="ops-when">{fmtWhen(t.last_used)}</td>
                      <td>
                        <span className={statusClass(status)}>{status}</span>
                      </td>
                      <td className="ops-actions">
                        <button className="link-btn danger" onClick={() => void revoke(t)}>
                          Revoke
                        </button>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}

        {error && <div className="error">{error}</div>}
        {ok && <div className="ingest-ok">✓ {ok}</div>}
      </div>

      <div className="section-label">Issue token</div>
      <div className="panel">
        <div className="ops-add">
          <input
            className="search"
            placeholder="Label (e.g. n8n-agent)"
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && !issuing && label.trim() && void issueToken()}
          />
          <select
            className="search ops-role"
            value={role}
            onChange={(e) => setRole(e.target.value as Role)}
          >
            <option value="analyst">analyst</option>
            <option value="lead">lead</option>
          </select>
          <input
            className="search"
            placeholder="e.g. 720h (optional)"
            value={expires}
            onChange={(e) => setExpires(e.target.value)}
          />
          <button
            className="btn btn-primary"
            disabled={issuing || !label.trim()}
            onClick={() => void issueToken()}
          >
            {issuing ? "Issuing…" : "Issue token"}
          </button>
        </div>
        {role === "lead" && (
          <p className="error mcp-lead-warn">
            A lead token can reveal AD cleartext via the MCP reveal tool — issue only when intended.
          </p>
        )}

        {revealed && (
          <div className="token-secret">
            <p className="token-secret-notice">Copy this now — it will not be shown again.</p>
            <div className="token-secret-row">
              <code className="token-secret-value">{revealed.token}</code>
              <button
                className="btn"
                onClick={() => void navigator.clipboard.writeText(revealed.token)}
              >
                Copy
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
