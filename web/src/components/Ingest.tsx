import { useEffect, useState, type FormEvent } from "react"
import { api, ApiError, type AuditResult } from "../api"
import { useAuth } from "../auth"
import { useAudits } from "../auditsData"
import { useAccountsData } from "../accountsData"
import { useNav } from "../nav"

export function Ingest() {
  const { me } = useAuth()
  const { activeId, active } = useAudits()
  const { refresh } = useAccountsData()
  const nav = useNav()
  const [domain, setDomain] = useState("")
  const [cracked, setCracked] = useState<File | null>(null)
  const [uncracked, setUncracked] = useState<File | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")
  const [result, setResult] = useState<AuditResult | null>(null)

  // Reset the form when the active audit changes (stale results would mislead).
  useEffect(() => {
    setDomain("")
    setCracked(null)
    setUncracked(null)
    setResult(null)
    setError("")
  }, [activeId])

  if (me?.role !== "lead") {
    return <div className="center-state">Ingesting data requires the lead role.</div>
  }
  if (!activeId) {
    return <div className="center-state">Select or create an audit (top right) before uploading.</div>
  }

  async function onSubmit(e: FormEvent) {
    e.preventDefault()
    if (!domain.trim() || !cracked || !me) return
    setBusy(true)
    setError("")
    setResult(null)
    try {
      setResult(await api.audit(domain.trim(), cracked, uncracked, me.csrf_token))
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "upload failed")
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <div className="section-label">Upload</div>
      <form className="panel ingest-form" onSubmit={onSubmit}>
        <p className="ingest-note">
          Upload a domain's credential dumps into <b>{active ? active.name : "this audit"}</b>. The server parses
          them, correlates against HIBP, scores each account, and ingests the results — cleartext is never
          written to disk.
        </p>

        <div className="field">
          <label htmlFor="dom">Domain</label>
          <input
            id="dom"
            className="search"
            placeholder="CORP.LOCAL"
            value={domain}
            spellCheck={false}
            onChange={(e) => setDomain(e.target.value)}
          />
        </div>

        <div className="field">
          <label>
            Cracked file <span className="req">required</span>
          </label>
          <input key={`c-${activeId}`} type="file" onChange={(e) => setCracked(e.target.files?.[0] ?? null)} />
          <div className="hint">
            secretsdump <code>user:rid:lm:nt:::password</code> or simple <code>user:hash:password</code>
          </div>
        </div>

        <div className="field">
          <label>
            Uncracked file <span className="opt">optional</span>
          </label>
          <input key={`u-${activeId}`} type="file" onChange={(e) => setUncracked(e.target.files?.[0] ?? null)} />
        </div>

        {error && <div className="error">{error}</div>}
        {result && (
          <div className="ingest-ok">
            ✓ ingested {result.accounts.toLocaleString()} account{result.accounts === 1 ? "" : "s"} for <b>{domain.trim()}</b>{" "}
            ({result.cracked} cracked{result.uncracked ? `, ${result.uncracked} uncracked` : ""}).
            <button
              type="button"
              className="btn"
              onClick={() => {
                refresh()
                nav("overview")
              }}
            >
              View results →
            </button>
          </div>
        )}

        <button className="btn btn-primary" type="submit" disabled={busy || !domain.trim() || !cracked}>
          {busy ? "Running audit…" : "Upload & run audit"}
        </button>
      </form>
    </>
  )
}
