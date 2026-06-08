import { useState, type FormEvent } from "react"
import { api, ApiError, type AuditResult } from "../api"
import { useAuth } from "../auth"

export function Ingest() {
  const { me } = useAuth()
  const [domain, setDomain] = useState("")
  const [cracked, setCracked] = useState<File | null>(null)
  const [uncracked, setUncracked] = useState<File | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")
  const [result, setResult] = useState<AuditResult | null>(null)

  if (me?.role !== "lead") {
    return <div className="center-state">Ingesting data requires the lead role.</div>
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
      <div className="section-label">Ingest</div>
      <form className="panel ingest-form" onSubmit={onSubmit}>
        <p className="ingest-note">
          Upload a domain's credential dumps. The server parses them, correlates against HIBP, scores each
          account, and ingests the results — cleartext is never written to disk.
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
          <input type="file" onChange={(e) => setCracked(e.target.files?.[0] ?? null)} />
          <div className="hint">
            secretsdump <code>user:rid:lm:nt:::password</code> or simple <code>user:hash:password</code>
          </div>
        </div>

        <div className="field">
          <label>
            Uncracked file <span className="opt">optional</span>
          </label>
          <input type="file" onChange={(e) => setUncracked(e.target.files?.[0] ?? null)} />
        </div>

        {error && <div className="error">{error}</div>}
        {result && (
          <div className="ingest-ok">
            ✓ ingested {result.accounts.toLocaleString()} account{result.accounts === 1 ? "" : "s"} for <b>{domain.trim()}</b>{" "}
            ({result.cracked} cracked{result.uncracked ? `, ${result.uncracked} uncracked` : ""}).
            <button type="button" className="btn" onClick={() => location.reload()}>
              Reload to view
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
