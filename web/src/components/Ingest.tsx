import { useEffect, useState, type FormEvent } from "react"
import { api, ApiError, type AuditResult, type ApplyCracksResult } from "../api"
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

  // "Apply hashcat results" (match cracked passwords to existing accounts by NT hash)
  const [crackfile, setCrackfile] = useState<File | null>(null)
  const [applyBusy, setApplyBusy] = useState(false)
  const [applyError, setApplyError] = useState("")
  const [applyResult, setApplyResult] = useState<ApplyCracksResult | null>(null)

  // Reset the form when the active audit changes (stale results would mislead).
  useEffect(() => {
    setDomain("")
    setCracked(null)
    setUncracked(null)
    setResult(null)
    setError("")
    setCrackfile(null)
    setApplyResult(null)
    setApplyError("")
  }, [activeId])

  if (me?.role !== "lead") {
    return <div className="center-state">Ingesting data requires the lead role.</div>
  }
  if (!activeId) {
    return <div className="center-state">Select or create an audit (top right) before uploading.</div>
  }

  async function onSubmit(e: FormEvent) {
    e.preventDefault()
    if (!domain.trim() || (!cracked && !uncracked) || !me) return
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

  async function onApply(e: FormEvent) {
    e.preventDefault()
    if (!crackfile || !me) return
    setApplyBusy(true)
    setApplyError("")
    setApplyResult(null)
    try {
      setApplyResult(await api.applyCracks(crackfile, me.csrf_token))
    } catch (err) {
      setApplyError(err instanceof ApiError ? err.message : "apply failed")
    } finally {
      setApplyBusy(false)
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
            Cracked file <span className="opt">optional</span>
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
          <div className="hint">
            The full secretsdump/<b>pwdump</b> (<code>user:rid:lm:nt:::</code>) goes here — every account loads with its
            NT hash; then apply hashcat results below to flip the cracked ones.
          </div>
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

        <button className="btn btn-primary" type="submit" disabled={busy || !domain.trim() || (!cracked && !uncracked)}>
          {busy ? "Running audit…" : "Upload & run audit"}
        </button>
      </form>

      <div className="section-label">Apply hashcat results</div>
      <form className="panel ingest-form" onSubmit={onApply}>
        <p className="ingest-note">
          Upload hashcat's cracked output and it's matched to the loaded accounts <b>by NT hash</b> — so one cracked
          hash flips <i>every</i> account that shares it (across domains, cracked or not), then everything is re-scored.
          Run it as you crack more over time.
        </p>
        <div className="field">
          <label>
            Crack file <span className="req">required</span>
          </label>
          <input key={`k-${activeId}`} type="file" onChange={(e) => setCrackfile(e.target.files?.[0] ?? null)} />
          <div className="hint">
            <code>user:hash:password</code> or a bare <code>hash:password</code> potfile
          </div>
        </div>

        {applyError && <div className="error">{applyError}</div>}
        {applyResult && (
          <div className="ingest-ok">
            ✓ {applyResult.hashes_matched.toLocaleString()} hash{applyResult.hashes_matched === 1 ? "" : "es"} matched →{" "}
            <b>{applyResult.newly_cracked.toLocaleString()}</b> account{applyResult.newly_cracked === 1 ? "" : "s"} newly
            cracked (from {applyResult.crack_entries.toLocaleString()} crack entries).
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

        <button className="btn btn-primary" type="submit" disabled={applyBusy || !crackfile}>
          {applyBusy ? "Applying…" : "Apply cracked hashes"}
        </button>
      </form>
    </>
  )
}
