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

  // Step 1 — load the dump (secretsdump/pwdump): every account, by NT hash.
  const [domain, setDomain] = useState("")
  const [dump, setDump] = useState<File | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")
  const [result, setResult] = useState<AuditResult | null>(null)

  // Step 2 — apply cracked passwords (hashcat output), matched by NT hash.
  const [crackfile, setCrackfile] = useState<File | null>(null)
  const [applyBusy, setApplyBusy] = useState(false)
  const [applyError, setApplyError] = useState("")
  const [applyResult, setApplyResult] = useState<ApplyCracksResult | null>(null)

  // Reset when the active audit changes (stale results would mislead).
  useEffect(() => {
    setDomain("")
    setDump(null)
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
    if (!domain.trim() || !dump || !me) return
    setBusy(true)
    setError("")
    setResult(null)
    try {
      // The dump loads as uncracked accounts (NT hashes); passwords come from step 2.
      setResult(await api.audit(domain.trim(), null, dump, me.csrf_token))
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
      <div className="section-label">1 · Load dump</div>
      <form className="panel ingest-form" onSubmit={onSubmit}>
        <p className="ingest-note">
          Upload a domain's <b>secretsdump / pwdump</b> (<code>user:rid:lm:nt:::</code>) into{" "}
          <b>{active ? active.name : "this audit"}</b>. Every account loads with its NT hash — all uncracked at first.
          Then apply hashcat's results below. Cleartext is never written to disk.
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
            Dump file <span className="req">required</span>
          </label>
          <input key={`d-${activeId}`} type="file" onChange={(e) => setDump(e.target.files?.[0] ?? null)} />
          <div className="hint">
            impacket secretsdump NTDS output (<code>user:rid:lm:nt:::</code>) or simple <code>user:hash</code>
          </div>
        </div>

        {error && <div className="error">{error}</div>}
        {result && (
          <div className="ingest-ok">
            ✓ loaded {result.accounts.toLocaleString()} account{result.accounts === 1 ? "" : "s"} for{" "}
            <b>{domain.trim()}</b>. Apply hashcat results below to fill in cracked passwords.
            <button type="button" className="btn" onClick={() => { refresh(); nav("overview") }}>
              View results →
            </button>
          </div>
        )}

        <button className="btn btn-primary" type="submit" disabled={busy || !domain.trim() || !dump}>
          {busy ? "Loading…" : "Load dump"}
        </button>
      </form>

      <div className="section-label">2 · Apply hashcat results</div>
      <form className="panel ingest-form" onSubmit={onApply}>
        <p className="ingest-note">
          Upload hashcat's cracked output; it's matched to the loaded accounts <b>by NT hash</b> — so one cracked hash
          flips <i>every</i> account that shares it (across domains, cracked or not), then everything is re-scored. Run
          it again as you crack more over time.
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
            <button type="button" className="btn" onClick={() => { refresh(); nav("overview") }}>
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
