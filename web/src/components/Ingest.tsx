import { useEffect, useState, useCallback, type FormEvent } from "react"
import { api, ApiError, type AuditResult, type ApplyCracksResult, type IngestEvent } from "../api"
import { useAuth } from "../auth"
import { useAudits } from "../auditsData"
import { useAccountsData } from "../accountsData"
import { useNav } from "../nav"
import { fmtWhen, fmtBytes } from "../format"
import { useJobs } from "../jobs"

export function Ingest() {
  const { me } = useAuth()
  const { activeId, active } = useAudits()
  const { refresh } = useAccountsData()
  const nav = useNav()
  const { enrich: enrichJob } = useJobs()

  // Step 1 — load the dump (secretsdump/pwdump): every account, by NT hash.
  const [domain, setDomain] = useState("")
  const [dump, setDump] = useState<File | null>(null)
  const [phase, setPhase] = useState<"idle" | "uploading" | "processing">("idle")
  const [pct, setPct] = useState(0)
  const [error, setError] = useState("")
  const [result, setResult] = useState<AuditResult | null>(null)

  // Step 2 — apply cracked passwords (hashcat output), matched by NT hash.
  const [crackfile, setCrackfile] = useState<File | null>(null)
  const [applyPhase, setApplyPhase] = useState<"idle" | "uploading" | "processing">("idle")
  const [applyPct, setApplyPct] = useState(0)
  const [applyError, setApplyError] = useState("")
  const [applyResult, setApplyResult] = useState<ApplyCracksResult | null>(null)

  const [history, setHistory] = useState<IngestEvent[]>([])

  const loadHistory = useCallback(async () => {
    try { setHistory(await api.ingests()) } catch { /* panel just stays empty */ }
  }, [])

  // Reset when the active audit changes (stale results would mislead).
  useEffect(() => {
    setDomain("")
    setDump(null)
    setResult(null)
    setError("")
    setCrackfile(null)
    setApplyResult(null)
    setApplyError("")
    setPhase("idle"); setPct(0); setApplyPhase("idle"); setApplyPct(0)
  }, [activeId])

  useEffect(() => { void loadHistory() }, [activeId, loadHistory])

  if (me?.role !== "lead") {
    return <div className="center-state">Ingesting data requires the lead role.</div>
  }
  if (me && me.store_unlocked === false) {
    return <div className="center-state">The store is locked. Unlock it (top right) before uploading.</div>
  }
  if (!activeId) {
    return <div className="center-state">Select or create an audit (top right) before uploading.</div>
  }

  function onUp(setPctFn: (n: number) => void, setPhaseFn: (p: "uploading" | "processing") => void) {
    return (loaded: number, total: number) => {
      setPctFn(total ? Math.round((loaded / total) * 100) : 0)
      if (loaded >= total) setPhaseFn("processing")
    }
  }

  async function onSubmit(e: FormEvent) {
    e.preventDefault()
    if (!domain.trim() || !dump || !me || phase !== "idle") return
    setPhase("uploading"); setPct(0); setError(""); setResult(null)
    try {
      const r = await api.audit(domain.trim(), null, dump, me.csrf_token, onUp(setPct, setPhase))
      setResult(r)
      void loadHistory()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "upload failed")
    } finally {
      setPhase("idle"); setPct(0)
    }
  }

  async function onApply(e: FormEvent) {
    e.preventDefault()
    if (!crackfile || !me || applyPhase !== "idle") return
    setApplyPhase("uploading"); setApplyPct(0); setApplyError(""); setApplyResult(null)
    try {
      const r = await api.applyCracks(crackfile, me.csrf_token, onUp(setApplyPct, setApplyPhase))
      setApplyResult(r)
      void loadHistory()
    } catch (err) {
      setApplyError(err instanceof ApiError ? err.message : "apply failed")
    } finally {
      setApplyPhase("idle"); setApplyPct(0)
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
            disabled={phase !== "idle"}
          />
        </div>

        <div className="field">
          <label>
            Dump file <span className="req">required</span>
          </label>
          <input key={`d-${activeId}`} type="file" onChange={(e) => setDump(e.target.files?.[0] ?? null)} disabled={phase !== "idle"} />
          {dump && <div className="hint">{dump.name} · {fmtBytes(dump.size)}</div>}
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

        {phase !== "idle" && (
          <div className="upload-progress">
            <div className="bar"><div className="fill" style={{ width: phase === "processing" ? "100%" : `${pct}%` }} /></div>
            <div className="hint">{phase === "uploading" ? `Uploading… ${pct}%` : "Processing on server…"}</div>
          </div>
        )}
        <button className="btn btn-primary" type="submit" disabled={phase !== "idle" || !domain.trim() || !dump}>
          {phase === "idle" ? "Load dump" : phase === "uploading" ? "Uploading…" : "Processing…"}
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
          <input key={`k-${activeId}`} type="file" onChange={(e) => setCrackfile(e.target.files?.[0] ?? null)} disabled={applyPhase !== "idle"} />
          {crackfile && <div className="hint">{crackfile.name} · {fmtBytes(crackfile.size)}</div>}
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

        {applyPhase !== "idle" && (
          <div className="upload-progress">
            <div className="bar"><div className="fill" style={{ width: applyPhase === "processing" ? "100%" : `${applyPct}%` }} /></div>
            <div className="hint">{applyPhase === "uploading" ? `Uploading… ${applyPct}%` : "Processing on server…"}</div>
          </div>
        )}
        <button className="btn btn-primary" type="submit" disabled={applyPhase !== "idle" || !crackfile}>
          {applyPhase === "idle" ? "Apply cracked hashes" : applyPhase === "uploading" ? "Uploading…" : "Processing…"}
        </button>
      </form>

      {enrichJob && enrichJob.phase !== "idle" && (
        <div className="hint">
          {enrichJob.phase === "running"
            ? `Enriching with BloodHound… ${enrichJob.processed}/${enrichJob.total}`
            : enrichJob.phase === "done"
              ? `BloodHound enrichment complete — enriched ${enrichJob.enriched}/${enrichJob.total}.`
              : enrichJob.phase === "failed"
                ? `BloodHound enrichment failed: ${enrichJob.error ?? "unknown"}`
                : `BloodHound enrichment ${enrichJob.phase}.`}
        </div>
      )}

      <div className="section-label">This audit — ingest history</div>
      <div className="panel">
        {history.length === 0 ? (
          <div className="muted">No uploads yet for this audit.</div>
        ) : (
          <div className="table-wrap">
            <table className="accounts">
              <thead>
                <tr><th>When</th><th>File</th><th>Kind</th><th>Domain</th><th>Result</th><th>By</th></tr>
              </thead>
              <tbody>
                {[...history].reverse().map((ev, i) => (
                  <tr key={i}>
                    <td className="muted">{fmtWhen(ev.at)}</td>
                    <td>{ev.filename || <span className="muted">—</span>}</td>
                    <td>{ev.kind}</td>
                    <td className="muted">{ev.domain || "—"}</td>
                    <td>
                      {ev.kind === "dump"
                        ? `+${(ev.accounts_loaded ?? 0).toLocaleString()} accounts`
                        : `${(ev.hashes_matched ?? 0).toLocaleString()} matched · ${(ev.newly_cracked ?? 0).toLocaleString()} cracked`}
                    </td>
                    <td className="muted">{ev.by}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  )
}
