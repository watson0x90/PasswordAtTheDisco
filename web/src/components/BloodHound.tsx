import { useCallback, useEffect, useRef, useState } from "react"
import { api, ApiError, type BHEStatus, type BHETestResult, type BHEConfigInput, type IngestEvent } from "../api"
import { useAuth } from "../auth"
import { useAudits } from "../auditsData"
import { useJobs } from "../jobs"
import { fmtWhen } from "../format"

export function BloodHound() {
  const { me } = useAuth()
  const csrf = me?.csrf_token ?? ""
  const { enrich: enrichJob, rescore, refresh } = useJobs()
  const [status, setStatus] = useState<BHEStatus | null>(null)
  const [loading, setLoading] = useState(true)
  const [scheme, setScheme] = useState("http")
  const [host, setHost] = useState("")
  const [port, setPort] = useState(8080)
  const [tokenId, setTokenId] = useState("")
  const [tokenKey, setTokenKey] = useState("")
  const [testing, setTesting] = useState(false)
  const [saving, setSaving] = useState(false)
  const [test, setTest] = useState<BHETestResult | null>(null)
  const [error, setError] = useState("")
  const [ok, setOk] = useState("")
  const [lastEnrich, setLastEnrich] = useState<IngestEvent | null>(null)

  // The most recent "enrich" ingest event for the active audit = the last time
  // BloodHound enrichment ran on it (persisted, survives restart).
  const loadLastEnrich = useCallback(async () => {
    try {
      const events = await api.ingests()
      setLastEnrich([...events].reverse().find((e) => e.kind === "enrich") ?? null)
    } catch {
      setLastEnrich(null) // no active audit / unavailable — show "not yet enriched"
    }
  }, [])

  const load = useCallback(async () => {
    try {
      const s = await api.bheStatus()
      setStatus(s)
      setScheme(s.scheme || "http")
      setHost(s.host || "")
      setPort(s.port || 8080)
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "failed to load status")
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void load()
    void loadLastEnrich()
  }, [load, loadLastEnrich])

  // Refresh the "last enriched" stamp when an enrichment job finishes.
  useEffect(() => {
    if (enrichJob?.phase === "done") void loadLastEnrich()
  }, [enrichJob?.phase, loadLastEnrich])

  function cfg(): BHEConfigInput {
    return {
      scheme,
      host: host.trim(),
      port: Number(port) || 0,
      token_id: tokenId.trim() || undefined,
      token_key: tokenKey.trim() || undefined,
    }
  }

  async function doTest() {
    setTesting(true)
    setError("")
    setTest(null)
    try {
      setTest(await api.bheTest(cfg(), csrf))
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "test failed")
    } finally {
      setTesting(false)
    }
  }

  async function doSave() {
    setSaving(true)
    setError("")
    setOk("")
    try {
      await api.bheConfig(cfg(), csrf)
      setTokenId("")
      setTokenKey("")
      setOk("Saved — BloodHound enrichment updated live (no restart).")
      window.setTimeout(() => setOk(""), 4000)
      await load()
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "save failed")
    } finally {
      setSaving(false)
    }
  }

  const [enrichErr, setEnrichErr] = useState("")

  async function runEnrich() {
    if (!me) return
    setEnrichErr("")
    try {
      await api.enrich(csrf)
      refresh()
    } catch (e) {
      setEnrichErr(e instanceof ApiError ? e.message : "could not start enrichment")
    }
  }

  if (me?.role !== "lead") return <div className="center-state">BloodHound settings require the lead role.</div>
  if (loading)
    return (
      <div className="center-state">
        <div className="spinner">loading</div>
      </div>
    )

  const tokenPlaceholder = status?.token_configured ? "(set — leave blank to keep)" : ""

  return (
    <div className="ops-page">
      <div className="section-label">BloodHound enrichment</div>
      <div className="panel">
        <p className="ingest-note">
          Connect a BloodHound CE instance to enrich accounts with <b>Domain Admin pathways</b> and controlled-object
          counts. Create an API token in <b>BloodHound CE → Administration → API Tokens</b> and enter it below. Saved
          settings apply <b>live — no restart</b>. The token is stored on the server (0600) and never shown back here.
        </p>

        <div className="stat-grid">
          <div className="stat">
            <div className="stat-label">Enrichment</div>
            <div className="stat-value">{status?.active ? "active" : "disabled"}</div>
          </div>
          <div className="stat">
            <div className="stat-label">Endpoint</div>
            <div className="stat-value fs-20">{status?.host || "—"}</div>
            {status?.host && <div className="stat-sub">{status.scheme}://{status.host}:{status.port}</div>}
          </div>
          <div className="stat">
            <div className="stat-label">API token</div>
            <div className="stat-value">{status?.token_configured ? "set" : "unset"}</div>
          </div>
        </div>

        <div className="bhe-form">
          <label>
            Scheme
            <select className="search" value={scheme} onChange={(e) => setScheme(e.target.value)}>
              <option value="http">http</option>
              <option value="https">https</option>
            </select>
          </label>
          <label>
            Host
            <input className="search" placeholder="127.0.0.1" value={host} onChange={(e) => setHost(e.target.value)} />
          </label>
          <label>
            Port
            <input type="number" className="search" value={port} onChange={(e) => setPort(Number(e.target.value))} />
          </label>
          <label>
            Token ID
            <input className="search" placeholder={tokenPlaceholder || "token id"} value={tokenId} onChange={(e) => setTokenId(e.target.value)} />
          </label>
          <label>
            Token key
            <input type="password" className="search" placeholder={tokenPlaceholder || "token key"} value={tokenKey} onChange={(e) => setTokenKey(e.target.value)} />
          </label>
        </div>

        <div className="pwned-actions">
          <button className="btn" disabled={testing || !host.trim()} onClick={doTest}>
            {testing ? "Testing…" : "Test connection"}
          </button>
          <button className="btn btn-primary" disabled={saving || !host.trim()} onClick={doSave}>
            {saving ? "Saving…" : "Save"}
          </button>
        </div>

        {error && <div className="error">{error}</div>}
        {ok && <div className="ingest-ok">✓ {ok}</div>}

        {test &&
          (test.ok ? (
            <div className="ingest-ok">
              ✓ Connected — BloodHound CE {test.server_version}
              {test.domains && test.domains.length > 0 && (
                <div className="stat-sub">
                  domains: {test.domains.map((d) => `${d.name}${d.collected ? "" : " (uncollected)"}`).join(", ")}
                </div>
              )}
            </div>
          ) : (
            <div className="error">Connection failed: {test.error}</div>
          ))}

        <div className="field bhe-run">
          <button type="button" className="btn" onClick={runEnrich}
                  disabled={enrichJob?.phase === "running" || rescore?.phase === "running" || !status?.active}>
            {enrichJob?.phase === "running" ? "Enriching…" : "Run BloodHound enrichment on this audit"}
          </button>
          <div className="field-hint">
            {lastEnrich
              ? `Last enriched ${fmtWhen(lastEnrich.at)}${lastEnrich.accounts_loaded ? ` · ${lastEnrich.accounts_loaded.toLocaleString()} accounts` : ""}`
              : "Not yet enriched on this audit."}
          </div>
          {enrichErr && <div className="error">{enrichErr}</div>}
          {enrichJob && enrichJob.phase !== "idle" && (
            <div className="hint">
              {enrichJob.phase === "running"
                ? `${enrichJob.message || "Enriching…"} ${enrichJob.processed}/${enrichJob.total} (${enrichJob.elapsed_sec}s)`
                : enrichJob.phase === "done"
                  ? `✓ Done — enriched ${enrichJob.enriched}/${enrichJob.total} accounts in ${enrichJob.elapsed_sec}s.`
                  : enrichJob.phase === "failed"
                    ? `✗ Failed: ${enrichJob.error ?? "unknown"}`
                    : enrichJob.phase}
            </div>
          )}
        </div>
      </div>

      <div className="section-label">Upload user properties (offline)</div>
      <div className="panel">
        <p className="ingest-note">
          Upload a <b>BloodHound users JSON export</b> (SharpHound collection, BHE export, or simplified format)
          to populate AD properties (<code>pwdLastSet</code>, <code>pwdNeverExpires</code>, <code>enabled</code>,
          controlled objects) on your accounts — <b>no live BHE connection needed</b>. Only DA-pathway checks
          require a live connection (use "Run enrichment" above for those).
        </p>
        <BHEUpload csrf={csrf} />
      </div>
    </div>
  )
}

function BHEUpload({ csrf }: { csrf: string }) {
  const { bumpData } = useAudits()
  const fileRef = useRef<HTMLInputElement>(null)
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState("")
  const [error, setError] = useState("")

  async function upload() {
    const file = fileRef.current?.files?.[0]
    if (!file) return
    setBusy(true)
    setResult("")
    setError("")
    try {
      const r = await api.uploadBHEUsers(file, csrf)
      setResult(`Uploaded ${r.uploaded_users.toLocaleString()} users, matched ${r.matched_accounts.toLocaleString()} accounts.`)
      bumpData()
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "upload failed")
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="field bhe-upload">
      <div className="bhe-upload-row">
        <input ref={fileRef} type="file" accept=".json" />
        <button className="btn btn-primary" onClick={upload} disabled={busy}>
          {busy ? "Uploading…" : "Upload user data"}
        </button>
      </div>
      {result && <div className="ingest-ok">✓ {result}</div>}
      {error && <div className="error">{error}</div>}
    </div>
  )
}
