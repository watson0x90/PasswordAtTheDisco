import { useCallback, useEffect, useState } from "react"
import { api, ApiError, type PwnedStatus, type PwnedBuild, type PwnedProbe, type PwnedJob, type PwnedPhase } from "../api"
import { useAuth } from "../auth"

function fmtBytes(n: number): string {
  if (!n) return "0 B"
  const u = ["B", "KB", "MB", "GB", "TB"]
  let i = 0
  let v = n
  while (v >= 1000 && i < u.length - 1) {
    v /= 1000
    i++
  }
  return `${v.toFixed(v < 10 && i > 0 ? 2 : 1)} ${u[i]}`
}
function fmtDur(sec: number): string {
  if (sec <= 0) return "0s"
  const h = Math.floor(sec / 3600)
  const m = Math.floor((sec % 3600) / 60)
  const s = sec % 60
  return [h ? `${h}h` : "", h || m ? `${m}m` : "", `${s}s`].filter(Boolean).join(" ")
}

const POLL_MS = 2500
const isActive = (p?: PwnedPhase) => p === "downloading" || p === "indexing"

export function PwnedPasswords() {
  const { me } = useAuth()
  const [status, setStatus] = useState<PwnedStatus | null>(null)
  const [loading, setLoading] = useState(true)
  const [building, setBuilding] = useState(false)
  const [probing, setProbing] = useState(false)
  const [buildRes, setBuildRes] = useState<PwnedBuild | null>(null)
  const [probeRes, setProbeRes] = useState<PwnedProbe | null>(null)
  const [job, setJob] = useState<PwnedJob | null>(null)
  const [resume, setResume] = useState(false)
  const [error, setError] = useState("")

  const loadStatus = useCallback(async () => {
    try {
      setStatus(await api.pwnedStatus())
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "failed to load status")
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void loadStatus()
    // pick up an already-running job after a page refresh
    api.pwnedJob().then(setJob).catch(() => {})
  }, [loadStatus])

  // poll while a job is active; refresh status when it finishes
  useEffect(() => {
    if (!isActive(job?.phase)) return
    const id = setInterval(async () => {
      try {
        const j = await api.pwnedJob()
        setJob(j)
        if (!isActive(j.phase)) void loadStatus()
      } catch {
        /* transient; keep polling */
      }
    }, POLL_MS)
    return () => clearInterval(id)
  }, [job?.phase, loadStatus])

  async function doBuild() {
    if (!me) return
    setBuilding(true)
    setError("")
    setBuildRes(null)
    try {
      setBuildRes(await api.pwnedBuild(me.csrf_token))
      void loadStatus()
    } catch (e) {
      if (e instanceof ApiError) {
        setError(e.message)
        const b = e.body as { output?: string } | null
        if (b && typeof b === "object" && b.output) setBuildRes({ ok: false, output: b.output, elapsed: "" })
      } else setError("build failed")
    } finally {
      setBuilding(false)
    }
  }

  async function doProbe() {
    if (!me) return
    setProbing(true)
    setError("")
    setProbeRes(null)
    try {
      setProbeRes(await api.pwnedProbe(me.csrf_token))
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "probe failed")
    } finally {
      setProbing(false)
    }
  }

  async function doDownload() {
    if (!me) return
    const msg = resume
      ? "Resume the Pwned Passwords NTLM download from the last checkpoint?"
      : "Download the FULL Pwned Passwords NTLM set? This is tens of gigabytes and can take hours; it overwrites the existing file, then rebuilds the index."
    if (!confirm(msg)) return
    setError("")
    try {
      setJob(await api.pwnedDownload(resume, me.csrf_token))
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "failed to start download")
    }
  }

  async function doIndex() {
    if (!me) return
    setError("")
    try {
      setJob(await api.pwnedIndex(me.csrf_token))
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "failed to start index build")
    }
  }

  async function doCancel() {
    if (!me) return
    try {
      setJob(await api.pwnedCancel(me.csrf_token))
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "failed to cancel")
    }
  }

  if (me?.role !== "lead") return <div className="center-state">The HIBP downloader requires the lead role.</div>
  if (loading)
    return (
      <div className="center-state">
        <div className="spinner">loading</div>
      </div>
    )

  const busy = isActive(job?.phase)

  return (
    <>
      <div className="section-label">HIBP Pwned Passwords</div>

      <div className="panel">
        <p className="ingest-note">
          Build the bundled <code>PwnedPasswordsDownloader</code> (.NET) tool and confirm the Have I Been Pwned
          source is reachable, then download the offline NTLM hash set and build its search index. Used for breach
          correlation across audits.
        </p>

        <div className="stat-grid">
          <div className="stat">
            <div className="stat-label">Downloader source</div>
            <div className="stat-value">{status?.source_present ? "present" : "missing"}</div>
            <div className="stat-sub" title={status?.source_dir}>{status?.source_dir}</div>
          </div>
          <div className="stat">
            <div className="stat-label">.NET SDK</div>
            <div className="stat-value">{status?.dotnet_version || "not found"}</div>
          </div>
          <div className="stat">
            <div className="stat-label">Tool built</div>
            <div className="stat-value">{status?.built ? "yes" : "no"}</div>
            {status?.exe_path && <div className="stat-sub" title={status.exe_path}>exe present</div>}
          </div>
          <div className="stat">
            <div className="stat-label">NTLM data file</div>
            <div className="stat-value">{fmtBytes(status?.data_bytes ?? 0)}</div>
            <div className="stat-sub" title={status?.data_file}>{status?.data_file || "not configured"}</div>
          </div>
        </div>

        <div className="policy-actions">
          <button className="btn" disabled={building || !status?.source_present} onClick={doBuild}>
            {building ? "Building…" : "Build downloader"}
          </button>
          <button className="btn" disabled={probing} onClick={doProbe}>
            {probing ? "Requesting…" : "Test HIBP request"}
          </button>
        </div>

        {error && <div className="error">{error}</div>}

        {probeRes && (
          <div className={probeRes.ok ? "ingest-ok" : "error"}>
            {probeRes.ok ? "✓ " : ""}HIBP responded {probeRes.status} — {probeRes.suffixes.toLocaleString()} NTLM
            suffixes in {probeRes.elapsed}
            {probeRes.sample && (
              <div className="stat-sub">
                sample: <code>{probeRes.sample}</code>
              </div>
            )}
          </div>
        )}

        {buildRes && (
          <div className="pwned-build">
            <div className={buildRes.ok ? "ingest-ok" : "error"}>
              {buildRes.ok ? `✓ build succeeded${buildRes.elapsed ? ` in ${buildRes.elapsed}` : ""}` : "build failed"}
              {buildRes.exe_path && (
                <div className="stat-sub" title={buildRes.exe_path}>
                  {buildRes.exe_path}
                </div>
              )}
            </div>
            {buildRes.output && <pre className="pwned-output">{buildRes.output}</pre>}
          </div>
        )}
      </div>

      <div className="panel">
        <div className="section-label" style={{ marginTop: 0 }}>Download &amp; index</div>
        <p className="ingest-note">
          Download the full NTLM hash set with the built tool, then build the <code>.index5</code> prefix index it
          needs. The download is tens of gigabytes and can take hours; it runs in the background — you can leave this
          page. Use <b>resume</b> to continue an interrupted download, or build the index from a file you already have.
        </p>

        <div className="policy-actions">
          <button className="btn btn-primary" disabled={busy || !status?.built} onClick={doDownload}>
            {job?.phase === "downloading" ? "Downloading…" : "Download latest NTLM set"}
          </button>
          <label className="pf-check" title="Continue a previously interrupted download">
            <input type="checkbox" checked={resume} disabled={busy} onChange={(e) => setResume(e.target.checked)} />
            resume
          </label>
          <button
            className="btn"
            disabled={busy || !status?.data_file || !(status?.data_bytes ?? 0)}
            onClick={doIndex}
            title="Rebuild the index from the existing data file (no download)"
          >
            {job?.phase === "indexing" ? "Indexing…" : "Build index from existing file"}
          </button>
          {job?.phase === "downloading" && (
            <button className="btn link-btn" onClick={doCancel}>
              Cancel
            </button>
          )}
        </div>

        {job && job.phase !== "idle" && <JobView job={job} />}
      </div>
    </>
  )
}

function JobView({ job }: { job: PwnedJob }) {
  if (job.phase === "downloading") {
    const pct = job.est_total > 0 ? Math.min(99, (job.bytes_now / job.est_total) * 100) : 0
    const remaining = job.rate_bps > 0 ? Math.max(0, (job.est_total - job.bytes_now) / job.rate_bps) : 0
    return (
      <div className="pwned-job">
        <Bar pct={pct} />
        <div className="pwned-job-line">
          downloading — {fmtBytes(job.bytes_now)} of ~{fmtBytes(job.est_total)} (~{pct.toFixed(0)}%)
          {job.rate_bps > 0 && <> · {fmtBytes(job.rate_bps)}/s · ETA ~{fmtDur(Math.round(remaining))}</>}
          {" · elapsed "}
          {fmtDur(job.elapsed_sec)}
          {job.resume && " · resumed"}
        </div>
      </div>
    )
  }
  if (job.phase === "indexing") {
    const pct = job.bytes_now > 0 ? Math.min(99, (job.index_scanned / job.bytes_now) * 100) : 0
    return (
      <div className="pwned-job">
        <Bar pct={pct} />
        <div className="pwned-job-line">
          building index — scanned {fmtBytes(job.index_scanned)} of {fmtBytes(job.bytes_now)} (~{pct.toFixed(0)}%) ·
          elapsed {fmtDur(job.elapsed_sec)}
        </div>
      </div>
    )
  }
  if (job.phase === "done") {
    return (
      <div className="ingest-ok">
        ✓ Complete — {fmtBytes(job.bytes_now)} downloaded and indexed
        {job.index_entries > 0 && <> ({job.index_entries.toLocaleString()} prefixes)</>} in {fmtDur(job.elapsed_sec)}.
        <div className="stat-sub">Restart the server to load the refreshed HIBP index.</div>
      </div>
    )
  }
  if (job.phase === "cancelled") {
    return <div className="error">Download cancelled — the partial file was kept; check “resume” to continue.</div>
  }
  if (job.phase === "failed") {
    return (
      <div className="pwned-build">
        <div className="error">Job failed.</div>
        {job.error && <pre className="pwned-output">{job.error}</pre>}
      </div>
    )
  }
  return null
}

function Bar({ pct }: { pct: number }) {
  return (
    <div className="pwned-bar">
      <div className="pwned-bar-fill" style={{ width: `${Math.max(2, pct)}%` }} />
    </div>
  )
}
