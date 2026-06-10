import { useCallback, useEffect, useState } from "react"
import { api, ApiError, type PwnedStatus, type PwnedBuild, type PwnedProbe } from "../api"
import { useAuth } from "../auth"

function sizeOf(bytes: number): string {
  if (!bytes) return "—"
  const g = bytes / 1e9
  return g >= 1 ? `${g.toFixed(1)} GB` : `${(bytes / 1e6).toFixed(0)} MB`
}

export function PwnedPasswords() {
  const { me } = useAuth()
  const [status, setStatus] = useState<PwnedStatus | null>(null)
  const [loading, setLoading] = useState(true)
  const [building, setBuilding] = useState(false)
  const [probing, setProbing] = useState(false)
  const [buildRes, setBuildRes] = useState<PwnedBuild | null>(null)
  const [probeRes, setProbeRes] = useState<PwnedProbe | null>(null)
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
  }, [loadStatus])

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
        const b = e.body as { output?: string } | null // build output is returned even on failure
        if (b && typeof b === "object" && b.output) setBuildRes({ ok: false, output: b.output, elapsed: "" })
      } else {
        setError("build failed")
      }
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

  if (me?.role !== "lead") return <div className="center-state">The HIBP downloader requires the lead role.</div>
  if (loading)
    return (
      <div className="center-state">
        <div className="spinner">loading</div>
      </div>
    )

  return (
    <>
      <div className="section-label">HIBP Pwned Passwords</div>
      <div className="panel">
        <p className="ingest-note">
          Build the bundled <code>PwnedPasswordsDownloader</code> (.NET) tool and confirm the Have I Been Pwned
          download source is reachable. This prepares the offline NTLM hash set used for breach correlation.
          Kicking off the full multi-gigabyte download will come next — for now this builds the tool and makes a
          single test request.
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
            <div className="stat-value">{sizeOf(status?.data_bytes ?? 0)}</div>
            <div className="stat-sub" title={status?.data_file}>{status?.data_file || "not configured"}</div>
          </div>
        </div>

        <div className="policy-actions">
          <button className="btn btn-primary" disabled={building || !status?.source_present} onClick={doBuild}>
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
    </>
  )
}
