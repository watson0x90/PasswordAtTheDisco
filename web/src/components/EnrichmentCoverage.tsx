import { useMemo } from "react"
import { useAccountsData } from "../accountsData"
import { RISK_CLASS } from "../util"
import { unenrichedAccounts, coverageWhy, coverageCsv } from "../coverage"

// EnrichmentCoverage: read-only list of accounts BloodHound did NOT enrich, with a
// why-diagnosis and a client-side CSV export. Visible to all operators (the Integrations
// page makes this section analyst-reachable). "Has enrichment run?" is derived from the
// accounts themselves (any account with coverage "full" => it ran and matched >=1) rather
// than the ingest log, because /api/ingests is lead-only -- this keeps the analyst view
// accurate and avoids a 403.
export function EnrichmentCoverage() {
  const { accounts } = useAccountsData()

  const unenriched = useMemo(() => (accounts ? unenrichedAccounts(accounts) : []), [accounts])
  const enrichRan = useMemo(() => (accounts ?? []).some((a) => a.coverage === "full"), [accounts])
  const why = coverageWhy({ unenrichedCount: unenriched.length, totalCount: accounts?.length ?? 0, enrichRan })

  function downloadCsv() {
    const blob = new Blob([coverageCsv(unenriched)], { type: "text/csv" })
    const url = URL.createObjectURL(blob)
    const a = document.createElement("a")
    a.href = url
    a.download = "unenriched-accounts.csv"
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(url)
  }

  if (!accounts) return <div className="center-state"><div className="spinner">loading</div></div>
  if (accounts.length === 0) {
    return (
      <div className="ops-page">
        <div className="section-label">Enrichment coverage</div>
        <div className="panel"><p className="ingest-note">No accounts loaded yet.</p></div>
      </div>
    )
  }

  return (
    <div className="ops-page">
      <div className="section-label">Enrichment coverage</div>
      <div className="panel">
        <CoverageBanner why={why} />
        {unenriched.length > 0 && (
          <>
            <div className="pwned-actions">
              <button className="btn" onClick={downloadCsv}>Export CSV</button>
            </div>
            <table className="accounts-table">
              <thead>
                <tr><th>Username</th><th>Domain</th><th>Cracked</th><th>Exposure level</th></tr>
              </thead>
              <tbody>
                {unenriched.map((a, i) => (
                  <tr key={`${a.username}|${a.domain}|${i}`}>
                    <td>{a.username}</td>
                    <td>{a.domain}</td>
                    <td>{a.cracked ? "yes" : <span className="muted">—</span>}</td>
                    <td><span className={`badge ${RISK_CLASS[a.risk_level] || ""}`}>{a.risk_level}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}
      </div>
    </div>
  )
}

function CoverageBanner({ why }: { why: ReturnType<typeof coverageWhy> }) {
  if (why.kind === "all-covered") {
    return (
      <div className="coverage-banner" role="status">
        <span className="coverage-banner-dot" aria-hidden="true" />
        <span className="coverage-banner-text">All {why.total} accounts are BloodHound-enriched. ✓</span>
      </div>
    )
  }
  const msg = why.kind === "never-run"
    ? `BloodHound hasn't been run on this audit yet — ${why.count} accounts have Unknown Impact. Run enrichment (lead) or upload BloodHound user data to populate it.`
    : `BloodHound ran, but ${why.count} accounts didn't match. Check their SAM/UPN names or re-collect them in BloodHound.`
  return (
    <div className="coverage-banner" role="status">
      <span className="coverage-banner-dot" aria-hidden="true" />
      <span className="coverage-banner-text">{msg}</span>
    </div>
  )
}
