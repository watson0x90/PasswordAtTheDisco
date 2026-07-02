import { useEffect, useState } from "react"
import { api, ApiError, type IngestEvent } from "../api"
import { useAccountsData } from "../accountsData"
import { useAudits } from "../auditsData"
import { useAuth } from "../auth"
import { useJobs } from "../jobs"
import { fmtWhen } from "../format"
import { perDomainStatus } from "../auditData"
import { useSortablePaged, type SortColumn } from "../sortPage"
import { SortHeader } from "./SortHeader"
import { Pager } from "./Pager"

// Sortable columns for the ingest-history table. Default sort is `at` descending
// (newest first), preserving the previous reverse-chronological order. `at` is an
// ISO-8601 string, so lexicographic order matches chronological order.
const INGEST_COLS: SortColumn<IngestEvent>[] = [
  { key: "at", get: (e) => e.at, defaultDir: "desc" },
  { key: "filename", get: (e) => e.filename || "" },
  { key: "kind", get: (e) => e.kind },
  { key: "domain", get: (e) => (e.kind === "cracks" ? "all domains" : e.domain || "") },
  { key: "by", get: (e) => e.by },
]

export function AuditData() {
  const { me } = useAuth()
  const { accounts, error } = useAccountsData()
  const { activeId, dataVersion, bumpData } = useAudits()
  const { enrich } = useJobs()
  const csrf = me?.csrf_token ?? ""

  const [ingests, setIngests] = useState<IngestEvent[]>([])
  const [delErr, setDelErr] = useState("")
  const [enrichErr, setEnrichErr] = useState("")

  useEffect(() => {
    api.ingests().then(setIngests).catch(() => {})
  }, [activeId, dataVersion])

  // Paginate the ingest history — one row accrues per upload/crack/enrich/delete,
  // so a heavily-reworked audit accumulates hundreds. The sort replaces the old
  // manual reverse (default: newest first).
  const ingestPage = useSortablePaged(ingests, INGEST_COLS, { defaultSort: { key: "at", dir: "desc" }, pageSize: 50 })

  if (me?.role !== "lead") {
    return <div className="center-state">Audit data management requires the lead role.</div>
  }
  if (!activeId) {
    return <div className="center-state">Select or create an audit (top right) before viewing audit data.</div>
  }
  if (accounts === null && !error) {
    return (
      <div className="center-state">
        <div className="spinner">loading</div>
      </div>
    )
  }

  const rows = perDomainStatus(accounts ?? [], ingests)

  async function onDelete(domain: string, n: number) {
    if (!window.confirm(`Delete ${domain} — ${n} account(s) — from this audit? This cannot be undone.`)) return
    setDelErr("")
    try {
      await api.deleteDomain(domain, csrf)
      bumpData()
      setIngests(await api.ingests())
    } catch (e) {
      setDelErr(e instanceof ApiError ? e.message : "delete failed")
    }
  }

  async function runEnrich() {
    setEnrichErr("")
    try {
      await api.enrich(csrf)
      bumpData()
    } catch (e) {
      setEnrichErr(e instanceof ApiError ? e.message : "could not start enrichment")
    }
  }

  async function cancelEnrich() {
    try {
      await api.enrichCancel(csrf)
    } catch {
      // best-effort
    }
  }

  function enrichStatus() {
    if (!enrich || enrich.phase === "idle") return <span className="muted">Not run yet.</span>
    if (enrich.phase === "running") {
      return (
        <span>
          Enriching… {enrich.processed}/{enrich.total}{" "}
          <button className="link-btn" onClick={() => void cancelEnrich()}>
            Cancel
          </button>
        </span>
      )
    }
    if (enrich.phase === "done") {
      return <span className="c-low">Done — enriched {enrich.enriched}/{enrich.total}</span>
    }
    if (enrich.phase === "failed") {
      return <span className="c-crit">Failed: {enrich.error ?? "unknown error"}</span>
    }
    if (enrich.phase === "cancelled") {
      return <span className="muted">Enrichment cancelled</span>
    }
    return <span className="muted">{enrich.phase}</span>
  }

  function ingestResult(ev: IngestEvent): string {
    if (ev.kind === "dump") return `+${ev.accounts_loaded ?? 0} accounts`
    if (ev.kind === "cracks") return `${ev.hashes_matched ?? 0} matched · ${ev.newly_cracked ?? 0} cracked`
    if (ev.kind === "domain_delete") return `−${ev.accounts_loaded ?? 0} removed`
    if (ev.kind === "enrich") return `enriched ${ev.accounts_loaded ?? 0}`
    return "—"
  }

  return (
    <>
      <div className="section-label">Domain data</div>
      <div className="panel mb-xl">
        {delErr && <div className="error">{delErr}</div>}
        {rows.length === 0 ? (
          <div className="muted py-sm">
            No data yet — load a dump on the Upload page.
          </div>
        ) : (
          <div className="table-wrap">
            <table className="accounts compact">
              <thead>
                <tr>
                  <th>Domain</th>
                  <th className="num">Accounts</th>
                  <th className="num">Cracked</th>
                  <th>Enriched</th>
                  <th>Loaded</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => (
                  <tr key={row.domain}>
                    <td className="font-mono fw-600">{row.domain}</td>
                    <td className="num">{row.accounts.toLocaleString()}</td>
                    <td className="num">{row.cracked.toLocaleString()}</td>
                    <td>
                      {row.enriched === "fresh" ? (
                        <span className="c-low">✓ enriched</span>
                      ) : row.enriched === "stale" ? (
                        <span className="c-high" title="loaded after last enrichment — re-run">⚠ stale</span>
                      ) : (
                        <span className="muted">✗ not run</span>
                      )}
                    </td>
                    <td className="muted">{fmtWhen(row.loadedAt)}</td>
                    <td>
                      <button
                        className="link-btn danger"
                        onClick={() => void onDelete(row.domain, row.accounts)}
                      >
                        delete
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="section-label">BloodHound enrichment</div>
      <div className="panel mb-xl">
        <div className="pwned-actions">
          <div style={{ flex: 1 }}>{enrichStatus()}</div>
          <button
            className="btn btn-primary"
            disabled={enrich?.phase === "running"}
            onClick={() => void runEnrich()}
          >
            Run enrichment
          </button>
        </div>
        {enrichErr && <div className="error mt-md">{enrichErr}</div>}
        <div className="hint mt-sm">
          Enriches all accounts with BloodHound DA-pathway data. Configure the BloodHound connection on the BloodHound settings page.
        </div>
      </div>

      <div className="section-label">Ingest history</div>
      <div className="panel">
        {ingests.length === 0 ? (
          <div className="muted py-sm">No ingest events yet.</div>
        ) : (
          <>
            <div className="table-wrap">
              <table className="accounts compact">
                <thead>
                  <tr>
                    <SortHeader label="When" colKey="at" sort={ingestPage.sort} onSort={ingestPage.setSort} />
                    <SortHeader label="File" colKey="filename" sort={ingestPage.sort} onSort={ingestPage.setSort} />
                    <SortHeader label="Kind" colKey="kind" sort={ingestPage.sort} onSort={ingestPage.setSort} />
                    <SortHeader label="Domain" colKey="domain" sort={ingestPage.sort} onSort={ingestPage.setSort} />
                    <th>Result</th>
                    <SortHeader label="By" colKey="by" sort={ingestPage.sort} onSort={ingestPage.setSort} />
                  </tr>
                </thead>
                <tbody>
                  {ingestPage.rows.map((ev, i) => (
                    <tr key={`${ev.at}|${ev.kind}|${i}`}>
                      <td className="muted">{fmtWhen(ev.at)}</td>
                      <td className="font-mono fs-12">{ev.filename || "—"}</td>
                      <td>{ev.kind}</td>
                      <td className="muted">
                        {ev.kind === "cracks" ? "all domains" : (ev.domain || "—")}
                      </td>
                      <td>{ingestResult(ev)}</td>
                      <td className="muted">{ev.by}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pager page={ingestPage} />
          </>
        )}
      </div>
    </>
  )
}
