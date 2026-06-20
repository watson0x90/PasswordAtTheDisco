import { useMemo, useState, type FormEvent } from "react"
import { api, ApiError, type Account } from "../api"
import { useAccountsData } from "../accountsData"
import { useAuth } from "../auth"
import { filterAccounts } from "../search"
import { AccountsTable } from "./AccountsTable"

export function Search() {
  const { accounts } = useAccountsData()
  const { me } = useAuth()

  const [query, setQuery] = useState("")
  const matches = useMemo(() => filterAccounts(accounts ?? [], query, 1000), [accounts, query])

  const [candidate, setCandidate] = useState("")
  const [showPw, setShowPw] = useState(false)
  const [busy, setBusy] = useState(false)
  const [probe, setProbe] = useState<{ count: number; matches: Account[] } | null>(null)
  const [probeErr, setProbeErr] = useState("")

  async function runProbe(e: FormEvent) {
    e.preventDefault()
    if (!candidate || !me) return
    setBusy(true)
    setProbeErr("")
    setProbe(null)
    try {
      const r = await api.probe(candidate, me.csrf_token)
      setProbe(r)
    } catch (err) {
      setProbeErr(err instanceof ApiError ? err.message : "probe failed")
    } finally {
      setCandidate("") // never keep the candidate around longer than the request
      setShowPw(false) // restore masked default for the next entry
      setBusy(false)
    }
  }

  return (
    <>
      <div className="section-label">Search</div>
      <div className="view-sub">Find accounts across this audit, or check whether a password is in use.</div>

      <div className="toolbar">
        <input
          className="search"
          placeholder="search username or domain…"
          value={query}
          spellCheck={false}
          onChange={(e) => setQuery(e.target.value)}
        />
        {query && <div className="toolbar-count">{matches.length.toLocaleString()} match(es)</div>}
      </div>
      {query ? (
        <AccountsTable accounts={matches} />
      ) : (
        <div className="center-state">Search this audit's accounts by username or domain.</div>
      )}

      <div className="section-label">Password in use?</div>
      <div className="panel">
        <p className="ingest-note">
          Check whether any account in this audit uses a specific password — even uncracked ones — by matching its
          NT hash. Useful for a leaked or banned credential. <b>The password you enter is never stored or logged</b>;
          each check is recorded in the audit log with the operator, time, and match count only.
        </p>
        <form className="probe-form" onSubmit={runProbe}>
          <input
            className="search"
            type={showPw ? "text" : "password"}
            placeholder="password to check…"
            value={candidate}
            spellCheck={false}
            autoComplete="off"
            onChange={(e) => setCandidate(e.target.value)}
          />
          <button type="button" className="link-btn" onClick={() => setShowPw((v) => !v)}>
            {showPw ? "hide" : "show"}
          </button>
          <button type="submit" className="btn btn-primary" disabled={!candidate || busy}>
            {busy ? "checking…" : "Check"}
          </button>
        </form>

        {probeErr && <div className="error">{probeErr}</div>}
        {probe && (probe.count === 0 ? (
          <div className="probe-result c-low">No accounts in this audit use that password.</div>
        ) : (
          <>
            <div className="probe-result c-crit">
              {probe.count.toLocaleString()} account(s) use this password — rotate them.
            </div>
            <AccountsTable accounts={probe.matches} />
          </>
        ))}
      </div>
    </>
  )
}
