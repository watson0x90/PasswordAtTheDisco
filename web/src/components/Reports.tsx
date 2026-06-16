import { useAudits } from "../auditsData"

// The columns the accounts CSV emits — shown so operators know exactly what's in
// the file (and what isn't). Kept in sync with internal/report.CSV.
const COLUMNS: [string, string][] = [
  ["domain / username", "which account"],
  ["enabled", "is the account enabled"],
  ["status", "Cracked or Uncracked"],
  ["password_length", "length only — never the password itself (cracked accounts)"],
  ["complexity / meets_policy", "character mix and policy compliance"],
  ["risk_level / risk_score", "CVSS-style risk rating"],
  ["hibp_found / hibp_breach_count", "is the NT hash in HIBP (cracked or uncracked) + how many breaches"],
  ["reused / shared_with", "does another account share the same hash, and how many"],
  ["tier0_pathway / tier0_pathway_domains", "can this account reach a Tier-0 / privileged (Domain Admin) account, and where"],
  ["controlled_objects", "BloodHound-controlled object count"],
]

export function Reports() {
  const { activeId, active } = useAudits()

  if (!activeId) {
    return <div className="center-state">Select or create an audit (top right) before exporting reports.</div>
  }

  return (
    <>
      <div className="section-label">Reports</div>

      <div className="panel report-export">
        <div className="report-export-head">
          <div>
            <div className="action-title">Accounts summary (CSV)</div>
            <div className="action-sub">
              One row per account for <b>{active ? active.name : "this audit"}</b> — crack status, HIBP exposure,
              password reuse, and any pathway to a Tier-0 / privileged account.
            </div>
          </div>
          <a className="btn btn-primary" href="/api/export/csv" download>
            Download CSV
          </a>
        </div>

        <div className="report-redaction">
          🔒 <b>No secrets in this file.</b> It never contains a cleartext password or an NT hash — only the redacted
          fields below. (Reveal a single cleartext value, audit-logged, from the Accounts tab.)
        </div>

        <ul className="report-cols">
          {COLUMNS.map(([col, desc]) => (
            <li key={col}>
              <code>{col}</code>
              <span>{desc}</span>
            </li>
          ))}
        </ul>
      </div>

      <div className="panel report-export">
        <div className="report-export-head">
          <div>
            <div className="action-title">Full report (HTML)</div>
            <div className="action-sub">
              A self-contained HTML summary (posture, per-domain breakdown, risk distribution) — also fully redacted.
            </div>
          </div>
          <a className="btn" href="/api/export/html" download>
            Download HTML
          </a>
        </div>
      </div>
    </>
  )
}
