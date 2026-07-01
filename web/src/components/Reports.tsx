import { useState, useEffect } from "react"
import { api, ApiError } from "../api"
import { useAuth } from "../auth"
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
  ["common_password / dictionary_word", "matched the common-password / dictionary wordlists"],
  ["forbidden_words / keyboard_patterns", "count of forbidden-word and keyboard-pattern matches (never the matched word)"],
]

function FocusedRow({
  title,
  sub,
  csv,
  html,
  tag,
}: {
  title: string
  sub: string
  csv: string
  html: string
  tag: "filtered" | "net-new"
}) {
  return (
    <div className="report-focused-row">
      <div>
        <div className="report-focused-title">
          {title}
          <span className={`report-tag ${tag === "net-new" ? "net-new" : ""}`}>
            {tag === "net-new" ? "net-new" : "filtered view"}
          </span>
        </div>
        <div className="action-sub">{sub}</div>
      </div>
      <div className="report-focused-actions">
        <a className="btn" href={csv} download>
          CSV
        </a>
        <a className="btn" href={html} download>
          HTML
        </a>
      </div>
    </div>
  )
}

export function Reports() {
  const { activeId, active } = useAudits()
  const { me } = useAuth()
  const isLead = me?.role === "lead"
  const csrf = me?.csrf_token ?? ""
  const [ctAcked, setCtAcked] = useState(false)
  const [ctErr, setCtErr] = useState("")
  const [ctBusy, setCtBusy] = useState(false)

  // The cleartext acknowledgement is a deliberate per-export opt-in: reset it when
  // the active audit changes so a tick on one audit never carries over to another.
  useEffect(() => {
    setCtAcked(false)
    setCtErr("")
  }, [activeId])

  async function downloadCleartext(fmt: "csv" | "html") {
    setCtErr("")
    setCtBusy(true)
    try {
      await api.exportCleartext(fmt, undefined, csrf)
    } catch (e) {
      setCtErr(e instanceof ApiError ? e.message : "export failed")
    } finally {
      setCtBusy(false)
    }
  }

  if (!activeId) {
    return <div className="center-state">Select or create an audit (top right) before exporting reports.</div>
  }

  return (
    <>
      <div className="section-label">Reports</div>
      <div className="view-sub">Export for tickets and leadership.</div>

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
        <div className="action-title">Focused reports (CSV)</div>
        <div className="action-sub">
          Same redaction — no passwords or hashes — each available as <b>CSV or HTML</b>. The first two are{" "}
          <b>pre-filtered views</b> of the accounts summary above (same columns, fewer rows) — a convenience so you
          don't have to filter it yourself. Password-reuse groups is the exception: it shows <i>which</i> accounts share
          a password, which the per-account file can't express (the grouping needs the redacted NT hash).
        </div>
        <div className="report-focused">
          <FocusedRow
            title="Cracked accounts"
            tag="filtered"
            sub="The accounts summary filtered to status = Cracked — the force-reset worklist."
            csv="/api/export/cracked.csv"
            html="/api/export/cracked.html"
          />
          <FocusedRow
            title="HIBP-exposed accounts"
            tag="filtered"
            sub="The accounts summary filtered to hibp_found = Yes (cracked or uncracked), most-breached first."
            csv="/api/export/hibp.csv"
            html="/api/export/hibp.html"
          />
          <FocusedRow
            title="Weak passwords"
            tag="filtered"
            sub="The accounts summary filtered to passwords matching a wordlist — common, dictionary word, forbidden term, or keyboard pattern."
            csv="/api/export/weak.csv"
            html="/api/export/weak.html"
          />
          <FocusedRow
            title="Password-reuse groups"
            tag="net-new"
            sub="One row per shared-password group (by NT hash): size, domains spanned, HIBP count, Tier-0 reach, and member usernames. Not derivable from the accounts summary."
            csv="/api/export/reuse.csv"
            html="/api/export/reuse.html"
          />
        </div>
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

      <div className="panel report-export">
        <div className="report-export-head">
          <div>
            <div className="action-title">Sanitized review export (JSON)</div>
            <div className="action-sub">
              Every per-account <b>scoring signal</b> and the audit aggregates, with <b>all identity removed</b> —
              no usernames, domain names, hashes, cleartext, or audit name. Domains and password-reuse groups are
              preserved as opaque labels so the scoring can be reviewed (by a person or an AI) without exposing
              customer data.
            </div>
          </div>
          <a className="btn" href="/api/export/sanitized.json" download>
            Download JSON
          </a>
        </div>
      </div>

      {isLead && (
        <div className="panel report-export">
          <div className="action-title">Cleartext export</div>
          <div className="cleartext-gate">
            <div className="cleartext-warning">
              ⚠ This file includes <b>cleartext cracked passwords</b>. NT hashes are never included.
              Every download is audit-logged. Handle per your data-handling policy.
            </div>
            <label className="cleartext-ack">
              <input
                type="checkbox"
                checked={ctAcked}
                onChange={(e) => { setCtAcked(e.target.checked); setCtErr("") }}
              />
              I understand this file contains cleartext passwords
            </label>
            <div className="cleartext-actions">
              <button
                className="btn"
                disabled={!ctAcked || ctBusy}
                onClick={() => void downloadCleartext("html")}
              >
                HTML
              </button>
              <button
                className="btn"
                disabled={!ctAcked || ctBusy}
                onClick={() => void downloadCleartext("csv")}
              >
                CSV
              </button>
            </div>
            {ctErr && <div className="cleartext-error">{ctErr}</div>}
          </div>
        </div>
      )}
    </>
  )
}
