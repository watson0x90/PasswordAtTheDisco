import { useState, type ReactNode } from "react"
import { api } from "../api"
import { useAuth } from "../auth"
import { useAudits } from "../auditsData"
import { Logo } from "./Logo"

export type View = "overview" | "actionable" | "domains" | "accounts" | "insights" | "ingest" | "policies"

const TABS: { id: View; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "actionable", label: "Actionable" },
  { id: "domains", label: "Domains" },
  { id: "accounts", label: "Accounts" },
  { id: "insights", label: "Insights" },
]

export function AppShell({ view, onNav, children }: { view: View; onNav: (v: View) => void; children: ReactNode }) {
  const { me, logout, refresh } = useAuth()
  async function lockStore() {
    if (!me) return
    try {
      await api.lock(me.csrf_token)
    } finally {
      await refresh() // store_unlocked becomes false -> the unlock screen reappears
    }
  }
  // Ingest (web upload) and Policies editing are lead-only.
  const tabs =
    me?.role === "lead"
      ? [...TABS, { id: "ingest" as View, label: "Upload" }, { id: "policies" as View, label: "Policies" }]
      : TABS
  return (
    <div className="shell">
      <header className="topbar">
        <div className="topbar-left">
          <div className="brand">
            <Logo size={28} />
            <span className="word">Password<b>!AtTheDisco</b></span>
          </div>
          <nav className="nav">
            {tabs.map((t) => (
              <button key={t.id} className={t.id === view ? "nav-tab active" : "nav-tab"} onClick={() => onNav(t.id)}>
                {t.label}
              </button>
            ))}
          </nav>
        </div>
        {me && (
          <div className="topbar-right">
            <AuditSwitcher />
            <div className="who">
              <span className="u">{me.username}</span>
              <span className="r">operator</span>
            </div>
            <span className={me.role === "lead" ? "role-badge lead" : "role-badge"}>{me.role}</span>
            {me.role === "lead" && (
              <button className="btn" onClick={() => void lockStore()} title="Lock the encrypted store">
                Lock
              </button>
            )}
            <button className="btn" onClick={() => void logout()}>
              Sign Out
            </button>
          </div>
        )}
      </header>
      <main className="main">{children}</main>
    </div>
  )
}

function AuditSwitcher() {
  const { me } = useAuth()
  const { audits, active, activeId, open, create, remove } = useAudits()
  const isLead = me?.role === "lead"
  const [menu, setMenu] = useState(false)
  const [creating, setCreating] = useState(false)
  const [name, setName] = useState("")
  const [busy, setBusy] = useState(false)

  async function doCreate() {
    if (!name.trim()) return
    setBusy(true)
    try {
      await create(name.trim())
      setName("")
      setCreating(false)
      setMenu(false)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="audit-switcher">
      <button className="audit-current" onClick={() => setMenu((o) => !o)}>
        <span className="audit-dot" />
        <span className="audit-name">{active ? active.name : "No audit"}</span>
        <span className="audit-caret">▾</span>
      </button>
      {menu && (
        <>
          <div className="audit-backdrop" onClick={() => setMenu(false)} />
          <div className="audit-menu">
            <div className="audit-menu-label">Audits</div>
            {audits.length === 0 && <div className="audit-empty-row">none yet</div>}
            {audits.map((a) => (
              <div key={a.id} className={a.id === activeId ? "audit-item active" : "audit-item"}>
                <button
                  className="audit-pick"
                  onClick={() => {
                    void open(a.id)
                    setMenu(false)
                  }}
                >
                  <span className="audit-item-name">{a.name}</span>
                  <span className="audit-item-meta">{a.total_accounts.toLocaleString()} accts</span>
                </button>
                {isLead && (
                  <button
                    className="audit-del"
                    title="Delete audit"
                    onClick={() => {
                      if (confirm(`Delete audit "${a.name}"? This cannot be undone.`)) void remove(a.id)
                    }}
                  >
                    ×
                  </button>
                )}
              </div>
            ))}
            {isLead &&
              (creating ? (
                <div className="audit-create-form">
                  <input
                    autoFocus
                    className="search"
                    placeholder="Audit name"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    onKeyDown={(e) => e.key === "Enter" && doCreate()}
                  />
                  <button className="btn btn-primary" disabled={busy} onClick={doCreate}>
                    Create
                  </button>
                </div>
              ) : (
                <button className="audit-new" onClick={() => setCreating(true)}>
                  + New audit
                </button>
              ))}
          </div>
        </>
      )}
    </div>
  )
}
