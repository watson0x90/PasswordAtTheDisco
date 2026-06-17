import { useEffect, useState, type ReactNode } from "react"
import { api } from "../api"
import { useAuth } from "../auth"
import { useAudits } from "../auditsData"
import { Logo } from "./Logo"
import { JobPill } from "./JobPill"

export type View =
  | "overview" | "actionable" | "accounts" | "domains" | "compare" | "reports"
  | "ingest" | "policies" | "integrations" | "operators" | "activity" | "audits"

const TABS: { id: View; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "actionable", label: "Actionable" },
  { id: "accounts", label: "Accounts" },
  { id: "domains", label: "Domains" },
  { id: "compare", label: "Compare" },
  { id: "reports", label: "Reports" },
]

// Lead-only groups, shown as Setup ▾ / Admin ▾ dropdowns.
const SETUP_ITEMS: { id: View; label: string }[] = [
  { id: "ingest", label: "Upload" },
  { id: "policies", label: "Policies" },
  { id: "integrations", label: "Integrations" },
]
const ADMIN_ITEMS: { id: View; label: string }[] = [
  { id: "operators", label: "Operators" },
  { id: "activity", label: "Activity" },
  { id: "audits", label: "Manage Audits" },
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
  return (
    <div className="shell">
      <header className="topbar">
        <div className="topbar-left">
          <div className="brand">
            <Logo size={28} />
            <span className="word">Password<b>!AtTheDisco</b></span>
          </div>
          <nav className="nav">
            {TABS.map((t) => (
              <button key={t.id} className={t.id === view ? "nav-tab active" : "nav-tab"} onClick={() => onNav(t.id)}>
                {t.label}
              </button>
            ))}
            {me?.role === "lead" && (
              <>
                <NavDropdown label="Setup" items={SETUP_ITEMS} view={view} onNav={onNav} />
                <NavDropdown label="Admin" items={ADMIN_ITEMS} view={view} onNav={onNav} />
              </>
            )}
          </nav>
        </div>
        {me && (
          <div className="topbar-right">
            <JobPill />
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

function NavDropdown({
  label,
  items,
  view,
  onNav,
}: {
  label: string
  items: { id: View; label: string }[]
  view: View
  onNav: (v: View) => void
}) {
  const [open, setOpen] = useState(false)
  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false)
    window.addEventListener("keydown", onKey)
    return () => window.removeEventListener("keydown", onKey)
  }, [open])
  const active = items.some((i) => i.id === view)
  return (
    <div className="nav-dd">
      <button
        className={active ? "nav-tab nav-dd-trigger active" : "nav-tab nav-dd-trigger"}
        onClick={() => setOpen((o) => !o)}
        aria-haspopup="menu"
        aria-expanded={open}
      >
        {label}
        <span className="nav-dd-caret" aria-hidden="true">▾</span>
      </button>
      {open && (
        <>
          <div className="audit-backdrop" onClick={() => setOpen(false)} />
          <div className="nav-dd-menu" role="menu">
            {items.map((i) => (
              <button
                key={i.id}
                role="menuitem"
                className={i.id === view ? "nav-dd-item active" : "nav-dd-item"}
                onClick={() => {
                  onNav(i.id)
                  setOpen(false)
                }}
              >
                {i.label}
              </button>
            ))}
          </div>
        </>
      )}
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

  useEffect(() => {
    if (!menu) return
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setMenu(false)
    window.addEventListener("keydown", onKey)
    return () => window.removeEventListener("keydown", onKey)
  }, [menu])

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
      <button className="audit-current" onClick={() => setMenu((o) => !o)} aria-haspopup="menu" aria-expanded={menu}>
        <span className="audit-dot" />
        <span className="audit-name">{active ? active.name : "No audit"}</span>
        <span className="audit-caret">▾</span>
      </button>
      {menu && (
        <>
          <div className="audit-backdrop" onClick={() => setMenu(false)} />
          <div className="audit-menu">
            <div className="audit-menu-label">Audits</div>
            <div className="audit-list">
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
            </div>
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
