import type { ReactNode } from "react"
import { useAuth } from "../auth"
import { Logo } from "./Logo"

export type View = "overview" | "actionable" | "domains" | "accounts"

const TABS: { id: View; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "actionable", label: "Actionable" },
  { id: "domains", label: "Domains" },
  { id: "accounts", label: "Accounts" },
]

export function AppShell({ view, onNav, children }: { view: View; onNav: (v: View) => void; children: ReactNode }) {
  const { me, logout } = useAuth()
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
          </nav>
        </div>
        {me && (
          <div className="topbar-right">
            <div className="who">
              <span className="u">{me.username}</span>
              <span className="r">operator</span>
            </div>
            <span className={me.role === "lead" ? "role-badge lead" : "role-badge"}>{me.role}</span>
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
