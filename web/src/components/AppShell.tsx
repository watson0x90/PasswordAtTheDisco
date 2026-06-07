import type { ReactNode } from "react"
import { useAuth } from "../auth"

export function AppShell({ children }: { children: ReactNode }) {
  const { me, logout } = useAuth()
  return (
    <div className="shell">
      <header className="topbar">
        <div className="brand">
          <span className="b-main">Password</span>
          <span className="b-dim">!AtTheDisco</span>
          <span className="cursor" />
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
