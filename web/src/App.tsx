import { useState } from "react"
import { AuthProvider, useAuth } from "./auth"
import { AccountsProvider } from "./accountsData"
import { AuditsProvider } from "./auditsData"
import { NavProvider } from "./nav"
import { Login } from "./components/Login"
import { AppShell, type View } from "./components/AppShell"
import { Dashboard } from "./components/Dashboard"
import { Actionable } from "./components/Actionable"
import { Domains } from "./components/Domains"
import { Accounts } from "./components/Accounts"
import { Compare } from "./components/Compare"
import { Ingest } from "./components/Ingest"
import { Insights } from "./components/Insights"
import { Policies } from "./components/Policies"
import { Unlock } from "./components/Unlock"

function viewFor(view: View) {
  switch (view) {
    case "actionable":
      return <Actionable />
    case "domains":
      return <Domains />
    case "accounts":
      return <Accounts />
    case "insights":
      return <Insights />
    case "compare":
      return <Compare />
    case "ingest":
      return <Ingest />
    case "policies":
      return <Policies />
    default:
      return <Dashboard />
  }
}

function Routed() {
  const { status, me } = useAuth()
  const [view, setView] = useState<View>("overview")

  if (status === "loading") {
    return (
      <div className="center-state">
        <div className="spinner">initializing</div>
      </div>
    )
  }
  if (status === "anonymous") return <Login />
  // Authenticated but the encrypted store is locked: gate behind the unlock screen.
  if (me && !me.store_unlocked) return <Unlock />

  return (
    <NavProvider value={setView}>
      <AuditsProvider>
        <AccountsProvider>
          <AppShell view={view} onNav={setView}>
            {viewFor(view)}
          </AppShell>
        </AccountsProvider>
      </AuditsProvider>
    </NavProvider>
  )
}

export function App() {
  return (
    <AuthProvider>
      <Routed />
    </AuthProvider>
  )
}
