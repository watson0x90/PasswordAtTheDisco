import { lazy, Suspense, useState } from "react"
import { AuthProvider, useAuth } from "./auth"
import { AccountsProvider } from "./accountsData"
import { AuditsProvider } from "./auditsData"
import { NavProvider } from "./nav"
import { Login } from "./components/Login"
import { AppShell, type View } from "./components/AppShell"
import { Actionable } from "./components/Actionable"
import { Accounts } from "./components/Accounts"
import { Compare } from "./components/Compare"
import { Ingest } from "./components/Ingest"
import { Policies } from "./components/Policies"
import { Integrations } from "./components/Integrations"
import { Operators } from "./components/Operators"
import { Activity } from "./components/Activity"
import { ManageAudits } from "./components/ManageAudits"
import { Reports } from "./components/Reports"
import { Unlock } from "./components/Unlock"

// Recharts is heavy (~180KB). Lazy-load Dashboard and Domains so the charting
// chunk is deferred until after auth, not on the login screen. (Insights renders
// inside Dashboard, so it rides in that lazy chunk.)
const Dashboard = lazy(() => import("./components/Dashboard").then((m) => ({ default: m.Dashboard })))
const Domains = lazy(() => import("./components/Domains").then((m) => ({ default: m.Domains })))

function viewFor(view: View) {
  switch (view) {
    case "actionable":
      return <Actionable />
    case "domains":
      return <Domains />
    case "accounts":
      return <Accounts />
    case "compare":
      return <Compare />
    case "reports":
      return <Reports />
    case "ingest":
      return <Ingest />
    case "policies":
      return <Policies />
    case "integrations":
      return <Integrations />
    case "operators":
      return <Operators />
    case "activity":
      return <Activity />
    case "audits":
      return <ManageAudits />
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
            <Suspense fallback={<div className="center-state"><div className="spinner">loading</div></div>}>
              {viewFor(view)}
            </Suspense>
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
