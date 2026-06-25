import { lazy, Suspense, useState } from "react"
import { AuthProvider, useAuth } from "./auth"
import { AccountsProvider } from "./accountsData"
import { AccountDrawerProvider } from "./accountDrawer"
import { AccountDetailProvider } from "./accountDetail"
import { AuditsProvider } from "./auditsData"
import { NavProvider } from "./nav"
import { JobsProvider } from "./jobs"
import { Login } from "./components/Login"
import { AppShell, type View } from "./components/AppShell"
import { Actionable } from "./components/Actionable"
import { Accounts } from "./components/Accounts"
import { Compare } from "./components/Compare"
import { Ingest } from "./components/Ingest"
import { Policies } from "./components/Policies"
import { Integrations } from "./components/Integrations"
import { Operators } from "./components/Operators"
import { McpTokens } from "./components/McpTokens"
import { Activity } from "./components/Activity"
import { ManageAudits } from "./components/ManageAudits"
import { Reports } from "./components/Reports"
import { Search } from "./components/Search"
import { Unlock } from "./components/Unlock"
import { CommandPalette } from "./components/CommandPalette"
// Help is a small, pure static surface and MUST load pre-auth (login/locked
// screens), so it is imported eagerly — never behind the recharts lazy chunk.
import { Help } from "./components/help/Help"
import { isHelpHash } from "./components/help/useChapterHash"

// Recharts is heavy (~180KB). Lazy-load Dashboard and Domains so the charting
// chunk is deferred until after auth, not on the login screen. (Insights renders
// inside Dashboard, so it rides in that lazy chunk.)
const Dashboard = lazy(() => import("./components/Dashboard").then((m) => ({ default: m.Dashboard })))
const Domains = lazy(() => import("./components/Domains").then((m) => ({ default: m.Domains })))
const AuditData = lazy(() => import("./components/AuditData").then((m) => ({ default: m.AuditData })))
const Exposure = lazy(() => import("./components/Exposure").then((m) => ({ default: m.Exposure })))

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
    case "mcptokens":
      return <McpTokens />
    case "activity":
      return <Activity />
    case "audits":
      return <ManageAudits />
    case "audit-data":
      return <AuditData />
    case "exposure":
      return <Exposure />
    case "search":
      return <Search />
    case "help":
      return <Help />
    default:
      return <Dashboard />
  }
}

function Routed() {
  const { status, me } = useAuth()
  const [view, setView] = useState<View>("overview")
  // Pre-auth / locked reachability for the Help surface. Seeded from the hash so
  // a cold `#help/<slug>` URL (an emailed chapter link) auto-opens Help even
  // before login. useState initializer runs once, so toggling does not re-read
  // the (possibly stale) hash. isHelpHash agrees with parseHelpHash on the
  // `#help` prefix (so `#helpfoo` does not false-trigger).
  const [showHelp, setShowHelp] = useState(() => isHelpHash(location.hash))

  if (status === "loading") {
    return (
      <div className="center-state">
        <div className="spinner">initializing</div>
      </div>
    )
  }
  if (showHelp)
    return (
      <Help
        onClose={() => {
          // Strip the `#help` deep-link before closing so a reload does not
          // re-open standalone Help (the useState initializer above re-reads it).
          if (isHelpHash(location.hash)) history.replaceState(null, "", location.pathname + location.search)
          setShowHelp(false)
        }}
      />
    )
  if (status === "anonymous") return <Login onShowHelp={() => setShowHelp(true)} />
  // Authenticated but the encrypted store is locked: gate behind the unlock screen.
  if (me && !me.store_unlocked) return <Unlock onShowHelp={() => setShowHelp(true)} />

  return (
    <NavProvider value={setView}>
      <AuditsProvider>
        <AccountsProvider>
          <AccountDetailProvider>
            <AccountDrawerProvider>
              <JobsProvider>
                <CommandPalette />
                <AppShell view={view} onNav={setView}>
                  <Suspense fallback={<div className="center-state"><div className="spinner">loading</div></div>}>
                    {viewFor(view)}
                  </Suspense>
                </AppShell>
              </JobsProvider>
            </AccountDrawerProvider>
          </AccountDetailProvider>
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
