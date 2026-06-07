import { useState } from "react"
import { AuthProvider, useAuth } from "./auth"
import { Login } from "./components/Login"
import { AppShell, type View } from "./components/AppShell"
import { Dashboard } from "./components/Dashboard"
import { Accounts } from "./components/Accounts"

function Routed() {
  const { status } = useAuth()
  const [view, setView] = useState<View>("overview")

  if (status === "loading") {
    return (
      <div className="center-state">
        <div className="spinner">initializing</div>
      </div>
    )
  }
  if (status === "anonymous") return <Login />

  return (
    <AppShell view={view} onNav={setView}>
      {view === "overview" ? <Dashboard /> : <Accounts />}
    </AppShell>
  )
}

export function App() {
  return (
    <AuthProvider>
      <Routed />
    </AuthProvider>
  )
}
