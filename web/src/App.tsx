import { AuthProvider, useAuth } from "./auth"
import { Login } from "./components/Login"
import { AppShell } from "./components/AppShell"
import { Dashboard } from "./components/Dashboard"

function Routed() {
  const { status } = useAuth()
  if (status === "loading") {
    return (
      <div className="center-state">
        <div className="spinner">initializing</div>
      </div>
    )
  }
  if (status === "anonymous") return <Login />
  return (
    <AppShell>
      <Dashboard />
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
