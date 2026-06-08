import { createContext, useContext } from "react"
import type { View } from "./components/AppShell"

// Lets any view request navigation to another tab (e.g. the empty-state guide).
const NavContext = createContext<(v: View) => void>(() => {})
export const NavProvider = NavContext.Provider
export const useNav = () => useContext(NavContext)
