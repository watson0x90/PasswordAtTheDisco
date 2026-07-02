import { describe, expect, it } from "vitest"
import { paletteNavItems, type NavTarget } from "./paletteNav"

// Minimal fixtures mirroring AppShell's TABS / SETUP_ITEMS / ADMIN_ITEMS shape.
const TABS: NavTarget[] = [
  { id: "overview", label: "Overview" },
  { id: "accounts", label: "Accounts" },
  { id: "search", label: "Search" },
]
const SETUP: NavTarget[] = [
  { id: "ingest", label: "Upload" },
  { id: "audit-data", label: "Audit Data" },
  { id: "policies", label: "Policies" },
  { id: "integrations", label: "Integrations" },
]
const ADMIN: NavTarget[] = [
  { id: "operators", label: "Operators" },
  { id: "mcptokens", label: "MCP Tokens" },
  { id: "activity", label: "Activity" },
  { id: "audits", label: "Manage Audits" },
]

const ids = (items: NavTarget[]) => items.map((i) => i.id)

describe("paletteNavItems", () => {
  it("gives leads every TABS + Setup + Admin destination, plus Help", () => {
    const got = ids(paletteNavItems("lead", TABS, SETUP, ADMIN))
    for (const id of [...ids(TABS), ...ids(SETUP), ...ids(ADMIN), "help"]) {
      expect(got).toContain(id)
    }
    // Help appears exactly once (not duplicated by any group).
    expect(got.filter((id) => id === "help")).toHaveLength(1)
  })

  it("gives analysts TABS + Integrations + Help, but no other Setup/Admin views", () => {
    const got = ids(paletteNavItems("analyst", TABS, SETUP, ADMIN))
    expect(got).toEqual([...ids(TABS), "integrations", "help"])
    // The lead-only destinations must not leak into the analyst palette.
    for (const id of ["ingest", "audit-data", "policies", "operators", "mcptokens", "activity", "audits"]) {
      expect(got).not.toContain(id)
    }
  })

  it("treats an unknown/undefined role as non-lead (TABS + Integrations + Help)", () => {
    expect(ids(paletteNavItems(undefined, TABS, SETUP, ADMIN))).toEqual([...ids(TABS), "integrations", "help"])
  })

  it("omits Integrations for analysts when Setup has no integrations entry", () => {
    const setupNoIntegrations = SETUP.filter((i) => i.id !== "integrations")
    expect(ids(paletteNavItems("analyst", TABS, setupNoIntegrations, ADMIN))).toEqual([...ids(TABS), "help"])
  })
})
