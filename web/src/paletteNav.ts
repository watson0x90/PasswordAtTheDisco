import type { View } from "./components/AppShell"

export interface NavTarget {
  id: View
  label: string
}

// paletteNavItems returns the view destinations the command palette can jump to,
// matching what each role can actually reach in the top nav:
//   - everyone: the primary TABS, plus Help (a top-bar button, no role gate);
//   - leads: additionally the Setup + Admin groups;
//   - analysts: only Integrations from Setup (their sole Setup destination, which
//     the nav exposes as a standalone top-bar button rather than the Setup menu).
// The arrays are passed in (from AppShell) so this stays a pure, dependency-free
// function — the `View` import above is type-only and erased at build time.
export function paletteNavItems(
  role: string | undefined,
  tabs: NavTarget[],
  setup: NavTarget[],
  admin: NavTarget[],
): NavTarget[] {
  const items: NavTarget[] = [...tabs]
  if (role === "lead") {
    items.push(...setup, ...admin)
  } else {
    const integrations = setup.find((i) => i.id === "integrations")
    if (integrations) items.push(integrations)
  }
  items.push({ id: "help", label: "Help" })
  return items
}
