import { PwnedPasswords } from "./PwnedPasswords"
import { BloodHound } from "./BloodHound"

// Integrations is the merged HIBP + BloodHound configuration page (Setup ▾ → Integrations).
// It composes the two existing pages as stacked sections — no behavior change to either.
export function Integrations() {
  return (
    <>
      <PwnedPasswords />
      <BloodHound />
    </>
  )
}
