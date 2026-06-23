import { PwnedPasswords } from "./PwnedPasswords"
import { BloodHound } from "./BloodHound"
import { EnrichmentCoverage } from "./EnrichmentCoverage"
import { useAuth } from "../auth"

// Integrations: HIBP + BloodHound config (lead) + Enrichment coverage (all operators).
// Analysts reach this page for the read-only coverage view only; the lead-only HIBP/
// BloodHound config components are not rendered for them.
export function Integrations() {
  const { me } = useAuth()
  const isLead = me?.role === "lead"
  return (
    <>
      {isLead && <PwnedPasswords />}
      {isLead && <BloodHound />}
      <EnrichmentCoverage />
    </>
  )
}
