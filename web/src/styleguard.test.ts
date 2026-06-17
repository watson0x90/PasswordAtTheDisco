import { readdirSync, readFileSync, statSync } from "node:fs"
import { join } from "node:path"
import { describe, expect, it } from "vitest"

// Node builtins are typed by styleguard.node.d.ts (this repo does not install
// @types/node). We use import.meta.dirname (vitest node runtime) rather than the
// CommonJS __dirname, which is undefined under the ESM module setting.
function walk(dir: string): string[] {
  const out: string[] = []
  for (const name of readdirSync(dir)) {
    const p = join(dir, name)
    if (statSync(p).isDirectory()) out.push(...walk(p))
    else if (p.endsWith(".tsx")) out.push(p)
  }
  return out
}

// Flags inline style props whose value is a LITERAL px/number for spacing/size.
// Computed values (start * ROW_H, `${x}px`, animationDelay) do not match because
// their value is not a bare number/px literal.
const BANNED =
  /\b(margin|marginTop|marginBottom|marginLeft|marginRight|padding|paddingTop|paddingBottom|paddingLeft|paddingRight|gap|width|height)\s*:\s*("?\d+(px)?"?)\s*[,}]/

describe("no static inline spacing styles", () => {
  const files = walk(import.meta.dirname)
  for (const file of files) {
    it(`${file} uses tokens, not literal inline spacing`, () => {
      const src = readFileSync(file, "utf8")
      const styleBlocks = src.match(/style=\{\{[^}]*\}\}/g) ?? []
      const offenders = styleBlocks.filter((b: string) => BANNED.test(b))
      expect(offenders, `convert to a token class:\n${offenders.join("\n")}`).toHaveLength(0)
    })
  }
})
