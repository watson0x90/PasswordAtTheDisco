// wrap — pure, deterministic greedy word-wrap for the static help diagrams.
//
// Splits a short caption into balanced lines no wider than `max` characters,
// breaking only on spaces. It NEVER drops words: every input word appears in the
// output (this is the regression guard for the silent-truncation bug that dropped
// "clusters" from the Analysis node). If a layout needs a hard line cap, the
// CALLER applies `.slice(0, n)` on the result — the shared function itself always
// wraps the whole string. Pure string layout (no DOM measurement) — test-friendly.
export function wrap(text: string, max = 22): string[] {
  const words = text.split(" ")
  const lines: string[] = []
  let cur = ""
  for (const w of words) {
    if ((cur + " " + w).trim().length > max && cur) {
      lines.push(cur)
      cur = w
    } else {
      cur = (cur + " " + w).trim()
    }
  }
  if (cur) lines.push(cur)
  return lines
}
