export type Crumb = { username: string; domain: string }

// pushCrumb appends c unless it equals the current tail (avoids self-pivot dupes).
export function pushCrumb(trail: Crumb[], c: Crumb): Crumb[] {
  const tail = trail[trail.length - 1]
  if (tail && tail.username === c.username && tail.domain === c.domain) return trail
  return [...trail, c]
}

// popCrumb removes the last crumb but keeps the root (depth never drops below 1).
export function popCrumb(trail: Crumb[]): Crumb[] {
  return trail.length > 1 ? trail.slice(0, -1) : trail
}

// jumpCrumb truncates the trail to the crumb at index (inclusive); out-of-range = no-op.
export function jumpCrumb(trail: Crumb[], index: number): Crumb[] {
  return index >= 0 && index < trail.length ? trail.slice(0, index + 1) : trail
}
