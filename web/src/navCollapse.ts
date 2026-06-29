// Pure decision for the auto-collapsing top nav (see AppShell's useNavCollapse).
// When expanded, collapse the moment the topbar's content overflows its box
// (scrollWidth exceeds clientWidth) and remember the full width it needed. When
// collapsed, expand again only once the bar is at least that wide. Remembering the
// needed width gives hysteresis: the inline nav is display:none while collapsed (so
// it can't be re-measured live), and the +1px tolerance plus the ">= neededWidth"
// expand gate prevent flip-flopping at the exact boundary.

export interface NavCollapseState {
  collapsed: boolean
  // Bar width (px) at which the inline nav last overflowed — the width the bar must
  // regain before it's safe to expand again. Meaningless while expanded.
  neededWidth: number
}

// nextNavCollapse returns the next state for the given live bar measurements. It
// returns the SAME object reference when nothing changes, so callers can cheaply
// skip redundant re-renders with an identity check.
export function nextNavCollapse(
  state: NavCollapseState,
  barClientWidth: number,
  barScrollWidth: number,
): NavCollapseState {
  if (!state.collapsed) {
    if (barScrollWidth > barClientWidth + 1) {
      return { collapsed: true, neededWidth: barScrollWidth }
    }
    return state
  }
  if (barClientWidth >= state.neededWidth) {
    return { collapsed: false, neededWidth: state.neededWidth }
  }
  return state
}
