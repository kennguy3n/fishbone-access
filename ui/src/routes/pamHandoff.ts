// Lightweight, in-tab handoff for the "request access to this target" flow.
// PamTargets stashes the chosen target id here, then routes to PamLeases, which
// reads and clears it on mount to pre-open the request form with that target
// already selected. Using sessionStorage (rather than router search params)
// keeps the handoff entirely inside this lane without touching the frozen
// router table, and degrades gracefully when storage is unavailable.
const KEY = "shieldnet.pam.requestTargetId";

export function stashRequestTarget(targetId: string): void {
  try {
    sessionStorage.setItem(KEY, targetId);
  } catch {
    // Private mode / storage disabled: the leases page simply opens without a
    // preselected target and the operator picks one from the dropdown.
  }
}

export function takeRequestTarget(): string | null {
  try {
    const v = sessionStorage.getItem(KEY);
    if (v) sessionStorage.removeItem(KEY);
    return v;
  } catch {
    return null;
  }
}
