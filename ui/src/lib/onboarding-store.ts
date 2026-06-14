// Day-1 onboarding progress — client-side persistence.
//
// The control plane has no server-side "setup progress" resource, so a
// half-finished wizard is resumed from the operator's own browser. Progress is
// keyed by the bound tenant id (from /me) so two workspaces opened in the same
// browser don't clobber each other's progress, and so signing into a different
// tenant starts fresh.
//
// IMPORTANT: this is browser-local only — it tracks *which guidance steps the
// operator has walked through*, NOT the authoritative setup state. The actual
// artifacts (connectors, policies, members) live server-side; the wizard reads
// those live (useConnectors / usePolicies / useRbacMembers) to reflect reality
// and never trusts this store for whether a thing truly exists. Clearing
// browser storage only forgets the walkthrough position, never any real setup.

import { useCallback, useState } from "react";

export type OnboardingStepId =
  | "welcome"
  | "connect"
  | "policy"
  | "invite"
  | "done";

// The ordered wizard flow. Exported so the wizard and the stepper render from a
// single source of truth.
export const ONBOARDING_STEPS: OnboardingStepId[] = [
  "welcome",
  "connect",
  "policy",
  "invite",
  "done",
];

export interface OnboardingProgress {
  /** Schema version, so a future shape change can migrate/discard cleanly. */
  version: 1;
  /** The step the operator was last on (resume point). */
  lastStep: OnboardingStepId;
  /** Steps the operator has explicitly advanced past. */
  completed: OnboardingStepId[];
  /** Operator-chosen friendly name for the workspace (display-only, local). */
  workspaceName: string;
  /** Set once the operator reaches and acknowledges the final summary. */
  finished: boolean;
  /** Set when the operator dismisses the dashboard "finish setup" nudge. */
  nudgeDismissed: boolean;
}

const STORAGE_PREFIX = "sng-onboarding:";

function defaults(): OnboardingProgress {
  return {
    version: 1,
    lastStep: "welcome",
    completed: [],
    workspaceName: "",
    finished: false,
    nudgeDismissed: false,
  };
}

function keyFor(tenantId: string): string {
  return `${STORAGE_PREFIX}${tenantId}`;
}

// localStorage can throw (private mode, quota, disabled) — never let a storage
// failure break the wizard. A read failure yields fresh defaults; a write
// failure is swallowed (progress simply won't persist across reloads).
const STEP_SET = new Set<string>(ONBOARDING_STEPS);

function isStep(value: unknown): value is OnboardingStepId {
  return typeof value === "string" && STEP_SET.has(value);
}

export function loadProgress(tenantId: string): OnboardingProgress {
  if (!tenantId) return defaults();
  try {
    const raw = localStorage.getItem(keyFor(tenantId));
    if (!raw) return defaults();
    const parsed = JSON.parse(raw) as Partial<OnboardingProgress>;
    if (parsed.version !== 1) return defaults();
    // Coerce each field to its expected type rather than spreading `parsed`
    // verbatim: a tampered or partially-written blob could carry a non-array
    // `completed` or an unknown `lastStep`, and a consumer doing
    // `completed.includes(...)` / `ONBOARDING_STEPS.indexOf(lastStep)` must not
    // crash or jump to a nonexistent step. Unknown values fall back to defaults.
    const base = defaults();
    return {
      version: 1,
      lastStep: isStep(parsed.lastStep) ? parsed.lastStep : base.lastStep,
      completed: Array.isArray(parsed.completed)
        ? parsed.completed.filter(isStep)
        : base.completed,
      workspaceName:
        typeof parsed.workspaceName === "string"
          ? parsed.workspaceName
          : base.workspaceName,
      finished:
        typeof parsed.finished === "boolean" ? parsed.finished : base.finished,
      nudgeDismissed:
        typeof parsed.nudgeDismissed === "boolean"
          ? parsed.nudgeDismissed
          : base.nudgeDismissed,
    };
  } catch {
    return defaults();
  }
}

function saveProgress(tenantId: string, value: OnboardingProgress): void {
  if (!tenantId) return;
  try {
    localStorage.setItem(keyFor(tenantId), JSON.stringify(value));
  } catch {
    // Best-effort: persistence is a convenience, not a correctness requirement.
  }
}

/**
 * useOnboardingProgress is the wizard's persisted state hook. It hydrates from
 * localStorage for the given tenant and writes through on every update. The
 * tenant id is part of the lazy initializer so a different bound tenant
 * resolves to its own progress.
 */
// A progress update is either a flat patch, or a function of the previous state
// (for updates that derive fields from the current value, e.g. appending to
// `completed`). The functional form is computed inside the setState updater so
// it always reads the latest state and can't clobber a concurrent update.
export type OnboardingPatch =
  | Partial<OnboardingProgress>
  | ((prev: OnboardingProgress) => Partial<OnboardingProgress>);

export type OnboardingUpdate = (patch: OnboardingPatch) => void;

export function useOnboardingProgress(
  tenantId: string,
): [OnboardingProgress, OnboardingUpdate] {
  const [state, setState] = useState<OnboardingProgress>(() =>
    loadProgress(tenantId),
  );

  const update = useCallback<OnboardingUpdate>(
    (patch) => {
      setState((prev) => {
        const resolved = typeof patch === "function" ? patch(prev) : patch;
        const next = { ...prev, ...resolved };
        saveProgress(tenantId, next);
        return next;
      });
    },
    [tenantId],
  );

  return [state, update];
}

/** markComplete returns a new completed list with `step` added (idempotent). */
export function withCompleted(
  completed: OnboardingStepId[],
  step: OnboardingStepId,
): OnboardingStepId[] {
  return completed.includes(step) ? completed : [...completed, step];
}
