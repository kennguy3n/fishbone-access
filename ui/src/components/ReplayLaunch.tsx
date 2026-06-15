import { FormattedMessage } from "react-intl";
import { useNavigate } from "@tanstack/react-router";

// ReplayLaunch is the small affordance that opens the flagship session-replay
// player for a given PAM session from elsewhere in the console (e.g. the live
// sessions list). It is intentionally tiny and side-effect-free so it can be
// dropped into existing screens without restructuring them. The replay player
// route is permission-gated server-side (pam.session.read); this is purely a
// navigation shortcut.
export function ReplayLaunch({
  sessionId,
  variant = "ghost",
}: {
  sessionId: string;
  /** "ghost" for inline placement (default), "link" for a text-only affordance. */
  variant?: "ghost" | "link";
}) {
  const navigate = useNavigate();
  const open = () =>
    navigate({
      to: "/pam/recordings/$recordingId",
      params: { recordingId: sessionId },
    });

  if (variant === "link") {
    return (
      <button
        type="button"
        className="btn btn--link btn--sm"
        onClick={open}
      >
        <FormattedMessage defaultMessage="Open replay" />
      </button>
    );
  }
  return (
    <button type="button" className="btn btn--ghost" onClick={open}>
      <FormattedMessage defaultMessage="Open replay player" />
    </button>
  );
}
