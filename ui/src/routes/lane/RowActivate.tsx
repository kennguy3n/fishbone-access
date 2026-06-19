import type { CSSProperties, ReactNode } from "react";

// The shared WS0 DataTable wires row interaction through a `<tr onClick>` only,
// which pointer users can click but keyboard and screen-reader users cannot
// reach or operate. Until that lands in the shared kit (see "WS0 follow-up" in
// the PR), each list screen in this lane renders its primary cell through this
// activator: a real, focusable, labelled button that opens the row. The row's
// onClick stays for pointer users, so the whole row remains a click target;
// this only adds the missing keyboard path and an accessible name.
const resetStyle: CSSProperties = {
  background: "none",
  border: "none",
  padding: 0,
  margin: 0,
  font: "inherit",
  color: "inherit",
  textAlign: "left",
  cursor: "pointer",
  display: "flex",
  flexDirection: "column",
  gap: 2,
  width: "100%",
};

export function RowActivate({
  label,
  onActivate,
  children,
}: {
  /** Accessible name announced for the control (e.g. "Open request for app:salesforce"). */
  label: string;
  onActivate: () => void;
  children: ReactNode;
}) {
  return (
    <button
      type="button"
      style={resetStyle}
      aria-label={label}
      onClick={(e) => {
        // The row's onClick would otherwise fire too; route activation through
        // this control alone so the behaviour is identical for pointer and
        // keyboard and never double-handled.
        e.stopPropagation();
        onActivate();
      }}
    >
      {children}
    </button>
  );
}
