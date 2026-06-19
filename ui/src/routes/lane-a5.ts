import { useLayoutEffect } from "react";
import "./lane-a5.css";

/**
 * Scopes Lane A5's accessibility overrides (see lane-a5.css) to this lane's
 * screens only. The router mounts exactly one route inside `.content` at a
 * time, so tagging that container while an owned route is mounted — and
 * untagging it on unmount — keeps the overrides off sibling lanes' screens
 * and off the frozen app shell (sidebar / topbar live outside `.content`).
 */
export function useLaneA5Scope(): void {
  useLayoutEffect(() => {
    const content = document.querySelector(".content");
    if (!content) return;
    content.classList.add("lane-a5");
    return () => content.classList.remove("lane-a5");
  }, []);
}
