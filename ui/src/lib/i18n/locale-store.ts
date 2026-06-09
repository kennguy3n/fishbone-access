// Locale persistence + the framework-agnostic accessor the axios
// layer uses. Kept separate from the React context so non-React code
// (the http-client request interceptor) can read the active locale
// without importing React or the provider.

import { DEFAULT_LOCALE, type Locale, matchLocale, resolveLocale } from "./locales";

const STORAGE_KEY = "sng.locale";

// In-memory source of truth for the request layer. It is the language the user
// is actually seeing this session: seeded lazily from persistence/the browser
// and updated synchronously by storeLocale on every change. Keeping it in
// memory means the axios interceptor never reads localStorage per request, and
// — crucially — it stays correct even when persistence fails (e.g. Safari
// private mode quota), so the Accept-Language header can't drift from the UI.
let activeLocale: Locale | null = null;

export function getStoredLocale(): Locale | null {
  if (typeof localStorage === "undefined") return null;
  const raw = localStorage.getItem(STORAGE_KEY);
  if (!raw) return null;
  // Use matchLocale (not resolveLocale): a stale/garbage persisted value
  // must yield null so detectInitialLocale falls through to browser
  // language detection, rather than being silently treated as an
  // explicit "English" choice.
  return matchLocale(raw);
}

export function storeLocale(locale: Locale): void {
  // Update the in-memory active locale first, unconditionally: this is what the
  // request layer reads, so it must reflect the user's choice even if the
  // persistence below is unavailable or throws.
  activeLocale = locale;
  if (typeof localStorage === "undefined") return;
  // Guard the write like setTheme does: a restricted or full localStorage
  // (e.g. Safari private mode quota) throws, and a failure to persist the
  // preference must not break the in-session locale change.
  try {
    localStorage.setItem(STORAGE_KEY, locale);
  } catch {
    /* persistence is best-effort; the in-memory locale still applies */
  }
}

// detectInitialLocale picks the startup locale: an explicit stored
// choice wins; otherwise the browser's preferred language is mapped
// onto the supported set; otherwise English.
export function detectInitialLocale(): Locale {
  const stored = getStoredLocale();
  if (stored) return stored;
  if (typeof navigator !== "undefined") {
    const nav = navigator.languages?.[0] ?? navigator.language;
    return resolveLocale(nav);
  }
  return DEFAULT_LOCALE;
}

// getActiveLocale is the accessor the axios interceptor calls to stamp
// Accept-Language on every API request, so the API negotiates the same
// language the operator selected in the UI. It resolves once (from the stored
// choice / browser, via detectInitialLocale) and then serves the in-memory
// value, which storeLocale keeps in sync on every change — so it neither
// re-reads localStorage per request nor disagrees with the in-session UI
// locale when a persist fails.
export function getActiveLocale(): Locale {
  if (activeLocale === null) {
    activeLocale = detectInitialLocale();
  }
  return activeLocale;
}
