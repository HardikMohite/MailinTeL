/**
 * Single source of truth for where the bearer token lives on the client.
 *
 * Uses sessionStorage (not localStorage) — a token that lived indefinitely
 * in localStorage would survive on a shared/kiosk machine long after the
 * person walked away. sessionStorage is cleared when the tab/browser closes,
 * which is the right tradeoff for a forensic-investigation tool. AuthContext
 * additionally mirrors the token in React state for the lifetime of the tab
 * so reads don't need to hit storage on every render.
 *
 * This stays the one place that knows the storage key — always go through
 * `getAuthToken` / `setAuthToken` / `clearAuthToken` rather than touching
 * sessionStorage directly elsewhere.
 */
const TOKEN_STORAGE_KEY = 'mailintel_access_token';

export function getAuthToken(): string | null {
  try {
    return sessionStorage.getItem(TOKEN_STORAGE_KEY);
  } catch {
    // Storage can throw in locked-down browser contexts (private mode, etc.)
    return null;
  }
}

export function setAuthToken(token: string): void {
  try {
    sessionStorage.setItem(TOKEN_STORAGE_KEY, token);
  } catch {
    // Non-fatal: the app still works for the current tab, just won't
    // survive a reload if storage is unavailable.
  }
}

export function clearAuthToken(): void {
  try {
    sessionStorage.removeItem(TOKEN_STORAGE_KEY);
  } catch {
    // no-op
  }
}
