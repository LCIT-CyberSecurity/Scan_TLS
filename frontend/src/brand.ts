// Product identity shown by the interface, and the per-browser preference keys that carry it.
export const PRODUCT_NAME = "Orion";

const STORAGE_PREFIX = "orion.";
// Keys written before the Orion rebranding: read once so nobody loses their language, theme or sidebar choice.
const LEGACY_STORAGE_PREFIX = "tls-scan.";

export const preferenceKey = (name: string) => STORAGE_PREFIX + name;

/** The stored preference, adopting (and removing) the pre-rebranding value when no new one exists. */
export function readPreference(name: string): string | null {
  try {
    const current = window.localStorage.getItem(preferenceKey(name));
    if (current !== null) return current;
    const legacy = window.localStorage.getItem(LEGACY_STORAGE_PREFIX + name);
    if (legacy !== null) {
      window.localStorage.setItem(preferenceKey(name), legacy);
      window.localStorage.removeItem(LEGACY_STORAGE_PREFIX + name);
    }
    return legacy;
  } catch {
    return null;
  }
}

export function writePreference(name: string, value: string) {
  try { window.localStorage.setItem(preferenceKey(name), value); } catch { /* storage can be disabled */ }
}
