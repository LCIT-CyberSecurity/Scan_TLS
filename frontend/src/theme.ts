// Appearance (light/dark/system) and palette are per-browser conveniences, mirrored to the user's
// profile on the server when signed in. Same model as LCIT-Sign.
export type ThemeId = "violet" | "blue" | "aurora" | "azure" | "studio";
export type Appearance = "light" | "dark" | "system";
export const THEMES: ThemeId[] = ["violet", "blue", "aurora", "azure", "studio"];
export const APPEARANCES: Appearance[] = ["light", "dark", "system"];

const read = (key: string) => { try { return window.localStorage.getItem(key); } catch { return null; } };
const write = (key: string, value: string) => { try { window.localStorage.setItem(key, value); } catch { /* storage refused */ } };

export const readTheme = (): ThemeId => { const v = read("tls-scan.theme"); return THEMES.includes(v as ThemeId) ? (v as ThemeId) : "violet"; };
export const readAppearance = (): Appearance => { const v = read("tls-scan.appearance"); return APPEARANCES.includes(v as Appearance) ? (v as Appearance) : "system"; };

export function applyTheme(theme: ThemeId) {
  const root = document.documentElement;
  if (theme === "blue") root.removeAttribute("data-theme"); else root.setAttribute("data-theme", theme);
  write("tls-scan.theme", theme);
}

export function applyAppearance(appearance: Appearance) {
  const dark = appearance === "dark" || (appearance === "system" && window.matchMedia?.("(prefers-color-scheme: dark)").matches);
  const root = document.documentElement;
  if (dark) root.setAttribute("data-appearance", "dark"); else root.removeAttribute("data-appearance");
  write("tls-scan.appearance", appearance);
}

export function applyStoredPreferences() { applyTheme(readTheme()); applyAppearance(readAppearance()); }
