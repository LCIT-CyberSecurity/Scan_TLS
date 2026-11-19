// Appearance (light/dark/system) and palette are per-browser conveniences, mirrored to the user's
// profile on the server when signed in. Same model as LCIT-Sign.
import { readPreference, writePreference } from "./brand";

export type ThemeId = "violet" | "blue" | "aurora" | "azure" | "studio";
export type Appearance = "light" | "dark" | "system";
export const THEMES: ThemeId[] = ["violet", "blue", "aurora", "azure", "studio"];
export const APPEARANCES: Appearance[] = ["light", "dark", "system"];

export const readTheme = (): ThemeId => { const v = readPreference("theme"); return THEMES.includes(v as ThemeId) ? (v as ThemeId) : "violet"; };
export const readAppearance = (): Appearance => { const v = readPreference("appearance"); return APPEARANCES.includes(v as Appearance) ? (v as Appearance) : "system"; };

export function applyTheme(theme: ThemeId) {
  const root = document.documentElement;
  if (theme === "blue") root.removeAttribute("data-theme"); else root.setAttribute("data-theme", theme);
  writePreference("theme", theme);
}

export function applyAppearance(appearance: Appearance) {
  const dark = appearance === "dark" || (appearance === "system" && window.matchMedia?.("(prefers-color-scheme: dark)").matches);
  const root = document.documentElement;
  if (dark) root.setAttribute("data-appearance", "dark"); else root.removeAttribute("data-appearance");
  writePreference("appearance", appearance);
}

export function applyStoredPreferences() { applyTheme(readTheme()); applyAppearance(readAppearance()); }
