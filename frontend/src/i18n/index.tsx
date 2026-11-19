import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from "react";
import { readPreference, writePreference } from "../brand";
import { de } from "./de";
import { en, type Messages } from "./en";
import { fr } from "./fr";

export type Locale = "fr" | "en" | "de";
export const LOCALES: Locale[] = ["fr", "en", "de"];
const dictionaries: Record<Locale, Messages> = { en, fr, de };
const KEY = "locale";

/** Explicit user choice (server profile or local storage) wins; otherwise the browser language; otherwise English. */
export function detectLocale(preferred?: string | null): Locale {
  if (preferred && LOCALES.includes(preferred as Locale)) return preferred as Locale;
  const stored = readPreference(KEY);
  if (stored && LOCALES.includes(stored as Locale)) return stored as Locale;
  const browser = (navigator.languages?.[0] ?? navigator.language ?? "en").slice(0, 2).toLowerCase();
  return LOCALES.includes(browser as Locale) ? (browser as Locale) : "en";
}

interface I18n { locale: Locale; setLocale: (l: Locale) => void; t: (key: keyof Messages, vars?: Record<string, string | number>) => string }
const Ctx = createContext<I18n>({ locale: "en", setLocale: () => undefined, t: (k) => String(k) });

export function I18nProvider({ initial, children }: { initial?: string | null; children: ReactNode }) {
  const [locale, setLocaleState] = useState<Locale>(() => detectLocale(initial));
  const setLocale = useCallback((l: Locale) => {
    setLocaleState(l);
    writePreference(KEY, l);
    document.documentElement.lang = l;
  }, []);
  const t = useCallback((key: keyof Messages, vars?: Record<string, string | number>) => {
    let text = dictionaries[locale][key] ?? en[key] ?? String(key);
    for (const [name, value] of Object.entries(vars ?? {})) text = text.replace(`{${name}}`, String(value));
    return text;
  }, [locale]);
  const value = useMemo(() => ({ locale, setLocale, t }), [locale, setLocale, t]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export const useI18n = () => useContext(Ctx);
