import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { api, setCsrf } from "../api/client";
import type { Role, User } from "../api/types";
import { useI18n, LOCALES, type Locale } from "../i18n";
import { THEMES, applyAppearance, applyTheme, type Appearance, type ThemeId } from "../theme";

const RANK: Record<Role, number> = { AUDITOR: 1, USER: 2, OPERATOR: 3, ADMIN: 4 };

interface AuthState {
  user: User | null; loading: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>; refresh: () => Promise<void>;
  atLeast: (role: Role) => boolean;
}
const Ctx = createContext<AuthState>(null as unknown as AuthState);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const { setLocale } = useI18n();

  const apply = useCallback((data: { user: User; csrf_token: string }) => {
    setCsrf(data.csrf_token);
    setUser(data.user);
    // A language chosen by the user is stored on their profile and overrides browser detection.
    // Display preferences saved on the profile follow the user across browsers.
    if (data.user.theme) applyAppearance(data.user.theme as Appearance);
    if (THEMES.includes(data.user.palette as ThemeId)) applyTheme(data.user.palette as ThemeId);
    if (data.user.locale && LOCALES.includes(data.user.locale as Locale)) setLocale(data.user.locale as Locale);
  }, [setLocale]);

  const refresh = useCallback(async () => {
    try { apply(await api<{ user: User; csrf_token: string }>("/auth/me")); } catch { setUser(null); } finally { setLoading(false); }
  }, [apply]);

  useEffect(() => { void refresh(); }, [refresh]);
  useEffect(() => { const h = () => setUser(null); window.addEventListener("tls-scan:unauthorized", h); return () => window.removeEventListener("tls-scan:unauthorized", h); }, []);

  const login = useCallback(async (username: string, password: string) => {
    apply(await api("/auth/login", { method: "POST", body: { username, password } }));
  }, [apply]);
  const logout = useCallback(async () => { await api("/auth/logout", { method: "POST" }); setUser(null); }, []);
  const atLeast = useCallback((role: Role) => !!user && RANK[user.role] >= RANK[role], [user]);

  return <Ctx.Provider value={{ user, loading, login, logout, refresh, atLeast }}>{children}</Ctx.Provider>;
}

export const useAuth = () => useContext(Ctx);
