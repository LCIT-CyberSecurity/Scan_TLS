import { Check, ChevronDown, LogOut, Monitor, Moon, Palette, Settings, Sun } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import type { User } from "../api/types";
import { useI18n } from "../i18n";
import { APPEARANCES, THEMES, applyAppearance, applyTheme, readAppearance, readTheme, type Appearance, type ThemeId } from "../theme";

export function initials(name: string | undefined): string {
  return (name ?? "?").split(/\s+/).filter(Boolean).map((part) => part[0]).join("").slice(0, 2).toUpperCase();
}

const APPEARANCE_ICON = { light: Sun, dark: Moon, system: Monitor } as const;

/** Account menu laid out like LCIT-Sign's: identity, appearance (light/dark/system), interface style, sign-out. */
export default function UserMenu({ user, onSignOut }: { user: User; onSignOut: () => void }) {
  const { t } = useI18n();
  const menu = useRef<HTMLDetailsElement>(null);
  const [theme, setTheme] = useState<ThemeId>(readTheme);
  const [appearance, setAppearance] = useState<Appearance>(readAppearance);
  const close = () => menu.current?.removeAttribute("open");

  // Mirrored to the server profile on a best-effort basis; the local choice applies immediately.
  const persist = (body: Record<string, string>) => { void api("/auth/preferences", { method: "PATCH", body }).catch(() => undefined); };
  const pickTheme = (next: ThemeId) => { setTheme(next); applyTheme(next); persist({ palette: next }); };
  const pickAppearance = (next: Appearance) => { setAppearance(next); applyAppearance(next); persist({ theme: next }); };

  // Follow the operating system while "system" is selected.
  useEffect(() => {
    if (appearance !== "system" || !window.matchMedia) return;
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const on = () => applyAppearance("system");
    media.addEventListener("change", on);
    return () => media.removeEventListener("change", on);
  }, [appearance]);

  // Close on outside click and Escape, like a native menu.
  useEffect(() => {
    const onPointer = (e: MouseEvent) => { if (menu.current?.open && !menu.current.contains(e.target as Node)) close(); };
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") close(); };
    document.addEventListener("mousedown", onPointer);
    document.addEventListener("keydown", onKey);
    return () => { document.removeEventListener("mousedown", onPointer); document.removeEventListener("keydown", onKey); };
  }, []);

  return (
    <details className="user-menu" ref={menu}>
      <summary aria-label={t("menu.account")} aria-haspopup="menu">
        <span className="avatar">{initials(user.display_name)}</span>
        <span className="user-name">{user.display_name}<span>{user.role}</span></span>
        <ChevronDown size={15} aria-hidden="true" />
      </summary>
      <div className="user-menu-panel" role="menu">
        <div className="user-menu-head">
          <span className="avatar">{initials(user.display_name)}</span>
          <span><strong>{user.display_name}</strong><small>{user.email || user.role}</small></span>
        </div>
        <div className="user-menu-section">
          <span className="user-menu-label"><Palette size={13} aria-hidden="true" /> {t("menu.settings")}</span>
          <div className="appearance-row" role="group" aria-label={t("pref.appearance")}>
            {APPEARANCES.map((a) => {
              const Icon = APPEARANCE_ICON[a];
              return <button key={a} type="button" aria-pressed={appearance === a} className={`appearance-option${appearance === a ? " active" : ""}`} onClick={() => pickAppearance(a)}><Icon aria-hidden="true" size={14} /> {t(`pref.${a}` as never)}</button>;
            })}
          </div>
          {THEMES.map((id) => (
            <button key={id} type="button" aria-pressed={theme === id} className={`style-option${theme === id ? " active" : ""}`} onClick={() => pickTheme(id)}>
              <span className={`style-swatch ${id}`} />
              <span className="style-option-text"><strong>{t(`theme.${id}` as never)}</strong><small>{t(`theme.${id}.sub` as never)}</small></span>
              {theme === id ? <Check size={15} aria-hidden="true" /> : null}
            </button>
          ))}
        </div>
        <div className="user-menu-foot">
          <Link to="/preferences" role="menuitem" onClick={close}><Settings size={15} aria-hidden="true" /> {t("nav.preferences")}</Link>
          <button type="button" role="menuitem" className="danger" onClick={() => { close(); onSignOut(); }}><LogOut size={15} aria-hidden="true" /> {t("nav.logout")}</button>
        </div>
      </div>
    </details>
  );
}
