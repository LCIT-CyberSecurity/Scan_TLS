import { Activity, BarChart3, CalendarClock, ChevronDown, FileText, ListChecks, LogOut, Menu, Network, Settings, ShieldCheck, SlidersHorizontal, UserCircle } from "lucide-react";
import { useState, type ReactNode } from "react";
import { NavLink, Outlet } from "react-router-dom";
import type { Role } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { useI18n } from "../i18n";
import type { Messages } from "../i18n/en";

interface Item { to: string; icon: ReactNode; label: keyof Messages; min: Role }
// One sidebar for everybody; entries the role cannot use are hidden (the API enforces it anyway).
const ITEMS: Item[] = [
  { to: "/", icon: <BarChart3 />, label: "nav.dashboard", min: "AUDITOR" },
  { to: "/tasks", icon: <ListChecks />, label: "nav.tasks", min: "USER" },
  { to: "/scans", icon: <Activity />, label: "nav.scans", min: "USER" },
  { to: "/schedules", icon: <CalendarClock />, label: "nav.schedules", min: "USER" },
  { to: "/targets", icon: <Network />, label: "nav.targets", min: "USER" },
  { to: "/policies", icon: <SlidersHorizontal />, label: "nav.policies", min: "USER" },
  { to: "/reports", icon: <FileText />, label: "nav.reports", min: "AUDITOR" },
  { to: "/admin", icon: <ShieldCheck />, label: "nav.admin", min: "ADMIN" },
];

export default function Shell() {
  const { user, atLeast, logout } = useAuth();
  const { t } = useI18n();
  const [open, setOpen] = useState(false);
  const [menu, setMenu] = useState(false);
  return (
    <div className="min-h-screen lg:grid lg:grid-cols-[248px_1fr]">
      <aside className={`${open ? "block" : "hidden"} border-r border-border bg-[var(--rail)] lg:block`}>
        <div className="flex h-16 items-center gap-2.5 px-5">
          <img src="/lcit-mark.png" alt="" className="size-8" />
          <span className="text-base font-semibold tracking-tight">TLS Scan</span>
        </div>
        <nav className="space-y-0.5 px-3 pb-4" aria-label="Main">
          {ITEMS.filter((i) => atLeast(i.min)).map((i) => (
            <NavLink key={i.to} to={i.to} end={i.to === "/"} onClick={() => setOpen(false)}
              className={({ isActive }) => `flex items-center gap-3 rounded-sm px-3 py-2 text-sm font-medium [&_svg]:size-4 ${isActive ? "bg-primary-soft text-primary" : "text-fg-2 hover:bg-surface-2 hover:text-fg"}`}>
              {i.icon}<span>{t(i.label)}</span>
            </NavLink>
          ))}
        </nav>
      </aside>
      <div className="min-w-0">
        <header className="sticky top-0 z-30 flex h-16 items-center justify-between border-b border-border bg-[var(--chrome)] px-4 backdrop-blur lg:px-8">
          <button className="rounded-sm p-2 hover:bg-surface-2 lg:hidden" aria-label="Menu" onClick={() => setOpen(!open)}><Menu className="size-5" /></button>
          <div className="lg:flex-1" />
          <div className="relative">
            <button className="flex items-center gap-2 rounded-sm px-2 py-1.5 text-sm hover:bg-surface-2" onClick={() => setMenu(!menu)} aria-haspopup="menu">
              <UserCircle className="size-5 text-muted" />
              <span className="hidden text-left sm:block"><span className="block leading-4">{user?.display_name}</span><span className="block text-xs text-muted">{user?.role}</span></span>
              <ChevronDown className="size-4 text-muted" />
            </button>
            {menu && (
              <div role="menu" className="absolute right-0 mt-1 w-52 rounded-lg border border-border bg-surface p-1 shadow-md" onClick={() => setMenu(false)}>
                <NavLink role="menuitem" to="/preferences" className="flex items-center gap-2 rounded-sm px-3 py-2 text-sm hover:bg-surface-2"><Settings className="size-4" />{t("nav.preferences")}</NavLink>
                <button role="menuitem" className="flex w-full items-center gap-2 rounded-sm px-3 py-2 text-sm hover:bg-surface-2" onClick={() => void logout()}><LogOut className="size-4" />{t("nav.logout")}</button>
              </div>
            )}
          </div>
        </header>
        <main className="mx-auto max-w-[1400px] px-4 py-6 lg:px-8 lg:py-8"><Outlet /></main>
      </div>
    </div>
  );
}
