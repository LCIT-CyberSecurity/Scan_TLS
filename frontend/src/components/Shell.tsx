import { Activity, BarChart3, CalendarClock, ChevronRight, FileText, ListChecks, Menu, Network, ShieldCheck, SlidersHorizontal } from "lucide-react";
import { Fragment, useState, type ReactNode } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import type { Role } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { useI18n } from "../i18n";
import type { Messages } from "../i18n/en";
import { SidebarActivity } from "./SidebarActivity";
import UserMenu from "./UserMenu";

interface Item { to: string; icon: ReactNode; label: keyof Messages; min: Role }
interface Section { heading: keyof Messages; items: Item[] }
// One sidebar for everybody; entries the role cannot use are hidden (the API enforces it anyway).
const SECTIONS: Section[] = [
  { heading: "nav.section.workspace", items: [
    { to: "/", icon: <BarChart3 size={22} />, label: "nav.dashboard", min: "AUDITOR" },
    { to: "/tasks", icon: <ListChecks size={22} />, label: "nav.tasks", min: "USER" },
  ] },
  { heading: "nav.section.scanning", items: [
    { to: "/scans", icon: <Activity size={22} />, label: "nav.scans", min: "USER" },
    { to: "/schedules", icon: <CalendarClock size={22} />, label: "nav.schedules", min: "USER" },
    { to: "/targets", icon: <Network size={22} />, label: "nav.targets", min: "USER" },
    { to: "/policies", icon: <SlidersHorizontal size={22} />, label: "nav.policies", min: "USER" },
  ] },
  { heading: "nav.section.results", items: [{ to: "/reports", icon: <FileText size={22} />, label: "nav.reports", min: "AUDITOR" }] },
  { heading: "nav.section.admin", items: [{ to: "/admin", icon: <ShieldCheck size={22} />, label: "nav.admin", min: "ADMIN" }] },
];
const ALL = SECTIONS.flatMap((s) => s.items).concat([{ to: "/preferences", icon: null, label: "nav.preferences", min: "AUDITOR" }]);

/** The breadcrumb's last segment: the navigation entry owning the current path (the scan detail belongs to Scans). */
function sectionLabel(pathname: string): keyof Messages {
  const match = ALL.filter((i) => i.to !== "/" && pathname.startsWith(i.to)).sort((a, b) => b.to.length - a.to.length)[0];
  return match?.label ?? "nav.dashboard";
}

export default function Shell() {
  const { user, atLeast, logout } = useAuth();
  const { t } = useI18n();
  const { pathname } = useLocation();
  const [open, setOpen] = useState(false);
  const close = () => setOpen(false);
  return (
    <div className="app-shell">
      <aside className={`sidebar${open ? " sidebar--open" : ""}`}>
        <div className="brand">
          <img className="brand-logo" src="/lcit-mark.png" alt="LCIT" />
          <div><span>TLS Scan</span><small>{t("brand.tagline")}</small></div>
        </div>
        <nav aria-label="Main">
          {SECTIONS.map((section) => ({ ...section, items: section.items.filter((i) => atLeast(i.min)) })).filter((section) => section.items.length).map((section) => (
            <Fragment key={section.heading}>
              <div className="nav-group">
                <div className="nav-heading">{t(section.heading)}</div>
                {section.items.map((i) => (
                  <NavLink key={i.to} to={i.to} end={i.to === "/"} onClick={close} className={({ isActive }) => `nav-link${isActive ? " active" : ""}`}>{i.icon}<span>{t(i.label)}</span></NavLink>
                ))}
              </div>
            </Fragment>
          ))}
        </nav>
        <SidebarActivity />
        <div className="sidebar-footer">
          <strong><ShieldCheck size={13} aria-hidden="true" /> LCIT Cybersecurity</strong>
          {t("brand.signedInAs", { role: (user?.role ?? "").toLowerCase() })}
        </div>
      </aside>
      {open && <div className="sidebar-scrim" onClick={close} aria-hidden="true" />}
      <div className="page">
        <header className="topbar">
          <div className="crumb">
            <button className="button button--ghost button--sm mobile-menu" onClick={() => setOpen(true)} aria-label={t("nav.openMenu")}><Menu size={18} /></button>
            <span>TLS Scan</span><ChevronRight size={14} aria-hidden="true" /><strong>{t(sectionLabel(pathname))}</strong>
          </div>
          <div className="top-actions">{user && <UserMenu user={user} onSignOut={() => void logout()} />}</div>
        </header>
        <main className={`app-main${pathname === "/" ? " app-main--wide" : ""}`}><Outlet /></main>
      </div>
    </div>
  );
}
