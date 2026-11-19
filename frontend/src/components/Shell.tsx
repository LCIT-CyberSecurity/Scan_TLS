import { Activity, BarChart3, CalendarClock, ChevronDown, ChevronRight, ListChecks, Map as MapIcon, Menu, Network, PanelLeftClose, PanelLeftOpen, ShieldCheck, SlidersHorizontal } from "lucide-react";
import { useEffect, useRef, useState, type ReactNode } from "react";
import { Link, Outlet, useLocation } from "react-router-dom";
import type { Role } from "../api/types";
import { PRODUCT_NAME, readPreference, writePreference } from "../brand";
import { useAuth } from "../auth/AuthContext";
import { useI18n } from "../i18n";
import type { Messages } from "../i18n/en";
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
    { to: "/scans", icon: <Activity size={22} />, label: "nav.scans", min: "AUDITOR" },
    { to: "/scans/map", icon: <MapIcon size={22} />, label: "nav.map", min: "USER" },
    { to: "/schedules", icon: <CalendarClock size={22} />, label: "nav.schedules", min: "USER" },
    { to: "/targets", icon: <Network size={22} />, label: "nav.targets", min: "USER" },
    { to: "/policies", icon: <SlidersHorizontal size={22} />, label: "nav.policies", min: "USER" },
  ] },
  { heading: "nav.section.admin", items: [{ to: "/admin", icon: <ShieldCheck size={22} />, label: "nav.admin", min: "ADMIN" }] },
];
const ALL = SECTIONS.flatMap((s) => s.items).concat([{ to: "/preferences", icon: null, label: "nav.preferences", min: "AUDITOR" }]);

/** The breadcrumb's last segment: the navigation entry owning the current path (the scan detail belongs to Scans). */
function sectionLabel(pathname: string): keyof Messages {
  const match = ALL.filter((i) => i.to !== "/" && pathname.startsWith(i.to)).sort((a, b) => b.to.length - a.to.length)[0];
  return match?.label ?? "nav.dashboard";
}

function pathMatches(pathname: string, route: string): boolean {
  return route === "/" ? pathname === "/" : pathname === route || pathname.startsWith(`${route}/`);
}

function activeSection(pathname: string): keyof Messages | null {
  const active = SECTIONS.find((section) => section.items.some((item) =>
    pathMatches(pathname, item.to) && !(item.to === "/scans" && pathname === "/scans/map")));
  return active?.heading ?? null;
}

function readCompactPreference(): boolean {
  return readPreference("sidebar-compact") === "true";
}

export default function Shell() {
  const { user, atLeast, logout } = useAuth();
  const { t } = useI18n();
  const { pathname } = useLocation();
  const [open, setOpen] = useState(false);
  const [compact, setCompact] = useState(readCompactPreference);
  const [expandedSection, setExpandedSection] = useState(() => activeSection(pathname));
  const mobileMenuButton = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    writePreference("sidebar-compact", String(compact));
  }, [compact]);
  useEffect(() => { setExpandedSection(activeSection(pathname)); }, [pathname]);
  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if (event.key !== "Escape") return;
      if (open) {
        setOpen(false);
        mobileMenuButton.current?.focus();
      }
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [open]);
  const close = () => setOpen(false);
  return (
    <div className="app-shell">
      <aside id="main-sidebar" className={`sidebar${compact ? " sidebar--compact" : ""}${open ? " sidebar--open" : ""}`}>
        <div className="brand">
          <img className="brand-logo" src="/lcit-mark.png" alt="LCIT" />
          <div className="brand-title"><span>{PRODUCT_NAME}</span><small>{t("brand.tagline")}</small></div>
          <button type="button" className="sidebar-collapse" aria-label={t(compact ? "nav.expandSidebar" : "nav.collapseSidebar")} title={t(compact ? "nav.expandSidebar" : "nav.collapseSidebar")} aria-expanded={!compact} aria-controls="main-sidebar" onClick={() => setCompact((value) => !value)}>
            {compact ? <PanelLeftOpen size={18} aria-hidden="true" /> : <PanelLeftClose size={18} aria-hidden="true" />}
          </button>
        </div>
        <nav id="main-sidebar-navigation" aria-label="Main">
          {SECTIONS.map((section) => ({ ...section, items: section.items.filter((i) => atLeast(i.min)) })).filter((section) => section.items.length).map((section) => {
            const expanded = expandedSection === section.heading;
            const groupId = `nav-group-${String(section.heading).replace(/[^a-z0-9]+/gi, "-").toLowerCase()}`;
            return <div className="nav-group" key={section.heading}>
              <button type="button" className={`nav-heading-toggle${expanded ? " expanded" : ""}`} aria-label={t(section.heading)} title={t(section.heading)} aria-expanded={expanded} aria-controls={groupId} onClick={() => setExpandedSection(expanded ? null : section.heading)}>
                <span className="nav-heading-icon" aria-hidden="true">{section.items[0].icon}</span>
                <span className="nav-heading-label">{t(section.heading)}</span>
                <ChevronDown size={16} aria-hidden="true" />
              </button>
              <div id={groupId} className="nav-group-items" hidden={!expanded}>
                {section.items.map((i) => {
                  const active = pathMatches(pathname, i.to) && !(i.to === "/scans" && pathname === "/scans/map");
                  return <Link key={i.to} to={i.to} onClick={close} aria-label={t(i.label)} aria-current={active ? "page" : undefined} title={t(i.label)} className={`nav-link${active ? " active" : ""}`}>{i.icon}<span>{t(i.label)}</span></Link>;
                })}
              </div>
            </div>;
          })}
        </nav>
        <div className="sidebar-footer">
          <strong><ShieldCheck size={13} aria-hidden="true" /> LCIT Cybersecurity</strong>
          {t("brand.signedInAs", { role: (user?.role ?? "").toLowerCase() })}
        </div>
      </aside>
      {open && <div className="sidebar-scrim" onClick={close} aria-hidden="true" />}
      <div className="page">
        <header className="topbar">
          <div className="crumb">
            <button ref={mobileMenuButton} className="button button--ghost button--sm mobile-menu" onClick={() => setOpen(true)} aria-label={t("nav.openMenu")} aria-expanded={open} aria-controls="main-sidebar"><Menu size={18} /></button>
            <span>{PRODUCT_NAME}</span><ChevronRight size={14} aria-hidden="true" /><strong>{t(sectionLabel(pathname))}</strong>
          </div>
          <div className="top-actions">{user && <UserMenu user={user} onSignOut={() => void logout()} />}</div>
        </header>
        <main className="app-main"><Outlet /></main>
      </div>
    </div>
  );
}
