import { ChevronRight } from "lucide-react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import type { Run } from "../api/types";
import { useI18n } from "../i18n";
import { StatusBadge, useLoad } from "./common";

/** Compact "last scan" reminder at the bottom of the sidebar: one request per minute, nothing shown without data. */
export function SidebarActivity() {
  const { t, locale } = useI18n();
  const { data } = useLoad(() => api<Run[]>("/scan-runs", { params: { limit: "1" } }), [], 60000);
  const run = data?.[0];
  if (!run) return null;
  const nonCompliant = run.summary?.non_compliant_endpoints;
  return (
    <Link to={`/scans/${run.id}`} className="side-activity" aria-label={`${t("side.lastScan")}: ${run.name}`}>
      <span className="side-activity__label">{t("side.lastScan")}</span>
      <span className="side-activity__name">{run.name}</span>
      <span className="side-activity__meta"><StatusBadge status={run.status} /><span>{new Date(run.finished_at ?? run.queued_at).toLocaleString(locale, { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" })}</span></span>
      {nonCompliant != null && <span className="side-activity__meta">{t("side.nonCompliant", { n: nonCompliant })}<ChevronRight size={16} aria-hidden="true" /></span>}
    </Link>
  );
}
