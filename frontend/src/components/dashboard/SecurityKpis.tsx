import { AlertTriangle, CalendarClock, Info, ShieldCheck, ShieldX } from "lucide-react";
import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import type { Posture } from "../../api/types";
import { useI18n } from "../../i18n";

type Tone = "green" | "red" | "amber" | "blue" | "";

function Kpi({ title, value, hint, tip, icon, tone, to, children }: { title: string; value: ReactNode; hint: ReactNode; tip?: string; icon: ReactNode; tone: Tone; to?: string; children?: ReactNode }) {
  const head = (
    <>
      <div className="metric-label"><span>{title}</span><span className={`metric-icon ${tone}`}>{icon}</span></div>
      <strong>{value}</strong>
      <small>{hint}</small>
      {children}
    </>
  );
  return (
    <div className="card metric kpi">
      {to ? <Link to={to} className="kpi-link">{head}</Link> : head}
      {tip && <button type="button" className="info-tip" data-tip={tip} aria-label={tip}><Info size={15} aria-hidden="true" /></button>}
    </div>
  );
}

/** Zone A: the four compliance and security indicators of the latest results (definitions in services/dashboard.py). */
export function SecurityKpis({ posture }: { posture: Posture | undefined }) {
  const { t, locale } = useI18n();
  const e = posture?.endpoints;
  const evaluated = e ? e.compliant + e.non_compliant : 0;
  const days = posture?.window_days ?? 30;
  const watched = posture ? posture.certificates.expired + posture.certificates.expiring : 0;
  const f = posture?.findings;
  const priority = f ? f.critical.unique + f.high.unique : 0;
  const na = t("dash.na");
  return (
    <div className="kpi-grid">
      <Kpi title={t("dash.kpi.compliance")} tone="green" icon={<ShieldCheck size={20} />} tip={t("dash.kpi.complianceTip")}
        value={e?.rate != null ? `${e.rate.toLocaleString(locale)} %` : posture ? t("dash.notEvaluated") : na}
        hint={e?.rate != null ? <>{t("dash.kpi.complianceHint", { n: e.compliant, total: evaluated })}{e.unevaluated > 0 && <span className="kpi-sub">{t("dash.kpi.unevaluated", { n: e.unevaluated })}</span>}</> : posture && e?.total ? t("dash.kpi.unevaluated", { n: e.unevaluated }) : t("dash.noData")} />
      <Kpi title={t("dash.kpi.noncompliant")} tone={e?.non_compliant ? "red" : "green"} icon={<ShieldX size={20} />} to={e?.non_compliant ? "/scans" : undefined}
        value={e ? e.non_compliant : na} hint={e && !e.non_compliant && evaluated ? t("dash.kpi.noncompliantNone") : t("dash.kpi.noncompliantHint")} />
      <Kpi title={t("dash.kpi.findings")} tone={priority ? "red" : "green"} icon={<AlertTriangle size={20} />} tip={f ? t("dash.kpi.findingsTip", { o: f.occurrences }) : undefined}
        value={f ? priority : na} hint={f ? t("dash.kpi.findingsHint", { c: f.critical.unique, h: f.high.unique }) : t("dash.noData")} />
      <Kpi title={t("dash.kpi.certs")} tone={posture?.certificates.expired ? "red" : watched ? "amber" : "green"} icon={<CalendarClock size={20} />} tip={t("dash.kpi.certsTip")}
        value={posture ? watched : na} hint={posture ? (watched ? t("dash.kpi.certsHint", { e: posture.certificates.expired, s: posture.certificates.expiring, d: days }) : t("dash.kpi.certsNone", { d: days })) : t("dash.noData")}>
        {!!posture?.certificates.items.length && (
          <ul className="kpi-list" aria-label={t("dash.kpi.certsList")}>
            {posture.certificates.items.slice(0, 3).map((c) => (
              <li key={`${c.run_id}-${c.subject}-${c.remaining_days}`}>
                <Link to={`/scans/${c.run_id}`} title={c.subject}>{c.subject.replace(/^CN=/, "")}</Link>
                <span>{c.remaining_days < 0 ? t("dash.cert.expired", { n: -c.remaining_days }) : t("dash.cert.in", { n: c.remaining_days })}</span>
              </li>
            ))}
          </ul>
        )}
      </Kpi>
    </div>
  );
}
