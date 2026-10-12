import { CircleCheck, CircleHelp, CircleX } from "lucide-react";
import type { Posture } from "../../api/types";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { useI18n } from "../../i18n";

/** Segmented bar of the distinct endpoints: the legend carries icon, number and percentage so colour is never the only cue. */
export function ComplianceBreakdown({ posture }: { posture: Posture | undefined }) {
  const { t, locale } = useI18n();
  const e = posture?.endpoints;
  const parts = e ? [
    { key: "ok", label: t("dash.compliant"), n: e.compliant, icon: <CircleCheck size={16} aria-hidden="true" /> },
    { key: "bad", label: t("dash.nonCompliant"), n: e.non_compliant, icon: <CircleX size={16} aria-hidden="true" /> },
    { key: "na", label: t("dash.unevaluated"), n: e.unevaluated, icon: <CircleHelp size={16} aria-hidden="true" /> },
  ] : [];
  const pct = (n: number) => `${((100 * n) / (e?.total || 1)).toLocaleString(locale, { maximumFractionDigits: 1 })} %`;
  return (
    <Card>
      <CardHeader><CardTitle>{t("dash.breakdown")}</CardTitle></CardHeader>
      <CardContent>
        {e?.total ? (
          <>
            <div className="split-bar" role="img" aria-label={parts.map((p) => `${p.label}: ${p.n}`).join(", ")}>
              {parts.filter((p) => p.n).map((p) => <span key={p.key} className={`split-bar__${p.key}`} style={{ flex: p.n }} />)}
            </div>
            <ul className="split-legend">
              {parts.map((p) => <li key={p.key} className={`split-legend__${p.key}`}>{p.icon}<span>{p.label}</span><strong>{p.n}</strong><em>{pct(p.n)}</em></li>)}
            </ul>
            <p className="dash-note">{t("dash.breakdownTotal", { n: e.total })} · {t("dash.basis", { n: posture?.scans ?? 0 })}</p>
            {posture?.mixed_policies && <p className="dash-note dash-note--warn">{t("dash.mixedPolicies", { names: posture.policies.map((p) => `${p.name} v${p.version}`).join(", ") })}</p>}
          </>
        ) : <p className="text-sm text-muted">{t("dash.noData")}</p>}
      </CardContent>
    </Card>
  );
}
