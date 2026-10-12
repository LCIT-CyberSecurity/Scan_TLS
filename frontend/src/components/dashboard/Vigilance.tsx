import { ChevronRight, ShieldCheck } from "lucide-react";
import { Link } from "react-router-dom";
import type { Posture } from "../../api/types";
import { useI18n } from "../../i18n";
import type { Messages } from "../../i18n/en";
import { SeverityBadge } from "../common";
import { Badge } from "../ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";

/** The most relevant anomalies actually present in the latest results (never disabled, untested or inconclusive checks). */
export function Vigilance({ posture }: { posture: Posture | undefined }) {
  const { t } = useI18n();
  const items = posture?.vigilance ?? [];
  return (
    <Card>
      <CardHeader><CardTitle>{t("dash.watch")}</CardTitle></CardHeader>
      <CardContent>
        {items.length ? (
          <ul className="watch-list">
            {items.map((i) => (
              <li key={i.finding_id}>
                <div className="watch-main">
                  <span className="watch-title">{i.category === "complementary_check" ? t(`tls.check.${i.finding_id}` as keyof Messages) : i.title}</span>
                  <span className="watch-meta">{i.severity ? <SeverityBadge severity={i.severity} /> : <Badge tone="neutral">{t("dash.watchCheck")}</Badge>}<span>{t("dash.watchEndpoints", { n: i.endpoints })}</span></span>
                </div>
                {i.run_id && <Link className="button button--ghost button--icon" to={`/scans/${i.run_id}`} aria-label={`${t("dash.watchOpen")}: ${i.title}`}><ChevronRight /></Link>}
              </li>
            ))}
          </ul>
        ) : <p className="watch-empty"><ShieldCheck size={20} aria-hidden="true" />{t("dash.watchEmpty")}</p>}
      </CardContent>
    </Card>
  );
}
