import { Check, Circle, Loader2 } from "lucide-react";
import { useEffect, useState } from "react";
import type { Run } from "../api/types";
import { useI18n } from "../i18n";
import { formatDuration } from "../lib/utils";
import { Card } from "./ui/card";

const BASE_STEPS = ["starting", "discovery", "tls_scan", "grading", "reporting"] as const;

/** Compact panel shown on top of a running scan: the steps, where it is, and what each one checks. */
export function ScanProgress({ run }: { run: Run }) {
  const { t } = useI18n();
  const tr = t as unknown as (k: string, v?: Record<string, string | number>) => string;
  const plan = run.plan;
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => { const id = window.setInterval(() => setNow(Date.now()), 1000); return () => window.clearInterval(id); }, []);
  const steps: string[] = plan?.crypto === "pqc" ? ["starting", "pqc_preflight", ...BASE_STEPS.slice(1)] : [...BASE_STEPS];
  const queued = run.status === "queued";
  const current = queued ? -1 : Math.max(0, steps.indexOf(run.phase));
  const elapsed = run.started_at ? Math.max(0, Math.round((now - new Date(run.started_at).getTime()) / 1000)) : 0;

  function what(step: string): string {
    if (!plan) return "";
    switch (step) {
      case "starting": return t("prog.what.starting", { n: plan.targets });
      case "pqc_preflight": return t("prog.what.pqc_preflight");
      case "discovery": return t("prog.what.discovery", { ports: plan.ports.join(" · "), n: plan.targets });
      case "tls_scan": {
        const parts = [t("prog.what.tls")];
        if (plan.certificate) parts.push(t("prog.what.cert"));
        if (plan.certificate && plan.trust) parts.push(t("prog.what.trust", { stores: [...(plan.public_store ? [t("prog.what.publicStore")] : []), ...plan.private_stores].join(", ") }));
        if (plan.certificate && plan.revocation) parts.push(t("prog.what.revocation"));
        if (plan.tls_checks > 0) parts.push(t("prog.what.tlsChecks", { n: plan.tls_checks }));
        return parts.join(" · ");
      }
      case "grading": return t("prog.what.grading", { policies: plan.policies.join(", ") });
      default: return t("prog.what.reporting", { formats: plan.formats.map((f) => f.toUpperCase()).join(", ") });
    }
  }

  const hosts = run.progress;
  return (
    <section aria-label={t("prog.title")} className="mb-4">
      <Card className="p-4">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2 text-sm">
          <strong className="flex items-center gap-2"><Loader2 className="size-4 animate-spin text-primary" aria-hidden />{queued ? t("prog.queued") : t("prog.title")}</strong>
          {!queued && <span className="text-muted">{t("prog.elapsed")} {formatDuration(elapsed)}</span>}
        </div>
        <ol className="grid gap-x-6 gap-y-2 sm:grid-cols-2 lg:grid-cols-5">
          {steps.map((step, i) => {
            const state = i < current ? "done" : i === current ? "current" : "pending";
            return (
              <li key={step} aria-current={state === "current" ? "step" : undefined} className={`flex gap-2 text-sm ${state === "pending" ? "text-muted" : ""}`}>
                <span className="mt-0.5 shrink-0" aria-hidden>{state === "done" ? <Check className="size-4 text-success" /> : state === "current" ? <Loader2 className="size-4 animate-spin text-primary" /> : <Circle className="size-4" />}</span>
                <span><span className={state === "current" ? "font-semibold" : "font-medium"}>{tr(`prog.step.${step}`)}</span>
                  {plan && <span className="block text-xs text-muted">{what(step)}</span>}
                  {state === "current" && step === "tls_scan" && hosts && <span className="mt-1 block text-xs"><progress className="w-full" max={hosts.hosts_total} value={hosts.hosts_done} aria-label={t("prog.hosts", { done: hosts.hosts_done, total: hosts.hosts_total })} />{t("prog.hosts", { done: hosts.hosts_done, total: hosts.hosts_total })}</span>}
                </span>
              </li>
            );
          })}
        </ol>
        {run.cancel_requested && <p className="mt-3 text-xs text-warning">{t("prog.cancelling")}</p>}
      </Card>
    </section>
  );
}
