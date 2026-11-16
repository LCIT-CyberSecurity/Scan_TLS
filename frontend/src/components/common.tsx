import { AlertTriangle, Inbox, Info, Loader2 } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { ApiError } from "../api/client";
import type { RunStatus } from "../api/types";
import { useI18n } from "../i18n";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: string; actions?: ReactNode }) {
  return (
    <div className="page-header">
      <div><h1 className="page-title">{title}</h1>{subtitle && <p className="page-subtitle">{subtitle}</p>}</div>
      {actions && <div className="page-actions">{actions}</div>}
    </div>
  );
}

const STATUS_TONE: Record<RunStatus, "neutral" | "info" | "primary" | "success" | "warning" | "danger"> = {
  scheduled: "neutral", queued: "info", running: "primary", completed: "success", partial: "warning", failed: "danger", cancelled: "neutral", expired: "danger",
};
export function StatusBadge({ status }: { status: RunStatus }) {
  const { t } = useI18n();
  return <Badge tone={STATUS_TONE[status] ?? "neutral"}>{status === "running" && <Loader2 className="size-3 animate-spin" />}{t(`status.${status}` as never)}</Badge>;
}

export function SeverityBadge({ severity }: { severity: string }) {
  const s = severity.toLowerCase();
  const tone = s === "critical" || s === "high" ? "danger" : s === "medium" ? "warning" : s === "low" ? "info" : "neutral";
  return <Badge tone={tone}>{severity || "—"}</Badge>;
}

export function ErrorNote({ error }: { error: unknown }) {
  if (!error) return null;
  const message = error instanceof ApiError || error instanceof Error ? error.message : String(error);
  return <div role="alert" className="note note--danger mb-4"><AlertTriangle className="size-4" />{message}</div>;
}

/** Inline message block (warning, info, success), same family as ErrorNote. */
export function Note({ tone = "info", children, className = "" }: { tone?: "info" | "warning" | "success" | "danger"; children: ReactNode; className?: string }) {
  return <div className={`note note--${tone} ${className}`}><Info className="size-4" /><div>{children}</div></div>;
}

/** Empty state: an icon and what is missing. */
export function Empty({ children, icon }: { children: ReactNode; icon?: ReactNode }) {
  return <div className="empty-state"><span className="empty-state__icon" aria-hidden="true">{icon ?? <Inbox className="size-6" />}</span><strong>{children}</strong></div>;
}

export function Loading() {
  const { t } = useI18n();
  return <div role="status" aria-live="polite" className="empty-state"><Loader2 className="size-6 animate-spin text-primary" /><p>{t("state.loading")}</p></div>;
}

/** KPI tile (LCIT-Sign's .metric). `tone` colours the icon chip and, for danger, the figure. */
export function Metric({ label, value, hint, icon, tone, to }: { label: string; value: ReactNode; hint?: string; icon?: ReactNode; tone?: "amber" | "red" | "green" | "blue"; to?: string }) {
  const body = (
    <>
      <div className="metric-label"><span>{label}</span>{icon && <span className={`metric-icon ${tone ?? ""}`}>{icon}</span>}</div>
      <strong>{value}</strong>
      {hint && <small>{hint}</small>}
    </>
  );
  const cls = `card metric${tone === "red" ? " metric-alert" : ""}`;
  return to ? <Link to={to} className={cls}>{body}</Link> : <div className={cls}>{body}</div>;
}

/** Loads data, exposes reload; keeps previous data while refreshing. */
export function useLoad<T>(loader: () => Promise<T>, deps: unknown[] = [], pollMs?: number) {
  const query = useQuery({
    queryKey: ["useLoad", loader.toString(), ...deps],
    queryFn: async (): Promise<{ value: T } | { undefinedValue: true }> => {
      const value = await loader();
      return value === undefined ? { undefinedValue: true } : { value };
    },
    placeholderData: (previous) => previous,
    refetchInterval: pollMs,
    refetchOnMount: "always",
    retry: false,
    staleTime: 0,
    gcTime: 0,
  });
  const reload = async () => { await query.refetch(); };
  const result = query.data && "value" in query.data ? query.data.value : undefined;
  return { data: result, error: query.error, loading: query.isLoading, reload };
}

export function ConfirmButton({ label, confirm, onConfirm, variant = "danger", size = "sm" }: { label: ReactNode; confirm: string; onConfirm: () => void | Promise<void>; variant?: "danger" | "outline"; size?: "sm" | "default" }) {
  return <Button variant={variant} size={size} onClick={() => { if (window.confirm(confirm)) void onConfirm(); }}>{label}</Button>;
}

export function TagList({ tags }: { tags: string[] }) {
  return <div className="tag-list">{tags.map((tag) => <Badge key={tag} tone="primary">{tag}</Badge>)}</div>;
}

/** Checkbox list used for choosing targets, groups, policies, SI. */
export function CheckList({ items, selected, onChange, empty }: { items: { id: string; label: string; sub?: string }[]; selected: string[]; onChange: (ids: string[]) => void; empty?: string }) {
  if (!items.length) return <p className="text-sm text-muted">{empty}</p>;
  return (
    <div className="check-list-box">
      {items.map((item) => (
        <label key={item.id}>
          <input type="checkbox" checked={selected.includes(item.id)} onChange={(e) => onChange(e.target.checked ? [...selected, item.id] : selected.filter((x) => x !== item.id))} />
          <span>{item.label}</span>{item.sub && <span className="text-xs text-muted">{item.sub}</span>}
        </label>
      ))}
    </div>
  );
}

export function TagsInput({ value, onChange, placeholder }: { value: string[]; onChange: (v: string[]) => void; placeholder?: string }) {
  const [text, setText] = useState(value.join(", "));
  return <input className="w-full" placeholder={placeholder} value={text}
    onChange={(e) => { setText(e.target.value); onChange(e.target.value.split(",").map((s) => s.trim()).filter(Boolean)); }} />;
}
