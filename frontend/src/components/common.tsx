import { AlertTriangle, Loader2 } from "lucide-react";
import { useCallback, useEffect, useState, type ReactNode } from "react";
import { ApiError } from "../api/client";
import type { RunStatus } from "../api/types";
import { useI18n } from "../i18n";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: string; actions?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-start justify-between gap-3">
      <div><h1>{title}</h1>{subtitle && <p className="mt-1 text-sm text-muted">{subtitle}</p>}</div>
      <div className="flex flex-wrap gap-2">{actions}</div>
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
  return <div role="alert" className="flex items-start gap-2 rounded-sm border border-danger-line bg-danger-soft px-3 py-2 text-sm text-danger"><AlertTriangle className="mt-0.5 size-4 shrink-0" />{message}</div>;
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="px-5 py-10 text-center text-sm text-muted">{children}</div>;
}

/** Loads data, exposes reload; keeps previous data while refreshing. */
export function useLoad<T>(loader: () => Promise<T>, deps: unknown[] = [], pollMs?: number) {
  const [data, setData] = useState<T | undefined>();
  const [error, setError] = useState<unknown>();
  const [loading, setLoading] = useState(true);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const reload = useCallback(async () => { try { setData(await loader()); setError(undefined); } catch (e) { setError(e); } finally { setLoading(false); } }, deps);
  useEffect(() => { void reload(); if (!pollMs) return; const id = setInterval(() => void reload(), pollMs); return () => clearInterval(id); }, [reload, pollMs]);
  return { data, error, loading, reload };
}

export function ConfirmButton({ label, confirm, onConfirm, variant = "danger", size = "sm" }: { label: ReactNode; confirm: string; onConfirm: () => void | Promise<void>; variant?: "danger" | "outline"; size?: "sm" | "default" }) {
  return <Button variant={variant} size={size} onClick={() => { if (window.confirm(confirm)) void onConfirm(); }}>{label}</Button>;
}

export function TagList({ tags }: { tags: string[] }) {
  return <div className="flex flex-wrap gap-1">{tags.map((tag) => <Badge key={tag} tone="primary">{tag}</Badge>)}</div>;
}

/** Checkbox list used for choosing targets, groups, policies, SI. */
export function CheckList({ items, selected, onChange, empty }: { items: { id: string; label: string; sub?: string }[]; selected: string[]; onChange: (ids: string[]) => void; empty?: string }) {
  if (!items.length) return <p className="text-sm text-muted">{empty}</p>;
  return (
    <div className="max-h-48 space-y-1 overflow-y-auto rounded-sm border border-border p-2">
      {items.map((item) => (
        <label key={item.id} className="flex cursor-pointer items-center gap-2 rounded-sm px-2 py-1 text-sm hover:bg-surface-2">
          <input type="checkbox" checked={selected.includes(item.id)} onChange={(e) => onChange(e.target.checked ? [...selected, item.id] : selected.filter((x) => x !== item.id))} />
          <span>{item.label}</span>{item.sub && <span className="text-xs text-muted">{item.sub}</span>}
        </label>
      ))}
    </div>
  );
}

export function TagsInput({ value, onChange, placeholder }: { value: string[]; onChange: (v: string[]) => void; placeholder?: string }) {
  const [text, setText] = useState(value.join(", "));
  return <input className="h-10 w-full rounded-sm border border-border-strong bg-surface px-3 text-sm" placeholder={placeholder} value={text}
    onChange={(e) => { setText(e.target.value); onChange(e.target.value.split(",").map((s) => s.trim()).filter(Boolean)); }} />;
}
