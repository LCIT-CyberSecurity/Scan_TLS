import { useEffect, useState } from "react";
import type { Group, SnmpPreviewItem, Target } from "../api/types";
import { api } from "../api/client";
import { ErrorNote } from "./common";
import { Card } from "./ui/card";
import { Button } from "./ui/button";
import { Field, Select } from "./ui/input";
import { useI18n } from "../i18n";

export function NetworkDiscovery() {
  const { t } = useI18n();
  const [targets, setTargets] = useState<Target[]>([]);
  const [groups, setGroups] = useState<Group[]>([]);
  const [configured, setConfigured] = useState(false);
  const [targetIds, setTargetIds] = useState<string[]>([]);
  const [groupIds, setGroupIds] = useState<string[]>([]);
  const [timeoutSeconds, setTimeoutSeconds] = useState(2);
  const [concurrency, setConcurrency] = useState(5);
  const [items, setItems] = useState<SnmpPreviewItem[]>([]);
  const [history, setHistory] = useState<{ id: string; status: string; created_at: string; applied_at: string | null; targets: number; observed: number }[]>([]);
  const [discoveryId, setDiscoveryId] = useState("");
  const [selected, setSelected] = useState<number[]>([]);
  const [error, setError] = useState<unknown>();
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let active = true;
    void Promise.all([api<{ enabled: boolean }>("/map/snmp/config"), api<Target[]>("/targets"), api<typeof history>("/map/snmp/discover"), api<Group[]>("/target-groups")])
      .then(([config, inventory, previous, savedGroups]) => { if (active) { setConfigured(config.enabled); setTargets(inventory); setHistory(previous); setGroups(savedGroups); } })
      .catch(setError);
    return () => { active = false; };
  }, []);
  const ipTargetIds = new Set(targets.filter((target) => target.kind === "ip").map((target) => target.id));
  const selectedTargetIds = [...new Set([...targetIds, ...groups.filter((group) => groupIds.includes(group.id)).flatMap((group) => group.target_ids.filter((id) => ipTargetIds.has(id)))])];

  async function openPrevious(id: string) {
    setBusy(true); setError(undefined);
    try {
      const response = await api<{ id: string; status: string; error?: string; items: SnmpPreviewItem[] }>(`/map/snmp/discover/${id}`);
      if (response.status !== "done") throw new Error(response.error || `Discovery status: ${response.status}`);
      setDiscoveryId(id); setItems(response.items);
      setSelected(response.items.flatMap((item, index) => item.status === "observed" ? [index] : []));
    } catch (cause) { setError(cause); }
    finally { setBusy(false); }
  }

  async function discover() {
    setBusy(true); setError(undefined);
    try {
      const response = await api<{ id: string; status: string; items: SnmpPreviewItem[] }>("/map/snmp/discover", {
        method: "POST", body: { target_ids: selectedTargetIds, authorized: true, timeout_seconds: timeoutSeconds, concurrency },
      });
      setDiscoveryId(response.id);
      let result: { id: string; status: string; error?: string; items: SnmpPreviewItem[] } = response;
      for (let attempt = 0; result.status !== "done" && result.status !== "failed" && attempt < 120; attempt++) {
        await new Promise((resolve) => window.setTimeout(resolve, 500));
        result = await api<{ id: string; status: string; error?: string; items: SnmpPreviewItem[] }>(`/map/snmp/discover/${response.id}`);
      }
      if (result.status === "failed") throw new Error(result.error || "SNMP discovery failed");
      if (result.status !== "done") throw new Error("SNMP discovery is taking too long; review it again from history");
      setItems(result.items);
      setSelected(result.items.flatMap((item, index) => item.status === "observed" ? [index] : []));
      setHistory((current) => [{ id: response.id, status: "done", created_at: new Date().toISOString(), applied_at: null, targets: selectedTargetIds.length,
        observed: result.items.filter((item) => item.status === "observed").length }, ...current]);
    } catch (cause) { setError(cause); }
    finally { setBusy(false); }
  }

  async function apply() {
    setBusy(true); setError(undefined);
    try {
      await api(`/map/snmp/discover/${discoveryId}/apply`, { method: "POST", body: { item_indexes: selected, confirm: true } });
      setItems([]); setDiscoveryId(""); setSelected([]);
      setHistory((current) => current.map((item) => item.id === discoveryId ? { ...item, applied_at: new Date().toISOString() } : item));
    } catch (cause) { setError(cause); }
    finally { setBusy(false); }
  }

  return <Card className="space-y-4 p-4">
    <ErrorNote error={error} />
    <p className="text-sm text-muted">{configured ? t("map.snmp.notice") : t("map.snmp.notConfigured")}</p>
    {configured && <>
      <Field label={t("map.snmp.targets")}>
        <select multiple value={targetIds} onChange={(event) => setTargetIds(Array.from(event.target.selectedOptions, (option) => option.value))} className="network-map-multiselect" disabled={Boolean(items.length)}>
          {targets.filter((item) => item.kind === "ip").map((item) => <option key={item.id} value={item.id}>{item.name ? `${item.name} — ${item.value}` : item.value}</option>)}
        </select>
      </Field>
      <Field label={t("map.snmp.groups")}>
        <select multiple value={groupIds} onChange={(event) => setGroupIds(Array.from(event.target.selectedOptions, (option) => option.value))} className="network-map-multiselect" disabled={Boolean(items.length)}>
          {groups.map((group) => <option key={group.id} value={group.id}>{group.name} ({group.target_ids.length})</option>)}
        </select>
      </Field>
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label={t("map.snmp.timeout")}><Select value={String(timeoutSeconds)} onChange={(event) => setTimeoutSeconds(Number(event.target.value))} disabled={Boolean(items.length)}>{[1, 2, 3, 5].map((value) => <option key={value} value={value}>{value} s</option>)}</Select></Field>
        <Field label={t("map.snmp.concurrency")}><Select value={String(concurrency)} onChange={(event) => setConcurrency(Number(event.target.value))} disabled={Boolean(items.length)}>{[1, 2, 5, 10].map((value) => <option key={value} value={value}>{value}</option>)}</Select></Field>
      </div>
      <p className="text-xs text-muted">{t("map.snmp.selectedCount", { count: selectedTargetIds.length })}</p>
      {!items.length && <Button disabled={!selectedTargetIds.length || selectedTargetIds.length > 100 || busy} onClick={() => void discover()}>{busy ? t("map.loading") : t("map.snmp.discover")}</Button>}
      {items.length > 0 && <>
        <p className="text-sm">{t("map.snmp.preview")}</p>
        <div className="space-y-2">{items.map((item, index) => <label key={`${item.target_id}:${index}`} className="flex items-start gap-2 rounded border border-border p-3 text-sm">
          <input type="checkbox" disabled={item.status !== "observed"} checked={selected.includes(index)} onChange={(event) => setSelected((current) => event.target.checked ? [...current, index] : current.filter((value) => value !== index))} />
          <span><strong>{item.system_name || item.target}</strong><small className="block text-muted">{item.target} · {t(`map.snmp.inventory.${item.inventory_status}` as never)} · {item.sys_descr || item.error || t("map.snmp.noDescription")} · {item.interfaces.length} {t("map.snmp.interfaces")} · {item.neighbors.length} {t("map.snmp.neighbors")}</small>
            {item.neighbors.map((neighbor, neighborIndex) => <small key={neighborIndex} className="block text-muted">{neighbor.local_port || "?"} → {neighbor.system_name || neighbor.chassis_id || neighbor.port_id || "?"} · {t(`map.snmp.inventory.${neighbor.inventory_status}` as never)}</small>)}
          </span>
        </label>)}</div>
        <div className="flex flex-wrap justify-end gap-2">
          <Button variant="outline" disabled={busy} onClick={() => { setItems([]); setDiscoveryId(""); setSelected([]); }}>{t("map.snmp.back")}</Button>
          <Button disabled={!selected.length || busy} onClick={() => void apply()}>{busy ? t("map.loading") : t("map.snmp.apply")}</Button>
        </div>
      </>}
      {!items.length && history.length > 0 && <div className="space-y-2 border-t border-border pt-3"><h3 className="text-sm font-semibold">{t("map.snmp.history")}</h3>{history.map((entry) => <button key={entry.id} type="button" className="flex w-full justify-between rounded border border-border p-2 text-left text-sm" onClick={() => void openPrevious(entry.id)}>
        <span>{new Date(entry.created_at).toLocaleString()} · {entry.targets} {t("map.snmp.targetsCount")} · {entry.observed} {t("map.snmp.observedCount")}</span><span>{entry.status !== "done" ? entry.status : entry.applied_at ? t("map.snmp.applied") : t("map.snmp.review")}</span>
      </button>)}</div>}
    </>}
  </Card>;
}
