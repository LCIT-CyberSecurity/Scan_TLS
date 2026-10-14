import { Graph, NodeEvent } from "@antv/g6";
import { ArrowUpRight, CircleHelp, Crosshair, Layers3, Minus, Pencil, Plus, Search, Settings2, X } from "lucide-react";
import { Fragment, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import type { MapDevice, MapGraph, MapHostDetail, MapNode, MapSummary, MapZone, SI, Target } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { ErrorNote, PageHeader } from "../components/common";
import { Button } from "../components/ui/button";
import { Dialog } from "../components/ui/dialog";
import { Field, Input, Select, Textarea } from "../components/ui/input";
import { useI18n } from "../i18n";
import "../styles/network-map.css";

type SearchItem = { kind: "host" | "si" | "zone" | "device"; id: string; name: string; value?: string; parent_zone_id?: string | null; zone_id?: string | null; si_ids?: string[]; zone_ids?: string[] };
type ZoneForm = { id?: string; name: string; description: string; zone_type: string; parent_zone_id: string; cidr: string; si_ids: string[]; target_ids: string[] };

const emptyZone: ZoneForm = { name: "", description: "", zone_type: "custom", parent_zone_id: "", cidr: "", si_ids: [], target_ids: [] };
const deviceTypes = ["router", "firewall", "gateway", "switch", "load_balancer", "reverse_proxy", "server", "subnet", "generic"] as const;

function nodeColor(node: MapNode): string {
  const severity = node.exposure?.severity;
  if (severity?.critical) return "#ee6b79";
  if (severity?.high) return "#f0b862";
  if (node.kind === "host") return "#42cdea";
  if (node.kind === "device") return node.provenance === "OBSERVED" ? "#53bfa2" : "#7897b4";
  if (node.kind === "zone") return "#688eaa";
  return "#7899ca";
}

export default function NetworkMap() {
  const { t, locale } = useI18n();
  const { atLeast } = useAuth();
  const stage = useRef<HTMLDivElement>(null);
  const graph = useRef<Graph | null>(null);
  const lastFitScope = useRef("");
  const selectNode = useRef<(node: MapNode) => void>(() => undefined);
  const [summary, setSummary] = useState<MapSummary>();
  const [graphData, setGraphData] = useState<MapGraph>();
  const [zones, setZones] = useState<MapZone[]>([]);
  const [devices, setDevices] = useState<MapDevice[]>([]);
  const [targets, setTargets] = useState<Target[]>([]);
  const [systems, setSystems] = useState<SI[]>([]);
  const [siId, setSiId] = useState("");
  const [zoneId, setZoneId] = useState("");
  const [groupId, setGroupId] = useState("");
  const [focusTargetId, setFocusTargetId] = useState("");
  const [expandUnassigned, setExpandUnassigned] = useState(false);
  const [mode, setMode] = useState<"si" | "network">("si");
  const [exposureFilter, setExposureFilter] = useState("all");
  const [searchText, setSearchText] = useState("");
  const [searchItems, setSearchItems] = useState<SearchItem[]>([]);
  const [selected, setSelected] = useState<MapNode>();
  const [host, setHost] = useState<MapHostDetail>();
  const [zoneForm, setZoneForm] = useState<ZoneForm | null>(null);
  const [deviceOpen, setDeviceOpen] = useState(false);
  const [deviceEditing, setDeviceEditing] = useState<MapDevice>();
  const [linkOpen, setLinkOpen] = useState(false);
  const [error, setError] = useState<unknown>();
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [revision, setRevision] = useState(0);
  const canEdit = atLeast("OPERATOR");

  const reload = useCallback(async () => {
    setLoading(true);
    setError(undefined);
    try {
      const [nextSummary, nextZones, nextDevices, nextTargets, nextSystems] = await Promise.all([
        api<MapSummary>("/map/summary"), api<MapZone[]>("/map/zones"), api<MapDevice[]>("/map/devices"),
        api<Target[]>("/targets"), api<SI[]>("/information-systems"),
      ]);
      setSummary(nextSummary); setZones(nextZones); setDevices(nextDevices); setTargets(nextTargets); setSystems(nextSystems);
    } catch (cause) { setError(cause); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { void reload(); }, [reload]);
  useEffect(() => { setExpandUnassigned(false); }, [siId, zoneId, groupId]);
  useEffect(() => {
    let cancelled = false;
    const params = { ...(siId ? { si_id: siId } : {}), ...(zoneId ? { zone_id: zoneId } : {}), ...(groupId ? { group_id: groupId } : {}), ...(focusTargetId ? { focus_target_id: focusTargetId } : {}), ...(expandUnassigned ? { expand_unassigned: true } : {}), mode };
    api<MapGraph>("/map/graph", { params }).then((data) => { if (!cancelled) setGraphData(data); })
      .catch((cause) => { if (!cancelled) setError(cause); });
    return () => { cancelled = true; };
  }, [siId, zoneId, groupId, focusTargetId, expandUnassigned, mode, revision]);

  const visibleNodes = useMemo(() => (graphData?.nodes ?? []).filter((node) => {
    if (exposureFilter === "critical") return Boolean(node.exposure?.severity?.critical);
    if (exposureFilter === "high") return Boolean(node.exposure?.severity?.critical || node.exposure?.severity?.high);
    if (exposureFilter === "unscanned") return node.exposure && "unscanned_targets" in node.exposure ? node.exposure.unscanned_targets > 0 : node.kind === "host" && !node.exposure;
    return true;
  }), [graphData, exposureFilter]);
  const nodeById = useMemo(() => new Map(visibleNodes.map((node) => [node.id, node])), [visibleNodes]);
  const si = systems.find((item) => item.id === siId);
  const zone = zones.find((item) => item.id === zoneId);
  const group = graphData?.scope.group;
  const zoneTrail: MapZone[] = [];
  let trailItem = zone;
  while (trailItem) {
    zoneTrail.unshift(trailItem);
    trailItem = trailItem.parent_zone_id ? zones.find((item) => item.id === trailItem?.parent_zone_id) : undefined;
  }
  const chooseNode = useCallback((node: MapNode) => {
    if (node.id) graph.current?.setElementState(node.id, "selected");
    setSelected(node);
    if (node.kind === "si" && node.si_id) { setSiId(node.si_id); setZoneId(""); setGroupId(""); setFocusTargetId(""); setSelected(undefined); }
    if (node.kind === "zone" && node.zone_id) { setZoneId(node.zone_id); setGroupId(""); setFocusTargetId(""); setSelected(undefined); }
    if (node.kind === "group" && node.group_id) { setGroupId(node.group_id); setZoneId(""); setFocusTargetId(""); setSelected(undefined); }
    if (node.kind === "unassigned") { setExpandUnassigned(true); setSelected(undefined); }
    if (node.kind === "host" && node.target_id) {
      void api<MapHostDetail>(`/map/hosts/${node.target_id}`).then(setHost).catch(setError);
    } else setHost(undefined);
  }, []);
  selectNode.current = chooseNode;

  useEffect(() => {
    if (!stage.current) return;
    const element = stage.current;
    const instance = new Graph({
      container: element,
      autoFit: "view",
      zoomRange: [0.4, 2.5],
      layout: { type: "grid", cols: 4 },
      behaviors: ["drag-canvas", "zoom-canvas"],
      node: {
        type: "circle",
        style: {
          size: (datum) => datum.data?.kind === "si" ? 100 : datum.data?.kind === "zone" ? 78 : datum.data?.kind === "host" ? 48 : 54,
          fill: (datum) => nodeColor((datum.data?.mapNode ?? {}) as MapNode),
          fillOpacity: (datum) => datum.data?.kind === "si" ? 0.16 : datum.data?.kind === "zone" ? 0.11 : 0.22,
          stroke: (datum) => nodeColor((datum.data?.mapNode ?? {}) as MapNode),
          strokeOpacity: 0.7,
          lineWidth: 1,
          labelText: (datum) => (datum.data?.label as string | undefined) ?? datum.id,
          labelPlacement: "bottom",
          labelFill: getComputedStyle(document.documentElement).getPropertyValue("--text-primary").trim() || "#e9ebf1",
          labelFontSize: 13,
          labelFontWeight: 500,
          labelOffsetY: 12,
        },
        state: { selected: { lineWidth: 2.5, strokeOpacity: 1, shadowColor: "#42cdea", shadowBlur: 14 } },
      },
      edge: { style: { stroke: "#63809b", strokeOpacity: 0.34, lineWidth: 1, endArrow: false } },
      combo: { type: "rect", style: { fill: "#14263a", fillOpacity: 0.42, stroke: "#294159", lineWidth: 1, radius: 18, padding: 28 } },
    });
    instance.on(NodeEvent.CLICK, (event) => {
      const elementId = (event as { target: { id: string } }).target.id;
      const node = instance.getNodeData(elementId);
      const record = nodeById.get(elementId) ?? (node?.data?.mapNode as MapNode | undefined);
      if (record) selectNode.current(record);
    });
    graph.current = instance;
    const resize = new ResizeObserver(([entry]) => {
      if (entry && entry.contentRect.width > 0 && entry.contentRect.height > 0) instance.resize(entry.contentRect.width, entry.contentRect.height);
    });
    resize.observe(element);
    return () => { resize.disconnect(); instance.destroy(); graph.current = null; };
    // The graph is created once per mounted page; node actions use a ref to keep closures current.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    const instance = graph.current;
    if (!instance || !graphData) return;
    const nodes = visibleNodes.map((item) => ({
      id: item.id,
      type: item.kind === "device" ? "rect" : "circle",
      data: { label: item.kind === "host" && item.value ? item.value : item.name, kind: item.kind, mapNode: item },
      style: { size: item.kind === "si" ? Math.min(150, 92 + Math.log2((item.exposure && "targets" in item.exposure ? item.exposure.targets : 0) + 1) * 10) : item.kind === "zone" ? 92 : item.kind === "host" ? 46 : item.kind === "unassigned" ? 82 : 58,
        fill: nodeColor(item), fillOpacity: item.kind === "si" ? 0.13 : item.kind === "zone" ? 0.09 : 0.2,
        stroke: nodeColor(item), lineWidth: 1, labelText: item.kind === "host" && item.value ? item.value : item.name,
        labelMaxWidth: 180, labelWordWrap: true, labelFontSize: 12 },
    }));
    const ids = new Set(visibleNodes.map((node) => node.id.replace("device:", "")));
    const edges = (graphData.links ?? []).filter((link) => ids.has(link.source_device_id) && ids.has(link.target_device_id)).map((link) => ({
      id: `link:${link.id}`, source: `device:${link.source_device_id}`, target: `device:${link.target_device_id}`,
      data: { provenance: link.provenance }, style: { stroke: link.provenance === "OBSERVED" ? "#53bfa2" : link.provenance === "INFERRED" ? "#f0b862" : "#7897b4",
        lineDash: link.provenance === "INFERRED" ? [5, 5] : undefined, lineWidth: 1, strokeOpacity: 0.48 },
    }));
    const hasZoneScope = Boolean(graphData.scope.zone);
    const scopeZoneId = graphData.scope.zone?.id ?? "current";
    const scopeZoneName = graphData.scope.zone?.name ?? t("map.zone");
    const scopeKey = graphData.scope.zone?.id ?? graphData.scope.group?.id ?? graphData.scope.si?.id ?? "global";
    const shouldFit = lastFitScope.current !== `${scopeKey}:${mode}`;
    if (shouldFit) lastFitScope.current = `${scopeKey}:${mode}`;
    const combos = hasZoneScope ? [{ id: `zone-scope:${scopeZoneId}`, data: { label: scopeZoneName }, style: { labelText: scopeZoneName, labelPlacement: "top" as const, labelFontSize: 15 } }] : [];
    const scopedNodes = hasZoneScope ? nodes.map((node) => ({ ...node, combo: combos[0].id })) : nodes;
    instance.setData({ nodes: scopedNodes, edges, combos });
    void instance.render().then(() => {
      if (shouldFit) return instance.fitView({ when: "always", direction: "both" }, reducedMotion() ? false : { duration: 260 });
    });
  }, [visibleNodes, graphData, t, mode]);

  useEffect(() => {
    function escape(event: KeyboardEvent) {
      if (event.key === "Escape") { setSelected(undefined); setHost(undefined); }
    }
    window.addEventListener("keydown", escape);
    return () => window.removeEventListener("keydown", escape);
  }, []);

  async function refreshMap() { await reload(); setRevision((value) => value + 1); }
  async function loadMore() {
    if (!graphData?.next_offset || loadingMore) return;
    setLoadingMore(true);
    try {
      const next = await api<MapGraph>("/map/graph", { params: { ...(siId ? { si_id: siId } : {}), ...(zoneId ? { zone_id: zoneId } : {}), ...(groupId ? { group_id: groupId } : {}), ...(expandUnassigned ? { expand_unassigned: true } : {}), mode, offset: String(graphData.next_offset) } });
      setGraphData((current) => current ? { ...next, nodes: [...new Map([...current.nodes, ...next.nodes].map((item) => [item.id, item])).values()],
        links: [...new Map([...current.links, ...next.links].map((item) => [item.id, item])).values()] } : next);
    } catch (cause) { setError(cause); }
    finally { setLoadingMore(false); }
  }
  async function runSearch() {
    if (searchText.trim().length < 2) return;
    try { setSearchItems(await api<SearchItem[]>("/map/search", { params: { q: searchText.trim() } })); }
    catch (cause) { setError(cause); }
  }
  function openSearchResult(item: SearchItem) {
    setSearchItems([]); setSearchText(item.name);
    if (item.kind === "si") { setSiId(item.id); setZoneId(""); setGroupId(""); setFocusTargetId(""); setSelected(undefined); return; }
    if (item.kind === "zone") { setSiId(zones.find((candidate) => candidate.id === item.id)?.si_ids[0] ?? ""); setZoneId(item.id); setGroupId(""); setFocusTargetId(""); setSelected(undefined); return; }
    if (item.kind === "host") {
      const node: MapNode = { id: `target:${item.id}`, kind: "host", target_id: item.id, name: item.name, value: item.value };
      const location = zones.find((candidate) => item.zone_ids?.includes(candidate.id));
      const firstSystem = location?.si_ids[0] ?? item.si_ids?.[0] ?? "";
      setSiId(firstSystem);
      setZoneId(location?.id ?? "");
      setGroupId("");
      setFocusTargetId(item.id);
      setSelected(node); void api<MapHostDetail>(`/map/hosts/${item.id}`).then(setHost).catch(setError);
      return;
    }
    if (item.kind === "device") {
      const device = devices.find((candidate) => candidate.id === item.id);
      if (device) {
        const deviceZone = zones.find((candidate) => candidate.id === device.zone_id);
        setSiId(deviceZone?.si_ids[0] ?? "");
        setZoneId(device.zone_id ?? "");
        setGroupId("");
        setSelected({ id: `device:${device.id}`, kind: "device", name: device.name, device_type: device.device_type, provenance: device.provenance, ip_address: device.ip_address });
        setHost(undefined);
      }
    }
  }
  function editZone(item?: MapZone) {
    setZoneForm(item ? { id: item.id, name: item.name, description: item.description, zone_type: item.zone_type,
      parent_zone_id: item.parent_zone_id ?? "", cidr: item.cidr ?? "", si_ids: item.si_ids, target_ids: item.target_ids } :
      { ...emptyZone, parent_zone_id: zoneId, si_ids: siId ? [siId] : [] });
  }
  async function saveZone(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault(); if (!zoneForm) return;
    try {
      const body = { ...zoneForm, parent_zone_id: zoneForm.parent_zone_id || null, cidr: zoneForm.cidr || null,
        primary_target_ids: zoneForm.target_ids };
      if (zoneForm.id) await api(`/map/zones/${zoneForm.id}`, { method: "PUT", body });
      else await api("/map/zones", { method: "POST", body });
      setZoneForm(null); await refreshMap();
    } catch (cause) { setError(cause); }
  }
  async function deleteZone(item: MapZone) {
    if (!window.confirm(`${t("map.zone.delete")}: ${item.name}?`)) return;
    try { await api(`/map/zones/${item.id}`, { method: "DELETE" }); if (zoneId === item.id) setZoneId(""); await refreshMap(); }
    catch (cause) { setError(cause); }
  }
  async function createDevice(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault(); const data = new FormData(event.currentTarget);
    try {
      const body = { name: data.get("name"), device_type: data.get("device_type"), zone_id: zoneId || data.get("zone_id") || null,
        ip_address: data.get("ip_address") || null, target_id: data.get("target_id") || null, provenance: data.get("provenance"),
        source: data.get("source") || "TLS Scan administrator", observed_at: data.get("observed_at") || null,
        confidence: data.get("confidence") ? Number(data.get("confidence")) : null, metadata: deviceEditing?.metadata ?? {} };
      if (deviceEditing) await api(`/map/devices/${deviceEditing.id}`, { method: "PUT", body });
      else await api("/map/devices", { method: "POST", body });
      setDeviceOpen(false); setDeviceEditing(undefined); await refreshMap();
    } catch (cause) { setError(cause); }
  }
  function openDevice(item?: MapDevice) { setDeviceEditing(item); setDeviceOpen(true); }
  async function createLink(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault(); const data = new FormData(event.currentTarget);
    try {
      await api("/map/links", { method: "POST", body: { source_device_id: data.get("from"), target_device_id: data.get("to"),
        link_type: "network", provenance: data.get("provenance"), source: data.get("source"), observed_at: data.get("observed_at") || null,
        confidence: data.get("confidence") ? Number(data.get("confidence")) : null } });
      setLinkOpen(false); await refreshMap();
    } catch (cause) { setError(cause); }
  }
  async function removeDevice(id: string) {
    if (!window.confirm(`${t("action.delete")}?`)) return;
    try { await api(`/map/devices/${id}`, { method: "DELETE" }); await refreshMap(); } catch (cause) { setError(cause); }
  }
  async function removeLink(id: string) {
    try { await api(`/map/links/${id}`, { method: "DELETE" }); await refreshMap(); } catch (cause) { setError(cause); }
  }

  const allNodes = graphData?.nodes ?? [];
  const selectedZoneDevices = zoneId ? devices.filter((item) => item.zone_id === zoneId) : [];
  const selectedDevice = selected?.kind === "device" ? devices.find((item) => item.id === selected.id.replace("device:", "")) : undefined;
  const targetLabel = (item: Target) => item.name || item.value;
  const exposureSummary = (node?: MapNode) => node?.exposure?.severity ?? {};
  const severityEntries = Object.entries(host?.scan?.severity ?? exposureSummary(selected)).filter(([, value]) => value > 0);
  const selectedLinks = (graphData?.links ?? []).filter((link) => selectedZoneDevices.some((device) => device.id === link.source_device_id || device.id === link.target_device_id));
  const selectedZone = zones.find((item) => item.id === zoneId);
  const reducedMotion = () => window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false;

  return <div className="network-map-page">
    <PageHeader title={t("map.title")} subtitle={t("map.subtitle")} />
    <ErrorNote error={error} />
    <section className="network-map-shell" aria-label={t("map.title")}>
      <div className="network-map-toolbar">
        <div className="network-map-crumbs">
          <button type="button" onClick={() => { setSiId(""); setZoneId(""); setGroupId(""); setFocusTargetId(""); setSelected(undefined); setHost(undefined); }} className={!siId ? "is-current" : ""}>{t("map.global")}</button>
          {si && <><span>/</span><button type="button" onClick={() => { setZoneId(""); setGroupId(""); setSelected(undefined); }}>{si.name}</button></>}
          {group && <><span>/</span><button type="button" className="is-current">{group.name}</button></>}
          {zoneTrail.map((item, index) => <Fragment key={item.id}><span>/</span><button type="button" className={index === zoneTrail.length - 1 ? "is-current" : ""} onClick={() => { setZoneId(item.id); setGroupId(""); }}>{item.name}</button></Fragment>)}
        </div>
        <div className="network-map-tools">
          <label className="network-map-search"><Search size={16} /><input value={searchText} placeholder={t("map.search")} onChange={(event) => setSearchText(event.target.value)} onKeyDown={(event) => event.key === "Enter" && void runSearch()} /><button type="button" aria-label={t("action.search")} onClick={() => void runSearch()}><Search size={15} /></button></label>
          {searchItems.length > 0 && <div className="network-map-search-results">{searchItems.map((item) => <button key={`${item.kind}:${item.id}`} onClick={() => openSearchResult(item)}>{item.name}<small>{item.kind === "host" ? item.value : item.kind}</small></button>)}</div>}
          <Select aria-label={t("map.systems")} value={siId} onChange={(event) => { setSiId(event.target.value); setZoneId(""); setGroupId(""); setFocusTargetId(""); setSelected(undefined); setHost(undefined); }}>
            <option value="">{t("map.global")}</option>{systems.filter((item) => !item.parent_id).map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}
          </Select>
          <Select aria-label={t("map.zone")} value={zoneId} onChange={(event) => { const selectedZone = zones.find((item) => item.id === event.target.value); setSiId(selectedZone?.si_ids[0] ?? siId); setZoneId(event.target.value); setGroupId(""); setFocusTargetId(""); setSelected(undefined); setHost(undefined); }}>
            <option value="">{t("map.zone")}</option>{zones.map((item) => <option key={item.id} value={item.id}>{item.parent_zone_id ? "↳ " : ""}{item.name}</option>)}
          </Select>
          <Select aria-label={t("map.filter.all")} value={exposureFilter} onChange={(event) => setExposureFilter(event.target.value)}>
            <option value="all">{t("map.filter.all")}</option><option value="critical">{t("map.filter.critical")}</option><option value="high">{t("map.filter.high")}</option><option value="unscanned">{t("map.filter.unscanned")}</option>
          </Select>
          <div className="network-map-segmented" role="group" aria-label={t("map.mode.si")}>
            <button type="button" aria-pressed={mode === "si"} onClick={() => setMode("si")}><Layers3 size={15} />{t("map.mode.si")}</button>
            <button type="button" aria-pressed={mode === "network"} onClick={() => setMode("network")}><CircleHelp size={15} />{t("map.mode.network")}</button>
          </div>
          {canEdit && siId && <Button size="sm" onClick={() => editZone()}><Plus size={16} />{t("map.zone.new")}</Button>}
        </div>
      </div>

      <div className="network-map-workspace">
        <div className="network-map-canvas-wrap">
          {loading && !summary && <div className="network-map-overlay">{t("map.loading")}</div>}
          {!loading && !summary?.systems.length && <div className="network-map-empty"><MapIconFallback /><h2>{t("map.empty")}</h2></div>}
          {!loading && summary?.systems.length && allNodes.length === 0 && <div className="network-map-empty"><h2>{t("map.emptyGraph")}</h2></div>}
          <div className="network-map-canvas" ref={stage} />
          <div className="network-map-canvas-actions">
            <button type="button" aria-label={t("map.zoomIn")} onClick={() => void graph.current?.zoomBy(1.2, reducedMotion() ? false : { duration: 180 })}><Plus size={16} /></button>
            <button type="button" aria-label={t("map.zoomOut")} onClick={() => void graph.current?.zoomBy(0.84, reducedMotion() ? false : { duration: 180 })}><Minus size={16} /></button>
            <button type="button" aria-label={t("map.center")} onClick={() => void graph.current?.fitView({ when: "always" }, reducedMotion() ? false : { duration: 220 })}><Crosshair size={16} /></button>
          </div>
          <div className="network-map-legend"><span><i className="map-dot map-dot--critical" />{t("map.critical")}</span><span><i className="map-dot map-dot--high" />{t("map.high")}</span><span><i className="map-dot map-dot--neutral" />{t("map.unscanned")}</span></div>
        </div>

        {host && selected && <aside className="network-map-detail" aria-label={t("map.host")}>
          <div className="network-map-detail-head"><div><span className="network-map-eyebrow">{t("map.host")}</span><h2>{host.target.name || host.target.value}</h2><code>{host.target.value}</code></div><button type="button" aria-label={t("map.closePanel")} onClick={() => { setHost(undefined); setSelected(undefined); }}><X size={18} /></button></div>
          <div className="network-map-detail-meta"><span>{[...systems.filter((item) => host.target.si_ids.includes(item.id)).map((item) => item.name), ...host.target.zones.map((item) => item.name)].join(" · ") || t("map.zone")}</span><span>{host.target.ports || t("map.profilePorts")}</span></div>
          {!host.scan ? <p className="network-map-no-scan">{t("map.noScan")}</p> : <>
            <div className="network-map-scan-summary"><span>{t("map.lastScan")}</span><time>{new Date(host.scan.finished_at).toLocaleString(locale)}</time><strong>{host.scan.status}</strong></div>
            <div className="network-map-severity-list">{severityEntries.map(([key, count]) => <span key={key} className={`severity-${key}`}>{t(`map.${key}` as never)} <b>{count}</b></span>)}</div>
            <h3>{t("map.endpoints")} <small>{host.scan.endpoints.length}</small></h3>
            <div className="network-map-endpoints">{host.scan.endpoints.map((endpoint) => <article key={endpoint.endpoint_id}>
              <div><strong>{endpoint.hostname || endpoint.ip_address || host.target.value}</strong><span>:{endpoint.port ?? "—"}</span></div>
              <span className={`network-map-status network-map-status--${endpoint.compliance_status || "unknown"}`}>{endpoint.compliance_status || t("map.unknown")}</span>
              <small>{endpoint.tls_versions.join(" · ") || "—"} {endpoint.certificate?.valid_until ? `· ${t("map.validUntil")}: ${endpoint.certificate.valid_until}` : ""}</small>
              {endpoint.certificate && <small>{t("map.issuer")}: {String(endpoint.certificate.issuer ?? "—")} · {t("map.trust")}: {String(endpoint.certificate.trust_classification ?? "—")}</small>}
            </article>)}</div>
            {host.findings.length > 0 && <><h3>{t("map.findings")} <small>{host.findings.length}</small></h3><ul className="network-map-findings">{host.findings.map((finding) => <li key={`${finding.finding_id}:${finding.title}`}><span className={`severity-${finding.severity}`}>{finding.severity}</span><span>{finding.title}</span></li>)}</ul></>}
            <Link className="network-map-run-link" to={`/scans/${host.scan.run_id}`}>{t("map.showRun")} <ArrowUpRight size={15} /></Link>
          </>}
        </aside>}
        {selectedDevice && <aside className="network-map-detail" aria-label={t("map.device")}>
          <div className="network-map-detail-head"><div><span className="network-map-eyebrow">{t("map.device")}</span><h2>{selectedDevice.name}</h2><code>{t(`map.deviceType.${selectedDevice.device_type}` as never)}</code></div><button type="button" aria-label={t("map.closePanel")} onClick={() => setSelected(undefined)}><X size={18} /></button></div>
          <div className="network-map-detail-meta"><span>{selectedDevice.ip_address || "—"}</span><span>{t(`map.provenance.${selectedDevice.provenance}` as never)}</span></div>
          <div className="network-map-device-evidence"><span>{t("map.device.source")}</span><strong>{selectedDevice.source || "—"}</strong><span>{t("map.link.observedAt")}</span><strong>{selectedDevice.observed_at ? new Date(selectedDevice.observed_at).toLocaleString(locale) : "—"}</strong><span>{t("map.confidence")}</span><strong>{selectedDevice.confidence ?? "—"}</strong></div>
          {canEdit && <Button variant="outline" size="sm" onClick={() => openDevice(selectedDevice)}><Pencil size={15} />{t("action.edit")}</Button>}
        </aside>}
      </div>

      <footer className="network-map-footer"><div><span className="network-map-footer-number">{summary?.totals.targets ?? 0}</span> {t("map.targets")} <span className="network-map-footer-divider" /> <span className="network-map-footer-number">{summary?.totals.scanned_targets ?? 0}</span> {t("map.scanned")}</div>
        <p><CircleHelp size={14} />{t("map.provenanceHint")}</p></footer>
      {graphData?.truncated && <div className="network-map-truncated"><span>{t("map.truncated", { count: 500 })}</span><Button size="sm" variant="outline" disabled={loadingMore} onClick={() => void loadMore()}>{loadingMore ? t("map.loading") : t("map.loadMore")}</Button></div>}
      {canEdit && siId && <details className="network-map-manage"><summary><Settings2 size={16} />{t("map.manage")}</summary>
        <div className="network-map-manage-actions"><Button size="sm" variant="outline" onClick={() => editZone(selectedZone)}><Layers3 size={15} />{selectedZone ? t("map.zone.edit") : t("map.zone.new")}</Button>
          {selectedZone && <Button size="sm" variant="outline" onClick={() => void deleteZone(selectedZone)}>{t("map.zone.delete")}</Button>}
          <Button size="sm" variant="outline" onClick={() => openDevice()}><Plus size={15} />{t("map.device.new")}</Button>
          {devices.length > 1 && <Button size="sm" variant="outline" onClick={() => setLinkOpen(true)}><Plus size={15} />{t("map.link.new")}</Button>}
        </div>
        {selectedZoneDevices.length > 0 && <div className="network-map-device-list">{selectedZoneDevices.map((item) => <div key={item.id}><span>{item.name} <small>{item.device_type} · {t(`map.provenance.${item.provenance}` as never)} {item.source && `· ${item.source}`}</small></span>{canEdit && <span className="flex gap-1"><button type="button" onClick={() => openDevice(item)} aria-label={t("map.device.edit")}><Pencil size={14} /></button><button type="button" onClick={() => void removeDevice(item.id)} aria-label={t("action.delete")}><X size={14} /></button></span>}</div>)}</div>}
        {selectedLinks.length > 0 && <div className="network-map-device-list">{selectedLinks.map((item) => <div key={item.id}><span>{devices.find((x) => x.id === item.source_device_id)?.name} → {devices.find((x) => x.id === item.target_device_id)?.name}<small>{t(`map.provenance.${item.provenance}` as never)} {item.source && `· ${item.source}`}</small></span><button type="button" onClick={() => void removeLink(item.id)} aria-label={t("action.delete")}><X size={14} /></button></div>)}</div>}
      </details>}
    </section>

    {zoneForm && <Dialog open onOpenChange={(open) => !open && setZoneForm(null)} title={zoneForm.id ? t("map.zone.edit") : t("map.zone.new")} wide>
      <form className="network-map-form" onSubmit={(event) => void saveZone(event)}>
        <Field label={t("map.zone.name")}><Input required maxLength={120} value={zoneForm.name} onChange={(event) => setZoneForm({ ...zoneForm, name: event.target.value })} /></Field>
        <div className="grid gap-3 sm:grid-cols-2"><Field label={t("map.zone.type")}><Select value={zoneForm.zone_type} onChange={(event) => setZoneForm({ ...zoneForm, zone_type: event.target.value })}>{["custom", "dmz", "lan", "administration", "production", "vlan", "subnet", "cloud", "partner"].map((value) => <option key={value} value={value}>{value}</option>)}</Select></Field>
          <Field label={t("map.zone.parent")}><Select value={zoneForm.parent_zone_id} onChange={(event) => setZoneForm({ ...zoneForm, parent_zone_id: event.target.value })}><option value="">—</option>{zones.filter((item) => item.id !== zoneForm.id).map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}</Select></Field></div>
        <Field label={t("map.zone.cidr")}><Input value={zoneForm.cidr} onChange={(event) => setZoneForm({ ...zoneForm, cidr: event.target.value })} placeholder="192.0.2.0/24" /></Field>
        <Field label={t("map.zone.description")}><Textarea rows={2} value={zoneForm.description} onChange={(event) => setZoneForm({ ...zoneForm, description: event.target.value })} /></Field>
        <Field label={t("map.zone.systems")}><select multiple value={zoneForm.si_ids} onChange={(event) => setZoneForm({ ...zoneForm, si_ids: Array.from(event.target.selectedOptions, (option) => option.value) })} className="network-map-multiselect">{systems.map((item) => <option key={item.id} value={item.id}>{item.parent_id ? "↳ " : ""}{item.name}</option>)}</select></Field>
        <Field label={t("map.zone.targets")}><select multiple value={zoneForm.target_ids} onChange={(event) => setZoneForm({ ...zoneForm, target_ids: Array.from(event.target.selectedOptions, (option) => option.value) })} className="network-map-multiselect">{targets.map((item) => <option key={item.id} value={item.id}>{targetLabel(item)}</option>)}</select></Field>
        <div className="flex justify-end gap-2"><Button type="button" variant="outline" onClick={() => setZoneForm(null)}>{t("action.cancel")}</Button><Button type="submit">{t("map.zone.save")}</Button></div>
      </form>
    </Dialog>}

    {deviceOpen && <Dialog open onOpenChange={(open) => { if (!open) { setDeviceOpen(false); setDeviceEditing(undefined); } }} title={deviceEditing ? t("map.device.edit") : t("map.device.new")}>
      <form className="network-map-form" onSubmit={(event) => void createDevice(event)}><Field label={t("map.device.name")}><Input name="name" required maxLength={160} defaultValue={deviceEditing?.name ?? ""} /></Field>
        <Field label={t("map.device.type")}><Select name="device_type" defaultValue={deviceEditing?.device_type ?? "generic"}>{deviceTypes.map((value) => <option key={value} value={value}>{t(`map.deviceType.${value}` as never)}</option>)}</Select></Field>
        <Field label={t("map.device.ip")}><Input name="ip_address" placeholder="192.0.2.10" defaultValue={deviceEditing?.ip_address ?? ""} /></Field>
        <Field label={t("map.device.zone")}><Select name="zone_id" defaultValue={deviceEditing?.zone_id ?? zoneId}>{zones.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}</Select></Field>
        <Field label={t("map.device.target")}><Select name="target_id" defaultValue={deviceEditing?.target_id ?? ""}><option value="">—</option>{targets.map((item) => <option key={item.id} value={item.id}>{targetLabel(item)}</option>)}</Select></Field>
        <Field label={t("map.device.provenance")}><Select name="provenance" defaultValue={deviceEditing?.provenance ?? "DECLARED"}><option value="DECLARED">{t("map.provenance.DECLARED")}</option><option value="OBSERVED">{t("map.provenance.OBSERVED")}</option><option value="INFERRED">{t("map.provenance.INFERRED")}</option></Select></Field>
        <Field label={t("map.device.source")}><Input name="source" maxLength={255} defaultValue={deviceEditing?.source ?? "TLS Scan administrator"} /></Field>
        <Field label={t("map.link.observedAt")}><Input name="observed_at" type="datetime-local" defaultValue={deviceEditing?.observed_at?.slice(0, 16) ?? ""} /></Field>
        <Field label={t("map.confidence")}><Input name="confidence" type="number" min="0" max="1" step="0.01" defaultValue={deviceEditing?.confidence ?? ""} /></Field>
        <div className="flex justify-end gap-2"><Button type="button" variant="outline" onClick={() => { setDeviceOpen(false); setDeviceEditing(undefined); }}>{t("action.cancel")}</Button><Button type="submit">{t("map.device.save")}</Button></div>
      </form>
    </Dialog>}

    {linkOpen && <Dialog open onOpenChange={(open) => !open && setLinkOpen(false)} title={t("map.link.new")}>
      <form className="network-map-form" onSubmit={(event) => void createLink(event)}><Field label={t("map.link.from")}><Select name="from" required>{devices.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}</Select></Field>
        <Field label={t("map.link.to")}><Select name="to" required>{devices.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}</Select></Field>
        <Field label={t("map.link.provenance")}><Select name="provenance"><option value="DECLARED">{t("map.provenance.DECLARED")}</option><option value="OBSERVED">{t("map.provenance.OBSERVED")}</option><option value="INFERRED">{t("map.provenance.INFERRED")}</option></Select></Field>
        <Field label={t("map.link.source")}><Input name="source" required maxLength={255} placeholder="CMDB, network documentation…" /></Field>
        <Field label={t("map.link.observedAt")}><Input name="observed_at" type="datetime-local" /></Field>
        <Field label={t("map.confidence")}><Input name="confidence" type="number" min="0" max="1" step="0.01" /></Field>
        <div className="flex justify-end gap-2"><Button type="button" variant="outline" onClick={() => setLinkOpen(false)}>{t("action.cancel")}</Button><Button type="submit">{t("map.link.save")}</Button></div>
      </form>
    </Dialog>}
  </div>;
}

function MapIconFallback() { return <div className="network-map-empty-icon"><Layers3 size={26} /></div>; }
