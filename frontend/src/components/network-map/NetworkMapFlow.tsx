import {
  Background, Controls, MiniMap, ReactFlow, ReactFlowProvider,
  type Edge, type Node,
  useReactFlow,
} from "@xyflow/react";
import { ChevronRight, Globe2, Layers3, ShieldCheck } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import type { MapEndpointPreview, MapGraph, MapNode } from "../../api/types";
import { useI18n } from "../../i18n";
import "@xyflow/react/dist/style.css";
import "../../styles/network-map-flow.css";

type Props = { nodes: MapNode[]; graph: MapGraph; links: Edge[]; onSelect: (node: MapNode) => void; onFit?: (fit: () => void) => void };
type FlowData = { label: string; subtitle?: string; kind: string; node?: MapNode; count?: number; status?: string; endpoints?: MapEndpointPreview[]; endpointCount?: number; onOpen?: () => void };
type FlowNode = Node<FlowData>;

function ipv4Number(value: string) {
  const parts = value.split(".");
  if (parts.length !== 4 || parts.some((part) => !/^\d{1,3}$/.test(part) || Number(part) > 255)) return null;
  return parts.reduce((result, part) => (result * 256 + Number(part)) >>> 0, 0);
}

export function subnetFor(address: string, zones: MapNode[]) {
  const zone = zones.filter((candidate) => candidate.cidr && candidate.cidr.includes("/")).find((candidate) => {
    const [network, maskText] = candidate.cidr!.split("/");
    const ip = ipv4Number(address);
    const base = ipv4Number(network);
    const mask = Number(maskText);
    if (ip === null || base === null || mask < 0 || mask > 32) return false;
    const netmask = mask === 0 ? 0 : (0xffffffff << (32 - mask)) >>> 0;
    return (ip & netmask) === (base & netmask);
  });
  if (zone) return { key: `cidr:${zone.cidr}`, label: zone.cidr!, zone };
  const ip = ipv4Number(address);
  if (ip === null) return null;
  const prefix = address.split(".").slice(0, 3).join(".");
  return { key: `prefix:${prefix}`, label: `${prefix}.0/24`, zone: undefined };
}

function AssetNode({ data, selected }: { data: FlowData; selected?: boolean }) {
  const { t } = useI18n();
  const host = data.kind === "host";
  const severity = data.status?.toLowerCase() || "unknown";
  const statusText = data.status === "critical" ? t("map.criticalShort") : data.status === "high" ? t("map.highShort") : data.status === "compliant" ? t("map.compliantShort") : data.status === "non-compliant" ? t("map.nonCompliantShort") : data.status;
  const statusTitle = data.status === "compliant" ? t("map.compliant") : data.status === "non-compliant" ? t("map.nonCompliant") : data.status ? t(data.status === "critical" ? "map.critical" : "map.high") : "";
  return <div className={`nmap-node nmap-node--${data.kind} ${data.endpoints?.length ? "has-endpoints" : ""} ${selected ? "is-selected" : ""}`}>
    <div className="nmap-node-main">
      <span className="nmap-node-icon">{host ? <Globe2 size={17} /> : data.kind === "si" ? <Layers3 size={17} /> : <ShieldCheck size={17} />}</span>
      <span className="nmap-node-copy"><strong title={data.label}>{data.label}</strong>{data.subtitle && <small title={data.subtitle}>{data.subtitle}</small>}</span>
      {data.status && <span className={`nmap-grade nmap-grade--${severity}`} title={`TLS ${statusTitle}`}>{statusText}</span>}
      {data.count !== undefined && <span className="nmap-count">{data.count}</span>}
      {data.onOpen && <button className="nmap-open nodrag" aria-label={`Open ${data.label}`} onClick={(event) => { event.stopPropagation(); data.onOpen?.(); }}><ChevronRight size={16} /></button>}
    </div>
    {data.endpoints && data.endpoints.length > 0 && <div className="nmap-node-services" aria-label={`${data.endpointCount ?? data.endpoints.length} TLS endpoints`}>
      {data.endpoints.slice(0, 3).map((endpoint) => {
        const address = endpoint.hostname || endpoint.ip_address || data.subtitle || data.label;
        const state = endpoint.compliance_status || "unknown";
        return <span key={endpoint.endpoint_id} title={`${address}:${endpoint.port ?? "—"} · ${state}`}><i className={`nmap-service-dot nmap-service-dot--${state}`} />{address}:{endpoint.port ?? "—"}</span>;
      })}
      {(data.endpointCount ?? data.endpoints.length) > 3 && <small>+{(data.endpointCount ?? data.endpoints.length) - 3}</small>}
    </div>}
  </div>;
}

const nodeTypes = { asset: AssetNode };

function FlowCanvas({ nodes, edges, onFit, onNodeClick }: { nodes: FlowNode[]; edges: Edge[]; onFit?: (fit: () => void) => void; onNodeClick: (_event: React.MouseEvent, node: FlowNode) => void }) {
  const flow = useReactFlow();
  const fit = useCallback(() => { void flow.fitView({ padding: 0.2, duration: 180 }); }, [flow]);
  const nodeSignature = nodes.map((node) => node.id).join("|");
  useEffect(() => { onFit?.(fit); }, [fit, onFit]);
  useEffect(() => {
    const frame = requestAnimationFrame(fit);
    return () => cancelAnimationFrame(frame);
  }, [fit, nodeSignature]);
  return <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} onNodeClick={onNodeClick} fitView fitViewOptions={{ padding: 0.2 }}
    nodesConnectable={false} nodesDraggable={false} elementsSelectable panOnDrag zoomOnScroll zoomOnPinch
    minZoom={0.25} maxZoom={1.8} proOptions={{ hideAttribution: true }}>
    <Background color="var(--border)" gap={24} size={1} />
    <MiniMap pannable zoomable nodeColor={(node) => node.type === "asset" ? "#5286a9" : "#56677c"} />
    <Controls showInteractive={false} />
  </ReactFlow>;
}

export default function NetworkMapFlow({ nodes, graph, links, onSelect, onFit }: Props) {
  const [expandedSubnet, setExpandedSubnet] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<string>();
  useEffect(() => { setExpandedSubnet(null); setSelectedNode(undefined); }, [graph.scope.si?.id, graph.scope.zone?.id, graph.scope.group?.id, graph.mode]);
  const flowNodes = useMemo<FlowNode[]>(() => {
    const zones = [...nodes.filter((node) => node.kind === "zone"), ...(graph.scope.zone ? [{ ...graph.scope.zone, id: `zone:${graph.scope.zone.id}`, kind: "zone" as const }] : [])];
    const hosts = nodes.filter((node) => node.kind === "host");
    const subnetGroups = new Map<string, { label: string; hosts: MapNode[]; zone?: MapNode }>();
    hosts.forEach((host) => {
      const value = host.ip_address || host.value || "";
      const group = subnetFor(value, zones);
      if (!group) return;
      const entry = subnetGroups.get(group.key) ?? { label: group.label, hosts: [], zone: group.zone };
      entry.hosts.push(host); subnetGroups.set(group.key, entry);
    });
    const groupedHostIds = new Set([...subnetGroups.values()].flatMap((group) => group.hosts.map((host) => host.id)));
    const result: FlowNode[] = [];
    const columns = Math.max(1, Math.ceil(Math.sqrt(nodes.length)));
    let index = 0;
    const pushAsset = (id: string, data: FlowData, node?: MapNode) => {
      const current = index++;
      result.push({ id, type: "asset", position: { x: (current % columns) * 350, y: Math.floor(current / columns) * 132 }, data: { ...data, node }, style: { width: data.kind === "subnet" ? 268 : data.kind === "host" ? 320 : 260, background: "transparent", border: 0 } });
    };
    nodes.filter((node) => !groupedHostIds.has(node.id)).forEach((node) => pushAsset(node.id, {
      label: node.name,
      subtitle: node.kind === "host" ? node.ip_address || node.value : node.cidr || node.ip_address || node.ports,
      kind: node.kind,
      node,
      count: node.child_count ?? node.count,
      status: node.exposure?.severity?.critical ? "critical" : node.exposure?.severity?.high ? "high" :
        node.kind === "host" && node.exposure && "non_compliant" in node.exposure && node.exposure.non_compliant > 0 ? "non-compliant" :
          node.kind === "host" && node.exposure && "compliant" in node.exposure && node.exposure.compliant > 0 ? "compliant" : undefined,
      endpoints: node.exposure && "endpoints" in node.exposure ? node.exposure.endpoints : undefined,
      endpointCount: node.exposure && "endpoint_count" in node.exposure ? node.exposure.endpoint_count : undefined,
    }, node));
    subnetGroups.forEach((group, key) => {
      const subnetId = `subnet:${key}`;
      pushAsset(subnetId, { label: group.zone?.name || group.label, subtitle: group.label, kind: "subnet", count: group.hosts.length,
        onOpen: () => setExpandedSubnet((current) => current === key ? null : key) });
      if (expandedSubnet === key) group.hosts.forEach((host) => pushAsset(host.id, {
        label: host.name, subtitle: host.ip_address || host.value, kind: "host", node: host,
        status: host.exposure?.severity?.critical ? "critical" : host.exposure?.severity?.high ? "high" :
          host.exposure && "non_compliant" in host.exposure && host.exposure.non_compliant > 0 ? "non-compliant" :
            host.exposure && "compliant" in host.exposure && host.exposure.compliant > 0 ? "compliant" : undefined,
        endpoints: host.exposure && "endpoints" in host.exposure ? host.exposure.endpoints : undefined,
        endpointCount: host.exposure && "endpoint_count" in host.exposure ? host.exposure.endpoint_count : undefined,
      }, host));
    });
    return result;
  }, [nodes, graph.scope.zone, expandedSubnet]);
  const visibleIds = new Set(flowNodes.map((node) => node.id));
  const safeEdges = useMemo(() => links.filter((edge) => visibleIds.has(edge.source) && visibleIds.has(edge.target)), [links, flowNodes]);
  const handleNodeClick = useCallback((_event: React.MouseEvent, node: FlowNode) => {
    if (node.id.startsWith("subnet:")) { node.data.onOpen?.(); return; }
    const mapNode = nodes.find((item) => item.id === node.id);
    if (mapNode) { setSelectedNode(mapNode.id); onSelect(mapNode); }
  }, [nodes, onSelect]);
  return <div className="network-map-flow" onKeyDown={(event) => { if (event.key === "Escape") setSelectedNode(undefined); }}>
    <ReactFlowProvider><FlowCanvas nodes={flowNodes.map((node) => ({ ...node, selected: node.id === selectedNode }))} edges={safeEdges} onFit={onFit} onNodeClick={handleNodeClick} /></ReactFlowProvider>
  </div>;
}
