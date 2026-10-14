import { ExtensionCategory, Rect, register } from "@antv/g6";
import type { MapGraph, MapNode } from "../api/types";
import type { Messages } from "../i18n/en";

type Translate = (key: keyof Messages) => string;

type GraphNodePosition = { id: string; x: number; y: number; combo?: string };
type CardAttributes = Record<string, unknown> & {
  mapTitle?: string;
  mapSubtitle?: string;
  mapKind?: string;
  mapBadge?: string;
  mapMetrics?: string;
  mapSeverity?: string;
  mapRatio?: number;
  mapAccent?: string;
  mapSeverityColor?: string;
};

const CARD_WIDTH = 232;
const CARD_HEIGHT = 116;
const HOST_CARD_WIDTH = 216;
const HOST_CARD_HEIGHT = 96;
const DEVICE_WIDTH = 208;
const DEVICE_HEIGHT = 92;
const HOST_GAP_X = 46;
const HOST_GAP_Y = 108;
const NODE_GAP_X = 46;
const NODE_GAP_Y = 34;
const DEVICE_ABBREVIATIONS: Record<string, string> = {
  router: "RT", firewall: "FW", gateway: "GW", switch: "SW", load_balancer: "LB",
  reverse_proxy: "RP", server: "SV", subnet: "SN", generic: "NW",
};

function clipped(value: string, max: number): string {
  return value.length > max ? `${value.slice(0, max - 1)}…` : value;
}

function mapCanvasColor(name: string, fallback: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || fallback;
}

class ExposureCardNode extends Rect {
  override render(attributes: Parameters<Rect["render"]>[0], container: Parameters<Rect["render"]>[1]) {
    if (!container) return;
    super.render(attributes, container);
    const card = attributes as unknown as CardAttributes;
    const [width, height] = this.getSize(attributes);
    const left = -width / 2 + 15;
    const top = -height / 2;
    const accent = card.mapAccent || "#7897b4";
    const mainText = mapCanvasColor("--text-primary", "#e9ebf1");
    const secondaryText = mapCanvasColor("--text-secondary", "#aeb6c6");
    const faintText = mapCanvasColor("--text-muted", "#96a0b2");
    const softSurface = mapCanvasColor("--surface-secondary", "#1b1f29");

    this.upsert("map-accent", "rect", { x: -width / 2, y: top, width: 3, height, radius: 2, fill: accent }, container);
    this.upsert("map-kind", "text", {
      x: left, y: top + 19, text: clipped(String(card.mapKind || ""), 24), fontSize: 9,
      fontWeight: 650, letterSpacing: 0.7, fill: accent, textAlign: "left", textBaseline: "middle",
    }, container);
    const compact = height < 105;
    this.upsert("map-badge-bg", "rect", {
      x: left, y: top + 29, width: 28, height: 24, radius: 6, fill: softSurface,
    }, container);
    this.upsert("map-badge", "text", {
      x: left + 14, y: top + 41, text: clipped(String(card.mapBadge || ""), 4), fontSize: 8,
      fontWeight: 700, fill: accent, textAlign: "center", textBaseline: "middle",
    }, container);
    this.upsert("map-title", "text", {
      x: left + 38, y: top + (compact ? 35 : 42), text: clipped(String(card.mapTitle || ""), 23), fontSize: 13,
      fontWeight: 600, fill: mainText, textAlign: "left", textBaseline: "middle",
    }, container);
    this.upsert("map-subtitle", "text", {
      x: left + 38, y: top + (compact ? 51 : 61), text: clipped(String(card.mapSubtitle || ""), 26), fontSize: 10,
      fill: secondaryText, textAlign: "left", textBaseline: "middle",
    }, container);
    this.upsert("map-divider", "rect", {
      x: left, y: top + (compact ? 62 : 76), width: width - 31, height: 1, fill: mapCanvasColor("--border", "#294159"),
    }, container);
    this.upsert("map-metrics", "text", {
      x: left, y: top + (compact ? 74 : 91), text: clipped(String(card.mapMetrics || ""), 34), fontSize: 9,
      fill: faintText, textAlign: "left", textBaseline: "middle",
    }, container);
    this.upsert("map-severity", "text", {
      x: left, y: top + (compact ? 85 : 106), text: clipped(String(card.mapSeverity || ""), 34), fontSize: 9,
      fontWeight: 600, fill: String(card.mapSeverityColor || secondaryText), textAlign: "left", textBaseline: "middle",
    }, container);

    const barY = top + height - 5;
    const barWidth = Math.max(0, (width - 30) * Math.max(0, Math.min(1, Number(card.mapRatio ?? 0))));
    this.upsert("map-progress-track", "rect", {
      x: left, y: barY, width: width - 30, height: 2, radius: 1, fill: softSurface,
    }, container);
    this.upsert("map-progress", "rect", {
      x: left, y: barY, width: barWidth, height: 2, radius: 1, fill: accent,
    }, container);
  }
}

register(ExtensionCategory.NODE, "network-exposure-card", ExposureCardNode);

function cardAccent(node: MapNode): string {
  const severity = node.exposure?.severity;
  if (severity?.critical) return "#dc6b76";
  if (severity?.high) return "#dfa95a";
  if (node.kind === "device") return node.provenance === "OBSERVED" ? "#56a98f" : node.provenance === "INFERRED" ? "#dfa95a" : "#6d9eba";
  if (node.kind === "host" && !node.exposure) return "#78889a";
  if (node.kind === "zone" && (!node.exposure || ("targets" in node.exposure && node.exposure.scanned_targets === 0))) return "#78889a";
  if (node.exposure && "scanned_targets" in node.exposure && node.exposure.scanned_targets > 0) return "#56a98f";
  if (node.kind === "zone") return "#6d9eba";
  return "#7897b4";
}

function exposureMetrics(node: MapNode, t: Translate) {
  const exposure = node.exposure;
  if (node.kind === "host") {
    const scan = exposure && "endpoints" in exposure ? exposure : undefined;
    const severity = scan?.severity ?? {};
    const findingSummary = [
      severity.critical ? `${t("map.criticalShort")}${severity.critical}` : "",
      severity.high ? `${t("map.highShort")}${severity.high}` : "",
      severity.medium ? `${t("map.mediumShort")}${severity.medium}` : "",
      severity.low ? `${t("map.lowShort")}${severity.low}` : "",
    ].filter(Boolean).join("   ");
    return {
      subtitle: [node.value || node.name, node.ports ? `:${node.ports}` : ""].filter(Boolean).join(" · "),
      metrics: scan ? `${scan.endpoints.length} ${t("map.endpoints")}` : t("map.notScannedState"),
      severity: scan ? findingSummary || (scan.endpoints.length ? t("map.noFindings") : t("map.notScannedState")) : "",
      ratio: scan ? 1 : 0,
    };
  }
  if (!exposure || !("targets" in exposure)) {
    const count = node.count ?? 0;
    return {
      subtitle: node.kind === "device" ? node.ip_address || t("map.device") : `${count} ${t("map.targets")}`,
      metrics: node.kind === "device" ? t(`map.provenance.${node.provenance || "DECLARED"}` as keyof Messages) : t("map.notScannedState"),
      severity: "",
      ratio: 0,
    };
  }
  const targetLabel = `${exposure.targets} ${t("map.targets")}`;
  const metrics = `${exposure.scanned_targets} ${t("map.scanned")} · ${exposure.unscanned_targets} ${t("map.unscanned")}`;
  const severity = exposure.severity || {};
  const findingSummary = [
    severity.critical ? `${t("map.criticalShort")}${severity.critical}` : "",
    severity.high ? `${t("map.highShort")}${severity.high}` : "",
    severity.medium ? `${t("map.mediumShort")}${severity.medium}` : "",
    severity.low ? `${t("map.lowShort")}${severity.low}` : "",
  ].filter(Boolean).join("   ") || (exposure.scanned_targets ? t("map.noFindings") : t("map.notScannedState"));
  return {
    subtitle: node.kind === "zone" ? [node.cidr || node.zone_type, targetLabel].filter(Boolean).join(" · ") :
      node.kind === "si" ? `${targetLabel} · ${node.child_count ?? 0} ${t("map.subsystems")}` : targetLabel,
    metrics,
    severity: findingSummary,
    ratio: exposure.targets ? Math.min(1, exposure.scanned_targets / exposure.targets) : 0,
  };
}

function nodeSubtitle(node: MapNode, t: Translate): string {
  if (node.kind === "si") return t("map.systems");
  if (node.kind === "zone") return t("map.zone");
  if (node.kind === "group") return t("map.group");
  if (node.kind === "unassigned") return t("map.unassigned");
  if (node.kind === "device") return t(`map.deviceType.${node.device_type || "generic"}` as keyof Messages);
  return t("map.host");
}

function nodeBadge(node: MapNode): string {
  if (node.kind === "si") return "SI";
  if (node.kind === "zone") return clipped((node.zone_type || "ZONE").toUpperCase(), 4);
  if (node.kind === "group") return "GRP";
  if (node.kind === "unassigned") return "—";
  if (node.kind === "device") return DEVICE_ABBREVIATIONS[node.device_type || "generic"] || "NW";
  return "TLS";
}

export function mapCardAttributes(node: MapNode, t: Translate) {
  const exposure = exposureMetrics(node, t);
  const severity = node.exposure?.severity ?? {};
  const severityColor = severity.critical ? "#dc6b76" : severity.high ? "#dfa95a" : cardAccent(node);
  const title = node.name;
  return {
    type: "network-exposure-card" as const,
    style: {
      size: node.kind === "host" ? [HOST_CARD_WIDTH, HOST_CARD_HEIGHT] as [number, number] :
        node.kind === "device" ? [DEVICE_WIDTH, DEVICE_HEIGHT] as [number, number] : [CARD_WIDTH, CARD_HEIGHT] as [number, number],
      radius: 10,
      fill: mapCanvasColor("--surface", "#14171f"),
      fillOpacity: 0.98,
      stroke: mapCanvasColor("--border-strong", "#294159"),
      lineWidth: 1,
      labelText: "",
      mapTitle: title,
      mapBadge: nodeBadge(node),
      mapKind: nodeSubtitle(node, t),
      mapSubtitle: exposure.subtitle,
      mapMetrics: exposure.metrics,
      mapSeverity: exposure.severity,
      mapRatio: exposure.ratio,
      mapAccent: cardAccent(node),
      mapSeverityColor: severityColor,
    },
  };
}

function placeLane(nodes: MapNode[], y: number, viewportWidth: number, kind: "card" | "host" = "card", xOffset = 0): GraphNodePosition[] {
  if (!nodes.length) return [];
  const width = kind === "host" ? HOST_CARD_WIDTH : CARD_WIDTH;
  const gapX = kind === "host" ? HOST_GAP_X : NODE_GAP_X;
  const gapY = kind === "host" ? HOST_GAP_Y : CARD_HEIGHT + NODE_GAP_Y;
  const columns = Math.max(1, Math.min(kind === "host" ? 12 : 5, Math.floor((Math.max(viewportWidth, 420) - 120) / (width + gapX))));
  const rows = Math.ceil(nodes.length / columns);
  const positions: GraphNodePosition[] = [];
  for (let index = 0; index < nodes.length; index += 1) {
    const row = Math.floor(index / columns);
    const rowStart = row * columns;
    const rowLength = Math.min(columns, nodes.length - rowStart);
    const column = index - rowStart;
    const stagger = row % 2 ? (width + gapX) * 0.22 : 0;
    const x = xOffset + (column - (rowLength - 1) / 2) * (width + gapX) + stagger;
    const yPosition = y + (row - (rows - 1) / 2) * gapY + (row % 2 ? 12 : -12);
    positions.push({ id: nodes[index].id, x, y: yPosition });
  }
  return positions;
}

export function positionMapNodes(nodes: MapNode[], graph: MapGraph, viewportWidth: number): GraphNodePosition[] {
  const ordered = [...nodes].sort((a, b) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id));
  const { si, zone, group } = graph.scope;
  if (zone) {
    const positions = [
      ...placeLane(ordered.filter((item) => item.kind === "zone"), -150, viewportWidth),
      ...placeLane(ordered.filter((item) => item.kind === "device"), 10, viewportWidth),
      ...placeLane(ordered.filter((item) => item.kind === "host"), 170, viewportWidth, "host"),
    ];
    return positions;
  }
  if (si) {
    if (graph.mode === "network") {
      const zones = ordered.filter((item) => item.kind === "zone");
      const devices = ordered.filter((item) => item.kind === "device");
      const deviceIds = new Set<string>();
      const clusters = zones.map((zone) => {
        const members = [zone, ...devices.filter((device) => device.zone_id === zone.zone_id)];
        members.slice(1).forEach((device) => deviceIds.add(device.id));
        const innerColumns = Math.min(2, members.length);
        const rows = Math.ceil(members.length / innerColumns);
        return { zone, members, innerColumns, rows, height: rows * (CARD_HEIGHT + 26) + 48 };
      });
      const clusterWidth = 2 * (CARD_WIDTH + 26) + 64;
      const parentColumns = Math.max(1, Math.min(2, Math.floor((Math.max(viewportWidth, 560) - 120) / (clusterWidth + 72))));
      const rowCount = Math.ceil(clusters.length / parentColumns);
      const rowHeights = Array.from({ length: rowCount }, (_, row) => Math.max(0, ...clusters.slice(row * parentColumns, (row + 1) * parentColumns).map((cluster) => cluster.height)));
      const totalClusterHeight = rowHeights.reduce((total, value) => total + value, 0) + Math.max(0, rowCount - 1) * 54;
      let cursorY = -totalClusterHeight / 2;
      const positions: GraphNodePosition[] = [];
      clusters.forEach((cluster, index) => {
        const row = Math.floor(index / parentColumns);
        const column = index % parentColumns;
        const rowLength = Math.min(parentColumns, clusters.length - row * parentColumns);
        const centerX = (column - (rowLength - 1) / 2) * (clusterWidth + 72);
        const centerY = cursorY + rowHeights[row] / 2;
        const zoneCombo = cluster.members.length > 1 ? `zone-group:${cluster.zone.zone_id}` : undefined;
        cluster.members.forEach((item, memberIndex) => {
          const itemRow = Math.floor(memberIndex / cluster.innerColumns);
          const rowLength = Math.min(cluster.innerColumns, cluster.members.length - itemRow * cluster.innerColumns);
          const itemColumn = memberIndex % cluster.innerColumns;
          positions.push({
            id: item.id,
            x: centerX + (itemColumn - (rowLength - 1) / 2) * (CARD_WIDTH + 26),
            y: centerY + (itemRow - (cluster.rows - 1) / 2) * (CARD_HEIGHT + 26),
            combo: zoneCombo,
          });
        });
        cursorY += rowHeights[row] + 54;
      });
      const clusterTop = -totalClusterHeight / 2;
      const clusterBottom = totalClusterHeight / 2;
      const freeDevices = devices.filter((device) => !deviceIds.has(device.id));
      positions.push(
        ...placeLane(ordered.filter((item) => item.kind === "si"), clusterTop - 112, viewportWidth),
        ...placeLane(freeDevices, clusterBottom + 170, viewportWidth),
        ...placeLane(ordered.filter((item) => item.kind === "group" || item.kind === "unassigned"), clusterBottom + 190, viewportWidth),
        ...placeLane(ordered.filter((item) => item.kind === "host"), clusterBottom + 245, viewportWidth, "host"),
      );
      return positions;
    }
    const positions = [
      ...placeLane(ordered.filter((item) => item.kind === "si"), -220, viewportWidth),
      ...placeLane(ordered.filter((item) => item.kind === "zone"), 0, viewportWidth),
      ...placeLane(ordered.filter((item) => item.kind === "group" || item.kind === "unassigned"), 210, viewportWidth),
      ...placeLane(ordered.filter((item) => item.kind === "host"), 380, viewportWidth, "host"),
    ];
    return positions;
  }
  if (group) return placeLane(ordered.filter((item) => item.kind === "host"), 0, viewportWidth, "host");
  return placeLane(ordered.filter((item) => item.kind === "si"), 0, viewportWidth);
}

