import { LatencyBadge } from "./LatencyBadge";
import { Button, Tag, Typography } from "antd";
import { useState } from "react";
import * as api from "./api";
import type { GroupHubState, Link, MeshLegReport, Topology } from "./types";
import {
  ApiErrorAlert,
  Fold,
  useApi,
  Note,
  StatusTag,
} from "./ui";

const LEG: Record<string, string> = { direct: "直连 WireGuard", mesh: "Mesh 上的 WireGuard", blackhole: "双腿不可用 · 黑洞" };
const WHY: Record<string, string> = { stable: "保持", both_down: "双腿无响应", direct_down: "直连无响应", mesh_down: "Mesh 无响应", reachable: "恢复可达", quality: "Mesh 质量持续更好", direct_recovered: "直连持续达标且冷却结束", route_failed: "路由更新失败" };

function MeshLegChoices({ report, events }: { report?: MeshLegReport; events: MeshLegReport[] }) {
  const active = report?.result === "ok" ? report.active : undefined;
  const lastSwitch = report?.switched && events.find(event =>
    event.result === "ok" && event.active === active && event.switched === report.switched,
  );
  const reason = !report ? "暂无样本"
    : report.result !== "ok" ? "切换失败"
    : active === "blackhole" ? "两条链路均不可用"
    : lastSwitch && report.reason === "stable" ? WHY[lastSwitch.reason]
    : report.reason !== "stable" ? WHY[report.reason] : undefined;
  return <>
    {(["direct", "mesh"] as const).map(leg => {
      const rtt = leg === "direct" ? report?.direct_rtt : report?.mesh_rtt;
      const loss = leg === "direct" ? report?.direct_loss : report?.mesh_loss;
      return <div key={leg} style={{ display: "flex", alignItems: "center", flexWrap: "wrap", gap: 4, marginBlock: 2 }}>
        {active === leg ? <StatusTag kind="ok">{leg === "direct" ? "直连" : "Mesh"} · 使用中</StatusTag>
          : <Typography.Text type="secondary">{leg === "direct" ? "直连" : "Mesh"}</Typography.Text>}
        {loss !== undefined ? <>
          <LatencyBadge ms={loss < 1000 ? rtt : undefined} failed={loss === 1000} label={loss === 1000 ? "无响应" : "无延迟样本"} title="枢纽到出口的探测延迟" />
          <Tag color={loss === 1000 ? "error" : loss > 0 ? "warning" : "default"}>丢包 {loss / 10}%</Tag>
        </> : null}
        {active === leg && reason ? <Typography.Text type="secondary">{reason}</Typography.Text> : null}
        {leg === "mesh" && (!active || active === "blackhole") && reason
          ? <Typography.Text type="secondary">{` · ${reason}`}</Typography.Text> : null}
      </div>;
    })}
  </>;
}

export function ExitMeshCarrier({ exit, topo, hubs, refresh }: {
  exit: string;
  topo: Topology;
  hubs: GroupHubState[];
  refresh: () => void;
}) {
  const peers = topo.nodes.filter(node => node.role === "hub" && topo.links.some(link =>
    link.enabled && link.transport === "cf_mesh" &&
    ((link.from === node.id && link.to === exit) || (link.from === exit && link.to === node.id)),
  ));
  if (!peers.length) return null;
  return <div className="state-line" data-testid={`exit-mesh-${exit}`}>
    {peers.map(peer => {
      const hub = hubs.find(h => h.hub_node === peer.id);
      const reports = hub?.mesh_legs ?? [];
      const current = reports.find(r => r.exit === exit && !r.event);
      return <div key={peer.id}>
        <strong>{peer.name || peer.id}{hub?.carrying ? "（承载中）" : ""}</strong>
        <MeshLegChoices report={current} events={reports.filter(r => r.exit === exit && r.event)} />
      </div>;
    })}
    <Button type="link" size="small" onClick={refresh}>刷新 Mesh 状态</Button>
  </div>;
}

/** The source is the hub's fixed read, not a panel simulation. */
/** ids are exit IDs, or "exit@hub" when both hubs have a Mesh leg to exits (a report then matches its hub). */
export function MeshLegRows({ reports, ids, history = false, hubNames = {} }: { reports: MeshLegReport[]; ids: string[]; history?: boolean; hubNames?: Record<string, string> }) {
  const legOf = (id: string) => { const i = id.lastIndexOf("@"); return i < 0 ? { exit: id, hub: "" } : { exit: id.slice(0, i), hub: id.slice(i + 1) }; };
  const label = (exit: string, hub?: string) => hub ? `${exit} · 经 ${hubNames[hub] ?? hub}` : exit;
  const events = reports.filter((r) => r.event).sort((a, b) => b.beat - a.beat);
  return <div data-testid="mesh-leg-quality" style={{ overflowWrap: "anywhere" }}>
    {ids.map((id) => {
      const leg = legOf(id);
      const matching = reports.filter(r => r.exit === leg.exit && (!leg.hub || r.hub === leg.hub));
      const r = matching.find(r => !r.event);
      return <div key={id} style={{ padding: "8px 0" }}><div><strong>{label(leg.exit, leg.hub)}</strong></div><MeshLegChoices report={r} events={matching.filter(r => r.event)} /></div>;
    })}
    {history ? <details><summary>枢纽切换记录（每出口最近 32 条，重启后清空）</summary>
      {events.length ? events.map((r, i) => <div key={`${r.exit}-${r.hub ?? ""}-${r.beat}-${i}`} style={{ padding: "8px 0" }}>{label(r.exit, r.hub)} · {r.result === "ok" ? LEG[r.active] : "切换失败"} · {WHY[r.reason]} · {new Date(r.beat * 1000).toLocaleString()}</div>) : <div>尚无有效切换记录</div>}
    </details> : null}
  </div>;
}

export function MeshLegQuality({ topo, history = false }: { topo?: Topology | null; history?: boolean }) {
  if (!topo || !topo.links.some((l) => l.enabled && l.transport === "cf_mesh")) return null;
  return <MeshLegRead topo={topo} history={history} />;
}
function MeshLegRead({ topo, history }: { topo: Topology; history: boolean }) {
  const view = useApi(() => api.listGroups(), []);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<api.ApiError | undefined>();
  // One row per hub → exit Mesh leg; the hub is named only when the backup
  // hub has Mesh legs too (each hub switches its own legs).
  const legs = topo.links.filter((l) => l.enabled && l.transport === "cf_mesh").map((l) => {
    const exit = topo.nodes.find((n) => n.role === "exit" && (n.id === l.from || n.id === l.to))?.id;
    const hub = topo.nodes.find((n) => n.role === "hub" && (n.id === l.from || n.id === l.to))?.id;
    return exit ? { exit, hub: hub ?? "" } : undefined;
  }).filter((x): x is { exit: string; hub: string } => !!x);
  const multiHub = new Set(legs.map((l) => l.hub)).size > 1;
  const ids = [...new Set(legs.map((l) => multiHub ? `${l.exit}@${l.hub}` : l.exit))];
  const hubNames = Object.fromEntries(topo.nodes.filter((n) => n.role === "hub").map((n) => [n.id, n.name || n.id]));
  const hubs = view.data?.hub_states ?? (view.data?.hub_state ? [view.data.hub_state] : []);
  const read = async () => {
    setBusy(true); setError(undefined);
    try { view.setData(await api.refreshGroupRuntime()); } catch (e) { setError(api.isApiError(e) ? e : new api.ApiError(500, { error: String(e) })); } finally { setBusy(false); }
  };
  const reports = hubs.flatMap((h) => (h.mesh_legs ?? []).map((r) => ({ ...r, hub: h.hub_node })));
  const now = ids.map((id) => { const at = id.lastIndexOf("@"); const exit = at < 0 ? id : id.slice(0, at), hub = at < 0 ? "" : id.slice(at + 1); return reports.find((r) => r.exit === exit && (!hub || r.hub === hub) && !r.event); });
  const known = now.filter((r) => r && r.result === "ok");
  const down = known.filter((r) => r!.active === "blackhole").length;
  const failed = now.filter((r) => r && r.result !== "ok").length;
  const summary = <span data-testid="mesh-leg-summary">
    {ids.length} {multiHub ? "条 Mesh 腿" : "个出口"} · {known.length ? `直连 ${known.filter((r) => r!.active === "direct").length} / Mesh ${known.filter((r) => r!.active === "mesh").length}` : "尚未读取"}
    {down + failed > 0 ? <span className="problem-bad"> · {down + failed} 个需要处理</span> : null}
  </span>;
  return <Fold title="同出口双腿质量" summary={summary} testId="fold-mesh-legs" extra={<Button loading={busy} aria-label="读取双腿质量与切换记录" onClick={() => void read()}>读取</Button>}>
    <ApiErrorAlert error={error || view.error} />
    <MeshLegRows reports={reports} ids={ids} history={history} hubNames={hubNames} />
    <Note title="同出口双腿质量">只切换枢纽到同一出口的一跳；双断时黑洞。质量与切换记录来自枢纽读取时的快照。「读取」同时读取双腿质量与切换记录。</Note>
  </Fold>;
}

/** A leg report with the hub it came from (hub_states[].hub_node). */
export type HubLegReport = MeshLegReport & { hub?: string };

/** The way a link carries WireGuard, in three words: WG 直连, WSS or Mesh. */
export function transportKind(t: Link["transport"]): string {
  switch (t) {
    case "cf_mesh":
      return "Mesh";
    case "wg_over_wss":
    case "ix_replacement_wss":
      return "WSS";
    case "udp_wss_failover":
      return "WG 直连 · WSS 备用";
    default:
      return "WG 直连";
  }
}

const ends = (l: Link, topo: Topology) => {
  const role = (id: string) => topo.nodes.find((n) => n.id === id)?.role;
  const hub = role(l.from) === "hub" ? l.from : role(l.to) === "hub" ? l.to : undefined;
  const exit = role(l.from) === "exit" ? l.from : role(l.to) === "exit" ? l.to : undefined;
  return { hub, exit };
};

const SHORT_WHY: Record<string, string> = { direct_down: "直连不通", both_down: "双腿不通", quality: "直连丢包", route_failed: "路由更新失败" };

/**
 * What a link shows on the topology: its transport and, where the same
 * hub → exit hop also has a Mesh leg, which leg carries now from the hub's
 * mesh_legs report ("直连 · Mesh 备用", "Mesh（直连丢包）"). Without a
 * report the leg in use is said to be unknown, never assumed.
 */
export function linkCarrier(l: Link, topo: Topology, reports: HubLegReport[] | null): { label: string; state: "plain" | "direct" | "mesh" | "blackhole" | "unknown" } {
  const base = transportKind(l.transport);
  const { hub, exit } = ends(l, topo);
  if (!hub || !exit || !l.enabled) return { label: base, state: "plain" };
  const twin = topo.links.find((o) => o.id !== l.id && o.enabled && (o.transport === "cf_mesh") !== (l.transport === "cf_mesh") && ends(o, topo).hub === hub && ends(o, topo).exit === exit);
  if (!twin) return { label: base, state: "plain" };
  const meshLink = l.transport === "cf_mesh";
  const r = (reports ?? []).find((x) => x.exit === exit && !x.event && (!x.hub || x.hub === hub));
  if (!r || r.result !== "ok") return { label: meshLink ? "Mesh 备用 · 实际未知" : "直连 · Mesh 备用 · 实际未知", state: "unknown" };
  if (r.active === "blackhole") return { label: "双腿不通", state: "blackhole" };
  if (r.active === "mesh") {
    const why = r.reason === "quality" && !r.direct_loss ? "Mesh 更好" : SHORT_WHY[r.reason] ?? "已切换";
    return { label: meshLink ? `Mesh 使用中（${why}）` : `Mesh（${why}）`, state: "mesh" };
  }
  return { label: meshLink ? "Mesh 备用" : "直连 · Mesh 备用", state: "direct" };
}
