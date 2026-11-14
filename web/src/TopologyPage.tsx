// 拓扑: the visual editor of nodes and links. The canvas is the map; a node
// or link opens in a side drawer. Managed nodes pick a server from the
// server list (address, login and host key live there, never in the
// topology). Edits change the working copy; the document bar saves it.

import {
  ApartmentOutlined,
  DeleteOutlined,
  ExpandOutlined,
  PlusOutlined,
  SettingOutlined,
} from "@ant-design/icons";
import {
  Background,
  Controls,
  MiniMap,
  ReactFlow,
  ReactFlowProvider,
  useEdgesState,
  useNodesState,
  useReactFlow,
  type Connection,
  type Edge,
  type Node as RFNode,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import {
  Alert,
  AutoComplete,
  Button,
  Collapse,
  Divider,
  Drawer,
  Dropdown,
  Form,
  Input,
  InputNumber,
  Modal,
  Radio,
  Select,
  Space,
  Switch,
  Tag,
  Tooltip,
  Typography,
} from "antd";
import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import * as api from "./api";
import { WSSLinkStatus } from "./WSS";
import { PathQualitySettings } from "./RelaySharing";
import { serverReadiness } from "./ServersPage";
import { href, useRouter, useTopologyDoc } from "./state";
import type {
  AllocationChange,
  AllocationView,
  DeploymentView,
  Issue,
  LinkAllocation,
  Link as TLink,
  Node,
  Role,
  ServerView,
  Settings,
  Topology,
  Transport,
} from "./types";
import { DEPLOYMENT_STATUS, WithdrawDialog, withdrawSucceeded } from "./Withdraw";
import { roleLabel, transportLabel } from "./types";
import {
  ApiErrorAlert,
  Facts,
  Link,
  Mono,
  Page,
  REGION_CODES,
  Section,
  StatusTag,
  TopologyDocBar,
  groupLabel,
  regionLabel,
  useApi,
  useConfirmDanger,
} from "./ui";

const ROLE_HELP: Record<Role, string> = {
  gateway: "本机：家里的网关，LAN 流量从这里进入。",
  relay: "国内中继（例如阿里云），把流量送进 IX 专线。",
  ix: "IX 专线的一段，不需要装机，也没有服务器。",
  hub: "境外枢纽，按地区组把流量分给各个出口。",
  exit: "出口：流量在这里离开到公网。",
};

const TRANSPORT_HELP: Record<Transport, string> = {
  direct_wg: "普通 WireGuard（UDP）。",
  wg_over_wss: "WireGuard 套在 WebSocket over TLS 里，用于 UDP 被限制的线路。",
  udp_wss_failover: "平时 UDP，UDP 不通时改走 WSS。",
  ix_replacement_wss: "IX 故障时的替代路线，平时待命，不进默认路由；网关到备用枢纽也用它（端口是备用枢纽的 WSS 监听端口）。",
  dedicated_line: "IX 专线本身（不是 WireGuard 隧道）。",
  cf_mesh: "Cloudflare Mesh 备路：组内成员都不可用时的最后一跳，平时待命（数据面未验证）。",
};

const WORKAROUND: Record<string, string> = {
  dualstack_relay: "双栈中继",
  mesh: "Mesh",
  v4_front: "v4 前置",
};

type Selection = { kind: "node" | "link"; id: string } | null;

// ----------------------------------------------------------------- canvas ---

function nodeLabel(n: Node, server: ServerView | undefined) {
  const flags = [
    n.role === "hub" && n.hub_tier === "backup" ? "备用" : null,
    n.role === "hub" && n.ix_line && n.hub_tier !== "backup" ? "IX 即主枢纽" : null,
    n.residential ? "住宅" : null,
    n.ix_bound ? "IX 绑定" : null,
    n.nat_dial_out ? "拨出" : null,
    n.role === "exit" && n.via_exit ? `经 ${n.via_exit} 中继` : null,
    n.role === "exit" && n.external ? "外部 SOCKS · 仅 TCP" : null,
  ]
    .filter(Boolean)
    .join(" · ");
  const needsServer = n.managed && n.role !== "gateway";
  const meta = `${roleLabel[n.role]}${n.region ? ` · ${n.region.toUpperCase()}` : ""}${flags ? ` · ${flags}` : ""}`;
  const serverText = needsServer ? (server ? `${server.name}${server.ready ? "" : " · 未就绪"}` : "未选服务器") : "";
  // One line each, cut with "…"; the whole text is the card's title (hover).
  return (
    <div className="node-card" title={[n.name || n.id, meta, serverText].filter(Boolean).join("\n")}>
      <strong>{n.name || n.id}</strong>
      <em>{meta}</em>
      {needsServer ? <span className={`node-server ${server ? (server.ready ? "ok" : "warn") : "missing"}`}>{serverText}</span> : null}
    </div>
  );
}

/** Spacing of the automatic layout: a node card is 200 px wide; the gap leaves room for the link labels. */
export const LAYOUT = { colWidth: 300, rowHeight: 130, rowsPerColumn: 5 } as const;
const ROLE_ORDER: Role[] = ["gateway", "relay", "ix", "hub", "exit"];

/**
 * Positions for a left-to-right layered layout (gateway → relay → IX → hub →
 * exit). A layer with more than LAYOUT.rowsPerColumn nodes wraps into further
 * columns, so many exits do not make one tall column. Display only: used for
 * nodes without a saved position, and by「自动排列」on request.
 */
export function autoLayout(nodes: Node[], groups?: readonly { members: string[] }[]): Map<string, { x: number; y: number }> {
  const out = new Map<string, { x: number; y: number }>();
  // Exits of one region group next to each other (fewer crossing links);
  // an exit reached through another exit goes into a layer to the right,
  // in the order of its carrier.
  const groupOf = (id: string) => {
    const i = (groups ?? []).findIndex((g) => g.members.includes(id));
    return i < 0 ? Number.MAX_SAFE_INTEGER : i;
  };
  const isNested = (n: Node) => n.role === "exit" && !!n.via_exit;
  const layers: Node[][] = [];
  const roles = [...ROLE_ORDER, ...new Set(nodes.map((n) => n.role).filter((r) => !ROLE_ORDER.includes(r)))];
  for (const role of roles) {
    let layer = nodes.filter((n) => n.role === role && !isNested(n));
    if (role === "exit") layer = [...layer].sort((a, b) => groupOf(a.id) - groupOf(b.id));
    layers.push(layer);
    if (role === "exit") {
      const order = new Map(layer.map((n, i) => [n.id, i]));
      layers.push(nodes.filter(isNested).sort((a, b) => (order.get(a.via_exit!) ?? 99) - (order.get(b.via_exit!) ?? 99)));
    }
  }
  let col = 0;
  for (const layer of layers) {
    if (layer.length === 0) continue;
    const cols = Math.ceil(layer.length / LAYOUT.rowsPerColumn);
    const rows = Math.min(layer.length, LAYOUT.rowsPerColumn);
    layer.forEach((n, i) => {
      const c = Math.floor(i / LAYOUT.rowsPerColumn);
      const r = i % LAYOUT.rowsPerColumn;
      // Centre short layers against the tallest possible layer.
      const offset = ((LAYOUT.rowsPerColumn - rows) * LAYOUT.rowHeight) / 2;
      out.set(n.id, { x: (col + c) * LAYOUT.colWidth, y: offset + r * LAYOUT.rowHeight });
    });
    col += cols;
  }
  return out;
}

function toFlow(topo: Topology, servers: Map<string, ServerView>, issues: Issue[]): { nodes: RFNode[]; edges: Edge[] } {
  const bad = new Set(issues.filter((i) => i.severity === "error").flatMap((i) => [i.node_id, i.link_id]).filter(Boolean) as string[]);
  // Nodes that were never placed get a layered position instead of all sitting at 0,0.
  const auto = topo.nodes.some((n) => n.x === undefined && n.y === undefined) ? autoLayout(topo.nodes, topo.region_groups) : null;
  return {
    nodes: topo.nodes.map((n) => ({
      id: n.id,
      position: n.x === undefined && n.y === undefined && auto ? auto.get(n.id)! : { x: n.x ?? 0, y: n.y ?? 0 },
      data: { label: nodeLabel(n, n.server_id ? servers.get(n.server_id) : undefined) },
      className: `topo-node role-${n.role}${n.residential ? " residential" : ""}${n.role === "exit" && n.external ? " external" : ""}${n.role === "exit" && n.via_exit ? " nested" : ""}${bad.has(n.id) ? " has-error" : ""}`,
    })),
    edges: topo.links.map((l) => ({
      id: l.id,
      source: l.from,
      target: l.to,
      label: transportLabel[l.transport] + (l.standby ? " · 待命" : "") + (l.enabled ? "" : " · 停用"),
      labelBgPadding: [6, 3] as [number, number],
      labelBgBorderRadius: 4,
      animated: !l.standby && l.enabled,
      className: `topo-edge${l.standby ? " standby" : ""}${l.enabled ? "" : " disabled"}${bad.has(l.id) ? " has-error" : ""}`,
    })),
  };
}

function Canvas({
  topo,
  servers,
  issues,
  onSelect,
  onChange,
}: {
  topo: Topology;
  servers: Map<string, ServerView>;
  issues: Issue[];
  onSelect: (s: Selection) => void;
  onChange: (t: Topology) => void;
}) {
  const initial = useMemo(() => toFlow(topo, servers, issues), [topo, servers, issues]);
  const [nodes, setNodes, onNodesChange] = useNodesState(initial.nodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initial.edges);
  const flow = useReactFlow();

  useEffect(() => {
    // Keep positions the user is dragging; take everything else from the document.
    setNodes((cur) => {
      const pos = new Map(cur.map((n) => [n.id, n.position]));
      return initial.nodes.map((n) => ({ ...n, position: pos.get(n.id) ?? n.position }));
    });
    setEdges(initial.edges);
  }, [initial, setNodes, setEdges]);

  const onConnect = useCallback(
    (conn: Connection) => {
      if (!conn.source || !conn.target || conn.source === conn.target) return;
      let id = `${conn.source}-${conn.target}`;
      for (let i = 2; topo.links.some((l) => l.id === id); i++) id = `${conn.source}-${conn.target}-${i}`;
      const link: TLink = { id, from: conn.source, to: conn.target, transport: "direct_wg", enabled: true, standby: false, mtu: 1420, keepalive: 25 };
      onChange({ ...topo, links: [...topo.links, link] });
      onSelect({ kind: "link", id });
    },
    [onChange, onSelect, topo],
  );

  return (
    <div className="canvas-wrap" data-testid="topology-canvas">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onConnect={onConnect}
        deleteKeyCode={null}
        onNodeDragStop={(_, node) =>
          onChange({ ...topo, nodes: topo.nodes.map((n) => (n.id === node.id ? { ...n, x: Math.round(node.position.x), y: Math.round(node.position.y) } : n)) })
        }
        onNodeClick={(_, n) => onSelect({ kind: "node", id: n.id })}
        onEdgeClick={(_, e) => onSelect({ kind: "link", id: e.id })}
        onPaneClick={() => onSelect(null)}
        fitView
        fitViewOptions={{ padding: 0.12, maxZoom: 1.1 }}
        minZoom={0.3}
        proOptions={{ hideAttribution: true }}
      >
        <Background gap={18} />
        <MiniMap pannable zoomable />
        <Controls showInteractive={false} />
      </ReactFlow>
      <Space size={4} className="canvas-fit">
        <Tooltip title="按 网关 → 中继 → IX → 枢纽 → 出口 重新排列全部节点；改的只是画布位置，保存后记住">
          <Button
            size="small"
            onClick={() => {
              const pos = autoLayout(topo.nodes, topo.region_groups);
              onChange({ ...topo, nodes: topo.nodes.map((n) => ({ ...n, ...(pos.get(n.id) ?? {}) })) });
              setNodes((cur) => cur.map((n) => ({ ...n, position: pos.get(n.id) ?? n.position })));
              window.setTimeout(() => flow.fitView({ duration: 200 }), 0);
            }}
          >
            自动排列
          </Button>
        </Tooltip>
        <Button size="small" icon={<ExpandOutlined />} onClick={() => flow.fitView({ duration: 200 })}>
          适应画布
        </Button>
      </Space>
    </div>
  );
}

// ------------------------------------------------------------ node drawer ---

function Row({ label, help, children }: { label: ReactNode; help?: ReactNode; children: ReactNode }) {
  return (
    <Form.Item label={label} extra={help} style={{ marginBottom: 12 }}>
      {children}
    </Form.Item>
  );
}

function Flag({ label, help, checked, onChange, disabled }: { label: string; help: string; checked: boolean; onChange: (v: boolean) => void; disabled?: boolean }) {
  return (
    <div className="flag-row">
      <div>
        <div>{label}</div>
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
          {help}
        </Typography.Text>
      </div>
      <Switch size="small" checked={checked} onChange={onChange} disabled={disabled} aria-label={label} />
    </div>
  );
}

// ------------------------------------------------------------- hub roles ---

/** A hub's tier as the backend reads it: empty on a lone hub means primary. */
export function hubTierOf(n: Node, topo: Topology): "primary" | "backup" | "" {
  if (n.hub_tier) return n.hub_tier;
  return topo.nodes.filter((x) => x.role === "hub").length === 1 ? "primary" : "";
}

function isIXHub(n: Node): boolean {
  return n.role === "hub" && !!n.ix_line && n.hub_tier !== "backup";
}

/** Old single-hub topology with an unmanaged ix node: the IX can now be the managed primary hub. */
export function needsIXHubMigrationNotice(t: Topology): boolean {
  return t.nodes.some((n) => n.role === "ix") && t.nodes.filter((n) => n.role === "hub").length === 1;
}

function HubRoleFields({ node, topo, patch }: { node: Node; topo: Topology; patch: (p: Partial<Node>) => void }) {
  const tier = hubTierOf(node, topo);
  const hubs = topo.nodes.filter((n) => n.role === "hub");
  return (
    <div data-testid="hub-role">
      <Row
        label="枢纽角色"
        help={
          tier === ""
            ? "有多个枢纽时每个都要指定角色：最多一个主枢纽、一个备用枢纽。"
            : tier === "backup"
              ? "备用枢纽：只有主路径整条不通时，网关才经 WSS 上的 WireGuard 拨它（链路传输方式选「IX 替换 WSS」、待命，端口是备用枢纽的 WSS 监听端口）。每个出口都要同时有到两个枢纽的隧道（非待命）。"
              : hubs.length > 1
                ? "主枢纽：平时承载流量（网关 → 中继 → IX → 主枢纽）。每个出口都要同时有到两个枢纽的隧道（非待命）。"
                : "主枢纽：平时承载流量（网关 → 中继 → IX → 主枢纽）。可以再加一个备用枢纽，主路径整条不通时由它承载。"
        }
      >
        <Select
          value={tier || undefined}
          placeholder="选择角色"
          aria-label="枢纽角色"
          options={[
            { value: "primary", label: "主枢纽" },
            { value: "backup", label: "备用枢纽" },
          ]}
          onChange={(v: "primary" | "backup") =>
            patch(v === "backup" ? { hub_tier: v, ix_line: undefined, ingress_v4: undefined, ingress_interface: undefined } : { hub_tier: v })
          }
        />
      </Row>
      {tier !== "backup" ? (
        <Flag
          label="IX 即主枢纽"
          help="这台主枢纽就是 IX：专线上一台能登录、受管的服务器。它通过所选的服务器记录装机和下发（可以是中继上的端口转发，只用密码登录也可以）。中继用普通 WireGuard 拨它的国内入口地址，出口拨它的香港出口地址。"
          checked={!!node.ix_line}
          onChange={(v) => patch(v ? { ix_line: true, hub_tier: node.hub_tier ?? (hubs.length > 1 ? "primary" : undefined) } : { ix_line: undefined, ingress_v4: undefined, ingress_interface: undefined })}
        />
      ) : null}
    </div>
  );
}

/** How an exit is reached (nested, external SOCKS, dynamic DNS endpoint); edited on the exits page. */
function ExitReachFacts({ node, topo }: { node: Node; topo: Topology }) {
  const nm = (id: string) => topo.nodes.find((n) => n.id === id)?.name || id;
  const ext = node.external;
  return (
    <Alert
      type={ext ? "warning" : "info"}
      showIcon
      style={{ marginBottom: 12 }}
      data-testid="exit-reach"
      message={ext ? "外部 SOCKS 出口 · 仅 TCP · 仅 IPv4" : node.via_exit ? `嵌套出口：经 ${nm(node.via_exit)} 中继` : "动态域名端点"}
      description={
        <>
          {ext ? (
            <Facts
              items={[
                ["承载出口", nm(ext.carrier)],
                ["SOCKS 代理", <Mono key="s">{`${ext.socks_address}:${ext.socks_port}`}</Mono>],
                ["承载出口上的接口", <Mono key="i">{ext.interface}</Mono>],
                ["SOCKS 凭据", <Mono key="c">{ext.credential_id}</Mono>],
              ]}
            />
          ) : null}
          {ext ? <div>没有链路：它经承载出口上的 SOCKS 代理到达。只承载 IPv4 上的 TCP，UDP 在承载出口上被拒绝。</div> : null}
          {node.via_exit ? <div>唯一的隧道是到 {nm(node.via_exit)} 的直连 WG 链路，不直接连枢纽。</div> : null}
          {node.endpoint_host ? (
            <div>
              动态域名端点 <Mono>{node.endpoint_host}</Mono>：拨它的节点按域名解析。
            </div>
          ) : null}
          <div>
            在 <Link to={href("exits")}>出口</Link> 页的「出口节点」里修改（未在真实设备上验证）。
          </div>
        </>
      }
    />
  );
}

function NodeDetail({
  node,
  topo,
  servers,
  serversError,
  onChange,
  onDelete,
}: {
  node: Node;
  topo: Topology;
  servers: ServerView[] | undefined;
  serversError: api.ApiError | null;
  onChange: (t: Topology) => void;
  onDelete: () => void;
}) {
  const patch = (p: Partial<Node>) => onChange({ ...topo, nodes: topo.nodes.map((n) => (n.id === node.id ? { ...n, ...p } : n)) });
  const server = servers?.find((s) => s.id === node.server_id);
  const usedBy = new Map(topo.nodes.filter((n) => n.server_id && n.id !== node.id).map((n) => [n.server_id!, n]));
  const needsServer = node.managed && node.role !== "gateway";
  const groups = (topo.region_groups ?? []).filter((g) => g.members.includes(node.id));
  const legacySSH = !node.server_id && (node.ssh_host || node.ssh_user || node.ssh_port);
  const regionOptions = useMemo(() => REGION_CODES.map((c) => ({ value: c, label: regionLabel(c) })), []);

  const selectServer = (id: string | undefined) => {
    // The server carries the SSH target: the node's own ssh_* fields go.
    onChange({
      ...topo,
      nodes: topo.nodes.map((n) => {
        if (n.id !== node.id) return n;
        const next: Node = { ...n, server_id: id || undefined };
        delete next.ssh_host;
        delete next.ssh_port;
        delete next.ssh_user;
        delete next.pool;
        delete next.pool_priority;
        if (!id) delete next.server_id;
        return next;
      }),
    });
  };

  return (
    <Form layout="vertical" size="small" data-testid="node-detail">
      <Row label="名称">
        <Input value={node.name} onChange={(e) => patch({ name: e.target.value })} aria-label="节点名称" />
      </Row>
      <Facts items={[["ID", <Mono key="id">{node.id}</Mono>]]} />
      <Row label="角色" help={ROLE_HELP[node.role]}>
        <Select
          value={node.role}
          options={(Object.keys(roleLabel) as Role[]).map((r) => ({ value: r, label: roleLabel[r] }))}
          onChange={(role: Role) => patch({ role, managed: role !== "ix", ...(role === "gateway" ? { server_id: undefined } : {}) })}
          aria-label="角色"
        />
      </Row>
      {node.role === "hub" ? <HubRoleFields node={node} topo={topo} patch={patch} /> : null}
      {node.role === "exit" && (node.external || node.via_exit || node.endpoint_host) ? <ExitReachFacts node={node} topo={topo} /> : null}
      <Row label="国家或地区" help="出口按它在出口页分区；解锁探测用它确认实际出口地区。">
        <AutoComplete value={node.region ?? ""} options={regionOptions} onChange={(v) => patch({ region: v.trim().toLowerCase() || undefined })} placeholder="例如 hk" />
      </Row>

      <Divider orientation="left" plain>
        服务器
      </Divider>
      {node.role === "gateway" ? (
        <Typography.Paragraph type="secondary">网关是运行面板的这台机器，不关联远端服务器；在「部署」页安装到本机。</Typography.Paragraph>
      ) : node.role === "exit" && node.external ? (
        <Typography.Paragraph type="secondary">外部 SOCKS 出口不装机，没有服务器：面板从不登录那台代理设备。</Typography.Paragraph>
      ) : !node.managed ? (
        <Typography.Paragraph type="secondary">这个节点不需要装机（例如 IX 专线），没有服务器。</Typography.Paragraph>
      ) : (
        <>
          {serversError ? <ApiErrorAlert error={serversError} /> : null}
          <Row
            label="运行在哪台服务器上"
            help={
              <span>
                地址、登录方式和主机指纹在 <Link to={href("servers")}>服务器</Link> 页管理。一台服务器只能给一个节点用。
              </span>
            }
          >
            <Select
              allowClear
              value={node.server_id || undefined}
              placeholder={servers?.length === 0 ? "还没有服务器，先去服务器页添加" : "选择服务器"}
              onChange={(v: string | undefined) => selectServer(v)}
              loading={!servers && !serversError}
              aria-label="服务器"
              options={(servers ?? []).map((s) => {
                const other = usedBy.get(s.id);
                const r = serverReadiness(s);
                return {
                  value: s.id,
                  disabled: !!other,
                  label: (
                    <Space size={4}>
                      <span>{s.name}</span>
                      <span className="mono-small muted">{s.address}</span>
                      {other ? <Tag>已被 {other.name || other.id} 使用</Tag> : <StatusTag kind={r.kind}>{r.label}</StatusTag>}
                    </Space>
                  ),
                };
              })}
            />
          </Row>
          {node.server_id && !server && servers ? (
            <Alert type="error" showIcon style={{ marginBottom: 12 }} message={`引用的服务器 ${node.server_id} 不存在`} />
          ) : null}
          {server ? (
            <div className="server-summary">
              <Space size={6} wrap>
                <StatusTag kind={serverReadiness(server).kind}>{serverReadiness(server).label}</StatusTag>
                <Mono>{`${server.user}@${server.address}:${server.port}`}</Mono>
                <Link to={href("servers", server.id)}>打开服务器</Link>
              </Space>
              {!server.ready ? (
                <Typography.Paragraph type="secondary" style={{ margin: "6px 0 0", fontSize: 12 }}>
                  装机和 Mesh 部署前要先在服务器页完成：选择密钥、确认主机指纹、通过连接测试。
                </Typography.Paragraph>
              ) : null}
            </div>
          ) : needsServer && !node.server_id ? (
            <Alert type="warning" showIcon style={{ marginBottom: 12 }} message="还没有选择服务器：这个节点不能装机，也不能参与 Mesh 部署。" />
          ) : null}
          {legacySSH ? (
            <Alert
              type="info"
              showIcon
              style={{ marginTop: 8 }}
              message={`旧的 SSH 地址 ${node.ssh_user ?? "root"}@${node.ssh_host ?? ""}${node.ssh_port ? `:${node.ssh_port}` : ""} 会在保存时转成一台服务器；选择已有服务器会替换它。`}
            />
          ) : null}
        </>
      )}

      <Divider orientation="left" plain>
        地址
      </Divider>
      {node.role === "gateway" ? (
        <Row label="局域网接口" help="网关上连接家里局域网的网卡；全局只有这一处，改它也会改网关设置。">
          <Input
            className="mono"
            value={topo.settings.lan_interface || ""}
            placeholder="eth0"
            onChange={(e) => {
              const v = e.target.value.trim();
              onChange({
                ...topo,
                settings: { ...topo.settings, lan_interface: v },
                nodes: topo.nodes.map((n) => (n.role === "gateway" ? { ...n, lan_interface: v || undefined } : n)),
              });
            }}
            aria-label="局域网接口"
          />
        </Row>
      ) : null}
      {isIXHub(node) ? (
        <>
          <Row label="香港出口地址（出口拨入）" help="IX 枢纽在香港一侧的地址：拨入的出口连它，它到出口的隧道也从这里出去。">
            <Input
              className="mono"
              value={node.endpoint_v4 ?? ""}
              onChange={(e) => patch({ endpoint_v4: e.target.value.trim() || undefined })}
              aria-label="香港出口地址（出口拨入）"
            />
          </Row>
          <Row label="国内入口地址（中继拨入）" help="IX 国内一侧的 IPv4，中继用普通 WireGuard 拨它；必填，只接受中继。">
            <Input
              className="mono"
              value={node.ingress_v4 ?? ""}
              status={node.ingress_v4 ? undefined : "warning"}
              placeholder="例如 198.51.100.10"
              onChange={(e) => patch({ ingress_v4: e.target.value.trim() || undefined })}
              aria-label="国内入口地址（中继拨入）"
            />
          </Row>
          <Row label="国内入口接口（可选）" help="承载国内入口地址的网卡；填了会在预检里核对，并像外网网卡一样加固。">
            <Input
              className="mono"
              value={node.ingress_interface ?? ""}
              placeholder="例如 eth1"
              onChange={(e) => patch({ ingress_interface: e.target.value.trim() || undefined })}
              aria-label="国内入口接口（可选）"
            />
          </Row>
        </>
      ) : (
        <Row label="公网 IPv4" help={node.nat_dial_out ? "NAT 拨出的节点必须留空：对端不应知道它的公网地址。" : "对端拨这个地址；没有公网地址的节点留空。"}>
          <Input className="mono" value={node.endpoint_v4 ?? ""} onChange={(e) => patch({ endpoint_v4: e.target.value.trim() || undefined })} disabled={node.nat_dial_out && !node.endpoint_v4} />
        </Row>
      )}
      <Row label="公网 IPv6" help="双栈中继或纯 IPv6 出口的公网地址。">
        <Input className="mono" value={node.endpoint_v6 ?? ""} onChange={(e) => patch({ endpoint_v6: e.target.value.trim() || undefined })} />
      </Row>
      <Space.Compact block>
        <Row label="WireGuard 监听端口" help="这个节点只监听一条没有单独设端口的链路时用它；监听多条时在每条链路上填「WireGuard 端口」。端口被占用时改这里或链路上的端口。">
          <InputNumber
            min={1}
            max={65534}
            value={node.listen_port}
            onChange={(v) => patch({ listen_port: v ?? undefined })}
            style={{ width: "100%" }}
            aria-label="WireGuard 监听端口"
          />
        </Row>
        <Row label="外网网卡">
          <Input className="mono" value={node.wan_interface ?? ""} onChange={(e) => patch({ wan_interface: e.target.value.trim() || undefined })} placeholder="eth0" />
        </Row>
      </Space.Compact>

      <Divider orientation="left" plain>
        能力
      </Divider>
      <Flag label="承载 IPv4 路径" help="这个节点转发 IPv4 流量。" checked={node.path_v4} onChange={(v) => patch({ path_v4: v })} />
      <Flag label="承载 IPv6 路径" help="这个节点转发 IPv6 流量。" checked={node.path_v6} onChange={(v) => patch({ path_v6: v })} />
      {node.role === "exit" ? (
        <>
          <Flag label="IPv4 出口" help="流量可以在这里以 IPv4 离开。" checked={node.egress_v4} onChange={(v) => patch({ egress_v4: v })} />
          <Flag label="IPv6 出口" help="流量可以在这里以 IPv6 离开；没有时不返回 AAAA，回落 IPv4。" checked={node.egress_v6} onChange={(v) => patch({ egress_v6: v })} />
          <Flag label="住宅（家宽）" help="家宽出口；Netflix、Disney+ 这类规则要求住宅出口。" checked={node.residential} onChange={(v) => patch({ residential: v })} />
          <Flag label="IX 绑定" help="出口直接挂在 IX 专线后面；在地区组里自动排在最前。" checked={node.ix_bound} onChange={(v) => patch({ ix_bound: v })} />
          <Row label="纯 IPv6 出口的绕行方式" help="出口没有 IPv4 时，枢纽怎么到达它。">
            <Select
              allowClear
              value={node.v6_workaround || undefined}
              options={Object.entries(WORKAROUND).map(([value, label]) => ({ value, label }))}
              onChange={(v?: string) => patch({ v6_workaround: v || undefined })}
              placeholder="不需要"
            />
          </Row>
          <Flag label="双栈中继" help="IX 之后的双栈跳板：枢纽用 IPv4 到它，纯 IPv6 出口用 IPv6 拨它。" checked={!!node.dualstack_relay} onChange={(v) => patch({ dualstack_relay: v })} />
          <Typography.Paragraph style={{ marginTop: 8 }}>
            <Typography.Text type="secondary">所在地区组：</Typography.Text>
            {groups.length > 0 ? (
              groups.map((g) => (
                <Link key={g.id} to={href("exits", g.id)}>
                  <Tag style={{ cursor: "pointer" }}>{groupLabel(g, topo.region_groups)}</Tag>
                </Link>
              ))
            ) : (
              <span>
                不在任何组里（在 <Link to={href("exits")}>出口</Link> 页加入）
              </span>
            )}
          </Typography.Paragraph>
        </>
      ) : null}
      <Flag label="NAT 拨出" help="节点在 NAT 后面，由它主动拨枢纽；对端不配置它的地址。" checked={node.nat_dial_out} onChange={(v) => patch({ nat_dial_out: v })} />

      {node.role === "hub" || node.role === "relay" || node.role === "exit" ? (
        <Collapse
          ghost
          style={{ marginTop: 8 }}
          items={[
            {
              key: "wss",
              label: "WSS 入口（高级）",
              children: (
                <>
                  <Row label="WSS 监听端口" help="默认 443。443 已被 nginx 或别的 wstunnel 占用时换一个端口（TCP）。">
                    <InputNumber
                      min={1}
                      max={65535}
                      value={node.wss_listen_port}
                      onChange={(v) => patch({ wss_listen_port: v ?? undefined })}
                      style={{ width: "100%" }}
                      placeholder="443"
                      aria-label="WSS 监听端口"
                    />
                  </Row>
                  <Typography.Paragraph type="secondary" style={{ fontSize: 12, marginBottom: 0 }} data-testid="wss-node-note">
                    WSS 路径和证书由面板自动生成：每条 WSS 链路一个随机路径，每个监听一张自签证书，客户端只信任这张证书并校验合成名称；不需要域名、证书文件，也没有 ACME。状态、指纹和重新生成在「部署」页的「WSS 承载」里。
                  </Typography.Paragraph>
                </>
              ),
            },
          ]}
        />
      ) : null}

      <Divider orientation="left" plain>
        密钥
      </Divider>
      <Facts
        items={[
          [
            "WireGuard 公钥",
            node.public_key ? (
              <Mono copy>{node.public_key}</Mono>
            ) : (
              <Typography.Text type="secondary">还没有：网关在首次安装时生成，远端节点在「部署」页下发时生成</Typography.Text>
            ),
          ],
        ]}
      />
      <Button danger icon={<DeleteOutlined />} style={{ marginTop: 16 }} onClick={onDelete}>
        删除节点
      </Button>
    </Form>
  );
}

// ------------------------------------------------------- link allocation ---

/**
 * What each link holds in the working copy (POST /api/topology/allocations),
 * re-read 300 ms after the last edit. null until the first answer; failed
 * when the panel cannot answer (an older backend): the editor then simply
 * does not show the allocation.
 */
function useAllocationView(topo: Topology | null): { view: AllocationView | null; failed: boolean } {
  const [view, setView] = useState<AllocationView | null>(null);
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    if (!topo) return;
    const ctl = new AbortController();
    const timer = window.setTimeout(() => {
      api
        .allocations(topo, ctl.signal)
        .then((v) => {
          if (!ctl.signal.aborted) {
            setView(v);
            setFailed(false);
          }
        })
        .catch(() => {
          if (!ctl.signal.aborted) setFailed(true);
        });
    }, 300);
    return () => {
      window.clearTimeout(timer);
      ctl.abort();
    };
  }, [topo]);
  return { view, failed };
}

const CHANGE_LABEL: Record<AllocationChange["what"], string> = {
  interface: "接口",
  listener: "监听端",
  wg_port: "WireGuard 端口",
  wss_leg_port: "WSS 腿端口",
  local_port: "wstunnel 本地端口",
  tunnel_v4: "隧道 IPv4",
  tunnel_ula: "隧道 ULA",
  enabled: "启用",
  state: "状态",
};

const WG_FROM: Record<string, string> = { link: "链路上填写", node: "监听节点的监听端口", default: "按分配序号" };

function changeText(c: AllocationChange) {
  return `${CHANGE_LABEL[c.what] ?? c.what}：${c.before || "（无）"} → ${c.after || "（无）"}`;
}

/** Read-only: the interface, ports and subnets the link's slot (or an override) gives it. */
function LinkAllocationFacts({ alloc, changes, failed, nm }: { alloc?: LinkAllocation; changes: AllocationChange[]; failed: boolean; nm: (id: string) => string }) {
  if (!alloc) {
    return <Typography.Text type="secondary">{failed ? "读不到分配信息。" : "读取中…"}</Typography.Text>;
  }
  if (alloc.state === "not_tunnel") {
    return <Typography.Text type="secondary">这种传输方式不建 WireGuard 接口，不占分配序号。</Typography.Text>;
  }
  if (alloc.state === "unallocated") {
    return (
      <Alert
        type="error"
        showIcon
        data-testid="link-allocation-exhausted"
        message="分不到接口序号"
        description="所有接口序号都已占用，或剩下的与手工填写的地址、端口冲突；已删除链路的序号在下一次保存之后才会复用。删掉不用的链路后保存，或改掉冲突的手工值。"
      />
    );
  }
  if (alloc.state === "unresolved") {
    return <Typography.Text type="secondary">链路的一端还不完整，补齐后显示接口和地址。</Typography.Text>;
  }
  const legs = alloc.legs ?? [];
  const items: [ReactNode, ReactNode][] = [
    [
      "分配序号",
      <span key="slot">
        <Mono>{String(alloc.slot)}</Mono>
        {alloc.new ? <Tag style={{ marginLeft: 8 }}>保存后分配</Tag> : null}
        {!alloc.enabled ? <Tag style={{ marginLeft: 8 }}>停用：保留序号</Tag> : null}
      </span>,
    ],
    ["接口", <Mono key="if">{legs.map((l) => l.iface).join("  ")}</Mono>],
    [
      "WireGuard 端口",
      <span key="wg">
        <Mono>{String(alloc.wg_port)}</Mono>
        {alloc.wss_leg_port ? (
          <>
            {" "}
            + WSS 腿 <Mono>{String(alloc.wss_leg_port)}</Mono>
          </>
        ) : null}
        <Typography.Text type="secondary">
          {" "}
          · 在 {nm(alloc.listener ?? "")} 上监听 · {WG_FROM[alloc.wg_from ?? "default"] ?? alloc.wg_from}
        </Typography.Text>
      </span>,
    ],
  ];
  if (alloc.local_port) {
    items.push([
      "wstunnel 本地端口",
      <span key="local">
        <Mono>{String(alloc.local_port)}</Mono>
        <Typography.Text type="secondary"> · {nm(alloc.dialer ?? "")} 的 127.0.0.1</Typography.Text>
      </span>,
    ]);
  }
  for (const l of legs) {
    items.push([
      `隧道地址（${l.iface}）`,
      <span key={`addr-${l.iface}`} className="mono-small">
        {nm(l.west)} {l.west_v4} · {l.west_ula}
        <br />
        {nm(l.east)} {l.east_v4} · {l.east_ula}
      </span>,
    ]);
  }
  return (
    <div data-testid="link-allocation">
      <Facts items={items} />
      {changes.length > 0 ? (
        <Alert
          type="warning"
          showIcon
          style={{ marginTop: 8 }}
          data-testid="link-allocation-changes"
          message="保存后这条已保存链路的接口/端口/地址会改变"
          description={
            <>
              {changes.map((c) => (
                <div key={c.what}>{changeText(c)}</div>
              ))}
              <div>两端节点都要重新下发；隧道会短暂中断。</div>
            </>
          }
        />
      ) : null}
    </div>
  );
}

function LinkDetail({
  link,
  topo,
  onChange,
  onDelete,
  alloc,
  allocChanges = [],
  allocFailed = false,
}: {
  link: TLink;
  topo: Topology;
  onChange: (t: Topology) => void;
  onDelete: () => void;
  alloc?: LinkAllocation;
  allocChanges?: AllocationChange[];
  allocFailed?: boolean;
}) {
  const patch = (p: Partial<TLink>) => {
    const next = { ...link, ...p };
    if (next.transport === "ix_replacement_wss" || next.transport === "cf_mesh") next.standby = true;
    onChange({ ...topo, links: topo.links.map((l) => (l.id === link.id ? next : l)) });
  };
  const nm = (id: string) => topo.nodes.find((n) => n.id === id)?.name ?? id;
  const forcedStandby = link.transport === "ix_replacement_wss" || link.transport === "cf_mesh";
  return (
    <Form layout="vertical" size="small" data-testid="link-detail">
      <Facts
        items={[
          ["ID", <Mono key="id">{link.id}</Mono>],
          [
            "两端",
            <span key="ends">
              <Link to={href("topology", link.from)}>{nm(link.from)}</Link> → <Link to={href("topology", link.to)}>{nm(link.to)}</Link>
            </span>,
          ],
        ]}
      />
      <Row label="名称">
        <Input value={link.name ?? ""} onChange={(e) => patch({ name: e.target.value || undefined })} placeholder="可选" />
      </Row>
      <Row label="传输方式" help={TRANSPORT_HELP[link.transport]}>
        <Select
          value={link.transport}
          options={(Object.keys(transportLabel) as Transport[]).map((t) => ({ value: t, label: transportLabel[t] }))}
          onChange={(transport: Transport) => patch({ transport })}
          aria-label="传输方式"
        />
      </Row>
      <Flag label="启用" help="停用的链路不生成配置。" checked={link.enabled} onChange={(v) => patch({ enabled: v })} />
      <Flag
        label="待命"
        help={forcedStandby ? "这种传输方式总是待命：建好并做健康检查，但不进默认路由。" : "建好并做健康检查，但不进默认路由。"}
        checked={link.standby}
        onChange={(v) => patch({ standby: v })}
        disabled={forcedStandby}
      />
      <Space.Compact block>
        <Row label="MTU">
          <InputNumber min={1280} max={9000} value={link.mtu} onChange={(v) => patch({ mtu: v ?? undefined })} style={{ width: "100%" }} />
        </Row>
        <Row label="WSS MTU">
          <InputNumber min={1280} max={9000} value={link.wss_mtu} onChange={(v) => patch({ wss_mtu: v ?? undefined })} style={{ width: "100%" }} />
        </Row>
      </Space.Compact>
      <Space.Compact block>
        <Row label="Keepalive（秒）" help="NAT 拨出的一端需要 > 0。">
          <InputNumber min={0} max={600} value={link.keepalive} onChange={(v) => patch({ keepalive: v ?? undefined })} style={{ width: "100%" }} />
        </Row>
        <Row label="WireGuard 端口" help="监听端的 UDP 端口；不填时用监听节点的监听端口或 51820+分配序号。UDP+WSS 故障切换还占用下一个端口。">
          <InputNumber min={1} max={65534} value={link.wg_port} onChange={(v) => patch({ wg_port: v ?? undefined })} style={{ width: "100%" }} aria-label="WireGuard 端口" />
        </Row>
      </Space.Compact>
      {link.transport === "wg_over_wss" || link.transport === "udp_wss_failover" || link.transport === "ix_replacement_wss" ? (
        <Row label="wstunnel 本地端口" help="拨号端 wstunnel 客户端在 127.0.0.1 上的 UDP 端口；不填时 52000+分配序号。被占用时改这里。">
          <InputNumber
            min={1}
            max={65535}
            value={link.wss_local_port}
            onChange={(v) => patch({ wss_local_port: v ?? undefined })}
            style={{ width: "100%" }}
            aria-label="wstunnel 本地端口"
          />
        </Row>
      ) : null}
      {link.transport === "wg_over_wss" || link.transport === "udp_wss_failover" || link.transport === "ix_replacement_wss" ? (
        <Row label="WSS 路径与证书" help="面板自动生成：随机路径（只显示已设置）和监听的自签证书（客户端固定校验）。">
          <WSSLinkStatus linkId={link.id} />
        </Row>
      ) : null}
      <Row
        label="接口与地址（只读）"
        help="链路第一次保存时按链路 ID 分配一个序号并存进拓扑：接口名、默认端口和隧道网段都由它决定。增删、重排别的链路不会改变它；要换端口填上面的覆盖项。"
      >
        <LinkAllocationFacts alloc={alloc} changes={allocChanges} failed={allocFailed} nm={nm} />
      </Row>
      {link.transport === "cf_mesh" ? (
        <Row label="Mesh 发布的路由" help="出口端 Mesh 节点通告的网段；在 Cloudflare 页部署时发布、失败时撤回。">
          <Select
            mode="tags"
            tokenSeparators={[",", " "]}
            placeholder="例如 198.51.100.0/24"
            value={link.mesh_routes ?? []}
            onChange={(v: string[]) => patch({ mesh_routes: v.map((x) => x.trim()).filter(Boolean) })}
          />
        </Row>
      ) : null}
      <Button danger icon={<DeleteOutlined />} style={{ marginTop: 8 }} onClick={onDelete}>
        删除链路
      </Button>
    </Form>
  );
}

// ------------------------------------------------------- gateway settings ---

// Appended to the help of the two resolver settings in every state: who
// else gets this policy, and what the unlisted-name check never touches.
const V6_SHARED_NOTE =
  "远程接入的设备用同一个解析器、同一个设置：全隧道模式的设备 IPv6 本来就经过网关，设置关闭时它们只拿走隧道域名的 IPv4，照常能用；仅家里网段模式的设备其余流量不经网关。外部 SOCKS 出口（只有 IPv4 TCP）以及会切到它的地区组，无论怎样都不返回 AAAA。";
const SPLIT_RULES_NOTE =
  "命中名单或规则的域名（包括指向默认组的规则）只问自己目标的解析器：打开这个设置也不会发给国内解析器，目标的解析器不通时解析失败、不改问国内。";

function SettingsDrawer({ open, topo, onClose, onChange }: { open: boolean; topo: Topology; onClose: () => void; onChange: (t: Topology) => void }) {
  const s = topo.settings;
  const set = (p: Partial<Settings>) => onChange({ ...topo, settings: { ...s, ...p } });
  const nat = s.nat64 ?? { reserved: true, enabled: false, prefix: "" };
  const text = (k: keyof Settings, label: string, help?: string, placeholder?: string) => (
    <Row label={label} help={help}>
      <Input className="mono" value={(s[k] as string) ?? ""} placeholder={placeholder} onChange={(e) => set({ [k]: e.target.value.trim() } as Partial<Settings>)} aria-label={label} />
    </Row>
  );
  return (
    <Drawer title="网关设置" open={open} onClose={onClose} width={480} mask={false}>
      <Alert type="info" showIcon style={{ marginBottom: 16 }} message="这些是整个网关共用的设置；修改进入工作副本，保存并安装后生效。" />
      <Form layout="vertical" size="small">
        <Divider orientation="left" plain>
          局域网
        </Divider>
        {text("lan_interface", "局域网接口", "网关连接家里局域网的网卡。", "eth0")}
        {text("gateway_lan_ipv4", "网关局域网地址", "带前缀长度。", "192.168.100.88/24")}
        {text("ros_ipv4", "主路由器 IPv4", "家里的主路由（例如 RouterOS）。", "192.168.100.1")}
        {text("ros_v6_lla", "主路由器 IPv6 链路本地地址", undefined, "fe80::1")}
        {text("lan_ipv6_prefix", "局域网 IPv6 前缀", undefined, "2001:db8:100::/64")}
        {text("ula_prefix", "ULA 前缀", "隧道内部地址。", "fd66::/48")}
        <Row label="国内 DoT 解析器" help="国内域名用的上游解析器。">
          <Select mode="tags" tokenSeparators={[",", " "]} value={s.domestic_dot ?? []} onChange={(v: string[]) => set({ domestic_dot: v })} />
        </Row>
        <Divider orientation="left" plain>
          解析（DNS）
        </Divider>
        <Flag
          label="客户端 IPv6 经本网关"
          help={
            s.clients_ipv6_via_gateway
              ? "已打开：出口（或地区组）能端到端承载 IPv6 时，走隧道的域名也返回 AAAA。前提是每台客户端的 IPv6 默认路由都指向本网关（见 docs/test-device.md）；手机只能手填 IPv4 网关和 DNS、IPv6 仍走家里路由器时不要打开，否则这些 IPv6 地址会从家宽直接出去、绕过隧道。" + V6_SHARED_NOTE
              : "关闭（默认）：除国内域名外，所有域名都不返回 AAAA。手机等客户端的 IPv6 来自家里路由器，拿不到国外域名的 IPv6 地址，只用 IPv4 经本网关进隧道，不会从家宽 IPv6 绕过隧道；国内域名照常返回 AAAA，经家里路由器直连。" + V6_SHARED_NOTE
          }
          checked={!!s.clients_ipv6_via_gateway}
          onChange={(v) => set({ clients_ipv6_via_gateway: v })}
        />
        <Flag
          label="未列名单的域名也问国内 DNS"
          help={
            s.unlisted_domestic_dns
              ? "已打开：不在任何名单、也没有命中规则的域名同时发给国内解析器和出口解析器，只有国内返回的地址全是中国地址时才采用并直连，否则（国外地址、CNAME 指向国外、混合或被污染的结果）用出口解析器的结果走隧道。代价：国内解析器能看到这些域名（包括国外的），查询经家宽直接发出；DNS 泄漏测试里会出现国内解析器。需要网关上的 meridian-dns-split 服务（安装时自动启用）。" + SPLIT_RULES_NOTE
              : "关闭（默认，严格）：不在名单里的域名只经隧道由出口解析器解析，国外域名的查询不经家宽发出。名单外的国内网站可能拿到面向海外的节点（走隧道或绕远）。打开后国内解析器会看到所有名单外的域名。" + SPLIT_RULES_NOTE
          }
          checked={!!s.unlisted_domestic_dns}
          onChange={(v) => set({ unlisted_domestic_dns: v })}
        />
        <Divider orientation="left" plain>
          隧道
        </Divider>
        {text("transit_v4_prefix", "IPv4 转运前缀", "网关把局域网源地址换成每个出口一个的转运地址，跨跳保持出口选择。", "10.66.200.0/24")}
        {text("transit_v6_prefix", "IPv6 转运前缀", undefined, "fd66:0:0:ff::/64")}
        <Flag
          label="IX 替换模式"
          help="把流量切到预先建好的 WSS 替代路线（IX 故障时）；不会临时新建隧道。"
          checked={!!s.ix_replacement_mode}
          onChange={(v) => set({ ix_replacement_mode: v })}
        />
        <Divider orientation="left" plain>
          多中继分担与路径质量
        </Divider>
        <PathQualitySettings topo={topo} onChange={(pq) => set({ path_quality: pq })} />
        <Divider orientation="left" plain>
          其他
        </Divider>
        <Row label="定时解锁探测间隔（秒）" help="0 或留空表示 6 小时。">
          <InputNumber min={0} value={s.unlock_interval_sec} onChange={(v) => set({ unlock_interval_sec: v ?? undefined })} style={{ width: "100%" }} />
        </Row>
        <Flag
          label="NAT64 预留"
          help="打开只是记下前缀：这一版不会把 NAT64 装进路由表，现有 IPv4 路径不变。"
          checked={nat.enabled}
          onChange={(v) => set({ nat64: { ...nat, reserved: true, enabled: v } })}
        />
        <Row label="NAT64 前缀">
          <Input className="mono" value={nat.prefix ?? ""} placeholder="64:ff9b::/96" onChange={(e) => set({ nat64: { ...nat, reserved: true, prefix: e.target.value.trim() } })} />
        </Row>
        <Typography.Paragraph type="secondary" style={{ fontSize: 12 }}>
          面板监听地址（{s.panel_bind || "—"}）由启动参数决定，这里不能改。
        </Typography.Paragraph>
      </Form>
    </Drawer>
  );
}

// ------------------------------------------------------------------ page ---

function issueTarget(i: Issue): string | null {
  if (i.node_id) return href("topology", i.node_id);
  if (i.link_id) return href("topology", i.link_id);
  if (i.exit_id) return href("topology", i.exit_id);
  if (i.rule_id) return href("rules", i.rule_id);
  if (i.group_id) return href("exits", i.group_id);
  if (i.device_id) return href("remote", i.device_id);
  return null;
}

function ClickableIssues({ issues }: { issues: Issue[] }) {
  const { navigate } = useRouter();
  if (issues.length === 0) return null;
  const errors = issues.filter((i) => i.severity === "error").length;
  return (
    <Section title={`校验问题（${errors} 个错误，${issues.length - errors} 个提示）`}>
      <ul className="issue-links" data-testid="topology-issues">
        {issues.map((i, n) => {
          const to = issueTarget(i);
          return (
            <li key={n} className={i.severity === "error" ? "error" : "warning"}>
              <StatusTag kind={i.severity === "error" ? "failed" : "attention"}>{i.severity === "error" ? "错误" : "提示"}</StatusTag>
              {to ? (
                <a
                  href={to}
                  onClick={(e) => {
                    e.preventDefault();
                    navigate(to, { replace: to.startsWith("#/topology") });
                  }}
                >
                  {i.message}
                </a>
              ) : (
                <span>{i.message}</span>
              )}
            </li>
          );
        })}
      </ul>
    </Section>
  );
}

// ------------------------------------------------------------ node delete ---

type RuleFix = "" | "delete" | `exit:${string}` | `group:${string}`;

/** Everything in the document that refers to node `id`. */
export function nodeReferences(t: Topology, id: string) {
  const links = t.links.filter((l) => l.from === id || l.to === id);
  const groups = (t.region_groups ?? []).filter((g) => g.members.includes(id));
  const rules = t.rules.filter((r) => r.target_exit === id);
  return { links, groups, rules };
}

/**
 * Removes node `id` with the clean-up the operator chose: its links go, it
 * leaves every region group (a manual choice of it is cleared), and each rule
 * pinned to it is retargeted or deleted as `fixes` says. Rules are never
 * changed without an entry in `fixes`.
 */
export function deleteNode(t: Topology, id: string, fixes: Record<string, RuleFix>): Topology {
  const rules = t.rules.flatMap((r) => {
    if (r.target_exit !== id) return [r];
    const fix = fixes[r.id];
    if (fix === "delete") return [];
    const ov = r.manual ? r.overridden : true;
    if (fix?.startsWith("exit:")) return [{ ...r, target_exit: fix.slice(5), overridden: ov }];
    if (fix?.startsWith("group:")) {
      const { target_exit: _e, ...rest } = r;
      void _e;
      return [{ ...rest, target_group: fix.slice(6), overridden: ov }];
    }
    return [r];
  });
  return {
    ...t,
    nodes: t.nodes.filter((n) => n.id !== id),
    links: t.links.filter((l) => l.from !== id && l.to !== id),
    rules,
    region_groups: (t.region_groups ?? []).map((g) => {
      if (!g.members.includes(id)) return g;
      const next = { ...g, members: g.members.filter((m) => m !== id) };
      if (next.chosen === id) delete next.chosen;
      return next;
    }),
  };
}

function NodeDeleteDialog({
  node,
  topo,
  servers,
  onCancel,
  onDelete,
}: {
  node: Node | null;
  topo: Topology;
  servers: ServerView[] | undefined;
  onCancel: () => void;
  onDelete: (t: Topology) => void;
}) {
  const [fixes, setFixes] = useState<Record<string, RuleFix>>({});
  // What is installed on the node's server is a separate question from the
  // topology: its deployment record decides whether there is anything to
  // withdraw. Deleting from the topology never withdraws by itself.
  const [dep, setDep] = useState<{ rec?: DeploymentView; loaded: boolean; error?: string }>({ loaded: false });
  const [choice, setChoice] = useState<"keep" | "withdraw" | null>(null);
  const [withdrawing, setWithdrawing] = useState(false);
  const [withdrawnOK, setWithdrawnOK] = useState(false);
  useEffect(() => {
    setFixes({});
    setChoice(null);
    setWithdrawing(false);
    setWithdrawnOK(false);
    setDep({ loaded: false });
    if (!node) return;
    let live = true;
    api
      .getDeployments()
      .then((d) => live && setDep({ rec: d.nodes.find((x) => x.node_id === node.id), loaded: true }))
      .catch((e: Error) => live && setDep({ loaded: true, error: e.message }));
    return () => {
      live = false;
    };
  }, [node?.id]);
  if (!node) return null;
  const onHost = !!dep.rec?.on_host && !withdrawnOK;
  const refs = nodeReferences(topo, node.id);
  const name = (id: string) => topo.nodes.find((n) => n.id === id)?.name || id;
  const server = node.server_id ? servers?.find((s) => s.id === node.server_id) : undefined;
  const targets = [
    ...(topo.region_groups ?? []).map((g) => ({ value: `group:${g.id}`, label: `地区组：${groupLabel(g, topo.region_groups)}` })),
    ...topo.nodes.filter((n) => n.role === "exit" && n.id !== node.id).map((n) => ({ value: `exit:${n.id}`, label: `固定出口：${n.name || n.id}` })),
  ];
  const undecided = refs.rules.filter((r) => !fixes[r.id]);
  const nothing = refs.links.length + refs.groups.length + refs.rules.length === 0 && !node.server_id;
  return (
    <Modal
      open
      title={`删除节点「${node.name || node.id}」`}
      onCancel={onCancel}
      width={620}
      destroyOnHidden
      okText={onHost && choice === "withdraw" ? "先撤回…" : "删除并清理引用"}
      okButtonProps={{ danger: true, disabled: undecided.length > 0 || (onHost && !choice) }}
      cancelText="取消"
      onOk={() => {
        if (onHost && choice === "withdraw") {
          setWithdrawing(true);
          return;
        }
        onDelete(deleteNode(topo, node.id, fixes));
      }}
    >
      <div data-testid="node-delete">
        <Typography.Paragraph>
          {nothing ? "没有别的东西引用这个节点。" : "下面这些地方引用了这个节点，会在同一步里处理："}
          只改工作副本，保存并安装之前网关不变。
        </Typography.Paragraph>
        {refs.links.length > 0 ? (
          <div className="delete-ref">
            <Typography.Text strong>链路 {refs.links.length} 条：一起删除</Typography.Text>
            <ul className="ref-list">
              {refs.links.map((l) => (
                <li key={l.id}>
                  {l.name || l.id} <span className="muted">（{name(l.from)} → {name(l.to)}）</span>
                </li>
              ))}
            </ul>
          </div>
        ) : null}
        {refs.groups.length > 0 ? (
          <div className="delete-ref" data-testid="node-delete-groups">
            <Typography.Text strong>地区组 {refs.groups.length} 个：把它移出成员</Typography.Text>
            <ul className="ref-list">
              {refs.groups.map((g) => {
                const left = g.members.filter((m) => m !== node.id).length;
                return (
                  <li key={g.id}>
                    <Link to={href("exits", g.id)}>{groupLabel(g, topo.region_groups)}</Link>
                    <span className="muted">（剩 {left} 个成员）</span>
                    {left === 0 ? (
                      <div className="consequence">这个组会变成空组：用它的规则（和默认组，如果是）将没有出口可走，校验会报错，保存只能存为草稿，直到你给它加成员。</div>
                    ) : null}
                    {g.chosen === node.id ? (
                      <div className="consequence">
                        这个组手动指定的就是这个节点：指定会被清除，{g.mode === "manual" ? "手动组没有指定成员时校验会报错，要在「出口」页重新指定一个。" : "组按自动顺序选成员。"}
                      </div>
                    ) : null}
                  </li>
                );
              })}
            </ul>
          </div>
        ) : null}
        {refs.rules.length > 0 ? (
          <div className="delete-ref" data-testid="node-delete-rules">
            <Typography.Text strong>固定到它的规则 {refs.rules.length} 条：逐条选择改指向哪里，或删除</Typography.Text>
            {refs.rules.map((r) => (
              <div key={r.id} className="delete-rule-row">
                <span>
                  <Link to={href("rules", r.id)}>{r.name}</Link> {r.manual ? null : <Tag>内置</Tag>}
                </span>
                <Select<RuleFix>
                  aria-label={`规则 ${r.name} 的处理`}
                  placeholder="选择…"
                  style={{ minWidth: 220 }}
                  value={fixes[r.id] || undefined}
                  onChange={(v) => setFixes((f) => ({ ...f, [r.id]: v }))}
                  options={[{ value: "delete", label: "删除这条规则" }, ...targets]}
                />
              </div>
            ))}
            {undecided.length > 0 ? <Typography.Text type="warning">还有 {undecided.length} 条规则没有选择处理方式。</Typography.Text> : null}
          </div>
        ) : null}
        {node.server_id ? (
          <div className="delete-ref">
            <Typography.Text strong>关联的服务器：</Typography.Text>{" "}
            <Link to={href("servers", node.server_id)}>{server?.name ?? node.server_id}</Link>
            <span className="muted"> 不会被删除，只是不再被这个节点使用；服务器上已经下发的 Meridian 文件和服务不会被自动清理。</span>
          </div>
        ) : null}
        {dep.error ? (
          <Alert
            type="warning"
            showIcon
            style={{ marginTop: 8 }}
            data-testid="node-delete-deploy-unknown"
            message="读不到部署记录，无法判断服务器上是否还有这个节点的安装"
            description={`${dep.error}。删除只改拓扑；服务器上的安装（如果有）会保留，之后可以在部署页的「部署记录与撤回」里撤回。`}
          />
        ) : null}
        {dep.rec && withdrawnOK ? (
          <Alert type="success" showIcon style={{ marginTop: 8 }} data-testid="node-delete-withdrawn" message="服务器上的安装已撤回，现在可以从拓扑删除。" />
        ) : null}
        {onHost && dep.rec ? (
          <div className="delete-ref" data-testid="node-delete-deployment">
            <Typography.Text strong>服务器上的安装：</Typography.Text>{" "}
            <StatusTag kind={DEPLOYMENT_STATUS[dep.rec.status]?.kind ?? "neutral"}>{DEPLOYMENT_STATUS[dep.rec.status]?.label ?? dep.rec.status}</StatusTag>
            <span className="mono-small"> {`${dep.rec.server_name || dep.rec.server_id} · ${dep.rec.address}:${dep.rec.port}`}</span>
            <Typography.Paragraph type="secondary" style={{ marginTop: 4 }}>
              从拓扑删除节点和撤回服务器上的安装是两件事。撤回只移除 Meridian 受管清单列出的服务、接口、路由、nft 表和文件；装机时安装的软件包（wireguard-tools、nftables、smartdns 等）按设计保留。
            </Typography.Paragraph>
            <Radio.Group value={choice} onChange={(e) => setChoice(e.target.value)} style={{ display: "flex", flexDirection: "column", gap: 6 }}>
              <Radio value="keep">仅从拓扑删除（保留服务器上的安装，之后仍可在部署页撤回）</Radio>
              <Radio value="withdraw">先撤回再删除</Radio>
            </Radio.Group>
            {choice === "keep" ? (
              <Typography.Text type="warning" style={{ display: "block", marginTop: 4 }}>
                服务器上的 Meridian 服务、接口和文件会继续运行；部署记录保留，这台服务器和它的凭据在撤回前不能删除。
              </Typography.Text>
            ) : null}
          </div>
        ) : null}
      </div>
      {withdrawing ? (
        <WithdrawDialog
          nodeId={node.id}
          nodeName={node.name}
          mode="manifest"
          onClose={() => setWithdrawing(false)}
          onDone={(outcome) => {
            if (withdrawSucceeded(outcome) && outcome !== "recovered") {
              setWithdrawnOK(true);
              setChoice(null);
            }
          }}
        />
      ) : null}
    </Modal>
  );
}

export default function TopologyPage() {
  const doc = useTopologyDoc();
  const { route, navigate } = useRouter();
  const confirm = useConfirmDanger();
  const servers = useApi(() => api.listServers(), []);
  const [deleting, setDeleting] = useState<Node | null>(null);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [migrationDismissed, setMigrationDismissed] = useState(false);
  const topo = doc.topo;
  const allocation = useAllocationView(topo);

  const selected: Selection = useMemo(() => {
    const id = route.params[0];
    if (!id || !topo) return null;
    if (topo.nodes.some((n) => n.id === id)) return { kind: "node", id };
    if (topo.links.some((l) => l.id === id)) return { kind: "link", id };
    return null;
  }, [route.params, topo]);
  const select = useCallback((s: Selection) => navigate(s ? href("topology", s.id) : href("topology"), { replace: true }), [navigate]);
  const serverMap = useMemo(() => new Map((servers.data?.servers ?? []).map((s) => [s.id, s])), [servers.data]);

  if (!topo) {
    return (
      <Page title="拓扑">
        {doc.error ? <ApiErrorAlert error={doc.error} onRetry={() => void doc.reload()} /> : <Typography.Text type="secondary">读取中…</Typography.Text>}
      </Page>
    );
  }

  const addNode = (role: Role) => {
    let id = role === "gateway" ? "gw" : role;
    for (let i = 2; topo.nodes.some((n) => n.id === id); i++) id = `${role}-${i}`;
    const node: Node = {
      id,
      name: `${roleLabel[role]} ${id}`,
      role,
      managed: role !== "ix",
      x: 80 + (topo.nodes.length % 6) * 40,
      y: 80 + (topo.nodes.length % 6) * 30,
      path_v4: true,
      path_v6: role === "exit",
      egress_v4: role === "exit",
      egress_v6: false,
      nat_dial_out: false,
      residential: false,
      ix_bound: false,
    };
    doc.setTopo({ ...topo, nodes: [...topo.nodes, node] });
    select({ kind: "node", id });
  };

  const node = selected?.kind === "node" ? topo.nodes.find((n) => n.id === selected.id) : undefined;
  const link = selected?.kind === "link" ? topo.links.find((l) => l.id === selected.id) : undefined;
  const managedWithout = topo.nodes.filter((n) => n.managed && n.role !== "gateway" && !n.server_id);

  return (
    <Page
      title="拓扑"
      description="节点和链路组成的路径：网关 → 中继 → IX → 枢纽 → 出口。点节点或链路编辑；从一个节点的边缘拖到另一个节点新建链路。"
      extra={
        <Space wrap>
          <Button icon={<SettingOutlined />} onClick={() => setSettingsOpen(true)}>
            网关设置
          </Button>
          <Dropdown
            trigger={["click"]}
            menu={{
              items: (Object.keys(roleLabel) as Role[]).map((r) => ({ key: r, label: `${roleLabel[r]} — ${ROLE_HELP[r]}` })),
              onClick: ({ key }) => addNode(key as Role),
            }}
          >
            <Button type="primary" icon={<PlusOutlined />}>
              添加节点
            </Button>
          </Dropdown>
        </Space>
      }
    >
      <TopologyDocBar />
      {needsIXHubMigrationNotice(topo) && !migrationDismissed ? (
        <Alert
          type="info"
          showIcon
          closable
          onClose={() => setMigrationDismissed(true)}
          style={{ marginBottom: 12 }}
          data-testid="ix-hub-migration"
          message="IX 现在可以作为受管的主枢纽建模"
          description={
            <>
              如果 IX 本身是一台能登录的服务器：在枢纽节点上选这台 IX 服务器、打开「IX 即主枢纽」并填国内入口地址，删除不受管的 IX 节点，再把中继 → 枢纽的链路设为普通 WireGuard。之后还可以加一个备用枢纽，主路径整条不通时由网关经 WSS 拨它。
              面板不会自动转换：现在的拓扑保持原样，照旧编译。
            </>
          }
        />
      ) : null}
      {managedWithout.length > 0 ? (
        <Alert
          type="warning"
          showIcon
          style={{ marginBottom: 12 }}
          message={`${managedWithout.length} 个受管节点还没有选择服务器：${managedWithout.map((n) => n.name || n.id).join("、")}`}
          description="点节点，在右侧选择它运行的服务器。没有服务器的节点不能装机，也不能参与 Mesh 部署。"
        />
      ) : null}
      {doc.dirty && (allocation.view?.changes ?? []).length > 0 ? (
        <Alert
          type="warning"
          showIcon
          style={{ marginBottom: 12 }}
          data-testid="allocation-changes"
          message="这次保存会改变已保存链路的接口、端口或地址"
          description={
            <>
              {(allocation.view?.changes ?? []).map((c) => (
                <div key={`${c.link_id}-${c.what}`}>
                  <Link to={href("topology", c.link_id)}>{c.link_id}</Link> {changeText(c)}
                </div>
              ))}
              <div>只有你明确改过的值会变（端口、地址、传输方式、启用）；增删别的链路不会改变已有链路的分配。变化的链路两端都要重新下发。</div>
            </>
          }
        />
      ) : null}
      <div className="topo-legend">
        {(Object.keys(roleLabel) as Role[]).map((r) => (
          <span key={r} className={`legend-dot role-${r}`}>
            {roleLabel[r]}
          </span>
        ))}
        <span className="legend-dot residential">住宅出口</span>
        {topo.nodes.some((n) => n.role === "exit" && n.external) ? <span className="legend-dot external">外部 SOCKS 出口（无链路）</span> : null}
        <span className="legend-line standby">待命链路</span>
        <span className="legend-line error">有错误</span>
      </div>
      <ReactFlowProvider>
        <Canvas topo={topo} servers={serverMap} issues={doc.issues} onSelect={select} onChange={doc.setTopo} />
      </ReactFlowProvider>
      <ClickableIssues issues={doc.issues} />
      {doc.paths.length > 0 ? (
        <Section title="各出口的路径（最近一次校验）">
          <div className="paths">
            {doc.paths.map((p) => (
              <div key={p.exit_id} className="path-row">
                <ApartmentOutlined />
                <span>{p.nodes.map((id) => topo.nodes.find((n) => n.id === id)?.name ?? id).join(" → ")}</span>
                <Typography.Text type="secondary" className="mono-small">
                  MTU {p.mtu} · MSS {p.mss4}/{p.mss6}
                </Typography.Text>
              </div>
            ))}
          </div>
        </Section>
      ) : (
        <Typography.Paragraph type="secondary" style={{ marginTop: 12 }}>
          点文档栏的「校验」可以看到每个出口的完整路径和 MTU。
        </Typography.Paragraph>
      )}
      <Drawer
        title={node ? `节点 · ${node.name || node.id}` : link ? `链路 · ${link.name || link.id}` : ""}
        open={!!node || !!link}
        onClose={() => select(null)}
        width={440}
        mask={false}
        destroyOnHidden
        extra={
          node ? (
            <Tooltip title={ROLE_HELP[node.role]}>
              <Tag>{roleLabel[node.role]}</Tag>
            </Tooltip>
          ) : link ? (
            <Tag>{transportLabel[link.transport]}</Tag>
          ) : null
        }
      >
        {node ? (
          <NodeDetail
            node={node}
            topo={topo}
            servers={servers.data?.servers}
            serversError={servers.error}
            onChange={doc.setTopo}
            onDelete={() => setDeleting(node)}
          />
        ) : link ? (
          <LinkDetail
            link={link}
            topo={topo}
            alloc={allocation.view?.links.find((l) => l.link_id === link.id)}
            allocChanges={(allocation.view?.changes ?? []).filter((c) => c.link_id === link.id)}
            allocFailed={allocation.failed}
            onChange={doc.setTopo}
            onDelete={() =>
              confirm({
                title: `删除链路「${link.name || link.id}」？`,
                consequence: "链路从工作副本里移除；保存并安装后这段隧道不再生成。",
                okText: "删除",
                onOk: () => {
                  doc.setTopo({ ...topo, links: topo.links.filter((l) => l.id !== link.id) });
                  select(null);
                },
              })
            }
          />
        ) : null}
      </Drawer>
      <SettingsDrawer open={settingsOpen} topo={topo} onClose={() => setSettingsOpen(false)} onChange={doc.setTopo} />
      <NodeDeleteDialog
        node={deleting}
        topo={topo}
        servers={servers.data?.servers}
        onCancel={() => setDeleting(null)}
        onDelete={(t) => {
          doc.setTopo(t);
          setDeleting(null);
          select(null);
        }}
      />
    </Page>
  );
}
