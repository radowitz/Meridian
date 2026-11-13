// 出口: region groups are the main view of exits. A region (香港, 美国 …)
// holds one or more groups; each group has an ordered member list, a mode
// (自动 / 手动) and two live lines kept apart: 实际使用, only from the hub's
// own report (actual.state "ok", read over SSH with a fixed command), and
// 面板推算, the panel's computation from health samples, never shown as the
// member in use.
// Every change edits the stored topology only (apply_required): the top bar
// and an inline notice say so until it is installed.
// Below the groups, 出口节点 lists every exit with what kind it is: a nested
// exit (reached through a relay exit, via_exit), an external SOCKS exit
// (an unmanaged SOCKS5 proxy behind a managed carrier exit) or one with a
// dynamic DNS endpoint (endpoint_host). Those settings are written into the
// stored topology with one PUT /api/topology, like the topology editor's
// save; the SOCKS username and password never pass through here (only the
// credential's ID does).

import {
  ArrowDownOutlined,
  ArrowUpOutlined,
  DeleteOutlined,
  EditOutlined,
  HolderOutlined,
  InfoCircleOutlined,
  PlusOutlined,
  ReloadOutlined,
  StarOutlined,
} from "@ant-design/icons";
import {
  Alert,
  App as AntApp,
  AutoComplete,
  Button,
  Checkbox,
  Drawer,
  Dropdown,
  Form,
  Input,
  InputNumber,
  Popover,
  Radio,
  Select,
  Space,
  Tag,
  Tooltip,
  Typography,
} from "antd";
import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import * as api from "./api";
import type { ApiError } from "./api";
import { href, useRouter, useStatus, useTopologyDoc } from "./state";
import { RelaySharingView } from "./RelaySharing";
import { isExternalExit, isNestedExit } from "./types";
import type {
  Carrying,
  Issue,
  Link as TLink,
  GroupActualView,
  GroupHubActual,
  GroupHubState,
  HubTier,
  GroupMemberView,
  GroupThresholds,
  Node,
  RegionGroup,
  RegionGroupInput,
  RegionGroupView,
  RegionGroupsView,
  SOCKSCredentialView,
  Topology,
} from "./types";
import {
  type StatusKind,
  ApiErrorAlert,
  ApplyRequiredNotice,
  DataView,
  EmptyState,
  IssueList,
  Link,
  Mono,
  Page,
  RefList,
  RefusedDialog,
  REGION_CODES,
  Section,
  StatusTag,
  TimeText,
  groupLabel,
  isDuplicateGroupName,
  regionLabel,
  showFieldError,
  useAction,
  useApi,
  useConfirmDanger,
  noteRateLimited,
  RateLimitNote,
  useServerCooldown,
} from "./ui";

// ------------------------------------------------------------ vocabulary ---

/** Why the group uses what it uses (state.reason / target_reason). */
export const GROUP_REASON: Record<string, string> = {
  preferred: "自动：实际顺序里第一个成员",
  chosen: "手动指定",
  constraint: "指定的成员不满足组的约束，改用第一个符合条件的成员",
  failover: "前面的成员不可用，自动切到后面的成员",
  fallback: "指定成员不可用，临时回落",
  held: "目标不可用，按设置保持不切换",
  mesh: "所有 WireGuard 成员都不可用，走 Mesh 备路",
  none: "没有可用成员",
};

const RETURN_BLOCK: Record<string, string> = {
  target_down: "首选仍不可用",
  target_last_failed: "首选最近一次检测失败",
  recovery_timer: "首选恢复后要持续正常一段时间才切回",
  switch_cooldown: "刚切换过，冷却中",
};

export const ON_FAILURE: Record<"hold" | "fallback", { title: string; desc: string }> = {
  hold: {
    title: "保持并告警",
    desc: "指定成员不可用时仍然用它（流量会断），只在面板告警；适合宁可断也不能换出口的服务。",
  },
  fallback: {
    title: "临时回落并告警",
    desc: "指定成员不可用时临时改用组里下一个可用成员，恢复后自动切回指定成员，同时告警。",
  },
};

const MESH_ACTIVE = "mmesh";

// ------------------------------------------------------- actual (hub) ---

/** Machine reasons of a non-ok actual state, in words. */
export const ACTUAL_CODE: Record<string, string> = {
  no_hub: "拓扑里没有枢纽节点",
  hub_no_server: "枢纽节点没有关联服务器",
  server_not_ready: "枢纽服务器还不能登录（指纹未确认或没有凭据）",
  ssh_failed: "登录枢纽读取状态失败",
  state_missing: "枢纽上没有这个组的运行记录",
  parse_error: "枢纽返回的内容无法解析",
  invalid_report: "枢纽报告的成员不属于这个组",
  plan_unavailable: "面板无法编译当前的地区组计划",
  heartbeat_old: "枢纽的心跳已过期",
  read_old: "上次读取太久了",
  plan_differs: "枢纽运行的不是当前配置",
  hop_failed: "枢纽切换路由失败",
  table_diverged: "枢纽路由表与切换器的选择不一致",
  static_only: "枢纽不切换这个组",
  not_read: "还没有读取枢纽状态",
  hub_identity_changed: "上次读取的不是当前枢纽（枢纽节点、服务器、地址、SSH 端口或主机指纹已变更），需要重新读取",
  carrying_unknown: "不知道现在由哪个枢纽承载",
};

// ------------------------------------------------------ carrying hub ---

export const HUB_TIER: Record<HubTier, string> = { primary: "主枢纽", backup: "备用枢纽" };

/** The gateway's path to the carrying hub (compile.planUpstream names). */
const UPSTREAM_PATH: Record<string, string> = { udp: "主路径 UDP", wss: "主路径 WSS", backup: "经 WSS", main: "主链路，多中继分担" };

/** The gateway's failover state in words (carrying.state). */
export const CARRYING_STATE: Record<string, { kind: StatusKind; label: string }> = {
  static: { kind: "unverified", label: "安装时设定" },
  ok: { kind: "ok", label: "已测量" },
  switching: { kind: "running", label: "切换中" },
  down: { kind: "failed", label: "全部路径不通" },
  degraded: { kind: "attention", label: "全部中继低于下限" },
};

/** Why the carrying hub is unknown (carrying.code). */
export const CARRYING_CODE: Record<string, string> = {
  agent_unavailable: "读不到本机 host agent",
  read_failed: "读取网关上游记录失败",
  not_recorded: "网关还没有上游记录",
  invalid_record: "网关的上游记录无法解析",
  record_mismatch: "网关记录的枢纽与当前拓扑不一致",
  stale: "网关的上游记录已过期",
};

/** "当前承载：备用枢纽 hk5（经 WSS，自 …）" or "承载枢纽未知：…". */
export function CarryingLine({ c }: { c: Carrying }) {
  if (!c.known) {
    return (
      <span data-testid="carrying" data-known="false">
        <Typography.Text type="warning">承载枢纽未知：</Typography.Text>
        <Typography.Text type="secondary">{c.message || CARRYING_CODE[c.code ?? ""] || c.code || "—"}</Typography.Text>
      </span>
    );
  }
  const st = c.state ? CARRYING_STATE[c.state] : undefined;
  const path = c.path ? UPSTREAM_PATH[c.path] ?? c.path : "";
  return (
    <span data-testid="carrying" data-known="true" data-tier={c.tier}>
      <Typography.Text type="secondary">当前承载：</Typography.Text>
      <Typography.Text strong>
        {c.tier ? HUB_TIER[c.tier] : "枢纽"} {c.hub_name || c.hub_node}
      </Typography.Text>
      {path || c.since ? (
        <Typography.Text type="secondary">
          （{path}
          {path && c.since ? "，" : ""}
          {c.since ? (
            <>
              自 <TimeText value={c.since} />
            </>
          ) : null}
          ）
        </Typography.Text>
      ) : null}{" "}
      {st ? (
        <StatusTag kind={st.kind} title={c.message}>
          {st.label}
        </StatusTag>
      ) : null}
    </span>
  );
}

/** Where a group's actual state was judged from (dual hub topologies). */
function readFrom(a: { hub_tier?: HubTier; hub_name?: string; hub_node?: string; server_name?: string }): string {
  if (!a.hub_tier && !a.hub_name && !a.hub_node) return "";
  return `读自 ${a.hub_tier ? HUB_TIER[a.hub_tier] + " " : ""}${a.hub_name || a.hub_node || ""}${a.server_name ? `（服务器 ${a.server_name}）` : ""}`;
}

/** Tag for a group's actual state: never "ok"-coloured unless the hub reported it. */
export function actualTag(a: GroupActualView): { kind: StatusKind; label: string } {
  switch (a.state) {
    case "ok":
      return { kind: "ok", label: "枢纽报告" };
    case "switch_failed":
      return { kind: "failed", label: "切换失败" };
    case "stale":
      return { kind: "unverified", label: "未验证 · 状态过期" };
    case "version_mismatch":
      return { kind: "unverified", label: "未验证 · 枢纽不是当前配置" };
    case "not_switchable":
      return { kind: "neutral", label: "枢纽不切换" };
    case "never_read":
      return { kind: "unverified", label: "未验证 · 未读取" };
    default:
      if (a.code === "hub_identity_changed") return { kind: "unverified", label: "未验证 · 枢纽已变更" };
      return { kind: "unverified", label: "未验证 · 读不到" };
  }
}

/** The fix for a non-ok actual state: a link or the refresh button. */
function ActualFix({ a, hub, onRefresh, refreshing }: { a: GroupActualView; hub?: GroupHubState; onRefresh?: () => void; refreshing?: boolean }) {
  const refresh = onRefresh ? (
    <Button size="small" icon={<ReloadOutlined />} loading={refreshing} onClick={onRefresh} disabled={hub ? !hub.readable : false}>
      重新读取
    </Button>
  ) : null;
  switch (a.code) {
    case "no_hub":
      return <Link to={href("topology")}>在拓扑里添加枢纽</Link>;
    case "hub_no_server":
      return <Link to={href("topology", hub?.hub_node)}>为枢纽节点选择服务器</Link>;
    case "server_not_ready":
      return hub?.server_id ? <Link to={href("servers", hub.server_id)}>到服务器页确认指纹和凭据</Link> : <Link to={href("servers")}>到服务器页</Link>;
    case "hub_identity_changed":
      // The old report is not the current hub's: read the current one, or
      // first make it readable (a new address or port needs its key
      // confirmed again).
      if (hub && !hub.readable) {
        return hub.server_id ? <Link to={href("servers", hub.server_id)}>到服务器页确认指纹和凭据</Link> : <Link to={href("topology", hub.hub_node)}>为枢纽节点选择服务器</Link>;
      }
      return refresh;
    case "plan_differs":
    case "state_missing":
      return (
        <Space size={4}>
          <Link to={href("deploy")}>到部署页为枢纽装机</Link>
          {refresh}
        </Space>
      );
    case "static_only":
    case "plan_unavailable":
      return null;
    default:
      return refresh;
  }
}

/** Hub-reported hop in words (member name, Mesh, or no member). */
function hopName(name: (id: string) => string, a: GroupActualView): string {
  if (a.active) return name(a.active);
  return a.hop === "blackhole" ? "无（路由表为黑洞，流量被丢弃）" : "—";
}

function stripView(g: RegionGroupView): RegionGroup {
  const out: RegionGroup = { id: g.id, name: g.name, members: [...g.members], mode: g.mode };
  if (g.region) out.region = g.region;
  if (g.chosen) out.chosen = g.chosen;
  if (g.on_failure) out.on_failure = g.on_failure;
  if (g.require_residential) out.require_residential = true;
  if (g.exclude_residential) out.exclude_residential = true;
  if (g.require_v6) out.require_v6 = true;
  if (g.notes) out.notes = g.notes;
  if (g.migrated_from) out.migrated_from = g.migrated_from;
  return out;
}

export function MemberAttrs({ m }: { m: { ix_bound?: boolean; residential?: boolean; egress_v6?: boolean } }) {
  return (
    <>
      {m.ix_bound ? (
        <Tooltip title="出口绑定在 IX 专线上：在组里自动排到最前">
          <Tag color="gold">IX 绑定</Tag>
        </Tooltip>
      ) : null}
      {m.residential ? <Tag color="green">住宅（家宽）</Tag> : null}
      {m.egress_v6 ? <Tag color="blue">IPv6</Tag> : null}
    </>
  );
}

function memberHealth(m: GroupMemberView, observed: boolean): ReactNode {
  if (!observed || !m.health) return <Typography.Text type="secondary">无健康样本</Typography.Text>;
  const h = m.health;
  const tip = (
    <span>
      连续失败 {h.fails} 次 · 连续成功 {h.goods} 次
      {h.last_at ? (
        <>
          <br />
          上次样本 {new Date(h.last_at).toLocaleString()}
        </>
      ) : null}
    </span>
  );
  return h.up ? (
    <StatusTag kind="ok" title={tip}>
      可用
    </StatusTag>
  ) : (
    <StatusTag kind="failed" title={tip}>
      不可用
    </StatusTag>
  );
}

// ----------------------------------------------------------- group card ---

function moved<T>(list: T[], from: number, to: number): T[] {
  const next = [...list];
  const [x] = next.splice(from, 1);
  next.splice(to, 0, x);
  return next;
}

function GroupCard({
  g,
  names,
  thresholds,
  highlighted,
  onChanged,
  onDeleted,
  onEdit,
  hub,
  dual,
  onRefresh,
  refreshing,
  allGroups,
  nodes,
}: {
  g: RegionGroupView;
  /** Topology nodes by ID: nested / external exits get their badges in the member list. */
  nodes?: Map<string, Node>;
  /** Every group: decides whether this one's name needs region + ID to be unambiguous. */
  allGroups: readonly RegionGroupView[];
  names: Map<string, string>;
  thresholds: GroupThresholds | undefined;
  hub?: GroupHubState;
  /** Backup hub topology: say which hub the actual state was read from. */
  dual?: boolean;
  onRefresh?: () => void;
  refreshing?: boolean;
  highlighted: boolean;
  onChanged: (g: RegionGroupView, what: string) => void;
  onDeleted: (id: string) => void;
  onEdit: () => void;
}) {
  const act = useAction();
  const confirm = useConfirmDanger();
  const [refused, setRefused] = useState<ApiError | null>(null);
  const [order, setOrder] = useState<string[] | null>(null);
  const [drag, setDrag] = useState<number | null>(null);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    setOrder(null);
  }, [g.members.join("\u0000")]);
  useEffect(() => {
    if (highlighted) ref.current?.scrollIntoView({ block: "center", behavior: "smooth" });
  }, [highlighted]);

  const name = (id: string) => (id === MESH_ACTIVE ? "Mesh 备路" : names.get(id) ?? id);
  // Unambiguous name for titles, labels and messages (region + ID when another group has the same name).
  const label = groupLabel(g, allGroups);
  const duplicate = isDuplicateGroupName(g, allGroups);
  const statusById = new Map(g.member_status.map((m) => [m.id, m]));
  const userOrder = order ?? g.members;
  const dirtyOrder = order !== null && order.join() !== g.members.join();
  const eligible = g.member_status.filter((m) => m.eligible);
  const effectiveDiffers =
    g.effective_order.join() !== g.members.filter((id) => statusById.get(id)?.eligible).join() ||
    g.member_status.some((m) => !m.eligible);

  const patch = (body: Partial<RegionGroupInput>, what: string, key: string) =>
    act.run(async () => {
      const r = await api.updateGroup(g.id, body);
      onChanged(r.group, what);
    }, key);

  const setMode = (mode: "auto" | "manual") => {
    if (mode === g.mode) return;
    if (mode === "auto") {
      void patch({ mode: "auto" }, "已改成自动模式", "mode");
      return;
    }
    const inUse = g.actual.state === "ok" && g.actual.active !== MESH_ACTIVE ? g.actual.active : "";
    const chosen = inUse || g.target || eligible[0]?.id;
    if (!chosen) return;
    void patch({ mode: "manual", chosen, on_failure: "hold" }, `已改成手动模式，指定 ${name(chosen)}`, "mode");
  };

  const st = g.model;
  const observed = st.observed;
  const a = g.actual;
  const aok = a.state === "ok";
  const tag = actualTag(a);
  const source = dual ? readFrom(a) : "";
  const thresholdText = thresholds
    ? `连续 ${thresholds.fails_need} 次检测失败判定不可用；恢复后连续 ${thresholds.recovers_need} 次成功、并且距上次切换满 ${Math.round(thresholds.cooldown_sec / 60)} 分钟才切回。`
    : "";

  return (
    <div ref={ref} className={`group-card${highlighted ? " highlighted" : ""}`} data-testid={`group-${g.id}`}>
      <div className="group-card-head">
        <div className="group-card-title">
          <Typography.Text strong style={{ fontSize: 15 }}>
            {g.name}
          </Typography.Text>
          <Typography.Text type="secondary" className="mono-small">
            {g.id}
          </Typography.Text>
          {duplicate ? (
            <Tooltip title="另有一个地区组同名；按地区和 ID 区分，选择器里也会显示它们">
              <Tag color="warning" data-testid={`dup-name-${g.id}`}>
                同名 · {regionLabel(g.region)}
              </Tag>
            </Tooltip>
          ) : null}
          {g.is_default ? (
            <Tooltip title="没有命中任何规则的境外流量走这个组">
              <Tag color="processing" icon={<StarOutlined />}>
                默认组
              </Tag>
            </Tooltip>
          ) : null}
        </div>
        <Radio.Group
          size="small"
          optionType="button"
          buttonStyle="solid"
          value={g.mode}
          disabled={!!act.busy || (g.mode === "auto" && eligible.length === 0)}
          onChange={(e) => setMode(e.target.value)}
          options={[
            { value: "auto", label: "自动" },
            { value: "manual", label: "手动" },
          ]}
          aria-label={`${label} 的模式`}
        />
      </div>
      <Space size={[4, 4]} wrap style={{ marginBottom: 8 }}>
        {g.require_residential ? <Tag color="green">要求住宅</Tag> : null}
        {g.exclude_residential ? <Tag>排除住宅</Tag> : null}
        {g.require_v6 ? <Tag color="blue">要求 IPv6</Tag> : null}
        {g.mesh_backup ? (
          <Tooltip title="所有 WireGuard 成员都不可用时，经 Cloudflare Mesh 备路出去（数据面未验证）">
            <Tag>Mesh 备路</Tag>
          </Tooltip>
        ) : null}
        {!g.switchable ? (
          <Tooltip title="枢纽不能在这个组的成员之间动态切换（成员只能经中继或 Mesh 到达）；只会使用静态选中的成员">
            <Tag color="orange">不能动态切换</Tag>
          </Tooltip>
        ) : null}
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
          {g.mode === "auto" ? "按顺序用第一个可用成员，失败时自动切到下一个" : "固定使用指定的成员"}
        </Typography.Text>
      </Space>

      {/* Live lines. 实际使用 comes only from the hub's report (actual.state
          "ok"); otherwise it is unknown with the reason and the fix. The
          panel's model is a separate, labelled line. */}
      <div className={`group-live${aok && a.alert ? " alert" : ""}`} data-testid="group-live">
        <Space size={[6, 4]} wrap data-testid="group-actual" data-state={a.state}>
          <Typography.Text type="secondary">实际使用</Typography.Text>
          {aok ? (
            <>
              <Typography.Text strong>{hopName(name, a)}</Typography.Text>
              <Typography.Text type="secondary">·</Typography.Text>
              <span>{GROUP_REASON[a.reason ?? ""] ?? a.reason}</span>
              <Typography.Text type="secondary">· 上次切换</Typography.Text>
              <TimeText value={a.last_switch} empty="启动以来未切换" />
              <Typography.Text type="secondary">· 读取于</Typography.Text>
              <TimeText value={a.read_at} />
              <StatusTag kind={tag.kind} title="枢纽切换服务记录的实际路由（从枢纽路由表读出），经 SSH 固定命令读回。">
                {tag.label}
              </StatusTag>
              {source ? (
                <Typography.Text type="secondary" data-testid="group-actual-source">
                  实测 · {source}
                </Typography.Text>
              ) : null}
            </>
          ) : (
            <>
              <Typography.Text strong>{a.state === "not_switchable" ? "不适用" : "未知"}</Typography.Text>
              <StatusTag kind={tag.kind} title={a.message}>
                {tag.label}
              </StatusTag>
              {a.read_at && a.state !== "not_switchable" ? (
                <>
                  <Typography.Text type="secondary">读取于</Typography.Text>
                  <TimeText value={a.read_at} />
                </>
              ) : null}
              {source ? (
                <Typography.Text type="secondary" data-testid="group-actual-source">
                  {source}
                </Typography.Text>
              ) : null}
            </>
          )}
        </Space>
        {!aok ? (
          <div className="group-actual-why" data-testid="group-actual-why">
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              {ACTUAL_CODE[a.code ?? ""] ?? a.code}
              {a.message ? `：${a.message}` : ""}
            </Typography.Text>{" "}
            <ActualFix a={a} hub={hub} onRefresh={onRefresh} refreshing={refreshing} />
            {a.state === "switch_failed" && a.reported ? (
              <Typography.Paragraph type="secondary" style={{ margin: "4px 0 0", fontSize: 12 }}>
                枢纽报告（未确认）：路由表 {a.reported.hop === "blackhole" ? "黑洞" : name(a.reported.hop)}
                {a.reported.want ? `，想切到 ${name(a.reported.want)}` : ""}
                {a.reported.failed_at ? (
                  <>
                    ，失败于 <TimeText value={a.reported.failed_at} />
                  </>
                ) : null}
              </Typography.Paragraph>
            ) : null}
            {a.code === "carrying_unknown" && g.actual_by_hub && g.actual_by_hub.length > 0 ? (
              <HubReports rows={g.actual_by_hub} name={name} />
            ) : null}
          </div>
        ) : null}
        {aok && a.clock_skew_sec !== undefined && hub && Math.abs(a.clock_skew_sec) > hub.skew_warn_sec ? (
          <Typography.Paragraph type="secondary" style={{ margin: "4px 0 0", fontSize: 12 }}>
            枢纽时钟与面板相差 {Math.abs(a.clock_skew_sec)} 秒；上面的时间已按读取时刻换算。
          </Typography.Paragraph>
        ) : null}
        {aok && a.alert ? (
          <Alert
            type="warning"
            showIcon
            style={{ marginTop: 8 }}
            message={<span data-testid="group-alert">{a.alert_message || "这个组需要处理"}</span>}
          />
        ) : null}

        <div className="group-model" data-testid="group-model">
          <Space size={[6, 4]} wrap>
            <Tooltip title="面板按网关送来的健康样本自行推算的状态（source: panel_model），不是从枢纽读回的实际路由。">
              <Tag icon={<InfoCircleOutlined />}>面板推算</Tag>
            </Tooltip>
            {observed ? (
              <>
                <Typography.Text>{st.active ? name(st.active) : "无可用成员"}</Typography.Text>
                <Typography.Text type="secondary">· {GROUP_REASON[st.reason] ?? st.reason}</Typography.Text>
                {st.last_switch ? (
                  <>
                    <Typography.Text type="secondary">· 推算切换于</Typography.Text>
                    <TimeText value={st.last_switch} />
                  </>
                ) : null}
              </>
            ) : (
              <>
                <Typography.Text type="secondary">按配置应使用</Typography.Text>
                <Typography.Text>{st.active ? name(st.active) : "—"}</Typography.Text>
                <StatusTag kind="unverified" title="还没有收到这个组的健康样本：这是按配置计算的目标，不代表枢纽上实际在用。">
                  未验证 · 无健康样本
                </StatusTag>
              </>
            )}
          </Space>
          {observed && st.alert ? (
            <Typography.Paragraph type="secondary" style={{ margin: "4px 0 0", fontSize: 12 }} data-testid="group-model-alert">
              面板推算：{st.alert_message || "这个组需要处理"}
            </Typography.Paragraph>
          ) : null}
          {observed && st.return_blocked_by ? (
            <Typography.Paragraph type="secondary" style={{ margin: "4px 0 0", fontSize: 12 }}>
              面板推算还没有切回 {name(g.target)}：{RETURN_BLOCK[st.return_blocked_by] ?? st.return_blocked_by}
              {st.return_not_before ? (
                <>
                  ，最早 <TimeText value={st.return_not_before} />
                </>
              ) : null}
            </Typography.Paragraph>
          ) : null}
        </div>
      </div>

      {g.mode === "manual" ? (
        <div className="group-manual">
          <Space wrap align="center">
            <Typography.Text>指定成员</Typography.Text>
            <Select
              size="small"
              style={{ minWidth: 200 }}
              value={g.chosen || undefined}
              aria-label={`${label} 的指定成员`}
              disabled={!!act.busy}
              onChange={(chosen: string) => void patch({ chosen }, `已指定 ${name(chosen)}`, "chosen")}
              options={g.member_status.map((m) => ({
                value: m.id,
                label: `${m.name || m.id}${m.eligible ? "" : "（不符合组约束）"}`,
                disabled: !m.eligible,
              }))}
            />
          </Space>
          <Radio.Group
            style={{ display: "flex", flexDirection: "column", gap: 6, marginTop: 8 }}
            value={g.on_failure_effective ?? g.on_failure ?? "hold"}
            disabled={!!act.busy}
            onChange={(e) => void patch({ on_failure: e.target.value }, `指定成员不可用时：${ON_FAILURE[e.target.value as "hold"].title}`, "on_failure")}
            aria-label={`${label} 指定成员不可用时`}
          >
            {(["hold", "fallback"] as const).map((k) => (
              <Radio key={k} value={k}>
                <Typography.Text strong>{ON_FAILURE[k].title}</Typography.Text>
                <Typography.Text type="secondary" style={{ display: "block", fontSize: 12 }}>
                  {ON_FAILURE[k].desc}
                </Typography.Text>
              </Radio>
            ))}
          </Radio.Group>
        </div>
      ) : null}

      <div className="group-members-head">
        <Typography.Text type="secondary">
          成员顺序{g.mode === "auto" ? "（自动模式按这个顺序尝试）" : ""}
        </Typography.Text>
        {thresholdText && g.mode === "auto" ? (
          <Tooltip title={thresholdText}>
            <Typography.Text type="secondary" style={{ fontSize: 12, cursor: "help" }}>
              <InfoCircleOutlined /> 切换规则
            </Typography.Text>
          </Tooltip>
        ) : null}
      </div>
      {userOrder.length === 0 ? (
        <Typography.Paragraph type="secondary">组里还没有成员。编辑这个组来添加出口。</Typography.Paragraph>
      ) : (
        <ol className="member-list" aria-label={`${label} 的成员`}>
          {userOrder.map((id, i) => {
            const m = statusById.get(id);
            const excluded = !m || !m.eligible;
            return (
              <li
                key={id}
                className={`member-row${excluded ? " excluded" : ""}${drag === i ? " dragging" : ""}`}
                data-testid={`member-${g.id}-${id}`}
                onDragOver={(e) => {
                  if (drag === null) return;
                  e.preventDefault();
                }}
                onDrop={(e) => {
                  e.preventDefault();
                  if (drag === null || drag === i) return;
                  setOrder(moved(userOrder, drag, i));
                  setDrag(null);
                }}
              >
                <span
                  className="member-handle"
                  draggable
                  onDragStart={(e) => {
                    setDrag(i);
                    e.dataTransfer.effectAllowed = "move";
                    e.dataTransfer.setData("text/plain", id);
                  }}
                  onDragEnd={() => setDrag(null)}
                  title="拖动排序"
                  aria-hidden
                >
                  <HolderOutlined />
                </span>
                <span className="member-pos">{i + 1}</span>
                <div className="member-main">
                  <Space size={[4, 2]} wrap>
                    <Link to={href("topology", id)}>{m?.name || id}</Link>
                    {m ? <MemberAttrs m={m} /> : null}
                    {nodes?.get(id) ? <ExitKindTags node={nodes.get(id)!} name={name} /> : null}
                    {m?.actual_active ? (
                      <Tooltip title="枢纽报告这个组的路由表正在使用它">
                        <Tag color="success">使用中</Tag>
                      </Tooltip>
                    ) : null}
                    {m && !m.actual_active && observed && m.model_active ? (
                      <Tooltip title="面板按健康样本推算组在用它，未经枢纽确认">
                        <Tag>推算在用</Tag>
                      </Tooltip>
                    ) : null}
                    {m && g.target === id && !m.actual_active ? (
                      <Tooltip title="按配置应使用的成员">
                        <Tag>目标</Tag>
                      </Tooltip>
                    ) : null}
                    {g.mode === "manual" && g.chosen === id ? <Tag color="purple">指定</Tag> : null}
                    {excluded ? <Tag color="default">已排除</Tag> : m && m.position !== m.user_position ? (
                      <Tag>实际第 {m.position + 1} 位</Tag>
                    ) : null}
                    {m?.switchable === false ? <Tag color="orange">不能动态切到</Tag> : null}
                  </Space>
                  {m && m.reasons.length > 0 ? (
                    <ul className="member-reasons">
                      {m.reasons.map((r) => (
                        <li key={r.code}>{r.message}</li>
                      ))}
                    </ul>
                  ) : !m ? (
                    <ul className="member-reasons">
                      <li>这个出口不在拓扑里了。</li>
                    </ul>
                  ) : null}
                </div>
                <div className="member-health">{m ? memberHealth(m, observed) : null}</div>
                <Space size={2} className="member-move">
                  <Button
                    size="small"
                    type="text"
                    icon={<ArrowUpOutlined />}
                    disabled={i === 0 || !!act.busy}
                    aria-label={`上移 ${m?.name || id}`}
                    onClick={() => setOrder(moved(userOrder, i, i - 1))}
                  />
                  <Button
                    size="small"
                    type="text"
                    icon={<ArrowDownOutlined />}
                    disabled={i === userOrder.length - 1 || !!act.busy}
                    aria-label={`下移 ${m?.name || id}`}
                    onClick={() => setOrder(moved(userOrder, i, i + 1))}
                  />
                </Space>
              </li>
            );
          })}
        </ol>
      )}
      {dirtyOrder ? (
        <div className="order-bar">
          <Typography.Text>顺序已调整，保存后生效（安装后网关才按新顺序切换）。</Typography.Text>
          <Space>
            <Button size="small" onClick={() => setOrder(null)}>
              撤销
            </Button>
            <Button size="small" type="primary" loading={act.busy === "order"} onClick={() => void patch({ members: order! }, "成员顺序已保存", "order")}>
              保存顺序
            </Button>
          </Space>
        </div>
      ) : null}
      {effectiveDiffers && !dirtyOrder ? (
        <Typography.Paragraph className="effective-order" data-testid="effective-order">
          <Typography.Text type="secondary">实际顺序：</Typography.Text>
          {g.effective_order.length > 0 ? g.effective_order.map(name).join(" → ") : "没有符合条件的成员"}
          <Typography.Text type="secondary">（和你排的顺序不同，原因见各成员）</Typography.Text>
        </Typography.Paragraph>
      ) : null}

      <ApiErrorAlert error={act.error} onClose={act.clear} style={{ marginTop: 8, marginBottom: 0 }} />
      <div className="group-card-foot">
        <Popover
          trigger="click"
          title="引用这个组的地方"
          content={<RefList refs={g.in_use_by} empty="没有规则引用这个组" />}
        >
          <Button size="small" type="link" style={{ paddingInline: 0 }}>
            {g.in_use_by.length > 0 ? `被 ${g.in_use_by.length} 处引用` : "未被引用"}
          </Button>
        </Popover>
        <Space size={4} wrap>
          {!g.is_default ? (
            <Button
              size="small"
              loading={act.busy === "default"}
              onClick={() =>
                act.run(async () => {
                  const r = await api.setDefaultGroup(g.id);
                  onChanged(r.group, `${label} 已设为默认组`);
                }, "default")
              }
            >
              设为默认
            </Button>
          ) : null}
          <Button size="small" icon={<EditOutlined />} onClick={onEdit}>
            编辑
          </Button>
          <Button
            size="small"
            danger
            icon={<DeleteOutlined />}
            onClick={() =>
              confirm({
                title: `删除地区组「${label}」？`,
                consequence:
                  g.in_use_by.length > 0
                    ? "这个组还被规则或默认组设置引用，删除会被拒绝；先把引用改到别的组。"
                    : "组从拓扑里移除，出口本身不受影响；安装后网关上不再有这个组的路由表。",
                okText: "删除",
                onOk: () =>
                  act.run(
                    async () => {
                      await api.deleteGroup(g.id);
                      onDeleted(g.id);
                    },
                    "delete",
                    (e) => {
                      if (e.code === "in_use") {
                        setRefused(e);
                        act.clear();
                      }
                    },
                  ),
              })
            }
          >
            删除
          </Button>
        </Space>
      </div>
      <RefusedDialog error={refused} title={`地区组「${label}」仍被引用，未删除`} onClose={() => setRefused(null)} />
    </div>
  );
}

/**
 * Each hub's own judgement of a group while the carrying hub is unknown:
 * shown for diagnosis only, never as the member in use.
 */
function HubReports({ rows, name }: { rows: GroupHubActual[]; name: (id: string) => string }) {
  return (
    <div className="group-hub-reports" data-testid="group-hub-reports" style={{ marginTop: 4, fontSize: 12 }}>
      <Typography.Text type="secondary">各枢纽报告（未确认承载）：</Typography.Text>
      {rows.map((r) => {
        const t = actualTag({ ...r, alert: r.alert ?? false } as GroupActualView);
        return (
          <div key={`${r.tier}:${r.hub_node}`} data-testid={`hub-report-${r.tier}`}>
            <Space size={[6, 2]} wrap>
              <Typography.Text type="secondary">
                {HUB_TIER[r.tier]} {r.hub_name || r.hub_node}
              </Typography.Text>
              {r.state === "ok" ? (
                <Typography.Text>报告在用 {r.active ? name(r.active) : r.hop === "blackhole" ? "无（黑洞）" : "—"}</Typography.Text>
              ) : (
                <Typography.Text type="secondary">{ACTUAL_CODE[r.code ?? ""] ?? r.code ?? r.state}</Typography.Text>
              )}
              <StatusTag kind={r.state === "ok" ? "unverified" : t.kind} title={r.message}>
                {r.state === "ok" ? "未确认承载" : t.label}
              </StatusTag>
            </Space>
          </div>
        );
      })}
    </div>
  );
}

// ------------------------------------------------------------- hub bar ---

/** One hub of a backup hub topology: tier, server, readability, last read, plan. */
function HubRow({ hub }: { hub: GroupHubState }) {
  const lr = hub.last_read;
  const limited = !!lr && lr.ssh_code === "ssh_rate_limited";
  useEffect(() => {
    if (limited && lr) noteRateLimited(hub.server_id, lr.retry_after ?? 60, Date.parse(lr.read_at));
  }, [limited, lr, hub.server_id]);
  const cooldown = useServerCooldown(hub.server_id);
  return (
    <div className="hub-row" data-testid={`hub-row-${hub.tier ?? "primary"}`} data-carrying={hub.carrying ? "true" : "false"} style={{ marginTop: 4 }}>
      <Space size={[6, 4]} wrap>
        <Tag color={hub.carrying ? "processing" : undefined}>{HUB_TIER[hub.tier ?? "primary"]}</Tag>
        <Typography.Text>{hub.hub_name || hub.hub_node || "—"}</Typography.Text>
        {hub.server_name ? <Typography.Text type="secondary">· 服务器 {hub.server_name}</Typography.Text> : null}
        {hub.carrying ? <Tag color="blue">承载中</Tag> : null}
        {!hub.readable ? (
          <StatusTag kind="attention" title={hub.not_readable_message}>
            不能读取
          </StatusTag>
        ) : lr ? (
          <>
            <Typography.Text type="secondary">· 上次读取</Typography.Text>
            <TimeText value={lr.read_at} />
            {lr.current_hub === false ? (
              <StatusTag kind="unverified" title={lr.identity_message}>
                不是当前枢纽
              </StatusTag>
            ) : lr.ok ? (
              <StatusTag kind="ok">读取成功</StatusTag>
            ) : (
              <StatusTag kind="failed" title={lr.error}>
                读取失败
              </StatusTag>
            )}
          </>
        ) : (
          <StatusTag kind="unverified">未读取</StatusTag>
        )}
        {hub.plan_id ? (
          <Tooltip title="面板现在会下发给这个枢纽的地区组计划">
            <Typography.Text type="secondary" className="mono-small">
              计划 {hub.plan_id.slice(0, 12)}
            </Typography.Text>
          </Tooltip>
        ) : null}
      </Space>
      {!hub.readable ? (
        <Typography.Paragraph type="secondary" style={{ margin: "2px 0 0", fontSize: 12 }}>
          {ACTUAL_CODE[hub.not_readable_code ?? ""] ?? hub.not_readable_code}
          {hub.not_readable_message ? `：${hub.not_readable_message}` : ""}{" "}
          <ActualFix a={{ state: "unavailable", code: hub.not_readable_code, active: "", alert: false, last_switch: null, read_at: null, hub_reported_at: null, deployed_matches: null }} hub={hub} />
        </Typography.Paragraph>
      ) : lr && lr.current_hub === false ? (
        <Typography.Paragraph type="secondary" style={{ margin: "2px 0 0", fontSize: 12 }}>
          {lr.identity_message || ACTUAL_CODE.hub_identity_changed}
        </Typography.Paragraph>
      ) : lr && !lr.ok && lr.error ? (
        <Typography.Paragraph type="secondary" style={{ margin: "2px 0 0", fontSize: 12 }}>
          {lr.error}
          {limited ? <RateLimitNote seconds={cooldown} /> : null}
        </Typography.Paragraph>
      ) : null}
    </div>
  );
}

/** Backup hub topology: which hub carries, then every hub with its own read. */
function DualHubStateBar({ hubs, carrying, onRefresh, refreshing }: { hubs: GroupHubState[]; carrying: Carrying; onRefresh: () => void; refreshing: boolean }) {
  const readable = hubs.some((h) => h.readable);
  const busy = refreshing || hubs.some((h) => h.refreshing);
  const first = hubs[0];
  return (
    <div className="hub-state-bar" data-testid="hub-state-bar" data-mode="dual">
      <Space size={[6, 4]} wrap>
        <Typography.Text strong>枢纽运行状态</Typography.Text>
        <CarryingLine c={carrying} />
        <Tooltip
          title={`读取全部枢纽：经服务器管理的 SSH 通道（已确认的主机指纹、保存的凭据）各执行一条固定的只读命令，并读取网关记录的上游路径。${
            first ? `枢纽切换服务每 ${first.loop_interval_sec} 秒记录一次；心跳超过 ${first.stale_after_sec} 秒或读取超过 ${Math.round(first.read_max_age_sec / 60)} 分钟即视为过期。` : ""
          }`}
        >
          <Button size="small" icon={<ReloadOutlined />} loading={busy} disabled={!readable} onClick={onRefresh}>
            读取枢纽状态
          </Button>
        </Tooltip>
      </Space>
      {hubs.map((h) => (
        <HubRow key={`${h.tier}:${h.hub_node}`} hub={h} />
      ))}
      <Typography.Paragraph type="secondary" style={{ margin: "4px 0 0", fontSize: 12 }}>
        只有承载中的枢纽的报告算作实际使用；承载枢纽由网关的上游记录决定，面板不自行推断。
      </Typography.Paragraph>
    </div>
  );
}

/**
 * Where the 实际使用 lines come from: the hub's server, the last read and a
 * refresh button. A hub that cannot be read says why and links to the fix.
 */
function HubStateBar({ hub, onRefresh, refreshing }: { hub: GroupHubState | undefined; onRefresh: () => void; refreshing: boolean }) {
  const lr = hub?.last_read;
  const limited = !!lr && lr.ssh_code === "ssh_rate_limited";
  useEffect(() => {
    if (limited && lr) noteRateLimited(hub?.server_id, lr.retry_after ?? 60, Date.parse(lr.read_at));
  }, [limited, lr, hub?.server_id]);
  const cooldown = useServerCooldown(hub?.server_id);
  if (!hub) return null;
  const rules = `枢纽切换服务每 ${hub.loop_interval_sec} 秒记录一次；心跳超过 ${hub.stale_after_sec} 秒或读取超过 ${Math.round(hub.read_max_age_sec / 60)} 分钟即视为过期。`;
  return (
    <div className="hub-state-bar" data-testid="hub-state-bar">
      <Space size={[6, 4]} wrap>
        <Typography.Text strong>枢纽运行状态</Typography.Text>
        {hub.hub_node ? (
          <Typography.Text type="secondary">
            {hub.hub_name || hub.hub_node}
            {hub.server_name ? ` · 服务器 ${hub.server_name}` : ""}
          </Typography.Text>
        ) : null}
        {lr ? (
          <>
            <Typography.Text type="secondary">· 上次读取</Typography.Text>
            <TimeText value={lr.read_at} />
            {lr.current_hub === false ? (
              <StatusTag kind="unverified" title={lr.identity_message}>
                不是当前枢纽
              </StatusTag>
            ) : lr.ok ? (
              <StatusTag kind="ok">读取成功</StatusTag>
            ) : (
              <StatusTag kind="failed" title={lr.error}>
                读取失败
              </StatusTag>
            )}
          </>
        ) : (
          <StatusTag kind="unverified">未读取</StatusTag>
        )}
        <Tooltip title={`经服务器管理的 SSH 通道（已确认的主机指纹、保存的凭据）执行一条固定的只读命令。${rules}`}>
          <Button size="small" icon={<ReloadOutlined />} loading={refreshing || hub.refreshing} disabled={!hub.readable || cooldown > 0} onClick={onRefresh}>
            {cooldown > 0 ? `${cooldown} 秒后可读取` : "读取枢纽状态"}
          </Button>
        </Tooltip>
      </Space>
      {!hub.readable ? (
        <Typography.Paragraph type="secondary" style={{ margin: "4px 0 0", fontSize: 12 }} data-testid="hub-not-readable">
          {ACTUAL_CODE[hub.not_readable_code ?? ""] ?? hub.not_readable_code}
          {hub.not_readable_message ? `：${hub.not_readable_message}` : ""}{" "}
          <ActualFix a={{ state: "unavailable", code: hub.not_readable_code, active: "", alert: false, last_switch: null, read_at: null, hub_reported_at: null, deployed_matches: null }} hub={hub} />
        </Typography.Paragraph>
      ) : lr && lr.current_hub === false ? (
        <Typography.Paragraph type="secondary" style={{ margin: "4px 0 0", fontSize: 12 }} data-testid="hub-identity-changed">
          {lr.identity_message || ACTUAL_CODE.hub_identity_changed}
        </Typography.Paragraph>
      ) : lr && !lr.ok && lr.error ? (
        <Typography.Paragraph type="secondary" style={{ margin: "4px 0 0", fontSize: 12 }}>
          {lr.error}
          {limited ? <RateLimitNote seconds={cooldown} /> : null}
        </Typography.Paragraph>
      ) : null}
    </div>
  );
}

/** Reads the hub once when the page opens, if it is readable and the last read is older than a minute. */
const AUTO_REFRESH_AFTER_MS = 60_000;

// ---------------------------------------------------------------- drawer ---

interface FormValues {
  name: string;
  id?: string;
  region?: string;
  members: string[];
  mode: "auto" | "manual";
  chosen?: string;
  on_failure?: "hold" | "fallback";
  constraint: "none" | "require" | "exclude";
  require_v6: boolean;
  notes?: string;
}

function exitOption(n: Node) {
  const attrs = [n.region ? regionLabel(n.region) : null, n.ix_bound ? "IX 绑定" : null, n.residential ? "住宅" : null, n.egress_v6 ? "IPv6" : null]
    .filter(Boolean)
    .join(" · ");
  return { value: n.id, label: `${n.name}（${n.id}）${attrs ? ` · ${attrs}` : ""}` };
}

function GroupDrawer({
  open,
  group,
  exits,
  others,
  onClose,
  onSaved,
}: {
  open: boolean;
  group: RegionGroupView | null;
  exits: Node[];
  /** The existing groups: a name that another group already has gets a hint. */
  others?: readonly RegionGroupView[];
  onClose: () => void;
  onSaved: (g: RegionGroupView, created: boolean) => void;
}) {
  const [form] = Form.useForm<FormValues>();
  const act = useAction();
  const [fieldHandled, setFieldHandled] = useState(false);
  const mode = Form.useWatch("mode", form) ?? group?.mode ?? "auto";
  const typedName = (Form.useWatch("name", form) as string | undefined) ?? group?.name ?? "";
  const sameName = typedName.trim()
    ? (others ?? []).filter((o) => o.id !== group?.id && o.name.trim().toLocaleLowerCase() === typedName.trim().toLocaleLowerCase())
    : [];
  const members = Form.useWatch("members", form) ?? group?.members ?? [];
  const regions = useMemo(() => {
    const set = new Set<string>(REGION_CODES);
    exits.forEach((n) => n.region && set.add(n.region));
    return [...set].map((c) => ({ value: c, label: regionLabel(c) }));
  }, [exits]);

  const initial: FormValues = group
    ? {
        name: group.name,
        region: group.region,
        members: group.members,
        mode: group.mode,
        chosen: group.chosen,
        on_failure: group.on_failure ?? "hold",
        constraint: group.require_residential ? "require" : group.exclude_residential ? "exclude" : "none",
        require_v6: !!group.require_v6,
        notes: group.notes,
      }
    : { name: "", members: [], mode: "auto", on_failure: "hold", constraint: "none", require_v6: false };

  async function save() {
    let v: FormValues;
    try {
      v = await form.validateFields();
    } catch {
      return;
    }
    const body: RegionGroupInput = {
      id: group ? group.id : v.id?.trim() || "",
      name: v.name.trim(),
      region: (v.region ?? "").trim().toLowerCase(),
      members: v.members ?? [],
      mode: v.mode,
      require_residential: v.constraint === "require",
      exclude_residential: v.constraint === "exclude",
      require_v6: v.require_v6,
      notes: v.notes ?? "",
    };
    if (v.mode === "manual") {
      body.chosen = v.chosen;
      body.on_failure = v.on_failure ?? "hold";
    }
    const fields = ["name", "id", "region", "members", "mode", "chosen", "on_failure", "require_v6", "notes"];
    const onError = (e: ApiError) =>
      setFieldHandled(
        showFieldError(form, e, fields, { require_residential: "constraint", exclude_residential: "constraint" }) ||
          (e.field === "require_residential" || e.field === "exclude_residential"
            ? (form.setFields([{ name: "constraint", errors: [e.message] }]), true)
            : false),
      );
    setFieldHandled(false);
    const res = await act.run(
      async () => {
        if (group) {
          const { id: _id, ...patch } = body;
          void _id;
          return (await api.updateGroup(group.id, patch)).group;
        }
        if (!body.id) delete (body as Partial<RegionGroupInput>).id;
        return (await api.createGroup(body)).group;
      },
      "save",
      onError,
    );
    if (res) onSaved(res, !group);
  }

  return (
    <Drawer
      title={group ? `编辑地区组「${group.name}」` : "新建地区组"}
      open={open}
      onClose={onClose}
      width={560}
      destroyOnHidden
      footer={
        <Space>
          <Button onClick={onClose}>取消</Button>
          <Button type="primary" loading={act.busy === "save"} onClick={() => void save()}>
            {group ? "保存" : "创建"}
          </Button>
        </Space>
      }
    >
      {act.error && !fieldHandled ? <ApiErrorAlert error={act.error} /> : null}
      <Form form={form} layout="vertical" initialValues={initial} requiredMark="optional" autoComplete="off">
        <Form.Item
          name="name"
          label="名称"
          rules={[{ required: true, message: "请填写名称" }]}
          extra={
            sameName.length > 0 ? (
              <span data-testid="group-same-name">
                已有同名地区组 {sameName.map((o) => `${o.id}（${regionLabel(o.region)}）`).join("、")}。可以保存；列表和选择器会附上地区和 ID 区分它们，起个不同的名字更好认。
              </span>
            ) : undefined
          }
        >
          <Input placeholder="例如 香港（机房）" />
        </Form.Item>
        {!group ? (
          <Form.Item name="id" label="ID" extra="留空按地区或名称自动生成。规则和链接用它引用这个组，创建后不能改。">
            <Input className="mono" placeholder="例如 hk" />
          </Form.Item>
        ) : null}
        <Form.Item name="region" label="国家或地区" extra="用于在出口页分区显示；一个地区可以有多个组，例如机房和住宅。">
          <AutoComplete options={regions} placeholder="例如 hk、us、jp" filterOption={(i, o) => !!o && (o.value + o.label).toLowerCase().includes(i.toLowerCase())} />
        </Form.Item>
        <Form.Item
          name="members"
          label="成员"
          extra="按选择的先后排序；创建后可以在卡片上拖动或用箭头调整。IX 绑定的出口会自动排在最前。"
        >
          <Select mode="multiple" options={exits.map(exitOption)} placeholder="选择出口" optionFilterProp="label" aria-label="成员" />
        </Form.Item>
        <Form.Item name="constraint" label="住宅约束">
          <Radio.Group>
            <Space direction="vertical">
              <Radio value="none">不限</Radio>
              <Radio value="require">
                要求住宅 <Typography.Text type="secondary">— 只用家宽出口；要求家宽的规则（如 Netflix）必须指向这样的组</Typography.Text>
              </Radio>
              <Radio value="exclude">
                排除住宅 <Typography.Text type="secondary">— 不用家宽出口，例如默认境外组</Typography.Text>
              </Radio>
            </Space>
          </Radio.Group>
        </Form.Item>
        <Form.Item name="require_v6" valuePropName="checked" extra="只用有 IPv6 出口能力的成员；要求 IPv6 的规则必须指向这样的组。">
          <Checkbox>要求 IPv6</Checkbox>
        </Form.Item>
        <Form.Item name="mode" label="模式">
          <Radio.Group optionType="button" buttonStyle="solid" options={[{ value: "auto", label: "自动" }, { value: "manual", label: "手动" }]} />
        </Form.Item>
        {mode === "manual" ? (
          <>
            <Form.Item name="chosen" label="指定成员" rules={[{ required: true, message: "手动模式要指定一个成员" }]}>
              <Select
                options={exits.filter((n) => members.includes(n.id)).map(exitOption)}
                placeholder={members.length ? "从成员里选一个" : "先选择成员"}
                aria-label="指定成员"
              />
            </Form.Item>
            <Form.Item name="on_failure" label="指定成员不可用时">
              <Radio.Group>
                <Space direction="vertical">
                  {(["hold", "fallback"] as const).map((k) => (
                    <Radio key={k} value={k}>
                      {ON_FAILURE[k].title} <Typography.Text type="secondary">— {ON_FAILURE[k].desc}</Typography.Text>
                    </Radio>
                  ))}
                </Space>
              </Radio.Group>
            </Form.Item>
          </>
        ) : null}
        <Form.Item name="notes" label="备注">
          <Input.TextArea rows={2} />
        </Form.Item>
      </Form>
    </Drawer>
  );
}

// ---------------------------------------------------- exit kinds ---

/** What an external SOCKS exit carries and how, stated wherever one is configured. */
export const EXTERNAL_LIMITS: string[] = [
  "只承载 IPv4 上的 TCP。",
  "UDP（包括 QUIC / HTTP/3）在承载节点上直接拒绝，绝不改从别的出口发出。",
  "路由到它的域名在承载节点上由一个专用解析组解析：上游查询经这个 SOCKS 代理以 TCP 发往 1.1.1.1 / 8.8.8.8；没有回退，代理不给应答时这个域名就解析失败。",
  "不返回 AAAA（这些域名没有 IPv6 地址）。",
  "健康检测：每 10 秒经代理发一次 DNS over TCP 查询。",
  "面板从不登录那台代理设备，也不为它生成安装包；它所在的隧道和接口也不归面板管理。",
];

/** The limitations block of external SOCKS exits. */
export function ExternalLimits({ style }: { style?: React.CSSProperties }) {
  return (
    <Alert
      type="warning"
      showIcon
      style={{ marginBottom: 12, ...style }}
      data-testid="external-limits"
      message="外部 SOCKS 出口的限制"
      description={
        <>
          <ul style={{ margin: 0, paddingInlineStart: 18 }}>
            {EXTERNAL_LIMITS.map((t) => (
              <li key={t}>{t}</li>
            ))}
          </ul>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            以上是面板生成的配置的设计行为，尚未在真实设备上验证。
          </Typography.Text>
        </>
      }
    />
  );
}

/** Badges of a nested exit (经 <relay> 中继), an external SOCKS exit and a dynamic DNS endpoint. */
export function ExitKindTags({ node, name }: { node: Node; name: (id: string) => string }) {
  return (
    <>
      {isNestedExit(node) ? (
        <Tooltip title="这个出口的唯一隧道连到中继出口，再由中继出口经枢纽到达；它不直接连枢纽。">
          <Tag color="purple" data-testid={`nested-tag-${node.id}`}>
            经 {name(node.via_exit!)} 中继
          </Tag>
        </Tooltip>
      ) : null}
      {isExternalExit(node) ? (
        <Tooltip title={`承载出口 ${name(node.external!.carrier)} 上经 SOCKS5 代理出去；只承载 IPv4 上的 TCP，UDP 被拒绝。`}>
          <Tag color="orange" data-testid={`external-tag-${node.id}`}>
            外部 SOCKS · 仅 TCP · 仅 IPv4
          </Tag>
        </Tooltip>
      ) : null}
      {node.role === "exit" && node.endpoint_host ? (
        <Tooltip title={`动态域名端点 ${node.endpoint_host}：拨它的节点按域名解析，握手超过 150 秒未更新时重新解析。`}>
          <Tag>动态域名</Tag>
        </Tooltip>
      ) : null}
    </>
  );
}

/** Which order a change to a nested or external exit must be provisioned in. */
export function DeployOrder({ node, name }: { node: Pick<Node, "via_exit" | "external">; name: (id: string) => string }) {
  if (node.external?.carrier) {
    return (
      <Alert
        type="info"
        showIcon
        style={{ marginBottom: 12 }}
        data-testid="deploy-order"
        message="部署顺序"
        description={`安装或修改这个外部 SOCKS 出口：先在「部署」页重新下发承载出口 ${name(node.external.carrier)}，再下发两个枢纽（主、备；只有一个枢纽时就是它），最后安装网关。外部出口本身不装机。这个顺序未在真实设备上验证。`}
      />
    );
  }
  if (node.via_exit) {
    return (
      <Alert
        type="info"
        showIcon
        style={{ marginBottom: 12 }}
        data-testid="deploy-order"
        message="部署顺序"
        description={`安装或修改这个嵌套出口：先在「部署」页重新下发中继出口 ${name(node.via_exit)}，再下发这个出口，然后两个枢纽（主、备；只有一个枢纽时就是它），最后安装网关。这个顺序未在真实设备上验证。`}
      />
    );
  }
  return null;
}

/** Managed exits that may carry an external exit or relay a nested one: neither nested nor external. */
function plainManagedExits(t: Topology): Node[] {
  return t.nodes.filter((n) => n.role === "exit" && n.managed && !isNestedExit(n) && !isExternalExit(n));
}

const NODE_ID_RE = /^[a-z0-9][a-z0-9-]{0,40}$/;
const IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const HOST_RE = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/;

/** The direct_wg links from an exit to its relay exit (enabled, not standby). */
function relayLinks(t: Topology, from: string, to: string): TLink[] {
  return t.links.filter((l) => l.from === from && l.to === to && l.transport === "direct_wg" && l.enabled && !l.standby);
}

function newLinkId(t: Topology, from: string, to: string): string {
  let id = `${from}-${to}`;
  for (let i = 2; t.links.some((l) => l.id === id); i++) id = `${from}-${to}-${i}`;
  return id;
}

interface ExternalValues {
  id?: string;
  name: string;
  region?: string;
  residential: boolean;
  carrier?: string;
  socks_address?: string;
  socks_port?: number;
  interface?: string;
  credential_id?: string;
}

/** The topology with this external exit written in (shape the backend validates: managed:false, IPv4 TCP only). */
export function withExternalExit(t: Topology, v: ExternalValues, existing: Node | null): Topology {
  const id = existing ? existing.id : (v.id ?? "").trim();
  const base: Node = existing ? { ...existing } : ({ id, x: 80 + (t.nodes.length % 6) * 40, y: 80 + (t.nodes.length % 6) * 30 } as Node);
  for (const k of [
    "server_id",
    "ssh_host",
    "ssh_port",
    "ssh_user",
    "endpoint_v4",
    "endpoint_v6",
    "endpoint_host",
    "listen_port",
    "public_key",
    "private_key",
    "via_exit",
    "v6_workaround",
    "dualstack_relay",
    "wss_listen_port",
    "pool",
    "pool_priority",
  ] as const)
    delete base[k];
  const node: Node = {
    ...base,
    id,
    name: v.name.trim(),
    role: "exit",
    managed: false,
    path_v4: true,
    path_v6: false,
    egress_v4: true,
    egress_v6: false,
    nat_dial_out: false,
    residential: !!v.residential,
    ix_bound: false,
    external: {
      carrier: v.carrier ?? "",
      socks_address: (v.socks_address ?? "").trim(),
      socks_port: v.socks_port ?? 0,
      interface: (v.interface ?? "").trim(),
      credential_id: v.credential_id ?? "",
    },
  };
  const region = (v.region ?? "").trim().toLowerCase();
  if (region) node.region = region;
  else delete node.region;
  return { ...t, nodes: existing ? t.nodes.map((n) => (n.id === existing.id ? node : n)) : [...t.nodes, node] };
}

interface ManagedValues {
  endpoint_host?: string;
  via_exit?: string;
  add_link: boolean;
}

/** The topology with this managed exit's endpoint_host / via_exit (and optionally the relay link) written in. */
export function withManagedExit(t: Topology, node: Node, v: ManagedValues): Topology {
  const next: Node = { ...node };
  const host = (v.endpoint_host ?? "").trim().toLowerCase();
  if (host) next.endpoint_host = host;
  else delete next.endpoint_host;
  if (v.via_exit) next.via_exit = v.via_exit;
  else delete next.via_exit;
  let links = t.links;
  if (v.via_exit && v.add_link && relayLinks(t, node.id, v.via_exit).length === 0) {
    links = [
      ...links,
      { id: newLinkId(t, node.id, v.via_exit), from: node.id, to: v.via_exit, transport: "direct_wg", enabled: true, standby: false, mtu: 1420, keepalive: 25 },
    ];
  }
  return { ...t, nodes: t.nodes.map((n) => (n.id === node.id ? next : n)), links };
}

function ExitDrawer({
  open,
  mode,
  topo,
  socks,
  socksError,
  blocked,
  onClose,
  onSave,
}: {
  open: boolean;
  /** external: create (node null) or edit an external SOCKS exit; managed: endpoint_host and via_exit of a managed exit. */
  mode: { kind: "external"; node: Node | null } | { kind: "managed"; node: Node };
  topo: Topology;
  socks: SOCKSCredentialView[] | undefined;
  socksError: ApiError | null;
  /** Why saving is not possible now (unsaved topology edits elsewhere). */
  blocked?: string;
  onClose: () => void;
  onSave: (next: Topology, what: string) => Promise<ApiError | null>;
}) {
  const [form] = Form.useForm();
  const [error, setError] = useState<ApiError | null>(null);
  const [saving, setSaving] = useState(false);
  const node = mode.node;
  const external = mode.kind === "external";
  const name = (id: string) => topo.nodes.find((n) => n.id === id)?.name || id;
  const regions = useMemo(() => REGION_CODES.map((c) => ({ value: c, label: regionLabel(c) })), []);

  const watchedCarrier = Form.useWatch("carrier", form) as string | undefined;
  const [via, setVia] = useState<string | undefined>(mode.kind === "managed" ? mode.node.via_exit : undefined);

  const carriers = plainManagedExits(topo);
  const relayCandidates = mode.kind === "managed" ? plainManagedExits(topo).filter((n) => n.id !== mode.node.id) : [];
  const nestedBehind = mode.kind === "managed" ? topo.nodes.filter((n) => n.via_exit === mode.node.id) : [];
  const carriedBy = node ? topo.nodes.filter((n) => n.external?.carrier === node.id) : [];

  const initial =
    mode.kind === "external"
      ? {
          name: node?.name ?? "",
          region: node?.region,
          residential: !!node?.residential,
          carrier: node?.external?.carrier,
          socks_address: node?.external?.socks_address,
          socks_port: node?.external?.socks_port || 1080,
          interface: node?.external?.interface,
          credential_id: node?.external?.credential_id || undefined,
        }
      : { endpoint_host: mode.node.endpoint_host ?? "", via_exit: mode.node.via_exit, add_link: true };

  async function save() {
    let v: Record<string, unknown>;
    try {
      v = await form.validateFields();
    } catch {
      return;
    }
    let next: Topology;
    let what: string;
    if (mode.kind === "external") {
      const ev = v as unknown as ExternalValues;
      next = withExternalExit(topo, ev, mode.node);
      what = mode.node ? `外部 SOCKS 出口 ${ev.name} 已保存` : `外部 SOCKS 出口 ${ev.name} 已添加`;
    } else {
      next = withManagedExit(topo, mode.node, v as unknown as ManagedValues);
      what = `出口 ${mode.node.name || mode.node.id} 已保存`;
    }
    setSaving(true);
    const err = await onSave(next, what);
    setSaving(false);
    setError(err);
    if (err?.field) {
      const map: Record<string, string> = { endpoint_host: "endpoint_host", via_exit: "via_exit" };
      if (map[err.field]) form.setFields([{ name: map[err.field], errors: [err.message] }]);
    }
  }

  const relayLinkCount = mode.kind === "managed" && via ? relayLinks(topo, mode.node.id, via).length : 0;
  const relay = via ? topo.nodes.find((n) => n.id === via) : undefined;

  return (
    <Drawer
      title={external ? (node ? `外部 SOCKS 出口「${node.name || node.id}」` : "添加外部 SOCKS 出口") : `出口「${node?.name || node?.id}」的到达方式`}
      open={open}
      onClose={onClose}
      width={600}
      destroyOnHidden
      footer={
        <Space>
          <Button onClick={onClose}>取消</Button>
          <Button type="primary" loading={saving} disabled={!!blocked} onClick={() => void save()}>
            保存到拓扑
          </Button>
        </Space>
      }
    >
      {blocked ? <Alert type="warning" showIcon style={{ marginBottom: 12 }} message={blocked} /> : null}
      {error ? <ApiErrorAlert error={error} onClose={() => setError(null)} /> : null}
      {error?.issues && error.issues.length > 0 ? <IssueList issues={error.issues} /> : null}
      {external ? (
        <>
          <Typography.Paragraph type="secondary">
            外部 SOCKS 出口是一台已有的 SOCKS5 代理：承载出口（一台受管出口）经一条面板不管理的隧道到达它，把发往这个出口的流量转给代理。它没有服务器、没有链路，面板不为它装机。
          </Typography.Paragraph>
          <ExternalLimits />
        </>
      ) : null}
      <Form form={form} layout="vertical" initialValues={initial} requiredMark="optional" autoComplete="off">
        {external ? (
          <>
            {!node ? (
              <Form.Item
                name="id"
                label="ID"
                extra="小写字母、数字和短横线；规则和地区组用它引用这个出口，创建后不能改。"
                rules={[
                  { required: true, message: "请填写 ID" },
                  { pattern: NODE_ID_RE, message: "ID 只能是小写字母、数字和短横线" },
                  { validator: (_, val: string) => (val && topo.nodes.some((n) => n.id === val.trim()) ? Promise.reject(new Error("已有这个 ID 的节点")) : Promise.resolve()) },
                ]}
              >
                <Input className="mono" placeholder="例如 my-socks" aria-label="ID" />
              </Form.Item>
            ) : null}
            <Form.Item name="name" label="显示名称" rules={[{ required: true, message: "请填写名称" }]}>
              <Input placeholder="例如 马来西亚住宅" aria-label="显示名称" />
            </Form.Item>
            <Form.Item name="region" label="国家或地区" extra="出口页按它分区；解锁探测用它确认实际出口地区。">
              <AutoComplete options={regions} placeholder="例如 my" aria-label="国家或地区" filterOption={(i, o) => !!o && (o.value + o.label).toLowerCase().includes(i.toLowerCase())} />
            </Form.Item>
            <Form.Item name="residential" valuePropName="checked" extra="代理的出口是家宽时勾选；要求住宅的地区组和规则才能用它。">
              <Checkbox>住宅（家宽）</Checkbox>
            </Form.Item>
            <Form.Item
              name="carrier"
              label="承载出口"
              rules={[{ required: true, message: "请选择承载出口" }]}
              extra="一台受管出口（不能是嵌套出口或外部出口）。它经下面的接口到达代理，装机时写入转发配置。"
            >
              <Select
                aria-label="承载出口"
                placeholder={carriers.length ? "选择受管出口" : "还没有可用的受管出口"}
                options={carriers.map((n) => ({ value: n.id, label: `${n.name || n.id}（${n.id}）${n.region ? ` · ${regionLabel(n.region)}` : ""}` }))}
              />
            </Form.Item>
            <Space.Compact block>
              <Form.Item
                name="socks_address"
                label="SOCKS 地址（IPv4）"
                style={{ flex: 2 }}
                rules={[
                  { required: true, message: "请填写代理的 IPv4 地址" },
                  { pattern: IPV4_RE, message: "必须是 IPv4 地址" },
                ]}
                extra="从承载出口看到的代理地址，通常是那条隧道上的地址。"
              >
                <Input className="mono" placeholder="例如 192.0.2.10" aria-label="SOCKS 地址" />
              </Form.Item>
              <Form.Item name="socks_port" label="端口" style={{ flex: 1 }} rules={[{ required: true, message: "请填写端口" }]}>
                <InputNumber min={1} max={65535} style={{ width: "100%" }} aria-label="SOCKS 端口" />
              </Form.Item>
            </Space.Compact>
            <Form.Item
              name="interface"
              label="承载出口上的接口"
              rules={[
                { required: true, message: "请填写接口名" },
                { pattern: /^[A-Za-z0-9_.-]{1,15}$/, message: "接口名最多 15 个字符：字母、数字、_ . -" },
              ]}
              extra={`承载出口${watchedCarrier ? ` ${name(watchedCarrier)} ` : ""}上那条面板不管理的隧道接口（例如 wg9）。代理只经这个接口访问；接口不在时直接失败，不会改走默认路由。`}
            >
              <Input className="mono" placeholder="例如 wg9" aria-label="承载出口上的接口" />
            </Form.Item>
            <Form.Item
              name="credential_id"
              label="SOCKS 凭据"
              rules={[{ required: true, message: "请选择 SOCKS 凭据" }]}
              extra={
                <span>
                  代理的用户名和密码保存在 <Link to={href("keys") + "?section=socks&socks=new"}>密钥页的「SOCKS 凭据」</Link> 里（只写不读）；拓扑里只记它的 ID。还没有就先去新建一个。
                </span>
              }
            >
              <Select
                aria-label="SOCKS 凭据"
                loading={!socks && !socksError}
                placeholder={socks && socks.length === 0 ? "还没有 SOCKS 凭据，先到密钥页新建" : "选择凭据"}
                options={(socks ?? []).map((c) => ({ value: c.id, label: `${c.name}（${c.id}）${c.secret_set ? "" : " · 未设置"}` }))}
              />
            </Form.Item>
            {socksError ? <ApiErrorAlert error={socksError} /> : null}
            <DeployOrder node={{ external: { carrier: watchedCarrier ?? node?.external?.carrier ?? "", socks_address: "", socks_port: 0, interface: "", credential_id: "" } }} name={name} />
            {node ? (
              <Typography.Paragraph type="secondary" style={{ fontSize: 12 }}>
                要删除这个出口，在 <Link to={href("topology", node.id)}>拓扑</Link> 页删除节点。
              </Typography.Paragraph>
            ) : null}
          </>
        ) : (
          <>
            <Form.Item
              name="endpoint_host"
              label="动态域名端点"
              rules={[{ validator: (_, val: string) => (!val || HOST_RE.test(val.trim().toLowerCase()) ? Promise.resolve() : Promise.reject(new Error("不是合法的域名（小写字母、数字、短横线，至少两段，不带结尾的点）"))) }]}
              extra="公网地址会变的出口（例如家宽）填一个 DDNS 域名：拨它的枢纽和嵌套出口用这个域名代替公网 IPv4，并在 WireGuard 握手超过 150 秒没有更新时重新解析。网关和中继从不拨出口，用不到它。未在真实设备上验证。"
            >
              <Input className="mono" placeholder="例如 exit.example.net" aria-label="动态域名端点" />
            </Form.Item>
            <Form.Item
              name="via_exit"
              label="经中继出口到达"
              extra="留空：这个出口照常直接连枢纽。选一个中继出口：这个出口不再直接连枢纽，而是拨到中继出口，由中继出口经枢纽到达它（只能嵌套一层）。"
            >
              <Select
                allowClear
                aria-label="经中继出口到达"
                placeholder="不经中继（直接连枢纽）"
                disabled={nestedBehind.length > 0 || carriedBy.length > 0}
                onChange={(v?: string) => setVia(v || undefined)}
                options={relayCandidates.map((n) => ({
                  value: n.id,
                  label: `${n.name || n.id}（${n.id}）${n.endpoint_v4 || n.endpoint_host ? "" : " · 缺少端点"}`,
                }))}
              />
            </Form.Item>
            {nestedBehind.length > 0 ? (
              <Typography.Paragraph type="secondary" style={{ fontSize: 12 }}>
                {nestedBehind.map((n) => n.name || n.id).join("、")} 经这个出口中继，所以它自己不能再经别的出口到达（只能嵌套一层）。
              </Typography.Paragraph>
            ) : null}
            {carriedBy.length > 0 ? (
              <Typography.Paragraph type="secondary" style={{ fontSize: 12 }}>
                它是外部 SOCKS 出口 {carriedBy.map((n) => n.name || n.id).join("、")} 的承载出口，承载出口不能是嵌套出口。
              </Typography.Paragraph>
            ) : null}
            {via ? (
              <Alert
                type={mode.node.nat_dial_out && mode.node.path_v4 && relayLinkCount === 1 && relay && (relay.endpoint_v4 || relay.endpoint_host) ? "info" : "warning"}
                showIcon
                style={{ marginBottom: 12 }}
                data-testid="via-exit-requirements"
                message="嵌套出口的条件（保存时由后端校验）"
                description={
                  <ul style={{ margin: 0, paddingInlineStart: 18 }}>
                    <li>
                      这个出口必须是 NAT 拨出：{mode.node.nat_dial_out ? "已满足" : "未满足，请在拓扑页打开「NAT 拨出」"}
                    </li>
                    <li>必须承载 IPv4 路径：{mode.node.path_v4 ? "已满足" : "未满足"}</li>
                    <li>
                      必须恰好有一条从这个出口到 {name(via)} 的直连 WG 链路（启用、非待命）：现在有 {relayLinkCount} 条
                    </li>
                    <li>
                      中继出口 {name(via)} 需要公网 IPv4 或动态域名端点：{relay && (relay.endpoint_v4 || relay.endpoint_host) ? "已满足" : "未满足"}
                    </li>
                    <li>中继出口照常留在它的地区组里，承载它自己的流量。</li>
                  </ul>
                }
              />
            ) : null}
            {via && relayLinkCount === 0 ? (
              <Form.Item name="add_link" valuePropName="checked">
                <Checkbox>
                  保存时补上一条直连 WG 链路 {mode.node.id} → {via}
                </Checkbox>
              </Form.Item>
            ) : null}
            {via ? <DeployOrder node={{ via_exit: via }} name={name} /> : null}
          </>
        )}
      </Form>
    </Drawer>
  );
}

/** Every exit with its kind, reachability and the drawer to change it. */
function ExitNodes({
  topo,
  socks,
  onEdit,
  onAddExternal,
}: {
  topo: Topology;
  socks: SOCKSCredentialView[] | undefined;
  onEdit: (n: Node) => void;
  onAddExternal: () => void;
}) {
  const exits = topo.nodes.filter((n) => n.role === "exit");
  const name = (id: string) => topo.nodes.find((n) => n.id === id)?.name || id;
  const hasExternal = exits.some(isExternalExit);
  return (
    <Section
      title="出口节点"
      id="exit-nodes"
      extra={
        <Button icon={<PlusOutlined />} onClick={onAddExternal}>
          添加外部 SOCKS 出口
        </Button>
      }
    >
      <Typography.Paragraph type="secondary">
        受管出口可以填动态域名端点，或者经另一台中继出口到达（嵌套出口）；外部 SOCKS 出口经一台受管的承载出口转给已有的 SOCKS5 代理。保存直接写入拓扑，安装后生效；这些方式都还没有在真实设备上验证。
      </Typography.Paragraph>
      {hasExternal ? <ExternalLimits /> : null}
      {exits.length === 0 ? (
        <Typography.Paragraph type="secondary">拓扑里还没有出口。</Typography.Paragraph>
      ) : (
        <div className="ungrouped" data-testid="exit-nodes">
          {exits.map((n) => {
            const cred = n.external ? socks?.find((c) => c.id === n.external!.credential_id) : undefined;
            return (
              <div key={n.id} className="ungrouped-item" data-testid={`exit-node-${n.id}`}>
                <div>
                  <Space size={[4, 2]} wrap>
                    <Link to={href("topology", n.id)}>{n.name || n.id}</Link>
                    <Typography.Text type="secondary" className="mono-small">
                      {n.id} · {regionLabel(n.region)}
                    </Typography.Text>
                    <ExitKindTags node={n} name={name} />
                    {n.residential ? <Tag color="green">住宅（家宽）</Tag> : null}
                  </Space>
                  {n.external ? (
                    <Typography.Paragraph type="secondary" style={{ margin: "2px 0 0", fontSize: 12 }}>
                      承载 {name(n.external.carrier)} · 接口 <Mono>{n.external.interface}</Mono> · 代理 <Mono>{`${n.external.socks_address}:${n.external.socks_port}`}</Mono> · 凭据{" "}
                      {cred ? cred.name : n.external.credential_id || "—"}
                    </Typography.Paragraph>
                  ) : n.endpoint_host ? (
                    <Typography.Paragraph type="secondary" style={{ margin: "2px 0 0", fontSize: 12 }}>
                      动态域名端点 <Mono>{n.endpoint_host}</Mono>
                    </Typography.Paragraph>
                  ) : null}
                </div>
                {n.managed || n.external ? (
                  <Button size="small" icon={<EditOutlined />} onClick={() => onEdit(n)} aria-label={`设置出口 ${n.name || n.id}`}>
                    设置
                  </Button>
                ) : null}
              </div>
            );
          })}
        </div>
      )}
    </Section>
  );
}

// ------------------------------------------------------------------ page ---

/** The hub state the actual lines were judged from: the carrying hub (single: the hub). */
function carrierState(d: RegionGroupsView): GroupHubState | undefined {
  if (d.carrying?.mode !== "dual") return d.hub_state;
  return d.hub_states?.find((h) => h.carrying);
}

export default function ExitsPage() {
  const groups = useApi(() => api.listGroups(), []);
  const doc = useTopologyDoc();
  const { markApplyRequired } = useStatus();
  const { route } = useRouter();
  const { message } = AntApp.useApp();
  const [editing, setEditing] = useState<RegionGroupView | null | "new">(null);
  const [changed, setChanged] = useState(false);
  const act = useAction();
  const hubAct = useAction();
  const focus = route.params[0];
  const refreshing = hubAct.busy === "hub";
  const refreshHub = () =>
    void hubAct.run(
      async () => {
        const d: RegionGroupsView = await api.refreshGroupRuntime();
        groups.setData(d);
      },
      "hub",
      // The hub changed while the read ran: the result was discarded;
      // show the current hub's state (unknown until read again).
      (e) => {
        if (e.code === "hub_identity_changed") void groups.reload();
      },
    );
  // One automatic read per visit, bounded: only when the hub can be read
  // and nothing recent is stored. No polling.
  const autoRead = useRef(false);
  useEffect(() => {
    const d = groups.data;
    const hubs = d?.carrying?.mode === "dual" && d.hub_states?.length ? d.hub_states : d?.hub_state ? [d.hub_state] : [];
    if (hubs.length === 0 || autoRead.current) return;
    autoRead.current = true;
    if (hubs.some((h) => h.refreshing)) return;
    // A read of another hub identity says nothing about this one.
    const last = (h: GroupHubState) => (h.last_read && h.last_read.current_hub !== false ? Date.parse(h.last_read.read_at) : 0);
    if (!hubs.some((h) => h.readable && Date.now() - last(h) >= AUTO_REFRESH_AFTER_MS)) return;
    refreshHub();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [groups.data]);

  const dual = groups.data?.carrying?.mode === "dual" && (groups.data.hub_states?.length ?? 0) > 0;
  const exits = useMemo(() => (doc.topo?.nodes ?? []).filter((n) => n.role === "exit"), [doc.topo]);
  const names = useMemo(() => new Map((doc.topo?.nodes ?? []).map((n) => [n.id, n.name || n.id])), [doc.topo]);
  const nodeMap = useMemo(() => new Map((doc.topo?.nodes ?? []).map((n) => [n.id, n])), [doc.topo]);
  const socks = useApi(() => api.listSocksCredentials(), []);
  const [exitEdit, setExitEdit] = useState<{ kind: "external"; node: Node | null } | { kind: "managed"; node: Node } | null>(null);
  const [savedIssues, setSavedIssues] = useState<Issue[]>([]);

  /**
   * Writes a node change into the stored topology with one PUT (the same
   * request the topology editor's save sends). Refused while the shared
   * working copy has other unsaved edits, so they are never saved by accident.
   */
  const saveExit = async (next: Topology, what: string, id: string): Promise<ApiError | null> => {
    try {
      const res = await api.putTopology(next, !!next.settings.draft);
      doc.applyServerChange(() => res.topology);
      markApplyRequired();
      setChanged(true);
      setSavedIssues((res.issues ?? []).filter((i) => i.node_id === id || i.exit_id === id));
      setExitEdit(null);
      message.success(`${what}；按部署顺序重新下发后生效`);
      void groups.reload();
      void socks.reload();
      return null;
    } catch (e) {
      return e instanceof api.ApiError ? e : new api.ApiError(0, {});
    }
  };

  const afterChange = (fn: (t: Topology) => Topology, what: string) => {
    doc.applyServerChange(fn);
    markApplyRequired();
    setChanged(true);
    message.success(`${what}；安装后在网关生效`);
    void groups.reload();
  };
  const putGroup = (g: RegionGroupView) => (t: Topology): Topology => {
    const list = t.region_groups ?? [];
    const plain = stripView(g);
    const has = list.some((x) => x.id === g.id);
    return {
      ...t,
      region_groups: has ? list.map((x) => (x.id === g.id ? plain : x)) : [...list, plain],
      settings: g.is_default ? { ...t.settings, default_group: g.id } : t.settings,
    };
  };

  const byRegion = useMemo(() => {
    const m = new Map<string, RegionGroupView[]>();
    for (const g of groups.data?.groups ?? []) {
      const k = (g.region ?? "").toLowerCase();
      m.set(k, [...(m.get(k) ?? []), g]);
    }
    return [...m.entries()].sort(([a], [b]) => (a === "" ? 1 : b === "" ? -1 : a.localeCompare(b)));
  }, [groups.data]);

  const ungrouped = useMemo(() => {
    const inGroup = new Set((groups.data?.groups ?? []).flatMap((g) => g.members));
    return exits.filter((n) => !inGroup.has(n.id));
  }, [groups.data, exits]);

  return (
    <Page
      title="出口"
      description="出口按国家或地区分组。每个组可以自动按顺序切换，也可以手动指定成员；规则指向组，切换行为只在这里设置。"
      extra={
        <Button type="primary" icon={<PlusOutlined />} onClick={() => setEditing("new")}>
          新建地区组
        </Button>
      }
    >
      {changed ? <ApplyRequiredNotice what="地区组已修改" /> : null}
      <ApiErrorAlert error={act.error} onClose={act.clear} />
      <ApiErrorAlert error={hubAct.error} onClose={hubAct.clear} />
      {dual && groups.data?.carrying ? (
        <DualHubStateBar hubs={groups.data.hub_states ?? []} carrying={groups.data.carrying} onRefresh={refreshHub} refreshing={refreshing} />
      ) : (
        <HubStateBar hub={groups.data?.hub_state} onRefresh={refreshHub} refreshing={refreshing} />
      )}
      {groups.data?.carrying?.sharing ? (
        <Section title="国内中继分担（网关测量与决定）">
          <RelaySharingView s={groups.data.carrying.sharing} />
        </Section>
      ) : null}
      <DataView
        state={groups}
        rows={8}
        isEmpty={(d) => d.groups.length === 0}
        empty={
          <EmptyState
            title="还没有地区组"
            description="把出口按国家或地区分组（例如香港、美国），规则再指向组。"
            action={
              <Button type="primary" icon={<PlusOutlined />} onClick={() => setEditing("new")}>
                新建地区组
              </Button>
            }
          />
        }
      >
        {(d) => (
          <>
            {byRegion.map(([region, list]) => (
              <Section key={region || "none"} title={regionLabel(region)} id={`region-${region || "none"}`}>
                <div className="group-grid">
                  {list.map((g) => (
                    <GroupCard
                      key={g.id}
                      g={g}
                      allGroups={d.groups}
                      names={names}
                      nodes={nodeMap}
                      thresholds={d.thresholds}
                      hub={carrierState(d)}
                      dual={dual}
                      onRefresh={refreshHub}
                      refreshing={refreshing}
                      highlighted={focus === g.id}
                      onEdit={() => setEditing(g)}
                      onChanged={(ng, what) => afterChange(putGroup(ng), what)}
                      onDeleted={(id) =>
                        afterChange((t) => ({ ...t, region_groups: (t.region_groups ?? []).filter((x) => x.id !== id) }), "地区组已删除")
                      }
                    />
                  ))}
                </div>
              </Section>
            ))}
          </>
        )}
      </DataView>
      {doc.topo ? (
        <ExitNodes
          topo={doc.topo}
          socks={socks.data?.credentials}
          onEdit={(n) => setExitEdit(n.external ? { kind: "external", node: n } : { kind: "managed", node: n })}
          onAddExternal={() => setExitEdit({ kind: "external", node: null })}
        />
      ) : null}
      {savedIssues.length > 0 ? (
        <div data-testid="exit-saved-issues">
          <IssueList issues={savedIssues} />
        </div>
      ) : null}
      {ungrouped.length > 0 && groups.data ? (
        <Section title="不在任何组里的出口" extra={<Typography.Text type="secondary">规则不能经组用到它们；可以被规则直接固定</Typography.Text>}>
          <div className="ungrouped" data-testid="ungrouped">
            {ungrouped.map((n) => (
              <div key={n.id} className="ungrouped-item">
                <Space size={[4, 2]} wrap>
                  <Link to={href("topology", n.id)}>{n.name || n.id}</Link>
                  <Typography.Text type="secondary" className="mono-small">
                    {regionLabel(n.region)}
                  </Typography.Text>
                  <MemberAttrs m={n} />
                  <ExitKindTags node={n} name={(id) => names.get(id) ?? id} />
                </Space>
                <Dropdown
                  trigger={["click"]}
                  menu={{
                    items: (groups.data?.groups ?? []).map((g) => ({ key: g.id, label: groupLabel(g, groups.data?.groups) })),
                    onClick: ({ key }) => {
                      const g = groups.data!.groups.find((x) => x.id === key)!;
                      void act.run(async () => {
                        const r = await api.updateGroup(g.id, { members: [...g.members, n.id] });
                        afterChange(putGroup(r.group), `${n.name} 已加入 ${groupLabel(g, groups.data?.groups)}`);
                      }, `join:${n.id}`);
                    },
                  }}
                >
                  <Button size="small" loading={act.busy === `join:${n.id}`}>
                    加入组…
                  </Button>
                </Dropdown>
              </div>
            ))}
          </div>
        </Section>
      ) : null}
      {exitEdit && doc.topo ? (
        <ExitDrawer
          open
          mode={exitEdit}
          topo={doc.topo}
          socks={socks.data?.credentials}
          socksError={socks.error}
          blocked={doc.dirty ? "拓扑有未保存的修改（拓扑、规则或泄漏页）：先在那里保存或放弃，再在这里保存，免得把它们一起写进去。" : undefined}
          onClose={() => setExitEdit(null)}
          onSave={(next, what) => saveExit(next, what, exitEdit.node?.id ?? next.nodes[next.nodes.length - 1]?.id ?? "")}
        />
      ) : null}
      <GroupDrawer
        open={editing !== null}
        group={editing === "new" ? null : editing}
        exits={exits}
        others={groups.data?.groups}
        onClose={() => setEditing(null)}
        onSaved={(g, created) => {
          setEditing(null);
          afterChange(putGroup(g), created ? `地区组 ${g.name} 已创建` : `地区组 ${g.name} 已保存`);
        }}
      />
    </Page>
  );
}
