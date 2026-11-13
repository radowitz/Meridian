// 出口: region groups are the main view of exits. A region (香港, 美国 …)
// holds one or more groups; each group has an ordered member list, a mode
// (自动 / 手动) and two live lines kept apart: 实际使用, only from the hub's
// own report (actual.state "ok", read over SSH with a fixed command), and
// 面板推算, the panel's computation from health samples, never shown as the
// member in use.
// Every change edits the stored topology only (apply_required): the top bar
// and an inline notice say so until it is installed.

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
import type {
  GroupActualView,
  GroupHubState,
  GroupMemberView,
  GroupThresholds,
  Node,
  RegionGroup,
  RegionGroupInput,
  RegionGroupView,
  RegionGroupsView,
  Topology,
} from "./types";
import {
  type StatusKind,
  ApiErrorAlert,
  ApplyRequiredNotice,
  DataView,
  EmptyState,
  Link,
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
};

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
  onRefresh,
  refreshing,
  allGroups,
}: {
  g: RegionGroupView;
  /** Every group: decides whether this one's name needs region + ID to be unambiguous. */
  allGroups: readonly RegionGroupView[];
  names: Map<string, string>;
  thresholds: GroupThresholds | undefined;
  hub?: GroupHubState;
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

// ------------------------------------------------------------- hub bar ---

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

// ------------------------------------------------------------------ page ---

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
    const h = groups.data?.hub_state;
    if (!h || autoRead.current) return;
    autoRead.current = true;
    if (!h.readable || h.refreshing) return;
    // A read of another hub identity says nothing about this one.
    const last = h.last_read && h.last_read.current_hub !== false ? Date.parse(h.last_read.read_at) : 0;
    if (Date.now() - last < AUTO_REFRESH_AFTER_MS) return;
    refreshHub();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [groups.data]);

  const exits = useMemo(() => (doc.topo?.nodes ?? []).filter((n) => n.role === "exit"), [doc.topo]);
  const names = useMemo(() => new Map((doc.topo?.nodes ?? []).map((n) => [n.id, n.name || n.id])), [doc.topo]);

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
      <HubStateBar hub={groups.data?.hub_state} onRefresh={refreshHub} refreshing={refreshing} />
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
                      thresholds={d.thresholds}
                      hub={d.hub_state}
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
