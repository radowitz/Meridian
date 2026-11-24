// 概览, one screen: a status line (gateway version, carrying path, leak
// check), the real-time throughput chart, then four compact cards — exits,
// domestic relays, tunnels (only abnormal ones), remote access. Every fact
// is real data or an explicit unknown; unknown never reads as normal.

import { Typography } from "antd";
import type { ReactNode } from "react";
import type { Carrying, LinkLogAnswer, RegionGroupView, RegionGroupsView, Sharing, SharingRelay } from "./types";
import { ExitLatencyValue, useExitLatency } from "./ExitLatency";
import { useHubAutoRead } from "./hub_read";
import { inactiveObjects, isCurrent } from "./link_scope";
import * as api from "./api";
import { ACTUAL_CODE, CarryingLine, actualTag } from "./status_words";
import { RELAY_STATUS, SpeedLine } from "./RelaySharing";
import { LeakStatusLine } from "./leak_status";
import TrafficChart from "./TrafficChart";
import { href, useStatus, useTopologyDoc, type InstallState } from "./state";
import {
  ApiErrorAlert,
  EllipsisText,
  Link,
  Page,
  Section,
  SplitStatus,
  StatusTag,
  Tile,
  EllipsisLink,
  errorTitle,
  groupLabel,
  joinReasons,
  useApi,
  type ApiState,
  PROBLEM,
} from "./ui";

/** Tile body for one API: skeleton text, error or the content. */
function TileData<T>({ state, children }: { state: ApiState<T>; children: (d: T) => ReactNode }) {
  if (state.data === undefined) {
    if (state.error) return <Typography.Text type="danger">{errorTitle(state.error)}</Typography.Text>;
    return <Typography.Text type="secondary">读取中…</Typography.Text>;
  }
  return <>{children(state.data)}</>;
}

type Done = boolean | null; // null: unknown (data unavailable)

/** The member in use only from the hub's report; otherwise unknown with the reason on hover. */
function GroupActualCell({ g, nodeName }: { g: RegionGroupView; nodeName: (id: string) => string }) {
  const a = g.actual;
  const model = g.model.observed ? `面板推算：${g.model.active ? nodeName(g.model.active) : "无可用成员"}` : `按配置应使用：${g.target ? nodeName(g.target) : "无目标"}（面板推算，无健康样本）`;
  if (a.state === "ok") {
    const who = a.active === "mmesh" ? "Mesh 备路" : a.active ? nodeName(a.active) : "无（黑洞）";
    return a.alert ? (
      <StatusTag kind="attention" title={`${who}：${a.alert_message ?? ""}`}>
        {who}
      </StatusTag>
    ) : (
      <span data-testid={`groups-tile-actual-${g.id}`} className="group-row-actual">
        <EllipsisText text={who} />
      </span>
    );
  }
  const t = actualTag(a);
  const label = a.state === "not_switchable" ? "枢纽不切换" : `实际未知 · ${t.label}`;
  return (
    <SplitStatus
      kind={t.kind}
      label={label}
      detail="hidden"
      testId={`groups-tile-status-${g.id}`}
      title={
        <span>
          {label}
          <br />
          {joinReasons([ACTUAL_CODE[a.code ?? ""] ?? a.code, a.message])}
          <br />
          {model}
        </span>
      }
    />
  );
}

function installText(i: InstallState): { kind: Parameters<typeof StatusTag>[0]["kind"]; label: string } {
  switch (i.kind) {
    case "in_sync":
      return { kind: "ok", label: `已同步 v${i.version}` };
    case "changed":
      return { kind: "attention", label: i.appliedOnly ? "已应用，未安装" : "有改动未安装" };
    case "not_installed":
      return { kind: "neutral", label: "未安装" };
    case "error":
      return { kind: "failed", label: "无法编译" };
    case "loading":
      return { kind: "neutral", label: "读取中" };
    default:
      return { kind: "unverified", label: "未知" };
  }
}

/** 当前路径: 主链路 or 备用枢纽 from the gateway's report; unknown says so. */
function PathFact({ c }: { c?: Carrying }) {
  if (!c) return <Typography.Text type="secondary">读取中</Typography.Text>;
  const s = c.sharing;
  if (s?.known && s.path) {
    return (
      <span data-testid="sharing-path">
        {s.path === "backup" ? <StatusTag kind="attention">备用枢纽 {s.backup?.name ?? s.backup_group?.name ?? ""}</StatusTag> : "主链路"}
      </span>
    );
  }
  if (c.mode === "dual") return <CarryingLine c={c} />;
  if (!c.known && c.source === "gateway") return <StatusTag kind="unverified">未知</StatusTag>;
  return <span data-testid="sharing-path">主链路</span>;
}

/** Every group fits next to the chart; more than this links to 出口. */
const EXIT_ROWS = 8;
const TUNNEL_ROWS = 4;

/** Groups that need attention first (alert, switch failed), the rest in their order. */
function attentionFirst(groups: RegionGroupView[]): RegionGroupView[] {
  const bad = (g: RegionGroupView) => (g.actual.state === "switch_failed" || (g.actual.state === "ok" && g.actual.alert) ? 0 : 1);
  return groups.map((g, i) => ({ g, i })).sort((a, b) => bad(a.g) - bad(b.g) || a.i - b.i).map((x) => x.g);
}

function RelayCard({ s }: { s: Sharing }) {
  if (!s.known) return <StatusTag kind="unverified">中继状态未知</StatusTag>;
  const row = (r: SharingRelay) => {
    const st = RELAY_STATUS[r.status] ?? RELAY_STATUS.unknown;
    return (
      <li key={r.id} data-testid={`ov-relay-${r.id}`}>
        <EllipsisText text={r.name} />
        <span>
          {PROBLEM.has(st.kind) ? <StatusTag kind={st.kind}>{st.label}</StatusTag> : null} <SpeedLine sp={r.speed} />
        </span>
      </li>
    );
  };
  if (s.backup_group) {
    // Two groups: the carrying one is marked; each lists its relays.
    return (
      <div data-testid="relay-sharing">
        {(["main", "backup"] as const).map((g) => {
          const label = g === "main" ? "主组" : `备用组 · ${s.backup_group?.name ?? ""}`;
          const carrying = (s.path ?? "main") === g;
          return (
            <ul key={g} className="ov-list" aria-label={label} data-testid={`ov-group-${g}`}>
              <li className="ov-group-head">
                <span>{label}</span>
                {carrying ? <StatusTag kind={g === "main" ? "ok" : "attention"}>承载中</StatusTag> : null}
              </li>
              {s.relays.filter((r) => (r.group ?? "main") === g).map(row)}
            </ul>
          );
        })}
      </div>
    );
  }
  return (
    <ul className="ov-list" data-testid="relay-sharing">
      {s.relays.map((r) => {
        const st = RELAY_STATUS[r.status] ?? RELAY_STATUS.unknown;
        return (
          <li key={r.id} data-testid={`ov-relay-${r.id}`}>
            <EllipsisText text={r.name} />
            <span>
              {PROBLEM.has(st.kind) ? <StatusTag kind={st.kind}>{st.label}</StatusTag> : null} <SpeedLine sp={r.speed} />
            </span>
          </li>
        );
      })}
    </ul>
  );
}

const LINK_LOG_DOWN: Record<string, string> = { agent_unavailable: "宿主通道不可用", agent_old: "宿主代理版本过旧", not_running: "链路日志未运行" };

function TunnelCard({ d, inactive }: { d: LinkLogAnswer; inactive: string[] }) {
  const sum = d.summary;
  if (!d.available || !sum) {
    return (
      <Typography.Text type="secondary" data-testid="ov-tunnels" data-state="unknown">
        状态未知 · {LINK_LOG_DOWN[d.code ?? ""] ?? d.message ?? "读不到"}
      </Typography.Text>
    );
  }
  // A self-check target removed from the rules keeps its last reading in the
  // journal: history, not a current unknown (same as 链路日志).
  const abnormal = sum.abnormal.filter((o) => isCurrent(o, inactive));
  const bad = [...abnormal, ...sum.unknown.filter((u) => isCurrent(u, inactive) && !abnormal.some((a) => a.id === u.id))];
  const history = new Set([...sum.abnormal, ...sum.unknown].filter((o) => !isCurrent(o, inactive)).map((o) => `${o.kind}|${o.id}`)).size;
  if (bad.length === 0) {
    return (
      <span data-testid="ov-tunnels" data-state="ok">
        全部正常 · {sum.objects - history} 条
      </span>
    );
  }
  return (
    <ul className="ov-list" data-testid="ov-tunnels" data-state="abnormal">
      {bad.slice(0, TUNNEL_ROWS).map((o) => (
        <li key={`${o.class}-${o.id}`}>
          <EllipsisText text={o.label || o.id} />
          {o.stale || !abnormal.includes(o) ? (
            <StatusTag kind="unverified">未知</StatusTag>
          ) : (
            <StatusTag kind="failed" title={o.evidence}>
              {o.reason || o.state}
            </StatusTag>
          )}
        </li>
      ))}
      {bad.length > TUNNEL_ROWS ? (
        <li>
          <Link to={href("link-log")}>还有 {bad.length - TUNNEL_ROWS} 条</Link>
        </li>
      ) : null}
    </ul>
  );
}

export default function OverviewPage() {
  const { install } = useStatus();
  const doc = useTopologyDoc();
  const servers = useApi(() => api.listServers(), []);
  const creds = useApi(() => api.listCredentials(), []);
  const groups = useApi(() => api.listGroups(), []);
  const remote = useApi(() => api.getRemoteAccess(), []);
  const unlock = useApi(() => api.getUnlockJobs(), []);
  const upstream = useApi(() => api.getUpstream(), []);
  const tunnels = useApi(() => api.getLinkLogCurrent(), []);
  const linkView = useApi(() => api.getLinkLog(), []);
  const latency = useExitLatency();
  const latencies = new Map((latency.view.data?.rows ?? []).map((r) => [r.exit_id, r]));
  // The exits card shows what the hub reports: read it once if the last read is old.
  useHubAutoRead(groups.data, () => {
    api.refreshGroupRuntime().then(
      (d: RegionGroupsView) => groups.setData(d),
      () => void groups.reload(),
    );
  });

  const nodeName = (id: string) => doc.topo?.nodes.find((n) => n.id === id)?.name ?? id;

  // ---------------------------------------------------------- next steps ---
  const sv = servers.data?.servers;
  const managed = doc.topo?.nodes.filter((n) => n.role !== "gateway" && n.managed) ?? null;
  // Peers an install refuses until they have a public key: managed nodes get
  // one from their first provisioning, unmanaged ones (IX …) from the topology.
  const keyless = managed ? managed.filter((n) => !n.public_key) : null;
  // External SOCKS exits have no key of their own (the carrier holds the tunnel).
  const keylessUnmanaged = doc.topo?.nodes.filter((n) => n.role !== "gateway" && !n.managed && !n.external && !n.public_key) ?? [];
  const steps: { title: string; done: Done; text: ReactNode; to: string }[] = [
    {
      title: "添加 SSH 密钥",
      done: creds.data ? creds.data.credentials.length > 0 : null,
      text: creds.data ? (creds.data.credentials.length > 0 ? `已有 ${creds.data.credentials.length} 把` : "生成或导入一把用于登录服务器") : "读不到密钥",
      to: href("keys"),
    },
    {
      title: "添加服务器",
      done: sv ? sv.length > 0 : null,
      text: sv ? (sv.length > 0 ? `已有 ${sv.length} 台` : "添加中继、枢纽和出口所在的主机") : "读不到服务器",
      to: href("servers"),
    },
    {
      title: "确认主机指纹并测试连接",
      done: sv ? sv.length > 0 && sv.every((s) => s.ready) : null,
      text: sv
        ? sv.length === 0
          ? "添加服务器之后进行"
          : sv.every((s) => s.ready)
            ? "全部就绪"
            : `${sv.filter((s) => !s.ready).length} 台还没就绪`
        : "读不到服务器",
      to: href("servers"),
    },
    {
      title: "在拓扑里为节点选择服务器",
      done: managed ? managed.length > 0 && managed.every((n) => !!n.server_id) : null,
      text: managed
        ? managed.length === 0
          ? "拓扑里还没有受管的远端节点"
          : managed.every((n) => !!n.server_id)
            ? "每个受管节点都关联了服务器"
            : `${managed.filter((n) => !n.server_id).length} 个节点还没关联服务器`
        : "读不到拓扑",
      to: href("topology"),
    },
    {
      title: "远端节点第一次下发",
      done: keyless && managed ? managed.length > 0 && keyless.length === 0 && keylessUnmanaged.length === 0 : null,
      text: keyless
        ? managed!.length === 0
          ? "拓扑里还没有受管的远端节点"
          : keyless.length === 0 && keylessUnmanaged.length === 0
            ? "每个远端节点都有密钥"
            : [
                keyless.length > 0 ? `${keyless.length} 个远端节点还没有密钥：在「部署 → 远端节点」对它们执行「生成密钥并下发」` : "",
                keylessUnmanaged.length > 0 ? `${keylessUnmanaged.length} 个不受管的节点要在拓扑里填入公钥` : "",
              ]
                .filter(Boolean)
                .join("；") + "。之后才能安装到网关。"
        : "读不到拓扑",
      to: keyless && keyless.length === 0 && keylessUnmanaged.length > 0 ? href("topology", keylessUnmanaged[0].id) : `${href("deploy")}?section=remote`,
    },
    {
      title: "设置出口地区组",
      done: groups.data ? groups.data.groups.length > 0 : null,
      text: groups.data ? (groups.data.groups.length > 0 ? `${groups.data.groups.length} 个地区组` : "按国家或地区把出口分组") : "读不到地区组",
      to: href("exits"),
    },
    {
      title: "安装到网关",
      done: install.kind === "loading" ? null : install.kind === "in_sync",
      text:
        install.kind === "changed"
          ? install.appliedOnly
            ? "已应用，尚未安装"
            : "有改动尚未安装"
          : install.kind === "not_installed"
            ? "还没有安装过"
            : install.kind === "error"
              ? "拓扑无法编译"
              : install.kind === "in_sync"
                ? `已安装 v${install.version}`
                : install.kind === "unknown"
                  ? "无法判断是否与网关一致"
                  : "读取中",
      to: href("deploy"),
    },
    {
      title: "运行验证",
      done: unlock.data ? unlock.data.jobs.some((j) => j.state === "done") : null,
      text: unlock.data
        ? unlock.data.jobs.some((j) => j.state === "done")
          ? "已跑过解锁探测"
          : "跑一轮解锁探测"
        : "读不到解锁探测记录",
      to: href("unlock"),
    },
  ];
  const firstOpen = steps.findIndex((s) => s.done !== true);

  // Open steps come first (what to do now); once all are done they fold away.
  const nextSteps = (
    <>
        {doc.error ? <ApiErrorAlert error={doc.error} onRetry={() => void doc.reload()} /> : null}
        {/* Only the steps still open: finished ones add nothing to read. */}
        <ul className="ov-next">
          {steps.map((s, i) =>
            s.done === true ? null : (
              <li key={i}>
                <Link to={s.to}>{s.title}</Link>
                <span data-testid={`next-step-${i}`}>
                  {s.done === null ? <Typography.Text type="secondary">{s.text}</Typography.Text> : s.text}
                </span>
              </li>
            ),
          )}
        </ul>
    </>
  );

  const inst = installText(install);

  return (
    <Page title="概览">
      <div className="overview-status" data-testid="overview-status">
        <span className="ov-fact" data-testid="ov-gateway">
          <span className="ov-label">网关</span>
          <StatusTag kind={inst.kind}>{inst.label}</StatusTag>
        </span>
        <span className="ov-fact" data-testid="ov-path">
          <span className="ov-label">当前路径</span>
          {upstream.error && !upstream.data ? <StatusTag kind="unverified">未知</StatusTag> : <PathFact c={upstream.data} />}
        </span>
        <LeakStatusLine />
      </div>
      {firstOpen === -1 ? null : <Section title="下一步">{nextSteps}</Section>}
      <div className="overview-workspace">
        <TrafficChart />
        <Tile title="出口" to={href("exits")}>
          <TileData state={groups}>
            {(d) =>
              d.groups.length === 0 ? (
                <Typography.Text type="secondary">还没有地区组</Typography.Text>
              ) : (
                <>
                  <ul className="group-rows" aria-label="地区组">
                    {attentionFirst(d.groups).slice(0, EXIT_ROWS).map((g) => {
                      const lat = g.actual.state === "ok" && g.actual.active ? latencies.get(g.actual.active) : undefined;
                      return (
                        <li key={g.id} className="group-row" data-testid={`groups-tile-row-${g.id}`}>
                          <EllipsisLink className="group-row-name" to={href("exits", g.id)} text={groupLabel(g, d.groups)} />
                          <span className="group-row-mode muted"><ExitLatencyValue row={lat} compact /></span>
                          <span className="group-row-state">
                            <GroupActualCell g={g} nodeName={nodeName} />
                          </span>
                        </li>
                      );
                    })}
                  </ul>
                  {d.groups.length > EXIT_ROWS ? (
                    <div className="tile-more" data-testid="groups-tile-more">
                      <Link to={href("exits")}>还有 {d.groups.length - EXIT_ROWS} 个</Link>
                    </div>
                  ) : null}
                </>
              )
            }
          </TileData>
        </Tile>
      </div>
      <div className="tile-grid">
        {upstream.data?.sharing ? (
          <Tile title="国内中继" to={href("exits")}>
            <RelayCard s={upstream.data.sharing} />
          </Tile>
        ) : null}

        <Tile title="隧道" to={href("link-log")}>
          <TileData state={tunnels}>{(d) => (linkView.data || linkView.error ? <TunnelCard d={d} inactive={inactiveObjects(linkView.data?.scope)} /> : <Typography.Text type="secondary">读取中…</Typography.Text>)}</TileData>
        </Tile>

        {remote.data?.settings.enabled ? (
          <Tile title="远程接入" to={href("remote")}>
            <span data-testid="ov-remote">
              {remote.data.runtime?.available ? (
                `${remote.data.devices.filter((x) => x.runtime?.online).length} / ${remote.data.devices.length} 台在线`
              ) : (
                <Typography.Text type="secondary" title={remote.data.runtime?.reason}>
                  在线数未知
                </Typography.Text>
              )}
            </span>
          </Tile>
        ) : null}
      </div>
      <div className="tile-more" data-testid="overview-log-links">
        <Link to={href("dns-log")}>解析日志</Link> · <Link to={href("conn-log")}>连接日志</Link> · <Link to={href("link-log")}>链路日志</Link>
      </div>
    </Page>
  );
}
