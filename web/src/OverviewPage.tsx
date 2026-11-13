// 概览: what state the system is in and what to do next. Every tile shows
// real data or an explicit empty / unavailable state.

import { Space, Steps, Typography } from "antd";
import type { ReactNode } from "react";
import type { RegionGroupView } from "./types";
import * as api from "./api";
import { ACTUAL_CODE, actualTag } from "./ExitsPage";
import { JOURNAL_STATE, checkSummary } from "./MeshDeploy";
import { serverReadiness } from "./ServersPage";
import { href, useStatus, useTopologyDoc } from "./state";
import {
  ApiErrorAlert,
  Link,
  Page,
  PendingInstallIndicator,
  Section,
  StatusTag,
  Tile,
  TimeText,
  errorTitle,
  useApi,
  type ApiState,
} from "./ui";

/** Tile body for one API: skeleton text, error or the content. */
function TileData<T>({ state, children }: { state: ApiState<T>; children: (d: T) => ReactNode }) {
  if (state.data === undefined) {
    if (state.error)
      return (
        <Typography.Text type="danger">
          {errorTitle(state.error)}
          {state.error.message && state.error.message !== errorTitle(state.error) ? `：${state.error.message}` : ""}
        </Typography.Text>
      );
    return <Typography.Text type="secondary">读取中…</Typography.Text>;
  }
  return <>{children(state.data)}</>;
}

function Row({ label, children }: { label: ReactNode; children: ReactNode }) {
  return (
    <div className="tile-row">
      <Typography.Text type="secondary">{label}</Typography.Text>
      <span>{children}</span>
    </div>
  );
}

type Done = boolean | null; // null: unknown (data unavailable)

/**
 * One group on the overview tile: the member in use only from the hub's
 * report (actual.state "ok"); otherwise unknown with the reason. The
 * panel's model is mentioned in the tooltip, labelled 面板推算.
 */
function GroupActualCell({ g, nodeName }: { g: RegionGroupView; nodeName: (id: string) => string }) {
  const a = g.actual;
  const model = g.model.observed ? `面板推算：${g.model.active ? nodeName(g.model.active) : "无可用成员"}` : `按配置应使用：${g.target ? nodeName(g.target) : "无目标"}（面板推算，无健康样本）`;
  if (a.state === "ok") {
    const who = a.active === "mmesh" ? "Mesh 备路" : a.active ? nodeName(a.active) : "无（黑洞）";
    return a.alert ? (
      <StatusTag kind="attention" title={a.alert_message}>
        {who}
      </StatusTag>
    ) : (
      <span data-testid={`groups-tile-actual-${g.id}`}>{who}</span>
    );
  }
  const t = actualTag(a);
  return (
    <StatusTag kind={t.kind} title={`${ACTUAL_CODE[a.code ?? ""] ?? a.code ?? ""}${a.message ? `：${a.message}` : ""}。${model}`}>
      {a.state === "not_switchable" ? "枢纽不切换" : `实际未知 · ${t.label}`}
    </StatusTag>
  );
}

/** Region groups listed by name on the overview tile; the rest behind a link. */
const GROUP_TILE_ROWS = 6;

export default function OverviewPage() {
  const { status, statusError, install } = useStatus();
  const doc = useTopologyDoc();
  const servers = useApi(() => api.listServers(), []);
  const creds = useApi(() => api.listCredentials(), []);
  const accounts = useApi(() => api.listAccounts(), []);
  const mesh = useApi(() => api.getMesh(), []);
  const groups = useApi(() => api.listGroups(), []);
  const lists = useApi(() => api.getLists(), []);
  const remote = useApi(() => api.getRemoteAccess(), []);
  const unlock = useApi(() => api.getUnlockJobs(), []);

  const nodeName = (id: string) => doc.topo?.nodes.find((n) => n.id === id)?.name ?? id;

  // ---------------------------------------------------------- next steps ---
  const sv = servers.data?.servers;
  const managed = doc.topo?.nodes.filter((n) => n.role !== "gateway" && n.managed) ?? null;
  // Peers an install refuses until they have a public key: managed nodes get
  // one from their first provisioning, unmanaged ones (IX …) from the topology.
  const keyless = managed ? managed.filter((n) => !n.public_key) : null;
  const keylessUnmanaged = doc.topo?.nodes.filter((n) => n.role !== "gateway" && !n.managed && !n.public_key) ?? [];
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
      title: "远端节点第一次装机",
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
          ? "已跑过解锁探测；防泄露的人工检查仍要你签收"
          : "跑一轮解锁探测，并完成防泄露页的人工检查"
        : "读不到解锁探测记录",
      to: href("unlock"),
    },
  ];
  const firstOpen = steps.findIndex((s) => s.done !== true);

  return (
    <Page title="概览" description="网关现在处于什么状态，以及下一步该做什么。">
      <div className="tile-grid">
        <Tile title="网关" to={href("deploy")} extra={<PendingInstallIndicator compact />}>
          {statusError ? (
            <Typography.Text type="danger">{errorTitle(statusError)}：{statusError.message}</Typography.Text>
          ) : !status ? (
            <Typography.Text type="secondary">读取中…</Typography.Text>
          ) : (
            <>
              <Row label="宿主执行通道">
                {status.agent.ok ? <StatusTag kind="ok">可用</StatusTag> : <StatusTag kind="attention" title={status.agent.error}>不可用</StatusTag>}
              </Row>
              <Row label="数据面">
                {status.install.installed_version != null ? (
                  <Space size={4}>
                    <span className="mono">v{status.install.installed_version}</span>
                    <TimeText value={status.install.installed_at} />
                  </Space>
                ) : (
                  <StatusTag kind="neutral">未安装</StatusTag>
                )}
              </Row>
              <Row label="安装事务">
                {status.pending ? <StatusTag kind="failed" title={status.pending.error}>{`未完成（${status.pending.phase}）`}</StatusTag> : <span>无</span>}
              </Row>
              {!status.agent.ok ? (
                <Typography.Text type="secondary">{status.agent.error}</Typography.Text>
              ) : null}
            </>
          )}
        </Tile>

        <Tile title="服务器" to={href("servers")}>
          <TileData state={servers}>
            {(d) =>
              d.servers.length === 0 ? (
                <Typography.Text type="secondary">还没有服务器。</Typography.Text>
              ) : (
                <>
                  <div className="tile-metric">{d.servers.length}</div>
                  <Row label="就绪">{d.servers.filter((s) => s.ready).length}</Row>
                  {d.servers
                    .filter((s) => !s.ready)
                    .slice(0, 4)
                    .map((s) => {
                      const r = serverReadiness(s);
                      return (
                        <Row key={s.id} label={<Link to={href("servers", s.id)}>{s.name}</Link>}>
                          <StatusTag kind={r.kind}>{r.label}</StatusTag>
                        </Row>
                      );
                    })}
                </>
              )
            }
          </TileData>
        </Tile>

        <Tile title="密钥" to={href("keys")}>
          <TileData state={creds}>
            {(d) =>
              d.credentials.length === 0 ? (
                <Typography.Text type="secondary">还没有 SSH 密钥。</Typography.Text>
              ) : (
                <>
                  <div className="tile-metric">{d.credentials.length}</div>
                  <Row label="私钥 / 密码">
                    {d.credentials.filter((c) => c.kind === "private_key").length} / {d.credentials.filter((c) => c.kind === "password").length}
                  </Row>
                  <Row label="未被使用">{d.credentials.filter((c) => c.in_use_by.length === 0).length}</Row>
                </>
              )
            }
          </TileData>
        </Tile>

        <Tile title="Cloudflare 与 Mesh" to={href("cloudflare")}>
          <TileData state={accounts}>
            {(d) => {
              const sel = d.accounts.find((a) => a.id === d.mesh_account);
              const ck = checkSummary(sel?.permission_check);
              return (
                <>
                  <Row label="账户">{d.accounts.length === 0 ? "未添加" : d.accounts.length}</Row>
                  <Row label="Mesh 账户">
                    {sel ? (
                      <Space size={4}>
                        <span>{sel.name}</span>
                        <StatusTag kind={ck.kind}>{ck.label}</StatusTag>
                      </Space>
                    ) : (
                      <Typography.Text type="secondary">未选择</Typography.Text>
                    )}
                  </Row>
                </>
              );
            }}
          </TileData>
          <TileData state={mesh}>
            {(m) => {
              const st = m.journal ? JOURNAL_STATE[m.journal.state] : null;
              return (
                <>
                  <Row label="Mesh 部署">{st ? <StatusTag kind={st.kind}>{st.label}</StatusTag> : <Typography.Text type="secondary">从未部署</Typography.Text>}</Row>
                  <Row label="数据面">
                    <StatusTag kind="unverified">未验证</StatusTag>
                  </Row>
                </>
              );
            }}
          </TileData>
        </Tile>

        <Tile title="出口地区组" to={href("exits")}>
          <TileData state={groups}>
            {(d) =>
              d.groups.length === 0 ? (
                <Typography.Text type="secondary">还没有地区组。</Typography.Text>
              ) : (
                <>
                <Row label="共">
                  <span data-testid="groups-tile-count">{d.groups.length} 个地区组</span>
                </Row>
                <Row label="枢纽状态">
                  {d.hub_state?.last_read ? (
                    <span data-testid="groups-tile-hub">
                      {d.hub_state.last_read.ok ? "读取于 " : "读取失败 · "}
                      <TimeText value={d.hub_state.last_read.read_at} />
                    </span>
                  ) : (
                    <StatusTag kind="unverified" title="还没有从枢纽读回地区组的实际状态；在出口页读取">
                      未读取
                    </StatusTag>
                  )}
                </Row>
                {d.groups.slice(0, GROUP_TILE_ROWS).map((g) => (
                  <Row
                    key={g.id}
                    label={
                      <Space size={4}>
                        <Link to={href("exits", g.id)}>{g.name}</Link>
                        <Typography.Text type="secondary" style={{ whiteSpace: "nowrap" }}>
                          {g.mode === "manual" ? "手动" : "自动"}
                        </Typography.Text>
                        {g.is_default ? <Typography.Text type="secondary">· 默认</Typography.Text> : null}
                      </Space>
                    }
                  >
                    <GroupActualCell g={g} nodeName={nodeName} />
                  </Row>
                ))}
                {d.groups.length > GROUP_TILE_ROWS ? (
                  <div className="tile-more">
                    <span data-testid="groups-tile-more">
                      <Link to={href("exits")}>还有 {d.groups.length - GROUP_TILE_ROWS} 个 · 查看全部 {d.groups.length} 个</Link>
                    </span>
                  </div>
                ) : null}
                </>
              )
            }
          </TileData>
        </Tile>

        <Tile title="名单" to={href("lists")}>
          <TileData state={lists}>
            {(d) => (
              <>
                <Row label="来源">{{ domestic: "国内源", overseas: "海外源", automatic: "全自动" }[d.policy] ?? d.policy}</Row>
                <Row label="最近更新">
                  {d.job ? (
                    <Space size={4}>
                      {d.job.state === "running" ? (
                        <StatusTag kind="running">更新中</StatusTag>
                      ) : d.job.state === "failed" ? (
                        <StatusTag kind="failed">没有执行</StatusTag>
                      ) : d.job.report?.ok ? (
                        <StatusTag kind="ok">全部更新</StatusTag>
                      ) : (
                        <StatusTag kind="attention">部分失败</StatusTag>
                      )}
                      <TimeText value={d.job.finished_at ?? d.job.started_at} />
                    </Space>
                  ) : (
                    <Typography.Text type="secondary">从未更新</Typography.Text>
                  )}
                </Row>
                {!d.host_available ? <Typography.Text type="secondary">宿主执行通道不可用，不能更新。</Typography.Text> : null}
              </>
            )}
          </TileData>
        </Tile>

        <Tile title="远程接入" to={href("remote")}>
          <TileData state={remote}>
            {(d) => (
              <>
                <Row label="状态">{d.settings.enabled ? <span>已开启</span> : <StatusTag kind="neutral">未开启</StatusTag>}</Row>
                <Row label="设备">{d.devices.length}</Row>
                <Row label="在线">
                  {d.runtime?.available ? (
                    d.devices.filter((x) => x.runtime?.online).length
                  ) : (
                    <Typography.Text type="secondary" title={d.runtime?.reason}>
                      {d.runtime?.state === "disabled"
                        ? "—"
                        : d.runtime?.state === "interface_absent"
                          ? "接口还没安装"
                          : "读不到（宿主通道不可用）"}
                    </Typography.Text>
                  )}
                </Row>
              </>
            )}
          </TileData>
        </Tile>

        <Tile title="解锁探测" to={href("unlock")}>
          <TileData state={unlock}>
            {(d) => {
              const last = d.jobs[0];
              return (
                <>
                  <Row label="探测通道">{d.available ? <span>可用</span> : <StatusTag kind="attention">不可用</StatusTag>}</Row>
                  <Row label="最近一轮">
                    {d.running ? (
                      <StatusTag kind="running">进行中</StatusTag>
                    ) : last ? (
                      <Space size={4}>
                        <span>{{ done: "完成", cancelled: "已取消", timeout: "超时", interrupted: "被中断" }[last.state] ?? last.state}</span>
                        <TimeText value={last.finished_at ?? last.created_at} />
                      </Space>
                    ) : (
                      <Typography.Text type="secondary">从未运行</Typography.Text>
                    )}
                  </Row>
                  <Typography.Text type="secondary">适配器只在合成样本上测试过，结论待人工核对。</Typography.Text>
                </>
              );
            }}
          </TileData>
        </Tile>
      </div>

      <Section title="下一步">
        {doc.error ? <ApiErrorAlert error={doc.error} onRetry={() => void doc.reload()} /> : null}
        <Steps
          direction="vertical"
          size="small"
          current={firstOpen === -1 ? steps.length : firstOpen}
          items={steps.map((s, i) => ({
            title: <Link to={s.to}>{s.title}</Link>,
            status: s.done === true ? "finish" : i === firstOpen ? "process" : "wait",
            description: (
              <span data-testid={`next-step-${i}`}>
                {s.done === null ? <Typography.Text type="secondary">{s.text}</Typography.Text> : s.text}
              </span>
            ),
          }))}
        />
      </Section>
    </Page>
  );
}
