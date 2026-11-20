// Mesh 部署 (on the Cloudflare page). The best state Mesh can reach here is
// "路由已发布 · 数据面未验证": the panel has no Linux packet-forwarding
// evidence, so nothing on this page ever says Mesh works.

import { Alert, App as AntApp, Button, Collapse, Select, Space, Steps, Typography } from "antd";
import { useEffect, useRef, useState } from "react";
import * as api from "./api";
import { HostMeshTable, InstallPlans } from "./host_mesh";
import type { ApiError } from "./api";
import { href } from "./state";
import { JOURNAL_STATE, checkSummary } from "./status_words";
import type { CloudflareAccountView, MeshJournal, MeshNodeReadiness, MeshRunResult, MeshStatus } from "./types";
import {
  DataTable,
  ApiErrorAlert,
  DataView,
  EmptyState,
  Facts,
  Link,
  Mono,
  Section,
  StatusTag,
  TimeText,
  errorTitle,
  useApi,
  useConfirmDanger,
  Note,
} from "./ui";

export const STAGE_LABEL: Record<string, string> = {
  plan: "计划与地址校验",
  preflight: "远端预检",
  cf_node: "Cloudflare 节点",
  install: "安装主机级节点",
  health: "节点检查",
  activate: "记录节点",
  // Stages of deployments made with Docker sidecars (old journals only).
  sidecar: "部署 sidecar（旧版）",
  routes: "发布路由（旧版）",
};

/** Journal states that block a new run (and allow a withdrawal). */
const BUSY = ["running", "published", "compensating", "compensation_failed"];

const MISSING: Record<string, string> = { server: "关联服务器", credential: "选择密钥", host_key: "确认主机指纹" };

function ReadinessTable({ rows }: { rows: MeshNodeReadiness[] }) {
  return (
    <DataTable
      size="small"
      rowKey="node_id"
      pageSize={50}
      dataSource={rows}
      columns={[
        { title: "节点", kind: "flex", width: 160, render: (_, r) => <Link to={href("topology", r.node_id)}>{r.name || r.node_id}</Link> },
        { title: "角色", kind: "fixed", width: 64, render: (_, r) => (r.role === "hub" ? "枢纽" : r.role === "exit" ? "出口" : r.role) },
        {
          title: "服务器",
          kind: "flex",
          width: 170,
          render: (_, r) =>
            r.server_id ? (
              <Link to={href("servers", r.server_id)}>{r.server_name || r.server_id}</Link>
            ) : (
              <Link to={href("topology", r.node_id)}>未关联，去拓扑选择</Link>
            ),
        },
        {
          title: "就绪",
          kind: "flex",
          width: 200,
          render: (_, r) =>
            r.ready ? (
              <StatusTag kind="ok">就绪</StatusTag>
            ) : (
              <span className="inline-status wrap">
                <StatusTag kind="attention">未就绪</StatusTag>
                <span className="cell-small">还需：{r.missing.map((m) => MISSING[m] ?? m).join("、")}</span>
              </span>
            ),
        },
        { title: "部署时固定的指纹", kind: "ellipsis", width: 200, mono: true, render: (_, r) => r.host_key || "—" },
      ]}
    />
  );
}

function StageSteps({ stages, journal }: { stages: string[]; journal: MeshJournal | null | undefined }) {
  const recs = new Map((journal?.stages ?? []).map((s) => [s.name, s]));
  return (
    <Steps
      size="small"
      direction="vertical"
      items={stages.map((name) => {
        const r = recs.get(name);
        const status =
          r?.status === "done" ? "finish" : r?.status === "failed" ? "error" : r?.status === "running" ? "process" : "wait";
        return {
          title: STAGE_LABEL[name] ?? name,
          status,
          description:
            r && (r.error || (r.detail ?? []).length > 0 || r.finished) ? (
              <div className="step-body">
                {r.status === "skipped" ? <Typography.Text type="secondary">未执行</Typography.Text> : null}
                {r.error ? <Typography.Text type="danger">{r.error}</Typography.Text> : null}
                {(r.detail ?? []).map((d) => (
                  <div key={d} className="mono-small muted">
                    {d}
                  </div>
                ))}
                {r.finished ? (
                  <div>
                    <TimeText value={r.finished} />
                  </div>
                ) : null}
              </div>
            ) : undefined,
        };
      })}
    />
  );
}

function RunResult({ result, error }: { result: MeshRunResult | null; error: ApiError | null }) {
  if (error) {
    const body = error.body as unknown as Partial<MeshRunResult>;
    return (
      <ApiErrorAlert error={error}>
        {error.code === "servers_not_ready" && body.not_ready ? (
          <div style={{ marginTop: 8 }}>
            <ReadinessTable rows={body.not_ready} />
          </div>
        ) : null}
        {error.code === "stage_failed" ? (
          <div style={{ marginTop: 8 }}>
            失败阶段：{STAGE_LABEL[body.stage ?? ""] ?? body.stage}；
            {body.compensated ? "已撤回这次创建的资源。" : "撤回没有完成，见下方部署记录，修复后「重试撤回」。"}
          </div>
        ) : null}
        {(body.compensation_errors ?? []).length > 0 ? (
          <ul className="ref-list">
            {(body.compensation_errors ?? []).map((c) => (
              <li key={c}>{c}</li>
            ))}
          </ul>
        ) : null}
      </ApiErrorAlert>
    );
  }
  if (!result) return null;
  const st = result.journal ? JOURNAL_STATE[result.journal.state] : undefined;
  return (
    <Alert
      type={result.journal?.state === "withdrawn" ? "success" : "info"}
      showIcon
      style={{ marginBottom: 16 }}
      message={result.journal?.state === "withdrawn" ? "已撤回" : st?.label ?? "完成"}
    />
  );
}

function JournalView({ journal, status }: { journal: MeshJournal; status: MeshStatus }) {
  const st = JOURNAL_STATE[journal.state] ?? { kind: "neutral" as const, label: journal.state };
  const busy = BUSY.includes(journal.state);
  const selected = status.mesh_account;
  return (
    <Space direction="vertical" size={16} style={{ width: "100%" }}>
      <Facts
        items={[
          ["运行", <Mono copy>{journal.run_id}</Mono>],
          ["状态", <Space wrap><StatusTag kind={st.kind}>{st.label}</StatusTag></Space>],
          ["开始", <TimeText value={journal.started} />],
          ["更新", <TimeText value={journal.updated} />],
          ["绑定账户", <Space wrap><Mono copy>{journal.account_id}</Mono>{busy ? <Note inline>撤回完成前不能换账户，同一账户可以替换 token</Note> : null}</Space>],
        ]}
      />
      {busy && selected && journal.account_id && selected.account_id !== journal.account_id ? (
        <Alert
          type="error"
          showIcon
          message={`Mesh 账户现在是 ${selected.account_id}，但这次部署绑定 ${journal.account_id}。撤回只在原账户进行，先把 Mesh 改回原账户。`}
        />
      ) : null}
      {journal.error ? <Alert type="error" showIcon message={journal.error} /> : null}
      {(journal.compensation_errors ?? []).length > 0 ? (
        <Alert
          type="error"
          showIcon
          message="撤回未完成：这些资源还在，部署记录保留，修复后「重试撤回」"
          description={
            <ul className="ref-list">
              {(journal.compensation_errors ?? []).map((c) => (
                <li key={c}>{c}</li>
              ))}
            </ul>
          }
        />
      ) : null}
      <div>
        <Typography.Title level={3}>固定的主机</Typography.Title>
        <DataTable
          size="small"
          rowKey="node_id"
          pageSize={50}
          dataSource={journal.hosts ?? []}
          columns={[
            { title: "节点", kind: "flex", width: 140, render: (_, h) => h.name || h.node_id },
            { title: "服务器", kind: "flex", width: 140, render: (_, h) => (h.server_id ? <Link to={href("servers", h.server_id)}>{h.server_id}</Link> : <StatusTag kind="attention">记录里没有</StatusTag>) },
            { title: "密钥", kind: "flex", width: 120, render: (_, h) => (h.credential_id ? <Link to={href("keys", h.credential_id)}>{h.credential_id}</Link> : "—") },
            { title: "目标", kind: "ellipsis", width: 200, mono: true, render: (_, h) => `${h.ssh_user}@${h.ssh_host}:${h.ssh_port}` },
            { title: "主机指纹", kind: "flex", width: 220, render: (_, h) => (h.host_key ? <Mono ellipsis copy>{h.host_key}</Mono> : <StatusTag kind="attention">未取得</StatusTag>) },
          ]}
        />
      </div>
      <Collapse
        items={[
          {
            key: "res",
            label: "这次运行创建的资源",
            children: (
              <pre className="diff">
                {[
                  ...(journal.routes ?? []).map((r) => `路由 ${r.network} → ${r.exit_id}  ${r.cf_id ?? "(id 未知)"}  ${r.state}${r.error ? `  ${r.error}` : ""}`),
                  ...(journal.remotes ?? []).map((r) =>
                    r.kind === "host_connector"
                      ? `主机 ${r.node_id} 主机级节点（面板安装）${r.mesh_addr ? ` ${r.mesh_addr} ${r.mesh_iface ?? ""}` : ""}  创建：${(r.created ?? []).join("、") || "无"}  ${r.state}${r.error ? `  ${r.error}` : ""}`
                      : `主机 ${r.node_id} sidecar（旧版，只能撤回）  ${r.state}${r.error ? `  ${r.error}` : ""}`,
                  ),
                  ...(journal.existing_hosts ?? []).map((id) => `主机 ${id} 沿用已有节点（不属于面板，撤回不动）`),
                  ...(journal.nodes ?? []).map((n) => `Cloudflare 节点 ${n.name}  ${n.cf_id ?? "(id 未知)"}  ${n.state}${n.error ? `  ${n.error}` : ""}`),
                ].join("\n") || "没有创建外部资源"}
              </pre>
            ),
          },
        ]}
      />
    </Space>
  );
}

export default function MeshDeploy({ accounts, onAccountsChanged }: { accounts: CloudflareAccountView[]; onAccountsChanged: () => void }) {
  const mesh = useApi(() => api.getMesh(), []);
  const confirm = useConfirmDanger();
  const { message } = AntApp.useApp();
  const [running, setRunning] = useState<"deploy" | "withdraw" | null>(null);
  const [detecting, setDetecting] = useState(false);

  async function detect() {
    setDetecting(true);
    try {
      await api.meshDetect();
    } catch (e) {
      setError(e as ApiError);
    } finally {
      setDetecting(false);
      await mesh.reload();
    }
  }
  const [result, setResult] = useState<MeshRunResult | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [failAfter, setFailAfter] = useState<string | undefined>(undefined);
  const poll = useRef<number | null>(null);

  // While a run is in flight the request blocks; poll the journal for stages.
  useEffect(() => {
    if (!running) return;
    poll.current = window.setInterval(() => void mesh.reload(), 3000);
    return () => {
      if (poll.current) window.clearInterval(poll.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [running]);

  async function run(kind: "deploy" | "withdraw", linkID?: string, confirmInstall?: boolean, retiredNode?: string) {
    setRunning(kind);
    setResult(null);
    setError(null);
    try {
      const r = kind === "deploy" ? await api.meshDeploy({ ...(failAfter ? { fail_after: failAfter } : {}), ...(confirmInstall ? { confirm_install: true } : {}) }) : await api.meshWithdraw(linkID, retiredNode);
      setResult(r);
      message.success(kind === "deploy" ? "路由已发布" : "已撤回");
    } catch (e) {
      setError(e as ApiError);
    } finally {
      setRunning(null);
      await mesh.reload();
      onAccountsChanged();
    }
  }

  return (
    <Section title="Mesh 部署">
      <DataView state={mesh} rows={6}>
        {(s) => {
          const journal = s.journal ?? null;
          const busy = !!journal && BUSY.includes(journal.state);
          const rows = s.plan_servers ?? [];
          const planNodes = s.plan?.nodes ?? [];
          const issues = s.plan?.issues ?? [];
          const installConfirm = s.plan?.install_confirm ?? [];
          const reused = planNodes.filter((n) => n.origin === "existing_host").map((n) => n.id);
          const legacySidecar = (journal?.remotes ?? []).some((r) => r.kind !== "host_connector" && r.state !== "removed");
          const notReady = rows.filter((r) => !r.ready);
          const acct = s.mesh_account;
          const acctView = accounts.find((a) => a.id === acct?.id);
          const blockers: string[] = [];
          if (!acct) blockers.push(accounts.length ? "在上方账户列表里选一个「用于 Mesh」" : "先添加 Cloudflare 账户并选为 Mesh 使用");
          if (s.plan_error) blockers.push("Mesh 计划无法生成");
          if (issues.length > 0) blockers.push("Mesh 计划有错误");
          if (planNodes.length === 0 && !s.plan_error) blockers.push("拓扑里没有 Mesh 边（cf_mesh 链路）");
          if (notReady.length > 0) blockers.push(`${notReady.length} 个节点的服务器还没就绪`);
          if (busy && (journal?.state !== "published" || !journal.underlay)) blockers.push("已有部署需要恢复或迁移：先撤回，再重新下发枢纽、出口与网关");
          if (journal?.state === "published" && journal.underlay && !(s.plan?.legs ?? []).some(l => !(journal.legs ?? []).some(old => old.link_id === l.link_id && old.state === "published"))) blockers.push("当前 Mesh 腿均已发布");
          const pendingLink = journal?.withdraw_links?.length === 1 ? journal.withdraw_links[0] : undefined;
          const pendingLeg = journal?.legs?.find(l => l.link_id === pendingLink);
          const retiredCandidates = journal?.state === "compensation_failed" && pendingLeg
            ? [pendingLeg.hub_id, pendingLeg.exit_id].filter(id =>
                journal.remotes?.some(r => r.node_id === id && r.state !== "removed") &&
                !journal.legs?.some(l => l.link_id !== pendingLink && l.state !== "withdrawn" && (l.hub_id === id || l.exit_id === id)))
            : [];
          const st = journal ? JOURNAL_STATE[journal.state] ?? { kind: "neutral" as const, label: journal.state } : null;
          const ck = checkSummary(acct?.permission_check ?? acctView?.permission_check);

          return (
            <Space direction="vertical" size={16} style={{ width: "100%" }}>
              {legacySidecar ? <Alert type="warning" showIcon message="旧版 sidecar 部署：只能撤回，撤回后改为主机级节点" /> : null}
              <Facts
                items={[
                  [
                    "Mesh 账户",
                    acct ? (
                      <Space wrap>
                        <span>{acct.name}</span>
                        <Mono>{acct.account_id}</Mono>
                        <StatusTag kind={ck.kind}>{ck.label}</StatusTag>
                      </Space>
                    ) : (
                      <StatusTag kind="attention">未选择</StatusTag>
                    ),
                  ],
                  ["部署状态", st ? <StatusTag kind={st.kind}>{st.label}</StatusTag> : <StatusTag kind="neutral">从未部署</StatusTag>],
                ]}
              />
              {s.credentials_error ? <Alert type="error" showIcon message="读取 Mesh 账户出错" description={s.credentials_error} /> : null}
              {s.journal_error ? <Alert type="error" showIcon message="读取部署记录出错" description={s.journal_error} /> : null}
              {s.plan_error ? <Alert type="error" showIcon message="Mesh 计划无法生成" description={s.plan_error} /> : null}
              {issues.length > 0 ? (
                <Space direction="vertical" size={2} data-testid="mesh-plan-issues">
                  {issues.map((i) => (
                    <Typography.Text key={i.code + i.message} type="danger">
                      {i.message} <Typography.Text type="secondary">（{i.code}）</Typography.Text>
                    </Typography.Text>
                  ))}
                </Space>
              ) : null}

              {planNodes.length === 0 && !s.plan_error ? (
                <EmptyState
                  title="拓扑里没有 Mesh 备路"
                  description="在拓扑里添加枢纽到出口的待命 cf_mesh 链路并保存。面板自动分配专用 /32，Mesh 仅承载 WireGuard 外层 UDP。旧版须撤回并重新下发枢纽和出口，再部署 Mesh。"
                  action={<Link to={href("topology")}>打开拓扑</Link>}
                />
              ) : (
                <>
                  <div>
                    <Typography.Title level={3}>计划里的节点</Typography.Title>
                    <ReadinessTable rows={rows} />
                  </div>
                  <HostMeshTable
                    nodes={planNodes.map((n) => ({ id: n.id, name: n.name }))}
                    detections={s.host_mesh ?? {}}
                    busy={detecting}
                    onDetect={() => void detect()}
                  />
                  {s.host_mesh_error ? <Alert type="error" showIcon message="读取 Mesh 检测结果出错" description={s.host_mesh_error} /> : null}
                  <InstallPlans nodes={installConfirm} detections={s.host_mesh ?? {}} />
                </>
              )}

              <RunResult result={result} error={error} />

              <Space wrap align="start">
                {s.fault_injection ? (
                  <Select
                    allowClear
                    style={{ width: 240 }}
                    placeholder="故障注入（演练补偿）"
                    value={failAfter}
                    onChange={setFailAfter}
                    options={(s.stages ?? []).map((x) => ({ value: x, label: `在「${STAGE_LABEL[x] ?? x}」后失败` }))}
                  />
                ) : null}
                <Button
                  type="primary"
                  disabled={blockers.length > 0 || !!running}
                  loading={running === "deploy"}
                  onClick={() =>
                    confirm({
                      title: "部署 Mesh？",
                      consequence:
                        `将在 Cloudflare 账户「${acct?.name}」部署新增 WireGuard Mesh 腿；失败只撤回本次新增资源。` +
                        (reused.length ? `沿用已有节点（不注册、不安装、撤回不动）：${reused.join("、")}。` : "") +
                        (installConfirm.length ? `在 ${installConfirm.join("、")} 上安装主机级 cloudflare-warp（官方源、校验签名公钥）并注册为 connector；装好后需重新下发并再部署一次。` : ""),
                      okText: "部署",
                      danger: false,
                      onOk: () => {
                        void run("deploy", undefined, installConfirm.length > 0);
                      },
                    })
                  }
                >
                  部署
                </Button>
                {retiredCandidates.map(id => (
                  <Button key={id} danger disabled={!!running} onClick={() => confirm({
                    title: `确认 ${id} 已永久退役？`,
                    consequence: "撤销面板为这台主机创建的 Cloudflare 注册。主机上的残留文件需在重新启用前清理。其他仍在使用的节点保留。",
                    okText: "确认永久退役",
                    onOk: () => { void run("withdraw", pendingLink, false, id); },
                  })}>离线退役 {id}</Button>
                ))}
                {busy ? (
                  <Button
                    danger
                    disabled={!!running}
                    loading={running === "withdraw"}
                    onClick={() =>
                      confirm({
                        title: journal?.state === "published" ? "撤回 Mesh 部署？" : "重试撤回？",
                        consequence: "删除面板在 Cloudflare 创建的节点注册，并在固定的服务器上只移除面板安装的软件包、源和服务；沿用的节点不动。Mesh 备路随之消失。",
                        okText: "撤回",
                        onOk: () => {
                          void run("withdraw");
                        },
                      })
                    }
                  >
                    {journal?.state === "published" ? "撤回" : "重试撤回"}
                  </Button>
                ) : null}
              </Space>
              {(journal?.legs ?? []).length > 0 ? <DataTable
                rowKey="link_id" size="small" dataSource={journal!.legs ?? []}
                columns={[
                  { title: "Mesh 腿", kind: "flex", render: (_, l) => <span>{l.link_id} · {l.exit_id}</span> },
                  { title: "对端 Mesh 地址", kind: "flex", render: (_, l) => (l.network ? <Mono>{`${l.network} UDP ${l.port}`}</Mono> : "待安装") },
                  { title: "MTU", kind: "flex", render: (_, l) => <span>路径 {l.path_mtu} / 接口 {l.device_mtu} / 载荷 {l.payload_mtu}</span> },
                  { title: "部署状态", kind: "flex", render: (_, l) => l.state === "withdrawn" ? "已撤回" : l.state === "published" ? "已发布 · 承载未验证" : l.state === "pending_provision" ? "待重新下发后再部署" : "待恢复 / 未完成" },
                  { title: "操作", kind: "fixed", width: 100, render: (_, l) => (l.state === "published" || l.state === "pending_provision") && journal?.state === "published" ? <Button danger disabled={!!running} onClick={() => confirm({ title: "撤回这条 Mesh 腿？", consequence: "只撤回这条腿；仍被其他腿使用的主机级节点保留，沿用的节点不动。直连 WireGuard 腿保留。", okText: "撤回这条腿", onOk: () => { void run("withdraw", l.link_id); } })}>撤回该腿</Button> : null },
                ]} /> : null}
              {blockers.length > 0 && !running ? (
                <Typography.Text type="warning">现在不能部署：{blockers.join("；")}</Typography.Text>
              ) : null}
              {running ? (
                <Alert
                  type="info"
                  showIcon
                  message={running === "deploy" ? "部署进行中，可能需要几分钟；不要关闭这个页面。" : "撤回进行中；不要关闭这个页面。"}
                />
              ) : null}

              {journal || running ? (
                <div>
                  <Typography.Title level={3}>阶段</Typography.Title>
                  <StageSteps stages={s.stages} journal={journal} />
                </div>
              ) : null}
              {journal ? <JournalView journal={journal} status={s} /> : null}
              {error && error.code && !["servers_not_ready", "stage_failed"].includes(error.code) ? (
                <Typography.Text type="secondary">{errorTitle(error)}</Typography.Text>
              ) : null}
              {journal?.fail_after ? <span className="muted">故障注入：{journal.fail_after}</span> : null}
            </Space>
          );
        }}
      </DataView>
    </Section>
  );
}
