// Mesh 部署 (on the Cloudflare page). The best state Mesh can reach here is
// "路由已发布 · 数据面未验证": the panel has no Linux packet-forwarding
// evidence, so nothing on this page ever says Mesh works.

import { Alert, App as AntApp, Button, Collapse, Select, Space, Steps, Table, Tag, Typography } from "antd";
import { useEffect, useRef, useState } from "react";
import * as api from "./api";
import type { ApiError } from "./api";
import { href } from "./state";
import type { CloudflareAccountView, MeshJournal, MeshNodeReadiness, MeshRunResult, MeshStatus, PermissionCheck } from "./types";
import {
  TABLE_SCROLL,
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
  type StatusKind,
} from "./ui";

export const STAGE_LABEL: Record<string, string> = {
  plan: "计划与地址校验",
  preflight: "远端预检",
  cf_node: "Cloudflare 节点",
  sidecar: "部署 sidecar",
  health: "健康检查",
  routes: "发布路由",
  activate: "枢纽重新封装",
};

export const JOURNAL_STATE: Record<string, { kind: StatusKind; label: string }> = {
  running: { kind: "running", label: "部署中（或被中断）" },
  published: { kind: "unverified", label: "路由已发布 · 数据面未验证" },
  failed: { kind: "failed", label: "失败，已撤回本次创建的资源" },
  compensating: { kind: "running", label: "撤回中（或被中断）" },
  compensation_failed: { kind: "failed", label: "撤回未完成" },
  withdrawn: { kind: "neutral", label: "已撤回" },
};

/** Journal states that block a new run (and allow a withdrawal). */
const BUSY = ["running", "published", "compensating", "compensation_failed"];

/** Summary of a permission check. A pass is never shown as a plain "正常". */
export function checkSummary(c: PermissionCheck | null | undefined): { kind: StatusKind; label: string } {
  if (!c) return { kind: "neutral", label: "未检查" };
  if (c.ok) return { kind: "unverified", label: "可读 · 写权限未确认" };
  if (c.missing && c.missing.length > 0) return { kind: "failed", label: "缺少权限" };
  return { kind: "attention", label: "检查未完成" };
}

const MISSING: Record<string, string> = { server: "关联服务器", credential: "选择密钥", host_key: "确认主机指纹" };

function ReadinessTable({ rows }: { rows: MeshNodeReadiness[] }) {
  return (
    <Table
      size="small"
      rowKey="node_id"
      pagination={false}
      dataSource={rows}
      scroll={TABLE_SCROLL}
      columns={[
        { title: "节点", className: "cell-name", render: (_, r) => <Link to={href("topology", r.node_id)}>{r.name || r.node_id}</Link> },
        { title: "角色", className: "nowrap", render: (_, r) => (r.role === "hub" ? "枢纽" : r.role === "exit" ? "出口" : r.role) },
        {
          title: "服务器",
          className: "nowrap",
          render: (_, r) =>
            r.server_id ? (
              <Link to={href("servers", r.server_id)}>{r.server_name || r.server_id}</Link>
            ) : (
              <Link to={href("topology", r.node_id)}>未关联，去拓扑选择</Link>
            ),
        },
        {
          title: "就绪",
          className: "nowrap",
          render: (_, r) =>
            r.ready ? (
              <StatusTag kind="ok">就绪</StatusTag>
            ) : (
              <StatusTag kind="attention">{`还需：${r.missing.map((m) => MISSING[m] ?? m).join("、")}`}</StatusTag>
            ),
        },
        { title: "部署时固定的指纹", render: (_, r) => <Mono>{r.host_key}</Mono> },
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
      description={result.journal?.state === "published" ? "Cloudflare 路由已发布。Mesh 数据面仍是未验证：这不表示 Mesh 可用。" : undefined}
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
          ["状态", <Space wrap><StatusTag kind={st.kind}>{st.label}</StatusTag><StatusTag kind="unverified">数据面未验证</StatusTag></Space>],
          ["开始", <TimeText value={journal.started} />],
          ["更新", <TimeText value={journal.updated} />],
          ["绑定账户", <Space wrap><Mono copy>{journal.account_id}</Mono>{busy ? <Typography.Text type="secondary">撤回完成前不能换账户，同一账户可以替换 token</Typography.Text> : null}</Space>],
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
        <Typography.Title level={5}>固定的主机</Typography.Title>
        <Typography.Paragraph type="secondary">
          部署和撤回只连这些目标，并要求同一个主机指纹；这些服务器和密钥在撤回完成前不能删除或改指向。
        </Typography.Paragraph>
        <Table
          size="small"
          rowKey="node_id"
          pagination={false}
          dataSource={journal.hosts ?? []}
          scroll={TABLE_SCROLL}
          columns={[
            { title: "节点", className: "cell-name", render: (_, h) => h.name || h.node_id },
            { title: "服务器", render: (_, h) => (h.server_id ? <Link to={href("servers", h.server_id)}>{h.server_id}</Link> : <StatusTag kind="attention">记录里没有</StatusTag>) },
            { title: "密钥", render: (_, h) => (h.credential_id ? <Link to={href("keys", h.credential_id)}>{h.credential_id}</Link> : "—") },
            { title: "目标", render: (_, h) => <Mono>{`${h.ssh_user}@${h.ssh_host}:${h.ssh_port}`}</Mono> },
            { title: "主机指纹", render: (_, h) => (h.host_key ? <Mono copy>{h.host_key}</Mono> : <StatusTag kind="attention">未取得</StatusTag>) },
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
                  ...(journal.remotes ?? []).map((r) => `主机 ${r.node_id} sidecar  ${r.state}${r.error ? `  ${r.error}` : ""}`),
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

  async function run(kind: "deploy" | "withdraw") {
    setRunning(kind);
    setResult(null);
    setError(null);
    try {
      const r = kind === "deploy" ? await api.meshDeploy(failAfter ? { fail_after: failAfter } : {}) : await api.meshWithdraw();
      setResult(r);
      message.success(kind === "deploy" ? "路由已发布；数据面仍未验证" : "已撤回");
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
          const routes = s.plan?.routes ?? [];
          const issues = s.plan?.issues ?? [];
          const notReady = rows.filter((r) => !r.ready);
          const acct = s.mesh_account;
          const acctView = accounts.find((a) => a.id === acct?.id);
          const blockers: string[] = [];
          if (!acct) blockers.push(accounts.length ? "在上方账户列表里选一个「用于 Mesh」" : "先添加 Cloudflare 账户并选为 Mesh 使用");
          if (s.plan_error) blockers.push("Mesh 计划无法生成");
          if (issues.length > 0) blockers.push("Mesh 计划有错误");
          if (planNodes.length === 0 && !s.plan_error) blockers.push("拓扑里没有 Mesh 边（cf_mesh 链路）");
          if (notReady.length > 0) blockers.push(`${notReady.length} 个节点的服务器还没就绪`);
          if (busy) blockers.push("已有一次部署未撤回完");
          const st = journal ? JOURNAL_STATE[journal.state] ?? { kind: "neutral" as const, label: journal.state } : null;
          const ck = checkSummary(acct?.permission_check ?? acctView?.permission_check);

          return (
            <Space direction="vertical" size={16} style={{ width: "100%" }}>
              <Alert
                type="warning"
                showIcon
                message="Mesh 数据面：未验证"
                description={s.dataplane_note}
              />
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
                  ["数据面", <StatusTag kind="unverified">未验证</StatusTag>],
                ]}
              />
              {s.credentials_error ? <Alert type="error" showIcon message="读取 Mesh 账户出错" description={s.credentials_error} /> : null}
              {s.journal_error ? <Alert type="error" showIcon message="读取部署记录出错" description={s.journal_error} /> : null}
              {s.plan_error ? <Alert type="error" showIcon message="Mesh 计划无法生成" description={s.plan_error} /> : null}
              {issues.map((i) => (
                <Alert key={i.code + i.message} type="error" showIcon message={i.message} description={i.code} />
              ))}

              {planNodes.length === 0 && !s.plan_error ? (
                <EmptyState
                  title="拓扑里没有 Mesh 备路"
                  description="Mesh 是枢纽到出口的备用一跳：在拓扑里加一条 Mesh 备路链路并填写要发布的网段，这里才会出现部署计划。"
                  action={<Link to={href("topology")}>打开拓扑</Link>}
                />
              ) : (
                <>
                  <div>
                    <Typography.Title level={5}>计划里的节点</Typography.Title>
                    <Typography.Paragraph type="secondary">
                      每个节点只经它关联的服务器连接：地址、用户、密钥和已确认的主机指纹都取自服务器页。
                    </Typography.Paragraph>
                    <ReadinessTable rows={rows} />
                  </div>
                  <div>
                    <Typography.Title level={5}>待发布的路由</Typography.Title>
                    {routes.length === 0 ? (
                      <Typography.Text type="secondary">无。在拓扑的 Mesh 链路上填写要发布的网段。</Typography.Text>
                    ) : (
                      <Space direction="vertical" size={2}>
                        {routes.map((r) => (
                          <span key={r.link_id + r.network}>
                            <Mono>{r.network}</Mono> → {r.exit_id} <Typography.Text type="secondary">（{r.link_id}）</Typography.Text>
                          </span>
                        ))}
                      </Space>
                    )}
                  </div>
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
                      consequence: `将在 Cloudflare 账户「${acct?.name}」创建 ${planNodes.length} 个 Mesh 节点、发布 ${routes.length} 条路由，并经 SSH 在 ${planNodes.length} 台服务器上部署 sidecar；任一阶段失败会撤回这次创建的资源。`,
                      okText: "部署",
                      danger: false,
                      onOk: () => {
                        void run("deploy");
                      },
                    })
                  }
                >
                  部署
                </Button>
                {busy ? (
                  <Button
                    danger
                    disabled={!!running}
                    loading={running === "withdraw"}
                    onClick={() =>
                      confirm({
                        title: journal?.state === "published" ? "撤回 Mesh 部署？" : "重试撤回？",
                        consequence: "删除这次部署在 Cloudflare 创建的节点和路由，并在固定的服务器上移除 sidecar、恢复受管文件；Mesh 备路随之消失。",
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
              {blockers.length > 0 && !running ? (
                <Typography.Text type="secondary">
                  现在不能部署：{blockers.join("；")}。
                </Typography.Text>
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
                  <Typography.Title level={5}>阶段</Typography.Title>
                  <StageSteps stages={s.stages} journal={journal} />
                </div>
              ) : null}
              {journal ? <JournalView journal={journal} status={s} /> : null}
              {error && error.code && !["servers_not_ready", "stage_failed"].includes(error.code) ? (
                <Typography.Text type="secondary">{errorTitle(error)}</Typography.Text>
              ) : null}
              {s.plan?.addressing ? (
                <Collapse
                  items={[
                    {
                      key: "addr",
                      label: "veth 地址与下一跳",
                      children: (
                        <div className="mono-small">
                          <div>
                            IPv4：主机 {s.plan.addressing.host_v4} dev {s.plan.addressing.host_iface} ↔ sidecar {s.plan.addressing.sidecar_v4} dev{" "}
                            {s.plan.addressing.sidecar_iface}（{s.plan.addressing.link_v4}）
                          </div>
                          <div>
                            IPv6：主机 {s.plan.addressing.host_v6}/{s.plan.addressing.v6_bits} ↔ sidecar {s.plan.addressing.sidecar_v6}/
                            {s.plan.addressing.v6_bits}
                          </div>
                          <div>
                            MAC {s.plan.addressing.host_mac} / {s.plan.addressing.sidecar_mac}；回程 {(s.plan.return_v4 ?? []).join(" ")}{" "}
                            {(s.plan.return_v6 ?? []).join(" ")}
                          </div>
                        </div>
                      ),
                    },
                  ]}
                />
              ) : null}
              <Typography.Text type="secondary">
                顺序：计划与地址校验 → 远端预检 → 创建 Cloudflare 节点 → 部署 sidecar → 健康检查 → 发布路由 → 枢纽重新封装。任一步失败即停止并撤回这次创建的资源；撤回失败会单独列出，可以重试。
              </Typography.Text>
              {journal?.fail_after ? <Tag color="purple">故障注入：{journal.fail_after}</Tag> : null}
            </Space>
          );
        }}
      </DataView>
    </Section>
  );
}
