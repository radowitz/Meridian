// 撤回: taking back what was installed on a server (remote nodes, over SSH
// with the identity the install was bound to) or on this gateway (host
// transaction through meridian-host). Deleting a node from the topology is
// a different thing: the deployment record stays until the install is
// withdrawn (or the operator explicitly gives up on a server that is gone).
//
// Nothing here reports success that the server did not report: only the
// outcomes withdrawn / already_withdrawn / recovered are shown as done.

import { DeleteOutlined, RollbackOutlined, StopOutlined, UndoOutlined } from "@ant-design/icons";
import { Alert, App as AntApp, Button, Input, Modal, Space, Tag, Tooltip, Typography } from "antd";
import { useEffect, useState, type ReactNode } from "react";
import * as api from "./api";
import type { ApiError } from "./api";
import { href, useStatus } from "./state";
import type {
  DeploymentView,
  DeploymentsView,
  GatewayDeploymentView,
  HostReport,
  HostWithdrawResult,
  WithdrawMode,
  WithdrawPlan,
  WithdrawRecord,
  WithdrawRunResult,
  WithdrawSet,
} from "./types";
import { ApiErrorAlert, DataTable, EllipsisLink, EllipsisText, Explain, Facts, Mono, RowActions, Section, StatusTag, TimeText, type MoreAction, type StatusKind } from "./ui";

// ------------------------------------------------------------- labels ---

export const DEPLOYMENT_STATUS: Record<string, { kind: StatusKind; label: string; tip?: string }> = {
  installed: { kind: "ok", label: "已安装", tip: "最近一次装机成功，安装在部署时绑定的服务器上" },
  left_behind: { kind: "failed", label: "有残留", tip: "装机失败后补偿没有全部完成，服务器上留有东西" },
  unknown: { kind: "unverified", label: "结果不明", tip: "装机中断或没有输出成功标记：服务器上可能留有东西" },
  withdrawing: { kind: "running", label: "撤回中" },
  withdraw_interrupted: { kind: "unverified", label: "撤回被中断", tip: "面板在撤回过程中退出：结果不明，重新生成计划会读出服务器上的状态" },
  withdrawn: { kind: "neutral", label: "已撤回" },
  abandoned: { kind: "attention", label: "已放弃（未核实）", tip: "操作员放弃了这台服务器：面板没有核实服务器上是否还留有安装" },
  withdraw_partial: { kind: "failed", label: "撤回未完成", tip: "有内容没能移除；清单保留，处理后可以再次撤回" },
  not_installed: { kind: "neutral", label: "未安装" },
};

const WITHDRAW_STATE: Record<string, string> = {
  running: "进行中",
  withdrawn: "已撤回",
  already_withdrawn: "之前已撤回",
  partial: "未全部完成",
  refused: "被拒绝（没有改动）",
  not_started: "没有开始（没有改动）",
  unknown: "结果不明",
  recovered: "中断的装机已补偿",
  recovery_incomplete: "补偿未全部完成",
  abandoned: "已放弃（未核实）",
};

const MODE_LABEL: Record<WithdrawMode, string> = {
  manifest: "撤回",
  journal: "恢复中断的装机",
  legacy: "旧版清理",
};

const SUCCESS = new Set(["withdrawn", "already_withdrawn", "recovered"]);

export function withdrawSucceeded(outcome: string | undefined) {
  return !!outcome && SUCCESS.has(outcome);
}

function StatusOf({ d }: { d: DeploymentView }) {
  const s = DEPLOYMENT_STATUS[d.status] ?? { kind: "neutral" as StatusKind, label: d.status };
  return (
    <StatusTag kind={s.kind} title={s.tip}>
      {s.label}
    </StatusTag>
  );
}

function List({ items, testid }: { items: string[] | undefined; testid?: string }) {
  if (!items || items.length === 0) return <Typography.Text type="secondary">无</Typography.Text>;
  return (
    <ul className="ref-list" data-testid={testid}>
      {items.map((l, i) => (
        <li key={`${i}:${l}`} className="mono-small">
          {l}
        </li>
      ))}
    </ul>
  );
}

/** 已移除 / 保留（有意） / 未能移除. */
export function WithdrawLists({ removed, kept, leftovers }: { removed?: string[]; kept?: string[]; leftovers?: string[] }) {
  return (
    <div className="withdraw-lists" data-testid="withdraw-lists">
      <Typography.Text strong>已移除</Typography.Text>
      <List items={removed} testid="withdraw-removed" />
      <Typography.Text strong>保留（有意）</Typography.Text>
      <List items={kept} testid="withdraw-kept" />
      {leftovers && leftovers.length > 0 ? (
        <>
          <Typography.Text strong type="danger">
            未能移除
          </Typography.Text>
          <List items={leftovers} testid="withdraw-leftovers" />
        </>
      ) : null}
    </div>
  );
}

function setLines(s: WithdrawSet): [ReactNode, ReactNode][] {
  const row = (label: string, v: (string | number)[]) => [label, v.length ? <span key={label} className="mono-small">{v.join("  ")}</span> : "—"] as [ReactNode, ReactNode];
  return [
    row("文件", s.files ?? []),
    row("接口", s.interfaces ?? []),
    row("服务", s.units ?? []),
    row("nft 表", s.nft_tables ?? []),
    row("路由表", s.route_tables ?? []),
  ];
}

const PACKAGES_KEPT =
  "按设计保留：装机时安装的软件包（wireguard-tools、nftables、smartdns 等）不会卸载；运行中的转发等 sysctl 值保持到重启；Docker、别的 WireGuard 接口、别的 nft 表和文件都不碰。";

// ------------------------------------------------------- withdraw dialog ---

/**
 * Plan (read-only) → typed confirmation → run. Shows the server's own
 * result. onDone gets the outcome (success or not) after a run or when the
 * plan reports the node as already withdrawn.
 */
export function WithdrawDialog({
  nodeId,
  nodeName,
  mode,
  onClose,
  onDone,
}: {
  nodeId: string | null;
  nodeName?: string;
  mode: WithdrawMode;
  onClose: () => void;
  onDone?: (outcome: string) => void;
}) {
  const [plan, setPlan] = useState<WithdrawPlan | null>(null);
  const [already, setAlready] = useState(false);
  const [planErr, setPlanErr] = useState<ApiError | null>(null);
  const [planning, setPlanning] = useState(false);
  const [confirm, setConfirm] = useState("");
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<WithdrawRunResult | null>(null);
  const [runErr, setRunErr] = useState<ApiError | null>(null);
  useEffect(() => {
    setPlan(null);
    setAlready(false);
    setPlanErr(null);
    setConfirm("");
    setResult(null);
    setRunErr(null);
  }, [nodeId, mode]);
  if (!nodeId) return null;

  const makePlan = () => {
    setPlanning(true);
    setPlanErr(null);
    setResult(null);
    setRunErr(null);
    api
      .withdrawPlan(nodeId, mode)
      .then((r) => {
        setPlan(r.plan);
        setAlready(!!r.already_withdrawn || !!r.plan?.already);
        if (r.already_withdrawn || r.plan?.already) onDone?.("already_withdrawn");
      })
      .catch((e: ApiError) => setPlanErr(e))
      .finally(() => setPlanning(false));
  };

  const run = () => {
    if (!plan) return;
    setRunning(true);
    setRunErr(null);
    api
      .withdrawRun(nodeId, plan.id, confirm)
      .then((r) => {
        setResult(r);
        onDone?.(r.outcome);
      })
      .catch((e: ApiError) => {
        const b = e.body as Partial<WithdrawRunResult>;
        if (typeof b.outcome === "string") {
          setResult({ removed: [], kept: [], leftovers: [], ...b } as WithdrawRunResult);
          onDone?.(b.outcome);
        } else {
          setRunErr(e);
        }
      })
      .finally(() => setRunning(false));
  };

  const title = `${nodeName || nodeId} · ${MODE_LABEL[mode]}`;
  const done = !!result;
  const ok = withdrawSucceeded(result?.outcome);
  const refusal = planErr?.code === "withdraw_refused" ? (planErr.body as { reason?: string; owner?: string }) : null;

  return (
    <Modal
      open
      title={title}
      width={820}
      onCancel={onClose}
      destroyOnHidden
      footer={
        <Space wrap style={{ justifyContent: "flex-end", width: "100%" }}>
          <Button onClick={onClose}>{done || already ? "关闭" : "取消"}</Button>
          {!done && !already ? (
            <Button onClick={makePlan} loading={planning} disabled={running} data-testid="withdraw-plan">
              {plan ? "重新生成计划" : "生成计划（只读）"}
            </Button>
          ) : null}
          {!done && !already && plan ? (
            <Button danger type="primary" icon={<RollbackOutlined />} disabled={confirm !== nodeId || planning} loading={running} onClick={run} data-testid="withdraw-run">
              {MODE_LABEL[mode]}
            </Button>
          ) : null}
        </Space>
      }
    >
      <div data-testid="withdraw-dialog">
        <Typography.Paragraph>
          {mode === "manifest"
            ? "撤回只处理服务器上 Meridian 受管清单列出的内容：停用并删除这些服务、接口、路由表的规则和路由、nft 表和文件；内容改动过的文件会保留并列出。"
            : mode === "journal"
              ? "服务器上有一次没有正常结束的装机。恢复按服务器上的 journal 和这次装机的工作目录补偿：撤掉这次新建的、恢复被替换的，和装机失败时的自动补偿相同。"
              : "旧版清理：服务器上是没有受管清单的旧版 Meridian。"}
          {" "}面板只连部署时绑定的服务器（地址、端口、用户、固定的主机指纹和凭据都必须一致），先只读生成计划，确认后才执行；执行前服务器上的状态变了会被拒绝。
        </Typography.Paragraph>
        {mode === "legacy" ? (
          <Alert
            type="warning"
            showIcon
            style={{ marginBottom: 12 }}
            data-testid="withdraw-legacy-warning"
            message="旧版清理只移除固定路径上带 Meridian 标记的内容"
            description="只考虑这些位置：/etc/wireguard/mNN.conf、meridian-*/wstunnel-meridian* 服务文件、/usr/local/sbin/meridian-*、/etc/nftables.d/meridian*.nft、/etc/sysctl.d/99-meridian.conf、/etc/iproute2/rt_tables.d/meridian.conf、/etc/smartdns/smartdns.conf（都要在开头带 Meridian 标记）和 /etc/meridian 下的文件，以及这些文件声明的接口、nft 表和路由表。不靠猜：旧版的黑洞路由没有记录，会列出来请你手动检查。请逐条核对下面的清单，确认它们确实是这个节点以前装的。"
          />
        ) : null}
        <Typography.Paragraph type="secondary" style={{ fontSize: 12 }}>
          {PACKAGES_KEPT}
        </Typography.Paragraph>
        {planning && !plan ? <Typography.Paragraph>正在生成计划（只读，不改动服务器）…</Typography.Paragraph> : null}
        {refusal ? (
          <Alert
            type="warning"
            showIcon
            style={{ marginBottom: 12 }}
            data-testid="withdraw-refused"
            message="服务器拒绝了这次撤回，没有改动任何东西"
            description={
              <div>
                <div>{planErr!.message}</div>
                <div className="muted">
                  原因代码 <span className="mono-small">{refusal.reason}</span>
                  {refusal.owner ? <> · 清单归属 <span className="mono-small">{refusal.owner}</span></> : null}
                </div>
              </div>
            }
          />
        ) : planErr ? (
          <ApiErrorAlert error={planErr} />
        ) : null}
        {already ? (
          <Alert type="info" showIcon data-testid="withdraw-already" message="服务器上的 journal 显示这个节点已经撤回过" description="清单已经删除，没有需要撤回的内容。" />
        ) : null}
        {plan && !already ? (
          <div data-testid="withdraw-plan-view">
            <Facts
              items={[
                ["目标服务器", <span key="s">{plan.target.server_name || plan.target.server_id}</span>],
                ["登录", <span key="l" className="mono-small">{`${plan.target.user}@${plan.target.address}:${plan.target.port}`}</span>],
                ["主机指纹", <Mono key="f">{plan.target.fingerprint}</Mono>],
                ...(plan.owner ? ([["清单归属（节点 部署 服务器）", <span key="o" className="mono-small">{plan.owner}</span>]] as [ReactNode, ReactNode][]) : []),
                ["计划有效至", <TimeText key="t" value={plan.expires_at} />],
              ]}
            />
            <Typography.Text strong>将要处理的内容</Typography.Text>
            <ul className="ref-list" data-testid="withdraw-plan-items">
              {plan.items.map((it, i) => (
                <li key={`${i}:${it}`} className="mono-small">
                  {it}
                  {it.endsWith(" changed") ? <Tag color="orange" style={{ marginLeft: 6 }}>改动过：会保留</Tag> : null}
                  {it.endsWith(" absent") ? <Tag style={{ marginLeft: 6 }}>已不存在</Tag> : null}
                </li>
              ))}
            </ul>
            {!done ? (
              <div style={{ marginTop: 12 }}>
                <Typography.Paragraph style={{ marginBottom: 4 }}>
                  输入节点 ID <span className="mono">{nodeId}</span> 确认{MODE_LABEL[mode]}：
                </Typography.Paragraph>
                <Input
                  aria-label="输入节点 ID 确认"
                  value={confirm}
                  onChange={(e) => setConfirm(e.target.value)}
                  placeholder={nodeId}
                  style={{ maxWidth: 320 }}
                />
              </div>
            ) : null}
          </div>
        ) : null}
        {runErr ? (
          <div style={{ marginTop: 12 }}>
            <ApiErrorAlert error={runErr} />
          </div>
        ) : null}
        {result ? (
          <div style={{ marginTop: 12 }} data-testid="withdraw-result">
            <Alert
              type={ok ? "success" : result.outcome === "refused" || result.outcome === "not_started" ? "warning" : "error"}
              showIcon
              style={{ marginBottom: 12 }}
              message={ok ? `${MODE_LABEL[mode]}完成：${WITHDRAW_STATE[result.outcome] ?? result.outcome}` : `没有完成：${WITHDRAW_STATE[result.outcome] ?? result.outcome}`}
              description={result.message || result.error}
            />
            <WithdrawLists removed={result.removed} kept={result.kept} leftovers={result.leftovers} />
            {result.output ? (
              <details style={{ marginTop: 8 }}>
                <summary>服务器输出</summary>
                <pre className="diff">{result.output}</pre>
              </details>
            ) : null}
          </div>
        ) : null}
      </div>
    </Modal>
  );
}

// -------------------------------------------------------- typed confirm ---

function TypedConfirm({
  open,
  title,
  expect,
  danger,
  okText,
  children,
  onOk,
  onCancel,
}: {
  open: boolean;
  title: ReactNode;
  expect: string;
  danger?: boolean;
  okText: string;
  children: ReactNode;
  onOk: () => Promise<unknown>;
  onCancel: () => void;
}) {
  const [v, setV] = useState("");
  const [busy, setBusy] = useState(false);
  useEffect(() => setV(""), [open]);
  if (!open) return null;
  return (
    <Modal
      open
      title={title}
      onCancel={onCancel}
      destroyOnHidden
      okText={okText}
      cancelText="取消"
      okButtonProps={{ danger: danger ?? true, disabled: v !== expect, loading: busy }}
      onOk={() => {
        setBusy(true);
        void onOk().finally(() => setBusy(false));
      }}
    >
      <div data-testid="typed-confirm">
        {children}
        <Typography.Paragraph style={{ marginTop: 12, marginBottom: 4 }}>
          输入 <span className="mono">{expect}</span> 确认：
        </Typography.Paragraph>
        <Input aria-label="输入确认内容" value={v} onChange={(e) => setV(e.target.value)} placeholder={expect} style={{ maxWidth: 320 }} />
      </div>
    </Modal>
  );
}

// ------------------------------------------------------ records section ---

export function DeploymentRecords({
  state,
  onChanged,
}: {
  state: { data?: DeploymentsView; error: ApiError | null; loading: boolean };
  onChanged: () => void;
}) {
  const { message } = AntApp.useApp();
  const [dlg, setDlg] = useState<{ d: DeploymentView; mode: WithdrawMode } | null>(null);
  const [abandon, setAbandon] = useState<DeploymentView | null>(null);
  const [err, setErr] = useState<ApiError | null>(null);
  const rows = state.data?.nodes ?? [];
  const forget = (d: DeploymentView) =>
    api
      .forgetDeployment(d.node_id)
      .then(() => {
        message.success("记录已删除");
        onChanged();
      })
      .catch((e: ApiError) => setErr(e));

  return (
    <Section title="部署记录与撤回" id="deployments">
      <Explain summary="从拓扑删除节点不会撤回服务器上的安装：记录留在这里直到撤回完成，在那之前这台服务器和它的凭据不能删除或改指向。">
        每个远端节点装机成功后，面板记下它装在哪台服务器上（地址、端口、用户、固定的主机指纹和凭据）。撤回只连这台服务器、只移除受管清单列出的内容。
      </Explain>
      {state.error ? <ApiErrorAlert error={state.error} /> : null}
      {err ? <ApiErrorAlert error={err} onClose={() => setErr(null)} /> : null}
      {rows.length === 0 && !state.loading && !state.error ? (
        <Typography.Text type="secondary" data-testid="no-deployments">
          还没有远端节点的部署记录。
        </Typography.Text>
      ) : null}
      {rows.length > 0 ? (
        <DataTable<DeploymentView>
          rowKey="node_id"
          dataSource={rows}
          pageSize={50}
          size="middle"
          onRow={(d) => ({ "data-testid": `deployment-${d.node_id}` }) as React.HTMLAttributes<HTMLElement>}
          expandable={{
            rowExpandable: (d) => !!d.withdraw,
            expandedRowRender: (d) => <WithdrawRecordView w={d.withdraw!} />,
          }}
          columns={[
            {
              title: "节点",
              kind: "flex",
              width: 200,
              render: (_, d) => (
                <Space size={4} wrap className="cell-wrap-space">
                  {d.in_topology ? <EllipsisLink to={href("topology", d.node_id)} text={d.node_name || d.node_id} /> : <EllipsisText text={d.node_name || d.node_id} />}
                  <EllipsisText className="mono-small muted" text={d.node_id} />
                  {!d.in_topology ? (
                    <Tag color="orange" data-testid={`deployment-orphan-${d.node_id}`}>
                      节点已从拓扑删除
                    </Tag>
                  ) : d.current_server_id && d.current_server_id !== d.server_id ? (
                    <Tooltip title="拓扑里这个节点现在指向另一台服务器；这条记录是之前那台服务器上的安装">
                      <Tag color="orange">节点已改用其他服务器</Tag>
                    </Tooltip>
                  ) : null}
                </Space>
              ),
            },
            {
              title: "部署时绑定的服务器",
              kind: "flex",
              width: 220,
              render: (_, d) => (
                <div className="cell-stack">
                  {d.server_name ? <EllipsisLink to={href("servers", d.server_id)} text={d.server_name} /> : <EllipsisText className="mono-small" text={d.server_id} />}
                  <EllipsisText className="mono-small" mono text={`${d.user || "root"}@${d.address}:${d.port}`} />
                  <EllipsisText className="mono-small muted" text={d.fingerprint} mono />
                </div>
              ),
            },
            {
              title: "状态",
              kind: "flex",
              width: 200,
              render: (_, d) => (
                <div>
                  <StatusOf d={d} />
                  {d.withdraw?.message && d.withdraw.state !== "running" ? <div className="muted" style={{ fontSize: 12 }}>{d.withdraw.message}</div> : null}
                  {d.on_host && d.identity_problem ? (
                    <Typography.Text type="warning" style={{ display: "block", fontSize: 12 }} data-testid={`deployment-identity-${d.node_id}`}>
                      {d.identity_problem}
                    </Typography.Text>
                  ) : null}
                  {d.mesh_bound ? (
                    <Typography.Text type="warning" style={{ display: "block", fontSize: 12 }} data-testid={`deployment-mesh-${d.node_id}`}>
                      {d.mesh_bound}
                    </Typography.Text>
                  ) : null}
                </div>
              ),
            },
            {
              title: "操作",
              kind: "actions",
              width: 120,
              render: (_, d) => {
                const busy = d.status === "withdrawing";
                const more: MoreAction[] = [];
                if (d.on_host && (d.status === "unknown" || d.status === "left_behind")) {
                  more.push({ key: "journal", icon: <UndoOutlined />, label: "恢复中断的装机", disabled: busy, onClick: () => setDlg({ d, mode: "journal" }) });
                }
                if (d.on_host) more.push({ key: "abandon", icon: <StopOutlined />, label: "放弃（服务器已不存在）", disabled: busy, onClick: () => setAbandon(d) });
                return (
                  <RowActions label={d.node_name || d.node_id} more={more}>
                    {d.on_host ? (
                      <Button size="small" danger icon={<RollbackOutlined />} disabled={busy} onClick={() => setDlg({ d, mode: "manifest" })} data-testid={`withdraw-${d.node_id}`}>
                        撤回
                      </Button>
                    ) : (
                      <Button size="small" icon={<DeleteOutlined />} onClick={() => void forget(d)}>
                        删除记录
                      </Button>
                    )}
                  </RowActions>
                );
              },
            },
          ]}
        />
      ) : null}
      {dlg ? (
        <WithdrawDialog
          nodeId={dlg.d.node_id}
          nodeName={dlg.d.node_name}
          mode={dlg.mode}
          onClose={() => {
            setDlg(null);
            onChanged();
          }}
          onDone={() => onChanged()}
        />
      ) : null}
      <TypedConfirm
        open={!!abandon}
        title={abandon ? `放弃 ${abandon.node_name || abandon.node_id} 在服务器上的安装？` : ""}
        expect={abandon?.node_id ?? ""}
        okText="放弃"
        onCancel={() => setAbandon(null)}
        onOk={() =>
          api
            .withdrawAbandon(abandon!.node_id, abandon!.node_id)
            .then(() => {
              setAbandon(null);
              onChanged();
            })
            .catch((e: ApiError) => {
              setAbandon(null);
              setErr(e);
            })
        }
      >
        <Alert
          type="warning"
          showIcon
          message="只在这台服务器确实已不存在（或你已手动清理）时使用"
          description="面板不会连接服务器，也不会移除任何东西：记录会标为「已放弃（未核实）」，服务器和凭据的绑定解除。如果服务器其实还在，上面的 Meridian 服务、接口和文件会继续留着。"
        />
      </TypedConfirm>
    </Section>
  );
}

function WithdrawRecordView({ w }: { w: WithdrawRecord }) {
  return (
    <div data-testid="withdraw-record">
      <Space size={6} wrap style={{ marginBottom: 8 }}>
        <Typography.Text type="secondary">最近一次</Typography.Text>
        <Tag>{MODE_LABEL[w.mode as WithdrawMode] ?? w.mode}</Tag>
        <Typography.Text>{WITHDRAW_STATE[w.state] ?? w.state}</Typography.Text>
        <TimeText value={w.finished || w.at} />
        {w.reason ? <span className="mono-small muted">{w.reason}</span> : null}
      </Space>
      <WithdrawLists removed={w.removed} kept={w.kept} leftovers={w.leftovers} />
    </div>
  );
}

// ------------------------------------------------------------- gateway ---

const GW_STATE: Record<string, string> = {
  withdrawn: "已撤回（兜底表保留）",
  already_withdrawn: "之前已撤回（已复查转发关闭和兜底表）",
  guard_released: "兜底表已移除",
  not_installed: "没有安装",
  refused: "被拒绝（没有改动）",
  compensated: "失败，已补偿回撤回前",
  uncompensated: "失败，补偿也失败了（事务日志保留）",
  check_failed: "已撤回，但复查失败",
};

export function GatewayWithdraw({
  gw,
  onChanged,
  hostReport,
}: {
  gw: GatewayDeploymentView | undefined;
  onChanged: () => void;
  hostReport: (r: HostReport, failed?: boolean) => ReactNode;
}) {
  const { refresh } = useStatus();
  const [ask, setAsk] = useState<"withdraw" | "guard" | null>(null);
  const [res, setRes] = useState<HostWithdrawResult | null>(null);
  const [err, setErr] = useState<ApiError | null>(null);
  if (!gw) return null;
  const go = (guard: boolean) =>
    api
      .hostWithdraw("gw", guard)
      .then((r) => {
        setRes(r);
        setErr(null);
      })
      .catch((e: ApiError) => {
        setRes(null);
        setErr(e);
      })
      .finally(() => {
        setAsk(null);
        refresh();
        onChanged();
      });
  const errBody = (err?.body ?? {}) as { host?: HostReport | null; compensated?: boolean };
  const plan = gw.plan;
  return (
    <Section title="撤回网关" id="gateway-withdraw">
      <Alert
        type="info"
        showIcon
        style={{ marginBottom: 12 }}
        message="撤回网关后局域网保持兜底拒绝"
        description="撤回先关闭转发，再按安装清单移除 Meridian 的文件、接口、服务、路由表和 inet meridian 表；局域网兜底表 inet meridian_guard、它的开机文件和 meridian-guard.service 保留，局域网经这台网关的转发继续被拒绝，不会从 ROS 直接出去。整个撤回是一次宿主事务，失败会补偿回撤回前的安装。"
        data-testid="gateway-guard-note"
      />
      {gw.error ? <Alert type="error" showIcon style={{ marginBottom: 12 }} message={gw.error} /> : null}
      {gw.pending ? (
        <Alert
          type="error"
          showIcon
          style={{ marginBottom: 12 }}
          message={`有未完成的宿主事务 ${gw.pending.id}（${gw.pending.kind}，阶段 ${gw.pending.phase}）`}
          description="先在上面「安装到本机」里点「恢复」：恢复会完成已生效的提交，或把网关补偿回事务前。"
        />
      ) : null}
      {gw.mesh_bound ? <Alert type="warning" showIcon style={{ marginBottom: 12 }} message={gw.mesh_bound} /> : null}
      {gw.installed ? (
        <>
          <Typography.Text strong>撤回会移除（来自安装清单 v{gw.version}）</Typography.Text>
          <Facts items={setLines(plan)} />
        </>
      ) : gw.withdrawn ? (
        <Typography.Paragraph data-testid="gateway-withdrawn">
          <StatusTag kind="neutral">已撤回</StatusTag> 网关上只保留局域网兜底表，局域网转发保持被拒绝。重新安装要先做安装前预检。
        </Typography.Paragraph>
      ) : (
        <Typography.Paragraph type="secondary">网关上没有受管的 Meridian 安装。</Typography.Paragraph>
      )}
      {gw.kept.length > 0 ? (
        <>
          <Typography.Text strong>保留（有意）</Typography.Text>
          <List items={gw.kept} testid="gateway-kept" />
        </>
      ) : null}
      <Space wrap style={{ marginTop: 8 }}>
        {gw.installed ? (
          <Button danger icon={<RollbackOutlined />} disabled={!!gw.pending || !!gw.mesh_bound} onClick={() => setAsk("withdraw")} data-testid="gateway-withdraw">
            撤回网关…
          </Button>
        ) : null}
        {gw.withdrawn ? (
          <Button danger disabled={!!gw.pending} onClick={() => setAsk("guard")} data-testid="gateway-release-guard">
            移除兜底表…
          </Button>
        ) : null}
      </Space>
      {gw.last && !res && !err ? (
        <div style={{ marginTop: 12 }} data-testid="gateway-withdraw-last">
          <Typography.Text type="secondary">最近一次：</Typography.Text> {GW_STATE[gw.last.state] ?? gw.last.state} <TimeText value={gw.last.at} />
          {gw.last.message ? <div className="muted">{gw.last.message}</div> : null}
        </div>
      ) : null}
      {err ? (
        <div style={{ marginTop: 12 }} data-testid="gateway-withdraw-error">
          <ApiErrorAlert error={err}>
            {err.code === "activation_failed_compensated" ? <div>网关已补偿回撤回前的安装，数据面重新启动；可以修正原因后再撤回。</div> : null}
            {err.code === "activation_failed_uncompensated" ? <div>补偿也失败了：宿主处于未知状态，事务日志已保留。修好原因后在上面「安装到本机」里点「恢复」。</div> : null}
          </ApiErrorAlert>
          {errBody.host ? hostReport(errBody.host, true) : null}
        </div>
      ) : null}
      {res ? (
        <div style={{ marginTop: 12 }} data-testid="gateway-withdraw-result">
          <Alert type="success" showIcon style={{ marginBottom: 12 }} message={GW_STATE[res.status] ?? res.status} />
          <Facts items={setLines(res.removed)} />
          <Typography.Text strong>保留（有意）</Typography.Text>
          <List items={res.kept} />
          {res.host ? hostReport(res.host) : null}
        </div>
      ) : null}
      <TypedConfirm
        open={ask === "withdraw"}
        title="撤回网关？"
        expect="gw"
        okText="撤回网关"
        onCancel={() => setAsk(null)}
        onOk={() => go(false)}
      >
        <Typography.Paragraph>
          先关闭转发，再移除安装清单里除兜底表以外的全部内容。<strong>局域网兜底表 inet meridian_guard 保留</strong>：局域网经这台网关的流量会被丢弃（兜底拒绝），直到重新安装或你单独移除兜底表。
        </Typography.Paragraph>
      </TypedConfirm>
      <TypedConfirm
        open={ask === "guard"}
        title="移除局域网兜底表？"
        expect="gw"
        okText="移除兜底表"
        onCancel={() => setAsk(null)}
        onOk={() => go(true)}
      >
        <Alert
          type="error"
          showIcon
          message="移除后 Meridian 不再为局域网兜底"
          description="会删除 inet meridian_guard 和它的开机文件（删除前先关闭转发）。之后如果有别的东西（例如 Docker）打开转发，把这台机器当网关的局域网设备的流量会直接经 ROS 出去，不再被拒绝。只在不再把这台机器当网关用时这样做。"
        />
      </TypedConfirm>
    </Section>
  );
}
