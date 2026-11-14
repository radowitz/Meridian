// The ordered deployment guide: deploys every node with pending changes in
// dependency order (exits → hubs → relays → gateway), one node at a time,
// each with its own preflight, review and confirmation. Every step is the
// existing single-node flow on the server (same credentials, pinned host
// keys, install transactions with compensation, fixed host actions); this
// component only shows the plan and drives the run the server stores.
//
// Kept in its own component on purpose (a later layout rework of every
// page); it uses the shared helpers of ui.tsx as they are.

import { Alert, Button, Collapse, Space, Tag, Typography } from "antd";
import { useEffect, useState, type ReactNode } from "react";
import * as api from "./api";
import type { ApiError } from "./api";
import { PreflightReport } from "./Preflight";
import { href } from "./state";
import type { DeployPhase, DeployRun, DeploySkip, DeployStep, DeployView } from "./types";
import { roleLabel } from "./types";
import { ApiErrorAlert, DataTable, DataView, ExecNote, Explain, Link, Section, StatusTag, TimeText, useAction, useApi, useConfirmDanger, type StatusKind } from "./ui";

const PHASE: Record<DeployPhase, { kind: StatusKind; label: string }> = {
  pending: { kind: "neutral", label: "待预检" },
  preflighting: { kind: "running", label: "预检中" },
  review: { kind: "pending", label: "待你确认" },
  blocked: { kind: "attention", label: "预检有阻断项" },
  installing: { kind: "running", label: "下发中" },
  done: { kind: "ok", label: "已装好" },
  failed: { kind: "failed", label: "失败，已停下" },
  unknown: { kind: "attention", label: "结果不明，已停下" },
};

const OUTCOME: Record<string, string> = {
  installed: "已安装",
  adopted: "已在服务器上（采纳，没有重做）",
  refused: "被服务器上的复核拒绝，没有改动",
  compensated: "失败并已补偿",
  left_behind: "失败，补偿有残留",
  unknown: "结果不明",
  interrupted: "被面板重启打断",
  not_started: "没有执行",
};

const RUN_STATE: Record<DeployRun["state"], { kind: StatusKind; label: string }> = {
  active: { kind: "running", label: "进行中" },
  stopped: { kind: "failed", label: "已停下" },
  done: { kind: "ok", label: "全部装好" },
  cancelled: { kind: "neutral", label: "已取消" },
};

const roleText = (r: string) => (roleLabel as Record<string, string>)[r] ?? r;

/** A node's install state when planned (remote node states and the gateway's install states). */
const NODE_STATE_TEXT: Record<string, string> = {
  changed: "有待下发的变更",
  not_installed: "未安装",
  unknown: "状态不明",
  target_changed: "服务器变了",
  withdrawn: "已撤回",
  in_sync: "已是最新",
};

/** Counts down from the moment the view was fetched. */
function useCountdown(seconds: number | undefined, key: string): number {
  const [until, setUntil] = useState(0);
  const [, setTick] = useState(0);
  useEffect(() => {
    setUntil(seconds && seconds > 0 ? Date.now() + seconds * 1000 : 0);
  }, [seconds, key]);
  const left = Math.max(0, Math.ceil((until - Date.now()) / 1000));
  useEffect(() => {
    if (left <= 0) return;
    const t = setTimeout(() => setTick((x) => x + 1), 1000);
    return () => clearTimeout(t);
  }, [left, until]);
  return left;
}

/** What "done" proves and what it does not; remote access is independent. */
function Limits({ limits }: { limits: DeployView["limits"] }) {
  return (
    <>
      <Alert
        type="info"
        showIcon
        style={{ marginBottom: 12 }}
        data-testid="deploy-limits"
        message="「已装好」只说明安装成功、服务已启动、健康检查通过，不是端到端验证"
        description={
          <Collapse
            size="small"
            ghost
            items={[
              {
                key: "l",
                label: "能证明什么、不能证明什么",
                children: (
                  <div>
                    <Typography.Text strong>能证明</Typography.Text>
                    <ul style={{ margin: "4px 0 8px", paddingLeft: 18 }}>
                      {limits.proves.map((t) => (
                        <li key={t}>{t}</li>
                      ))}
                    </ul>
                    <Typography.Text strong>不能证明（要另外实际验证）</Typography.Text>
                    <ul style={{ margin: "4px 0 0", paddingLeft: 18 }}>
                      {limits.does_not_prove.map((t) => (
                        <li key={t}>{t}</li>
                      ))}
                    </ul>
                  </div>
                ),
              },
            ]}
          />
        }
      />
      <Typography.Paragraph type="secondary" style={{ fontSize: 12 }} data-testid="deploy-remote-access-note">
        {limits.independent.join("。")}。远程接入在 <Link to={href("remote")}>远程接入</Link> 页管理。
      </Typography.Paragraph>
    </>
  );
}

function Warnings({ items }: { items?: string[] }) {
  if (!items || items.length === 0) return null;
  return (
    <ul style={{ margin: "4px 0 0", paddingLeft: 18 }}>
      {items.map((w) => (
        <li key={w}>
          <Typography.Text type="warning" style={{ fontSize: 12 }}>
            {w}
          </Typography.Text>
        </li>
      ))}
    </ul>
  );
}

function Skipped({ items }: { items: DeploySkip[] }) {
  if (items.length === 0) return null;
  return (
    <Collapse
      size="small"
      style={{ marginTop: 12 }}
      data-testid="deploy-skipped"
      items={[
        {
          key: "s",
          label: `跳过的节点（${items.length}）：没有变化，或不需要装机`,
          children: (
            <ul style={{ margin: 0, paddingLeft: 18 }}>
              {items.map((s) => (
                <li key={s.node_id} data-testid={`deploy-skip-${s.node_id}`}>
                  <Typography.Text strong>{s.node_name || s.node_id}</Typography.Text> <Tag>{roleText(s.role)}</Tag>
                  <Typography.Text type="secondary">{s.why}</Typography.Text>
                </li>
              ))}
            </ul>
          ),
        },
      ]}
    />
  );
}

/** The plan before a run starts. */
function PlanPreview({ view, onStart, starting }: { view: DeployView; onStart: () => void; starting: boolean }) {
  const plan = view.plan;
  if (!plan) {
    return (
      <Alert
        type="error"
        showIcon
        message="拓扑现在不能编译，无法计划"
        description={view.plan_error ?? "先在拓扑或分流规则页修正错误。"}
        data-testid="deploy-plan-error"
      />
    );
  }
  return (
    <div data-testid="deploy-plan">
      {plan.steps.length === 0 ? (
        <Typography.Paragraph data-testid="deploy-nothing">所有受管节点都与它们上一次成功安装的内容一致，没有要部署的。</Typography.Paragraph>
      ) : (
        <>
          <Typography.Paragraph>
            {plan.steps.length} 个节点有待下发的变更，按下面的顺序一台一台装：每台先只读预检、给你看要做的变更和冲突，你确认后才下发；任何一台失败、补偿或结果不明就停在那里，已经装好的保持不动。
          </Typography.Paragraph>
          {plan.notes?.map((n) => (
            <Alert key={n} type="warning" showIcon style={{ marginBottom: 8 }} message={n} />
          ))}
          <DataTable
            size="small"
            rowKey="node_id"
            pageSize={50}
            dataSource={plan.steps}
            onRow={(s) => ({ "data-testid": `plan-step-${s.node_id}` }) as React.HTMLAttributes<HTMLElement>}
            columns={[
              { title: "#", kind: "fixed", width: 48, render: (_, __, i) => i + 1 },
              {
                title: "节点",
                kind: "flex",
                width: 200,
                render: (_, s) => (
                  <Space size={4} wrap>
                    <Typography.Text strong>{s.node_name || s.node_id}</Typography.Text>
                    <Tag>{roleText(s.role)}</Tag>
                  </Space>
                ),
              },
              { title: "现在", kind: "ellipsis", width: 150, render: (_, s) => NODE_STATE_TEXT[s.plan_state] ?? s.plan_state },
              {
                title: "为什么在这个位置",
                kind: "flex",
                width: 320,
                render: (_, s) => (
                  <>
                    <span>{s.reason}</span>
                    <Warnings items={s.warnings} />
                  </>
                ),
              },
            ]}
          />
          <Button type="primary" style={{ marginTop: 12 }} onClick={onStart} loading={starting} data-testid="deploy-start">
            按这个顺序开始
          </Button>
        </>
      )}
      <Skipped items={plan.skipped} />
    </div>
  );
}

function HealthView({ st }: { st: DeployStep }) {
  const h = st.health;
  if (!h) return null;
  const src = h.source === "gateway_transaction" ? "网关安装事务" : h.source === "remote_script" ? "装机脚本与服务器记录" : "服务器上的安装记录";
  return (
    <div data-testid={`deploy-health-${st.node_id}`} style={{ marginTop: 4 }}>
      <Typography.Text type="secondary" style={{ fontSize: 12 }}>
        依据：{src}
        {h.committed ? "（已提交）" : ""}
        {h.verify ? `；读回服务器记录：${h.verify === "verified" ? "一致" : h.verify === "mismatch" ? "不一致" : "没读到"}` : ""}
        {h.detail ? `；${h.detail}` : ""}
      </Typography.Text>
      {h.steps && h.steps.length > 0 ? (
        <div>
          {h.steps.map((x) => (
            <Tag key={x.name} color={x.ok ? "success" : x.skipped ? "default" : "error"}>
              {x.name}
            </Tag>
          ))}
        </div>
      ) : null}
      {h.warnings?.map((w) => (
        <div key={w}>
          <Typography.Text type="warning" style={{ fontSize: 12 }}>
            {w}
          </Typography.Text>
        </div>
      ))}
      <StatusTag kind="unverified">端到端未验证</StatusTag>
    </div>
  );
}

function PhaseTag({ st, plain }: { st: DeployStep; plain?: boolean }) {
  const p = PHASE[st.phase] ?? { kind: "neutral" as StatusKind, label: st.phase };
  const label = st.phase === "done" && st.outcome === "adopted" ? "已在服务器上" : p.label;
  return (
    <span data-testid={plain ? undefined : `deploy-phase-${st.node_id}`} data-phase={st.phase}>
      <StatusTag kind={p.kind}>{label}</StatusTag>
    </span>
  );
}

/** The current step: its preflight, the review and the confirmation. */
function CurrentStep({
  run,
  st,
  busy,
  onPreflight,
  onInstall,
}: {
  run: DeployRun;
  st: DeployStep;
  busy: string | false;
  onPreflight: () => void;
  onInstall: () => void;
}) {
  const wait = useCountdown(st.wait_seconds, `${st.node_id}:${st.retry_at ?? ""}`);
  const retry = st.phase === "failed" || st.phase === "unknown";
  const pfLabel = retry ? "重新核对（预检，读取实际安装记录）" : st.phase === "pending" ? "预检" : "重新预检";
  const what = st.kind === "gateway" ? "安装到网关" : `下发到 ${st.node_name || st.node_id}`;
  return (
    <div data-testid="deploy-current" style={{ marginTop: 12 }}>
      <Typography.Title level={5} style={{ marginTop: 0 }}>
        第 {st.position} 步：{st.node_name || st.node_id} <Tag>{roleText(st.role)}</Tag>
        <PhaseTag st={st} plain />
      </Typography.Title>
      {st.message ? <Typography.Paragraph>{st.message}</Typography.Paragraph> : null}
      {st.invalidated ? (
        <Alert type="warning" showIcon style={{ marginBottom: 8 }} data-testid="deploy-invalidated" message="之前的预检不再有效" description={st.invalidated} />
      ) : null}
      {st.changes && st.changes.length > 0 ? (
        <Alert
          type="warning"
          showIcon
          style={{ marginBottom: 8 }}
          data-testid="deploy-changes"
          message="和计划或预检时不一样了"
          description={
            <ul style={{ margin: 0, paddingLeft: 18 }}>
              {st.changes.map((c) => (
                <li key={c}>{c}</li>
              ))}
            </ul>
          }
        />
      ) : null}
      {st.outcome === "not_started" ? <ExecNote notExecuted safeToRetry={st.safe_to_retry} /> : null}
      {st.leftovers && st.leftovers.length > 0 ? (
        <Alert
          type="error"
          showIcon
          style={{ marginBottom: 8 }}
          message="留在服务器上、没有撤掉的东西"
          description={
            <ul style={{ margin: 0, paddingLeft: 18 }}>
              {st.leftovers.map((l) => (
                <li key={l} className="mono-small">
                  {l}
                </li>
              ))}
            </ul>
          }
        />
      ) : null}
      {retry ? (
        <Typography.Paragraph type="secondary" data-testid="deploy-retry-note">
          重试前先重新核对：预检会读取这个节点实际的安装记录（远端是服务器上的清单和 journal，网关是安装清单）。内容已经装上就直接采纳，不会重做；否则审阅新的预检结果后由你再次确认。有残留或中断的装机时，到下面「远端节点」里用预检对话框提供的恢复操作处理。
        </Typography.Paragraph>
      ) : null}
      {wait > 0 ? (
        <Alert
          type="warning"
          showIcon
          style={{ marginBottom: 8 }}
          data-testid="deploy-wait"
          message={`服务器暂时拒绝面板的来源地址（限速）：${wait} 秒后可以重试`}
          description={`面板在 ${st.retry_at ? new Date(st.retry_at).toLocaleTimeString() : "那之前"} 之前不会再连接这台服务器。这不是密码、密钥或指纹的问题；连续尝试会让限速时间变长。`}
        />
      ) : null}
      <Space wrap>
        <Button
          onClick={onPreflight}
          loading={busy === "preflight" || st.phase === "preflighting"}
          disabled={!!busy || run.stale || wait > 0 || !st.current || st.in_flight || !!run.in_flight}
          data-testid="deploy-preflight"
        >
          {wait > 0 ? `${wait} 秒后可${pfLabel}` : pfLabel}
        </Button>
        {st.phase === "review" || st.phase === "installing" ? (
          <Button
            type="primary"
            onClick={onInstall}
            loading={busy === "install" || st.phase === "installing"}
            disabled={!!busy || !st.can_install}
            data-testid="deploy-install"
          >
            确认并{what}
          </Button>
        ) : null}
      </Space>
      {run.preflight && (st.phase === "review" || st.phase === "blocked") ? (
        <div style={{ marginTop: 12 }} data-testid="deploy-review">
          <PreflightReport rec={run.preflight} />
        </div>
      ) : null}
    </div>
  );
}

function RunView({
  view,
  busy,
  onPreflight,
  onInstall,
  onReplan,
  onCancel,
  onNew,
}: {
  view: DeployView;
  busy: string | false;
  onPreflight: (st: DeployStep) => void;
  onInstall: (st: DeployStep) => void;
  onReplan: () => void;
  onCancel: () => void;
  onNew: () => void;
}) {
  const run = view.run!;
  const rs = RUN_STATE[run.state];
  const open = run.state === "active" || run.state === "stopped";
  const cur = run.steps.find((s) => s.node_id === run.current);
  const done = run.steps.filter((s) => s.phase === "done").length;
  return (
    <div data-testid="deploy-run">
      <Space wrap style={{ marginBottom: 8 }}>
        <span data-testid="deploy-run-state" data-state={run.state}>
          <StatusTag kind={rs.kind}>{rs.label}</StatusTag>
        </span>
        <Typography.Text type="secondary">
          {done} / {run.steps.length} 已装好 · 开始于 <TimeText value={run.created_at} />
        </Typography.Text>
        {open ? (
          <Button size="small" onClick={onCancel} disabled={!!busy || !!run.in_flight} data-testid="deploy-cancel">
            取消这次引导
          </Button>
        ) : (
          <Button size="small" onClick={onNew} disabled={!!busy} data-testid="deploy-new">
            看新的计划
          </Button>
        )}
      </Space>
      {run.state === "stopped" && run.stop_reason ? (
        <Alert type="error" showIcon style={{ marginBottom: 8 }} data-testid="deploy-stopped" message="已停在这一台，后面的节点没有动" description={run.stop_reason} />
      ) : null}
      {run.stale && open ? (
        <Alert
          type="warning"
          showIcon
          style={{ marginBottom: 8 }}
          data-testid="deploy-stale"
          message="拓扑在计划之后变了"
          description={
            <>
              <div>{run.stale_reason}</div>
              {run.affected && run.affected.length > 0 ? <div>受影响的节点：{run.affected.join("、")}</div> : null}
            </>
          }
          action={
            <Button size="small" onClick={onReplan} loading={busy === "replan"} disabled={!!run.in_flight} data-testid="deploy-replan">
              按当前拓扑重新计划
            </Button>
          }
        />
      ) : null}
      {open && !run.stale && run.pending_outside && run.pending_outside.length > 0 ? (
        <Alert
          type="info"
          showIcon
          style={{ marginBottom: 8 }}
          message={`还有 ${run.pending_outside.length} 个节点有待下发的变更，但不在这次计划里：${run.pending_outside.join("、")}`}
          action={
            <Button size="small" onClick={onReplan} loading={busy === "replan"} disabled={!!run.in_flight}>
              重新计划
            </Button>
          }
        />
      ) : null}
      {run.state === "done" ? (
        <Alert
          type="success"
          showIcon
          style={{ marginBottom: 8 }}
          data-testid="deploy-done"
          message="全部节点已装好：安装成功、服务已启动、健康检查通过"
          description="这还不是端到端验证：到「防泄露」页做验收、到「解锁」页跑探测，实际执行过的才算通过。"
        />
      ) : null}
      <DataTable
        size="small"
        rowKey="node_id"
        pageSize={50}
        dataSource={run.steps}
        onRow={(s) => ({ "data-testid": `deploy-step-${s.node_id}` }) as React.HTMLAttributes<HTMLElement>}
        columns={[
          { title: "#", kind: "fixed", width: 48, render: (_, s) => s.position },
          {
            title: "节点",
            kind: "flex",
            width: 200,
            render: (_, s) => (
              <Space size={4} wrap>
                <Typography.Text strong={s.current}>{s.node_name || s.node_id}</Typography.Text>
                <Tag>{roleText(s.role)}</Tag>
              </Space>
            ),
          },
          { title: "状态", kind: "fixed", width: 132, render: (_, s) => <PhaseTag st={s} /> },
          {
            title: "说明",
            kind: "flex",
            width: 320,
            render: (_, s) => (
              <>
                <span>{s.outcome && s.outcome !== "not_started" ? (OUTCOME[s.outcome] ?? s.outcome) : s.reason}</span>
                {s.phase === "done" ? <HealthView st={s} /> : <Warnings items={s.current ? s.warnings : undefined} />}
              </>
            ),
          },
        ]}
      />
      {open && cur ? <CurrentStep run={run} st={cur} busy={busy} onPreflight={() => onPreflight(cur)} onInstall={() => onInstall(cur)} /> : null}
      <Skipped items={run.skipped} />
      {run.events && run.events.length > 0 ? (
        <Collapse
          size="small"
          style={{ marginTop: 12 }}
          items={[
            {
              key: "e",
              label: `记录（${run.events.length}）`,
              children: (
                <ul style={{ margin: 0, paddingLeft: 18 }}>
                  {[...run.events].reverse().map((e, i) => (
                    <li key={i}>
                      <TimeText value={e.at} /> {e.node ? <Tag>{e.node}</Tag> : null}
                      {e.text}
                    </li>
                  ))}
                </ul>
              ),
            },
          ]}
        />
      ) : null}
    </div>
  );
}

/**
 * The guide. `onChanged` is called after every step (the page refreshes
 * the status bar and the other sections).
 */
export function DeploymentGuide({ onChanged, header }: { onChanged?: () => void; header?: ReactNode }) {
  const state = useApi(() => api.getDeploy(), []);
  const act = useAction();
  const confirm = useConfirmDanger();
  const [showPlan, setShowPlan] = useState(false);
  const view = state.data;
  const inFlight = !!view?.run?.in_flight;
  // A step started before a page reload is still running on the server:
  // look again until it has finished.
  useEffect(() => {
    if (!inFlight || act.busy) return;
    const t = setInterval(() => void state.reload(), 3000);
    return () => clearInterval(t);
  }, [inFlight, act.busy]); // eslint-disable-line react-hooks/exhaustive-deps

  const apply = (v: DeployView | undefined) => {
    if (v) state.setData(v);
    onChanged?.();
  };
  const refusal = (e: ApiError) => {
    const d = (e.body as { deploy?: DeployView } | undefined)?.deploy;
    if (d) state.setData(d);
  };
  const run = view?.run ?? null;
  const start = () =>
    act.run(
      async () => {
        apply(await api.startDeploy(view?.topology_version));
        setShowPlan(false);
      },
      "start",
      () => void state.reload(),
    );
  const preflight = (st: DeployStep) => act.run(async () => apply(await api.deployPreflight(run!.id, st.node_id)), "preflight", refusal);
  const install = (st: DeployStep) =>
    confirm({
      title: st.kind === "gateway" ? "安装到网关？" : `下发到 ${st.node_name || st.node_id}？`,
      consequence:
        (st.kind === "gateway"
          ? "把存储的拓扑装到这台网关：经 meridian-host 写入 Meridian 的文件、激活并做健康检查；失败会补偿回安装前。"
          : "经 SSH（固定指纹、已有凭据）在这台服务器上执行装机脚本：写入 Meridian 的文件并重启它的服务；失败会补偿。") +
        "执行前面板会再预检一次，结果和你审阅的不一样就不执行。只确认这一台，下一台要单独确认。",
      okText: "确认",
      danger: false,
      onOk: () => act.run(async () => apply(await api.deployInstall(run!.id, st.node_id, st.preflight_id ?? "")), "install", refusal),
    });
  const replan = () => act.run(async () => apply(await api.deployReplan(run!.id)), "replan", refusal);
  const cancel = () =>
    confirm({
      title: "取消这次部署引导？",
      consequence: "已经装好的节点保持不变，不会撤回任何东西；没装的节点留在「有待下发的变更」。之后可以开始新的引导。",
      okText: "取消引导",
      onOk: () => act.run(async () => apply(await api.deployCancel(run!.id)), "cancel", refusal),
    });

  const open = run && (run.state === "active" || run.state === "stopped");
  return (
    <Section title="按顺序部署待变更节点" id="guide">
      <div data-testid="deploy-guide">
        {header}
        <Explain summary="一台一台按顺序预检、确认、下发；每台都要你单独确认，不会一次确认全部。">
          顺序：挂在中继出口后面的出口 → 出口 → 备用枢纽 → 主枢纽 → 中继 → 网关；管理通道经过别的节点时，被经过的节点排在后面。每一步都是下面「远端节点」和「安装到本机」里的同一套预检和下发，只是按顺序串起来。
        </Explain>
        <ApiErrorAlert error={act.error} onClose={act.clear} />
        <DataView state={state} rows={4}>
          {(v) => (
            <>
              <Limits limits={v.limits} />
              {v.run && (open || !showPlan) ? (
                <RunView
                  view={v}
                  busy={act.busy}
                  onPreflight={preflight}
                  onInstall={install}
                  onReplan={replan}
                  onCancel={cancel}
                  onNew={() => setShowPlan(true)}
                />
              ) : (
                <PlanPreview view={v} onStart={start} starting={act.busy === "start"} />
              )}
            </>
          )}
        </DataView>
      </div>
    </Section>
  );
}
