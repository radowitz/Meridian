import { deployPendingNodes } from "./automatic_deploy";
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
import { VerifyGroup } from "./DeployVerifyGroup";
import { PreflightReport } from "./Preflight";
import { ErrorBoundary } from "./ErrorBoundary";
import { href } from "./state";
import type { DeployPhase, DeployRun, DeploySkip, DeployStep, DeployView, MTUChange, PreflightFinding } from "./types";
import { roleLabel } from "./types";
import {
  ApiErrorAlert,
  DataTable,
  DataView,
  ExecNote,
  Link,
  Section,
  StatusTag,
  TimeText,
  useAction,
  useApi,
  useConfirmDanger,
  type StatusKind,
  Note,
} from "./ui";

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

/** How a done step became done (stored per step by the server). */
export function completionOf(st: DeployStep): "installed" | "adopted" | "in_sync" | "" {
  if (st.phase !== "done") return "";
  if (st.completion) return st.completion;
  if (st.outcome === "installed") return "installed";
  return st.evidence === "panel_record" ? "in_sync" : "adopted";
}

const COMPLETION_TAG: Record<"installed" | "adopted" | "in_sync", { kind: StatusKind; label: string }> = {
  installed: { kind: "ok", label: "已安装 · 健康检查通过" },
  adopted: { kind: "unverified", label: "已采纳记录 · 未重新检查健康" },
  in_sync: { kind: "unverified", label: "已一致 · 本次未执行" },
};

const RUN_STATE: Record<DeployRun["state"], { kind: StatusKind; label: string }> = {
  active: { kind: "running", label: "进行中" },
  stopped: { kind: "failed", label: "已停下" },
  done: { kind: "ok", label: "全部步骤完成" },
  cancelled: { kind: "neutral", label: "已取消" },
  partial: { kind: "attention", label: "已结束 · 有跳过的节点仍待处理" },
};

const SKIP_KIND: Record<string, string> = {
  blocked: "预检有阻断项",
  unreachable: "连不上服务器",
  waiting: "限速等待",
};

/** Node names of the run's steps (node IDs the server lists). */
function namesOf(run: DeployRun, ids: string[] | undefined): string {
  return (ids ?? []).map((id) => run.steps.find((s) => s.node_id === id)?.node_name || id).join("、");
}

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

/** Remote access has its own configuration page. */
function Limits({ limits }: { limits: DeployView["limits"] }) {
  return (
    <>
      <Note testId="deploy-remote-access-note">
        {(limits?.independent ?? []).join("。")}。远程接入在 <Link to={href("remote")}>远程接入</Link> 页管理。
      </Note>
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

function Skipped({ items: raw }: { items: DeploySkip[] | null | undefined }) {
  const items = raw ?? [];
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
                  <Typography.Text strong>{s.node_name || s.node_id}</Typography.Text> <span className="muted">{roleText(s.role)}</span>
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
  const installs = plan.steps.filter((s) => !s.verify_only);
  const verifies = plan.steps.filter((s) => s.verify_only);
  return (
    <div data-testid="deploy-plan">
      {plan.steps.length === 0 ? (
        <Typography.Paragraph data-testid="deploy-nothing">没有要部署的节点</Typography.Paragraph>
      ) : (
        <>
          {installs.length > 0 ? (
            <Typography.Paragraph>
              {installs.length} 个节点待下发，按顺序逐台装{" "}
              <Note inline>每台先只读预检并列出变更和冲突，你确认后才下发；任何一台失败、补偿或结果不明就停下，已装好的不动。</Note>
            </Typography.Paragraph>
          ) : null}
          {plan.notes?.map((n) => (
            <Alert key={n} type="warning" showIcon style={{ marginBottom: 8 }} message={n} />
          ))}
          <DataTable
            size="small"
            rowKey="node_id"
            pageSize={50}
            dataSource={installs}
            onRow={(s) => ({ "data-testid": `plan-step-${s.node_id}` }) as React.HTMLAttributes<HTMLElement>}
            columns={[
              { title: "#", kind: "fixed", width: 48, render: (_, __, i) => i + 1 },
              {
                title: "节点",
                kind: "flex",
                width: 200,
                card: "title",
                render: (_, s) => (
                  <Space size={4} wrap>
                    <Typography.Text strong>{s.node_name || s.node_id}</Typography.Text>
                    <span className="muted">{roleText(s.role)}</span>
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
          {verifies.length > 0 ? (
            <Typography.Paragraph style={{ marginTop: 12 }} data-testid="plan-verify-only">
              另外 {verifies.length} 个节点只需核对（{verifies.map((s) => s.node_name || s.node_id).join("、")}
              ）：面板的记录已与这份内容一致，只是没有读回服务器上的安装记录。开始后可以单独或全部核对，不安装任何东西，也不受上面的顺序约束。
            </Typography.Paragraph>
          ) : null}
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
      {completionOf(st) !== "installed" ? <StatusTag kind="unverified">健康未重新检查</StatusTag> : null}
      <StatusTag kind="unverified">端到端未验证</StatusTag>
    </div>
  );
}

function PhaseTag({ st, plain }: { st: DeployStep; plain?: boolean }) {
  const c = completionOf(st);
  const p = c
    ? COMPLETION_TAG[c]
    : st.skip
      ? { kind: "attention" as StatusKind, label: "已跳过 · 仍待处理" }
      : st.waiting_for && st.waiting_for.length > 0
        ? { kind: "neutral" as StatusKind, label: "等待被跳过的节点" }
        : (PHASE[st.phase] ?? { kind: "neutral" as StatusKind, label: st.phase });
  return (
    <span
      data-testid={plain ? undefined : `deploy-phase-${st.node_id}`}
      data-phase={st.phase}
      data-completion={c || undefined}
      data-skipped={st.skip ? "true" : undefined}
      data-waiting={st.waiting_for && st.waiting_for.length > 0 ? "true" : undefined}
    >
      <StatusTag kind={p.kind}>{p.label}</StatusTag>
    </span>
  );
}

/**
 * The finished run, from the per-step completion: only the nodes installed
 * in this run are described as health-checked; adopted ones are named.
 */
function DoneSummary({ run }: { run: DeployRun }) {
  const names = (c: string) => run.steps.filter((s) => completionOf(s) === c).map((s) => s.node_name || s.node_id);
  const installed = names("installed");
  const adopted = names("adopted");
  const inSync = names("in_sync");
  const all = installed.length > 0 && adopted.length === 0 && inSync.length === 0;
  return (
    <Alert
      type={all ? "success" : "info"}
      showIcon
      style={{ marginBottom: 8 }}
      data-testid="deploy-done"
      data-prose-exempt
      message={
        all
          ? `全部 ${installed.length} 个节点都在这次运行中安装：服务已启动、健康检查通过`
          : installed.length > 0
            ? `全部步骤完成：${installed.length} 个节点在这次运行中安装并通过健康检查，${adopted.length + inSync.length} 个节点没有重新检查健康`
            : `全部步骤完成：没有节点在这次运行中安装，${adopted.length + inSync.length} 个节点没有重新检查健康`
      }
      description={
        <>
          {installed.length > 0 && !all ? <div data-testid="deploy-done-installed">安装并通过健康检查：{installed.join("、")}</div> : null}
          {adopted.length > 0 ? (
            <div data-testid="deploy-done-adopted">按服务器记录采纳（未重新执行、未检查健康）：{adopted.join("、")}</div>
          ) : null}
          {inSync.length > 0 ? <div data-testid="deploy-done-insync">已装好且记录一致（本次未执行、未检查健康）：{inSync.join("、")}</div> : null}
        </>
      }
    />
  );
}

/**
 * A run that ended with skipped nodes: never "all done". The skipped nodes
 * (with why) and the nodes that wait for them are named; each skipped one
 * can be returned to from its row.
 */
function PartialSummary({ run }: { run: DeployRun }) {
  const sm = run.summary;
  const skipped = sm?.skipped_nodes ?? run.steps.filter((s) => s.skip).map((s) => ({ node_id: s.node_id, node_name: s.node_name, kind: s.skip!.kind, reason: s.skip!.reason }));
  const waiting =
    sm?.waiting_nodes ??
    run.steps.filter((s) => s.waiting_for && s.waiting_for.length > 0).map((s) => ({ node_id: s.node_id, node_name: s.node_name, waits_for: (s.waiting_for ?? []).map((id) => namesOf(run, [id])) }));
  const installed = run.steps.filter((s) => completionOf(s) === "installed").map((s) => s.node_name || s.node_id);
  return (
    <Alert
      type="warning"
      showIcon
      style={{ marginBottom: 8 }}
      data-testid="deploy-partial"
      message={`运行已结束，但没有全部完成：${skipped.length} 个节点被跳过、仍待处理${waiting.length > 0 ? `，${waiting.length} 个节点因依赖它们没有安装` : ""}`}
      description={
        <>
          {installed.length > 0 ? <div>在这次运行中安装并通过健康检查：{installed.join("、")}</div> : null}
          <div data-testid="deploy-partial-skipped">
            跳过（没有安装，也没有采纳）：
            <ul style={{ margin: 0, paddingLeft: 18 }}>
              {skipped.map((x) => (
                <li key={x.node_id} style={{ overflowWrap: "anywhere" }}>
                  <Typography.Text strong>{x.node_name || x.node_id}</Typography.Text>（{SKIP_KIND[x.kind] ?? x.kind}）：{x.reason}
                </li>
              ))}
            </ul>
          </div>
          {waiting.length > 0 ? (
            <div data-testid="deploy-partial-waiting">
              依赖被跳过的节点、没有安装：{waiting.map((x) => `${x.node_name || x.node_id}（等 ${x.waits_for.join("、")}）`).join("；")}
            </div>
          ) : null}
          <div>在下面的表里点「回到这一台」继续处理它们；也可以之后开始新的引导。</div>
        </>
      }
    />
  );
}

/** The current step's skip action: the reason it cannot go on, and what would still wait. */
function SkipOffer({ run, st, busy, onSkip }: { run: DeployRun; st: DeployStep; busy: string | false; onSkip: () => void }) {
  if (!st.can_skip) return null;
  const holds = namesOf(run, st.skip_holds);
  return (
    <div data-testid="deploy-skip-offer" data-prose-exempt style={{ marginTop: 8, padding: "8px 12px", border: "1px dashed var(--m-border)", borderRadius: 6, overflowWrap: "anywhere" }}>
      <Typography.Paragraph style={{ marginBottom: 4 }}>
        {st.phase === "blocked" ? "这一台的预检有阻断项" : (st.wait_seconds ?? 0) > 0 ? "这台服务器在限速等待" : "这台服务器连不上或登录不了（没有执行任何操作）"}
        ：可以先跳过它，继续不依赖它的节点（跳过的保持待处理，之后可以回到它）。
      </Typography.Paragraph>
      <Typography.Paragraph data-testid="deploy-skip-holds" style={{ marginBottom: 4 }}>
        {holds ? `依赖它、会继续等待的：${holds}` : "没有节点依赖它。"}
      </Typography.Paragraph>
      <Button onClick={onSkip} loading={busy === "skip"} disabled={!!busy || !!run.in_flight} data-testid="deploy-skip">
        跳过这一台，继续其余节点
      </Button>
    </div>
  );
}

/** The current step: its preflight, the review and the confirmation. */
function CurrentStep({
  run,
  st,
  busy,
  onPreflight,
  onInstall,
  onSkip,
}: {
  run: DeployRun;
  st: DeployStep;
  busy: string | false;
  onPreflight: () => void;
  onInstall: () => void;
  onSkip: () => void;
}) {
  const wait = useCountdown(st.wait_seconds, `${st.node_id}:${st.retry_at ?? ""}`);
  const retry = st.phase === "failed" || st.phase === "unknown";
  const pfLabel = retry ? "重新核对（预检，读取实际安装记录）" : st.phase === "pending" ? "预检" : "重新预检";
  const what = st.kind === "gateway" ? "安装到网关" : `下发到 ${st.node_name || st.node_id}`;
  return (
    <div data-testid="deploy-current" style={{ marginTop: 12 }}>
      <Typography.Title level={3} style={{ marginTop: 0 }}>
        第 {st.position} 步：{st.node_name || st.node_id} <span className="muted">{roleText(st.role)}</span>
        <PhaseTag st={st} plain />
      </Typography.Title>
      {st.message ? <Typography.Paragraph data-prose-exempt data-testid="deploy-step-message">{st.message}</Typography.Paragraph> : null}
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
        <Note testId="deploy-retry-note">
          重试前先重新核对：预检会读取这个节点实际的安装记录（远端是服务器上的清单和 journal，网关是安装清单）。内容已经装上就直接采纳，不会重做；否则审阅新的预检结果后由你再次确认。有残留或中断的装机时，到下面「远端节点」里用预检对话框提供的恢复操作处理。
        </Note>
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
      <SkipOffer run={run} st={st} busy={busy} onSkip={onSkip} />
      {run.preflight && (st.phase === "review" || st.phase === "blocked") ? (
        // In its own (open) panel: the report's per-finding alerts belong to
        // it, not to the guide's section (one primary alert per section).
        <Collapse
          size="small"
          style={{ marginTop: 12 }}
          defaultActiveKey={["review"]}
          items={[
            {
              key: "review",
              label: st.phase === "blocked" ? "预检结果：阻断项与处理办法" : "预检结果：要做的变更和冲突",
              children: (
                <div data-testid="deploy-review">
                  <ErrorBoundary>
                    <PreflightReport rec={run.preflight} />
                  </ErrorBoundary>
                </div>
              ),
            },
          ]}
        />
      ) : null}
    </div>
  );
}

function RunView({
  view,
  busy,
  onPreflight,
  onInstall,
  onVerify,
  onVerifyAll,
  onReplan,
  onCancel,
  onNew,
  onSkip,
  onUnskip,
}: {
  view: DeployView;
  busy: string | false;
  onPreflight: (st: DeployStep) => void;
  onInstall: (st: DeployStep) => void;
  onSkip: (st: DeployStep) => void;
  onUnskip: (st: DeployStep) => void;
  onVerify: (st: DeployStep) => void;
  onVerifyAll: () => void;
  onReplan: () => void;
  onCancel: () => void;
  onNew: () => void;
}) {
  const run = view.run!;
  const rs = RUN_STATE[run.state] ?? { kind: "neutral" as StatusKind, label: run.state };
  const open = run.state === "active" || run.state === "stopped";
  const cur = run.steps.find((s) => s.node_id === run.current);
  const done = run.steps.filter((s) => s.phase === "done").length;
  const installSteps = run.steps.filter((s) => !s.verify_only);
  const verifySteps = run.steps.filter((s) => s.verify_only);
  return (
    <div data-testid="deploy-run">
      <Space wrap style={{ marginBottom: 8 }}>
        <span data-testid="deploy-run-state" data-state={run.state}>
          <StatusTag kind={rs.kind}>{rs.label}</StatusTag>
        </span>
        <Typography.Text type="secondary">
          {done} / {run.steps.length} 已完成 · 开始于 <TimeText value={run.created_at} />
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
      {run.state === "done" ? <DoneSummary run={run} /> : null}
      {run.state === "partial" ? <PartialSummary run={run} /> : null}
      {installSteps.length > 0 && verifySteps.length > 0 ? (
        <Typography.Title level={3} style={{ marginTop: 0 }}>
          按顺序安装（{installSteps.length}）
        </Typography.Title>
      ) : null}
      <DataTable
        size="small"
        rowKey="node_id"
        pageSize={50}
        dataSource={installSteps}
        onRow={(s) => ({ "data-testid": `deploy-step-${s.node_id}` }) as React.HTMLAttributes<HTMLElement>}
        columns={[
          { title: "#", kind: "fixed", width: 48, render: (_, s) => s.position },
          {
            title: "节点",
            kind: "flex",
            width: 200,
            card: "title",
            render: (_, s) => (
              <Space size={4} wrap>
                <Typography.Text strong={s.current}>{s.node_name || s.node_id}</Typography.Text>
                <span className="muted">{roleText(s.role)}</span>
              </Space>
            ),
          },
          { title: "状态", kind: "flex", width: 210, render: (_, s) => <PhaseTag st={s} /> },
          {
            title: "说明",
            kind: "flex",
            width: 320,
            render: (_, s) => (
              <>
                <span>{s.outcome && s.outcome !== "not_started" ? (OUTCOME[s.outcome] ?? s.outcome) : s.reason}</span>
                {s.verify_diff ? (
                  <div data-testid={`deploy-verify-diff-${s.node_id}`}>
                    <StatusTag kind="attention">核对发现记录不同</StatusTag>
                    <Note inline>{s.verify_diff}：原来只需核对，现在按顺序安装，轮到它时要你确认</Note>
                  </div>
                ) : null}
                {s.skip ? (
                  <div data-testid={`deploy-skipped-${s.node_id}`} style={{ overflowWrap: "anywhere" }}>
                    <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                      跳过（{SKIP_KIND[s.skip.kind] ?? s.skip.kind}）：{s.skip.reason}
                    </Typography.Text>
                    {s.can_unskip ? (
                      <div>
                        <Button size="small" onClick={() => onUnskip(s)} loading={busy === `unskip:${s.node_id}`} disabled={!!busy || !!run.in_flight} data-testid={`deploy-unskip-${s.node_id}`}>
                          回到这一台
                        </Button>
                      </div>
                    ) : null}
                  </div>
                ) : null}
                {s.waiting_for && s.waiting_for.length > 0 ? (
                  <div data-testid={`deploy-waiting-${s.node_id}`}>
                    <Note inline>等 {namesOf(run, s.waiting_for)}（已跳过）：它依赖被跳过的节点，那台装好之前不会轮到它</Note>
                  </div>
                ) : null}
                {s.phase === "done" ? <HealthView st={s} /> : <Warnings items={s.current ? s.warnings : undefined} />}
              </>
            ),
          },
        ]}
      />
      {open && cur ? (
        <ErrorBoundary>
          <CurrentStep run={run} st={cur} busy={busy} onPreflight={() => onPreflight(cur)} onInstall={() => onInstall(cur)} onSkip={() => onSkip(cur)} />
        </ErrorBoundary>
      ) : null}
      <VerifyGroup steps={verifySteps} busy={busy} disabled={!open || run.stale || !!run.in_flight} onVerify={onVerify} onVerifyAll={onVerifyAll} />
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
                      <TimeText value={e.at} /> {e.node ? <span className="muted">{e.node}</span> : null}
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
/** Managed nodes without a link: shown whatever the plan says (it may be invalid). */
export function NodeBlockers({ blockers }: { blockers?: PreflightFinding[] }) {
  const list = (blockers ?? []).filter((b) => b && b.message);
  if (list.length === 0) return null;
  return (
    <Space direction="vertical" style={{ width: "100%", marginBottom: 12 }} data-testid="node-blockers">
      {list.map((b, i) => (
        <Alert
          key={`${b.resource ?? ""}-${i}`}
          type="error"
          showIcon
          message={
            <span>
              {b.resource ? <Typography.Text code>{b.resource}</Typography.Text> : null} {b.message}{" "}
              <a href={href("topology")}>去拓扑</a>
            </span>
          }
        />
      ))}
    </Space>
  );
}

export function DeploymentGuide({ onChanged, header, onLinkChanged }: { onChanged?: () => void; header?: ReactNode; onLinkChanged?: (changes: MTUChange[]) => void }) {
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
  const verifyOne = (st: DeployStep) => act.run(async () => apply(await api.deployVerify(run!.id, { nodeId: st.node_id })), `verify:${st.node_id}`, refusal);
  const verifyAll = () => act.run(async () => apply(await api.deployVerify(run!.id, "all")), "verify-all", refusal);
  const skip = (st: DeployStep) => {
    const holds = namesOf(run!, st.skip_holds);
    confirm({
      title: `跳过 ${st.node_name || st.node_id}，继续其余节点？`,
      consequence: (
        <div data-testid="deploy-skip-confirm">
          <p>这一台这次不安装：它保持「待处理」，不算完成，也不采纳，会列在这次运行的总结里；之后可以「回到这一台」。不会连接它，也不会改动它。</p>
          <p>{holds ? `依赖它、会继续等待的节点：${holds}。` : "没有节点依赖它。"}其余不依赖它的节点按顺序继续，每台仍要你单独确认。</p>
        </div>
      ),
      okText: "跳过这一台",
      danger: false,
      onOk: () => act.run(async () => apply(await api.deploySkip(run!.id, st.node_id)), "skip", refusal),
    });
  };
  const unskip = (st: DeployStep) => act.run(async () => apply(await api.deployUnskip(run!.id, st.node_id)), `unskip:${st.node_id}`, refusal);
  const cancel = () =>
    confirm({
      title: "取消这次部署引导？",
      consequence: "已经装好的节点保持不变，不会撤回任何东西；没装的节点留在「有待下发的变更」。之后可以开始新的引导。",
      okText: "取消引导",
      onOk: () => act.run(async () => apply(await api.deployCancel(run!.id)), "cancel", refusal),
    });

  const open = run && (run.state === "active" || run.state === "stopped");
  const autoReady = !!(open || view?.plan?.steps.length);
  return (
    <Section title="按顺序部署待变更节点" id="guide">
      <div data-testid="deploy-guide">
        {header}
        <Note>{"可逐台确认，或启动自动检测并部署。"}{" "}
          顺序：挂在中继出口后面的出口 → 出口 → 备用枢纽 → 主枢纽 → 中继 → 网关；管理通道经过别的节点时，被经过的节点排在后面。每一步都是下面「远端节点」和「安装到本机」里的同一套预检和下发，只是按顺序串起来。只需核对、不会安装任何东西的节点单独列出，不受这个顺序约束。一台被预检阻断或连不上时，可以跳过它继续不依赖它的节点（同层的出口、其它中继）；依赖它的节点（它后面的枢纽、中继和网关，它转发的中继出口，经它管理的节点）继续等待。结果不明或失败的一步不能跳过，要先重新核对。
        </Note>
        <Button disabled={!view || !autoReady || !!act.busy || inFlight} loading={act.busy === "auto"} onClick={() => confirm({
          title: "自动预检并部署待变更节点？",
          consequence: "按当前部署计划依次预检和下发，可能短暂中断相关路径。必要时会采用预检支持的较低 MTU。若预检阻断、拓扑变化或下发失败，将停在对应节点。",
          okText: "开始自动部署",
          onOk: () => act.run(() => deployPendingNodes(apply, onLinkChanged), "auto", () => void state.reload()),
        })}>自动检测并部署</Button>
        {view && !autoReady ? <Typography.Text type="secondary" style={{ marginInlineStart: 8 }}>当前没有待部署节点</Typography.Text> : null}
        <ApiErrorAlert error={act.error} onClose={act.clear} />
        <DataView state={state} rows={4}>
          {(v) => (
            <>
              <NodeBlockers blockers={v.node_blockers} />
              <Limits limits={v.limits} />
              {v.run && (open || !showPlan) ? (
                <RunView
                  view={v}
                  busy={act.busy}
                  onPreflight={preflight}
                  onInstall={install}
                  onVerify={verifyOne}
                  onVerifyAll={verifyAll}
                  onReplan={replan}
                  onCancel={cancel}
                  onNew={() => setShowPlan(true)}
                  onSkip={skip}
                  onUnskip={unskip}
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
