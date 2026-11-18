// The guide's verify-only steps: nodes whose panel record already matches
// and whose host record was only never read back. They install nothing and
// are not part of the install order: each can be verified on its own, or
// all at once ("全部核对"), whatever the install steps are doing. The
// server still verifies one host at a time, one login each, and does not
// contact a host inside its rate-limit wait (deploy_verify.go).

import { Alert, Button, Space, Typography } from "antd";
import { useEffect, useState } from "react";
import type { DeployStep, DeployVerifyState } from "./types";
import { roleLabel } from "./types";
import {
  DataTable,
  StatusTag,
  type StatusKind,
  Note,
} from "./ui";

const VERIFY_STATE: Record<DeployVerifyState, { kind: StatusKind; label: string }> = {
  pending: { kind: "neutral", label: "待核对" },
  verifying: { kind: "running", label: "核对中" },
  verified: {
    kind: "unverified",
    label: "已核对 · 采纳记录（未重新检查健康）",
  },
  unreachable: { kind: "failed", label: "连不上" },
  waiting: { kind: "attention", label: "限速等待" },
  differs: { kind: "attention", label: "记录不同 · 改为按顺序安装" },
};

const roleText = (r: string) => (roleLabel as Record<string, string>)[r] ?? r;

/** The verify state of a step (old servers without the field: from the phase). */
export function verifyStateOf(st: DeployStep): DeployVerifyState {
  if (st.verify_state) return st.verify_state;
  if (st.phase === "done") return "verified";
  if (st.phase === "preflighting") return "verifying";
  if ((st.wait_seconds ?? 0) > 0) return "waiting";
  return st.outcome === "not_started" ? "unreachable" : "pending";
}

/** Seconds left of a rate-limit wait, counting down from the fetch. */
function WaitLeft({ seconds }: { seconds: number }) {
  const [start] = useState(() => Date.now());
  const [, tick] = useState(0);
  const left = Math.max(0, seconds - Math.floor((Date.now() - start) / 1000));
  useEffect(() => {
    if (left <= 0) return;
    const t = setTimeout(() => tick((x) => x + 1), 1000);
    return () => clearTimeout(t);
  }, [left]);
  return <span data-testid="verify-wait-left">{left > 0 ? `${left} 秒后可以再核对；在那之前面板不会连接这台服务器` : "等待已结束，可以再核对"}</span>;
}

function Detail({ st }: { st: DeployStep }) {
  const vs = verifyStateOf(st);
  if (vs === "verified") return <span>{st.health?.detail ?? st.message ?? "服务器上的记录就是这份内容：采纳，没有安装任何东西"}</span>;
  if (vs === "waiting")
    return (
      <span>
        服务器暂时拒绝面板的来源地址（限速）：
        <WaitLeft seconds={st.wait_seconds ?? 0} />
      </span>
    );
  if (vs === "unreachable")
    return (
      <span>
        <span style={{ overflowWrap: "anywhere" }}>{st.message || "没有连上这台服务器"}</span>
        {st.path_note ? (
          <Typography.Text type="secondary" style={{ display: "block", fontSize: 12 }} data-testid={`verify-path-note-${st.node_id}`}>
            {st.path_note}
          </Typography.Text>
        ) : null}
        <Note inline>没有执行任何操作；它不挡住其它节点。面板不会自动重试，也不会改走别的管理通道。</Note>
      </span>
    );
  return <span>{st.reason}</span>;
}

/**
 * The verify-only group of a run. `onVerify(node)` verifies one step,
 * `onVerifyAll()` every one not done yet (the server runs them one by one).
 */
export function VerifyGroup({
  steps,
  busy,
  disabled,
  onVerify,
  onVerifyAll,
}: {
  steps: DeployStep[];
  busy: string | false;
  /** The run cannot act now (stale plan, a step in flight, closed run). */
  disabled?: boolean;
  onVerify: (st: DeployStep) => void;
  onVerifyAll: () => void;
}) {
  if (steps.length === 0) return null;
  const states = steps.map(verifyStateOf);
  const count = (s: DeployVerifyState) => states.filter((x) => x === s).length;
  const open = steps.filter((s) => s.phase !== "done");
  const canAll = !disabled && !busy && open.some((s) => s.can_verify);
  const unreachable = count("unreachable");
  const waiting = count("waiting");
  return (
    <div data-testid="deploy-verify-group" style={{ marginTop: 16 }}>
      <Space
        wrap
        style={{
          justifyContent: "space-between",
          width: "100%",
          marginBottom: 8,
        }}
      >
        <Typography.Title level={3} style={{ margin: 0 }}>
          只需核对（{steps.length}）
        </Typography.Title>
        <Button onClick={onVerifyAll} disabled={!canAll} loading={busy === "verify-all"} data-testid="deploy-verify-all">
          全部核对
        </Button>
      </Space>
      <Note>{"不安装任何东西，不受安装顺序约束；一台连不上不挡住其它。"}{" "}
        这些节点在面板的记录里已经是这份内容，只是没有读回服务器上的安装记录。核对只读服务器上的清单：内容在就采纳（没有重新执行，也没有重新检查健康）；记录不同就变成按顺序安装的一步，轮到它时要你审阅预检并确认。全部核对时面板一台一台连接，每台一次登录，处在限速等待里的服务器不会被连接，也不会自动重试。核对结果只对这次计划、这个节点、这台服务器和它固定的主机指纹有效。
      </Note>
      {unreachable + waiting > 0 ? (
        <Alert
          type="warning"
          showIcon
          style={{ margin: "8px 0" }}
          data-testid="deploy-verify-alert"
          message={`已核对 ${count("verified")} 台；${unreachable} 台连不上、${waiting} 台在限速等待：它们不影响其它节点，可以稍后单独再核对`}
        />
      ) : null}
      <DataTable
        size="small"
        rowKey="node_id"
        pageSize={50}
        dataSource={steps}
        onRow={(s) =>
          ({
            "data-testid": `deploy-verify-${s.node_id}`,
          }) as React.HTMLAttributes<HTMLElement>
        }
        columns={[
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
          {
            title: "核对",
            kind: "flex",
            width: 200,
            render: (_, s) => {
              const v = VERIFY_STATE[verifyStateOf(s)];
              return (
                <span data-testid={`deploy-verify-state-${s.node_id}`} data-verify={verifyStateOf(s)}>
                  <StatusTag kind={v.kind}>{v.label}</StatusTag>
                </span>
              );
            },
          },
          {
            title: "说明",
            kind: "flex",
            width: 320,
            render: (_, s) => <Detail st={s} />,
          },
          {
            title: "操作",
            kind: "actions",
            width: 96,
            render: (_, s) =>
              s.phase === "done" ? null : (
                <Button
                  size="small"
                  onClick={() => onVerify(s)}
                  disabled={disabled || !!busy || !s.can_verify}
                  loading={busy === `verify:${s.node_id}` || s.phase === "preflighting"}
                  data-testid={`deploy-verify-one-${s.node_id}`}
                >
                  核对
                </Button>
              ),
          },
        ]}
      />
    </div>
  );
}
