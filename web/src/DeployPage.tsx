// 部署: the operations centre. What an install would change, installing to
// this gateway (one transaction, compensated on failure), rolling back,
// pushing configuration to remote nodes over SSH, and what is installed now.
// Nothing here calls anything verified: an install proves activation and
// health checks, not routing, leak protection or unlocking.

import {
  CloudUploadOutlined,
  EllipsisOutlined,
  EyeOutlined,
  KeyOutlined,
  ReloadOutlined,
  RollbackOutlined,
  SendOutlined,
  ToolOutlined,
} from "@ant-design/icons";
import { Alert, App as AntApp, Button, Collapse, Dropdown, Empty, Modal, Radio, Space, Table, Tag, Tooltip, Typography } from "antd";
import { useEffect, useMemo, useState, type ReactNode } from "react";
import * as api from "./api";
import type { ApiError } from "./api";
import { serverReadiness } from "./ServersPage";
import { href, useRouter, useStatus, useTopologyDoc } from "./state";
import { LoginHelpView, PreflightReport, loginHelpOf, preflightBlockedReason, preflightOf } from "./Preflight";
import type {
  ApplyResult,
  HostReport,
  HostStatus,
  InstalledDiff,
  Issue,
  Node,
  PreflightRecord,
  ProvisionResult,
  ServerView,
  SysctlReport,
  SysctlState,
  WithdrawMode,
} from "./types";
import { DeploymentRecords, GatewayWithdraw, WithdrawDialog } from "./Withdraw";
import { roleLabel } from "./types";
import {
  TABLE_SCROLL,
  ApiErrorAlert,
  CopyButton,
  DataView,
  Facts,
  IssueList,
  Link,
  Mono,
  Page,
  Section,
  StatusTag,
  TimeText,
  useAction,
  useApi,
  errorTitle,
  useConfirmDanger,
  type StatusKind,
  noteRateLimited,
  retryAfterOf,
  useCooldowns,
} from "./ui";

// -------------------------------------------------------------- the diff ---

interface FileDiff {
  path: string;
  node: string;
  file: string;
  status: "added" | "removed" | "changed";
  lines: string[];
  plus: number;
  minus: number;
}

const NO_CHANGE = "（没有变化）";

export function parseDiff(text: string): FileDiff[] {
  if (text.trim() === NO_CHANGE || !text.trim()) return [];
  const out: FileDiff[] = [];
  let cur: FileDiff | null = null;
  for (const line of text.split("\n")) {
    const m = line.match(/^===== (.+) \((added|removed|changed)\) =====$/);
    if (m) {
      const path = m[1];
      const seg = path.split("/");
      const node = seg[0] === "nodes" && seg.length > 2 ? seg[1] : "";
      cur = { path, node, file: node ? seg.slice(2).join("/") : path, status: m[2] as FileDiff["status"], lines: [], plus: 0, minus: 0 };
      out.push(cur);
      continue;
    }
    if (!cur) continue;
    cur.lines.push(line);
    if (line.startsWith("+")) cur.plus++;
    else if (line.startsWith("-")) cur.minus++;
  }
  return out;
}

/** Changed lines with 3 lines of context; long unchanged runs collapse. */
function DiffBody({ lines }: { lines: string[] }) {
  const ctx = 3;
  const keep = lines.map((l) => l.startsWith("+") || l.startsWith("-"));
  const show = lines.map((_, i) => {
    for (let k = Math.max(0, i - ctx); k <= Math.min(lines.length - 1, i + ctx); k++) if (keep[k]) return true;
    return false;
  });
  const rows: ReactNode[] = [];
  let skipped = 0;
  lines.forEach((l, i) => {
    if (!show[i]) {
      skipped++;
      return;
    }
    if (skipped) {
      rows.push(
        <div key={`s${i}`} className="diff-skip">
          … {skipped} 行未改动
        </div>,
      );
      skipped = 0;
    }
    rows.push(
      <div key={i} className={l.startsWith("+") ? "diff-add" : l.startsWith("-") ? "diff-del" : "diff-ctx"}>
        {l || " "}
      </div>,
    );
  });
  if (skipped) rows.push(<div key="end" className="diff-skip">… {skipped} 行未改动</div>);
  return <div className="diff diff-lines">{rows}</div>;
}

const FILE_STATUS: Record<FileDiff["status"], { label: string; color: string }> = {
  added: { label: "新增", color: "green" },
  removed: { label: "删除", color: "red" },
  changed: { label: "修改", color: "blue" },
};

function PendingChanges({ nodeName }: { nodeName: (id: string) => string }) {
  const { install, status } = useStatus();
  const diff = useApi(() => api.diff(), [install.kind]);
  const files = useMemo(() => (diff.data ? parseDiff(diff.data.diff) : []), [diff.data]);
  const byNode = useMemo(() => {
    const m = new Map<string, FileDiff[]>();
    for (const f of files) m.set(f.node, [...(m.get(f.node) ?? []), f]);
    return [...m.entries()].sort(([a], [b]) => (a === "gw" ? -1 : b === "gw" ? 1 : a.localeCompare(b)));
  }, [files]);

  if (install.kind === "error") {
    const issues: Issue[] = status?.install.issues ?? [];
    const lan = issues.find((i) => i.code === "lan_interface_mismatch");
    return (
      <Section title="待安装的改动">
        <Alert
          type="error"
          showIcon
          style={{ marginBottom: 12 }}
          message="拓扑现在无法编译，不能安装"
          description={
            <span>
              存储的拓扑带着错误（保存为草稿）。在 <Link to={href("topology")}>拓扑</Link> 或 <Link to={href("rules")}>分流规则</Link> 页改正后保存，再回来安装。
            </span>
          }
        />
        {lan ? (
          <Alert
            type="warning"
            showIcon
            style={{ marginBottom: 12 }}
            message="网关的局域网接口不一致"
            description={
              <span>
                {lan.message} 在 <Link to={href("topology", lan.node_id)}>网关节点</Link> 上改，或者在拓扑页的「网关设置」里改。
              </span>
            }
          />
        ) : null}
        <IssueList issues={issues.filter((i) => i !== lan)} />
      </Section>
    );
  }

  return (
    <Section
      title="待安装的改动"
      extra={
        <Button size="small" icon={<ReloadOutlined />} loading={diff.loading} onClick={() => void diff.reload()}>
          重新比较
        </Button>
      }
    >
      <Typography.Paragraph type="secondary">
        存储的拓扑编译出的文件与上一次应用的版本逐文件比较。密钥只以占位符出现，真实私钥只在写入宿主时注入。
      </Typography.Paragraph>
      {install.kind === "changed" && install.appliedOnly ? (
        <Alert
          type="warning"
          showIcon
          style={{ marginBottom: 12 }}
          message={`改动已写入数据目录，但网关上运行的仍是 v${install.version ?? "?"}`}
          description="逐行差分只和上一次「应用」的版本比，那一份已经包含这些改动，所以逐行看没有变化。下面列出的是安装会让网关上哪些文件新增、修改或删除（按已安装清单里的文件哈希比较）；这种情况下看不到逐行内容。"
        />
      ) : null}
      {install.kind === "unknown" ? (
        <Alert
          type="info"
          showIcon
          style={{ marginBottom: 12 }}
          message="网关上的安装是从旧版本接管的，没有内容摘要，无法判断是否与当前拓扑一致"
          description="安装一次之后就能比较。"
        />
      ) : null}
      <DataView state={diff} rows={3}>
        {(d) =>
          files.length === 0 && install.kind === "changed" && d.installed && installedCount(d.installed) > 0 ? (
            <InstalledChanges diff={d.installed} version={install.version} />
          ) : files.length === 0 ? (
            <Empty
              image={Empty.PRESENTED_IMAGE_SIMPLE}
              description={
                install.kind === "not_installed"
                  ? "和上一次应用的版本相比没有文件变化；网关上还什么都没装。"
                  : install.kind === "in_sync"
                    ? "没有待安装的改动，网关上的安装和存储的拓扑一致。"
                    : "和上一次应用的版本相比没有文件变化。"
              }
            />
          ) : (
            <div data-testid="pending-diff">
              <Typography.Paragraph>
                共 {files.length} 个文件，涉及 {byNode.length} 个节点。安装只写网关（本机）的文件；远端节点的文件在下面「远端节点」里下发。
              </Typography.Paragraph>
              <Collapse
                size="small"
                items={byNode.map(([node, list]) => ({
                  key: node || "_",
                  label: (
                    <Space size={6} wrap>
                      <Typography.Text strong>{node ? nodeName(node) : "其他"}</Typography.Text>
                      {node ? <span className="mono-small muted">{node}</span> : null}
                      {node === "gw" ? <Tag color="processing">本机安装</Tag> : node ? <Tag>远端下发</Tag> : null}
                      <Typography.Text type="secondary">{list.length} 个文件</Typography.Text>
                    </Space>
                  ),
                  children: (
                    <Collapse
                      size="small"
                      ghost
                      items={list.map((f) => ({
                        key: f.path,
                        label: (
                          <Space size={6} wrap>
                            <Tag color={FILE_STATUS[f.status].color}>{FILE_STATUS[f.status].label}</Tag>
                            <span className="mono">{f.file}</span>
                            <span className="diff-count">
                              <span className="add">+{f.plus}</span> <span className="del">−{f.minus}</span>
                            </span>
                          </Space>
                        ),
                        children: <DiffBody lines={f.lines} />,
                      }))}
                    />
                  ),
                }))}
              />
            </div>
          )
        }
      </DataView>
    </Section>
  );
}

/** Files and resources an install would change, by the installed manifest's hashes. */
function installedCount(d: InstalledDiff) {
  return (d.files_added?.length ?? 0) + (d.files_changed?.length ?? 0) + (d.files_removed?.length ?? 0);
}

function InstalledChanges({ diff, version }: { diff: InstalledDiff; version: number | null }) {
  const rows: { path: string; status: FileDiff["status"] }[] = [
    ...(diff.files_added ?? []).map((path) => ({ path, status: "added" as const })),
    ...(diff.files_changed ?? []).map((path) => ({ path, status: "changed" as const })),
    ...(diff.files_removed ?? []).map((path) => ({ path, status: "removed" as const })),
  ].sort((a, b) => a.path.localeCompare(b.path));
  const res = DIFF_LABEL.filter(([k]) => !k.startsWith("files_"))
    .map(([k, label]) => [label, (diff[k as keyof InstalledDiff] ?? []) as (string | number)[]] as const)
    .filter(([, v]) => v.length > 0);
  return (
    <div data-testid="installed-diff">
      <Typography.Paragraph>
        安装会改动网关上的 {rows.length} 个文件（与已安装的 v{version ?? "?"} 按文件哈希比较，没有逐行内容）：
      </Typography.Paragraph>
      <ul className="installed-files">
        {rows.map((r) => (
          <li key={r.path}>
            <Tag color={FILE_STATUS[r.status].color}>{FILE_STATUS[r.status].label}</Tag>
            <span className="mono-small">/{r.path}</span>
          </li>
        ))}
      </ul>
      {res.length > 0 ? <Facts items={res.map(([label, v]) => [label, <span key={label} className="mono-small">{v.join("  ")}</span>])} /> : null}
    </div>
  );
}

// ------------------------------------------------------------ host report ---

const DIFF_LABEL: [string, string][] = [
  ["files_added", "新增文件"],
  ["files_changed", "修改文件"],
  ["files_removed", "删除文件"],
  ["interfaces_added", "新增接口"],
  ["interfaces_removed", "删除接口"],
  ["units_added", "新增服务"],
  ["units_removed", "删除服务"],
  ["nft_tables_added", "新增 nft 表"],
  ["nft_tables_removed", "删除 nft 表"],
  ["route_tables_added", "新增路由表"],
  ["route_tables_removed", "删除路由表"],
];

const SYSCTL_STATE: Record<SysctlState, { label: string; kind: StatusKind }> = {
  in_effect: { label: "已生效", kind: "ok" },
  differs: { label: "未生效：值不同", kind: "failed" },
  missing: { label: "内核没有这个参数", kind: "failed" },
  boot_only: { label: "开机值（运行时由 forwarding.conf 打开）", kind: "neutral" },
  stale: { label: "已从文件删除，内核保留到重启", kind: "attention" },
  not_checked: { label: "没有读取内核", kind: "neutral" },
};

/**
 * The managed sysctl files after an install: what was written (the whole
 * file, every install), what the kernel has now, and lines of the previous
 * file that are gone from the file but still in the running kernel.
 */
function SysctlView({ rep }: { rep: SysctlReport }) {
  const count = (st: SysctlState) => rep.written.filter((e) => e.state === st).length;
  const shown = [...rep.written.filter((e) => e.state === "differs" || e.state === "missing"), ...(rep.removed ?? [])];
  return (
    <div style={{ marginTop: 12 }} data-testid="sysctl-report">
      <Typography.Text type="secondary">内核参数（/etc/sysctl.d/99-meridian.conf 与 /etc/meridian/forwarding.conf，每次安装整份重写）</Typography.Text>
      <div>
        {rep.checked ? (
          <Space size={6} wrap>
            <span>写入 {rep.written.length} 项</span>
            <StatusTag kind="ok">已生效 {count("in_effect")}</StatusTag>
            {rep.problems > 0 ? <StatusTag kind="failed">未生效 {rep.problems}</StatusTag> : null}
            {count("boot_only") > 0 ? <StatusTag kind="neutral">开机值 {count("boot_only")}</StatusTag> : null}
            {(rep.removed ?? []).length > 0 ? <StatusTag kind="attention">旧文件遗留 {rep.removed!.length}</StatusTag> : null}
          </Space>
        ) : (
          <Typography.Text type="secondary">文件已写入 {rep.written.length} 项；没有读取运行中的内核{rep.reason ? `（${rep.reason}）` : ""}，不判断是否生效。</Typography.Text>
        )}
      </div>
      {shown.length > 0 ? (
        <ul className="ref-list" data-testid="sysctl-problems">
          {shown.map((e) => (
            <li key={`${e.state}|${e.file}|${e.key}`}>
              <span className="mono-small">{e.key}</span> <StatusTag kind={SYSCTL_STATE[e.state].kind}>{SYSCTL_STATE[e.state].label}</StatusTag>{" "}
              <Typography.Text type="secondary">
                {e.state === "stale" ? `旧文件写的是 ${e.want ?? "?"}，内核现在 ${e.got ?? "读不到"}` : `文件 ${e.want ?? "?"}，内核 ${e.got ?? "读不到"}`}
              </Typography.Text>
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}

export function HostReportView({ report, failed }: { report: HostReport; failed?: boolean }) {
  const diffs = DIFF_LABEL.map(([k, label]) => [label, (report.diff?.[k] ?? []) as (string | number)[]] as const).filter(([, v]) => v.length > 0);
  const firstFail = report.steps?.findIndex((s) => !s.ok) ?? -1;
  return (
    <div className="host-report" data-testid="host-report">
      <Space size={6} wrap style={{ marginBottom: 8 }}>
        <Typography.Text type="secondary">事务</Typography.Text>
        <Mono>{report.transaction}</Mono>
        <Typography.Text type="secondary">
          v{report.from_version} → v{report.to_version}
        </Typography.Text>
        {report.committed ? (
          <StatusTag kind="ok">已提交</StatusTag>
        ) : report.compensated ? (
          <StatusTag kind="attention">已补偿回安装前</StatusTag>
        ) : failed ? (
          <StatusTag kind="failed">未完成</StatusTag>
        ) : null}
      </Space>
      {report.steps && report.steps.length > 0 ? (
        <ol className="txn-steps" data-testid="txn-steps">
          {report.steps.map((s, i) => (
            <li key={i} className={!s.ok ? "failed" : s.skipped ? "skipped" : "ok"} data-step-status={!s.ok ? "failed" : s.skipped ? "skipped" : "ok"}>
              <StatusTag kind={!s.ok ? "failed" : s.skipped ? "neutral" : "ok"}>{!s.ok ? "失败" : s.skipped ? "跳过" : "完成"}</StatusTag>
              <span className="mono">{s.name}</span>
              {s.detail ? <div className="muted step-detail">{s.detail}</div> : null}
              {i === firstFail ? <div className="step-first-fail">从这一步开始失败</div> : null}
            </li>
          ))}
        </ol>
      ) : (
        <Typography.Text type="secondary">宿主没有返回步骤。</Typography.Text>
      )}
      {(report.warnings ?? []).map((w) => (
        <Alert key={w} type="warning" showIcon style={{ marginTop: 8 }} message={w} />
      ))}
      {report.sysctl ? <SysctlView rep={report.sysctl} /> : null}
      {diffs.length > 0 ? (
        <div style={{ marginTop: 12 }}>
          <Typography.Text type="secondary">{report.committed ? "这次改变的资源" : "这次本来要改变的资源"}</Typography.Text>
          <Facts items={diffs.map(([label, v]) => [label, <span key={label} className="mono-small">{v.join("  ")}</span>])} />
        </div>
      ) : null}
    </div>
  );
}

// ------------------------------------------------------------- install ---

interface PeerKeyProblem {
  peer: string;
  file?: string;
  problem?: string;
}

/** Where a peer without a public key is fixed: its row in 远端节点 (managed) or the topology. */
function scrollToRemote(id: string) {
  const row = document.querySelector(`[data-testid="remote-node-${CSS.escape(id)}"]`) as HTMLElement | null;
  row?.scrollIntoView?.({ behavior: "smooth", block: "center" });
  row?.classList.add("row-flash");
  window.setTimeout(() => row?.classList.remove("row-flash"), 2000);
}

/**
 * Explains an install/rollback refusal or failure in operator terms. It
 * decides on the API's machine code (internal/api/server.go), never on the
 * message text.
 */
function TxnFailure({
  error,
  nodes,
  onRecover,
  recovering,
}: {
  error: ApiError;
  nodes: Node[];
  onRecover: () => void;
  recovering: boolean;
}) {
  const body = error.body as { host?: HostReport | null; compensated?: boolean; peer_key_problems?: PeerKeyProblem[]; issues?: Issue[] };
  const node = (id: string) => nodes.find((n) => n.id === id);
  const pf = preflightOf(error);
  switch (error.code) {
    case "preflight_required":
    case "preflight_blocked":
    case "preflight_changed":
    case "preflight_stale":
    case "bundle_changed":
    case "node_busy":
      return (
        <div data-testid="txn-refused">
          <Alert
            type="warning"
            showIcon
            message={`没有安装：${errorTitle(error)}`}
            description={
              <span>
                网关、快照和数据目录都没有改动。{error.message ? <span className="muted">{error.message}</span> : null}
              </span>
            }
          />
          {pf ? (
            <Typography.Paragraph type="secondary" style={{ marginTop: 8, marginBottom: 0 }}>
              最新的预检结果显示在上面「安装前预检」处。
            </Typography.Paragraph>
          ) : null}
        </div>
      );
    case "host_unavailable":
      return (
        <Alert
          type="warning"
          showIcon
          data-testid="txn-refused"
          message="没有宿主执行通道，什么都没改"
          description={
            <span>
              安装和回滚必须经由网关上的 meridian-host 启动服务。它没有运行或面板连不上它（例如面板不在网关上运行）。宿主、快照和数据目录都没有改动。
              <div className="muted">{error.message}</div>
            </span>
          }
        />
      );
    case "peer_keys_missing": {
      const peers = [...new Set((body.peer_key_problems ?? []).map((p) => p.peer))];
      return (
        <Alert
          type="warning"
          showIcon
          data-testid="txn-refused"
          message="拒绝安装：这些对端节点还没有可用的公钥"
          description={
            <div>
              <ul className="ref-list" data-testid="peer-key-list">
                {peers.map((p) => {
                  const n = node(p);
                  const remote = !!n && n.managed && n.role !== "gateway";
                  return (
                    <li key={p}>
                      <Link to={href("topology", p)}>{n?.name || p}</Link> <span className="mono-small muted">{p}</span>
                      {" — "}
                      {remote ? (
                        <Button type="link" size="small" style={{ padding: 0 }} onClick={() => scrollToRemote(p)}>
                          在下面「远端节点」里生成密钥并下发
                        </Button>
                      ) : (
                        <Link to={href("topology", p)}>在拓扑里填入它的公钥</Link>
                      )}
                    </li>
                  );
                })}
              </ul>
              受管的远端节点第一次装机时生成密钥；不受管的节点（例如专线）在拓扑里填入 44 字符的公钥。网关上没有写入任何文件。
            </div>
          }
        />
      );
    }
    case "legacy_install_refused":
      return (
        <Alert
          type="error"
          showIcon
          data-testid="txn-refused"
          message="网关上有旧版 Meridian 的安装，无法可靠接管"
          description={<span>{error.message} 需要先在网关上手动清理旧版本（见 docs/install-debian13.md 的升级说明），再回来安装。</span>}
        />
      );
    case "transaction_pending":
      return (
        <Alert
          type="error"
          showIcon
          data-testid="txn-refused"
          message="上一次宿主事务没有完成，先恢复"
          description={error.message}
          action={
            <Button danger size="small" loading={recovering} onClick={onRecover}>
              恢复
            </Button>
          }
        />
      );
    case "topology_invalid":
    case "lan_interface_mismatch":
      return (
        <Alert
          type="error"
          showIcon
          data-testid="txn-refused"
          message={error.code === "lan_interface_mismatch" ? "拒绝安装：网关的局域网接口不一致" : "拒绝安装：拓扑校验没有通过"}
          description={
            <div>
              <Typography.Paragraph style={{ marginBottom: 8 }}>
                在 <Link to={href("topology")}>拓扑</Link> 或 <Link to={href("rules")}>分流规则</Link> 页改正后保存，再回来安装。网关上没有写入任何文件。
              </Typography.Paragraph>
              <IssueList issues={(body.issues ?? []).filter((i) => i.severity === "error")} />
            </div>
          }
        />
      );
    case "nothing_to_rollback":
      return <Alert type="info" showIcon data-testid="txn-refused" message="没有上一份配置可以回滚" description="回滚要在至少两次安装或应用之后才有东西可回。什么都没有改。" />;
    case "activation_failed_compensated":
    case "activation_failed_uncompensated":
    case "commit_failed": {
      const compensated = error.code === "activation_failed_compensated";
      return (
        <Alert
          type="error"
          showIcon
          data-testid="txn-failed"
          message={
            compensated ? "失败，已补偿回事务前的状态" : error.code === "commit_failed" ? "网关已生效，但提交记录失败" : "失败，补偿也失败了"
          }
          description={
            <div>
              <Typography.Paragraph style={{ marginBottom: 8 }}>{error.message}</Typography.Paragraph>
              {compensated ? (
                <Typography.Paragraph type="secondary">网关和数据目录都回到了事务前；可以修正问题后再试。</Typography.Paragraph>
              ) : (
                <Typography.Paragraph>
                  {error.code === "commit_failed"
                    ? "事务日志已保留，新的安装和回滚都会被拒绝；「恢复」会完成这次提交。"
                    : "宿主处于未知状态，事务日志已保留，新的安装和回滚都会被拒绝。修好原因后点「恢复」。"}
                  <Button danger size="small" style={{ marginLeft: 8 }} loading={recovering} onClick={onRecover}>
                    恢复
                  </Button>
                </Typography.Paragraph>
              )}
              {body.host ? <HostReportView report={body.host} failed /> : null}
            </div>
          }
        />
      );
    }
    default:
      return <ApiErrorAlert error={error} />;
  }
}

function InstallSection({ host, reloadHost, nodes }: { host: HostStatus | undefined; reloadHost: () => void; nodes: Node[] }) {
  const { install, status, refresh } = useStatus();
  const confirm = useConfirmDanger();
  const act = useAction();
  const { message } = AntApp.useApp();
  const [result, setResult] = useState<{ kind: "install" | "apply" | "rollback" | "recover"; res: ApplyResult | { host?: HostReport | null; mode?: string } } | null>(null);
  const [rbMode, setRbMode] = useState<"runtime" | "snapshot">("runtime");
  // A withdrawn gateway keeps only the LAN guard: a reinstall is a first
  // install again (pre-check required) and there is nothing to roll back.
  const withdrawn = !!host?.installed?.withdrawn || status?.install.state === "withdrawn";
  const installed = withdrawn ? null : host?.installed ?? null;
  const pending = status?.pending ?? host?.pending ?? null;
  const agentOK = status?.agent.ok ?? host?.agent.ok ?? false;
  const blocked = install.kind === "error";
  // The install pre-check (read-only, through meridian-host). A first
  // install needs a reviewed, fresh result without blocking findings; every
  // install re-runs it on the server right before executing.
  const [hostPf, setHostPf] = useState<{ rec?: PreflightRecord; error?: ApiError; running?: boolean } | null>(null);
  const runHostPf = () => {
    setHostPf({ running: true });
    api
      .hostPreflight()
      .then((r) => setHostPf({ rec: r.preflight }))
      .catch((e: ApiError) => setHostPf({ error: e }));
  };
  const pfReason = preflightBlockedReason(hostPf?.rec);
  const pfBlocks = !!hostPf?.rec?.blocking || (!installed && !!pfReason);
  const usablePf = hostPf?.rec && !pfReason ? hostPf.rec.id : undefined;

  const after = () => {
    refresh();
    reloadHost();
  };
  const recover = () =>
    act.run(async () => {
      const r = await api.recoverHost();
      setResult({ kind: "recover", res: r });
      message.success("已处理未完成的事务");
    }, "recover").finally(after);

  const doInstall = () =>
    confirm({
      title: "安装到网关？",
      consequence:
        "把存储的拓扑编译后写入这台网关：写入 Meridian 自己的文件，经 meridian-host 重新加载并启动服务、做健康检查。任何一步失败都会把网关和数据目录补偿回安装前。远端节点不受影响。",
      okText: "安装",
      danger: false,
      onOk: () =>
        act.run(
          async () => {
            setResult(null);
            const r = await api.apply(false, true, usablePf);
            setResult({ kind: "install", res: r });
            message.success("已安装并通过健康检查");
          },
          "install",
          (e) => {
            const rec = preflightOf(e);
            if (rec) setHostPf({ rec });
          },
        ).finally(after),
    });

  const doApplyOnly = () =>
    confirm({
      title: "只写入数据目录？",
      consequence:
        "把编译结果存成数据目录里的新快照，网关上的服务、接口和防火墙一样都不动。用于没有宿主执行通道的场合（开发，或面板不在网关上）：之后可以在下面看编译结果、把快照拿去手动部署。之后能安装时，仍要点「安装到网关」才生效；顶栏会显示「已应用，尚未安装」。",
      okText: "只写入",
      danger: false,
      onOk: () =>
        act.run(async () => {
          setResult(null);
          const r = await api.apply(false, false);
          setResult({ kind: "apply", res: r });
        }, "apply").finally(after),
    });

  const mode: "runtime" | "snapshot" = installed ? "runtime" : rbMode;
  // Older panels' status has no previous_available: assume there may be one.
  const canRollBack = status?.previous_available !== false;
  const doRollback = () =>
    confirm({
      title: mode === "runtime" ? "回滚网关（含宿主网络）？" : "只回滚数据目录快照？",
      consequence:
        mode === "runtime"
          ? "网关上的文件、接口、服务和防火墙表恢复到上一次安装前的版本，数据目录快照一起交换；这次安装新加的资源会被移除。失败会补偿。再回滚一次会换回来。"
          : "只交换数据目录里的两份快照，网关上什么都不动。只在网关上还没有安装 Meridian 时可用。",
      okText: "回滚",
      onOk: () =>
        act.run(async () => {
          setResult(null);
          const r = await api.rollback(mode);
          setResult({ kind: "rollback", res: r });
          message.success("已回滚");
        }, "rollback").finally(after),
    });

  const report = result ? ("host" in result.res ? result.res.host ?? null : null) : null;

  return (
    <>
      <Section title="安装到本机">
        {pending ? (
          <Alert
            type="error"
            showIcon
            style={{ marginBottom: 12 }}
            data-testid="pending-txn"
            message={`有未完成的宿主事务 ${pending.id}（${pending.kind}，阶段 ${pending.phase}）`}
            description={
              <span>
                {pending.error ? <div>{pending.error}</div> : null}
                在恢复之前不会接受新的安装或回滚。「恢复」会完成已经生效的提交，或者把网关补偿回事务前的状态。
              </span>
            }
            action={
              <Button danger loading={act.busy === "recover"} onClick={() => void recover()}>
                恢复
              </Button>
            }
          />
        ) : null}
        {!agentOK ? (
          <Alert
            type="warning"
            showIcon
            style={{ marginBottom: 12 }}
            message="宿主执行通道不可用，现在不能安装"
            description={status?.agent.error || "面板连不上网关上的 meridian-host。安装必须经由它启动服务；在它恢复之前，安装会被拒绝且什么都不改。"}
          />
        ) : null}
        <div className="install-row">
          <div>
            <Typography.Paragraph style={{ marginBottom: 4 }}>
              把存储的拓扑装到这台网关：写入 Meridian 自己的文件，经 meridian-host 启动服务并做健康检查；失败自动补偿回安装前。
            </Typography.Paragraph>
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              安装成功只说明服务已启动、健康检查通过，不说明分流、防泄露或解锁已经验证——这些去「防泄露」和「解锁」页确认。
            </Typography.Text>
          </div>
          <Space wrap>
            <Button disabled={!agentOK || !!pending} loading={!!hostPf?.running} onClick={runHostPf} data-testid="host-preflight-run">
              安装前预检
            </Button>
            <Tooltip title={agentOK && pfBlocks ? pfReason ?? "预检有阻断项" : undefined}>
              <Button
                type="primary"
                icon={<CloudUploadOutlined />}
                disabled={blocked || !!pending || !agentOK || install.kind === "in_sync" || pfBlocks}
                loading={act.busy === "install"}
                onClick={doInstall}
              >
                安装到网关
              </Button>
            </Tooltip>
            {!agentOK ? (
              <Tooltip title="没有宿主执行通道时可用：只把编译结果存成快照，不碰网关">
                <Button disabled={blocked || !!pending} loading={act.busy === "apply"} onClick={doApplyOnly} data-testid="apply-only">
                  只写入数据目录
                </Button>
              </Tooltip>
            ) : null}
          </Space>
        </div>
        {!agentOK ? (
          <Typography.Paragraph type="secondary" style={{ marginTop: 8, marginBottom: 0, fontSize: 12 }}>
            「只写入数据目录」：没有宿主执行通道时（开发，或面板不在网关上）把编译结果存成快照，不安装、不改网关。有宿主执行通道时不提供，直接安装即可。
          </Typography.Paragraph>
        ) : null}
        {agentOK && pfBlocks ? (
          <Typography.Paragraph type="warning" style={{ marginTop: 8, marginBottom: 0 }} data-testid="install-preflight-reason">
            {!installed && !hostPf?.rec ? "第一次安装到网关前，先点「安装前预检」看清要做什么、和网关上已有的服务有没有冲突。" : pfReason ?? "预检有阻断项"}
          </Typography.Paragraph>
        ) : null}
        {hostPf?.error ? (
          <div style={{ marginTop: 12 }}>
            <ApiErrorAlert error={hostPf.error} />
          </div>
        ) : null}
        {hostPf?.rec ? (
          <div style={{ marginTop: 12 }} data-testid="host-preflight">
            <PreflightReport rec={hostPf.rec} />
          </div>
        ) : null}
        {install.kind === "in_sync" ? (
          <Typography.Paragraph type="secondary" style={{ marginTop: 8, marginBottom: 0 }}>
            网关上的 v{install.version} 和存储的拓扑一致，没有需要安装的。
          </Typography.Paragraph>
        ) : null}
        {act.error ? (
          <div style={{ marginTop: 12 }}>
            <TxnFailure error={act.error} nodes={nodes} onRecover={() => void recover()} recovering={act.busy === "recover"} />
          </div>
        ) : null}
        {result ? (
          <div style={{ marginTop: 12 }} data-testid="txn-result">
            <Alert
              type="success"
              showIcon
              message={
                result.kind === "install"
                  ? "已安装：服务已启动，健康检查通过"
                  : result.kind === "apply"
                    ? `已写入数据目录（${(result.res as ApplyResult).wrote?.length ?? 0} 个文件），网关未改变`
                    : result.kind === "rollback"
                      ? (result.res as { mode?: string }).mode === "runtime"
                        ? "已回滚：网关和数据目录恢复到上一份"
                        : "已回滚数据目录快照，网关未改变"
                      : "事务已处理"
              }
              description={result.kind === "install" ? "这不代表分流、防泄露或解锁已经验证。" : undefined}
              style={{ marginBottom: report ? 12 : 0 }}
            />
            {report ? <HostReportView report={report} /> : null}
          </div>
        ) : null}
      </Section>

      <Section title="回滚">
        {withdrawn ? (
          <Typography.Paragraph type="secondary" data-testid="rollback-withdrawn">
            网关已撤回（只保留局域网兜底表），不提供回滚：要恢复，请重新「安装到网关」（先做安装前预检）。
          </Typography.Paragraph>
        ) : null}
        {!canRollBack ? (
          <Typography.Paragraph type="secondary" data-testid="no-previous">
            还没有上一份配置可以回滚：第一次安装（或应用）之后，下一次安装前的版本才会留作回滚目标。
          </Typography.Paragraph>
        ) : null}
        <Radio.Group value={mode} onChange={(e) => setRbMode(e.target.value)} style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          <Radio value="runtime" disabled={!installed}>
            <Typography.Text strong>回滚网关（含宿主网络）</Typography.Text>
            <Typography.Text type="secondary" style={{ display: "block", fontSize: 12 }}>
              网关上的文件、接口、服务和防火墙恢复到上一份，数据目录快照一起交换。{installed ? "" : "网关上还没有安装，不适用。"}
            </Typography.Text>
          </Radio>
          <Radio value="snapshot" disabled={!!installed}>
            <Typography.Text strong>只回滚数据目录快照</Typography.Text>
            <Typography.Text type="secondary" style={{ display: "block", fontSize: 12 }}>
              只交换两份快照，不碰网关。{installed ? "网关上已安装 Meridian，只交换快照会让记录与网关不一致，所以不提供。" : "网关上没有安装时可用。"}
            </Typography.Text>
          </Radio>
        </Radio.Group>
        <Button
          style={{ marginTop: 12 }}
          icon={<RollbackOutlined />}
          danger
          disabled={withdrawn || !canRollBack || !!pending || (installed ? !agentOK : false)}
          loading={act.busy === "rollback"}
          onClick={doRollback}
        >
          回滚
        </Button>
      </Section>
    </>
  );
}

// ---------------------------------------------------------- remote nodes ---

type RemoteMode = "push" | "rotate";

/** Preflight findings that have a panel-driven recovery (withdraw script modes). */
const RECOVERY: Record<string, { mode: WithdrawMode; label: string }> = {
  previous_run_incomplete: { mode: "journal", label: "恢复中断的装机" },
  legacy_install: { mode: "legacy", label: "旧版清理（先列清单再确认）" },
  withdraw_incomplete: { mode: "manifest", label: "继续撤回" },
};

function RemoteNodes({ nodes, servers, onWithdrawn }: { nodes: Node[]; servers: ServerView[] | undefined; onWithdrawn: () => void }) {
  const doc = useTopologyDoc();
  const [wd, setWd] = useState<{ node: Node; mode: WithdrawMode } | null>(null);
  const { markApplyRequired } = useStatus();
  const act = useAction();
  const [out, setOut] = useState<{ node: Node; title: string; res?: ProvisionResult; error?: ApiError } | null>(null);
  // The preflight dialog: every real run starts here. It shows the target,
  // the planned changes and the findings; execution is possible only with
  // a fresh result without blocking findings.
  const [pf, setPf] = useState<{ node: Node; mode: RemoteMode; rec?: PreflightRecord; error?: ApiError; running: boolean } | null>(null);
  const server = (n: Node) => servers?.find((s) => s.id === n.server_id);
  // Servers that refused the panel's source address: their buttons stay
  // disabled for the retry_after the panel was given.
  const cooldownOf = useCooldowns();

  const runPreflight = (n: Node, mode: RemoteMode) => {
    setPf({ node: n, mode, running: true });
    api
      .provisionPreflight(n.id)
      .then((r) => setPf((p) => (p && p.node.id === n.id ? { ...p, rec: r.preflight, error: undefined, running: false } : p)))
      .catch((e: ApiError) => {
        noteRateLimited(n.server_id, retryAfterOf(e));
        setPf((p) => (p && p.node.id === n.id ? { ...p, rec: undefined, error: e, running: false } : p));
      });
  };

  const execute = () => {
    if (!pf?.rec) return;
    const { node: n, mode, rec } = pf;
    void act.run(
      async () => {
        const res = await api.provision(n.id, { dryRun: false, generateKeys: mode === "rotate", preflightId: rec.id });
        setPf(null);
        setOut({ node: n, title: mode === "rotate" ? "已生成密钥并下发" : "已下发", res });
        if (mode === "rotate" && typeof res.public_key === "string" && res.public_key) {
          const pub = res.public_key;
          doc.applyServerChange((t) => ({ ...t, nodes: t.nodes.map((x) => (x.id === n.id ? { ...x, public_key: pub } : x)) }));
          markApplyRequired();
        }
      },
      `${mode}:${n.id}`,
      (e) => {
        noteRateLimited(n.server_id, retryAfterOf(e));
        const fresh = preflightOf(e);
        if (fresh) {
          // Refused before anything ran: show the new result in the dialog.
          setPf((p) => (p ? { ...p, rec: fresh, error: e } : p));
          return;
        }
        setPf(null);
        setOut({ node: n, title: "下发失败", error: e });
      },
    );
  };

  const preview = (n: Node) =>
    act.run(
      async () => {
        const res = await api.provision(n.id, { dryRun: true });
        setOut({ node: n, title: "预览脚本（没有连接服务器）", res });
      },
      `preview:${n.id}`,
      (e) => setOut({ node: n, title: "预览失败", error: e }),
    );

  const keyless = nodes.filter((n) => !n.public_key);

  if (nodes.length === 0)
    return (
      <Section title="远端节点" id="remote">
        <Typography.Text type="secondary">拓扑里没有需要装机的远端节点。</Typography.Text>
      </Section>
    );

  const pfReason = pf && !pf.running ? preflightBlockedReason(pf.rec) : null;
  const sv = pf ? server(pf.node) : undefined;
  const first = pf ? !pf.node.public_key : false;
  const execLabel = !pf ? "" : pf.mode === "push" ? "下发" : first ? "生成密钥并下发" : "生成新密钥并下发";
  const outBody = (out?.error?.body ?? {}) as { output?: string; leftovers?: string[]; kept?: string[]; outcome?: string };

  return (
    <Section title="远端节点" id="remote">
      <Typography.Paragraph>
        推荐顺序：先在这里给每个远端节点「生成密钥并下发」（第一次装机），再「安装到网关」——网关的配置要用到每个对端的公钥，缺了会被拒绝安装。以后改了拓扑，也是先对受影响的远端节点「下发」，再「安装到网关」：可切换地区组的解析走组的隧道地址（fd66::53:…），只有已经下发新配置的出口才会应答，网关先装的话组内的名字在出口更新前解析不了（不会改问国内或别的出口）。
      </Typography.Paragraph>
      {keyless.length > 0 ? (
        <Alert
          type="warning"
          showIcon
          style={{ marginBottom: 12 }}
          data-testid="keyless-nodes"
          message={`${keyless.length} 个节点还没有密钥，还没有第一次装机：${keyless
            .slice(0, 5)
            .map((n) => n.name || n.id)
            .join("、")}${keyless.length > 5 ? ` 等 ${keyless.length} 个` : ""}`}
          description="在它们那一行点「生成密钥并下发」。服务器要先在「服务器」页确认指纹并测试连接。"
        />
      ) : null}
      <Typography.Paragraph type="secondary">
        「预览脚本」不连接服务器，密钥显示为占位符。「下发」和「生成密钥并下发」先做只读预检：列出要做的变更和与服务器上已有服务的冲突，有阻断项就不能执行；确认后才会真的在服务器上执行，执行前面板还会再预检一次。
      </Typography.Paragraph>
      <Table<Node>
        rowKey="id"
        dataSource={nodes}
        pagination={false}
        size="middle"
        scroll={TABLE_SCROLL}
        onRow={(n) => ({ "data-testid": `remote-node-${n.id}` }) as React.HTMLAttributes<HTMLElement>}
        columns={[
          {
            title: "节点",
            className: "cell-name",
            render: (_, n) => (
              <Space size={4}>
                <Link to={href("topology", n.id)}>{n.name || n.id}</Link>
                <Tag>{roleLabel[n.role]}</Tag>
              </Space>
            ),
          },
          {
            title: "服务器",
            className: "nowrap",
            render: (_, n) => {
              const sv = server(n);
              if (!n.server_id) return <StatusTag kind="attention">未选服务器</StatusTag>;
              if (!sv) return servers ? <StatusTag kind="failed">服务器不存在</StatusTag> : <Typography.Text type="secondary">…</Typography.Text>;
              const r = serverReadiness(sv);
              return (
                <Space size={4}>
                  <Link to={href("servers", sv.id)}>{sv.name}</Link>
                  <StatusTag kind={r.kind}>{r.label}</StatusTag>
                </Space>
              );
            },
          },
          {
            title: "密钥",
            render: (_, n) =>
              n.public_key ? (
                <Tooltip title={n.public_key}>
                  <Tag>已有</Tag>
                </Tooltip>
              ) : (
                <span data-testid={`keyless-${n.id}`}>
                  <StatusTag kind="attention">还没有 · 第一次装机</StatusTag>
                </span>
              ),
          },
          {
            title: "操作",
            fixed: "right",
            className: "cell-actions",
            render: (_, n) => {
              const sv = server(n);
              const ready = !!sv?.ready;
              const notReady = !n.server_id ? "节点还没有选择服务器" : !sv ? "服务器不存在" : !ready ? "服务器还没就绪：先确认指纹并测试连接" : undefined;
              const first = !n.public_key;
              const more = [
                { key: "preview", icon: <EyeOutlined />, label: "预览脚本（不连接服务器）" },
                ...(first ? [] : [{ key: "rotate", icon: <KeyOutlined />, label: "生成新密钥并下发…", danger: true, disabled: !ready }]),
              ];
              return (
                <Space size={4} className="table-actions">
                  <Tooltip title={cooldownOf(n.server_id) > 0 ? `服务器暂时拒绝面板的来源地址（限速）：${cooldownOf(n.server_id)} 秒后再试` : notReady}>
                    {first ? (
                      <Button type="primary" size="small" icon={<KeyOutlined />} disabled={!ready || cooldownOf(n.server_id) > 0} loading={pf?.node.id === n.id && pf.running} onClick={() => runPreflight(n, "rotate")}>
                        生成密钥并下发
                      </Button>
                    ) : (
                      <Button size="small" icon={<SendOutlined />} disabled={!ready || cooldownOf(n.server_id) > 0} loading={pf?.node.id === n.id && pf.running && pf.mode === "push"} onClick={() => runPreflight(n, "push")}>
                        下发
                      </Button>
                    )}
                  </Tooltip>
                  <Dropdown
                    trigger={["click"]}
                    menu={{
                      items: more,
                      onClick: ({ key }) => (key === "preview" ? void preview(n) : runPreflight(n, "rotate")),
                    }}
                  >
                    <Button size="small" icon={<EllipsisOutlined />} aria-label={`${n.name || n.id} 的更多操作`} loading={act.busy === `preview:${n.id}`} />
                  </Dropdown>
                </Space>
              );
            },
          },
        ]}
      />
      <Modal
        open={!!pf}
        title={pf ? `${pf.node.name || pf.node.id} · 装机前预检` : ""}
        width={900}
        onCancel={() => setPf(null)}
        destroyOnHidden
        footer={
          pf ? (
            <Space wrap style={{ justifyContent: "flex-end", width: "100%" }}>
              {pfReason ? (
                <Typography.Text type="danger" data-testid="preflight-disabled-reason">
                  {pfReason}
                </Typography.Text>
              ) : null}
              <Button onClick={() => setPf(null)}>取消</Button>
              <Button
                onClick={() => runPreflight(pf.node, pf.mode)}
                loading={pf.running}
                disabled={!!act.busy || cooldownOf(pf.node.server_id) > 0}
                data-testid="preflight-rerun"
              >
                {cooldownOf(pf.node.server_id) > 0 ? `${cooldownOf(pf.node.server_id)} 秒后可重新预检` : "重新预检"}
              </Button>
              <Button
                type="primary"
                danger={pf.mode === "rotate" && !first}
                disabled={pf.running || !!pfReason || cooldownOf(pf.node.server_id) > 0}
                loading={act.busy === `${pf.mode}:${pf.node.id}`}
                onClick={execute}
                data-testid="preflight-execute"
              >
                {execLabel}
              </Button>
            </Space>
          ) : null
        }
      >
        {pf ? (
          <>
            <Typography.Paragraph type="secondary">
              {pf.mode === "push"
                ? `用节点已有的密钥生成配置，经 SSH 登录 ${sv ? `${sv.name}（${sv.address}）` : "它的服务器"} 执行：写入 Meridian 的文件并重启它的服务。`
                : first
                  ? `生成这个节点的 WireGuard 密钥（私钥只保存在面板里），然后经 SSH 在 ${sv ? `${sv.name}（${sv.address}）` : "它的服务器"} 上执行：写入 Meridian 的文件并启动它的服务。`
                  : "这会轮换这个节点的 WireGuard 私钥：旧密钥立即作废，在网关重新安装、相邻节点重新下发之前，经过这个节点的隧道会断开。只在怀疑私钥泄露时使用。"}
              失败时脚本会补偿（撤掉这次新建的、恢复被替换的），撤不掉的会逐项列出。
            </Typography.Paragraph>
            {pf.running && !pf.rec ? (
              <Typography.Paragraph data-testid="preflight-running">正在预检（只读，不改动服务器）…</Typography.Paragraph>
            ) : null}
            {pf.error ? (
              <ApiErrorAlert error={pf.error}>
                {loginHelpOf(pf.error) ? <LoginHelpView help={loginHelpOf(pf.error)!} /> : null}
                {pf.error.code === "deployed_elsewhere" ? (
                  <div data-testid="deployed-elsewhere">
                    这个节点之前装在另一台服务器上，还没有撤回。先在下面「部署记录与撤回」里撤回那台服务器上的安装（服务器确实已不存在时选「放弃」），再装到新服务器。
                  </div>
                ) : null}
              </ApiErrorAlert>
            ) : null}
            {pf.rec
              ? (() => {
                  const fixes = [...new Set(pf.rec.findings.map((f) => f.code))].filter((c) => RECOVERY[c]);
                  return fixes.length > 0 ? (
                    <Alert
                      type="warning"
                      showIcon
                      style={{ marginBottom: 12 }}
                      data-testid="preflight-recovery"
                      message="面板可以处理这个阻断项"
                      description={
                        <Space wrap>
                          {fixes.map((c) => (
                            <Button key={c} size="small" onClick={() => setWd({ node: pf.node, mode: RECOVERY[c].mode })}>
                              {RECOVERY[c].label}
                            </Button>
                          ))}
                        </Space>
                      }
                    />
                  ) : null;
                })()
              : null}
            {pf.rec ? <PreflightReport rec={pf.rec} /> : null}
          </>
        ) : null}
      </Modal>
      {wd ? (
        <WithdrawDialog
          nodeId={wd.node.id}
          nodeName={wd.node.name}
          mode={wd.mode}
          onClose={() => {
            setWd(null);
            onWithdrawn();
          }}
          onDone={() => onWithdrawn()}
        />
      ) : null}
      <Modal
        open={!!out}
        title={out ? `${out.node.name} · ${out.title}` : ""}
        width={860}
        onCancel={() => setOut(null)}
        footer={<Button onClick={() => setOut(null)}>关闭</Button>}
        destroyOnHidden
      >
        {out?.error ? (
          <>
            <ApiErrorAlert error={out.error}>{loginHelpOf(out.error) ? <LoginHelpView help={loginHelpOf(out.error)!} /> : null}</ApiErrorAlert>
            {outBody.outcome === "unknown" ? (
              <Alert type="warning" showIcon style={{ marginBottom: 12 }} data-testid="provision-unknown" message="结果不明，不当作成功" description="重新预检会显示服务器上这次装机的 journal 状态。" />
            ) : null}
            {outBody.leftovers && outBody.leftovers.length > 0 ? (
              <Alert
                type="error"
                showIcon
                style={{ marginBottom: 12 }}
                data-testid="provision-leftovers"
                message="留在服务器上、没有撤掉的东西"
                description={
                  <ul style={{ margin: 0, paddingLeft: 18 }}>
                    {outBody.leftovers.map((l) => (
                      <li key={l} className="mono-small">
                        {l}
                      </li>
                    ))}
                  </ul>
                }
              />
            ) : null}
            {outBody.kept && outBody.kept.length > 0 ? (
              <Alert
                type="info"
                showIcon
                style={{ marginBottom: 12 }}
                data-testid="provision-kept"
                message="按设计保留的（不会自动卸载）"
                description={
                  <ul style={{ margin: 0, paddingLeft: 18 }}>
                    {outBody.kept.map((l) => (
                      <li key={l} className="mono-small">
                        {l}
                      </li>
                    ))}
                  </ul>
                }
              />
            ) : null}
            {typeof outBody.output === "string" && outBody.output ? <pre className="diff">{outBody.output}</pre> : null}
          </>
        ) : out?.res ? (
          <>
            {out.res.dry_run ? (
              <Alert type="info" showIcon style={{ marginBottom: 12 }} message="这是预览：私钥是占位符，复制到服务器上执行会被拒绝。" />
            ) : (
              <Alert
                type="success"
                showIcon
                style={{ marginBottom: 12 }}
                message="脚本已在服务器上执行完毕"
                description="这只说明脚本跑完了；隧道是否通、流量是否正确要在网关安装后再看健康状态。"
              />
            )}
            {out.res.script ? (
              <>
                <Space style={{ marginBottom: 8 }}>
                  <CopyButton text={String(out.res.script)} label="复制脚本" />
                </Space>
                <pre className="diff">{String(out.res.script)}</pre>
              </>
            ) : null}
            {typeof out.res.output === "string" ? <pre className="diff">{out.res.output || "（没有输出）"}</pre> : null}
          </>
        ) : null}
      </Modal>
    </Section>
  );
}

// ---------------------------------------------------------- installed now ---

/** The binaries the panel delivers itself: pinned version and digest per
 * architecture, and whether the panel holds a verified copy. */
function ArtifactsCard() {
  const arts = useApi(() => api.listArtifacts(), []);
  const list = arts.data?.artifacts ?? [];
  const missing = list.filter((a) => !a.available);
  const versions = [...new Map(list.map((a) => [a.name, `${a.name} ${a.version}`])).values()].join("、");
  return (
    <Section title="面板下发的二进制">
      <Typography.Paragraph type="secondary" style={{ marginBottom: 8 }}>
        wstunnel 和 SmartDNS 由面板按架构（x86_64 / aarch64）提供固定版本，随节点配置经 SSH 传到主机的 /usr/local/sbin/meridian-*，主机不需要也不会自己下载；面板在加载和每次发送前校验 SHA-256，主机在激活前再校验一次，不一致就拒绝安装。主机上别的服务自己装的 wstunnel 或 smartdns 不会被覆盖或删除。
      </Typography.Paragraph>
      {missing.length > 0 ? (
        <Alert
          type="error"
          showIcon
          style={{ marginBottom: 8 }}
          data-testid="artifacts-missing"
          message={`${missing.length} 个二进制没有可用的已校验副本：需要它们的节点会在预检里被阻断`}
          description={missing.map((a) => `${a.name} ${a.version}（${a.arch}）：${a.error ?? "不可用"}`).join("；")}
        />
      ) : null}
      <DataView state={arts} rows={2}>
        {() => (
          <Collapse
            size="small"
            items={[
              {
                key: "list",
                label: versions ? `固定版本：${versions}` : "固定版本",
                children: (
                  <Table
                    size="small"
                    pagination={false}
                    rowKey={(a) => `${a.name}-${a.arch}`}
                    dataSource={list}
                    scroll={TABLE_SCROLL}
                    data-testid="artifacts-table"
                    columns={[
                      { title: "名称", dataIndex: "name" },
                      { title: "版本", dataIndex: "version" },
                      { title: "架构", dataIndex: "arch" },
                      { title: "SHA-256", dataIndex: "sha256", render: (v: string) => <Mono>{v.slice(0, 16) + "…"}</Mono> },
                      { title: "主机路径", dataIndex: "host_path", render: (v: string) => <Mono>{v}</Mono> },
                      {
                        title: "面板副本",
                        dataIndex: "available",
                        render: (v: boolean, a) => (v ? <StatusTag kind="ok">已校验</StatusTag> : <StatusTag kind="failed" title={a.error}>不可用</StatusTag>),
                      },
                    ]}
                  />
                ),
              },
            ]}
          />
        )}
      </DataView>
    </Section>
  );
}

function CurrentInstall({ host }: { host: HostStatus }) {
  const { status } = useStatus();
  const m = host.installed;
  return (
    <Facts
      items={[
        [
          "宿主执行通道",
          host.agent.ok ? <StatusTag kind="ok">可用</StatusTag> : <StatusTag kind="attention" title={host.agent.error}>不可用</StatusTag>,
        ],
        ...(!host.agent.ok && host.agent.error ? ([["原因", <span key="e" className="muted">{host.agent.error}</span>]] as [ReactNode, ReactNode][]) : []),
        [
          "已安装",
          m ? (
            <Space key="v" size={6} wrap>
              <span className="mono">v{m.version}</span>
              <TimeText value={m.created_at} />
              {m.origin === "legacy" ? <Tag color="orange">从旧版本接管</Tag> : null}
              {m.withdrawn ? <Tag color="orange">已撤回：只保留局域网兜底表</Tag> : null}
            </Space>
          ) : (
            <StatusTag kind="neutral">未安装</StatusTag>
          ),
        ],
        ...(m
          ? ([
              ["文件", `${m.files} 个`],
              ["接口", <span key="i" className="mono-small">{m.interfaces.join("  ") || "—"}</span>],
              ["服务", <span key="u" className="mono-small">{m.units.join("  ") || "—"}</span>],
              ["nft 表", <span key="n" className="mono-small">{m.nft_tables.join("  ") || "—"}</span>],
              ["路由表", <span key="r" className="mono-small">{m.route_tables.join("  ") || "—"}</span>],
              ["DNS", m.dns ? "由 Meridian 管理" : "不管理"],
            ] as [ReactNode, ReactNode][])
          : []),
        [
          "与存储的拓扑",
          !status ? (
            "—"
          ) : status.install.state === "in_sync" ? (
            <StatusTag kind="ok">一致</StatusTag>
          ) : status.install.state === "changed" ? (
            <StatusTag kind="pending">{status.install.applied_matches ? "已应用，尚未安装" : "有改动尚未安装"}</StatusTag>
          ) : status.install.state === "invalid" ? (
            <StatusTag kind="attention">拓扑无法编译</StatusTag>
          ) : status.install.state === "unknown" ? (
            <StatusTag kind="unverified">无法判断</StatusTag>
          ) : status.install.state === "withdrawn" ? (
            <StatusTag kind="neutral">网关已撤回</StatusTag>
          ) : (
            <StatusTag kind="neutral">网关上未安装</StatusTag>
          ),
        ],
        [
          "未完成的事务",
          host.pending ? (
            <StatusTag kind="failed" title={host.pending.error}>
              {host.pending.id} · {host.pending.phase}
            </StatusTag>
          ) : (
            "无"
          ),
        ],
      ]}
    />
  );
}

// ------------------------------------------------------------------ page ---

export default function DeployPage() {
  const doc = useTopologyDoc();
  const { route } = useRouter();
  useEffect(() => {
    const sec = route.query.get("section");
    if (sec === "remote" || sec === "deployments") {
      const t = window.setTimeout(() => document.getElementById(sec)?.scrollIntoView?.({ behavior: "smooth" }), 200);
      return () => window.clearTimeout(t);
    }
  }, [route.query]);
  const host = useApi(() => api.hostStatus(), []);
  const deployments = useApi(() => api.getDeployments(), []);
  const servers = useApi(() => api.listServers(), []);
  const nodeName = (id: string) => doc.topo?.nodes.find((n) => n.id === id)?.name ?? id;
  const remote = (doc.topo?.nodes ?? []).filter((n) => n.managed && n.role !== "gateway");

  return (
    <Page
      title="部署"
      description="把存储的拓扑装到网关、回滚，以及把配置下发到远端节点。所有页面的修改都要在这里安装后才生效。"
      extra={
        <Button icon={<ToolOutlined />} onClick={() => void host.reload()} loading={host.loading}>
          刷新状态
        </Button>
      }
    >
      {doc.dirty ? (
        <Alert
          type="warning"
          showIcon
          style={{ marginBottom: 16 }}
          message="拓扑有未保存的修改"
          description={
            <span>
              安装用的是已保存的拓扑，不包括这些修改。先到 <Link to={href("topology")}>拓扑</Link> 或 <Link to={href("rules")}>分流规则</Link> 页保存。
            </span>
          }
        />
      ) : null}
      <PendingChanges nodeName={nodeName} />
      <InstallSection host={host.data} reloadHost={() => void host.reload()} nodes={doc.topo?.nodes ?? []} />
      <RemoteNodes nodes={remote} servers={servers.data?.servers} onWithdrawn={() => void deployments.reload()} />
      <ArtifactsCard />
      <DeploymentRecords state={deployments} onChanged={() => void deployments.reload()} />
      <Section title="当前安装">
        <DataView state={host} rows={4}>
          {(h) => <CurrentInstall host={h} />}
        </DataView>
      </Section>
      <GatewayWithdraw
        gw={deployments.data?.gateway}
        onChanged={() => {
          void deployments.reload();
          void host.reload();
        }}
        hostReport={(r, failed) => <HostReportView report={r} failed={failed} />}
      />
      <Typography.Paragraph type="secondary" style={{ fontSize: 12 }}>
        Mesh 备路的部署和撤回在 <Link to={href("cloudflare") + "?section=mesh"}>Cloudflare</Link> 页。
      </Typography.Paragraph>
    </Page>
  );
}
