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
import type { ApplyResult, HostReport, HostStatus, InstalledDiff, Issue, Node, ProvisionResult, ServerView } from "./types";
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
  useConfirmDanger,
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
  switch (error.code) {
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
  const installed = host?.installed ?? null;
  const pending = status?.pending ?? host?.pending ?? null;
  const agentOK = status?.agent.ok ?? host?.agent.ok ?? false;
  const blocked = install.kind === "error";

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
        act.run(async () => {
          setResult(null);
          const r = await api.apply(false, true);
          setResult({ kind: "install", res: r });
          message.success("已安装并通过健康检查");
        }, "install").finally(after),
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
            <Button
              type="primary"
              icon={<CloudUploadOutlined />}
              disabled={blocked || !!pending || !agentOK || install.kind === "in_sync"}
              loading={act.busy === "install"}
              onClick={doInstall}
            >
              安装到网关
            </Button>
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
          disabled={!canRollBack || !!pending || (installed ? !agentOK : false)}
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

function RemoteNodes({ nodes, servers }: { nodes: Node[]; servers: ServerView[] | undefined }) {
  const doc = useTopologyDoc();
  const { markApplyRequired } = useStatus();
  const confirm = useConfirmDanger();
  const act = useAction();
  const [out, setOut] = useState<{ node: Node; title: string; res?: ProvisionResult; error?: ApiError } | null>(null);
  const server = (n: Node) => servers?.find((s) => s.id === n.server_id);

  const run = (n: Node, mode: "preview" | "push" | "rotate") => {
    const go = () =>
      act.run(
        async () => {
          const res = await api.provision(n.id, { dryRun: mode === "preview", generateKeys: mode === "rotate" });
          setOut({ node: n, title: mode === "preview" ? "预览脚本（没有连接服务器）" : mode === "rotate" ? "已生成新密钥并下发" : "已下发", res });
          if (mode === "rotate" && typeof res.public_key === "string" && res.public_key) {
            const pub = res.public_key;
            doc.applyServerChange((t) => ({ ...t, nodes: t.nodes.map((x) => (x.id === n.id ? { ...x, public_key: pub } : x)) }));
            markApplyRequired();
          }
        },
        `${mode}:${n.id}`,
        (e) => setOut({ node: n, title: mode === "preview" ? "预览失败" : "下发失败", error: e }),
      );
    const sv = server(n);
    if (mode === "preview") return void go();
    if (mode === "push")
      return confirm({
        title: `下发到「${n.name}」？`,
        consequence: `经 SSH 登录 ${sv ? `${sv.name}（${sv.address}）` : "它的服务器"}，用节点已有的密钥生成配置并执行脚本：覆盖 Meridian 在那台机器上的文件并重启它的服务。这会真的在服务器上执行。`,
        okText: "下发",
        danger: false,
        onOk: go,
      });
    if (!n.public_key)
      return confirm({
        title: `为「${n.name}」生成密钥并第一次下发？`,
        consequence: `生成这个节点的 WireGuard 密钥（私钥只保存在面板里），然后经 SSH 在 ${sv ? `${sv.name}（${sv.address}）` : "它的服务器"} 上真的执行脚本：写入 Meridian 的文件并启动它的服务。之后网关安装时才认得这个节点。`,
        okText: "生成并下发",
        danger: false,
        onOk: go,
      });
    confirm({
      title: `为「${n.name}」生成新密钥并下发？`,
      consequence: (
        <div>
          <p>
            这会<b>轮换这个节点的 WireGuard 私钥</b>，并经 SSH 在 {sv ? `${sv.name}（${sv.address}）` : "它的服务器"} 上真的执行脚本。
          </p>
          <p>
            旧密钥立即作废：在网关重新安装、相邻节点重新下发之前，经过这个节点的隧道会断开。只在第一次装机，或怀疑私钥泄露时使用。
          </p>
        </div>
      ),
      okText: "生成并下发",
      onOk: go,
    });
  };

  const keyless = nodes.filter((n) => !n.public_key);

  if (nodes.length === 0)
    return (
      <Section title="远端节点" id="remote">
        <Typography.Text type="secondary">拓扑里没有需要装机的远端节点。</Typography.Text>
      </Section>
    );

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
        「预览脚本」不连接服务器，密钥显示为占位符；「下发」和「生成密钥并下发」会真的在服务器上执行。
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
                  <Tooltip title={notReady}>
                    {first ? (
                      <Button type="primary" size="small" icon={<KeyOutlined />} disabled={!ready} loading={act.busy === `rotate:${n.id}`} onClick={() => run(n, "rotate")}>
                        生成密钥并下发
                      </Button>
                    ) : (
                      <Button size="small" icon={<SendOutlined />} disabled={!ready} loading={act.busy === `push:${n.id}`} onClick={() => run(n, "push")}>
                        下发
                      </Button>
                    )}
                  </Tooltip>
                  <Dropdown
                    trigger={["click"]}
                    menu={{ items: more, onClick: ({ key }) => run(n, key as "preview" | "rotate") }}
                  >
                    <Button size="small" icon={<EllipsisOutlined />} aria-label={`${n.name || n.id} 的更多操作`} loading={act.busy === `preview:${n.id}` || (!first && act.busy === `rotate:${n.id}`)} />
                  </Dropdown>
                </Space>
              );
            },
          },
        ]}
      />
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
            <ApiErrorAlert error={out.error} />
            {typeof (out.error.body as { output?: string }).output === "string" && (out.error.body as { output?: string }).output ? (
              <pre className="diff">{(out.error.body as { output: string }).output}</pre>
            ) : null}
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
    if (route.query.get("section") === "remote") {
      const t = window.setTimeout(() => document.getElementById("remote")?.scrollIntoView?.({ behavior: "smooth" }), 200);
      return () => window.clearTimeout(t);
    }
  }, [route.query]);
  const host = useApi(() => api.hostStatus(), []);
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
      <RemoteNodes nodes={remote} servers={servers.data?.servers} />
      <Section title="当前安装">
        <DataView state={host} rows={4}>
          {(h) => <CurrentInstall host={h} />}
        </DataView>
      </Section>
      <Typography.Paragraph type="secondary" style={{ fontSize: 12 }}>
        Mesh 备路的部署和撤回在 <Link to={href("cloudflare") + "?section=mesh"}>Cloudflare</Link> 页。
      </Typography.Paragraph>
    </Page>
  );
}
