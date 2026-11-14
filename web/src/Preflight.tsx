// The install pre-check ("预检") as the operator reviews it before a first
// install, an update or a gateway install: the target identity it is bound
// to, what the install would change, and every finding grouped by severity
// with what was found and what to do. Blocking findings disable execution;
// nothing here can override them.

import { CheckCircleFilled, CloseCircleFilled, ExclamationCircleFilled, InfoCircleFilled } from "@ant-design/icons";
import { Alert, Collapse, Space, Tag, Typography } from "antd";
import type { ReactNode } from "react";
import type { ApiError } from "./api";
import type { LoginHelp, PreflightBinary, PreflightChange, PreflightFileChanges, PreflightFinding, PreflightPackage, PreflightRecord } from "./types";
import { href } from "./state";
import { CopyButton, Facts, Link, Mono, TimeText } from "./ui";

const SEVERITY: Record<PreflightFinding["severity"], { title: string; type: "error" | "warning" | "info"; icon: ReactNode }> = {
  blocking: { title: "阻断：必须先处理", type: "error", icon: <CloseCircleFilled /> },
  warning: { title: "警告：确认后可以继续", type: "warning", icon: <ExclamationCircleFilled /> },
  info: { title: "信息", type: "info", icon: <InfoCircleFilled /> },
};

const OWNERSHIP: Record<string, string> = {
  none: "主机上没有 Meridian：第一次装机",
  same: "已由本面板为这个节点装过：这次是更新",
  other: "属于另一个节点或另一个面板",
  legacy: "有旧版 Meridian 的痕迹，但没有受管清单",
  unknown: "受管清单无法读懂",
};

const CHANGE_KIND: Record<string, string> = {
  file: "文件",
  interface: "接口",
  listen: "监听端口",
  route: "路由",
  rule: "策略规则",
  nft: "nft 表",
  unit: "服务",
  package: "软件包",
  sysctl: "内核参数",
  state: "受管记录",
  binary: "面板下发的二进制",
  firewall: "转发放行规则（DOCKER-USER）",
};

const CHANGE_ACTION: Record<string, string> = {
  create: "新建",
  change: "内容变化",
  not_compared: "未比较",
  replace: "替换",
  update: "更新",
  bind: "绑定",
  add: "添加",
  enable: "启用",
  install: "安装",
  set: "设置",
  keep: "保留",
  remove: "移除",
};

const BINARY_ACTION: Record<PreflightBinary["action"], { label: string; color: string }> = {
  install: { label: "传输并安装", color: "blue" },
  replace: { label: "传输并替换", color: "gold" },
  keep: { label: "已是固定版本，不传输", color: "green" },
  refuse: { label: "不能下发", color: "red" },
};

const PACKAGE_ACTION: Record<PreflightPackage["action"], { label: string; color: string }> = {
  none: { label: "已有", color: "green" },
  install: { label: "apt 安装", color: "blue" },
  unavailable: { label: "apt 没有候选版本", color: "red" },
};

function kb(v: number | undefined): string {
  if (v === undefined || v < 0) return "未知";
  if (v >= 1024 * 1024) return `${(v / 1024 / 1024).toFixed(1)} GB`;
  return `${Math.floor(v / 1024)} MB`;
}

/** Platform, versions, binaries and packages: what this install brings to the host. */
export function InstallPlan({ rec }: { rec: PreflightRecord }) {
  const bins = rec.binaries ?? [];
  const pkgs = rec.package_plan ?? [];
  return (
    <div data-testid="preflight-install-plan" style={{ marginTop: 12 }}>
      <Typography.Text strong>安装计划</Typography.Text>
      <Facts
        items={[
          [
            "平台",
            rec.platform ? (
              <Tag key="p" color="green" data-testid="preflight-platform">
                {rec.platform}
              </Tag>
            ) : (
              <Tag key="p" color="red" data-testid="preflight-platform">
                不在支持范围
              </Tag>
            ),
          ],
          ["架构", <Mono key="a">{rec.host.arch || "未知"}</Mono>],
          ["内存", <span key="m">{`共 ${kb(rec.host.mem_total_kb)}，可用 ${kb(rec.host.mem_avail_kb)}`}</span>],
        ]}
      />
      {bins.length > 0 ? (
        <div data-testid="preflight-binaries" style={{ marginTop: 6 }}>
          <Typography.Text type="secondary">面板下发的二进制（固定版本，按架构区分，主机不下载任何东西；激活前在主机上再校验 SHA-256）：</Typography.Text>
          <ul style={{ margin: "4px 0 0", paddingLeft: 18 }}>
            {bins.map((b) => (
              <li key={b.name} className="mono-small" data-binary={b.name} data-action={b.action}>
                <Tag color={BINARY_ACTION[b.action]?.color}>{BINARY_ACTION[b.action]?.label ?? b.action}</Tag>
                {b.name} {b.version ?? ""}（{b.arch || "?"}）→ {b.path}
                {b.sha256 ? <Typography.Text type="secondary">{` sha256 ${b.sha256.slice(0, 16)}…`}</Typography.Text> : null}
                {b.size ? <Typography.Text type="secondary">{`，${kb(Math.ceil(b.size / 1024))}`}</Typography.Text> : null}
                {b.detail ? <Typography.Text type="secondary">（{b.detail}）</Typography.Text> : null}
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      {pkgs.length > 0 ? (
        <div data-testid="preflight-packages" style={{ marginTop: 6 }}>
          <Typography.Text type="secondary">发行版软件包（缺的经 apt 安装，--no-install-recommends，失败补偿时不卸载）：</Typography.Text>
          <ul style={{ margin: "4px 0 0", paddingLeft: 18 }}>
            {pkgs.map((p) => (
              <li key={p.package} className="mono-small" data-package={p.package} data-action={p.action}>
                <Tag color={PACKAGE_ACTION[p.action]?.color}>{PACKAGE_ACTION[p.action]?.label ?? p.action}</Tag>
                {p.package}
                {p.installed ? <Typography.Text type="secondary">{` 已安装 ${p.installed}`}</Typography.Text> : null}
                {p.action === "install" && p.candidate ? <Typography.Text type="secondary">{` 候选 ${p.candidate}`}</Typography.Text> : null}
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  );
}

/**
 * The firewall rules the install would add to the host (Docker FORWARD DROP
 * coexistence), shown outside the collapsed change list: they change a
 * chain on the host that is not Meridian's own table.
 */
export function ForwardRules({ rec }: { rec: PreflightRecord }) {
  const rules = rec.changes.filter((c) => c.kind === "firewall");
  if (rules.length === 0) return null;
  return (
    <div data-testid="preflight-fwcompat" style={{ marginTop: 12 }}>
      <Typography.Text strong>主机防火墙：在 DOCKER-USER 里加的放行规则（{rules.length} 条）</Typography.Text>
      <div>
        <Typography.Text type="secondary">
          只匹配 Meridian 自己的接口；不改 Docker 的链和规则、不改策略、不清空任何链。Docker 重启时自动重新加上，撤回和失败补偿按注释精确删除。
        </Typography.Text>
      </div>
      <ul style={{ margin: "4px 0 0", paddingLeft: 18 }}>
        {rules.map((c, i) => (
          <li key={i} className="mono-small" data-action={c.action}>
            <Tag color={c.action === "update" ? "gold" : "blue"}>{CHANGE_ACTION[c.action] ?? c.action}</Tag>
            {c.resource}
            {c.detail ? <Typography.Text type="secondary">（{c.detail}）</Typography.Text> : null}
          </li>
        ))}
      </ul>
    </div>
  );
}

const FILE_BASIS: Record<string, string> = {
  installed_manifest: "与网关上已安装的受管清单按文件内容比较（与部署页「待安装的改动」同一份比较）",
  host_manifest: "与节点上的受管清单按文件内容比较",
};

/** Order of file entries: what changes first. */
const FILE_ORDER: Record<string, number> = { change: 0, create: 1, remove: 2, not_compared: 3, replace: 4 };

/**
 * The per-file comparison in one line, outside the collapsed change list:
 * "nothing changes" is said plainly.
 */
export function FileChangesSummary({ fc }: { fc: PreflightFileChanges }) {
  const none = fc.added.length + fc.changed.length + fc.removed.length + fc.not_compared.length === 0;
  return (
    <div data-testid="preflight-file-summary" data-none={none ? "true" : "false"} style={{ marginTop: 12 }}>
      <Typography.Text strong>{fc.summary}</Typography.Text>
      <div>
        <Typography.Text type="secondary">
          {FILE_BASIS[fc.basis] ?? fc.basis}。只比较文件；接口、路由、监听等条目按这次安装要建立的状态列出，不与已安装的状态比较。
        </Typography.Text>
      </div>
    </div>
  );
}

/** File entries of the change list: what differs first, then the unchanged count (expandable). */
function FileChangeList({ list, fc }: { list: PreflightChange[]; fc?: PreflightFileChanges }) {
  const sorted = [...list].sort((a, b) => (FILE_ORDER[a.action] ?? 9) - (FILE_ORDER[b.action] ?? 9) || a.resource.localeCompare(b.resource));
  return (
    <>
      {sorted.length > 0 ? <ChangeItems list={sorted} /> : <Typography.Text type="secondary"> 没有要改动的文件</Typography.Text>}
      {fc && fc.unchanged.length > 0 ? (
        <details data-testid="preflight-unchanged" style={{ marginTop: 4, paddingLeft: 18 }}>
          <summary>
            <Typography.Text type="secondary">{fc.unchanged.length} 个文件内容不变</Typography.Text>
          </summary>
          <ul style={{ margin: "4px 0 0", paddingLeft: 18 }}>
            {fc.unchanged.map((p) => (
              <li key={p} className="mono-small">
                {p}
              </li>
            ))}
          </ul>
        </details>
      ) : null}
    </>
  );
}

function ChangeItems({ list }: { list: PreflightChange[] }) {
  return (
    <ul style={{ margin: "4px 0 0", paddingLeft: 18 }}>
      {list.map((c, i) => (
        <li key={i} className="mono-small" data-change={`${c.kind}:${c.action}`}>
          <Tag style={{ marginRight: 6 }} color={c.action === "remove" ? "volcano" : c.action === "change" ? "gold" : undefined}>
            {CHANGE_ACTION[c.action] ?? c.action}
          </Tag>
          {c.resource}
          {c.detail ? <Typography.Text type="secondary">（{c.detail}）</Typography.Text> : null}
        </li>
      ))}
    </ul>
  );
}

/** Why execution is not possible with this result, or null when it is. */
export function preflightBlockedReason(rec: PreflightRecord | null | undefined, now = new Date()): string | null {
  if (!rec) return "还没有预检：先预检并审阅结果";
  if (rec.blocking) return `预检有 ${rec.counts.blocking} 个阻断项：按每一项的处理办法解决后重新预检`;
  if (new Date(rec.expires_at).getTime() <= now.getTime()) return "预检结果已过期：重新预检";
  return null;
}

export function PreflightReport({ rec }: { rec: PreflightRecord }) {
  const groups = (["blocking", "warning", "info"] as const).map((sev) => ({ sev, items: rec.findings.filter((f) => f.severity === sev) }));
  const byKind = new Map<string, PreflightChange[]>();
  // With a file comparison the files come first (also when none changes).
  if (rec.file_changes) byKind.set("file", []);
  for (const c of rec.changes) byKind.set(c.kind, [...(byKind.get(c.kind) ?? []), c]);
  const t = rec.target;
  return (
    <div data-testid="preflight-report">
      {rec.blocking ? (
        <Alert
          type="error"
          showIcon
          style={{ marginBottom: 12 }}
          data-testid="preflight-blocked"
          message={`有 ${rec.counts.blocking} 个阻断项，不能执行`}
          description="面板不会覆盖或改动主机上已有的服务。按下面每一项的处理办法解决后重新预检；阻断项不能在面板里跳过。"
        />
      ) : (
        <Alert
          type={rec.counts.warning > 0 ? "warning" : "success"}
          showIcon
          style={{ marginBottom: 12 }}
          data-testid="preflight-ok"
          message={rec.counts.warning > 0 ? `没有阻断项，有 ${rec.counts.warning} 个警告` : "没有发现冲突"}
          description="执行前面板会在同一台主机（同一指纹）上再预检一次；结果变了会拒绝执行，让你重新审阅。"
        />
      )}
      <Facts
        items={[
          ["节点", <span key="n">{rec.node_name || rec.node_id}</span>],
          ...(t
            ? ([
                ["服务器", <span key="s">{t.server_name}</span>],
                ["地址", <Mono key="a">{`${t.user}@${t.address}:${t.port}`}</Mono>],
                ["固定指纹", <Mono key="f">{t.fingerprint}</Mono>],
                ["凭据", <span key="c">{t.credential_name || t.credential_id}</span>],
              ] as [ReactNode, ReactNode][])
            : ([["目标", "本机（经 meridian-host）"]] as [ReactNode, ReactNode][])),
          ["主机", <span key="h">{[rec.host.os, rec.host.arch, rec.host.kernel].filter(Boolean).join(" · ") || "—"}</span>],
          ["现状", <span key="o">{OWNERSHIP[rec.ownership] ?? rec.ownership}</span>],
          [
            "预检时间",
            <Space key="t" size={4}>
              <TimeText value={rec.at} />
              <Typography.Text type="secondary">（有效到 <TimeText value={rec.expires_at} />）</Typography.Text>
            </Space>,
          ],
        ]}
      />
      <InstallPlan rec={rec} />
      {rec.file_changes ? <FileChangesSummary fc={rec.file_changes} /> : null}
      <ForwardRules rec={rec} />
      {groups.map(({ sev, items }) =>
        items.length === 0 ? null : (
          <div key={sev} data-testid={`preflight-${sev}`} style={{ marginTop: 12 }}>
            <Typography.Text strong>
              {SEVERITY[sev].title}（{items.length}）
            </Typography.Text>
            {items.map((f, i) => (
              <Alert
                key={`${f.code}-${i}`}
                type={SEVERITY[sev].type}
                icon={SEVERITY[sev].icon}
                showIcon
                style={{ marginTop: 6 }}
                data-code={f.code}
                message={
                  <Space size={6} wrap>
                    <span>{f.message}</span>
                  </Space>
                }
                description={
                  f.action || f.resource ? (
                    <div>
                      {f.action ? (
                        <div>
                          <Typography.Text strong>处理办法：</Typography.Text>
                          {f.action}
                        </div>
                      ) : null}
                      {f.fix ? (
                        <div data-testid="preflight-fix">
                          <Link to={href("topology", f.fix.id)}>去拓扑修改：{f.fix.label}</Link>
                          <Typography.Text type="secondary">（保存后节点配置和对端的 Endpoint 一起更新，再重新预检）</Typography.Text>
                        </div>
                      ) : null}
                      <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                        {f.resource ? `资源：${f.resource} · ` : ""}代码 {f.code}
                      </Typography.Text>
                    </div>
                  ) : undefined
                }
              />
            ))}
          </div>
        ),
      )}
      <Collapse
        style={{ marginTop: 12 }}
        size="small"
        items={[
          {
            key: "changes",
            label: `拟执行的变更（${rec.changes.length} 项）`,
            children: (
              <div data-testid="preflight-changes">
                {[...byKind.entries()].map(([kind, list]) => (
                  <div key={kind} style={{ marginBottom: 8 }}>
                    <Typography.Text strong>{CHANGE_KIND[kind] ?? kind}</Typography.Text>
                    {kind === "file" ? <FileChangeList list={list} fc={rec.file_changes} /> : <ChangeItems list={list} />}
                  </div>
                ))}
              </div>
            ),
          },
          {
            key: "managed",
            label: "受管资源（这次装的东西，记进受管清单）",
            children: (
              <Facts
                items={[
                  ["接口", <span key="i" className="mono-small">{rec.footprint.interfaces.map((i) => i.name).join("  ") || "—"}</span>],
                  [
                    "监听",
                    <span key="l" className="mono-small">
                      {rec.footprint.listens.map((l) => `${l.proto} ${l.wildcard ? "*" : l.addr}:${l.port}`).join("  ") || "—"}
                    </span>,
                  ],
                  ["nft 表", <span key="n" className="mono-small">{rec.footprint.nft_tables.join("  ") || "—"}</span>],
                  ["路由表", <span key="r" className="mono-small">{rec.footprint.route_tables.join("  ") || "—"}</span>],
                  ["服务", <span key="u" className="mono-small">{rec.footprint.units.join("  ") || "—"}</span>],
                  [
                    "转发放行规则",
                    <span key="fw" className="mono-small" data-testid="preflight-managed-fw">
                      {rec.footprint.fw_rules && rec.footprint.fw_rules.length > 0
                        ? `${rec.footprint.fw_chain ?? "DOCKER-USER"} 里 ${rec.footprint.fw_rules.length} 条（注释 ${rec.footprint.fw_tag ?? "—"}，只在 FORWARD 策略为 DROP 的族里加）`
                        : "—"}
                    </span>,
                  ],
                  [
                    "内核参数只改这些接口",
                    <span key="sy" className="mono-small" data-testid="preflight-managed-sysctl">
                      {(rec.footprint.sysctl_ifaces ?? []).join("  ") || "—"}
                    </span>,
                  ],
                  ["文件", `${rec.footprint.files.length} 个`],
                ]}
              />
            ),
          },
          {
            key: "not",
            label: "预检不检查什么",
            children: (
              <ul style={{ margin: 0, paddingLeft: 18 }} data-testid="preflight-not-checked">
                {rec.not_checked.map((s) => (
                  <li key={s}>{s}</li>
                ))}
              </ul>
            ),
          },
        ]}
      />
    </div>
  );
}

/** Login trouble: what to do and the public key to paste (never a secret). */
export function LoginHelpView({ help }: { help: LoginHelp }) {
  return (
    <div data-testid="login-help" style={{ marginTop: 8 }}>
      {help.offered_methods && help.offered_methods.length > 0 ? (
        <div data-testid="login-offered" style={{ marginBottom: 4 }}>
          <Typography.Text type="secondary">服务器提供的登录方式：</Typography.Text>
          {help.offered_methods.map((m) => (
            <Tag key={m}>{m}</Tag>
          ))}
        </div>
      ) : null}
      <ol style={{ margin: "0 0 8px", paddingLeft: 18 }}>
        {help.steps.map((s) => (
          <li key={s}>{s}</li>
        ))}
      </ol>
      {help.public_key ? (
        <div>
          <Space style={{ marginBottom: 4 }}>
            <Typography.Text strong>{help.credential_name ?? "这份凭据"} 的公钥</Typography.Text>
            <CopyButton text={help.public_key} label="复制公钥" />
          </Space>
          <Mono block>{help.public_key}</Mono>
        </div>
      ) : null}
      {help.key_credentials?.map((k) => (
        <div key={k.id} style={{ marginTop: 6 }}>
          <Space style={{ marginBottom: 4 }}>
            <Typography.Text strong>{k.name} 的公钥</Typography.Text>
            <CopyButton text={k.public_key} label="复制公钥" />
          </Space>
          <Mono block>{k.public_key}</Mono>
        </div>
      ))}
    </div>
  );
}

/** The login help carried by an API error body, if any. */
export function loginHelpOf(e: ApiError | null | undefined): LoginHelp | null {
  const h = e?.body?.login_help;
  return h && typeof h === "object" ? (h as LoginHelp) : null;
}

/** The preflight record carried by a refused execution, if any. */
export function preflightOf(e: ApiError | null | undefined): PreflightRecord | null {
  const p = e?.body?.preflight;
  return p && typeof p === "object" ? (p as PreflightRecord) : null;
}

export function PreflightStatusIcon({ rec }: { rec: PreflightRecord | null | undefined }) {
  if (!rec) return null;
  return rec.blocking ? <CloseCircleFilled style={{ color: "var(--ant-color-error, #cf1322)" }} /> : <CheckCircleFilled style={{ color: "var(--ant-color-success, #389e0d)" }} />;
}
