// The install pre-check ("预检") as the operator reviews it before a first
// install, an update or a gateway install: the target identity it is bound
// to, what the install would change, and every finding grouped by severity
// with what was found and what to do. Blocking findings disable execution;
// nothing here can override them.

import { CheckCircleFilled, CloseCircleFilled, ExclamationCircleFilled, InfoCircleFilled } from "@ant-design/icons";
import { Alert, Button, Collapse, Space, Tag, Typography } from "antd";
import { useState, type ReactNode } from "react";
import * as api from "./api";
import type { ApiError } from "./api";
import type {
  LoginHelp,
  MTUAdoptResult,
  MTUChange,
  PreflightBinary,
  PreflightChange,
  PreflightFileChanges,
  PreflightFinding,
  PreflightPackage,
  PreflightRecord,
  UplinkStatus,
} from "./types";
import { href } from "./state";
import {
  ApiErrorAlert,
  CopyButton,
  Facts,
  Link,
  Mono,
  TimeText,
  useAction,
  useApi,
  Note,
  StatusTag,
} from "./ui";

const SEVERITY: Record<PreflightFinding["severity"], { title: string; type: "error" | "warning" | "info"; icon: ReactNode }> = {
  blocking: { title: "阻断：必须先处理", type: "error", icon: <CloseCircleFilled /> },
  warning: { title: "警告：确认后可以继续", type: "warning", icon: <ExclamationCircleFilled /> },
  info: { title: "信息", type: "info", icon: <InfoCircleFilled /> },
};

const OWNERSHIP: Record<string, string> = {
  none: "主机上没有 Meridian：第一次下发",
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
              <span className="muted" key="p" data-testid="preflight-platform">
                {rec.platform}
              </span>
            ) : (
              <StatusTag kind="failed" key="p" data-testid="preflight-platform">
                不在支持范围
              </StatusTag>
            ),
          ],
          ["架构", <Mono key="a">{rec.host.arch || "未知"}</Mono>],
          ["内存", <span key="m">{`共 ${kb(rec.host.mem_total_kb)}，可用 ${kb(rec.host.mem_avail_kb)}`}</span>],
        ]}
      />
      {bins.length > 0 ? (
        <div data-testid="preflight-binaries" style={{ marginTop: 6 }}>
          <Note inline>面板下发的二进制（固定版本，按架构区分，主机不下载任何东西；激活前在主机上再校验 SHA-256）：</Note>
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
          <Note inline>发行版软件包（缺的经 apt 安装，--no-install-recommends，失败补偿时不卸载）：</Note>
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
        <Note inline>只匹配 Meridian 自己的接口；不改 Docker 的链和规则、不改策略、不清空任何链。Docker 重启时自动重新加上，撤回和失败补偿按注释精确删除。</Note>
      </div>
      <ul style={{ margin: "4px 0 0", paddingLeft: 18 }}>
        {rules.map((c, i) => (
          <li key={i} className="mono-small" data-action={c.action}>
            <span className="muted">{CHANGE_ACTION[c.action] ?? c.action}</span>
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
        <Note inline>{FILE_BASIS[fc.basis] ?? fc.basis}。只比较文件；接口、路由、监听等条目按这次安装要建立的状态列出，不与已安装的状态比较。</Note>
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
          {c.action === "remove" ? (
            <StatusTag kind="attention">{CHANGE_ACTION[c.action] ?? c.action}</StatusTag>
          ) : (
            <span className="muted">{CHANGE_ACTION[c.action] ?? c.action} </span>
          )}
          {c.resource}
          {c.detail ? <Typography.Text type="secondary">（{c.detail}）</Typography.Text> : null}
        </li>
      ))}
    </ul>
  );
}

const arr = <T,>(v: T[] | null | undefined): T[] => (Array.isArray(v) ? v.filter((x) => x != null) : []);

/**
 * A preflight record with every list present (a missing or null list is
 * empty, null entries dropped) and the counts derived when absent: records
 * also arrive inside refusals, stored runs and older panels' answers, and a
 * missing list must not take the deploy page down.
 */
export function normalizePreflight(rec: PreflightRecord): PreflightRecord {
  const fp = (rec.footprint ?? {}) as Partial<PreflightRecord["footprint"]>;
  const findings = arr(rec.findings).map((f) => ({ ...f, code: f.code ?? "", message: f.message ?? "" }));
  const count = (sev: string) => findings.filter((f) => f.severity === sev).length;
  const fc = rec.file_changes;
  return {
    ...rec,
    host: rec.host ?? ({ mem_total_kb: -1, mem_avail_kb: -1, complete: false } as PreflightRecord["host"]),
    findings,
    changes: arr(rec.changes).map((c) => ({ ...c, kind: c.kind ?? "", action: c.action ?? "", resource: c.resource ?? "" })),
    not_checked: arr(rec.not_checked),
    counts: rec.counts ?? { blocking: count("blocking"), warning: count("warning"), info: count("info") },
    footprint: {
      ...fp,
      files: arr(fp.files),
      interfaces: arr(fp.interfaces),
      listens: arr(fp.listens),
      route_tables: arr(fp.route_tables),
      nft_tables: arr(fp.nft_tables),
      units: arr(fp.units),
    } as PreflightRecord["footprint"],
    file_changes: fc
      ? {
          ...fc,
          added: arr(fc.added),
          changed: arr(fc.changed),
          removed: arr(fc.removed),
          unchanged: arr(fc.unchanged),
          not_compared: arr(fc.not_compared),
          summary: fc.summary ?? "",
        }
      : undefined,
  };
}

/** Why execution is not possible with this result, or null when it is. */
export function preflightBlockedReason(rec: PreflightRecord | null | undefined, now = new Date()): string | null {
  if (!rec) return "还没有预检：先预检并审阅结果";
  if (rec.blocking) return `预检有 ${rec.counts?.blocking ?? "若干"} 个阻断项：按每一项的处理办法解决后重新预检`;
  if (new Date(rec.expires_at).getTime() <= now.getTime()) return "预检结果已过期：重新预检";
  return null;
}

export function PreflightReport({ rec: raw }: { rec: PreflightRecord }) {
  const rec = normalizePreflight(raw);
  const groups = (["blocking", "warning", "info"] as const).map((sev) => ({ sev, items: rec.findings.filter((f) => f.severity === sev) }));
  const byKind = new Map<string, PreflightChange[]>();
  // With a file comparison the files come first (also when none changes).
  if (rec.file_changes) byKind.set("file", []);
  for (const c of rec.changes) byKind.set(c.kind, [...(byKind.get(c.kind) ?? []), c]);
  const t = rec.target;
  const infos = groups.find((g) => g.sev === "info")!.items;
  return (
    <div data-testid="preflight-report" data-prose-exempt>
      {rec.blocking ? (
        <Alert
          type="error"
          showIcon
          style={{ marginBottom: 12 }}
          data-testid="preflight-blocked"
          message={`有 ${rec.counts.blocking} 个阻断项，不能执行`}
        />
      ) : (
        <Alert
          type={rec.counts.warning > 0 ? "warning" : "success"}
          showIcon
          style={{ marginBottom: 12 }}
          data-testid="preflight-ok"
          message={rec.counts.warning > 0 ? `没有阻断项，有 ${rec.counts.warning} 个警告` : "没有发现冲突"}
        />
      )}
      {rec.file_changes ? <FileChangesSummary fc={rec.file_changes} /> : null}
      <ForwardRules rec={rec} />
      {groups.filter((g) => g.sev !== "info").map(({ sev, items }) =>
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
                          <Note inline>（保存后节点配置和对端的 Endpoint 一起更新，再重新预检）</Note>
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
            key: "host",
            label: "主机与安装计划",
            forceRender: true,
            children: (
              <>
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
              </>
            ),
          },
          ...(infos.length > 0
            ? [
                {
                  key: "info",
                  label: `${SEVERITY.info.title}（${infos.length}）`,
                  forceRender: true,
                  children: (
                    <div data-testid="preflight-info">
                      {infos.map((f, i) => (
                        <div key={`${f.code}-${i}`} data-code={f.code} style={{ marginBottom: 4 }}>
                          {f.message}
                          {f.action ? <Typography.Text type="secondary">{` · ${f.action}`}</Typography.Text> : null}
                        </div>
                      ))}
                    </div>
                  ),
                },
              ]
            : []),
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
            <span className="muted" key={m}>{m}</span>
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
  return p && typeof p === "object" && typeof (p as { id?: unknown }).id === "string" ? normalizePreflight(p as PreflightRecord) : null;
}

export function PreflightStatusIcon({ rec }: { rec: PreflightRecord | null | undefined }) {
  if (!rec) return null;
  return rec.blocking ? <CloseCircleFilled style={{ color: "var(--m-bad)" }} /> : <CheckCircleFilled style={{ color: "var(--m-ok)" }} />;
}

// ------------------------------------------------------------ uplink MTU ---

const UPLINK_STATUS: Record<UplinkStatus, { label: string; color: string }> = {
  fits: { label: "能承载", color: "green" },
  too_small: { label: "承载不了", color: "red" },
  tcp_carrier: { label: "WSS：TCP 承载", color: "blue" },
  unknown: { label: "未验证", color: "default" },
  stale: { label: "已过期，未验证", color: "default" },
  no_preflight: { label: "没有预检", color: "default" },
};

function mtuFrom(c: MTUChange): string {
  return c.from === 0 ? `${c.from_effective ?? "默认值"}（默认值）` : String(c.from);
}

/**
 * The uplink MTU of both ends of every tunnel leg (from the latest preflights)
 * and the explicit adoption of a suggested tunnel MTU. Adopting only writes the
 * links' MTU field after a second, explicit confirmation that shows the
 * per-node differences; nothing reaches a host until the deploy page's own
 * review and confirmation. `dirty`: the topology editor has unsaved edits
 * (adoption is refused until they are saved or discarded).
 */
export function UplinkMTUCard({ dirty, onAdopted }: { dirty: boolean; onAdopted: () => void }) {
  const view = useApi(() => api.uplinkMTU(), []);
  const act = useAction();
  const [confirming, setConfirming] = useState(false);
  const [done, setDone] = useState<MTUAdoptResult | null>(null);
  const v = view.data;
  if (view.error) return <ApiErrorAlert error={view.error} onRetry={() => void view.reload()} />;
  if (!v) return null;
  const bad = v.legs.filter((l) => l.status === "too_small");
  const unverified = v.legs.filter((l) => l.status === "unknown" || l.status === "stale" || l.status === "no_preflight").length;
  const verified = v.legs.filter((l) => l.status === "fits" || l.status === "tcp_carrier").length;
  const p = v.proposal;
  const adopt = async () => {
    if (!p) return;
    const r = await act.run(() => api.adoptUplinkMTU(p.changes), "adopt");
    if (r) {
      setDone(r);
      setConfirming(false);
      onAdopted();
      void view.reload();
    }
  };
  return (
    <div data-testid="uplink-mtu">
      <Note>
        各隧道两端上联能承载的隧道 MTU，来自最近 {v.ttl_hours} 小时内、与现在的服务器和隧道走向一致的预检：{verified} 条已验证，{bad.length} 条承载不了，{unverified}{" "}
        条未验证（未验证不算通过，面板也不会据此改任何配置）。
      </Note>
      {bad.map((l) => (
        <div key={`${l.link_id}/${l.mode}`} className="path-row" data-testid="uplink-leg" data-link={l.link_id}>
          <Space wrap size={4}>
            <Link to={href("topology", l.link_id)}>{l.link_name || l.link_id}</Link>
            <Mono>{l.iface}</Mono>
            <span className="mono-small">
              隧道 MTU {l.tunnel_mtu}
              {l.suggested ? ` → 建议 ${l.suggested}` : ""}
            </span>
            {l.ends.map((e) => (
              <Tag key={e.node_id} color={UPLINK_STATUS[e.status]?.color} data-testid="uplink-end">
                {e.node_name || e.node_id}：{UPLINK_STATUS[e.status]?.label ?? e.status}
                {e.uplink_mtu ? `（${e.dev ?? ""} ${e.uplink_mtu}，IPv${e.family}${e.shortfall ? `，超出 ${e.shortfall} 字节` : ""}）` : ""}
              </Tag>
            ))}
          </Space>
          {l.note ? <Typography.Text type="secondary"> {l.note}</Typography.Text> : null}
        </div>
      ))}
      {done ? (
        <Alert
          type="success"
          showIcon
          style={{ marginTop: 8 }}
          data-testid="uplink-adopted"
          message={done.message}
          description={
            <>
              {done.adopted.map((c) => `${c.link_id}：${mtuFrom(c)} → ${c.to}`).join("；")}。<Link to={href("deploy")}>去部署页审阅并确认</Link>
            </>
          }
        />
      ) : null}
      {p && !confirming ? (
        <Space direction="vertical" style={{ marginTop: 8 }}>
          <Button onClick={() => setConfirming(true)} disabled={dirty || !!p.error} data-testid="uplink-adopt-open">
            采用建议值…
          </Button>
          {dirty ? <Typography.Text type="warning">拓扑有未保存的修改：先保存或放弃</Typography.Text> : null}
          {p.error ? <Typography.Text type="danger">{p.error}</Typography.Text> : null}
        </Space>
      ) : null}
      {p && confirming ? (
        <Alert
          type="warning"
          style={{ marginTop: 8 }}
          data-testid="uplink-adopt-confirm"
          message="采用这些建议值？只改拓扑里的 MTU 字段，不下发"
          description={
            <>
              <ul className="plain-list">
                {p.changes.map((c) => (
                  <li key={c.link_id} data-testid="uplink-change">
                    链路 <Mono>{c.link_id}</Mono> 的「{c.field === "mtu" ? "MTU" : c.field}」：{mtuFrom(c)} → {c.to}
                  </li>
                ))}
              </ul>
              <div>保存后各节点要下发的文件会变（部署页预检、审阅每个节点的变更并确认后才生效）：</div>
              <ul className="plain-list" data-testid="uplink-node-diffs">
                {p.nodes.map((n) => (
                  <li key={n.node_id} data-node={n.node_id}>
                    {n.node_name || n.node_id}：<span className="mono-small">{n.files.join("、")}</span>
                  </li>
                ))}
              </ul>
              {p.paths.length > 0 ? (
                <ul className="plain-list" data-testid="uplink-path-diffs">
                  {p.paths.map((x) => (
                    <li key={x.exit_id}>
                      到 {x.exit_id} 的路径 MTU {x.mtu_before} → {x.mtu_after}，MSS {x.mss4_before}/{x.mss6_before} → {x.mss4_after}/{x.mss6_after}（转发、嗅探和本机连接的钳制一起变）
                    </li>
                  ))}
                </ul>
              ) : (
                <div>各出口路径的 MTU 和 MSS 钳制不变。</div>
              )}
              {(p.group_paths ?? []).length > 0 ? (
                <ul className="plain-list" data-testid="uplink-group-path-diffs">
                  {(p.group_paths ?? []).map((x) => (
                    <li key={x.group_id}>
                      地区组 {x.group_id}{x.mesh ? "（含 Mesh 备路）" : ""}的路径 MTU {x.mtu_before} → {x.mtu_after}，MSS {x.mss4_before}/{x.mss6_before} → {x.mss4_after}/{x.mss6_after}
                    </li>
                  ))}
                </ul>
              ) : null}
              <Space style={{ marginTop: 8 }}>
                <Button type="primary" loading={act.busy === "adopt"} onClick={() => void adopt()} disabled={dirty} data-testid="uplink-adopt-ok">
                  确认写入拓扑
                </Button>
                <Button onClick={() => setConfirming(false)}>取消</Button>
              </Space>
            </>
          }
        />
      ) : null}
      {act.error ? <ApiErrorAlert error={act.error} /> : null}
      <Collapse
        ghost
        size="small"
        items={[{ key: "nv", label: "预检证明了什么、没证明什么", children: <ul className="plain-list">{v.not_verified.map((x) => <li key={x}>{x}</li>)}</ul> }]}
      />
    </div>
  );
}
