// The install pre-check ("预检") as the operator reviews it before a first
// install, an update or a gateway install: the target identity it is bound
// to, what the install would change, and every finding grouped by severity
// with what was found and what to do. Blocking findings disable execution;
// nothing here can override them.

import { CheckCircleFilled, CloseCircleFilled, ExclamationCircleFilled, InfoCircleFilled } from "@ant-design/icons";
import { Alert, Collapse, Space, Tag, Typography } from "antd";
import type { ReactNode } from "react";
import type { ApiError } from "./api";
import type { LoginHelp, PreflightChange, PreflightFinding, PreflightRecord } from "./types";
import { CopyButton, Facts, Mono, TimeText } from "./ui";

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
};

const CHANGE_ACTION: Record<string, string> = {
  create: "新建",
  replace: "替换",
  update: "更新",
  bind: "绑定",
  add: "添加",
  enable: "启用",
  install: "安装",
  set: "设置",
};

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
                    <ul style={{ margin: "4px 0 0", paddingLeft: 18 }}>
                      {list.map((c, i) => (
                        <li key={i} className="mono-small">
                          <Tag style={{ marginRight: 6 }}>{CHANGE_ACTION[c.action] ?? c.action}</Tag>
                          {c.resource}
                          {c.detail ? <Typography.Text type="secondary">（{c.detail}）</Typography.Text> : null}
                        </li>
                      ))}
                    </ul>
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
