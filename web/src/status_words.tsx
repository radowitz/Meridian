// Status words shared by the overview and the pages it summarises: a
// server's readiness, a region group's hub-reported state and carrying hub,
// and the Mesh journal / permission-check summaries. In a module of their
// own so the overview (the first page after login) does not load the
// exits, servers, keys and Mesh pages to show a tag (web/README.md
// 「首屏与拆包」).

import { Typography } from "antd";
import type { Carrying, GroupActualView, HubTier, NodeInstallState, PermissionCheck, ServerView, SOCKSCredentialView, SOCKSVersionTracking } from "./types";
import { StatusTag, TimeText, type StatusKind } from "./ui";

// --------------------------------------------------------------- servers ---

export function serverReadiness(s: ServerView): { kind: StatusKind; label: string } {
  if (s.host_key.state === "mismatch") return { kind: "failed", label: "指纹不符" };
  if (s.ready) return { kind: "ok", label: "就绪" };
  if (s.last_test && !s.last_test.ok && s.operable) return { kind: "failed", label: "连接失败" };
  return { kind: "attention", label: "需要处理" };
}

// ------------------------------------------------------- actual (hub) ---

/** Machine reasons of a non-ok actual state, in words. */
export const ACTUAL_CODE: Record<string, string> = {
  no_hub: "拓扑里没有枢纽节点",
  hub_no_server: "枢纽节点没有关联服务器",
  server_not_ready: "枢纽服务器还不能登录（指纹未确认或没有凭据）",
  ssh_failed: "登录枢纽读取状态失败",
  state_missing: "枢纽上没有这个组的运行记录",
  parse_error: "枢纽返回的内容无法解析",
  invalid_report: "枢纽报告的成员不属于这个组",
  plan_unavailable: "面板无法编译当前的地区组计划",
  heartbeat_old: "枢纽的心跳已过期",
  read_old: "上次读取太久了",
  plan_differs: "枢纽运行的不是当前配置",
  hop_failed: "枢纽切换路由失败",
  table_diverged: "枢纽路由表与切换器的选择不一致",
  static_only: "枢纽不切换这个组",
  not_read: "还没有读取枢纽状态",
  hub_identity_changed: "上次读取的不是当前枢纽（枢纽节点、服务器、地址、SSH 端口或主机指纹已变更），需要重新读取",
  carrying_unknown: "不知道现在由哪个枢纽承载",
};

// ------------------------------------------------------ carrying hub ---

export const HUB_TIER: Record<HubTier, string> = { primary: "主枢纽", backup: "备用枢纽" };

/** The gateway's path to the carrying hub (compile.planUpstream names). */
const UPSTREAM_PATH: Record<string, string> = { udp: "主路径 UDP", wss: "主路径 WSS", backup: "经 WSS", main: "主链路，多中继分担" };

/** The gateway's failover state in words (carrying.state). */
export const CARRYING_STATE: Record<string, { kind: StatusKind; label: string }> = {
  static: { kind: "unverified", label: "安装时设定" },
  ok: { kind: "ok", label: "已测量" },
  switching: { kind: "running", label: "切换中" },
  down: { kind: "failed", label: "全部路径不通" },
  degraded: { kind: "attention", label: "全部中继低于下限" },
};

/** Why the carrying hub is unknown (carrying.code). */
export const CARRYING_CODE: Record<string, string> = {
  agent_unavailable: "读不到本机 host agent",
  read_failed: "读取网关上游记录失败",
  not_recorded: "网关还没有上游记录",
  invalid_record: "网关的上游记录无法解析",
  record_mismatch: "网关记录的枢纽与当前拓扑不一致",
  stale: "网关的上游记录已过期",
};

/** "当前承载：备用枢纽 hkb（经 WSS，自 …）" or "承载枢纽未知：…". */
export function CarryingLine({ c }: { c: Carrying }) {
  if (!c.known) {
    return (
      <span data-testid="carrying" data-known="false">
        <Typography.Text type="warning">承载枢纽未知：</Typography.Text>
        <Typography.Text type="secondary">{c.message || CARRYING_CODE[c.code ?? ""] || c.code || "—"}</Typography.Text>
      </span>
    );
  }
  const st = c.state ? CARRYING_STATE[c.state] : undefined;
  const path = c.path ? UPSTREAM_PATH[c.path] ?? c.path : "";
  return (
    <span data-testid="carrying" data-known="true" data-tier={c.tier}>
      <Typography.Text type="secondary">当前承载：</Typography.Text>
      <Typography.Text strong>
        {c.tier ? HUB_TIER[c.tier] : "枢纽"} {c.hub_name || c.hub_node}
      </Typography.Text>
      {path || c.since ? (
        <Typography.Text type="secondary">
          （{path}
          {path && c.since ? "，" : ""}
          {c.since ? (
            <>
              自 <TimeText value={c.since} />
            </>
          ) : null}
          ）
        </Typography.Text>
      ) : null}{" "}
      {st ? (
        <StatusTag kind={st.kind} title={c.message}>
          {st.label}
        </StatusTag>
      ) : null}
    </span>
  );
}

/** Tag for a group's actual state: never "ok"-coloured unless the hub reported it. */
export function actualTag(a: GroupActualView): { kind: StatusKind; label: string } {
  switch (a.state) {
    case "ok":
      return { kind: "ok", label: "枢纽报告" };
    case "switch_failed":
      return { kind: "failed", label: "切换失败" };
    case "stale":
      return { kind: "unverified", label: "未验证 · 状态过期" };
    case "version_mismatch":
      return { kind: "unverified", label: "未验证 · 枢纽不是当前配置" };
    case "not_switchable":
      return { kind: "neutral", label: "枢纽不切换" };
    case "never_read":
      return { kind: "unverified", label: "未验证 · 未读取" };
    default:
      if (a.code === "hub_identity_changed") return { kind: "unverified", label: "未验证 · 枢纽已变更" };
      return { kind: "unverified", label: "未验证 · 读不到" };
  }
}

// ------------------------------------------------------------------ Mesh ---

export const JOURNAL_STATE: Record<string, { kind: StatusKind; label: string }> = {
  running: { kind: "running", label: "部署中（或被中断）" },
  published: { kind: "unverified", label: "路由已发布 · 数据面未验证" },
  failed: { kind: "failed", label: "失败，已撤回本次创建的资源" },
  compensating: { kind: "running", label: "撤回中（或被中断）" },
  compensation_failed: { kind: "failed", label: "撤回未完成" },
  withdrawn: { kind: "neutral", label: "已撤回" },
};

/** Summary of a permission check. A pass is never shown as a plain "正常". */
export function checkSummary(c: PermissionCheck | null | undefined): { kind: StatusKind; label: string } {
  if (!c) return { kind: "neutral", label: "未检查" };
  if (c.ok) return { kind: "unverified", label: "可读 · 写权限未确认" };
  if (c.missing && c.missing.length > 0) return { kind: "failed", label: "缺少权限" };
  return { kind: "attention", label: "检查未完成" };
}

// ------------------------------------------- SOCKS credential versions ---
//
// A SOCKS credential's version counts its values (1 when created, +1 per
// rotation). It is compiled into the carrier's configuration, so a
// rotation shows on the carrier as pending — except for credentials that
// existed before the panel recorded versions and have not been rotated
// since: a line for them would have made every carrier pending on upgrade.

/** Tag of an in-sync carrier whose install recorded no version of a SOCKS credential it uses. */
export const SOCKS_UNRECORDED_LABEL = "凭据版本未记录";

/** What that tag means, when the backend sent no sentence of its own. */
export const SOCKS_UNRECORDED_TEXT =
  "这个节点承载的外部 SOCKS 出口使用的凭据在面板开始记录凭据版本之前就已存在，节点安装时没有记录用的是哪一版：面板不能证明节点上的用户名和密码就是现在保存的。升级本身不把它算作待下发；要确认，重新预检并安装一次（配置内容不变）。此后每次轮换都会让它显示待下发。";

/** "socks-… 版本 3、…" (credential ids in order). */
export function socksVersionsText(m: Record<string, number> | undefined): string {
  return Object.keys(m ?? {})
    .sort()
    .map((id) => `${id} 版本 ${m![id]}`)
    .join("、");
}

/** The tooltip lines of a carrier's SOCKS credential versions (none for a node that carries no external exit). */
export function socksStateLines(st: NodeInstallState): string[] {
  const planned = socksVersionsText(st.socks_versions);
  const installed = socksVersionsText(st.installed_socks_versions);
  const lines: string[] = [];
  if (planned && installed && planned !== installed) lines.push(`外部 SOCKS 凭据：现在是 ${planned}；已安装 ${installed}`);
  else if (installed) lines.push(`外部 SOCKS 凭据：已安装 ${installed}`);
  else if (planned) lines.push(`外部 SOCKS 凭据：现在是 ${planned}；已安装的版本没有记录`);
  if (st.note) lines.push(st.note);
  else if (st.state === "in_sync" && st.socks_unrecorded?.length) lines.push(SOCKS_UNRECORDED_TEXT);
  return lines;
}

/** "版本 3", and for a credential from before versions were recorded that it has not been rotated since. */
export function SocksVersionText({ c }: { c: SOCKSCredentialView }) {
  if (!c.version) return null;
  return (
    <Typography.Text type="secondary" data-testid={`socks-version-${c.id}`}>
      版本 {c.version}
      {c.tracked === false ? "（记录版本之前已有，未轮换过）" : ""}
    </Typography.Text>
  );
}

/** The credentials whose carriers' installed version is not recorded: from before versions, not rotated since, and in use. */
export function socksUnrecorded(list: SOCKSCredentialView[]): SOCKSCredentialView[] {
  return list.filter((c) => c.tracked === false && (c.carriers?.length ?? 0) > 0);
}

/** Why rotations are not tracked yet ("" when they are, or when the backend does not say). */
export function socksTrackingProblem(t: SOCKSVersionTracking | undefined): string {
  if (!t || t.ready) return "";
  return `面板还没能写入 SOCKS 凭据的版本基线${t.error ? `（${t.error}）` : ""}：在写入之前，承载节点的配置按原样生成，轮换不会让承载节点显示待下发。下次启动面板、新建或轮换 SOCKS 凭据时会重试。`;
}

/** The message after a rotation: which carriers now wait for an install. */
export function socksRotatedMessage(res: { credential: SOCKSCredentialView; pending?: string[]; note?: string }): string {
  if (res.note) return res.note;
  if (res.pending?.length) return `已轮换：承载节点 ${res.pending.join("、")} 待下发，重新预检并安装后才用新的用户名和密码`;
  return "已轮换；承载节点重新下发后生效";
}
