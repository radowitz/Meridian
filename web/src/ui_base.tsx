// The shell-level building blocks: what the application shell and the
// login gate (App.tsx) need before any page is loaded — the status
// vocabulary, error display, in-app links, monospace text and the
// pending-install indicator. Kept apart from ui.tsx so the entry chunk does
// not pull in the table, dialog and pagination code every page shares.
// Pages keep importing everything from "./ui", which re-exports this module
// (web/README.md「首屏与拆包」).

import {
  CheckCircleFilled,
  CloseCircleFilled,
  CopyOutlined,
  ExclamationCircleFilled,
  MinusCircleOutlined,
  QuestionCircleOutlined,
  ReloadOutlined,
  SyncOutlined,
  UserOutlined,
  CloudUploadOutlined,
} from "@ant-design/icons";
import { Alert, App as AntApp, Button, Space, Tag, Tooltip, Typography } from "antd";
import { useEffect, useState, type CSSProperties, type ReactNode } from "react";
import { ApiError } from "./api";
import * as api from "./api";
import { href, useOptionalRouter, useOptionalStatus, useRouter, useStatus } from "./state";
import type { IndependentFieldRefusal, Ref, RulesFastApply } from "./types";

// ======================================================== status vocabulary ===

/**
 * The one status vocabulary of the panel. Colours and wording are fixed:
 * a configured or reachable state must never look like a verified one.
 *
 * - ok          正常 / 已完成 — really executed and passed
 * - attention   需要处理 — the user has to do something
 * - failed      失败
 * - pending     配置完成但尚未安装 — stored, nothing on the host yet
 * - unverified  未验证 — exists / reachable, not proven to work
 * - signoff     待人工签收 — only a human check can close it
 * - running     进行中
 * - neutral     未配置 / 不适用 / 未知
 */
export type StatusKind = "ok" | "attention" | "failed" | "pending" | "unverified" | "signoff" | "running" | "neutral";

export const STATUS: Record<StatusKind, { label: string; color: string; icon: ReactNode }> = {
  ok: { label: "正常", color: "success", icon: <CheckCircleFilled /> },
  attention: { label: "需要处理", color: "warning", icon: <ExclamationCircleFilled /> },
  failed: { label: "失败", color: "error", icon: <CloseCircleFilled /> },
  pending: { label: "配置完成但尚未安装", color: "geekblue", icon: <CloudUploadOutlined /> },
  unverified: { label: "未验证", color: "purple", icon: <QuestionCircleOutlined /> },
  signoff: { label: "待人工签收", color: "cyan", icon: <UserOutlined /> },
  running: { label: "进行中", color: "processing", icon: <SyncOutlined spin /> },
  neutral: { label: "未配置", color: "default", icon: <MinusCircleOutlined /> },
};

/** States that get a coloured tag: something failed, needs attention or a human sign-off. */
export const PROBLEM: ReadonlySet<StatusKind> = new Set<StatusKind>(["attention", "failed", "signoff"]);

/** `<StatusTag kind="unverified">数据面未验证</StatusTag>`; children override the label, never the colour. */
export function StatusTag({ kind, children, title, "data-testid": testId }: { kind: StatusKind; children?: ReactNode; title?: ReactNode; "data-testid"?: string }) {
  const s = STATUS[kind];
  // Only problems are coloured; healthy and neutral states are plain muted text.
  if (!PROBLEM.has(kind)) {
    const text = (
      <span className={`status-text status-${kind}`} data-status={kind} data-testid={testId} tabIndex={title ? 0 : undefined}>
        {children ?? s.label}
      </span>
    );
    return title ? <Tooltip title={title}>{text}</Tooltip> : text;
  }
  const tag = (
    <Tag color={s.color} icon={s.icon} className={`status-tag status-${kind}`} data-status={kind} data-testid={testId}>
      {children ?? s.label}
    </Tag>
  );
  return title ? <Tooltip title={title}>{tag}</Tooltip> : tag;
}

// =================================================================== errors ===

/** Chinese wording for the API's machine-readable codes, in one place. */
export const ERROR_TEXT: Record<string, string> = {
  network: "无法连接面板服务",
  unauthorized: "需要面板口令",
  bad_request: "请求格式错误",
  invalid_field: "填写的内容不符合要求",
  unknown_field: "请求里有面板不认识的字段",
  field_removed: "请求里有已移除的字段",
  not_found: "对象不存在",
  hub_identity_changed: "读取期间枢纽已变更，这次结果已丢弃",
  conflict: "对象已被修改，请刷新后重试",
  in_use: "仍被其他对象引用",
  storage_error: "面板存储出错",
  insecure_storage: "凭据存储的文件权限不安全",
  kind_mismatch: "凭据种类与认证方式不一致",
  invalid_key: "无法识别这把私钥",
  passphrase_required: "这把私钥带口令，需要填写口令",
  passphrase_invalid: "私钥口令不正确",
  no_credential: "还没有选择 SSH 凭据",
  host_key_not_discovered: "还没有获取主机指纹",
  host_key_changed: "主机指纹在确认前变了",
  host_key_untrusted: "主机指纹还没有确认",
  host_key_mismatch: "主机指纹与固定值不符，已拒绝连接",
  host_key_not_pinned_by_deployment: "主机指纹与部署记录固定的不一致",
  target_changed: "服务器的地址、指纹或凭据与固定的不一致",
  unreachable: "连不上这台服务器",
  timeout: "连接超时",
  ssh_banner_timeout: "连上了，但服务器没有发出 SSH 版本行（超时）",
  ssh_handshake_timeout: "SSH 握手超时",
  ssh_closed_before_banner: "服务器在 SSH 握手之前就断开了连接",
  run_timeout: "远端执行超时，结果不明",
  run_interrupted: "远端执行中连接断开，结果不明",
  jump_forward_refused: "中继不允许转发到这台服务器",
  channel_not_allowed: "这个管理通道不能使用",
  not_ssh: "对端不是 SSH 服务",
  auth_failed: "SSH 登录被拒绝：服务器不接受这份凭据",
  auth_method_unavailable: "服务器不接受这种登录方式",
  ssh_rate_limited: "服务器暂时拒绝面板的来源地址（限速），稍后再试",
  command_failed: "远端命令执行失败",
  account_locked: "账户被未撤回完的 Mesh 部署绑定",
  check_failed: "权限检查无法进行",
  no_server: "节点还没有关联服务器",
  servers_not_ready: "有节点的服务器还没就绪",
  no_mesh_account: "还没有选择 Mesh 使用的 Cloudflare 账户",
  busy: "已有部署或撤回在进行",
  hosts_blocked: "部署记录固定的主机不可用，未撤回任何资源",
  account_mismatch: "当前 Mesh 账户与部署绑定的账户不同",
  nothing_to_withdraw: "没有需要撤回的部署",
  journal_too_new: "部署记录来自更新版本的面板",
  stage_failed: "部署阶段失败",
  update_running: "名单更新已在进行",
  host_unavailable: "宿主执行通道不可用",
  invalid_lists: "拓扑里的名单无法提交给宿主",
  remote_pool_full: "远程接入地址池已满",
  gateway_server: "网关不能关联远端服务器",
  unknown_server: "节点引用的服务器不存在",
  server_shared: "两个节点不能共用一台服务器",
  ssh_fields_moved: "SSH 地址已移到服务器管理",
  // install / rollback (POST /api/apply, /api/rollback, /api/host/recover)
  legacy_install_refused: "网关上的旧版 Meridian 无法可靠接管",
  transaction_pending: "上一次宿主事务没有完成，先恢复",
  peer_keys_missing: "有对端节点还没有可用的公钥",
  topology_invalid: "拓扑校验没有通过",
  lan_interface_mismatch: "网关的局域网接口不一致",
  activation_failed_compensated: "启动失败，已补偿回事务前",
  activation_failed_uncompensated: "启动失败，补偿也失败了",
  commit_failed: "网关已生效，但提交记录失败",
  nothing_to_rollback: "没有上一份配置可以回滚",
  rollback_mode_required: "网关已安装，回滚必须包含宿主网络",
  gateway_key_unavailable: "网关私钥无法取得",
  host_state_malformed: "宿主事务状态文件损坏",
  apply_failed: "安装或回滚没有完成",
  // install pre-check (POST /api/provision/preflight, /api/host/preflight)
  preflight_required: "第一次安装前必须先预检",
  preflight_stale: "预检结果已过期或已被替换，需要重新预检",
  preflight_blocked: "预检有阻断项，没有执行",
  preflight_changed: "执行前重新预检出现了新问题，没有执行",
  preflight_failed: "预检没有完成",
  // whole-topology save (PUT /api/topology)
  independent_resource_changed: "这些内容要在各自的页面修改，整份拓扑保存没有写入任何内容",
  preflight_bad_args: "预检参数不合法",
  bundle_changed: "预检之后要下发的配置变了，需要重新预检",
  node_busy: "这个节点正在预检或下发",
  provision_refused: "服务器上的执行前复核拒绝了下发，没有改动",
  provision_failed_compensated: "下发失败，已补偿",
  provision_failed_leftovers: "下发失败，有残留没有撤掉",
  // withdraw (POST /api/provision/withdraw*, /api/host/withdraw)
  withdraw_refused: "服务器上的撤回脚本拒绝执行，没有改动",
  withdraw_partial: "撤回没有全部完成",
  withdraw_unknown: "撤回结果不明，不当作完成",
  recovery_incomplete: "补偿没有全部完成",
  withdraw_plan_stale: "撤回计划已过期或已被替换，需要重新生成",
  confirm_required: "需要输入确认内容",
  mesh_deployed: "Mesh 还部署在这台主机上，先撤回 Mesh",
  deployed_elsewhere: "节点还装在之前的服务器上，先撤回那里的安装",
  nothing_installed: "网关上没有受管的安装",
  legacy_install: "旧版 Meridian（没有清单），不能按清单撤回",
  guard_missing: "已安装清单里没有局域网兜底表，拒绝撤回",
  not_withdrawn: "网关还没有撤回",
  gateway_withdrawn: "网关已撤回，重新安装请走安装",
  still_on_host: "安装可能还在服务器上，不能删除记录",
};

// ======================================================= SSH rate limiting ===
//
// A server that answers "Not allowed at this time" before its SSH banner
// (OpenSSH per-source penalties) refuses the panel's source address for a
// while; the panel does not connect to it again for retry_after seconds.
// The cooldown is remembered per server so every button that would connect
// to it is disabled until then, instead of inviting more attempts (each of
// which lengthens the penalty).

const cooldowns = new Map<string, number>();
const cooldownListeners = new Set<() => void>();

/** Forgets every cooldown (tests). */
export function clearCooldowns() {
  cooldowns.clear();
  cooldownListeners.forEach((cb) => cb());
}

/** Seconds the server asked the panel to stay away, from an error (or 0). */
export function retryAfterOf(e: ApiError | null | undefined): number {
  if (!e) return 0;
  const limited = e.code === "ssh_rate_limited" || e.body?.ssh_code === "ssh_rate_limited";
  if (!limited) return 0;
  const n = Number(e.body?.retry_after);
  return Number.isFinite(n) && n > 0 ? n : 60;
}

/** Records that a server is rate-limiting the panel until now + seconds. */
export function noteRateLimited(serverId: string | undefined, seconds: number, from = Date.now()) {
  if (!serverId || seconds <= 0) return;
  const until = from + seconds * 1000;
  if ((cooldowns.get(serverId) ?? 0) >= until) return;
  cooldowns.set(serverId, until);
  cooldownListeners.forEach((cb) => cb());
}

/** Seconds left of a server's cooldown (0 when none); re-renders every second while counting. */
export function useServerCooldown(serverId: string | undefined): number {
  const [, setTick] = useState(0);
  useEffect(() => {
    const cb = () => setTick((t) => t + 1);
    cooldownListeners.add(cb);
    return () => {
      cooldownListeners.delete(cb);
    };
  }, []);
  const until = serverId ? (cooldowns.get(serverId) ?? 0) : 0;
  const left = Math.max(0, Math.ceil((until - Date.now()) / 1000));
  useEffect(() => {
    if (left <= 0) return;
    const t = setTimeout(() => setTick((x) => x + 1), 1000);
    return () => clearTimeout(t);
  }, [left]);
  return left;
}

/** Like useServerCooldown for many servers: returns a lookup of seconds left. */
export function useCooldowns(): (serverId: string | undefined) => number {
  const [, setTick] = useState(0);
  useEffect(() => {
    const cb = () => setTick((t) => t + 1);
    cooldownListeners.add(cb);
    const iv = setInterval(() => {
      const now = Date.now();
      for (const until of cooldowns.values()) {
        if (until > now - 1000) {
          setTick((t) => t + 1);
          return;
        }
      }
    }, 1000);
    return () => {
      cooldownListeners.delete(cb);
      clearInterval(iv);
    };
  }, []);
  return (id) => (id ? Math.max(0, Math.ceil(((cooldowns.get(id) ?? 0) - Date.now()) / 1000)) : 0);
}

/** The "retry later" note shown with a rate-limit refusal. */
export function RateLimitNote({ seconds }: { seconds: number }) {
  return (
    <span data-testid="rate-limit-note" style={{ display: "block", marginTop: 8 }}>
      <Typography.Text strong>服务器暂时拒绝来自面板这个地址的连接（限速）。</Typography.Text>
      这不是密码、密钥或主机指纹的问题，面板没有尝试登录。
      {seconds > 0 ? `${seconds} 秒内面板不会再连接这台服务器，相关按钮暂时停用；` : "现在可以重试；"}
      若仍被拒绝，再多等几分钟（连续尝试会让限速时间变长）。
    </span>
  );
}

/**
 * What is known about execution after a failed SSH operation: the failure
 * was before anything ran on the server (not_executed) and, when transient
 * (safe_to_retry: connect, banner or handshake timeout, refused before the
 * handshake), that trying again cannot repeat anything. Nothing is shown
 * when execution may have started: then the outcome is what the operation
 * itself reports, and nothing is retried automatically.
 */
export function ExecNote({ notExecuted, safeToRetry }: { notExecuted?: boolean; safeToRetry?: boolean }) {
  if (!notExecuted) return null;
  return (
    <span data-testid="exec-note" style={{ display: "block", marginTop: 8 }}>
      {safeToRetry ? (
        <>
          <Typography.Text strong>没有执行任何操作，可以安全重试。</Typography.Text>
          连接在登录或执行之前就失败了（超时或握手前被拒绝），服务器上什么都没有改；面板不会自动重试。
        </>
      ) : (
        <>
          <Typography.Text strong>没有执行任何操作。</Typography.Text>
          失败发生在登录或执行之前，服务器上什么都没有改；按上面的原因处理后再试。
        </>
      )}
    </span>
  );
}

export function errorTitle(e: ApiError): string {
  if (e.code && ERROR_TEXT[e.code]) return ERROR_TEXT[e.code];
  if (e.status === 401) return ERROR_TEXT.unauthorized;
  if (e.status === 0) return ERROR_TEXT.network;
  if (e.status >= 500) return "服务端出错";
  return "操作没有完成";
}

/** Retry, disabled while a rate-limited server's cooldown runs. */
function RetryButton({ error, onRetry }: { error: ApiError; onRetry: () => void }) {
  const [until] = useState(() => Date.now() + retryAfterOf(error) * 1000);
  const [, setTick] = useState(0);
  const left = Math.max(0, Math.ceil((until - Date.now()) / 1000));
  useEffect(() => {
    if (left <= 0) return;
    const t = setTimeout(() => setTick((x) => x + 1), 1000);
    return () => clearTimeout(t);
  }, [left]);
  return (
    <Button size="small" icon={<ReloadOutlined />} onClick={onRetry} disabled={left > 0} data-testid="error-retry">
      {left > 0 ? `${left} 秒后可重试` : "重试"}
    </Button>
  );
}

/** Counts down from the moment the refusal was shown. */
function RateLimitCountdown({ error }: { error: ApiError }) {
  const [until] = useState(() => Date.now() + retryAfterOf(error) * 1000);
  const [, setTick] = useState(0);
  const left = Math.max(0, Math.ceil((until - Date.now()) / 1000));
  useEffect(() => {
    if (left <= 0) return;
    const t = setTimeout(() => setTick((x) => x + 1), 1000);
    return () => clearTimeout(t);
  }, [left]);
  return <RateLimitNote seconds={left} />;
}

/** Where each independent block of the topology is changed in the panel. */
const INDEPENDENT_PAGE: Record<string, { page: string; label: string }> = {
  rule_sets: { page: "rules", label: "分流规则页的「规则集」" },
  mihomo_import: { page: "rules", label: "分流规则页的「导入」" },
  "settings.sniff": { page: "rules", label: "分流规则页的「按域名嗅探」" },
  "settings.dns_log": { page: "dns-log", label: "解析日志页的「开关与状态」" },
  "settings.exit_dns": { page: "dns", label: "解析设置页的「出口解析上游」" },
  "nodes[].exit_dns": { page: "dns", label: "解析设置页的「出口解析上游」" },
  remote_access: { page: "remote", label: "远程接入页" },
};

/**
 * A refused whole-topology save (independent_resource_changed): each block
 * the request could not change, the entries that differ, and where it is
 * changed (panel page and API).
 */
export function IndependentFieldsNote({ fields, onNavigate }: { fields: IndependentFieldRefusal[]; onNavigate?: () => void }) {
  return (
    <ul className="ref-list" data-testid="independent-fields">
      {fields.map((f) => {
        const where = INDEPENDENT_PAGE[f.field];
        return (
          <li key={f.field} data-field={f.field}>
            <Typography.Text strong>{f.resource}</Typography.Text>
            {f.items && f.items.length > 0 ? (
              <Typography.Text type="secondary">{`（不同的：${f.items.join("、")}）`}</Typography.Text>
            ) : null}
            ：在{" "}
            {where ? (
              <Link to={href(where.page)} onNavigate={onNavigate}>
                {where.label}
              </Link>
            ) : (
              "它自己的页面"
            )}{" "}
            修改（接口 <Mono>{f.endpoint}</Mono>）
          </li>
        );
      })}
    </ul>
  );
}

function independentFieldsOf(e: ApiError): IndependentFieldRefusal[] {
  return e.code === "independent_resource_changed" && Array.isArray(e.body?.fields) ? (e.body.fields as IndependentFieldRefusal[]) : [];
}

/** Shows the API's message, its code in Chinese, referrers as links, and a retry. */
export function ApiErrorAlert({
  error,
  onRetry,
  onClose,
  style,
  children,
}: {
  error: ApiError | null | undefined;
  onRetry?: () => void;
  onClose?: () => void;
  style?: CSSProperties;
  children?: ReactNode;
}) {
  if (!error) return null;
  const title = errorTitle(error);
  const showMessage = error.message && error.message !== title;
  const independent = independentFieldsOf(error);
  return (
    <Alert
      type="error"
      showIcon
      style={{ marginBottom: 16, ...style }}
      closable={!!onClose}
      onClose={onClose}
      message={title}
      description={
        showMessage || error.inUseBy.length > 0 || independent.length > 0 || children || retryAfterOf(error) > 0 || error.body?.not_executed === true ? (
          <div className="error-body">
            {showMessage ? <div>{error.message}</div> : null}
            {independent.length > 0 ? <IndependentFieldsNote fields={independent} /> : null}
            {retryAfterOf(error) > 0 ? <RateLimitCountdown error={error} /> : null}
            <ExecNote notExecuted={error.body?.not_executed === true} safeToRetry={error.body?.safe_to_retry === true && retryAfterOf(error) === 0} />
            {error.inUseBy.length > 0 ? (
              <div style={{ marginTop: 8 }}>
                <Typography.Text type="secondary">引用者：</Typography.Text>
                <RefList refs={error.inUseBy} />
              </div>
            ) : null}
            {children}
          </div>
        ) : undefined
      }
      action={
        onRetry ? <RetryButton error={error} onRetry={onRetry} /> : undefined
      }
    />
  );
}

// ==================================================================== links ===

/** In-app link that goes through the router (and its unsaved-changes guard). */
export function Link({ to, children, className, onNavigate }: { to: string; children: ReactNode; className?: string; onNavigate?: () => void }) {
  const router = useOptionalRouter();
  return (
    <a
      href={to}
      className={className}
      onClick={(e) => {
        onNavigate?.();
        if (!router || e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return;
        e.preventDefault();
        router.navigate(to);
      }}
    >
      {children}
    </a>
  );
}

/**
 * A navigation action that looks like a button: an anchor (so it can be
 * opened in a new tab and is announced as a link) that goes through the
 * router and its unsaved-changes guard.
 */
export function LinkButton({
  to,
  children,
  type,
  size,
  testId,
}: {
  to: string;
  children: ReactNode;
  type?: "primary" | "default" | "link";
  size?: "small" | "middle";
  testId?: string;
}) {
  const router = useOptionalRouter();
  return (
    <Button
      href={to}
      type={type}
      size={size}
      data-testid={testId}
      onClick={(e) => {
        if (!router || e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return;
        e.preventDefault();
        router.navigate(to);
      }}
    >
      {children}
    </Button>
  );
}

const REF_KIND: Record<string, { label: string; to: (id: string) => string | null }> = {
  node: { label: "节点", to: (id) => href("topology", id) },
  server: { label: "服务器", to: (id) => href("servers", id) },
  credential: { label: "密钥", to: (id) => href("keys", id) },
  ssh_credential: { label: "密钥", to: (id) => href("keys", id) },
  cloudflare_account: { label: "Cloudflare 账户", to: () => href("cloudflare") },
  mesh_deployment: { label: "Mesh 部署", to: () => href("cloudflare") + "?section=mesh" },
  rule: { label: "分流规则", to: (id) => href("rules", id) },
  rule_set: { label: "规则集", to: (id) => `${href("rules")}?rule_set=${encodeURIComponent(id)}` },
  group: { label: "地区组", to: (id) => href("exits", id) },
  region_group: { label: "地区组", to: (id) => href("exits", id) },
  settings: { label: "设置", to: () => href("exits") },
  remote_device: { label: "远程设备", to: (id) => href("remote", id) },
  apply: { label: "安装", to: () => href("deploy") },
  node_deployment: { label: "节点安装", to: () => href("deploy") + "?section=deployments" },
  snapshot: { label: "快照", to: () => href("deploy") },
};

export function refLink(ref: Ref): string | null {
  return REF_KIND[ref.kind]?.to(ref.id) ?? null;
}

export function refKindLabel(kind: string) {
  return REF_KIND[kind]?.label ?? kind;
}

/** Referrers (`in_use_by`) as a list of links. */
export function RefList({ refs, empty = "无", onNavigate }: { refs: Ref[] | null | undefined; empty?: ReactNode; onNavigate?: () => void }) {
  if (!refs || refs.length === 0) return <Typography.Text type="secondary">{empty}</Typography.Text>;
  return (
    <ul className="ref-list">
      {refs.map((r) => {
        const to = refLink(r);
        const text = r.name ? `${r.name}` : r.id;
        return (
          <li key={`${r.kind}:${r.id}`}>
            <Typography.Text type="secondary">{refKindLabel(r.kind)}</Typography.Text>{" "}
            {to ? (
              <Link to={to} onNavigate={onNavigate}>
                {text}
              </Link>
            ) : (
              <span>{text}</span>
            )}
            {r.name && r.name !== r.id ? <Typography.Text type="secondary" className="mono-small"> {r.id}</Typography.Text> : null}
          </li>
        );
      })}
    </ul>
  );
}

// ============================================================ text helpers ===

/**
 * The one way to show identifiers, paths, addresses, fingerprints, keys and
 * commands: monospace, and never wider than its container.
 *
 * - default: inline, may break anywhere (`overflow-wrap: anywhere`)
 * - `ellipsis`: one line, cut with "…"; the full text is a tooltip that also
 *   opens on keyboard focus
 * - `block`: its own box, wraps (configuration text, public keys)
 * - `block` + `scroll`: its own box that scrolls sideways inside itself and
 *   never splits across lines (commands). The box is keyboard focusable.
 *   `label` names it for screen readers.
 */
export function Mono({
  children,
  copy,
  block,
  ellipsis,
  scroll,
  label,
}: {
  children: string | null | undefined;
  copy?: boolean;
  block?: boolean;
  ellipsis?: boolean;
  scroll?: boolean;
  label?: string;
}) {
  if (!children) return <Typography.Text type="secondary">—</Typography.Text>;
  if (block || scroll) {
    return (
      <div className={scroll ? "mono-block mono-block-scroll" : "mono-block"}>
        <code
          className={scroll ? "mono-scroll" : undefined}
          {...(scroll ? { tabIndex: 0, role: "group", "aria-label": label ?? "命令，可左右滚动" } : {})}
        >
          {children}
        </code>
        {copy ? <CopyButton text={children} /> : null}
      </div>
    );
  }
  if (ellipsis) {
    return (
      <span className="mono-ellipsis-wrap">
        <EllipsisText text={children} mono />
        {copy ? <CopyButton text={children} /> : null}
      </span>
    );
  }
  return (
    <Typography.Text className="mono" copyable={copy ? { text: children, tooltips: ["复制", "已复制"] } : false}>
      {children}
    </Typography.Text>
  );
}

/** A command the user copies: `<Mono block scroll copy>` with a fixed name. */
export function CommandBlock({ children, label }: { children: string; label?: string }) {
  return (
    <Mono block scroll copy label={label}>
      {children}
    </Mono>
  );
}

/**
 * One line of text cut with "…" when it does not fit. The full text is a
 * tooltip that opens on hover and on keyboard focus (the span is focusable).
 * Use it in `ellipsis` table columns and anywhere text must stay one line.
 */
export function EllipsisText({ text, mono, className }: { text: ReactNode; mono?: boolean; className?: string }) {
  const plain = typeof text === "string" || typeof text === "number" ? String(text) : null;
  const cls = ["ellipsis-text", mono ? "mono" : "", className ?? ""].filter(Boolean).join(" ");
  if (plain === null || plain === "") return <span className={cls}>{text}</span>;
  return (
    <Tooltip title={plain} trigger={["hover", "focus"]} mouseEnterDelay={0.2}>
      <span className={cls} tabIndex={0}>
        {plain}
      </span>
    </Tooltip>
  );
}

/**
 * A link whose text is cut with "…" when it does not fit; the full text is a
 * tooltip on hover and on keyboard focus of the link. For names in tight rows
 * (overview tiles, matrix headers, member rows).
 */
export function EllipsisLink({ to, text, className, style, testId }: { to: string; text: string; className?: string; style?: CSSProperties; testId?: string }) {
  return (
    <Tooltip title={text} trigger={["hover", "focus"]} mouseEnterDelay={0.2}>
      <span className={["ellipsis-text", "ellipsis-link", className ?? ""].filter(Boolean).join(" ")} style={style} data-testid={testId}>
        <Link to={to}>{text}</Link>
      </span>
    </Tooltip>
  );
}

/**
 * One row of a tile: a name that is cut with "…" (full text on hover/focus)
 * and a status that always keeps its own space at the right edge.
 */
export function TileItem({ name, status, testId }: { name: ReactNode; status: ReactNode; testId?: string }) {
  return (
    <div className="tile-item" data-testid={testId}>
      <span className="tile-item-name">{name}</span>
      <span className="tile-item-status">{status}</span>
    </div>
  );
}

export function CopyButton({ text, label = "复制" }: { text: string; label?: string }) {
  const { message } = AntApp.useApp();
  return (
    <Button
      size="small"
      icon={<CopyOutlined />}
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          message.success("已复制");
        } catch {
          message.error("浏览器不允许写剪贴板，请手动选中复制");
        }
      }}
    >
      {label}
    </Button>
  );
}

// ======================================================= install indicator ===

/**
 * The persistent「有改动尚未安装」indicator (top bar). Use
 * <ApplyRequiredNotice/> inline on a page after a mutation that answered
 * `apply_required: true` (and call useStatus().markApplyRequired()).
 */
export function PendingInstallIndicator({ compact }: { compact?: boolean }) {
  const { install, status } = useStatus();
  const { navigate } = useRouter();
  if (install.kind === "loading" || install.kind === "in_sync") return null;
  if (install.kind === "error") {
    return (
      <Space size={6} className="pending-install" data-testid="pending-install">
        <StatusTag kind="attention" title={install.message}>
          拓扑无法编译
        </StatusTag>
        {!compact ? (
          <Button size="small" onClick={() => navigate(href("deploy"))}>
            查看问题
          </Button>
        ) : null}
      </Space>
    );
  }
  if (install.kind === "unknown") {
    return (
      <Space size={6} className="pending-install" data-testid="pending-install">
        <StatusTag kind="unverified" title="网关上的安装是从旧版本接管的，没有记录内容摘要，面板无法判断它是否与当前拓扑一致。安装一次即可恢复判断。">
          无法判断是否已安装
        </StatusTag>
        <Button size="small" type="primary" ghost onClick={() => navigate(href("deploy"))}>
          {compact ? "安装" : "去安装"}
        </Button>
      </Space>
    );
  }
  const text =
    install.kind === "not_installed"
      ? install.withdrawn
        ? "网关已撤回"
        : "尚未安装到网关"
      : install.appliedOnly
        ? "已应用，尚未安装"
        : "有改动尚未安装";
  const tip =
    install.kind === "not_installed" && install.withdrawn
      ? "网关上的 Meridian 已撤回，只保留局域网兜底表（局域网转发保持兜底拒绝）。重新安装要先做安装前预检。"
      : install.kind === "not_installed"
      ? status?.agent.ok
        ? "网关上还没有安装过 Meridian。"
        : "网关上还没有安装过 Meridian；宿主执行通道当前不可用。"
      : install.appliedOnly
        ? `改动已写入数据目录，但网关上运行的仍是 v${install.version ?? "?"}。在「部署」页安装后才生效。`
        : `存储的拓扑和网关上安装的 v${install.version ?? "?"} 不一样。网关上什么都没变，直到在「部署」页安装。`;
  return (
    <Space size={6} className="pending-install" data-testid="pending-install">
      <StatusTag kind="pending" title={tip}>
        {text}
      </StatusTag>
      <Button size="small" type="primary" ghost onClick={() => navigate(href("deploy"))}>
        {compact ? "安装" : "去安装"}
      </Button>
    </Space>
  );
}

/** Inline notice after a document-only change. */
export function ApplyRequiredNotice({ what = "改动已保存" }: { what?: ReactNode }) {
  return (
    <Alert
      type="info"
      showIcon
      style={{ marginBottom: 16 }}
      message={<span>{what}，但还没有安装到网关；网关上的行为不变，直到在「部署」页安装。</span>}
      action={<Link to={href("deploy")}>去部署</Link>}
    />
  );
}

/**
 * The one line after a rules / service-group / rule-set / import save (the
 * automatic install, settings.rules_auto_apply): 已生效（vN）, 将自动生效,
 * or 未自动生效 with its reason and the deploy link (only then).
 */
/** How often a scheduled automatic install is re-checked, and for how long. */
export const RULES_APPLY_POLL_MS = 3000;
export const RULES_APPLY_POLL_MAX = 60;

export function RulesApplyLine({ fa, applyRequired }: { fa?: RulesFastApply | null; applyRequired?: boolean }) {
  // A scheduled (coalesced) install finishes after the save answered: follow
  // it to its outcome instead of leaving 将自动生效 on the page. When the
  // polls run out without an outcome the line says so (结果待确认) and offers
  // another look; it never keeps promising 将自动生效.
  const [done, setDone] = useState<RulesFastApply | null>(null);
  const [lost, setLost] = useState(false);
  const [round, setRound] = useState(0);
  const st = useOptionalStatus();
  useEffect(() => {
    setDone(null);
    setLost(false);
    if (fa?.status !== "scheduled") return;
    const ctl = new AbortController();
    let n = 0;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const tick = async () => {
      n++;
      try {
        const v = await api.getRulesAutoApply(ctl.signal);
        if (ctl.signal.aborted) return;
        if (!v.pending && v.last && v.last.status !== "scheduled") {
          setDone({ status: v.last.status, reason: v.last.reason, version: v.last.version });
          st?.refresh();
          return;
        }
      } catch {
        if (ctl.signal.aborted) return;
      }
      if (ctl.signal.aborted) return;
      if (n < RULES_APPLY_POLL_MAX) timer = setTimeout(tick, RULES_APPLY_POLL_MS);
      else setLost(true);
    };
    timer = setTimeout(tick, round > 0 ? 0 : RULES_APPLY_POLL_MS);
    return () => {
      ctl.abort();
      if (timer) clearTimeout(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [fa, round]);
  const cur = done ?? fa;
  if (!cur && !applyRequired) return null;
  if (cur?.status === "applied")
    return <Typography.Text type="secondary" data-testid="rules-apply-line">已生效{cur.version ? `（v${cur.version}）` : ""}</Typography.Text>;
  if (cur?.status === "scheduled" && lost)
    return (
      <span data-testid="rules-apply-line">
        <Typography.Text type="warning">结果待确认</Typography.Text>{" "}
        <Button type="link" size="small" onClick={() => setRound((r) => r + 1)}>
          重新查看
        </Button>{" "}
        <Link to={href("deploy")}>去部署</Link>
      </span>
    );
  if (cur?.status === "scheduled") return <Typography.Text type="secondary" data-testid="rules-apply-line">将自动生效</Typography.Text>;
  if (cur?.status === "none" && done) return <Typography.Text type="secondary" data-testid="rules-apply-line">已是最新</Typography.Text>;
  if (cur?.status === "none" && !applyRequired) return null;
  return (
    <span data-testid="rules-apply-line">
      <Typography.Text type="warning">未自动生效{cur?.reason ? `：${cur.reason}` : ""}</Typography.Text> <Link to={href("deploy")}>去部署</Link>
    </span>
  );
}

/** After a rules save: keep the install indicator honest (an applied save needs no install). */
export function useRulesApplied() {
  const st = useOptionalStatus();
  return (res: { apply_required?: boolean; fast_apply?: RulesFastApply }) => {
    if (!st) return;
    const { markApplyRequired, refresh } = st;
    if (res.fast_apply?.status === "applied" || (!res.apply_required && res.fast_apply?.status !== "failed" && res.fast_apply?.status !== "required")) refresh();
    else markApplyRequired();
  };
}
