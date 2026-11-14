// Shared building blocks for every page. See web/README.md「面板约定」.

import {
  CheckCircleFilled,
  ClockCircleOutlined,
  CloseCircleFilled,
  CopyOutlined,
  ExclamationCircleFilled,
  EyeInvisibleOutlined,
  MinusCircleOutlined,
  QuestionCircleOutlined,
  ReloadOutlined,
  SyncOutlined,
  UserOutlined,
  CloudUploadOutlined,
  EllipsisOutlined,
} from "@ant-design/icons";
import {
  Alert,
  App as AntApp,
  Button,
  Dropdown,
  Empty,
  Input,
  Modal,
  Pagination,
  Popover,
  Skeleton,
  Space,
  Table,
  Tag,
  Tooltip,
  Typography,
  type FormInstance,
  type InputRef,
  type TableColumnType,
  type TableProps,
} from "antd";
import { useCallback, useEffect, useId, useMemo, useRef, useState, type CSSProperties, type HTMLAttributes, type Key, type ReactNode } from "react";
import { ApiError, isApiError } from "./api";
import { href, useOptionalRouter, useRouter, useStatus, useTopologyDoc, useUnsavedGuard } from "./state";
import type { IndependentFieldRefusal, Issue, Ref } from "./types";

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

/** `<StatusTag kind="unverified">数据面未验证</StatusTag>`; children override the label, never the colour. */
export function StatusTag({ kind, children, title }: { kind: StatusKind; children?: ReactNode; title?: ReactNode }) {
  const s = STATUS[kind];
  const tag = (
    <Tag color={s.color} icon={s.icon} className={`status-tag status-${kind}`} data-status={kind}>
      {children ?? s.label}
    </Tag>
  );
  return title ? <Tooltip title={title}>{tag}</Tooltip> : tag;
}

// ============================================================== page layout ===

/**
 * Header of every page: title, one sentence of purpose, actions on the right.
 * The action area wraps (and may itself fill the row on narrow screens), so
 * it can never widen the page. `menu` puts the secondary actions behind a
 * "更多操作" dropdown at every width; keep the one primary action in `extra`.
 */
export function PageHeader({
  title,
  description,
  extra,
  menu,
}: {
  title: ReactNode;
  description?: ReactNode;
  extra?: ReactNode;
  menu?: MoreAction[];
}) {
  const items = (menu ?? []).filter(Boolean);
  return (
    <div className="page-header">
      <div className="page-header-text">
        <Typography.Title level={3} style={{ margin: 0 }}>
          {title}
        </Typography.Title>
        {description ? <Typography.Text type="secondary">{description}</Typography.Text> : null}
      </div>
      {extra || items.length > 0 ? (
        <div className="page-header-extra" data-testid="page-header-actions">
          {extra}
          {items.length > 0 ? (
            <Dropdown
              trigger={["click"]}
              menu={{
                items: items.map((m) => ({ key: m.key, label: m.label, icon: m.icon, danger: m.danger, disabled: m.disabled })),
                onClick: ({ key }) => items.find((m) => m.key === key)?.onClick(),
              }}
            >
              <Button icon={<EllipsisOutlined />} aria-label="更多操作">
                更多
              </Button>
            </Dropdown>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

export function Page({
  title,
  description,
  extra,
  menu,
  children,
}: {
  title: ReactNode;
  description?: ReactNode;
  extra?: ReactNode;
  menu?: MoreAction[];
  children: ReactNode;
}) {
  return (
    <div className="page">
      <PageHeader title={title} description={description} extra={extra} menu={menu} />
      {children}
    </div>
  );
}

/** A titled block inside a page. */
export function Section({ title, extra, children, id }: { title: ReactNode; extra?: ReactNode; children: ReactNode; id?: string }) {
  return (
    <section className="section" id={id}>
      <div className="section-head">
        <Typography.Title level={5} style={{ margin: 0 }}>
          {title}
        </Typography.Title>
        {extra ? <div>{extra}</div> : null}
      </div>
      {children}
    </section>
  );
}

// =============================================================== data hooks ===

export interface ApiState<T> {
  data: T | undefined;
  error: ApiError | null;
  loading: boolean;
  /** Re-run the loader; keeps the old data while loading. */
  reload: () => Promise<void>;
  /** Replace the data locally (after a mutation returned the new object). */
  setData: (fn: T | ((old: T | undefined) => T | undefined)) => void;
}

function toApiError(e: unknown): ApiError {
  if (isApiError(e)) return e;
  return new ApiError(0, { error: e instanceof Error ? e.message : String(e) }, "client");
}

/** `const servers = useApi(() => api.listServers(), [])`. */
export function useApi<T>(loader: () => Promise<T>, deps: unknown[] = []): ApiState<T> {
  const [data, setDataState] = useState<T | undefined>(undefined);
  const [error, setError] = useState<ApiError | null>(null);
  const [loading, setLoading] = useState(true);
  const seq = useRef(0);
  const loaderRef = useRef(loader);
  loaderRef.current = loader;

  const reload = useCallback(async () => {
    const my = ++seq.current;
    setLoading(true);
    try {
      const d = await loaderRef.current();
      if (my !== seq.current) return;
      setDataState(d);
      setError(null);
    } catch (e) {
      if (my !== seq.current) return;
      setError(toApiError(e));
    } finally {
      if (my === seq.current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    void reload();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  const setData = useCallback((fn: T | ((old: T | undefined) => T | undefined)) => {
    setDataState((old) => (typeof fn === "function" ? (fn as (o: T | undefined) => T | undefined)(old) : fn));
  }, []);

  return { data, error, loading, reload, setData };
}

/**
 * Runs mutations: `busy` disables the buttons while one is in flight, `error`
 * holds the last failure (show it with <ApiErrorAlert>); `onError` gets it
 * right away (e.g. to put a `field` error on a form field).
 * `const act = useAction(); act.run(() => api.deleteServer(id))`.
 */
export function useAction() {
  const [busy, setBusy] = useState<string | false>(false);
  const [error, setError] = useState<ApiError | null>(null);
  const run = useCallback(
    async <R,>(fn: () => Promise<R>, key = "default", onError?: (e: ApiError) => void): Promise<R | undefined> => {
      setBusy(key);
      setError(null);
      try {
        return await fn();
      } catch (e) {
        const ae = toApiError(e);
        setError(ae);
        onError?.(ae);
        return undefined;
      } finally {
        setBusy(false);
      }
    },
    [],
  );
  return { run, busy, error, setError, clear: () => setError(null) };
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
  node_busy: "这个节点正在预检或装机",
  provision_refused: "服务器上的执行前复核拒绝了装机，没有改动",
  provision_failed_compensated: "装机失败，已补偿",
  provision_failed_leftovers: "装机失败，有残留没有撤掉",
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
  service_groups: { page: "rules", label: "分流规则页的「服务组」" },
  rule_sets: { page: "rules", label: "分流规则页的「规则集」" },
  mihomo_import: { page: "rules", label: "分流规则页的「导入」" },
  "settings.sniff": { page: "rules", label: "分流规则页的「按域名嗅探」" },
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

/**
 * A refused change or delete (409 in_use, account_locked …) as a dialog
 * listing the referrers as links. Render it in the page:
 * `<RefusedDialog error={refused} onClose={() => setRefused(null)} />`.
 */
export function RefusedDialog({ error, title, onClose }: { error: ApiError | null; title?: ReactNode; onClose: () => void }) {
  return (
    <Modal open={!!error} title={title ?? (error ? errorTitle(error) : "")} onCancel={onClose} footer={<Button onClick={onClose}>知道了</Button>} destroyOnHidden>
      {error ? (
        <div data-testid="refused-dialog">
          {error.message && error.message !== errorTitle(error) ? <Typography.Paragraph>{error.message}</Typography.Paragraph> : null}
          {error.inUseBy.length > 0 ? (
            <>
              <Typography.Text type="secondary">先处理这些引用：</Typography.Text>
              <RefList refs={error.inUseBy} onNavigate={onClose} />
            </>
          ) : null}
        </div>
      ) : null}
    </Modal>
  );
}

/**
 * Puts an API error with a `field` onto the matching form field (one of
 * `fields`; `map` translates API names to form names). Returns true when it did.
 */
export function showFieldError(
  form: FormInstance,
  err: ApiError | null | undefined,
  fields: string[],
  map: Record<string, string> = {},
): boolean {
  if (!err?.field) return false;
  const name = map[err.field] ?? err.field;
  if (!fields.includes(name)) return false;
  form.setFields([{ name, errors: [err.message || errorTitle(err)] }]);
  return true;
}

// =============================================================== data view ===

/**
 * Loading (skeleton), error (message + retry), empty (what it is + primary
 * action) and data, in one place:
 * `<DataView state={servers} isEmpty={d => d.servers.length === 0} empty={…}>{d => …}</DataView>`.
 */
export function DataView<T>({
  state,
  isEmpty,
  empty,
  children,
  rows = 4,
}: {
  state: ApiState<T>;
  isEmpty?: (d: T) => boolean;
  empty?: ReactNode;
  children: (d: T) => ReactNode;
  rows?: number;
}) {
  if (state.data === undefined) {
    if (state.error) return <ApiErrorAlert error={state.error} onRetry={() => void state.reload()} />;
    return <Skeleton active paragraph={{ rows }} />;
  }
  return (
    <>
      {state.error ? <ApiErrorAlert error={state.error} onRetry={() => void state.reload()} /> : null}
      {isEmpty && isEmpty(state.data) && empty ? empty : children(state.data)}
    </>
  );
}

/** Empty state: what this is, and the primary action. */
export function EmptyState({ title, description, action }: { title: ReactNode; description?: ReactNode; action?: ReactNode }) {
  return (
    <div className="empty-state">
      <Empty
        image={Empty.PRESENTED_IMAGE_SIMPLE}
        description={
          <div>
            <div className="empty-title">{title}</div>
            {description ? <Typography.Text type="secondary">{description}</Typography.Text> : null}
          </div>
        }
      >
        {action}
      </Empty>
    </div>
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

const REF_KIND: Record<string, { label: string; to: (id: string) => string | null }> = {
  node: { label: "节点", to: (id) => href("topology", id) },
  server: { label: "服务器", to: (id) => href("servers", id) },
  credential: { label: "密钥", to: (id) => href("keys", id) },
  ssh_credential: { label: "密钥", to: (id) => href("keys", id) },
  cloudflare_account: { label: "Cloudflare 账户", to: () => href("cloudflare") },
  mesh_deployment: { label: "Mesh 部署", to: () => href("cloudflare") + "?section=mesh" },
  rule: { label: "分流规则", to: (id) => href("rules", id) },
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

/**
 * Offers text as a file download, built in the browser (no network, no
 * storage). The object URL is revoked right away.
 */
export function downloadText(filename: string, text: string) {
  const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.rel = "noopener";
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

function pad(n: number) {
  return n < 10 ? `0${n}` : String(n);
}

export function formatAbsolute(d: Date) {
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

export function formatRelative(d: Date, now = new Date()) {
  const s = Math.round((now.getTime() - d.getTime()) / 1000);
  const future = s < 0;
  const a = Math.abs(s);
  let t: string;
  if (a < 45) t = "刚刚";
  else if (a < 3600) t = `${Math.round(a / 60)} 分钟`;
  else if (a < 86400) t = `${Math.round(a / 3600)} 小时`;
  else if (a < 86400 * 30) t = `${Math.round(a / 86400)} 天`;
  else return formatAbsolute(d).slice(0, 10);
  if (t === "刚刚") return t;
  return future ? `${t}后` : `${t}前`;
}

/** Relative time, absolute time on hover. Empty / zero times render "—". */
export function TimeText({ value, empty = "—" }: { value: string | null | undefined; empty?: ReactNode }) {
  if (!value || value.startsWith("0001-")) return <Typography.Text type="secondary">{empty}</Typography.Text>;
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return <span>{value}</span>;
  return (
    <Tooltip title={formatAbsolute(d)}>
      <span className="time-text">
        <ClockCircleOutlined style={{ marginRight: 4, opacity: 0.6 }} />
        {formatRelative(d)}
      </span>
    </Tooltip>
  );
}

// ============================================================== SecretField ===

/**
 * Write-only secret input for antd Form (`<Form.Item name="password"><SecretField …/></Form.Item>`).
 *
 * - Never prefilled; autocomplete off; not spell-checked.
 * - With `isSet`, shows「已设置 · 替换」until the user chooses to replace it.
 * - The parent clears the field after every request, success or failure
 *   (`form.setFieldValue(name, undefined)`, or unmount the form).
 */
export function SecretField({
  value,
  onChange,
  isSet,
  multiline,
  placeholder,
  rows = 6,
  id,
  "aria-label": ariaLabel,
}: {
  value?: string;
  onChange?: (v: string | undefined) => void;
  isSet?: boolean;
  multiline?: boolean;
  placeholder?: string;
  rows?: number;
  id?: string;
  "aria-label"?: string;
}) {
  const [replacing, setReplacing] = useState(!isSet);
  const inputRef = useRef<InputRef>(null);
  useEffect(() => {
    if (!isSet) setReplacing(true);
  }, [isSet]);
  if (isSet && !replacing) {
    return (
      <Space>
        <StatusTag kind="ok">已设置</StatusTag>
        <Typography.Text type="secondary">
          <EyeInvisibleOutlined /> 不可查看
        </Typography.Text>
        <Button size="small" onClick={() => setReplacing(true)}>
          替换
        </Button>
      </Space>
    );
  }
  const common = {
    id,
    "aria-label": ariaLabel,
    value: value ?? "",
    placeholder,
    autoComplete: "off",
    spellCheck: false,
    "data-secret": "true",
    "data-1p-ignore": "true",
    "data-lpignore": "true",
  } as const;
  return (
    <Space direction="vertical" style={{ width: "100%" }}>
      {multiline ? (
        <Input.TextArea
          {...common}
          rows={rows}
          className="mono secret-textarea"
          onChange={(e) => onChange?.(e.target.value || undefined)}
        />
      ) : (
        <Input.Password
          {...common}
          ref={inputRef}
          autoComplete="new-password"
          visibilityToggle={false}
          onChange={(e) => onChange?.(e.target.value || undefined)}
        />
      )}
      {isSet ? (
        <Button
          size="small"
          type="link"
          style={{ padding: 0 }}
          onClick={() => {
            onChange?.(undefined);
            setReplacing(false);
          }}
        >
          不替换，保留已设置的值
        </Button>
      ) : null}
    </Space>
  );
}

// ============================================================ danger confirm ===

/**
 * Destructive actions: one sentence stating the consequence.
 * `const confirm = useConfirmDanger(); confirm({title, consequence, okText, onOk})`.
 * onOk may return a promise; the dialog stays open (button loading) until it settles.
 */
export function useConfirmDanger() {
  const { modal } = AntApp.useApp();
  return useCallback(
    (o: { title: ReactNode; consequence: ReactNode; okText?: string; danger?: boolean; onOk: () => unknown }) => {
      modal.confirm({
        title: o.title,
        content: o.consequence,
        okText: o.okText ?? "确定",
        okButtonProps: { danger: o.danger ?? true },
        cancelText: "取消",
        onOk: async () => {
          await o.onOk();
        },
      });
    },
    [modal],
  );
}

// =================================================================== tables ===

/**
 * LEGACY (kept so pages not yet migrated behave as before; new work uses
 * <DataTable>, see docs/ui-layout.md). Table props: the table is as wide as its
 * content and scrolls sideways inside its own box when the page is narrower
 * (never clipping columns). Give the name column `className: "cell-name"`
 * (no wrapping), long free text `className: "cell-text"` with a width, and
 * the action column `fixed: "right"` with `className: "cell-actions"`.
 */
export const TABLE_SCROLL = { x: "max-content" } as const;

export interface MoreAction {
  key: string;
  label: ReactNode;
  icon?: ReactNode;
  danger?: boolean;
  disabled?: boolean;
  onClick: () => void;
}

/**
 * Row actions in a table: the one or two actions used most stay as buttons,
 * the rest go into a "…" menu, so the column stays narrow and nothing is cut.
 * `label` names the row for the menu button ("<name> 的更多操作").
 */
export function RowActions({ children, more, label }: { children?: ReactNode; more?: MoreAction[]; label: string }) {
  const items = (more ?? []).filter(Boolean);
  return (
    <Space size={2} className="table-actions">
      {children}
      {items.length > 0 ? (
        <Dropdown
          trigger={["click"]}
          menu={{
            items: items.map((m) => ({ key: m.key, label: m.label, icon: m.icon, danger: m.danger, disabled: m.disabled })),
            onClick: ({ key }) => items.find((m) => m.key === key)?.onClick(),
          }}
        >
          <Button type="text" size="small" icon={<EllipsisOutlined />} aria-label={`${label} 的更多操作`} />
        </Dropdown>
      ) : null}
    </Space>
  );
}

// ================================================================ misc bits ===

/** One Facts row: [label, value] or [label, value, "stacked"] to put a long value on its own line. */
export type FactItem = [ReactNode, ReactNode] | [ReactNode, ReactNode, "stacked"];

/**
 * Key/value rows. The label column is at least `labelMin` px wide and never
 * wraps; the value cell may shrink to nothing and breaks long text inside
 * itself, so a long value can no longer squeeze the label. A row marked
 * "stacked" (or all rows with `stacked`) puts the value on its own line
 * under the label.
 */
export function Facts({ items, stacked, labelMin }: { items: FactItem[]; stacked?: boolean; labelMin?: number }) {
  return (
    <dl className={stacked ? "facts facts-stacked" : "facts"} style={labelMin ? ({ "--m-fact-label": `${labelMin}px` } as CSSProperties) : undefined}>
      {items.map(([k, v, mode], i) => (
        <div key={i} className={mode === "stacked" ? "fact fact-stacked" : "fact"}>
          <dt>{k}</dt>
          <dd>{v}</dd>
        </div>
      ))}
    </dl>
  );
}

/**
 * One "label: value" row for tiles and cards (what the overview's local Row
 * was). Same rules as Facts: the label never wraps and keeps its width, the
 * value wraps inside its own cell. `stacked` puts the value under the label.
 */
export function KV({ label, children, stacked }: { label: ReactNode; children: ReactNode; stacked?: boolean }) {
  return (
    <div className={stacked ? "kv kv-stacked" : "kv"}>
      <span className="kv-label">{label}</span>
      <span className="kv-value">{children}</span>
    </div>
  );
}

/** Small tile used on the overview and summary rows. */
export function Tile({ title, extra, children, to }: { title: ReactNode; extra?: ReactNode; children: ReactNode; to?: string }) {
  return (
    <div className="tile">
      <div className="tile-head">
        <span className="tile-title">{to ? <Link to={to}>{title}</Link> : title}</span>
        {extra}
      </div>
      <div className="tile-body">{children}</div>
    </div>
  );
}

export function bytes(n: number) {
  if (n < 1024) return `${n} B`;
  const u = ["KiB", "MiB", "GiB", "TiB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v < 10 ? 1 : 0)} ${u[i]}`;
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

// ======================================================== topology doc bar ===

/** Validation issues of the topology document. */
export function IssueList({ issues }: { issues: Issue[] }) {
  if (issues.length === 0) return null;
  return (
    <div className="issues">
      {issues.map((iss, i) => (
        <Alert
          key={i}
          type={iss.severity === "error" ? "error" : "warning"}
          showIcon
          message={iss.message}
          description={
            [iss.node_id && `节点 ${iss.node_id}`, iss.link_id && `链路 ${iss.link_id}`, iss.rule_id && `规则 ${iss.rule_id}`, iss.group_id && `地区组 ${iss.group_id}`]
              .filter(Boolean)
              .join(" · ") || undefined
          }
        />
      ))}
    </div>
  );
}

/**
 * Save bar for pages that edit the whole topology document (topology,
 * rules, leak settings). Registers the unsaved-changes guard while dirty.
 */
export function TopologyDocBar() {
  const doc = useTopologyDoc();
  const act = useAction();
  const { message } = AntApp.useApp();
  useUnsavedGuard(doc.dirty, "拓扑有未保存的修改，离开后会丢失。");
  const errors = doc.issues.filter((i) => i.severity === "error");
  return (
    <div className="doc-bar sticky-bar">
      <Space wrap>
        {doc.dirty ? <StatusTag kind="attention">有未保存的修改</StatusTag> : <Typography.Text type="secondary">拓扑已保存</Typography.Text>}
      </Space>
      <Space wrap>
        <Button onClick={() => act.run(() => doc.validate(), "validate")} loading={act.busy === "validate"}>
          校验
        </Button>
        <Button disabled={!doc.dirty} onClick={() => void doc.reload()}>
          放弃修改
        </Button>
        <Button
          disabled={!doc.dirty}
          loading={act.busy === "draft"}
          onClick={() => act.run(async () => (await doc.save(true)) && message.success("已保存为草稿"), "draft")}
        >
          保存草稿
        </Button>
        <Button
          type="primary"
          disabled={!doc.dirty || errors.length > 0}
          loading={act.busy === "save" || doc.saving}
          onClick={() => act.run(async () => (await doc.save(false)) && message.success("已保存；安装后在网关生效"), "save")}
        >
          保存
        </Button>
      </Space>
      {act.error ? <ApiErrorAlert error={act.error} onClose={act.clear} style={{ width: "100%", marginTop: 12, marginBottom: 0 }} /> : null}
    </div>
  );
}

// ===================================================== layout primitives ===
// The global layout rules live in styles.css and here; docs/ui-layout.md is
// the reference (rules, recipes, migration notes, browser-only checks).

/**
 * The breakpoints of the panel, stated once. CSS cannot read these, so the
 * media queries in styles.css repeat them as max-width values (marked
 * "BREAKPOINT" there): desktop-xl >= 1440, desktop >= 1280 (every table shows
 * its key columns without sideways scrolling from here up), laptop 1024
 * (max-width 1279 and down: secondary columns move into the expandable row),
 * tablet 768 (max-width 1023 / 767: one-column grids, header actions fill
 * the row), phone 390 (max-width 479: tables scroll in their box or become
 * cards, buttons keep a 32 px touch height).
 */
export const BREAKPOINTS = { desktopXL: 1440, desktop: 1280, laptop: 1024, tablet: 768, phone: 390 } as const;

/**
 * A toolbar that sticks under the top bar as ONE continuous opaque area: its
 * top is the top bar's height (--m-topbar-h) minus the border pixel, and its
 * background is opaque, so no table row shows through between the two.
 */
export function StickyBar({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={["sticky-bar", className ?? ""].filter(Boolean).join(" ")}>{children}</div>;
}

/**
 * Explanatory prose. A short summary is always visible; the rest is behind a
 * "了解更多" toggle (`mode="inline"`, default) or a click popover
 * (`mode="popover"`). Collapsing is what this component is FOR, so never put
 * a safety statement (未验证, 失败关闭, 需要人工签收) in `children`: use
 * <SafetyNotice>, which has no collapsed state at all.
 */
export function Explain({
  summary,
  children,
  mode = "inline",
  defaultOpen = false,
  label = "了解更多",
}: {
  summary: ReactNode;
  children?: ReactNode;
  mode?: "inline" | "popover";
  defaultOpen?: boolean;
  label?: string;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const id = useId();
  if (!children) {
    return (
      <div className="explain">
        <span className="explain-summary">{summary}</span>
      </div>
    );
  }
  if (mode === "popover") {
    return (
      <div className="explain explain-popover">
        <span className="explain-summary">{summary}</span>{" "}
        <Popover trigger="click" content={<div className="explain-pop">{children}</div>}>
          <button type="button" className="explain-toggle">
            {label}
          </button>
        </Popover>
      </div>
    );
  }
  return (
    <div className="explain">
      <span className="explain-summary">{summary}</span>{" "}
      <button type="button" className="explain-toggle" aria-expanded={open} aria-controls={id} onClick={() => setOpen((o) => !o)}>
        {open ? "收起" : label}
      </button>
      <div id={id} className="explain-more" hidden={!open}>
        {children}
      </div>
    </div>
  );
}

export type SafetyKind = "unverified" | "failclosed" | "signoff";

const SAFETY: Record<SafetyKind, { status: StatusKind; label: string }> = {
  unverified: { status: "unverified", label: "未验证" },
  failclosed: { status: "attention", label: "失败关闭" },
  signoff: { status: "signoff", label: "待人工签收" },
};

/**
 * A safety-relevant notice: not verified, fail-closed, needs a human
 * sign-off. Always fully visible; there is deliberately no collapse, summary
 * or popover prop. Keep the wording short, but do not drop it.
 */
export function SafetyNotice({ kind, title, children }: { kind: SafetyKind; title?: ReactNode; children?: ReactNode }) {
  const k = SAFETY[kind];
  return (
    <div className={`safety-notice safety-${kind}`} role="note" data-safety={kind}>
      <StatusTag kind={k.status}>{k.label}</StatusTag>
      <div className="safety-text">
        {title ? <div className="safety-title">{title}</div> : null}
        {children ? <div>{children}</div> : null}
      </div>
    </div>
  );
}

/**
 * A short status tag plus ONE line of reason. The reason is not part of the
 * tag and repeats nothing: empty, duplicate and already-contained reasons
 * (also when equal to the label) are dropped, the rest joined with "；".
 * One line, cut with "…" with the full text on hover/focus; `wrap` lets it
 * wrap (use it where the reason is itself safety-relevant).
 */
export function StatusReason({
  kind,
  label,
  reason,
  wrap,
}: {
  kind: StatusKind;
  label?: ReactNode;
  reason?: string | (string | null | undefined)[] | null;
  wrap?: boolean;
}) {
  const text = joinReasons(reason, typeof label === "string" ? label : STATUS[kind].label);
  return (
    <div className="status-reason" data-status={kind}>
      <StatusTag kind={kind}>{label}</StatusTag>
      {text ? wrap ? <span className="status-reason-text wrap">{text}</span> : <EllipsisText className="status-reason-text" text={text} /> : null}
    </div>
  );
}

/**
 * A status label made of several dot-separated facts ("未验证 · 状态过期"):
 * the tag holds only the first, short part; the rest follows as one line of
 * muted text (`detail="inline"`, cut with "…") or only in the tooltip and for
 * screen readers (`detail="hidden"`, for tight rows such as overview tiles).
 * The wrapper carries `data-status` and the whole label as its text.
 */
export function SplitStatus({
  kind,
  label,
  title,
  detail = "inline",
  testId,
}: {
  kind: StatusKind;
  label: string;
  title?: ReactNode;
  detail?: "inline" | "hidden";
  testId?: string;
}) {
  const [head, ...rest] = label.split(" · ");
  const tail = rest.join(" · ");
  const tag = <StatusTag kind={kind}>{head}</StatusTag>;
  return (
    <span className={`split-status split-${detail}`} data-status={kind} data-testid={testId}>
      {title || (detail === "hidden" && tail) ? (
        <Tooltip title={title ?? label}>
          <span className="split-status-tag" tabIndex={detail === "hidden" ? 0 : undefined}>
            {tag}
          </span>
        </Tooltip>
      ) : (
        tag
      )}
      {tail ? (
        detail === "hidden" ? (
          <span className="sr-only"> · {tail}</span>
        ) : (
          <span className="split-status-detail">
            <span className="split-status-sep"> · </span>
            {tail}
          </span>
        )
      ) : null}
    </span>
  );
}

/** Reasons without blanks, duplicates, parts of a longer reason, or the label itself; joined with "；". */
export function joinReasons(reason: string | (string | null | undefined)[] | null | undefined, label?: string): string {
  const list = (Array.isArray(reason) ? reason : [reason]).map((r) => (r ?? "").trim()).filter((r) => r !== "" && r !== label);
  const uniq = list.filter((r, i) => list.indexOf(r) === i);
  return uniq.filter((r) => !uniq.some((o) => o !== r && o.includes(r))).join("；");
}

// -------------------------------------------------------------------- tables

/**
 * How a column takes width (docs/ui-layout.md):
 * - fixed: exactly `width` px, never wraps (ids, counts, times, tags)
 * - flex: takes the remaining width, at least `width` px (default 160), wraps normally
 * - ellipsis: `width` px, one line cut with "…"; the full text is a
 *   keyboard-reachable tooltip
 * - actions: `width` px, pinned right with an opaque background
 */
export type ColKind = "fixed" | "flex" | "ellipsis" | "actions";

/**
 * Where a column goes when the table is shown as stacked cards (phone width,
 * see DataTable `stack`):
 * - title: the card's heading (one per table; the row's identity). Without
 *   one, the first column that declares no place is the heading.
 * - key: label + value, always visible (default)
 * - detail: label + value under the card's 「详情」 toggle, with `secondary`
 * - hidden: not shown in the card (its content is already in another field)
 * The `actions` column is always the card's top-right corner.
 */
export type CardRole = "title" | "key" | "detail" | "hidden";

export interface DataColumn<T> extends Omit<TableColumnType<T>, "width" | "fixed" | "ellipsis"> {
  kind?: ColKind;
  width?: number;
  /** Render the value in monospace (ellipsis columns). */
  mono?: boolean;
  /** Place of the column in the stacked cards (default "key"; the actions column is always the card's corner). */
  card?: CardRole;
}

const FLEX_MIN = 160;

/** Width antd gives the expand-icon column of a table with an expandable row. */
export const EXPAND_COL = 48;

/**
 * Width a table really has at a 1280 px viewport with the sidebar expanded
 * (216 px) and the content padding (24 px each side), measured in a real
 * browser on the local panel: the content column is 1016 px; a table directly
 * in the page gets all of it; a Section card takes 2 × 20 px padding + 2 × 1 px
 * border (974 px inside). Drawers and dialogs: their width minus 2 × 24 px body
 * padding. Smaller insets: a bordered card inside a section (WSS listener,
 * 2 × 12 + 2), a Collapse panel body (2 × 16 + 2) and an expanded table row
 * (2 × 16). The sum of a DataTable's declared minimum column widths (see
 * tableMinWidth) must not exceed the width of its container, or the table
 * scrolls at 1280 (docs/ui-layout.md, "Table width budget").
 */
export const TABLE_BUDGET = {
  viewport: 1280,
  page: 1016,
  section: 974,
  sectionInset: 42,
  drawerPadding: 48,
  modalPadding: 48,
  cardInset: 26,
  collapseInset: 34,
  expandedRowInset: 32,
} as const;

/**
 * The unlock matrix's column widths (rendered as a <colgroup> with
 * table-layout: fixed, so the browser uses exactly these; cell padding and
 * borders are inside them, box-sizing is border-box). `box` is the grid's
 * scroll box at 1280 (a Section's 974 px minus the box's 2 px border):
 * the service column plus 9 exit columns fit it without scrolling.
 */
export const MATRIX_LAYOUT = { box: TABLE_BUDGET.section - 2, firstCol: 180, exitCol: 86, fitExits: 9 } as const;

/**
 * The minimum width a DataTable forces: fixed / ellipsis / actions widths,
 * flex minimums (default 160) and the expand column when rows expand. This is
 * the table's `scroll.x`, so it is what has to fit its container.
 */
export function tableMinWidth<T>(columns: DataColumn<T>[], expandable: boolean): number {
  return columns.reduce((n, c) => n + (c.width ?? ((c.kind ?? "flex") === "flex" ? FLEX_MIN : 120)), 0) + (expandable ? EXPAND_COL : 0);
}

function prepareColumns<T extends object>(columns: DataColumn<T>[]): { cols: TableColumnType<T>[]; minWidth: number } {
  let minWidth = 0;
  const cols = columns.map((c): TableColumnType<T> => {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { kind = "flex", width, mono, render, className, card, ...rest } = c;
    const cls = (extra: string) => [className, extra].filter(Boolean).join(" ");
    if (kind === "flex") {
      const min = width ?? FLEX_MIN;
      minWidth += min;
      return { ...rest, render, className: cls("col-flex"), onCell: (r, i) => ({ ...(rest.onCell?.(r, i) ?? {}), style: { minWidth: min } }) };
    }
    const w = width ?? 120;
    minWidth += w;
    if (kind === "fixed") return { ...rest, render, width: w, className: cls("col-fixed") };
    if (kind === "actions") return { ...rest, render, width: w, fixed: "right", className: cls("col-actions") };
    return {
      ...rest,
      width: w,
      ellipsis: { showTitle: false },
      className: cls("col-ellipsis"),
      render: (value, record, index) => {
        const node = render ? render(value, record, index) : value;
        return typeof node === "string" || typeof node === "number" ? <EllipsisText text={node} mono={mono} /> : (node as ReactNode);
      },
    };
  });
  return { cols, minWidth };
}

/**
 * Whether the scroll container `selector` (inside `ref`; omit it to measure the
 * ref itself) scrolls sideways and whether it is at its end, for the hint.
 */
export function useScrollHint(ref: { current: HTMLElement | null }, selector?: string) {
  const [state, setState] = useState({ overflow: false, atEnd: false });
  useEffect(() => {
    const root = ref.current;
    const el = selector ? root?.querySelector<HTMLElement>(selector) : root;
    if (!el) return;
    const measure = () => {
      const overflow = el.scrollWidth > el.clientWidth + 2;
      const atEnd = el.scrollLeft + el.clientWidth >= el.scrollWidth - 2;
      setState((o) => (o.overflow === overflow && o.atEnd === atEnd ? o : { overflow, atEnd }));
    };
    measure();
    el.addEventListener("scroll", measure, { passive: true });
    window.addEventListener("resize", measure);
    const ro = typeof ResizeObserver === "undefined" ? null : new ResizeObserver(measure);
    ro?.observe(el);
    return () => {
      el.removeEventListener("scroll", measure);
      window.removeEventListener("resize", measure);
      ro?.disconnect();
    };
  });
  return state;
}

function ScrollHint({ overflow, atEnd }: { overflow: boolean; atEnd: boolean }) {
  if (!overflow) return null;
  return (
    <div className={atEnd ? "scroll-hint at-end" : "scroll-hint"} role="note">
      {atEnd ? "已到最右" : "还有更多列，可左右滚动 →"}
    </div>
  );
}

/**
 * The panel's table: antd Table with explicit column width classes (see
 * ColKind), an expandable row for secondary fields, pagination past
 * `pageSize` rows, and a visible hint when it scrolls inside its box.
 * Replaces `scroll={TABLE_SCROLL}`: the table is as wide as the sum of its
 * column widths (at least its container) instead of "max-content".
 */
export function DataTable<T extends object>({
  columns,
  secondary,
  pageSize = 20,
  pagination,
  expandable,
  stack = true,
  ...rest
}: Omit<TableProps<T>, "columns" | "scroll"> & {
  columns: DataColumn<T>[];
  /** Secondary fields, shown in an expandable row. */
  secondary?: (record: T) => ReactNode;
  pageSize?: number;
  /**
   * Below the tablet breakpoint (phone width) show the rows as stacked cards
   * (label + value, actions in the card's corner, no sideways scrolling, no
   * pinned column). Default true; `false` keeps the scrolling table (wide
   * matrix-like tables).
   */
  stack?: boolean;
}) {
  const wrap = useRef<HTMLDivElement>(null);
  const { cols, minWidth } = useMemo(() => prepareColumns(columns), [columns]);
  const hint = useScrollHint(wrap, ".ant-table-content");
  const phone = useMediaQuery(STACK_QUERY);
  const rows = (rest.dataSource ?? []).length;
  if (stack && phone) {
    return <DataCards<T> columns={columns} prepared={cols} secondary={secondary} pageSize={pageSize} pagination={pagination} expandable={expandable} {...rest} />;
  }
  return (
    <div className="data-table-wrap" ref={wrap} data-overflow={hint.overflow ? "true" : "false"}>
      <Table<T>
        size="middle"
        {...rest}
        className={["data-table", rest.className ?? ""].filter(Boolean).join(" ")}
        columns={cols}
        scroll={{ x: minWidth + (secondary || expandable?.expandedRowRender ? EXPAND_COL : 0) }}
        pagination={pagination ?? (rows > pageSize ? { pageSize, showSizeChanger: true, hideOnSinglePage: true } : false)}
        expandable={secondary ? { expandedRowRender: (r) => <div className="row-secondary">{secondary(r)}</div>, ...expandable } : expandable}
      />
      <ScrollHint {...hint} />
    </div>
  );
}

/** Media query of the stacked (card) table layout: below the tablet breakpoint. */
export const STACK_QUERY = `(max-width: ${BREAKPOINTS.tablet - 1}px)`;

/** Whether a media query matches now; follows changes. False where matchMedia is missing. */
export function useMediaQuery(query: string): boolean {
  const get = () => (typeof window !== "undefined" && typeof window.matchMedia === "function" ? !!window.matchMedia(query)?.matches : false);
  const [match, setMatch] = useState(get);
  useEffect(() => {
    if (typeof window.matchMedia !== "function") return;
    const mq = window.matchMedia(query);
    if (!mq) return;
    const on = () => setMatch(!!mq.matches);
    on();
    mq.addEventListener?.("change", on);
    return () => mq.removeEventListener?.("change", on);
  }, [query]);
  return match;
}

function cellValue<T>(record: T, dataIndex: unknown): unknown {
  if (dataIndex === undefined || dataIndex === null) return undefined;
  const path = Array.isArray(dataIndex) ? dataIndex : [dataIndex];
  let v: unknown = record;
  for (const k of path) v = v == null ? undefined : (v as Record<string, unknown>)[k as string];
  return v;
}

function titleText(t: unknown): ReactNode {
  return typeof t === "function" ? null : (t as ReactNode);
}

/**
 * DataTable's stacked mode (phone width): one card per row. The column with
 * `card: "title"` is the heading, the actions column sits in the card's top
 * right, `key` columns are label + value rows, `detail` columns and
 * `secondary` / `expandable` go under a 「详情」 toggle. Same pagination,
 * row attributes (onRow, rowClassName) and expansion state as the table.
 */
function DataCards<T extends object>({
  columns,
  prepared,
  secondary,
  pageSize,
  pagination,
  expandable,
  dataSource,
  rowKey,
  onRow,
  rowClassName,
  locale,
  loading,
  className,
  ...rest
}: Omit<TableProps<T>, "columns" | "scroll"> & {
  columns: DataColumn<T>[];
  prepared: TableColumnType<T>[];
  secondary?: (record: T) => ReactNode;
  pageSize: number;
}) {
  const data = (dataSource ?? []) as readonly T[];
  const pg = pagination === false ? null : pagination ?? (data.length > pageSize ? { pageSize, showSizeChanger: true, hideOnSinglePage: true } : null);
  const [ownPage, setOwnPage] = useState(1);
  const [ownSize, setOwnSize] = useState(pg?.pageSize ?? pageSize);
  const [ownOpen, setOwnOpen] = useState<readonly Key[]>(expandable?.defaultExpandedRowKeys ?? []);
  const size = pg?.pageSize ?? ownSize;
  const pages = Math.max(1, Math.ceil(data.length / size));
  const current = pg ? Math.min(Math.max(1, pg.current ?? ownPage), pages) : 1;
  const shown = pg ? data.slice((current - 1) * size, current * size) : data;
  const open = expandable?.expandedRowKeys ?? ownOpen;
  const keyOf = (r: T, i: number): Key =>
    typeof rowKey === "function" ? (rowKey as (r: T, i?: number) => Key)(r, i) : ((r as Record<string, unknown>)[(rowKey as string) ?? "key"] as Key) ?? i;
  const toggle = (r: T, k: Key) => {
    const was = open.includes(k);
    const next = was ? open.filter((x) => x !== k) : [...open, k];
    if (!expandable?.expandedRowKeys) setOwnOpen(next);
    expandable?.onExpandedRowsChange?.(next);
    expandable?.onExpand?.(!was, r);
  };
  const render = (c: TableColumnType<T>, r: T, i: number): ReactNode => {
    const v = cellValue(r, (c as { dataIndex?: unknown }).dataIndex);
    const out = c.render ? c.render(v, r, i) : v;
    return (out ?? null) as ReactNode;
  };
  // Without an explicit "title" column, the first column that declares no place is the card's heading.
  const implicitTitle = columns.some((c) => c.card === "title") ? -1 : columns.findIndex((c) => c.kind !== "actions" && c.card === undefined);
  const cols = columns.map((c, i) => ({
    def: c,
    col: prepared[i],
    role: (c.kind === "actions" ? "actions" : i === implicitTitle ? "title" : (c.card ?? "key")) as CardRole | "actions",
  }));
  const titleCol = cols.find((c) => c.role === "title");
  const actionCols = cols.filter((c) => c.role === "actions");
  const keyCols = cols.filter((c) => c.role === "key");
  const detailCols = cols.filter((c) => c.role === "detail");
  const expandRender = secondary ? (r: T) => <div className="row-secondary">{secondary(r)}</div> : expandable?.expandedRowRender;
  const field = (c: (typeof cols)[number], r: T, i: number, j: number) => (
    <div className="data-card-field" key={j}>
      <dt>{titleText(c.def.title)}</dt>
      <dd>{render(c.col, r, i)}</dd>
    </div>
  );
  if (loading && data.length === 0) {
    return (
      <div className="data-table-wrap data-cards-wrap" data-stacked="true">
        <Skeleton active paragraph={{ rows: 3 }} />
      </div>
    );
  }
  return (
    <div className="data-table-wrap data-cards-wrap" data-stacked="true" data-overflow="false" {...pickData(rest)}>
      {data.length === 0 ? (
        <div className="data-cards-empty">{(locale?.emptyText as ReactNode) ?? <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无数据" />}</div>
      ) : (
        <ul className={["data-cards", className ?? ""].filter(Boolean).join(" ")}>
          {shown.map((r, i) => {
            const k = keyOf(r, i);
            const attrs = (onRow?.(r, i) ?? {}) as HTMLAttributes<HTMLElement> & Record<string, unknown>;
            const extraCls = typeof rowClassName === "function" ? rowClassName(r, i, 0) : rowClassName ?? "";
            const canExpand = !!expandRender && (expandable?.rowExpandable ? expandable.rowExpandable(r) : true);
            const hasMore = canExpand || detailCols.length > 0;
            const isOpen = open.includes(k);
            const moreId = `card-more-${String(k)}`;
            return (
              <li {...attrs} key={k} data-row-key={String(k)} className={["data-card", extraCls, attrs.className ?? ""].filter(Boolean).join(" ")}>
                <div className="data-card-head">
                  <div className="data-card-title">{titleCol ? render(titleCol.col, r, i) : null}</div>
                  {actionCols.length > 0 ? (
                    <div className="data-card-actions" data-card-actions="">
                      {actionCols.map((c, j) => (
                        <span key={j}>{render(c.col, r, i)}</span>
                      ))}
                    </div>
                  ) : null}
                </div>
                {keyCols.length > 0 ? <dl className="data-card-fields">{keyCols.map((c, j) => field(c, r, i, j))}</dl> : null}
                {hasMore ? (
                  <>
                    <button type="button" className="data-card-toggle explain-toggle" aria-expanded={isOpen} aria-controls={moreId} onClick={() => toggle(r, k)}>
                      {isOpen ? "收起详情" : "详情"}
                    </button>
                    <div id={moreId} className="data-card-more" hidden={!isOpen}>
                      {isOpen ? (
                        <>
                          {detailCols.length > 0 ? <dl className="data-card-fields">{detailCols.map((c, j) => field(c, r, i, j))}</dl> : null}
                          {canExpand && expandRender ? expandRender(r, i, 0, true) : null}
                        </>
                      ) : null}
                    </div>
                  </>
                ) : null}
              </li>
            );
          })}
        </ul>
      )}
      {pg && !(pg.hideOnSinglePage && pages <= 1) ? (
        <Pagination
          className="data-cards-pagination"
          size="small"
          current={current}
          pageSize={size}
          total={data.length}
          showSizeChanger={pg.showSizeChanger}
          pageSizeOptions={pg.pageSizeOptions}
          showTotal={pg.showTotal}
          onChange={(p, s) => {
            setOwnPage(s !== size ? 1 : p);
            setOwnSize(s);
            pg.onChange?.(p, s);
          }}
        />
      ) : null}
    </div>
  );
}

/** data-* attributes passed to a DataTable (e.g. data-testid) go onto the card list's wrapper. */
function pickData(o: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(o).filter(([k]) => k.startsWith("data-") || k.startsWith("aria-")));
}

/**
 * Wrapper for wide grids (unlock matrix, coverage table): the grid scrolls
 * inside this box, its first column stays frozen (opaque), and a hint says
 * there is more to the right. Put a `<table>` inside; cells hold <GridCell>.
 * The box is focusable so the keyboard can scroll it.
 */
export function WideGrid({ children, label }: { children: ReactNode; label: string }) {
  const box = useRef<HTMLDivElement>(null);
  const hint = useScrollHint(box);
  return (
    <div className="wide-grid" data-overflow={hint.overflow ? "true" : "false"}>
      <div className="wide-grid-scroll" ref={box} tabIndex={0} role="region" aria-label={label}>
        {children}
      </div>
      <ScrollHint {...hint} />
    </div>
  );
}

/**
 * A compact grid cell: the result on one line (chips never wrap), an optional
 * one-line note under it, cut with "…" and readable on hover/focus.
 */
export function GridCell({ children, note }: { children: ReactNode; note?: string | null }) {
  return (
    <div className="grid-cell">
      <div className="grid-cell-main">{children}</div>
      {note ? <EllipsisText className="grid-cell-note" text={note} /> : null}
    </div>
  );
}

// ================================================================ regions ===

const REGION_NAMES: Record<string, string> = {
  hk: "香港",
  tw: "台湾",
  mo: "澳门",
  cn: "中国大陆",
  jp: "日本",
  kr: "韩国",
  sg: "新加坡",
  my: "马来西亚",
  th: "泰国",
  vn: "越南",
  ph: "菲律宾",
  id: "印度尼西亚",
  in: "印度",
  au: "澳大利亚",
  us: "美国",
  ca: "加拿大",
  gb: "英国",
  uk: "英国",
  de: "德国",
  fr: "法国",
  nl: "荷兰",
  tr: "土耳其",
  ru: "俄罗斯",
  br: "巴西",
};

/** "hk" → "香港 · HK"; unknown codes stay as typed; empty → "未设地区". */
export function regionLabel(code: string | undefined | null): string {
  const c = (code ?? "").trim();
  if (!c) return "未设地区";
  const name = REGION_NAMES[c.toLowerCase()];
  return name ? `${name} · ${c.toUpperCase()}` : c.toUpperCase();
}

export const REGION_CODES = Object.keys(REGION_NAMES).filter((c) => c !== "uk");

/** The fields a group label needs (RegionGroup, RegionGroupView, unlock rows …). */
export interface GroupNameLike {
  id: string;
  name: string;
  region?: string;
}

const groupNameKey = (name: string) => name.trim().toLocaleLowerCase();

/**
 * Display name of a region group that stays unambiguous: the plain name
 * when no other group in `all` has the same name (trimmed, case-insensitive),
 * otherwise the name with its region and its stable ID, e.g.
 * "香港（香港 · HK · hk-home）". Pickers, lists and messages all use it so
 * two groups called the same can always be told apart.
 */
export function groupLabel(g: GroupNameLike, all: readonly GroupNameLike[] | null | undefined): string {
  const name = g.name?.trim() || g.id;
  if (!all || !isDuplicateGroupName(g, all)) return name;
  return `${name}（${regionLabel(g.region)} · ${g.id}）`;
}

/** Another group in `all` has the same display name. */
export function isDuplicateGroupName(g: GroupNameLike, all: readonly GroupNameLike[]): boolean {
  const k = groupNameKey(g.name?.trim() || g.id);
  return all.some((o) => o.id !== g.id && groupNameKey(o.name?.trim() || o.id) === k);
}
