// Application shell: theme, panel token gate, sidebar + top bar, hash routes.

import {
  ApartmentOutlined,
  BranchesOutlined,
  CloudOutlined,
  CloudServerOutlined,
  CompassOutlined,
  DashboardOutlined,
  DeploymentUnitOutlined,
  FileSearchOutlined,
  GlobalOutlined,
  HistoryOutlined,
  KeyOutlined,
  LockOutlined,
  UserOutlined,
  MenuFoldOutlined,
  MenuOutlined,
  MenuUnfoldOutlined,
  MoonOutlined,
  ProfileOutlined,
  SunOutlined,
  UnorderedListOutlined,
  WifiOutlined,
  DesktopOutlined,
  PlayCircleOutlined,
} from "@ant-design/icons";
import {
  App as AntApp,
  Button,
  ConfigProvider,
  Drawer,
  Dropdown,
  Form,
  Grid,
  Input,
  Layout,
  Menu,
  Modal,
  Result,
  Skeleton,
  Space,
  Tooltip,
  Typography,
  type MenuProps,
} from "antd";
import zhCN from "antd/locale/zh_CN";
import {
  Component,
  createContext,
  lazy,
  Suspense,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ComponentType,
  type ReactNode,
} from "react";
import * as api from "./api";
import { PanelUpdate } from "./PanelUpdate";
import { RouteOverride, RouterProvider, StatusProvider, TopologyProvider, href, parseHash, useRouter, useStatus, type Route } from "./state";
import { HelpGuide, HelpIcon } from "./HelpGuide";
import { HelpSlotContext } from "./ui";
import { themeConfig } from "./theme";
import { wizardEvents } from "./wizard_events";
// The shell imports only ui_base (not ui.tsx): the table, dialog and pagination
// code every page shares stays out of the entry chunk (web/README.md「首屏与拆包」).
import { ApiErrorAlert, CommandBlock, Link, PendingInstallIndicator, StatusTag, errorTitle } from "./ui_base";

// ==================================================================== theme ===

type ThemePref = "system" | "light" | "dark";
const THEME_KEY = "meridian.theme"; // the only thing the panel keeps in localStorage

function readThemePref(): ThemePref {
  try {
    const v = localStorage.getItem(THEME_KEY);
    return v === "light" || v === "dark" ? v : "system";
  } catch {
    return "system";
  }
}

function useSystemDark() {
  const query = "(prefers-color-scheme: dark)";
  const [dark, setDark] = useState(() => (typeof window.matchMedia === "function" ? window.matchMedia(query).matches : false));
  useEffect(() => {
    if (typeof window.matchMedia !== "function") return;
    const mq = window.matchMedia(query);
    const on = () => setDark(mq.matches);
    mq.addEventListener?.("change", on);
    return () => mq.removeEventListener?.("change", on);
  }, []);
  return dark;
}

// =================================================================== routes ===

/**
 * A page module that could not be loaded: the network to the gateway
 * dropped, or the panel was upgraded while this tab stayed open and the
 * file it asks for no longer exists. Shown with a reload action
 * (PageLoadFailed) instead of the generic page error.
 */
export class PageLoadError extends Error {
  constructor(cause: unknown) {
    super(cause instanceof Error ? cause.message : String(cause));
    this.name = "PageLoadError";
    this.cause = cause;
  }
}

type PageModule = { default: ComponentType };

/** React.lazy for a route; a failed import becomes a PageLoadError. */
export function lazyPage(load: () => Promise<PageModule>) {
  return lazy(() =>
    load().catch((e: unknown) => {
      throw new PageLoadError(e);
    }),
  );
}

/** Reloads the whole panel (a stale tab picks up the current files). Replaceable in tests. */
export const panelReload = { run: () => window.location.reload() };

interface RouteDef {
  key: string;
  label: string;
  icon: ReactNode;
  /** The page module, loaded on first visit (one chunk per page). */
  load: () => Promise<PageModule>;
  component: ComponentType;
}

function route(key: string, label: string, icon: ReactNode, load: () => Promise<PageModule>): RouteDef {
  return { key, label, icon, load, component: lazyPage(load) };
}

interface RouteGroup {
  label: string | null;
  routes: RouteDef[];
}

/** The information architecture. Keys are the first hash segment. */
export const NAV: RouteGroup[] = [
  { label: null, routes: [route("", "概览", <DashboardOutlined />, () => import("./OverviewPage"))] },
  {
    // Everything that decides where traffic goes, the resolution settings included.
    label: "网络",
    routes: [
      route("topology", "拓扑", <ApartmentOutlined />, () => import("./TopologyPage")),
      route("exits", "出口", <GlobalOutlined />, () => import("./ExitsPage")),
      route("rules", "分流规则", <BranchesOutlined />, () => import("./RulesPage")),
      route("lists", "名单", <UnorderedListOutlined />, () => import("./ListsPage")),
      // A bare `#dns` (the old anchor of the resolution section on the lists page) parses to the page "dns".
      route("dns", "解析设置", <CompassOutlined />, () => import("./DNSView")),
    ],
  },
  {
    label: "日志",
    routes: [
      route("dns-log", "解析日志", <FileSearchOutlined />, () => import("./DNSLogsPage")),
      route("conn-log", "连接日志", <ProfileOutlined />, () => import("./ConnectionLogsPage")),
      route("link-log", "链路日志", <HistoryOutlined />, () => import("./LinkLogsPage")),
    ],
  },
  {
    label: "运维",
    routes: [
      route("deploy", "部署", <DeploymentUnitOutlined />, () => import("./DeployPage")),
      route("unlock", "解锁", <PlayCircleOutlined />, () => import("./UnlockPage")),
    ],
  },
  {
    label: "资源",
    routes: [
      route("servers", "服务器", <CloudServerOutlined />, () => import("./ServersPage")),
      route("keys", "密钥", <KeyOutlined />, () => import("./CredentialsPage")),
      route("cloudflare", "Cloudflare", <CloudOutlined />, () => import("./CloudflarePage")),
      route("remote", "远程接入", <WifiOutlined />, () => import("./RemotePage")),
    ],
  },
];

/** The first-run wizard (#/setup): not in the sidebar; shown while GET /api/setup/wizard says active. */
const SetupWizardPage = lazyPage(() => import("./SetupWizard"));

const GUIDE_GROUPS = NAV.map((g) => ({ label: g.label, routes: g.routes.map((r) => ({ key: r.key, label: r.label })) }));

/** The hash of a parsed route (path and query). */
function rawHash(r: Route) {
  const q = r.query.toString();
  return href(r.page, ...r.params) + (q ? `?${q}` : "");
}

const ROUTES = new Map(NAV.flatMap((g) => g.routes).map((r) => [r.key, r]));

/** Removed pages: their old addresses open the overview (service groups: the rules, which now target region groups). */
export const REDIRECTS: Record<string, string> = { leak: "", acceptance: "", "service-groups": "rules" };

function menuItems(): MenuProps["items"] {
  return NAV.map((g, i) => {
    const children = g.routes.map((r) => ({ key: r.key || "overview", icon: r.icon, label: <a href={href(r.key)} onClick={(e) => e.preventDefault()}>{r.label}</a> }));
    if (!g.label) return children[0];
    return { type: "group" as const, key: `g${i}`, label: g.label, children };
  });
}

// ============================================================== token gate ===

function GateCard({ subtitle, children }: { subtitle: string; children: ReactNode }) {
  return (
    <div className="token-screen">
      <div className="token-card">
        <Space align="center" style={{ marginBottom: 8 }}>
          <span className="brand-mark">M</span>
          <Typography.Title level={4} style={{ margin: 0 }}>
            Meridian 控制面板
          </Typography.Title>
        </Space>
        <Typography.Paragraph type="secondary">{subtitle}</Typography.Paragraph>
        {children}
      </div>
    </div>
  );
}

// First start of a fresh install: create the administrator with the
// one-time code printed on the gateway (meridian setup-code).
function SetupScreen({ onDone }: { onDone: () => void }) {
  const [form] = Form.useForm<{ code: string; username: string; password: string; confirm: string }>();
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<api.ApiError | null>(null);
  return (
    <GateCard subtitle="首次使用：创建管理员账户">
      {err ? <ApiErrorAlert error={err} /> : null}
      <Form
        form={form}
        layout="vertical"
        onFinish={async ({ code, username, password }) => {
          setBusy(true);
          try {
            const r = await api.postSetup({ code, username, password });
            api.setToken(r.token);
            setErr(null);
            onDone();
          } catch (e) {
            setErr(e instanceof api.ApiError ? e : new api.ApiError(0, {}));
          } finally {
            setBusy(false);
          }
        }}
      >
        <Form.Item name="code" label="初始化码" rules={[{ required: true, message: "请输入初始化码" }]}>
          <Input autoComplete="off" autoFocus aria-label="初始化码" />
        </Form.Item>
        <div className="token-hint">
          <CommandBlock label="在网关上生成初始化码的命令，可左右滚动">docker compose exec meridian meridian setup-code</CommandBlock>
        </div>
        <Form.Item name="username" label="用户名" initialValue="admin" rules={[{ required: true, message: "请输入用户名" }]}>
          <Input autoComplete="username" aria-label="用户名" />
        </Form.Item>
        <Form.Item name="password" label="密码" rules={[{ required: true, min: 12, message: "至少 12 个字符" }]}>
          <Input.Password autoComplete="new-password" aria-label="密码" />
        </Form.Item>
        <Form.Item
          name="confirm"
          label="再输一次"
          dependencies={["password"]}
          rules={[
            { required: true, message: "请再输一次密码" },
            ({ getFieldValue }) => ({
              validator: (_, v) => (v === getFieldValue("password") ? Promise.resolve() : Promise.reject(new Error("两次输入不一致"))),
            }),
          ]}
        >
          <Input.Password autoComplete="new-password" aria-label="再输一次" />
        </Form.Item>
        <Button type="primary" htmlType="submit" loading={busy} block>
          创建并进入
        </Button>
      </Form>
    </GateCard>
  );
}

function TokenScreen({ onUnlocked, error }: { onUnlocked: () => void; error: api.ApiError | null }) {
  const [form] = Form.useForm<{ token: string; username: string; password: string }>();
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<api.ApiError | null>(error);
  // An administrator password exists: log in with it; the token stays a fallback.
  const [admin, setAdmin] = useState(false);
  const [useToken, setUseToken] = useState(false);
  useEffect(() => {
    let live = true;
    api.getSetupStatus().then(
      (s) => live && setAdmin(Boolean(s && s.admin)),
      () => undefined,
    );
    return () => {
      live = false;
    };
  }, []);
  const passwordMode = admin && !useToken;
  return (
    <GateCard subtitle={passwordMode ? "管理员登录（只存在本标签页，关闭即清除）" : "输入面板口令（只存在本标签页，关闭即清除）"}>
      {err ? <ApiErrorAlert error={err} /> : null}
      <Form
        form={form}
        layout="vertical"
        onFinish={async ({ token, username, password }) => {
          setBusy(true);
          try {
            if (passwordMode) {
              const r = await api.postLogin({ username, password });
              api.setToken(r.token);
            } else {
              api.setToken(token || "");
            }
            await api.getMeta();
            setErr(null);
            onUnlocked();
          } catch (e) {
            api.clearToken();
            setErr(e instanceof api.ApiError ? e : new api.ApiError(0, {}));
          } finally {
            form.resetFields();
            setBusy(false);
          }
        }}
      >
        {passwordMode ? (
          <>
            <Form.Item name="username" label="用户名" rules={[{ required: true, message: "请输入用户名" }]}>
              <Input autoComplete="username" autoFocus aria-label="用户名" />
            </Form.Item>
            <Form.Item name="password" label="密码" rules={[{ required: true, message: "请输入密码" }]}>
              <Input.Password autoComplete="current-password" aria-label="密码" />
            </Form.Item>
          </>
        ) : (
          <>
            <Form.Item name="token" label="面板口令" rules={[{ required: true, message: "请输入面板口令" }]}>
              <Input.Password autoComplete="off" autoFocus aria-label="面板口令" />
            </Form.Item>
            <div className="token-hint">
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                口令在网关的数据目录里：
              </Typography.Text>
              <CommandBlock label="读取面板口令的命令，可左右滚动">docker compose exec meridian cat /var/lib/meridian/panel.token</CommandBlock>
            </div>
          </>
        )}
        <Button type="primary" htmlType="submit" loading={busy} block>
          进入
        </Button>
        {admin ? (
          <Button type="link" block onClick={() => setUseToken((v) => !v)}>
            {useToken ? "用管理员密码登录" : "改用面板口令"}
          </Button>
        ) : null}
      </Form>
    </GateCard>
  );
}

function AuthGate({ children }: { children: ReactNode }) {
  const [state, setState] = useState<"checking" | "setup" | "locked" | "open">("checking");
  const [err, setErr] = useState<api.ApiError | null>(null);
  const [generation, setGeneration] = useState(0);

  const check = useCallback(async () => {
    try {
      await api.getMeta();
      setState("open");
      setErr(null);
    } catch (e) {
      const ae = e instanceof api.ApiError ? e : new api.ApiError(0, {});
      if (ae.status === 403 && ae.code === "setup_required") {
        setState("setup");
        setErr(null);
      } else if (ae.status === 401) {
        setState("locked");
        setErr(api.getToken() ? ae : null);
      } else {
        setState("locked");
        setErr(ae);
      }
    }
  }, []);

  useEffect(() => {
    void check();
    return api.onUnauthorized(() => setState("locked"));
  }, [check]);

  if (state === "checking") return <div className="token-screen"><Skeleton active style={{ maxWidth: 420 }} /></div>;
  if (state === "setup")
    return (
      <SetupScreen
        onDone={() => {
          setGeneration((g) => g + 1);
          setState("open");
        }}
      />
    );
  if (state === "locked")
    return (
      <TokenScreen
        error={err}
        onUnlocked={() => {
          setGeneration((g) => g + 1);
          setState("open");
        }}
      />
    );
  return <LockContext.Provider value={() => { api.clearToken(); setState("locked"); setErr(null); }} key={generation}>{children}</LockContext.Provider>;
}

const LockContext = createContext<() => void>(() => {});

// =========================================================== error boundary ===

/**
 * A page module that did not load: say so and offer a reload, which fetches
 * the panel's current files (the old ones may be gone after an upgrade).
 */
function PageLoadFailed() {
  // Only a click reloads: an automatic reload could loop if the file stays
  // unreachable. A tab still running a build from before this state existed
  // shows whatever that build had; see docs/architecture.md「静态文件缓存与升级提示」.
  return (
    <div data-testid="page-load-failed">
      <Result
        status="warning"
        title="面板已更新，请刷新"
        subTitle="这个页面的文件没有下载成功：面板多半刚升级过，这个标签页还是旧版本（也可能是与网关的连接断了）。刷新即可。"
        extra={
          <Button type="primary" onClick={() => panelReload.run()}>
            刷新
          </Button>
        }
      />
    </div>
  );
}

/** A page that throws while rendering shows this instead of a blank panel. */
class PageBoundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state = { error: null as Error | null };
  static getDerivedStateFromError(error: Error) {
    return { error };
  }
  render() {
    if (this.state.error instanceof PageLoadError) return <PageLoadFailed />;
    if (this.state.error)
      return (
        <Result
          status="error"
          title="这个页面出错了"
          subTitle={this.state.error.message}
          extra={<Button onClick={() => this.setState({ error: null })}>重试</Button>}
        />
      );
    return this.props.children;
  }
}

/** While a page module loads. */
function PageLoading() {
  return (
    <div role="status" aria-label="页面加载中" data-testid="page-loading">
      <Skeleton active paragraph={{ rows: 8 }} />
    </div>
  );
}

/**
 * Where a route's page renders: its loading state while the module
 * downloads, the load-failure state when it cannot, and the page error
 * boundary. Keyed by the page so leaving a failed page clears the failure.
 */
export function PageSlot({ page, component: Page }: { page: string; component: ComponentType }) {
  return (
    <Suspense fallback={<PageLoading />}>
      <PageBoundary key={page}>
        <Page />
      </PageBoundary>
    </Suspense>
  );
}

// ================================================================== top bar ===

function GlobalStatus() {
  const { status, statusError, jobs } = useStatus();
  const { navigate } = useRouter();
  const items: ReactNode[] = [];
  const go = (to: string) => (e: React.MouseEvent) => {
    e.preventDefault();
    navigate(to);
  };
  if (statusError) {
    items.push(
      <StatusTag key="status" kind="failed" title={statusError.message}>
        {errorTitle(statusError)}
      </StatusTag>,
    );
  } else if (status) {
    items.push(
      status.agent.ok ? (
        <StatusTag key="agent" kind="ok" title="meridian-host 刚刚应答了健康检查">
          宿主通道正常
        </StatusTag>
      ) : (
        <StatusTag key="agent" kind="attention" title={status.agent.error || "meridian-host 不可达"}>
          宿主通道不可用
        </StatusTag>
      ),
    );
    if (status.pending) {
      const p = status.pending;
      items.push(
        <a key="txn" href={href("deploy")} onClick={go(href("deploy"))}>
          <StatusTag kind="failed" title={`事务 ${p.id}：${p.phase}${p.error ? `，${p.error}` : ""}。在部署页恢复。`}>
            安装事务未完成
          </StatusTag>
        </a>,
      );
    }
    items.push(
      status.install.installed_version != null ? (
        <Tooltip key="ver" title={status.install.installed_at ? `安装于 ${status.install.installed_at}` : undefined}>
          <span className="topbar-fact">
            已安装 <span className="mono">v{status.install.installed_version}</span>
          </span>
        </Tooltip>
      ) : (
        <StatusTag key="ver" kind="neutral">
          数据面未安装
        </StatusTag>
      ),
    );
  }
  const running: [boolean, string, string][] = [
    [jobs.lists, "名单更新中", href("lists")],
    [jobs.unlock, "解锁探测中", href("unlock")],
    [jobs.mesh, "Mesh 部署进行中", href("cloudflare") + "?section=mesh"],
  ];
  for (const [on, label, to] of running) {
    if (on)
      items.push(
        <a key={label} href={to} onClick={go(to)}>
          <StatusTag kind="running">{label}</StatusTag>
        </a>,
      );
  }
  return <Space size={4} wrap className="global-status" data-testid="global-status">{items}</Space>;
}

function ThemeMenu({ pref, setPref }: { pref: ThemePref; setPref: (p: ThemePref) => void }) {
  const labels: Record<ThemePref, string> = { system: "跟随系统", light: "浅色", dark: "深色" };
  return (
    <Dropdown
      trigger={["click"]}
      menu={{
        selectable: true,
        selectedKeys: [pref],
        items: (Object.keys(labels) as ThemePref[]).map((k) => ({ key: k, label: labels[k] })),
        onClick: ({ key }) => setPref(key as ThemePref),
      }}
    >
      <Button type="text" aria-label="外观" icon={pref === "dark" ? <MoonOutlined /> : pref === "light" ? <SunOutlined /> : <DesktopOutlined />} />
    </Dropdown>
  );
}

// ================================================================== account ===

/** Changes the administrator's password (PUT /api/auth/admin). */
function AccountButton() {
  const [open, setOpen] = useState(false);
  const [form] = Form.useForm<{ current_password: string; username: string; password: string; confirm: string }>();
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<api.ApiError | null>(null);
  const [done, setDone] = useState(false);
  const submit = async (v: { current_password: string; username: string; password: string }) => {
    setBusy(true);
    setErr(null);
    try {
      await api.putAdmin({ current_password: v.current_password, username: v.username, password: v.password });
      setDone(true);
      form.resetFields();
    } catch (e) {
      setErr(e as api.ApiError);
    } finally {
      setBusy(false);
    }
  };
  return (
    <>
      <Tooltip title="管理员账户">
        <Button type="text" aria-label="管理员账户" icon={<UserOutlined />} onClick={() => { setOpen(true); setDone(false); setErr(null); }} />
      </Tooltip>
      <Modal open={open} title="管理员账户" onCancel={() => setOpen(false)} footer={null} destroyOnClose>
        {err ? <ApiErrorAlert error={err} /> : null}
        {done ? <StatusTag kind="ok">已更新</StatusTag> : null}
        <Form form={form} layout="vertical" onFinish={(v) => void submit(v)} initialValues={{ username: "admin" }}>
          <Form.Item name="username" label="用户名" rules={[{ required: true, message: "必填" }]}>
            <Input autoComplete="username" />
          </Form.Item>
          <Form.Item name="current_password" label="当前密码">
            <Input.Password autoComplete="current-password" />
          </Form.Item>
          <Form.Item name="password" label="新密码" rules={[{ required: true, min: 12, message: "至少 12 个字符" }]}>
            <Input.Password autoComplete="new-password" />
          </Form.Item>
          <Form.Item
            name="confirm"
            label="再输一次"
            dependencies={["password"]}
            rules={[{ required: true, message: "必填" }, ({ getFieldValue }) => ({ validator: (_, v) => (v === getFieldValue("password") ? Promise.resolve() : Promise.reject(new Error("两次不一致"))) })]}
          >
            <Input.Password autoComplete="new-password" />
          </Form.Item>
          <Button type="primary" htmlType="submit" loading={busy}>
            保存
          </Button>
        </Form>
      </Modal>
    </>
  );
}

// ================================================================== wizard ===

/** Whether the first-run wizard applies (fresh install). Any failure: no wizard. */
function useWizardActive(): [boolean | null, () => void] {
  const [active, setActive] = useState<boolean | null>(null);
  useEffect(() => {
    let live = true;
    api.getWizard().then(
      (v) => live && setActive(!!v?.active),
      () => live && setActive(false),
    );
    return () => {
      live = false;
    };
  }, []);
  return [active, useCallback(() => setActive(false), [])];
}

// ==================================================================== shell ===

function Shell({ themePref, setThemePref }: { themePref: ThemePref; setThemePref: (p: ThemePref) => void }) {
  const { route: address, navigate } = useRouter();
  // #/help/<page>: the usage guide over that page. The page underneath keeps
  // the address it was opened from (or its bare address on a deep link).
  const helpOpen = address.page === "help";
  const lastPage = useRef<Route>(address);
  if (!helpOpen) lastPage.current = address;
  const helpFor = helpOpen ? (address.params[0] === "overview" ? "" : address.params[0] ?? lastPage.current.page) : "";
  const [wizardActive, endWizard] = useWizardActive();
  useEffect(() => {
    wizardEvents.onFinish = endWizard;
  }, [endWizard]);
  useEffect(() => {
    if (wizardActive && address.page === "") navigate(href("setup"), { replace: true });
  }, [wizardActive, address.page, navigate]);
  const route = useMemo<Route>(
    () => (helpOpen ? (lastPage.current.page === helpFor ? lastPage.current : parseHash(href(helpFor))) : address),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [helpOpen, helpFor, address],
  );
  // The current page's explanations (ui.tsx Note/Help) live in this node:
  // inside the guide while it is open, in a hidden store otherwise.
  const [slot] = useState(() => {
    const d = document.createElement("div");
    d.dataset.testid = "page-help";
    return d;
  });
  const store = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!helpOpen && store.current && slot.parentNode !== store.current) store.current.appendChild(slot);
  });
  const closeHelp = () => navigate(lastPage.current.page === helpFor ? rawHash(lastPage.current) : href(helpFor));
  const lock = useContext(LockContext);
  const screens = Grid.useBreakpoint();
  const wide = screens.lg !== false && (screens.lg ?? true);
  const [collapsed, setCollapsed] = useState(false);
  const [drawer, setDrawer] = useState(false);
  const wizardPage = route.page === "setup";
  const current = wizardPage ? { key: "setup", label: "首次配置", component: SetupWizardPage } : ROUTES.get(route.page);
  const Component = current?.component;
  const guideGroups = useMemo(() => (helpFor === "setup" ? [{ label: null, routes: [{ key: "setup", label: "首次配置" }] }, ...GUIDE_GROUPS] : GUIDE_GROUPS), [helpFor]);
  const items = useMemo(menuItems, []);
  const selected = [route.page || "overview"];
  const redirect = Object.prototype.hasOwnProperty.call(REDIRECTS, route.page) ? REDIRECTS[route.page] : undefined;
  useEffect(() => {
    if (redirect !== undefined) navigate(href(redirect), { replace: true });
  }, [redirect, navigate]);

  useEffect(() => {
    document.title = current ? `${current.label} · Meridian` : "Meridian";
    setDrawer(false);
  }, [current, route.page]);

  const menu = (
    <nav aria-label="主导航" data-testid="main-nav">
    <Menu
      mode="inline"
      selectedKeys={selected}
      items={items}
      inlineCollapsed={wide ? collapsed : false}
      onClick={({ key }) => navigate(href(key === "overview" ? "" : key))}
      className="nav-menu"
    />
    </nav>
  );

  const brand = (
    <div className="brand">
      <span className="brand-mark">M</span>
      {!collapsed || !wide ? <span className="brand-name">Meridian</span> : null}
    </div>
  );

  return (
    <Layout className="shell">
      {wide ? (
        <Layout.Sider width={216} collapsedWidth={64} collapsed={collapsed} trigger={null} className="sider">
          {brand}
          {menu}
        </Layout.Sider>
      ) : (
        <Drawer placement="left" open={drawer} onClose={() => setDrawer(false)} width={248} styles={{ body: { padding: 8 } }} title={brand}>
          {menu}
        </Drawer>
      )}
      <Layout>
        <Layout.Header className="topbar">
          <Button
            type="text"
            aria-label={wide ? (collapsed ? "展开侧栏" : "收起侧栏") : "打开导航"}
            icon={wide ? (collapsed ? <MenuUnfoldOutlined /> : <MenuFoldOutlined />) : <MenuOutlined />}
            onClick={() => (wide ? setCollapsed((c) => !c) : setDrawer(true))}
          />
          {!wide ? <span className="brand-name topbar-brand">Meridian</span> : null}
          <div className="topbar-status">
            <GlobalStatus />
          </div>
          <div className="topbar-right">
            <PendingInstallIndicator compact={!wide} />
            <Tooltip title="使用说明">
              <Button
                type="text"
                aria-label="使用说明"
                data-testid="help-button"
                aria-pressed={helpOpen}
                icon={<HelpIcon />}
                onClick={() => (helpOpen ? closeHelp() : navigate(href("help", route.page || "overview")))}
              />
            </Tooltip>
            <ThemeMenu pref={themePref} setPref={setThemePref} />
            <AccountButton />
            <Tooltip title="锁定：清除这个标签页里的面板口令">
              <Button type="text" aria-label="锁定" icon={<LockOutlined />} onClick={lock} />
            </Tooltip>
          </div>
        </Layout.Header>
        <Layout.Content className="content">
          {redirect !== undefined ? null : Component ? (
            <HelpSlotContext.Provider value={slot}>
              <RouteOverride route={route}>
                <PageSlot page={route.page} component={Component} />
              </RouteOverride>
            </HelpSlotContext.Provider>
          ) : (
            <Result
              status="404"
              title="没有这个页面"
              subTitle={<span>地址 <code>{window.location.hash}</code> 不对应任何页面。</span>}
              extra={<Link to={href("")}>回到概览</Link>}
            />
          )}
        </Layout.Content>
        <div ref={store} hidden data-testid="page-help-store" />
        {helpOpen ? <HelpGuide groups={guideGroups} page={helpFor} slot={slot} onClose={closeHelp} /> : null}
      </Layout>
    </Layout>
  );
}

// ===================================================================== root ===

export default function App() {
  const [themePref, setThemePrefState] = useState<ThemePref>(readThemePref);
  const systemDark = useSystemDark();
  const dark = themePref === "dark" || (themePref === "system" && systemDark);
  const setThemePref = useCallback((p: ThemePref) => {
    setThemePrefState(p);
    try {
      if (p === "system") localStorage.removeItem(THEME_KEY);
      else localStorage.setItem(THEME_KEY, p);
    } catch {
      /* preference not remembered */
    }
  }, []);

  useEffect(() => {
    document.documentElement.dataset.theme = dark ? "dark" : "light";
    document.documentElement.style.colorScheme = dark ? "dark" : "light";
  }, [dark]);

  const config = useMemo(() => themeConfig(dark), [dark]);

  return (
    <ConfigProvider locale={zhCN} theme={config} button={{ autoInsertSpace: false }}>
      <AntApp>
        {/* Outside AuthGate: the login page also learns about an upgrade. */}
        <PanelUpdate />
        <AuthGate>
          <RouterProvider>
            <StatusProvider>
              <TopologyProvider>
                <Shell themePref={themePref} setThemePref={setThemePref} />
              </TopologyProvider>
            </StatusProvider>
          </RouterProvider>
        </AuthGate>
      </AntApp>
    </ConfigProvider>
  );
}
