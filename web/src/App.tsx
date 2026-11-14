// Application shell: theme, panel token gate, sidebar + top bar, hash routes.

import {
  ApartmentOutlined,
  BranchesOutlined,
  CloudOutlined,
  CloudServerOutlined,
  DashboardOutlined,
  DeploymentUnitOutlined,
  GlobalOutlined,
  KeyOutlined,
  LockOutlined,
  MenuFoldOutlined,
  MenuOutlined,
  MenuUnfoldOutlined,
  MoonOutlined,
  SafetyOutlined,
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
  Result,
  Skeleton,
  Space,
  Tooltip,
  Typography,
  theme as antdTheme,
  type MenuProps,
  type ThemeConfig,
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
  useState,
  type ComponentType,
  type ReactNode,
} from "react";
import * as api from "./api";
import { RouterProvider, StatusProvider, TopologyProvider, href, useRouter, useStatus } from "./state";
import { ApiErrorAlert, CommandBlock, Link, PendingInstallIndicator, StatusTag, errorTitle } from "./ui";

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

const FONT =
  '-apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", "Noto Sans SC", "Source Han Sans SC", sans-serif';
const MONO = 'ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace';

function themeConfig(dark: boolean): ThemeConfig {
  return {
    algorithm: dark ? antdTheme.darkAlgorithm : antdTheme.defaultAlgorithm,
    token: {
      colorPrimary: "#2f6fde",
      colorInfo: "#2f6fde",
      borderRadius: 8,
      fontFamily: FONT,
      fontFamilyCode: MONO,
      colorBgLayout: dark ? "#0f1318" : "#f4f6f9",
      colorBgContainer: dark ? "#161b22" : "#ffffff",
      colorBorderSecondary: dark ? "#262d36" : "#e8ebf0",
    },
    components: {
      Layout: {
        headerBg: dark ? "#161b22" : "#ffffff",
        siderBg: dark ? "#161b22" : "#ffffff",
        headerHeight: 56,
        headerPadding: "0 16px",
      },
      Menu: { itemBg: "transparent", subMenuItemBg: "transparent", itemBorderRadius: 6, itemHeight: 36 },
      Table: { cellPaddingBlock: 10, cellPaddingInline: 12, headerBg: dark ? "#1b2129" : "#f7f8fa" },
      Drawer: { footerPaddingBlock: 12 },
    },
  };
}

// =================================================================== routes ===

const OverviewPage = lazy(() => import("./OverviewPage"));
const ServersPage = lazy(() => import("./ServersPage"));
const CredentialsPage = lazy(() => import("./CredentialsPage"));
const CloudflarePage = lazy(() => import("./CloudflarePage"));
const ListsPage = lazy(() => import("./ListsPage"));
const TopologyPage = lazy(() => import("./TopologyPage"));
const ExitsPage = lazy(() => import("./ExitsPage"));
const RulesPage = lazy(() => import("./RulesPage"));
const RemotePage = lazy(() => import("./RemotePage"));
const DeployPage = lazy(() => import("./DeployPage"));
const UnlockPage = lazy(() => import("./UnlockPage"));
const LeakPage = lazy(() => import("./LeakPage"));

interface RouteDef {
  key: string;
  label: string;
  icon: ReactNode;
  component: ComponentType;
}

interface RouteGroup {
  label: string | null;
  routes: RouteDef[];
}

/** The information architecture. Keys are the first hash segment. */
export const NAV: RouteGroup[] = [
  { label: null, routes: [{ key: "", label: "概览", icon: <DashboardOutlined />, component: OverviewPage }] },
  {
    label: "网络",
    routes: [
      { key: "topology", label: "拓扑", icon: <ApartmentOutlined />, component: TopologyPage },
      { key: "exits", label: "出口", icon: <GlobalOutlined />, component: ExitsPage },
      { key: "rules", label: "分流规则", icon: <BranchesOutlined />, component: RulesPage },
      { key: "lists", label: "名单", icon: <UnorderedListOutlined />, component: ListsPage },
    ],
  },
  {
    label: "资源",
    routes: [
      { key: "servers", label: "服务器", icon: <CloudServerOutlined />, component: ServersPage },
      { key: "keys", label: "密钥", icon: <KeyOutlined />, component: CredentialsPage },
      { key: "cloudflare", label: "Cloudflare", icon: <CloudOutlined />, component: CloudflarePage },
    ],
  },
  { label: "接入", routes: [{ key: "remote", label: "远程接入", icon: <WifiOutlined />, component: RemotePage }] },
  {
    label: "运维",
    routes: [
      { key: "deploy", label: "部署", icon: <DeploymentUnitOutlined />, component: DeployPage },
      { key: "unlock", label: "解锁", icon: <PlayCircleOutlined />, component: UnlockPage },
      { key: "leak", label: "防泄露", icon: <SafetyOutlined />, component: LeakPage },
    ],
  },
];

const ROUTES = new Map(NAV.flatMap((g) => g.routes).map((r) => [r.key, r]));

function menuItems(): MenuProps["items"] {
  return NAV.map((g, i) => {
    const children = g.routes.map((r) => ({ key: r.key || "overview", icon: r.icon, label: <a href={href(r.key)} onClick={(e) => e.preventDefault()}>{r.label}</a> }));
    if (!g.label) return children[0];
    return { type: "group" as const, key: `g${i}`, label: g.label, children };
  });
}

// ============================================================== token gate ===

function TokenScreen({ onUnlocked, error }: { onUnlocked: () => void; error: api.ApiError | null }) {
  const [form] = Form.useForm<{ token: string }>();
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<api.ApiError | null>(error);
  return (
    <div className="token-screen">
      <div className="token-card">
        <Space align="center" style={{ marginBottom: 8 }}>
          <span className="brand-mark">M</span>
          <Typography.Title level={4} style={{ margin: 0 }}>
            Meridian 控制面板
          </Typography.Title>
        </Space>
        <Typography.Paragraph type="secondary">
          输入面板口令。口令只保存在这个标签页里，关闭标签页即清除。
        </Typography.Paragraph>
        {err ? <ApiErrorAlert error={err} /> : null}
        <Form
          form={form}
          layout="vertical"
          onFinish={async ({ token }) => {
            setBusy(true);
            api.setToken(token || "");
            try {
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
          <Form.Item name="token" label="面板口令" rules={[{ required: true, message: "请输入面板口令" }]}>
            <Input.Password autoComplete="off" autoFocus aria-label="面板口令" />
          </Form.Item>
          <div className="token-hint">
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              口令在网关的数据目录里：
            </Typography.Text>
            <CommandBlock label="读取面板口令的命令，可左右滚动">docker compose exec meridian cat /var/lib/meridian/panel.token</CommandBlock>
          </div>
          <Button type="primary" htmlType="submit" loading={busy} block>
            进入
          </Button>
        </Form>
      </div>
    </div>
  );
}

function AuthGate({ children }: { children: ReactNode }) {
  const [state, setState] = useState<"checking" | "locked" | "open">("checking");
  const [err, setErr] = useState<api.ApiError | null>(null);
  const [generation, setGeneration] = useState(0);

  const check = useCallback(async () => {
    try {
      await api.getMeta();
      setState("open");
      setErr(null);
    } catch (e) {
      const ae = e instanceof api.ApiError ? e : new api.ApiError(0, {});
      if (ae.status === 401) {
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

/** A page that throws while rendering shows this instead of a blank panel. */
class PageBoundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state = { error: null as Error | null };
  static getDerivedStateFromError(error: Error) {
    return { error };
  }
  render() {
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

// ==================================================================== shell ===

function Shell({ themePref, setThemePref }: { themePref: ThemePref; setThemePref: (p: ThemePref) => void }) {
  const { route, navigate } = useRouter();
  const lock = useContext(LockContext);
  const screens = Grid.useBreakpoint();
  const wide = screens.lg !== false && (screens.lg ?? true);
  const [collapsed, setCollapsed] = useState(false);
  const [drawer, setDrawer] = useState(false);
  const current = ROUTES.get(route.page);
  const Component = current?.component;
  const items = useMemo(menuItems, []);
  const selected = [route.page || "overview"];

  useEffect(() => {
    document.title = current ? `${current.label} · Meridian` : "Meridian";
    setDrawer(false);
  }, [current, route.page]);

  const menu = (
    <Menu
      mode="inline"
      selectedKeys={selected}
      items={items}
      inlineCollapsed={wide ? collapsed : false}
      onClick={({ key }) => navigate(href(key === "overview" ? "" : key))}
      className="nav-menu"
    />
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
            <ThemeMenu pref={themePref} setPref={setThemePref} />
            <Tooltip title="锁定：清除这个标签页里的面板口令">
              <Button type="text" aria-label="锁定" icon={<LockOutlined />} onClick={lock} />
            </Tooltip>
          </div>
        </Layout.Header>
        <Layout.Content className="content">
          <Suspense fallback={<Skeleton active paragraph={{ rows: 8 }} />}>
            {Component ? (
              <PageBoundary key={route.page}>
                <Component />
              </PageBoundary>
            ) : (
              <Result
                status="404"
                title="没有这个页面"
                subTitle={<span>地址 <code>{window.location.hash}</code> 不对应任何页面。</span>}
                extra={<Link to={href("")}>回到概览</Link>}
              />
            )}
          </Suspense>
        </Layout.Content>
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
