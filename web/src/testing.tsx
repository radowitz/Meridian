// Test helpers: an in-memory fake of the panel API (a fetch mock with
// per-test handlers) and a way to render the whole app at a route.
// Only imported by *.test.tsx files; never part of the app bundle.

import { render } from "@testing-library/react";
import { vi } from "vitest";
import App from "./App";
import { TABLE_BUDGET } from "./ui";
import type { PanelStatus } from "./types";

export interface FakeRequest {
  method: string;
  path: string;
  query: URLSearchParams;
  params: Record<string, string>;
  /** Parsed JSON body (undefined without one). */
  body: unknown;
  /** The raw body text, to check what left the browser. */
  raw: string | undefined;
}

export type FakeResponse = { status?: number; body?: unknown } | unknown;
export type Handler = (req: FakeRequest) => FakeResponse | Promise<FakeResponse>;

/** A response with a status: `reply(409, {error, code, in_use_by})`. */
export function reply(status: number, body: unknown) {
  return { __status: status, body };
}

interface Route {
  method: string;
  pattern: RegExp;
  keys: string[];
  handler: Handler;
}

function compile(spec: string, handler: Handler): Route {
  const [method, path] = spec.split(" ");
  const keys: string[] = [];
  const pattern = new RegExp(
    "^" +
      path.replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/:([a-z_]+)/g, (_, k) => {
        keys.push(k);
        return "([^/]+)";
      }) +
      "$",
  );
  return { method, pattern, keys, handler };
}

/** GET /api/status with overrides: no agent, nothing installed, no jobs. */
export function panelStatus(over: Partial<PanelStatus> & { installOver?: Partial<PanelStatus["install"]> } = {}): PanelStatus {
  const { installOver, ...rest } = over;
  const idle = { state: "none", running: false };
  return {
    agent: { configured: false, ok: false, error: "测试：没有宿主执行通道" },
    lists_available: false,
    probe_available: false,
    install: { state: "not_installed", installed_version: null, applied: false, applied_matches: false, ...installOver },
    pending: null,
    jobs: { lists: idle, unlock: idle, mesh: idle },
    previous_available: true,
    ...rest,
  };
}

/** Defaults that keep the shell quiet: no agent, nothing installed, no jobs. */
export const DEFAULTS: Record<string, Handler> = {
  "GET /api/status": () => panelStatus(),
  "GET /api/meta": () => ({ phase: 3, features: [] }),
  "GET /api/host": () => ({ installed: null, pending: null, agent: { ok: false, error: "测试：没有宿主执行通道" } }),
  "POST /api/diff": () => ({ diff: "（没有变化）\n", order: [], issues: [] }),
  "GET /api/lists/job": () => ({ job: null }),
  "GET /api/artifacts": () => ({ artifacts: [] }),
  "GET /api/wss": () => ({ listeners: [], validity_days: 365, rotate_before: 30, verification: "", interruption: "", order: "" }),
  "GET /api/unlock/jobs": () => ({ jobs: [], running: "", catalog: [], available: false }),
  "GET /api/mesh": () => ({
    dataplane: "unverified",
    dataplane_note: "Mesh 数据面：未验证。",
    fault_injection: false,
    stages: ["plan", "preflight", "cf_node", "sidecar", "health", "routes", "activate"],
    mesh_account: null,
    plan_servers: [],
    plan: { addressing: null, nodes: [], routes: [], return_v4: [], return_v6: [], issues: [] },
    journal: null,
  }),
  "GET /api/topology": () => ({
    settings: { draft: false },
    nodes: [],
    links: [],
    rules: [],
  }),
  "GET /api/upstream": () => ({ mode: "single", known: false, source: "topology" }),
  "GET /api/deploy": () => ({
    limits: { proves: ["安装事务已提交"], does_not_prove: ["端到端连通"], independent: ["远程接入是独立资源"] },
    run: null,
    plan: { topology_version: "v0", steps: [], skipped: [] },
    topology_version: "v0",
  }),
  "GET /api/sniff": () => ({
    setting: { enabled: false, ports: [80, 443], ech_public_names: ["cloudflare-ech.com"], record_names: false },
    listen_port: 5358,
    coverage: { by_name: ["能读到名字的 TCP"], address_only: ["所有 UDP"], costs: ["ECH 公共名"] },
    runtime: { available: false, code: "agent_unavailable", message: "没有配置 host agent", present: false },
  }),
  "GET /api/ssh-credentials": () => ({ credentials: [] }),
  "GET /api/socks-credentials": () => ({ credentials: [] }),
  "GET /api/servers": () => ({ servers: [] }),
  "GET /api/cloudflare/accounts": () => ({ accounts: [], mesh_account: null }),
  "GET /api/cloudflare/requirements": () => ({
    permissions: [{ name: "Cloudflare One Connectors Write", scope: "account", why: "节点" }],
    how_to: ["在 Cloudflare 控制台创建账户令牌"],
    check: { does: ["只读调用"], does_not: ["不能证明写权限"] },
  }),
  "GET /api/lists/status": () => reply(503, { error: "宿主执行通道不可用", code: "host_unavailable" }),
  "GET /api/deployments": () => ({
    nodes: [],
    gateway: {
      installed: false,
      withdrawn: false,
      plan: { files: [], interfaces: [], units: [], nft_tables: [], route_tables: [] },
      kept: [],
      pending: null,
      last: null,
    },
  }),
};

export interface FakeApi {
  calls: FakeRequest[];
  /** Replace or add a handler during a test. */
  on: (spec: string, handler: Handler) => void;
  /** Calls matching "METHOD /path" (exact path, no query). */
  find: (spec: string) => FakeRequest[];
}

/** Installs the fetch mock. Handlers override DEFAULTS. */
export function fakeApi(handlers: Record<string, Handler> = {}): FakeApi {
  let routes = Object.entries({ ...DEFAULTS, ...handlers }).map(([k, h]) => compile(k, h));
  const calls: FakeRequest[] = [];
  vi.spyOn(globalThis, "fetch").mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url, "http://panel.test");
    const method = (init?.method ?? "GET").toUpperCase();
    const raw = typeof init?.body === "string" ? init.body : undefined;
    let body: unknown;
    try {
      body = raw ? JSON.parse(raw) : undefined;
    } catch {
      body = raw;
    }
    const route = routes.find((r) => r.method === method && r.pattern.test(url.pathname));
    const params: Record<string, string> = {};
    if (route) {
      const m = url.pathname.match(route.pattern)!;
      route.keys.forEach((k, i) => (params[k] = decodeURIComponent(m[i + 1])));
    }
    const req: FakeRequest = { method, path: url.pathname, query: url.searchParams, params, body, raw };
    calls.push(req);
    if (!route) return new Response(JSON.stringify({ error: `测试里没有 ${method} ${url.pathname}`, code: "not_found" }), { status: 404 });
    const out = (await route.handler(req)) as { __status?: number; body?: unknown } | undefined;
    const status = out && typeof out === "object" && "__status" in out ? out.__status! : 200;
    const payload = out && typeof out === "object" && "__status" in out ? out.body : out;
    return new Response(JSON.stringify(payload ?? {}), { status, headers: { "Content-Type": "application/json" } });
  });
  return {
    calls,
    on: (spec, handler) => {
      routes = [compile(spec, handler), ...routes];
    },
    find: (spec) => {
      const [m, p] = spec.split(" ");
      return calls.filter((c) => c.method === m && c.path === p);
    },
  };
}

/** Renders the whole app (shell included) at `hash`, e.g. "#/servers". */
export function renderAt(hash: string) {
  window.history.replaceState(null, "", `/${hash}`);
  return render(<App />);
}

/** Everything the page could have persisted in web storage, as one string. */
export function webStorageDump(): string {
  const out: string[] = [];
  for (const s of [localStorage, sessionStorage]) {
    for (let i = 0; i < s.length; i++) {
      const k = s.key(i)!;
      out.push(`${k}=${s.getItem(k)}`);
    }
  }
  return out.join("\n");
}

// ------------------------------------------------------ table budgets ---

/**
 * The width a DataTable's container really has at a 1280 px viewport
 * (TABLE_BUDGET in ui.tsx, measured in a browser), from where the table sits
 * in the DOM: the page, a drawer or dialog body, minus each Section card,
 * nested card, Collapse body and expanded table row around it.
 */
export function tableBudgetOf(wrap: HTMLElement): { budget: number; container: string } {
  const drawer = wrap.closest<HTMLElement>(".ant-drawer-content-wrapper");
  const modal = wrap.closest<HTMLElement>(".ant-modal");
  const outer = drawer ?? modal;
  let budget: number = TABLE_BUDGET.page;
  let container = "page";
  if (drawer) {
    budget = parseInt(drawer.style.width || "378", 10) - TABLE_BUDGET.drawerPadding;
    container = `drawer ${drawer.style.width}`;
  } else if (modal) {
    budget = parseInt(modal.style.width || "520", 10) - TABLE_BUDGET.modalPadding;
    container = `dialog ${modal.style.width || "520px"}`;
  }
  for (let a = wrap.parentElement; a && a !== outer && a !== document.body; a = a.parentElement) {
    if (a.classList.contains("section")) {
      budget -= TABLE_BUDGET.sectionInset;
      container += " > section";
    } else if (a.classList.contains("wss-listener")) {
      budget -= TABLE_BUDGET.cardInset;
      container += " > card";
    } else if (a.classList.contains("ant-collapse-content-box")) {
      budget -= TABLE_BUDGET.collapseInset;
      container += " > collapse";
    } else if (a.classList.contains("ant-table-expanded-row")) {
      budget -= TABLE_BUDGET.expandedRowInset;
      container += " > expanded row";
    }
  }
  return { budget, container };
}

/** Every rendered DataTable: its declared minimum width (scroll.x) against its container's budget. */
export function tableBudgets(root: ParentNode = document): { name: string; container: string; budget: number; width: number }[] {
  return [...root.querySelectorAll<HTMLElement>(".data-table-wrap")].map((wrap) => {
    const table = wrap.querySelector<HTMLTableElement>(".ant-table-content > table, .ant-table-body > table, table")!;
    const heads = [...wrap.querySelectorAll("thead th")].map((th) => th.textContent?.trim()).filter(Boolean);
    const { budget, container } = tableBudgetOf(wrap);
    return { name: heads.slice(0, 3).join("/"), container, budget, width: parseInt(table.style.width, 10) || 0 };
  });
}
