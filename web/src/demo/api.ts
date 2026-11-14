// The demo's in-browser API: answers every endpoint of web/src/api.ts from
// the scenario's generated responses (fixtures.ts) and never touches the
// network. Reads return what the Go handlers answered on the synthetic
// gateway; every change (POST/PUT/PATCH/DELETE that is not a read) is
// refused with a clear "not executed in the demo" error, which the panel's
// shared error display shows. The production panel never imports this.

import type { DemoResponse } from "./fixtures";

export const DEMO_REFUSAL_CODE = "demo_read_only";
export const DEMO_REFUSAL_TEXT =
  "演示模式下不执行：这是用合成数据驱动的界面预览，没有连接任何网关、服务器或外部服务，改动不会保存，也不会发出任何请求。";

/**
 * How the demo answers one endpoint:
 *  read     the generated response for exactly this path (detail reads: per id);
 *  post     a read-only POST, answered with the generated response of the stored state;
 *  refuse   a change: 403 demo_read_only, nothing happens;
 *  special  answered by a function below.
 */
export type DemoKind = "read" | "post" | "refuse" | "special";

export interface DemoRoute {
  method: string;
  /** Path with `:param` segments. */
  path: string;
  kind: DemoKind;
}

const R = (method: string, path: string, kind: DemoKind): DemoRoute => ({ method, path, kind });

/** Every endpoint of web/src/api.ts (demo.test.tsx checks the list against the source). */
export const DEMO_ROUTES: DemoRoute[] = [
  // core
  R("GET", "/api/health", "read"),
  R("GET", "/api/meta", "read"),
  R("GET", "/api/topology", "read"),
  R("PUT", "/api/topology", "special"),
  R("POST", "/api/validate", "post"),
  R("POST", "/api/topology/allocations", "post"),
  R("POST", "/api/compile", "refuse"),
  R("POST", "/api/diff", "post"),
  R("POST", "/api/apply", "refuse"),
  R("POST", "/api/host/preflight", "post"),
  R("GET", "/api/artifacts", "read"),
  R("POST", "/api/rollback", "refuse"),
  R("GET", "/api/status", "read"),
  R("GET", "/api/host", "read"),
  R("POST", "/api/host/recover", "refuse"),
  R("POST", "/api/provision", "refuse"),
  // deployment guide
  R("GET", "/api/deploy", "read"),
  R("POST", "/api/deploy/runs", "refuse"),
  R("POST", "/api/deploy/runs/:id/preflight", "refuse"),
  R("POST", "/api/deploy/runs/:id/install", "refuse"),
  R("POST", "/api/deploy/runs/:id/replan", "refuse"),
  R("POST", "/api/deploy/runs/:id/cancel", "refuse"),
  R("POST", "/api/provision/preflight", "refuse"),
  // servers
  R("GET", "/api/servers", "read"),
  R("GET", "/api/servers/:id", "read"),
  R("POST", "/api/servers", "refuse"),
  R("PATCH", "/api/servers/:id", "refuse"),
  R("DELETE", "/api/servers/:id", "refuse"),
  R("POST", "/api/servers/:id/host-key/discover", "refuse"),
  R("POST", "/api/servers/:id/host-key/trust", "refuse"),
  R("DELETE", "/api/servers/:id/host-key", "refuse"),
  R("POST", "/api/servers/:id/test", "refuse"),
  // SSH credentials
  R("GET", "/api/ssh-credentials", "read"),
  R("GET", "/api/ssh-credentials/:id", "read"),
  R("POST", "/api/ssh-credentials", "refuse"),
  R("PATCH", "/api/ssh-credentials/:id", "refuse"),
  R("PUT", "/api/ssh-credentials/:id/secret", "refuse"),
  R("DELETE", "/api/ssh-credentials/:id", "refuse"),
  // SOCKS credentials
  R("GET", "/api/socks-credentials", "read"),
  R("POST", "/api/socks-credentials", "refuse"),
  R("PATCH", "/api/socks-credentials/:id", "refuse"),
  R("PUT", "/api/socks-credentials/:id/secret", "refuse"),
  R("DELETE", "/api/socks-credentials/:id", "refuse"),
  // Cloudflare
  R("GET", "/api/cloudflare/accounts", "read"),
  R("GET", "/api/cloudflare/accounts/:id", "read"),
  R("POST", "/api/cloudflare/accounts", "refuse"),
  R("PATCH", "/api/cloudflare/accounts/:id", "refuse"),
  R("PUT", "/api/cloudflare/accounts/:id/token", "refuse"),
  R("DELETE", "/api/cloudflare/accounts/:id", "refuse"),
  R("POST", "/api/cloudflare/accounts/:id/check", "refuse"),
  R("PUT", "/api/cloudflare/mesh-account", "refuse"),
  R("GET", "/api/cloudflare/requirements", "read"),
  // Mesh
  R("GET", "/api/mesh", "read"),
  R("POST", "/api/mesh/deploy", "refuse"),
  R("POST", "/api/mesh/withdraw", "refuse"),
  R("PUT", "/api/mesh/credentials", "refuse"),
  R("DELETE", "/api/mesh/credentials", "refuse"),
  // lists
  R("GET", "/api/lists", "read"),
  R("PUT", "/api/lists/policy", "refuse"),
  R("POST", "/api/lists/update", "refuse"),
  R("GET", "/api/lists/job", "read"),
  R("GET", "/api/lists/status", "read"),
  // region groups
  R("GET", "/api/region-groups", "read"),
  R("GET", "/api/region-groups/:id", "read"),
  R("POST", "/api/region-groups", "refuse"),
  R("PATCH", "/api/region-groups/:id", "refuse"),
  R("DELETE", "/api/region-groups/:id", "refuse"),
  R("PUT", "/api/region-groups/default", "refuse"),
  R("GET", "/api/upstream", "read"),
  R("POST", "/api/region-groups/runtime/refresh", "special"),
  R("POST", "/api/region-groups/health", "refuse"),
  // remote access
  R("GET", "/api/remote-access", "read"),
  R("PUT", "/api/remote-access", "refuse"),
  R("GET", "/api/remote-access/devices", "read"),
  R("GET", "/api/remote-access/devices/:id", "read"),
  R("POST", "/api/remote-access/devices", "refuse"),
  R("PATCH", "/api/remote-access/devices/:id", "refuse"),
  R("DELETE", "/api/remote-access/devices/:id", "refuse"),
  R("POST", "/api/remote-access/devices/:id/regenerate", "refuse"),
  // unlock
  R("GET", "/api/unlock", "read"),
  R("POST", "/api/unlock/report", "refuse"),
  R("GET", "/api/unlock/catalog", "read"),
  R("POST", "/api/unlock/run", "refuse"),
  R("GET", "/api/unlock/jobs", "read"),
  R("GET", "/api/unlock/jobs/:id", "read"),
  R("POST", "/api/unlock/jobs/:id/cancel", "refuse"),
  R("GET", "/api/unlock/results", "special"),
  R("POST", "/api/unlock/results/prune", "refuse"),
  // withdraw
  R("GET", "/api/deployments", "read"),
  R("POST", "/api/provision/withdraw/plan", "refuse"),
  R("POST", "/api/provision/withdraw", "refuse"),
  R("POST", "/api/provision/withdraw/abandon", "refuse"),
  R("DELETE", "/api/provision/state/:id", "refuse"),
  R("POST", "/api/host/withdraw", "refuse"),
  // WSS
  R("GET", "/api/wss", "read"),
  R("POST", "/api/wss/links/:id/regenerate-path", "refuse"),
  R("POST", "/api/wss/listeners/:id/regenerate-cert", "refuse"),
  R("POST", "/api/wss/listeners/:id/cancel", "refuse"),
  // leak check
  R("GET", "/api/leakcheck", "read"),
  // ordered rules
  R("GET", "/api/rule-sets", "read"),
  R("POST", "/api/rule-sets", "refuse"),
  R("PUT", "/api/rule-sets/:id/auth", "refuse"),
  R("DELETE", "/api/rule-sets/:id/auth", "refuse"),
  R("PATCH", "/api/rule-sets/:id", "refuse"),
  R("DELETE", "/api/rule-sets/:id", "refuse"),
  R("POST", "/api/rule-sets/:id/update", "refuse"),
  R("POST", "/api/rule-sets/:id/activate-held", "refuse"),
  R("GET", "/api/service-groups", "read"),
  R("PATCH", "/api/service-groups/:id", "refuse"),
  R("POST", "/api/service-groups", "refuse"),
  R("DELETE", "/api/service-groups/:id", "refuse"),
  R("POST", "/api/rules/import/preview", "refuse"),
  R("POST", "/api/rules/import/confirm", "refuse"),
  R("POST", "/api/rules/test", "special"),
  R("GET", "/api/sniff", "read"),
  R("PUT", "/api/sniff", "refuse"),
  R("GET", "/api/rules/analysis", "read"),
];

interface Compiled extends DemoRoute {
  re: RegExp;
}

const COMPILED: Compiled[] = DEMO_ROUTES.map((r) => ({
  ...r,
  re: new RegExp("^" + r.path.replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/:[a-z_]+/g, "[^/]+") + "$"),
}));

// Static paths win over parameter ones ("/api/region-groups/default" before "/:id").
COMPILED.sort((a, b) => Number(a.path.includes(":")) - Number(b.path.includes(":")));

/** The route answering method + path, or undefined (an endpoint the demo does not know). */
export function demoRouteOf(method: string, path: string): DemoRoute | undefined {
  return COMPILED.find((r) => r.method === method && r.re.test(path));
}

export interface DemoReply extends DemoResponse {
  /** Set when the demo has no answer: a gap the contract test reports. */
  unhandled?: boolean;
}

function refusal(): DemoReply {
  return { status: 403, body: { error: DEMO_REFUSAL_TEXT, code: DEMO_REFUSAL_CODE, not_executed: true } };
}

function missing(method: string, path: string): DemoReply {
  return { status: 404, body: { error: `演示数据里没有 ${method} ${path} 的回答`, code: "not_found" }, unhandled: true };
}

function notFound(path: string): DemoReply {
  return { status: 404, body: { error: `演示数据里没有这个对象（${path}）`, code: "not_found" } };
}

/**
 * The demo API of one scenario: (method, path with query, parsed body) → reply.
 * Pure: no network, no timers, nothing persisted.
 */
export function makeDemoApi(responses: Record<string, DemoResponse>) {
  return function answer(method: string, url: string, body?: unknown): DemoReply {
    const u = new URL(url, "http://demo.invalid");
    const path = u.pathname;
    const route = demoRouteOf(method, path);
    if (!route) return missing(method, path);
    const key = `${method} ${path}`;
    switch (route.kind) {
      case "refuse":
        return refusal();
      case "read":
      case "post": {
        const r = responses[key];
        if (r) return r;
        return route.path.includes(":") ? notFound(path) : missing(method, path);
      }
    }
    // special
    if (key === "PUT /api/topology") return responses[key] ?? refusal();
    if (key === "POST /api/region-groups/runtime/refresh") {
      // The read of the hub is not repeated: the stored state is shown.
      return responses["GET /api/region-groups"] ?? missing(method, path);
    }
    if (key === "POST /api/rules/test") {
      const name = body && typeof body === "object" ? String((body as { name?: unknown }).name ?? "") : "";
      const r = responses[`POST /api/rules/test?name=${name}`];
      if (r) return r;
      const known = Object.keys(responses)
        .filter((k) => k.startsWith("POST /api/rules/test?name="))
        .map((k) => k.slice("POST /api/rules/test?name=".length));
      return {
        status: 403,
        body: {
          error: `演示模式下规则测试只有这些合成名字的真实结果：${known.join("、")}。其它名字不在演示数据里，没有测试。`,
          code: DEMO_REFUSAL_CODE,
          not_executed: true,
        },
      };
    }
    if (key === "GET /api/unlock/results") {
      const r = responses[key];
      if (!r) return missing(method, path);
      const b = r.body as { results?: Record<string, unknown>[] };
      const f = (name: string, field: string, rows: Record<string, unknown>[]) => {
        const v = u.searchParams.get(name);
        return v ? rows.filter((x) => x[field] === v) : rows;
      };
      let rows = b.results ?? [];
      rows = f("service", "service", rows);
      rows = f("exit", "exit_id", rows);
      rows = f("family", "family", rows);
      const g = u.searchParams.get("group");
      if (g) rows = rows.filter((x) => Array.isArray(x.exit_groups) && (x.exit_groups as { id: string }[]).some((e) => e.id === g));
      return { status: r.status, body: { ...b, results: rows } };
    }
    return missing(method, path);
  };
}

export type DemoAnswer = ReturnType<typeof makeDemoApi>;

/**
 * Replaces window.fetch: /api/* is answered by the demo API, anything else
 * is refused (the demo never goes to the network). Returns the requests
 * that had no answer, for the scenario bar and the tests.
 */
export function installDemoFetch(answer: DemoAnswer, target: { fetch: typeof fetch } = window) {
  const gaps: string[] = [];
  const pending = { n: 0 };
  target.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    const method = (init?.method ?? (typeof input === "object" && "method" in input ? input.method : "GET")).toUpperCase();
    const u = new URL(url, "http://demo.invalid");
    pending.n++;
    try {
      await Promise.resolve();
      if (init?.signal?.aborted) throw new DOMException("aborted", "AbortError");
      let body: unknown;
      if (typeof init?.body === "string") {
        try {
          body = JSON.parse(init.body);
        } catch {
          body = undefined;
        }
      }
      const reply = u.pathname.startsWith("/api/") ? answer(method, u.pathname + u.search, body) : missing(method, u.pathname);
      if (reply.unhandled) gaps.push(`${method} ${u.pathname}`);
      return new Response(JSON.stringify(reply.body ?? {}), { status: reply.status, headers: { "Content-Type": "application/json" } });
    } finally {
      pending.n--;
    }
  }) as typeof fetch;
  return { gaps, pending };
}
