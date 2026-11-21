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
  R("GET", "/api/setup/status", "special"),
  R("POST", "/api/setup", "refuse"),
  R("POST", "/api/auth/login", "refuse"),
  R("PUT", "/api/auth/admin", "refuse"),
  R("GET", "/api/templates", "special"),
  R("POST", "/api/templates/:id/preview", "refuse"),
  R("GET", "/api/setup/wizard", "special"),
  R("PUT", "/api/setup/wizard", "refuse"),
  R("POST", "/api/setup/wizard/complete", "refuse"),
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
  R("GET", "/api/traffic", "special"),
  R("GET", "/api/rules/auto-apply", "special"),
  R("GET", "/api/host", "read"),
  R("POST", "/api/host/recover", "refuse"),
  R("POST", "/api/provision", "refuse"),
  // deployment guide
  R("GET", "/api/deploy", "read"),
  R("POST", "/api/deploy/runs", "refuse"),
  R("POST", "/api/deploy/runs/:id/preflight", "refuse"),
  R("POST", "/api/deploy/runs/:id/install", "refuse"),
  R("POST", "/api/deploy/runs/:id/verify", "refuse"),
  R("POST", "/api/deploy/runs/:id/replan", "refuse"),
  R("POST", "/api/deploy/runs/:id/repair-wg-port", "refuse"),
  R("POST", "/api/deploy/runs/:id/cancel", "refuse"),
  R("POST", "/api/deploy/runs/:id/skip", "refuse"),
  R("POST", "/api/deploy/runs/:id/unskip", "refuse"),
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
  R("GET", "/api/servers/:id/tunnel-candidates", "read"),
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
  R("POST", "/api/mesh/detect", "refuse"),
  R("PUT", "/api/mesh/credentials", "refuse"),
  R("DELETE", "/api/mesh/credentials", "refuse"),
  // lists
  R("GET", "/api/lists", "read"),
  R("PUT", "/api/lists/policy", "refuse"),
  R("PUT", "/api/lists/schedule", "refuse"),
  R("POST", "/api/lists/update", "refuse"),
  R("GET", "/api/lists/job", "read"),
  R("GET", "/api/lists/status", "read"),
  // region groups
  R("GET", "/api/exits/latency", "special"),
  R("POST", "/api/exits/latency", "refuse"),
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
  R("GET", "/api/unlock/matrix", "read"),
  R("POST", "/api/unlock/adopt", "special"),
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
  // acceptance: the stored results are read; nothing is carried out in the demo
  R("GET", "/api/acceptance", "read"),
  R("GET", "/api/acceptance/summary", "read"),
  R("POST", "/api/acceptance/items/:id/prepare", "refuse"),
  R("POST", "/api/acceptance/items/:id/run", "refuse"),
  R("POST", "/api/acceptance/items/:id/cancel", "refuse"),
  R("POST", "/api/acceptance/items/:id/signoff", "refuse"),
  R("POST", "/api/acceptance/drill/retry", "refuse"),
  R("POST", "/api/acceptance/drill/release", "refuse"),
  // ordered rules
  R("GET", "/api/rule-sets", "read"),
  R("POST", "/api/rule-sets", "refuse"),
  R("PUT", "/api/rule-sets/:id/auth", "refuse"),
  R("DELETE", "/api/rule-sets/:id/auth", "refuse"),
  R("PATCH", "/api/rule-sets/:id", "refuse"),
  R("DELETE", "/api/rule-sets/:id", "refuse"),
  R("POST", "/api/rule-sets/update-all", "refuse"),
  R("GET", "/api/rule-sets/update-all", "special"),
  R("POST", "/api/rule-sets/:id/update", "refuse"),
  R("POST", "/api/rule-sets/:id/activate-held", "refuse"),
  R("POST", "/api/rules/retarget", "refuse"),
  R("POST", "/api/rules/import/preview", "refuse"),
  R("POST", "/api/rules/import/confirm", "refuse"),
  R("POST", "/api/rules/test", "special"),
  R("GET", "/api/sniff", "read"),
  R("PUT", "/api/sniff", "refuse"),
  R("POST", "/api/sniff/selfcheck", "refuse"),
  R("GET", "/api/sniff/journal", "special"),
  R("GET", "/api/sniff/devices", "read"),
  R("PUT", "/api/sniff/devices/:addr/label", "refuse"),
  R("DELETE", "/api/sniff/devices/:addr/label", "refuse"),
  R("POST", "/api/sniff/journal/clear", "refuse"),
  R("GET", "/api/sniff/journal/related", "special"),
  // DNS query journal and link journal: every scenario has generated
  // responses for them (the real reader and collector on synthetic input,
  // or the real answer of a gateway without them). The lists are filtered
  // and paged here (「the logs」 below): each journal was generated as one page that
  // holds all of it.
  R("GET", "/api/dns-log", "read"),
  R("PUT", "/api/dns-log", "refuse"),
  R("GET", "/api/dns-log/journal", "special"),
  R("GET", "/api/dns-log/devices", "read"),
  R("POST", "/api/dns-log/clear", "refuse"),
  R("GET", "/api/dns-log/related", "special"),
  R("GET", "/api/link-log", "read"),
  R("GET", "/api/link-log/current", "read"),
  R("GET", "/api/link-log/events", "special"),
  R("POST", "/api/link-log/clear", "refuse"),
  R("GET", "/api/rules/analysis", "read"),
  R("GET", "/api/mtu/uplinks", "read"),
  R("POST", "/api/mtu/adopt", "refuse"),
  // resolution (DNS) view
  R("GET", "/api/dns", "read"),
  R("GET", "/api/dns/config", "special"),
  R("PUT", "/api/dns/upstream", "refuse"),
  R("POST", "/api/dns/check", "refuse"),
  R("GET", "/api/dns-accounts", "read"),
  R("POST", "/api/dns-accounts", "refuse"),
  R("PUT", "/api/dns-accounts/:id/secret", "refuse"),
  R("DELETE", "/api/dns-accounts/:id", "refuse"),
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

// ------------------------------------------------------------ the logs ---
//
// The query journal and the link journal of a scenario are generated as
// one page each (their largest page: the synthetic journals fit into it),
// and one related lookup in each direction. What the pages ask beyond that
// — a filter, the next page, the records of the other journal around
// another record — is answered here from those generated lists, with the
// rules of the real services (internal/dnsjournal, internal/linkjournal,
// internal/api/dns_journal.go). Nothing is invented: every record shown is
// one the real reader or collector wrote. A scenario whose journal has
// nothing to list (off, not installed, unreadable, empty) answers that for
// every question.

type Row = Record<string, unknown>;

interface Listed {
  available?: boolean;
  page?: { records?: Row[]; events?: Row[]; matched?: number; next_before?: unknown; open_merged?: number; record_names?: boolean } & Row;
}

function listOf(r: DemoResponse | undefined): Listed {
  return (r?.body ?? {}) as Listed;
}

/** The journal of this response has rows to filter. */
function hasRows(r: DemoResponse | undefined): boolean {
  const b = listOf(r);
  return !!b.available && ((b.page?.records ?? b.page?.events ?? []) as Row[]).length > 0;
}

const ms = (v: unknown) => (typeof v === "string" ? Date.parse(v) : Number.NaN);
const iso = (t: number) => new Date(t).toISOString().replace(/\.\d{3}Z$/, "Z");
const lower = (v: unknown) => (typeof v === "string" ? v.toLowerCase() : "");

function bounded(v: string | null, dflt: number, max: number): number {
  const n = Number(v);
  return v && Number.isInteger(n) && n >= 1 ? Math.min(n, max) : dflt;
}

/** GET /api/dns-log/journal: device, mac, result, group, from, to, text, before, limit (dnsjournal.Query). */
function dnsJournalPage(r: DemoResponse, q: URLSearchParams): DemoReply {
  const body = listOf(r);
  if (!hasRows(r) || !body.page) return r;
  const text = (q.get("text") ?? "").trim().toLowerCase();
  const from = ms(q.get("from"));
  const to = ms(q.get("to"));
  const result = q.get("result");
  let rows = (body.page.records ?? []).filter(
    (x) =>
      (!q.get("device") || x.client === q.get("device")) &&
      (!q.get("mac") || lower(x.mac) === lower(q.get("mac"))) &&
      (!result || (result === "no_answer_any" ? x.result === "no_answer" || x.result === "no_answer_slow" : x.result === result)) &&
      (!q.get("group") || x.group === q.get("group")) &&
      (Number.isNaN(from) || ms(x.time) >= from) &&
      (Number.isNaN(to) || ms(x.time) < to) &&
      (!text || lower(x.name).includes(text)),
  );
  const matched = rows.length;
  const before = Number(q.get("before") ?? 0);
  if (before > 0) rows = rows.filter((x) => Number(x.id) < before);
  const limit = bounded(q.get("limit"), 50, 200);
  const records = rows.slice(0, limit);
  const next = rows.length > limit ? records[records.length - 1].id : undefined;
  const { next_before: _dropped, ...page } = body.page;
  return { status: r.status, body: { ...body, page: { ...page, records, matched, ...(next === undefined ? {} : { next_before: next }) } } };
}

/** GET /api/link-log/events: class, kind, id, from, to, before, limit (linkjournal.Query). Merged records still being counted come first, on the first page only. */
function linkEventsPage(r: DemoResponse, q: URLSearchParams): DemoReply {
  const body = listOf(r);
  if (!hasRows(r) || !body.page) return r;
  const from = ms(q.get("from"));
  const to = ms(q.get("to"));
  const match = (e: Row) =>
    (!q.get("class") || e.class === q.get("class")) &&
    (!q.get("kind") || e.kind === q.get("kind")) &&
    (!q.get("id") || e.id === q.get("id")) &&
    // A merged record speaks about [at, last_at]: it matches a range it overlaps.
    (Number.isNaN(from) || ms(e.last_at ?? e.at) >= from) &&
    (Number.isNaN(to) || ms(e.at) <= to);
  const all = (body.page.events ?? []).filter(match);
  const cursor = /^(\d+)-(\d+)$/.exec(q.get("before") ?? "");
  const open = cursor ? [] : all.filter((e) => e.open);
  let stored = all.filter((e) => !e.open);
  if (cursor) {
    const at = Number(cursor[1]);
    const seq = Number(cursor[2]);
    stored = stored.filter((e) => {
      const t = Math.floor(ms(e.at) / 1000);
      return t < at || (t === at && Number(e.seq) < seq);
    });
  }
  const limit = bounded(q.get("limit"), 100, 500);
  const shown = stored.slice(0, limit);
  const last = shown[shown.length - 1];
  const { next_before: _dropped, open_merged: _open, ...page } = body.page;
  return {
    status: r.status,
    body: {
      ...body,
      page: {
        ...page,
        events: [...open, ...shown],
        ...(stored.length > limit && last ? { next_before: `${Math.floor(ms(last.at) / 1000)}-${String(last.seq)}` } : {}),
        ...(open.length > 0 ? { open_merged: open.length } : {}),
      },
    },
  };
}

/**
 * A related lookup (internal/api/dns_journal.go): the other journal's
 * records of an address inside a bounded window around a time. With the
 * asking record's MAC, records that carry another MAC are left out and
 * counted, records without one are kept and counted, and `identity` says
 * what the match rests on. `sample` is the generated lookup of this
 * direction: its shape, and its answer when the other journal cannot be
 * read.
 */
function related(sample: DemoResponse, q: URLSearchParams, rows: Row[], inWindow: (r: Row, from: number, to: number) => boolean, macOf: (r: Row) => string, extra: Row): DemoReply {
  const device = q.get("device") ?? "";
  const at = ms(q.get("at"));
  const base = sample.body as Row;
  if (!device || Number.isNaN(at)) return sample;
  const asked = lower(q.get("mac"));
  const win = bounded(q.get("window"), 120, 600);
  const from = at - win * 1000;
  const to = at + win * 1000;
  const head = { ...base, device, mac: asked || undefined, from: iso(from), to: iso(to), window_s: win, records: [] as Row[], listed: 0, other_mac: 0, no_mac: 0, more: false, identity: "address" };
  if (!base.available) return { status: sample.status, body: head };
  let other = 0;
  let none = 0;
  const kept: Row[] = [];
  for (const r of rows) {
    if (!inWindow(r, from, to)) continue;
    const got = macOf(r);
    if (!got) none++;
    else if (asked && got !== asked) {
      other++;
      continue;
    }
    kept.push(r);
  }
  const records = kept.slice(0, 100);
  const identity = !asked || records.length === none ? "address" : none === 0 ? "mac" : "partial";
  return { status: sample.status, body: { ...head, ...extra, records, listed: records.length, other_mac: other, no_mac: none, more: kept.length > records.length, identity } };
}

/** Every connection record the scenario has (the newest page and each device's page), newest end first. */
function connectionRows(responses: Record<string, DemoResponse>): Row[] {
  const seen = new Map<unknown, Row>();
  if (!hasRows(responses["GET /api/sniff/journal"])) return [];
  for (const [k, r] of Object.entries(responses)) {
    if (k !== "GET /api/sniff/journal" && !k.startsWith("GET /api/sniff/journal?device=")) continue;
    for (const x of listOf(r).page?.records ?? []) seen.set(x.id, x);
  }
  const end = (x: Row) => ms(x.start) + Number(x.duration_ms ?? 0);
  return [...seen.values()].sort((a, b) => end(b) - end(a));
}

/**
 * Synthetic throughput counters: the integral of smooth made-up rates, so
 * consecutive reads give plausible Mbit/s. A scenario whose host agent is
 * down answers like the real handler does without one.
 */
export function demoTraffic(responses: Record<string, DemoResponse>, now: number): DemoReply {
  const st = responses["GET /api/status"]?.body as { agent?: { ok?: boolean } } | undefined;
  if (!st?.agent?.ok) {
    return { status: 200, body: { available: false, reset: false, counters: {}, code: "agent_unavailable", message: "演示：没有宿主执行通道" } };
  }
  const s = now / 1000;
  // bytes(t) = a·t − b·p·cos(t/p): rate a + b·sin(t/p) ≥ 0 since a > b.
  const c = (mbit: number, swing: number, p: number) => {
    const a = (mbit * 1e6) / 8, b = (swing * 1e6) / 8;
    return { bytes: Math.round(a * s - b * p * Math.cos(s / p) + b * p), packets: Math.round((a * s) / 1200) };
  };
  return {
    status: 200,
    body: {
      available: true,
      read_at: new Date(now).toISOString(),
      reset: false,
      counters: { down_domestic: c(42, 18, 23), up_domestic: c(4, 2, 17), down_foreign: c(85, 40, 31), up_foreign: c(6, 3, 13) },
      connections: (() => {
        const w = (base: number, swing: number, p: number) => Math.round(base + swing * Math.sin(s / p));
        const domestic = w(120, 30, 41), foreign = w(260, 60, 53), redirected = w(18, 6, 29);
        return { available: true, read_at: new Date(now).toISOString(), scope: "lan_and_remote_access", split: true, domestic, foreign, redirected, total: domestic + foreign + redirected };
      })(),
    },
  };
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
    if (key === "GET /api/traffic") return demoTraffic(responses, Date.now());
    if (key === "GET /api/setup/status") return { status: 200, body: { state: "ready", admin: false, token_login: true } };
    // The demo is an existing deployment: no first-run wizard.
    if (key === "GET /api/setup/wizard")
      return { status: 200, body: { active: false, state: { step: "gateway", done: [], gateway: { lan_interface: "", lan_ipv4: "", router_ipv4: "" }, template: "" }, detected: {} } };
    if (key === "GET /api/templates") return { status: 200, body: { templates: [] } };
    if (key === "GET /api/rule-sets/update-all") return { status: 200, body: { job: null } };
    if (key === "GET /api/rules/auto-apply") return { status: 200, body: { enabled: true, pending: false, last: null } };
    if (key === "PUT /api/topology") return responses[key] ?? refusal();
    if (key === "POST /api/unlock/adopt") {
      // 确认 / 手动 (出口组 or 具体节点): the generated preview and save of exactly
      // the demo's three examples (what the synthetic gateway answered);
      // anything else is refused.
      const b = (body && typeof body === "object" ? body : {}) as { exit?: string; group?: string; manual?: boolean; preview?: boolean };
      const kind = !b.manual ? "confirm" : b.group ? "group" : "manual";
      const r = responses[`${key}?${b.preview ? "preview" : "save"}=${kind}`];
      const rb = (r?.body ?? {}) as { exit?: string; group?: string };
      return r && (kind === "group" ? rb.group === b.group : rb.exit === b.exit) ? r : refusal();
    }
    if (key === "GET /api/exits/latency") return { status: 200, body: { available: false, running: false, rows: [] } };
    if (key === "POST /api/region-groups/runtime/refresh") {
      // The read of the hub is not repeated: the stored state is shown.
      return responses["GET /api/region-groups"] ?? missing(method, path);
    }
    if (key === "GET /api/sniff/journal") {
      // One generated page per device of the synthetic journal; any other filter shows that device's (or the newest) page.
      // A scenario whose own journal lists nothing answers that for every device (the pages of its base are not its data).
      const own = responses[key];
      if (!own) return missing(method, path);
      const device = u.searchParams.get("device");
      return (device && hasRows(own) ? responses[`GET /api/sniff/journal?device=${device}`] : undefined) ?? own;
    }
    if (key === "GET /api/dns-log/journal") {
      const r = responses[key];
      return r ? dnsJournalPage(r, u.searchParams) : missing(method, path);
    }
    if (key === "GET /api/link-log/events") {
      const r = responses[key];
      return r ? linkEventsPage(r, u.searchParams) : missing(method, path);
    }
    if (key === "GET /api/dns-log/related") {
      // The connections of a device around a query: open inside the window (ended at or after its start, began before its end).
      const sample = responses[key];
      if (!sample) return missing(method, path);
      const dev = u.searchParams.get("device");
      const rows = connectionRows(responses).filter((x) => x.source === dev);
      const names = listOf(responses["GET /api/sniff/journal"]).page?.record_names;
      return related(sample, u.searchParams, rows, (x, from, to) => ms(x.start) + Number(x.duration_ms ?? 0) >= from && ms(x.start) < to, (x) => lower(x.mac), names === undefined ? {} : { record_names: names });
    }
    if (key === "GET /api/sniff/journal/related") {
      // The queries of a device around a connection.
      const sample = responses[key];
      if (!sample) return missing(method, path);
      const dev = u.searchParams.get("device");
      const journal = responses["GET /api/dns-log/journal"];
      const rows = hasRows(journal) ? (listOf(journal).page?.records ?? []).filter((x) => x.client === dev) : [];
      return related(sample, u.searchParams, rows, (x, from, to) => ms(x.time) >= from && ms(x.time) < to, (x) => lower(x.mac), {});
    }
    if (key === "GET /api/dns/config") {
      // One generated config per node of the synthetic topology.
      const node = u.searchParams.get("node");
      return (node ? responses[`GET /api/dns/config?node=${node}`] : undefined) ?? notFound(path);
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
