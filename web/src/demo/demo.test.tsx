// Contract and isolation tests of the demo preview (src/demo/).
//
// Contract: every endpoint of web/src/api.ts is in the demo's route table
// and is answered in every scenario (a generated response, a "not in the
// demo data" 404 for an unknown object id, or the explicit demo refusal of
// a change) — never an unhandled request; every page renders in the main
// scenarios without the page error boundary, and the pages a partial
// scenario changes render in it too (demo_pages_*.test.tsx, split by
// scenario so the workers run them in parallel; testkit.tsx).
//
// Isolation: the production entry's import graph (src/main.tsx and
// everything it imports, statically or lazily) contains no module under
// src/demo/; the production HTML entry does not reference it; the Docker
// image copies only web/dist; and, when a production build exists in
// web/dist, none of its files contains the demo marker.

import { render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { DEMO_REFUSAL_CODE, DEMO_ROUTES, demoRouteOf, installDemoFetch, makeDemoApi } from "./api";
import { DemoChrome } from "./chrome";
import { hasFixture, type DemoResponse } from "./fixtures";
import { DEMO_MARKER, SCENARIOS, demoHref, readDemoParams } from "./scenarios";
import { responsesOf } from "./testkit";

// Files read as text at transform time (no Node types needed): every
// source module of web/src, the HTML entries and build configs, the Docker
// files, the Go sources, and the production build when one exists.
const SOURCES = import.meta.glob<string>(["../**/*.ts", "../**/*.tsx", "!../**/*.test.tsx", "!./generated/**"], { query: "?raw", import: "default", eager: true });
const WEB_FILES = import.meta.glob<string>(["../../index.html", "../../demo.html", "../../vite.config.ts", "../../vite.demo.config.ts"], { query: "?raw", import: "default", eager: true });
const REPO_FILES = import.meta.glob<string>(["../../../deploy/Dockerfile", "../../../.dockerignore"], { query: "?raw", import: "default", eager: true });
const GO_FILES = import.meta.glob<string>(["../../../cmd/**/*.go", "../../../internal/**/*.go", "!../../../**/*_test.go"], { query: "?raw", import: "default", eager: true });
const DIST_FILES = import.meta.glob<string>(["../../dist/**/*.js", "../../dist/**/*.css", "../../dist/**/*.html"], { query: "?raw", import: "default", eager: true });

// ------------------------------------------------------------ helpers ---

/** Every request web/src/api.ts can make: method and path template (":p" for parameters). */
function apiEndpoints(): { method: string; path: string }[] {
  const src = SOURCES["../api.ts"].replace(/\$\{qs \? `\?\$\{qs\}` : ""\}/g, "");
  const out: { method: string; path: string }[] = [];
  const call = /request<[^(]*?>\(\s*"(GET|POST|PUT|PATCH|DELETE)",([^;]*)/g;
  for (const m of src.matchAll(call)) {
    for (const lit of m[2].matchAll(/`(\/api\/[^`]*)`|"(\/api\/[^"]*)"/g)) {
      const raw = (lit[1] ?? lit[2]).split("?")[0];
      out.push({ method: m[1], path: raw.replace(/\$\{[^}]*\}/g, ":p") });
    }
  }
  const seen = new Set<string>();
  return out.filter((e) => {
    const k = `${e.method} ${e.path}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

/** A concrete path for a template: a real id from the scenario where it has one. */
function samplePath(tpl: string, responses: Record<string, DemoResponse>, method: string): string {
  if (!tpl.includes(":p")) return tpl;
  const prefix = tpl.slice(0, tpl.indexOf(":p"));
  const real = Object.keys(responses).find((k) => k.startsWith(`${method} ${prefix}`) && !k.slice(method.length + 1 + prefix.length).includes("/"));
  return real ? real.slice(method.length + 1) : tpl.replace(/:p/g, "demo-unknown-id");
}

let realFetch: typeof fetch;
beforeEach(() => {
  realFetch = globalThis.fetch;
});
afterEach(() => {
  globalThis.fetch = realFetch;
});

// ----------------------------------------------------------- contract ---

describe("demo contract", () => {
  it("routes every endpoint of api.ts and nothing the panel does not call", () => {
    const eps = apiEndpoints();
    // Guards the source parser: api.ts has well over a hundred calls.
    expect(eps.length).toBeGreaterThan(110);
    const missing = eps.filter((e) => !demoRouteOf(e.method, e.path.replace(/:p/g, "x")));
    expect(missing).toEqual([]);
    const used = new Set(eps.map((e) => `${e.method} ${e.path.replace(/:p/g, "x")}`));
    const extra = DEMO_ROUTES.filter((r) => ![...used].some((u) => u.startsWith(r.method + " ") && demoRouteOf(r.method, u.slice(r.method.length + 1))?.path === r.path));
    expect(extra.map((r) => `${r.method} ${r.path}`)).toEqual([]);
  });

  it("has a fixture file for every scenario, and the URL picks scenario and theme", () => {
    for (const s of SCENARIOS) expect(hasFixture(s.id)).toBe(true);
    expect(readDemoParams("?scenario=degraded&theme=dark")).toEqual({ scenario: "degraded", theme: "dark" });
    expect(readDemoParams("?scenario=nonsense")).toEqual({ scenario: "healthy", theme: "system" });
    expect(demoHref({ scenario: "deploy-done", theme: "light" }, "#/deploy")).toBe("?scenario=deploy-done&theme=light#/deploy");
  });

  for (const sc of SCENARIOS) {
    it(`answers every endpoint in scenario ${sc.id}`, async () => {
      const responses = await responsesOf(sc.id);
      const answer = makeDemoApi(responses);
      const problems: string[] = [];
      for (const e of apiEndpoints()) {
        const route = demoRouteOf(e.method, e.path.replace(/:p/g, "x"))!;
        const path = samplePath(e.path, responses, e.method);
        const r = answer(e.method, path, e.method === "POST" && path === "/api/rules/test" ? { name: "api-01.example.com" } : undefined);
        if (r.unhandled) problems.push(`unhandled ${e.method} ${path}`);
        const code = (r.body as { code?: string } | null)?.code;
        if (route.kind === "refuse" && (r.status !== 403 || code !== DEMO_REFUSAL_CODE)) problems.push(`not refused ${e.method} ${path}`);
        if (route.kind === "read" && !route.path.includes(":") && code === DEMO_REFUSAL_CODE) problems.push(`read refused ${e.method} ${path}`);
        if (route.kind === "read" && route.path.includes(":") && r.status === 404 && sc.id !== "unavailable")
          problems.push(`no object for ${e.method} ${path}`);
      }
      expect(problems).toEqual([]);
    });
  }

  it("refuses changes with the demo error and answers reads from the generated responses", async () => {
    const answer = makeDemoApi(await responsesOf("healthy"));
    const del = answer("DELETE", "/api/servers/srv-dc1");
    expect(del.status).toBe(403);
    expect(del.body).toMatchObject({ code: DEMO_REFUSAL_CODE, not_executed: true });
    expect(String((del.body as { error: string }).error)).toContain("演示模式下不执行");
    expect(answer("GET", "/api/servers/srv-dc1").status).toBe(200);
    expect(answer("GET", "/api/servers/no-such").status).toBe(404);
    const test = answer("POST", "/api/rules/test", { name: "api-01.example.com" });
    expect(test.status).toBe(200);
    expect(answer("POST", "/api/rules/test", { name: "other.example.org" }).status).toBe(403);
    // 确认 / 手动 answer only the generated examples, with their apply outcome.
    const responses = await responsesOf("healthy");
    const save = responses["POST /api/unlock/adopt?save=confirm"].body as { exit: string; fast_apply: { status: string } };
    const ok = answer("POST", "/api/unlock/adopt", { service: "x", exit: save.exit });
    expect(ok.status).toBe(200);
    expect((ok.body as { fast_apply: unknown }).fast_apply).toBeTruthy();
    expect(answer("POST", "/api/unlock/adopt", { service: "x", exit: "no-such-exit" }).status).toBe(403);
    const pv = answer("POST", "/api/unlock/adopt", { service: "x", exit: save.exit, preview: true });
    expect((pv.body as { preview?: boolean }).preview).toBe(true);
    // 手动 to a group or a pinned exit: only rules change, installed on the gateway.
    const grp = responses["POST /api/unlock/adopt?save=group"].body as { group: string; kind: string; fast_apply: { status: string } };
    expect(grp.kind).toBe("group");
    expect(grp.fast_apply.status).toBe("applied");
    expect(answer("POST", "/api/unlock/adopt", { service: "x", exit: "", group: grp.group, manual: true, identity: "i" }).status).toBe(200);
    expect(answer("POST", "/api/unlock/adopt", { service: "x", exit: "", group: "no-such-group", manual: true, identity: "i" }).status).toBe(403);
    const pin = responses["POST /api/unlock/adopt?save=manual"].body as { kind: string; fast_apply: { status: string } };
    expect(pin.kind).toBe("exit");
    expect(pin.fast_apply.status).toBe("applied");
    expect((save as { fast_apply: { status: string; reason?: string } }).fast_apply.reason).toContain("需要到部署页安装");
    const refused = makeDemoApi(await responsesOf("save-refused"))("PUT", "/api/topology", {});
    expect(refused.status).toBe(409);
    expect(refused.body).toMatchObject({ code: "independent_resource_changed" });
    // Times are shifted to "now": the newest status read is not in the anchor year.
    const st = (await responsesOf("healthy"))["GET /api/status"].body as { install: { installed_at: string } };
    expect(Math.abs(Date.parse(st.install.installed_at) - Date.now())).toBeLessThan(7 * 86400_000);
  });

  it("never goes to the network: non-API requests are refused by the fetch stand-in", async () => {
    const target = { fetch: realFetch };
    installDemoFetch(makeDemoApi({}), target);
    const r = await target.fetch("https://example.org/x");
    expect(r.status).toBe(404);
  });

  it("shows the permanent demo marker", () => {
    render(<DemoChrome params={{ scenario: "degraded", theme: "dark" }} />);
    const bar = screen.getByRole("region", { name: "演示数据说明" });
    expect(bar).toHaveTextContent("演示数据");
    expect(bar.getAttribute("data-marker")).toBe(DEMO_MARKER);
    expect(screen.getByLabelText("演示场景")).toHaveValue("degraded");
    expect(document.title.startsWith("【演示】")).toBe(true);
  });
});

// --------------------------------------------------------------- logs ---
//
// The three logs in the demo: every scenario has generated answers for
// them (no hand-written "no data" stand-in), the lists are filtered and
// paged from the generated journals with the services' rules, the related
// lookups agree with the ones the handlers generated, and a scenario whose
// journal lists nothing never shows its base scenario's records.

type Row = Record<string, unknown>;
interface LogBody {
  available?: boolean;
  code?: string;
  page?: { records?: Row[]; events?: Row[]; matched?: number; next_before?: unknown; open_merged?: number };
  records?: Row[];
  listed?: number;
  other_mac?: number;
  no_mac?: number;
  identity?: string;
  device?: string;
  mac?: string;
  from?: string;
  window_s?: number;
}

const LOG_READS = [
  "GET /api/sniff/devices",
  "GET /api/sniff/journal",
  "GET /api/sniff/journal/related",
  "GET /api/dns-log",
  "GET /api/dns-log/devices",
  "GET /api/dns-log/journal",
  "GET /api/dns-log/related",
  "GET /api/link-log",
  "GET /api/link-log/current",
  "GET /api/link-log/events",
];

const bodyOf = (r: { body: unknown }) => r.body as LogBody;
const idsOf = (rows: Row[] | undefined) => (rows ?? []).map((x) => x.id);

/** The lookup a generated related answer was made with (its window is at ± window_s). */
function lookupOf(b: LogBody): string {
  const at = new Date(Date.parse(b.from!) + b.window_s! * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
  return `?device=${encodeURIComponent(b.device!)}&at=${encodeURIComponent(at)}${b.mac ? `&mac=${encodeURIComponent(b.mac)}` : ""}`;
}

describe("demo logs", () => {
  it("every scenario answers the three logs from generated responses", async () => {
    for (const sc of SCENARIOS) {
      const responses = await responsesOf(sc.id);
      for (const k of LOG_READS) expect(responses[k], `${sc.id} ${k}`).toBeDefined();
    }
    // The states the scenarios stand for.
    const state = async (id: string) => {
      const r = await responsesOf(id);
      const dns = r["GET /api/dns-log"].body as { setting: { enabled: boolean }; installed: { enabled: boolean }; capability: { available: boolean; code?: string }; runtime: { code?: string; present: boolean } };
      const link = r["GET /api/link-log"].body as { runtime: { available: boolean; code?: string; present: boolean } };
      return {
        dns: `${dns.setting.enabled ? "on" : "off"}/${dns.installed.enabled ? "installed" : "absent"}/${dns.capability.available ? "capable" : dns.capability.code}/${dns.runtime.code ?? "ok"}`,
        dnsRecords: (bodyOf(r["GET /api/dns-log/journal"]).page?.records ?? []).length,
        link: `${link.runtime.present ? "running" : "absent"}/${link.runtime.code ?? "ok"}`,
        events: (bodyOf(r["GET /api/link-log/events"]).page?.events ?? []).length,
        conn: bodyOf(r["GET /api/sniff/devices"]).available ? "readable" : bodyOf(r["GET /api/sniff/devices"]).code,
      };
    };
    expect(await state("healthy")).toMatchObject({ dns: "on/installed/capable/ok", link: "running/ok", conn: "readable" });
    expect(await state("degraded")).toMatchObject({ dns: "on/installed/version_unverified/unverified_running", link: "running/ok", conn: "readable" });
    expect(await state("unavailable")).toMatchObject({ dns: "off/absent/agent_unavailable/agent_unavailable", dnsRecords: 0, link: "absent/agent_unavailable", events: 0, conn: "agent_unavailable" });
    expect(await state("logs-off")).toMatchObject({ dns: "off/absent/capable/ok", dnsRecords: 0, link: "absent/not_installed", events: 0, conn: "no_socket" });
    expect(await state("logs-empty")).toMatchObject({ dns: "on/installed/capable/ok", dnsRecords: 0, link: "running/ok", events: 0, conn: "readable" });
    expect((await state("healthy")).dnsRecords).toBeGreaterThan(100);
    expect((await state("healthy")).events).toBeGreaterThan(3);
    expect((await state("degraded")).events).toBeGreaterThan((await state("healthy")).events);
  });

  it("holds only documentation addresses, documentation MACs and example names", async () => {
    for (const id of ["healthy", "degraded"]) {
      const r = await responsesOf(id);
      const records = bodyOf(r["GET /api/dns-log/journal"]).page!.records!;
      for (const x of records) {
        expect(String(x.client), id).toMatch(/^(192\.168\.77\.\d+|2001:db8:77::[0-9a-f]+)$/);
        if (x.mac) expect(String(x.mac), id).toMatch(/^00:00:5e:00:53:[0-9a-f]{2}$/);
        expect(String(x.name), id).toMatch(/(^|\.)example\.(com|net|org)$|\.exam$/);
      }
      // A link event names topology objects only: no device address, no name a device asked for.
      const events = JSON.stringify(bodyOf(r["GET /api/link-log/events"]).page!.events);
      expect(events).not.toMatch(/192\.168\.77\.|2001:db8:77:|00:00:5e:00:53|example\.(com|net|org)/);
    }
  });

  it("filters and pages the query journal from the generated list", async () => {
    const responses = await responsesOf("healthy");
    const answer = makeDemoApi(responses);
    const all = bodyOf(responses["GET /api/dns-log/journal"]).page!.records!;
    const page = (q: string) => bodyOf(answer("GET", `/api/dns-log/journal${q}`)).page!;
    // The default page is the service's 50; the next one continues below it.
    const first = page("");
    expect(first.records).toHaveLength(50);
    expect(first.matched).toBe(all.length);
    expect(first.next_before).toBe(first.records![49].id);
    const second = page(`?before=${String(first.next_before)}`);
    expect(second.records).toHaveLength(50);
    expect(idsOf(second.records).some((id) => idsOf(first.records).includes(id))).toBe(false);
    expect(Number(second.records![0].id)).toBeLessThan(Number(first.records![49].id));
    // Device, result class, group and name text.
    const dev = page("?device=192.168.77.21&limit=200");
    expect(dev.records!.length).toBe(all.filter((x) => x.client === "192.168.77.21").length);
    expect(dev.records!.length).toBeGreaterThan(0);
    expect(dev.matched).toBe(dev.records!.length);
    expect(dev.next_before).toBeUndefined();
    const empty = page("?result=no_answer_any&limit=200");
    expect(empty.records!.length).toBe(all.filter((x) => x.result !== "answered").length);
    expect(page("?result=no_answer_slow&limit=200").records!.every((x) => x.result === "no_answer_slow" && Number(x.elapsed_ms) >= 1500)).toBe(true);
    expect(page("?text=INTERNAL-only&limit=200").records!.every((x) => x.name === "internal-only.example.net")).toBe(true);
    expect(page("?text=internal-only&limit=200").records!.length).toBeGreaterThan(0);
    const group = String(all[0].group);
    expect(page(`?group=${group}&limit=200`).records!.every((x) => x.group === group)).toBe(true);
    // A time range: the last hour only.
    const from = new Date(Date.now() - 3600_000).toISOString().replace(/\.\d{3}Z$/, "Z");
    const recent = page(`?from=${encodeURIComponent(from)}&limit=200`);
    expect(recent.records!.length).toBeGreaterThan(0);
    expect(recent.records!.length).toBeLessThan(all.length);
    expect(page("?device=192.0.2.200").records).toEqual([]);
  });

  it("filters and pages the link timeline; merged records that are still open come first", async () => {
    const responses = await responsesOf("degraded");
    const answer = makeDemoApi(responses);
    const all = bodyOf(responses["GET /api/link-log/events"]).page!.events!;
    const page = (q: string) => bodyOf(answer("GET", `/api/link-log/events${q}`)).page!;
    const whole = page("?limit=500");
    expect(whole.events).toHaveLength(all.length);
    expect(whole.events![0].open).toBe(true);
    expect(whole.open_merged).toBe(1);
    // What the scenario is there to show: a collection gap, changes found after it, a merged flap.
    expect(all.some((e) => e.class === "collector" && e.kind === "collector" && e.after_gap)).toBe(true);
    expect(all.some((e) => e.class !== "collector" && e.after_gap)).toBe(true);
    expect(all.some((e) => Number(e.changes) > 1)).toBe(true);
    expect(all.some((e) => e.kind === "source" && e.to === "unavailable")).toBe(true);
    const tunnels = page("?class=tunnel&limit=500");
    expect(tunnels.events!.length).toBeGreaterThan(3);
    expect(tunnels.events!.every((e) => e.class === "tunnel")).toBe(true);
    const one = page("?kind=external_exit&id=myext");
    expect(one.events!.length).toBe(all.filter((e) => e.kind === "external_exit" && e.id === "myext").length);
    expect(one.events!.length).toBeGreaterThanOrEqual(3);
    // Paging: five stored events a page, no event twice, the open record on the first page only.
    const p1 = page("?limit=5");
    expect(p1.events!.filter((e) => !e.open)).toHaveLength(5);
    expect(typeof p1.next_before).toBe("string");
    const p2 = page(`?limit=5&before=${String(p1.next_before)}`);
    expect(p2.events!.some((e) => e.open)).toBe(false);
    expect(p2.events!.map((e) => e.seq).some((x) => p1.events!.map((e) => e.seq).includes(x))).toBe(false);
    expect(page("?class=wss&kind=tunnel").events).toEqual([]);
  });

  it("answers a related lookup like the handlers did", async () => {
    const responses = await responsesOf("healthy");
    const answer = makeDemoApi(responses);
    for (const key of ["GET /api/dns-log/related", "GET /api/sniff/journal/related"]) {
      const sample = bodyOf(responses[key]);
      expect(sample.available, key).toBe(true);
      expect(sample.listed, key).toBeGreaterThan(0);
      expect(sample.identity, key).toBe("mac");
      const got = bodyOf(answer("GET", key.slice(4) + lookupOf(sample)));
      expect(idsOf(got.records), key).toEqual(idsOf(sample.records));
      expect({ listed: got.listed, other: got.other_mac, none: got.no_mac, identity: got.identity, window: got.window_s }, key).toEqual({
        listed: sample.listed,
        other: sample.other_mac,
        none: sample.no_mac,
        identity: sample.identity,
        window: sample.window_s,
      });
    }
    // Without a MAC the match rests on the address alone; another device's address finds nothing.
    const sample = bodyOf(responses["GET /api/sniff/journal/related"]);
    const noMac = bodyOf(answer("GET", `/api/sniff/journal/related${lookupOf({ ...sample, mac: undefined })}`));
    expect(noMac.identity).toBe("address");
    expect(noMac.listed).toBe(sample.listed);
    const other = bodyOf(answer("GET", `/api/sniff/journal/related${lookupOf({ ...sample, mac: "00:00:5e:00:53:99" })}`));
    expect(other.records).toEqual([]);
    expect(other.other_mac).toBe(sample.listed);
    expect(bodyOf(answer("GET", `/api/dns-log/related${lookupOf({ ...sample, device: "192.0.2.200" })}`)).records).toEqual([]);
  });

  it("an address used by two devices is told apart by MAC in the degraded journal", async () => {
    const responses = await responsesOf("degraded");
    const answer = makeDemoApi(responses);
    const records = bodyOf(responses["GET /api/dns-log/journal"]).page!.records!;
    const macs = new Set(records.filter((x) => x.client === "192.168.77.35" && x.mac).map((x) => x.mac));
    expect(macs.size).toBe(2);
    expect(records.some((x) => x.time_approx)).toBe(true);
    expect(records.filter((x) => !x.mac && x.client !== "2001:db8:77::50").length).toBeGreaterThan(5);
    // Around the newest record of that address, asked with the old MAC: the new device's queries are left out and counted.
    const newest = records.find((x) => x.client === "192.168.77.35" && x.mac === "00:00:5e:00:53:36")!;
    const got = bodyOf(answer("GET", `/api/sniff/journal/related?device=192.168.77.35&at=${encodeURIComponent(String(newest.time))}&mac=00:00:5e:00:53:35&window=600`));
    expect(got.other_mac).toBeGreaterThan(0);
    expect((got.records ?? []).every((x) => !x.mac || x.mac === "00:00:5e:00:53:35")).toBe(true);
  });

  it("a scenario whose journals list nothing never shows its base scenario's records", async () => {
    for (const id of ["logs-off", "logs-empty", "unavailable"]) {
      const responses = await responsesOf(id);
      const answer = makeDemoApi(responses);
      const at = encodeURIComponent(new Date().toISOString().replace(/\.\d{3}Z$/, "Z"));
      const conn = bodyOf(answer("GET", "/api/sniff/journal?device=192.168.77.20"));
      expect(conn.page?.records ?? [], id).toEqual([]);
      expect(bodyOf(answer("GET", "/api/dns-log/journal?device=192.168.77.20")).page?.records ?? [], id).toEqual([]);
      expect(bodyOf(answer("GET", "/api/link-log/events?class=tunnel")).page?.events ?? [], id).toEqual([]);
      for (const path of ["/api/dns-log/related", "/api/sniff/journal/related"]) {
        const b = bodyOf(answer("GET", `${path}?device=192.168.77.20&at=${at}&mac=00:00:5e:00:53:20`));
        expect(b.records, `${id} ${path}`).toEqual([]);
        expect(b.device, `${id} ${path}`).toBe("192.168.77.20");
        expect(b.available, `${id} ${path}`).toBe(id === "logs-empty");
      }
    }
  });
});

// ---------------------------------------------------------- isolation ---

/** "../a/./b/../c.ts" → "../a/c.ts" (paths are relative to this directory, as the glob keys). */
function normalize(p: string): string {
  const out: string[] = [];
  for (const seg of p.split("/")) {
    if (seg === "." || seg === "") continue;
    if (seg === ".." && out.length && out[out.length - 1] !== "..") out.pop();
    else out.push(seg);
  }
  const r = out.join("/");
  return r.startsWith("..") ? r : `./${r}`;
}

/** Every module the production entry reaches (relative imports, static and dynamic). */
function importGraph(entry: string): Set<string> {
  const seen = new Set<string>();
  const stack = [entry];
  const spec = /(?:import|export)\s[^"'`;]*?from\s*["']([^"']+)["']|import\(\s*["']([^"']+)["']\s*\)|import\s+["']([^"']+)["']/g;
  while (stack.length) {
    const file = stack.pop()!;
    if (seen.has(file)) continue;
    seen.add(file);
    for (const m of (SOURCES[file] ?? "").matchAll(spec)) {
      const s = m[1] ?? m[2] ?? m[3];
      if (!s.startsWith(".")) continue;
      const base = normalize(`${file.slice(0, file.lastIndexOf("/"))}/${s}`);
      const cand = [base, `${base}.ts`, `${base}.tsx`, `${base}/index.ts`, `${base}/index.tsx`].find((p) => p in SOURCES);
      if (cand) stack.push(cand);
      else if (!/\.(css|svg|json)$/.test(s)) throw new Error(`${file}: cannot resolve ${s}`);
    }
  }
  return seen;
}

describe("demo isolation", () => {
  it("the production entry imports nothing under src/demo/", () => {
    const graph = importGraph("../main.tsx");
    expect(graph.size).toBeGreaterThan(20); // the parser found the pages
    expect(graph.has("../App.tsx")).toBe(true);
    expect(graph.has("../RulesPage.tsx")).toBe(true); // lazy routes are followed
    expect([...graph].filter((f) => f.startsWith("./") || f.startsWith("../demo/"))).toEqual([]);
    // No production module mentions the demo, its marker or a demo switch.
    for (const f of graph) {
      const text = SOURCES[f];
      expect(text.includes(DEMO_MARKER), f).toBe(false);
      expect(/src\/demo|\.\/demo\/|__meridianDemo|scenario=/.test(text), f).toBe(false);
    }
  });

  it("the production HTML entry and the production build config do not reference the demo", () => {
    const html = WEB_FILES["../../index.html"];
    expect(html).toContain("/src/main.tsx");
    expect(html).not.toMatch(/demo/i);
    expect(WEB_FILES["../../vite.config.ts"]).not.toMatch(/demo/i);
    expect(WEB_FILES["../../vite.demo.config.ts"]).toMatch(/outDir: "dist-demo"/);
    expect(WEB_FILES["../../demo.html"]).toContain("/src/demo/main.tsx");
  });

  // Needs the repository around web/ (deploy/, .dockerignore, the Go tree):
  // a checkout of web/ alone (e.g. a container that mounts only web/) has
  // none of them and skips this check instead of failing on undefined.
  it.skipIf(REPO_FILES["../../../deploy/Dockerfile"] === undefined)("the Docker image copies only web/dist and the Go server serves only its web dir", () => {
    const docker = REPO_FILES["../../../deploy/Dockerfile"];
    const copies = docker.split("\n").filter((l: string) => /COPY --from=web/.test(l));
    expect(copies).toEqual(["COPY --from=web /src/web/dist /usr/share/meridian/web"]);
    expect(docker).not.toMatch(/dist-demo|demo:build/);
    expect(REPO_FILES["../../../.dockerignore"]).toMatch(/^web\/dist-demo$/m);
    const goFiles = Object.entries(GO_FILES);
    expect(goFiles.length).toBeGreaterThan(50);
    expect(goFiles.filter(([, t]) => /dist-demo|src\/demo/.test(t)).map(([f]) => f)).toEqual([]);
  });

  it("a production build in web/dist (when present) contains no demo code or data", () => {
    // Nothing built in this checkout: the import graph test above still holds.
    const hits = Object.entries(DIST_FILES)
      .filter(([, t]) => t.includes(DEMO_MARKER) || t.includes("演示数据") || t.includes("demo_read_only") || t.includes("__meridianDemo"))
      .map(([f]) => f);
    expect(hits).toEqual([]);
  });
});
