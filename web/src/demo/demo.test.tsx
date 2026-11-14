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

  it("the Docker image copies only web/dist and the Go server serves only its web dir", () => {
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
