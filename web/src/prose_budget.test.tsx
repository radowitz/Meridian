// Every routed page shows no explanatory sentence by default (there is no
// subtitle: the layout says what a page is for), and a drawer/dialog a test
// can open at most one. Everything else that explains (section notes, field help, table
// footnotes, unverified/limit notes) is behind a 「说明」/「?」 toggle. Danger
// consequences, errors and blocking notices are exempt (warning/error
// alerts, fail-closed and sign-off notices, confirm dialogs). Synthetic data.

import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { NAV } from "./App";
import { healthyTags, helpEntries, optionHints, proseSentences, sentences } from "./prose_check";
import { GROUPS_API, RULES_API, UNLOCK_API, topology } from "./layout_fixtures";
import { server } from "./pages_fixtures";
import { fakeApi, phoneWidth, renderAt, type Handler } from "./testing";

const DUMP = !!(globalThis as { process?: { env?: Record<string, string> } }).process?.env?.PROSE_DUMP;

/** Data of real size per page, so table footnotes and per-row notes render too. */
const RICH: Record<string, Record<string, Handler>> = {
  "": { "GET /api/topology": () => topology(), ...GROUPS_API },
  topology: { "GET /api/topology": () => topology(), "GET /api/servers": () => ({ servers: [server()] }) },
  exits: { "GET /api/topology": () => topology(), ...GROUPS_API },
  rules: RULES_API,
  unlock: UNLOCK_API,
  servers: { "GET /api/topology": () => topology(), "GET /api/servers": () => ({ servers: [server()] }) },
  deploy: { "GET /api/topology": () => topology() },
  dns: { "GET /api/topology": () => topology() },
  cloudflare: { "GET /api/topology": () => topology() },
};

afterEach(() => {
  vi.restoreAllMocks();
  sessionStorage.clear();
  localStorage.clear();
});

const ROUTES = NAV.flatMap((g) => g.routes).map((r) => r.key);

/** Visible explanatory sentences allowed by default: a page, an open drawer or dialog. */
const PAGE_MAX = 0;
const PANEL_MAX = 1;
/** Non-status tags a page may show by default; labels are plain text. */
const RAW_TAG_MAX = 3;

/** At most one 「说明」 entry, in the page header; no coloured tag for a healthy state. */
function expectOneHelp(key: string) {
  const help = helpEntries();

  expect(help.map((b) => b.closest("[data-testid], section, div")?.outerHTML.slice(0, 120)), `#/${key}: 说明 entries`).toHaveLength(Math.min(help.length, 1));
  if (help.length === 1) expect(help[0].closest(".page-header"), `#/${key}: the 说明 is in the header`).not.toBeNull();
  const raw = [...document.querySelectorAll("main .ant-tag:not([data-status])")];
  if (DUMP) console.log(`@@ ${key} raw tags ${raw.length}: ` + raw.map((t) => t.textContent).join(" | "));
  expect(raw.length, `#/${key}: raw (non-status) tags: ${raw.map((t) => t.textContent).join(" | ")}`).toBeLessThanOrEqual(RAW_TAG_MAX);
  expect(optionHints(), `#/${key}: hint text next to options`).toEqual([]);
  const ok = healthyTags();
  expect(ok.map((t) => t.textContent), `#/${key}: coloured tags for healthy states`).toEqual([]);
}

async function openPage(key: string, handlers: Record<string, Handler> = {}) {
  fakeApi(handlers);
  renderAt(`#/${key}`);
  const label = NAV.flatMap((g) => g.routes).find((r) => r.key === key)!.label;
  await screen.findByRole("heading", { level: 1, name: label }, { timeout: 4000 });
  await new Promise((r) => setTimeout(r, 50));
}

describe("explanatory prose is collapsed by default", () => {
  it("sentence splitting", () => {
    expect(sentences("这是一句足够长的完整的话。这是第二句足够长的完整的话；")).toHaveLength(2);
    expect(sentences("还没有服务器。")).toHaveLength(0);
    expect(sentences("未被引用")).toHaveLength(0);
    expect(sentences("这是一段没有句号但是相当长的说明文字内容")).toHaveLength(1);
  });

  it("a grey paragraph cannot slip past by its markup (an exempt marker on explanatory text, a muted block)", () => {
    document.body.innerHTML = `<main>
      <div class="explain" data-prose-exempt><div>断连影响：已有连接会断开，客户端需要重新连接才能恢复。</div></div>
      <div class="muted">吞吐探测会消耗中继的计费流量，每台中继每天最多探测若干次。</div>
      <div class="flag-warn" data-prose-exempt>这条警告属于危险后果，必须一直显示出来。</div>
    </main>`;
    expect(proseSentences()).toHaveLength(2);
    document.body.innerHTML = "";
  });

  for (const key of ROUTES) {
    it(`page #/${key} shows no explanatory sentence (empty data)`, async () => {
      await openPage(key);
      const s = proseSentences();
      if (DUMP) console.log(`@@ ${key} empty\n` + s.join("\n"));
      expect(s.length, `#/${key}:\n${s.join("\n")}`).toBeLessThanOrEqual(PAGE_MAX);
      expectOneHelp(key);
    });
    if (RICH[key]) it(`page #/${key} shows no explanatory sentence (data of real size)`, async () => {
      await openPage(key, RICH[key]);
      const s = proseSentences();
      if (DUMP) console.log(`@@ ${key}\n` + s.join("\n"));
      expect(s.length, `#/${key}:\n${s.join("\n")}`).toBeLessThanOrEqual(PAGE_MAX);
      expectOneHelp(key);
    });
  }

  // Drawers and dialogs: the open panel counts as a page of its own (its
  // title is the heading; at most one sentence of explanation by default).
  const DRAWERS: [string, string, Record<string, Handler>][] = [
    ["rules", "添加规则", RULES_API],
    ["exits", "新建地区组", { "GET /api/topology": () => topology(), ...GROUPS_API }],
    ["servers", "添加服务器", {}],
    ["keys", "新建密钥", {}],
    ["cloudflare", "添加账户", {}],
    ["topology", "网关设置", { "GET /api/topology": () => topology() }],
  ];
  for (const [key, button, handlers] of DRAWERS) {
    it(`#/${key}: the 「${button}」 panel shows at most one sentence`, async () => {
      await openPage(key, handlers);
      await userEvent.click(screen.getAllByRole("button", { name: new RegExp(button) })[0]);
      const panel = await waitFor(() => {
        const el = document.querySelector(".ant-drawer-open .ant-drawer-content, .ant-modal-wrap:not([style*='display: none']) .ant-modal-content");
        expect(el).not.toBeNull();
        return el!;
      });
      const s = proseSentences(panel);
      if (DUMP) console.log(`@@ ${key} ${button}\n` + s.join("\n"));
      expect(s.length, `#/${key} ${button}:\n${s.join("\n")}`).toBeLessThanOrEqual(PANEL_MAX);
    });
  }

  // Phone width (390 px): nothing in a page, opened 「说明」 included, has a
  // fixed width wider than the screen outside a table's own scroll box.
  // (jsdom has no layout; widths and wrapping are rechecked in a browser.)
  for (const key of ROUTES) {
    it(`#/${key} at phone width: no fixed width wider than the screen, notes open`, async () => {
      phoneWidth();
      await openPage(key, RICH[key] ?? {});
      for (const b of Array.from(document.querySelectorAll<HTMLButtonElement>("main .explain-toggle[aria-expanded='false']"))) b.click();
      const wide = Array.from(document.querySelectorAll<HTMLElement>("main [style]")).filter((e) => {
        if (e.closest(".ant-table-wrapper, .table-scroll, .wide-grid, .react-flow, .topo-canvas, pre, .mono-block")) return false;
        const px = [e.style.width, e.style.minWidth].map((v) => (v.endsWith("px") ? parseFloat(v) : 0));
        return Math.max(...px) > 390 - 32;
      });
      expect(wide.map((e) => `${e.tagName}.${e.className} ${e.style.cssText}`)).toEqual([]);
    });
  }
});

// Panels the page tests cannot open with data (deployment guide, pre-check,
// withdraw, WSS, sniff, link log…) are guarded at the source: a raw antd Tag
// is only allowed when its colour comes from a status map. Labels are text;
// problems use StatusTag.
describe("no decorative tags in any source file", () => {
  const sources = import.meta.glob(["./*.tsx", "!./*.test.tsx"], { query: "?raw", import: "default", eager: true }) as Record<string, string>;
  it("every <Tag> takes a computed status colour", () => {
    const bad: string[] = [];
    for (const [file, src] of Object.entries(sources)) {
      if (file.endsWith("ui_base.tsx")) continue;
      for (const m of src.matchAll(/<Tag\b[^>]*>/g)) if (!/\scolor=\{/.test(m[0])) bad.push(`${file}: ${m[0]}`);
    }
    expect(bad).toEqual([]);
  });
});
