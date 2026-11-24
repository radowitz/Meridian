// Navigation of the resolution settings and the three logs: four entries of
// the side menu, each with a hash route of its own (解析设置 #/dns, 解析日志
// #/dns-log, 连接日志 #/conn-log, 链路日志 #/link-log); the old ways in keep
// working (the lists page's "解析配置" section and its #dns anchor; the sniff
// card's connection-log button is covered in sniff_journal.test.tsx); and the
// links that lead to the resolution settings from where an operator looks
// for them: the overview, the gateway's DNS switches, the sniff card.

import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { tabGroupOf } from "./page_tabs";
import { NAV } from "./App";
import { topology } from "./pages_fixtures";
import { fakeApi, renderAt } from "./testing";
import { IndependentFieldsNote } from "./ui";
import type { DNSLogView, DNSView, LinkLogView } from "./types";

afterEach(() => vi.restoreAllMocks());

const MASK = "‹账户标识已隐藏›";

function dnsView(transports: string[]): DNSView {
  return {
    paths: [],
    exits: transports.map((t, i) => ({ id: `ex${i + 1}`, name: `示例出口 ${i + 1}`, source: t === "plain" ? "default" : "global", description: t === "plain" ? "内置公共解析器（明文 53）" : `DoT 198.51.100.153:853（证书校验 ${MASK}.dns.example.net）`, transport: t, checkable: true })),
    global_upstream: transports.some((t) => t !== "plain") ? { protocol: "dot", addresses: ["198.51.100.153"], tls_host_name: "{account}.dns.example.net", account_credential: "dnsacct-1" } : null,
    configs: [],
    forwarder: { available: false, code: "sniff_off", message: "嗅探转发服务关闭", resolvers: [] },
    checks: [],
    check_available: false,
    check_name: "example.com",
    unverified: ["面板显示的上游来自编译结果"],
    masked: MASK,
  };
}

const DNS_LOG_OFF: DNSLogView = {
  setting: { enabled: false },
  installed: { known: true, enabled: false },
  capability: { available: false, code: "agent_unavailable", reason: "没有配置 host agent：读不到网关解析器的版本，解析日志保持不可用" },
  runtime: { available: false, code: "agent_unavailable", message: "没有配置 host agent", audit_installed: false, present: false, data_files: 0, data_bytes: 0 },
  bounds: { max_age_s: 86400, max_records: 50000, budget: { total: 33554432, raw: 8388608, queue: 2097152, journal: 23068672 }, disk_bytes: 31457280, slow_empty_ms: 1500, related_window_max_s: 600, related_window_default_s: 120 },
  scope: { covered: [], not_covered: [], results: [], storage: [], switch: [], identity: [] },
  groups: [],
  qtypes: {},
};

const LINK_LOG_OFF: LinkLogView = {
  installed: { known: true, enabled: false },
  pending: "install",
  runtime: { available: false, code: "agent_unavailable", message: "没有配置 host agent：读不到链路日志", present: false, config_installed: false },
  bounds: { max_age_s: 2592000, max_events: 20000, budget: { total: 16777216, events: 15716352, checkpoint: 532480, rewrite: 528384 }, disk_bytes: 16777216, max_line: 1024, writes_per_hour: 600, page_max: 500 },
  timing: { interval_s: 10, slow_interval_s: 30, gap_after_s: 120, handshake_stale_s: 180, upstream_stale_s: 60, selfcheck_every_s: 900, selfcheck_max_age_s: 2400, flap_after: 4, flap_window_s: 600, flap_quiet_s: 600, flap_max_s: 3600 },
  scope: { sources: [], not_in_scope: [], kinds: [], sniff_on: false, externals: [], unobserved: [], notes: { records: [], storage: [], rules: [], install: [] } },
  objects: [],
};

const SNIFF_SCOPE = { covered: [], lifecycle: [], results: [], not_covered: [], storage: [], names_on: [], names_off: [] };

/** The reads of the four pages, answered as on a panel without a host agent. */
function pagesApi(extra: Parameters<typeof fakeApi>[0] = {}) {
  return fakeApi({
    "GET /api/dns": () => dnsView(["plain"]),
    "GET /api/dns-log": () => DNS_LOG_OFF,
    "GET /api/link-log": () => LINK_LOG_OFF,
    "GET /api/sniff/devices": () => ({ available: false, code: "agent_unavailable", message: "没有配置 host agent，读不到嗅探服务的连接日志", record_names: false, scope: SNIFF_SCOPE, labels: [] }),
    ...extra,
  });
}

const PAGES: [string, string, string][] = [
  ["dns", "解析设置", "DNSView"],
  ["dns-log", "解析日志", "DNSLogsPage"],
  ["conn-log", "连接日志", "ConnectionLogsPage"],
  ["link-log", "链路日志", "LinkLogsPage"],
];

function menu() {
  return document.querySelector<HTMLElement>(".nav-menu")!;
}

describe("navigation: resolution settings and logs", () => {
  it("has four routes of their own (the three logs as tabs of one menu entry), each with a readable name", () => {
    const dns = NAV.find((g) => g.routes.some((r) => r.key === "dns"))!;
    expect(dns.routes.find((r) => r.key === "dns")?.label).toBe("解析设置");
    const logs = NAV.find((g) => g.routes.some((r) => r.key === "dns-log"))!;
    const logKeys = new Set(PAGES.slice(1).map(([k]) => k));
    expect(logs.routes.filter((r) => logKeys.has(r.key)).map((r) => [r.key, r.label]).sort()).toEqual(PAGES.slice(1).map(([k, l]) => [k, l]).sort());
    expect(tabGroupOf("dns-log")?.title).toBe("日志");
    expect(tabGroupOf("dns")?.tabs.map((t) => t.key)).toEqual(["dns", "lists"]);
    // The lists page is still there, and no key is used twice.
    const keys = NAV.flatMap((g) => g.routes).map((r) => r.key);
    expect(keys).toContain("lists");
    expect(new Set(keys).size).toBe(keys.length);
  });

  it("each page opens from its menu entry and its tab, at its own address", async () => {
    pagesApi();
    renderAt("#/");
    await screen.findByRole("heading", { level: 1, name: "概览" });
    for (const [key, label] of PAGES) {
      const group = tabGroupOf(key)!;
      await userEvent.click(within(menu()).getByRole("link", { name: group.title }));
      const tabs = await screen.findByRole("navigation", { name: `${group.title}的标签` });
      await userEvent.click(within(tabs).getByRole("link", { name: label }));
      expect(await screen.findByRole("heading", { level: 1, name: label })).toBeInTheDocument();
      expect(window.location.hash).toBe(`#/${key}`);
      expect(document.title).toBe(`${label} · Meridian`);
      expect(menu().querySelector(".ant-menu-item-selected")).toHaveTextContent(group.title);
      expect(screen.queryByText("这个页面出错了")).toBeNull();
      expect(screen.queryByText("没有这个页面")).toBeNull();
    }
  });

  it("each route opens directly from its address", async () => {
    for (const [key, label] of PAGES) {
      pagesApi();
      const view = renderAt(`#/${key}`);
      expect(await screen.findByRole("heading", { level: 1, name: label })).toBeInTheDocument();
      view.unmount();
      vi.restoreAllMocks();
    }
  });
});

describe("old ways in", () => {
  it("the lists page keeps the 解析配置 section as a pointer to the new page and reads no DNS data itself", async () => {
    const api = pagesApi();
    const scrolled: string[] = [];
    vi.spyOn(Element.prototype, "scrollIntoView").mockImplementation(function (this: Element) {
      scrolled.push(this.id);
    });
    renderAt("#/lists");
    const pointer = await screen.findByTestId("lists-dns-pointer");
    const section = pointer.closest("section")!;
    expect(section).toHaveAttribute("id", "dns");
    expect(within(section).getByRole("heading", { name: "解析配置" })).toBeInTheDocument();
    expect(pointer).toHaveTextContent("已移到 解析设置");
    expect(within(pointer).getByRole("link", { name: "解析设置" })).toHaveAttribute("href", "#/dns");
    expect(api.find("GET /api/dns")).toHaveLength(0);
    expect(scrolled).toEqual([]);
    await userEvent.click(within(section).getByRole("link", { name: "打开解析设置" }));
    expect(await screen.findByRole("heading", { level: 1, name: "解析设置" })).toBeInTheDocument();
    expect(window.location.hash).toBe("#/dns");
    expect(await screen.findByTestId("dns-upstream-status")).toHaveAttribute("data-state", "none");
  });

  it("#/lists/dns and #/lists?section=dns bring the pointer into view", async () => {
    for (const hash of ["#/lists/dns", "#/lists?section=dns"]) {
      pagesApi();
      const scrolled: string[] = [];
      vi.spyOn(Element.prototype, "scrollIntoView").mockImplementation(function (this: Element) {
        scrolled.push(this.id);
      });
      const view = renderAt(hash);
      await screen.findByTestId("lists-dns-pointer");
      await waitFor(() => expect(scrolled).toContain("dns"));
      view.unmount();
      vi.restoreAllMocks();
    }
  });

  it("a bare #dns (the old anchor) opens the resolution settings, not the 404 page", async () => {
    pagesApi();
    renderAt("#dns");
    expect(await screen.findByRole("heading", { level: 1, name: "解析设置" })).toBeInTheDocument();
    expect(screen.queryByText("没有这个页面")).toBeNull();
    expect(menu().querySelector(".ant-menu-item-selected")).toHaveTextContent("解析与名单");
  });
});

describe("links to the resolution settings", () => {
  it("a refused whole-topology save points to the pages where the resolver upstream and the query log are changed", () => {
    render(
      <IndependentFieldsNote
        fields={[
          { field: "settings.exit_dns", resource: "出口解析上游（全局）", endpoint: "/api/dns/upstream", methods: ["PUT"] },
          { field: "nodes[].exit_dns", resource: "出口解析上游（单个出口）", endpoint: "/api/dns/upstream", methods: ["PUT"], items: ["ex1"] },
          { field: "settings.dns_log", resource: "解析日志", endpoint: "/api/dns-log", methods: ["PUT"] },
        ]}
      />,
    );
    const rows = [...screen.getByTestId("independent-fields").querySelectorAll<HTMLElement>("li")];
    expect(rows.map((r) => within(r).getByRole("link").getAttribute("href"))).toEqual(["#/dns", "#/dns", "#/dns-log"]);
    expect(rows[0]).toHaveTextContent("解析设置页的「出口解析上游」");
    expect(rows[2]).toHaveTextContent("解析日志页的「开关与状态」");
    expect(screen.queryByText(/它自己的页面/)).toBeNull();
  });

  it("overview: links to the three logs", async () => {
    pagesApi();
    renderAt("#/");
    const logs = await screen.findByTestId("overview-log-links");
    expect(within(logs).getByRole("link", { name: "解析日志" })).toHaveAttribute("href", "#/dns-log");
    expect(within(logs).getByRole("link", { name: "连接日志" })).toHaveAttribute("href", "#/conn-log");
    expect(within(logs).getByRole("link", { name: "链路日志" })).toHaveAttribute("href", "#/link-log");
  });

  it("gateway settings: next to the DNS switches, links to the resolution settings and the query log", async () => {
    pagesApi({ "GET /api/topology": () => topology(), "GET /api/servers": () => ({ servers: [] }) });
    renderAt("#/topology");
    await userEvent.click(await screen.findByRole("button", { name: /网关设置/ }));
    const note = await screen.findByTestId("settings-dns-link");
    const drawer = note.closest(".ant-drawer-content") as HTMLElement;
    // It sits in the 解析（DNS） part, after the two switches.
    const split = within(drawer).getByRole("switch", { name: "未列名单的域名也问国内 DNS" });
    expect(split.compareDocumentPosition(note) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(note).toHaveTextContent("出口向哪个上游解析");
    // Collapsed by default: the links show after 「说明」.
    await userEvent.click(within(note).getByRole("button", { name: /说明/ }));
    expect(within(note).getByRole("link", { name: "解析日志" })).toHaveAttribute("href", "#/dns-log");
    const link = within(note).getByRole("link", { name: "解析设置" });
    expect(link).toHaveAttribute("href", "#/dns");
    await userEvent.click(link);
    expect(await screen.findByRole("heading", { level: 1, name: "解析设置" })).toBeInTheDocument();
    expect(window.location.hash).toBe("#/dns");
  });
});
