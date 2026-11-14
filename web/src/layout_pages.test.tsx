// Layout regressions of the pages with data of real size (docs/ui-layout.md,
// "Applied to the pages"): about 14 nodes, 7 region groups, 165 rules, 56
// rule-sets, 17 service groups, 41 adapters and 9 exits in the matrix. All
// data is synthetic (documentation address ranges, example names).
//
// jsdom has no layout engine: these tests prove structure and interaction
// (pagination with global order numbers, key columns vs the expandable row,
// full text reachable behind "…", header actions, matrix filters, safety
// notices never inside a collapsed block). Widths, wrapping and sticky
// behaviour are checked in a real browser (docs/ui-layout.md).

import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { autoLayout, LAYOUT } from "./TopologyPage";
import { RULES_PAGE_SIZE } from "./RulesPage";
import { fakeApi, panelStatus, renderAt } from "./testing";
import type {
  CoverageItem,
  GroupActualView,
  GroupHubState,
  Node,
  ProbeCatalogEntry,
  ProbeResultRow,
  RegionGroupView,
  Rule,
  RuleSetView,
  Topology,
} from "./types";

afterEach(() => {
  vi.restoreAllMocks();
  sessionStorage.clear();
  localStorage.clear();
});

const NOW = "2026-11-12T10:00:00Z";
const REGIONS = ["hk", "jp", "tw", "sg", "us", "my", "gb"];

// ------------------------------------------------------------- fixture ---

function node(id: string, role: Node["role"], region: string, over: Partial<Node> = {}): Node {
  return {
    id,
    name: `${role}-${id}.example`,
    role,
    region,
    managed: role !== "ix",
    path_v4: true,
    path_v6: true,
    egress_v4: role === "exit",
    egress_v6: false,
    nat_dial_out: false,
    residential: false,
    ix_bound: false,
    ...over,
  };
}

/** 15 nodes: gateway, 2 relays, IX, primary + backup hub, 9 exits (only the gateway has a saved position). */
function nodes(): Node[] {
  const exits = Array.from({ length: 9 }, (_, i) => node(`ex${i + 1}`, "exit", REGIONS[i % REGIONS.length], { name: `出口 ${i + 1} · 一个比较长的出口名字.example` }));
  return [
    node("gw", "gateway", "cn", { x: 0, y: 0 }),
    node("relay1", "relay", "cn"),
    node("relay2", "relay", "cn"),
    node("ix1", "ix", "hk"),
    node("hub1", "hub", "hk", { hub_tier: "primary" }),
    node("hub2", "hub", "hk", { hub_tier: "backup" }),
    ...exits,
  ];
}

function rule(i: number): Rule {
  const id = `r${String(i).padStart(3, "0")}`;
  return {
    id,
    name: `规则 ${i} · service-${i}.example`,
    manual: i % 3 !== 0,
    origin: i % 5 === 0 ? "mihomo" : undefined,
    source_line: i % 5 === 0 ? i + 10 : undefined,
    source_text: i % 5 === 0 ? `DOMAIN-SUFFIX,service-${i}.example,Proxy` : undefined,
    priority: i * 10,
    enabled: true,
    overridden: false,
    match_type: i % 7 === 0 ? "ruleset" : "suffix",
    match_value: i % 7 === 0 ? "" : `service-${i}.with-a-rather-long-subdomain.example.net`,
    rule_set: i % 7 === 0 ? `rs${(i % 56) + 1}` : undefined,
    domains: i % 4 === 0 ? [`a-${i}.example.org`, `b-${i}.example.org`] : [],
    target_group: i % 11 === 0 ? undefined : `g-${REGIONS[i % REGIONS.length]}`,
    target_service: i % 11 === 0 ? `svc${(i % 17) + 1}` : undefined,
    require_residential: i % 13 === 0,
    require_v6: false,
  };
}

function topology(): Topology {
  return {
    settings: {
      draft: false,
      ix_replacement_mode: false,
      lan_interface: "eth0",
      gateway_lan_ipv4: "192.0.2.88/24",
      ros_ipv4: "192.0.2.1",
      ros_v6_lla: "fe80::1",
      lan_ipv6_prefix: "2001:db8:100::/64",
      ula_prefix: "fd66::/48",
      panel_bind: "192.0.2.88:8787",
      domestic_dot: [],
      transit_v4_prefix: "10.66.200.0/24",
      transit_v6_prefix: "fd66:0:0:ff::/64",
      default_group: "g-hk",
    } as Topology["settings"],
    nodes: nodes(),
    links: [],
    rules_ordered: true,
    rules: Array.from({ length: 165 }, (_, i) => rule(i + 1)),
    region_groups: REGIONS.map((r, i) => ({ id: `g-${r}`, name: `地区组 ${r.toUpperCase()} 机房`, region: r, members: [`ex${i + 1}`, `ex${i + 2}`].filter((x) => Number(x.slice(2)) <= 9), mode: i % 2 ? "manual" : "auto" })),
    service_groups: Array.from({ length: 17 }, (_, i) => ({ id: `svc${i + 1}`, name: `服务组 ${i + 1}`, target_group: `g-${REGIONS[i % REGIONS.length]}`, origin: "mihomo" })),
    rule_sets: Array.from({ length: 56 }, (_, i) => ({ id: `rs${i + 1}`, name: `RuleSet${i + 1}`, url: `https://rules.example.org/sets/very/long/path/RuleSet${i + 1}.list` })),
  } as Topology;
}

function ruleSets(): RuleSetView[] {
  return Array.from({ length: 56 }, (_, i) => ({
    rule_set: { id: `rs${i + 1}`, name: `RuleSet${i + 1}`, url: `https://rules.example.org/sets/very/long/path/RuleSet${i + 1}.list` },
    status: { state: "ok", fetched_at: NOW, counts: { domain: 120 + i }, unsupported: i % 9 === 0 ? { "PROCESS-NAME": 3 } : undefined },
    used_by: [{ rule_id: `r${String(i + 1).padStart(3, "0")}`, name: `规则 ${i + 1}`, position: i + 1 }],
    candidates: [],
  })) as RuleSetView[];
}

const RULES_API = {
  "GET /api/topology": () => topology(),
  "GET /api/rules/analysis": () => ({
    rules: [{ rule_id: "r002", entries: 3, shadowed: 3, fully_shadowed: true, shadowed_by: ["r001"] }],
    shared_address: "两个名字解析到同一个地址时，该地址按更靠前的规则走。",
    upgrade_notes: ["升级后，苹果的域名不再内置直连", "第二条升级说明"],
  }),
  "GET /api/service-groups": () => ({ service_groups: topology().service_groups!.map((g) => ({ service_group: g, used_by: [] })) }),
  "GET /api/rule-sets": () => ({ rule_sets: ruleSets(), formats: ["surge-list"] }),
  "POST /api/validate": () => ({ issues: [], paths: [] }),
};

const NEVER_READ: GroupActualView = {
  state: "unavailable",
  code: "carrying_unknown",
  message: "不知道现在由哪个枢纽承载（网关还没有上游记录）；不把任一枢纽的报告当作实际使用",
  active: "",
  alert: false,
  last_switch: null,
  read_at: null,
  hub_reported_at: null,
  deployed_matches: null,
};

function groupView(i: number): RegionGroupView {
  const r = REGIONS[i];
  const members = [`ex${i + 1}`, `ex${i + 2}`].filter((x) => Number(x.slice(2)) <= 9);
  return {
    id: `g-${r}`,
    name: `地区组 ${r.toUpperCase()} 机房一个很长的名字`,
    region: r,
    members,
    mode: i % 2 ? "manual" : "auto",
    is_default: i === 0,
    effective_order: members,
    target: members[0],
    target_reason: "preferred",
    switchable: true,
    switch_order: members,
    mesh_backup: false,
    member_status: members.map((m, k) => ({
      id: m,
      name: `出口 ${m}`,
      region: r,
      user_position: k,
      position: k,
      eligible: true,
      ix_bound: false,
      residential: false,
      egress_v6: false,
      reasons: [],
      target: k === 0,
      actual_active: false,
      model_active: false,
      health: null,
    })),
    actual: i === 0 ? { ...NEVER_READ, state: "stale", code: "heartbeat_old", message: "枢纽这个组的心跳已停 300 秒" } : NEVER_READ,
    model: { active: members[0], reason: "preferred", alert: false, last_switch: null, observed: false, source: "panel_model" },
    in_use_by: [],
  } as RegionGroupView;
}

function hubState(): GroupHubState {
  return {
    hub_node: "hub1",
    hub_name: "hub1.example",
    server_id: "srv-hub",
    server_name: "枢纽服务器",
    readable: true,
    // Read a moment ago: the page does not read the hub again on open.
    last_read: { read_at: new Date().toISOString(), ok: true, clock_skew_sec: 0, ignored: [] },
    refreshing: false,
    loop_interval_sec: 5,
    stale_after_sec: 135,
    read_max_age_sec: 600,
    skew_warn_sec: 300,
    counts: {},
  } as GroupHubState;
}

const GROUPS_API = {
  "GET /api/region-groups": () => ({
    groups: REGIONS.map((_, i) => groupView(i)),
    default_group: "g-hk",
    thresholds: { fails_need: 3, recovers_need: 3, cooldown_sec: 1800 },
    hub_state: hubState(),
  }),
};

const CATALOG: ProbeCatalogEntry[] = Array.from({ length: 41 }, (_, i) => ({
  service: `svc-${i + 1}`,
  name: `服务 ${i + 1}`,
  reachability: i % 6 === 0,
  capability: i % 6 === 0 ? "reachability" : "region_verdict",
  basis: "公开方法（合成样本）",
  probeable: true,
  enabled: true,
  group: `g-${REGIONS[i % REGIONS.length]}`,
  group_mode: "auto",
})) as ProbeCatalogEntry[];

/** 9 exits in 5 region groups, 8 services, IPv4 only: 72 cells. */
function results(): ProbeResultRow[] {
  const out: ProbeResultRow[] = [];
  const cats = ["unlocked", "not_unlocked", "network_ok", "unknown", "failed"] as const;
  for (let s = 0; s < 8; s++) {
    for (let e = 0; e < 9; e++) {
      const g = REGIONS[e % 5];
      out.push({
        service: `svc-${s + 1}`,
        service_name: `服务 ${s + 1}`,
        exit_id: `ex${e + 1}`,
        exit_name: `出口 ${e + 1} · 一个比较长的出口名字`,
        family: "ipv4",
        state: "done",
        category: cats[(s + e) % cats.length],
        grade: cats[(s + e) % cats.length] === "unknown" ? "unknown_response" : "platform_signal",
        exit_groups: [{ id: `g-${g}`, name: `地区组 ${g.toUpperCase()}`, mode: "auto", actual_active: "", model_active: "" }],
        is_active: false,
        expired: (s + e) % 4 === 0,
        ingestible: true,
        validation: "synthetic_only",
      } as ProbeResultRow);
    }
  }
  return out;
}

function coverage(): CoverageItem[] {
  const sections = ["international", "ai", "hk", "tw", "jp", "sg", "us"];
  return Array.from({ length: 130 }, (_, i) => ({
    section: sections[i % sections.length],
    name: `项目 ${i + 1} · Example Streaming Service`,
    scripts: ["lmc999", "1-stream"],
    ...(i % 3 === 0 ? { reason: "login_required" } : { adapter: `svc-${(i % 41) + 1}` }),
    note: i % 3 === 0 ? undefined : "这一项的说明比较长，用来检查说明列是否在单元格里折行而不是把表格撑宽。",
  }));
}

const UNLOCK_API = {
  "GET /api/topology": () => topology(),
  "GET /api/status": () => panelStatus({ agent: { configured: true, ok: true }, probe_available: true } as never),
  "GET /api/unlock/catalog": () => ({ catalog: CATALOG, available: true, validation: "synthetic_only", validation_text: "合成样本", grades: [], ingest_rule: "", coverage: coverage(), reasons: { login_required: "需要登录" } }),
  "GET /api/unlock/jobs": () => ({ jobs: [], running: "", catalog: CATALOG, available: true }),
  "GET /api/unlock/results": () => ({ results: results(), validation: "synthetic_only", validation_text: "x" }),
  "GET /api/unlock": () => ({ services: [], states: {}, history: [], next_run: NOW, interval_sec: 21600, pending_apply: false, decisions: {}, owners: [] }),
  ...GROUPS_API,
};

// ------------------------------------------------------------- helpers ---

/** No safety notice (role="note" / data-safety) sits inside a collapsed explanation. */
function expectNoSafetyInsideCollapsed() {
  expect(document.querySelectorAll(".explain-more [data-safety], .explain-more .safety-notice, .explain-pop [data-safety]")).toHaveLength(0);
}

async function pickOption(label: string, option: string) {
  fireEvent.mouseDown(screen.getByRole("combobox", { name: label }));
  const el = await waitFor(() => {
    const hit = [...document.querySelectorAll<HTMLElement>(".ant-select-dropdown:not(.ant-select-dropdown-hidden) .ant-select-item-option")].find((e) => e.textContent?.includes(option));
    if (!hit) throw new Error(`no option ${option}`);
    return hit;
  });
  fireEvent.click(el);
}

function ruleRows() {
  return [...document.querySelectorAll<HTMLElement>('[data-testid^="rule-row-"]')];
}

// --------------------------------------------------------------- rules ---

describe("rules page with 165 rules", () => {
  it("paginates, keeps the global order number across pages and follows a moved row to its page", async () => {
    fakeApi(RULES_API);
    renderAt("#/rules");
    await screen.findByTestId("rule-row-r001");
    expect(ruleRows()).toHaveLength(RULES_PAGE_SIZE);
    const table = screen.getByTestId("rule-row-r001").closest(".data-table-wrap")!;
    expect(table.querySelector(".ant-pagination")).not.toBeNull();
    expect(table).toHaveTextContent("共 165 条");

    // Page 2 starts at the 51st rule, numbered 51 (not 1).
    fireEvent.click(table.querySelector(".ant-pagination-item-2")!);
    const r051 = await screen.findByTestId("rule-row-r051");
    expect(screen.getByTestId("rule-pos-r051")).toHaveTextContent(/^51$/);
    expect(screen.queryByTestId("rule-row-r001")).toBeNull();

    // Moving the first row of page 2 up puts it at 50, on page 1, and the table follows it.
    fireEvent.click(within(r051).getByRole("button", { name: `提前 ${rule(51).name}` }));
    await waitFor(() => expect(screen.getByTestId("rule-pos-r051")).toHaveTextContent(/^50$/));
    expect(screen.getByTestId("rule-row-r001")).toBeInTheDocument();
  });

  it("moves a rule to a typed position on another page and shows it there", async () => {
    fakeApi(RULES_API);
    renderAt("#/rules");
    const row = await screen.findByTestId("rule-row-r001");
    fireEvent.click(within(row).getByRole("button", { name: `移动 ${rule(1).name}` }));
    fireEvent.click(await screen.findByText("移到第 N 条…"));
    const dlg = await screen.findByRole("dialog");
    const box = within(dlg).getByLabelText("目标位置");
    await userEvent.clear(box);
    await userEvent.type(box, "120");
    await userEvent.click(within(dlg).getByRole("button", { name: /移\s*动/ }));
    await waitFor(() => expect(screen.getByTestId("rule-pos-r001")).toHaveTextContent(/^120$/));
    // Page 3 (positions 101–150) is shown: r102 moved up to 101; r101 (now 100) is on page 2.
    expect(screen.queryByTestId("rule-row-r002")).toBeNull();
    expect(screen.getByTestId("rule-pos-r102")).toHaveTextContent(/^101$/);
    expect(screen.queryByTestId("rule-row-r101")).toBeNull();
  });

  it("shows the key columns with declared widths, full text behind a cut match, one primary header action and visible safety wording", async () => {
    fakeApi(RULES_API);
    renderAt("#/rules");
    const row = await screen.findByTestId("rule-row-r004");
    const tableEl = row.closest("table")!;
    const heads = [...tableEl.querySelectorAll("thead th")].map((th) => th.textContent?.trim()).filter(Boolean);
    expect(heads).toEqual(["顺序", "规则", "去向", "要求与遮蔽", "校验", "启用", "操作"]);
    // The sum of the declared widths fits the 1016 px content box at 1280.
    expect(parseInt(tableEl.style.width, 10)).toBeLessThanOrEqual(1000);
    expect(row.querySelector("td.col-actions.ant-table-cell-fix-right")).not.toBeNull();
    // The match line is one line cut with "…": the whole text, explicit domains included, is focusable.
    // Two lines: the name (cut, focusable) with its origin tag on the same line, then the match.
    const head = row.querySelector<HTMLElement>(".rule-cell-head")!;
    expect(head.querySelector(".rule-name")).toHaveAttribute("tabindex", "0");
    const imported = screen.getByTestId("rule-row-r005").querySelector<HTMLElement>(".rule-cell-head")!;
    expect(imported.children[0]).toHaveClass("rule-name");
    expect(imported.querySelector(".ant-tag")).toHaveTextContent("导入 · 第 15 行");
    // The target is one tag plus a cut name on one line.
    const target = screen.getByTestId("rule-row-r011").querySelector<HTMLElement>(".rule-target")!;
    expect(target.querySelector(".ant-tag")).toHaveTextContent("服务组");
    expect(target.querySelector(".rule-target-name")).toHaveAttribute("tabindex", "0");
    const match = row.querySelector<HTMLElement>(".rule-cell-match")!;
    expect(match).toHaveAttribute("tabindex", "0");
    expect(match).toHaveTextContent("service-4.with-a-rather-long-subdomain.example.net · 显式域名 2 个：a-4.example.org、b-4.example.org");
    // Shadowing stays in its own wrapping column, not under the action column.
    await waitFor(() => expect(screen.getByTestId("rule-shadow-r002")).toHaveTextContent("永远不会命中（被 第 1 条 遮蔽）"));
    expect(screen.getByTestId("rule-shadow-r002").closest("td")!.className).toContain("col-flex");

    // Header: one primary action, the rest in "更多操作".
    const actions = screen.getByTestId("page-header-actions");
    expect(within(actions).getAllByRole("button").map((b) => b.textContent?.replace(/\s/g, ""))).toEqual(["添加规则", "更多"]);
    await userEvent.click(within(actions).getByRole("button", { name: "更多操作" }));
    await waitFor(() => expect(document.querySelector(".ant-dropdown:not(.ant-dropdown-hidden)")).toHaveTextContent("从 mihomo 导入"));

    // The fail-closed DNS statement is a visible safety notice; long explanations are collapsed.
    const dns = screen.getByTestId("rules-dns-note");
    expect(within(dns).getByRole("note")).toHaveAttribute("data-safety", "failclosed");
    expect(within(screen.getByTestId("rules-order-note")).getByRole("button", { name: "了解更多" })).toHaveAttribute("aria-expanded", "false");
    expect(screen.getByTestId("rules-upgrade-notes")).toHaveTextContent("升级后的解析变化（2 条）");
    expectNoSafetyInsideCollapsed();

    // 56 rule-sets: paginated in their own table, each row with its URL cut and reachable.
    const rs = await screen.findByText("RuleSet1");
    const rsTable = rs.closest(".data-table-wrap")!;
    await waitFor(() => expect(rsTable.querySelectorAll("tbody tr.ant-table-row")).toHaveLength(20));
    expect(rsTable.querySelector(".ant-pagination")).not.toBeNull();
    expect(rsTable.querySelector("td.col-ellipsis .ellipsis-text")).toHaveTextContent("https://rules.example.org/sets/very/long/path/RuleSet1.list");
  });
});

// -------------------------------------------------------------- unlock ---

describe("unlock page with 41 adapters and 9 exits", () => {
  it("draws a compact matrix in a frozen-column grid, filters by exit and keeps the full verdict readable", async () => {
    fakeApi(UNLOCK_API);
    renderAt("#/unlock");
    const matrix = await screen.findByTestId("unlock-matrix");
    expect(matrix.closest('[role="region"]')).toHaveAttribute("aria-label", "服务 × 出口矩阵，可左右滚动");
    expect(matrix.querySelectorAll("thead tr:nth-child(2) th")).toHaveLength(9);

    // Compact cell: one short word on screen, the full label for screen readers and on hover.
    const unknown = matrix.querySelector<HTMLElement>('[data-category="unknown"]')!;
    expect(unknown.firstChild?.textContent).toBe("未知");
    expect(unknown).toHaveTextContent("未知 应答无法识别");
    expect(unknown.getAttribute("title")).toContain("证据：应答无法识别");
    // 已过期 is an icon with hidden text, never a visible word that can be squeezed.
    const expired = matrix.querySelector<HTMLElement>('[data-testid^="expired-"]')!;
    expect(expired.querySelector(".sr-only")).toHaveTextContent("已过期");
    expect(expired.closest("button")!.getAttribute("aria-label")).toContain("（已过期）");

    // Hidden labels inside the scrolling grid sit in a wrapper that is positioned (styles.css:
    // ".cat-chip.compact, .matrix-btn, .matrix-expired … { position: relative }") and that is
    // itself inside the scroll box, so the box clips them and they cannot widen the document.
    const hidden = [...matrix.querySelectorAll<HTMLElement>(".sr-only")];
    expect(hidden.length).toBeGreaterThan(0);
    for (const el of hidden) {
      const holder = el.parentElement!.closest(".cat-chip.compact, .matrix-btn, .matrix-expired, .split-status");
      expect(holder).not.toBeNull();
      expect(holder!.closest(".wide-grid-scroll")).not.toBeNull();
    }

    // Filter to one exit: one column left.
    await pickOption("按出口筛选", "出口 ex3");
    await waitFor(() => expect(screen.getByTestId("unlock-matrix").querySelectorAll("thead tr:nth-child(2) th")).toHaveLength(1));

    // The probe-launcher's fail-closed note is visible; nothing safety-relevant is collapsed.
    expect(screen.getByTestId("probe-launcher").querySelector('[data-safety="failclosed"]')).not.toBeNull();
    expectNoSafetyInsideCollapsed();
  });

  it("gives the coverage table declared widths, wrapping notes and a section filter", async () => {
    fakeApi(UNLOCK_API);
    renderAt("#/unlock");
    const cov = await screen.findByTestId("coverage-table");
    const heads = [...cov.querySelectorAll("thead th")].map((th) => th.className);
    expect(heads.every((c) => /col-(fixed|flex|ellipsis)/.test(c))).toBe(true);
    expect(cov.querySelector("td.col-flex")).not.toBeNull();
    expect(cov.querySelectorAll("tbody tr.ant-table-row")).toHaveLength(20);
    await pickOption("按地区筛选覆盖表", "日本");
    await waitFor(() => {
      const rows = [...cov.querySelectorAll("tbody tr.ant-table-row")];
      expect(rows.length).toBeGreaterThan(0);
      expect(rows.every((r) => r.textContent?.startsWith("日本"))).toBe(true);
    });
    expect(within(cov).getByRole("note")).toHaveAttribute("data-safety", "unverified");
  });
});

// --------------------------------------------------------------- exits ---

describe("exits page with 7 region groups and a shared unknown cause", () => {
  it("says the mode rules once, keeps tags short and puts each card's cause on one line", async () => {
    fakeApi({ "GET /api/topology": () => topology(), ...GROUPS_API });
    renderAt("#/exits");
    const card = await screen.findByTestId("group-g-jp");
    expect(screen.getAllByTestId("group-modes-note")).toHaveLength(1);
    expect(card).not.toHaveTextContent("按顺序用第一个可用成员");
    // "未验证 · 读不到": the tag says 未验证, the rest follows as muted text.
    const split = within(card).getByTestId("group-actual").querySelector<HTMLElement>(".split-status")!;
    expect(split.querySelector(".ant-tag")).toHaveTextContent(/^未验证$/);
    expect(split).toHaveTextContent("未验证 · 读不到");
    // The cause once (the code's own text is inside the message), on one focusable line.
    const why = within(card).getByTestId("group-actual-why");
    const line = why.querySelector<HTMLElement>(".group-actual-why-text")!;
    expect(line).toHaveAttribute("tabindex", "0");
    expect(line.textContent!.match(/不知道现在由哪个枢纽承载/g)).toHaveLength(1);
    expectNoSafetyInsideCollapsed();
  });
});

describe("exits page with a backup hub whose reports are unusable for every group", () => {
  it("says each hub's shared cause once in the hub bar and shows only short tags per card", async () => {
    const changed = { state: "unavailable", code: "hub_identity_changed", message: "上次读取的不是当前枢纽（枢纽节点、服务器、地址、SSH 端口或主机指纹已变更），需要重新读取", active: "", alert: false, last_switch: null, read_at: null, hub_reported_at: null, deployed_matches: null };
    const groupsDual = REGIONS.map((_, i) => ({
      ...groupView(i),
      actual: { ...NEVER_READ },
      actual_by_hub: [
        { ...changed, tier: "primary", hub_node: "hub1", hub_name: "hub1.example", carrying: false },
        { ...changed, tier: "backup", hub_node: "hub2", hub_name: "hub2.example", carrying: false },
      ],
    }));
    const hs = (tier: "primary" | "backup", id: string) => ({ ...hubState(), tier, hub_node: id, hub_name: `${id}.example`, carrying: false });
    fakeApi({
      "GET /api/topology": () => topology(),
      "GET /api/region-groups": () => ({
        groups: groupsDual,
        default_group: "g-hk",
        thresholds: { fails_need: 3, recovers_need: 3, cooldown_sec: 1800 },
        hub_states: [hs("primary", "hub1"), hs("backup", "hub2")],
        carrying: { mode: "dual", known: false, source: "gateway", code: "not_recorded", message: "网关还没有上游记录" },
      }),
    });
    renderAt("#/exits");
    const bar = await screen.findByTestId("hub-state-bar");
    // Once per hub in the bar: one row, the shared cause on one line.
    for (const tier of ["primary", "backup"]) {
      const row = within(bar).getByTestId(`hub-row-${tier}`);
      expect(row).toHaveTextContent("各地区组的报告：未验证 · 枢纽已变更");
      expect(row.textContent!.match(/上次读取的不是当前枢纽/g)).toHaveLength(1);
    }
    // Each card: a short tag per hub, 未验证 visible, the reason only in the tooltip / hidden text.
    for (const id of REGIONS.map((r) => `g-${r}`)) {
      const reports = within(screen.getByTestId(`group-${id}`)).getByTestId("group-hub-reports");
      for (const tier of ["primary", "backup"]) {
        const short = within(reports).getByTestId(`hub-report-${tier}`);
        expect(short).toHaveAttribute("data-shared", "true");
        expect(short.querySelector(".ant-tag")).toHaveTextContent(/^未验证$/);
        expect(short.querySelector(".sr-only")).not.toBeNull();
      }
      expect(reports.querySelector(".hub-report-row")).toBeNull();
    }
  });
});

// ------------------------------------------------------------ overview ---

describe("overview tiles", () => {
  it("lays group rows out as name / mode / one short tag with the details in the tooltip", async () => {
    fakeApi({ "GET /api/topology": () => topology(), ...GROUPS_API });
    renderAt("#/");
    const row = await screen.findByTestId("groups-tile-row-g-tw");
    expect(row.querySelector(".group-row-name")).toHaveTextContent("地区组 TW 机房一个很长的名字");
    const st = within(row).getByTestId("groups-tile-status-g-tw");
    expect(st.querySelector(".ant-tag")).toHaveTextContent(/^实际未知$/);
    expect(st.querySelector(".sr-only")).toHaveTextContent("· 未验证 · 读不到");
    // 7 groups: 6 rows and a link to the rest.
    expect(document.querySelectorAll(".group-row")).toHaveLength(6);
    expect(screen.getByTestId("groups-tile-more")).toHaveTextContent("还有 1 个");
  });
});

// ------------------------------------------------------------ topology ---

describe("topology automatic layout", () => {
  it("places 15 nodes in role layers without overlapping cards", () => {
    const ns = nodes();
    const pos = autoLayout(ns);
    expect(pos.size).toBe(ns.length);
    const list = ns.map((n) => ({ id: n.id, role: n.role, ...pos.get(n.id)! }));
    for (const a of list)
      for (const b of list)
        if (a.id !== b.id) expect(Math.abs(a.x - b.x) >= 200 + 40 || Math.abs(a.y - b.y) >= 110).toBe(true);
    // Left to right: gateway, relays, IX, hubs, exits; 9 exits wrap into two columns of at most 5.
    const x = (id: string) => pos.get(id)!.x;
    expect(x("gw")).toBeLessThan(x("relay1"));
    expect(x("relay1")).toBeLessThan(x("ix1"));
    expect(x("ix1")).toBeLessThan(x("hub1"));
    expect(x("hub1")).toBeLessThan(x("ex1"));
    expect(new Set(list.filter((n) => n.role === "exit").map((n) => n.x)).size).toBe(2);
    expect(Math.max(...list.map((n) => n.y))).toBeLessThan(LAYOUT.rowsPerColumn * LAYOUT.rowHeight);
  });

  it("puts exits of one region group next to each other and a nested exit to the right of its carrier", () => {
    const ns = [...nodes(), node("ex10", "exit", "my", { via_exit: "ex2" })];
    const pos = autoLayout(ns, [{ members: ["ex9", "ex1"] }, { members: ["ex2"] }]);
    const p = (id: string) => pos.get(id)!;
    // The first group's exits (ex1, ex9) are adjacent at the top of the column, then ex2.
    expect(Math.abs(p("ex9").y - p("ex1").y)).toBe(LAYOUT.rowHeight);
    expect(Math.max(p("ex1").y, p("ex9").y)).toBeLessThan(p("ex2").y);
    expect(p("ex10").x).toBeGreaterThan(Math.max(...["ex1", "ex2", "ex3", "ex9"].map((id) => p(id).x)));
  });
});
