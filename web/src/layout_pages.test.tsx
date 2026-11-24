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
import { fakeApi, renderAt, tableBudgets } from "./testing";
import { GROUPS_API, NEVER_READ, REGIONS, RULES_API, UNLOCK_API, groupView, hubState, node, nodes, rule, topology } from "./layout_fixtures";

afterEach(() => {
  vi.restoreAllMocks();
  sessionStorage.clear();
  localStorage.clear();
});

// ------------------------------------------------------------- helpers ---

/** Every rendered DataTable fits its container at 1280 (TABLE_BUDGET, see table_budget.test.tsx). */
function expectTablesWithinBudget(min: number) {
  const tables = tableBudgets();
  expect(tables.length).toBeGreaterThanOrEqual(min);
  const over = tables.filter((t) => t.width > t.budget);
  expect(over, over.map((t) => `${t.name} in ${t.container}: ${t.width} > ${t.budget}`).join("; ")).toEqual([]);
}

/** No safety notice (role="note" / data-safety) sits inside a collapsed explanation. */
function expectNoSafetyInsideCollapsed() {
  expect(document.querySelectorAll(".explain-more [data-safety], .explain-more .safety-notice, .explain-pop [data-safety], .field-help-content [data-safety]")).toHaveLength(0);
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
    // The sum of the declared widths (with the expand column) fits the 1016 px content box at 1280.
    expect(parseInt(tableEl.style.width, 10)).toBeLessThanOrEqual(1016);
    expect(row.querySelector("td.col-actions.ant-table-cell-fix-right")).not.toBeNull();
    // The match line is one line cut with "…": the whole text, explicit domains included, is focusable.
    // Two lines: the name (cut, focusable) with its origin word on the same line (muted text, not a tag), then the match.
    const head = row.querySelector<HTMLElement>(".rule-cell-head")!;
    expect(head.querySelector(".rule-name")).toHaveAttribute("tabindex", "0");
    const imported = screen.getByTestId("rule-row-r005").querySelector<HTMLElement>(".rule-cell-head")!;
    expect(imported.children[0]).toHaveClass("rule-name");
    expect(imported.querySelector(".state-word")).toHaveTextContent("导入 · 第 15 行");
    expect(imported.querySelector(".ant-tag")).toBeNull();
    // The target is its kind (one muted word) plus its name on one line.
    const target = screen.getByTestId("rule-row-r011").querySelector<HTMLElement>(".rule-target")!;
    expect(target.querySelector(".state-word")).toHaveTextContent("地区组");
    expect(target.querySelector(".rule-target-name")).toBeTruthy();
    const match = row.querySelector<HTMLElement>(".rule-cell-match")!;
    expect(match).toHaveAttribute("tabindex", "0");
    expect(match).toHaveTextContent("service-4.with-a-rather-long-subdomain.example.net · 显式域名 2 个：a-4.example.org、b-4.example.org");
    // Shadowing: a compact indicator in its own fixed column (never under the action column);
    // the full text is one click away in the row's detail.
    const hint = await screen.findByTestId("rule-hints-r002");
    expect(hint).toHaveTextContent("不会命中");
    expect(hint.closest("td")!.className).toContain("col-fixed");
    expect(hint).toHaveAttribute("aria-label", expect.stringContaining("永远不会命中（被 第 1 条 遮蔽）"));
    fireEvent.click(hint);
    await waitFor(() => expect(screen.getByTestId("rule-shadow-r002")).toHaveTextContent("永远不会命中（被 第 1 条 遮蔽）"));
    expect(screen.getByTestId("rule-shadow-r002").closest("tr")!.className).toContain("ant-table-expanded-row");

    // Header: one primary action, the rest in "更多操作".
    const actions = screen.getByTestId("page-header-actions");
    expect(within(actions).getAllByRole("button").map((b) => b.getAttribute("aria-label") ?? b.textContent?.replace(/\s/g, ""))).toEqual(["添加规则", "更多操作"]);
    await userEvent.click(within(actions).getByRole("button", { name: "更多操作" }));
    await waitFor(() => expect(document.querySelector(".ant-dropdown:not(.ant-dropdown-hidden)")).toHaveTextContent("从 mihomo 导入"));

    // The fail-closed DNS statement is a visible safety notice; long explanations are collapsed.
    const dns = screen.getByTestId("rules-dns-note");
    expect(within(dns).getByRole("note")).toHaveAttribute("data-safety", "failclosed");
    // Section notes live in the usage guide, not on the page.
    expect(screen.getByTestId("page-help")).not.toBeVisible();
    expect(screen.getByTestId("rules-order-note").querySelector(".explain-toggle")).toBeNull();
    expect(screen.getByTestId("rules-upgrade-notes")).toHaveTextContent("升级后的解析变化（2 条）");
    expectNoSafetyInsideCollapsed();

    // 56 rule-sets: paginated in their own table, each row with its URL cut and reachable.
    const rs = await screen.findByText("RuleSet1");
    const rsTable = rs.closest(".data-table-wrap")!;
    await waitFor(() => expect(rsTable.querySelectorAll("tbody tr.ant-table-row")).toHaveLength(20));
    expect(rsTable.querySelector(".ant-pagination")).not.toBeNull();
    expect(rsTable.querySelector("td.col-ellipsis .ellipsis-text")).toHaveTextContent("https://rules.example.org/sets/very/long/path/RuleSet1.list");
    // Rules table (page) and rule-sets (section) fit their containers at 1280.
    expectTablesWithinBudget(2);
  });
});

// -------------------------------------------------------------- unlock ---

describe("unlock page with 41 services and 9 exits", () => {
  it("draws each region as a scrollable service × exit table that fits its section", async () => {
    fakeApi(UNLOCK_API);
    renderAt("#/unlock");
    const global = await screen.findByTestId("unlock-table-global");
    expect(global.closest('[role="region"]')).toHaveAttribute("aria-label", "全球：服务 × 出口");
    expect(global.querySelectorAll("thead th")).toHaveLength(9 + 3); // 服务, 9 exits, 当前, 推荐
    expect(global.querySelectorAll("tbody tr")).toHaveLength(41);
    for (const r of REGIONS.slice(0, 5)) expect(screen.getByTestId(`unlock-table-${r}`)).toBeInTheDocument();
    // A cell with a reason is focusable and reads the reason.
    const why = global.querySelector<HTMLElement>('[data-state="unverified"][tabindex="0"]')!;
    expect(why.getAttribute("aria-label")).toContain("出口地址未确认");
    expect(document.querySelector('input[type="checkbox"]')).toBeNull();
  });
});

// --------------------------------------------------------------- exits ---

describe("exits page with 7 region groups and a shared unknown cause", () => {
  it("says the mode rules once, keeps tags short and puts each card's cause on one line", async () => {
    fakeApi({ "GET /api/topology": () => topology(), ...GROUPS_API });
    renderAt("#/exits", { foldsOpen: true });
    const card = await screen.findByTestId("group-g-jp");
    expect(screen.getAllByTestId("group-modes-note")).toHaveLength(1);
    expect(card).not.toHaveTextContent("按顺序用第一个可用成员");
    // "未验证 · 读不到": the tag says 未验证, the rest follows as muted text.
    const split = within(card).getByTestId("group-actual").querySelector<HTMLElement>(".split-status")!;
    // Not a problem: plain muted text, no coloured tag.
    expect(split.querySelector(".status-text")).toHaveTextContent(/^未验证$/);
    expect(split.querySelector(".ant-tag")).toBeNull();
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
    renderAt("#/exits", { foldsOpen: true });
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
        expect(short.querySelector(".status-text")).toHaveTextContent(/^未验证$/);
        expect(short.querySelector(".sr-only")).not.toBeNull();
      }
      expect(reports.querySelector(".hub-report-row")).toBeNull();
    }
  });
});

// ------------------------------------------------------------ overview ---

describe("overview tiles", () => {
  it("lays group rows out as name / mode / one short status with the details in the tooltip", async () => {
    fakeApi({ "GET /api/topology": () => topology(), ...GROUPS_API });
    renderAt("#/");
    const row = await screen.findByTestId("groups-tile-row-g-jp");
    expect(row.querySelector(".group-row-name")).toHaveTextContent(/^地区组 JP/);
    const st = within(row).getByTestId("groups-tile-status-g-jp");
    expect(st.querySelector(".status-text")).toHaveTextContent(/^实际未知$/);
    expect(st.querySelector(".sr-only")).toHaveTextContent("· 未验证 · 读不到");
    // The exits card lists every group up to 8 next to the chart.
    expect(document.querySelectorAll(".group-row")).toHaveLength(7);
    expect(screen.queryByTestId("groups-tile-more")).toBeNull();
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
