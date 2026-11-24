// 解锁: 确认 / 手动 in the recommendation column, the manual picker (scope
// and order), the two-step impact confirmation, 409 refresh and the
// automatic-apply line after a save. Synthetic data only.

import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { fakeApi, panelStatus, renderAt, reply } from "./testing";
import type { UnlockCellState, UnlockMatrixService, UnlockMatrixView } from "./types";
import { OK_AGENT, topology } from "./pages_fixtures";
import { currentLabel, pickGroups, pickOptions } from "./UnlockPage";

const cell = (exit_id: string, state: UnlockCellState) => ({ exit_id, state });
const EXITS = [
  { id: "hk-ix", name: "香港 IX", regions: ["hk"], groups: ["hk"], identity: "v2:aa" },
  { id: "us", name: "美国", regions: ["us"], groups: ["us"], identity: "v2:bb" },
  { id: "jp", name: "日本", regions: ["jp"], groups: ["jp"], identity: "v2:cc" },
];

function svc(id: string, name: string, over: Partial<UnlockMatrixService> = {}): UnlockMatrixService {
  return { id, name, rules: [id], targets: ["us"], cells: [cell("hk-ix", "untested"), cell("us", "untested"), cell("jp", "untested")], recommend: null, ...over };
}

const view = (services: UnlockMatrixService[]): UnlockMatrixView => ({
  running: "",
  available: true,
  regions: [{ code: "global", name: "全球", exits: EXITS, services }],
});

const rec = (exit_id: string, exit_name: string, adopted = false) => ({ exit_id, exit_name, group: exit_id, group_name: exit_name, adopted });

const base = (m: () => UnlockMatrixView) => ({
  "GET /api/topology": () => topology(),
  "GET /api/status": () => panelStatus({ ...OK_AGENT, probe_available: true }),
  "GET /api/unlock/matrix": m,
});

async function choose(box: HTMLElement, label: string, option: string) {
  fireEvent.mouseDown(within(box).getByRole("combobox", { name: label }));
  const el = await waitFor(() => {
    const hit = [...document.querySelectorAll<HTMLElement>(".ant-select-dropdown:not(.ant-select-dropdown-hidden) .ant-select-item-option")].find((e) => e.textContent?.includes(option));
    if (!hit) throw new Error(`no option ${option}`);
    return hit;
  });
  fireEvent.click(el);
}

describe("unlock: 确认 and 手动", () => {
  it("offers 确认 + 手动 with a recommendation, 在用 + 手动 when in use, only 手动 without one, nothing without rules", async () => {
    fakeApi(
      base(() =>
        view([
          svc("auto-netflix", "Netflix", { cells: [cell("hk-ix", "unlocked"), cell("us", "blocked"), cell("jp", "untested")], recommend: rec("hk-ix", "香港 IX") }),
          svc("auto-disney", "Disney+", { cells: [cell("hk-ix", "unlocked"), cell("us", "untested"), cell("jp", "untested")], recommend: rec("hk-ix", "香港 IX", true) }),
          svc("youtube-premium", "YouTube Premium"),
          svc("dazn", "DAZN", { rules: [] }),
        ]),
      ),
    );
    renderAt("#/unlock");
    const t = await screen.findByTestId("unlock-table-global");
    const nf = within(t).getByTestId("row-global-auto-netflix");
    expect(within(nf).getByRole("button", { name: "确认 Netflix → 香港 IX" })).toBeInTheDocument();
    expect(within(nf).getByRole("button", { name: "手动 Netflix" })).toBeInTheDocument();
    const dp = within(t).getByTestId("row-global-auto-disney");
    expect(within(dp).getByText("在用")).toBeInTheDocument();
    expect(within(dp).queryByRole("button", { name: /^确认/ })).toBeNull();
    expect(within(dp).getByRole("button", { name: "手动 Disney+" })).toBeInTheDocument();
    const yt = within(t).getByTestId("row-global-youtube-premium");
    expect(within(yt).queryByRole("button", { name: /^确认/ })).toBeNull();
    expect(within(yt).getByRole("button", { name: "手动 YouTube Premium" })).toBeInTheDocument();
    expect(within(within(t).getByTestId("row-global-dazn")).queryAllByRole("button")).toHaveLength(0);
    // No hint text in the column.
    expect(t.querySelector(".unlock-rec")?.textContent).not.toMatch(/选择|说明|提示/);
  });

  it("lists only the row's exits, unlocked first with the result words", () => {
    const s = svc("auto-netflix", "Netflix", { cells: [cell("hk-ix", "blocked"), cell("us", "untested"), cell("jp", "unlocked")] });
    const opts = pickOptions(view([s]).regions[0], s);
    expect(opts.map((o) => o.label)).toEqual(["日本 · 解锁", "香港 IX · 不可用", "美国 · 未测"]);
    const regional = { code: "jp", name: "日本", exits: [EXITS[2]], services: [] };
    const r = svc("auto-abema", "ABEMA", { cells: [cell("jp", "unverified")] });
    expect(pickOptions(regional, r).map((o) => o.label)).toEqual(["日本 · 未测到"]);
  });

  it("saves a manual pick through the same endpoint, confirms the impact first, and shows the apply result", async () => {
    let saved = false;
    const api = fakeApi({
      ...base(() =>
        view([
          svc("youtube-premium", "YouTube Premium", {
            cells: [cell("hk-ix", "blocked"), cell("us", "unlocked"), cell("jp", "untested")],
            recommend: rec("us", "美国", saved),
          }),
        ]),
      ),
      "POST /api/unlock/adopt": (req) => {
        const b = req.body as { preview?: boolean };
        if (b.preview) return { preview: true, group: "jp", exit: "jp", service_rules: ["youtube-premium"], other_rules: 2 };
        saved = true;
        return { updated: 1, group: "jp", exit: "jp", manual: true, apply_required: false, fast_apply: { status: "applied", version: 8 } };
      },
    });
    renderAt("#/unlock");
    const t = await screen.findByTestId("unlock-table-global");
    await userEvent.click(within(t).getByRole("button", { name: "手动 YouTube Premium" }));
    const box = await screen.findByTestId("manual-global-youtube-premium");
    expect(within(box).getByRole("button", { name: /^保存/ })).toBeDisabled();
    await choose(box, "YouTube Premium 出口", "日本 · 未测");
    await userEvent.click(within(box).getByRole("button", { name: "保存 YouTube Premium → 日本" }));
    await waitFor(() => expect(box).toHaveTextContent("同时影响 2 条规则"));
    expect(api.find("POST /api/unlock/adopt")).toHaveLength(1);
    expect(api.find("POST /api/unlock/adopt")[0].body).toEqual({ service: "youtube-premium", exit: "jp", manual: true, identity: "v2:cc", preview: true });
    await userEvent.click(within(box).getByRole("button", { name: "保存 YouTube Premium → 日本" }));
    await waitFor(() => expect(api.find("POST /api/unlock/adopt")).toHaveLength(2));
    expect(api.find("POST /api/unlock/adopt")[1].body).toEqual({ service: "youtube-premium", exit: "jp", manual: true, identity: "v2:cc" });
    expect(await screen.findByTestId("rules-apply-line")).toHaveTextContent("已生效（v8）");
    // The picker closes; the result words stay what was measured.
    await waitFor(() => expect(screen.queryByTestId("manual-global-youtube-premium")).toBeNull());
    expect(within(screen.getByTestId("row-global-youtube-premium")).getByTestId("cell-jp")).toHaveTextContent("未测");
  });

  it("a refused manual save (409) shows the error, saves nothing and reloads the table", async () => {
    const api = fakeApi({
      ...base(() => view([svc("youtube-premium", "YouTube Premium")])),
      "POST /api/unlock/adopt": () => reply(409, { error: "出口配置已变化，探测结果不再对应这个出口；刷新后再选" }),
    });
    renderAt("#/unlock");
    const t = await screen.findByTestId("unlock-table-global");
    const loads = api.find("GET /api/unlock/matrix").length;
    await userEvent.click(within(t).getByRole("button", { name: "手动 YouTube Premium" }));
    const box = await screen.findByTestId("manual-global-youtube-premium");
    await choose(box, "YouTube Premium 出口", "美国 · 未测");
    await userEvent.click(within(box).getByRole("button", { name: "保存 YouTube Premium → 美国" }));
    expect(await screen.findByText(/出口配置已变化/)).toBeInTheDocument();
    await waitFor(() => expect(api.find("GET /api/unlock/matrix").length).toBeGreaterThan(loads));
    expect(api.find("POST /api/unlock/adopt")).toHaveLength(1);
    expect(screen.queryByTestId("rules-apply-line")).toBeNull();
  });

  it("确认 with an impact asks once more, then shows 将自动生效", async () => {
    const api = fakeApi({
      ...base(() => view([svc("auto-netflix", "Netflix", { cells: [cell("hk-ix", "unlocked"), cell("us", "untested"), cell("jp", "untested")], recommend: rec("hk-ix", "香港 IX") })])),
      "POST /api/unlock/adopt": (req) =>
        (req.body as { preview?: boolean }).preview
          ? { preview: true, group: "hk-ix", exit: "hk-ix", service_rules: ["auto-netflix"], other_rules: 3 }
          : { updated: 1, group: "hk-ix", exit: "hk-ix", apply_required: false, fast_apply: { status: "scheduled" } },
    });
    renderAt("#/unlock");
    await screen.findByTestId("unlock-table-global");
    await userEvent.click(screen.getByRole("button", { name: "确认 Netflix → 香港 IX" }));
    const box = await screen.findByTestId("adopt-confirm-auto-netflix");
    expect(box).toHaveTextContent("同时影响 3 条规则");
    await userEvent.click(within(box).getByRole("button", { name: "确认采用 Netflix → 香港 IX" }));
    await waitFor(() => expect(api.find("POST /api/unlock/adopt")).toHaveLength(2));
    expect(api.find("POST /api/unlock/adopt")[1].body).toEqual({ service: "auto-netflix", exit: "hk-ix" });
    expect(await screen.findByTestId("rules-apply-line")).toHaveTextContent("将自动生效");
  });

  it("offers 出口组 (name · preferred) before 具体节点, and shows the current direction apart from the recommendation", async () => {
    const s = svc("auto-netflix", "Netflix", {
      cells: [cell("hk-ix", "blocked"), cell("us", "untested"), cell("jp", "unlocked")],
      groups: [{ id: "hk", name: "香港", preferred: "hk-ix", preferred_name: "香港 IX", identity: "gv2:hk" }],
      current: { group: "hk", group_name: "香港", exit: "hk-ix", exit_name: "香港 IX", pinned: false },
      recommend: rec("jp", "日本"),
    });
    const g = pickGroups(view([s]).regions[0], s);
    expect(g.map((x) => x.label)).toEqual(["出口组", "具体节点"]);
    expect(g[0].options.map((o) => o.label)).toEqual(["香港 · 香港 IX"]);
    expect(g[1].options.map((o) => o.label)).toEqual(["日本 · 解锁", "香港 IX · 不可用", "美国 · 未测"]);
    expect(currentLabel({ exit: "hk-2", exit_name: "hk2", pinned: true })).toBe("hk2（固定出口）");
    expect(currentLabel(null)).toBe("");
    expect(
      currentLabel({ pinned: false, mixed: [{ group: "hk", group_name: "香港住宅", exit: "hk-2", exit_name: "hk2", pinned: false }, { exit: "hk-8", exit_name: "hk8", pinned: true }] }),
    ).toBe("香港住宅 · hk2 / hk8（固定出口）");
    fakeApi(base(() => view([s])));
    renderAt("#/unlock");
    const t = await screen.findByTestId("unlock-table-global");
    expect(within(t).getByTestId("current-global-auto-netflix")).toHaveTextContent("香港 · 香港 IX");
    expect(within(t).getByRole("columnheader", { name: "当前" })).toBeInTheDocument();
  });

  it("a group pick sends group + identity without impact, refreshes the matrix and the Rules page target", async () => {
    let saved = false;
    const s = () =>
      svc("auto-netflix", "Netflix", {
        cells: [cell("hk-ix", "unlocked"), cell("us", "untested"), cell("jp", "untested")],
        groups: [{ id: "hk", name: "香港", preferred: "hk-ix", preferred_name: "香港 IX", identity: "gv2:hk" }],
        current: saved ? { exit: "hk-ix", exit_name: "香港 IX", pinned: true } : { group: "hk", group_name: "香港", exit: "hk-2", exit_name: "香港二号", pinned: false },
        recommend: rec("hk-ix", "香港 IX"),
      });
    const topo = () => {
      const t = topology();
      if (saved) t.rules = t.rules.map((r) => (r.id === "auto-netflix" ? { ...r, target_group: undefined, target_exit: "hk-ix" } : r));
      return t;
    };
    const api = fakeApi({
      ...base(() => view([s()])),
      "GET /api/topology": () => topo(),
      "POST /api/unlock/adopt": (req) => {
        const b = req.body as { preview?: boolean; group?: string };
        if (b.preview) return { preview: true, kind: b.group ? "group" : "exit", group: b.group ?? "", exit: "hk-ix", service_rules: ["auto-netflix"], other_rules: 0 };
        saved = true;
        return { updated: 1, kind: b.group ? "group" : "exit", group: b.group ?? "", exit: "hk-ix", manual: true, rules: ["auto-netflix"], apply_required: false, fast_apply: { status: "applied", version: 9 } };
      },
    });
    renderAt("#/unlock");
    const t = await screen.findByTestId("unlock-table-global");
    await userEvent.click(within(t).getByRole("button", { name: "手动 Netflix" }));
    let box = await screen.findByTestId("manual-global-auto-netflix");
    await choose(box, "Netflix 出口", "香港 · 香港 IX");
    await userEvent.click(within(box).getByRole("button", { name: "保存 Netflix → 香港" }));
    await waitFor(() => expect(api.find("POST /api/unlock/adopt")).toHaveLength(2));
    expect(api.find("POST /api/unlock/adopt")[1].body).toEqual({ service: "auto-netflix", exit: "", manual: true, identity: "gv2:hk", group: "hk" });
    expect(await screen.findByTestId("rules-apply-line")).toHaveTextContent("已生效（v9）");
    saved = false;
    // A pinned exit: e:<id>, the exit's identity; then the Rules page shows the pin.
    await userEvent.click(within(screen.getByTestId("unlock-table-global")).getByRole("button", { name: "手动 Netflix" }));
    box = await screen.findByTestId("manual-global-auto-netflix");
    await choose(box, "Netflix 出口", "香港 IX · 解锁");
    await userEvent.click(within(box).getByRole("button", { name: "保存 Netflix → 香港 IX" }));
    await waitFor(() => expect(api.find("POST /api/unlock/adopt")).toHaveLength(4));
    expect(api.find("POST /api/unlock/adopt")[3].body).toEqual({ service: "auto-netflix", exit: "hk-ix", manual: true, identity: "v2:aa" });
    await waitFor(() => expect(screen.getByTestId("current-global-auto-netflix")).toHaveTextContent("香港 IX（固定出口）"));
    const topoLoads = api.find("GET /api/topology").length;
    expect(topoLoads).toBeGreaterThan(1);
    window.location.hash = "#/rules";
    const row = await screen.findByTestId("rule-row-auto-netflix");
    await waitFor(() => expect(row).toHaveTextContent("香港 IX"));
  });
});
