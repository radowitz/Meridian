import { MeshLegRows } from "./MeshLegQuality";
// Interaction tests of the operational pages against the in-memory fake
// API (split out of the former pages.test.tsx; helpers and fixtures in
// pages_fixtures.tsx).
//
// Region groups and their hub-reported state, same-named groups, the primary
// and backup hub, relay sharing, nested and external SOCKS exits and their
// credentials, and the overview tiles built from them.

import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it } from "vitest";
import { fakeApi, renderAt, reply, webStorageDump } from "./testing";
import { clearCooldowns } from "./ui";
import { PATH_QUALITY_DEFAULTS } from "./types";
import type {
  GroupHubState,
  Node,
  RegionGroupView,
  Topology,
  Sharing,
} from "./types";
import {
  NOW,
  btn,
  confirmModal,
  pick,
  menuItem,
  exitNode,
  topology,
  member,
  NEVER_READ,
  actualOK,
  hubState,
  group,
  THRESHOLDS,
  server,
} from "./pages_fixtures";

// -------------------------------------------------------- region groups ---

describe("region groups", () => {
  it("reorders members locally and saves the whole order with one PATCH", async () => {
    let g = group();
    const api = fakeApi({
      "GET /api/topology": () => topology(),
      "GET /api/region-groups": () => ({ groups: [g], default_group: "hk", thresholds: THRESHOLDS }),
      "PATCH /api/region-groups/:id": (req) => {
        g = group({ members: (req.body as { members: string[] }).members });
        return { group: g, apply_required: true };
      },
    });
    renderAt("#/exits", { foldsOpen: true });
    const card = await screen.findByTestId("group-hk");
    // Move 香港二号 (user position 1) down twice: hk-ix, hk-resi, hk-2.
    await userEvent.click(within(card).getByRole("button", { name: "下移 香港二号" }));
    await userEvent.click(within(card).getByRole("button", { name: "下移 香港二号" }));
    expect(api.find("PATCH /api/region-groups/hk")).toHaveLength(0);
    await userEvent.click(within(card).getByRole("button", { name: btn("保存顺序") }));
    await waitFor(() => expect(api.find("PATCH /api/region-groups/hk")).toHaveLength(1));
    expect(api.find("PATCH /api/region-groups/hk")[0].body).toEqual({ members: ["hk-ix", "hk-resi", "hk-2"] });
    // Document-only change: the page and the top bar say an install is needed.
    expect(await screen.findByText(/地区组已修改，但还没有安装到网关/)).toBeInTheDocument();
  });

  it("explains the effective order and exclusions in plain words", async () => {
    fakeApi({
      "GET /api/topology": () => topology(),
      "GET /api/region-groups": () => ({ groups: [group()], default_group: "hk", thresholds: THRESHOLDS }),
    });
    renderAt("#/exits", { foldsOpen: true });
    const card = await screen.findByTestId("group-hk");
    expect(within(card).getByText("IX 绑定的出口排在用户顺序之前。")).toBeInTheDocument();
    expect(within(card).getByText("组排除家宽，这个出口是家宽。")).toBeInTheDocument();
    expect(within(screen.getByTestId("member-hk-hk-resi")).getByText("已排除")).toBeInTheDocument();
    expect(within(card).getByTestId("effective-order")).toHaveTextContent("香港 IX → 香港二号");
    expect(within(card).getByText("默认组")).toBeInTheDocument();
  });

  it("switches to manual with a choice, then changes the choice and the on-failure behaviour", async () => {
    let g = group();
    const api = fakeApi({
      "GET /api/topology": () => topology(),
      "GET /api/region-groups": () => ({ groups: [g], default_group: "hk", thresholds: THRESHOLDS }),
      "PATCH /api/region-groups/:id": (req) => {
        const b = req.body as Partial<RegionGroupView>;
        g = group({ ...g, ...b, on_failure_effective: b.on_failure ?? g.on_failure_effective, model: { ...g.model, reason: "chosen", active: b.chosen ?? g.chosen ?? "hk-ix" } });
        return { group: g, apply_required: true };
      },
    });
    renderAt("#/exits", { foldsOpen: true });
    const card = await screen.findByTestId("group-hk");
    fireEvent.click(within(card).getByRole("radio", { name: "手动" }));
    await waitFor(() => expect(api.find("PATCH /api/region-groups/hk")).toHaveLength(1));
    expect(api.find("PATCH /api/region-groups/hk")[0].body).toEqual({ mode: "manual", chosen: "hk-ix", on_failure: "hold" });

    // Both on-failure options are explained.
    await within(card).findByText("保持并告警");
    expect(card).toHaveTextContent("临时回落并告警");
    await pick("香港（机房） 的指定成员", "香港二号", card);
    await waitFor(() => expect(api.find("PATCH /api/region-groups/hk")).toHaveLength(2));
    expect(api.find("PATCH /api/region-groups/hk")[1].body).toEqual({ chosen: "hk-2" });

    await userEvent.click(within(card).getByRole("radio", { name: /临时回落并告警/ }));
    await waitFor(() => expect(api.find("PATCH /api/region-groups/hk")).toHaveLength(3));
    expect(api.find("PATCH /api/region-groups/hk")[2].body).toEqual({ on_failure: "fallback" });
    // Excluded members cannot be chosen.
    fireEvent.mouseDown(within(card).getByRole("combobox", { name: "香港（机房） 的指定成员" }));
    const resi = await waitFor(() => {
      const el = [...document.querySelectorAll(".ant-select-item-option")].find((e) => e.textContent?.includes("香港住宅"));
      if (!el) throw new Error("missing");
      return el;
    });
    expect(resi).toHaveClass("ant-select-item-option-disabled");
  });

  it("labels the live state as the panel's model, unverified without samples, and shows an alert", async () => {
    const alerting = group({
      id: "us",
      name: "美国",
      region: "us",
      members: ["us"],
      member_status: [member("us", "美国", { region: "us", target: true, health: { up: false, fails: 3, goods: 0, last_ok: false, ok_since: null, last_at: NOW } })],
      effective_order: ["us"],
      target: "us",
      is_default: false,
      in_use_by: [],
      model: {
        active: "",
        reason: "none",
        alert: true,
        alert_message: "组内没有可用的出口，引用它的规则不会生效。",
        last_switch: NOW,
        observed: true,
        source: "panel_model",
      },
    });
    fakeApi({
      "GET /api/topology": () => topology(),
      "GET /api/region-groups": () => ({ groups: [group(), alerting], default_group: "hk", thresholds: THRESHOLDS }),
    });
    renderAt("#/exits", { foldsOpen: true });
    const hk = await screen.findByTestId("group-hk");
    const hkLive = within(hk).getByTestId("group-live");
    expect(within(hk).getByTestId("group-model")).toHaveTextContent("按配置应使用");
    expect(within(hk).getByTestId("group-model").querySelector('[data-status="unverified"]')).toHaveTextContent("仅配置参考 · 未收到组健康报告");
    // Without a hub read the member in use is unknown, not the target.
    expect(within(hk).getByTestId("group-actual")).toHaveTextContent("实际使用未知");
    expect(within(hk).getByTestId("group-actual")).not.toHaveTextContent("香港 IX");
    expect(hkLive.querySelector('[data-testid="group-actual"] [data-status="unverified"]')).toHaveTextContent("未验证");
    expect(within(hk).queryByText("使用中")).toBeNull();

    const us = screen.getByTestId("group-us");
    // The model's alert is labelled as the model's; the actual line stays unknown.
    expect(within(us).getByTestId("group-model")).toHaveTextContent("面板推算");
    expect(within(us).getByTestId("group-model-alert")).toHaveTextContent("面板推算：组内没有可用的出口");
    expect(within(us).getByTestId("group-actual")).toHaveTextContent("未知");
    expect(within(us).queryByTestId("group-alert")).toBeNull();
    expect(within(screen.getByTestId("member-us-us")).getByText("不可用")).toBeInTheDocument();
  });

  it("refuses a delete with the referrers as links", async () => {
    fakeApi({
      "GET /api/topology": () => topology(),
      "GET /api/region-groups": () => ({ groups: [group()], default_group: "hk", thresholds: THRESHOLDS }),
      "DELETE /api/region-groups/:id": () =>
        reply(409, {
          error: "地区组 香港（机房） 仍被 2 处引用（规则或默认境外组），先改掉这些引用",
          code: "in_use",
          in_use_by: [
            { kind: "settings", id: "default_group", name: "默认境外组" },
            { kind: "rule", id: "auto-netflix", name: "Netflix" },
          ],
        }),
    });
    renderAt("#/exits", { foldsOpen: true });
    const card = await screen.findByTestId("group-hk");
    await userEvent.click(within(card).getByRole("button", { name: /删除/ }));
    await confirmModal("删除");
    const refused = await screen.findByTestId("refused-dialog");
    expect(refused).toHaveTextContent("先改掉这些引用");
    expect(within(refused).getByRole("link", { name: "Netflix" })).toHaveAttribute("href", "#/rules/auto-netflix");
    expect(within(refused).getByRole("link", { name: "默认境外组" })).toHaveAttribute("href", "#/exits");
  });

  it("lists exits that belong to no group", async () => {
    fakeApi({
      "GET /api/topology": () => topology(),
      "GET /api/region-groups": () => ({ groups: [group()], default_group: "hk", thresholds: THRESHOLDS }),
    });
    renderAt("#/exits", { foldsOpen: true });
    const box = await screen.findByTestId("ungrouped");
    expect(box).toHaveTextContent("美国");
    expect(box).not.toHaveTextContent("香港二号");
    // One list of exit nodes: the ungrouped ones come first, each with 「加入组…」.
    expect(screen.getByTestId("fold-exit-nodes")).toContainElement(box);
    expect(within(box).getAllByRole("button", { name: /加入组/ }).length).toBeGreaterThan(0);
    expect(within(screen.getByTestId("exit-nodes")).queryByRole("button", { name: /加入组/ })).toBeNull();
  });
});

describe("region groups: the hub's actual state", () => {
  const observedModel = { active: "hk-2", reason: "failover", alert: false, last_switch: NOW, observed: true, source: "panel_model" };

  it("shows the hub's member, reason and times only from an ok report, the model separately", async () => {
    const g = group({
      actual: actualOK("hk-2"),
      model: { ...observedModel, active: "hk-ix", reason: "preferred" },
      member_status: group().member_status.map((m) => ({ ...m, actual_active: m.id === "hk-2", model_active: m.id === "hk-ix" })),
    });
    fakeApi({
      "GET /api/topology": () => topology(),
      "GET /api/region-groups": () => ({ groups: [g], default_group: "hk", thresholds: THRESHOLDS, hub_state: hubState() }),
    });
    renderAt("#/exits", { foldsOpen: true });
    const card = await screen.findByTestId("group-hk");
    const actual = within(card).getByTestId("group-actual");
    expect(actual).toHaveAttribute("data-state", "ok");
    expect(actual).toHaveTextContent("实际使用香港二号");
    expect(actual).toHaveTextContent("前面的成员不可用，自动切到后面的成员");
    expect(actual).toHaveTextContent("上次切换");
    expect(actual).toHaveTextContent("读取于");
    expect(actual.querySelector('[data-status="ok"]')).toHaveTextContent("枢纽报告");
    // 使用中 follows the hub; the model's member is only 推算在用.
    expect(within(screen.getByTestId("member-hk-hk-2")).getByText("使用中")).toBeInTheDocument();
    expect(within(screen.getByTestId("member-hk-hk-ix")).queryByText("使用中")).toBeNull();
    expect(within(card).getByTestId("group-model")).toHaveTextContent("面板推算");
    expect(within(card).getByTestId("group-model")).not.toHaveTextContent("实际使用");
  });

  it("with only the model, never says 实际使用 of a member nor 使用中", async () => {
    const g = group({
      model: observedModel,
      member_status: group().member_status.map((m) => ({ ...m, model_active: m.id === "hk-2" })),
    });
    fakeApi({
      "GET /api/topology": () => topology(),
      "GET /api/region-groups": () => ({ groups: [g], default_group: "hk", thresholds: THRESHOLDS, hub_state: hubState({ readable: false, not_readable_code: "server_not_ready", not_readable_message: "服务器 枢纽服务器 的主机指纹还没有确认", last_read: null }) }),
    });
    renderAt("#/exits", { foldsOpen: true });
    const card = await screen.findByTestId("group-hk");
    const actual = within(card).getByTestId("group-actual");
    expect(actual).toHaveTextContent("实际使用未知");
    expect(actual).not.toHaveTextContent("香港二号");
    expect(actual.querySelector('[data-status="unverified"]')).toHaveTextContent("未验证");
    expect(within(card).queryByText("使用中")).toBeNull();
    expect(within(screen.getByTestId("member-hk-hk-2")).getByText("推算在用")).toBeInTheDocument();
    expect(within(card).getByTestId("group-model")).toHaveTextContent("面板推算香港二号");
    // The hub cannot be read: why, and where to fix it; no automatic read.
    const bar = screen.getByTestId("hub-state-bar");
    expect(within(bar).getByTestId("hub-not-readable")).toHaveTextContent("主机指纹还没有确认");
    expect(within(bar).getByRole("link", { name: /服务器页/ })).toHaveAttribute("href", "#/servers/srv-hub");
    expect(within(bar).getByRole("button", { name: /读取枢纽状态/ })).toBeDisabled();
  });

  it("explains stale, version mismatch and failed switches with their fix and no member", async () => {
    const groups = [
      group({ id: "a", name: "甲", actual: { ...NEVER_READ, state: "stale", code: "heartbeat_old", message: "枢纽这个组的心跳已停 300 秒（超过 135 秒）", read_at: NOW } }),
      group({ id: "b", name: "乙", is_default: false, actual: { ...NEVER_READ, state: "version_mismatch", code: "plan_differs", message: "枢纽还没有按当前拓扑装机", read_at: NOW, deployed_matches: false } }),
      group({
        id: "c",
        name: "丙",
        is_default: false,
        actual: { ...NEVER_READ, state: "switch_failed", code: "hop_failed", message: "枢纽切换到 hk-2 的路由命令失败", read_at: NOW, reported: { hop: "hk-ix", want: "hk-2", failed_at: NOW } },
      }),
    ];
    fakeApi({
      "GET /api/topology": () => topology(),
      "GET /api/region-groups": () => ({ groups, default_group: "a", thresholds: THRESHOLDS, hub_state: hubState() }),
    });
    renderAt("#/exits", { foldsOpen: true });
    const a = await screen.findByTestId("group-a");
    expect(within(a).getByTestId("group-actual")).toHaveTextContent("未验证 · 状态过期");
    expect(within(a).getByTestId("group-actual-why")).toHaveTextContent("心跳已停");
    expect(within(a).getByRole("button", { name: /重新读取/ })).toBeEnabled();
    const b = screen.getByTestId("group-b");
    expect(within(b).getByTestId("group-actual")).toHaveTextContent("未验证 · 枢纽不是当前配置");
    expect(within(b).getByRole("link", { name: /部署页/ })).toHaveAttribute("href", "#/deploy");
    const c = screen.getByTestId("group-c");
    expect(within(c).getByTestId("group-actual").querySelector('[data-status="failed"]')).toHaveTextContent("切换失败");
    expect(within(c).getByTestId("group-actual-why")).toHaveTextContent("枢纽报告（未确认）：路由表 香港 IX，想切到 香港二号");
    for (const card of [a, b, c]) {
      expect(within(card).getByTestId("group-actual")).toHaveTextContent("实际使用未知");
      expect(within(card).queryByText("使用中")).toBeNull();
    }
  });

  it("reads the hub once when the page opens and again on request", async () => {
    let g = group();
    let reads = 0;
    const api = fakeApi({
      "GET /api/topology": () => topology(),
      "GET /api/region-groups": () => ({ groups: [g], default_group: "hk", thresholds: THRESHOLDS, hub_state: hubState({ last_read: null }) }),
      "POST /api/region-groups/runtime/refresh": () => {
        reads++;
        g = group({ actual: actualOK("hk-2", { read_at: new Date().toISOString() }) });
        return { groups: [g], default_group: "hk", thresholds: THRESHOLDS, hub_state: hubState({ last_read: { read_at: new Date().toISOString(), ok: true, ignored: [] } }) };
      },
    });
    renderAt("#/exits", { foldsOpen: true });
    await waitFor(() => expect(api.find("POST /api/region-groups/runtime/refresh")).toHaveLength(1));
    const card = await screen.findByTestId("group-hk");
    await waitFor(() => expect(within(card).getByTestId("group-actual")).toHaveTextContent("实际使用香港二号"));
    expect(api.find("POST /api/region-groups/runtime/refresh")[0].body).toBeUndefined();
    await userEvent.click(within(screen.getByTestId("hub-state-bar")).getByRole("button", { name: /读取枢纽状态/ }));
    await waitFor(() => expect(reads).toBe(2));
    // No polling: nothing more without a click.
    await new Promise((r) => setTimeout(r, 50));
    expect(reads).toBe(2);
  });

  it("shows a read of another hub identity as unknown with the reason, and reads the current hub", async () => {
    const changed = "上次读取的不是当前的枢纽（服务器、地址已变更）；旧报告不再采信，需要对当前枢纽重新读取";
    const g = group({
      actual: { ...NEVER_READ, state: "unavailable", code: "hub_identity_changed", message: changed, read_at: NOW },
      model: observedModel,
      member_status: group().member_status.map((m) => ({ ...m, model_active: m.id === "hk-2" })),
    });
    // The stored read is recent, but of another identity: it is read again.
    let hub = hubState({
      last_read: { read_at: new Date().toISOString(), ok: true, ignored: [], current_hub: false, identity_code: "hub_identity_changed", identity_message: changed },
    });
    const api = fakeApi({
      "GET /api/topology": () => topology(),
      "GET /api/region-groups": () => ({ groups: [g], default_group: "hk", thresholds: THRESHOLDS, hub_state: hub }),
      // The hub changes again while this read runs: the result is discarded.
      "POST /api/region-groups/runtime/refresh": () => {
        hub = hubState({ server_name: "新枢纽服务器", last_read: hub.last_read });
        return reply(409, { error: "读取期间枢纽的服务器已变更，这次读取的结果已丢弃，没有作为当前状态保存；请对当前枢纽重新读取", code: "hub_identity_changed" });
      },
    });
    renderAt("#/exits", { foldsOpen: true });
    const card = await screen.findByTestId("group-hk");
    const actual = within(card).getByTestId("group-actual");
    expect(actual).toHaveAttribute("data-state", "unavailable");
    expect(actual).toHaveTextContent("实际使用未知");
    expect(actual.querySelector('[data-status="unverified"]')).toHaveTextContent("未验证 · 枢纽已变更");
    expect(actual).not.toHaveTextContent("香港二号");
    expect(within(card).getByTestId("group-actual-why")).toHaveTextContent("上次读取的不是当前枢纽");
    expect(within(card).getByTestId("group-actual-why")).toHaveTextContent("服务器、地址已变更");
    expect(within(card).getByRole("button", { name: /重新读取/ })).toBeEnabled();
    expect(within(card).queryByText("使用中")).toBeNull();
    // The model stays separate and labelled.
    expect(within(card).getByTestId("group-model")).toHaveTextContent("面板推算香港二号");
    const bar = screen.getByTestId("hub-state-bar");
    expect(within(bar).getByText("不是当前枢纽")).toBeInTheDocument();
    expect(within(bar).queryByText("读取成功")).toBeNull();
    expect(within(bar).getByTestId("hub-identity-changed")).toHaveTextContent("旧报告不再采信");
    // Read automatically despite the recent time; the discarded result is
    // reported and the groups are loaded again.
    await waitFor(() => expect(api.find("POST /api/region-groups/runtime/refresh")).toHaveLength(1));
    expect(await screen.findByText("读取期间枢纽已变更，这次结果已丢弃")).toBeInTheDocument();
    await waitFor(() => expect(screen.getByTestId("hub-state-bar")).toHaveTextContent("新枢纽服务器"));
    expect(within(screen.getByTestId("group-hk")).getByTestId("group-actual")).toHaveTextContent("实际使用未知");
  });

  it("links to the server page when the changed hub cannot be read yet", async () => {
    const changed = "上次读取的不是当前的枢纽（地址已变更）；旧报告不再采信，需要对当前枢纽重新读取";
    const g = group({ actual: { ...NEVER_READ, state: "unavailable", code: "hub_identity_changed", message: changed, read_at: NOW } });
    const api = fakeApi({
      "GET /api/topology": () => topology(),
      "GET /api/region-groups": () => ({
        groups: [g],
        default_group: "hk",
        thresholds: THRESHOLDS,
        hub_state: hubState({
          readable: false,
          not_readable_code: "server_not_ready",
          not_readable_message: "服务器 枢纽服务器 的主机指纹还没有确认",
          last_read: { read_at: NOW, ok: true, ignored: [], current_hub: false, identity_code: "hub_identity_changed", identity_message: changed },
        }),
      }),
    });
    renderAt("#/exits", { foldsOpen: true });
    const card = await screen.findByTestId("group-hk");
    expect(within(card).getByTestId("group-actual")).toHaveTextContent("未验证 · 枢纽已变更");
    expect(within(card).getByRole("link", { name: /服务器页/ })).toHaveAttribute("href", "#/servers/srv-hub");
    expect(within(screen.getByTestId("hub-state-bar")).getByText("不是当前枢纽")).toBeInTheDocument();
    await new Promise((r) => setTimeout(r, 50));
    expect(api.find("POST /api/region-groups/runtime/refresh")).toHaveLength(0);
  });

  it("does not read automatically when a recent read is stored", async () => {
    const api = fakeApi({
      "GET /api/topology": () => topology(),
      "GET /api/region-groups": () => ({ groups: [group()], default_group: "hk", thresholds: THRESHOLDS, hub_state: hubState({ last_read: { read_at: new Date().toISOString(), ok: true, ignored: [] } }) }),
    });
    renderAt("#/exits", { foldsOpen: true });
    await screen.findByTestId("group-hk");
    await new Promise((r) => setTimeout(r, 50));
    expect(api.find("POST /api/region-groups/runtime/refresh")).toHaveLength(0);
  });

  it("the overview tile names a member only from the hub's report", async () => {
    const groups = [
      group({ id: "g0", name: "组0", actual: actualOK("hk-2") }),
      group({ id: "g1", name: "组1", is_default: false, model: observedModel }),
    ];
    fakeApi({
      "GET /api/topology": () => topology(),
      "GET /api/servers": () => ({ servers: [server()] }),
      "GET /api/region-groups": () => ({ groups, default_group: "g0", thresholds: THRESHOLDS, hub_state: hubState() }),
    });
    renderAt("#/");
    expect(await screen.findByTestId("groups-tile-actual-g0")).toHaveTextContent("香港二号");
    expect(screen.queryByTestId("groups-tile-actual-g1")).toBeNull();
    // The tag holds the short status; the rest of the label is in the tooltip and for screen readers.
    const tag = await screen.findByTestId("groups-tile-status-g1");
    expect(tag).toHaveTextContent("实际未知 · 未验证 · 未读取");
    expect(tag).toHaveAttribute("data-status", "unverified");
    expect(within(tag).getByText("实际未知").closest(".status-text")).not.toBeNull();
  });
});

describe("region groups with the same name", () => {
  const twins = () => [
    group({ id: "hk-dc", name: "香港", region: "hk", is_default: true }),
    group({ id: "hk-home", name: "香港", region: "hk", is_default: false, in_use_by: [] }),
    group({ id: "us", name: "美国", region: "us", is_default: false, in_use_by: [], members: ["us"], member_status: [member("us", "美国", { region: "us" })] }),
  ];
  const topo = () =>
    topology({
      region_groups: [
        { id: "hk-dc", name: "香港", region: "hk", members: ["hk-2", "hk-ix"], mode: "auto" },
        { id: "hk-home", name: "香港", region: "hk", members: ["hk-resi"], mode: "auto" },
        { id: "us", name: "美国", region: "us", members: ["us"], mode: "auto" },
      ],
      settings: { ...topology().settings, default_group: "hk-dc" },
    });

  it("marks both cards and shows region and ID wherever a group is labelled on the exits page", async () => {
    fakeApi({
      "GET /api/topology": topo,
      "GET /api/region-groups": () => ({ groups: twins(), default_group: "hk-dc", thresholds: THRESHOLDS }),
    });
    renderAt("#/exits", { foldsOpen: true });
    expect(await screen.findByTestId("dup-name-hk-dc")).toHaveTextContent("同名 · 香港 · HK");
    expect(screen.getByTestId("dup-name-hk-home")).toBeInTheDocument();
    expect(screen.queryByTestId("dup-name-us")).toBeNull();
    // Labels inside the cards carry the stable ID.
    expect(screen.getByLabelText("香港（香港 · HK · hk-home） 的成员")).toBeInTheDocument();
    expect(screen.getByLabelText("美国 的成员")).toBeInTheDocument();
  });

});

// ----------------------------------------------- primary and backup hub ---

describe("primary and backup hub", () => {
  afterEach(() => clearCooldowns());

  function dualTopology(): Topology {
    const t = topology();
    t.nodes = t.nodes.map((n) => (n.id === "hk-hub" ? { ...n, name: "hk1", hub_tier: "primary" as const, ix_line: true, ingress_v4: "198.51.100.10", endpoint_v4: "203.0.113.10" } : n));
    t.nodes.push({ ...exitNode("hkb", "hkb", { role: "hub" }), hub_tier: "backup", endpoint_v4: "203.0.113.50", wss_listen_port: 8443 });
    return t;
  }

  const recent = () => new Date().toISOString();
  const primary = (over: Partial<GroupHubState> = {}) =>
    hubState({ tier: "primary", hub_node: "hk-hub", hub_name: "hk1", server_name: "IX 服务器", plan_id: "aaaaaaaaaaaaaaaa", carrying: false, last_read: { read_at: recent(), ok: true, ignored: [] }, ...over });
  const backup = (over: Partial<GroupHubState> = {}) =>
    hubState({ tier: "backup", hub_node: "hkb", hub_name: "hkb", server_id: "srv-hkb", server_name: "hkb 机房", plan_id: "bbbbbbbbbbbbbbbb", carrying: false, last_read: { read_at: recent(), ok: true, ignored: [] }, ...over });

  it("shows the backup hub as carrying and the group's actual state read from it", async () => {
    const g = group({
      actual: { ...actualOK("hk-2"), hub_tier: "backup", hub_node: "hkb", hub_name: "hkb", server_name: "hkb 机房" },
      actual_by_hub: [
        { ...NEVER_READ, tier: "primary", hub_node: "hk-hub", hub_name: "hk1", carrying: false, state: "stale", code: "heartbeat_old" },
        { ...actualOK("hk-2"), tier: "backup", hub_node: "hkb", hub_name: "hkb", carrying: true },
      ],
      member_status: group().member_status.map((m) => ({ ...m, actual_active: m.id === "hk-2" })),
    });
    const hubs = [primary(), backup({ carrying: true })];
    const body = () => ({
      groups: [g],
      default_group: "hk",
      thresholds: THRESHOLDS,
      hub_state: hubs[0],
      hub_states: hubs,
      carrying: { mode: "dual", known: true, tier: "backup", hub_node: "hkb", hub_name: "hkb", path: "backup", iface: "wg-hkb", state: "ok", since: NOW, beat: recent(), source: "gateway" },
    });
    fakeApi({
      "GET /api/topology": () => dualTopology(),
      "GET /api/region-groups": body,
      "POST /api/region-groups/runtime/refresh": body,
    });
    renderAt("#/exits", { foldsOpen: true });
    const bar = await screen.findByTestId("hub-state-bar");
    expect(bar).toHaveAttribute("data-mode", "dual");
    expect(within(bar).getByTestId("carrying")).toHaveTextContent("当前承载：备用枢纽 hkb（经 WSS，自");
    expect(within(bar).getByTestId("hub-row-primary")).toHaveTextContent("主枢纽");
    expect(within(bar).getByTestId("hub-row-primary")).toHaveTextContent("IX 服务器");
    expect(within(bar).getByTestId("hub-row-primary")).toHaveAttribute("data-carrying", "false");
    expect(within(bar).getByTestId("hub-row-backup")).toHaveTextContent("备用枢纽");
    expect(within(bar).getByTestId("hub-row-backup")).toHaveTextContent("hkb 机房");
    expect(within(bar).getByTestId("hub-row-backup")).toHaveAttribute("data-carrying", "true");
    expect(within(bar).getByTestId("hub-row-backup")).toHaveTextContent("承载中");
    const card = screen.getByTestId("group-hk");
    const actual = within(card).getByTestId("group-actual");
    expect(actual).toHaveTextContent("实际使用香港二号");
    expect(within(actual).getByTestId("group-actual-source")).toHaveTextContent("实测 · 读自 备用枢纽 hkb（服务器 hkb 机房）");
    expect(within(screen.getByTestId("member-hk-hk-2")).getByText("使用中")).toBeInTheDocument();
    // The model stays its own labelled line.
    expect(within(card).getByTestId("group-model")).toHaveTextContent("面板推算");
    expect(within(card).getByTestId("group-model")).not.toHaveTextContent("实测");
    expect(within(card).queryByTestId("group-hub-reports")).toBeNull();
  });

  it("with the carrying hub unknown, shows no member in use, the reason and each hub's unconfirmed report", async () => {
    const why = "网关还没有上游记录（还没有按带备用枢纽的拓扑安装到本机，或切换服务没有运行）";
    const g = group({
      actual: { ...NEVER_READ, state: "unavailable", code: "carrying_unknown", message: `不知道现在由哪个枢纽承载（${why}）；不把任一枢纽的报告当作实际使用`, read_at: null },
      actual_by_hub: [
        { ...actualOK("hk-ix"), tier: "primary", hub_node: "hk-hub", hub_name: "hk1", carrying: false },
        { ...actualOK("hk-2"), tier: "backup", hub_node: "hkb", hub_name: "hkb", carrying: false },
      ],
    });
    const hubs = [primary(), backup()];
    fakeApi({
      "GET /api/topology": () => dualTopology(),
      "GET /api/servers": () => ({ servers: [server()] }),
      "GET /api/region-groups": () => ({
        groups: [g],
        default_group: "hk",
        thresholds: THRESHOLDS,
        hub_state: hubs[0],
        hub_states: hubs,
        carrying: { mode: "dual", known: false, source: "gateway", code: "not_recorded", message: why },
      }),
    });
    renderAt("#/exits", { foldsOpen: true });
    const bar = await screen.findByTestId("hub-state-bar");
    expect(within(bar).getByTestId("carrying")).toHaveTextContent(`承载枢纽未知：${why}`);
    expect(within(bar).getByTestId("hub-row-primary")).toHaveAttribute("data-carrying", "false");
    expect(within(bar).getByTestId("hub-row-backup")).toHaveAttribute("data-carrying", "false");
    const card = screen.getByTestId("group-hk");
    const actual = within(card).getByTestId("group-actual");
    expect(actual).toHaveAttribute("data-state", "unavailable");
    expect(actual).toHaveTextContent("实际使用未知");
    expect(actual).not.toHaveTextContent("香港二号");
    expect(within(card).queryByText("使用中")).toBeNull();
    const whyEl = within(card).getByTestId("group-actual-why");
    expect(whyEl).toHaveTextContent("不知道现在由哪个枢纽承载");
    expect(whyEl).toHaveTextContent("网关还没有上游记录");
    const reports = within(card).getByTestId("group-hub-reports");
    expect(reports).toHaveTextContent("各枢纽报告（未确认承载）");
    expect(within(reports).getByTestId("hub-report-backup")).toHaveTextContent("备用枢纽 hkb");
    expect(within(reports).getByTestId("hub-report-backup")).toHaveTextContent("未确认承载");
    expect(reports.querySelector('[data-status="ok"]')).toBeNull();

    // The overview names the unknown carrying hub too.
    renderAt("#/");
    await waitFor(() => expect(screen.getAllByTestId("carrying").some((e) => e.textContent?.includes("承载枢纽未知"))).toBe(true));
  });

  it("shows the IX hub fields in the topology editor", async () => {
    fakeApi({
      "GET /api/topology": () => dualTopology(),
      "GET /api/servers": () => ({ servers: [server()] }),
    });
    renderAt("#/topology/hk-hub");
    const detail = await screen.findByTestId("node-detail");
    expect(within(detail).getByRole("combobox", { name: "枢纽角色" })).toBeInTheDocument();
    expect(within(detail).getByText("主枢纽")).toBeInTheDocument();
    expect(within(detail).getByRole("switch", { name: "IX 即主枢纽" })).toBeChecked();
    expect(within(detail).getByLabelText("国内入口地址（中继拨入）")).toHaveValue("198.51.100.10");
    expect(within(detail).getByLabelText("国内入口接口（可选）")).toHaveValue("");
    expect(within(detail).getByLabelText("境外出口地址（出口拨入）")).toHaveValue("203.0.113.10");
    expect(within(detail).queryByText("公网 IPv4")).toBeNull();
    // Not an old single-hub topology: no migration notice.
    expect(screen.queryByTestId("ix-hub-migration")).toBeNull();
  });

  it("offers the IX-as-primary-hub migration on an old topology with an ix node, converting nothing", async () => {
    const t = topology();
    t.nodes.push({ ...exitNode("ix", "IX 专线", { role: "ix", managed: false }) });
    fakeApi({
      "GET /api/topology": () => t,
      "GET /api/servers": () => ({ servers: [server()] }),
    });
    renderAt("#/topology/hk-hub");
    const notice = await screen.findByTestId("ix-hub-migration");
    expect(notice).toHaveTextContent("IX 即主枢纽");
    expect(notice).toHaveTextContent("不会自动转换");
    // The lone hub reads as primary; its IX fields stay hidden until switched on.
    const detail = await screen.findByTestId("node-detail");
    expect(within(detail).getByText("主枢纽")).toBeInTheDocument();
    expect(within(detail).getByRole("switch", { name: "IX 即主枢纽" })).not.toBeChecked();
    expect(within(detail).queryByLabelText("国内入口地址（中继拨入）")).toBeNull();
    await userEvent.click(within(notice.closest(".ant-alert") as HTMLElement).getByRole("button", { name: /close|关闭/i }));
    await waitFor(() => expect(screen.queryByTestId("ix-hub-migration")).toBeNull());
  });
});

// ------------------------------------------------ relay sharing (S4) ---

describe("domestic relays sharing the main path", () => {
  afterEach(() => clearCooldowns());

  function sharedTopology(): Topology {
    const t = topology();
    t.nodes.push(exitNode("access", "中继 1", { role: "relay", region: "cn" }), exitNode("access2", "中继 2", { role: "relay", region: "cn" }));
    t.links.push(
      { id: "gw-access", from: "gw", to: "access", transport: "udp_wss_failover", enabled: true, standby: false },
      { id: "gw-access2", from: "gw", to: "access2", transport: "direct_wg", enabled: true, standby: false },
    );
    return t;
  }

  const recent = () => new Date().toISOString();
  function sharing(over: Partial<Sharing> = {}): Sharing {
    return {
      known: true,
      controller: "go",
      path: "main",
      designated: "access",
      switched: NOW,
      beat: recent(),
      relays: [
        {
          id: "access",
          name: "中继 1",
          iface: "m02",
          status: "active",
          in_set: true,
          weight: 1000,
          drain: false,
          grade: "good",
          measured: { rtt_ms: 31.5, loss_pct: 0.4, last_rtt_ms: 30.2, last_loss_pct: 0, at: recent() },
          speed: { qos: "ok", mbps: 186.2, at: recent(), age_sec: 30, baseline_mbps: 190, baseline_src: "p90", threshold_mbps: 47.5, recover_mbps: 95 },
          traffic: { rx_bytes: 52428800, tx_bytes: 1048576, rx_bps: 204800, tx_bps: 10240, new_conns: 42 },
        },
        {
          id: "access2",
          name: "中继 2",
          iface: "m03",
          status: "evicted",
          in_set: false,
          weight: 0,
          drain: true,
          reason: "no_throughput",
          status_since: NOW,
          grade: "poor",
          suspicious: "rtt_inflation",
          measured: { rtt_ms: 120, loss_pct: 0, last_rtt_ms: 118, last_loss_pct: 0, at: recent() },
          traffic: { rx_bytes: 1024, tx_bytes: 2048, rx_bps: 0, tx_bps: 0, new_conns: 7 },
          probe: { at: NOW, kbps: 420, loss_pct: 86, ok: false, bytes_today: 640136 },
          speed: { qos: "throttled", mbps: 38, at: recent(), age_sec: 30, baseline_mbps: 200, baseline_src: "nominal", threshold_mbps: 50, recover_mbps: 100 },
        },
      ],
      backup: { hub: "hkb", name: "hkb", iface: "m04", grade: "good", drain: false, measured: { rtt_ms: 60, loss_pct: 0, at: recent() }, traffic: { rx_bytes: 0, tx_bytes: 0, rx_bps: 0, tx_bps: 0, new_conns: 0 } },
      settings: { ...PATH_QUALITY_DEFAULTS },
      probe_cost: {
        enabled: true,
        bytes_per_probe: 1123072,
        min_interval_sec: 900,
        max_probes_per_day: 59,
        max_bytes_per_day: 66261248,
        daily_budget_bytes: 67108864,
        source: "estimated",
        trigger: "只在该中继有业务流量、且被动信号可疑时触发。",
      },
      speed_test_cost: { enabled: true, bytes_per_test: 20971520, interval_sec: 1800, tests_per_day: 48, bytes_per_day: 1006632960, source: "estimated" },
      eviction_impact: "剔除时，该中继上已有的 TCP 连接会被网关重置。",
      ...over,
    };
  }

  function groupsBody(s: Sharing) {
    return {
      groups: [group()],
      default_group: "hk",
      thresholds: THRESHOLDS,
      hub_state: hubState(),
      carrying: { mode: "single", known: true, tier: "primary", hub_node: "hk-hub", hub_name: "主枢纽", source: "topology", sharing: s },
    };
  }

  it("shows each relay's share, measured quality with its time, the eviction reason, the disconnect impact and the estimated probe cost", async () => {
    fakeApi({ "GET /api/topology": () => sharedTopology(), "GET /api/region-groups": () => groupsBody(sharing()) });
    renderAt("#/exits", { foldsOpen: true });
    const view = await screen.findByTestId("relay-sharing");
    expect(within(view).getByTestId("sharing-path")).toHaveTextContent("主链路（多中继分担）");
    expect(within(view).getByTestId("relay-weight-access")).toHaveTextContent("100%");
    expect(within(view).getByTestId("relay-weight-access2")).toHaveTextContent("0%");
    expect(within(view).getByTestId("relay-status-access")).toHaveTextContent("分担中");
    expect(within(view).getByTestId("relay-status-access2")).toHaveTextContent("已剔除");
    expect(view).toHaveTextContent("吞吐探测不达标（小包通、没有速率）");
    expect(within(view).getByTestId("relay-drain-access2")).toHaveTextContent("已有连接正被清理");
    // Measured by the gateway, with a time; the probe result with its cost.
    expect(within(view).getAllByTestId("measured")[0]).toHaveTextContent("网关测量");
    expect(within(view).getByTestId("probe-access2")).toHaveTextContent("不达标");
    expect(within(view).getByTestId("probe-access2")).toHaveTextContent("今日");
    expect(within(view).getByTestId("sharing-backup")).toHaveTextContent("备用枢纽 hkb");
    // The disconnect impact and the cost (the panel's estimate, labelled as such) are in the page's 「说明」.
    const help = screen.getByTestId("page-help");
    expect(within(help).getByTestId("sharing-impact")).toHaveTextContent("断连影响");
    expect(within(help).getByTestId("sharing-probe-cost")).toHaveTextContent("面板估算");
    expect(within(view).queryByTestId("sharing-fallback")).toBeNull();
    // Speed tests: one line per relay; only the throttled one is a tag.
    expect(within(view).getByTestId("relay-speed-access")).toHaveTextContent("186 Mbit/s");
    expect(within(view).getByTestId("relay-speed-access").querySelector(".ant-tag")).toBeNull();
    expect(within(view).getByTestId("relay-speed-access2")).toHaveTextContent("限速 38 Mbit/s");
    expect(within(help).getByTestId("sharing-speed-cost")).toHaveTextContent("48 次");
  });

  it("says when the shell fallback runs, when all relays are poor, and when the state is unknown", async () => {
    fakeApi({
      "GET /api/topology": () => sharedTopology(),
      "GET /api/region-groups": () => groupsBody(sharing({ controller: "shell", alert: "all_relays_poor_backup_not_better", alert_text: "所有中继都低于可用下限，备用枢纽也不比它们好" })),
    });
    renderAt("#/exits", { foldsOpen: true });
    const view = await screen.findByTestId("relay-sharing");
    expect(within(view).getByTestId("sharing-fallback")).toHaveTextContent("应急规则在运行");
    expect(within(view).getByTestId("sharing-alert")).toHaveTextContent("备用枢纽也不比它们好");
  });

  it("says when the gateway's relay record is unknown", async () => {
    fakeApi({ "GET /api/topology": () => sharedTopology(), "GET /api/region-groups": () => groupsBody(sharing({ known: false, code: "stale", message: "网关的中继记录已超过 60 秒没有更新" })) });
    renderAt("#/exits", { foldsOpen: true });
    const view = await screen.findByTestId("relay-sharing");
    expect(within(view).getByTestId("sharing-unknown")).toHaveTextContent("超过 60 秒没有更新");
  });

  it("shows a compact tile on the overview when the gateway shares relays", async () => {
    fakeApi({
      "GET /api/topology": () => sharedTopology(),
      "GET /api/upstream": () => ({ mode: "dual", known: true, tier: "backup", hub_node: "hkb", hub_name: "hkb", path: "backup", source: "gateway", sharing: sharing({ path: "backup", designated: "backup" }) }),
    });
    renderAt("#/");
    const view = await screen.findByTestId("relay-sharing");
    expect(screen.getByTestId("sharing-path")).toHaveTextContent("备用枢纽 hkb");
    // Compact: the path, the relay count and the problems; the per-relay table is on the exits page.
    expect(within(view).queryByRole("table")).toBeNull();
  });

  function groupSharing(path: "main" | "backup"): Sharing {
    const base = sharing();
    const bk = { ...base.relays[0], id: "bk1", name: "备用中继 1", iface: "m06", group: "backup" as const };
    const main = { ...base.relays[0], group: "main" as const };
    return sharing({
      path,
      designated: path === "main" ? "access" : "bk1",
      backup: undefined,
      backup_group: { hub: "hkb", name: "hkb", relays: ["bk1"] },
      relays: path === "main" ? [main, { ...bk, weight: 0, in_set: false }] : [{ ...main, weight: 0, in_set: false, status: "evicted", grade: "down" }, { ...bk, weight: 1000 }],
    });
  }

  it("shows the main and the backup group, which one carries and the backup hub reached via relays", async () => {
    fakeApi({ "GET /api/topology": () => sharedTopology(), "GET /api/region-groups": () => groupsBody(groupSharing("backup")) });
    renderAt("#/exits", { foldsOpen: true });
    const view = await screen.findByTestId("relay-sharing");
    expect(within(view).getByTestId("sharing-path")).toHaveTextContent("备用组 · hkb");
    expect(within(view).getByTestId("relay-group-access")).toHaveTextContent("主组");
    expect(within(view).getByTestId("relay-group-bk1")).toHaveTextContent("备用组 · hkb");
    // The backup group shares by weight: no "0%（备用枢纽承载）" override.
    expect(within(view).getByTestId("relay-weight-bk1")).toHaveTextContent("100%");
    expect(within(view).queryByTestId("sharing-backup")).toBeNull();
  });

  it("shows both groups on the overview with the backup hub's name as the current path", async () => {
    fakeApi({
      "GET /api/topology": () => sharedTopology(),
      "GET /api/upstream": () => ({ mode: "dual", known: true, tier: "backup", hub_node: "hkb", hub_name: "hkb", path: "backup", source: "gateway", sharing: groupSharing("backup") }),
    });
    renderAt("#/");
    await screen.findByTestId("ov-group-backup");
    expect(screen.getAllByTestId("sharing-path")[0]).toHaveTextContent("备用枢纽 hkb");
    const main = screen.getByRole("list", { name: "主组" });
    expect(within(main).getByTestId("ov-relay-access")).toBeInTheDocument();
    const backup = screen.getByRole("list", { name: "备用组 · hkb" });
    expect(within(backup).getByTestId("ov-relay-bk1")).toBeInTheDocument();
    expect(within(backup).getByText("承载中")).toBeInTheDocument();
    expect(within(main).queryByText("承载中")).toBeNull();
  });

  it("edits the thresholds and the probe budget in the gateway settings, with the cost estimate", async () => {
    let saved: Topology | undefined;
    const api = fakeApi({
      "GET /api/topology": () => sharedTopology(),
      "PUT /api/topology": (req) => {
        saved = req.body as Topology;
        return { topology: req.body, issues: [], paths: [], draft: false };
      },
    });
    renderAt("#/topology");
    await userEvent.click(await screen.findByRole("button", { name: /网关设置/ }));
    const box = await screen.findByTestId("path-quality-settings");
    expect(box).toHaveTextContent("网关连着 2 台中继");
    expect(within(box).getByTestId("probe-cost-estimate")).toHaveTextContent("估算：每次约");
    expect(within(box).getByTestId("speed-cost-estimate")).toHaveTextContent("/天/中继");
    await userEvent.type(within(box).getByLabelText("测速间隔"), "3600");
    await userEvent.type(within(box).getByLabelText("标称带宽 access"), "300");
    const evict = within(box).getByLabelText("低于下限多久剔除");
    await userEvent.type(evict, "45");
    const budget = within(box).getByLabelText("每台中继每天预算");
    await userEvent.type(budget, "16");
    await userEvent.click(within(box).getByLabelText("启用吞吐探测"));
    expect(within(box).getByTestId("probe-cost-estimate")).toHaveTextContent("已关闭");
    await userEvent.click(screen.getByRole("button", { name: btn("保存") }));
    await waitFor(() => expect(api.find("PUT /api/topology")).toHaveLength(1));
    expect(saved!.settings.path_quality).toEqual({ speed_test_interval_sec: 3600, overrides: [{ relay: "access", nominal_mbps: 300 }], evict_after_sec: 45, probe_daily_budget_mb: 16, probe_off: true });
  });
});

// ------------------------------------------- nested and external exits ---

describe("nested and external SOCKS exits", () => {
  const SOCKS_CRED = {
    id: "socks-1",
    name: "马来西亚代理",
    notes: "住宅",
    secret_set: true,
    created_at: NOW,
    updated_at: NOW,
    used_by: [{ kind: "node", id: "ext-1", name: "马来西亚住宅" }],
  };
  const withKinds = () =>
    topology({
      nodes: [
        ...topology().nodes,
        exitNode("my-nested", "嵌套出口", { region: "my", nat_dial_out: true, path_v6: false, via_exit: "hk-2" }),
        exitNode("ext-1", "马来西亚住宅", {
          region: "my",
          managed: false,
          path_v6: false,
          egress_v6: false,
          residential: true,
          external: { carrier: "hk-2", socks_address: "192.0.2.10", socks_port: 1080, interface: "wg9", credential_id: "socks-1" },
        }),
      ],
    });

  it("adds an external exit with the backend's shape and never puts a username or password into the topology", async () => {
    let saved: Topology | null = null;
    const api = fakeApi({
      "GET /api/topology": () => topology(),
      "GET /api/region-groups": () => ({ groups: [group()], default_group: "hk", thresholds: THRESHOLDS }),
      "GET /api/socks-credentials": () => ({ credentials: [{ ...SOCKS_CRED, used_by: [] }] }),
      "PUT /api/topology": (req) => {
        saved = req.body as Topology;
        return { topology: saved, issues: [], paths: [], draft: false };
      },
    });
    renderAt("#/exits", { foldsOpen: true });
    await userEvent.click(await screen.findByRole("button", { name: /添加外部 SOCKS 出口/ }));
    const drawer = await screen.findByRole("dialog");
    // The limitations and the deployment order are stated before anything is saved.
    const limits = within(drawer).getByTestId("external-limits");
    expect(limits).toHaveTextContent("只承载 IPv4 上的 TCP");
    expect(limits).toHaveTextContent("UDP（包括 QUIC / HTTP/3）在承载节点上直接拒绝");
    expect(limits).toHaveTextContent("1.1.1.1 / 8.8.8.8；没有回退");
    expect(limits).toHaveTextContent("不返回 AAAA");
    expect(limits).toHaveTextContent("每 10 秒经代理发一次 DNS over TCP 查询");
    expect(limits).toHaveTextContent("面板从不登录那台代理设备，也不为它生成安装包");
    expect(limits).toHaveTextContent("尚未在真实设备上验证");
    expect(within(drawer).getByRole("link", { name: /SOCKS 凭据/ })).toHaveAttribute("href", "#/keys?section=socks&socks=new");

    fireEvent.change(within(drawer).getByLabelText("ID"), { target: { value: "my-socks" } });
    fireEvent.change(within(drawer).getByLabelText("显示名称"), { target: { value: "马来西亚住宅" } });
    fireEvent.change(within(drawer).getByRole("combobox", { name: "国家或地区" }), { target: { value: "my" } });
    await userEvent.click(within(drawer).getByRole("checkbox", { name: /住宅（家宽）/ }));
    await pick("承载出口", "香港二号", drawer);
    fireEvent.change(within(drawer).getByLabelText("SOCKS 地址"), { target: { value: "192.0.2.10" } });
    fireEvent.change(within(drawer).getByLabelText("承载出口上的接口"), { target: { value: "wg9" } });
    await pick("SOCKS 凭据", "马来西亚代理", drawer);
    expect(within(drawer).getByTestId("deploy-order")).toHaveTextContent("先在「部署」页重新下发承载出口 香港二号，再下发两个枢纽");
    await userEvent.click(within(drawer).getByRole("button", { name: btn("保存到拓扑") }));

    await waitFor(() => expect(api.find("PUT /api/topology")).toHaveLength(1));
    const node = saved!.nodes.find((n: Node) => n.id === "my-socks")!;
    expect(node).toMatchObject({
      id: "my-socks",
      name: "马来西亚住宅",
      role: "exit",
      region: "my",
      managed: false,
      path_v4: true,
      path_v6: false,
      egress_v4: true,
      egress_v6: false,
      nat_dial_out: false,
      residential: true,
      ix_bound: false,
      external: { carrier: "hk-2", socks_address: "192.0.2.10", socks_port: 1080, interface: "wg9", credential_id: "socks-1" },
    });
    for (const k of ["server_id", "endpoint_v4", "endpoint_v6", "endpoint_host", "via_exit", "listen_port", "public_key"]) expect(node).not.toHaveProperty(k);
    expect(saved!.links).toEqual([]);
    // Only the credential's ID reaches the topology.
    const raw = api.find("PUT /api/topology")[0].raw!;
    expect(raw).not.toMatch(/username|password/);
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(within(await screen.findByTestId("exit-node-my-socks")).getByTestId("external-tag-my-socks")).toHaveTextContent("外部 SOCKS · 仅 TCP · 仅 IPv4");
  });

  it.each(["save", "deploy", "blocked"])("adds a managed relay link (%s)", async (mode) => {
    const deploy = mode !== "save";
    const step = { node_id: "hk-ix", node_name: "香港 IX", phase: "pending" };
    const run = { id: "deploy-1", state: "active", current: step.node_id, steps: [step] };
    let saved: Topology | null = null;
    const api = fakeApi({
      "GET /api/topology": withKinds,
      "GET /api/deploy": () => ({ topology_version: "v1", plan: { steps: [step] } }),
      "POST /api/deploy/runs": () => ({ run }),
      "POST /api/deploy/runs/deploy-1/preflight": () => ({
        run: { ...run, steps: [mode === "blocked"
          ? { ...step, phase: "blocked", message: "需要确认 SSH 主机指纹" }
          : { ...step, phase: "review", can_install: true, preflight_id: "pf-1" }] },
      }),
      "POST /api/deploy/runs/deploy-1/install": () => ({
        run: { ...run, state: "done", steps: [{ ...step, phase: "done" }] },
      }),
      "GET /api/region-groups": () => ({ groups: [group()], default_group: "hk", thresholds: THRESHOLDS }),
      "GET /api/socks-credentials": () => ({ credentials: [SOCKS_CRED] }),
      "PUT /api/topology": (req) => {
        saved = req.body as Topology;
        return { topology: saved, issues: [], paths: [], draft: false };
      },
    });
    renderAt("#/exits", { foldsOpen: true });
    const nested = await screen.findByTestId("exit-node-my-nested");
    expect(within(nested).getByTestId("nested-tag-my-nested")).toHaveTextContent("经 香港二号 中继");
    const ext = screen.getByTestId("exit-node-ext-1");
    expect(within(ext).getByTestId("external-tag-ext-1")).toHaveTextContent("外部 SOCKS · 仅 TCP · 仅 IPv4");
    expect(ext).toHaveTextContent("192.0.2.10:1080");
    expect(ext).toHaveTextContent("马来西亚代理");
    expect(screen.getAllByTestId("external-limits")[0]).toHaveTextContent("只承载 IPv4 上的 TCP");

    await userEvent.click(screen.getByRole("button", { name: "设置出口 香港 IX" }));
    const drawer = await screen.findByRole("dialog");
    expect(drawer).toHaveTextContent("WireGuard 握手超过 150 秒没有更新时重新解析");
    fireEvent.mouseDown(within(drawer).getByRole("combobox", { name: "经中继出口到达" }));
    const options = await waitFor(() => {
      const els = [...document.querySelectorAll<HTMLElement>(".ant-select-dropdown:not(.ant-select-dropdown-hidden) .ant-select-item-option")];
      if (els.length === 0) throw new Error("no options");
      return els.map((e) => e.textContent ?? "");
    });
    expect(options.some((t) => t.includes("香港二号"))).toBe(true);
    expect(options.some((t) => t.includes("美国"))).toBe(true);
    expect(options.some((t) => t.includes("嵌套出口"))).toBe(false);
    expect(options.some((t) => t.includes("马来西亚住宅"))).toBe(false);
    expect(options.some((t) => t.includes("香港 IX"))).toBe(false);
    const hk2 = [...document.querySelectorAll<HTMLElement>(".ant-select-dropdown:not(.ant-select-dropdown-hidden) .ant-select-item-option")].find((e) =>
      e.textContent?.includes("香港二号"),
    )!;
    fireEvent.click(hk2);
    const req = await within(drawer).findByTestId("via-exit-requirements");
    expect(req).toHaveTextContent("必须是 NAT 拨出：未满足");
    expect(req).toHaveTextContent("现在有 0 条");
    expect(within(drawer).getByTestId("deploy-order")).toHaveTextContent("先在「部署」页重新下发中继出口 香港二号，再下发这个出口，然后两个枢纽");
    expect(within(drawer).getByRole("checkbox", { name: /补上一条直连 WG 链路 hk-ix → hk-2/ })).toBeChecked();
    await userEvent.click(within(drawer).getByRole("button", { name: btn(deploy ? "保存并部署" : "仅保存") }));
    if (deploy) {
      expect(api.find("PUT /api/topology")).toHaveLength(0);
      const detail = await screen.findByText(/将预检并下发当前待安装的节点和链路/);
      const confirmation = detail.closest<HTMLElement>('[role="dialog"]')!;
      await userEvent.click(within(confirmation).getByRole("button", { name: btn("保存并部署") }));
      if (mode === "blocked") {
        await screen.findByText("出口已保存，部署已暂停");
        expect(screen.getByText(/需要确认 SSH 主机指纹/)).toBeVisible();
        expect(screen.getByRole("link", { name: "查看部署并继续" })).toBeVisible();
        expect(api.find("POST /api/deploy/runs/deploy-1/install")).toHaveLength(0);
      } else {
        await screen.findByText("自动部署完成");
        expect(api.find("POST /api/deploy/runs/deploy-1/install")[0].body).toEqual({ node_id: "hk-ix", preflight_id: "pf-1" });
      }
    } else {
      expect(api.find("GET /api/deploy")).toHaveLength(0);
    }
    await waitFor(() => expect(api.find("PUT /api/topology")).toHaveLength(1));
    expect(saved!.nodes.find((n: Node) => n.id === "hk-ix")!.via_exit).toBe("hk-2");
    expect(saved!.links).toEqual([expect.objectContaining({ id: "hk-ix-hk-2", from: "hk-ix", to: "hk-2", transport: "direct_wg", enabled: true, standby: false, mtu: 1420, keepalive: 25 })]);
    // The external exit went back unchanged, still without any secret.
    expect(saved!.nodes.find((n: Node) => n.id === "ext-1")!.external).toEqual(withKinds().nodes.find((n) => n.id === "ext-1")!.external);
    expect(api.find("PUT /api/topology")[0].raw).not.toMatch(/username|password/);
  });

  it("disables the relay choice on an exit that relays a nested exit", async () => {
    fakeApi({
      "GET /api/topology": withKinds,
      "GET /api/region-groups": () => ({ groups: [group()], default_group: "hk", thresholds: THRESHOLDS }),
      "GET /api/socks-credentials": () => ({ credentials: [SOCKS_CRED] }),
    });
    renderAt("#/exits", { foldsOpen: true });
    await userEvent.click(await screen.findByRole("button", { name: "设置出口 香港二号" }));
    const drawer = await screen.findByRole("dialog");
    expect(drawer).toHaveTextContent("嵌套出口 经这个出口中继，所以它自己不能再经别的出口到达");
    expect(drawer).toHaveTextContent("它是外部 SOCKS 出口 马来西亚住宅 的承载出口");
    expect(within(drawer).getByRole("combobox", { name: "经中继出口到达" })).toBeDisabled();
  });
});

describe("SOCKS credentials", () => {
  const cred = (over: Record<string, unknown> = {}) => ({
    id: "socks-1",
    name: "马来西亚代理",
    notes: "住宅",
    secret_set: true,
    created_at: NOW,
    updated_at: NOW,
    used_by: [] as { kind: string; id: string; name: string }[],
    ...over,
  });

  it("creates a credential write-only: clears both fields after every attempt and never shows them again", async () => {
    const USER = "proxyuser-4711";
    const PASS = "S3cret_pass-0815";
    let list: ReturnType<typeof cred>[] = [];
    let attempts = 0;
    const api = fakeApi({
      "GET /api/socks-credentials": () => ({ credentials: list }),
      "POST /api/socks-credentials": () => {
        attempts++;
        if (attempts === 1) return reply(422, { error: "SOCKS 凭据名称已存在", code: "invalid_field", field: "name" });
        list = [cred({ id: "socks-9", name: "新代理", notes: "" })];
        return reply(201, { credential: list[0] });
      },
    });
    renderAt("#/keys");
    const section = await screen.findByTestId("socks-credentials");
    await within(section).findByText("还没有 SOCKS 凭据");
    await userEvent.click(within(section).getByRole("button", { name: /新建 SOCKS 凭据/ }));
    const drawer = await screen.findByRole("dialog");
    await userEvent.type(within(drawer).getByLabelText("名称"), "新代理");
    await userEvent.type(within(drawer).getByLabelText("SOCKS 用户名"), USER);
    await userEvent.type(within(drawer).getByLabelText("SOCKS 密码"), PASS);
    await userEvent.click(within(drawer).getByRole("button", { name: btn("创建") }));
    await within(drawer).findByText("SOCKS 凭据名称已存在");
    expect(within(drawer).getByLabelText("SOCKS 用户名")).toHaveValue("");
    expect(within(drawer).getByLabelText("SOCKS 密码")).toHaveValue("");

    await userEvent.type(within(drawer).getByLabelText("SOCKS 用户名"), USER);
    await userEvent.type(within(drawer).getByLabelText("SOCKS 密码"), PASS);
    await userEvent.click(within(drawer).getByRole("button", { name: btn("创建") }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    const posts = api.find("POST /api/socks-credentials");
    expect(posts).toHaveLength(2);
    expect(posts[1].body).toEqual({ name: "新代理", notes: "", username: USER, password: PASS });
    const row = await within(section).findByTestId("socks-row-socks-9");
    expect(row).toHaveTextContent("已设置");
    expect(row).toHaveTextContent("不可查看");
    expect(document.body.textContent).not.toContain(USER);
    expect(document.body.textContent).not.toContain(PASS);
    const stored = webStorageDump();
    expect(stored).not.toContain(USER);
    expect(stored).not.toContain(PASS);
    expect(window.location.href).not.toContain(PASS);
  });

  it("rotates with a new username and password, cleared afterwards", async () => {
    const api = fakeApi({
      "GET /api/socks-credentials": () => ({ credentials: [cred()] }),
      "PUT /api/socks-credentials/:id/secret": () => ({ credential: cred({ rotated_at: NOW }) }),
    });
    renderAt("#/keys");
    const row = await screen.findByTestId("socks-row-socks-1");
    await menuItem(within(row).getByRole("button", { name: "马来西亚代理 的更多操作" }), "轮换");
    const drawer = await screen.findByRole("dialog");
    expect(drawer).toHaveTextContent("承载节点重新装机后才生效");
    await userEvent.type(within(drawer).getByLabelText("SOCKS 用户名"), "rotated-user");
    await userEvent.type(within(drawer).getByLabelText("SOCKS 密码"), "rotated-pass");
    await userEvent.click(within(drawer).getByRole("button", { name: btn("轮换") }));
    await waitFor(() => expect(api.find("PUT /api/socks-credentials/socks-1/secret")).toHaveLength(1));
    expect(api.find("PUT /api/socks-credentials/socks-1/secret")[0].body).toEqual({ username: "rotated-user", password: "rotated-pass" });
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(document.body.textContent).not.toContain("rotated-pass");
  });

  it("refuses a delete while an external exit uses it, naming that exit", async () => {
    fakeApi({
      "GET /api/socks-credentials": () => ({ credentials: [cred({ used_by: [{ kind: "node", id: "ext-1", name: "马来西亚住宅" }] })] }),
      "DELETE /api/socks-credentials/:id": () =>
        reply(409, {
          error: "SOCKS 凭据 马来西亚代理 仍被外部出口 马来西亚住宅 使用：先让它们改用别的凭据或删除它们（可以原地轮换）",
          code: "in_use",
          in_use_by: [{ kind: "node", id: "ext-1", name: "马来西亚住宅" }],
        }),
    });
    renderAt("#/keys");
    const row = await screen.findByTestId("socks-row-socks-1");
    expect(row).toHaveTextContent("马来西亚住宅");
    await menuItem(within(row).getByRole("button", { name: "马来西亚代理 的更多操作" }), "删除");
    await confirmModal("删除");
    const refused = await screen.findByTestId("refused-dialog");
    expect(refused).toHaveTextContent("仍被外部出口 马来西亚住宅 使用");
    expect(within(refused).getByRole("link", { name: "马来西亚住宅" })).toHaveAttribute("href", "#/topology/ext-1");
  });
});

describe("overview: first-time order and all region groups", () => {
  it("adds the first provisioning step with the count and shows how many region groups there are", async () => {
    const t = topology();
    t.nodes = t.nodes.map((n) => (n.role === "gateway" ? n : n.id === "hk-2" ? { ...n, server_id: "srv-1", public_key: "PUBKEY=" } : { ...n, server_id: "srv-1" }));
    const groups = Array.from({ length: 10 }, (_, i) => group({ id: `g${i}`, name: `组${i}`, is_default: i === 0 }));
    fakeApi({
      "GET /api/topology": () => t,
      "GET /api/servers": () => ({ servers: [server()] }),
      "GET /api/region-groups": () => ({ groups, default_group: "g0", thresholds: THRESHOLDS }),
    });
    renderAt("#/");
    const steps = await screen.findAllByTestId(/^next-step-/);
    const first = await waitFor(() => {
      const el = steps.find((s) => s.textContent?.includes("远端节点还没有密钥"));
      if (!el) throw new Error("no provisioning step");
      return el;
    });
    // hk-hub, hk-ix, hk-resi, us have no key; hk-2 has one.
    expect(first).toHaveTextContent("4 个远端节点还没有密钥");
    expect(screen.getByRole("link", { name: "远端节点第一次装机" })).toHaveAttribute("href", "#/deploy?section=remote");
    const order = steps.map((s) => s.getAttribute("data-testid"));
    const idx = (text: string) => steps.findIndex((s) => s.textContent?.includes(text));
    expect(idx("远端节点还没有密钥")).toBeLessThan(steps.length - 1);
    expect(order.length).toBeGreaterThan(6);
    expect(await screen.findByTestId("groups-tile-more")).toHaveTextContent("还有 6 个");
    expect(within(screen.getByTestId("groups-tile-more")).getByRole("link")).toHaveAttribute("href", "#/exits");
  });
});

describe("same-exit Mesh quality", () => {
  it("highlights the selected leg and keeps missing samples and history distinct", () => {
    render(<MeshLegRows ids={["synthetic-us", "synthetic-jp"]} history reports={[
      { plan: "synthetic", exit: "synthetic-us", beat: 1800000000, active: "mesh", reason: "quality", switched: 1800000000, direct_loss: 200, direct_rtt: 420, mesh_loss: 0, mesh_rtt: 70, result: "ok" },
      { plan: "synthetic", exit: "synthetic-us", beat: 1799999990, active: "blackhole", reason: "both_down", switched: 1799999990, direct_loss: 1000, direct_rtt: 0, mesh_loss: 1000, mesh_rtt: 0, result: "ok", event: true },
    ]} />);
    expect(screen.getByText("Mesh · 使用中")).toBeInTheDocument();
    expect(screen.getByText("420 ms · 丢包 20%")).toBeInTheDocument();
    expect(screen.getByText("70 ms · 丢包 0%")).toBeInTheDocument();
    expect(screen.getByText("Mesh 质量持续更好")).toBeInTheDocument();
    expect(screen.getByText(/暂无样本/)).toBeInTheDocument();
    expect(screen.getByText(/双腿不可用 · 黑洞/)).toBeInTheDocument();
    expect(screen.getByText(/双腿无响应/)).toBeInTheDocument();
  });
});


it("shows measured gateway RTT beside a group member without inventing group health", async () => {
 fakeApi({
  "GET /api/topology":()=>topology(),
  "GET /api/region-groups":()=>({groups:[group()],default_group:"hk",thresholds:THRESHOLDS}),
  "GET /api/exits/latency":()=>({available:true,running:false,rows:[{exit_id:"hk-ix",name:"香港 IX",scope:"exit_resolver",state:"ok",rtt_ms:42.25,sent:3,received:3,stale:false,measured_at:NOW}]})
 });
 renderAt("#/exits",{foldsOpen:true});
 const member=await screen.findByTestId("member-hk-hk-ix");
 await waitFor(()=>expect(member).toHaveTextContent("42.3 ms · 网关实测"));
 expect(within(screen.getByTestId("group-hk")).getByTestId("group-model")).toHaveTextContent("未收到组健康报告");
});
