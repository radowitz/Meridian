// Third UI pass: discarding unsaved changes asks first; the connection log
// names groups and exits as the topology does.

import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { targetText } from "./Sniff";
import { fakeApi, panelStatus, renderAt } from "./testing";
import { THRESHOLDS, group, topology } from "./pages_fixtures";
import { latencySummary, type ExitLatencyRow } from "./ExitLatency";
import { isCurrent } from "./link_scope";

describe("discarding unsaved topology changes", () => {
  it("asks first and reloads only after the confirmation", async () => {
    const api = fakeApi({ "GET /api/topology": () => topology() });
    renderAt("#/rules");
    await userEvent.click(await screen.findByRole("switch", { name: "启用 Netflix" }));
    const discard = screen.getByRole("button", { name: "放弃修改" });
    await waitFor(() => expect(discard).toBeEnabled());
    const reads = api.find("GET /api/topology").length;
    await userEvent.click(discard);
    expect((await screen.findAllByText("放弃未保存的修改？")).length).toBeGreaterThan(0);
    expect(api.find("GET /api/topology")).toHaveLength(reads);
    await userEvent.click(screen.getAllByRole("button", { name: "放弃修改" }).at(-1)!);
    await waitFor(() => expect(api.find("GET /api/topology").length).toBeGreaterThan(reads));
  });
});

describe("connection log targets", () => {
  it("show the group or exit name when known, the id otherwise", () => {
    const known: Record<string, string> = { "group:hk-home": "香港家宽", "exit:hk2": "hk2（HKT 家宽）" };
    const names = (kind: "group" | "exit", id: string) => known[`${kind}:${id}`];
    expect(targetText("group:hk-home", names)).toBe("地区组 香港家宽");
    expect(targetText("exit:hk2", names)).toBe("出口 hk2（HKT 家宽）");
    expect(targetText("group:gone", names)).toBe("地区组 gone");
    expect(targetText("direct", names)).toBe("直连");
  });
});

describe("locking the panel", () => {
  it("asks first while a group's member order is not saved, and keeps it on cancel", async () => {
    fakeApi({
      "GET /api/topology": () => topology(),
      "GET /api/region-groups": () => ({ groups: [group()], default_group: "hk", thresholds: THRESHOLDS }),
    });
    renderAt("#/exits");
    const card = await screen.findByTestId("group-hk");
    await userEvent.click(within(card).getByRole("button", { name: /^展开 / }));
    await userEvent.click(within(card).getByRole("button", { name: "下移 香港二号" }));
    await userEvent.click(screen.getByRole("button", { name: "锁定" }));
    expect((await screen.findAllByText("有未保存的修改")).length).toBeGreaterThan(0);
    await userEvent.click(screen.getByRole("button", { name: "取消" }));
    expect(within(card).getByRole("button", { name: /保存顺序/ })).toBeVisible();
  });
});

describe("history in the link journal", () => {
  it("only an old reading of an object the rules no longer measure is history", () => {
    const inactive = ["sniff_target|group:old"];
    expect(isCurrent({ kind: "sniff_target", id: "group:old", stale: true }, inactive)).toBe(false);
    // The rules were saved ahead of the gateway: a fresh failing reading still counts.
    expect(isCurrent({ kind: "sniff_target", id: "group:old", stale: false }, inactive)).toBe(true);
    expect(isCurrent({ kind: "sniff_target", id: "group:hk", stale: true }, inactive)).toBe(true);
  });
});

describe("latency summary", () => {
  const row = (over: Partial<ExitLatencyRow>): ExitLatencyRow => ({ exit_id: "x", name: "x", scope: "exit_resolver", state: "ok", rtt_ms: 30, sent: 3, received: 3, measured_at: "2026-11-24T00:00:00Z", stale: false, ...over });
  it("counts fresh own-resolver readings only", () => {
    expect(
      latencySummary([
        row({ exit_id: "a" }),
        row({ exit_id: "b", state: "unreachable", rtt_ms: undefined }),
        row({ exit_id: "c", stale: true }),
        row({ exit_id: "s", scope: "carrier_resolver" }),
      ]),
    ).toBe("1/3 个出口连通 · 1 个不通 · 1 个待重测 · 1 个外部出口只测到承载节点");
  });
});

describe("部署: three status cards, one main action, the rest folded", () => {
  const nodes = [
    { node_id: "gw", node_name: "家宽网关", role: "gateway", state: "changed", pending: true, installed_at: "2026-11-23T10:00:00Z" },
    { node_id: "hk10", node_name: "hk10", role: "hub", state: "changed", pending: true, installed_at: "2026-11-23T09:00:00Z" },
    { node_id: "jp1", node_name: "jp1", role: "exit", state: "in_sync", pending: false, installed_at: "2026-11-20T09:00:00Z" },
  ];
  const api = () =>
    fakeApi({
      "GET /api/status": () => panelStatus({ installOver: { state: "changed", installed_version: 53 }, nodes: nodes as never, pending_nodes: 2 }),
      "GET /api/deploy": () => ({ plan: { steps: [{ node_id: "hk10", node_name: "hk10", phase: "pending" }, { node_id: "gw", node_name: "家宽网关", phase: "pending" }] }, topology_version: "v1", limits: { proves: [], does_not_prove: [], independent: [] }, run: null }),
    });

  it("sums up the gateway, the remote nodes and the last install, and deploys from the header", async () => {
    api();
    renderAt("#/deploy");
    expect(await screen.findByTestId("deploy-stat-gateway", {}, { timeout: 4000 })).toHaveTextContent("有改动待安装");
    expect(screen.getByTestId("deploy-stat-remote")).toHaveTextContent("1 / 2 已是最新");
    expect(screen.getByTestId("deploy-stat-last")).toHaveTextContent("前");
    expect(screen.getByTestId("fold-deploy-pending")).toHaveTextContent("家宽网关、hk10");
    const go = await screen.findByTestId("deploy-auto");
    expect(go).toHaveTextContent("按顺序部署 2 个节点");
    await waitFor(() => expect(go).toBeEnabled());
    await userEvent.click(go);
    expect((await screen.findAllByText("自动预检并部署待变更节点？")).length).toBeGreaterThan(0);
    // The confirmation names what it installs, in order.
    expect(await screen.findByTestId("deploy-auto-confirm")).toHaveTextContent("将安装：hk10、家宽网关");
  });

  it("counts what the plan installs, not the pending flags", async () => {
    fakeApi({
      "GET /api/status": () => panelStatus({ installOver: { state: "changed", installed_version: 53 }, nodes: [nodes[0]] as never, pending_nodes: 1 }),
      "GET /api/deploy": () => ({ plan: { steps: [{ node_id: "jp1", node_name: "jp1", phase: "pending" }, { node_id: "gw", node_name: "家宽网关", phase: "pending" }, { node_id: "hk10", node_name: "hk10", phase: "pending", verify_only: true }] }, topology_version: "v1", limits: { proves: [], does_not_prove: [], independent: [] }, run: null }),
    });
    renderAt("#/deploy");
    expect(await screen.findByTestId("deploy-auto", {}, { timeout: 4000 })).toHaveTextContent("按顺序部署 2 个节点");
  });

  it("a resumed run counts only the steps it can run now", async () => {
    const step = (id: string, over: object = {}) => ({ node_id: id, node_name: id, phase: "pending", can_preflight: true, ...over });
    fakeApi({
      "GET /api/status": () => panelStatus({ installOver: { state: "changed", installed_version: 53 }, nodes: nodes as never }),
      "GET /api/deploy": () => ({
        run: { id: "r1", state: "stopped", current: "b", steps: [step("a", { skip: { kind: "blocked", reason: "x", at: "" } }), step("b"), step("hub", { waiting_for: ["a"] }), step("gw", { waiting_for: ["a"] })] },
        limits: { proves: [], does_not_prove: [], independent: [] },
      }),
    });
    renderAt("#/deploy");
    expect(await screen.findByTestId("deploy-auto", {}, { timeout: 4000 })).toHaveTextContent("按顺序部署 1 个节点");
  });

  it("the same link opens a fold again after it was closed by hand", async () => {
    api();
    renderAt("#/deploy");
    const card = await screen.findByRole("link", { name: "远端节点" }, { timeout: 4000 });
    await userEvent.click(card);
    const fold = await screen.findByRole("button", { name: "远端节点" });
    await waitFor(() => expect(fold).toHaveAttribute("aria-expanded", "true"));
    await userEvent.click(fold);
    expect(fold).toHaveAttribute("aria-expanded", "false");
    await userEvent.click(card);
    await waitFor(() => expect(fold).toHaveAttribute("aria-expanded", "true"));
  });

  it("keeps the gateway part open while a host transaction is unfinished", async () => {
    fakeApi({
      "GET /api/status": () => panelStatus({ installOver: { state: "changed", installed_version: 53 }, pending: { id: "t1", kind: "install", phase: "commit" } as never }),
    });
    renderAt("#/deploy");
    const fold = await screen.findByRole("button", { name: "网关安装与回滚" }, { timeout: 4000 });
    await waitFor(() => expect(fold).toHaveAttribute("aria-expanded", "true"));
  });

  it("a link to a part opens its fold", async () => {
    api();
    renderAt("#/deploy?section=remote");
    const remote = await screen.findByRole("button", { name: "远端节点" });
    expect(remote).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByRole("button", { name: "网关安装与回滚" })).toHaveAttribute("aria-expanded", "false");
  });
});

describe("the save bar of 分流规则 and 拓扑", () => {
  it("is one quiet line when nothing is unsaved, the full bar after a change", async () => {
    fakeApi({ "GET /api/topology": () => topology() });
    renderAt("#/rules");
    const bar = await screen.findByTestId("doc-bar");
    expect(bar).toHaveAttribute("data-dirty", "false");
    expect(within(bar).queryByRole("button", { name: "保存" })).toBeNull();
    await userEvent.click(await screen.findByRole("switch", { name: "启用 Netflix" }));
    await waitFor(() => expect(screen.getByTestId("doc-bar")).toHaveAttribute("data-dirty", "true"));
    expect(within(screen.getByTestId("doc-bar")).getByRole("button", { name: "保存" })).toBeEnabled();
  });

  it("sits at the top of 拓扑 too", async () => {
    fakeApi({ "GET /api/topology": () => topology() });
    renderAt("#/topology");
    const bar = await screen.findByTestId("doc-bar");
    const main = bar.closest("main")!;
    // Before the graph: the first block under the page header.
    expect(main.querySelector(".react-flow")?.compareDocumentPosition(bar)).toBe(Node.DOCUMENT_POSITION_PRECEDING);
  });
});
