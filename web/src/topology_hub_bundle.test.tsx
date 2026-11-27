import { screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { HubLegReport } from "./MeshLegQuality";
import { exitNode, topology as pageTopology } from "./pages_fixtures";
import { fakeApi, renderAt } from "./testing";
import { HUB_GROUP_ID, bentPath, hubBundle, orderedHubs, quietStandby, splitFrameChanges, toFlow } from "./TopologyPage";
import type { Link, Node, Topology, Transport } from "./types";

const node = (id: string, role: Node["role"], extra: Partial<Node> = {}): Node => ({ id, name: id, role, managed: true, region: "hk", ...extra }) as Node;
const link = (id: string, from: string, to: string, transport: Transport = "direct_wg", extra: Partial<Link> = {}): Link =>
  ({ id, from, to, transport, enabled: true, standby: false, ...extra }) as Link;

// Two hubs (the backup listed first), two exits dialling both, one of them
// with Mesh standby legs; a relay into the primary hub.
function topo(): Topology {
  return {
    nodes: [
      node("gw", "gateway"),
      node("relay", "relay"),
      node("hub5", "hub", { hub_tier: "backup" }),
      node("hub10", "hub", { hub_tier: "primary" }),
      node("us7", "exit"),
      node("us8", "exit"),
    ],
    links: [
      link("gw-relay", "gw", "relay", "udp_wss_failover"),
      link("relay-hub10", "relay", "hub10"),
      link("us7-hub10", "us7", "hub10"),
      link("us7-hub5", "us7", "hub5"),
      link("hub10-us7-mesh", "hub10", "us7", "cf_mesh", { standby: true }),
      link("hub5-us7-mesh", "hub5", "us7", "cf_mesh", { standby: true }),
      link("us8-hub10", "us8", "hub10"),
      link("us8-hub5", "us8", "hub5", "direct_wg", { enabled: false }),
    ],
  } as unknown as Topology;
}

describe("topology: hubs drawn as one group", () => {
  it("gives each exit one dot per hub, the primary hub first, with the hub's main link state", () => {
    const t = topo();
    expect(orderedHubs(t).map((h) => h.id)).toEqual(["hub10", "hub5"]);
    const b = hubBundle(t, null, new Set(["us7-hub5"]))!;
    expect(b.links.size).toBe(6);
    const us7 = b.dots.get("us7")!;
    expect(us7.map((d) => [d.hub, d.link, d.state])).toEqual([
      ["hub10", "us7-hub10", "ok"],
      ["hub5", "us7-hub5", "bad"],
    ]);
    expect(us7[1].text).toContain("有错误");
    expect(b.dots.get("us8")!.map((d) => d.state)).toEqual(["ok", "idle"]);
  });

  it("draws one line per exit from the hub frame and hides quiet standby links until asked", () => {
    const t = topo();
    const plain = toFlow(t, new Map(), [], null, { showStandby: false, focus: null });
    const ids = plain.edges.map((e) => e.id).sort();
    expect(ids).toEqual(["gw-relay", "relay-hub10", `${HUB_GROUP_ID}>us7`, `${HUB_GROUP_ID}>us8`].sort());
    expect(plain.edges.filter((e) => e.source === HUB_GROUP_ID).every((e) => !e.label)).toBe(true);

    const standby = toFlow(t, new Map(), [], null, { showStandby: true, focus: null });
    expect(standby.edges.map((e) => e.id)).toEqual(expect.arrayContaining(["hub10-us7-mesh", "hub5-us7-mesh"]));
  });

  it("shows the real links of the exit in focus, drawn left to right and apart when parallel", () => {
    const f = toFlow(topo(), new Map(), [], null, { showStandby: false, focus: "us7" });
    const real = f.edges.filter((e) => e.className?.includes("focus"));
    expect(real.map((e) => e.id).sort()).toEqual(["hub10-us7-mesh", "hub5-us7-mesh", "us7-hub10", "us7-hub5"]);
    // An exit dials its hub, but the line runs from the hub (left) to the exit (right).
    for (const e of real) expect([e.source, e.target]).toEqual([e.id.includes("hub10") ? "hub10" : "hub5", "us7"]);
    // The second link between the same two cards bends further out.
    const alts = real.filter((e) => e.source === "hub10").map((e) => (e.data as { alt: number }).alt);
    expect(alts.sort()).toEqual([0, 1]);
    expect(f.edges.find((e) => e.id === `${HUB_GROUP_ID}>us7`)?.className).toContain("dim");
  });

  it("draws links as they are with a single hub", () => {
    const t = topo();
    t.nodes = t.nodes.filter((n) => n.id !== "hub5");
    t.links = t.links.filter((l) => l.from !== "hub5" && l.to !== "hub5");
    expect(hubBundle(t, null, new Set())).toBeNull();
    const f = toFlow(t, new Map(), [], null, { showStandby: true, focus: null });
    expect(f.edges.some((e) => e.source === HUB_GROUP_ID)).toBe(false);
    expect(f.edges.map((e) => e.id)).toContain("us7-hub10");
  });
});

describe("topology: what the hub drawing must not hide or misstate", () => {
  it("keeps a lone standby link (it may be the one carrying) and folds only the standby half of a pair", () => {
    const t = topo();
    const lone = link("hub10-us8-mesh", "hub10", "us8", "cf_mesh", { standby: true });
    t.links = [...t.links.filter((l) => l.id !== "us8-hub10"), lone];
    expect(quietStandby(lone, t, null)).toBe(false);
    expect(quietStandby(t.links.find((l) => l.id === "hub10-us7-mesh")!, t, null)).toBe(true);
    const f = toFlow(t, new Map(), [], null, { showStandby: false, focus: null });
    expect(f.edges.map((e) => e.id)).toContain(`${HUB_GROUP_ID}>us8`);
  });

  it("shows a hub's failed route update as a problem, not as enabled", () => {
    const rep = { exit: "us7", hub: "hub10", result: "failed", active: "blackhole", reason: "route_failed" } as unknown as HubLegReport;
    const dot = hubBundle(topo(), [rep], new Set())!.dots.get("us7")![0];
    expect(dot.state).toBe("bad");
    expect(dot.text).toContain("路由更新失败");
  });

  it("bends a second line between the same cards away from the first", () => {
    const [a] = bentPath(0, 0, 100, 0, 1);
    const [b] = bentPath(0, 0, 100, 0, 2);
    expect(a).not.toBe(b);
    expect(a).toContain("C50,28");
  });
});

describe("topology: second review round", () => {
  const failed = (exit: string, hub: string) => ({ exit, hub, result: "failed", active: "blackhole", reason: "route_failed" }) as unknown as HubLegReport;

  it("always draws the open link, even a folded standby one", () => {
    const f = toFlow(topo(), new Map(), [], null, { showStandby: false, focus: null, selectedLink: "hub10-us7-mesh" });
    expect(f.edges.find((e) => e.id === "hub10-us7-mesh")?.selected).toBe(true);
  });

  it("speaks for the enabled link when an old disabled one comes first", () => {
    const t = topo();
    t.links = [link("old", "us8", "hub5", "direct_wg", { enabled: false }), ...t.links.filter((l) => l.id !== "us8-hub5"), link("us8-hub5-new", "us8", "hub5")];
    const dot = hubBundle(t, null, new Set())!.dots.get("us8")![1];
    expect([dot.link, dot.state]).toEqual(["us8-hub5-new", "ok"]);
  });

  it("reports a route failure on an exit's only Mesh leg", () => {
    const t = topo();
    t.nodes = t.nodes.filter((n) => n.id !== "hub5");
    t.links = [link("hub10-v6-mesh", "hub10", "us8", "cf_mesh")];
    const f = toFlow(t, new Map(), [], [failed("us8", "hub10")], { showStandby: false, focus: null });
    const e = f.edges.find((x) => x.id === "hub10-v6-mesh")!;
    expect(e.label).toBe("路由更新失败");
    expect(e.className).toContain("has-error");
    expect(e.animated).toBe(false);
  });

  it("animates the leg that carries after a switch to Mesh", () => {
    const rep = { exit: "us7", hub: "hub10", result: "ok", active: "mesh", reason: "direct_down" } as unknown as HubLegReport;
    const f = toFlow(topo(), new Map(), [], [rep], { showStandby: false, focus: "us7" });
    expect(f.edges.find((e) => e.id === "us7-hub10")?.animated).toBe(false);
    expect(f.edges.find((e) => e.id === "hub10-us7-mesh")?.animated).toBe(true);
  });

  it("separates parallel links with a single hub too", () => {
    const t = topo();
    t.nodes = t.nodes.filter((n) => n.id !== "hub5");
    t.links = t.links.filter((l) => l.from !== "hub5" && l.to !== "hub5");
    const f = toFlow(t, new Map(), [], null, { showStandby: true, focus: null });
    const alts = f.edges.filter((e) => e.id === "us7-hub10" || e.id === "hub10-us7-mesh").map((e) => (e.data as { alt: number }).alt);
    expect(alts.sort()).toEqual([0, 1]);
  });
});

describe("topology canvas: the hub frame", () => {
  it("keeps the frame's measured size out of the cards' state, and sends no empty card batch", () => {
    const only = splitFrameChanges([{ type: "dimensions", id: HUB_GROUP_ID, dimensions: { width: 240, height: 200 } }]);
    expect(only).toEqual({ nodes: [], frame: { width: 240, height: 200 } });
    const mixed = splitFrameChanges([
      { type: "dimensions", id: HUB_GROUP_ID, dimensions: { width: 240, height: 200 } },
      { type: "position", id: "us", position: { x: 1, y: 2 } },
    ]);
    expect(mixed.nodes.map((c) => ("id" in c ? c.id : ""))).toEqual(["us"]);
  });

  it("draws the frame around two hubs", async () => {
    const t = pageTopology({
      nodes: [
        { ...exitNode("gw", "网关", { role: "gateway", region: "cn" }) },
        { ...exitNode("hub-a", "主枢纽", { role: "hub", hub_tier: "primary" }) },
        { ...exitNode("hub-b", "备用枢纽", { role: "hub", hub_tier: "backup" }) },
        exitNode("us", "美国", { region: "us" }),
      ],
      links: [link("us-a", "us", "hub-a"), link("us-b", "us", "hub-b")],
    });
    fakeApi({ "GET /api/topology": () => t, "GET /api/servers": () => ({ servers: [] }) });
    renderAt("#/topology");
    expect(await screen.findByText("香港枢纽组")).toBeInTheDocument();
    expect(document.querySelector(`.react-flow__node[data-id="${HUB_GROUP_ID}"]`)).not.toBeNull();
  });
});
