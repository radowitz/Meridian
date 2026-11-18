// A topology with no IX: gateway → relays → primary hub → exits, a backup hub
// reached over a standby ix_replacement_wss link, one relay link disabled.
// Pages load and name the primary hub instead of an IX. Synthetic data only.

import { screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { fakeApi, renderAt } from "./testing";
import { hasIX, mainPathText, newLink } from "./TopologyPage";
import type { Topology } from "./types";
import { exitNode, server, topology } from "./pages_fixtures";

function noIX(): Topology {
  const t = topology({
    nodes: [
      exitNode("gw", "网关", { role: "gateway", region: "cn" }),
      exitNode("relay-a", "中继甲", { role: "relay", region: "cn" }),
      exitNode("relay-b", "中继乙", { role: "relay", region: "cn" }),
      exitNode("hub-p", "东京枢纽", { role: "hub", hub_tier: "primary", region: "jp" }),
      exitNode("hub-b", "新加坡枢纽", { role: "hub", hub_tier: "backup", region: "sg" }),
      exitNode("hk-2", "香港二号"),
      exitNode("us", "美国", { region: "us" }),
    ],
    region_groups: [{ id: "hk", name: "香港", region: "hk", members: ["hk-2"], mode: "auto", exclude_residential: true }],
  });
  const add = (from: string, to: string, tr: Parameters<typeof newLink>[3] = "direct_wg", standby = false, enabled = true) =>
    t.links.push({ ...newLink(t, from, to, tr, standby), enabled });
  add("gw", "relay-a");
  add("gw", "relay-b", "direct_wg", false, false);
  add("relay-a", "hub-p");
  add("relay-b", "hub-p", "direct_wg", false, false);
  add("gw", "hub-b", "ix_replacement_wss", true);
  for (const e of ["hk-2", "us"]) {
    add("hub-p", e);
    add("hub-b", e);
  }
  return t;
}

describe("topology without an IX", () => {
  it("derives the main path from the primary hub", () => {
    const t = noIX();
    expect(hasIX(t)).toBe(false);
    expect(mainPathText(t)).toBe("网关 → 中继 → 东京枢纽");
    expect(hasIX(topology({ nodes: [...t.nodes, exitNode("ix", "IX", { role: "ix", managed: false })] }))).toBe(true);
  });

  it("loads the topology page and labels the primary hub without IX wording", async () => {
    fakeApi({
      "GET /api/topology": () => noIX(),
      "GET /api/servers": () => ({ servers: [server()] }),
      "POST /api/validate": () => ({ issues: [], paths: [] }),
    });
    renderAt("#/topology/hub-p");
    const detail = await screen.findByTestId("node-detail");
    expect(within(detail).getByTestId("hub-role")).toHaveTextContent("网关 → 中继 → 东京枢纽");
    // Only the opt-in "IX 即主枢纽" switch may mention IX here.
    expect(within(detail).getByTestId("hub-role").textContent!.replace(/IX 即主枢纽.*$/, "")).not.toMatch(/IX/);
    expect(detail).not.toHaveTextContent(/中继 → IX|境外出口地址（出口拨入）|国内入口地址（中继拨入）/);
    expect(screen.queryByTestId("ix-hub-migration")).toBeNull();
  });

  it("does not mention IX on a relay or the backup WSS link", async () => {
    fakeApi({
      "GET /api/topology": () => noIX(),
      "GET /api/servers": () => ({ servers: [] }),
      "POST /api/validate": () => ({ issues: [], paths: [] }),
    });
    renderAt("#/topology/relay-a");
    expect(await screen.findByTestId("node-detail")).toHaveTextContent("国内中继，把流量送到主枢纽。");
  });

  it("loads the deploy page with disabled relay links and a backup hub", async () => {
    fakeApi({
      "GET /api/topology": () => noIX(),
      "GET /api/servers": () => ({ servers: [] }),
    });
    renderAt("#/deploy");
    expect(await screen.findByTestId("remote-node-hub-p")).toBeInTheDocument();
    expect(document.body).not.toHaveTextContent(/深港|阿里云/);
  });
});
