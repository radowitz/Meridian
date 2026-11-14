// Second display pass (docs/ui-layout.md, "Second pass"): the pieces jsdom
// can prove outside a whole page — the import drawer's upload control and
// placeholder, the remote-access mode cards, the topology's routed links.

import { App as AntApp } from "antd";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { responsesOf, keepFetch, renderDemoPage, layoutChecks } from "./demo/testkit";
import { CONFIG_PLACEHOLDER, ImportDrawer } from "./RulesImport";
import { LAYOUT, NODE_WIDTH, autoLayout, edgeRoute } from "./TopologyPage";
import type { Node, Topology } from "./types";

describe("import drawer: upload control and placeholder", () => {
  it("offers a Chinese file control that reads the file in the browser, and a real multi-line example", async () => {
    const topo = (await responsesOf("healthy"))["GET /api/topology"].body as Topology;
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    render(
      <AntApp>
        <ImportDrawer open topo={topo} onClose={() => {}} onDone={() => {}} />
      </AntApp>,
    );
    const drawer = await screen.findByRole("dialog");
    const box = within(drawer).getByLabelText("mihomo 配置") as HTMLTextAreaElement;
    expect(box.placeholder).toBe(CONFIG_PLACEHOLDER);
    expect(box.placeholder.split("\n")).toHaveLength(3);
    expect(box.placeholder).not.toContain("\\n");
    const pick = within(drawer).getByTestId("import-file-pick");
    expect(within(pick).getByRole("button", { name: "上传配置文件" })).toHaveTextContent("选择配置文件");
    expect(within(pick).getByTestId("import-file-name")).toHaveTextContent("未选择文件");
    // The browser's own file input is hidden behind the button.
    const input = pick.querySelector<HTMLInputElement>('input[type="file"]')!;
    expect(input).not.toBeVisible();
    expect(input.accept).toBe(".yaml,.yml,.txt");
    const file = new File(["rules:\n  - MATCH,Proxy\n"], "demo.yaml", { type: "text/yaml" });
    fireEvent.change(input, { target: { files: [file] } });
    await waitFor(() => expect(box.value).toBe("rules:\n  - MATCH,Proxy\n"));
    expect(within(pick).getByTestId("import-file-name")).toHaveTextContent("已读入 demo.yaml");
    // Read locally: nothing was sent anywhere.
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});

describe("remote access: add-device drawer", () => {
  keepFetch();
  it("shows each mode as one sentence, its safety line visible and the long explanation collapsed", async () => {
    await renderDemoPage("healthy", "remote");
    layoutChecks("#/remote");
    await userEvent.click(screen.getAllByRole("button", { name: /添加设备/ })[0]);
    const drawer = await screen.findByRole("dialog");
    for (const m of ["full", "home"]) {
      const card = within(drawer).getByTestId(`mode-card-${m}`);
      expect(within(card).getByRole("radio")).toBeInTheDocument();
      // The long text from the API is behind 「了解更多」 (collapsed), not shown.
      const more = card.querySelector<HTMLElement>(".explain-more")!;
      expect(more).not.toBeVisible();
      expect(more.textContent!.length).toBeGreaterThan(40);
    }
    const safety = within(drawer).getByTestId("mode-safety-home");
    expect(safety).toBeVisible();
    expect(safety.closest("[hidden]")).toBeNull();
    expect(safety).toHaveTextContent("不受分流和防泄漏规则保护");
    // The page itself: one sentence about the independent resource; the
    // "can the phone reach home" statement is a visible safety notice in the devices section.
    expect(screen.getByTestId("remote-independent").querySelector(".ant-alert")).toBeNull();
    const notice = [...document.querySelectorAll<HTMLElement>(".section .safety-notice")].find((n) => n.textContent?.includes("面板验证不了"));
    expect(notice).toBeDefined();
  });
});

describe("topology: links do not run under cards", () => {
  const node = (id: string, role: Node["role"]): Node => ({ id, name: id, role, managed: true }) as Node;
  const ns = [node("gw", "gateway"), node("hub", "hub"), ...Array.from({ length: 9 }, (_, i) => node(`ex${i}`, "exit"))];

  it("shifts a wrapped column by part of a row, so a link to it crosses the first column between two cards", () => {
    const pos = autoLayout(ns);
    const exits = ns.filter((n) => n.role === "exit").map((n) => pos.get(n.id)!);
    const xs = [...new Set(exits.map((p) => p.x))].sort((a, b) => a - b);
    expect(xs).toHaveLength(2);
    const first = exits.filter((p) => p.x === xs[0]);
    const second = exits.filter((p) => p.x === xs[1]);
    const hub = pos.get("hub")!;
    const CARD_H = 80; // a three-line card (styles.css): name, role, server
    for (const t of second) {
      // The link leaves the hub's right side, turns in the gap next to it, then runs at the target's middle height.
      const r = edgeRoute(hub.x + NODE_WIDTH, hub.y + CARD_H / 2, t.x, t.y + CARD_H / 2);
      expect(r.routed).toBe(true);
      expect(r.centerX).toBeGreaterThan(hub.x + NODE_WIDTH);
      expect(r.centerX).toBeLessThan(xs[0]);
      const y = t.y + CARD_H / 2;
      for (const c of first) expect(y < c.y || y > c.y + CARD_H).toBe(true);
      // Its label sits in the gap just before the target, not on a card.
      expect(r.labelX).toBeGreaterThan(xs[0] + NODE_WIDTH);
      expect(r.labelX).toBeLessThan(t.x);
    }
    // A link to the neighbouring column stays the usual curve.
    expect(edgeRoute(hub.x + NODE_WIDTH, 0, xs[0], 0).routed).toBe(false);
    expect(LAYOUT.colWidth - NODE_WIDTH).toBeGreaterThan(0);
  });
});
