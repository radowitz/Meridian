// The row-oriented tables at phone width (390 px class; STACK_QUERY matches):
// rules, servers, SSH and SOCKS keys, remote-access devices, deploy remote
// nodes and deployment records render as stacked cards in the demo's
// "healthy" scenario, and so do the tables of 解析设置 and the three log pages. jsdom proves the structure (no table, no pinned
// column, a heading per card, every row action present, pagination and
// moving still work); widths and wrapping are browser checks
// (docs/ui-layout.md, "Browser acceptance").

import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { phoneWidth } from "../testing";
import { keepFetch, layoutChecks, renderDemoPage, responsesOf } from "./testkit";

/** Cards whose data-testid starts with `prefix`; each has a heading and an action corner. */
function cards(prefix: string): HTMLElement[] {
  const list = [...document.querySelectorAll<HTMLElement>(`li.data-card[data-testid^="${prefix}"]`)];
  for (const c of list) {
    expect(c.closest(".data-table-wrap")).toHaveAttribute("data-stacked", "true");
    expect(c.querySelector(".data-card-title")?.textContent?.trim(), c.dataset.testid).toBeTruthy();
    expect(c.querySelector(".data-card-actions button, .data-card-actions a"), c.dataset.testid).not.toBeNull();
  }
  return list;
}

async function count(path: string, key: string): Promise<number> {
  const r = await responsesOf("healthy");
  const body = r[`GET ${path}`]?.body as Record<string, unknown[]> | undefined;
  const n = (body?.[key] ?? []).length;
  expect(n, `${path} rows in the scenario`).toBeGreaterThan(0);
  return n;
}

describe("demo at phone width: stacked cards", () => {
  keepFetch();

  it("rules: cards with order controls, edit and paging", async () => {
    phoneWidth();
    await renderDemoPage("healthy", "rules");
    layoutChecks("phone #/rules");
    const wrap = document.querySelector(".rules-table")!.closest(".data-table-wrap")!;
    expect(wrap.querySelector("table")).toBeNull();
    expect(document.querySelector(".page .ant-table-cell-fix-right")).toBeNull();
    const list = cards("rule-row-");
    expect(list).toHaveLength(50);
    for (const c of list.slice(0, 5)) {
      const name = c.dataset.testid!.slice("rule-row-".length);
      expect(within(c).getByRole("button", { name: /编\s*辑/ })).toBeInTheDocument();
      expect(c.querySelector(`[data-testid="rule-pos-${name}"]`)).not.toBeNull();
    }
    // Move the second card up: it becomes number 1 (order controls work in cards).
    const second = list[1].dataset.testid!.slice("rule-row-".length);
    fireEvent.click(within(list[1]).getAllByRole("button").find((b) => /^提前 /.test(b.getAttribute("aria-label") ?? ""))!);
    await waitFor(() => expect(screen.getByTestId(`rule-pos-${second}`)).toHaveTextContent(/^1$/));
    // Page 2 starts at 51.
    fireEvent.click(within(wrap as HTMLElement).getByTitle("2"));
    await waitFor(() => expect(cards("rule-row-")[0].querySelector(".rule-pos")).toHaveTextContent(/^51$/));
  });

  it("servers and keys: one card per row with every action", async () => {
    phoneWidth();
    await renderDemoPage("healthy", "servers");
    layoutChecks("phone #/servers");
    expect(cards("server-row-")).toHaveLength(await count("/api/servers", "servers"));
  });

  it("keys: SSH and SOCKS credentials", async () => {
    phoneWidth();
    await renderDemoPage("healthy", "keys");
    layoutChecks("phone #/keys");
    expect(cards("credential-row-")).toHaveLength(await count("/api/ssh-credentials", "credentials"));
    expect(cards("socks-row-")).toHaveLength(await count("/api/socks-credentials", "credentials"));
  });

  it("remote access: devices", async () => {
    phoneWidth();
    await renderDemoPage("healthy", "remote");
    layoutChecks("phone #/remote");
    expect(cards("device-row-").length).toBeGreaterThan(0);
  });

  // 解析设置 and the three log pages: every table is stacked cards, nothing is pinned, no table scrolls sideways.
  for (const page of ["dns", "dns-log", "conn-log", "link-log"]) {
    it(`${page}: no table scrolls sideways and nothing is pinned`, async () => {
      phoneWidth();
      await renderDemoPage("healthy", page);
      layoutChecks(`phone #/${page}`);
      const root = document.querySelector<HTMLElement>(".page")!;
      expect(root.querySelector("h1")?.textContent?.trim()).toBeTruthy();
      expect(root.querySelector("table")).toBeNull();
      expect(root.querySelector(".ant-table-cell-fix-right")).toBeNull();
      expect(root.querySelector("[data-overflow='true']")).toBeNull();
      for (const w of root.querySelectorAll(".data-table-wrap")) expect(w).toHaveAttribute("data-stacked", "true");
      // Never a blank page: the opening sentences or the settings' status are there.
      expect(document.querySelector("[data-testid$='-intro'], [data-testid='dns-upstream-status']")).not.toBeNull();
      // The per-exit rows are cards (the gateway's row has no action by design, so not cards()).
      if (page === "dns") expect(root.querySelectorAll('li.data-card[data-testid^="dns-exit-"]').length).toBeGreaterThan(1);
      // The logs have data in this scenario: devices, records and events are cards.
      if (page !== "dns") expect(root.querySelectorAll(".data-card").length).toBeGreaterThan(3);
    });
  }

  it("opens log filters in a full-width drawer with a bottom action", async () => {
    phoneWidth();
    await renderDemoPage("healthy", "dns-log");
    fireEvent.click(await screen.findByRole("button", { name: "筛选" }));
    const drawer = await screen.findByRole("dialog", { name: "日志筛选" });
    expect(drawer.closest(".ant-drawer-content-wrapper")).toHaveStyle({ width: "100%" });
    expect(within(drawer).getByTestId("dns-log-filters")).toBeVisible();
    fireEvent.click(within(drawer).getByRole("button", { name: "查看结果" }));
    await waitFor(() => expect(screen.queryByRole("dialog", { name: "日志筛选" })).toBeNull());
  });

  // The link journal at its busiest (the degraded scenario): the state now with its tables, the unknown and
  // flapping objects, and a timeline with a gap, changes found after it and a merged record — all as cards.
  it("link-log with observation gaps: every table is cards", async () => {
    phoneWidth();
    await renderDemoPage("degraded", "link-log");
    layoutChecks("phone degraded #/link-log");
    const root = document.querySelector<HTMLElement>(".page")!;
    expect(root.querySelector("table")).toBeNull();
    expect(root.querySelector("[data-overflow='true']")).toBeNull();
    for (const w of root.querySelectorAll(".data-table-wrap")) expect(w).toHaveAttribute("data-stacked", "true");
    expect(within(screen.getByTestId("link-log-abnormal")).getAllByRole("listitem").length).toBeGreaterThan(4);
    const shapes = screen.getAllByTestId("link-event").map((e) => e.getAttribute("data-shape"));
    expect(shapes).toContain("gap");
    expect(shapes).toContain("merged");
    expect(screen.getByTestId("link-log-unknown")).toBeInTheDocument();
    expect(screen.getByTestId("link-log-flapping")).toBeInTheDocument();
  });

  it("deploy: remote nodes and deployment records", async () => {
    phoneWidth();
    await renderDemoPage("healthy", "deploy");
    layoutChecks("phone #/deploy");
    expect(cards("remote-node-").length).toBeGreaterThan(0);
    expect(cards("deployment-").filter((c) => c.closest("#deployments")).length).toBeGreaterThan(0);
    expect(document.querySelector(".page .ant-table-cell-fix-right")).toBeNull();
  });
});
