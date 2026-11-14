// The row-oriented tables at phone width (390 px class; STACK_QUERY matches):
// rules, servers, SSH and SOCKS keys, remote-access devices, deploy remote
// nodes and deployment records render as stacked cards in the demo's
// "healthy" scenario. jsdom proves the structure (no table, no pinned
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

  it("deploy: remote nodes and deployment records", async () => {
    phoneWidth();
    await renderDemoPage("healthy", "deploy");
    layoutChecks("phone #/deploy");
    expect(cards("remote-node-").length).toBeGreaterThan(0);
    expect(cards("deployment-").filter((c) => c.closest("#deployments")).length).toBeGreaterThan(0);
    expect(document.querySelector(".page .ant-table-cell-fix-right")).toBeNull();
  });
});
