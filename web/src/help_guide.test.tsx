// 使用说明: one guide behind the header's question-mark button, organised
// like the sidebar, opening at the current page's section (#/help/<page>);
// pages themselves show no description or 「说明」 block.

import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { NAV } from "./App";
import { GUIDE_TEXT } from "./HelpGuide";
import { fakeApi, renderAt } from "./testing";

afterEach(() => vi.restoreAllMocks());

const ROUTES = NAV.flatMap((g) => g.routes);

describe("usage guide", () => {
  for (const r of ROUTES) {
    const id = r.key || "overview";
    it(`#/${r.key}: the header has the guide button; it opens the 「${r.label}」 section; the page shows no description`, async () => {
      fakeApi();
      renderAt(`#/${r.key}`);
      await screen.findByRole("heading", { level: 1, name: r.label }, { timeout: 4000 });
      const page = screen.getByTestId("page");
      // No description, no 「说明」 toggle in the page header, no visible moved explanation.
      expect(page.querySelector(".page-header-desc, [data-testid='page-help'] button")).toBeNull();
      expect(within(page.querySelector(".page-header")!).queryByRole("button", { name: /说明/ })).toBeNull();
      expect(screen.getByTestId("page-help")).not.toBeVisible();
      const btn = screen.getByRole("button", { name: "使用说明" });
      expect(btn.querySelector("svg")).not.toBeNull();
      await userEvent.click(btn);
      expect(window.location.hash).toBe(`#/help/${id}`);
      const guide = await screen.findByRole("dialog", { name: "使用说明" });
      const sec = within(guide).getByTestId(`help-section-${id}`);
      expect(sec).toHaveAttribute("aria-current", "true");
      expect(within(sec).getByRole("heading", { name: r.label })).toBeInTheDocument();
      if (GUIDE_TEXT[r.key]) expect(sec).toHaveTextContent(GUIDE_TEXT[r.key]);
      // The page stays underneath.
      expect(screen.getByRole("heading", { level: 1, name: r.label })).toBeInTheDocument();
    });
  }

  it("is organised like the sidebar: same groups, pages and order", async () => {
    fakeApi();
    renderAt("#/help/rules");
    const guide = await screen.findByRole("dialog", { name: "使用说明" }, { timeout: 4000 });
    const ids = Array.from(guide.querySelectorAll("[data-testid^='help-section-']")).map((s) => s.getAttribute("data-testid")!.slice("help-section-".length));
    expect(ids).toEqual(ROUTES.map((r) => r.key || "overview"));
    const groups = Array.from(guide.querySelectorAll(".help-group-title")).map((h) => h.textContent);
    expect(groups).toEqual(NAV.filter((g) => g.label).map((g) => g.label));
  });

  it("a deep link opens the guide over that page; closing returns to the page", async () => {
    fakeApi();
    renderAt("#/help/exits");
    const guide = await screen.findByRole("dialog", { name: "使用说明" }, { timeout: 4000 });
    expect(within(guide).getByTestId("help-section-exits")).toHaveAttribute("aria-current", "true");
    expect(await screen.findByRole("heading", { level: 1, name: "出口" })).toBeInTheDocument();
    expect(screen.queryByText("没有这个页面")).toBeNull();
    await userEvent.click(within(guide).getByRole("button", { name: "关闭使用说明" }));
    await waitFor(() => expect(screen.queryByRole("dialog", { name: "使用说明" })).toBeNull());
    expect(window.location.hash).toBe("#/exits");
  });

  it("moves the page's own explanations into its section while open, and back out of sight after", async () => {
    fakeApi();
    renderAt("#/dns-log");
    await screen.findByRole("heading", { level: 1, name: "解析日志" }, { timeout: 4000 });
    await waitFor(() => expect(screen.getByTestId("page-help").textContent).not.toBe(""));
    expect(screen.getByTestId("page-help")).not.toBeVisible();
    await userEvent.click(screen.getByRole("button", { name: "使用说明" }));
    const sec = within(await screen.findByRole("dialog", { name: "使用说明" })).getByTestId("help-section-dns-log");
    expect(within(sec).getByTestId("page-help")).toBeVisible();
    await userEvent.keyboard("{Escape}");
    await waitFor(() => expect(screen.queryByRole("dialog", { name: "使用说明" })).toBeNull());
    expect(screen.getByTestId("page-help")).not.toBeVisible();
  });
});
