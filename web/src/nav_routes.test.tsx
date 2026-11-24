// Every route of the side menu opens its page: one h1 named like the menu
// entry, inside the main landmark, the menu inside a navigation landmark with
// the entry selected, and the document title in step. The logs, the
// resolution settings are pinned by URL so a
// regrouping of the menu can never drop them. Synthetic data only.

import { fireEvent, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { NAV } from "./App";
import { tabGroupOf } from "./page_tabs";
import { fakeApi, renderAt } from "./testing";

afterEach(() => {
  vi.restoreAllMocks();
  sessionStorage.clear();
});

const ROUTES = NAV.flatMap((g) => g.routes);

/** URLs that must keep working whatever the menu looks like. */
const PINNED: [string, string][] = [
  ["#/", "概览"],
  ["#/topology", "拓扑"],
  ["#/exits", "出口"],
  ["#/rules", "分流规则"],
  ["#/lists", "名单"],
  ["#/dns", "解析设置"],
  ["#/dns-log", "解析日志"],
  ["#/conn-log", "连接日志"],
  ["#/link-log", "链路日志"],
  ["#/deploy", "部署"],
  ["#/unlock", "解锁"],
  ["#/servers", "服务器"],
  ["#/keys", "密钥"],
  ["#/cloudflare", "Cloudflare"],
  ["#/remote", "远程接入"],
];

describe("navigation", () => {
  it("finds a page by keyword and opens it from the keyboard", async () => {
    fakeApi();
    renderAt("#/");
    await screen.findByRole("heading", { level: 1, name: "概览" });
    fireEvent.keyDown(window, { key: "k", ctrlKey: true });
    const search = await screen.findByRole("textbox", { name: "搜索页面" });
    await userEvent.type(search, "deploy{Enter}");
    expect(await screen.findByRole("heading", { level: 1, name: "部署" })).toBeInTheDocument();
    expect(window.location.hash).toBe("#/deploy");
  });

  it("the menu holds exactly the pinned routes, each once", () => {
    expect(ROUTES.map((r) => [r.key ? `#/${r.key}` : "#/", r.label]).sort()).toEqual([...PINNED].sort());
    expect(NAV.length).toBeLessThanOrEqual(5);
  });

  for (const [hash, label] of PINNED) {
    it(`${hash} renders 「${label}」 with one h1, landmarks and the menu entry selected`, async () => {
      fakeApi();
      renderAt(hash);
      const h1 = await screen.findByRole("heading", { level: 1, name: label }, { timeout: 4000 });
      expect(screen.getAllByRole("heading", { level: 1 })).toHaveLength(1);
      const main = screen.getByRole("main");
      expect(main).toContainElement(h1);
      const nav = screen.getByRole("navigation", { name: "主导航" });
      // A page of a tab group (page_tabs.ts) selects its group's one menu entry and shows the tabs.
      const page = hash.slice(2);
      const group = tabGroupOf(page);
      const entry = group ? group.title : label;
      const link = within(nav).getByRole("link", { name: entry });
      expect(link).toHaveAttribute("href", group ? `#/${group.tabs[0].key}` : hash);
      expect(nav.querySelector(".ant-menu-item-selected")).toHaveTextContent(entry);
      if (group) {
        const tabs = screen.getByRole("navigation", { name: `${group.title}的标签` });
        expect(within(tabs).getByRole("link", { name: label })).toHaveAttribute("aria-current", "page");
      }
      expect(document.title).toBe(`${label} · Meridian`);
      expect(screen.queryByText("这个页面出错了")).toBeNull();
      expect(screen.queryByText("没有这个页面")).toBeNull();
      // Section headings sit below the page title (h2), never above it.
      for (const h of main.querySelectorAll(".section-title")) expect(h.tagName).toBe("H2");
    });
  }

  for (const old of ["#/leak", "#/acceptance", "#/acceptance/dns-leak"]) {
    it(`${old} (a removed page) opens the overview`, async () => {
      fakeApi();
      renderAt(old);
      expect(await screen.findByRole("heading", { level: 1, name: "概览" }, { timeout: 4000 })).toBeInTheDocument();
      expect(window.location.hash).toBe("#/");
      expect(screen.queryByText("没有这个页面")).toBeNull();
    });
  }

  for (const [old, h1, to] of [
    ["#/service-groups", "分流规则", "#/rules"],
    ["#/service-groups/sg-1", "分流规则", "#/rules"],
  ] as const) {
    it(`${old} (removed service groups) opens 「${h1}」`, async () => {
      fakeApi();
      renderAt(old);
      expect(await screen.findByRole("heading", { level: 1, name: h1 }, { timeout: 4000 })).toBeInTheDocument();
      expect(window.location.hash).toBe(to);
      expect(screen.queryByText("没有这个页面")).toBeNull();
    });
  }

  it("#/rules?service_group=… (an old link) still opens the rules", async () => {
    fakeApi();
    renderAt("#/rules?service_group=sg-1");
    expect(await screen.findByRole("heading", { level: 1, name: "分流规则" }, { timeout: 4000 })).toBeInTheDocument();
    expect(screen.queryByText("没有这个页面")).toBeNull();
  });

  it("an unknown route says so instead of a blank page", async () => {
    fakeApi();
    renderAt("#/no-such-page");
    expect(await screen.findByText("没有这个页面")).toBeInTheDocument();
  });
});
