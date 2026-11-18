// Lazy routes (web/README.md「首屏与拆包」): every route of NAV loads its own
// page module; the shell shows a loading state while a page module
// downloads, and a page module that fails to load (the network dropped, or
// the panel was upgraded under an open tab) shows a load-failure state with
// a reload action instead of a blank page or the page error.

import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { App as AntApp } from "antd";
import { describe, expect, it, vi } from "vitest";
import { NAV, PageSlot, lazyPage, panelReload } from "./App";
import { fakeApi, renderAt } from "./testing";

/** Route key → the page module it must load. */
const EXPECTED: Record<string, () => Promise<{ default: unknown }>> = {
  "": () => import("./OverviewPage"),
  topology: () => import("./TopologyPage"),
  exits: () => import("./ExitsPage"),
  rules: () => import("./RulesPage"),
  lists: () => import("./ListsPage"),
  dns: () => import("./DNSView"),
  "dns-log": () => import("./DNSLogsPage"),
  "conn-log": () => import("./ConnectionLogsPage"),
  "link-log": () => import("./LinkLogsPage"),
  servers: () => import("./ServersPage"),
  keys: () => import("./CredentialsPage"),
  cloudflare: () => import("./CloudflarePage"),
  remote: () => import("./RemotePage"),
  deploy: () => import("./DeployPage"),
  unlock: () => import("./UnlockPage"),
};

describe("lazy routes", () => {
  it("each route loads its own page module", async () => {
    const routes = NAV.flatMap((g) => g.routes);
    expect(routes.map((r) => r.key).sort()).toEqual(Object.keys(EXPECTED).sort());
    for (const r of routes) {
      const page = (await r.load()).default;
      expect(typeof page, r.key).toBe("function");
      expect(page, r.key).toBe((await EXPECTED[r.key]()).default);
    }
  });

  it("shows the loading state until the page module arrives", async () => {
    let arrive: (m: { default: () => JSX.Element }) => void = () => {};
    const Slow = lazyPage(() => new Promise((resolve) => (arrive = resolve)));
    render(
      <AntApp>
        <PageSlot page="lists" component={Slow} />
      </AntApp>,
    );
    expect(screen.getByTestId("page-loading")).toHaveAccessibleName("页面加载中");
    arrive({ default: () => <p>页面内容</p> });
    expect(await screen.findByText("页面内容")).toBeInTheDocument();
    expect(screen.queryByTestId("page-loading")).toBeNull();
  });

  it("opens a lazy page in the shell and navigates to another one from the menu", async () => {
    fakeApi();
    renderAt("#/lists");
    expect(await screen.findByRole("heading", { level: 1, name: "名单" })).toBeInTheDocument();
    await userEvent.click(within(document.querySelector<HTMLElement>(".nav-menu")!).getByText("解锁"));
    expect(await screen.findByRole("heading", { level: 1, name: "解锁" })).toBeInTheDocument();
    expect(window.location.hash).toBe("#/unlock");
    expect(screen.queryByTestId("page-load-failed")).toBeNull();
    expect(screen.queryByText("这个页面出错了")).toBeNull();
  });

  it("a page module that fails to load shows the failure state with a reload action", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {}); // React reports the caught error
    const reload = vi.spyOn(panelReload, "run").mockImplementation(() => {});
    const Broken = lazyPage(() => Promise.reject(new TypeError("Failed to fetch dynamically imported module: /assets/RulesPage-0000.js")));
    render(
      <AntApp>
        <PageSlot page="rules" component={Broken} />
      </AntApp>,
    );
    const failed = await screen.findByTestId("page-load-failed");
    expect(failed).toHaveTextContent("面板已更新，请刷新");
    expect(failed).toHaveTextContent("刚升级过");
    expect(screen.queryByText("这个页面出错了")).toBeNull();
    await userEvent.click(within(failed).getByRole("button", { name: /刷\s*新/ }));
    expect(reload).toHaveBeenCalledTimes(1);
  });

  it("a page that throws while rendering still shows the page error, not the load failure", async () => {
    vi.spyOn(console, "error").mockImplementation(() => {}); // React reports the caught error
    const Throws = lazyPage(async () => ({
      default: () => {
        throw new Error("渲染失败");
      },
    }));
    render(
      <AntApp>
        <PageSlot page="rules" component={Throws} />
      </AntApp>,
    );
    expect(await screen.findByText("这个页面出错了")).toBeInTheDocument();
    expect(screen.getByText("渲染失败")).toBeInTheDocument();
    await waitFor(() => expect(screen.queryByTestId("page-load-failed")).toBeNull());
  });
});
