// Every page of the panel in the demo's "healthy" scenario (testkit.tsx):
// renders without the page error boundary and without a request the demo
// cannot answer; a few checks that the scenario's state is what is shown.

import { screen, waitFor } from "@testing-library/react";
import { describe, expect } from "vitest";
import { ALL_PAGES } from "./scenarios";
import { keepFetch, pageTests } from "./testkit";

describe("demo pages: healthy", () => {
  keepFetch();
  pageTests("healthy", ALL_PAGES, {
    "": async () => {
      expect(screen.getByTestId("global-status")).toHaveTextContent("宿主通道正常");
      await waitFor(() => expect(screen.getByTestId("leak-status-line")).toHaveTextContent("防泄露 正常"));
      expect(screen.getByTestId("ov-gateway")).toHaveTextContent("已同步 v1");
      expect(screen.getByTestId("ov-path")).toHaveTextContent("主链路");
      expect(screen.getByTestId("relay-sharing")).toHaveTextContent("Mbit/s");
      expect(screen.getByTestId("ov-tunnels")).toHaveTextContent("全部正常");
      expect(screen.getByTestId("traffic-chart")).not.toHaveAttribute("data-state", "unavailable");
      // The external SOCKS exit has no key of its own and needs none.
      expect(document.body).not.toHaveTextContent("不受管的节点要在拓扑里填入公钥");
      // 出口地区组 rows: the group name (cut, full text on hover/focus) and the actual member, cut on its own.
      const rows = document.querySelectorAll<HTMLElement>('[data-testid^="groups-tile-row-"]');
      expect(rows.length).toBeGreaterThan(0);
      for (const r of rows) {
        expect(r.querySelector(".group-row-name.ellipsis-text a")?.textContent).toBeTruthy();
        const actual = r.querySelector('[data-testid^="groups-tile-actual-"]');
        if (actual) expect(actual.querySelector(".ellipsis-text")).toHaveAttribute("tabindex", "0");
      }
    },
    // The three logs recording normally: devices with their labels, records, the state now and the timeline.
    "dns-log": () => {
      expect(screen.getByTestId("dns-log-switch")).toHaveAttribute("data-setting", "on");
      expect(screen.getByTestId("dns-log-switch")).toHaveAttribute("data-installed", "on");
      expect(screen.queryByTestId("dns-log-unavailable")).toBeNull();
      expect(screen.queryByTestId("dns-log-empty")).toBeNull();
      expect(screen.getByTestId("dns-log-devices")).toHaveTextContent("示例手机");
      expect(screen.getByTestId("dns-log-devices")).toHaveTextContent("192.168.77.21");
      expect(screen.getByTestId("dns-log-matched")).toHaveTextContent(/共 1\d\d 条查询符合/);
      expect(screen.getByTestId("dns-log-records")).toHaveTextContent("example.");
    },
    "conn-log": () => {
      expect(screen.queryByTestId("conn-log-empty")).toBeNull();
      expect(screen.queryByTestId("sniff-journal-unclean")).toBeNull();
      expect(screen.getByTestId("sniff-journal")).toHaveTextContent("示例手机");
      expect(screen.getByTestId("conn-log-names")).toHaveTextContent("网关上已开启");
    },
    "link-log": () => {
      expect(screen.queryByTestId("link-log-empty")).toBeNull();
      expect(screen.getByTestId("link-log-carrying")).toHaveTextContent("主链路（经分担中的中继）");
      expect(screen.getByTestId("link-log-abnormal")).toHaveTextContent("现在没有处于异常状态的对象");
      expect(screen.queryByTestId("link-log-unknown")).toBeNull();
      expect(screen.queryByTestId("link-log-flapping")).toBeNull();
      const events = screen.getAllByTestId("link-event");
      expect(events.length).toBeGreaterThanOrEqual(6);
      expect(events.every((e) => e.getAttribute("data-shape") === "change")).toBe(true);
      // The external exit is observed by the gateway's own check, and says what that check is not.
      expect(screen.getByTestId("link-log-externals")).toHaveTextContent("有网关自己的检查");
      expect(screen.getByTestId("link-log-not-in-scope")).toHaveTextContent("meridian-ext-health");
    },
    unlock: () => {
      // Regions with exits, Global first; 确认 for a recommendation, 手动 on rows with rules; no AI rows; Viu its own Hong Kong row.
      const tables = [...document.querySelectorAll<HTMLElement>('[data-testid^="unlock-table-"]')].map((t) => t.dataset.testid);
      expect(tables[0]).toBe("unlock-table-global");
      expect(tables).toContain("unlock-table-tw");
      expect(document.querySelector('input[type="checkbox"]')).toBeNull();
      expect(document.querySelectorAll("button").length).toBeGreaterThan(0);
      const labels = [...document.querySelectorAll("button")].map((b) => b.getAttribute("aria-label") ?? "");
      expect(labels.some((l) => l.startsWith("确认 "))).toBe(true);
      expect(labels.some((l) => l.startsWith("手动 "))).toBe(true);
      expect(document.querySelector('[data-testid^="row-"][data-testid*="auto-openai"], [data-testid^="row-"][data-testid*="auto-gemini"], [data-testid="unlock-table-ai"]')).toBeNull();
      expect(document.querySelector('[data-testid="row-hk-auto-viu"]')).not.toBeNull();
    },
  });
});
