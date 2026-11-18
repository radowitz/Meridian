// Every page in the demo's "degraded" scenario (testkit.tsx).

import { screen, waitFor } from "@testing-library/react";
import { describe, expect } from "vitest";
import { ALL_PAGES } from "./scenarios";
import { keepFetch, pageTests } from "./testkit";

describe("demo pages: degraded", () => {
  keepFetch();
  pageTests("degraded", ALL_PAGES, {
    "": async () => {
      // The tiles load independently: wait for the state, not for a clock.
      await waitFor(() => expect(screen.getByTestId("sharing-path")).toHaveTextContent("备用枢纽"));
      // The relay tile names the problems (evicted relays) in its one coloured line.
      await waitFor(() => expect(screen.getByTestId("relay-sharing")).toHaveTextContent("已剔除"));
      // 服务器 tile: one row per server needing attention, the name cut (full text on hover/focus) and the tag in its own slot.
      for (const r of document.querySelectorAll<HTMLElement>('[data-testid^="servers-tile-row-"]')) {
        expect(r.querySelector(".tile-item-name .ellipsis-text a")?.textContent).toBeTruthy();
        expect(r.querySelector(".tile-item-status .ant-tag")).not.toBeNull();
      }
    },
    // The three logs with observation gaps, each said in words.
    "dns-log": () => {
      // Still recording, next to a resolver nobody verified: the reason, what to do, and no way to turn it on again elsewhere.
      expect(screen.getByTestId("dns-log-unavailable")).toHaveTextContent("1.2026.12.20-0815");
      expect(screen.getByTestId("dns-log-unavailable")).toHaveTextContent("verify-smartdns.sh --audit-check --record");
      expect(screen.getByTestId("dns-log-runtime")).toHaveTextContent("解析日志仍在记录");
      // One address, two MACs; records that are still listed.
      expect(screen.getByTestId("dns-log-devices")).toHaveTextContent("2 个 MAC");
      expect(screen.getByTestId("dns-log-matched")).toHaveTextContent(/共 \d\d 条查询符合/);
    },
    "conn-log": () => {
      expect(screen.getByTestId("sniff-journal-unclean")).toHaveTextContent("没有正常退出");
      expect(screen.getByTestId("sniff-journal-unclean")).toHaveTextContent("3 条连接没有记录");
      expect(screen.getByTestId("sniff-journal")).toHaveTextContent("示例手机");
    },
    "link-log": () => {
      expect(screen.getByTestId("link-log-carrying")).toHaveTextContent("备用枢纽");
      expect(screen.getByTestId("link-log-abnormal")).toHaveTextContent("被剔除");
      expect(screen.getByTestId("link-log-abnormal")).toHaveTextContent("网关自检失败");
      expect(screen.getByTestId("link-log-unknown")).toHaveTextContent("现在未知");
      expect(screen.getByTestId("link-log-flapping")).toHaveTextContent("已变化 34 次");
      const shapes = screen.getAllByTestId("link-event").map((e) => e.getAttribute("data-shape"));
      for (const s of ["gap", "after_gap", "merged", "change"]) expect(shapes, s).toContain(s);
      const gap = screen.getAllByTestId("link-event").find((e) => e.getAttribute("data-shape") === "gap")!;
      expect(gap).toHaveTextContent("没有采集");
      const merged = screen.getAllByTestId("link-event").find((e) => e.getAttribute("data-shape") === "merged")!;
      expect(merged).toHaveTextContent("不是一次连续的中断");
      // A duration that ran into the gap is a lower bound.
      expect(screen.getAllByTestId("link-event-prev").some((e) => /^至少 /.test(e.textContent ?? ""))).toBe(true);
    },
    exits: () => {
      // Relay sharing: the state cell is at most a tag line and one cut reason line.
      for (const s of document.querySelectorAll<HTMLElement>('[data-testid^="relay-status-"]')) {
        const cell = s.closest("td");
        if (!cell) continue;
        expect(cell.querySelectorAll(":scope > .cell-stack > *").length).toBeLessThanOrEqual(2);
      }
    },
  });
});
