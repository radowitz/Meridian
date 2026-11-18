// Every page in the demo's "unavailable" (first run) scenario (testkit.tsx).

import { screen, waitFor } from "@testing-library/react";
import { describe, expect } from "vitest";
import { ALL_PAGES } from "./scenarios";
import { keepFetch, pageTests } from "./testkit";

describe("demo pages: unavailable", () => {
  keepFetch();
  pageTests("unavailable", ALL_PAGES, {
    "": async () => {
      expect(screen.getByTestId("global-status")).toHaveTextContent("宿主通道不可用");
      await waitFor(() => expect(document.body).toHaveTextContent("添加中继、枢纽和出口所在的主机"));
      // No host agent: the chart is one quiet line, tunnels are unknown (never 全部正常).
      expect(screen.getByTestId("traffic-chart")).toHaveAttribute("data-state", "unavailable");
      expect(screen.getByTestId("ov-tunnels")).toHaveAttribute("data-state", "unknown");
    },
    // Without a host agent none of the three logs can be read: each page says so (never a blank page), and the query journal cannot be turned on.
    "dns-log": () => {
      expect(screen.getByTestId("dns-log-empty")).toHaveAttribute("data-state", "unavailable");
      expect(screen.getByTestId("dns-log-unavailable")).toHaveTextContent("host agent");
      expect(screen.queryByRole("button", { name: /打开解析日志/ })).toBeNull();
      expect(screen.getByTestId("dns-log-scope")).toHaveTextContent("不在日志里");
    },
    "conn-log": () => {
      expect(screen.getByTestId("conn-log-empty").getAttribute("data-state")).toMatch(/^(unreadable|not-enabled)$/);
      expect(screen.getByTestId("conn-log-intro")).toHaveTextContent("不记录");
    },
    "link-log": () => {
      expect(screen.getByTestId("link-log-empty")).toHaveAttribute("data-state", "unreadable");
      expect(screen.getByTestId("link-log-not-in-scope")).toHaveTextContent("meridian-ext-health");
    },
  });
});
