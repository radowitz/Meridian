// The partial scenarios (deployment guide states, preflight with blocking
// findings, refused save, the three logs off and without data): the pages
// each one changes (testkit.tsx).

import { screen } from "@testing-library/react";
import { describe, expect } from "vitest";
import { SCENARIOS } from "./scenarios";
import { keepFetch, pageTests } from "./testkit";

const TEXT: Record<string, string> = {
  "deploy-running": "下发中",
  "deploy-rate-limited": "已安装 · 健康检查通过",
  "deploy-compensated": "失败并已补偿",
  "deploy-unknown": "结果不明",
  "deploy-done": "全部步骤完成",
  "deploy-verify": "只需核对（3）",
  "deploy-skipped": "已跳过 · 仍待处理",
};

/** The explicit empty state of a log page in a scenario: which state it is. */
function emptyState(id: string): string | null {
  return screen.queryByTestId(`${id}-empty`)?.getAttribute("data-state") ?? null;
}

// The two log scenarios: nothing is recording (off / not installed), and everything records but has no data yet.
const LOGS: Record<string, Record<string, () => void | Promise<void>>> = {
  "logs-off": {
    "dns-log": () => {
      expect(emptyState("dns-log")).toBe("not-enabled");
      expect(screen.getByTestId("dns-log-switch")).toHaveAttribute("data-setting", "off");
      expect(screen.getByTestId("dns-log-switch")).toHaveAttribute("data-installed", "off");
      // The resolver was verified: the journal can be turned on, by an explicit step.
      expect(screen.queryByTestId("dns-log-unavailable")).toBeNull();
      expect(screen.getByRole("button", { name: /打开解析日志/ })).toBeInTheDocument();
    },
    "conn-log": async () => {
      expect(await screen.findByTestId("conn-log-empty")).toHaveAttribute("data-state", "not-enabled");
      expect(screen.getByTestId("conn-log-empty")).toHaveTextContent("去开启按域名嗅探");
    },
    "link-log": () => {
      expect(emptyState("link-log")).toBe("not-installed");
      expect(screen.getByTestId("link-log-empty")).toHaveTextContent("去部署页安装");
      expect(screen.queryByTestId("link-log-current")).toBeNull();
    },
  },
  "logs-empty": {
    "dns-log": () => {
      expect(emptyState("dns-log")).toBe("no-data");
      expect(screen.getByTestId("dns-log-switch")).toHaveAttribute("data-installed", "on");
      expect(screen.getByTestId("dns-log-matched")).toHaveTextContent("共 0 条");
    },
    "conn-log": () => {
      expect(emptyState("conn-log")).toBe("no-data");
      expect(screen.getByTestId("conn-log-names")).toHaveTextContent("网关上未开启");
    },
    "link-log": () => {
      expect(emptyState("link-log")).toBe("no-events");
      expect(screen.getByTestId("link-log-empty")).toHaveTextContent("基线");
      // The state now is there although nothing has changed yet.
      expect(screen.getByTestId("link-log-carrying")).toHaveTextContent("主链路");
      expect(screen.getByTestId("link-log-carrying")).toHaveTextContent("至少");
    },
  },
};

describe("demo pages: partial scenarios", () => {
  keepFetch();
  for (const sc of SCENARIOS.filter((s) => !["healthy", "degraded", "unavailable"].includes(s.id))) {
    pageTests(sc.id, sc.pages, LOGS[sc.id] ?? (TEXT[sc.id] ? { deploy: () => expect(document.body).toHaveTextContent(TEXT[sc.id]) } : {}));
  }
});
