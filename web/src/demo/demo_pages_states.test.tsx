// The partial scenarios (deployment guide states, preflight with blocking
// findings, refused save): the pages each one changes (testkit.tsx).

import { describe, expect } from "vitest";
import { SCENARIOS } from "./scenarios";
import { keepFetch, pageTests } from "./testkit";

const TEXT: Record<string, string> = {
  "deploy-running": "下发中",
  "deploy-rate-limited": "已安装 · 健康检查通过",
  "deploy-compensated": "失败并已补偿",
  "deploy-unknown": "结果不明",
  "deploy-done": "全部步骤完成",
};

describe("demo pages: partial scenarios", () => {
  keepFetch();
  for (const sc of SCENARIOS.filter((s) => !["healthy", "degraded", "unavailable"].includes(s.id))) {
    pageTests(sc.id, sc.pages, TEXT[sc.id] ? { deploy: () => expect(document.body).toHaveTextContent(TEXT[sc.id]) } : {});
  }
});
