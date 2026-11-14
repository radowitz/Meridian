// Every page in the demo's "degraded" scenario (testkit.tsx).

import { screen } from "@testing-library/react";
import { describe, expect } from "vitest";
import { ALL_PAGES } from "./scenarios";
import { keepFetch, pageTests } from "./testkit";

describe("demo pages: degraded", () => {
  keepFetch();
  pageTests("degraded", ALL_PAGES, {
    "": () => {
      expect(document.body).toHaveTextContent("备用枢纽承载");
      expect(screen.getAllByText("已剔除").length).toBeGreaterThanOrEqual(2);
      // 服务器 tile: one row per server needing attention, the name cut (full text on hover/focus) and the tag in its own slot.
      for (const r of document.querySelectorAll<HTMLElement>('[data-testid^="servers-tile-row-"]')) {
        expect(r.querySelector(".tile-item-name .ellipsis-text a")?.textContent).toBeTruthy();
        expect(r.querySelector(".tile-item-status .ant-tag")).not.toBeNull();
      }
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
