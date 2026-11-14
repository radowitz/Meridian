// Every page of the panel in the demo's "healthy" scenario (testkit.tsx):
// renders without the page error boundary and without a request the demo
// cannot answer; a few checks that the scenario's state is what is shown.

import { screen } from "@testing-library/react";
import { describe, expect } from "vitest";
import { ALL_PAGES } from "./scenarios";
import { MATRIX_LAYOUT } from "../ui";
import { keepFetch, pageTests } from "./testkit";

describe("demo pages: healthy", () => {
  keepFetch();
  pageTests("healthy", ALL_PAGES, {
    "": () => {
      expect(screen.getByTestId("global-status")).toHaveTextContent("宿主通道正常");
      expect(document.body).toHaveTextContent("主链路（多中继分担）");
      expect(screen.getAllByText("分担中").length).toBeGreaterThanOrEqual(2);
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
    unlock: () => {
      // Region-group headers are cut and bounded by the columns they span (9 exits fit at 1280).
      const heads = document.querySelectorAll<HTMLElement>('[data-testid^="matrix-group-"]');
      expect(heads.length).toBeGreaterThan(0);
      for (const h of heads) {
        const span = Number(h.closest("th")!.getAttribute("colspan") ?? 1);
        expect(h).toHaveClass("ellipsis-text");
        expect(parseInt(h.style.maxWidth, 10)).toBe(span * MATRIX_LAYOUT.exitCol - 14);
      }
      // The widths the browser honours: a fixed-layout table with one <col> per column.
      const table = document.querySelector<HTMLTableElement>('[data-testid="unlock-matrix"]')!;
      expect(table.style.tableLayout).toBe("fixed");
      const widths = [...table.querySelectorAll("colgroup col")].map((c) => parseInt((c as HTMLElement).style.width, 10));
      expect(widths[0]).toBe(MATRIX_LAYOUT.firstCol);
      expect(widths.slice(1).every((w) => w === MATRIX_LAYOUT.exitCol)).toBe(true);
      const sum = widths.reduce((a, b) => a + b, 0);
      expect(parseInt(table.style.width, 10)).toBe(sum);
      if (widths.length - 1 <= MATRIX_LAYOUT.fitExits) expect(sum).toBeLessThanOrEqual(MATRIX_LAYOUT.box);
    },
  });
});
