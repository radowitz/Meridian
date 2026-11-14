// Test helpers of the demo preview (imported only by src/demo/*.test.tsx;
// neither the demo entry nor the production entry imports it).

import { render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, it } from "vitest";
import App from "../App";
import { installDemoFetch, makeDemoApi } from "./api";
import { loadScenario, type DemoResponse } from "./fixtures";

const cache = new Map<string, Record<string, DemoResponse>>();

/** A scenario's responses (times shifted to now), loaded once per test file. */
export async function responsesOf(id: string) {
  if (!cache.has(id)) cache.set(id, await loadScenario(id));
  return cache.get(id)!;
}

/**
 * Renders the whole panel at a page with the scenario's demo API and waits
 * until it is settled (no loading skeleton, no request in flight); fails on
 * the page error boundary or on any request the demo cannot answer.
 * Returns the container for content checks.
 */
export async function renderDemoPage(scenario: string, page: string) {
  const responses = await responsesOf(scenario);
  const { gaps, pending } = installDemoFetch(makeDemoApi(responses), globalThis as unknown as { fetch: typeof fetch });
  window.history.replaceState(null, "", `/?scenario=${scenario}#/${page}`);
  const view = render(<App />);
  await waitFor(
    () => {
      expect(document.querySelector(".content")).not.toBeNull();
      expect(document.querySelector(".content .ant-skeleton")).toBeNull();
      expect(pending.n).toBe(0);
    },
    { timeout: 8000, interval: 40 },
  );
  expect(screen.queryByText("这个页面出错了")).toBeNull();
  expect(gaps).toEqual([]);
  return view;
}

/** Keeps the real fetch around each test (the demo stand-in replaces it). */
export function keepFetch() {
  let real: typeof fetch;
  beforeEach(() => {
    real = globalThis.fetch;
  });
  afterEach(() => {
    globalThis.fetch = real;
  });
}

/**
 * Page-level alerts: antd alerts in the page that are not inside a section,
 * tile, card, table, drawer, dialog or the sticky save bar (docs/ui-layout.md,
 * "One primary alert"). At most one per page.
 */
export const LOCAL_ALERT_SCOPE = ".section, .tile, .group-card, .data-table-wrap, .ant-table, .ant-drawer, .ant-modal, .sticky-bar, .doc-bar, .ant-collapse, .issues";

export function pageAlerts(root: ParentNode = document): HTMLElement[] {
  return [...root.querySelectorAll<HTMLElement>(".page .ant-alert")].filter((a) => !a.parentElement?.closest(LOCAL_ALERT_SCOPE));
}

/** Alerts that belong to this section itself (not to a nested table, card, drawer or dialog). */
export function sectionAlerts(sec: HTMLElement): HTMLElement[] {
  return [...sec.querySelectorAll<HTMLElement>(".ant-alert")].filter((a) => a.parentElement?.closest(LOCAL_ALERT_SCOPE) === sec);
}

/**
 * The layout rules jsdom can prove on any rendered page: at most one
 * page-level alert; no safety notice inside a collapsed region (an Explain's
 * hidden part, a card's closed details, anything `hidden`); every cut text
 * carries its full text (focusable, non-empty).
 */
export function layoutChecks(where: string) {
  const alerts = pageAlerts();
  expect(alerts.map((a) => a.textContent?.slice(0, 40)), `${where}: page-level alerts`).toHaveLength(Math.min(alerts.length, 1));
  for (const sec of document.querySelectorAll<HTMLElement>(".page .section")) {
    const own = sectionAlerts(sec);
    expect(own.map((a) => a.textContent?.slice(0, 40)), `${where}: alerts in section ${sec.querySelector(".section-head")?.textContent?.slice(0, 20)}`).toHaveLength(Math.min(own.length, 1));
  }
  const hiddenSafety = [...document.querySelectorAll<HTMLElement>(".safety-notice")].filter((n) => n.closest("[hidden], .explain-more, .explain-pop"));
  expect(hiddenSafety.map((n) => n.textContent), `${where}: safety notices inside a collapsed region`).toEqual([]);
  const cut = [...document.querySelectorAll<HTMLElement>(".page .ellipsis-text")].filter((e) => (e.textContent ?? "").trim() !== "" && (e.tabIndex < 0 && !e.closest("[title]") && !e.querySelector("a")));
  expect(cut.map((e) => e.outerHTML.slice(0, 120)), `${where}: cut text without its full text`).toEqual([]);
}

/** One test per page: renders it in the scenario, checks the layout rules, then runs the optional checks. */
export function pageTests(scenario: string, pages: string[], checks: Record<string, () => void> = {}) {
  for (const page of pages) {
    it(`${scenario}: #/${page} renders`, async () => {
      await renderDemoPage(scenario, page);
      layoutChecks(`${scenario} #/${page}`);
      checks[page]?.();
    });
  }
}
