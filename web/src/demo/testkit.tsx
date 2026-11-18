// Test helpers of the demo preview (imported only by src/demo/*.test.tsx;
// neither the demo entry nor the production entry imports it).

import { render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, it } from "vitest";
import App from "../App";
import { installDemoFetch, makeDemoApi } from "./api";
import { loadScenario, type DemoResponse } from "./fixtures";
import { healthyTags, helpEntries, proseSentences } from "../prose_check";

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
  // Explanations are collapsed: no visible explanatory sentence by default.
  const prose = proseSentences(document.body, { authoredOnly: true });
  expect(prose.length, `${where}: visible explanation\n${prose.join("\n")}`).toBeLessThanOrEqual(0);
  // One 「说明」 per page, in the header; colour only for problems.
  const help = helpEntries();
  expect(help.map((b) => b.outerHTML.slice(0, 120)), `${where}: 说明 entries`).toHaveLength(Math.min(help.length, 1));
  if (help.length === 1) expect(help[0].closest(".page-header"), `${where}: the 说明 is in the header`).not.toBeNull();
  expect(healthyTags().map((t) => t.textContent), `${where}: coloured tags for healthy states`).toEqual([]);
  // Tags: a status is said once, not stacked per row (data tables and matrices hold per-row states).
  const tags = visibleTags(document.querySelector(".page") ?? document.body);
  const loose = tags.filter((t) => !t.closest(".ant-table, .data-cards, .wide-grid"));
  if ((globalThis as { process?: { env?: Record<string, string> } }).process?.env?.TAG_DUMP) {
    console.log(`@@TAGS ${where} total=${tags.length} outside=${loose.length} ${loose.map((t) => t.textContent).join("|").slice(0, 300)}`);
  }
  expect(loose.length, `${where}: tags outside tables\n${loose.map((t) => t.textContent).join("|")}`).toBeLessThanOrEqual(TAG_BUDGET.loose);
  expect(tags.length, `${where}: tags on the page`).toBeLessThanOrEqual(TAG_BUDGET.total);
}

/**
 * Semantic structure an agent or a screen reader relies on: one h1, one main
 * landmark, the menu in a navigation landmark, at most one primary action in
 * the page header, every button and table header named.
 */
export function structureChecks(where: string) {
  expect(document.querySelectorAll("h1"), `${where}: h1`).toHaveLength(1);
  expect(document.querySelectorAll("main"), `${where}: main landmark`).toHaveLength(1);
  expect(document.querySelector('nav[aria-label="主导航"]'), `${where}: navigation landmark`).not.toBeNull();
  const header = document.querySelector(".page-header");
  expect(header?.querySelectorAll(".ant-btn-primary:not(.ant-dropdown-trigger)").length ?? 0, `${where}: primary actions in the header`).toBeLessThanOrEqual(1);
  const unnamed = [...document.querySelectorAll<HTMLElement>(".page button")].filter(
    (b) => !b.closest("[hidden]") && b.tabIndex >= 0 && !(b.getAttribute("aria-label") || b.getAttribute("title") || b.getAttribute("aria-labelledby") || (b.textContent ?? "").trim()),
  );
  expect(unnamed.map((b) => b.outerHTML.slice(0, 160)), `${where}: buttons without a name`).toEqual([]);
  const blankTh = [...document.querySelectorAll<HTMLElement>(".page thead th")].filter(
    (th) => !th.classList.contains("ant-table-selection-column") && !th.classList.contains("ant-table-row-expand-icon-cell") && !(th.textContent ?? "").trim() && !th.getAttribute("aria-label"),
  );
  expect(blankTh.map((th) => th.outerHTML.slice(0, 200)), `${where}: table headers without text`).toEqual([]);
}

/** Upper bounds of visible tags per page (demo data of real size). */
export const TAG_BUDGET = { loose: 15, total: 160 } as const;

/** Tags (antd Tag and status tags) shown, not inside a hidden region. */
export function visibleTags(root: ParentNode): HTMLElement[] {
  return [...root.querySelectorAll<HTMLElement>(".ant-tag")].filter((t) => !t.closest("[hidden], .explain-more, .ant-drawer:not(.ant-drawer-open), .ant-tooltip, .ant-popover, .ant-select-dropdown"));
}

/** One test per page: renders it in the scenario, checks the layout rules, then runs the optional checks. */
export function pageTests(scenario: string, pages: string[], checks: Record<string, () => void | Promise<void>> = {}) {
  for (const page of pages) {
    it(`${scenario}: #/${page} renders`, async () => {
      await renderDemoPage(scenario, page);
      layoutChecks(`${scenario} #/${page}`);
      structureChecks(`${scenario} #/${page}`);
      await checks[page]?.();
    });
  }
}
