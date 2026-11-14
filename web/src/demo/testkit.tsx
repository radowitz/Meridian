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

/** One test per page: renders it in the scenario, then runs the optional checks. */
export function pageTests(scenario: string, pages: string[], checks: Record<string, () => void> = {}) {
  for (const page of pages) {
    it(`${scenario}: #/${page} renders`, async () => {
      await renderDemoPage(scenario, page);
      checks[page]?.();
    });
  }
}
