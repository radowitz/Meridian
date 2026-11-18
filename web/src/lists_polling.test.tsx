// 名单: the job polling (T6). One read at a time; a read slower than the
// interval holds the next one back; the finished answer ends it; leaving
// the page cancels it. Fake timers, synthetic data only.

import { act, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { fakeApi, panelStatus, renderAt } from "./testing";
import type { ListsJob, ListsView } from "./types";

const NOW = "2026-11-17T00:00:00Z";
const running: ListsJob = { id: "lists-1", state: "running", policy: "automatic", lists: ["geosite"], started_at: NOW };

const view = (): ListsView => ({
  policy: "automatic",
  saved: false,
  policies: ["domestic", "overseas", "automatic"],
  order: ["domestic", "overseas"],
  sources: [],
  lists: { geosite: ["cn"], keywords: [], chnroute: [] },
  host_available: true,
  job: running,
});

const flush = async (ms = 0) => {
  for (let i = 0; i < 5; i++) await act(() => vi.advanceTimersByTimeAsync(ms / 5));
};

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe("lists job polling", () => {
  it("never overlaps reads, stops at the finished job and on unmount", async () => {
    vi.useFakeTimers();
    const pending: Array<(v: unknown) => void> = [];
    const api = fakeApi({
      "GET /api/status": () => panelStatus({ agent: { configured: true, ok: true }, lists_available: true }),
      "GET /api/lists": () => view(),
      "GET /api/lists/job": () => new Promise((r) => pending.push(r)),
    });
    const reads = () => api.calls.filter((c) => c.path === "/api/lists/job").length;
    const v = renderAt("#/lists");
    for (let i = 0; i < 100 && reads() === 0; i++) await flush(100);
    expect(reads()).toBe(1);
    await flush(6000);
    expect(reads()).toBe(1);
    pending[0]({ job: running });
    await flush(2010);
    expect(reads()).toBe(2);
    v.unmount();
    pending[1]({ job: { ...running, state: "done", finished_at: NOW } });
    await flush(8000);
    expect(reads()).toBe(2);
  });

  it("a late running answer after completion is dropped and does not restart polling", async () => {
    vi.useFakeTimers();
    const pending: Array<(v: unknown) => void> = [];
    const done: ListsJob = { ...running, state: "done", finished_at: NOW };
    const api = fakeApi({
      "GET /api/status": () => panelStatus({ agent: { configured: true, ok: true }, lists_available: true }),
      "GET /api/lists": () => view(),
      "GET /api/lists/job": () => new Promise((r) => pending.push(r)),
      // Answered out of order: a server snapshot taken while the job still ran.
      // A fresh object (same id) so the page's [v?.job] effect really re-runs
      // and only the finished-job guard keeps the stale "running" out.
      "PUT /api/lists/policy": () => ({ ...view(), policy: "domestic", job: { ...running } }),
    });
    const reads = () => api.calls.filter((c) => c.path === "/api/lists/job").length;
    renderAt("#/lists");
    for (let i = 0; i < 100 && reads() === 0; i++) await flush(100);
    pending[0]({ job: done });
    await flush(10);
    expect(screen.queryByText("更新中")).toBeNull();
    await act(async () => screen.getByRole("radio", { name: /^国内源/ }).click());
    await flush(10);
    expect(api.calls.some((c) => c.path === "/api/lists/policy")).toBe(true);
    // The new view landed (its job object differs from the first one).
    expect(screen.getByRole("radio", { name: /^国内源/ })).toBeChecked();
    await flush(8000);
    expect(screen.queryByText("更新中")).toBeNull();
    expect(reads()).toBe(1);
  });
});
