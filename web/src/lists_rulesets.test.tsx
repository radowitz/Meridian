// 名单 → 规则集: list, per-set update, update-all job polling, stale marks.
// Synthetic data only.

import { act, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { entryCount, isStale, shortError } from "./ListsRuleSets";
import { fakeApi, panelStatus, renderAt } from "./testing";
import type { ListsView, RuleSetBulkJob, RuleSetView } from "./types";

const NOW = Date.parse("2026-11-17T12:00:00Z");
const iso = (agoH: number) => new Date(NOW - agoH * 3600_000).toISOString();

const rs = (id: string, extra: Partial<RuleSetView["status"]> = {}): RuleSetView => ({
  rule_set: { id, name: `set-${id}`, url: `https://rules.example.org/${id}.list`, interval_sec: 86400 } as RuleSetView["rule_set"],
  status: { state: "ok", fetched_at: iso(1), counts: { suffix: 10, domain: 5 }, ...extra },
  used_by: [{ rule_id: `r-${id}`, name: `rule-${id}`, position: 3 }],
  candidates: [],
});

const view = (): ListsView => ({
  policy: "automatic",
  saved: true,
  policies: ["domestic", "overseas", "automatic"],
  order: ["domestic", "overseas"],
  sources: [],
  lists: { geosite: [], keywords: [], chnroute: [] },
  host_available: true,
  job: null,
});

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe("rule-set helpers", () => {
  it("counts entries, marks stale, shortens errors", () => {
    expect(entryCount(rs("a"))).toBe(15);
    expect(isStale(rs("a"), NOW)).toBe(false);
    expect(isStale(rs("a", { fetched_at: iso(49) }), NOW)).toBe(true);
    expect(isStale(rs("a", { last_error: "x" }), NOW)).toBe(true);
    expect(isStale(rs("a", { state: "never", fetched_at: undefined }), NOW)).toBe(false);
    expect(shortError("domestic: boom；overseas: bang")).toBe("domestic: boom");
    expect(shortError("x".repeat(200)).length).toBe(80);
  });
});

describe("lists page rule-sets", () => {
  it("lists every set, updates one and all, polls the job to its end", async () => {
    vi.spyOn(Date, "now").mockReturnValue(NOW);
    const running: RuleSetBulkJob = { id: "rs-1", state: "running", total: 2, done: 1, failed: [], skipped: [], started_at: iso(0) };
    let jobReads = 0;
    const api = fakeApi({
      "GET /api/status": () => panelStatus({ agent: { configured: true, ok: true }, lists_available: true }),
      "GET /api/lists": () => view(),
      "GET /api/rule-sets": () => ({
        formats: [],
        rule_sets: [rs("a"), rs("b", { last_error: "domestic: dial tcp: write: operation not permitted；overseas: same", failures: 1 })],
      }),
      "POST /api/rule-sets/:id/update": (r) => ({ ...rs(r.params.id), status: { state: "fetching" } }),
      "POST /api/rule-sets/update-all": () => ({ __status: 202, body: { job: running } }),
      "GET /api/rule-sets/update-all": () => {
        jobReads++;
        return { job: jobReads <= 1 ? null : { ...running, state: "done", done: 2, failed: ["b"], finished_at: iso(0) } };
      },
    });
    renderAt("#/lists");
    const row = await screen.findByText("set-b");
    expect(screen.getByText("set-a")).toBeInTheDocument();
    expect(screen.getByTestId("rs-stale-b")).toHaveTextContent("过期");
    expect(screen.queryByTestId("rs-stale-a")).toBeNull();
    expect(screen.getByText("domestic: dial tcp: write: operation not permitted")).toBeInTheDocument();
    expect(screen.getByText("失败，用旧版")).toBeInTheDocument();
    expect(row).toBeInTheDocument();

    const buttons = screen.getAllByRole("button", { name: "立即更新" });
    // The page's own 立即更新 (lists) plus one per rule-set.
    const rsButtons = buttons.filter((b) => b.closest("#rule-sets"));
    expect(rsButtons).toHaveLength(2);
    await act(async () => rsButtons[0].click());
    await waitFor(() => expect(api.find("POST /api/rule-sets/a/update")).toHaveLength(1));

    const section = document.getElementById("rule-sets")!;
    await act(async () => within(section).getByRole("button", { name: /全部更新/ }).click());
    await waitFor(() => expect(api.find("POST /api/rule-sets/update-all")).toHaveLength(1));
    await waitFor(() => expect(screen.getByTestId("rs-bulk-failed")).toHaveTextContent("1 个失败"), { timeout: 5000 });
    const reads = jobReads;
    await new Promise((r) => setTimeout(r, 2500));
    expect(jobReads).toBe(reads);
  });

  it("stays out of the way when there are no rule-sets", async () => {
    fakeApi({
      "GET /api/status": () => panelStatus({ agent: { configured: true, ok: true }, lists_available: true }),
      "GET /api/lists": () => view(),
      "GET /api/rule-sets": () => ({ formats: [], rule_sets: [] }),
      "GET /api/rule-sets/update-all": () => ({ job: null }),
    });
    renderAt("#/lists");
    await screen.findByText("下载来源");
    expect(document.getElementById("rule-sets")).toBeNull();
  });
});
