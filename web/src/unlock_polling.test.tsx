// 解锁: the matrix polling while a probe runs (T5). One read at a time, the
// next scheduled after the answer; only the newest read's answer is shown;
// unmount and the end of the probe stop it. Controllable promises and fake
// timers, synthetic data only.

import { act, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { fakeApi, panelStatus, renderAt, reply } from "./testing";
import type { UnlockMatrixView } from "./types";
import { OK_AGENT, topology } from "./pages_fixtures";
import { UNLOCK_POLL_MS } from "./UnlockPage";

const EXITS = [{ id: "us", name: "美国", regions: ["us"], groups: ["us"], identity: "v2:bb" }];

const view = (running: string, state: "unlocked" | "untested" = "untested"): UnlockMatrixView => ({
  running,
  available: true,
  regions: [
    {
      code: "global",
      name: "全球",
      exits: EXITS,
      services: [{ id: "auto-netflix", name: "Netflix", rules: ["auto-netflix"], targets: ["us"], cells: [{ exit_id: "us", state }], recommend: null }],
    },
  ],
});

function deferred<T>() {
  let resolve!: (v: T) => void;
  let reject!: (e: unknown) => void;
  const p = new Promise<T>((a, b) => {
    resolve = a;
    reject = b;
  });
  return { p, resolve, reject };
}

const flush = async (ms = 0) => {
  for (let i = 0; i < 5; i++) await act(() => vi.advanceTimersByTimeAsync(ms / 5));
};

// Answers to GET /api/unlock/matrix, in order; each a value or a deferred.
function rig(first: UnlockMatrixView) {
  const queue: Array<ReturnType<typeof deferred<unknown>>> = [];
  let n = 0;
  const api = fakeApi({
    "GET /api/topology": () => topology(),
    "GET /api/status": () => panelStatus({ ...OK_AGENT, probe_available: true }),
    "GET /api/unlock/matrix": () => {
      n++;
      if (n === 1) return first;
      const d = deferred<unknown>();
      queue.push(d);
      return d.p;
    },
    "POST /api/unlock/jobs/:id/cancel": () => ({ cancelled: "job1" }),
    "POST /api/unlock/run": () => ({ job: { id: "job2" } }),
  });
  const reads = () => api.calls.filter((c) => c.path === "/api/unlock/matrix").length;
  return { api, queue, reads };
}

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe("unlock polling", () => {
  it("never overlaps reads: a read slower than the interval holds the next one back", async () => {
    vi.useFakeTimers();
    const r = rig(view("job1"));
    renderAt("#/unlock");
    await flush(10);
    expect(r.reads()).toBe(1);
    await flush(UNLOCK_POLL_MS);
    expect(r.reads()).toBe(2);
    // The read hangs for three intervals: no second request meanwhile.
    await flush(UNLOCK_POLL_MS * 3);
    expect(r.reads()).toBe(2);
    r.queue[0].resolve(view("job1"));
    await flush(10);
    expect(r.reads()).toBe(2);
    await flush(UNLOCK_POLL_MS);
    expect(r.reads()).toBe(3);
  });

  it("a failed read keeps polling; the finished answer stops it", async () => {
    vi.useFakeTimers();
    const r = rig(view("job1"));
    renderAt("#/unlock");
    await flush(10);
    await flush(UNLOCK_POLL_MS + 10);
    expect(r.reads()).toBe(2);
    r.queue[0].reject(new TypeError("synthetic network failure"));
    await flush(UNLOCK_POLL_MS + 10);
    expect(r.reads()).toBe(3);
    r.queue[1].resolve(view("", "unlocked"));
    await flush(UNLOCK_POLL_MS * 4);
    expect(r.reads()).toBe(3);
    expect(screen.getByRole("button", { name: "全部探测" })).toBeTruthy();
  });

  it("an older running answer arriving after the stop's fresh answer is dropped and does not restart polling", async () => {
    vi.useFakeTimers();
    const r = rig(view("job1"));
    renderAt("#/unlock");
    await flush(10);
    await flush(UNLOCK_POLL_MS + 10);
    expect(r.reads()).toBe(2); // poll read in flight (queue[0])
    await act(async () => screen.getByRole("button", { name: "停止" }).click());
    await flush(10);
    expect(r.reads()).toBe(3); // the stop's fresh read (queue[1])
    r.queue[1].resolve(view("", "unlocked"));
    await flush(10);
    expect(screen.getByRole("button", { name: "全部探测" })).toBeTruthy();
    // The slow poll answer still says running: ignored.
    r.queue[0].resolve(view("job1"));
    await flush(UNLOCK_POLL_MS * 3);
    expect(screen.queryByRole("button", { name: "停止" })).toBeNull();
    expect(screen.getByRole("button", { name: "全部探测" })).toBeTruthy();
    expect(r.reads()).toBe(3);
  });

  it("a stale poll answer keeps polling while the probe still runs (the stop's read still says running)", async () => {
    vi.useFakeTimers();
    const r = rig(view("job1"));
    renderAt("#/unlock");
    await flush(10);
    await flush(UNLOCK_POLL_MS + 10);
    expect(r.reads()).toBe(2); // poll read in flight (queue[0])
    await act(async () => screen.getByRole("button", { name: "停止" }).click());
    await flush(10);
    expect(r.reads()).toBe(3); // the stop's fresh read (queue[1])
    r.queue[1].resolve(view("job1"));
    await flush(10);
    // The superseded poll answer is dropped, yet polling goes on.
    r.queue[0].resolve(view("job1"));
    await flush(UNLOCK_POLL_MS + 10);
    expect(r.reads()).toBe(4);
    r.queue[2].resolve(view("", "unlocked"));
    await flush(UNLOCK_POLL_MS * 3);
    expect(r.reads()).toBe(4);
    expect(screen.getByRole("button", { name: "全部探测" })).toBeTruthy();
  });

  it("unmount cancels the read in flight and schedules nothing more", async () => {
    vi.useFakeTimers();
    const r = rig(view("job1"));
    const v = renderAt("#/unlock");
    await flush(10);
    await flush(UNLOCK_POLL_MS + 10);
    expect(r.reads()).toBe(2);
    v.unmount();
    r.queue[0].resolve(view("job1"));
    await flush(UNLOCK_POLL_MS * 4);
    expect(r.reads()).toBe(2);
  });

  it("a new probe after a finished one polls again; an answer read before it started is dropped", async () => {
    vi.useFakeTimers();
    const r = rig(view(""));
    r.api.on("POST /api/unlock/run", () => reply(200, { job: { id: "job2" } }));
    renderAt("#/unlock");
    await flush(10);
    expect(r.reads()).toBe(1);
    await act(async () => screen.getByRole("button", { name: "全部探测" }).click());
    await flush(10);
    expect(screen.getByRole("button", { name: "停止" })).toBeTruthy();
    await flush(UNLOCK_POLL_MS);
    expect(r.reads()).toBe(2);
    r.queue[0].resolve(view("job2"));
    await flush(UNLOCK_POLL_MS + 10);
    expect(r.reads()).toBe(3);
    r.queue[1].resolve(view("", "unlocked"));
    await flush(UNLOCK_POLL_MS * 3);
    expect(r.reads()).toBe(3);
    expect(screen.getByRole("button", { name: "全部探测" })).toBeTruthy();
  });
});
