// The overview's live stats panel (rates from counter samples, resets, gaps,
// window, freshness, polling only while visible) and the one-screen layout.

import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import TrafficChart, { POLL_MS, STALE_MS, TrafficStats, fmtCount, fmtRate, freshness, rateBetween, sampleOf } from "./TrafficChart";
import { fakeApi, panelStatus, renderAt } from "./testing";
import type { TrafficView } from "./types";
import { THRESHOLDS, actualOK, group, hubState, topology } from "./pages_fixtures";

const T0 = Date.parse("2026-11-17T01:00:00Z");
const view = (sec: number, bytes: Partial<Record<string, number>>, over: Partial<TrafficView> = {}): TrafficView => ({
  available: true,
  read_at: new Date(T0 + sec * 1000).toISOString(),
  reset: false,
  counters: Object.fromEntries(Object.entries(bytes).map(([k, b]) => [k, { bytes: b!, packets: 1 }])),
  ...over,
});

describe("traffic rates", () => {
  it("bit/s from two samples, per counter", () => {
    const a = sampleOf(view(0, { down_domestic: 0, down_foreign: 1000, up_domestic: 0, up_foreign: 0 }));
    const p = rateBetween(a, view(2, { down_domestic: 2_500_000, down_foreign: 1000, up_domestic: 250_000, up_foreign: 0 }))!;
    expect(p.v.down_domestic).toBe(10_000_000);
    expect(p.v.up_domestic).toBe(1_000_000);
    expect(p.v.down_foreign).toBe(0);
    expect(fmtRate(p.v.down_domestic)).toEqual({ n: "10.0", unit: "Mbit/s" });
  });

  it("a reset sample is a new baseline, never a rate; backwards or missing counters give no value", () => {
    const a = sampleOf(view(0, { down_domestic: 9_000_000, down_foreign: 100 }));
    expect(rateBetween(a, view(2, { down_domestic: 10, down_foreign: 200 }, { reset: true }))).toBeNull();
    expect(rateBetween(null, view(2, { down_domestic: 10 }))).toBeNull();
    const p = rateBetween(a, view(2, { down_domestic: 10, down_foreign: 300 }))!;
    expect(p.v.down_domestic).toBeNull();
    expect(p.v.down_foreign).toBe(800);
    expect(p.v.up_foreign).toBeNull();
    // Unavailable or no time progress: nothing.
    expect(rateBetween(a, { available: false, reset: false, counters: {}, code: "agent_unavailable" })).toBeNull();
    expect(rateBetween(a, view(0, { down_domestic: 9_000_001 }))).toBeNull();
  });

  it("auto units, unknown is a dash, and freshness", () => {
    expect(fmtRate(800)).toEqual({ n: "0.80", unit: "kbit/s" });
    expect(fmtRate(512_000)).toEqual({ n: "512", unit: "kbit/s" });
    expect(fmtRate(2_500_000_000)).toEqual({ n: "2.50", unit: "Gbit/s" });
    expect(fmtRate(null).n).toBe("—");
    expect(fmtCount(null)).toBe("—");
    expect(fmtCount(0)).toBe("0");
    expect(freshness(null, T0, false)).toBe("waiting");
    expect(freshness(T0, T0 + POLL_MS, false)).toBe("live");
    expect(freshness(T0, T0 + STALE_MS + 1, false)).toBe("stale");
    expect(freshness(T0, T0, true)).toBe("paused");
  });

  it("three columns: rates split 国内/国外, connections split with total; no chart", () => {
    const rate = { t: T0, v: { down_domestic: 4e6, down_foreign: 12e6, up_domestic: 3e5, up_foreign: null } };
    const { container } = render(
      <TrafficStats rate={rate} conns={{ available: true, scope: "lan_and_remote_access", split: true, domestic: 12, foreign: 30, redirected: 4, total: 46 }} />,
    );
    expect(container.querySelector("svg")).toBeNull();
    expect(screen.getByTestId("traffic-down-dom")).toHaveTextContent("4.00Mbit/s");
    expect(screen.getByTestId("traffic-down-for")).toHaveTextContent("12.0Mbit/s");
    expect(screen.getByTestId("traffic-up-dom")).toHaveTextContent("300kbit/s");
    expect(screen.getByTestId("traffic-up-for")).toHaveTextContent("—");
    expect(screen.getByTestId("traffic-conn-dom")).toHaveTextContent("12");
    expect(screen.getByTestId("traffic-conn-for")).toHaveTextContent("30");
    expect(screen.getByTestId("traffic-conn-total")).toHaveTextContent("46");
    expect(screen.getByTestId("ts-conns")).not.toHaveTextContent(/重定向|嗅探/);
  });

  it("connections: total only without split, dash (never 0) when unknown", () => {
    const { rerender } = render(<TrafficStats rate={null} conns={{ available: true, scope: "lan_and_remote_access", split: false, domestic: null, foreign: null, redirected: 2, total: 9 }} />);
    expect(screen.queryByTestId("traffic-conn-dom")).toBeNull();
    expect(screen.getByTestId("traffic-conn-total")).toHaveTextContent("9");
    rerender(<TrafficStats rate={null} conns={{ available: false, scope: "lan_and_remote_access", split: false, domestic: null, foreign: null, redirected: null, total: null }} />);
    expect(screen.getByTestId("traffic-conn-total")).toHaveTextContent("—");
    rerender(<TrafficStats rate={null} conns={null} />);
    expect(screen.getByTestId("traffic-conn-total")).toHaveTextContent("—");
    expect(screen.getByTestId("traffic-down-dom")).toHaveTextContent("—");
  });
});

describe("overview", () => {
  afterEach(() => {
    Object.defineProperty(document, "visibilityState", { configurable: true, value: "visible" });
  });

  it("one status line, the live stats and the compact cards", async () => {
    let n = 0;
    const api = fakeApi({
      "GET /api/status": () => panelStatus({ installOver: { installed_version: 7 } }),
      "GET /api/topology": () => topology(),
      "GET /api/traffic": () =>
        view(n++, { down_domestic: n * 500_000, down_foreign: n * 1_000_000, up_domestic: n, up_foreign: n }, {
          connections: { available: true, scope: "lan_and_remote_access", split: true, domestic: 3, foreign: 5, redirected: 1, total: 9 },
          usage_bytes: { domestic: 12_500_000_000, foreign: 1_250_000_000_000 },
        }),
      "GET /api/region-groups": () => ({
        groups: [group({ id: "g0", name: "组0", actual: actualOK("hk-2") })],
        default_group: "g0",
        thresholds: THRESHOLDS,
        hub_state: hubState({ mesh_legs: [{ plan: "p", exit: "hk-2", beat: 1, active: "direct", reason: "stable", switched: 0, direct_loss: 0, direct_rtt: 38, mesh_loss: 0, mesh_rtt: 0, result: "ok" }] }),
      }),
      "GET /api/link-log/current": () => ({ available: true, summary: { at: "2026-11-17T01:00:00Z", abnormal: [], unknown: [], flapping: [], objects: 6 } }),
      // The exits card shows the gateway's measured latency of the exit in use, like 出口.
      "GET /api/exits/latency": () => ({ available: true, running: false, rows: [{ exit_id: "hk-2", name: "香港二号", scope: "exit_resolver", state: "ok", rtt_ms: 38, sent: 3, received: 3, measured_at: new Date().toISOString(), stale: false }] }),
      "GET /api/remote-access": () => ({ settings: { enabled: false }, devices: [] }),
      "GET /api/leakcheck": () => ({ items: [] }),
    });
    renderAt("#/");
    const status = await screen.findByTestId("overview-status");
    await waitFor(() => expect(within(status).getByTestId("ov-path")).toHaveTextContent("主链路"));
    expect(screen.queryByText(/下一步该做什么/)).toBeNull();
    // 防泄露 is a fact like the others: direct child of the status line, same classes, label + tag only.
    const leak = await within(status).findByTestId("leak-status-line");
    expect(leak.parentElement).toBe(status);
    expect(leak).toHaveClass("ov-fact");
    expect(Array.from(leak.children).map((c) => c.className.split(" ")[0])).toEqual(["ov-label", "status-text"]);
    for (const f of Array.from(status.children)) expect(f).toHaveClass("ov-fact");
    expect(await screen.findByTestId("groups-tile-actual-g0")).toHaveTextContent("香港二号");
    expect(await within(screen.getByTestId("groups-tile-row-g0")).findByText(/38\.0 ms/)).toBeInTheDocument();
    expect(await screen.findByTestId("ov-tunnels")).toHaveTextContent("全部正常 · 6 条");
    expect(screen.queryByTestId("ov-remote")).toBeNull();
    // Second sample gives the first rate: the chart is live with current values.
    await waitFor(() => expect(screen.getByTestId("traffic-chart")).toHaveAttribute("data-state", "live"), { timeout: 5000 });
    await waitFor(() => expect(screen.getByTestId("traffic-down-dom")).toHaveTextContent("4.00Mbit/s"), { timeout: 5000 });
    expect(screen.getByTestId("traffic-conn-total")).toHaveTextContent("9");
    expect(screen.getByTestId("traffic-used-domestic")).toHaveTextContent("12.50 GB");
    expect(screen.getByTestId("traffic-used-foreign")).toHaveTextContent("1.25 TB");
    expect(screen.getByTestId("traffic-freshness")).toHaveTextContent("实时");

    // Hidden page: polling stops and the chart says so.
    Object.defineProperty(document, "visibilityState", { configurable: true, value: "hidden" });
    act(() => void document.dispatchEvent(new Event("visibilitychange")));
    expect(screen.getByTestId("traffic-chart")).toHaveAttribute("data-state", "paused");
    const calls = api.find("GET /api/traffic").length;
    await new Promise((r) => setTimeout(r, POLL_MS + 300));
    expect(api.find("GET /api/traffic")).toHaveLength(calls);
  }, 15000);

  it("unknown never reads as normal: tunnels, counters and remote online count", async () => {
    fakeApi({
      "GET /api/topology": () => topology(),
      "GET /api/traffic": () => ({ available: false, reset: false, counters: {}, code: "not_installed" }),
      "GET /api/link-log/current": () => ({
        available: true,
        summary: {
          at: "2026-11-17T01:00:00Z",
          abnormal: [{ class: "tunnel", kind: "wg", id: "wg-us", label: "美国隧道", state: "down", level: "abnormal", reason: "握手超时", since: "", for_s: 0, last_seen: "" }],
          unknown: [{ class: "tunnel", kind: "wg", id: "wg-jp", label: "日本隧道", state: "up", stale: true, level: "ok", since: "", for_s: 0, last_seen: "" }],
          flapping: [],
          objects: 4,
        },
      }),
      "GET /api/remote-access": () => ({ settings: { enabled: true }, devices: [{ id: "d" }], runtime: { available: false, state: "agent_unavailable" } }),
    });
    renderAt("#/");
    await waitFor(() => expect(screen.getByTestId("traffic-chart")).toHaveAttribute("data-state", "unavailable"));
    expect(screen.getByTestId("traffic-chart")).toHaveTextContent("网速：数据面还没装计数器");
    const tunnels = await screen.findByTestId("ov-tunnels");
    expect(tunnels).toHaveAttribute("data-state", "abnormal");
    expect(tunnels).toHaveTextContent("美国隧道握手超时");
    expect(tunnels).toHaveTextContent("日本隧道未知");
    expect(tunnels).not.toHaveTextContent("全部正常");
    expect(await screen.findByTestId("ov-remote")).toHaveTextContent("在线数未知");
  });

  it("link log unreadable: tunnels are unknown, the logs stay one click away", async () => {
    fakeApi({ "GET /api/topology": () => topology(), "GET /api/link-log/current": () => ({ available: false, code: "agent_unavailable" }) });
    renderAt("#/");
    expect(await screen.findByTestId("ov-tunnels")).toHaveTextContent("状态未知 · 宿主通道不可用");
    expect(within(screen.getByTestId("overview-log-links")).getByRole("link", { name: "链路日志" })).toHaveAttribute("href", "#/link-log");
  });
});

describe("traffic chart freshness", () => {
  afterEach(() => {
    vi.useRealTimers();
    Object.defineProperty(document, "visibilityState", { configurable: true, value: "visible" });
  });
  const flush = async (ms: number) => act(async () => void (await vi.advanceTimersByTimeAsync(ms)));
  const down = () => screen.getByTestId("traffic-down-dom");

  it("a reset sample clears the shown rate instead of keeping the old one as 实时", async () => {
    vi.useFakeTimers();
    const seq = [view(0, { down_domestic: 0 }), view(2, { down_domestic: 1_000_000 }), view(4, { down_domestic: 5 }, { reset: true }), view(6, { down_domestic: 10 }, { reset: true })];
    let i = 0;
    fakeApi({ "GET /api/traffic": () => seq[Math.min(i++, seq.length - 1)] });
    render(<TrafficChart />);
    await flush(0);
    await flush(POLL_MS);
    expect(down()).toHaveTextContent("4.00Mbit/s");
    await flush(POLL_MS);
    expect(screen.getByTestId("traffic-chart")).toHaveAttribute("data-state", "live");
    expect(down()).toHaveTextContent("—");
    await flush(POLL_MS);
    expect(down()).toHaveTextContent("—");
  });

  it("returning to the foreground drops the old rate until a new one exists", async () => {
    vi.useFakeTimers();
    let i = 0;
    fakeApi({ "GET /api/traffic": () => view(i * 2, { down_domestic: 1_000_000 * i++ }) });
    render(<TrafficChart />);
    await flush(0);
    await flush(POLL_MS);
    expect(down()).toHaveTextContent("4.00Mbit/s");
    Object.defineProperty(document, "visibilityState", { configurable: true, value: "hidden" });
    act(() => void document.dispatchEvent(new Event("visibilitychange")));
    Object.defineProperty(document, "visibilityState", { configurable: true, value: "visible" });
    act(() => void document.dispatchEvent(new Event("visibilitychange")));
    await flush(0);
    expect(screen.getByTestId("traffic-chart")).toHaveAttribute("data-state", "live");
    expect(down()).toHaveTextContent("—");
  });

  it("shows upload and download together and keeps the chart during a read outage", async () => {
    vi.useFakeTimers();
    let i = 0;
    fakeApi({ "GET /api/traffic": () => {
      const n = i++;
      if (n >= 3) return { available: false, reset: false, counters: {}, code: "read_failed" };
      return view(n, {
        down_domestic: n * 1_000_000, down_foreign: 0, up_domestic: n * 125_000, up_foreign: 0,
      }, { usage_bytes: { domestic: 10 }, usage_since: { domestic: new Date(T0).toISOString() } });
    } });
    render(<TrafficChart />);
    await flush(0);
    await flush(POLL_MS);
    await flush(POLL_MS);
    const chart = screen.getByRole("img", { name: /上传下载图/ });
    fireEvent.keyDown(chart, { key: "ArrowLeft" });
    expect(screen.getByText(/下载 8.00 Mbit\/s · 上传 1.00 Mbit\/s/)).toBeVisible();
    expect(screen.getByText(/起始采样/)).toBeVisible();
    await flush(POLL_MS);
    expect(screen.getByTestId("traffic-freshness")).toHaveTextContent("数据暂停");
    expect(chart).toBeInTheDocument();
    expect(down()).toHaveTextContent("—");
  });

  it("a hanging request goes 过期 on time and hides the numbers", async () => {
    vi.useFakeTimers();
    let i = 0;
    fakeApi({ "GET /api/traffic": () => (i < 2 ? view(i * 2, { down_domestic: 1_000_000 * i++ }) : new Promise(() => {})) });
    render(<TrafficChart />);
    await flush(0);
    await flush(POLL_MS);
    expect(down()).toHaveTextContent("4.00Mbit/s");
    i = 2;
    await flush(POLL_MS + STALE_MS + 1000);
    expect(screen.getByTestId("traffic-chart")).toHaveAttribute("data-state", "stale");
    expect(screen.getByTestId("traffic-freshness")).toHaveTextContent("过期");
    expect(down()).toHaveTextContent("—");
  });

  it("reads an old hub state once and ignores a self-check target that left the rules", async () => {
    const stale = { groups: [group({ id: "g0", name: "组0", actual: { state: "stale", code: "read_old", active: "", alert: false } as never })], default_group: "g0", thresholds: THRESHOLDS, hub_state: hubState() };
    const fresh = { ...stale, groups: [group({ id: "g0", name: "组0", actual: actualOK("hk-2") })], hub_state: hubState({ last_read: { read_at: new Date().toISOString(), ok: true, clock_skew_sec: 0, ignored: [] } }) };
    const api = fakeApi({
      "GET /api/status": () => panelStatus({ installOver: { installed_version: 7 } }),
      "GET /api/topology": () => topology(),
      "GET /api/region-groups": () => stale,
      "POST /api/region-groups/runtime/refresh": () => fresh,
      "GET /api/link-log/current": () => ({ available: true, summary: { at: "2026-11-17T01:00:00Z", abnormal: [], flapping: [], objects: 6,
        unknown: [{ class: "sniff_target", kind: "sniff_target", id: "group:old", label: "自检目标：地区组 old", state: "check_ok", stale: true, level: "ok" }] } }),
      "GET /api/link-log": () => ({ scope: { unobserved: [{ class: "sniff_target", kind: "sniff_target", id: "group:old" }] } }),
    });
    renderAt("#/");
    expect(await screen.findByTestId("groups-tile-actual-g0")).toHaveTextContent("香港二号");
    expect(api.find("POST /api/region-groups/runtime/refresh")).toHaveLength(1);
    // The old target is history (链路日志 says so), not an unknown tunnel, and not counted.
    expect(await screen.findByTestId("ov-tunnels")).toHaveTextContent("全部正常 · 5 条");
  });
});
