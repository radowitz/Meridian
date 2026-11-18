// The sniff card separates "the unit runs" from "its paths are usable":
// the last self-check per target, recent failures, sniff_denied growth,
// sniff_wg_outer, one primary alert, and the on-demand self-check.

import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { SniffSection, SniffSummary } from "./Sniff";
import { fakeApi, tableBudgets } from "./testing";
import type { SniffDiagnosis, SniffView } from "./types";

afterEach(() => vi.restoreAllMocks());

const AT = "2026-11-14T00:00:00Z";

function selfCheck(defaultOK: boolean) {
  return {
    version: 1,
    trigger: "reload",
    started_at: AT,
    finished_at: AT,
    duration_ms: 412,
    generation: 7,
    targets_sha256: "ab".repeat(32),
    qname: ".",
    qtype: "NS",
    default: "group:hk",
    ok: defaultOK,
    targets: [],
  };
}

function view(d: Partial<SniffDiagnosis> | null): SniffView {
  const diagnosis: SniffDiagnosis | null = d
    ? {
        paths: "usable",
        age_s: 60,
        current: true,
        window_s: 900,
        tunnel_concentrated: false,
        self_check: selfCheck(true),
        verdict: { code: "ok", ok: true, default: "group:hk" },
        denied: {
          present: true,
          packets: 3,
          bytes: 468,
          delta: 0,
          since_s: 300,
          growing: false,
        },
        wg_outer: { present: true, packets: 9000, bytes: 1200000 },
        targets: [
          {
            target: "group:hk",
            default: true,
            tunnel: true,
            check: "ok",
            recent_ok: 40,
            recent_resolve_failed: 0,
            recent_dial_failed: 0, recent_relay_failed: 0,
          },
          {
            target: "exit:jp-a-a-rather-long-exit-name-for-the-layout",
            tunnel: true,
            check: "ok",
            recent_ok: 12,
            recent_resolve_failed: 0,
            recent_dial_failed: 0, recent_relay_failed: 0,
          },
          {
            target: "direct",
            tunnel: false,
            check: "ok",
            recent_ok: 300,
            recent_resolve_failed: 0,
            recent_dial_failed: 0, recent_relay_failed: 0,
          },
        ],
        ...d,
      }
    : null;
  return {
    setting: {
      enabled: true,
      ports: [80, 443],
      ech_public_names: ["cloudflare-ech.com"],
      record_names: false,
    },
    listen_port: 5358,
    coverage: { by_name: ["a"], address_only: ["b"], costs: ["c"] },
    runtime: {
      available: true,
      present: true,
      active: "active",
      health: {
        ready: true,
        mode: "redirect",
        listen: "[::]:5358",
        generation: 7,
        rules: 3,
        targets: ["group:hk"],
        mac_rules: false,
        mac_lookup: true,
        active: 1,
        max_conns: 2048,
        record_names: false,
        ech_outer: true,
        counters: {},
      },
      recent: { record_names: false, connections: [] },
      diagnosis,
    },
  };
}

const INCIDENT: Partial<SniffDiagnosis> = {
  paths: "failing",
  message: "服务在运行，但默认目标 group:hk 的路径不通：解析器 [fd66::53:d]:53 超时，没有任何回应。",
  self_check: selfCheck(false),
  verdict: {
    code: "default_failed",
    ok: false,
    default: "group:hk",
    reason: "默认目标 group:hk 的路径不通：解析器 [fd66::53:d]:53 超时，没有任何回应",
  },
  denied: {
    present: true,
    packets: 231,
    bytes: 36036,
    delta: 41,
    since_s: 300,
    growing: true,
  },
  tunnel_concentrated: true,
  targets: [
    {
      target: "group:hk",
      default: true,
      tunnel: true,
      check: "failed",
      check_reason: "解析器 [fd66::53:d]:53 超时，没有任何回应",
      recent_ok: 0,
      recent_resolve_failed: 230,
      recent_dial_failed: 12, recent_relay_failed: 0,
      last_failure_at: AT,
      last_failure: "resolve_failed timeout",
    },
    {
      target: "direct",
      tunnel: false,
      check: "ok",
      recent_ok: 380,
      recent_resolve_failed: 0,
      recent_dial_failed: 0, recent_relay_failed: 0,
    },
  ],
};

describe("sniff card: paths", () => {
  it("running and usable: both shown, no alert, counters and per-target rows", async () => {
    fakeApi({ "GET /api/sniff": () => view({}) });
    render(<SniffSection />);
    const paths = await screen.findByTestId("sniff-paths");
    expect(screen.getByTestId("sniff-runtime")).toHaveTextContent("运行中");
    expect(screen.getByTestId("sniff-runtime")).toHaveTextContent("路径可用");
    expect(screen.queryByTestId("sniff-alert")).toBeNull();
    expect(within(paths).getByTestId("sniff-denied")).toHaveTextContent("300 秒内没有增长");
    expect(paths).toHaveTextContent("9000 个包已放行");
    expect(paths).toHaveTextContent("第 7 代规则");
    expect(within(paths).getAllByText("可达")).toHaveLength(3);
    const tables = tableBudgets();
    expect(tables.length).toBeGreaterThanOrEqual(1);
    const over = tables.filter((t) => t.width > t.budget);
    expect(over, over.map((t) => `${t.name}: ${t.width} > ${t.budget}`).join("; ")).toEqual([]);
  });

  it("the incident: running but failing, one error alert, denied growing, the default target's reason", async () => {
    fakeApi({ "GET /api/sniff": () => view(INCIDENT) });
    render(<SniffSection />);
    const alert = await screen.findByTestId("sniff-alert");
    expect(alert).toHaveTextContent("默认目标 group:hk 的路径不通");
    expect(screen.getAllByRole("alert")).toHaveLength(1);
    expect(screen.getByTestId("sniff-runtime")).toHaveTextContent("运行中");
    expect(screen.getByTestId("sniff-runtime")).toHaveTextContent("路径不通");
    const paths = screen.getByTestId("sniff-paths");
    expect(within(paths).getByTestId("sniff-denied")).toHaveTextContent("300 秒内 +41，在增长");
    expect(paths).toHaveTextContent("不通");
    expect(paths).toHaveTextContent("230");
  });

  it("degraded: another target failing is a warning, not the default", async () => {
    fakeApi({
      "GET /api/sniff": () =>
        view({
          paths: "degraded",
          message: "默认目标可用；1 个其它目标自检未通过，按名字判断到它们的连接会失败。",
          verdict: {
            code: "ok",
            ok: true,
            default: "group:hk",
            failing: ["exit:us1：解析器 [fd66::54:4]:53 超时，没有任何回应"],
          },
          targets: [
            {
              target: "group:hk",
              default: true,
              tunnel: true,
              check: "ok",
              recent_ok: 40,
              recent_resolve_failed: 0,
              recent_dial_failed: 0, recent_relay_failed: 0,
            },
            {
              target: "exit:us1",
              tunnel: true,
              check: "failed",
              check_reason: "解析器 [fd66::54:4]:53 超时，没有任何回应",
              recent_ok: 0,
              recent_resolve_failed: 17,
              recent_dial_failed: 0, recent_relay_failed: 0,
            },
          ],
        }),
    });
    render(<SniffSection />);
    expect(await screen.findByTestId("sniff-alert")).toHaveTextContent("1 个其它目标自检未通过");
    expect(screen.getByTestId("sniff-runtime")).toHaveTextContent("部分目标不通");
  });

  it("a self-check of other rules is not current; the on-demand self-check reloads the view", async () => {
    let n = 0;
    const api = fakeApi({
      "GET /api/sniff": () =>
        n === 0
          ? view({
              paths: "unchecked",
              current: false,
              message: "最近一次自检不属于当前安装的规则，路径是否可用未知。",
              verdict: {
                code: "stale_generation",
                ok: false,
                reason: "自检结果属于另一版规则",
              },
            })
          : view({}),
      "POST /api/sniff/selfcheck": () => {
        n++;
        return view({});
      },
    });
    render(<SniffSection />);
    const paths = await screen.findByTestId("sniff-paths");
    expect(paths).toHaveTextContent("不属于当前安装的规则");
    expect(screen.getByTestId("sniff-runtime")).toHaveTextContent("路径未自检");
    await userEvent.click(within(paths).getByRole("button", { name: /立即自检/ }));
    await waitFor(() => expect(api.find("POST /api/sniff/selfcheck")).toHaveLength(1));
    await waitFor(() => expect(screen.getByTestId("sniff-runtime")).toHaveTextContent("路径可用"));
  });

  it("the overview tile says running and whether the paths work", () => {
    render(<SniffSummary v={view(INCIDENT)} />);
    expect(screen.getByText("运行中")).toBeInTheDocument();
    expect(screen.getByText("路径不通")).toBeInTheDocument();
  });

  it("recent records: a name that gave no address and a missing socket mark are named, with the mark", async () => {
    const v = view({});
    const rec = {
      start: AT,
      source: "192.168.77.20",
      dest: "198.51.100.50:80",
      proto: "http",
      sniffed: false,
      by: "addr",
      rule_index: -1,
      decide_ms: 21,
      generation: 7,
    };
    v.runtime.recent = {
      record_names: false,
      connections: [
        {
          ...rec,
          why: "name_unresolved",
          target: "group:hk",
          result: "ok",
          error: "nxdomain",
          mark_status: "ok",
          raw_mark: "0x100010d",
          name_rule: { rule_index: 4, rule_id: "home", target: "direct", by: "name", error: "nxdomain" },
        },
        {
          ...rec,
          dest: "198.51.100.51:443",
          why: "other",
          target: "direct",
          result: "mark_missing",
          error: "classification_unconfirmed",
          mark_status: "without_bit",
          raw_mark: "0x0",
          view: "own_address_view",
        },
      ],
    };
    fakeApi({ "GET /api/sniff": () => v });
    render(<SniffSection />);
    expect(await screen.findByText("名字解析不到，按地址")).toBeInTheDocument();
    expect(screen.getByText("分类标记无法确认（失败关闭）")).toBeInTheDocument();
    for (const b of screen.getAllByRole("button", { name: /展开行|Expand row/ })) await userEvent.click(b);
    const details = Array.from(document.querySelectorAll(".row-secondary"))
      .map((e) => e.textContent ?? "")
      .join(" ");
    expect(details).toContain("home → direct（名字不存在，未采用）");
    expect(details).toContain("带接管位 0x100010d");
    expect(details).toContain("缺接管位 0x0；已拒绝，规则和目标栏是转发服务自己的地址判断（未采用）");
  });
});
