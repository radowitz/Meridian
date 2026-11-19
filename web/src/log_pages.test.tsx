// 解析日志 (#/dns-log) and 链路日志 (#/link-log) as small renders of the page
// components (the connection log page is covered in sniff_journal.test.tsx).
//
// DNS query log: the opening sentences; the explicit switch — the
// capability gate first (unavailable: the reason and the action, and no way
// to turn it on), enabling only after the acknowledgement and then "saved,
// not in effect: preflight → confirm → install", disabling with what happens
// to the records; the empty states (not enabled, saved but not installed,
// not running, no data yet); the device summary, the filters (device, time
// range, name text, result class, resolver group), paging and the confirmed
// clear; the cross-link to the connection log in both directions and what
// it says when the device cannot be confirmed.
//
// Link log: the opening sentences; the empty states (collector not
// installed yet, not running, host program too old) with the way to get it;
// the state now (carrying path, abnormal objects with duration and
// evidence, unknown and flapping objects); the scope with evidence
// strengths and what is not in scope; the timeline with filters, paging and
// the confirmed clear; and the truthful rendering of a collection gap, an
// "at least" duration, a change found after a gap and a merged record.
//
// Every address, name and device here is invented (documentation ranges,
// example.* names).

import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { App as AntApp } from "antd";
import type { ComponentType } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import DNSLogsPage from "./DNSLogsPage";
import { layoutChecks } from "./demo/testkit";
import LinkLogsPage, { eventShape, prevText } from "./LinkLogsPage";
import { absTime, relatedIdentity, spanText } from "./log_common";
import { btn, pick } from "./pages_fixtures";

/** Opens a log toolbar's "…" menu (inside `scope`) and returns its 清空 item. */
async function clearItem(scope: HTMLElement = document.body, label = "清空"): Promise<HTMLElement> {
  await userEvent.click(within(scope).getByRole("button", { name: "日志的更多操作" }));
  return waitFor(() => {
    const hit = [...document.querySelectorAll<HTMLElement>(".ant-dropdown:not(.ant-dropdown-hidden) .ant-dropdown-menu-item")].find((e) => e.textContent?.trim() === label);
    if (!hit) throw new Error(`no menu item ${label}`);
    return hit;
  });
}
const isDisabled = (el: HTMLElement) => el.getAttribute("aria-disabled") === "true" || el.classList.contains("ant-dropdown-menu-item-disabled");
import { RouterProvider, StatusProvider, TopologyProvider } from "./state";
import { fakeApi, nowrapCellRisks, phoneWidth, reply, tableBudgets, webStorageDump, type FakeRequest } from "./testing";
import type {
  DNSLogJournalView,
  DNSLogRecord,
  DNSLogView,
  LinkLogAnswer,
  LinkLogEvent,
  LinkLogObjectState,
  LinkLogStats,
  LinkLogView,
  LogRelatedView,
} from "./types";

afterEach(() => vi.restoreAllMocks());

const AT = "2026-11-14T00:00:00Z";
const MAC = "00:00:5e:00:53:10";

function mount(Page: ComponentType, hash: string) {
  window.history.replaceState(null, "", `/${hash}`);
  return render(
    <AntApp>
      <RouterProvider>
        <StatusProvider>
          <TopologyProvider>
            <Page />
          </TopologyProvider>
        </StatusProvider>
      </RouterProvider>
    </AntApp>,
  );
}

function withinBudget() {
  const over = tableBudgets().filter((t) => t.width > t.budget);
  expect(over, over.map((t) => `${t.name} in ${t.container}: ${t.width} > ${t.budget}`).join("; ")).toEqual([]);
  // And no nowrap cell holds more text than its declared width (estimate; testing.tsx).
  expect(nowrapCellRisks()).toEqual([]);
}

const LABEL64 = "客厅里那台很旧的示例电视盒子（给孩子看动画片用的那一台，放在电视柜左边第二层）".padEnd(64, "备注名很长");
const LONGNAME = `${"a-very-long-label-for-layout-checks.".repeat(5)}example.com`;

// ============================================================ DNS query log ===

const DNS_SCOPE = {
  covered: ["网关上的 SmartDNS 应答的查询，每条一行"],
  not_covered: ["被网关解析器自己的规则直接回答的名字：不在日志里", "各出口节点上解析器的查询：这一轮只记录网关上的查询"],
  results: ["无应答（no_answer）：名字不存在是这样，审计行里没有应答码，分不开", "无应答且慢（no_answer_slow）：多半是失败或超时"],
  storage: ["只存在网关本机 /var/lib/meridian-dnslog", "保留最近 24 小时、最多 50000 条"],
  switch: ["默认关闭", "关闭并安装成功之后，网关上已有的记录全部删除"],
  identity: ["MAC 未知时只能按地址和时间窗关联，界面会标明「仅按地址」"],
};

const CAP_OK = { available: true, version: "1.2026.11.09-1240", verified_by: "builtin", verified_on: "2026-11-15" };
const CAP_NO = {
  available: false,
  code: "version_unverified",
  reason: "网关解析器的版本 9.9.9-example 没有核对过审计日志的行为",
  action: "在网关上运行 deploy/verify-smartdns.sh --audit-check --record 核对这个版本",
};

function dnsLog(over: Partial<DNSLogView> = {}): DNSLogView {
  return {
    setting: { enabled: false },
    installed: { known: true, enabled: false },
    capability: CAP_OK,
    runtime: { available: true, audit_installed: false, present: false, data_files: 0, data_bytes: 0 },
    bounds: { max_age_s: 86400, max_records: 50000, budget: { total: 33554432, raw: 8388608, queue: 2097152, journal: 23068672 }, disk_bytes: 31457280, slow_empty_ms: 1500, related_window_max_s: 600, related_window_default_s: 120 },
    scope: DNS_SCOPE,
    groups: [
      { group: "g_hk", kind: "region_group", id: "hk", label: "地区组 香港" },
      { group: "domestic", kind: "domestic", label: "国内" },
    ],
    qtypes: { "1": "A", "28": "AAAA" },
    ...over,
  };
}

const ON = (over: Partial<DNSLogView> = {}) =>
  dnsLog({ setting: { enabled: true }, installed: { known: true, enabled: true }, runtime: { available: true, audit_installed: true, present: true, data_files: 2, data_bytes: 4096 }, ...over });

const DNS_STATS = { records: 3, bytes: 600, segments: 1, dropped: 0, write_errors: 0, oversized: 0, max_records: 50000, max_age_s: 86400, max_bytes: 23068672 };

const RECS: DNSLogRecord[] = [
  { id: 9, time: AT, client: "192.0.2.10", mac: MAC, name: "www.example.com", qtype: 1, result: "answered", group: "g_hk", elapsed_ms: 23, answers: 2 },
  { id: 8, time: AT, client: "192.0.2.10", mac: MAC, name: "missing.example.net", qtype: 28, result: "no_answer", group: "domestic", elapsed_ms: 12, answers: 0 },
  { id: 7, time: AT, time_approx: true, client: "192.0.2.77", name: "slow.example.org", qtype: 65, result: "no_answer_slow", elapsed_ms: 2004, answers: 0 },
];

function journalBase(): DNSLogJournalView {
  return { available: true, enabled: true, labels: [{ address: "192.0.2.10", label: "示例手机" }], groups: dnsLog().groups };
}

function dnsDevices(): DNSLogJournalView {
  return {
    ...journalBase(),
    summary: {
      stats: DNS_STATS,
      devices: [
        { device: "192.0.2.10", mac: MAC, macs: [MAC], first_seen: AT, last_seen: AT, total: 2, by_result: { answered: 1, no_answer: 1 }, by_group: { g_hk: 1, domestic: 1 }, top_names: [{ name: "www.example.com", count: 1 }], distinct_names: 2 },
        { device: "192.0.2.77", macs: ["00:00:5e:00:53:77", "00:00:5e:00:53:78"], no_mac: 1, first_seen: AT, last_seen: AT, total: 1, by_result: { no_answer_slow: 1 }, by_group: {}, top_names: [], distinct_names: 1 },
      ],
    },
  };
}

function dnsApi(view: () => DNSLogView, extra: Record<string, (r: FakeRequest) => unknown> = {}) {
  return fakeApi({
    "GET /api/dns-log": () => view(),
    "GET /api/dns-log/devices": () => dnsDevices(),
    "GET /api/dns-log/journal": (r) => ({
      ...journalBase(),
      page: { stats: DNS_STATS, matched: 60, records: r.query.get("before") ? RECS.slice(2) : RECS, ...(r.query.get("before") ? {} : { next_before: 7 }) },
    }),
    ...extra,
  });
}

describe("DNS query log page", () => {
  it("starts with what it records and does not, for how long, where and who can read it", async () => {
    dnsApi(() => dnsLog());
    mount(DNSLogsPage, "#/dns-log");
    expect(screen.getByRole("heading", { level: 1, name: "解析日志" })).toBeInTheDocument();
    const intro = screen.getByTestId("dns-log-intro");
    expect(intro).toHaveTextContent("记录：网关上的 SmartDNS 应答的每一次查询");
    expect(intro).toHaveTextContent("不记录：被网关解析器的规则直接回答的名字");
    expect(intro).toHaveTextContent("各出口节点上的查询");
    expect(intro).toHaveTextContent("只能按耗时区分");
    expect(intro).toHaveTextContent("/var/lib/meridian-dnslog");
    expect(intro).toHaveTextContent("谁能看：只有网关上的 root");
    await waitFor(() => expect(intro).toHaveTextContent("最近 24 小时、最多 50000 条、磁盘上不超过 30 MiB"));
    // The stated limits are shown as scope text.
    const scope = await screen.findByTestId("dns-log-scope");
    expect(scope).toHaveTextContent("被网关解析器自己的规则直接回答的名字：不在日志里");
    expect(scope).toHaveTextContent("各出口节点上解析器的查询");
    expect(scope).toHaveTextContent("审计行里没有应答码，分不开");
    expect(scope).toHaveTextContent("仅按地址");
  });

  it("not enabled: says so, reads no journal, and enabling needs the acknowledgement, then points to the deploy page", async () => {
    let view = dnsLog();
    const api = dnsApi(() => view, {
      "PUT /api/dns-log": (r) => {
        view = dnsLog({ setting: { enabled: (r.body as { enabled: boolean }).enabled }, pending: "enable" });
        return view;
      },
    });
    mount(DNSLogsPage, "#/dns-log");
    const empty = await screen.findByTestId("dns-log-empty");
    expect(empty).toHaveAttribute("data-state", "not-enabled");
    expect(empty).toHaveTextContent("解析日志没有开启");
    expect(empty).toHaveTextContent("必须由你明确打开");
    const sw = screen.getByTestId("dns-log-switch");
    expect(sw).toHaveAttribute("data-setting", "off");
    expect(sw).toHaveTextContent("没有安装：现在不记录任何查询");
    expect(sw).toHaveTextContent("可以打开：SmartDNS 1.2026.11.09-1240");
    expect(api.find("GET /api/dns-log/devices")).toHaveLength(0);
    expect(api.find("GET /api/dns-log/journal")).toHaveLength(0);
    // Step 1: ask. Nothing is sent, and saving is not possible before the acknowledgement.
    expect(screen.queryByTestId("dns-log-enable-confirm")).toBeNull();
    await userEvent.click(within(sw).getByRole("button", { name: "打开解析日志…" }));
    const box = within(sw).getByTestId("dns-log-enable-confirm");
    expect(box).toHaveTextContent("网关会在本机保存每台设备查询过的名字（最多保留 24 小时、50000 条、磁盘上不超过 30 MiB）");
    expect(box).toHaveTextContent("只存在网关本机 /var/lib/meridian-dnslog");
    expect(box).toHaveTextContent("关闭并安装成功之后，网关上已有的记录全部删除");
    const save = within(box).getByRole("button", { name: "保存：下次网关安装时打开" });
    expect(save).toBeDisabled();
    expect(api.find("PUT /api/dns-log")).toHaveLength(0);
    await userEvent.click(within(box).getByRole("checkbox", { name: "我已了解：打开后网关会保存每台设备查询的名字" }));
    expect(save).toBeEnabled();
    await userEvent.click(save);
    await waitFor(() => expect(api.find("PUT /api/dns-log")).toHaveLength(1));
    expect(api.find("PUT /api/dns-log")[0].body).toEqual({ enabled: true, acknowledge: true });
    // Step 2: saved, not in effect — preflight → confirm → install on the deploy page.
    const pending = await within(sw).findByTestId("dns-log-pending");
    expect(pending).toHaveTextContent("已保存为打开，还没有生效");
    expect(pending).toHaveTextContent("预检");
    expect(pending).toHaveTextContent("安装之后才开始记录");
    expect(within(pending).getByRole("link", { name: btn("去部署页") })).toHaveAttribute("href", "#/deploy");
    expect(within(sw).queryByTestId("dns-log-enable-confirm")).toBeNull();
    const now = screen.getByTestId("dns-log-empty");
    expect(now).toHaveAttribute("data-state", "not-installed");
    expect(now).toHaveTextContent("已保存为打开，但还没有安装到网关");
    expect(within(now).getByRole("link", { name: btn("去部署页安装") })).toHaveAttribute("href", "#/deploy");
    // Still nothing read from a journal that does not exist, and nothing but the switch was changed.
    expect(api.find("GET /api/dns-log/journal")).toHaveLength(0);
    expect(api.calls.filter((c) => c.method !== "GET").map((c) => `${c.method} ${c.path}`)).toEqual(["PUT /api/dns-log"]);
    // It can be taken back before any install: nothing on the gateway changes.
    await userEvent.click(within(sw).getByRole("button", { name: "关闭解析日志…" }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByTestId("dns-log-disable-confirm")).toHaveTextContent("只是撤销这次设置，网关上什么都不变");
    layoutChecks("#/dns-log pending");
  });

  it("unavailable: the reason and the action, and no way to turn it on", async () => {
    let reads = 0;
    const api = dnsApi(() => {
      reads++;
      return dnsLog({ capability: CAP_NO });
    });
    mount(DNSLogsPage, "#/dns-log");
    const gate = await screen.findByTestId("dns-log-unavailable");
    expect(gate).toHaveTextContent("这台网关现在不能打开解析日志");
    expect(gate).toHaveTextContent(CAP_NO.reason);
    expect(gate).toHaveTextContent(CAP_NO.action);
    expect(screen.getByTestId("page-help")).toHaveTextContent("没有绕过的办法");
    const sw = screen.getByTestId("dns-log-switch");
    // No switch, no enable button, no checkbox, no confirmation: nothing that could send the request.
    expect(within(sw).queryByRole("button", { name: /打开解析日志/ })).toBeNull();
    expect(within(sw).queryByRole("switch")).toBeNull();
    expect(within(sw).queryByRole("checkbox")).toBeNull();
    expect(screen.queryByTestId("dns-log-enable-confirm")).toBeNull();
    expect(within(sw).queryByRole("button", { name: /关闭解析日志/ })).toBeNull();
    const empty = screen.getByTestId("dns-log-empty");
    expect(empty).toHaveAttribute("data-state", "unavailable");
    expect(empty).toHaveTextContent("这台网关现在也不能打开");
    // The only action re-reads the gate.
    const before = reads;
    await userEvent.click(within(gate).getByRole("button", { name: btn("重新检查") }));
    await waitFor(() => expect(reads).toBeGreaterThan(before));
    expect(api.calls.filter((c) => c.method !== "GET")).toEqual([]);
    layoutChecks("#/dns-log unavailable");
  });

  it("a save the server refuses (the gate changed in between) shows the reason and enables nothing", async () => {
    let cap: DNSLogView["capability"] = CAP_OK;
    const api = dnsApi(() => dnsLog({ capability: cap }), {
      "PUT /api/dns-log": () => {
        cap = CAP_NO;
        return reply(409, { error: `解析日志不可用，没有保存：${CAP_NO.reason}`, code: "dns_log_unavailable", capability: CAP_NO });
      },
    });
    mount(DNSLogsPage, "#/dns-log");
    const sw = await screen.findByTestId("dns-log-switch");
    await userEvent.click(within(sw).getByRole("button", { name: "打开解析日志…" }));
    await userEvent.click(within(sw).getByRole("checkbox"));
    await userEvent.click(within(sw).getByRole("button", { name: "保存：下次网关安装时打开" }));
    await waitFor(() => expect(sw).toHaveTextContent("解析日志不可用，没有保存"));
    expect(api.find("PUT /api/dns-log")).toHaveLength(1);
    // The view was read again: the gate now shows, the setting is still off, nothing pending.
    expect(await within(sw).findByTestId("dns-log-unavailable")).toHaveTextContent(CAP_NO.reason);
    expect(sw).toHaveAttribute("data-setting", "off");
    expect(within(sw).queryByTestId("dns-log-pending")).toBeNull();
    expect(within(sw).queryByRole("button", { name: /打开解析日志/ })).toBeNull();
  });

  it("disabling says that the records are deleted after the install succeeded, and are kept until then", async () => {
    let view = ON();
    const api = dnsApi(() => view, {
      "PUT /api/dns-log": () => {
        view = ON({ setting: { enabled: false }, pending: "disable" });
        return view;
      },
    });
    mount(DNSLogsPage, "#/dns-log");
    const sw = await screen.findByTestId("dns-log-switch");
    expect(sw).toHaveAttribute("data-setting", "on");
    expect(sw).toHaveAttribute("data-installed", "on");
    expect(sw).toHaveTextContent("已安装，解析日志服务在运行");
    await userEvent.click(within(sw).getByRole("button", { name: "关闭解析日志…" }));
    const dialog = await screen.findByRole("dialog");
    const text = within(dialog).getByTestId("dns-log-disable-confirm");
    expect(text).toHaveTextContent("预检 → 确认 → 安装之后才生效");
    expect(text).toHaveTextContent("安装成功之后，网关停止记录并删除已有的全部解析记录");
    expect(text).toHaveTextContent("取消预检、安装失败——仍在记录，记录也都保留");
    expect(api.find("PUT /api/dns-log")).toHaveLength(0);
    await userEvent.click(within(dialog).getByRole("button", { name: "保存：下次网关安装时关闭" }));
    await waitFor(() => expect(api.find("PUT /api/dns-log")).toHaveLength(1));
    expect(api.find("PUT /api/dns-log")[0].body).toEqual({ enabled: false });
    const pending = await within(sw).findByTestId("dns-log-pending");
    expect(pending).toHaveTextContent("已保存为关闭，还没有生效：网关上现在仍在记录");
    expect(pending).toHaveTextContent("安装成功之后，网关停止记录并删除已有的全部解析记录");
    expect(within(pending).getByRole("link", { name: btn("去部署页") })).toHaveAttribute("href", "#/deploy");
    // Until the install the records are still there and still shown; nothing was cleared.
    expect(await screen.findByText("www.example.com")).toBeInTheDocument();
    expect(api.find("POST /api/dns-log/clear")).toHaveLength(0);
    layoutChecks("#/dns-log pending disable");
  });

  it("lists devices and records; the filters, paging and the confirmed clear send what they say", async () => {
    const api = dnsApi(() => ON(), { "POST /api/dns-log/clear": () => ({ cleared: { cleared: 3 } }) });
    mount(DNSLogsPage, "#/dns-log");
    const devs = await screen.findByTestId("dns-log-devices");
    const phone = (await within(devs).findByText("示例手机")).closest("tr")!;
    expect(phone).toHaveTextContent("192.0.2.10");
    expect(phone).toHaveTextContent(MAC);
    // The resolver groups are in the row's expansion.
    await userEvent.click(within(phone).getByRole("button", { name: /展开行|Expand row/ }));
    expect(devs).toHaveTextContent("地区组 香港 1");
    // An address used by more than one device is flagged, not merged silently.
    const shared = within(devs).getByText("192.0.2.77").closest("tr")!;
    expect(shared).toHaveTextContent("2 个 MAC");
    expect(shared).toHaveTextContent("1（慢 1）");
    const recs = screen.getByTestId("dns-log-records");
    await waitFor(() => expect(within(recs).getByTestId("dns-log-matched")).toHaveTextContent("共 60 条查询符合"));
    const rows = [...recs.querySelectorAll("tbody tr.ant-table-row")];
    expect(rows).toHaveLength(3);
    expect(rows[0]).toHaveTextContent("示例手机");
    expect(rows[0]).toHaveTextContent("www.example.com");
    expect(rows[0]).toHaveTextContent("有应答");
    expect(rows[1]).toHaveTextContent("AAAA");
    expect(rows[1]).toHaveTextContent("无应答");
    expect(rows[2]).toHaveTextContent("类型 65");
    expect(rows[2]).toHaveTextContent("无应答且慢");
    // The resolver group is in the expansion.
    await userEvent.click(within(rows[0] as HTMLElement).getByRole("button", { name: /展开行|Expand row/ }));
    expect(recs).toHaveTextContent("地区组 香港（解析器记为");
    expect(screen.getByTestId("page-help")).toHaveTextContent("只能按耗时分成「无应答」和「无应答且慢」（1.5 秒为界），不是确定的结论");
    withinBudget();
    const last = () => api.find("GET /api/dns-log/journal").at(-1)!.query;
    expect(Object.fromEntries(last())).toEqual({ limit: "50" });
    // Device: from the summary row, and it shows in the filter.
    await userEvent.click(within(devs).getByRole("button", { name: "查看 示例手机 的查询" }));
    await waitFor(() => expect(last().get("device")).toBe("192.0.2.10"));
    const filters = within(recs).getByTestId("dns-log-filters");
    expect(filters).toHaveTextContent("示例手机（192.0.2.10）");
    // Result class, resolver group, time range, name text.
    await pick("结果", /^无应答且慢/, filters);
    await waitFor(() => expect(last().get("result")).toBe("no_answer_slow"));
    await pick("结果", /^全部无应答$/, filters);
    await waitFor(() => expect(last().get("result")).toBe("no_answer_any"));
    await pick("解析组", /^国内$/, filters);
    await waitFor(() => expect(last().get("group")).toBe("domestic"));
    await pick("时间", "最近 1 小时", filters);
    await waitFor(() => expect(last().get("from")).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/));
    expect(Date.now() - Date.parse(last().get("from")!)).toBeGreaterThan(3590_000);
    expect(Date.now() - Date.parse(last().get("from")!)).toBeLessThan(3700_000);
    await userEvent.type(within(filters).getByRole("textbox", { name: "按名字搜索" }), "example");
    await waitFor(() => expect(last().get("text")).toBe("example"));
    expect(Object.fromEntries(last())).toMatchObject({ device: "192.0.2.10", result: "no_answer_any", group: "domestic", text: "example", limit: "50" });
    // Paging by cursor; a changed filter goes back to the first page.
    await userEvent.click(within(recs).getByRole("button", { name: btn("更早的记录") }));
    await waitFor(() => expect(last().get("before")).toBe("7"));
    await waitFor(() => expect(within(recs).getByRole("button", { name: btn("更早的记录") })).toBeDisabled());
    expect(within(recs).getByTestId("dns-log-matched")).toHaveTextContent("第 2 页");
    await pick("设备", /^全部设备$/, filters);
    await waitFor(() => expect(last().get("device")).toBeNull());
    expect(last().get("before")).toBeNull();
    // Clear asks first.
    await userEvent.click(await clearItem());
    const dialog = await screen.findByRole("dialog");
    expect(dialog).toHaveTextContent("立即删除网关上全部 3 条解析记录");
    expect(dialog).toHaveTextContent("解析日志保持打开，之后的查询照常记录");
    expect(api.find("POST /api/dns-log/clear")).toHaveLength(0);
    await userEvent.click(within(dialog).getByRole("button", { name: btn("清空") }));
    await waitFor(() => expect(api.find("POST /api/dns-log/clear")).toHaveLength(1));
    expect(api.find("POST /api/dns-log/clear")[0].body).toEqual({ confirm: true });
    // Nothing of the journal is kept in the browser's storage.
    expect(webStorageDump()).not.toMatch(/example|192\.0\.2|00:00:5e/);
    layoutChecks("#/dns-log data");
  });

  it("installed but nothing to show: no data yet, the service not running, filters that match nothing", async () => {
    const none: DNSLogJournalView = { ...journalBase(), labels: [], summary: { stats: { ...DNS_STATS, records: 0 }, devices: [] } };
    dnsApi(() => ON(), { "GET /api/dns-log/devices": () => none, "GET /api/dns-log/journal": () => ({ ...journalBase(), page: { stats: { ...DNS_STATS, records: 0 }, matched: 0, records: [] } }) });
    let view = mount(DNSLogsPage, "#/dns-log");
    let empty = await screen.findByTestId("dns-log-empty");
    expect(empty).toHaveAttribute("data-state", "no-data");
    expect(empty).toHaveTextContent("还没有解析记录");
    expect(await screen.findByText("还没有查询记录")).toBeInTheDocument();
    await pick("结果", /^有应答$/, screen.getByTestId("dns-log-filters"));
    expect(await screen.findByText(/没有符合筛选条件的查询/)).toBeInTheDocument();
    view.unmount();
    vi.restoreAllMocks();

    const api = dnsApi(() => ON({ runtime: { available: true, code: "not_running", message: "解析日志已安装，但解析日志服务没有运行：查询没有被记录（解析不受影响）", audit_installed: true, present: false, data_files: 1, data_bytes: 10 } }), {
      "GET /api/dns-log/devices": () => ({ available: false, code: "no_socket", message: "解析日志服务没有运行", labels: [], enabled: true, groups: [] }),
      "GET /api/dns-log/journal": () => ({ available: false, code: "no_socket", message: "解析日志服务没有运行", labels: [], enabled: true, groups: [] }),
    });
    view = mount(DNSLogsPage, "#/dns-log");
    empty = await screen.findByTestId("dns-log-empty");
    expect(empty).toHaveAttribute("data-state", "not-running");
    expect(empty).toHaveTextContent("解析日志服务没有运行，读不到记录");
    expect(screen.getByTestId("dns-log-runtime")).toHaveTextContent("查询没有被记录（解析不受影响）");
    expect(screen.getByTestId("dns-log-switch")).toHaveTextContent("已安装，但解析日志服务没有运行");
    expect(screen.queryByTestId("dns-log-records")).toBeNull();
    expect(isDisabled(await clearItem())).toBe(true);
    expect(api.calls.filter((c) => c.method !== "GET")).toEqual([]);
  });

  it("a clear that left something is not shown as done: what is left, why and the retry stay until a clear completes", async () => {
    // The gateway's state: 3 records; the first clear deletes one and cannot delete the rest.
    let residual: DNSLogView["runtime"]["clear_residual"] = null;
    let left = RECS;
    const stats = () => ({ ...DNS_STATS, records: left.length, ...(residual ? { residual: { segments: residual.segments, records: residual.records, bytes: residual.bytes, clear_at: AT } } : {}) });
    const api = dnsApi(
      () =>
        ON({
          runtime: { available: true, audit_installed: true, present: true, data_files: 2, data_bytes: 4096, ...(residual ? { code: "clear_incomplete", message: "网关上还留着没有删掉的解析日志数据", clear_residual: residual } : {}) },
        }),
      {
        "GET /api/dns-log/devices": () => ({ ...dnsDevices(), summary: { ...dnsDevices().summary!, stats: stats(), devices: left.length ? dnsDevices().summary!.devices : [] } }),
        "GET /api/dns-log/journal": () => ({ ...journalBase(), page: { stats: stats(), matched: left.length, records: left } }),
      },
    );
    let attempts = 0;
    api.on("POST /api/dns-log/clear", () => {
      attempts++;
      if (attempts === 1) {
        left = RECS.slice(0, 2);
        residual = { segments: 1, records: 2, bytes: 400, raw_files: 1, raw_bytes: 2048 };
        return reply(500, {
          error: "解析日志没有全部清除：结构化日志还留着 1 个分段（2 条记录，400 字节）；审计目录还留着 1 个文件（2048 字节）。排除原因后可以再清空一次",
          code: "dns_log_clear_incomplete",
          complete: false,
          residual,
          errors: [
            { part: "journal", op: "remove", cause: "permission", count: 1 },
            { part: "raw", op: "truncate", cause: "read_only", count: 1 },
          ],
        });
      }
      if (attempts === 2) return reply(503, { error: "解析日志没有清空：宿主执行通道不可用", code: "dns_log_clear_failed", complete: false });
      left = [];
      residual = null;
      return { complete: true, cleared: { complete: true, cleared: 2, raw_bytes: 2048 } };
    });
    mount(DNSLogsPage, "#/dns-log");
    const devs = await screen.findByTestId("dns-log-devices");
    await within(devs).findByText("示例手机");
    expect(screen.queryByTestId("dns-log-clear-residual")).toBeNull();
    const reads = () => api.find("GET /api/dns-log/journal").length;
    const before = reads();
    await userEvent.click(await clearItem());
    await userEvent.click(within(await screen.findByRole("dialog")).getByRole("button", { name: btn("清空") }));

    // Not a success: the warning says what is still there and why, and offers the retry.
    const warn = await screen.findByTestId("dns-log-clear-residual");
    expect(warn).toHaveAttribute("role", "alert");
    expect(warn).toHaveTextContent("解析日志没有全部清除");
    expect(within(warn).getByTestId("dns-log-clear-left")).toHaveTextContent("结构化日志 1 个分段、2 条记录（400 B）；审计目录 1 个文件（2.0 KiB）");
    expect(within(warn).getByTestId("dns-log-clear-left")).toHaveTextContent("仍然会出现在下面的记录里");
    expect(within(warn).getByTestId("dns-log-clear-why")).toHaveTextContent("结构化日志1 个文件删除失败（权限不足）；审计目录审计文件截断失败（文件系统只读）");
    expect(within(warn).getByRole("button", { name: btn("重试清空") })).toBeEnabled();
    // The lists were read again and still show what is left; nothing claims it is empty.
    await waitFor(() => expect(reads()).toBeGreaterThan(before));
    const recs = screen.getByTestId("dns-log-records");
    await waitFor(() => expect(within(recs).getByTestId("dns-log-matched")).toHaveTextContent("共 2 条查询符合"));
    expect(within(recs).getByText("www.example.com")).toBeInTheDocument();
    expect(screen.queryByText("还没有解析记录")).toBeNull();
    expect(screen.getByText(/^2 条/)).toBeInTheDocument();
    layoutChecks("#/dns-log clear incomplete");

    // A retry that cannot even be carried out keeps the warning (and adds why), still one alert.
    await userEvent.click(within(warn).getByRole("button", { name: btn("重试清空") }));
    let dialog = await screen.findByRole("dialog");
    expect(dialog).toHaveTextContent("上一次没有删掉的数据会再删一次");
    await userEvent.click(within(dialog).getByRole("button", { name: btn("清空") }));
    await waitFor(() => expect(api.find("POST /api/dns-log/clear")).toHaveLength(2));
    expect(await screen.findByTestId("dns-log-clear-failed")).toHaveTextContent("宿主执行通道不可用");
    expect(screen.getByTestId("dns-log-clear-left")).toHaveTextContent("2 条记录");
    layoutChecks("#/dns-log clear failed after incomplete");

    // The retry that completes: the warning goes, the lists are empty.
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    await userEvent.click(screen.getByRole("button", { name: btn("重试清空") }));
    dialog = await screen.findByRole("dialog");
    await userEvent.click(within(dialog).getByRole("button", { name: btn("清空") }));
    await waitFor(() => expect(api.find("POST /api/dns-log/clear")).toHaveLength(3));
    await waitFor(() => expect(screen.queryByTestId("dns-log-clear-residual")).toBeNull());
    expect(await screen.findByText("还没有解析记录")).toBeInTheDocument();
    for (const c of api.find("POST /api/dns-log/clear")) expect(c.body).toEqual({ confirm: true });
    expect(webStorageDump()).not.toMatch(/example|192\.0\.2|00:00:5e/);
  });

  it("what a clear left is still reported after a reload or a restart of the reader: the warning comes from the gateway's state", async () => {
    const api = dnsApi(() =>
      ON({
        runtime: {
          available: true,
          code: "clear_incomplete",
          message: "网关上还留着没有删掉的解析日志数据",
          audit_installed: true,
          present: true,
          data_files: 3,
          data_bytes: 9000,
          clear_residual: { segments: 2, records: 40, bytes: 6000, raw_files: 0, raw_bytes: 0, unknown: true },
        },
      }),
    );
    mount(DNSLogsPage, "#/dns-log");
    const warn = await screen.findByTestId("dns-log-clear-residual");
    expect(within(warn).getByTestId("dns-log-clear-left")).toHaveTextContent("结构化日志 2 个分段、40 条记录");
    expect(within(warn).getByTestId("dns-log-clear-left")).toHaveTextContent("留下的可能比数到的多");
    expect(within(warn).queryByTestId("dns-log-clear-why")).toBeNull();
    expect(within(warn).getByRole("button", { name: btn("重试清空") })).toBeEnabled();
    expect(api.calls.filter((c) => c.method !== "GET")).toEqual([]);
    layoutChecks("#/dns-log residue from state");
  });

  it("an incomplete clear is not dropped silently when the gateway then reports nothing left", async () => {
    // The listing failed during the clear ("unknown"), yet nothing is left afterwards.
    const api = dnsApi(() => ON(), {
      "POST /api/dns-log/clear": () =>
        reply(500, {
          error: "解析日志没有全部清除：有目录或文件读不到，留下的可能比数到的多；审计目录目录读取失败（磁盘读写错误）",
          code: "dns_log_clear_incomplete",
          complete: false,
          residual: { segments: 0, records: 0, bytes: 0, raw_files: 0, raw_bytes: 0, unknown: true },
          errors: [{ part: "raw", op: "readdir", cause: "io", count: 1 }],
        }),
    });
    mount(DNSLogsPage, "#/dns-log");
    const devs = await screen.findByTestId("dns-log-devices");
    await within(devs).findByText("示例手机");
    await userEvent.click(await clearItem());
    await userEvent.click(within(await screen.findByRole("dialog")).getByRole("button", { name: btn("清空") }));
    const warn = await screen.findByTestId("dns-log-clear-residual");
    await waitFor(() => expect(api.find("GET /api/dns-log").length).toBeGreaterThan(1));
    await waitFor(() => expect(within(warn).getByTestId("dns-log-clear-left")).toHaveTextContent("上一次清空没有确认全部完成；网关现在没有报告残留"));
    expect(within(warn).getByTestId("dns-log-clear-why")).toHaveTextContent("审计目录目录读取失败（磁盘读写错误）");
    expect(within(warn).getByRole("button", { name: btn("重试清空") })).toBeEnabled();
  });

  it("journal off with data left: a clear that cannot delete everything keeps the warning and the button; the retry removes both", async () => {
    let dataBytes = 4096;
    const api = dnsApi(() => dnsLog({ runtime: { available: true, code: "leftover", message: "解析日志没有安装，但网关上还留有它的数据：用「清空」删除", audit_installed: false, present: false, data_files: 3, data_bytes: dataBytes } }));
    let attempts = 0;
    api.on("POST /api/dns-log/clear", () => {
      if (++attempts === 1) {
        dataBytes = 1024;
        return reply(500, {
          error: "解析日志没有全部清除：审计目录还留着 1 个文件（1024 字节）",
          code: "dns_log_clear_incomplete",
          complete: false,
          residual: { segments: 0, records: 0, bytes: 0, raw_files: 1, raw_bytes: 1024 },
          errors: [{ part: "raw", op: "remove", cause: "busy", count: 1 }],
        });
      }
      dataBytes = 0;
      return { complete: true, cleared: { complete: true, purged_files: 1, purged_bytes: 1024 } };
    });
    mount(DNSLogsPage, "#/dns-log");
    const empty = await screen.findByTestId("dns-log-empty");
    await userEvent.click(within(empty).getByRole("button", { name: btn("清空网关上留下的数据") }));
    await userEvent.click(within(await screen.findByRole("dialog")).getByRole("button", { name: btn("清空") }));
    const warn = await screen.findByTestId("dns-log-clear-residual");
    expect(within(warn).getByTestId("dns-log-clear-left")).toHaveTextContent("审计目录 1 个文件（1.0 KiB）");
    expect(within(warn).getByTestId("dns-log-clear-why")).toHaveTextContent("审计目录1 个文件删除失败（文件被占用）");
    // The state was read again: the data is still there, so is the way to delete it.
    await waitFor(() => expect(api.find("GET /api/dns-log").length).toBeGreaterThan(1));
    expect(within(screen.getByTestId("dns-log-empty")).getByRole("button", { name: btn("清空网关上留下的数据") })).toBeEnabled();
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    await userEvent.click(within(warn).getByRole("button", { name: btn("重试清空") }));
    await userEvent.click(within(await screen.findByRole("dialog")).getByRole("button", { name: btn("清空") }));
    await waitFor(() => expect(api.find("POST /api/dns-log/clear")).toHaveLength(2));
    await waitFor(() => expect(screen.queryByTestId("dns-log-clear-residual")).toBeNull());
    await waitFor(() => expect(within(screen.getByTestId("dns-log-empty")).queryByRole("button", { name: btn("清空网关上留下的数据") })).toBeNull());
  });

  it("a query links to the same device's connections around it; without a MAC it says it cannot confirm the device", async () => {
    dnsApi(() => ON());
    mount(DNSLogsPage, "#/dns-log");
    const recs = await screen.findByTestId("dns-log-records");
    await within(recs).findByText("www.example.com");
    for (const b of within(recs).getAllByRole("button", { name: /展开行|Expand row/ })) await userEvent.click(b);
    const links = within(recs).getAllByTestId("dns-related-link");
    expect(links).toHaveLength(3);
    const href = within(links[0]).getByRole("link").getAttribute("href")!;
    expect(href.startsWith("#/conn-log?")).toBe(true);
    expect(Object.fromEntries(new URLSearchParams(href.split("?")[1]))).toEqual({ device: "192.0.2.10", at: AT, mac: MAC });
    expect(links[0]).toHaveTextContent("按地址和 MAC");
    // No name in any link.
    for (const l of links) expect(within(l).getByRole("link").getAttribute("href")).not.toContain("example");
    const noMac = within(links[2]).getByRole("link").getAttribute("href")!;
    expect(Object.fromEntries(new URLSearchParams(noMac.split("?")[1]))).toEqual({ device: "192.0.2.77", at: AT });
    expect(links[2]).toHaveTextContent("这条记录没有 MAC：只能按地址和时间查找，不能确认是同一台设备");
    expect(recs).toHaveTextContent("这一行的时区无法确定");
  });

  it("opened from a connection: the queries of the window, and the basis of the match", async () => {
    const rel = (over: Partial<LogRelatedView<DNSLogRecord>>): LogRelatedView<DNSLogRecord> => ({
      available: true,
      device: "192.0.2.10",
      mac: MAC,
      from: "2026-11-13T23:58:00Z",
      to: "2026-11-14T00:02:00Z",
      window_s: 120,
      identity: "mac",
      records: RECS.slice(0, 2),
      listed: 2,
      other_mac: 0,
      no_mac: 0,
      more: false,
      ...over,
    });
    const q = `device=192.0.2.10&at=${encodeURIComponent(AT)}`;
    let api = dnsApi(() => ON(), { "GET /api/sniff/journal/related": () => rel({}) });
    let view = mount(DNSLogsPage, `#/dns-log?${q}&mac=${encodeURIComponent(MAC)}`);
    let panel = await screen.findByTestId("dns-log-related");
    await waitFor(() => expect(panel).toHaveAttribute("data-identity", "mac"));
    expect(within(panel).getByTestId("dns-log-related-title")).toHaveTextContent(/^同一设备相近时间的查询$/);
    expect(within(panel).getByTestId("dns-log-related-identity")).toHaveTextContent(`列出的每条查询都带同一个 MAC ${MAC}`);
    expect(panel).toHaveTextContent("来自一条连接记录");
    expect(panel).toHaveTextContent("missing.example.net");
    expect(Object.fromEntries(api.find("GET /api/sniff/journal/related")[0].query)).toEqual({ device: "192.0.2.10", at: AT, mac: MAC, window: "120" });
    // A wider window is asked for explicitly and never beyond the bound.
    await pick("时间窗", "前后各 10 分钟", panel);
    await waitFor(() => expect(api.find("GET /api/sniff/journal/related").at(-1)!.query.get("window")).toBe("600"));
    view.unmount();
    vi.restoreAllMocks();

    // A remote-access device (no MAC anywhere): address only, never "the same device".
    api = dnsApi(() => ON(), { "GET /api/sniff/journal/related": () => rel({ mac: undefined, identity: "address", no_mac: 1, listed: 1, records: [RECS[2]] }) });
    view = mount(DNSLogsPage, `#/dns-log?${q}`);
    panel = await screen.findByTestId("dns-log-related");
    await waitFor(() => expect(panel).toHaveAttribute("data-identity", "address"));
    const title = within(panel).getByTestId("dns-log-related-title");
    expect(title).toHaveTextContent("同一地址相近时间的查询（未确认是同一台设备）");
    expect(title).not.toHaveTextContent("同一设备");
    const basis = within(panel).getByTestId("dns-log-related-identity");
    expect(basis).toHaveClass("unconfirmed");
    expect(basis).toHaveTextContent("仅按地址 192.0.2.10 和时间窗关联，不能确认是同一台设备");
    expect(within(panel).getByText("仅按地址")).toBeInTheDocument();
    expect(within(panel).getByText("无 MAC · 仅按地址")).toBeInTheDocument();
    view.unmount();
    vi.restoreAllMocks();

    // The DNS log is not collecting: said in the panel, not shown as "no queries".
    dnsApi(() => dnsLog(), { "GET /api/sniff/journal/related": () => rel({ available: false, code: "no_socket", message: "解析日志服务没有运行", identity: "address", records: [], listed: 0 }) });
    mount(DNSLogsPage, `#/dns-log?${q}`);
    const empty = await screen.findByTestId("dns-log-related-empty");
    expect(empty).toHaveAttribute("data-state", "no_socket");
    expect(empty).toHaveTextContent("解析日志服务没有运行");
    await userEvent.click(within(screen.getByTestId("dns-log-related")).getByRole("button", { name: btn("关闭") }));
    expect(window.location.hash).toBe("#/dns-log");
  });

  it("a 64-character device label, a long name and large numbers sit in wrapping or cut cells, never in nowrap ones", async () => {
    expect([...LABEL64]).toHaveLength(64);
    const labels = [{ address: "192.0.2.10", label: LABEL64 }];
    const groups = [{ group: "g_hk", kind: "region_group", id: "hk", label: "地区组 香港（机房，一个很长很长的地区组名字用来测试换行）" }];
    const recs: DNSLogRecord[] = [
      { ...RECS[0], name: LONGNAME, qtype: 65535, elapsed_ms: 123456 },
      { ...RECS[1], client: "2001:db8:77:1234:5678:9abc:def0:1234", group: "a_group_the_panel_does_not_know_with_a_long_name" },
    ];
    dnsApi(() => ON({ groups }), {
      "GET /api/dns-log/devices": () => ({
        ...journalBase(),
        labels,
        groups,
        summary: {
          stats: { ...DNS_STATS, records: 50000 },
          devices: [
            { device: "192.0.2.10", mac: MAC, macs: [MAC], first_seen: AT, last_seen: AT, total: 49999, by_result: { answered: 20000, no_answer: 17654, no_answer_slow: 12345 }, by_group: { g_hk: 49999 }, top_names: [{ name: LONGNAME, count: 40000 }], distinct_names: 12345, names_truncated: true },
          ],
        },
      }),
      "GET /api/dns-log/journal": () => ({ ...journalBase(), labels, groups, page: { stats: DNS_STATS, matched: 2, records: recs } }),
    });
    mount(DNSLogsPage, "#/dns-log");
    const devs = await screen.findByTestId("dns-log-devices");
    const label = await within(devs).findByText(LABEL64);
    expect(label.closest("td")).toHaveClass("col-flex");
    // The counts wrap too: 29999（慢 12345） does not fit a narrow nowrap column.
    expect(within(devs).getByText("29999（慢 12345）").closest("td")).toHaveClass("col-flex");
    const recsBox = screen.getByTestId("dns-log-records");
    const name = await within(recsBox).findByText(LONGNAME);
    expect(name).toHaveClass("ellipsis-text");
    expect(name).toHaveAttribute("tabindex", "0");
    expect(name.closest("td")).toHaveClass("col-flex");
    expect(within(recsBox).getAllByText(LABEL64)[0].closest("td")).toHaveClass("col-flex");
    // Worst-case short values of the nowrap columns still fit their declared widths.
    expect(recsBox).toHaveTextContent("类型 65535");
    withinBudget();
  });

  it("the words for the basis of a match never call an unconfirmed device the same", () => {
    const base = { available: true, device: "192.0.2.10", from: AT, to: AT, window_s: 120, records: [], other_mac: 0, more: false };
    expect(relatedIdentity({ ...base, mac: MAC, identity: "mac", listed: 2, no_mac: 0 }, "连接").same).toBe(true);
    for (const v of [
      { ...base, mac: MAC, identity: "partial" as const, listed: 3, no_mac: 1 },
      { ...base, mac: MAC, identity: "address" as const, listed: 2, no_mac: 2 },
      { ...base, identity: "address" as const, listed: 2, no_mac: 0 },
      { ...base, mac: MAC, identity: "address" as const, listed: 0, no_mac: 0 },
    ]) {
      const r = relatedIdentity(v, "连接");
      expect(r.same).toBe(false);
      expect(r.text).toContain("不能确认");
    }
  });

  it("on a phone the tables are cards and nothing is pinned or scrolls sideways", async () => {
    phoneWidth();
    dnsApi(() => ON());
    const { container } = mount(DNSLogsPage, "#/dns-log");
    const devs = await screen.findByTestId("dns-log-devices");
    await within(devs).findByText("示例手机");
    const recs = screen.getByTestId("dns-log-records");
    await waitFor(() => expect(recs.querySelectorAll(".data-card")).toHaveLength(3));
    expect(container.querySelector(".page table")).toBeNull();
    expect(container.querySelector(".ant-table-cell-fix-right")).toBeNull();
    for (const w of container.querySelectorAll(".data-table-wrap, .data-cards-wrap")) expect(w).toHaveAttribute("data-stacked", "true");
    expect(container.querySelector("[data-overflow='true']")).toBeNull();
    // The name is the card's heading; every device card keeps its action.
    expect(recs.querySelector(".data-card .data-card-title")).toHaveTextContent("www.example.com");
    for (const c of devs.querySelectorAll(".data-card")) expect(c.querySelector(".data-card-actions button")).not.toBeNull();
    layoutChecks("phone #/dns-log");
  });
});

// ================================================================= link log ===

const KINDS: LinkLogView["scope"]["kinds"] = [
  { class: "path", kind: "upstream", label: "承载路径", open: true, states: [{ state: "udp", label: "主链路，到中继走 UDP 腿", level: "ok" }, { state: "backup", label: "备用枢纽", level: "abnormal" }] },
  { class: "relay", kind: "relay", label: "中继在分担里的状态", states: [{ state: "active", label: "在分担中", level: "ok" }, { state: "evicted", label: "被剔除（低于可用下限或没有应答）", level: "abnormal" }] },
  { class: "tunnel", kind: "tunnel", label: "隧道握手", states: [{ state: "ok", label: "握手正常", level: "ok" }, { state: "stale", label: "握手超时（视为不通）", level: "abnormal" }] },
  { class: "wss", kind: "wss", label: "WSS 伴随承载", states: [{ state: "connected", label: "客户端在运行，里面的隧道握手正常", level: "ok" }] },
  { class: "external_exit", kind: "external_exit", label: "外部出口", states: [{ state: "ok", label: "网关自检通过", level: "ok" }, { state: "failed", label: "网关自检失败", level: "abnormal" }] },
  { class: "collector", kind: "collector", label: "采集空窗", states: [{ state: "unknown", label: "未知（没有采集）", level: "abnormal" }, { state: "collecting", label: "采集中", level: "ok" }] },
];

const OBJECTS: LinkLogView["objects"] = [
  { class: "path", kind: "upstream", id: "gateway", label: "承载路径", observed: true },
  { class: "relay", kind: "relay", id: "relay-a", label: "中继 relay-a（分担）", observed: true },
  { class: "tunnel", kind: "tunnel", id: "mwg1", label: "隧道 mwg1：链路 l1，到 relay-a（UDP 腿）", observed: true },
  { class: "tunnel", kind: "tunnel", id: "mwg9", label: "隧道 mwg9：链路 l9，到 hub-b（UDP 腿），备用", observed: false, note: "这条链路关闭了保活：不记录" },
  { class: "external_exit", kind: "external_exit", id: "ext1", label: "外部出口 ext1（由 exit-a 承载）", observed: true },
];

function linkLog(over: Partial<LinkLogView> = {}): LinkLogView {
  return {
    installed: { known: true, enabled: true },
    runtime: { available: true, present: true, config_installed: true, unit_active: "active" },
    bounds: { max_age_s: 2592000, max_events: 20000, budget: { total: 16777216, events: 15716352, checkpoint: 532480, rewrite: 528384 }, disk_bytes: 16777216, max_line: 1024, writes_per_hour: 600, page_max: 500 },
    timing: { interval_s: 10, slow_interval_s: 30, gap_after_s: 120, handshake_stale_s: 180, upstream_stale_s: 60, selfcheck_every_s: 900, selfcheck_max_age_s: 2400, flap_after: 4, flap_window_s: 600, flap_quiet_s: 600, flap_max_s: 3600 },
    scope: {
      sources: [
        { class: "path", class_label: "承载路径", events: "网关的境外流量走哪条路径", source: "upstream", how: "读固定文件", cadence: "每 10 秒读一次", strength: "direct", evidence: "切换是故障切换服务自己的决定" },
        { class: "wss", class_label: "WSS 伴随承载", events: "wstunnel 客户端停止 / 运行", source: "wss_unit", how: "systemctl is-active", cadence: "每 30 秒", strength: "indirect", evidence: "间接：WebSocket 会话本身的连接状态没有读取" },
        { class: "external_exit", class_label: "外部出口", events: "网关对某个外部 SOCKS 出口的自检由通过变为失败、恢复", source: "selfcheck", how: "读嗅探转发服务的最近一次自检", cadence: "每 30 秒读一次", strength: "probe", evidence: "不是「代理已经确认不通」：承载节点自己的健康检查网关读不到" },
      ],
      not_in_scope: [
        { what: "承载节点上的外部出口健康检查（meridian-ext-health）", why: "它在承载节点上运行，网关没有任何现有的固定通道能读到", instead: "网关自己的检查（外部出口这一类）" },
        { what: "任何流量内容", why: "链路日志不读取连接、名字、地址或设备信息" },
      ],
      kinds: KINDS,
      mode: "share",
      mode_note: "这个拓扑由多台中继分担：承载路径取自分担控制器每一轮写的记录",
      sniff_on: true,
      externals: [{ id: "ext1", carrier: "exit-a", observed: true, note: "只有网关自己的自检，承载节点上的健康检查不在记录范围内" }],
      unobserved: OBJECTS.filter((o) => !o.observed),
      notes: { records: ["记录的是状态的变化，不是周期性的采样"], storage: ["只存在网关本机 /var/lib/meridian-linklog"], rules: ["抖动：之后的变化合并成一条「变化了 N 次」的记录"], install: ["没有开关：采集服务是每个网关安装内容的一部分"] },
    },
    objects: OBJECTS,
    ...over,
  };
}

const LINK_STATS: LinkLogStats = {
  events: 5, bytes: 1500, segments: 1, objects: 5, oldest: AT, newest: AT, disk_bytes: 8192, written: 5, merged: 3, dropped_budget: 2, write_errors: 0, trimmed: 0, open_flaps: 1, restored: true,
  baseline_at: AT, max_events: 20000, max_age_s: 2592000, budget: { total: 16777216, events: 15716352, checkpoint: 532480, rewrite: 528384 }, gap_after_s: 120, flap_after: 4, flap_window_s: 600, flap_quiet_s: 600, writes_per_hour: 600,
};

function obj(over: Partial<LinkLogObjectState>): LinkLogObjectState {
  return { class: "tunnel", kind: "tunnel", id: "mwg1", label: "隧道 mwg1：链路 l1，到 relay-a（UDP 腿）", source: "handshake", state: "ok", level: "ok", since: AT, for_s: 60, last_seen: AT, ...over };
}

const CARRY = obj({ class: "path", kind: "upstream", id: "gateway", label: "承载路径", source: "upstream", state: "backup", level: "abnormal", for_s: 11400, evidence: "故障切换服务记下：主链路的两条腿都没有应答，已切到备用枢纽" });
const STALE_TUNNEL = obj({ state: "stale", level: "abnormal", for_s: 7500, since_open: true, evidence: "最近一次握手在 7500 秒之前" });
const EXT = obj({ class: "external_exit", kind: "external_exit", id: "ext1", label: "外部出口 ext1（由 exit-a 承载）", source: "selfcheck", state: "failed", level: "abnormal", for_s: 10800, reason: "timeout", evidence: "网关经隧道问这个出口的解析器没有得到回答" });
const UNKNOWN = obj({ class: "wss", kind: "wss", id: "l1", label: "WSS 承载 l1", source: "wss_unit", state: "connected", stale: true, level: "ok", for_s: 400, last_seen: "2026-11-13T23:50:00Z" });
const FLAP = obj({ class: "relay", kind: "relay", id: "relay-a", label: "中继 relay-a（分担）", source: "upstream", state: "evicted", level: "abnormal", for_s: 30, flapping: { changes: 7, first_at: "2026-11-13T23:40:00Z", last_at: AT } });

function currentAnswer(over: Partial<NonNullable<LinkLogAnswer["summary"]>> = {}): LinkLogAnswer {
  return { available: true, summary: { at: AT, carrying: CARRY, abnormal: [CARRY, STALE_TUNNEL, EXT, FLAP], unknown: [UNKNOWN], flapping: [FLAP], objects: 5, last_pass: AT, ...over } };
}

function ev(over: Partial<LinkLogEvent>): LinkLogEvent {
  return { seq: 1, at: AT, class: "tunnel", kind: "tunnel", id: "mwg1", label: "隧道 mwg1：链路 l1，到 relay-a（UDP 腿）", from: "ok", to: "stale", source: "handshake", ...over };
}

const GAP = { from: "2026-11-13T22:00:00Z", to: "2026-11-13T23:30:00Z" };
const EVENTS: LinkLogEvent[] = [
  // Merged and still being counted: seven changes, not one outage.
  ev({ seq: 0, class: "relay", kind: "relay", id: "relay-a", label: "中继 relay-a（分担）", from: "active", to: "evicted", source: "upstream", changes: 7, at: "2026-11-13T23:40:00Z", last_at: AT, open: true, prev_for_s: 900 }),
  // A plain change with a known previous duration.
  ev({ seq: 5, prev_for_s: 176400, evidence: "最近一次握手在 190 秒之前", reason: "handshake_stale" }),
  // The previous state was already there at the first reading: "at least".
  ev({ seq: 4, class: "external_exit", kind: "external_exit", id: "ext1", label: "外部出口 ext1（由 exit-a 承载）", from: "ok", to: "failed", source: "selfcheck", prev_for_s: 600, prev_open: true }),
  // Found after a gap: when inside it the change happened is not known.
  ev({ seq: 3, class: "path", kind: "upstream", id: "gateway", label: "承载路径", from: "udp", to: "backup", source: "upstream", after_gap: GAP, prev_for_s: 300, prev_open: true }),
  // The gap itself: nothing was collected.
  ev({ seq: 2, class: "collector", kind: "collector", id: "gateway", label: "链路日志采集", from: "unknown", to: "collecting", source: "collector", reason: "restart", after_gap: GAP, prev_for_s: 5400, evidence: "采集服务没有运行：这段时间里的状态未知" }),
];

function linkApi(view: () => LinkLogView, extra: Record<string, (r: FakeRequest) => unknown> = {}) {
  return fakeApi({
    "GET /api/link-log": () => view(),
    "GET /api/link-log/current": () => currentAnswer(),
    "GET /api/link-log/events": (r) => ({
      available: true,
      page: { events: r.query.get("before") ? EVENTS.slice(4) : EVENTS, stats: LINK_STATS, open_merged: r.query.get("before") ? 0 : 1, ...(r.query.get("before") ? {} : { next_before: "c2" }) },
    }),
    ...extra,
  });
}

describe("link log page", () => {
  it("starts with what it records and does not, for how long, where and who can read it", async () => {
    linkApi(() => linkLog());
    mount(LinkLogsPage, "#/link-log");
    expect(screen.getByRole("heading", { level: 1, name: "链路日志" })).toBeInTheDocument();
    const intro = screen.getByTestId("link-log-intro");
    expect(intro).toHaveTextContent("记录：状态的变化，不是周期采样");
    expect(intro).toHaveTextContent("不记录：任何流量内容（没有设备地址、域名或连接）");
    expect(intro).toHaveTextContent("承载节点上的外部出口健康检查");
    expect(intro).toHaveTextContent("/var/lib/meridian-linklog");
    expect(intro).toHaveTextContent("谁能看：只有网关上的 root");
    await waitFor(() => expect(intro).toHaveTextContent("最近 30 天、最多 20000 条、合计不超过 16 MiB"));
  });

  it("collector not installed yet, not running, or a host program without it: each said with the way to get it, and nothing is asked of it", async () => {
    const cases: [Partial<LinkLogView>, string, string, string][] = [
      [
        { installed: { known: true, enabled: false }, pending: "install", runtime: { available: true, code: "not_installed", message: "链路日志的采集服务还没有安装到网关", present: false, config_installed: false } },
        "not-installed",
        "链路日志的采集服务还没有安装到网关",
        "到部署页对网关预检 → 确认差异 → 安装",
      ],
      [
        { runtime: { available: true, code: "not_running", message: "链路日志的采集服务已安装但没有运行：状态变化没有被记录（转发和故障切换不受影响）", present: false, config_installed: true } },
        "not-running",
        "采集服务已安装，但没有运行",
        "转发和故障切换不受影响",
      ],
      [
        { installed: { known: true, enabled: false }, pending: "install", runtime: { available: false, code: "agent_old", message: "宿主程序不支持链路日志", present: false, config_installed: false } },
        "agent-old",
        "网关宿主机上的程序比面板旧，还没有链路日志",
        "deploy/debian/install.sh",
      ],
      [
        { runtime: { available: false, code: "agent_unavailable", message: "没有配置 host agent：读不到链路日志", present: false, config_installed: false } },
        "unreadable",
        "读不到网关上的链路日志",
        "没有配置 host agent",
      ],
    ];
    for (const [over, state, title, body] of cases) {
      const api = linkApi(() => linkLog(over));
      const view = mount(LinkLogsPage, "#/link-log");
      const empty = await screen.findByTestId("link-log-empty");
      expect(empty, state).toHaveAttribute("data-state", state);
      expect(empty).toHaveTextContent(title);
      expect(empty).toHaveTextContent(body);
      if (state !== "unreadable") expect(within(empty).getByRole("link")).toHaveAttribute("href", "#/deploy");
      expect(api.find("GET /api/link-log/current")).toHaveLength(0);
      expect(api.find("GET /api/link-log/events")).toHaveLength(0);
      // The scope is still stated: what would be observed, and what never is.
      expect(screen.getByTestId("link-log-not-in-scope")).toHaveTextContent("承载节点上的外部出口健康检查");
      layoutChecks(`#/link-log ${state}`);
      view.unmount();
      vi.restoreAllMocks();
    }
  });

  it("the state now: the carrying path, abnormal objects with duration and evidence, unknown and flapping objects", async () => {
    linkApi(() => linkLog());
    mount(LinkLogsPage, "#/link-log");
    const cur = await screen.findByTestId("link-log-current");
    const carrying = within(cur).getByTestId("link-log-carrying");
    expect(carrying).toHaveTextContent("备用枢纽");
    expect(carrying).toHaveTextContent(`已持续 ${spanText(11400)}`);
    expect(carrying).toHaveTextContent("主链路的两条腿都没有应答");
    expect(carrying).toHaveTextContent("直接读到");
    const abnormal = within(cur).getByTestId("link-log-abnormal");
    expect(abnormal).toHaveTextContent("现在处于异常状态的对象（4）");
    const rows = [...abnormal.querySelectorAll("tbody tr.ant-table-row")];
    expect(rows).toHaveLength(4);
    // A duration whose start is not known is a lower bound.
    expect(within(rows[1] as HTMLElement).getByTestId("link-object-for")).toHaveTextContent("至少 2 小时 5 分（开始的时间不确定");
    expect(rows[1]).toHaveTextContent("握手超时（视为不通）");
    // The external exit: the gateway's own check, labelled as a probe, with its evidence.
    expect(rows[2]).toHaveTextContent("外部出口 ext1（由 exit-a 承载）");
    expect(rows[2]).toHaveTextContent("网关自检失败");
    expect(within(rows[2] as HTMLElement).getByTestId("link-object-for")).toHaveTextContent("已持续 3 小时 0 分");
    expect(rows[2]).toHaveTextContent("网关自己的探测");
    expect(rows[2]).toHaveTextContent("没有得到回答");
    // Not read for too long: unknown now, the last state is only the last one read.
    const unknown = within(cur).getByTestId("link-log-unknown");
    expect(screen.getByTestId("page-help")).toHaveTextContent("超过 120 秒没有读到");
    expect(unknown).toHaveTextContent("WSS 承载 l1：现在未知最后读到「客户端在运行，里面的隧道握手正常」");
    expect(unknown).toHaveTextContent(absTime("2026-11-13T23:50:00Z"));
    // Flapping: a count, not one outage.
    const flapping = within(cur).getByTestId("link-log-flapping");
    expect(flapping).toHaveTextContent("已变化 7 次，仍在合并计数");
    expect(screen.getByTestId("page-help")).toHaveTextContent("不是一次连续的中断");
    withinBudget();
    layoutChecks("#/link-log current");
  });

  it("a carrying path that was not read lately is unknown, and an empty abnormal list says what that proves", async () => {
    linkApi(() => linkLog(), { "GET /api/link-log/current": () => currentAnswer({ carrying: { ...CARRY, stale: true }, abnormal: [], unknown: [{ ...CARRY, stale: true }], flapping: [] }) });
    mount(LinkLogsPage, "#/link-log");
    const cur = await screen.findByTestId("link-log-current");
    expect(within(cur).getByTestId("link-log-carrying")).toHaveTextContent("现在未知：超过 120 秒没有读到承载路径。最后读到的是「备用枢纽」");
    expect(within(cur).getByTestId("link-log-carrying")).not.toHaveTextContent("已持续");
    expect(screen.getByTestId("page-help")).toHaveTextContent("这只说明网关读到的这些对象");
    expect(within(cur).queryByTestId("link-log-flapping")).toBeNull();
  });

  it("the scope: what is observed with which evidence, and what is not in scope", async () => {
    linkApi(() => linkLog());
    mount(LinkLogsPage, "#/link-log");
    const scope = await screen.findByTestId("link-log-scope");
    expect(screen.getByTestId("page-help")).toHaveTextContent("这个拓扑由多台中继分担");
    const rows = [...scope.querySelectorAll("tbody tr.ant-table-row")];
    expect(rows.map((r) => r.querySelectorAll("td")[1].textContent)).toEqual(["承载路径", "WSS 伴随承载", "外部出口"]);
    expect(rows[0]).toHaveTextContent("直接读到");
    expect(rows[1]).toHaveTextContent("间接推断");
    expect(rows[2]).toHaveTextContent("网关自己的探测");
    expect(rows[2]).toHaveTextContent("不是「代理已经确认不通」");
    const out = within(scope).getByTestId("link-log-not-in-scope");
    expect(out).toHaveTextContent("承载节点上的外部出口健康检查（meridian-ext-health）：它在承载节点上运行，网关没有任何现有的固定通道能读到。最接近的记录：网关自己的检查");
    expect(out).toHaveTextContent("任何流量内容");
    expect(within(scope).getByTestId("link-log-externals")).toHaveTextContent("ext1（由 exit-a 承载）：有网关自己的检查");
    expect(within(scope).getByTestId("link-log-unobserved")).toHaveTextContent("隧道 mwg9：链路 l9，到 hub-b（UDP 腿），备用：这条链路关闭了保活：不记录");
    expect(scope).toHaveTextContent("没有开关：采集服务是每个网关安装内容的一部分");
  });

  it("renders a gap, an at-least duration, a change found after a gap and a merged record as what they are", async () => {
    linkApi(() => linkLog());
    mount(LinkLogsPage, "#/link-log");
    const box = await screen.findByTestId("link-log-events");
    await waitFor(() => expect(within(box).getAllByTestId("link-event")).toHaveLength(5));
    const cells = within(box).getAllByTestId("link-event");
    const prev = within(box).getAllByTestId("link-event-prev").map((c) => c.textContent);
    expect(cells.map((c) => c.getAttribute("data-shape"))).toEqual(["merged", "change", "change", "after_gap", "gap"]);
    // Merged: a count with its first and last time, still open, and never one outage.
    expect(cells[0]).toHaveTextContent("变化了 7 次");
    expect(cells[0]).toHaveTextContent("仍在合并计数");
    expect(cells[0]).toHaveTextContent(`第一次在 ${absTime("2026-11-13T23:40:00Z")}，最后一次在 ${absTime(AT)}`);
    expect(cells[0]).toHaveTextContent("这是反复变化，不是一次连续的中断");
    expect(cells[0]).toHaveTextContent("在分担中");
    expect(cells[0]).toHaveTextContent("被剔除（低于可用下限或没有应答）");
    // A plain change: both states in words, the previous one's length as measured.
    expect(cells[1]).toHaveTextContent("握手正常 → 握手超时（视为不通）");
    expect(prev[1]).toBe(spanText(176400));
    expect(prev[1]).toBe("2 天 1 小时");
    // The previous state was there at the first reading: at least.
    expect(prev[2]).toBe("至少 10 分 0 秒（第一次读到时就已是这个状态）");
    // Found after a gap: the time of the change is not known.
    expect(cells[3]).toHaveTextContent("空窗后才发现");
    expect(cells[3]).toHaveTextContent(`变化发生在 ${absTime(GAP.from)} 到 ${absTime(GAP.to)} 之间`);
    expect(cells[3]).toHaveTextContent("具体时间不确定");
    expect(prev[3]).toBe("至少 5 分 0 秒（之后进入空窗，实际更长或不确定）");
    // The gap: not a state of any link.
    expect(cells[4]).toHaveTextContent("采集空窗");
    expect(cells[4]).toHaveTextContent(`${absTime(GAP.from)} 到 ${absTime(GAP.to)}（1 小时 30 分）没有采集`);
    expect(cells[4]).toHaveTextContent("状态未知，发生过的变化没有记录");
    expect(cells[4]).not.toHaveTextContent("→");
    expect(prev[4]).toBe("—");
    expect(screen.getByTestId("page-help")).toHaveTextContent("其中 1 条是仍在合并计数的抖动记录");
    const stats = within(box).getByTestId("link-log-stats");
    expect(stats).toHaveTextContent("5 条事件");
    expect(stats).toHaveTextContent("合并掉 3 次变化");
    expect(stats).toHaveTextContent("因每小时写入上限丢弃 2 条");
    // Evidence and reason are in the row's details.
    await userEvent.click(within(box).getAllByRole("button", { name: /展开行|Expand row/ })[1]);
    expect(box).toHaveTextContent("最近一次握手在 190 秒之前");
    expect(box).toHaveTextContent("handshake_stale");
    withinBudget();
    // The classification the rendering rests on.
    expect(EVENTS.map(eventShape)).toEqual(["merged", "change", "change", "after_gap", "gap"]);
    expect(prevText(ev({}))).toBe("—");
    expect(prevText(ev({ prev_open: true }))).toBe("不确定");
  });

  it("long object names and state phrases wrap: object and state cells are wrapping cells, states are text, not tags", async () => {
    const LONGOBJ = "隧道 mwg-a-long-interface：链路 link-with-a-really-long-identifier-for-layout，到 relay-shanghai-telecom-a（UDP 腿），备用";
    const EVID = "故障切换服务记下：主链路的两条腿都没有应答，已切到备用枢纽；" + "这段依据文字故意写得很长用来检查换行。".repeat(4);
    const longObj = obj({ label: LONGOBJ, state: "stale", level: "abnormal", for_s: 7500, since_open: true, evidence: EVID });
    const view = linkLog();
    view.scope.sources[0] = { ...view.scope.sources[0], class_label: "承载路径（单中继、无备用枢纽）", evidence: EVID };
    linkApi(() => view, {
      "GET /api/link-log/current": () => currentAnswer({ abnormal: [longObj, CARRY], unknown: [], flapping: [] }),
      "GET /api/link-log/events": () => ({ available: true, page: { events: [ev({ seq: 9, label: LONGOBJ, evidence: EVID, prev_for_s: 176400 }), EVENTS[0], EVENTS[4]], stats: LINK_STATS } }),
    });
    mount(LinkLogsPage, "#/link-log");
    const cur = await screen.findByTestId("link-log-current");
    const name = within(cur).getByText(LONGOBJ);
    expect(name.closest("td")).toHaveClass("col-flex");
    const state = within(within(cur).getByTestId("link-log-abnormal")).getAllByText("握手超时（视为不通）")[0];
    expect(state).toHaveClass("link-state", "link-state-abnormal");
    expect(state.tagName).toBe("SPAN");
    expect(state.closest(".ant-tag")).toBeNull();
    expect(state.closest("td")).toHaveClass("col-flex");
    const box = await screen.findByTestId("link-log-events");
    await waitFor(() => expect(within(box).getAllByTestId("link-event")).toHaveLength(3));
    expect(within(box).getByText(LONGOBJ).closest("td")).toHaveClass("col-flex");
    for (const s of box.querySelectorAll(".link-state")) expect(s.closest(".ant-tag")).toBeNull();
    // The source inventory's first column wraps as well (its labels can be long).
    const scope = screen.getByTestId("link-log-scope");
    expect(within(scope).getByText("承载路径（单中继、无备用枢纽）").closest("td")).toHaveClass("col-flex");
    // The only nowrap cells left hold a relative time or a short strength tag.
    const fixed = [...document.querySelectorAll(".page td.col-fixed")].map((td) => td.textContent ?? "");
    for (const t of fixed) expect(t.length, t).toBeLessThanOrEqual(12);
    withinBudget();
  });

  it("filters by object, class and time, pages by cursor, and clears only after confirmation", async () => {
    const api = linkApi(() => linkLog(), { "POST /api/link-log/clear": () => ({ cleared: { events: 5 } }) });
    mount(LinkLogsPage, "#/link-log");
    const box = await screen.findByTestId("link-log-events");
    await waitFor(() => expect(within(box).getAllByTestId("link-event")).toHaveLength(5));
    const last = () => api.find("GET /api/link-log/events").at(-1)!.query;
    expect(Object.fromEntries(last())).toEqual({ limit: "50" });
    const filters = within(box).getByTestId("link-log-filters");
    await pick("类别", /^隧道握手$/, filters);
    await waitFor(() => expect(last().get("class")).toBe("tunnel"));
    await pick("时间", "最近 24 小时", filters);
    await waitFor(() => expect(last().get("from")).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/));
    expect(Date.now() - Date.parse(last().get("from")!)).toBeGreaterThan(86390_000);
    // One object: kind and id; the class filter no longer applies.
    await pick("对象", "外部出口 ext1", filters);
    await waitFor(() => expect(last().get("id")).toBe("ext1"));
    expect(last().get("kind")).toBe("external_exit");
    expect(last().get("class")).toBeNull();
    expect(within(filters).getByRole("combobox", { name: "类别" })).toBeDisabled();
    // An object that is listed but not read says so in the choice.
    await pick("对象", "（不读取）", filters);
    await waitFor(() => expect(last().get("id")).toBe("mwg9"));
    await pick("对象", /^全部对象$/, filters);
    await waitFor(() => expect(last().get("id")).toBeNull());
    expect(last().get("class")).toBe("tunnel");
    await userEvent.click(within(box).getByRole("button", { name: btn("更早的事件") }));
    await waitFor(() => expect(last().get("before")).toBe("c2"));
    await waitFor(() => expect(within(box).getByRole("button", { name: btn("更早的事件") })).toBeDisabled());
    await userEvent.click(within(box).getByRole("button", { name: btn("较新的事件") }));
    await waitFor(() => expect(last().get("before")).toBeNull());
    await userEvent.click(await clearItem(box));
    const dialog = await screen.findByRole("dialog");
    expect(dialog).toHaveTextContent("立即删除网关上全部 5 条事件和已记下的各对象状态");
    expect(dialog).toHaveTextContent("重新建立基线");
    expect(api.find("POST /api/link-log/clear")).toHaveLength(0);
    await userEvent.click(within(dialog).getByRole("button", { name: btn("清空") }));
    await waitFor(() => expect(api.find("POST /api/link-log/clear")).toHaveLength(1));
    expect(api.find("POST /api/link-log/clear")[0].body).toEqual({ confirm: true });
  });

  it("running without events yet, and filters that match nothing, are explicit states", async () => {
    linkApi(() => linkLog(), { "GET /api/link-log/events": () => ({ available: true, page: { events: [], stats: { ...LINK_STATS, events: 0 } } }) });
    mount(LinkLogsPage, "#/link-log");
    const empty = await screen.findByTestId("link-log-empty");
    expect(empty).toHaveAttribute("data-state", "no-events");
    expect(empty).toHaveTextContent("还没有状态变化事件");
    expect(empty).toHaveTextContent("第一次读到每个对象时只记下状态（基线），不产生事件");
    await pick("类别", /^中继分担$/, screen.getByTestId("link-log-filters"));
    await waitFor(() => expect(screen.getByTestId("link-log-empty")).toHaveAttribute("data-state", "no-match"));
    expect(screen.getByTestId("link-log-empty")).toHaveTextContent("没有符合筛选条件的事件");
    // The state now is still shown above.
    expect(screen.getByTestId("link-log-current")).toBeInTheDocument();
  });

  it("on a phone the tables are cards and nothing is pinned or scrolls sideways", async () => {
    phoneWidth();
    linkApi(() => linkLog());
    const { container } = mount(LinkLogsPage, "#/link-log");
    const box = await screen.findByTestId("link-log-events");
    await waitFor(() => expect(box.querySelectorAll(".data-card")).toHaveLength(5));
    await screen.findByTestId("link-log-current");
    expect(container.querySelector(".page table")).toBeNull();
    expect(container.querySelector(".ant-table-cell-fix-right")).toBeNull();
    for (const w of container.querySelectorAll(".data-table-wrap, .data-cards-wrap")) expect(w).toHaveAttribute("data-stacked", "true");
    expect(container.querySelector("[data-overflow='true']")).toBeNull();
    // The object is each card's heading; the change stays readable in the card.
    expect(box.querySelector(".data-card .data-card-title")).toHaveTextContent("中继 relay-a（分担）");
    expect(within(box).getAllByTestId("link-event")).toHaveLength(5);
    layoutChecks("phone #/link-log");
  });
});

describe("dns log clear error words", () => {
  it("names a clear mark that could not be written (the residue would not be known after a restart)", async () => {
    const { clearErrorText } = await import("./DNSLogsPage");
    expect(clearErrorText({ part: "journal", op: "write", cause: "read_only", count: 1 })).toBe("结构化日志清除标记写入失败（文件系统只读）");
  });
});


it("does not report an inactive historical self-check target as a current tunnel fault", async () => {
 const v=linkLog();
 v.scope.unobserved.push({class:"sniff_target",kind:"sniff_target",id:"group:old",label:"旧规则目标",observed:false,note:"当前规则不检查"});
 const old={...CARRY,class:"sniff_target",kind:"sniff_target",id:"group:old",label:"旧规则目标",stale:true};
 linkApi(()=>v,{"GET /api/link-log/current":()=>currentAnswer({unknown:[old,{...CARRY,stale:true}]})});
 mount(LinkLogsPage,"#/link-log");
 const cur=await screen.findByTestId("link-log-current");
 expect(within(cur).getByTestId("link-log-inactive-targets")).toHaveTextContent("不代表隧道故障");
 const unknown=within(cur).getByTestId("link-log-unknown");
 expect(unknown).not.toHaveTextContent("旧规则目标");
 expect(unknown).toHaveTextContent(CARRY.label!);
});
