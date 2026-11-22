// The device connection journal on its own page (连接日志, #/conn-log): read
// only when the page is opened (the sniff card links to it and reads
// nothing), the device list with summaries and labels, a device's paged
// records ("未记录名字" when names are off, the name when on), the label
// editor, the confirmed clear, the confirmation when name recording is
// switched (still on the sniff card; the page links to it), the scope text
// (what is not in the log), the result legend, results with how the
// connection ended, the connections still being relayed, the report of an
// unclean stop, the explicit empty states, the cross-link with the DNS
// query journal (and what it says when the device cannot be confirmed), and
// no sideways overflow on a phone.

import { App as AntApp } from "antd";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import ConnectionLogsPage from "./ConnectionLogsPage";
import { layoutChecks } from "./demo/testkit";
import { NAMES_OFF_TEXT, NAMES_ON_TEXT, SniffSection } from "./Sniff";
import { RouterProvider } from "./state";
import { fakeApi, nowrapCellRisks, phoneWidth, tableBudgets, type FakeRequest } from "./testing";
import type { LogRelatedView, SniffJournalRecord, SniffJournalView, SniffView } from "./types";

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

afterEach(() => vi.restoreAllMocks());

const AT = "2026-11-14T00:00:00Z";

function btn(text: string) {
  return new RegExp(`^\\s*${text.split("").join("\\s*")}\\s*$`);
}

function sniffView(names: boolean): SniffView {
  return {
    setting: { enabled: true, ports: [80, 443], ech_public_names: [], record_names: names },
    listen_port: 5358,
    coverage: { by_name: ["a"], address_only: ["b"], costs: ["c"] },
    runtime: { available: true, present: true, active: "active", recent: { record_names: names, connections: [] } },
  };
}

const SCOPE = {
  covered: ["接管端口上的 TCP"],
  lifecycle: ["每条连接在结束时写一条记录", "仍在转发的连接显示在设备的「正在转发」中"],
  results: ["成功：上游连上并且至少有一个字节从上游回到客户端", "不算失败：被规则拒绝、客户端关闭"],
  not_covered: ["所有 UDP，包括 QUIC", "不在接管列表里的 TCP 端口", "嗅探关闭期间的全部流量", "DNS 查询：这一轮没有接入"],
  storage: ["只存在网关本机"],
  names_on: ["已开启名字记录：SNI、Host、ECH 外层名"],
  names_off: ["未记录名字：日志不保存任何名字"],
};

const STATS = { records: 3, bytes: 900, segments: 1, dropped: 0, write_errors: 0, oversized: 0, max_records: 50000, max_age_s: 86400, max_bytes: 33554432, record_names: false };

function devices(names: boolean): SniffJournalView {
  return {
    available: true,
    record_names: names,
    scope: SCOPE,
    labels: [{ address: "192.0.2.10", label: "示例手机" }],
    summary: {
      record_names: names,
      stats: { ...STATS, record_names: names },
      devices: [
        { device: "192.0.2.10", mac: "00:00:5e:00:53:10", first_seen: AT, last_seen: AT, total: 2, by_name: 1, by_address: 1, name_unresolved: 1, failed: 1, by_class: { ok: 1, dial_failed: 1 }, by_end: { client_closed: 1 }, by_target: { "group:hk": 1, direct: 1 }, bytes_up: 517, bytes_down: 4096 },
        { device: "2001:db8::50", first_seen: AT, last_seen: AT, total: 1, by_name: 1, by_address: 0, name_unresolved: 0, failed: 0, by_class: { ok: 1 }, by_target: { "exit:jp-a": 1 }, bytes_up: 0, bytes_down: 0 },
      ],
    },
  };
}

function records(names: boolean): SniffJournalRecord[] {
  const base = { start: AT, source: "192.0.2.10", mac: "00:00:5e:00:53:10", decide_ms: 3, generation: 7 };
  return [
    { ...base, id: 3, dest: "198.51.100.1:443", proto: "tls", sniffed: true, by: "name", rule_index: 2, rule_id: "m2", target: "group:hk", upstream: "198.51.100.1:443", result: "dial_failed", reason: "timeout", duration_ms: 10003, ...(names ? { name: "www.example.com" } : {}) },
    {
      ...base,
      id: 2,
      dest: "198.51.100.2:80",
      proto: "http",
      sniffed: false,
      by: "addr",
      why: "name_unresolved",
      rule_index: -1,
      target: "direct",
      result: "ok",
      end: "client_closed",
      duration_ms: 4200,
      bytes_up: 517,
      bytes_down: 4096,
      error: "nxdomain",
      name_rule: { rule_index: 4, rule_id: "home", target: "direct", by: "name", error: "nxdomain" },
      ...(names ? { name: "internal.example.net" } : {}),
    },
  ];
}

function journalApi(names: boolean, extra: Record<string, (r: FakeRequest) => unknown> = {}) {
  return fakeApi({
    "GET /api/sniff": () => sniffView(names),
    "GET /api/sniff/devices": () => devices(names),
    "GET /api/sniff/journal": (r) => ({
      available: true,
      record_names: names,
      scope: SCOPE,
      labels: [],
      page: {
        record_names: names,
        stats: STATS,
        matched: 60,
        records: r.query.get("before") ? records(names).slice(1) : records(names),
        ...(r.query.get("before") ? {} : { next_before: 2 }),
      },
    }),
    ...extra,
  });
}

/** Renders the connection log page at `hash` (router only: the page needs no shell). */
function mountPage(hash = "#/conn-log?view=devices") {
  window.history.replaceState(null, "", `/${hash}`);
  return render(
    <AntApp>
      <RouterProvider>
        <ConnectionLogsPage />
      </RouterProvider>
    </AntApp>,
  );
}

async function openJournal(hash?: string) {
  mountPage(hash ?? "#/conn-log?view=devices");
  return screen.findByTestId("sniff-journal");
}

it("opens a query without waiting for device counts and confirms disconnecting active connections", async () => {
  const api = journalApi(true, {
    "POST /api/sniff/connections/disconnect": () => ({ disconnected: 3 }),
  });
  mountPage("#/conn-log");
  await waitFor(() => expect(api.find("GET /api/sniff/journal")).not.toHaveLength(0));
  expect(api.find("GET /api/sniff/devices")).toHaveLength(0);
  await userEvent.click(screen.getByRole("button", { name: btn("断开所有连接") }));
  expect(api.find("POST /api/sniff/connections/disconnect")).toHaveLength(0);
  const text = await screen.findByText(/立即关闭网关嗅探服务/);
  await userEvent.click(within(text.closest<HTMLElement>('[role="dialog"]')!).getByRole("button", { name: btn("断开所有连接") }));
  await screen.findByText("已断开 3 条连接");
  expect(api.find("POST /api/sniff/connections/disconnect")[0].body).toEqual({ confirm: true });
});

it("starts live refresh on open, updates a filtered first page and pauses on demand", async () => {
  vi.spyOn(document, "hidden", "get").mockReturnValue(false);
  let notify: ((value: { revision: string }) => void) | undefined;
  const api = journalApi(true, {
    "GET /api/sniff/journal/changes": r => {
      if (!r.query.get("after")) return { revision: "1" };
      return new Promise<{ revision: string }>(resolve => { notify = resolve; });
    },
  });
  mountPage("#/conn-log");
  const source = await screen.findAllByRole("button", { name: "筛选来源 192.0.2.10" });
  await userEvent.click(source[0]);
  await waitFor(() => expect(notify).toBeDefined());
  expect(api.find("GET /api/sniff/journal/changes")[0].query.get("after")).toBe("");
  const before = api.find("GET /api/sniff/journal").length;
  notify?.({ revision: "2" });
  await waitFor(() => expect(api.find("GET /api/sniff/journal")).toHaveLength(before + 1));
  expect(api.find("GET /api/sniff/journal").at(-1)?.query.get("device")).toBe("192.0.2.10");
  await userEvent.click(screen.getByRole("button", { name: btn("暂停实时刷新") }));
  expect(screen.getByRole("button", { name: btn("开启实时刷新") })).toBeInTheDocument();
});

it("shows the discovered hostname again after deleting a manual note", async () => {
  let useManualLabel = true;
  journalApi(true, {
    "GET /api/sniff/devices": () => ({
      ...devices(true),
      labels: useManualLabel ? devices(true).labels : [],
      device_names: { "192.0.2.10": "phone.lan" },
    }),
    "DELETE /api/sniff/devices/192.0.2.10/label": () => {
      useManualLabel = false;
      return {};
    },
  });
  const page = await openJournal();
  await userEvent.click(await within(page).findByRole("button", { name: "查看 示例手机 的连接" }));
  await userEvent.click(await screen.findByRole("button", { name: "改备注" }));
  await userEvent.click(screen.getByRole("button", { name: btn("删除备注") }));
  expect(await screen.findByText("phone.lan")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "加备注" })).toBeInTheDocument();
});

describe("connection log page: device connection journal", () => {
  it("the sniff card reads nothing of the journal and links to the page", async () => {
    const api = journalApi(false);
    window.history.replaceState(null, "", "/#/rules");
    render(
      <AntApp>
        <RouterProvider>
          <SniffSection />
        </RouterProvider>
      </AntApp>,
    );
    await screen.findByTestId("sniff-runtime");
    const entry = within(screen.getByTestId("sniff-journal-entry")).getByRole("link", { name: btn("查看设备连接日志") });
    expect(entry).toHaveAttribute("href", "#/conn-log");
    expect(api.find("GET /api/sniff/devices")).toHaveLength(0);
    expect(screen.queryByTestId("sniff-journal")).toBeNull();
    await userEvent.click(entry);
    expect(window.location.hash).toBe("#/conn-log");
    // Where the card talks about resolution: the way to the resolution settings (behind 「说明」).
    await userEvent.click(within(screen.getByTestId("sniff-dns-link")).getByRole("button", { name: /说明/ }));
    expect(within(screen.getByTestId("sniff-dns-link")).getByRole("link", { name: "解析设置" })).toHaveAttribute("href", "#/dns");
  });

  it("starts with what it records, what it does not, for how long, where and who can read it", async () => {
    journalApi(false);
    const j = await openJournal();
    expect(j).toBeInTheDocument();
    const intro = screen.getByTestId("conn-log-intro");
    expect(intro).toHaveTextContent("记录：");
    expect(intro).toHaveTextContent("不记录：");
    expect(intro).toHaveTextContent("UDP（含 QUIC）");
    expect(intro).toHaveTextContent("保留：");
    expect(intro).toHaveTextContent("/var/lib/meridian-sniff");
    expect(intro).toHaveTextContent("谁能看：");
    // The bounds are the journal's own once it answered.
    await waitFor(() => expect(intro).toHaveTextContent("最近 24 小时、最多 50000 条、不超过 32 MiB"));
  });

  it("lists devices with label, MAC and failures; states what is not logged", async () => {
    journalApi(false);
    const j = await openJournal();
    expect(await within(j).findByText("示例手机")).toBeInTheDocument();
    expect(j).toHaveTextContent("00:00:5e:00:53:10");
    expect(j).toHaveTextContent("2001:db8::50");
    const scope = screen.getByTestId("sniff-journal-scope");
    expect(scope).toHaveTextContent("未记录名字");
    expect(scope).toHaveTextContent("所有 UDP，包括 QUIC");
    expect(scope).toHaveTextContent("DNS 查询");
    const over = tableBudgets().filter((t) => t.width > t.budget);
    expect(over, over.map((t) => `${t.name}: ${t.width} > ${t.budget}`).join("; ")).toEqual([]);
  });

  it("a device's records: filtered by device, names not recorded, the unresolved name explained, paged", async () => {
    const api = journalApi(false);
    const j = await openJournal();
    await userEvent.click(await within(j).findByRole("button", { name: "查看 示例手机 的连接" }));
    const d = await screen.findByTestId("sniff-device");
    await waitFor(() => expect(d).toHaveTextContent("共 60 条已结束的连接符合"));
    expect(api.find("GET /api/sniff/journal")[0].query.get("device")).toBe("192.0.2.10");
    expect(within(d).getAllByText("未记录名字").length).toBeGreaterThanOrEqual(1);
    expect(within(d).getByRole("textbox", { name: "按名字搜索" })).toBeDisabled();
    expect(d).toHaveTextContent("名字解析不到，按地址");
    expect(d).toHaveTextContent("连接失败");
    expect(d).toHaveTextContent("地区组 hk");
    for (const b of within(d).getAllByRole("button", { name: /展开行|Expand row/ })) await userEvent.click(b);
    expect(d).toHaveTextContent("home → 直连（名字不存在，未采用，已按地址处理）");
    // dial_failed keeps its reason class and the address tried last.
    expect(d).toHaveTextContent("最后尝试的地址198.51.100.1:443");
    expect(d).toHaveTextContent("失败原因超时");
    expect(d).not.toHaveTextContent("www.example.com");
    await userEvent.click(within(d).getByRole("button", { name: btn("更早的记录") }));
    await waitFor(() => expect(api.find("GET /api/sniff/journal").some((c) => c.query.get("before") === "2")).toBe(true));
    await waitFor(() => expect(within(d).getByRole("button", { name: btn("更早的记录") })).toBeDisabled());
  });

  it("names recorded: shown and searchable", async () => {
    const api = journalApi(true);
    const j = await openJournal();
    expect(screen.getByTestId("sniff-journal-scope")).toHaveTextContent("SNI、Host、ECH 外层名");
    await userEvent.click(await within(j).findByRole("button", { name: "查看 2001:db8::50 的连接" }));
    const d = await screen.findByTestId("sniff-device");
    expect(await within(d).findByText("www.example.com")).toBeInTheDocument();
    await userEvent.type(within(d).getByRole("textbox", { name: "按名字搜索" }), "www");
    await waitFor(() => expect(api.find("GET /api/sniff/journal").some((c) => c.query.get("text") === "www")).toBe(true));
    const searches = api.find("GET /api/sniff/journal").filter(c => c.query.has("text"));
    expect(searches.map(c => c.query.get("text"))).toEqual(["www"]);
    expect(searches[0].query.get("page_only")).toBe("true");
  });

  it("labels are saved and removed through the panel", async () => {
    const api = journalApi(false, {
      "PUT /api/sniff/devices/:addr/label": (r) => ({ label: { address: r.params.addr, label: (r.body as { label: string }).label } }),
      "DELETE /api/sniff/devices/:addr/label": () => ({}),
    });
    const j = await openJournal();
    await userEvent.click(await within(j).findByRole("button", { name: "查看 2001:db8::50 的连接" }));
    const d = await screen.findByTestId("sniff-device");
    await userEvent.click(within(d).getByRole("button", { name: "加备注" }));
    await userEvent.type(within(d).getByRole("textbox", { name: "设备备注名" }), "示例平板");
    await userEvent.click(within(d).getByRole("button", { name: btn("保存备注") }));
    await waitFor(() => expect(api.find("PUT /api/sniff/devices/2001%3Adb8%3A%3A50/label")).toHaveLength(1));
    expect(api.find("PUT /api/sniff/devices/2001%3Adb8%3A%3A50/label")[0].body).toEqual({ label: "示例平板" });
  });

  it("clear asks first and sends the fixed confirmed request", async () => {
    const api = journalApi(false, { "POST /api/sniff/journal/clear": () => ({ cleared: { cleared: 3 } }) });
    const j = await openJournal();
    await within(j).findByText("示例手机");
    await userEvent.click(await clearItem(j, "清空日志"));
    const dialog = await screen.findByRole("dialog");
    expect(dialog).toHaveTextContent("立即删除网关上全部 3 条连接记录");
    expect(api.find("POST /api/sniff/journal/clear")).toHaveLength(0);
    await userEvent.click(within(dialog).getByRole("button", { name: btn("清空") }));
    await waitFor(() => expect(api.find("POST /api/sniff/journal/clear")).toHaveLength(1));
    expect(api.find("POST /api/sniff/journal/clear")[0].body).toEqual({ confirm: true });
  });

  it("switching name recording says what happens before saving", async () => {
    for (const [from, text] of [
      [false, NAMES_ON_TEXT],
      [true, NAMES_OFF_TEXT],
    ] as const) {
      const api = journalApi(from, { "PUT /api/sniff": (r) => ({ setting: r.body }) });
      const { unmount } = render(
        <AntApp>
          <SniffSection />
        </AntApp>,
      );
      await userEvent.click(await screen.findByRole("checkbox", { name: /记录嗅探读到的名字/ }));
      await userEvent.click(screen.getByRole("button", { name: btn("保存设置") }));
      const dialog = await screen.findByRole("dialog");
      expect(within(dialog).getByTestId("sniff-names-confirm")).toHaveTextContent(text);
      expect(api.find("PUT /api/sniff")).toHaveLength(0);
      await userEvent.click(within(dialog).getByRole("button", { name: from ? /下次安装时关闭/ : /下次安装时开启/ }));
      await waitFor(() => expect(api.find("PUT /api/sniff")).toHaveLength(1));
      expect((api.find("PUT /api/sniff")[0].body as { record_names: boolean }).record_names).toBe(!from);
      unmount();
      vi.restoreAllMocks();
    }
    expect(NAMES_OFF_TEXT).toContain("删除设备连接日志里已有的全部名字");
    expect(NAMES_ON_TEXT).toContain("24 小时");
  });

  it("results say how a relayed connection ended; the legend is shown; client closes are no failures", async () => {
    const recs: SniffJournalRecord[] = [
      { start: AT, source: "192.0.2.10", decide_ms: 2, generation: 7, id: 9, dest: "198.51.100.9:443", sniffed: false, rule_index: -1, target: "exit:jp-a", result: "relay_failed", end: "upstream_reset", reason: "read_reset", duration_ms: 300 },
      { start: AT, source: "192.0.2.10", decide_ms: 2, generation: 7, id: 8, dest: "198.51.100.8:443", sniffed: false, rule_index: -1, target: "exit:jp-a", result: "no_response", end: "idle_timeout", duration_ms: 7200000, bytes_up: 517 },
      { start: AT, source: "192.0.2.10", decide_ms: 2, generation: 7, id: 7, dest: "198.51.100.7:443", sniffed: false, rule_index: -1, target: "exit:jp-a", result: "ok", end: "upstream_reset", reason: "read_reset", bytes_down: 10 },
      { start: AT, source: "192.0.2.10", decide_ms: 2, generation: 7, id: 6, dest: "198.51.100.6:443", sniffed: false, rule_index: -1, target: "exit:jp-a", result: "ok" },
      { start: AT, source: "192.0.2.10", decide_ms: 2, generation: 7, id: 5, dest: "198.51.100.5:443", sniffed: false, rule_index: -1, target: "exit:jp-a", result: "shutdown", end: "shutdown", bytes_down: 99 },
    ];
    const view = devices(false);
    view.summary!.devices![0] = { ...view.summary!.devices![0], total: 10, failed: 3, by_class: { ok: 2, relay_failed: 1, no_response: 1, shutdown: 1, client_closed: 4, rejected: 1 }, active: 2 };
    view.summary!.stats = { ...STATS, unclean_stop: { last_alive: AT, active: 4, detected_at: AT } };
    fakeApi({
      "GET /api/sniff": () => sniffView(false),
      "GET /api/sniff/devices": () => view,
      "GET /api/sniff/journal": () => ({
        available: true,
        record_names: false,
        scope: SCOPE,
        labels: [],
        page: {
          record_names: false,
          stats: STATS,
          matched: recs.length,
          records: recs,
          active: [{ start: AT, source: "192.0.2.10", decide_ms: 3, generation: 7, dest: "198.51.100.30:443", sniffed: true, rule_index: 1, target: "group:hk", result: "active", conn: 77, duration_ms: 125000, bytes_up: 2048, bytes_down: 1048576 }],
          active_matched: 2,
        },
      }),
    });
    const j = await openJournal();
    expect(screen.getByTestId("sniff-journal-legend")).toHaveTextContent("成功：上游连上并且至少有一个字节从上游回到客户端");
    expect(within(j).getByTestId("sniff-journal-unclean")).toHaveTextContent("当时仍打开的 4 条连接没有记录");
    // The device list's failures are the forwarder's count (client closes and rejects are not failures); open connections apart.
    const row = (await within(j).findByText("示例手机")).closest("tr")!;
    expect(row).toHaveTextContent("+2 转发中");
    expect(within(row).getByText("3")).toBeInTheDocument();
    await userEvent.click(within(j).getByRole("button", { name: "查看 示例手机 的连接" }));
    const d = await screen.findByTestId("sniff-device");
    const active = await within(d).findByTestId("sniff-journal-active");
    expect(active).toHaveTextContent("正在转发 2（列出最新的 1 条）");
    expect(active).toHaveTextContent("2 分 5 秒");
    const cells = within(d).getAllByTestId("sniff-result").map((c) => c.textContent);
    expect(cells).toEqual([
      "连上后被重置 / 出错上游重置，读：被重置",
      "连上后无回应空闲超时",
      "成功上游重置，读：被重置",
      "结束情况未知旧版本记录：连上时就记了",
      "服务停止时中断服务停止",
    ]);
  });

  it("on a phone the device list and the records are cards, not a wide table", async () => {
    phoneWidth();
    journalApi(false);
    const { container } = mountPage();
    const j = await screen.findByTestId("sniff-journal");
    await within(j).findByText("示例手机");
    expect(j.querySelector("table")).toBeNull();
    expect(j.querySelector(".data-table-wrap")).toHaveAttribute("data-stacked", "true");
    await userEvent.click(within(j).getByRole("button", { name: "查看 示例手机 的连接" }));
    const d = await screen.findByTestId("sniff-device");
    await waitFor(() => expect(d.querySelectorAll(".data-card").length).toBe(2));
    expect(d.querySelector("table")).toBeNull();
    expect(container.querySelector(".data-table-wrap[data-overflow='true']")).toBeNull();
    expect(container.querySelector(".ant-table-cell-fix-right")).toBeNull();
    layoutChecks("phone #/conn-log");
  });

  it("a gateway without the journal or a stopped forwarder is said plainly", async () => {
    fakeApi({
      "GET /api/sniff": () => sniffView(false),
      "GET /api/sniff/devices": () => ({ available: false, code: "no_journal", record_names: false, scope: SCOPE, labels: [] }),
    });
    const j = await openJournal();
    expect(await within(j).findByText(/没有连接日志（旧版本或日志目录无法打开）/)).toBeInTheDocument();
    expect(isDisabled(await clearItem(j, "清空日志"))).toBe(true);
  });

  it("says where the switch of name recording is and what the gateway records now", async () => {
    const view = devices(false);
    fakeApi({ "GET /api/sniff": () => sniffView(true), "GET /api/sniff/devices": () => ({ ...view, record_names: true }) });
    const j = await openJournal();
    const line = await within(j).findByTestId("conn-log-names");
    expect(line).toHaveTextContent("网关上未开启");
    expect(screen.getByTestId("page-help")).toHaveTextContent("默认不记录名字");
    // Saved as on, not installed yet.
    expect(line).toHaveTextContent("设置已改为开启，下次安装到网关后才生效");
    expect(within(line).getByRole("link", { name: "去修改名字记录的设置" })).toHaveAttribute("href", "#/rules?section=sniff");
    expect(screen.getByTestId("sniff-journal-scope")).toHaveTextContent("名字记录的设置已经修改");
  });

  it("explicit empty states: sniffing off, forwarder not running, no data yet", async () => {
    const off = { available: false, code: "no_socket", record_names: false, scope: SCOPE, labels: [] };
    // Sniffing is off in the topology and nothing runs on the gateway.
    fakeApi({
      "GET /api/sniff": () => ({ ...sniffView(false), setting: { enabled: false, ports: [80, 443], ech_public_names: [], record_names: false }, runtime: { available: true, present: false } }),
      "GET /api/sniff/devices": () => off,
    });
    let view = mountPage();
    let empty = await screen.findByTestId("conn-log-empty");
    expect(empty).toHaveAttribute("data-state", "not-enabled");
    expect(empty).toHaveTextContent("按域名嗅探没有开启，所以没有连接日志");
    expect(within(empty).getByRole("link", { name: btn("去开启按域名嗅探") })).toHaveAttribute("href", "#/rules?section=sniff");
    expect(within(empty).getByRole("link", { name: btn("去部署页安装") })).toHaveAttribute("href", "#/deploy");
    view.unmount();
    vi.restoreAllMocks();

    // Saved as on, but no forwarder runs on the gateway (not installed yet, or stopped).
    fakeApi({ "GET /api/sniff": () => ({ ...sniffView(false), runtime: { available: true, present: false } }), "GET /api/sniff/devices": () => off });
    view = mountPage();
    empty = await screen.findByTestId("conn-log-empty");
    expect(empty).toHaveAttribute("data-state", "not-installed");
    expect(empty).toHaveTextContent("还没有安装到网关");
    expect(within(empty).getByRole("link", { name: btn("去部署页安装") })).toHaveAttribute("href", "#/deploy");
    view.unmount();
    vi.restoreAllMocks();

    // Running, nothing recorded yet.
    const none = devices(false);
    none.summary = { record_names: false, stats: { ...STATS, records: 0, bytes: 0 }, devices: [] };
    fakeApi({ "GET /api/sniff": () => sniffView(false), "GET /api/sniff/devices": () => none });
    mountPage();
    empty = await screen.findByTestId("conn-log-empty");
    expect(empty).toHaveAttribute("data-state", "no-data");
    expect(empty).toHaveTextContent("日志里还没有连接");
    expect(isDisabled(await clearItem(undefined, "清空日志"))).toBe(false);
  });

  it("a record links to the same device's queries around it, saying what the link rests on", async () => {
    journalApi(false);
    const j = await openJournal();
    await userEvent.click(await within(j).findByRole("button", { name: "查看 示例手机 的连接" }));
    const d = await screen.findByTestId("sniff-device");
    await waitFor(() => expect(d).toHaveTextContent("共 60 条已结束的连接符合"));
    for (const b of within(d).getAllByRole("button", { name: /展开行|Expand row/ })) await userEvent.click(b);
    const links = within(d).getAllByTestId("conn-related-link");
    expect(links).toHaveLength(2);
    const a = within(links[0]).getByRole("link");
    const q = new URLSearchParams(a.getAttribute("href")!.split("?")[1]);
    expect(a.getAttribute("href")!.startsWith("#/dns-log?")).toBe(true);
    expect(Object.fromEntries(q)).toEqual({ device: "192.0.2.10", at: AT, mac: "00:00:5e:00:53:10" });
    expect(links[0]).toHaveTextContent("按地址和 MAC");
    // No name is ever part of the link.
    expect(a.getAttribute("href")).not.toContain("example");
  });

  it("opened from a query: lists the connections of the window; a confirmed device, an unconfirmed one, and excluded records", async () => {
    const rel = (over: Partial<LogRelatedView<SniffJournalRecord>>): LogRelatedView<SniffJournalRecord> => ({
      available: true,
      device: "192.0.2.10",
      mac: "00:00:5e:00:53:10",
      from: "2026-11-13T23:58:00Z",
      to: "2026-11-14T00:02:00Z",
      window_s: 120,
      identity: "mac",
      records: records(false),
      listed: 2,
      other_mac: 0,
      no_mac: 0,
      more: false,
      record_names: false,
      ...over,
    });
    // 1. Every listed connection carries the asked MAC: the same device.
    let api = journalApi(false, { "GET /api/dns-log/related": () => rel({ other_mac: 3 }) });
    let view = mountPage(`#/conn-log?device=192.0.2.10&at=${encodeURIComponent(AT)}&mac=${encodeURIComponent("00:00:5e:00:53:10")}`);
    let panel = await screen.findByTestId("conn-log-related");
    await waitFor(() => expect(panel).toHaveAttribute("data-identity", "mac"));
    expect(within(panel).getByTestId("conn-log-related-title")).toHaveTextContent(/^同一设备相近时间的连接$/);
    const idn = within(panel).getByTestId("conn-log-related-identity");
    expect(idn).toHaveTextContent("按设备身份关联：地址 192.0.2.10");
    expect(idn).toHaveTextContent("另有 3 条同一地址、但 MAC 不同的连接没有列出");
    const sent = api.find("GET /api/dns-log/related")[0].query;
    expect(Object.fromEntries(sent)).toEqual({ device: "192.0.2.10", at: AT, mac: "00:00:5e:00:53:10", window: "120" });
    expect(panel).toHaveTextContent("198.51.100.1:443");
    // The window is bounded: the choices end at ten minutes.
    await userEvent.click(within(panel).getByRole("combobox", { name: "时间窗" }));
    const opts = [...document.querySelectorAll(".ant-select-dropdown:not(.ant-select-dropdown-hidden) .ant-select-item-option")].map((o) => o.textContent);
    expect(opts).toEqual(["前后各 1 分钟", "前后各 2 分钟", "前后各 5 分钟", "前后各 10 分钟"]);
    // The device list is still there below.
    expect(await screen.findByText("示例手机")).toBeInTheDocument();
    view.unmount();
    vi.restoreAllMocks();

    // 2. The query had no MAC: matched by address only, never called the same device.
    api = journalApi(false, {
      "GET /api/dns-log/related": () => rel({ mac: undefined, identity: "address", no_mac: 0, records: records(false).map((r) => ({ ...r, mac: undefined })) }),
    });
    view = mountPage(`#/conn-log?device=192.0.2.10&at=${encodeURIComponent(AT)}`);
    panel = await screen.findByTestId("conn-log-related");
    await waitFor(() => expect(panel).toHaveAttribute("data-identity", "address"));
    expect(within(panel).getByTestId("conn-log-related-title")).toHaveTextContent("同一地址相近时间的连接（未确认是同一台设备）");
    expect(within(panel).getByTestId("conn-log-related-title")).not.toHaveTextContent("同一设备");
    const basis = within(panel).getByTestId("conn-log-related-identity");
    expect(basis).toHaveClass("unconfirmed");
    expect(basis).toHaveTextContent("仅按地址 192.0.2.10 和时间窗关联，不能确认是同一台设备");
    expect(basis).toHaveTextContent("没有 MAC");
    expect(within(panel).getAllByText("无 MAC · 仅按地址")).toHaveLength(2);
    expect(api.find("GET /api/dns-log/related")[0].query.get("mac")).toBeNull();
    view.unmount();
    vi.restoreAllMocks();

    // 3. Some listed connections carry no MAC: said, and marked per row.
    journalApi(false, {
      "GET /api/dns-log/related": () => rel({ identity: "partial", no_mac: 1, more: true, records: [records(false)[0], { ...records(false)[1], mac: undefined }] }),
    });
    view = mountPage(`#/conn-log?device=192.0.2.10&at=${encodeURIComponent(AT)}&mac=${encodeURIComponent("00:00:5e:00:53:10")}`);
    panel = await screen.findByTestId("conn-log-related");
    await waitFor(() => expect(panel).toHaveAttribute("data-identity", "partial"));
    expect(within(panel).getByTestId("conn-log-related-title")).toHaveTextContent("未确认是同一台设备");
    expect(within(panel).getByTestId("conn-log-related-identity")).toHaveTextContent("列出的 2 条连接里有 1 条没有 MAC");
    expect(within(panel).getByTestId("conn-log-related-identity")).toHaveTextContent("只列出最新的 2 条");
    expect(within(panel).getAllByText("无 MAC · 仅按地址")).toHaveLength(1);
    view.unmount();
    vi.restoreAllMocks();

    // 4. Nothing in the window, and a journal that cannot be read: both said plainly.
    journalApi(false, { "GET /api/dns-log/related": () => rel({ identity: "address", records: [], listed: 0 }) });
    view = mountPage(`#/conn-log?device=192.0.2.10&at=${encodeURIComponent(AT)}&mac=${encodeURIComponent("00:00:5e:00:53:10")}`);
    let empty = await screen.findByTestId("conn-log-related-empty");
    expect(empty).toHaveAttribute("data-state", "none");
    expect(empty).toHaveTextContent("这个时间窗里没有这个地址的连接");
    await userEvent.click(within(screen.getByTestId("conn-log-related")).getByRole("button", { name: btn("关闭") }));
    expect(window.location.hash).toBe("#/conn-log");
    await waitFor(() => expect(screen.queryByTestId("conn-log-related")).toBeNull());
    view.unmount();
    vi.restoreAllMocks();
    journalApi(false, { "GET /api/dns-log/related": () => rel({ available: false, code: "no_socket", message: "嗅探服务没有运行", identity: "address", records: [], listed: 0 }) });
    mountPage(`#/conn-log?device=192.0.2.10&at=${encodeURIComponent(AT)}`);
    empty = await screen.findByTestId("conn-log-related-empty");
    expect(empty).toHaveAttribute("data-state", "no_socket");
    expect(empty).toHaveTextContent("嗅探服务没有运行");
  });

  it("a 64-character device label and a long recorded name sit in wrapping cells, not in nowrap ones", async () => {
    const LABEL64 = "客厅里那台很旧的示例电视盒子（给孩子看动画片用的那一台，放在电视柜左边第二层）".padEnd(64, "备注名很长");
    expect([...LABEL64]).toHaveLength(64);
    const LONGNAME = `${"a-very-long-label-for-layout-checks.".repeat(5)}example.com`;
    const view = devices(true);
    view.labels = [{ address: "192.0.2.10", label: LABEL64 }];
    fakeApi({
      "GET /api/sniff": () => sniffView(true),
      "GET /api/sniff/devices": () => view,
      "GET /api/sniff/journal": () => ({
        available: true,
        record_names: true,
        scope: SCOPE,
        labels: view.labels,
        page: { record_names: true, stats: STATS, matched: 2, records: records(true).map((r) => ({ ...r, name: LONGNAME, rule_id: "a-rule-with-a-very-long-identifier-for-layout" })) },
      }),
    });
    const j = await openJournal();
    const label = await within(j).findByText(LABEL64);
    expect(label.closest("td")).toHaveClass("col-flex");
    expect(nowrapCellRisks(j)).toEqual([]);
    await userEvent.click(within(j).getByRole("button", { name: `查看 ${LABEL64} 的连接` }));
    const d = await screen.findByTestId("sniff-device");
    const names = await within(d).findAllByText(LONGNAME);
    // The name is cut with "…" (full text on hover and focus), inside a cell that wraps.
    for (const n of names) {
      expect(n).toHaveClass("ellipsis-text");
      expect(n).toHaveAttribute("tabindex", "0");
      expect(n.closest("td")).toHaveClass("col-flex");
    }
    expect(nowrapCellRisks(d)).toEqual([]);
    const over = tableBudgets().filter((t) => t.width > t.budget);
    expect(over, over.map((t) => `${t.name}: ${t.width} > ${t.budget}`).join("; ")).toEqual([]);
  });

  it("opens a device directly from #/conn-log?device=", async () => {
    const api = journalApi(false);
    await openJournal("#/conn-log?device=192.0.2.10");
    const d = await screen.findByTestId("sniff-device");
    await waitFor(() => expect(api.find("GET /api/sniff/journal")[0]?.query.get("device")).toBe("192.0.2.10"));
    expect(screen.queryByTestId("conn-log-related")).toBeNull();
    await userEvent.click(within(d).getByRole("button", { name: /全部设备/ }));
    expect(window.location.hash).toBe("#/conn-log");
    expect(await screen.findByRole("button", { name: "查看 示例手机 的连接" })).toBeInTheDocument();
  });
});
