// Interaction tests of the operational pages against the in-memory fake
// API (split out of the former pages.test.tsx; helpers and fixtures in
// pages_fixtures.tsx).
//
// Remote access (the one-time configuration, runtime states), unlock
// (reachability is never an unlock, the validation notice, batch by group,
// removed exits, TCP-only exits), leak (nothing in the integration or human
// groups ever passes) and tables at narrow widths.

import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { fakeApi, panelStatus, renderAt, reply, webStorageDump } from "./testing";
import { endpointAccessText } from "./leak_status";
import type { RemoteDeviceView, UnlockCellState, UnlockMatrixView } from "./types";
import {
  NOW,
  btn,
  confirmModal,
  menuItem,
  topology,
  server,
  PRIVATE,
  PSK,
  device,
  remoteView,
  configText,
  OK_AGENT,
} from "./pages_fixtures";

describe("remote access", () => {
  it("lets devices reach each other only when switched on, and says it takes an install", async () => {
    let sent: unknown;
    fakeApi({
      "GET /api/remote-access": () => remoteView([]),
      "PUT /api/remote-access": (req) => {
        sent = req.body;
        const v = remoteView([]);
        return { ...v, settings: { ...v.settings, allow_peers: true }, apply_required: true };
      },
    });
    renderAt("#/remote");
    const toggle = await screen.findByRole("switch", { name: "允许接入设备互相访问" });
    expect(toggle).not.toBeChecked();
    await userEvent.click(toggle);
    await waitFor(() => expect(sent).toEqual({ allow_peers: true }));
    await waitFor(() => expect(screen.getByRole("switch", { name: "允许接入设备互相访问" })).toBeChecked());
  });

  it("shows the one-time configuration once (text, copy, download, QR), requires an acknowledgement and forgets it on close", async () => {
    let devices: RemoteDeviceView[] = [];
    const created = vi.fn();
    (URL as unknown as { createObjectURL: unknown }).createObjectURL = vi.fn(() => "blob:test");
    (URL as unknown as { revokeObjectURL: unknown }).revokeObjectURL = vi.fn();
    const clickSpy = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    const api = fakeApi({
      "GET /api/remote-access": () => remoteView(devices),
      "POST /api/remote-access/devices": (req) => {
        created(req.body);
        const d = device({ name: (req.body as { name: string }).name });
        devices = [d];
        return reply(201, {
          device: d,
          config: { text: configText(d.name), filename: "meridian-phone.conf", mode: "full", explanation: "全隧道模式：全部流量进隧道。", shown_once: true },
          router_forward: remoteView([]).router_forward,
          apply_required: true,
        });
      },
    });
    renderAt("#/remote");
    await userEvent.click(await screen.findByRole("button", { name: /添加设备/ }));
    const drawer = await screen.findByRole("dialog");
    expect(drawer).toHaveTextContent("部分 DNS 可能仍走当前网络");
    await userEvent.type(within(drawer).getByLabelText("设备名称"), "我的手机");
    await userEvent.click(within(drawer).getByRole("button", { name: /添加并生成配置/ }));
    expect(created).toHaveBeenCalledWith(expect.objectContaining({ name: "我的手机", preshared_key: true, mode: "full" }));

    const dialog = await screen.findByTestId("config-once");
    expect(within(dialog).getByTestId("config-text")).toHaveTextContent(PRIVATE);
    expect(dialog).toHaveTextContent("这份配置只显示这一次");
    expect(dialog).toHaveTextContent("网关不保存这把私钥");
    expect(dialog.querySelector(".ant-qrcode svg")).not.toBeNull();
    expect(within(dialog).getByRole("button", { name: /复制配置/ })).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole("button", { name: /下载 meridian-phone.conf/ }));
    expect(URL.createObjectURL).toHaveBeenCalledTimes(1);
    expect(clickSpy).toHaveBeenCalled();

    // Cannot be dismissed without the acknowledgement.
    const close = screen.getByRole("button", { name: btn("关闭") });
    expect(close).toBeDisabled();
    fireEvent.keyDown(document.activeElement ?? document.body, { key: "Escape" });
    expect(screen.getByTestId("config-once")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("checkbox", { name: /我已导入设备或保存好配置/ }));
    await userEvent.click(close);
    await waitFor(() => expect(screen.queryByTestId("config-once")).toBeNull());

    // Gone: not in the DOM, web storage or the URL, and never sent back.
    await userEvent.click(screen.getByRole("button", { name: /刷新/ }));
    await waitFor(() => expect(api.find("GET /api/remote-access").length).toBeGreaterThan(1));
    expect(document.body.innerHTML).not.toContain(PRIVATE);
    expect(document.body.innerHTML).not.toContain(PSK);
    expect(webStorageDump()).not.toContain(PRIVATE);
    expect(window.location.href).not.toContain(PRIVATE);
    expect(api.calls.filter((c) => c.raw?.includes(PRIVATE) || c.raw?.includes(PSK))).toHaveLength(0);
    expect(screen.getByTestId("device-status-dev-1")).toHaveTextContent("尚未安装");
  });

  it("regenerates with a consequence, then shows the new configuration once", async () => {
    const api = fakeApi({
      "GET /api/remote-access": () => remoteView([device({ runtime_state: "ok", runtime: { last_handshake_at: NOW, rx_bytes: 2048, tx_bytes: 4096, online: false } })]),
      "POST /api/remote-access/devices/:id/regenerate": () => ({
        device: device({ config_outdated: false }),
        config: { text: configText("我的手机"), filename: "meridian-phone.conf", mode: "full", explanation: "", shown_once: true },
        router_forward: remoteView([]).router_forward,
        apply_required: true,
      }),
    });
    renderAt("#/remote");
    const row = await screen.findByTestId("device-row-dev-1");
    await userEvent.click(within(row).getByRole("button", { name: /重新生成/ }));
    await waitFor(() => expect(document.querySelector(".ant-modal-confirm")).toHaveTextContent("旧配置在下一次安装后失效"));
    await confirmModal("重新生成");
    await waitFor(() => expect(api.find("POST /api/remote-access/devices/dev-1/regenerate")).toHaveLength(1));
    expect(api.find("POST /api/remote-access/devices/dev-1/regenerate")[0].body).toEqual({ preshared_key: true });
    expect(await screen.findByTestId("config-text")).toHaveTextContent(PRIVATE);
  });

  it("disables and deletes a device, each after a consequence sentence", async () => {
    let devs = [device({ runtime_state: "ok", runtime: { last_handshake_at: NOW, rx_bytes: 1, tx_bytes: 1, online: true } })];
    const api = fakeApi({
      "GET /api/remote-access": () => remoteView(devs),
      "PATCH /api/remote-access/devices/:id": (req) => {
        devs = [device({ ...devs[0], ...(req.body as object), runtime_state: "not_read" })];
        return { device: devs[0], apply_required: true };
      },
      "DELETE /api/remote-access/devices/:id": () => {
        devs = [];
        return { deleted: "dev-1", apply_required: true };
      },
    });
    renderAt("#/remote");
    expect(await screen.findByTestId("device-status-dev-1")).toHaveTextContent("在线");
    await userEvent.click(screen.getByRole("switch", { name: "启用 我的手机" }));
    await waitFor(() => expect(document.querySelector(".ant-modal-confirm")).toHaveTextContent("配置和地址保留"));
    await confirmModal("停用");
    await waitFor(() => expect(api.find("PATCH /api/remote-access/devices/dev-1")).toHaveLength(1));
    expect(api.find("PATCH /api/remote-access/devices/dev-1")[0].body).toEqual({ enabled: false });

    await menuItem(within(screen.getByTestId("device-row-dev-1")).getByRole("button", { name: "我的手机 的更多操作" }), "删除");
    await waitFor(() => expect(document.querySelector(".ant-modal-confirm")).toHaveTextContent("设备上的配置作废"));
    await confirmModal("删除");
    await waitFor(() => expect(api.find("DELETE /api/remote-access/devices/dev-1")).toHaveLength(1));
    await waitFor(() => expect(screen.queryByTestId("device-row-dev-1")).toBeNull());
    expect(await screen.findByText(/远程接入已修改，但还没有安装到网关/)).toBeInTheDocument();
  });

  it("a peer-only change applied at once shows 已生效 and no install prompt; a failure shows its reason", async () => {
    let devs: RemoteDeviceView[] = [];
    let fail = false;
    const api = fakeApi({
      "GET /api/remote-access": () => remoteView(devs),
      "POST /api/remote-access/devices": () => {
        const d = device({ name: "平板" });
        devs = [d];
        return reply(201, {
          device: d,
          config: { text: configText(d.name), filename: "meridian-pad.conf", mode: "full", explanation: "", shown_once: true },
          router_forward: remoteView([]).router_forward,
          apply_required: false,
          fast_apply: { status: "applied", version: 8 },
        });
      },
      "DELETE /api/remote-access/devices/:id": () => {
        devs = [];
        return fail
          ? { deleted: "dev-1", apply_required: true, fast_apply: { status: "failed", reason: "wg syncconf mra 失败（已恢复原配置）" } }
          : { deleted: "dev-1", apply_required: false, fast_apply: { status: "applied", version: 9 } };
      },
    });
    renderAt("#/remote");
    await userEvent.click(await screen.findByRole("button", { name: /添加设备/ }));
    const drawer = await screen.findByRole("dialog");
    await userEvent.type(within(drawer).getByLabelText("设备名称"), "平板");
    await userEvent.click(within(drawer).getByRole("button", { name: /添加并生成配置/ }));
    const dialog = await screen.findByTestId("config-once");
    expect(within(dialog).getByTestId("fast-applied")).toHaveTextContent("已生效");
    expect(dialog).not.toHaveTextContent("到「部署」页安装后生效");
    expect(await screen.findByText(/设备 平板 已添加，已生效/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("checkbox", { name: /我已导入设备或保存好配置/ }));
    await userEvent.click(screen.getByRole("button", { name: btn("关闭") }));
    await waitFor(() => expect(screen.queryByTestId("config-once")).toBeNull());

    fail = true;
    await menuItem(within(await screen.findByTestId("device-row-dev-1")).getByRole("button", { name: "平板 的更多操作" }), "删除");
    await confirmModal("删除");
    await waitFor(() => expect(api.find("DELETE /api/remote-access/devices/dev-1")).toHaveLength(1));
    expect(await screen.findByText(/平板 已删除，未生效：wg syncconf mra 失败（已恢复原配置）/)).toBeInTheDocument();
  });

  it("shows why the runtime is unavailable instead of inventing a state", async () => {
    fakeApi({
      "GET /api/remote-access": () =>
        remoteView([device({ runtime_state: "unavailable" }), device({ id: "dev-2", name: "平板", enabled: false, runtime_state: "disabled", config_outdated: true })], {
          available: false,
          state: "agent_unavailable",
          reason: "没有配置 host agent，读不到运行状态",
          interface: "mra",
        }),
    });
    renderAt("#/remote");
    const s1 = await screen.findByTestId("device-status-dev-1");
    expect(s1).toHaveTextContent("读不到状态");
    expect(s1.querySelector('[data-status="unverified"]')).not.toBeNull();
    expect(screen.getByTestId("device-status-dev-2")).toHaveTextContent("已停用");
    expect(screen.getByText("宿主执行通道不可用，读不到运行状态")).toBeInTheDocument();
    expect(screen.getByText("配置已过期")).toBeInTheDocument();
    // The router forward is spelled out, with copy buttons, and marked as unverifiable.
    const fwd = screen.getByTestId("router-forward");
    expect(fwd).toHaveTextContent("192.0.2.88");
    expect(fwd).toHaveTextContent("51888");
    expect(screen.getByText("面板无法验证")).toBeInTheDocument();
  });
});

describe("remote access: configuration text", () => {
  it("wraps the one-time configuration for reading without changing the text", async () => {
    const text = configText("长名字的设备") + "# " + "x".repeat(300) + "\n";
    fakeApi({
      "GET /api/remote-access": () => remoteView([device()]),
      "POST /api/remote-access/devices/:id/regenerate": () => ({
        device: device(),
        config: { text, filename: "meridian-phone.conf", mode: "full", explanation: "", shown_once: true },
        router_forward: remoteView([]).router_forward,
        apply_required: true,
      }),
    });
    renderAt("#/remote");
    const row = await screen.findByTestId("device-row-dev-1");
    await userEvent.click(within(row).getByRole("button", { name: /重新生成/ }));
    await confirmModal("重新生成");
    const pre = await screen.findByTestId("config-text");
    expect(pre.textContent).toBe(text);
    expect(pre.style.whiteSpace).toBe("pre-wrap");
    expect(pre.style.overflowX).toBe("hidden");
  });
});

describe("unlock by region", () => {
  const cell = (exit_id: string, state: UnlockCellState, extra: Record<string, unknown> = {}) => ({ exit_id, state, ...extra });
  const matrix = (adopted = false): UnlockMatrixView => ({
    running: "",
    available: true,
    regions: [
      {
        code: "global",
        name: "全球",
        exits: [
          { id: "hk-ix", name: "香港 IX", regions: ["hk"], groups: ["hk"] },
          { id: "us", name: "美国", regions: ["us"], groups: ["us"] },
        ],
        services: [
          {
            id: "auto-netflix",
            name: "Netflix",
            rules: ["auto-netflix"],
            targets: ["us"],
            cells: [cell("hk-ix", "unlocked", { region: "hk" }), cell("us", "unverified", { reason: "出口地址未确认：trace 超时" })],
            recommend: { exit_id: "hk-ix", exit_name: "香港 IX", group: "hk", group_name: "香港", adopted },
          },
          { id: "auto-perplexity", name: "Perplexity", rules: [], targets: [], cells: [cell("hk-ix", "local"), cell("us", "untested")], recommend: null },
          { id: "youtube-premium", name: "YouTube Premium", rules: [], targets: [], cells: [cell("hk-ix", "blocked"), cell("us", "untested")], recommend: null },
        ],
      },
      {
        code: "hk",
        name: "香港",
        exits: [{ id: "hk-ix", name: "香港 IX", regions: ["hk"], groups: ["hk"] }],
        services: [{ id: "auto-mytvsuper", name: "MyTV SUPER", rules: [], targets: [], cells: [cell("hk-ix", "untested")], recommend: null }],
      },
    ],
  });
  const base = () => ({
    "GET /api/topology": () => topology(),
    "GET /api/status": () => panelStatus({ ...OK_AGENT, probe_available: true }),
    "GET /api/unlock/matrix": () => matrix(),
  });

  it("shows one table per region with cell words, no checkboxes, no service groups and no fail-closed banner", async () => {
    fakeApi(base());
    renderAt("#/unlock");
    const global = await screen.findByTestId("unlock-table-global");
    expect(screen.getByTestId("unlock-table-hk")).toBeInTheDocument();
    expect(screen.queryByTestId("unlock-table-jp")).toBeNull();
    expect(document.querySelector('input[type="checkbox"]')).toBeNull();
    expect(document.body).not.toHaveTextContent("服务组");
    expect(document.body).not.toHaveTextContent("策略组");
    expect(document.body).not.toHaveTextContent("失败关闭");
    expect(document.body).not.toHaveTextContent("验收");
    const nf = within(global).getByTestId("row-global-auto-netflix");
    expect(within(nf).getByTestId("cell-hk-ix")).toHaveTextContent("解锁HK");
    const miss = within(nf).getByTestId("cell-us");
    expect(miss).toHaveTextContent("未测到");
    expect(miss).toHaveAttribute("aria-label", "未测到：出口地址未确认：trace 超时");
    expect(within(within(global).getByTestId("row-global-auto-perplexity")).getByTestId("cell-hk-ix")).toHaveTextContent("仅本地");
    expect(within(within(global).getByTestId("row-global-youtube-premium")).getByTestId("cell-hk-ix")).toHaveTextContent("不可用");
    expect(within(within(global).getByTestId("row-global-youtube-premium")).getByTestId("cell-us")).toHaveTextContent("未测");
    // Only a service with a recommendation and rules offers 确认.
    expect(within(global).getAllByRole("button", { name: /^确认 / })).toHaveLength(1);
  });

  it("probes everything or one region", async () => {
    const api = fakeApi({
      ...base(),
      "POST /api/unlock/run": () => reply(202, { job: { id: "job-1", kind: "manual", state: "running", created_at: NOW, items: [] } }),
    });
    renderAt("#/unlock");
    await screen.findByTestId("unlock-table-hk");
    await userEvent.click(screen.getByRole("button", { name: "探测香港" }));
    await waitFor(() => expect(api.find("POST /api/unlock/run")).toHaveLength(1));
    expect(api.find("POST /api/unlock/run")[0].body).toEqual({ scope: "hk" });
    await waitFor(() => expect(screen.getByRole("button", { name: "探测香港" })).toBeDisabled());
  });

  it("starts a probe of everything from the page header", async () => {
    const api = fakeApi({
      ...base(),
      "POST /api/unlock/run": () => reply(202, { job: { id: "job-1", kind: "manual", state: "running", created_at: NOW, items: [] } }),
    });
    renderAt("#/unlock");
    await screen.findByTestId("unlock-table-global");
    await userEvent.click(screen.getByRole("button", { name: "全部探测" }));
    await waitFor(() => expect(api.find("POST /api/unlock/run")).toHaveLength(1));
    expect(api.find("POST /api/unlock/run")[0].body).toEqual({ scope: "all" });
  });

  it("adopts a recommendation and says whether it is in effect or needs a deploy", async () => {
    let adopted = false;
    const api = fakeApi({
      ...base(),
      "GET /api/unlock/matrix": () => matrix(adopted),
      "POST /api/unlock/adopt": (req) => {
        if ((req.body as { preview?: boolean }).preview) return { preview: true, group: "hk", exit: "hk-ix", service_rules: ["auto-netflix"], other_rules: 0 };
        adopted = true;
        return { updated: 1, group: "hk", exit: "hk-ix", apply_required: true, fast_apply: { status: "required", reason: "地区组也改了" } };
      },
    });
    renderAt("#/unlock");
    await screen.findByTestId("unlock-table-global");
    await userEvent.click(screen.getByRole("button", { name: "确认 Netflix → 香港 IX" }));
    await waitFor(() => expect(api.find("POST /api/unlock/adopt")).toHaveLength(2));
    // Nothing else moves: no confirm step, no extra text.
    expect(screen.queryByText(/同时影响/)).toBeNull();
    expect(api.find("POST /api/unlock/adopt")[1].body).toEqual({ service: "auto-netflix", exit: "hk-ix" });
    const line = await screen.findByTestId("rules-apply-line");
    expect(line).toHaveTextContent("未自动生效：地区组也改了");
    expect(within(line).getByRole("link", { name: "去部署" })).toBeInTheDocument();
    await waitFor(() => expect(within(screen.getByTestId("row-global-auto-netflix")).getByText("在用")).toBeInTheDocument());
    expect(screen.queryByRole("button", { name: /^确认 / })).toBeNull();
  });

  it("asks to confirm when other rules move with the group, and applies on the second click", async () => {
    const api = fakeApi({
      ...base(),
      "GET /api/unlock/matrix": () => matrix(false),
      "POST /api/unlock/adopt": (req) =>
        (req.body as { preview?: boolean }).preview
          ? { preview: true, group: "hk", exit: "hk-ix", service_rules: ["auto-netflix"], other_rules: 4 }
          : { updated: 1, group: "hk", exit: "hk-ix", apply_required: true },
    });
    renderAt("#/unlock");
    await screen.findByTestId("unlock-table-global");
    await userEvent.click(screen.getByRole("button", { name: "确认 Netflix → 香港 IX" }));
    const box = await screen.findByTestId("adopt-confirm-auto-netflix");
    expect(box).toHaveTextContent("同时影响 4 条规则");
    expect(api.find("POST /api/unlock/adopt")).toHaveLength(1);
    await userEvent.click(within(box).getByRole("button", { name: "确认采用 Netflix → 香港 IX" }));
    await waitFor(() => expect(api.find("POST /api/unlock/adopt")).toHaveLength(2));
    expect(api.find("POST /api/unlock/adopt")[1].body).toEqual({ service: "auto-netflix", exit: "hk-ix" });
  });
});

describe("unlock: evidence and Hong Kong services", () => {
  const cell = (exit_id: string, state: UnlockCellState, extra: Record<string, unknown> = {}) => ({ exit_id, state, ...extra });
  const hkExit = { id: "hk-2", name: "香港 2", regions: ["hk"], groups: ["hk"] };
  const view = (hk: UnlockMatrixView["regions"][number]["services"], global: UnlockMatrixView["regions"][number]["services"] = []): UnlockMatrixView => ({
    running: "",
    available: true,
    regions: [
      { code: "global", name: "全球", exits: [hkExit], services: global },
      { code: "hk", name: "香港", exits: [hkExit], services: hk },
    ],
  });
  const mytv = (adopted = false) => ({
    id: "auto-mytvsuper",
    name: "MyTV SUPER",
    rules: ["auto-mytvsuper"],
    targets: ["hk"],
    cells: [cell("hk-2", "unlocked", { region: "hk" })],
    recommend: { exit_id: "hk-2", exit_name: "香港 2", group: "hk", group_name: "香港", adopted },
  });
  const base = (m: () => UnlockMatrixView) => ({
    "GET /api/topology": () => topology(),
    "GET /api/status": () => panelStatus({ ...OK_AGENT, probe_available: true }),
    "GET /api/unlock/matrix": m,
  });

  it("shows MyTV SUPER and Viu as separate Hong Kong rows; an undecidable Viu is only 未测到", async () => {
    fakeApi(
      base(() =>
        view([
          mytv(),
          { id: "auto-viu", name: "Viu", rules: ["u-viu"], targets: [], cells: [cell("hk-2", "unverified", { reason: "Viu：应答无法识别" })], recommend: null },
        ]),
      ),
    );
    renderAt("#/unlock");
    const hk = await screen.findByTestId("unlock-table-hk");
    expect(within(within(hk).getByTestId("row-hk-auto-mytvsuper")).getByTestId("cell-hk-2")).toHaveTextContent("解锁HK");
    const viu = within(hk).getByTestId("row-hk-auto-viu");
    expect(within(viu).getByTestId("cell-hk-2")).toHaveTextContent(/^未测到$/);
    expect(within(viu).queryByRole("button", { name: /^确认 / })).toBeNull();
    expect(within(hk).getAllByRole("button", { name: /^确认 / })).toHaveLength(1);
  });

  it("shows a result of a changed exit as 未测 with no recommendation", async () => {
    fakeApi(base(() => view([{ id: "auto-mytvsuper", name: "MyTV SUPER", rules: ["auto-mytvsuper"], targets: ["hk"], cells: [cell("hk-2", "untested")], recommend: null }])));
    renderAt("#/unlock");
    const hk = await screen.findByTestId("unlock-table-hk");
    const row = within(hk).getByTestId("row-hk-auto-mytvsuper");
    expect(within(row).getByTestId("cell-hk-2")).toHaveTextContent(/^未测$/);
    expect(within(row).queryByRole("button", { name: /^确认 / })).toBeNull();
    expect(within(row).queryByText("在用")).toBeNull();
  });

  it("a refused adoption (409) shows the server's error and never 在用", async () => {
    const api = fakeApi({
      ...base(() => view([mytv(false)])),
      "POST /api/unlock/adopt": (req) =>
        (req.body as { preview?: boolean }).preview
          ? { preview: true, group: "hk", exit: "hk-2", service_rules: ["auto-mytvsuper"], other_rules: 0 }
          : reply(409, { error: "探测结果已变化，推荐出口不再是这个；刷新后再采用" }),
    });
    renderAt("#/unlock");
    await screen.findByTestId("unlock-table-hk");
    await userEvent.click(screen.getByRole("button", { name: "确认 MyTV SUPER → 香港 2" }));
    await waitFor(() => expect(api.find("POST /api/unlock/adopt")).toHaveLength(2));
    expect(await screen.findByText(/探测结果已变化/)).toBeInTheDocument();
    expect(within(screen.getByTestId("row-hk-auto-mytvsuper")).queryByText("在用")).toBeNull();
    expect(screen.queryByTestId("rules-apply-line")).toBeNull();
  });
});

describe("leak check", () => {
  it("never renders an integration or human item as passed, whatever the API says", async () => {
    fakeApi({
      "GET /api/leakcheck": () => ({
        items: [
          { id: "dns_guard", status: "pass", scope: "automated", title: "DNS 兜底", detail: "配置里有" },
          { id: "netns_reload_no_leak", status: "pass", scope: "integration", title: "重载不泄露", detail: "netns" },
          { id: "tunnel_cut", status: "pass", scope: "human", title: "断隧道", detail: "人工" },
          { id: "remote_phone_full", status: "pass", scope: "human", title: "手机蜂窝网络拨入", detail: "人工" },
          { id: "lists_update_runtime", status: "pass", scope: "integration", title: "名单更新", detail: "网关" },
          { id: "webrtc_host_gua", status: "known_limitation", scope: "limitation", title: "WebRTC", detail: "限制" },
        ],
      }),
    });
    renderAt("#/");
    await userEvent.click(await screen.findByTestId("leak-status-line"));
    const integ = await screen.findByTestId("leak-item-netns_reload_no_leak");
    expect(integ).toHaveTextContent("未执行");
    const human = screen.getByTestId("leak-item-tunnel_cut");
    expect(human).toHaveTextContent("待人工签收");
    const phone = screen.getByTestId("leak-item-remote_phone_full");
    expect(phone).toHaveTextContent("待人工签收");
    const lists = screen.getByTestId("leak-item-lists_update_runtime");
    expect(lists).toHaveTextContent("未执行");
    for (const row of [integ, human, phone, lists]) {
      expect(row.querySelector('[data-status="ok"]')).toBeNull();
      expect(row).not.toHaveTextContent(/通过|配置包含|正常/);
    }
    const auto = screen.getByTestId("leak-item-dns_guard");
    expect(auto).toHaveTextContent("配置包含");
    expect(auto.querySelector('[data-status="ok"]')).toBeNull();
    expect(screen.getByTestId("leak-status-line")).toHaveTextContent("防泄露 正常");
  });
});

describe("tables at narrow widths", () => {
  it("render inside a horizontally scrollable box, with explicit column widths and a fixed action column", async () => {
    fakeApi({ "GET /api/servers": () => ({ servers: [server({ name: "一台名字很长很长的香港机房服务器" })] }) });
    renderAt("#/servers");
    const row = await screen.findByTestId("server-row-srv-1");
    const table = row.closest("table")!;
    // DataTable: as wide as the sum of the declared column widths (not max-content), scrolling in its own box.
    expect(table.style.width).not.toBe("max-content");
    expect(row.closest(".ant-table-content, .ant-table-body")).not.toBeNull();
    expect(row.closest(".data-table-wrap")).not.toBeNull();
    expect(row.querySelector("td.col-flex")).toHaveTextContent("一台名字很长很长的香港机房服务器");
    expect(row.querySelector("td.col-actions.ant-table-cell-fix-right")).not.toBeNull();
  });
});

describe("leak check: endpoint access", () => {
  it("shows the endpoint-access policy as one line when the API reports it, nothing otherwise", async () => {
    fakeApi({ "GET /api/leakcheck": () => ({ items: [], endpoint_access: { domestic: "direct", overseas: "default_group" } }) });
    renderAt("#/");
    await userEvent.click(await screen.findByTestId("leak-status-line"));
    expect(await screen.findByTestId("leak-endpoint-access")).toHaveTextContent("局域网到隧道端点：国内直连 · 境外经默认出口");
  });

  it("renders the status counts shape, with blocked count and reasons only when present", async () => {
    fakeApi({
      "GET /api/leakcheck": () => ({
        items: [],
        endpoint_access: {
          direct: 2,
          tunnel: 3,
          blocked: 1,
          items: [{ addr: "2001:db8::70", family: 6, node_id: "v6", node_name: "纯 IPv6 出口", class: "blocked", reason: "默认组不承载 IPv6" }],
        },
      }),
    });
    renderAt("#/");
    await userEvent.click(await screen.findByTestId("leak-status-line"));
    const row = await screen.findByTestId("leak-endpoint-access");
    expect(row).toHaveTextContent("局域网到隧道端点：国内直连 2 · 境外经默认出口 3 · 拦截 1");
    expect(row.getAttribute("title")).toContain("默认组不承载 IPv6");
    expect(row).not.toHaveTextContent("默认组不承载 IPv6");
    expect(endpointAccessText({ direct: 1, tunnel: 4, blocked: 0, items: [] })).toBe("国内直连 1 · 境外经默认出口 4");
  });

  it("renders no endpoint-access line without the field", async () => {
    fakeApi({ "GET /api/leakcheck": () => ({ items: [{ id: "a", status: "pass", scope: "automated", title: "x", detail: "y" }] }) });
    renderAt("#/");
    await userEvent.click(await screen.findByTestId("leak-status-line"));
    await screen.findByTestId("leak-item-a");
    expect(screen.queryByTestId("leak-endpoint-access")).toBeNull();
  });
});
