// Interaction tests for the rebuilt operational pages against the in-memory
// fake API: region groups (order, reasons, manual choice, live state,
// refused delete), rules (one target, no mode), topology (server instead of
// ssh_*), remote access (the one-time configuration and the runtime
// states), deploy (failed and refused installs, rollback choices), unlock
// (reachability is never an unlock, the validation notice, batch by group),
// leak (nothing in the integration or human groups ever passes) and the
// unsaved-changes guard.

import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { fakeApi, panelStatus, renderAt, reply, webStorageDump } from "./testing";
import type {
  GroupMemberView,
  Node,
  ProbeCatalogEntry,
  ProbeResultRow,
  RegionGroupView,
  RemoteAccessView,
  RemoteDeviceView,
  Rule,
  ServerView,
  Topology,
} from "./types";

const NOW = "2026-11-12T10:00:00Z";

function btn(text: string) {
  return new RegExp(`^\\s*${text.split("").join("\\s*")}\\s*$`);
}

async function confirmModal(okText: string) {
  const box = await waitFor(() => {
    const el = document.querySelector<HTMLElement>(".ant-modal-confirm");
    if (!el) throw new Error("no confirm dialog");
    return el;
  });
  await userEvent.click(within(box).getByRole("button", { name: btn(okText) }));
}

/** Opens an antd Select (by its aria-label) and clicks the option with this text. */
async function pick(label: string, option: string | RegExp, scope: HTMLElement = document.body) {
  const box = within(scope).getByRole("combobox", { name: label });
  fireEvent.mouseDown(box);
  const opt = await waitFor(() => {
    const els = [...document.querySelectorAll<HTMLElement>(".ant-select-dropdown:not(.ant-select-dropdown-hidden) .ant-select-item-option")];
    const hit = els.find((e) => (typeof option === "string" ? e.textContent?.includes(option) : option.test(e.textContent ?? "")));
    if (!hit) throw new Error(`no option ${option}`);
    return hit;
  });
  fireEvent.click(opt);
}

// ------------------------------------------------------------ fixtures ---

function exitNode(id: string, name: string, over: Partial<Node> = {}): Node {
  return {
    id,
    name,
    role: "exit",
    region: "hk",
    managed: true,
    path_v4: true,
    path_v6: true,
    egress_v4: true,
    egress_v6: true,
    nat_dial_out: false,
    residential: false,
    ix_bound: false,
    ...over,
  };
}

function topology(over: Partial<Topology> = {}): Topology {
  return {
    settings: {
      draft: false,
      ix_replacement_mode: false,
      lan_interface: "eth0",
      gateway_lan_ipv4: "192.168.100.88/24",
      ros_ipv4: "192.168.100.1",
      ros_v6_lla: "fe80::1",
      lan_ipv6_prefix: "2001:db8:100::/64",
      ula_prefix: "fd66::/48",
      panel_bind: "192.168.100.88:8787",
      domestic_dot: [],
      transit_v4_prefix: "10.66.200.0/24",
      transit_v6_prefix: "fd66:0:0:ff::/64",
      default_group: "hk",
    },
    nodes: [
      { ...exitNode("gw", "家宽网关", { role: "gateway", region: "cn" }) },
      { ...exitNode("hk-hub", "香港枢纽", { role: "hub" }) },
      exitNode("hk-ix", "香港 IX", { ix_bound: true }),
      exitNode("hk-2", "香港二号"),
      exitNode("hk-resi", "香港家宽", { residential: true }),
      exitNode("us", "美国", { region: "us" }),
    ],
    links: [],
    rules: [
      {
        id: "auto-netflix",
        name: "Netflix",
        manual: false,
        priority: 200,
        enabled: true,
        overridden: false,
        match_type: "geosite",
        match_value: "netflix",
        geosite: "netflix",
        target_group: "hk",
        require_residential: false,
        require_v6: false,
      },
    ],
    region_groups: [{ id: "hk", name: "香港（机房）", region: "hk", members: ["hk-2", "hk-ix", "hk-resi"], mode: "auto", exclude_residential: true }],
    ...over,
  };
}

function member(id: string, name: string, over: Partial<GroupMemberView> = {}): GroupMemberView {
  return {
    id,
    name,
    region: "hk",
    user_position: 0,
    position: 0,
    eligible: true,
    ix_bound: false,
    residential: false,
    egress_v6: true,
    reasons: [],
    target: false,
    active: false,
    health: null,
    ...over,
  };
}

function group(over: Partial<RegionGroupView> = {}): RegionGroupView {
  return {
    id: "hk",
    name: "香港（机房）",
    region: "hk",
    members: ["hk-2", "hk-ix", "hk-resi"],
    mode: "auto",
    exclude_residential: true,
    is_default: true,
    effective_order: ["hk-ix", "hk-2"],
    target: "hk-ix",
    target_reason: "preferred",
    switchable: true,
    switch_order: ["hk-ix", "hk-2"],
    mesh_backup: false,
    member_status: [
      member("hk-2", "香港二号", { user_position: 0, position: 1, reasons: [{ code: "after_ix", message: "前面插入了 IX 绑定的出口，位置后移。" }] }),
      member("hk-ix", "香港 IX", { user_position: 1, position: 0, ix_bound: true, target: true, active: true, reasons: [{ code: "ix_first", message: "IX 绑定的出口排在用户顺序之前。" }] }),
      member("hk-resi", "香港家宽", { user_position: 2, position: -1, eligible: false, residential: true, reasons: [{ code: "residential_excluded", message: "组排除家宽，这个出口是家宽。" }] }),
    ],
    state: { active: "hk-ix", reason: "preferred", alert: false, last_switch: null, observed: false, source: "panel_model" },
    in_use_by: [
      { kind: "settings", id: "default_group", name: "默认境外组" },
      { kind: "rule", id: "auto-netflix", name: "Netflix" },
    ],
    ...over,
  };
}

const THRESHOLDS = { fails_need: 3, recovers_need: 3, cooldown_sec: 1800 };

// -------------------------------------------------------- region groups ---

describe("region groups", () => {
  it("reorders members locally and saves the whole order with one PATCH", async () => {
    let g = group();
    const api = fakeApi({
      "GET /api/topology": () => topology(),
      "GET /api/region-groups": () => ({ groups: [g], default_group: "hk", thresholds: THRESHOLDS }),
      "PATCH /api/region-groups/:id": (req) => {
        g = group({ members: (req.body as { members: string[] }).members });
        return { group: g, apply_required: true };
      },
    });
    renderAt("#/exits");
    const card = await screen.findByTestId("group-hk");
    // Move 香港二号 (user position 1) down twice: hk-ix, hk-resi, hk-2.
    await userEvent.click(within(card).getByRole("button", { name: "下移 香港二号" }));
    await userEvent.click(within(card).getByRole("button", { name: "下移 香港二号" }));
    expect(api.find("PATCH /api/region-groups/hk")).toHaveLength(0);
    await userEvent.click(within(card).getByRole("button", { name: btn("保存顺序") }));
    await waitFor(() => expect(api.find("PATCH /api/region-groups/hk")).toHaveLength(1));
    expect(api.find("PATCH /api/region-groups/hk")[0].body).toEqual({ members: ["hk-ix", "hk-resi", "hk-2"] });
    // Document-only change: the page and the top bar say an install is needed.
    expect(await screen.findByText(/地区组已修改，但还没有安装到网关/)).toBeInTheDocument();
  });

  it("explains the effective order and exclusions in plain words", async () => {
    fakeApi({
      "GET /api/topology": () => topology(),
      "GET /api/region-groups": () => ({ groups: [group()], default_group: "hk", thresholds: THRESHOLDS }),
    });
    renderAt("#/exits");
    const card = await screen.findByTestId("group-hk");
    expect(within(card).getByText("IX 绑定的出口排在用户顺序之前。")).toBeInTheDocument();
    expect(within(card).getByText("组排除家宽，这个出口是家宽。")).toBeInTheDocument();
    expect(within(screen.getByTestId("member-hk-hk-resi")).getByText("已排除")).toBeInTheDocument();
    expect(within(card).getByTestId("effective-order")).toHaveTextContent("香港 IX → 香港二号");
    expect(within(card).getByText("默认组")).toBeInTheDocument();
  });

  it("switches to manual with a choice, then changes the choice and the on-failure behaviour", async () => {
    let g = group();
    const api = fakeApi({
      "GET /api/topology": () => topology(),
      "GET /api/region-groups": () => ({ groups: [g], default_group: "hk", thresholds: THRESHOLDS }),
      "PATCH /api/region-groups/:id": (req) => {
        const b = req.body as Partial<RegionGroupView>;
        g = group({ ...g, ...b, on_failure_effective: b.on_failure ?? g.on_failure_effective, state: { ...g.state, reason: "chosen", active: b.chosen ?? g.chosen ?? "hk-ix" } });
        return { group: g, apply_required: true };
      },
    });
    renderAt("#/exits");
    const card = await screen.findByTestId("group-hk");
    fireEvent.click(within(card).getByRole("radio", { name: "手动" }));
    await waitFor(() => expect(api.find("PATCH /api/region-groups/hk")).toHaveLength(1));
    expect(api.find("PATCH /api/region-groups/hk")[0].body).toEqual({ mode: "manual", chosen: "hk-ix", on_failure: "hold" });

    // Both on-failure options are explained.
    await within(card).findByText("保持并告警");
    expect(card).toHaveTextContent("临时改用组里下一个可用成员");
    await pick("香港（机房） 的指定成员", "香港二号", card);
    await waitFor(() => expect(api.find("PATCH /api/region-groups/hk")).toHaveLength(2));
    expect(api.find("PATCH /api/region-groups/hk")[1].body).toEqual({ chosen: "hk-2" });

    await userEvent.click(within(card).getByRole("radio", { name: /临时回落并告警/ }));
    await waitFor(() => expect(api.find("PATCH /api/region-groups/hk")).toHaveLength(3));
    expect(api.find("PATCH /api/region-groups/hk")[2].body).toEqual({ on_failure: "fallback" });
    // Excluded members cannot be chosen.
    fireEvent.mouseDown(within(card).getByRole("combobox", { name: "香港（机房） 的指定成员" }));
    const resi = await waitFor(() => {
      const el = [...document.querySelectorAll(".ant-select-item-option")].find((e) => e.textContent?.includes("香港家宽"));
      if (!el) throw new Error("missing");
      return el;
    });
    expect(resi).toHaveClass("ant-select-item-option-disabled");
  });

  it("labels the live state as the panel's model, unverified without samples, and shows an alert", async () => {
    const alerting = group({
      id: "us",
      name: "美国",
      region: "us",
      members: ["us"],
      member_status: [member("us", "美国", { region: "us", target: true, health: { up: false, fails: 3, goods: 0, last_ok: false, ok_since: null, last_at: NOW } })],
      effective_order: ["us"],
      target: "us",
      is_default: false,
      in_use_by: [],
      state: {
        active: "",
        reason: "none",
        alert: true,
        alert_message: "组内没有可用的出口，引用它的规则不会生效。",
        last_switch: NOW,
        observed: true,
        source: "panel_model",
      },
    });
    fakeApi({
      "GET /api/topology": () => topology(),
      "GET /api/region-groups": () => ({ groups: [group(), alerting], default_group: "hk", thresholds: THRESHOLDS }),
    });
    renderAt("#/exits");
    const hk = await screen.findByTestId("group-hk");
    const hkLive = within(hk).getByTestId("group-live");
    expect(hkLive).toHaveTextContent("按配置应使用");
    expect(hkLive.querySelector('[data-status="unverified"]')).toHaveTextContent("未验证");

    const us = screen.getByTestId("group-us");
    const usLive = within(us).getByTestId("group-live");
    expect(usLive).toHaveTextContent("实际使用");
    expect(usLive).toHaveTextContent("面板推算");
    expect(within(us).getByTestId("group-alert")).toHaveTextContent("组内没有可用的出口");
    expect(within(screen.getByTestId("member-us-us")).getByText("不可用")).toBeInTheDocument();
  });

  it("refuses a delete with the referrers as links", async () => {
    fakeApi({
      "GET /api/topology": () => topology(),
      "GET /api/region-groups": () => ({ groups: [group()], default_group: "hk", thresholds: THRESHOLDS }),
      "DELETE /api/region-groups/:id": () =>
        reply(409, {
          error: "地区组 香港（机房） 仍被 2 处引用（规则或默认境外组），先改掉这些引用",
          code: "in_use",
          in_use_by: [
            { kind: "settings", id: "default_group", name: "默认境外组" },
            { kind: "rule", id: "auto-netflix", name: "Netflix" },
          ],
        }),
    });
    renderAt("#/exits");
    const card = await screen.findByTestId("group-hk");
    await userEvent.click(within(card).getByRole("button", { name: /删除/ }));
    await confirmModal("删除");
    const refused = await screen.findByTestId("refused-dialog");
    expect(refused).toHaveTextContent("先改掉这些引用");
    expect(within(refused).getByRole("link", { name: "Netflix" })).toHaveAttribute("href", "#/rules/auto-netflix");
    expect(within(refused).getByRole("link", { name: "默认境外组" })).toHaveAttribute("href", "#/exits");
  });

  it("lists exits that belong to no group", async () => {
    fakeApi({
      "GET /api/topology": () => topology(),
      "GET /api/region-groups": () => ({ groups: [group()], default_group: "hk", thresholds: THRESHOLDS }),
    });
    renderAt("#/exits");
    const box = await screen.findByTestId("ungrouped");
    expect(box).toHaveTextContent("美国");
    expect(box).not.toHaveTextContent("香港二号");
  });
});

// ---------------------------------------------------------------- rules ---

describe("rules", () => {
  it("adds a rule with exactly one target and no mode, then saves the document", async () => {
    let saved: Topology | null = null;
    const api = fakeApi({
      "GET /api/topology": () => topology(),
      "POST /api/validate": () => ({ issues: [], paths: [] }),
      "PUT /api/topology": (req) => {
        saved = req.body as Topology;
        return { topology: saved, issues: [], paths: [], draft: false };
      },
    });
    renderAt("#/rules");
    await userEvent.click(await screen.findByRole("button", { name: /添加规则/ }));
    const drawer = await screen.findByRole("dialog");
    await userEvent.type(within(drawer).getByLabelText("名称"), "公司 API");
    await userEvent.type(within(drawer).getByLabelText("匹配值"), "api.example.com");
    // The target is an explicit two-way choice; switching behaviour is the group's.
    expect(drawer).toHaveTextContent("切换方式（自动 / 手动、失败时怎么办）在 地区组 上设置");
    await userEvent.click(within(drawer).getByRole("radio", { name: /固定出口/ }));
    await pick("出口", "美国", drawer);
    await userEvent.click(within(drawer).getByRole("button", { name: btn("添加") }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(api.find("POST /api/validate")).toHaveLength(1);

    await userEvent.click(screen.getByRole("button", { name: btn("保存") }));
    await waitFor(() => expect(api.find("PUT /api/topology")).toHaveLength(1));
    const rule = saved!.rules.find((r: Rule) => r.name === "公司 API")!;
    expect(rule.target_exit).toBe("us");
    expect(rule).not.toHaveProperty("target_group");
    expect(rule.domains).toEqual(["api.example.com"]);
    for (const r of saved!.rules) {
      expect(r).not.toHaveProperty("mode");
      expect(r).not.toHaveProperty("target_pool");
      expect(!!r.target_group !== !!r.target_exit).toBe(true);
    }
  });

  it("puts a requirement mismatch from validation on the field and keeps the drawer open", async () => {
    fakeApi({
      "GET /api/topology": () => topology(),
      "POST /api/validate": (req) => {
        const t = req.body as Topology;
        const r = t.rules.find((x) => x.name === "Disney+")!;
        return {
          issues: [
            {
              code: "residential_required",
              severity: "error",
              rule_id: r.id,
              group_id: "hk",
              field: "require_residential",
              message: "规则「Disney+」要求家宽，但组 香港（机房） 没有 require_residential。",
            },
          ],
          paths: [],
        };
      },
    });
    renderAt("#/rules");
    await userEvent.click(await screen.findByRole("button", { name: /添加规则/ }));
    const drawer = await screen.findByRole("dialog");
    await userEvent.type(within(drawer).getByLabelText("名称"), "Disney+");
    await userEvent.type(within(drawer).getByLabelText("匹配值"), "disneyplus.com");
    await userEvent.click(within(drawer).getByRole("checkbox", { name: /必须走住宅/ }));
    await userEvent.click(within(drawer).getByRole("button", { name: btn("添加") }));
    expect(await within(drawer).findByText(/要求家宽，但组 香港（机房） 没有 require_residential/)).toBeInTheDocument();
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    expect(within(drawer).getByRole("button", { name: /仍然放入/ })).toBeInTheDocument();
  });
});

// ------------------------------------------------------- unsaved guard ---

describe("unsaved-changes guard", () => {
  it("asks before leaving the rules page with unsaved edits", async () => {
    fakeApi({ "GET /api/topology": () => topology() });
    renderAt("#/rules");
    await userEvent.click(await screen.findByRole("switch", { name: "启用 Netflix" }));
    expect(await screen.findByText("有未保存的修改")).toBeInTheDocument();
    await userEvent.click(screen.getAllByRole("menuitem").find((m) => m.textContent?.includes("出口"))!);
    const box = await waitFor(() => {
      const el = document.querySelector<HTMLElement>(".ant-modal-confirm");
      if (!el) throw new Error("no guard");
      return el;
    });
    expect(box).toHaveTextContent("离开这个页面？");
    expect(window.location.hash).toBe("#/rules");
    await userEvent.click(within(box).getByRole("button", { name: btn("留在这里") }));
    expect(window.location.hash).toBe("#/rules");
  });
});

// ------------------------------------------------------------- topology ---

function server(over: Partial<ServerView> = {}): ServerView {
  return {
    id: "srv-1",
    name: "香港机房",
    address: "192.0.2.10",
    port: 22,
    user: "root",
    auth: "key",
    credential: null,
    host_key: { state: "trusted", fingerprint: "SHA256:x" },
    created_at: NOW,
    updated_at: NOW,
    operable: true,
    ready: true,
    missing: [],
    in_use_by: [],
    node: null,
    ...over,
  };
}

describe("topology", () => {
  it("lets a node pick a managed server and sends no ssh_* fields", async () => {
    let saved: string | undefined;
    const t = topology();
    // A pre-server node still carrying the old SSH target.
    t.nodes = t.nodes.map((n) => (n.id === "hk-hub" ? { ...n, ssh_host: "192.0.2.10", ssh_user: "root", ssh_port: 22 } : n));
    const api = fakeApi({
      "GET /api/topology": () => t,
      "GET /api/servers": () => ({ servers: [server(), server({ id: "srv-2", name: "备用机", address: "192.0.2.11", ready: false, missing: ["connection_test"] })] }),
      "PUT /api/topology": (req) => {
        saved = req.raw;
        return { topology: req.body, issues: [], paths: [], draft: false };
      },
    });
    renderAt("#/topology/hk-hub");
    const detail = await screen.findByTestId("node-detail");
    expect(within(detail).queryByLabelText(/SSH 主机/)).toBeNull();
    expect(detail).toHaveTextContent("旧的 SSH 地址");
    await pick("服务器", "香港机房", detail);
    await within(detail).findByRole("link", { name: "打开服务器" });
    await userEvent.click(screen.getByRole("button", { name: btn("保存") }));
    await waitFor(() => expect(api.find("PUT /api/topology")).toHaveLength(1));
    const body = JSON.parse(saved!) as Topology;
    const hub = body.nodes.find((n) => n.id === "hk-hub")!;
    expect(hub.server_id).toBe("srv-1");
    expect(saved).not.toMatch(/"ssh_(host|port|user)"/);
    expect(saved).not.toMatch(/"pool(_priority)?"/);
  });
});

// -------------------------------------------------------- remote access ---

const PRIVATE = "TESTPRIVATEKEYdoNotKeep0000000000000000000=";
const PSK = "TESTPSKdoNotKeep1111111111111111111111111=";

function device(over: Partial<RemoteDeviceView> = {}): RemoteDeviceView {
  return {
    id: "dev-1",
    name: "我的手机",
    notes: "",
    mode: "full",
    enabled: true,
    public_key: "PUBLICKEYdev1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=",
    ipv4: "10.66.250.2/32",
    ipv6: "fd66:0:0:fa::2/128",
    preshared_key: true,
    created_at: NOW,
    updated_at: NOW,
    key_created_at: NOW,
    config_available: false,
    config_outdated: false,
    runtime: null,
    runtime_state: "not_installed",
    ...over,
  };
}

function remoteView(devices: RemoteDeviceView[], runtime: RemoteAccessView["runtime"] = { available: true, state: "ok", interface: "mra", read_at: NOW }): RemoteAccessView {
  return {
    settings: {
      enabled: true,
      endpoint: "home.example.net",
      listen_port: 51888,
      ipv4_prefix: "10.66.250.0/24",
      ipv6_prefix: "fd66:0:0:fa::/64",
      mtu: 1380,
      keepalive: 25,
      interface: "mra",
      gateway_ipv4: "10.66.250.1",
      gateway_ipv6: "fd66:0:0:fa::1",
      dns: ["10.66.250.1"],
      public_key: "GWPUBLICKEYaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=",
      max_devices: 32,
      device_count: devices.length,
      defaults: { ipv4_prefix: "10.66.250.0/24", ipv6_prefix: "fd66:0:0:fa::/64", mtu: 1380, keepalive: 25, mode: "full" },
      modes: { full: "全隧道模式：全部流量和 DNS 进隧道。", home: "仅家网模式：手机访问公网仍走它当前的网络，部分 DNS 可能仍走当前网络。" },
    },
    router_forward: {
      protocol: "udp",
      external_port: 51888,
      internal_address: "192.168.100.88",
      internal_port: 51888,
      description: "在家里的路由器上添加端口转发（dst-nat）。面板不会修改路由器。",
      ipv6_note: "IPv6 防火墙还要放行。",
    },
    devices,
    runtime,
    issues: [],
  };
}

function configText(name: string) {
  return `[Interface]\n# ${name}\nPrivateKey = ${PRIVATE}\nAddress = 10.66.250.2/32, fd66:0:0:fa::2/128\nDNS = 10.66.250.1\n\n[Peer]\nPublicKey = GWPUBLICKEYaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=\nPresharedKey = ${PSK}\nEndpoint = home.example.net:51888\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n`;
}

describe("remote access", () => {
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

    await userEvent.click(within(screen.getByTestId("device-row-dev-1")).getByRole("button", { name: /删除/ }));
    await waitFor(() => expect(document.querySelector(".ant-modal-confirm")).toHaveTextContent("设备上的配置作废"));
    await confirmModal("删除");
    await waitFor(() => expect(api.find("DELETE /api/remote-access/devices/dev-1")).toHaveLength(1));
    await waitFor(() => expect(screen.queryByTestId("device-row-dev-1")).toBeNull());
    expect(await screen.findByText(/远程接入已修改，但还没有安装到网关/)).toBeInTheDocument();
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
    expect(fwd).toHaveTextContent("192.168.100.88");
    expect(fwd).toHaveTextContent("51888");
    expect(screen.getByText("面板无法验证")).toBeInTheDocument();
  });
});

// --------------------------------------------------------------- deploy ---

const OK_AGENT = { agent: { configured: true, ok: true } };

describe("deploy", () => {
  const changed = () => panelStatus({ ...OK_AGENT, installOver: { state: "changed", installed_version: 3, applied: true, applied_matches: false } });
  const host = (installed: boolean) => ({
    installed: installed ? { version: 3, files: 10, interfaces: ["m1"], units: ["meridian.service"], nft_tables: ["inet meridian"], route_tables: [100], dns: true } : null,
    pending: null,
    agent: { ok: true },
  });

  it("shows the failing step and that the install was compensated", async () => {
    fakeApi({
      "GET /api/status": changed,
      "GET /api/host": () => host(true),
      "POST /api/diff": () => ({ diff: "===== nodes/gw/etc/meridian/meridian.nft (changed) =====\n table\n-old\n+new\n", order: [], issues: [] }),
      "POST /api/apply": () =>
        reply(500, {
          error: "安装失败，已补偿回到事务前的状态：宿主动作 activate 失败：start meridian.service",
          compensated: true,
          host: {
            transaction: "txn-1",
            kind: "apply",
            from_version: 3,
            to_version: 4,
            diff: { files_changed: ["etc/meridian/meridian.nft"] },
            steps: [
              { name: "daemon-reload", ok: true },
              { name: "start meridian.service", ok: false, detail: "Job for meridian.service failed" },
            ],
            committed: false,
            compensated: true,
          },
        }),
    });
    renderAt("#/deploy");
    expect(await screen.findByTestId("pending-diff")).toHaveTextContent("1 个文件");
    await userEvent.click(await screen.findByRole("button", { name: /安装到网关/ }));
    await confirmModal("安装");
    const failed = await screen.findByTestId("txn-failed");
    expect(failed).toHaveTextContent("安装失败，已补偿回安装前的状态");
    const step = failed.querySelector('[data-step-status="failed"]')!;
    expect(step).toHaveTextContent("start meridian.service");
    expect(step).toHaveTextContent("从这一步开始失败");
    expect(failed).toHaveTextContent("已补偿回安装前");
    expect(screen.queryByText(/已安装：服务已启动/)).toBeNull();
  });

  it("explains refusals: no host agent, missing peer keys, a legacy install", async () => {
    const api = fakeApi({
      "GET /api/topology": () => topology(),
      "GET /api/status": changed,
      "GET /api/host": () => host(true),
      "POST /api/apply": () => reply(503, { error: "面板没有宿主执行能力：……未写入任何宿主文件" }),
    });
    renderAt("#/deploy");
    const install = async () => {
      await userEvent.click(await screen.findByRole("button", { name: /安装到网关/ }));
      await confirmModal("安装");
    };
    await install();
    expect(await screen.findByTestId("txn-refused")).toHaveTextContent("没有宿主执行通道，什么都没改");

    api.on("POST /api/apply", () =>
      reply(422, { error: "拒绝安装", peer_key_problems: [{ peer: "hk-hub", problem: "missing" }, { peer: "hk-ix", problem: "placeholder" }] }),
    );
    await install();
    await waitFor(() => expect(screen.getByTestId("txn-refused")).toHaveTextContent("这些对端节点还没有可用的公钥"));
    expect(within(screen.getByTestId("txn-refused")).getByRole("link", { name: "香港枢纽" })).toHaveAttribute("href", "#/topology/hk-hub");

    api.on("POST /api/apply", () => reply(409, { error: "宿主上有旧版 Meridian 数据面（没有受管清单），无法可靠接管；已停止" }));
    await install();
    await waitFor(() => expect(screen.getByTestId("txn-refused")).toHaveTextContent("无法可靠接管"));
  });

  it("offers runtime rollback when installed and snapshot-only only when nothing is installed", async () => {
    const api = fakeApi({
      "GET /api/status": changed,
      "GET /api/host": () => host(true),
      "POST /api/rollback": () => ({ status: "rolled_back", mode: "runtime", host: null }),
    });
    renderAt("#/deploy");
    const runtime = await screen.findByRole("radio", { name: /回滚网关（含宿主网络）/ });
    const snapshot = screen.getByRole("radio", { name: /只回滚数据目录快照/ });
    await waitFor(() => expect(runtime).toBeChecked());
    expect(snapshot).toBeDisabled();
    await userEvent.click(screen.getByRole("button", { name: /回滚/ }));
    await confirmModal("回滚");
    await waitFor(() => expect(api.find("POST /api/rollback")).toHaveLength(1));
    expect(api.find("POST /api/rollback")[0].body).toEqual({ install: true });
  });

  it("uses snapshot-only rollback when nothing is installed and blocks install while the topology does not compile", async () => {
    const api = fakeApi({
      "GET /api/status": () =>
        panelStatus({
          ...OK_AGENT,
          installOver: {
            state: "invalid",
            error: "拓扑校验未通过",
            issues: [{ code: "lan_interface_mismatch", severity: "error", node_id: "gw", message: "网关节点的 lan_interface 和 settings 不一致。" }],
          },
        }),
      "GET /api/host": () => host(false),
      "POST /api/rollback": () => ({ status: "rolled_back", mode: "snapshot" }),
    });
    renderAt("#/deploy");
    expect(await screen.findByText("拓扑现在无法编译，不能安装")).toBeInTheDocument();
    expect(screen.getByText("网关的局域网接口不一致")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /安装到网关/ })).toBeDisabled();
    const snapshot = await screen.findByRole("radio", { name: /只回滚数据目录快照/ });
    await waitFor(() => expect(snapshot).toBeEnabled());
    await userEvent.click(snapshot);
    await userEvent.click(screen.getByRole("button", { name: /回滚/ }));
    await confirmModal("回滚");
    await waitFor(() => expect(api.find("POST /api/rollback")).toHaveLength(1));
    expect(api.find("POST /api/rollback")[0].body).toEqual({ snapshot_only: true });
  });
});

// --------------------------------------------------------------- unlock ---

const CATALOG: ProbeCatalogEntry[] = [
  { service: "auto-netflix", name: "Netflix", reachability: false, capability: "region_verdict", basis: "公开方法", probeable: true, enabled: true, group: "hk", group_mode: "auto" },
  { service: "auto-perplexity", name: "Perplexity", reachability: true, capability: "reachability", basis: "只能判断可达", probeable: true, enabled: true, group: "us", group_mode: "auto" },
];

function result(over: Partial<ProbeResultRow>): ProbeResultRow {
  return {
    service: "auto-netflix",
    service_name: "Netflix",
    exit_id: "hk-ix",
    exit_name: "香港 IX",
    family: "ipv4",
    state: "done",
    exit_groups: [{ id: "hk", name: "香港（机房）", mode: "auto", active: "hk-ix" }],
    is_active: true,
    ingestible: true,
    validation: "synthetic_only",
    ...over,
  };
}

describe("unlock", () => {
  const base = () => ({
    "GET /api/topology": () => topology(),
    "GET /api/status": () => panelStatus({ ...OK_AGENT, probe_available: true }),
    "GET /api/unlock/catalog": () => ({
      catalog: CATALOG,
      available: true,
      validation: "synthetic_only",
      validation_text: "检测规则依据公开检测方法与合成样本编写，本项目尚未在真实平台上验证；真实平台行为待人工核对。",
      grades: [],
      ingest_rule: "",
    }),
    "GET /api/unlock/jobs": () => ({ jobs: [], running: "", catalog: CATALOG, available: true }),
    "GET /api/unlock": () => ({ services: [], states: {}, history: [], next_run: NOW, interval_sec: 21600, pending_apply: false, decisions: {} }),
    "GET /api/region-groups": () => ({ groups: [group()], default_group: "hk", thresholds: THRESHOLDS }),
  });

  it("never presents a reachability-only result as unlocked, and states that adapters are unvalidated", async () => {
    fakeApi({
      ...base(),
      "GET /api/unlock/results": () => ({
        results: [
          result({ service: "auto-perplexity", service_name: "Perplexity", category: "network_ok", grade: "reachability_only", signal: "reachable" }),
          result({ category: "not_unlocked", grade: "platform_signal", signal: "blocked_marker", exit_id: "hk-2", exit_name: "香港二号", is_active: false }),
        ],
        validation: "synthetic_only",
        validation_text: "x",
      }),
    });
    renderAt("#/unlock");
    expect(await screen.findByTestId("validation-notice")).toHaveTextContent("尚未在真实平台上验证");
    const matrix = await screen.findByTestId("unlock-matrix");
    const cell = within(matrix).getByTestId("cell-auto-perplexity-hk-ix-ipv4");
    expect(cell.querySelector("[data-category]")!.getAttribute("data-category")).toBe("network_ok");
    expect(cell).toHaveTextContent("仅可达");
    expect(matrix.querySelector('[data-category="unlocked"]')).toBeNull();
    await userEvent.click(cell);
    const detail = await screen.findByTestId("result-detail");
    expect(detail).toHaveTextContent("「仅可达」不是解锁");
    expect(detail).toHaveTextContent("检测方法未在真实平台验证");
  });

  it("starts a batch probe by region group", async () => {
    const api = fakeApi({
      ...base(),
      "GET /api/unlock/results": () => ({ results: [], validation: "synthetic_only", validation_text: "x" }),
      "POST /api/unlock/run": () => reply(202, { job: { id: "job-1", kind: "manual", state: "running", created_at: NOW, items: [] } }),
      "GET /api/unlock/jobs/:id": () => ({ job: { id: "job-1", kind: "manual", state: "running", created_at: NOW, items: [] }, running: true }),
    });
    renderAt("#/unlock");
    const launcher = await screen.findByTestId("probe-launcher");
    fireEvent.click(within(launcher).getByRole("radio", { name: "按地区组" }));
    await pick("按地区组", "香港（机房）", launcher);
    await userEvent.click(within(launcher).getByRole("button", { name: /开始探测/ }));
    await waitFor(() => expect(api.find("POST /api/unlock/run")).toHaveLength(1));
    expect(api.find("POST /api/unlock/run")[0].body).toEqual({ groups: ["hk"] });
    expect(await screen.findByTestId("job-progress")).toHaveTextContent("进行中");
  });

  it("explains that only one probe can run at a time", async () => {
    fakeApi({
      ...base(),
      "GET /api/unlock/results": () => ({ results: [], validation: "synthetic_only", validation_text: "x" }),
      "POST /api/unlock/run": () => reply(409, { error: "已有一轮探测在运行" }),
    });
    renderAt("#/unlock");
    const launcher = await screen.findByTestId("probe-launcher");
    await userEvent.click(within(launcher).getByRole("button", { name: /开始探测/ }));
    expect(await within(launcher).findByText("同一时间只能有一轮探测；等它结束或取消它。")).toBeInTheDocument();
  });
});

// ----------------------------------------------------------------- leak ---

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
    renderAt("#/leak");
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
    expect(screen.getByText(/这一页没有任何一项能证明不泄露/)).toBeInTheDocument();
    expect(document.body).toHaveTextContent("docs/verification.md");
  });
});
