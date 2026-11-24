// The first-run wizard: each step, resume after a reload, back navigation,
// and an existing deployment never seeing it. Synthetic data only.

import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { WizardState } from "./api";
import { CLEAN } from "./pages_fixtures";
import { fakeApi, renderAt } from "./testing";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  sessionStorage.clear();
});

const TEMPLATES = [
  { id: "direct", name: "直连出口", nodes: ["gateway", "exit"], fields: [] },
  { id: "relay", name: "单中继", nodes: ["gateway", "relay", "exit"], fields: [] },
  { id: "relay_hub", name: "中继 + 枢纽", nodes: ["gateway", "relay", "hub", "exit"], fields: [] },
  { id: "ix", name: "IX 专线", nodes: ["gateway", "relay", "ix", "exit"], fields: [] },
];

const GW = { lan_interface: "eth0", lan_ipv4: "192.0.2.2/24", router_ipv4: "192.0.2.1" };

const SERVER = {
  id: "srv-1",
  name: "出口机",
  address: "203.0.113.41",
  port: 22,
  user: "root",
  auth: "password",
  credential_id: "cred-1",
  credential: { id: "cred-1", name: "出口机", kind: "password" },
  host_key: { state: "trusted", fingerprint: "SHA256:testFINGERPRINT" },
  created_at: "2026-11-18T00:00:00Z",
  updated_at: "2026-11-18T00:00:00Z",
  last_test: { at: "2026-11-18T00:00:00Z", ok: true, wan_interface: "ens3", duration_ms: 10 },
  operable: true,
  ready: true,
};

function wizardServer(start: Partial<WizardState> = {}, opts: { servers?: unknown[]; active?: boolean } = {}) {
  let state: WizardState = { step: "gateway", done: [], gateway: { lan_interface: "", lan_ipv4: "", router_ipv4: "" }, template: "", ...start };
  let active = opts.active ?? true;
  let servers = opts.servers ?? [];
  const api = fakeApi({
    "GET /api/setup/wizard": () => ({ active, state, detected: { lan_ip: "192.0.2.2" } }),
    "PUT /api/setup/wizard": (req) => {
      state = req.body as WizardState;
      return { active, state, detected: {} };
    },
    "POST /api/setup/wizard/complete": () => {
      active = false;
      return { active, state: { ...state, completed: true }, detected: {} };
    },
    "GET /api/templates": () => ({ templates: TEMPLATES }),
    "GET /api/servers": () => ({ servers }),
    "POST /api/ssh-credentials": () => ({ credential: { id: "cred-1", name: "出口机", kind: "password", secret_set: true } }),
    "POST /api/servers": () => {
      servers = [{ ...SERVER, host_key: { state: "unknown" }, last_test: null, operable: false, ready: false }];
      return { server: servers[0] };
    },
    "POST /api/servers/:id/host-key/discover": () => ({ discovery: { key_type: "ssh-ed25519", fingerprint: "SHA256:testFINGERPRINT", matches_pinned: false }, server: servers[0] }),
    "POST /api/servers/:id/host-key/trust": () => {
      servers = [{ ...SERVER, last_test: null, ready: false }];
      return { server: servers[0] };
    },
    "POST /api/servers/:id/test": () => {
      servers = [SERVER];
      return { test: SERVER.last_test, server: SERVER };
    },
    "POST /api/templates/:id/preview": () => ({
      template: "direct",
      valid: true,
      issues: [],
      paths: [],
      topology: { settings: {}, nodes: [{ id: "gw", role: "gateway", name: "网关" }, { id: "exit-jp", role: "exit", name: "出口 A" }], links: [], rules: [] },
    }),
    "PUT /api/topology": (req) => ({ topology: req.body, issues: [], paths: [], draft: false }),
    "GET /api/deploy": () => ({ limits: { proves: [], does_not_prove: [], independent: [] }, run: null, plan: { topology_version: "tv-1", steps: [], skipped: [] }, topology_version: "tv-1" }),
    "POST /api/host/preflight": () => ({ preflight: CLEAN({ id: "pf-gw", kind: "gateway", node_id: "gw", role: "gateway" }) }),
  });
  return { api, state: () => state };
}

const lastPut = (api: ReturnType<typeof fakeApi>) => api.find("PUT /api/setup/wizard").at(-1)?.body as WizardState;

describe("setup wizard", () => {
  it("a fresh install opens the wizard; the gateway step is prefilled from detection", async () => {
    const { api } = wizardServer();
    renderAt("#/");
    await screen.findByTestId("wizard-step-gateway", {}, { timeout: 4000 });
    expect(window.location.hash).toBe("#/setup");
    expect((screen.getByLabelText("网关地址") as HTMLInputElement).value).toBe("192.0.2.2/24");
    fireEvent.change(screen.getByLabelText("局域网网卡"), { target: { value: "eth0" } });
    fireEvent.change(screen.getByLabelText("主路由器"), { target: { value: "192.0.2.1" } });
    fireEvent.click(screen.getByRole("button", { name: "下一步" }));
    await screen.findByTestId("wizard-step-template");
    expect(lastPut(api)).toMatchObject({ step: "template", done: ["gateway"], gateway: GW });
  });

  it("template step lists the templates and saves the choice; back keeps the earlier answers", async () => {
    const { api } = wizardServer({ step: "template", done: ["gateway"], gateway: GW });
    renderAt("#/setup");
    await screen.findByText("直连出口", {}, { timeout: 4000 });
    expect(screen.getAllByRole("radio")).toHaveLength(4);
    fireEvent.click(screen.getByRole("button", { name: "上一步" }));
    await screen.findByTestId("wizard-step-gateway");
    expect(lastPut(api)).toMatchObject({ step: "gateway", done: ["gateway"], gateway: GW });
    expect((screen.getByLabelText("局域网网卡") as HTMLInputElement).value).toBe("eth0");
    fireEvent.click(screen.getByRole("button", { name: "下一步" }));
    await screen.findByText("直连出口");
    fireEvent.click(screen.getByText("直连出口"));
    fireEvent.click(screen.getByRole("button", { name: "下一步" }));
    await screen.findByTestId("wizard-step-servers");
    expect(lastPut(api)).toMatchObject({ step: "servers", template: "direct", done: ["gateway", "template"] });
  });

  it("servers step: credential, fingerprint confirmation and connection test before going on", async () => {
    const { api } = wizardServer({ step: "servers", done: ["gateway", "template"], gateway: GW, template: "direct" });
    renderAt("#/setup");
    const row = await screen.findByTestId("wizard-exit-0", {}, { timeout: 4000 });
    const next = () => screen.getByRole("button", { name: "下一步" });
    expect(next()).toHaveProperty("disabled", true);
    fireEvent.click(within(row).getByRole("button", { name: "添加服务器" }));
    const dialog = await screen.findByRole("dialog");
    fireEvent.change(within(dialog).getByLabelText("名称"), { target: { value: "出口机" } });
    fireEvent.change(within(dialog).getByLabelText("地址"), { target: { value: "203.0.113.41" } });
    fireEvent.change(within(dialog).getByLabelText("登录密码"), { target: { value: "synthetic-password" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "获取指纹" }));
    expect(await within(dialog).findByText("SHA256:testFINGERPRINT")).toBeTruthy();
    expect(api.find("POST /api/servers/srv-1/host-key/trust")).toHaveLength(0);
    fireEvent.click(within(dialog).getByRole("button", { name: "确认指纹并测试" }));
    // The connection test read the default route's NIC.
    expect((await within(dialog).findByTestId("wizard-detected-wan")).textContent).toContain("ens3");
    fireEvent.click(await within(dialog).findByRole("button", { name: "完成" }));
    expect(api.find("POST /api/servers/srv-1/host-key/trust")[0].body).toEqual({ fingerprint: "SHA256:testFINGERPRINT" });
    expect(api.find("POST /api/servers/srv-1/test")).toHaveLength(1);
    await waitFor(() => expect(within(row).getByText("已连通")).toBeTruthy());
    // Shown for confirmation, editable.
    const wan = within(row).getByLabelText("出口 1WAN 网卡") as HTMLInputElement;
    expect(wan.value).toBe("ens3");
    fireEvent.change(wan, { target: { value: "ens5" } });
    fireEvent.change(within(row).getByLabelText("出口 1地区"), { target: { value: "jp" } });
    fireEvent.mouseDown(screen.getByRole("combobox", { name: "默认地区" }));
    fireEvent.click(await screen.findByTitle("jp"));
    await waitFor(() => expect(next()).toHaveProperty("disabled", false));
    fireEvent.click(next());
    await screen.findByTestId("wizard-step-topology");
    const put = lastPut(api);
    expect(put.input).toMatchObject({ default_region: "jp", exits: [{ name: "出口机", region: "jp", endpoint_v4: "203.0.113.41", server_id: "srv-1", wan_interface: "ens5" }] });
    // The secret never reaches the wizard record.
    expect(JSON.stringify(api.find("PUT /api/setup/wizard"))).not.toContain("synthetic-password");
  });

  it("relay_hub: optional backup hub and backup relays are asked for, saved, restored after a reload and previewed", async () => {
    const srv = (name: string, extra: Record<string, string> = {}) => ({ name, endpoint_v4: "203.0.113.41", server_id: "srv-1", ...extra });
    const input = {
      exits: [srv("出口 A", { region: "jp", wan_interface: "ens3" })],
      relay: srv("中继", { wan_interface: "ens3" }),
      hub: srv("枢纽", { wan_interface: "ens3" }),
      backup_hub: srv("备用枢纽", { wan_interface: "ens4" }),
      backup_relays: [srv("备用中继 A", { wan_interface: "ens3" })],
      default_region: "jp",
    };
    const { api } = wizardServer({ step: "servers", done: ["gateway", "template"], gateway: GW, template: "relay_hub", input }, { servers: [SERVER] });
    renderAt("#/setup");
    const bh = await screen.findByTestId("wizard-backup-hub", {}, { timeout: 4000 });
    // Restored from the stored record, the confirmed NIC kept over the detected one.
    expect((within(bh).getByLabelText("备用枢纽名称") as HTMLInputElement).value).toBe("备用枢纽");
    expect((within(bh).getByLabelText("备用枢纽WAN 网卡") as HTMLInputElement).value).toBe("ens4");
    const br = screen.getByTestId("wizard-backup-relay-0");
    expect((within(br).getByLabelText("备用中继 1名称") as HTMLInputElement).value).toBe("备用中继 A");
    // Another backup relay: incomplete until it has a server.
    fireEvent.click(screen.getByRole("button", { name: "添加备用中继" }));
    const next = () => screen.getByRole("button", { name: "下一步" });
    await waitFor(() => expect(next()).toHaveProperty("disabled", true));
    fireEvent.click(screen.getByRole("button", { name: "移除最后一个备用中继" }));
    await waitFor(() => expect(next()).toHaveProperty("disabled", false));
    fireEvent.click(next());
    await screen.findByTestId("wizard-preview");
    expect(lastPut(api).input).toMatchObject({ backup_hub: input.backup_hub, backup_relays: input.backup_relays, relay: input.relay, hub: input.hub });
    expect(api.find("POST /api/templates/relay_hub/preview")[0].body).toMatchObject({ gateway: GW, backup_hub: input.backup_hub, backup_relays: input.backup_relays });
    // Reload: the topology step previews the stored backups again.
    cleanup();
    renderAt("#/setup");
    await screen.findByTestId("wizard-preview", {}, { timeout: 4000 });
    expect(api.find("POST /api/templates/relay_hub/preview").at(-1)?.body).toMatchObject({ backup_hub: input.backup_hub, backup_relays: input.backup_relays });
    // Back on the servers step the rows are still there; removing the backup hub drops its relays.
    fireEvent.click(screen.getByRole("button", { name: "上一步" }));
    await screen.findByTestId("wizard-backup-hub");
    fireEvent.click(screen.getByRole("button", { name: "移除备用枢纽" }));
    expect(screen.queryByTestId("wizard-backup-relay-0")).toBeNull();
    fireEvent.click(next());
    await screen.findByTestId("wizard-preview");
    const put = lastPut(api).input!;
    expect(put.backup_hub).toBeUndefined();
    expect(put.backup_relays).toBeUndefined();
  });

  it("ix: a backup hub can be added, but no backup relays; detected NICs fill the rows", async () => {
    const input = {
      exits: [{ name: "出口 A", region: "jp", endpoint_v4: "203.0.113.41", server_id: "srv-1" }],
      relay: { name: "中继", endpoint_v4: "203.0.113.41", server_id: "srv-1" },
      hub: { name: "专线", endpoint_v4: "203.0.113.41", ingress_v4: "198.51.100.9", server_id: "srv-1" },
      default_region: "jp",
    };
    const { api } = wizardServer({ step: "servers", done: ["gateway", "template"], gateway: GW, template: "ix", input }, { servers: [SERVER] });
    renderAt("#/setup");
    const relay = await screen.findByTestId("wizard-relay", {}, { timeout: 4000 });
    await waitFor(() => expect((within(relay).getByLabelText("中继WAN 网卡") as HTMLInputElement).value).toBe("ens3"));
    fireEvent.click(screen.getByRole("button", { name: "添加备用枢纽" }));
    const bh = await screen.findByTestId("wizard-backup-hub");
    expect(screen.queryByRole("button", { name: "添加备用中继" })).toBeNull();
    const next = () => screen.getByRole("button", { name: "下一步" });
    expect(next()).toHaveProperty("disabled", true);
    fireEvent.change(within(bh).getByLabelText("备用枢纽名称"), { target: { value: "备用" } });
    fireEvent.change(within(bh).getByLabelText("备用枢纽公网地址"), { target: { value: "203.0.113.50" } });
    fireEvent.mouseDown(within(bh).getByRole("combobox", { name: "备用枢纽服务器" }));
    await waitFor(() => expect(document.querySelector('.ant-select-item-option[title="出口机"]')).not.toBeNull());
    fireEvent.click(document.querySelector('.ant-select-item-option[title="出口机"]')!);
    await waitFor(() => expect(next()).toHaveProperty("disabled", false));
    expect((within(screen.getByTestId("wizard-backup-hub")).getByLabelText("备用枢纽WAN 网卡") as HTMLInputElement).value).toBe("ens3");
    fireEvent.click(next());
    await screen.findByTestId("wizard-step-topology");
    expect(lastPut(api).input).toMatchObject({
      backup_hub: { name: "备用", endpoint_v4: "203.0.113.50", server_id: "srv-1", wan_interface: "ens3" },
      relay: { wan_interface: "ens3" },
      hub: { wan_interface: "ens3" },
      exits: [{ wan_interface: "ens3" }],
    });
    expect(lastPut(api).input?.backup_relays).toBeUndefined();
  });

  it("WAN NIC is required: empty blocks the step with an inline error; a typed name is saved", async () => {
    const input = { exits: [{ name: "出口 A", region: "jp", endpoint_v4: "203.0.113.41", server_id: "srv-1" }], default_region: "jp" };
    const undetected = { ...SERVER, last_test: { ...SERVER.last_test, wan_interface: undefined } };
    const { api } = wizardServer({ step: "servers", done: ["gateway", "template"], gateway: GW, template: "direct", input }, { servers: [undetected] });
    renderAt("#/setup");
    const row = await screen.findByTestId("wizard-exit-0", {}, { timeout: 4000 });
    await waitFor(() => expect(within(row).getByText("已连通")).toBeTruthy());
    const next = () => screen.getByRole("button", { name: "下一步" });
    expect(next()).toHaveProperty("disabled", true);
    expect(within(row).getByTestId("wizard-exit-0-wan-error").textContent).toBe("填写 WAN 网卡");
    fireEvent.change(within(row).getByLabelText("出口 1WAN 网卡"), { target: { value: "enp1s0" } });
    await waitFor(() => expect(next()).toHaveProperty("disabled", false));
    expect(within(row).queryByTestId("wizard-exit-0-wan-error")).toBeNull();
    fireEvent.click(next());
    await screen.findByTestId("wizard-step-topology");
    expect(lastPut(api).input).toMatchObject({ exits: [{ wan_interface: "enp1s0" }] });
  });

  it("topology step previews, saves through PUT /api/topology and records the version", async () => {
    const input = { exits: [{ name: "出口 A", region: "jp", endpoint_v4: "203.0.113.41", server_id: "srv-1" }], default_region: "jp" };
    const { api } = wizardServer({ step: "topology", done: ["gateway", "template", "servers"], gateway: GW, template: "direct", input }, { servers: [SERVER] });
    renderAt("#/setup");
    await screen.findByTestId("wizard-preview", {}, { timeout: 4000 });
    expect(api.find("POST /api/templates/direct/preview")[0].body).toEqual({ gateway: GW, ...input });
    fireEvent.click(screen.getByRole("button", { name: "保存拓扑" }));
    await screen.findByTestId("wizard-step-preflight");
    expect(api.find("PUT /api/topology")).toHaveLength(1);
    expect(lastPut(api)).toMatchObject({ step: "preflight", topology_version: "tv-1" });
  });

  it("preview keeps the filled gateway even when the stored input carries an empty one", async () => {
    // Shape an older backend returned: input serialised as a full TemplateInput.
    const emptyGw = { lan_interface: "", lan_ipv4: "", router_ipv4: "" };
    const input = { gateway: emptyGw, exits: [{ name: "出口 A", region: "jp", endpoint_v4: "203.0.113.41", server_id: "srv-1" }], default_region: "jp" };
    const start = JSON.parse(JSON.stringify({ step: "topology", done: ["gateway", "template", "servers"], gateway: GW, template: "direct", input }));
    const { api } = wizardServer(start, { servers: [SERVER] });
    renderAt("#/setup");
    await screen.findByTestId("wizard-preview", {}, { timeout: 4000 });
    expect((api.find("POST /api/templates/direct/preview")[0].body as { gateway: unknown }).gateway).toEqual(GW);
  });

  it("preflight and install: the wizard only opens the deployment guide", async () => {
    const { api } = wizardServer({ step: "preflight", done: ["gateway", "template", "servers", "topology"], gateway: GW, template: "direct", topology_version: "tv-1" });
    renderAt("#/setup");
    const next = await screen.findByRole("button", { name: "下一步" }, { timeout: 4000 });
    expect(next).toHaveProperty("disabled", true);
    fireEvent.click(screen.getByRole("button", { name: "运行预检" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "下一步" })).toHaveProperty("disabled", false));
    fireEvent.click(screen.getByRole("button", { name: "下一步" }));
    await screen.findByTestId("wizard-step-install");
    expect(lastPut(api)).toMatchObject({ step: "install", preflight_id: "pf-gw" });
    fireEvent.click(screen.getByRole("button", { name: "打开部署" }));
    await waitFor(() => expect(window.location.hash).toBe("#/deploy"));
    expect(api.find("POST /api/setup/wizard/complete")).toHaveLength(1);
    expect(api.find("POST /api/apply")).toHaveLength(0);
    expect(api.find("POST /api/deploy/runs")).toHaveLength(0);
  });

  it("resumes at the stored step after a reload", async () => {
    wizardServer({ step: "template", done: ["gateway"], gateway: GW });
    renderAt("#/");
    await screen.findByTestId("wizard-step-template", {}, { timeout: 4000 });
    cleanup();
    renderAt("#/");
    await screen.findByTestId("wizard-step-template", {}, { timeout: 4000 });
    // Done steps can be revisited from the step bar.
    fireEvent.click(screen.getByText("添加网关"));
    await screen.findByTestId("wizard-step-gateway");
  });

  it("an existing deployment never sees the wizard", async () => {
    const { api } = wizardServer({}, { active: false });
    renderAt("#/");
    await waitFor(() => expect(api.find("GET /api/setup/wizard").length).toBeGreaterThan(0));
    await new Promise((r) => setTimeout(r, 50));
    expect(window.location.hash).not.toBe("#/setup");
    expect(screen.queryByTestId("setup-wizard")).toBeNull();
  });

  it("the administrator password changes from the account dialog", async () => {
    const { api } = wizardServer({}, { active: false });
    api.on("PUT /api/auth/admin", () => ({ state: "ready", admin: true, token_login: true }));
    renderAt("#/");
    fireEvent.click(await screen.findByRole("button", { name: "管理员账户" }, { timeout: 4000 }));
    const dialog = await screen.findByRole("dialog");
    fireEvent.change(within(dialog).getByLabelText("当前密码"), { target: { value: "old synthetic pass" } });
    fireEvent.change(within(dialog).getByLabelText("新密码"), { target: { value: "new synthetic pass" } });
    fireEvent.change(within(dialog).getByLabelText("再输一次"), { target: { value: "new synthetic pass" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "保存" }));
    // Saved: the dialog closes and says so.
    expect(await screen.findByText("管理员账户已更新")).toBeInTheDocument();
    expect(api.find("PUT /api/auth/admin")[0].body).toEqual({ current_password: "old synthetic pass", username: "admin", password: "new synthetic pass" });
  });
});
