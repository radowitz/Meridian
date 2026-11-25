// Shared helpers and synthetic fixtures of the page interaction tests
// (pages_*.test.tsx; split out of one file so the test workers run them in
// parallel). Only imported by those test files; never part of the app bundle.

import { fireEvent, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type {
  DeploymentView,
  GatewayDeploymentView,
  WithdrawPlan,
  GroupActualView,
  GroupHubState,
  GroupMemberView,
  Node,
  PreflightRecord,
  ProbeCatalogEntry,
  ProbeResultRow,
  RegionGroupView,
  RemoteAccessView,
  RemoteDeviceView,
  ServerView,
  Topology,
} from "./types";

export const NOW = "2026-11-12T10:00:00Z";

export function btn(text: string) {
  return new RegExp(`^\\s*${text.split("").join("\\s*")}\\s*$`);
}

export async function confirmModal(okText: string) {
  const box = await waitFor(() => {
    const el = document.querySelector<HTMLElement>(".ant-modal-confirm");
    if (!el) throw new Error("no confirm dialog");
    return el;
  });
  await userEvent.click(within(box).getByRole("button", { name: btn(okText) }));
}

/** Opens an antd Select (by its aria-label) and clicks the option with this text. */
export async function pick(label: string, option: string | RegExp, scope: HTMLElement = document.body) {
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

/** Opens a "…" menu and clicks the item with this text. */
export async function menuItem(trigger: HTMLElement, text: string) {
  await userEvent.click(trigger);
  const item = await waitFor(() => {
    const els = [...document.querySelectorAll<HTMLElement>(".ant-dropdown:not(.ant-dropdown-hidden) .ant-dropdown-menu-item")];
    const hit = els.find((e) => e.textContent?.includes(text));
    if (!hit) throw new Error(`no menu item ${text}`);
    return hit;
  });
  await userEvent.click(item);
}

// ------------------------------------------------------------ fixtures ---

export function exitNode(id: string, name: string, over: Partial<Node> = {}): Node {
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

export function topology(over: Partial<Topology> = {}): Topology {
  return {
    settings: {
      draft: false,
      ix_replacement_mode: false,
      lan_interface: "eth0",
      gateway_lan_ipv4: "192.0.2.88/24",
      ros_ipv4: "192.0.2.1",
      ros_v6_lla: "fe80::1",
      lan_ipv6_prefix: "2001:db8:100::/64",
      ula_prefix: "fd66::/48",
      panel_bind: "192.0.2.88:8787",
      domestic_dot: [],
      transit_v4_prefix: "10.66.200.0/24",
      transit_v6_prefix: "fd66:0:0:ff::/64",
      default_group: "hk",
    },
    nodes: [
      { ...exitNode("gw", "网关", { role: "gateway", region: "cn" }) },
      { ...exitNode("hk-hub", "主枢纽", { role: "hub" }) },
      exitNode("hk-ix", "香港 IX", { ix_bound: true }),
      exitNode("hk-2", "香港二号"),
      exitNode("hk-resi", "香港住宅", { residential: true }),
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

export function member(id: string, name: string, over: Partial<GroupMemberView> = {}): GroupMemberView {
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
    actual_active: false,
    model_active: false,
    health: null,
    ...over,
  };
}

export const NEVER_READ: GroupActualView = {
  state: "never_read",
  code: "not_read",
  message: "还没有读取过枢纽的运行状态",
  active: "",
  alert: false,
  last_switch: null,
  read_at: null,
  hub_reported_at: null,
  deployed_matches: null,
};

export function actualOK(active: string, over: Partial<GroupActualView> = {}): GroupActualView {
  return {
    state: "ok",
    active,
    hop: active,
    reason: "failover",
    alert: false,
    last_switch: "2026-11-12T09:50:00Z",
    running_since: "2026-11-12T08:00:00Z",
    read_at: NOW,
    hub_reported_at: NOW,
    deployed_matches: true,
    clock_skew_sec: 0,
    ...over,
  };
}

export function hubState(over: Partial<GroupHubState> = {}): GroupHubState {
  return {
    hub_node: "hk-hub",
    hub_name: "主枢纽",
    server_id: "srv-hub",
    server_name: "枢纽服务器",
    readable: true,
    last_read: { read_at: NOW, ok: true, clock_skew_sec: 0, ignored: [] },
    refreshing: false,
    loop_interval_sec: 5,
    stale_after_sec: 135,
    read_max_age_sec: 600,
    skew_warn_sec: 300,
    counts: {},
    ...over,
  };
}

export function group(over: Partial<RegionGroupView> = {}): RegionGroupView {
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
      member("hk-ix", "香港 IX", { user_position: 1, position: 0, ix_bound: true, target: true, model_active: true, reasons: [{ code: "ix_first", message: "IX 绑定的出口排在用户顺序之前。" }] }),
      member("hk-resi", "香港住宅", { user_position: 2, position: -1, eligible: false, residential: true, reasons: [{ code: "residential_excluded", message: "组排除家宽，这个出口是家宽。" }] }),
    ],
    actual: NEVER_READ,
    model: { active: "hk-ix", reason: "preferred", alert: false, last_switch: null, observed: false, source: "panel_model" },
    in_use_by: [
      { kind: "settings", id: "default_group", name: "默认境外组" },
      { kind: "rule", id: "auto-netflix", name: "Netflix" },
    ],
    ...over,
  };
}

export const THRESHOLDS = { fails_need: 3, recovers_need: 3, cooldown_sec: 1800 };




// ------------------------------------------------------------- topology ---

export function server(over: Partial<ServerView> = {}): ServerView {
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



// -------------------------------------------------------- remote access ---

export const PRIVATE = "TESTPRIVATEKEYdoNotKeep0000000000000000000=";
export const PSK = "TESTPSKdoNotKeep1111111111111111111111111=";

export function device(over: Partial<RemoteDeviceView> = {}): RemoteDeviceView {
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

export function remoteView(devices: RemoteDeviceView[], runtime: RemoteAccessView["runtime"] = { available: true, state: "ok", interface: "mra", read_at: NOW }): RemoteAccessView {
  return {
    settings: {
      enabled: true,
      endpoint: "home.example.net",
      listen_port: 51888,
      ipv4_prefix: "10.66.250.0/24",
      ipv6_prefix: "fd66:0:0:fa::/64",
      mtu: 1380,
      keepalive: 25,
      allow_peers: false,
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
      internal_address: "192.0.2.88",
      internal_port: 51888,
      description: "在家里的路由器上添加端口转发（dst-nat）。面板不会修改路由器。",
      ipv6_note: "IPv6 防火墙还要放行。",
    },
    devices,
    runtime,
    issues: [],
  };
}

export function configText(name: string) {
  return `[Interface]\n# ${name}\nPrivateKey = ${PRIVATE}\nAddress = 10.66.250.2/32, fd66:0:0:fa::2/128\nDNS = 10.66.250.1\n\n[Peer]\nPublicKey = GWPUBLICKEYaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=\nPresharedKey = ${PSK}\nEndpoint = home.example.net:51888\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n`;
}


// --------------------------------------------------------------- deploy ---

export const OK_AGENT = { agent: { configured: true, ok: true } };


// --------------------------------------------------------------- unlock ---

export const CATALOG: ProbeCatalogEntry[] = [
  { service: "auto-netflix", name: "Netflix", reachability: false, capability: "region_verdict", basis: "公开方法", probeable: true, enabled: true, group: "hk", group_mode: "auto" },
  { service: "auto-perplexity", name: "Perplexity", reachability: true, capability: "reachability", basis: "只能判断可达", probeable: true, enabled: true, group: "us", group_mode: "auto" },
];

export function result(over: Partial<ProbeResultRow>): ProbeResultRow {
  return {
    service: "auto-netflix",
    service_name: "Netflix",
    exit_id: "hk-ix",
    exit_name: "香港 IX",
    family: "ipv4",
    state: "done",
    exit_groups: [{ id: "hk", name: "香港（机房）", mode: "auto", actual_active: "hk-ix", model_active: "hk-ix" }],
    is_active: true,
    ingestible: true,
    validation: "synthetic_only",
    ...over,
  };
}











// ---------------------------------------------------- install pre-check ---

export const PUBKEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITESTPUBLICKEYONLY panel";

export function preflightRec(over: Partial<PreflightRecord> = {}): PreflightRecord {
  const at = new Date(Date.now() - 60_000).toISOString();
  const expires = new Date(Date.now() + 9 * 60_000).toISOString();
  return {
    id: "pf-1",
    kind: "remote",
    node_id: "us",
    node_name: "美国",
    role: "exit",
    target: {
      server_id: "srv-2",
      server_name: "美国机",
      address: "198.51.100.40",
      port: 2222,
      user: "root",
      fingerprint: "SHA256:pinnedFINGERPRINTexample",
      credential_id: "cred-1",
      credential_name: "运维密钥",
    },
    deployment: "dep-1",
    bundle: "a".repeat(64),
    first_install: true,
    at,
    expires_at: expires,
    host: { os: "Debian GNU/Linux 12 (bookworm)", arch: "x86_64", kernel: "6.1.0-28-amd64", mem_total_kb: 1012000, mem_avail_kb: 420000, complete: true },
    footprint: {
      files: ["/etc/wireguard/m07.conf"],
      interfaces: [{ name: "m07", addresses: ["10.66.7.2/30"] }],
      listens: [{ proto: "udp", addr: "10.66.7.2", wildcard: false, port: 53, owner: "smartdns" }],
      route_tables: [100, 102, 150],
      nft_tables: ["inet meridian"],
      units: ["meridian-unlock.timer"],
      packages: [{ package: "wireguard-tools", command: "wg" }],
      binaries: [],
    },
    not_checked: ["不检查云厂商安全组"],
    ownership: "none",
    blocking: true,
    findings: [
      {
        severity: "blocking",
        code: "forward_policy_drop",
        resource: "ipv4 FORWARD",
        message: "ipv4 转发会被丢弃：iptables filter 表 FORWARD 策略 DROP（Docker 在运行，这通常是 Docker 设置的）。",
        action: "这一版面板不会替你改 Docker 或别的防火墙的规则。",
      },
      { severity: "warning", code: "low_memory", resource: "memory", message: "内存很紧。", action: "确认已有服务的内存余量。" },
      { severity: "info", code: "docker_present", resource: "docker", message: "Docker 在运行。" },
    ],
    changes: [
      { kind: "interface", action: "create", resource: "m07", detail: "10.66.7.2/30" },
      { kind: "package", action: "install", resource: "wireguard-tools" },
    ],
    counts: { blocking: 1, warning: 1, info: 1 },
    ...over,
  };
}

export const CLEAN = (over: Partial<PreflightRecord> = {}) =>
  preflightRec({
    id: "pf-2",
    blocking: false,
    findings: [{ severity: "info", code: "host_summary", message: "主机：Debian 12。" }],
    counts: { blocking: 0, warning: 0, info: 1 },
    ...over,
  });





// ------------------------------------------------------- withdraw (R4) ---

export function deployment(over: Partial<DeploymentView> = {}): DeploymentView {
  return {
    node_id: "us",
    node_name: "美国",
    in_topology: true,
    server_id: "srv-2",
    server_name: "美国机",
    current_server_id: "srv-2",
    address: "198.51.100.40",
    port: 2222,
    fingerprint: "SHA256:pinnedFINGERPRINTexample",
    user: "root",
    credential_id: "cred-1",
    run: "run-1",
    bundle: "b".repeat(64),
    at: NOW,
    ok: true,
    installed: true,
    outcome: "installed",
    on_host: true,
    status: "installed",
    ...over,
  };
}

export const EMPTY_SET = { files: [], interfaces: [], units: [], nft_tables: [], route_tables: [] };

export function deploymentsView(nodes: DeploymentView[], gateway: Partial<GatewayDeploymentView> = {}) {
  return {
    nodes,
    gateway: { installed: false, withdrawn: false, plan: EMPTY_SET, kept: [], pending: null, last: null, ...gateway },
  };
}

export function withdrawPlanOf(over: Partial<WithdrawPlan> = {}): WithdrawPlan {
  return {
    id: "wp-1",
    node_id: "us",
    mode: "manifest",
    target: { server_id: "srv-2", server_name: "美国机", address: "198.51.100.40", port: 2222, user: "root", fingerprint: "SHA256:pinnedFINGERPRINTexample", credential_id: "cred-1" },
    deployment: "dep-1",
    digest: "d".repeat(64),
    owner: "us dep-1 srv-2",
    items: ["iface m07 present", "nft inet meridian present", "file /etc/sysctl.d/99-meridian.conf changed"],
    at: NOW,
    expires_at: "2099-01-01T00:00:00Z",
    already: false,
    ...over,
  };
}
