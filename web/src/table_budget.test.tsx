// Table width budget (docs/ui-layout.md, "Table width budget"): every
// DataTable's declared minimum width (its scroll.x: column minimums plus the
// expand column) must fit the width its container has at a 1280 px viewport
// with the sidebar expanded (TABLE_BUDGET in ui.tsx, measured in a browser).
// The pages are rendered with synthetic rows of real shape and long values,
// so tables that are empty on a fresh panel are exercised too.

import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { fakeApi, panelStatus, renderAt, tableBudgets } from "./testing";
import { TABLE_BUDGET, tableMinWidth, type DataColumn } from "./ui";
import type { Node, Topology } from "./types";

afterEach(() => {
  vi.restoreAllMocks();
  sessionStorage.clear();
  localStorage.clear();
});

const NOW = new Date().toISOString();
const LONG = "一个相当长的名字用来检查列宽.example";

/** All rendered DataTables fit their containers; returns them for the caller's own checks. */
function expectWithinBudget(min: number) {
  const tables = tableBudgets();
  expect(tables.length).toBeGreaterThanOrEqual(min);
  const over = tables.filter((t) => t.width > t.budget);
  expect(over, over.map((t) => `${t.name} in ${t.container}: ${t.width} > ${t.budget}`).join("; ")).toEqual([]);
  return tables;
}

function node(id: string, role: Node["role"], over: Partial<Node> = {}): Node {
  return { id, name: `${id} ${LONG}`, role, region: "hk", managed: role !== "ix", path_v4: true, path_v6: true, egress_v4: true, egress_v6: false, nat_dial_out: false, residential: false, ix_bound: false, ...over };
}

function topology(): Topology {
  return {
    settings: { draft: false, default_group: "g1", lan_interface: "eth0" } as Topology["settings"],
    nodes: [
      node("gw", "gateway", { region: "cn", managed: true }),
      node("relay1", "relay", { region: "cn", server_id: "srv-1", public_key: "PUB1=" }),
      node("hub1", "hub", { server_id: "srv-2" }),
      node("ex1", "exit", { server_id: "srv-3" }),
      node("ex2", "exit", { server_id: "srv-404" }),
    ],
    links: [],
    rules: [],
    region_groups: [{ id: "g1", name: "香港", region: "hk", members: ["ex1", "ex2"], mode: "auto" }],
  } as Topology;
}

function server(i: number) {
  return {
    id: `srv-${i}`,
    name: `服务器 ${i} · ${LONG}`,
    address: `host-${i}.a-really-long-subdomain-for-layout-checks.example.net`,
    port: 22022,
    user: "administrator",
    auth: "key",
    credential: { id: "cred-1", name: `登录密钥 ${LONG}`, kind: "private_key" },
    host_key: { state: i === 2 ? "seen" : "trusted", fingerprint: "SHA256:" + "A".repeat(43) },
    created_at: NOW,
    updated_at: NOW,
    operable: true,
    ready: i !== 2,
    missing: i === 2 ? ["host_key", "connection_test"] : [],
    in_use_by: [],
    node: { kind: "node", id: `n${i}`, name: `节点 ${LONG}` },
    last_test: { ok: true, at: NOW },
    channel: i === 3 ? { mode: "jump", via: "srv-1" } : undefined,
  };
}

// ------------------------------------------------------------------ helper ---

describe("tableMinWidth", () => {
  it("sums the declared minimums, the flex default and the expand column", () => {
    const cols: DataColumn<object>[] = [{ kind: "fixed", width: 100 }, { kind: "flex" }, { kind: "ellipsis", width: 200 }, { kind: "actions", width: 120 }];
    expect(tableMinWidth(cols, false)).toBe(100 + 160 + 200 + 120);
    expect(tableMinWidth(cols, true)).toBe(100 + 160 + 200 + 120 + 48);
    expect(TABLE_BUDGET.page - TABLE_BUDGET.sectionInset).toBe(TABLE_BUDGET.section);
  });
});

// ------------------------------------------------------------------- pages ---

describe("table width budget at 1280 with real-size rows", () => {
  it("servers: name, address, host key, state and actions fit; login and node are in the expandable row", async () => {
    fakeApi({ "GET /api/servers": () => ({ servers: [1, 2, 3].map(server) }) });
    renderAt("#/servers");
    const row = await screen.findByTestId("server-row-srv-1");
    const [t] = expectWithinBudget(1);
    expect(t.width).toBeLessThanOrEqual(TABLE_BUDGET.section);
    const heads = [...row.closest("table")!.querySelectorAll("thead th")].map((th) => th.textContent?.trim()).filter(Boolean);
    expect(heads).toEqual(["名称", "地址", "主机指纹", "状态", "操作"]);
    fireEvent.click(row.querySelector<HTMLElement>(".ant-table-row-expand-icon")!);
    const sec = await waitFor(() => {
      const el = document.querySelector<HTMLElement>(".row-secondary");
      if (!el) throw new Error("no secondary row");
      return el;
    });
    expect(sec).toHaveTextContent("登录");
    expect(sec).toHaveTextContent("节点");
    expect(row.querySelector(".ellipsis-text")).toHaveTextContent("administrator@host-1.a-really-long-subdomain-for-layout-checks.example.net:22022");
  });

  it("keys: SSH and SOCKS credentials", async () => {
    fakeApi({
      "GET /api/ssh-credentials": () => ({
        credentials: [1, 2].map((i) => ({
          id: `cred-${i}`,
          name: `密钥 ${i} ${LONG}`,
          kind: "private_key",
          generated: true,
          has_passphrase: true,
          fingerprint: "SHA256:" + "B".repeat(43),
          created_at: NOW,
          rotated_at: NOW,
          in_use_by: [1, 2, 3, 4].map((k) => ({ kind: "server", id: `srv-${k}`, name: `服务器 ${k} ${LONG}` })),
        })),
      }),
      "GET /api/socks-credentials": () => ({
        credentials: [{ id: "socks-1", name: `SOCKS ${LONG}`, notes: "一段比较长的备注，说明这个代理是谁的、在哪里".repeat(2), secret_set: true, created_at: NOW, rotated_at: NOW, used_by: [{ kind: "node", id: "ex9", name: LONG }] }],
      }),
    });
    renderAt("#/keys");
    await screen.findByTestId("credential-row-cred-1");
    await screen.findByTestId("socks-row-socks-1");
    expectWithinBudget(2);
  });

  it("remote access: devices", async () => {
    const device = (i: number) => ({
      id: `dev-${i}`,
      name: `设备 ${i} ${LONG}`,
      notes: "这台设备的备注写得很长，用来检查备注只占一行".repeat(2),
      mode: "full",
      enabled: true,
      public_key: "PUB=",
      ipv4: "10.66.250.2/32",
      ipv6: "fd66:0:0:fa:1234:5678:9abc:def0/128",
      preshared_key: true,
      created_at: NOW,
      updated_at: NOW,
      key_created_at: NOW,
      config_available: false,
      config_outdated: i === 1,
      runtime: { online: true, last_handshake_at: NOW, rx_bytes: 123456789, tx_bytes: 987654321, endpoint: "203.0.113.9:40000" },
      runtime_state: "ok",
    });
    fakeApi({
      "GET /api/remote-access": () => ({
        settings: { enabled: true, endpoint: "home.example.net", listen_port: 51888, ipv4_prefix: "10.66.250.0/24", ipv6_prefix: "fd66:0:0:fa::/64", mtu: 1380, keepalive: 25, interface: "mra", gateway_ipv4: "10.66.250.1", gateway_ipv6: "fd66:0:0:fa::1", dns: ["10.66.250.1"], public_key: "GW=", max_devices: 32, device_count: 2, defaults: { ipv4_prefix: "10.66.250.0/24", ipv6_prefix: "fd66:0:0:fa::/64", mtu: 1380, keepalive: 25, mode: "full" }, modes: { full: "全隧道", home: "仅家网" } },
        router_forward: { protocol: "udp", external_port: 51888, internal_address: "192.0.2.88", internal_port: 51888, description: "端口转发", ipv6_note: "IPv6" },
        devices: [device(1), device(2)],
        runtime: { available: true, state: "ok", interface: "mra", read_at: NOW },
        issues: [],
      }),
    });
    renderAt("#/remote");
    await screen.findByTestId("device-row-dev-1");
    expectWithinBudget(1);
  });

  it("cloudflare: accounts with an expanded permission check, and Mesh readiness", async () => {
    const check = {
      ok: false,
      checked_at: NOW,
      token_status: "active",
      token_kind: "account",
      detail: "缺少一项权限",
      checks: [{ name: "connectors", endpoint: "/accounts/0123456789abcdef0123456789abcdef/cfd_tunnel?is_deleted=false&per_page=1", status: "denied", detail: "没有 Cloudflare One Connectors 的读权限，部署会在 Cloudflare 节点阶段失败" }],
      missing: ["Cloudflare One Connectors Write"],
      unconfirmed: ["写权限"],
    };
    fakeApi({
      "GET /api/cloudflare/accounts": () => ({
        accounts: [{ id: "cf-1", name: `账户 ${LONG}`, account_id: "0123456789abcdef0123456789abcdef", token_set: true, created_at: NOW, updated_at: NOW, used_for_mesh: false, bound_deployment: { kind: "mesh_deployment", id: "run-1", name: LONG }, in_use_by: [], permission_check: check }],
        mesh_account: null,
      }),
      "GET /api/mesh": () => ({
        dataplane: "unverified",
        dataplane_note: "Mesh 数据面：未验证。",
        fault_injection: false,
        stages: ["plan"],
        mesh_account: null,
        plan_servers: [
          { node_id: "hub1", name: `枢纽 ${LONG}`, role: "hub", server_id: "srv-1", server_name: `服务器 ${LONG}`, ready: false, missing: ["server", "credential", "host_key"], host_key: "SHA256:" + "C".repeat(43) },
          { node_id: "ex1", name: `出口 ${LONG}`, role: "exit", server_id: "srv-2", server_name: LONG, ready: true, missing: [] },
        ],
        plan: { addressing: null, nodes: [{ node_id: "hub1", name: "hub1", role: "hub" }], routes: [], return_v4: [], return_v6: [], issues: [] },
        journal: null,
      }),
    });
    renderAt("#/cloudflare");
    const name = await screen.findByText(`账户 ${LONG}`);
    fireEvent.click(name.closest("tr")!.querySelector<HTMLElement>(".ant-table-row-expand-icon")!);
    await screen.findByTestId("permission-check");
    await waitFor(() => expect(document.body).toHaveTextContent("还需：关联服务器、选择密钥、确认主机指纹"));
    expectWithinBudget(3);
  });

  it("deploy: remote nodes, the guide's plan, deployment records, binaries and WSS", async () => {
    const step = (id: string, i: number) => ({
      node_id: id,
      node_name: `${id} ${LONG}`,
      role: "exit",
      kind: "remote",
      reason: "出口要先于枢纽装好：枢纽装机时要用到出口的公钥，管理通道也经过它；这是一个很长的原因说明。",
      warnings: ["服务器上已有 wstunnel，面板不会覆盖它"],
      plan_state: "changed",
      phase: "pending",
      attempts: 0,
      position: i + 1,
      current: false,
      in_flight: false,
      confirmation_valid: false,
      can_preflight: false,
      can_install: false,
    });
    fakeApi({
      "GET /api/status": () => panelStatus({ agent: { configured: true, ok: true } }),
      "GET /api/topology": () => topology(),
      "GET /api/servers": () => ({ servers: [1, 2, 3].map(server) }),
      "GET /api/deploy": () => ({
        limits: { proves: ["安装事务已提交"], does_not_prove: ["端到端连通"], independent: ["远程接入是独立资源"] },
        run: null,
        plan: { topology_version: "v1", steps: ["ex1", "hub1", "relay1"].map(step), skipped: [] },
        topology_version: "v1",
      }),
      "GET /api/deployments": () => ({
        nodes: [1, 2].map((i) => ({
          node_id: `n${i}`,
          node_name: `节点 ${i} ${LONG}`,
          in_topology: i === 1,
          server_id: `srv-${i}`,
          server_name: `服务器 ${LONG}`,
          current_server_id: `srv-${i + 1}`,
          address: "host.a-really-long-subdomain-for-layout-checks.example.net",
          port: 22022,
          fingerprint: "SHA256:" + "D".repeat(43),
          user: "administrator",
          credential_id: "cred-1",
          run: "run-1",
          bundle: "b".repeat(64),
          at: NOW,
          ok: true,
          installed: true,
          outcome: "installed",
          on_host: true,
          status: i === 1 ? "installed" : "unknown",
          identity_problem: i === 2 ? "服务器的地址或指纹与部署时固定的不一致，撤回前先核对" : undefined,
        })),
        gateway: { installed: false, withdrawn: false, plan: { files: [], interfaces: [], units: [], nft_tables: [], route_tables: [] }, kept: [], pending: null, last: null },
      }),
      "GET /api/artifacts": () => ({
        artifacts: ["x86_64", "aarch64"].map((arch) => ({ name: "smartdns", version: "1.2026.08.05-0921", arch, sha256: "1208c556".padEnd(64, "0"), size: 5301472, source_url: "https://example.org/smartdns", host_path: "/usr/local/sbin/meridian-smartdns", available: true })),
      }),
      "GET /api/wss": () => ({
        listeners: [
          {
            node_id: "hub1",
            server_name: "w0123456789abcdef.invalid",
            cert: { fingerprint_sha256: "E".repeat(64), not_before: NOW, not_after: NOW, created_at: NOW, days_left: 364 },
            legacy: false,
            rotating: false,
            inconsistent: false,
            links: [{ link_id: "gw-hub1-a-long-link-identifier", dialer_id: "gw", path_set: true, path_created_at: NOW, pending_path_created_at: NOW, legacy_path_accepted: true }],
            parties: [{ party: "server", role: "server", node_id: "hub1", installed_stage: 0, target_stage: 0, involved: true }],
            next_steps: [],
            results: [],
            warnings: [],
          },
        ],
        validity_days: 365,
        rotate_before: 30,
        verification: "x",
        interruption: "x",
        order: "x",
      }),
    });
    renderAt("#/deploy");
    await screen.findByTestId("remote-node-ex1");
    await screen.findByTestId("plan-step-ex1");
    await screen.findByTestId("deployment-n1");
    await screen.findByTestId("wss-links-hub1");
    // The binaries table sits in a closed Collapse panel: open it.
    await userEvent.click((await screen.findByText(/^固定版本：/)).closest<HTMLElement>(".ant-collapse-header")!);
    await waitFor(() => expect(document.querySelector(".ant-collapse-content-box .data-table-wrap")).not.toBeNull());
    expectWithinBudget(6);
    // Records: withdraw stays a button; the rarer actions are in the row menu.
    expect(within(screen.getByTestId("deployment-n1")).getByTestId("withdraw-n1")).toBeInTheDocument();
  });

  it("lists: the report and the configured lists", async () => {
    fakeApi({
      "GET /api/lists": () => ({
        policy: "automatic",
        saved: false,
        policies: ["domestic", "overseas", "automatic"],
        order: ["domestic", "overseas"],
        sources: [{ name: "domestic", geosite_base: "https://example.org/a", chnroute_base: "https://example.org/b" }],
        lists: { geosite: ["cn", "a-very-long-geosite-category-name"], keywords: [], chnroute: ["chnroute4", "chnroute6"] },
        host_available: true,
        job: {
          id: "lists-1",
          state: "done",
          policy: "automatic",
          lists: ["geosite"],
          started_at: NOW,
          finished_at: NOW,
          report: {
            policy: "automatic",
            sources: ["domestic"],
            started_at: NOW,
            finished_at: NOW,
            ok: false,
            partial: true,
            lists: [
              {
                list: "geosite:a-very-long-geosite-category-name",
                kind: "geosite",
                updated: false,
                kept: true,
                count: 123456,
                files: 3,
                dropped: { regexp: 2 },
                attempts: [{ source: "domestic", url: "https://example.org/a/a-very-long-geosite-category-name", ok: false, error: "HTTP 503 Service Unavailable from the mirror" }],
                current: { source: "overseas", url: "https://example.org", updated_at: NOW, count: 123456, files: 3 },
              },
            ],
          },
        },
      }),
    });
    renderAt("#/lists");
    await screen.findByText("名单与网关上的版本");
    await waitFor(() => expect(document.querySelectorAll(".data-table-wrap").length).toBeGreaterThanOrEqual(2));
    expectWithinBudget(2);
  });

  it("leak checks", async () => {
    fakeApi({
      "GET /api/leakcheck": () => ({
        items: [
          { id: "a", title: "生成的 nft 规则里有局域网兜底拒绝，一个比较长的检查标题", status: "pass", scope: "automated", detail: "说明".repeat(60) },
          { id: "b", title: "实机 DNS 泄漏", status: "pending", scope: "human", detail: "说明".repeat(40) },
        ],
      }),
    });
    renderAt("#/leak");
    await screen.findByTestId("leak-item-a");
    expectWithinBudget(2);
  });
});
