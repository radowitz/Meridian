// Small tests for honesty fixes (kept out of the big page suites):
// the whole-topology save leaves the independent blocks out and shows a
// refusal with where to change them; the preflight's file list puts what
// changes first, counts the unchanged files and says "nothing changes"
// plainly.

import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import * as api from "./api";
import { linkCarrier, transportKind, type HubLegReport } from "./MeshLegQuality";
import { PreflightReport, UplinkMTUCard } from "./Preflight";
import { PathQualitySettings } from "./RelaySharing";
import { edgeLabel } from "./TopologyPage";
import { fakeApi, renderAt, reply } from "./testing";
import type { Link, PreflightRecord, Topology, UplinkMTUView } from "./types";
import { ApiErrorAlert } from "./ui";

function doc(): Topology {
  return {
    settings: {
      draft: false,
      lan_interface: "eth0",
      sniff: { enabled: true, ports: [443] },
      dns_log: { enabled: true },
      exit_dns: { protocol: "dot", addresses: ["192.0.2.53"], tls_host_name: "dns.example.net" },
    },
    nodes: [
      { id: "gw", name: "网关", role: "gateway" },
      { id: "jp-a", name: "日本", role: "exit", exit_dns: { protocol: "builtin" } },
    ],
    links: [],
    rules: [],
    rule_sets: [{ id: "rs1", name: "规则集", url: "https://rules.example.net/a.list" }],
    mihomo_import: { mapping: { Line: "group:hk" } },
    remote_access: { enabled: false },
  } as unknown as Topology;
}

it("opens a new managed exit from the exits page shortcut", async () => {
  const fake = fakeApi({ "GET /api/topology": doc });
  renderAt("#/topology?add=exit");
  expect(await screen.findByRole("textbox", { name: "节点名称" })).toHaveValue("出口 exit");
  expect(fake.find("PUT /api/topology")).toHaveLength(0);
});

describe("whole-topology save", () => {
  it("sends the document without the blocks owned by their own endpoints", async () => {
    const fake = fakeApi({ "PUT /api/topology": (req) => ({ topology: req.body, issues: [], paths: [], draft: false }) });
    await api.putTopology(doc(), false);
    const sent = fake.find("PUT /api/topology")[0].body as Record<string, unknown>;
    for (const k of ["rule_sets", "mihomo_import", "remote_access"]) expect(sent).not.toHaveProperty(k);
    expect(sent.settings).not.toHaveProperty("sniff");
    expect(sent.settings).not.toHaveProperty("exit_dns");
    expect(sent.settings).not.toHaveProperty("dns_log");
    expect((sent.settings as Record<string, unknown>).lan_interface).toBe("eth0");
    expect((sent.nodes as unknown[]).length).toBe(2);
    for (const n of sent.nodes as Record<string, unknown>[]) expect(n).not.toHaveProperty("exit_dns");
  });

  it("shows a refusal with each resource and where to change it", async () => {
    fakeApi({
      "PUT /api/topology": () =>
        reply(409, {
          error: "整份拓扑保存不能修改独立资源：规则集（rule_sets，用 /api/rule-sets）。没有保存任何内容。",
          code: "independent_resource_changed",
          fields: [
            { field: "rule_sets", resource: "规则集", endpoint: "/api/rule-sets", methods: ["PATCH /api/rule-sets/{id}"], items: ["rs1"] },
            { field: "remote_access", resource: "远程接入", endpoint: "/api/remote-access", methods: ["PUT /api/remote-access"], items: ["settings"] },
          ],
        }),
    });
    let err: api.ApiError | null = null;
    try {
      await api.putTopology(doc(), false);
    } catch (e) {
      err = e as api.ApiError;
    }
    expect(err?.code).toBe("independent_resource_changed");
    render(<ApiErrorAlert error={err} />);
    expect(screen.getByText("这些内容要在各自的页面修改，整份拓扑保存没有写入任何内容")).toBeInTheDocument();
    const list = screen.getByTestId("independent-fields");
    const sg = within(list).getByText("规则集").closest("li")!;
    expect(sg).toHaveTextContent("rs1");
    expect(within(sg).getByRole("link")).toHaveAttribute("href", "#/rules");
    expect(sg).toHaveTextContent("/api/rule-sets");
    const ra = list.querySelector('[data-field="remote_access"]')!;
    expect(within(ra as HTMLElement).getByRole("link")).toHaveAttribute("href", "#/remote");
  });
});

/** The change list is collapsed: open it. */
function openChanges() {
  fireEvent.click(screen.getByText(/拟执行的变更/));
  return screen.getByTestId("preflight-changes");
}

function rec(over: Partial<PreflightRecord>): PreflightRecord {
  return {
    id: "pf-1",
    kind: "gateway",
    node_id: "gw",
    node_name: "网关",
    role: "gateway",
    deployment: "dep",
    bundle: "b",
    first_install: false,
    at: "2026-11-14T10:00:00Z",
    expires_at: "2099-01-01T00:00:00Z",
    host: { mem_total_kb: 1, mem_avail_kb: 1, complete: true },
    footprint: { files: [], interfaces: [], listens: [], route_tables: [], nft_tables: [], units: [], packages: [], binaries: [] },
    not_checked: [],
    ownership: "same",
    blocking: false,
    findings: [],
    changes: [],
    counts: { blocking: 0, warning: 0, info: 0 },
    ...over,
  };
}

describe("preflight file list", () => {
  it("lists what changes first and counts the unchanged files", () => {
    render(
      <PreflightReport
        rec={rec({
          changes: [
            { kind: "interface", action: "update", resource: "m01", detail: "已存在、受管" },
            { kind: "file", action: "remove", resource: "/etc/meridian/old.conf", detail: "不再由拓扑生成：安装会删除它" },
            { kind: "file", action: "change", resource: "/etc/smartdns/smartdns.conf", detail: "内容有变化" },
          ],
          file_changes: {
            basis: "installed_manifest",
            added: [],
            changed: ["/etc/smartdns/smartdns.conf"],
            removed: ["/etc/meridian/old.conf"],
            unchanged: ["/etc/a.conf", "/etc/b.conf", "/etc/c.conf"],
            not_compared: [],
            summary: "文件：内容变化 1 个、不再生成 1 个；3 个与已安装的内容相同。",
          },
        })}
      />,
    );
    expect(screen.getByTestId("preflight-file-summary")).toHaveTextContent("内容变化 1 个");
    expect(screen.getByTestId("preflight-file-summary")).toHaveAttribute("data-none", "false");
    const changes = openChanges();
    const items = [...changes.querySelectorAll("[data-change]")].map((e) => e.getAttribute("data-change"));
    // Files first, the changed one before the removed one; other kinds as they were.
    expect(items).toEqual(["file:change", "file:remove", "interface:update"]);
    expect(within(changes).getByTestId("preflight-unchanged")).toHaveTextContent("3 个文件内容不变");
  });

  it("says plainly that no file changes", () => {
    render(
      <PreflightReport
        rec={rec({
          file_changes: {
            basis: "installed_manifest",
            added: [],
            changed: [],
            removed: [],
            unchanged: ["/etc/a.conf"],
            not_compared: [],
            summary: "没有文件变化：这次安装写入的 1 个文件与已安装的内容相同。",
          },
        })}
      />,
    );
    const s = screen.getByTestId("preflight-file-summary");
    expect(s).toHaveAttribute("data-none", "true");
    expect(s).toHaveTextContent("没有文件变化");
    expect(openChanges()).toHaveTextContent("没有要改动的文件");
  });

  it("keeps the old list when there is nothing to compare with", () => {
    render(<PreflightReport rec={rec({ changes: [{ kind: "file", action: "create", resource: "/etc/a.conf" }] })} />);
    expect(screen.queryByTestId("preflight-file-summary")).toBeNull();
    openChanges();
    expect(screen.queryByTestId("preflight-unchanged")).toBeNull();
    expect(document.querySelector('[data-change="file:create"]')).not.toBeNull();
  });
});

// The uplink MTU card: both ends of a leg, the suggestion, and the explicit
// two-step adoption that shows the per-node differences and only writes the
// topology (the deploy page confirms the install).
function uplinks(): UplinkMTUView {
  return {
    ttl_hours: 24,
    not_verified: ["预检只证明每一端本机的约束"],
    legs: [
      {
        link_id: "tw-hub",
        link_name: "台湾拨向枢纽",
        mode: "udp",
        iface: "m14",
        field: "mtu",
        configured: 1420,
        tunnel_mtu: 1420,
        status: "too_small",
        suggested: 1408,
        limiting: "tw",
        adoptable: true,
        ends: [
          { node_id: "tw", node_name: "台湾出口", status: "too_small", dev: "eth0", uplink_mtu: 1472, family: 4, shortfall: 8, suggested: 1408 },
          { node_id: "hk-hub", node_name: "主枢纽", status: "no_preflight", family: 4 },
        ],
      },
      { link_id: "hub-jp", mode: "udp", iface: "m09", field: "mtu", configured: 1420, tunnel_mtu: 1420, status: "fits", adoptable: false, ends: [] },
    ],
    proposal: {
      changes: [{ link_id: "tw-hub", field: "mtu", from: 1420, to: 1408, from_effective: 1420 }],
      nodes: [
        { node_id: "hk-hub", node_name: "主枢纽", files: ["/etc/wireguard/m14.conf"] },
        { node_id: "tw", node_name: "台湾出口", files: ["/etc/wireguard/m14.conf"] },
      ],
      paths: [],
    },
  };
}

describe("uplink MTU suggestion", () => {
  it("shows both ends and adopts only after an explicit confirmation", async () => {
    const fake = fakeApi({
      "GET /api/mtu/uplinks": () => uplinks(),
      "POST /api/mtu/adopt": (req) => ({
        topology: {},
        adopted: (req.body as { changes: unknown[] }).changes,
        proposal: uplinks().proposal,
        message: "已写入拓扑的 MTU 字段，没有下发到任何节点",
      }),
    });
    const adopted = vi.fn();
    render(<UplinkMTUCard dirty={false} onAdopted={adopted} />);
    const leg = await screen.findByTestId("uplink-leg");
    expect(leg).toHaveTextContent("隧道 MTU 1420 → 建议 1408");
    const ends = within(leg).getAllByTestId("uplink-end").map((e) => e.textContent);
    expect(ends).toEqual(["台湾出口：承载不了（eth0 1472，IPv4，超出 8 字节）", "主枢纽：没有预检"]);
    // Opening shows what changes; nothing is sent yet.
    fireEvent.click(screen.getByTestId("uplink-adopt-open"));
    const box = screen.getByTestId("uplink-adopt-confirm");
    expect(within(box).getByTestId("uplink-change")).toHaveTextContent("tw-hub 的「MTU」：1420 → 1408");
    expect(within(box).getByTestId("uplink-node-diffs")).toHaveTextContent("主枢纽：/etc/wireguard/m14.conf");
    expect(within(box).getByTestId("uplink-node-diffs")).toHaveTextContent("台湾出口：/etc/wireguard/m14.conf");
    expect(fake.find("POST /api/mtu/adopt")).toHaveLength(0);
    fireEvent.click(screen.getByTestId("uplink-adopt-ok"));
    await waitFor(() => expect(fake.find("POST /api/mtu/adopt")).toHaveLength(1));
    expect(fake.find("POST /api/mtu/adopt")[0].body).toEqual({ changes: [{ link_id: "tw-hub", field: "mtu", from: 1420, to: 1408 }] });
    const ok = await screen.findByTestId("uplink-adopted");
    expect(ok).toHaveTextContent("没有下发到任何节点");
    expect(within(ok).getByRole("link")).toHaveAttribute("href", "#/deploy");
    expect(adopted).toHaveBeenCalledTimes(1);
  });

  it("refuses to adopt over unsaved topology edits", async () => {
    fakeApi({ "GET /api/mtu/uplinks": () => uplinks() });
    render(<UplinkMTUCard dirty onAdopted={() => {}} />);
    expect(await screen.findByTestId("uplink-adopt-open")).toBeDisabled();
    expect(screen.getByText(/先保存或放弃/)).toBeInTheDocument();
  });
});


describe("Mesh quality settings", () => {
  it("edits a bounded sampling window and explains hub installation and fail-closed behavior", () => {
    const topo = doc();
    topo.links = [{ id: "mesh-synthetic", from: "hub", to: "jp-a", transport: "cf_mesh", enabled: true, standby: true }];
    const change = vi.fn();
    render(<PathQualitySettings topo={topo} onChange={change} />);
    expect(screen.getByText(/双断黑洞/)).toBeInTheDocument();
    const window = screen.getByRole("spinbutton", { name: "Mesh 双腿采样窗口" });
    fireEvent.change(window, { target: { value: "8" } });
    expect(change).toHaveBeenLastCalledWith(expect.objectContaining({ mesh_window_samples: 8 }));
    expect(screen.getByText(/修改须重新下发枢纽/)).toBeInTheDocument();
  });
});

// ------------------------------------------- transport and Mesh leg labels ---


describe("topology: what each link carries on", () => {
  const L = (id: string, from: string, to: string, transport: Link["transport"], over: Partial<Link> = {}): Link => ({ id, from, to, transport, enabled: true, standby: false, mtu: 1420, keepalive: 25, ...over });
  const meshTopo = (): Topology => ({
    settings: { draft: false },
    nodes: [
      { id: "gw", name: "网关", role: "gateway" },
      { id: "hub", name: "枢纽", role: "hub" },
      { id: "hub2", name: "备用枢纽", role: "hub" },
      { id: "us", name: "美国", role: "exit" },
    ],
    links: [
      L("l-gw", "gw", "hub", "wg_over_wss"),
      L("l-direct", "hub", "us", "direct_wg"),
      L("l-mesh", "hub", "us", "cf_mesh", { standby: true }),
      L("l-direct2", "hub2", "us", "direct_wg"),
      L("l-mesh2", "hub2", "us", "cf_mesh", { standby: true }),
    ],
    rules: [],
  } as unknown as Topology);
  const rep = (active: HubLegReport["active"], over: Partial<HubLegReport> = {}): HubLegReport => ({ plan: "p", exit: "us", beat: 1800000000, active, reason: "stable", switched: 0, direct_loss: 0, direct_rtt: 40, mesh_loss: 0, mesh_rtt: 70, result: "ok", hub: "hub", ...over });

  it("names each transport in three words", () => {
    expect(transportKind("direct_wg")).toBe("WG 直连");
    expect(transportKind("dedicated_line")).toBe("WG 直连");
    expect(transportKind("wg_over_wss")).toBe("WSS");
    expect(transportKind("ix_replacement_wss")).toBe("WSS");
    expect(transportKind("cf_mesh")).toBe("Mesh");
    const t = meshTopo();
    expect(edgeLabel(t.links[0], t, null)).toBe("WSS");
    // A lone Mesh link (no direct twin) keeps the plain label with 待命.
    const lone = { ...t, links: [L("m", "hub", "us", "cf_mesh", { standby: true })] };
    expect(edgeLabel(lone.links[0], lone, null)).toBe("Mesh · 待命");
    expect(edgeLabel(L("x", "gw", "hub", "direct_wg", { enabled: false }), t, null)).toBe("WG 直连 · 停用");
  });

  it("shows the leg in use from mesh_legs, per hub, and unknown without a report", () => {
    const t = meshTopo();
    const [, direct, mesh, direct2] = t.links;
    expect(linkCarrier(direct, t, null)).toEqual({ label: "直连 · Mesh 备用 · 实际未知", state: "unknown" });
    expect(linkCarrier(direct, t, [rep("direct")]).label).toBe("直连 · Mesh 备用");
    expect(linkCarrier(mesh, t, [rep("direct")]).label).toBe("Mesh 备用");
    expect(linkCarrier(direct, t, [rep("mesh", { reason: "quality", direct_loss: 200 })]).label).toBe("Mesh（直连丢包）");
    expect(linkCarrier(mesh, t, [rep("mesh", { reason: "direct_down" })]).label).toBe("Mesh 使用中（直连不通）");
    expect(linkCarrier(direct, t, [rep("blackhole", { reason: "both_down" })]).state).toBe("blackhole");
    expect(linkCarrier(direct, t, [rep("mesh", { result: "failed" })]).state).toBe("unknown");
    // Two hubs: each hub's own report; the backup hub without one stays unknown.
    expect(linkCarrier(direct2, t, [rep("mesh", { reason: "direct_down" })]).state).toBe("unknown");
    expect(linkCarrier(direct2, t, [rep("mesh", { reason: "direct_down" }), rep("direct", { hub: "hub2" })]).label).toBe("直连 · Mesh 备用");
    // Event rows are history, not the state now.
    expect(linkCarrier(direct, t, [rep("mesh", { event: true })]).state).toBe("unknown");
  });

  it("the link drawer names the leg in use", async () => {
    const t = meshTopo();
    fakeApi({
      "GET /api/topology": () => t,
      "POST /api/validate": () => ({ issues: [], paths: [] }),
      "GET /api/region-groups": () => ({ groups: [], default_group: "", thresholds: { fails_need: 3, recovers_need: 3, cooldown_sec: 1800 }, hub_states: [{ hub_node: "hub", tier: "primary", mesh_legs: [rep("mesh", { reason: "quality", direct_loss: 300 })] }] }),
    });
    renderAt("#/topology/l-direct");
    await waitFor(() => expect(screen.getByTestId("link-carrier")).toHaveTextContent("Mesh（直连丢包）"));
  });
});
