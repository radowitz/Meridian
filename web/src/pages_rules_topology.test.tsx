// Interaction tests of the operational pages against the in-memory fake
// API (split out of the former pages.test.tsx; helpers and fixtures in
// pages_fixtures.tsx).
//
// Rules (one target, no mode, ordering, same-named groups), the unsaved-
// changes guard, topology (server instead of ssh_*, deleting nodes), gateway
// resolver settings, ports and WSS carriers.

import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { effectiveOrder, moveRule } from "./RulesPage";
import { fakeApi, renderAt, webStorageDump } from "./testing";
import { deleteNode } from "./TopologyPage";
import type {
  AllocationView,
  Rule,
  Topology,
  WSSListenerView,
} from "./types";
import {
  NOW,
  btn,
  confirmModal,
  pick,
  menuItem,
  topology,
  server,
  preflightRec,
  deployment,
  deploymentsView,
} from "./pages_fixtures";

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

  it("states that rule names never go to the domestic resolvers, whatever the unlisted-name setting", async () => {
    for (const split of [false, true]) {
      const t = topology();
      t.settings = { ...t.settings, unlisted_domestic_dns: split };
      fakeApi({ "GET /api/topology": () => t });
      const { unmount } = renderAt("#/rules");
      await screen.findByTestId("rules-dns-note");
      // The fail-closed statement is visible; its explanation is in the page's 「说明」 (the DNS note's text is spread over both).
      const note = document.body;
      expect(note).toHaveTextContent("规则命中的域名只由规则目标（地区组或出口）的解析器解析");
      expect(note).toHaveTextContent("不会改问国内解析器");
      expect(note).toHaveTextContent(split ? "（当前已打开）" : "（当前关闭）");
      expect(note).toHaveTextContent("指向外部 SOCKS 出口（只有 IPv4 TCP）的规则永远不返回");
      unmount();
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

describe("gateway settings: resolver", () => {
  it("shows both DNS settings off for an existing topology, explains each, and saves them as booleans", async () => {
    let saved: string | undefined;
    const t = topology(); // saved before the settings existed: neither field present
    const api = fakeApi({
      "GET /api/topology": () => t,
      "GET /api/servers": () => ({ servers: [] }),
      "PUT /api/topology": (req) => {
        saved = req.raw;
        return { topology: req.body, issues: [], paths: [], draft: false };
      },
    });
    renderAt("#/topology");
    await userEvent.click(await screen.findByRole("button", { name: /网关设置/ }));
    const v6 = await screen.findByRole("switch", { name: "客户端 IPv6 经本网关" });
    const split = screen.getByRole("switch", { name: "未列名单的域名也问国内 DNS" });
    expect(v6).not.toBeChecked();
    expect(split).not.toBeChecked();
    const drawer = v6.closest(".ant-drawer-content") as HTMLElement;
    // Off: what happens to clients' IPv6, and the strict DNS guarantee.
    expect(drawer).toHaveTextContent("除国内域名外，所有域名都不返回 AAAA");
    expect(drawer).toHaveTextContent("不会从家宽 IPv6 绕过隧道");
    expect(drawer).toHaveTextContent("国外域名的查询不经家宽发出");
    // Remote-access devices share the policy; rule names never go domestic.
    expect(drawer).toHaveTextContent("远程接入的设备用同一个解析器、同一个设置");
    expect(drawer).toHaveTextContent("外部 SOCKS 出口（只有 IPv4 TCP）以及会切到它的地区组，无论怎样都不返回 AAAA");
    expect(drawer).toHaveTextContent("打开这个设置也不会发给国内解析器");

    await userEvent.click(v6);
    expect(v6).toBeChecked();
    expect(drawer).toHaveTextContent("IPv6 默认路由都指向本网关（见 docs/test-device.md）");
    expect(drawer).toHaveTextContent("绕过隧道");
    await userEvent.click(split);
    expect(split).toBeChecked();
    expect(drawer).toHaveTextContent("只有国内返回的地址全是中国地址时才采用并直连");
    expect(drawer).toHaveTextContent("CNAME 指向国外");
    expect(drawer).toHaveTextContent("国内解析器能看到这些域名（包括国外的）");
    expect(drawer).toHaveTextContent("DNS 泄漏测试里会出现国内解析器");

    await userEvent.click(screen.getByRole("button", { name: btn("保存") }));
    await waitFor(() => expect(api.find("PUT /api/topology")).toHaveLength(1));
    const body = JSON.parse(saved!) as Topology;
    expect(body.settings.clients_ipv6_via_gateway).toBe(true);
    expect(body.settings.unlisted_domestic_dns).toBe(true);
  });

  it("turns a setting back off", async () => {
    let saved: string | undefined;
    const t = topology();
    t.settings = { ...t.settings, clients_ipv6_via_gateway: true, unlisted_domestic_dns: true };
    const api = fakeApi({
      "GET /api/topology": () => t,
      "GET /api/servers": () => ({ servers: [] }),
      "PUT /api/topology": (req) => {
        saved = req.raw;
        return { topology: req.body, issues: [], paths: [], draft: false };
      },
    });
    renderAt("#/topology");
    await userEvent.click(await screen.findByRole("button", { name: /网关设置/ }));
    const split = await screen.findByRole("switch", { name: "未列名单的域名也问国内 DNS" });
    expect(split).toBeChecked();
    expect(screen.getByRole("switch", { name: "客户端 IPv6 经本网关" })).toBeChecked();
    await userEvent.click(split);
    await userEvent.click(screen.getByRole("button", { name: btn("保存") }));
    await waitFor(() => expect(api.find("PUT /api/topology")).toHaveLength(1));
    const body = JSON.parse(saved!) as Topology;
    expect(body.settings.unlisted_domestic_dns).toBe(false);
    expect(body.settings.clients_ipv6_via_gateway).toBe(true);
  });
});

describe("rules: ordering", () => {
  const rule = (id: string, manual: boolean, priority: number): Rule => ({
    id,
    name: id,
    manual,
    priority,
    enabled: true,
    overridden: false,
    match_type: "domain",
    match_value: `${id}.example`,
    target_group: "hk",
    require_residential: false,
    require_v6: false,
  });

  it("moveRule keeps manual rules before built-in ones and renumbers predictably", () => {
    const rules = [rule("m1", true, 10), rule("m2", true, 20), rule("m3", true, 30), rule("a", false, 100), rule("b", false, 110), rule("c", false, 110)];
    expect(effectiveOrder(rules).map((r) => r.id)).toEqual(["m1", "m2", "m3", "a", "b", "c"]);
    // Room between neighbours: only the moved rule changes.
    let out = moveRule(rules, "m3", 0);
    expect(effectiveOrder(out).map((r) => r.id)).toEqual(["m3", "m1", "m2", "a", "b", "c"]);
    expect(out.filter((r) => r.priority !== rules.find((x) => x.id === r.id)!.priority).map((r) => r.id)).toEqual(["m3"]);
    // Ties (b and c share 110): the built-in class is renumbered in the shown order from its base, step 10.
    out = moveRule(rules, "a", 2);
    expect(effectiveOrder(out).map((r) => r.id)).toEqual(["m1", "m2", "m3", "b", "c", "a"]);
    out = moveRule(rules, "c", 0);
    expect(effectiveOrder(out).filter((r) => !r.manual).map((r) => [r.id, r.priority])).toEqual([["c", 90], ["a", 100], ["b", 110]]);
    out = moveRule(rules, "a", 1);
    expect(effectiveOrder(out).filter((r) => !r.manual).map((r) => [r.id, r.priority])).toEqual([["b", 100], ["a", 110], ["c", 120]]);
    expect(out.find((r) => r.id === "c")!.overridden).toBe(true);
    expect(out.find((r) => r.id === "a")!.overridden).toBe(true);
    // A built-in rule never crosses above a manual one.
    out = moveRule(rules, "b", -5);
    expect(effectiveOrder(out).slice(0, 3).every((r) => r.manual)).toBe(true);
    // Numbers that collide with built-in ones do not change what is shown first.
    const mixed = [rule("auto", false, 5), rule("man", true, 50)];
    expect(effectiveOrder(mixed).map((r) => r.id)).toEqual(["man", "auto"]);
  });

  it("moves a rule to the bottom of its class from the row menu and saves that order", async () => {
    const t = topology({ rules: [rule("m1", true, 10), rule("m2", true, 20), rule("m3", true, 30), rule("a", false, 100)] });
    let saved: Topology | undefined;
    const api = fakeApi({
      "GET /api/topology": () => t,
      "POST /api/validate": () => ({ issues: [], paths: [] }),
      "PUT /api/topology": (req) => {
        saved = req.body as Topology;
        return { topology: req.body, issues: [], paths: [], draft: false };
      },
    });
    renderAt("#/rules");
    const row = await screen.findByTestId("rule-row-m1");
    await menuItem(within(row).getByRole("button", { name: "移动 m1" }), "移到手动规则的最后");
    await waitFor(() => expect(screen.getByTestId("rule-pos-m1")).toHaveTextContent("3"));
    expect(screen.getByTestId("rule-pos-a")).toHaveTextContent("4");
    await userEvent.click(screen.getByRole("button", { name: btn("保存") }));
    await waitFor(() => expect(api.find("PUT /api/topology")).toHaveLength(1));
    expect(effectiveOrder(saved!.rules).map((r) => r.id)).toEqual(["m2", "m3", "m1", "a"]);
    expect(saved!.rules.find((r) => r.id === "m1")!.priority).toBe(40);
  });
});

describe("topology: deleting a node", () => {
  it("lists what refers to the node, cleans up groups and links, and requires a choice for pinned rules", async () => {
    const t = topology({
      links: [{ id: "l1", name: "枢纽到美国", from: "hk-hub", to: "us", transport: "wireguard", enabled: true, standby: false } as unknown as Topology["links"][number]],
      rules: [
        {
          id: "pin-us",
          name: "钉到美国",
          manual: true,
          priority: 10,
          enabled: true,
          overridden: false,
          match_type: "domain",
          match_value: "x.example",
          target_exit: "us",
          require_residential: false,
          require_v6: false,
        },
      ],
      region_groups: [
        { id: "us", name: "美国", members: ["us"], mode: "manual", chosen: "us" },
        { id: "hk", name: "香港（机房）", members: ["hk-2", "us"], mode: "auto" },
      ],
    });
    let saved: Topology | undefined;
    const api = fakeApi({
      "GET /api/topology": () => t,
      "PUT /api/topology": (req) => {
        saved = req.body as Topology;
        return { topology: req.body, issues: [], paths: [], draft: true };
      },
      "PUT /api/topology?draft=1": (req) => {
        saved = req.body as Topology;
        return { topology: req.body, issues: [], paths: [], draft: true };
      },
    });
    renderAt("#/topology/us");
    await userEvent.click(await screen.findByRole("button", { name: /删除节点/ }));
    const dlg = await screen.findByTestId("node-delete");
    expect(dlg).toHaveTextContent("链路 1 条：一起删除");
    const groups = within(dlg).getByTestId("node-delete-groups");
    expect(groups).toHaveTextContent("这个组会变成空组");
    expect(groups).toHaveTextContent("这个组手动指定的就是这个节点");
    expect(within(dlg).getByTestId("node-delete-rules")).toHaveTextContent("钉到美国");
    const ok = screen.getByRole("button", { name: /删除并清理引用/ });
    expect(ok).toBeDisabled();
    await pick("规则 钉到美国 的处理", "地区组：香港（机房）", dlg);
    await waitFor(() => expect(ok).toBeEnabled());
    await userEvent.click(ok);
    await waitFor(() => expect(screen.queryByTestId("node-delete")).toBeNull());
    await userEvent.click(screen.getByRole("button", { name: btn("保存草稿") }));
    await waitFor(() => expect(api.calls.some((c) => c.method === "PUT" && c.path === "/api/topology")).toBe(true));
    expect(saved!.nodes.some((n) => n.id === "us")).toBe(false);
    expect(saved!.links).toHaveLength(0);
    expect(saved!.region_groups!.find((g) => g.id === "us")).toMatchObject({ members: [] });
    expect(saved!.region_groups!.find((g) => g.id === "us")!.chosen).toBeUndefined();
    expect(saved!.region_groups!.find((g) => g.id === "hk")!.members).toEqual(["hk-2"]);
    const r = saved!.rules.find((x) => x.id === "pin-us")!;
    expect(r.target_group).toBe("hk");
    expect(r.target_exit).toBeUndefined();
  });

  it("never touches a pinned rule without a choice (deleteNode)", () => {
    const t = topology({
      rules: [{ id: "p", name: "p", manual: true, priority: 1, enabled: true, overridden: false, match_type: "domain", match_value: "a", target_exit: "us", require_residential: false, require_v6: false }],
    });
    expect(deleteNode(t, "us", {}).rules[0].target_exit).toBe("us");
    expect(deleteNode(t, "us", { p: "delete" }).rules).toHaveLength(0);
  });
});

describe("topology: deleting a deployed node", () => {
  it("offers 仅从拓扑删除 and 先撤回再删除; keeping the install leaves the record alone", async () => {
    const t = topology();
    t.nodes = t.nodes.map((n) => (n.id === "us" ? { ...n, server_id: "srv-2" } : n));
    let saved: Topology | undefined;
    const api = fakeApi({
      "GET /api/topology": () => t,
      "GET /api/servers": () => ({ servers: [server({ id: "srv-2", name: "美国机", address: "198.51.100.40" })] }),
      "GET /api/deployments": () => deploymentsView([deployment()]),
      "PUT /api/topology": (req) => {
        saved = req.body as Topology;
        return { topology: req.body, issues: [], paths: [], draft: false };
      },
    });
    renderAt("#/topology/us");
    await userEvent.click(await screen.findByRole("button", { name: /删除节点/ }));
    const part = await screen.findByTestId("node-delete-deployment");
    expect(part).toHaveTextContent("仅从拓扑删除（保留服务器上的安装，之后仍可在部署页撤回）");
    expect(part).toHaveTextContent("先撤回再删除");
    expect(part).toHaveTextContent("wireguard-tools");
    const ok = screen.getByRole("button", { name: /删除并清理引用/ });
    expect(ok).toBeDisabled();
    await userEvent.click(within(part).getByText("先撤回再删除"));
    expect(await screen.findByRole("button", { name: /先撤回/ })).toBeEnabled();
    await userEvent.click(within(part).getByText(/仅从拓扑删除/));
    const del = await screen.findByRole("button", { name: /删除并清理引用/ });
    await waitFor(() => expect(del).toBeEnabled());
    await userEvent.click(del);
    await waitFor(() => expect(screen.queryByTestId("node-delete")).toBeNull());
    await userEvent.click(screen.getByRole("button", { name: btn("保存") }));
    await waitFor(() => expect(saved).toBeDefined());
    expect(saved!.nodes.some((n) => n.id === "us")).toBe(false);
    // Nothing was withdrawn or forgotten.
    expect(api.calls.some((c) => c.path.startsWith("/api/provision/withdraw") || c.path.startsWith("/api/provision/state"))).toBe(false);
  });
});

describe("rules: same-named region groups", () => {
  it("shows region and ID in the target picker and in the rules list", async () => {
    const t = topology({
      region_groups: [
        { id: "hk-dc", name: "香港", region: "hk", members: ["hk-2", "hk-ix"], mode: "auto" },
        { id: "hk-home", name: "香港", region: "hk", members: ["hk-resi"], mode: "auto" },
      ],
      settings: { ...topology().settings, default_group: "hk-dc" },
    });
    t.rules = t.rules.map((r) => ({ ...r, target_group: "hk-home" }));
    fakeApi({ "GET /api/topology": () => t, "POST /api/validate": () => ({ issues: [], paths: [] }) });
    renderAt("#/rules");
    expect(await screen.findByText("香港（香港 · HK · hk-home）")).toBeInTheDocument();
    await userEvent.click(await screen.findByRole("button", { name: /添加规则/ }));
    const drawer = await screen.findByRole("dialog");
    fireEvent.mouseDown(within(drawer).getByRole("combobox", { name: "地区组" }));
    const options = await waitFor(() => {
      const els = [...document.querySelectorAll<HTMLElement>(".ant-select-dropdown:not(.ant-select-dropdown-hidden) .ant-select-item-option")].map((e) => e.textContent ?? "");
      if (els.length < 2) throw new Error("options not open");
      return els;
    });
    expect(options.some((o) => o.includes("hk-dc"))).toBe(true);
    expect(options.some((o) => o.includes("hk-home"))).toBe(true);
  });
});

describe("ports", () => {
  it("links a port conflict to the field that sets the port", async () => {
    const t = topology();
    t.nodes = t.nodes.map((n) => (n.id === "us" ? { ...n, server_id: "srv-2" } : n));
    const rec = preflightRec({
      findings: [
        {
          severity: "blocking",
          code: "port_in_use",
          resource: "udp [::]:51820",
          message: "WireGuard 监听端口（m07）要绑定 udp [::]:51820，但 udp [::]:51820 已被WireGuard 接口 wg0占用。",
          action: "在拓扑里把链路 hub-us的「WireGuard 端口」（链路 hub-us 的 WireGuard 监听端口）改成这台主机上未占用的端口。",
          fix: { kind: "link", id: "hub-us", field: "wg_port", label: "链路 hub-us 的「WireGuard 端口」" },
        },
      ],
      counts: { blocking: 1, warning: 0, info: 0 },
    });
    fakeApi({
      "GET /api/topology": () => t,
      "GET /api/servers": () => ({ servers: [server({ id: "srv-2", name: "美国机", address: "198.51.100.40" })] }),
      "POST /api/provision/preflight": () => ({ preflight: rec }),
    });
    renderAt("#/deploy");
    await userEvent.click(within(await screen.findByTestId("remote-node-us")).getByRole("button", { name: /生成密钥并下发/ }));
    const fix = await screen.findByTestId("preflight-fix");
    expect(within(fix).getByRole("link", { name: /去拓扑修改：链路 hub-us 的「WireGuard 端口」/ })).toHaveAttribute("href", "#/topology/hub-us");
    expect(screen.getByTestId("preflight-execute")).toBeDisabled();
  });

  it("offers the WireGuard, wstunnel and WSS ports where the link and node are edited", async () => {
    let saved: string | undefined;
    const t = topology({ links: [{ id: "gw-hub", from: "gw", to: "hk-hub", transport: "wg_over_wss", enabled: true, standby: false, wg_port: 51841 }] });
    const api = fakeApi({
      "GET /api/topology": () => t,
      "PUT /api/topology": (req) => {
        saved = req.raw;
        return { topology: req.body, issues: [], paths: [], draft: false };
      },
    });
    renderAt("#/topology/gw-hub");
    const detail = await screen.findByTestId("link-detail");
    expect(within(detail).getByLabelText("WireGuard 端口")).toHaveValue("51841");
    const local = within(detail).getByLabelText("wstunnel 本地端口");
    await userEvent.type(local, "52900");
    await userEvent.click(screen.getByRole("button", { name: btn("保存") }));
    await waitFor(() => expect(api.find("PUT /api/topology")).toHaveLength(1));
    const body = JSON.parse(saved!) as Topology;
    expect(body.links[0].wss_local_port).toBe(52900);
    expect(body.links[0].wg_port).toBe(51841);
  });

  it("shows the link's allocated interface, ports and subnets read-only and warns before a save changes them", async () => {
    const t = topology({ links: [{ id: "gw-hub", from: "gw", to: "hk-hub", transport: "udp_wss_failover", enabled: true, standby: false }] });
    let wgPortSent: number | undefined;
    const view = (changed: boolean): AllocationView => ({
      links: [
        {
          link_id: "gw-hub",
          slot: 3,
          state: "allocated",
          enabled: true,
          new: false,
          listener: "hk-hub",
          dialer: "gw",
          wg_port: changed ? 40001 : 51823,
          wg_from: changed ? "link" : "default",
          wss_leg_port: changed ? 40002 : 51824,
          local_port: 52003,
          legs: [
            { iface: "m03", mode: "udp", wg_port: 51823, west: "gw", east: "hk-hub", west_v4: "10.66.4.1", east_v4: "10.66.4.2", west_ula: "fd66:0:0:4::1", east_ula: "fd66:0:0:4::2" },
            { iface: "m03w", mode: "wss", wg_port: 51824, west: "gw", east: "hk-hub", west_v4: "10.66.103.1", east_v4: "10.66.103.2", west_ula: "fd66:0:0:83::1", east_ula: "fd66:0:0:83::2" },
          ],
        },
      ],
      marks: [],
      changes: changed ? [{ link_id: "gw-hub", what: "wg_port", before: "51823", after: "40001" }] : [],
      max_links: 99,
      max_marks: 240,
    });
    const api = fakeApi({
      "GET /api/topology": () => t,
      "POST /api/topology/allocations": (req) => {
        wgPortSent = (req.body as Topology).links[0].wg_port;
        return view(wgPortSent === 40001);
      },
    });
    renderAt("#/topology/gw-hub");
    const facts = await screen.findByTestId("link-allocation");
    expect(facts).toHaveTextContent("m03");
    expect(facts).toHaveTextContent("m03w");
    expect(facts).toHaveTextContent("51823");
    expect(facts).toHaveTextContent("52003");
    expect(facts).toHaveTextContent("10.66.4.1");
    expect(facts).toHaveTextContent("10.66.103.2");
    expect(screen.queryByTestId("allocation-changes")).toBeNull();
    // Editing the override shows what the save would change.
    const detail = screen.getByTestId("link-detail");
    await userEvent.type(within(detail).getByLabelText("WireGuard 端口"), "40001");
    expect(await screen.findByTestId("link-allocation-changes")).toHaveTextContent("WireGuard 端口：51823 → 40001");
    expect(await screen.findByTestId("allocation-changes")).toHaveTextContent("gw-hub");
    expect(api.find("POST /api/topology/allocations").length).toBeGreaterThan(1);
  });

  it("shows the WSS listen port for an exit node", async () => {
    fakeApi({ "GET /api/topology": () => topology() });
    renderAt("#/topology/us");
    const detail = await screen.findByTestId("node-detail");
    expect(within(detail).getByLabelText("WireGuard 监听端口")).toBeInTheDocument();
    await userEvent.click(within(detail).getByText("WSS 入口（高级）"));
    expect(await within(detail).findByLabelText("WSS 监听端口")).toBeInTheDocument();
  });
});

// ----------------------------------------------------------- WSS carriers ---

describe("WSS carriers: random path and pinned self-signed certificate", () => {
  const FP = "AB:CD:".repeat(15) + "EF:01";
  const NEWFP = "12:34:".repeat(15) + "56:78";
  function listener(over: Partial<WSSListenerView> = {}): WSSListenerView {
    return {
      node_id: "hk-hub",
      server_name: "w0123456789abcdef.invalid",
      cert: { fingerprint_sha256: FP, not_before: NOW, not_after: "2027-11-12T10:00:00Z", created_at: NOW, days_left: 364 },
      legacy: false,
      rotating: false,
      inconsistent: false,
      links: [{ link_id: "gw-hub", dialer_id: "gw", path_set: true, path_created_at: NOW }],
      parties: [
        { party: "server", role: "server", node_id: "hk-hub", installed_stage: 0, target_stage: 0, involved: true },
        { party: "client:gw-hub", role: "client", link_id: "gw-hub", node_id: "gw", installed_stage: 0, target_stage: 0, involved: true },
      ],
      next_steps: [],
      results: [],
      warnings: [],
      ...over,
    };
  }
  const view = (ls: WSSListenerView[]) => ({ listeners: ls, validity_days: 365, rotate_before: 30, verification: "唯一信任根", interruption: "中断几秒。", order: "交替下发。" });

  it("shows fingerprint, validity and 'set' only, and regenerates a certificate through the API", async () => {
    let current = listener();
    const api = fakeApi({
      "GET /api/topology": () => topology(),
      "GET /api/wss": () => view([current]),
      "POST /api/wss/listeners/:id/regenerate-cert": (req) => {
        current = listener({
          rotating: true,
          rotation_reason: "manual_cert",
          rotation_started: NOW,
          pending_cert: { fingerprint_sha256: NEWFP, not_before: NOW, not_after: "2027-12-12T10:00:00Z", created_at: NOW, days_left: 394 },
          parties: [
            { party: "server", role: "server", node_id: "hk-hub", installed_stage: 1, target_stage: 1, involved: true },
            { party: "client:gw-hub", role: "client", link_id: "gw-hub", node_id: "gw", installed_stage: 0, target_stage: 2, involved: true },
          ],
          inconsistent: true,
          next_steps: [{ node_id: "gw", party: "client:gw-hub", from: 0, to: 2 }],
          warnings: [{ level: "warning", message: "两端暂不一致（只更新了一端）" }],
        });
        return { listener: { ...current, node_id: req.params.id }, committed: false };
      },
    });
    renderAt("#/deploy");
    const card = await screen.findByTestId("wss-listener-hk-hub");
    expect(card).toHaveTextContent(FP);
    expect(card).toHaveTextContent("w0123456789abcdef.invalid");
    expect(card).toHaveTextContent("剩 364 天");
    expect(within(screen.getByTestId("wss-links-hk-hub")).getByText("已设置")).toBeInTheDocument();
    expect(card).not.toHaveTextContent(/ACME/i);
    await userEvent.click(within(card).getByRole("button", { name: btn("重新生成证书") }));
    await confirmModal("重新生成");
    await waitFor(() => expect(api.find("POST /api/wss/listeners/hk-hub/regenerate-cert")).toHaveLength(1));
    const next = await screen.findByTestId("wss-next-hk-hub");
    expect(next).toHaveTextContent("安装到本机（网关）");
    expect(next).toHaveTextContent("阶段 2");
    const after = screen.getByTestId("wss-listener-hk-hub");
    expect(after).toHaveTextContent(NEWFP);
    expect(after).toHaveTextContent("两端暂不一致");
    expect(within(screen.getByTestId("wss-parties-hk-hub")).getAllByText(/阶段 1/).length).toBeGreaterThan(0);
    expect(within(after).getByRole("button", { name: btn("重新生成证书") })).toBeDisabled();
    expect(webStorageDump()).not.toContain(FP);
  });

  it("regenerates a link's path and shows a legacy migration and an expired certificate", async () => {
    const api = fakeApi({
      "GET /api/topology": () => topology(),
      "GET /api/wss": () =>
        view([
          listener(),
          listener({
            node_id: "access",
            legacy: true,
            rotating: true,
            rotation_reason: "migration",
            links: [{ link_id: "gw-access", dialer_id: "gw", path_set: true, path_created_at: NOW, legacy_path_accepted: true }],
            cert: { fingerprint_sha256: FP, not_before: NOW, not_after: "2026-11-01T00:00:00Z", created_at: NOW, days_left: -11 },
            warnings: [{ level: "error", message: "证书已过期：客户端校验证书有效期，WSS 承载已无法建立。" }],
          }),
        ]),
      "POST /api/wss/links/:id/regenerate-path": () => ({ listener: listener(), committed: true }),
    });
    renderAt("#/deploy");
    const access = await screen.findByTestId("wss-listener-access");
    expect(access).toHaveTextContent("旧固定路径仍被接受");
    expect(access).toHaveTextContent("证书已过期");
    expect(access).toHaveTextContent("需要立即处理");
    expect(within(access).getByRole("button", { name: btn("重新生成路径") })).toBeDisabled();
    const hub = screen.getByTestId("wss-listener-hk-hub");
    await userEvent.click(within(hub).getByRole("button", { name: btn("重新生成路径") }));
    await confirmModal("重新生成");
    await waitFor(() => expect(api.find("POST /api/wss/links/gw-hub/regenerate-path")).toHaveLength(1));
  });

  it("has no path or certificate-path inputs in the topology editor and shows the link's WSS status", async () => {
    const t = topology({ links: [{ id: "gw-hub", from: "gw", to: "hk-hub", transport: "wg_over_wss", enabled: true, standby: false }] });
    fakeApi({ "GET /api/topology": () => t, "GET /api/wss": () => view([listener()]) });
    renderAt("#/topology/gw-hub");
    const status = await screen.findByTestId("wss-link-status");
    expect(status).toHaveTextContent("已设置（面板随机生成，不显示）");
    expect(status).toHaveTextContent(FP);
    renderAt("#/topology/hk-hub");
    const detail = await screen.findByTestId("node-detail");
    await userEvent.click(within(detail).getByText("WSS 入口（高级）"));
    expect(await within(detail).findByTestId("wss-node-note")).toHaveTextContent("没有 ACME");
    expect(within(detail).queryByText("WSS 路径前缀")).toBeNull();
    expect(within(detail).queryByText("TLS 证书路径")).toBeNull();
    expect(within(detail).queryByText("TLS 私钥路径")).toBeNull();
  });
});

// ------------------------------------------------------ adding links ---

describe("topology: adding links", () => {
  const save = () => {
    let saved: Topology | null = null;
    const api = fakeApi({
      "GET /api/topology": () => topology(),
      "POST /api/validate": () => ({ issues: [], paths: [] }),
      "PUT /api/topology": (req) => {
        saved = req.body as Topology;
        return { topology: saved, issues: [], paths: [], draft: false };
      },
    });
    return { api, saved: () => saved! };
  };

  it("adds a link from the toolbar button with standby false", async () => {
    const s = save();
    renderAt("#/topology");
    await userEvent.click(await screen.findByRole("button", { name: /添加链路/ }));
    const dlg = await screen.findByTestId("add-link-form");
    await pick("起点", "网关", dlg);
    await pick("终点", "主枢纽", dlg);
    await pick("承载方式", /WSS/, dlg);
    await userEvent.click(screen.getByRole("button", { name: btn("添加") }));
    await userEvent.click(await screen.findByRole("button", { name: btn("保存") }));
    await waitFor(() => expect(s.api.find("PUT /api/topology")).toHaveLength(1));
    const l = s.saved().links.find((x) => x.from === "gw" && x.to === "hk-hub" && x.id.startsWith("gw-hk-hub"))!;
    expect(l.standby).toBe(false);
    expect(l.transport).not.toBe("direct_wg");
  });

  it("refuses a standby-only transport until 待命 is ticked", async () => {
    save();
    renderAt("#/topology");
    await userEvent.click(await screen.findByRole("button", { name: /添加链路/ }));
    const dlg = await screen.findByTestId("add-link-form");
    await pick("起点", "网关", dlg);
    await pick("终点", "主枢纽", dlg);
    await pick("承载方式", "Mesh", dlg);
    expect(screen.getByRole("button", { name: btn("添加") })).toBeDisabled();
    await userEvent.click(within(dlg).getByRole("checkbox", { name: "待命" }));
    expect(screen.getByRole("button", { name: btn("添加") })).toBeEnabled();
  });

  it("connects from the node drawer", async () => {
    const s = save();
    renderAt("#/topology/gw");
    await userEvent.click(await screen.findByRole("button", { name: /连接到/ }));
    const dlg = await screen.findByTestId("add-link-form");
    await pick("终点", "主枢纽", dlg);
    await userEvent.click(screen.getByRole("button", { name: btn("添加") }));
    await userEvent.click(await screen.findByRole("button", { name: btn("保存") }));
    await waitFor(() => expect(s.api.find("PUT /api/topology")).toHaveLength(1));
    const added = s.saved().links.filter((x) => x.from === "gw" && x.to === "hk-hub");
    expect(added.at(-1)).toMatchObject({ transport: "direct_wg", standby: false, enabled: true });
  });

  it("shows 连 IX 出口地址 only for relay ↔ IX hub with ingress_v4 and sends dial_egress", async () => {
    const t = topology();
    t.nodes = t.nodes.map((n) => (n.id === "hk-hub" ? { ...n, ix_line: true, ingress_v4: "198.51.100.1", endpoint_v4: "203.0.113.1" } : n));
    t.nodes.push({ ...t.nodes.find((n) => n.id === "hk-hub")!, id: "relay", name: "中继", role: "relay", ix_line: undefined, ingress_v4: undefined, server_id: undefined });
    t.links.push({ id: "r-ix", from: "relay", to: "hk-hub", transport: "direct_wg", enabled: true, standby: false });
    t.links.push({ id: "g-ix", from: "gw", to: "hk-hub", transport: "direct_wg", enabled: true, standby: false });
    let saved: Topology | null = null;
    const api = fakeApi({
      "GET /api/topology": () => t,
      "POST /api/validate": () => ({ issues: [], paths: [] }),
      "PUT /api/topology": (req) => {
        saved = req.body as Topology;
        return { topology: saved, issues: [], paths: [], draft: false };
      },
    });
    const { unmount } = renderAt("#/topology/g-ix");
    await screen.findByTestId("link-detail");
    expect(screen.queryByRole("switch", { name: "连 IX 出口地址" })).toBeNull();
    unmount();
    renderAt("#/topology/r-ix");
    await userEvent.click(await screen.findByRole("switch", { name: "连 IX 出口地址" }));
    await userEvent.click(await screen.findByRole("button", { name: btn("保存") }));
    await waitFor(() => expect(api.find("PUT /api/topology")).toHaveLength(1));
    expect(saved!.links.find((l) => l.id === "r-ix")!.dial_egress).toBe(true);
    expect(saved!.links.find((l) => l.id === "g-ix")!.dial_egress).toBeUndefined();
  });
});
