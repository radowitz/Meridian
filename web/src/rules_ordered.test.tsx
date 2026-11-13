// The explicit rule list (first match wins, top to bottom), the mihomo
// import flow, service groups, rule-sets and the rule tester.

import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { moveInList } from "./RulesPage";
import { fakeApi, renderAt, webStorageDump } from "./testing";
import type { ImportPreview, Rule, Topology } from "./types";

afterEach(() => {
  vi.restoreAllMocks();
  sessionStorage.clear();
  localStorage.clear();
});

function btn(text: string) {
  return new RegExp(`^\\s*${text.split("").join("\\s*")}\\s*$`);
}

function rule(id: string, over: Partial<Rule> = {}): Rule {
  return {
    id,
    name: id,
    manual: true,
    priority: 10,
    enabled: true,
    overridden: false,
    match_type: "suffix",
    match_value: `${id}.example.net`,
    target_group: "hk",
    require_residential: false,
    require_v6: false,
    ...over,
  };
}

function topo(over: Partial<Topology> = {}): Topology {
  return {
    settings: {
      draft: false,
      ix_replacement_mode: false,
      lan_interface: "eth0",
      gateway_lan_ipv4: "192.168.100.88/24",
      ros_ipv4: "192.168.100.1",
      ros_v6_lla: "fe80::1",
      lan_ipv6_prefix: "",
      ula_prefix: "fd66::/48",
      panel_bind: "192.168.100.88:8787",
      domestic_dot: [],
      transit_v4_prefix: "10.66.200.0/24",
      transit_v6_prefix: "fd66:0:0:ff::/64",
      default_group: "hk",
    } as Topology["settings"],
    nodes: [{ id: "us", name: "美国", role: "exit", region: "us" } as Topology["nodes"][number]],
    links: [],
    rules_ordered: true,
    rules: [
      rule("m1"),
      rule("auto-a", { manual: false, priority: 100 }),
      rule("imp", { manual: false, origin: "mihomo", source_line: 12, source_text: "DOMAIN-SUFFIX,imp.example.net,AI", target_group: undefined, target_service: "svc-ai" }),
    ],
    service_groups: [{ id: "svc-ai", name: "AI", target_group: "hk", origin: "mihomo" }],
    rule_sets: [],
    region_groups: [
      { id: "hk", name: "香港", region: "hk", members: [], mode: "auto" },
      { id: "us-g", name: "美国", region: "us", members: ["us"], mode: "auto" },
    ],
    ...over,
  };
}

const ORDERED_DEFAULTS = {
  "GET /api/rules/analysis": () => ({
    rules: [{ rule_id: "auto-a", entries: 1, shadowed: 1, fully_shadowed: true, shadowed_by: ["m1"] }],
    shared_address: "两个名字解析到同一个地址时，该地址按更靠前的规则走。",
  }),
  "GET /api/service-groups": () => ({ service_groups: [{ service_group: { id: "svc-ai", name: "AI", target_group: "hk", origin: "mihomo" }, used_by: [{ rule_id: "imp", name: "imp", position: 3 }] }] }),
  "GET /api/rule-sets": () => ({ rule_sets: [], formats: ["surge-list"] }),
};

describe("rules: one ordered list", () => {
  it("moveInList moves across manual, built-in and imported rules", () => {
    const rs = [rule("a"), rule("b", { manual: false }), rule("c", { origin: "mihomo" })];
    expect(moveInList(rs, "c", 0).map((r) => r.id)).toEqual(["c", "a", "b"]);
    expect(moveInList(rs, "a", 9).map((r) => r.id)).toEqual(["b", "c", "a"]);
  });

  it("moves a built-in rule above a manual one, shows origin, service target and shadowing, and saves the list order", async () => {
    let saved: Topology | undefined;
    const api = fakeApi({
      ...ORDERED_DEFAULTS,
      "GET /api/topology": () => topo(),
      "POST /api/validate": () => ({ issues: [], paths: [] }),
      "PUT /api/topology": (req) => {
        saved = req.body as Topology;
        return { topology: req.body, issues: [], paths: [], draft: false };
      },
    });
    renderAt("#/rules");
    expect(await screen.findByTestId("rules-order-note")).toHaveTextContent("第一条命中生效");
    const imp = await screen.findByTestId("rule-row-imp");
    expect(imp).toHaveTextContent("导入 · 第 12 行");
    expect(imp).toHaveTextContent("服务组");
    expect(imp).toHaveTextContent("AI → 地区组 香港");
    await waitFor(() => expect(screen.getByTestId("rule-shadow-auto-a")).toHaveTextContent("永远不会命中（被 第 1 条 遮蔽）"));
    const row = screen.getByTestId("rule-row-auto-a");
    fireEvent.click(within(row).getByRole("button", { name: "提前 auto-a" }));
    await waitFor(() => expect(screen.getByTestId("rule-pos-auto-a")).toHaveTextContent("1"));
    await userEvent.click(screen.getByRole("button", { name: btn("保存") }));
    await waitFor(() => expect(api.find("PUT /api/topology")).toHaveLength(1));
    expect(saved!.rules.map((r) => r.id)).toEqual(["auto-a", "m1", "imp"]);
  });

  it("retargets a service group through its endpoint", async () => {
    const api = fakeApi({
      ...ORDERED_DEFAULTS,
      "GET /api/topology": () => topo(),
      "PATCH /api/service-groups/:id": () => ({ service_group: { id: "svc-ai", name: "AI", target_group: "us-g" } }),
    });
    renderAt("#/rules");
    const box = await screen.findByRole("combobox", { name: "服务组 AI 指向" });
    fireEvent.mouseDown(box);
    const opt = await waitFor(() => {
      const el = [...document.querySelectorAll<HTMLElement>(".ant-select-dropdown:not(.ant-select-dropdown-hidden) .ant-select-item-option")].find((e) => e.textContent?.includes("地区组 美国"));
      if (!el) throw new Error("no option");
      return el;
    });
    fireEvent.click(opt);
    await waitFor(() => expect(api.find("PATCH /api/service-groups/svc-ai")).toHaveLength(1));
    expect(api.find("PATCH /api/service-groups/svc-ai")[0].body).toEqual({ target: "group:us-g" });
  });

  it("asks which rule matches a name", async () => {
    fakeApi({
      ...ORDERED_DEFAULTS,
      "GET /api/topology": () => topo(),
      "POST /api/rules/test": () => ({ reason: "域名后缀 m1.example.net", target: "group:hk", rule: { id: "m1", name: "m1", position: 1 } }),
    });
    renderAt("#/rules");
    await userEvent.type(await screen.findByLabelText("测试域名"), "x.m1.example.net");
    await userEvent.click(screen.getByRole("button", { name: btn("判断") }));
    expect(await screen.findByTestId("rule-test-result")).toHaveTextContent("第 1 条「m1」：域名后缀 m1.example.net → group:hk");
  });
});

describe("rules: import from mihomo", () => {
  const preview = (blocked: boolean): ImportPreview => ({
    rows: [
      { line: 3, text: "DOMAIN-SUFFIX,ai.example.net,AI", type: "DOMAIN-SUFFIX", action: "rule", match: "域名后缀 ai.example.net", target: { kind: "service", name: "AI", resolved: "group:us-g" }, status: "ok", diff: "new", position: 2, rule_id: "mh-1" },
      {
        line: 4,
        text: "DOMAIN-KEYWORD,vendor,AI",
        type: "DOMAIN-KEYWORD",
        action: "rule",
        flags: [{ code: "keyword_expanded", severity: "accept", message: "SmartDNS 不能按子串匹配域名", }],
        status: blocked ? "blocked" : "accepted",
        diff: "new",
      },
      { line: 5, text: "PROCESS-NAME,x.exe,DIRECT", type: "PROCESS-NAME", action: "unsupported", flags: [{ code: "unsupported_type", severity: "block", message: "网关看不到客户端的进程" }], status: "dropped" },
      { line: 6, text: "MATCH,Others", type: "MATCH", action: "match", status: "info" },
    ],
    mapping: [{ name: "LB-US P", kind: "line", suggestions: [{ value: "group:us-g", label: "地区组 美国" }], used_by: [3] }],
    services: [{ id: "svc-ai", name: "AI", chain: ["AI", "US", "LB-US P"], target: "group:us-g", pick: "US", pick_from: "selection", existing: true }],
    rule_sets: [],
    notes: ["导入的配置只读取 rules、rule-providers、proxy-groups 三段"],
    blocking: blocked ? 1 : 0,
    can_confirm: !blocked,
    digest: blocked ? "d1" : "d2",
    summary: blocked ? { ok: 1, blocked: 1 } : { ok: 1, accepted: 1 },
  });

  it("previews in order, needs the alternative accepted, confirms with the digest and keeps the config out of storage", async () => {
    const secretish = "password: fake-pass-in-paste";
    const api = fakeApi({
      ...ORDERED_DEFAULTS,
      "GET /api/topology": () => topo(),
      "POST /api/rules/import/preview": (req) => {
        const b = req.body as { accept?: Record<string, string[]> };
        return preview(!(b.accept?.["4"] ?? []).includes("keyword_expanded"));
      },
      "POST /api/rules/import/confirm": () => ({ imported: 2, services: 1, rule_sets: 0, default_group: "hk", digest: "d2" }),
    });
    renderAt("#/rules");
    await userEvent.click(await screen.findByRole("button", { name: btn("从 mihomo 导入") }));
    const drawer = await screen.findByRole("dialog");
    fireEvent.change(within(drawer).getByLabelText("mihomo 配置"), { target: { value: `proxies:\n  - {${secretish}}\nrules:\n  - MATCH,Others\n` } });
    await userEvent.click(within(drawer).getByRole("button", { name: btn("预览") }));
    const pv = await within(drawer).findByTestId("import-preview");
    expect(pv).toHaveTextContent("1 条阻止确认");
    expect(within(pv).getByTestId("import-row-3")).toHaveTextContent("服务组 AI（地区组 美国）");
    expect(within(drawer).getByRole("button", { name: btn("确认导入") })).toBeDisabled();
    await userEvent.click(within(drawer).getByRole("checkbox", { name: "接受 第4行 keyword_expanded" }));
    await userEvent.click(within(drawer).getByRole("button", { name: btn("刷新预览") }));
    await waitFor(() => expect(within(drawer).getByRole("button", { name: btn("确认导入") })).toBeEnabled());
    await userEvent.click(within(drawer).getByRole("button", { name: btn("确认导入") }));
    expect(await within(drawer).findByTestId("import-done")).toHaveTextContent("已写入 2 条规则");
    const confirm = api.find("POST /api/rules/import/confirm")[0].body as { digest: string; accept: Record<string, string[]> };
    expect(confirm.digest).toBe("d2");
    expect(confirm.accept["4"]).toEqual(["keyword_expanded"]);
    expect(webStorageDump()).not.toContain("fake-pass-in-paste");
  });
});

describe("rules: remaining gaps (accept by code, subscription credentials, move to N, upgrade difference)", () => {
  it("accepts every row of one code at once and sends accept_codes", async () => {
    const rowsFor = (accepted: boolean): ImportPreview => ({
      rows: [7, 8].map((line) => ({
        line,
        text: `RULE-SET,S${line},AI`,
        type: "RULE-SET",
        action: "rule" as const,
        flags: [{ code: "ruleset_partial", severity: "accept" as const, message: "规则集只部分生效", accepted }],
        status: accepted ? ("accepted" as const) : ("blocked" as const),
      })),
      mapping: [],
      services: [],
      rule_sets: [{ name: "S7", id: "rs-s7", url: "https://rules.example.org/s7.list", behavior: "classical", existing: false, state: "available", auth: "query" }],
      notes: [],
      blocking: accepted ? 0 : 2,
      can_confirm: accepted,
      digest: accepted ? "d-acc" : "d-blk",
      summary: accepted ? { accepted: 2 } : { blocked: 2 },
      accept_summary: [{ code: "ruleset_partial", class: "unsupported", lines: [7, 8], accepted: accepted ? 2 : 0, by_code: accepted }],
    });
    const api = fakeApi({
      ...ORDERED_DEFAULTS,
      "GET /api/topology": () => topo(),
      "POST /api/rules/import/preview": (req) => rowsFor(((req.body as { accept_codes?: string[] }).accept_codes ?? []).includes("ruleset_partial")),
    });
    renderAt("#/rules");
    await userEvent.click(await screen.findByRole("button", { name: btn("从 mihomo 导入") }));
    const drawer = await screen.findByRole("dialog");
    fireEvent.change(within(drawer).getByLabelText("mihomo 配置"), { target: { value: "rules:\n  - MATCH,AI\n" } });
    await userEvent.click(within(drawer).getByRole("button", { name: btn("预览") }));
    const codes = await within(drawer).findByTestId("accept-codes");
    expect(codes).toHaveTextContent("2 行：第 7、8 行");
    expect(within(drawer).getByText("订阅认证 query")).toBeTruthy();
    await userEvent.click(within(drawer).getByRole("checkbox", { name: "全部接受 ruleset_partial" }));
    // Each row still shows, ticked through the code.
    expect(within(drawer).getByRole("checkbox", { name: "接受 第7行 ruleset_partial" })).toBeChecked();
    await userEvent.click(within(drawer).getByRole("button", { name: btn("刷新预览") }));
    await waitFor(() => expect(within(drawer).getByRole("button", { name: btn("确认导入") })).toBeEnabled());
    const last = api.find("POST /api/rules/import/preview").at(-1)!.body as { accept_codes?: string[] };
    expect(last.accept_codes).toEqual(["ruleset_partial"]);
  });

  it("shows only the kind of a rule-set's credential, sets and clears it write-only", async () => {
    const token = "fake-ui-token-5150";
    const view = (auth: boolean) => ({
      rule_set: { id: "rs-p", name: "Private", url: "https://private.example.org/p.list" },
      status: { state: "ok" },
      used_by: [],
      candidates: [],
      auth: auth ? { kind: "bearer", secret_set: true } : null,
    });
    let has = true;
    const api = fakeApi({
      ...ORDERED_DEFAULTS,
      "GET /api/topology": () => topo(),
      "GET /api/rule-sets": () => ({ rule_sets: [view(has)], formats: [] }),
      "DELETE /api/rule-sets/:id/auth": () => {
        has = false;
        return view(false);
      },
      "PUT /api/rule-sets/:id/auth": () => {
        has = true;
        return view(true);
      },
    });
    renderAt("#/rules");
    expect(await screen.findByTestId("rs-auth-rs-p")).toHaveTextContent("Bearer 令牌（已设置）");
    await userEvent.click(screen.getByRole("button", { name: btn("清除认证") }));
    await waitFor(() => expect(api.find("DELETE /api/rule-sets/rs-p/auth")).toHaveLength(1));
    await userEvent.click(await screen.findByRole("button", { name: btn("设置认证") }));
    const dlg = await screen.findByRole("dialog");
    await userEvent.type(within(dlg).getByLabelText("订阅令牌"), token);
    await userEvent.click(within(dlg).getByRole("button", { name: btn("保存") }));
    await waitFor(() => expect(api.find("PUT /api/rule-sets/rs-p/auth")).toHaveLength(1));
    expect(api.find("PUT /api/rule-sets/rs-p/auth")[0].body).toEqual({ kind: "bearer", token });
    expect(webStorageDump()).not.toContain(token);
  });

  it("moves a rule to a typed position and shows the upgrade difference and DNS change notes", async () => {
    fakeApi({
      ...ORDERED_DEFAULTS,
      "GET /api/topology": () => topo(),
      "GET /api/rules/analysis": () => ({
        rules: [{ rule_id: "imp", entries: 1, shadowed: 0, fully_shadowed: false, legacy_lost: 1, legacy_lost_to: ["m1"] }],
        shared_address: "按更靠前的规则走。",
        upgrade_notes: ["升级后，苹果和各系统的联网检测域名不再内置直连"],
      }),
    });
    renderAt("#/rules");
    await waitFor(() => expect(screen.getByTestId("rule-shadow-imp")).toHaveTextContent("升级后变化：1 个名字以前按更长的名字归本条，现在被 第 1 条 先命中"));
    expect(screen.getByTestId("rules-upgrade-notes")).toHaveTextContent("联网检测域名不再内置直连");
    const row = screen.getByTestId("rule-row-imp");
    fireEvent.click(within(row).getByRole("button", { name: "移动 imp" }));
    fireEvent.click(await screen.findByText("移到第 N 条…"));
    const dlg = await screen.findByRole("dialog");
    const box = within(dlg).getByLabelText("目标位置");
    await userEvent.clear(box);
    await userEvent.type(box, "1");
    await userEvent.click(within(dlg).getByRole("button", { name: btn("移动") }));
    await waitFor(() => expect(screen.getByTestId("rule-pos-imp")).toHaveTextContent("1"));
  });
});

describe("rules: name sniffing", () => {
  it("shows what is decided by name and by address, saves the setting and lists recent decisions without names", async () => {
    const api = fakeApi({
      ...ORDERED_DEFAULTS,
      "GET /api/topology": () => topo(),
      "GET /api/sniff": () => ({
        setting: { enabled: true, ports: [80, 443], ech_public_names: ["cloudflare-ech.com"], record_names: false },
        listen_port: 5358,
        coverage: { by_name: ["嗅探端口上能读到名字的 TCP"], address_only: ["所有 UDP，包括 QUIC"], costs: ["ECH 公共名字的误差"] },
        runtime: {
          available: true,
          present: true,
          active: "active",
          health: { ready: true, mode: "redirect", listen: "[::]:5358", generation: 2, rules: 3, targets: ["group:hk"], mac_rules: false, mac_lookup: true, active: 1, max_conns: 2048, record_names: false, ech_outer: true, counters: { decided_by_name: 4, decided_by_address_no_sni: 1 } },
          recent: {
            record_names: false,
            connections: [
              { start: "2026-11-14T00:00:00Z", source: "192.168.100.50", dest: "203.0.113.1:443", proto: "tls", sniffed: true, rule_index: 0, rule_id: "m1", target: "group:hk", result: "ok", decide_ms: 3, generation: 2 },
              { start: "2026-11-14T00:00:01Z", source: "192.168.100.50", dest: "203.0.113.2:443", why: "no_sni", sniffed: false, rule_index: -1, target: "group:hk", result: "ok", decide_ms: 1, generation: 2 },
            ],
          },
        },
      }),
      "PUT /api/sniff": (r) => ({ setting: { ...(r.body as object), ports: [443] } }),
    });
    renderAt("#/rules");
    expect(await screen.findByTestId("sniff-coverage")).toHaveTextContent("所有 UDP，包括 QUIC");
    expect(screen.getByTestId("sniff-runtime")).toHaveTextContent("按名字 4 · 按地址 1");
    expect(await screen.findByText("没有 SNI")).toBeInTheDocument();
    await userEvent.clear(screen.getByLabelText("嗅探端口"));
    await userEvent.type(screen.getByLabelText("嗅探端口"), "443");
    await userEvent.click(screen.getByRole("button", { name: btn("保存设置") }));
    await waitFor(() => expect(api.find("PUT /api/sniff")).toHaveLength(1));
    expect(api.find("PUT /api/sniff")[0].body).toEqual({ enabled: true, ports: [443], ech_public_names: ["cloudflare-ech.com"], record_names: false });
  });

  it("sends the device MAC to the rule tester", async () => {
    const api = fakeApi({
      ...ORDERED_DEFAULTS,
      "GET /api/topology": () => topo(),
      "POST /api/rules/test": () => ({ reason: "域名后缀", target: "group:hk" }),
    });
    renderAt("#/rules");
    await userEvent.type(await screen.findByLabelText("测试域名"), "x.m1.example.net");
    await userEvent.type(screen.getByLabelText("测试设备 MAC"), "02:00:00:00:00:01");
    await userEvent.click(screen.getByRole("button", { name: btn("判断") }));
    await waitFor(() => expect(api.find("POST /api/rules/test")).toHaveLength(1));
    expect(api.find("POST /api/rules/test")[0].body).toEqual({ name: "x.m1.example.net", address: "", source_mac: "02:00:00:00:00:01" });
  });
});
