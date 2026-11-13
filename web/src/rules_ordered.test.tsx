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
