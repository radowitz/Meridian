// Synthetic page data of real size (layout_pages.test.tsx, prose_budget.test.tsx):
// documentation address ranges and example names only.

import { panelStatus } from "./testing";
import type {
  UnlockMatrixView,
  CoverageItem,
  GroupActualView,
  GroupHubState,
  Node,
  ProbeCatalogEntry,
  ProbeResultRow,
  RegionGroupView,
  Rule,
  RuleSetView,
  Topology,
} from "./types";

export const NOW = "2026-11-12T10:00:00Z";
export const REGIONS = ["hk", "jp", "tw", "sg", "us", "my", "gb"];

// ------------------------------------------------------------- fixture ---

export function node(id: string, role: Node["role"], region: string, over: Partial<Node> = {}): Node {
  return {
    id,
    name: `${role}-${id}.example`,
    role,
    region,
    managed: role !== "ix",
    path_v4: true,
    path_v6: true,
    egress_v4: role === "exit",
    egress_v6: false,
    nat_dial_out: false,
    residential: false,
    ix_bound: false,
    ...over,
  };
}

/** 15 nodes: gateway, 2 relays, IX, primary + backup hub, 9 exits (only the gateway has a saved position). */
export function nodes(): Node[] {
  const exits = Array.from({ length: 9 }, (_, i) => node(`ex${i + 1}`, "exit", REGIONS[i % REGIONS.length], { name: `出口 ${i + 1} · 一个比较长的出口名字.example` }));
  return [
    node("gw", "gateway", "cn", { x: 0, y: 0 }),
    node("relay1", "relay", "cn"),
    node("relay2", "relay", "cn"),
    node("ix1", "ix", "hk"),
    node("hub1", "hub", "hk", { hub_tier: "primary" }),
    node("hub2", "hub", "hk", { hub_tier: "backup" }),
    ...exits,
  ];
}

export function rule(i: number): Rule {
  const id = `r${String(i).padStart(3, "0")}`;
  return {
    id,
    name: `规则 ${i} · service-${i}.example`,
    manual: i % 3 !== 0,
    origin: i % 5 === 0 ? "mihomo" : undefined,
    source_line: i % 5 === 0 ? i + 10 : undefined,
    source_text: i % 5 === 0 ? `DOMAIN-SUFFIX,service-${i}.example,Proxy` : undefined,
    priority: i * 10,
    enabled: true,
    overridden: false,
    match_type: i % 7 === 0 ? "ruleset" : "suffix",
    match_value: i % 7 === 0 ? "" : `service-${i}.with-a-rather-long-subdomain.example.net`,
    rule_set: i % 7 === 0 ? `rs${(i % 56) + 1}` : undefined,
    domains: i % 4 === 0 ? [`a-${i}.example.org`, `b-${i}.example.org`] : [],
    target_group: `g-${REGIONS[i % REGIONS.length]}`,
    mihomo_group: i % 11 === 0 ? `策略组 ${(i % 17) + 1}` : undefined,
    require_residential: i % 13 === 0,
    require_v6: false,
  };
}

export function topology(): Topology {
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
      default_group: "g-hk",
    } as Topology["settings"],
    nodes: nodes(),
    links: [],
    rules_ordered: true,
    rules: Array.from({ length: 165 }, (_, i) => rule(i + 1)),
    region_groups: REGIONS.map((r, i) => ({ id: `g-${r}`, name: `地区组 ${r.toUpperCase()} 机房`, region: r, members: [`ex${i + 1}`, `ex${i + 2}`].filter((x) => Number(x.slice(2)) <= 9), mode: i % 2 ? "manual" : "auto" })),
    rule_sets: Array.from({ length: 56 }, (_, i) => ({ id: `rs${i + 1}`, name: `RuleSet${i + 1}`, url: `https://rules.example.org/sets/very/long/path/RuleSet${i + 1}.list` })),
  } as Topology;
}

export function ruleSets(): RuleSetView[] {
  return Array.from({ length: 56 }, (_, i) => ({
    rule_set: { id: `rs${i + 1}`, name: `RuleSet${i + 1}`, url: `https://rules.example.org/sets/very/long/path/RuleSet${i + 1}.list` },
    status: { state: "ok", fetched_at: NOW, counts: { domain: 120 + i }, unsupported: i % 9 === 0 ? { "PROCESS-NAME": 3 } : undefined },
    used_by: [{ rule_id: `r${String(i + 1).padStart(3, "0")}`, name: `规则 ${i + 1}`, position: i + 1 }],
    candidates: [],
  })) as RuleSetView[];
}

export const RULES_API = {
  "GET /api/topology": () => topology(),
  "GET /api/rules/analysis": () => ({
    rules: [{ rule_id: "r002", entries: 3, shadowed: 3, fully_shadowed: true, shadowed_by: ["r001"] }],
    shared_address: "两个名字解析到同一个地址时，该地址按更靠前的规则走。",
    upgrade_notes: ["升级后，苹果的域名不再内置直连", "第二条升级说明"],
  }),
  "GET /api/rule-sets": () => ({ rule_sets: ruleSets(), formats: ["surge-list"] }),
  "POST /api/validate": () => ({ issues: [], paths: [] }),
};

export const NEVER_READ: GroupActualView = {
  state: "unavailable",
  code: "carrying_unknown",
  message: "不知道现在由哪个枢纽承载（网关还没有上游记录）；不把任一枢纽的报告当作实际使用",
  active: "",
  alert: false,
  last_switch: null,
  read_at: null,
  hub_reported_at: null,
  deployed_matches: null,
};

export function groupView(i: number): RegionGroupView {
  const r = REGIONS[i];
  const members = [`ex${i + 1}`, `ex${i + 2}`].filter((x) => Number(x.slice(2)) <= 9);
  return {
    id: `g-${r}`,
    name: `地区组 ${r.toUpperCase()} 机房一个很长的名字`,
    region: r,
    members,
    mode: i % 2 ? "manual" : "auto",
    is_default: i === 0,
    effective_order: members,
    target: members[0],
    target_reason: "preferred",
    switchable: true,
    switch_order: members,
    mesh_backup: false,
    member_status: members.map((m, k) => ({
      id: m,
      name: `出口 ${m}`,
      region: r,
      user_position: k,
      position: k,
      eligible: true,
      ix_bound: false,
      residential: false,
      egress_v6: false,
      reasons: [],
      target: k === 0,
      actual_active: false,
      model_active: false,
      health: null,
    })),
    actual: i === 0 ? { ...NEVER_READ, state: "stale", code: "heartbeat_old", message: "枢纽这个组的心跳已停 300 秒" } : NEVER_READ,
    model: { active: members[0], reason: "preferred", alert: false, last_switch: null, observed: false, source: "panel_model" },
    in_use_by: [],
  } as RegionGroupView;
}

export function hubState(): GroupHubState {
  return {
    hub_node: "hub1",
    hub_name: "hub1.example",
    server_id: "srv-hub",
    server_name: "枢纽服务器",
    readable: true,
    // Read a moment ago: the page does not read the hub again on open.
    last_read: { read_at: new Date().toISOString(), ok: true, clock_skew_sec: 0, ignored: [] },
    refreshing: false,
    loop_interval_sec: 5,
    stale_after_sec: 135,
    read_max_age_sec: 600,
    skew_warn_sec: 300,
    counts: {},
  } as GroupHubState;
}

export const GROUPS_API = {
  "GET /api/region-groups": () => ({
    groups: REGIONS.map((_, i) => groupView(i)),
    default_group: "g-hk",
    thresholds: { fails_need: 3, recovers_need: 3, cooldown_sec: 1800 },
    hub_state: hubState(),
  }),
};

export const CATALOG: ProbeCatalogEntry[] = Array.from({ length: 41 }, (_, i) => ({
  service: `svc-${i + 1}`,
  name: `服务 ${i + 1}`,
  reachability: i % 6 === 0,
  capability: i % 6 === 0 ? "reachability" : "region_verdict",
  basis: "公开方法（合成样本）",
  probeable: true,
  enabled: true,
  group: `g-${REGIONS[i % REGIONS.length]}`,
  group_mode: "auto",
})) as ProbeCatalogEntry[];

/** 9 exits in 5 region groups, 8 services, IPv4 only: 72 cells. */
export function results(): ProbeResultRow[] {
  const out: ProbeResultRow[] = [];
  const cats = ["unlocked", "not_unlocked", "network_ok", "unknown", "failed"] as const;
  for (let s = 0; s < 8; s++) {
    for (let e = 0; e < 9; e++) {
      const g = REGIONS[e % 5];
      out.push({
        service: `svc-${s + 1}`,
        service_name: `服务 ${s + 1}`,
        exit_id: `ex${e + 1}`,
        exit_name: `出口 ${e + 1} · 一个比较长的出口名字`,
        family: "ipv4",
        state: "done",
        category: cats[(s + e) % cats.length],
        grade: cats[(s + e) % cats.length] === "unknown" ? "unknown_response" : "platform_signal",
        exit_groups: [{ id: `g-${g}`, name: `地区组 ${g.toUpperCase()}`, mode: "auto", actual_active: "", model_active: "" }],
        is_active: false,
        expired: (s + e) % 4 === 0,
        ingestible: true,
        validation: "synthetic_only",
      } as ProbeResultRow);
    }
  }
  return out;
}

export function coverage(): CoverageItem[] {
  const sections = ["international", "hk", "tw", "jp", "sg", "us"];
  return Array.from({ length: 130 }, (_, i) => ({
    section: sections[i % sections.length],
    name: `项目 ${i + 1} · Example Streaming Service`,
    scripts: ["lmc999", "1-stream"],
    ...(i % 3 === 0 ? { reason: "login_required" } : { adapter: `svc-${(i % 41) + 1}` }),
    note: i % 3 === 0 ? undefined : "这一项的说明比较长，用来检查说明列是否在单元格里折行而不是把表格撑宽。",
  }));
}

/** The by-region matrix: 9 exits, 41 global services; one regional section per region. */
export function unlockMatrix(): UnlockMatrixView {
  const states = ["unlocked", "blocked", "local", "unverified", "untested"] as const;
  const exits = Array.from({ length: 9 }, (_, e) => ({
    id: `ex${e + 1}`,
    name: `出口 ${e + 1} · 一个比较长的出口名字`,
    regions: [REGIONS[e % 5]],
    groups: [`g-${REGIONS[e % 5]}`],
  }));
  const svc = (id: string, name: string, ex: typeof exits, k: number) => ({
    id,
    name,
    rules: k % 3 === 0 ? [id] : [],
    targets: [],
    cells: ex.map((e, j) => ({ exit_id: e.id, state: states[(k + j) % states.length], region: REGIONS[j % 5], reason: (k + j) % 5 === 3 ? "出口地址未确认" : undefined })),
    recommend: k % 2 === 0 ? { exit_id: ex[0].id, exit_name: ex[0].name, group: ex[0].groups[0], group_name: "地区组", adopted: k % 4 === 0 } : null,
  });
  return {
    running: "",
    available: true,
    regions: [
      { code: "global", name: "全球", exits, services: CATALOG.map((c, k) => svc(c.service, c.name, exits, k)) },
      ...REGIONS.slice(0, 5).map((r) => {
        const ex = exits.filter((e) => e.regions[0] === r);
        return { code: r, name: r.toUpperCase(), exits: ex, services: [svc(`${r}-tv`, `${r.toUpperCase()} TV`, ex, 2)] };
      }),
    ],
  };
}

export const UNLOCK_API = {
  "GET /api/unlock/matrix": () => unlockMatrix(),
  "GET /api/topology": () => topology(),
  "GET /api/status": () => panelStatus({ agent: { configured: true, ok: true }, probe_available: true } as never),
  "GET /api/unlock/catalog": () => ({ catalog: CATALOG, available: true, validation: "synthetic_only", validation_text: "合成样本", grades: [], ingest_rule: "", coverage: coverage(), reasons: { login_required: "需要登录" } }),
  "GET /api/unlock/jobs": () => ({ jobs: [], running: "", catalog: CATALOG, available: true }),
  "GET /api/unlock/results": () => ({ results: results(), validation: "synthetic_only", validation_text: "x" }),
  "GET /api/unlock": () => ({ services: [], states: {}, history: [], next_run: NOW, interval_sec: 21600, pending_apply: false, decisions: {}, owners: [] }),
  ...GROUPS_API,
};

