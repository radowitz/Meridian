// 分流规则: which traffic goes where, in priority order. A rule points at
// exactly one target: a region group (switching behaviour lives on the
// group) or one pinned exit. Rules are part of the topology document, so the
// page edits the working copy and saves through the document bar.

import {
  ArrowDownOutlined,
  ArrowUpOutlined,
  DeleteOutlined,
  EditOutlined,
  EllipsisOutlined,
  PlusOutlined,
  SearchOutlined,
  VerticalAlignBottomOutlined,
  VerticalAlignTopOutlined,
} from "@ant-design/icons";
import {
  Alert,
  Button,
  Checkbox,
  Collapse,
  Drawer,
  Dropdown,
  Form,
  Input,
  InputNumber,
  Modal,
  Radio,
  Select,
  Space,
  Switch,
  Table,
  Tag,
  Tooltip,
  Typography,
} from "antd";
import { useEffect, useMemo, useState } from "react";
import * as api from "./api";
import { ImportDrawer, RuleSetsSection, RuleTester, ServiceGroupsSection, specLabel } from "./RulesImport";
import { href, useRouter, useTopologyDoc } from "./state";
import type { Issue, Rule, RuleAnalysis, Topology } from "./types";
import { ApiErrorAlert, EmptyState, IssueList, Link, Page, StatusTag, TABLE_SCROLL, TopologyDocBar, groupLabel, isDuplicateGroupName, regionLabel, useConfirmDanger } from "./ui";

export const MATCH_TYPES: { value: string; label: string; help: string; placeholder: string }[] = [
  { value: "domain", label: "完整域名", help: "只匹配这个域名本身。", placeholder: "api.example.com" },
  { value: "suffix", label: "域名后缀", help: "匹配这个域名和它的所有子域名。", placeholder: "example.com" },
  { value: "keyword", label: "域名关键词", help: "网关上只匹配已下载的 geosite 名单里含这个词的域名（SmartDNS 不能按子串匹配，名单之外的域名不会命中）。", placeholder: "netflix" },
  { value: "geosite", label: "geosite 名单", help: "使用「名单」页下载的 geosite 分类；下载之前只用下面的显式域名。", placeholder: "netflix" },
  { value: "cidr", label: "IP / CIDR", help: "目的地址或网段。", placeholder: "203.0.113.0/24" },
  { value: "geoip", label: "geoip", help: "只有 CN 会写入数据面（中国地址名单 chnroute）；其它国家没有数据源，这一期不会写入数据面，流量会落到后面的策略。", placeholder: "cn" },
  { value: "asn", label: "ASN", help: "这一期不会写入数据面：不按 ASN 分流，流量会落到后面的策略。", placeholder: "AS13335" },
  { value: "ruleset", label: "规则集", help: "使用下面「规则集」里订阅的规则集；它的全部条目都在这一条的位置匹配（和 Clash 的 RULE-SET 一样）。", placeholder: "" },
  { value: "quic_reject", label: "QUIC 开关", help: "这一行之下的规则和默认组：走隧道的 UDP 443 被拒绝（客户端立即改用 TCP）；之上的规则豁免；直连不受影响。", placeholder: "" },
];
const MATCH_LABEL = Object.fromEntries(MATCH_TYPES.map((m) => [m.value, m.label]));

/** Where a validation issue of a rule belongs in the form. */
const ISSUE_FIELD: Record<string, string> = {
  residential_required: "require_residential",
  constraint_conflict: "require_v6",
  rule_target_conflict: "target",
  group_not_found: "target",
  exit_not_found: "target",
  bad_domain: "match_value",
  bad_keyword: "match_value",
  bad_address: "match_value",
  rule_mode_removed: "target",
  legacy_pool_target: "target",
};

function cleanRule(r: Rule): Rule {
  // No per-rule mode exists any more, and a rule has exactly one target.
  const { mode: _m, target_pool: _p, ...rest } = r;
  void _m;
  void _p;
  const out: Rule = { ...rest };
  if (out.target_group) delete out.target_exit;
  else delete out.target_group;
  return out;
}

function targetOf(t: Topology, r: Rule) {
  if (r.match_type === "quic_reject") return { kind: "quic" as const, id: "", name: "UDP 443 拒绝开关", missing: false };
  if (r.target_action) return { kind: r.target_action, id: "", name: r.target_action === "direct" ? "直连" : "拒绝", missing: false };
  if (r.target_service) {
    const sg = (t.service_groups ?? []).find((x) => x.id === r.target_service);
    const spec = sg ? (sg.target_action ?? (sg.target_group ? `group:${sg.target_group}` : sg.target_exit ? `exit:${sg.target_exit}` : "")) : "";
    return { kind: "service" as const, id: r.target_service, name: sg ? `${sg.name} → ${specLabel(t, spec)}` : r.target_service, missing: !sg };
  }
  if (r.target_exit) {
    const n = t.nodes.find((x) => x.id === r.target_exit);
    return { kind: "exit" as const, id: r.target_exit, name: n?.name ?? r.target_exit, missing: !n };
  }
  const g = (t.region_groups ?? []).find((x) => x.id === r.target_group);
  return { kind: "group" as const, id: r.target_group ?? "", name: g ? groupLabel(g, t.region_groups) : r.target_group ?? "—", missing: !g, mode: g?.mode };
}

// ------------------------------------------------------------- ordering ---

/**
 * The order the compiler matches rules in (internal/compile planRules):
 * every manual rule before every built-in rule, then ascending priority,
 * then ID. The page shows exactly this order.
 */
export function effectiveOrder(rules: Rule[]): Rule[] {
  return [...rules].sort((a, b) => (a.manual === b.manual ? 0 : a.manual ? -1 : 1) || a.priority - b.priority || a.id.localeCompare(b.id));
}

/** Moves rule id to position to in an explicit (ordered) list. */
export function moveInList(rules: Rule[], id: string, to: number): Rule[] {
  const from = rules.findIndex((r) => r.id === id);
  if (from < 0) return rules;
  const dest = Math.max(0, Math.min(rules.length - 1, to));
  const out = rules.filter((r) => r.id !== id);
  out.splice(dest, 0, rules[from]);
  return out;
}

/** Lowest priority number a rule of this class may get: manual ≥ 1, built-in above every manual one. */
function classFloor(rules: Rule[], manual: boolean) {
  if (manual) return 1;
  return Math.max(1, ...rules.filter((r) => r.manual).map((r) => r.priority + 1));
}

/**
 * Moves rule `id` to position `to` within its own class (manual or
 * built-in: the compiler always puts manual rules first, so a rule cannot
 * cross into the other class). Only the moved rule gets a new priority when
 * its new neighbours leave room for one; otherwise the whole class is
 * renumbered in the shown order, in steps of 10 from the class's base (10
 * for manual, the lowest built-in number for built-in). Built-in rules whose
 * number changed are marked 已改默认. The array order is kept.
 */
export function moveRule(rules: Rule[], id: string, to: number): Rule[] {
  const r = rules.find((x) => x.id === id);
  if (!r) return rules;
  const cls = effectiveOrder(rules).filter((x) => x.manual === r.manual);
  const from = cls.findIndex((x) => x.id === id);
  const dest = Math.max(0, Math.min(cls.length - 1, to));
  if (dest === from) return rules;
  const order = cls.filter((x) => x.id !== id);
  order.splice(dest, 0, r);
  const floor = classFloor(rules, r.manual);
  const prev = order[dest - 1]?.priority;
  const next = order[dest + 1]?.priority;
  let p: number | null = null;
  if (prev === undefined && next !== undefined) p = next - floor >= 1 ? Math.max(floor, next - 10) : null;
  else if (next === undefined && prev !== undefined) p = prev + 10;
  else if (prev !== undefined && next !== undefined) p = next - prev >= 2 ? prev + Math.floor((next - prev) / 2) : null;
  const want = new Map<string, number>();
  const strictly = (ps: number[]) => ps.every((v, i) => i === 0 || v > ps[i - 1]);
  if (p !== null && strictly(order.map((x) => (x.id === id ? p! : x.priority)))) {
    want.set(id, p);
  } else {
    const base = r.manual ? 10 : Math.max(floor, Math.min(...cls.map((x) => x.priority)));
    const start = Math.ceil(base / 10) * 10;
    order.forEach((x, i) => want.set(x.id, start + i * 10));
  }
  return rules.map((x) => {
    const np = want.get(x.id);
    if (np === undefined || np === x.priority) return x;
    return { ...x, priority: np, overridden: x.manual ? x.overridden : true };
  });
}

/** Priority for a new manual rule: at the top of the manual rules. */
function topManualPriority(rules: Rule[]) {
  const manual = rules.filter((r) => r.manual).map((r) => r.priority);
  if (manual.length === 0) return 10;
  const min = Math.min(...manual);
  return min > 1 ? Math.max(1, min - 10) : null;
}

// --------------------------------------------------------------- drawer ---

function initialTarget(rule: Rule | null): "group" | "exit" | "service" | "direct" | "reject" {
  if (!rule) return "group";
  if (rule.target_action) return rule.target_action;
  if (rule.target_service) return "service";
  return rule.target_exit ? "exit" : "group";
}

interface FormValues {
  name: string;
  match_type: string;
  match_value: string;
  domains: string[];
  target: "group" | "exit" | "service" | "direct" | "reject";
  target_group?: string;
  target_exit?: string;
  target_service?: string;
  rule_set?: string;
  insert_at?: number;
  require_residential: boolean;
  require_v6: boolean;
  source_mac?: string;
  source_ipv4?: string;
  source_ipv6?: string;
  notes?: string;
}

function RuleDrawer({
  open,
  rule,
  topo,
  onClose,
  onApply,
}: {
  open: boolean;
  rule: Rule | null;
  topo: Topology;
  onClose: () => void;
  onApply: (r: Rule, insertAt?: number) => void;
}) {
  const [form] = Form.useForm<FormValues>();
  const [checking, setChecking] = useState(false);
  const [problems, setProblems] = useState<Issue[] | null>(null);
  const [checkError, setCheckError] = useState<api.ApiError | null>(null);
  const target = Form.useWatch("target", form) ?? initialTarget(rule);
  const matchType = Form.useWatch("match_type", form) ?? rule?.match_type ?? "domain";
  const mt = MATCH_TYPES.find((m) => m.value === matchType);
  const groups = topo.region_groups ?? [];
  const exits = topo.nodes.filter((n) => n.role === "exit");

  useEffect(() => {
    if (open) {
      setProblems(null);
      setCheckError(null);
    }
  }, [open]);

  const initial: FormValues = rule
    ? {
        name: rule.name,
        match_type: rule.match_type,
        match_value: rule.match_value,
        domains: rule.domains ?? [],
        target: initialTarget(rule),
        target_group: rule.target_group,
        target_exit: rule.target_exit,
        target_service: rule.target_service,
        rule_set: rule.rule_set,
        require_residential: rule.require_residential,
        require_v6: rule.require_v6,
        source_mac: rule.source_mac,
        source_ipv4: rule.source_ipv4,
        source_ipv6: rule.source_ipv6,
        notes: rule.notes,
      }
    : {
        name: "",
        match_type: "domain",
        match_value: "",
        domains: [],
        target: "group",
        target_group: topo.settings.default_group || groups[0]?.id,
        require_residential: false,
        require_v6: false,
        insert_at: 1,
      };

  function build(v: FormValues): Rule {
    const manualIDs = new Set(topo.rules.map((r) => r.id));
    let id = rule?.id;
    if (!id) {
      const base = `manual-${(v.match_value || v.name).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 32) || "rule"}`;
      id = base;
      for (let i = 2; manualIDs.has(id); i++) id = `${base}-${i}`;
    }
    const value = v.match_value.trim();
    let domains = (v.domains ?? []).map((d) => d.trim().replace(/^\./, "")).filter(Boolean);
    // Explicit names match the name and everything under it; in an explicit
    // (ordered) list a "完整域名" rule stays exact, so its value is not added.
    if ((v.match_type === "suffix" || (v.match_type === "domain" && !topo.rules_ordered)) && value && !domains.includes(value.replace(/^\./, ""))) {
      domains = [value.replace(/^\./, ""), ...domains];
    }
    const base: Rule = rule ?? {
      id,
      name: "",
      manual: true,
      // Placed at the top of the manual rules; RulesPage renumbers when there is no room.
      priority: topManualPriority(topo.rules) ?? 0,
      enabled: true,
      overridden: false,
      match_type: "domain",
      match_value: "",
      require_residential: false,
      require_v6: false,
    };
    const out: Rule = {
      ...base,
      name: v.name.trim(),
      match_type: v.match_type,
      match_value: v.match_type === "geosite" ? value.replace(/^geosite:/, "") : value,
      domains,
      geosite: v.match_type === "geosite" ? value.replace(/^geosite:/, "") : undefined,
      require_residential: !!v.require_residential,
      require_v6: !!v.require_v6,
      source_mac: v.source_mac?.trim() || undefined,
      source_ipv4: v.source_ipv4?.trim() || undefined,
      source_ipv6: v.source_ipv6?.trim() || undefined,
      notes: v.notes?.trim() || undefined,
      target_group: v.target === "group" ? v.target_group : undefined,
      target_exit: v.target === "exit" ? v.target_exit : undefined,
      target_service: v.target === "service" ? v.target_service : undefined,
      target_action: v.target === "direct" || v.target === "reject" ? v.target : undefined,
      rule_set: v.match_type === "ruleset" ? v.rule_set : undefined,
      overridden: base.manual ? base.overridden : true,
    };
    if (v.match_type === "ruleset" || v.match_type === "quic_reject") out.match_value = "";
    if (v.match_type === "quic_reject") {
      delete out.target_group;
      delete out.target_exit;
      delete out.target_service;
      delete out.target_action;
    }
    for (const k of ["target_service", "target_action", "rule_set"] as const) if (!out[k]) delete out[k];
    if (!out.geosite) delete out.geosite;
    return cleanRule(out);
  }

  async function submit(force: boolean) {
    let v: FormValues;
    try {
      v = await form.validateFields();
    } catch {
      return;
    }
    const r = build(v);
    if (force) {
      onApply(r, v.insert_at);
      return;
    }
    // Check the candidate document; put this rule's errors on its fields.
    const candidate: Topology = { ...topo, rules: rule ? topo.rules.map((x) => (x.id === rule.id ? r : x)) : [...topo.rules, r] };
    setChecking(true);
    setCheckError(null);
    try {
      const res = await api.validate(candidate);
      const mine = (res.issues ?? []).filter((i) => i.rule_id === r.id);
      const errors = mine.filter((i) => i.severity === "error");
      if (errors.length === 0) {
        onApply(r, v.insert_at);
        return;
      }
      setProblems(mine);
      form.setFields(
        errors.map((i) => {
          const f = ISSUE_FIELD[i.code] ?? "match_value";
          const name = (f === "target" ? (v.target === "exit" ? "target_exit" : "target_group") : f) as keyof FormValues;
          return { name, errors: [i.message] };
        }),
      );
    } catch (e) {
      setCheckError(e instanceof api.ApiError ? e : new api.ApiError(0, {}));
    } finally {
      setChecking(false);
    }
  }

  const errors = problems?.filter((i) => i.severity === "error") ?? [];
  const warnings = problems?.filter((i) => i.severity !== "error") ?? [];

  return (
    <Drawer
      title={rule ? `编辑规则「${rule.name}」` : "添加规则"}
      open={open}
      onClose={onClose}
      width={560}
      destroyOnHidden
      footer={
        <Space wrap>
          <Button onClick={onClose}>取消</Button>
          {errors.length > 0 ? (
            <Tooltip title="规则先放进工作副本；拓扑有错误时只能保存为草稿，不能安装。">
              <Button onClick={() => void submit(true)}>仍然放入（草稿）</Button>
            </Tooltip>
          ) : null}
          <Button type="primary" loading={checking} onClick={() => void submit(false)}>
            {rule ? "应用修改" : "添加"}
          </Button>
        </Space>
      }
    >
      <Alert
        type="info"
        showIcon
        style={{ marginBottom: 16 }}
        message="修改先进入拓扑的工作副本；点页面顶部的「保存」后写入，安装后才在网关生效。"
      />
      {checkError ? <ApiErrorAlert error={checkError} /> : null}
      {errors.length > 0 ? (
        <Alert type="error" showIcon style={{ marginBottom: 16 }} message={`这条规则有 ${errors.length} 个问题，已标在对应字段上`} />
      ) : null}
      {warnings.length > 0 ? <IssueList issues={warnings} /> : null}
      <Form form={form} layout="vertical" initialValues={initial} requiredMark="optional" autoComplete="off" style={{ marginTop: warnings.length ? 12 : 0 }}>
        <Form.Item name="name" label="名称" rules={[{ required: true, message: "请填写名称" }]}>
          <Input placeholder="例如 公司 API" />
        </Form.Item>
        <Space.Compact block>
          <Form.Item name="match_type" label="匹配方式" style={{ width: 170 }}>
            <Select options={MATCH_TYPES.map((m) => ({ value: m.value, label: m.label }))} aria-label="匹配方式" />
          </Form.Item>
          {matchType === "ruleset" ? (
            <Form.Item name="rule_set" label="规则集" style={{ flex: 1 }} rules={[{ required: true, message: "选择一个规则集" }]} extra={mt?.help}>
              <Select aria-label="规则集" options={(topo.rule_sets ?? []).map((x) => ({ value: x.id, label: x.name }))} placeholder="先在下方「规则集」里按 URL 添加" />
            </Form.Item>
          ) : matchType === "quic_reject" ? (
            <Form.Item label=" " style={{ flex: 1 }} extra={mt?.help}>
              <Typography.Text type="secondary">没有匹配值，也没有去向。</Typography.Text>
            </Form.Item>
          ) : (
            <Form.Item name="match_value" label="匹配值" style={{ flex: 1 }} rules={[{ required: true, message: "请填写匹配值" }]} extra={mt?.help}>
              <Input className="mono" placeholder={mt?.placeholder} aria-label="匹配值" />
            </Form.Item>
          )}
        </Space.Compact>
        {!rule && topo.rules_ordered ? (
          <Form.Item name="insert_at" label="放在第几条" extra="列表从上到下匹配，第一条命中生效。">
            <InputNumber min={1} max={topo.rules.length + 1} aria-label="放在第几条" />
          </Form.Item>
        ) : null}
        <Form.Item
          name="domains"
          label="显式域名"
          extra="总是写入解析器的域名（名单还没下载时也生效）。完整域名和后缀会自动加入。"
        >
          <Select mode="tags" tokenSeparators={[",", " "]} placeholder="例如 example.com" aria-label="显式域名" />
        </Form.Item>

        <Form.Item name="target" label="去向" extra={<span>切换方式（自动 / 手动、失败时怎么办）在 <Link to={href("exits")}>地区组</Link> 上设置，规则不重复设置。</span>}>
          <Radio.Group>
            <Space direction="vertical">
              <Radio value="group">
                地区组 <Typography.Text type="secondary">— 跟随组的模式、顺序和故障切换</Typography.Text>
              </Radio>
              <Radio value="exit">
                固定出口 <Typography.Text type="secondary">— 只用这一个出口，不受健康状态或解锁结果影响</Typography.Text>
              </Radio>
              {topo.rules_ordered ? (
                <>
                  <Radio value="service">
                    服务组 <Typography.Text type="secondary">— 可切换的指向，改服务组不必改规则</Typography.Text>
                  </Radio>
                  <Radio value="direct">
                    直连 <Typography.Text type="secondary">— 国内解析器解析，直连出去</Typography.Text>
                  </Radio>
                  <Radio value="reject">
                    拒绝 <Typography.Text type="secondary">— 照常解析（只给 IPv4），连接被网关立即拒绝：TCP 复位，其它返回 ICMP 端口不可达</Typography.Text>
                  </Radio>
                </>
              ) : null}
            </Space>
          </Radio.Group>
        </Form.Item>
        {target === "direct" || target === "reject" || matchType === "quic_reject" ? null : target === "service" ? (
          <Form.Item name="target_service" label="服务组" rules={[{ required: true, message: "选择一个服务组" }]}>
            <Select aria-label="服务组" options={(topo.service_groups ?? []).map((x) => ({ value: x.id, label: x.name }))} />
          </Form.Item>
        ) : target === "group" ? (
          <Form.Item name="target_group" label="地区组" rules={[{ required: true, message: "选择一个地区组" }]}>
            <Select
              aria-label="地区组"
              options={groups.map((g) => ({
                value: g.id,
                label: `${g.name}（${regionLabel(g.region)}${isDuplicateGroupName(g, groups) ? ` · ${g.id}` : ""} · ${g.mode === "manual" ? "手动" : "自动"}${g.require_residential ? " · 住宅" : ""}${g.require_v6 ? " · IPv6" : ""}）`,
              }))}
            />
          </Form.Item>
        ) : (
          <Form.Item name="target_exit" label="出口" rules={[{ required: true, message: "选择一个出口" }]}>
            <Select
              aria-label="出口"
              showSearch
              optionFilterProp="label"
              options={exits.map((n) => ({
                value: n.id,
                label: `${n.name}（${n.id} · ${regionLabel(n.region)}${n.residential ? " · 住宅" : ""}${n.egress_v6 ? " · IPv6" : ""}）`,
              }))}
            />
          </Form.Item>
        )}
        <Typography.Text>要求</Typography.Text>
        <Typography.Paragraph type="secondary" style={{ fontSize: 12, margin: "2px 0 6px" }}>
          这是对去向的断言，不是第二处配置：指向的组必须带有相同约束，固定的出口必须满足它，否则校验不通过。
        </Typography.Paragraph>
        <Form.Item name="require_residential" valuePropName="checked" style={{ marginBottom: 4 }}>
          <Checkbox>必须走住宅（家宽）出口</Checkbox>
        </Form.Item>
        <Form.Item name="require_v6" valuePropName="checked">
          <Checkbox>必须有 IPv6 出口</Checkbox>
        </Form.Item>
        <Collapse
          ghost
          items={[
            {
              key: "src",
              label: "只对某台设备生效（可选）",
              children: (
                <>
                  <Typography.Paragraph type="secondary" style={{ fontSize: 12 }}>
                    按设备匹配和目的地址同时生效；其他设备访问同一地址时不套用这条规则。
                  </Typography.Paragraph>
                  <Form.Item name="source_mac" label="源 MAC">
                    <Input className="mono" placeholder="aa:bb:cc:dd:ee:ff" />
                  </Form.Item>
                  <Form.Item name="source_ipv4" label="源 IPv4">
                    <Input className="mono" placeholder="192.168.100.20" />
                  </Form.Item>
                  <Form.Item name="source_ipv6" label="源 IPv6">
                    <Input className="mono" />
                  </Form.Item>
                </>
              ),
            },
          ]}
        />
        <Form.Item name="notes" label="备注">
          <Input.TextArea rows={2} />
        </Form.Item>
      </Form>
    </Drawer>
  );
}

// ------------------------------------------------------------------ page ---

export default function RulesPage() {
  const doc = useTopologyDoc();
  const { route, navigate } = useRouter();
  const confirm = useConfirmDanger();
  const [editing, setEditing] = useState<Rule | "new" | null>(null);
  const [q, setQ] = useState("");
  const [kind, setKind] = useState<"all" | "manual" | "auto">("all");
  const [importing, setImporting] = useState(false);
  const [analysis, setAnalysis] = useState<Map<string, RuleAnalysis>>(new Map());
  const [sharedNote, setSharedNote] = useState("");
  const [upgradeNotes, setUpgradeNotes] = useState<string[]>([]);
  const [moveTo, setMoveTo] = useState<{ rule: Rule; to: number } | null>(null);
  const topo = doc.topo;
  const focus = route.params[0];
  const ordered = !!topo?.rules_ordered;

  // The static ordering analysis of the saved list (shadowing, keyword and
  // rule-set notes); only for the explicit list and a saved document.
  useEffect(() => {
    if (!ordered || doc.dirty) return;
    let live = true;
    api
      .ruleAnalysis()
      .then((r) => {
        if (!live) return;
        setAnalysis(new Map(r.rules.map((a) => [a.rule_id, a])));
        setSharedNote(r.shared_address);
        setUpgradeNotes(r.upgrade_notes ?? []);
      })
      .catch(() => undefined);
    return () => {
      live = false;
    };
  }, [ordered, doc.dirty, topo]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (!topo || !focus) return;
    const r = topo.rules.find((x) => x.id === focus);
    if (r) setEditing(r);
  }, [focus, topo === null]); // eslint-disable-line react-hooks/exhaustive-deps

  const issuesByRule = useMemo(() => {
    const m = new Map<string, Issue[]>();
    for (const i of doc.issues) if (i.rule_id) m.set(i.rule_id, [...(m.get(i.rule_id) ?? []), i]);
    return m;
  }, [doc.issues]);

  if (!topo) {
    return (
      <Page title="分流规则">
        {doc.error ? <ApiErrorAlert error={doc.error} onRetry={() => void doc.reload()} /> : <Typography.Text type="secondary">读取中…</Typography.Text>}
      </Page>
    );
  }

  const sorted = ordered ? topo.rules : effectiveOrder(topo.rules);
  const manualCount = topo.rules.filter((r) => r.manual).length;
  const shown = sorted.filter((r) => {
    if (kind === "manual" && !r.manual) return false;
    if (kind === "auto" && r.manual) return false;
    if (!q) return true;
    const hay = [r.name, r.id, r.match_value, r.geosite, ...(r.domains ?? []), r.target_group, r.target_exit].join(" ").toLowerCase();
    return hay.includes(q.toLowerCase());
  });

  const setRules = (rules: Rule[]) => doc.setTopo({ ...topo, rules: rules.map(cleanRule) });
  const patch = (id: string, p: Partial<Rule>) =>
    setRules(topo.rules.map((r) => (r.id === id ? { ...r, ...p, overridden: r.manual ? r.overridden : true } : r)));
  /** Position of r within its class (manual rules, then built-in rules); the whole list once it is explicit. */
  const classIndex = (r: Rule) => (ordered ? sorted.findIndex((x) => x.id === r.id) : sorted.filter((x) => x.manual === r.manual).findIndex((x) => x.id === r.id));
  const classSize = (r: Rule) => (ordered ? topo.rules.length : r.manual ? manualCount : topo.rules.length - manualCount);
  const move = (r: Rule, to: number) => setRules(ordered ? moveInList(topo.rules, r.id, to) : moveRule(topo.rules, r.id, to));
  const byID = new Map(sorted.map((r, i) => [r.id, i + 1]));

  return (
    <Page
      title="分流规则"
      description="按优先级从上到下匹配，第一条命中的规则决定去向；没有命中的境外流量走默认组。规则是拓扑的一部分，保存后安装才生效。"
      extra={
        <Space>
          {ordered ? (
            <Tooltip title={doc.dirty ? "先保存或放弃当前修改" : "粘贴 mihomo 配置，预览后导入"}>
              <Button disabled={doc.dirty} onClick={() => setImporting(true)}>
                从 mihomo 导入
              </Button>
            </Tooltip>
          ) : null}
          {ordered && !topo.rules.some((r) => r.match_type === "quic_reject") ? (
            <Tooltip title="在列表末尾加一行 QUIC 开关；它之上的规则豁免，把它移到需要的位置">
              <Button
                onClick={() =>
                  setRules([
                    ...topo.rules,
                    { id: "quic-switch", name: "QUIC 开关", manual: true, priority: 0, enabled: true, overridden: false, match_type: "quic_reject", match_value: "", require_residential: false, require_v6: false },
                  ])
                }
              >
                添加 QUIC 开关
              </Button>
            </Tooltip>
          ) : null}
          {ordered && !topo.rules.some((r) => r.id === "template-apple-direct") ? (
            <Tooltip title="可选模板：geosite apple → 直连。默认不启用；苹果的名字不是国内名字，只有你确定要直连时才启用。">
              <Button
                onClick={() =>
                  setRules([
                    ...topo.rules,
                    { id: "template-apple-direct", name: "模板：Apple 直连（未启用）", manual: true, priority: 0, enabled: false, overridden: false, match_type: "geosite", match_value: "apple", geosite: "apple", target_action: "direct", require_residential: false, require_v6: false },
                  ])
                }
              >
                Apple 直连模板
              </Button>
            </Tooltip>
          ) : null}
          <Button type="primary" icon={<PlusOutlined />} onClick={() => setEditing("new")}>
            添加规则
          </Button>
        </Space>
      }
    >
      <TopologyDocBar />
      <Space wrap style={{ marginBottom: 12 }}>
        <Input
          allowClear
          prefix={<SearchOutlined />}
          placeholder="搜索名称、域名或去向"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          style={{ width: 260 }}
          aria-label="搜索规则"
        />
        <Radio.Group
          optionType="button"
          value={kind}
          onChange={(e) => setKind(e.target.value)}
          options={[
            { value: "all", label: `全部 ${topo.rules.length}` },
            { value: "manual", label: `手动 ${topo.rules.filter((r) => r.manual).length}` },
            { value: "auto", label: `内置 ${topo.rules.filter((r) => !r.manual).length}` },
          ]}
        />
        <Typography.Text type="secondary">
          默认组：
          {topo.settings.default_group ? (
            <Link to={href("exits", topo.settings.default_group)}>
              {(() => {
                const g = (topo.region_groups ?? []).find((x) => x.id === topo.settings.default_group);
                return g ? groupLabel(g, topo.region_groups) : topo.settings.default_group;
              })()}
            </Link>
          ) : (
            "未设置"
          )}
        </Typography.Text>
      </Space>
      {topo.rules.length > 0 && ordered ? (
        <Typography.Paragraph type="secondary" style={{ fontSize: 12 }} data-testid="rules-order-note">
          表格就是匹配顺序，和 Clash / Surge 一样从上到下、第一条命中生效；手动、导入、内置规则在同一个列表里，可以任意上下移动。所有规则之后依次是：内置国内名单（geosite cn，国内解析、直连）、中国地址直连（chnroute）、默认组。网关按解析出的目的地址分流：两个指向不同目标的名字解析到同一个地址时，该地址按更靠前的规则走。
        </Typography.Paragraph>
      ) : null}
      {topo.rules.length > 0 && !ordered ? (
        <Typography.Paragraph type="secondary" style={{ fontSize: 12 }}>
          表格就是匹配顺序：手动规则总是排在内置规则前面，各自按优先级排。上下箭头和「…」里的移到最前 / 最后只在同一类里移动；移动后需要时会把这一类重新编号（步长 10），保存后按这个顺序生效。
        </Typography.Paragraph>
      ) : null}
      <Typography.Paragraph type="secondary" style={{ fontSize: 12 }} data-testid="rules-dns-note">
        解析：规则命中的域名只由规则目标（地区组或出口）的解析器解析，经同一条隧道；目标的解析器不通时解析失败，不会改问国内解析器。网关设置「未列名单的域名也问国内 DNS」只作用于没有命中任何名单和规则的域名
        {topo.settings.unlisted_domestic_dns ? "（当前已打开）" : "（当前关闭）"}。走隧道的规则默认不返回 AAAA；只有「客户端 IPv6 经本网关」打开且目标的每个可切换成员都有 IPv6 时才返回，指向外部 SOCKS 出口（只有 IPv4 TCP）的规则永远不返回。
      </Typography.Paragraph>
      {topo.rules.length === 0 ? (
        <EmptyState
          title="还没有规则"
          description="规则决定哪些域名或地址走哪个地区组或出口。"
          action={
            <Button type="primary" icon={<PlusOutlined />} onClick={() => setEditing("new")}>
              添加规则
            </Button>
          }
        />
      ) : (
        <Table<Rule>
          rowKey="id"
          size="middle"
          dataSource={shown}
          pagination={false}
          scroll={TABLE_SCROLL}
          onRow={(r) => ({ "data-testid": `rule-row-${r.id}` }) as React.HTMLAttributes<HTMLElement>}
          rowClassName={(r) => (r.enabled ? "" : "row-disabled")}
          columns={[
            {
              title: "顺序",
              width: 132,
              className: "nowrap",
              render: (_, r) => {
                const i = sorted.findIndex((x) => x.id === r.id);
                const ci = classIndex(r);
                const last = classSize(r) - 1;
                return (
                  <Space size={0}>
                    <Tooltip title={`优先级数值 ${r.priority}`}>
                      <span className="rule-pos" data-testid={`rule-pos-${r.id}`}>
                        {i + 1}
                      </span>
                    </Tooltip>
                    <Button type="text" size="small" icon={<ArrowUpOutlined />} aria-label={`提前 ${r.name}`} disabled={ci === 0} onClick={() => move(r, ci - 1)} />
                    <Button type="text" size="small" icon={<ArrowDownOutlined />} aria-label={`推后 ${r.name}`} disabled={ci === last} onClick={() => move(r, ci + 1)} />
                    <Dropdown
                      trigger={["click"]}
                      menu={{
                        items: [
                          { key: "top", icon: <VerticalAlignTopOutlined />, label: ordered || r.manual ? "移到最前" : "移到内置规则的最前", disabled: ci === 0 },
                          { key: "bottom", icon: <VerticalAlignBottomOutlined />, label: ordered ? "移到最后" : r.manual ? "移到手动规则的最后" : "移到最后", disabled: ci === last },
                          ...(ordered ? [{ key: "to", label: "移到第 N 条…" }] : []),
                        ],
                        onClick: ({ key }) => (key === "to" ? setMoveTo({ rule: r, to: ci + 1 }) : move(r, key === "top" ? 0 : last)),
                      }}
                    >
                      <Button type="text" size="small" icon={<EllipsisOutlined />} aria-label={`移动 ${r.name}`} />
                    </Dropdown>
                  </Space>
                );
              },
            },
            {
              title: "规则",
              className: "cell-name",
              render: (_, r) => (
                <div>
                  <Space size={4}>
                    <Typography.Text strong>{r.name}</Typography.Text>
                    {r.origin === "mihomo" ? (
                      <Tooltip title={r.source_text}>
                        <Tag color="cyan">导入 · 第 {r.source_line} 行</Tag>
                      </Tooltip>
                    ) : r.manual ? (
                      <Tag color="blue">手动</Tag>
                    ) : (
                      <Tooltip title="内置的自动规则；改动后标为「已改默认」"><Tag>内置</Tag></Tooltip>
                    )}
                    {!r.manual && r.overridden ? <Tag color="orange">已改默认</Tag> : null}
                  </Space>
                  <div className="muted" style={{ fontSize: 12 }}>
                    {MATCH_LABEL[r.match_type] ?? r.match_type}：
                    <span className="mono">
                      {r.match_type === "geosite"
                        ? `geosite:${r.geosite || r.match_value}`
                        : r.match_type === "ruleset"
                          ? ((topo.rule_sets ?? []).find((x) => x.id === r.rule_set)?.name ?? r.rule_set)
                          : r.match_value}
                    </span>
                    {(r.domains?.length ?? 0) > 0 ? (
                      <Tooltip title={r.domains!.join("、")}>
                        <span> · 显式域名 {r.domains!.length} 个</span>
                      </Tooltip>
                    ) : null}
                    {r.source_mac || r.source_ipv4 || r.source_ipv6 ? <span> · 仅限设备 {r.source_mac || r.source_ipv4 || r.source_ipv6}</span> : null}
                  </div>
                </div>
              ),
            },
            {
              title: "去向",
              className: "nowrap",
              render: (_, r) => {
                const t = targetOf(topo, r);
                if (t.kind === "quic" || t.kind === "direct" || t.kind === "reject") {
                  return <Tag color={t.kind === "reject" ? "red" : t.kind === "direct" ? "green" : "purple"}>{t.name}</Tag>;
                }
                if (t.kind === "service") {
                  return (
                    <Space size={4}>
                      <Tag color="geekblue">服务组</Tag>
                      {t.missing ? <StatusTag kind="failed">{t.id} 不存在</StatusTag> : <span>{t.name}</span>}
                    </Space>
                  );
                }
                return (
                  <Space size={4}>
                    {t.kind === "group" ? <Tag>地区组</Tag> : <Tag color="purple">固定出口</Tag>}
                    {t.missing ? (
                      <StatusTag kind="failed">{t.id || "未设置"} 不存在</StatusTag>
                    ) : (
                      <Link to={t.kind === "group" ? href("exits", t.id) : href("topology", t.id)}>{t.name}</Link>
                    )}
                    {t.kind === "group" && t.mode ? (
                      <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                        {t.mode === "manual" ? "手动" : "自动"}
                      </Typography.Text>
                    ) : null}
                  </Space>
                );
              },
            },
            {
              title: "要求",
              className: "nowrap",
              render: (_, r) => (
                <>
                  {r.require_residential ? <Tag color="green">住宅</Tag> : null}
                  {r.require_v6 ? <Tag color="blue">IPv6</Tag> : null}
                </>
              ),
            },
            ...(ordered
              ? [
                  {
                    title: "遮蔽",
                    className: "nowrap",
                    render: (_: unknown, r: Rule) => {
                      const a = analysis.get(r.id);
                      if (!a) return <Typography.Text type="secondary">—</Typography.Text>;
                      const ref = (ids?: string[] | null) => (ids ?? []).map((id) => `第 ${byID.get(id) ?? "?"} 条`).join("、");
                      const notes: string[] = [];
                      if (a.keyword_note) notes.push(a.keyword_note);
                      if (a.keywords && !a.keyword_note) notes.push(`${a.keywords} 条关键词条目在网关上不执行`);
                      if (a.rule_set?.unsupported && Object.keys(a.rule_set.unsupported).length) notes.push("规则集只部分生效：" + Object.entries(a.rule_set.unsupported).map(([k, v]) => `${k} ${v}`).join("，"));
                      if (a.rule_set?.held) notes.push("规则集有被暂缓的新版本");
                      if (a.legacy_lost) notes.push(`升级后变化：${a.legacy_lost} 个名字以前按更长的名字归本条，现在被 ${ref(a.legacy_lost_to)} 先命中`);
                      return (
                        <Space direction="vertical" size={0} data-testid={`rule-shadow-${r.id}`}>
                          {a.fully_shadowed ? (
                            <StatusTag kind="attention">永远不会命中（被 {ref(a.shadowed_by)} 遮蔽）</StatusTag>
                          ) : a.shadowed > 0 ? (
                            <Typography.Text type="warning" style={{ fontSize: 12 }}>
                              {a.shadowed}/{a.entries} 个条目被 {ref(a.shadowed_by)} 遮蔽
                            </Typography.Text>
                          ) : null}
                          {(a.partly_by ?? []).length > 0 ? (
                            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                              部分名字先被 {ref(a.partly_by)} 接走
                            </Typography.Text>
                          ) : null}
                          {notes.map((n) => (
                            <Typography.Text key={n} type="secondary" style={{ fontSize: 12 }}>
                              {n}
                            </Typography.Text>
                          ))}
                          {!a.fully_shadowed && !a.shadowed && !(a.partly_by ?? []).length && notes.length === 0 ? <Typography.Text type="secondary">—</Typography.Text> : null}
                        </Space>
                      );
                    },
                  },
                ]
              : []),
            {
              title: "校验",
              className: "nowrap",
              render: (_, r) => {
                const iss = issuesByRule.get(r.id) ?? [];
                const err = iss.filter((i) => i.severity === "error");
                if (iss.length === 0) return <Typography.Text type="secondary">—</Typography.Text>;
                return (
                  <Tooltip title={iss.map((i) => i.message).join("\n")}>
                    {err.length > 0 ? <StatusTag kind="failed">{err.length} 个错误</StatusTag> : <StatusTag kind="attention">{iss.length} 个提示</StatusTag>}
                  </Tooltip>
                );
              },
            },
            {
              title: "启用",
              render: (_, r) => <Switch size="small" checked={r.enabled} onChange={(enabled) => patch(r.id, { enabled })} aria-label={`启用 ${r.name}`} />,
            },
            {
              title: "操作",
              fixed: "right",
              className: "cell-actions",
              render: (_, r) => (
                <Space size={0} className="table-actions">
                  <Button
                    type="link"
                    size="small"
                    icon={<EditOutlined />}
                    onClick={() => {
                      setEditing(r);
                      navigate(href("rules", r.id), { replace: true });
                    }}
                  >
                    编辑
                  </Button>
                  {r.manual || (ordered && r.origin === "mihomo") ? (
                    <Button
                      type="link"
                      size="small"
                      danger
                      icon={<DeleteOutlined />}
                      aria-label={`删除 ${r.name}`}
                      onClick={() =>
                        confirm({
                          title: `删除规则「${r.name}」？`,
                          consequence: "规则从工作副本里移除；保存并安装后，命中它的流量改走后面的规则或默认组。",
                          okText: "删除",
                          onOk: () => setRules(topo.rules.filter((x) => x.id !== r.id)),
                        })
                      }
                    />
                  ) : null}
                </Space>
              ),
            },
          ]}
        />
      )}
      <IssueList issues={doc.issues.filter((i) => !i.rule_id && (i.group_id || i.code === "no_default_exit"))} />
      {ordered && upgradeNotes.length > 0 ? (
        <Alert
          type="info"
          showIcon
          style={{ marginTop: 12 }}
          data-testid="rules-upgrade-notes"
          message="升级后的解析变化"
          description={
            <ul style={{ margin: 0, paddingLeft: 18 }}>
              {upgradeNotes.map((n) => (
                <li key={n}>{n}</li>
              ))}
            </ul>
          }
        />
      ) : null}
      <Modal
        title={moveTo ? `把「${moveTo.rule.name}」移到第几条？` : ""}
        open={moveTo !== null}
        onCancel={() => setMoveTo(null)}
        okText="移动"
        onOk={() => {
          if (moveTo) move(moveTo.rule, moveTo.to - 1);
          setMoveTo(null);
        }}
      >
        <InputNumber
          aria-label="目标位置"
          min={1}
          max={topo.rules.length}
          value={moveTo?.to}
          onChange={(v) => setMoveTo((m) => (m && v ? { ...m, to: Number(v) } : m))}
        />
        <Typography.Text type="secondary" style={{ marginLeft: 8 }}>
          共 {topo.rules.length} 条；从上到下第一条命中生效。
        </Typography.Text>
      </Modal>
      {ordered && sharedNote ? (
        <Typography.Paragraph type="secondary" style={{ fontSize: 12 }}>
          {sharedNote}
        </Typography.Paragraph>
      ) : null}
      {ordered ? (
        <>
          <RuleTester />
          <ServiceGroupsSection topo={topo} dirty={doc.dirty} onChanged={() => void doc.reload()} />
          <RuleSetsSection dirty={doc.dirty} onChanged={() => void doc.reload()} />
          <ImportDrawer open={importing} topo={topo} onClose={() => setImporting(false)} onDone={() => void doc.reload()} />
        </>
      ) : null}
      <RuleDrawer
        open={editing !== null}
        rule={editing === "new" ? null : editing}
        topo={topo}
        onClose={() => {
          setEditing(null);
          if (focus) navigate(href("rules"), { replace: true });
        }}
        onApply={(r, insertAt) => {
          const exists = topo.rules.some((x) => x.id === r.id);
          if (!exists && ordered) {
            const next = [...topo.rules];
            next.splice(Math.max(0, Math.min(next.length, (insertAt ?? 1) - 1)), 0, r);
            setRules(next);
            setEditing(null);
            if (focus) navigate(href("rules"), { replace: true });
            return;
          }
          let next = exists ? topo.rules.map((x) => (x.id === r.id ? r : x)) : [...topo.rules, r];
          // A new manual rule goes to the top; with no room above the first one, renumber the manual rules.
          if (!exists && r.manual && r.priority < 1) next = moveRule(next.map((x) => (x.id === r.id ? { ...x, priority: Number.MAX_SAFE_INTEGER } : x)), r.id, 0);
          setRules(next);
          setEditing(null);
          if (focus) navigate(href("rules"), { replace: true });
        }}
      />
    </Page>
  );
}
