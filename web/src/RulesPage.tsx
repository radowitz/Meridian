// 分流规则: which traffic goes where, in priority order. A rule points at
// exactly one target: a region group (switching behaviour lives on the
// group) or one pinned exit. Rules are part of the topology document, so the
// page edits the working copy and saves through the document bar.

import { ArrowDownOutlined, ArrowUpOutlined, DeleteOutlined, EditOutlined, PlusOutlined, SearchOutlined } from "@ant-design/icons";
import {
  Alert,
  Button,
  Checkbox,
  Collapse,
  Drawer,
  Form,
  Input,
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
import { href, useRouter, useTopologyDoc } from "./state";
import type { Issue, Rule, Topology } from "./types";
import { ApiErrorAlert, EmptyState, IssueList, Link, Page, StatusTag, TopologyDocBar, regionLabel, useConfirmDanger } from "./ui";

export const MATCH_TYPES: { value: string; label: string; help: string; placeholder: string }[] = [
  { value: "domain", label: "完整域名", help: "只匹配这个域名本身。", placeholder: "api.example.com" },
  { value: "suffix", label: "域名后缀", help: "匹配这个域名和它的所有子域名。", placeholder: "example.com" },
  { value: "keyword", label: "域名关键词", help: "域名里含有这个词就匹配（字母、数字、点、下划线、短横线）。", placeholder: "netflix" },
  { value: "geosite", label: "geosite 名单", help: "使用「名单」页下载的 geosite 分类；下载之前只用下面的显式域名。", placeholder: "netflix" },
  { value: "cidr", label: "IP / CIDR", help: "目的地址或网段。", placeholder: "203.0.113.0/24" },
  { value: "geoip", label: "geoip", help: "这一期不会写入数据面：不按归属地分流，流量会落到后面的策略。", placeholder: "us" },
  { value: "asn", label: "ASN", help: "这一期不会写入数据面：不按 ASN 分流，流量会落到后面的策略。", placeholder: "AS13335" },
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
  if (r.target_exit) {
    const n = t.nodes.find((x) => x.id === r.target_exit);
    return { kind: "exit" as const, id: r.target_exit, name: n?.name ?? r.target_exit, missing: !n };
  }
  const g = (t.region_groups ?? []).find((x) => x.id === r.target_group);
  return { kind: "group" as const, id: r.target_group ?? "", name: g?.name ?? r.target_group ?? "—", missing: !g, mode: g?.mode };
}

// --------------------------------------------------------------- drawer ---

interface FormValues {
  name: string;
  match_type: string;
  match_value: string;
  domains: string[];
  target: "group" | "exit";
  target_group?: string;
  target_exit?: string;
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
  onApply: (r: Rule) => void;
}) {
  const [form] = Form.useForm<FormValues>();
  const [checking, setChecking] = useState(false);
  const [problems, setProblems] = useState<Issue[] | null>(null);
  const [checkError, setCheckError] = useState<api.ApiError | null>(null);
  const target = Form.useWatch("target", form) ?? (rule?.target_exit ? "exit" : "group");
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
        target: rule.target_exit ? "exit" : "group",
        target_group: rule.target_group,
        target_exit: rule.target_exit,
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
      };

  function build(v: FormValues): Rule {
    const manualIDs = new Set(topo.rules.map((r) => r.id));
    let id = rule?.id;
    if (!id) {
      const base = `manual-${(v.match_value || v.name).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 32) || "rule"}`;
      id = base;
      for (let i = 2; manualIDs.has(id); i++) id = `${base}-${i}`;
    }
    const minManual = Math.min(...topo.rules.filter((r) => r.manual).map((r) => r.priority), 20);
    const value = v.match_value.trim();
    let domains = (v.domains ?? []).map((d) => d.trim().replace(/^\./, "")).filter(Boolean);
    if ((v.match_type === "domain" || v.match_type === "suffix") && value && !domains.includes(value.replace(/^\./, ""))) {
      domains = [value.replace(/^\./, ""), ...domains];
    }
    const base: Rule = rule ?? {
      id,
      name: "",
      manual: true,
      priority: minManual - 10,
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
      overridden: base.manual ? base.overridden : true,
    };
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
      onApply(r);
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
        onApply(r);
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
          <Form.Item name="match_value" label="匹配值" style={{ flex: 1 }} rules={[{ required: true, message: "请填写匹配值" }]} extra={mt?.help}>
            <Input className="mono" placeholder={mt?.placeholder} aria-label="匹配值" />
          </Form.Item>
        </Space.Compact>
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
            </Space>
          </Radio.Group>
        </Form.Item>
        {target === "group" ? (
          <Form.Item name="target_group" label="地区组" rules={[{ required: true, message: "选择一个地区组" }]}>
            <Select
              aria-label="地区组"
              options={groups.map((g) => ({
                value: g.id,
                label: `${g.name}（${regionLabel(g.region)} · ${g.mode === "manual" ? "手动" : "自动"}${g.require_residential ? " · 住宅" : ""}${g.require_v6 ? " · IPv6" : ""}）`,
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
  const topo = doc.topo;
  const focus = route.params[0];

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

  const sorted = [...topo.rules].sort((a, b) => a.priority - b.priority || a.id.localeCompare(b.id));
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
  const swap = (a: Rule, b: Rule) =>
    setRules(
      topo.rules.map((r) => {
        if (r.id === a.id) return { ...r, priority: b.priority === a.priority ? a.priority + 1 : b.priority, overridden: r.manual ? r.overridden : true };
        if (r.id === b.id) return { ...r, priority: a.priority, overridden: r.manual ? r.overridden : true };
        return r;
      }),
    );

  return (
    <Page
      title="分流规则"
      description="按优先级从上到下匹配，第一条命中的规则决定去向；没有命中的境外流量走默认组。规则是拓扑的一部分，保存后安装才生效。"
      extra={
        <Button type="primary" icon={<PlusOutlined />} onClick={() => setEditing("new")}>
          添加规则
        </Button>
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
              {(topo.region_groups ?? []).find((g) => g.id === topo.settings.default_group)?.name ?? topo.settings.default_group}
            </Link>
          ) : (
            "未设置"
          )}
        </Typography.Text>
      </Space>
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
          scroll={{ x: 980 }}
          onRow={(r) => ({ "data-testid": `rule-row-${r.id}` }) as React.HTMLAttributes<HTMLElement>}
          rowClassName={(r) => (r.enabled ? "" : "row-disabled")}
          columns={[
            {
              title: "顺序",
              width: 96,
              render: (_, r) => {
                const i = sorted.findIndex((x) => x.id === r.id);
                return (
                  <Space size={0}>
                    <span className="rule-pos">{i + 1}</span>
                    <Button
                      type="text"
                      size="small"
                      icon={<ArrowUpOutlined />}
                      aria-label={`提前 ${r.name}`}
                      disabled={i === 0}
                      onClick={() => swap(r, sorted[i - 1])}
                    />
                    <Button
                      type="text"
                      size="small"
                      icon={<ArrowDownOutlined />}
                      aria-label={`推后 ${r.name}`}
                      disabled={i === sorted.length - 1}
                      onClick={() => swap(r, sorted[i + 1])}
                    />
                  </Space>
                );
              },
            },
            {
              title: "规则",
              render: (_, r) => (
                <div>
                  <Space size={4} wrap>
                    <Typography.Text strong>{r.name}</Typography.Text>
                    {r.manual ? <Tag color="blue">手动</Tag> : <Tooltip title="内置的自动规则；改动后标为「已改默认」"><Tag>内置</Tag></Tooltip>}
                    {!r.manual && r.overridden ? <Tag color="orange">已改默认</Tag> : null}
                  </Space>
                  <div className="muted" style={{ fontSize: 12 }}>
                    {MATCH_LABEL[r.match_type] ?? r.match_type}：<span className="mono">{r.match_type === "geosite" ? `geosite:${r.geosite || r.match_value}` : r.match_value}</span>
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
              width: 260,
              render: (_, r) => {
                const t = targetOf(topo, r);
                return (
                  <Space size={4} wrap>
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
              width: 110,
              render: (_, r) => (
                <>
                  {r.require_residential ? <Tag color="green">住宅</Tag> : null}
                  {r.require_v6 ? <Tag color="blue">IPv6</Tag> : null}
                </>
              ),
            },
            {
              title: "校验",
              width: 110,
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
              width: 72,
              render: (_, r) => <Switch size="small" checked={r.enabled} onChange={(enabled) => patch(r.id, { enabled })} aria-label={`启用 ${r.name}`} />,
            },
            {
              title: "",
              width: 120,
              fixed: "right",
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
                  {r.manual ? (
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
      <RuleDrawer
        open={editing !== null}
        rule={editing === "new" ? null : editing}
        topo={topo}
        onClose={() => {
          setEditing(null);
          if (focus) navigate(href("rules"), { replace: true });
        }}
        onApply={(r) => {
          const exists = topo.rules.some((x) => x.id === r.id);
          setRules(exists ? topo.rules.map((x) => (x.id === r.id ? r : x)) : [...topo.rules, r]);
          setEditing(null);
          if (focus) navigate(href("rules"), { replace: true });
        }}
      />
    </Page>
  );
}
