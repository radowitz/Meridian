// The ordered rule list's companions on the rules page: import from mihomo
// (paste → mapping → ordered preview → confirm), service groups (switchable
// targets), subscribed rule-sets, and the "which rule matches" tester.
//
// The pasted config stays in this component's state only; it is sent to the
// panel for preview / confirm and never stored in web storage. The panel
// keeps only the rule part (docs/architecture.md「从 mihomo 导入」).

import { Alert, Button, Checkbox, Drawer, Form, Input, InputNumber, Modal, Radio, Select, Space, Switch, Table, Tag, Tooltip, Typography } from "antd";
import { useEffect, useMemo, useState } from "react";
import * as api from "./api";
import type { ImportPreview, ImportRequest, ImportRow, RuleRef, RuleSetView, RuleTestResult, ServiceGroup, Topology } from "./types";
import { ApiErrorAlert, Section, StatusTag, TABLE_SCROLL, TimeText, groupLabel, useConfirmDanger } from "./ui";

/** Panel targets a service group or a mapping can point at. */
export function targetOptions(topo: Topology): { value: string; label: string }[] {
  const out: { value: string; label: string }[] = [];
  for (const g of topo.region_groups ?? []) out.push({ value: `group:${g.id}`, label: `地区组 ${groupLabel(g, topo.region_groups)}${g.require_residential ? "（住宅）" : ""}` });
  for (const n of topo.nodes.filter((x) => x.role === "exit")) out.push({ value: `exit:${n.id}`, label: `出口 ${n.name}` });
  out.push({ value: "direct", label: "直连（国内解析器，直连出去）" }, { value: "reject", label: "拒绝（连接被网关立即拒绝）" });
  return out;
}

export function specLabel(topo: Topology, spec: string | undefined): string {
  if (!spec) return "未指定";
  return targetOptions(topo).find((o) => o.value === spec)?.label ?? spec;
}

export function serviceSpec(s: ServiceGroup): string {
  if (s.target_action) return s.target_action;
  if (s.target_group) return `group:${s.target_group}`;
  if (s.target_exit) return `exit:${s.target_exit}`;
  return "";
}

const STATUS_TAG: Record<ImportRow["status"], { kind: "ok" | "failed" | "attention" | "neutral"; text: string }> = {
  ok: { kind: "ok", text: "可写入" },
  accepted: { kind: "attention", text: "已接受替代" },
  blocked: { kind: "failed", text: "阻止确认" },
  dropped: { kind: "neutral", text: "已删除" },
  info: { kind: "neutral", text: "不写入" },
};

const ACTION_LABEL: Record<ImportRow["action"], string> = {
  rule: "规则",
  quic: "QUIC 开关",
  match: "MATCH → 默认组",
  tail: "内置中国地址直连",
  after_match: "MATCH 之后",
  unsupported: "不支持",
};

type Filter = "all" | "blocked" | "unsupported" | "shadowed" | "changed";

/** Paste / upload a mihomo config, map its lines, preview in order, confirm. */
export function ImportDrawer({ open, topo, onClose, onDone }: { open: boolean; topo: Topology; onClose: () => void; onDone: () => void }) {
  const [config, setConfig] = useState("");
  const [selection, setSelection] = useState("");
  const [mapping, setMapping] = useState<Record<string, string>>({});
  const [drop, setDrop] = useState<number[]>([]);
  const [accept, setAccept] = useState<Record<string, string[]>>({});
  const [disableBuiltin, setDisableBuiltin] = useState(true);
  const [atStart, setAtStart] = useState(false);
  const [resetServices, setResetServices] = useState(false);
  const [preview, setPreview] = useState<ImportPreview | null>(null);
  const [error, setError] = useState<api.ApiError | null>(null);
  const [busy, setBusy] = useState(false);
  const [filter, setFilter] = useState<Filter>("all");
  const [done, setDone] = useState<string | null>(null);

  useEffect(() => {
    if (!open) {
      // Nothing of the pasted text outlives the drawer.
      setConfig("");
      setSelection("");
      setPreview(null);
      setDone(null);
    }
  }, [open]);

  const body = (extra: Partial<ImportRequest> = {}): ImportRequest => ({
    config,
    selection: selection || undefined,
    mapping,
    drop,
    accept,
    disable_builtin: disableBuiltin,
    at_start: atStart,
    reset_services: resetServices,
    ...extra,
  });

  async function runPreview(fetch = false) {
    setBusy(true);
    setError(null);
    try {
      setPreview(await api.importPreview(body({ fetch_rule_sets: fetch })));
    } catch (e) {
      setError(e instanceof api.ApiError ? e : new api.ApiError(0, {}));
    } finally {
      setBusy(false);
    }
  }

  async function confirmImport() {
    if (!preview) return;
    setBusy(true);
    setError(null);
    try {
      const res = await api.importConfirm(body({ digest: preview.digest }));
      setDone(`已写入 ${res.imported} 条规则、${res.services} 个服务组、${res.rule_sets} 个规则集；默认组 ${res.default_group || "不变"}。安装后在网关生效。`);
      onDone();
    } catch (e) {
      setError(e instanceof api.ApiError ? e : new api.ApiError(0, {}));
    } finally {
      setBusy(false);
    }
  }

  const toggleAccept = (line: number, code: string, on: boolean) =>
    setAccept((a) => {
      const cur = new Set(a[String(line)] ?? []);
      if (on) cur.add(code);
      else cur.delete(code);
      return { ...a, [String(line)]: [...cur] };
    });

  const rows = useMemo(() => {
    if (!preview) return [];
    return preview.rows.filter((r) => {
      switch (filter) {
        case "blocked":
          return r.status === "blocked";
        case "unsupported":
          return r.action === "unsupported";
        case "shadowed":
          return (r.flags ?? []).some((f) => f.code === "shadowed" || f.code === "partly_shadowed");
        case "changed":
          return r.diff === "new" || r.diff === "changed";
      }
      return true;
    });
  }, [preview, filter]);

  const opts = targetOptions(topo);

  return (
    <Drawer title="从 mihomo 导入分流规则" open={open} onClose={onClose} width={1100} destroyOnHidden>
      <Alert
        type="info"
        showIcon
        style={{ marginBottom: 12 }}
        message="只读取 rules、rule-providers、proxy-groups 三段"
        description="可以粘贴整份配置：proxies、proxy-providers 等其它内容在面板解析后立即丢弃，不保存、不记录、不返回。确认之前不写入任何东西；手工规则不会被改动。"
      />
      {done ? <Alert type="success" showIcon message={done} style={{ marginBottom: 12 }} data-testid="import-done" /> : null}
      {error ? <ApiErrorAlert error={error} /> : null}
      <Form layout="vertical">
        <Form.Item label="mihomo 配置（YAML）">
          <Input.TextArea rows={8} className="mono" value={config} onChange={(e) => setConfig(e.target.value)} aria-label="mihomo 配置" placeholder="rules:\n  - DOMAIN-SUFFIX,example.com,Proxy\n  - MATCH,Proxy" />
          <input
            type="file"
            accept=".yaml,.yml,.txt"
            aria-label="上传配置文件"
            style={{ marginTop: 6 }}
            onChange={(e) => {
              const f = e.target.files?.[0];
              if (f) void f.text().then(setConfig);
            }}
          />
        </Form.Item>
        <Form.Item
          label="当前选中状态（可选）"
          extra="在 mihomo 网关上执行 curl -s -H 'Authorization: Bearer <secret>' http://127.0.0.1:9090/proxies，把输出粘贴到这里；只用到各 Selector 的 now。没有时按每个组的第一个成员映射，可以在服务组里再改。"
        >
          <Input.TextArea rows={3} className="mono" value={selection} onChange={(e) => setSelection(e.target.value)} aria-label="选中状态" />
        </Form.Item>
        <Space wrap>
          <Checkbox checked={disableBuiltin} onChange={(e) => setDisableBuiltin(e.target.checked)}>
            停用面板内置的默认规则（以 mihomo 的规则为准）
          </Checkbox>
          <Checkbox checked={atStart} onChange={(e) => setAtStart(e.target.checked)}>
            导入的规则放在手工规则之前
          </Checkbox>
          <Checkbox checked={resetServices} onChange={(e) => setResetServices(e.target.checked)}>
            已有服务组改回导入的指向
          </Checkbox>
        </Space>
        <div style={{ marginTop: 12 }}>
          <Space>
            <Button type="primary" loading={busy} disabled={!config.trim()} onClick={() => void runPreview(true)}>
              预览
            </Button>
            {preview ? (
              <Button loading={busy} onClick={() => void runPreview(false)}>
                刷新预览
              </Button>
            ) : null}
          </Space>
        </div>
      </Form>

      {preview ? (
        <div data-testid="import-preview" style={{ marginTop: 16 }}>
          <Space wrap style={{ marginBottom: 8 }}>
            {preview.can_confirm ? <StatusTag kind="ok">可以确认</StatusTag> : <StatusTag kind="failed">{preview.blocking} 条阻止确认</StatusTag>}
            {Object.entries(preview.summary).map(([k, v]) => (
              <Tag key={k}>
                {STATUS_TAG[k as ImportRow["status"]]?.text ?? k} {v}
              </Tag>
            ))}
            {preview.quic ? <Tag color="purple">QUIC 开关（{preview.quic}）</Tag> : null}
          </Space>
          {preview.notes.map((n) => (
            <Typography.Paragraph key={n} type="secondary" style={{ fontSize: 12, marginBottom: 4 }}>
              {n}
            </Typography.Paragraph>
          ))}

          {preview.mapping.length > 0 ? (
            <Section title="线路映射：mihomo 的线路 / 地区 → 面板的地区组或出口">
              <Table
                size="small"
                rowKey="name"
                pagination={false}
                dataSource={preview.mapping}
                columns={[
                  { title: "mihomo 名字", dataIndex: "name", render: (v: string, m) => <span>{v} <Tag>{m.kind === "line" ? "线路组" : m.kind === "selector" ? "选择组" : "节点"}</Tag></span> },
                  { title: "用到的行", render: (_, m) => (m.used_by ?? []).join("、") },
                  {
                    title: "对应到",
                    render: (_, m) => (
                      <Select
                        style={{ minWidth: 260 }}
                        aria-label={`映射 ${m.name}`}
                        value={mapping[m.name] ?? m.mapped}
                        placeholder="选择地区组或出口"
                        options={[...(m.suggestions ?? []).map((s) => ({ value: s.value, label: `建议：${s.label}` })), ...opts.filter((o) => !(m.suggestions ?? []).some((s) => s.value === o.value))]}
                        onChange={(v) => setMapping((x) => ({ ...x, [m.name]: v }))}
                      />
                    ),
                  },
                ]}
              />
            </Section>
          ) : null}

          {preview.services.length > 0 ? (
            <Section title="服务组（mihomo 的选择组）">
              <Table
                size="small"
                rowKey="id"
                pagination={false}
                dataSource={preview.services}
                columns={[
                  { title: "服务组", render: (_, s) => <span>{s.name} {s.default ? <Tag color="gold">MATCH</Tag> : null}</span> },
                  { title: "mihomo 选中路径", render: (_, s) => <span className="mono">{s.chain.join(" → ")}</span> },
                  { title: "选中来源", render: (_, s) => ({ selection: "选中状态", ui: "手动选择", first_member: "第一个成员（没有选中状态）" })[s.pick_from] ?? s.pick_from },
                  { title: "导入后指向", render: (_, s) => (s.keep_current ? `${specLabel(topo, s.current)}（保留面板当前）` : specLabel(topo, s.target)) },
                ]}
              />
            </Section>
          ) : null}

          {preview.rule_sets.length > 0 ? (
            <Section title="规则集">
              <Table
                size="small"
                rowKey="name"
                pagination={false}
                dataSource={preview.rule_sets}
                columns={[
                  { title: "名称", dataIndex: "name" },
                  { title: "状态", render: (_, r) => <Tooltip title={r.error}>{r.state === "available" ? <StatusTag kind="ok">已下载</StatusTag> : r.state === "pending" ? <StatusTag kind="running">下载中</StatusTag> : <StatusTag kind="failed">{r.state}</StatusTag>}</Tooltip> },
                  { title: "格式", render: (_, r) => r.format ?? "—" },
                  { title: "条目", render: (_, r) => (r.counts ? Object.entries(r.counts).map(([k, v]) => `${k} ${v}`).join("，") : "—") },
                  { title: "不能执行", render: (_, r) => (r.unsupported ? Object.entries(r.unsupported).map(([k, v]) => `${k} ${v}`).join("，") : "—") },
                ]}
              />
            </Section>
          ) : null}

          <Section title="逐条预览（原顺序）">
            <Radio.Group
              optionType="button"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              style={{ marginBottom: 8 }}
              options={[
                { value: "all", label: "全部" },
                { value: "blocked", label: "阻止" },
                { value: "unsupported", label: "不支持" },
                { value: "shadowed", label: "遮蔽" },
                { value: "changed", label: "变化" },
              ]}
            />
            <Table<ImportRow>
              size="small"
              rowKey={(r) => String(r.line)}
              pagination={false}
              scroll={TABLE_SCROLL}
              dataSource={rows}
              onRow={(r) => ({ "data-testid": `import-row-${r.line}` }) as React.HTMLAttributes<HTMLElement>}
              columns={[
                { title: "行", dataIndex: "line", width: 56 },
                { title: "原文", render: (_, r) => <span className="mono">{r.text}</span> },
                { title: "映射为", render: (_, r) => <span>{ACTION_LABEL[r.action]}{r.match ? `：${r.match}` : ""}{r.target ? ` → ${r.target.kind === "service" ? `服务组 ${r.target.name}（${specLabel(topo, r.target.resolved)}）` : specLabel(topo, r.target.resolved ?? r.target.kind)}` : ""}</span> },
                {
                  title: "状态",
                  render: (_, r) => (
                    <Space size={2} direction="vertical">
                      <StatusTag kind={STATUS_TAG[r.status].kind}>{STATUS_TAG[r.status].text}</StatusTag>
                      {r.diff && r.diff !== "same" ? <Tag color={r.diff === "new" ? "green" : "orange"}>{r.diff === "new" ? "新增" : "变化"}</Tag> : null}
                      {r.position ? <Typography.Text type="secondary" style={{ fontSize: 12 }}>列表第 {r.position} 条</Typography.Text> : null}
                    </Space>
                  ),
                },
                {
                  title: "说明",
                  render: (_, r) => (
                    <Space direction="vertical" size={2}>
                      {(r.flags ?? []).map((f) => (
                        <div key={f.code} style={{ fontSize: 12 }}>
                          {f.severity === "accept" ? (
                            <Checkbox
                              checked={(accept[String(r.line)] ?? []).includes(f.code)}
                              onChange={(e) => toggleAccept(r.line, f.code, e.target.checked)}
                              aria-label={`接受 第${r.line}行 ${f.code}`}
                            >
                              接受：
                            </Checkbox>
                          ) : f.severity === "block" ? (
                            <Tag color="red">阻止</Tag>
                          ) : null}
                          {f.message}
                          {f.by?.length ? `（${f.by.join("、")}）` : ""}
                        </div>
                      ))}
                    </Space>
                  ),
                },
                {
                  title: "删除",
                  render: (_, r) =>
                    r.action === "match" || r.action === "tail" || r.action === "after_match" ? null : (
                      <Switch
                        size="small"
                        aria-label={`删除 第${r.line}行`}
                        checked={drop.includes(r.line)}
                        onChange={(on) => setDrop((d) => (on ? [...d, r.line] : d.filter((x) => x !== r.line)))}
                      />
                    ),
                },
              ]}
            />
            {(preview.removed ?? []).length > 0 ? (
              <Alert
                type="warning"
                showIcon
                style={{ marginTop: 8 }}
                message={`上次导入的 ${preview.removed!.length} 条规则这次没有，确认后会移除`}
                description={preview.removed!.map((r) => `第 ${r.line} 行 ${r.text}`).join("；")}
              />
            ) : null}
            {(preview.builtin_disabled ?? []).length > 0 ? (
              <Typography.Paragraph type="secondary" style={{ fontSize: 12, marginTop: 8 }}>
                确认后停用的内置规则：{preview.builtin_disabled!.join("、")}
              </Typography.Paragraph>
            ) : null}
          </Section>
          <Space style={{ marginTop: 12 }}>
            <Typography.Text type="secondary">改了映射、删除或接受后请先「刷新预览」，确认的是最后一次预览的内容。</Typography.Text>
            <Button type="primary" disabled={!preview.can_confirm} loading={busy} onClick={() => void confirmImport()}>
              确认导入
            </Button>
          </Space>
        </div>
      ) : null}
    </Drawer>
  );
}

/** Service groups: list, current target, change target. */
export function ServiceGroupsSection({ topo, dirty, onChanged }: { topo: Topology; dirty: boolean; onChanged: () => void }) {
  const [data, setData] = useState<{ service_group: ServiceGroup; used_by: RuleRef[] }[] | null>(null);
  const [error, setError] = useState<api.ApiError | null>(null);
  const load = () =>
    api
      .listServiceGroups()
      .then((r) => setData(r.service_groups))
      .catch((e) => setError(e instanceof api.ApiError ? e : new api.ApiError(0, {})));
  useEffect(() => {
    void load();
  }, [topo.service_groups?.length]); // eslint-disable-line react-hooks/exhaustive-deps
  const opts = targetOptions(topo);
  return (
    <Section title="服务组">
      <Typography.Paragraph type="secondary" style={{ fontSize: 12 }}>
        规则可以指向服务组，服务组再指向一个地区组、出口、直连或拒绝。改服务组的指向就像在 mihomo 里切换选择组：所有用它的规则一起改，不必动规则；安装后生效，住宅 / IPv6 要求照常校验。
      </Typography.Paragraph>
      {dirty ? <Alert type="warning" showIcon message="规则有未保存的修改：先保存或放弃，再改服务组。" style={{ marginBottom: 8 }} /> : null}
      {error ? <ApiErrorAlert error={error} /> : null}
      <Table
        size="small"
        rowKey={(r) => r.service_group.id}
        pagination={false}
        dataSource={data ?? []}
        locale={{ emptyText: "还没有服务组（导入 mihomo 配置时按它的选择组创建）" }}
        columns={[
          { title: "服务组", render: (_, r) => <span>{r.service_group.name} {r.service_group.default ? <Tag color="gold">MATCH / 默认组</Tag> : null}{r.service_group.origin === "mihomo" ? <Tag>导入</Tag> : null}</span> },
          {
            title: "指向",
            render: (_, r) => (
              <Select
                style={{ minWidth: 260 }}
                aria-label={`服务组 ${r.service_group.name} 指向`}
                disabled={dirty}
                value={serviceSpec(r.service_group)}
                options={r.service_group.default ? opts.filter((o) => o.value.startsWith("group:")) : opts}
                onChange={async (v) => {
                  setError(null);
                  try {
                    await api.setServiceTarget(r.service_group.id, v);
                    await load();
                    onChanged();
                  } catch (e) {
                    setError(e instanceof api.ApiError ? e : new api.ApiError(0, {}));
                  }
                }}
              />
            ),
          },
          { title: "使用的规则", render: (_, r) => (r.used_by.length ? r.used_by.map((u) => `第 ${u.position} 条`).join("、") : "—") },
        ]}
      />
    </Section>
  );
}

function counts(m?: Record<string, number>) {
  return m && Object.keys(m).length ? Object.entries(m).map(([k, v]) => `${k} ${v}`).join("，") : "—";
}

/** Subscribed rule-sets: add by URL, status, update now, used-by. */
export function RuleSetsSection({ dirty, onChanged }: { dirty: boolean; onChanged: () => void }) {
  const [data, setData] = useState<RuleSetView[] | null>(null);
  const [formats, setFormats] = useState<string[]>([]);
  const [error, setError] = useState<api.ApiError | null>(null);
  const [adding, setAdding] = useState(false);
  const [form] = Form.useForm<{ name: string; url: string; format?: string; source: "url" | "policy"; interval_h?: number; allow_lan?: boolean }>();
  const confirm = useConfirmDanger();
  const load = () =>
    api
      .listRuleSets()
      .then((r) => {
        setData(r.rule_sets);
        setFormats(r.formats);
      })
      .catch((e) => setError(e instanceof api.ApiError ? e : new api.ApiError(0, {})));
  useEffect(() => {
    void load();
    const t = setInterval(() => {
      if (data?.some((x) => x.status.state === "fetching")) void load();
    }, 2000);
    return () => clearInterval(t);
  }, [data?.some((x) => x.status.state === "fetching")]); // eslint-disable-line react-hooks/exhaustive-deps
  const act = async (fn: () => Promise<unknown>) => {
    setError(null);
    try {
      await fn();
      await load();
      onChanged();
    } catch (e) {
      setError(e instanceof api.ApiError ? e : new api.ApiError(0, {}));
    }
  };
  return (
    <Section
      title="规则集"
      extra={
        <Button size="small" disabled={dirty} onClick={() => setAdding(true)}>
          按 URL 添加
        </Button>
      }
    >
      <Typography.Paragraph type="secondary" style={{ fontSize: 12 }}>
        支持 Clash/mihomo 规则集（yaml 或 text；classical、domain、ipcidr）和 Surge 的 .list 与 DOMAIN-SET。规则集在列表里占一条规则的位置。下载沿用名单的国内源 / 海外源 / 全自动（GitHub 原始文件经镜像），也可只用填写的 URL；失败时保留旧版本；新版本里网关执行不了的条目变多时暂缓，等你确认。不能执行的条目（进程、UA、端口、逻辑规则、关键词等）按类型计数。
      </Typography.Paragraph>
      {error ? <ApiErrorAlert error={error} /> : null}
      <Table<RuleSetView>
        size="small"
        rowKey={(r) => r.rule_set.id}
        pagination={false}
        scroll={TABLE_SCROLL}
        dataSource={data ?? []}
        locale={{ emptyText: "还没有规则集" }}
        columns={[
          { title: "名称", render: (_, r) => <span>{r.rule_set.name}{r.rule_set.origin === "mihomo" ? <Tag style={{ marginLeft: 4 }}>导入</Tag> : null}</span> },
          { title: "URL", render: (_, r) => <Typography.Text className="mono" ellipsis style={{ maxWidth: 260 }}>{r.rule_set.url}</Typography.Text> },
          { title: "格式", render: (_, r) => r.status.format ?? (r.rule_set.format || "自动识别") },
          { title: "条目", render: (_, r) => counts(r.status.counts) },
          { title: "不能执行", render: (_, r) => counts(r.status.unsupported) },
          {
            title: "状态",
            render: (_, r) => (
              <Space direction="vertical" size={2}>
                {r.status.state === "ok" ? <StatusTag kind="ok">可用</StatusTag> : r.status.state === "fetching" ? <StatusTag kind="running">下载中</StatusTag> : r.status.state === "held" ? <StatusTag kind="attention">新版本暂缓</StatusTag> : r.status.state === "failed" ? <StatusTag kind="failed">下载失败</StatusTag> : <StatusTag kind="neutral">未下载</StatusTag>}
                {r.status.fetched_at ? <TimeText value={r.status.fetched_at} /> : null}
                {r.status.last_error ? <Typography.Text type="danger" style={{ fontSize: 12 }}>{r.status.last_error}</Typography.Text> : null}
                {r.status.held ? <Typography.Text type="warning" style={{ fontSize: 12 }}>{r.status.held.reason}</Typography.Text> : null}
                {r.status.applied ? <Typography.Text type="secondary" style={{ fontSize: 12 }}>{r.status.applied}</Typography.Text> : null}
              </Space>
            ),
          },
          { title: "使用", render: (_, r) => (r.used_by.length ? r.used_by.map((u) => `第 ${u.position} 条 ${u.name}`).join("、") : "—") },
          {
            title: "操作",
            render: (_, r) => (
              <Space size={0}>
                <Button type="link" size="small" onClick={() => void act(() => api.fetchRuleSet(r.rule_set.id))}>
                  立即更新
                </Button>
                {r.status.held ? (
                  <Button type="link" size="small" onClick={() => void act(() => api.activateHeldRuleSet(r.rule_set.id))}>
                    启用暂缓的版本
                  </Button>
                ) : null}
                <Button
                  type="link"
                  size="small"
                  danger
                  disabled={dirty}
                  onClick={() =>
                    confirm({
                      title: `删除规则集「${r.rule_set.name}」？`,
                      consequence: r.used_by.length ? "还有规则在用它，面板会拒绝删除。" : "定义和已下载的内容一起删除。",
                      okText: "删除",
                      onOk: () => void act(() => api.deleteRuleSet(r.rule_set.id)),
                    })
                  }
                >
                  删除
                </Button>
              </Space>
            ),
          },
        ]}
      />
      <Modal
        title="按 URL 添加规则集"
        open={adding}
        onCancel={() => setAdding(false)}
        onOk={async () => {
          const v = await form.validateFields();
          await act(() =>
            api.createRuleSet({ name: v.name, url: v.url, format: v.format || "", source: v.source, interval_sec: v.interval_h ? v.interval_h * 3600 : 0, allow_lan: !!v.allow_lan }),
          );
          setAdding(false);
          form.resetFields();
        }}
        okText="添加并下载"
      >
        <Form form={form} layout="vertical" initialValues={{ source: "policy" }}>
          <Form.Item name="name" label="名称" rules={[{ required: true }]}>
            <Input />
          </Form.Item>
          <Form.Item name="url" label="URL" rules={[{ required: true }]}>
            <Input className="mono" placeholder="https://raw.githubusercontent.com/org/repo/main/rules/Example.list" />
          </Form.Item>
          <Form.Item name="format" label="格式" extra="默认按内容自动识别（再看扩展名）">
            <Select allowClear options={formats.map((f) => ({ value: f, label: f }))} placeholder="自动识别" />
          </Form.Item>
          <Form.Item name="source" label="下载方式">
            <Radio.Group
              options={[
                { value: "policy", label: "按名单的下载源（GitHub 文件走国内镜像 / 海外源），最后用原 URL" },
                { value: "url", label: "只用填写的 URL（例如已经是加速地址）" },
              ]}
            />
          </Form.Item>
          <Form.Item name="interval_h" label="更新间隔（小时，默认 24）">
            <InputNumber min={1} max={720} />
          </Form.Item>
          <Form.Item name="allow_lan" valuePropName="checked" extra="默认拒绝解析到局域网、回环、链路本地或本机地址的 URL（包括重定向后的）。">
            <Checkbox>允许局域网地址的下载源</Checkbox>
          </Form.Item>
        </Form>
      </Modal>
    </Section>
  );
}

/** Which rule matches a name / address (the reference interpreter). */
export function RuleTester() {
  const [name, setName] = useState("");
  const [addr, setAddr] = useState("");
  const [res, setRes] = useState<RuleTestResult | null>(null);
  const [error, setError] = useState<api.ApiError | null>(null);
  return (
    <Section title="哪条规则会命中？">
      <Typography.Paragraph type="secondary" style={{ fontSize: 12 }}>
        按已保存的列表从上到下判断（和 Clash / Surge 一样，第一条命中生效），之后是内置国内名单、中国地址直连和默认组。
      </Typography.Paragraph>
      <Space wrap>
        <Input placeholder="域名，例如 www.example.com" value={name} onChange={(e) => setName(e.target.value)} aria-label="测试域名" style={{ width: 260 }} />
        <Input placeholder="地址（可选）" value={addr} onChange={(e) => setAddr(e.target.value)} aria-label="测试地址" style={{ width: 200 }} />
        <Button
          onClick={async () => {
            setError(null);
            try {
              setRes(await api.testRule(name.trim(), addr.trim()));
            } catch (e) {
              setError(e instanceof api.ApiError ? e : new api.ApiError(0, {}));
            }
          }}
        >
          判断
        </Button>
      </Space>
      {error ? <ApiErrorAlert error={error} /> : null}
      {res ? (
        <div data-testid="rule-test-result" style={{ marginTop: 8 }}>
          {res.rule ? (
            <Typography.Text>
              第 {res.rule.position} 条「{res.rule.name}」{res.rule.source_line ? `（mihomo 第 ${res.rule.source_line} 行）` : ""}：{res.reason} → {res.target}
            </Typography.Text>
          ) : (
            <Typography.Text>没有规则命中：{res.reason} → {res.target}</Typography.Text>
          )}
          {(res.notes ?? []).map((n) => (
            <div key={n} className="muted" style={{ fontSize: 12 }}>
              {n}
            </div>
          ))}
          {res.note_address ? <div className="muted" style={{ fontSize: 12 }}>{res.note_address}</div> : null}
        </div>
      ) : null}
    </Section>
  );
}
