import { Button, Form, Input, Select, Switch, Table, Tag } from "antd";
import type { Rule, Topology } from "./types";

const matchTypes = [
  { value: "domain", label: "域名（完整）" },
  { value: "suffix", label: "域名后缀" },
  { value: "keyword", label: "关键词" },
  { value: "geosite", label: "geosite" },
  { value: "cidr", label: "IP / CIDR" },
  { value: "geoip", label: "geoip" },
  { value: "asn", label: "ASN" },
];

export default function RulesPanel({ topo, onChange }: { topo: Topology; onChange: (t: Topology) => void }) {
  const manual = topo.rules.filter((r) => r.manual).sort((a, b) => a.priority - b.priority);
  const auto = topo.rules.filter((r) => !r.manual);

  function patch(id: string, partial: Partial<Rule>) {
    onChange({
      ...topo,
      rules: topo.rules.map((r) => (r.id === id ? { ...r, ...partial, overridden: r.manual ? r.overridden : true } : r)),
    });
  }

  return (
    <div className="panel">
      <h3>手动规则（优先于自动表）</h3>
      <Table
        size="small"
        rowKey="id"
        pagination={false}
        dataSource={manual}
        columns={[
          { title: "优先级", dataIndex: "priority", width: 80 },
          { title: "名称", dataIndex: "name" },
          { title: "匹配", render: (_, r) => `${r.match_type}:${r.match_value}` },
          { title: "出口", render: (_, r) => r.target_exit || r.target_pool },
          { title: "模式", dataIndex: "mode", render: (m) => (m === "pin" ? "钉死" : "自动") },
          {
            title: "",
            render: (_, r) => (
              <Button size="small" danger onClick={() => onChange({ ...topo, rules: topo.rules.filter((x) => x.id !== r.id) })}>
                删除
              </Button>
            ),
          },
        ]}
      />
      <Form
        layout="inline"
        style={{ margin: "12px 0 28px" }}
        onFinish={(v: { name: string; match_type: Rule["match_type"]; match_value: string; target_pool: string; mode: Rule["mode"] }) => {
          const rule: Rule = {
            id: `manual-${Date.now()}`,
            name: v.name,
            manual: true,
            priority: (manual[0]?.priority ?? 100) - 10,
            enabled: true,
            overridden: false,
            match_type: v.match_type,
            match_value: v.match_value,
            target_pool: v.target_pool,
            mode: v.mode,
            require_residential: /netflix|disney/i.test(v.name + v.match_value),
            require_v6: false,
            domains: v.match_type === "domain" || v.match_type === "suffix" ? [v.match_value.replace(/^\./, "")] : [],
            geosite: v.match_type === "geosite" ? v.match_value.replace(/^geosite:/, "") : "",
          };
          onChange({ ...topo, rules: [...topo.rules, rule] });
        }}
      >
        <Form.Item name="name" rules={[{ required: true, message: "需要名称" }]}>
          <Input placeholder="名称" />
        </Form.Item>
        <Form.Item name="match_type" initialValue="domain">
          <Select style={{ width: 140 }} options={matchTypes} />
        </Form.Item>
        <Form.Item name="match_value" rules={[{ required: true, message: "需要匹配值" }]}>
          <Input placeholder="api.example.com / geosite 名" />
        </Form.Item>
        <Form.Item name="target_pool" initialValue="us">
          <Select
            style={{ width: 160 }}
            options={["us", "hk", "hk-residential", "jp", "sg", "tw"].map((p) => ({ value: p, label: p }))}
          />
        </Form.Item>
        <Form.Item name="mode" initialValue="pin">
          <Select
            style={{ width: 100 }}
            options={[
              { value: "pin", label: "钉死" },
              { value: "auto", label: "自动" },
            ]}
          />
        </Form.Item>
        <Button htmlType="submit" type="primary">
          添加手动规则
        </Button>
      </Form>

      <h3>自动规则（默认表，改动会标成「已改默认」）</h3>
      <Table
        size="small"
        rowKey="id"
        pagination={false}
        dataSource={auto}
        columns={[
          { title: "服务", dataIndex: "name" },
          { title: "来源", render: (_, r) => r.geosite ? `geosite:${r.geosite}` : r.match_value },
          { title: "出口池", dataIndex: "target_pool" },
          {
            title: "约束",
            render: (_, r) => r.require_residential ? <Tag color="gold">家宽</Tag> : null,
          },
          {
            title: "启用",
            render: (_, r) => (
              <Switch checked={r.enabled} onChange={(enabled) => patch(r.id, { enabled })} />
            ),
          },
          {
            title: "",
            render: (_, r) => r.overridden ? <Tag>已改默认</Tag> : null,
          },
        ]}
      />
    </div>
  );
}
