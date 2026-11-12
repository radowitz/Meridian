import { Alert, Input, Switch, Table, Tag } from "antd";
import { useEffect, useState } from "react";
import { getLeakcheck, type LeakItem } from "./api";
import type { Topology } from "./types";

const color: Record<string, string> = {
  pass: "green",
  fail: "red",
  known_limitation: "gold",
  unknown: "default",
  pending_signoff: "blue",
  skip: "default",
};

// "pass" here only ever means the generated configuration contains the rule.
const label: Record<string, string> = {
  pass: "配置包含",
  fail: "失败",
  known_limitation: "已知限制",
  unknown: "未执行",
  pending_signoff: "待人工签收",
  skip: "不适用",
};

const scopes: { key: string; title: string; note: string }[] = [
  {
    key: "automated",
    title: "自动化回归：生成配置核对",
    note: "面板和 go test 读的是编译出来的文本。「配置包含」只说明规则写进了配置，不说明它已经加载到网关，更不证明不泄漏。",
  },
  {
    key: "integration",
    title: "隔离 Linux 集成证据",
    note: "netns 测试和 deploy/ 下的验证脚本要在 Linux 上实际运行并存档日志。面板不代跑，也无法得知是否跑过，所以一律显示「未执行」。",
  },
  {
    key: "human",
    title: "实机人工签收",
    note: "真实测试机、ROS、断隧道和抓包。面板不会把这些标成通过；签收时把截图、命令输出和抓包存档。",
  },
  { key: "limitation", title: "已知限制", note: "设计边界，不算失败，也不能写成已解决。" },
];

export default function LeakPanel({ topo, onChange }: { topo: Topology; onChange: (t: Topology) => void }) {
  const [items, setItems] = useState<LeakItem[]>([]);
  const [err, setErr] = useState("");
  const nat = topo.settings.nat64 || { reserved: true, enabled: false, prefix: "" };

  useEffect(() => {
    getLeakcheck().then((r) => setItems(r.items || [])).catch((e) => setErr(e instanceof Error ? e.message : String(e)));
  }, [topo]);

  function patchNAT(partial: Partial<typeof nat>) {
    onChange({ ...topo, settings: { ...topo.settings, nat64: { ...nat, reserved: true, ...partial } } });
  }

  const columns = [
    { title: "检查", dataIndex: "title" },
    {
      title: "结果",
      width: 120,
      render: (_: unknown, it: LeakItem) => <Tag color={color[it.status] || "default"}>{label[it.status] || it.status}</Tag>,
    },
    { title: "说明", dataIndex: "detail" },
  ];

  return (
    <div>
      <Alert
        type="warning"
        showIcon
        style={{ marginBottom: 12 }}
        message="本页没有任何一项能证明不泄漏。"
        description="发布前需要：网关上 meridian-verify.sh 的输出（缺防火墙表即失败）、隔离 Linux 集成测试日志，以及测试机 DNS 泄漏、WebRTC、ROS fd00::/8、断隧道和抓包的人工签收。WebRTC host 候选里出现运营商 GUA 是单条 /64 的已知限制，不算失败。"
      />
      {err && <p>{err}</p>}
      {scopes.map((sc) => {
        const rows = items.filter((it) => (it.scope || "automated") === sc.key);
        if (rows.length === 0) return null;
        return (
          <div key={sc.key} style={{ marginBottom: 20 }}>
            <h3>{sc.title}</h3>
            <p>{sc.note}</p>
            <Table size="small" pagination={false} rowKey="id" dataSource={rows} columns={columns} />
          </div>
        );
      })}
      <h3 style={{ marginTop: 24 }}>NAT64 预留</h3>
      <p>打开也只是记下前缀。这一期不会把 NAT64 装进路由表，现有 IPv4 路径保持原样。保存拓扑后才会写入枢纽上的占位文件。</p>
      <div style={{ display: "flex", gap: 16, alignItems: "center" }}>
        <span>启用占位</span>
        <Switch checked={nat.enabled} onChange={(enabled) => patchNAT({ enabled })} />
        <Input
          style={{ width: 240 }}
          placeholder="前缀，例如 64:ff9b::/96"
          value={nat.prefix || ""}
          onChange={(e) => patchNAT({ prefix: e.target.value })}
        />
      </div>
    </div>
  );
}
