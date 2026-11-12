import { Input, Switch, Table, Tag } from "antd";
import { useEffect, useState } from "react";
import { getLeakcheck, type LeakItem } from "./api";
import type { Topology } from "./types";

const color: Record<string, string> = {
  pass: "green",
  fail: "red",
  known_limitation: "gold",
  hardware: "blue",
  skip: "default",
};

const label: Record<string, string> = {
  pass: "通过",
  fail: "失败",
  known_limitation: "已知限制",
  hardware: "需要实机",
  skip: "跳过",
};

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

  return (
    <div>
      <p>
        这里核对的是生成配置。测试机上的 dnsleaktest、ipleak，以及 ROS 是否有 fd00::/8 黑洞，都要在实机上做。WebRTC 的 srflx 应该是出口地址；host 候选里出现运营商 GUA 是单条 /64 的已知限制，不算失败。
      </p>
      {err && <p>{err}</p>}
      <Table
        size="small"
        pagination={false}
        rowKey="id"
        dataSource={items}
        columns={[
          { title: "检查", dataIndex: "title" },
          {
            title: "结果",
            width: 120,
            render: (_, it) => <Tag color={color[it.status] || "default"}>{label[it.status] || it.status}</Tag>,
          },
          { title: "说明", dataIndex: "detail" },
        ]}
      />
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
