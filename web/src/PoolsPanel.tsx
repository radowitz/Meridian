import { Input, InputNumber, Table, Tag } from "antd";
import { useEffect, useState } from "react";
import { getPools, type PoolView } from "./api";
import type { Node, Topology } from "./types";

export default function PoolsPanel({ topo, onChange }: { topo: Topology; onChange: (t: Topology) => void }) {
  const [live, setLive] = useState<PoolView[]>([]);
  const [err, setErr] = useState("");

  useEffect(() => {
    getPools().then((r) => setLive(r.pools || [])).catch((e) => setErr(e instanceof Error ? e.message : String(e)));
  }, [topo.nodes]);

  const exits = topo.nodes.filter((n) => n.role === "exit");
  function patch(id: string, partial: Partial<Node>) {
    onChange({ ...topo, nodes: topo.nodes.map((n) => (n.id === id ? { ...n, ...partial } : n)) });
  }

  const pools = new Map<string, Node[]>();
  for (const n of exits) {
    const key = n.pool || "（未分组）";
    pools.set(key, [...(pools.get(key) || []), n]);
  }

  return (
    <div>
      <p>
        默认境外是香港池，IX 绑定的成员优先。家宽单独成池，不进默认池。链路故障时只改这个池对应路由表的下一跳：连续 3 次失败才换，连续 5 次成功再加 120 秒冷却才切回。一次失败不会抖。Mesh 只在池里所有 WireGuard 成员都失败之后，才会成为这一跳的下一跳。
      </p>
      {err && <p>{err}</p>}
      {[...pools.entries()].map(([id, members]) => {
        const remote = live.find((p) => p.id === id);
        const ordered = [...members].sort((a, b) => {
          if (a.ix_bound !== b.ix_bound) return a.ix_bound ? -1 : 1;
          return (a.pool_priority || 0) - (b.pool_priority || 0) || a.id.localeCompare(b.id);
        });
        return (
          <section key={id} style={{ marginBottom: 28 }}>
            <h3>
              {id}{" "}
              {remote?.residential || ordered.every((m) => m.residential) ? <Tag color="green">家宽</Tag> : null}
              {remote?.mesh_backup ? <Tag>Mesh 备路</Tag> : null}
              {remote?.active ? <Tag color="gold">当前下一跳 {remote.active}</Tag> : <Tag>尚未收到健康探测</Tag>}
            </h3>
            <Table
              size="small"
              pagination={false}
              rowKey="id"
              dataSource={ordered}
              columns={[
                { title: "出口", dataIndex: "name" },
                { title: "ID", dataIndex: "id", width: 120 },
                {
                  title: "池",
                  render: (_, n) => <Input value={n.pool || ""} onChange={(e) => patch(n.id, { pool: e.target.value })} />,
                },
                {
                  title: "优先级",
                  width: 110,
                  render: (_, n) => (
                    <InputNumber value={n.pool_priority || 0} onChange={(v) => patch(n.id, { pool_priority: v ?? 0 })} />
                  ),
                },
                {
                  title: "属性",
                  render: (_, n) => (
                    <>
                      {n.ix_bound ? <Tag color="blue">IX</Tag> : null}
                      {n.residential ? <Tag color="green">家宽</Tag> : null}
                      {ordered[0]?.id === n.id ? <Tag color="gold">首选</Tag> : null}
                    </>
                  ),
                },
                {
                  title: "健康",
                  width: 90,
                  render: (_, n) => {
                    const up = remote?.members.find((m) => m.id === n.id)?.up;
                    if (up === undefined) return "—";
                    return up ? "通" : "失败累计中";
                  },
                },
              ]}
            />
          </section>
        );
      })}
    </div>
  );
}
