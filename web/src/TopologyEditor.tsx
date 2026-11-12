import { useCallback, useEffect, useMemo } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  addEdge,
  useEdgesState,
  useNodesState,
  type Connection,
  type Edge,
  type Node as RFNode,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { Button, Form, Input, InputNumber, Select, Switch } from "antd";
import type { Link, Node, Role, Topology, Transport } from "./types";
import { roleLabel, transportLabel } from "./types";

const roleColor: Record<Role, string> = {
  gateway: "#1d4e89",
  relay: "#0f6e6e",
  ix: "#8a5a00",
  hub: "#6b3fa0",
  exit: "#1f6b3a",
};

function toFlow(topo: Topology): { nodes: RFNode[]; edges: Edge[] } {
  return {
    nodes: topo.nodes.map((n) => ({
      id: n.id,
      position: { x: n.x ?? 0, y: n.y ?? 0 },
      data: { label: nodeLabel(n) },
      style: {
        background: n.residential ? "#0b7a3b" : roleColor[n.role],
        color: "#f4f7fb",
        border: n.role === "ix" ? "1px dashed #e2a33a" : "1px solid #0b1016",
        borderRadius: 10,
        width: 150,
        fontSize: 12,
      },
    })),
    edges: topo.links.map((l) => ({
      id: l.id,
      source: l.from,
      target: l.to,
      label: transportLabel[l.transport] + (l.standby ? " · 待命" : ""),
      animated: !l.standby && l.enabled,
      style: { stroke: l.standby ? "#8a6a2a" : "#9ec0de" },
    })),
  };
}

function nodeLabel(n: Node) {
  return (
    <div className="node-card">
      <strong>{n.name}</strong>
      <em>
        {roleLabel[n.role]}
        {n.residential ? " · 家宽" : ""}
        {n.nat_dial_out ? " · 拨出" : ""}
        {n.ix_bound ? " · IX" : ""}
      </em>
    </div>
  );
}

export default function TopologyEditor({
  topo,
  selected,
  onSelect,
  onChange,
}: {
  topo: Topology;
  selected: { kind: "node" | "link"; id: string } | null;
  onSelect: (sel: { kind: "node" | "link"; id: string } | null) => void;
  onChange: (topo: Topology) => void;
}) {
  const initial = useMemo(() => toFlow(topo), [topo]);
  const [nodes, setNodes, onNodesChange] = useNodesState(initial.nodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initial.edges);

  const structureKey = [
    topo.nodes.map((n) => `${n.id}:${n.role}:${n.residential}:${n.nat_dial_out}:${n.ix_bound}`).join(),
    topo.links.map((l) => `${l.id}:${l.transport}:${l.standby}:${l.enabled}`).join(),
  ].join("|");
  const labelKey = topo.nodes.map((n) => `${n.id}:${n.name}:${n.role}:${n.residential}:${n.nat_dial_out}:${n.ix_bound}`).join();

  useEffect(() => {
    const next = toFlow(topo);
    setNodes(next.nodes);
    setEdges(next.edges);
  }, [structureKey, setEdges, setNodes]);

  useEffect(() => {
    setNodes((current) =>
      current.map((n) => {
        const src = topo.nodes.find((x) => x.id === n.id);
        return src ? { ...n, data: { label: nodeLabel(src) } } : n;
      }),
    );
  }, [labelKey, setNodes]);

  const onConnect = useCallback(
    (conn: Connection) => {
      if (!conn.source || !conn.target) return;
      const id = `link-${conn.source}-${conn.target}-${Math.random().toString(36).slice(2, 6)}`;
      const link: Link = {
        id,
        from: conn.source,
        to: conn.target,
        transport: "direct_wg",
        enabled: true,
        standby: false,
        mtu: 1420,
        keepalive: 25,
      };
      onChange({ ...topo, links: [...topo.links, link] });
      setEdges((eds) => addEdge({ ...conn, id, label: "直连 WG" }, eds));
      onSelect({ kind: "link", id });
    },
    [onChange, onSelect, setEdges, topo],
  );

  function commitPositions() {
    const pos = new Map(nodes.map((n) => [n.id, n.position]));
    onChange({
      ...topo,
      nodes: topo.nodes.map((n) => ({ ...n, x: pos.get(n.id)?.x ?? n.x, y: pos.get(n.id)?.y ?? n.y })),
    });
  }

  function addNode(role: Role) {
    const id = `${role}-${Math.random().toString(36).slice(2, 6)}`;
    const node: Node = {
      id,
      name: roleLabel[role],
      role,
      managed: role !== "ix",
      x: 80 + topo.nodes.length * 24,
      y: 80,
      path_v4: true,
      path_v6: role === "hub" ? false : role === "exit",
      egress_v4: role === "exit",
      egress_v6: false,
      nat_dial_out: false,
      residential: false,
      ix_bound: false,
      wan_interface: "eth0",
    };
    onChange({ ...topo, nodes: [...topo.nodes, node] });
    onSelect({ kind: "node", id });
  }

  const currentNode = topo.nodes.find((n) => selected?.kind === "node" && n.id === selected.id);
  const currentLink = topo.links.find((l) => selected?.kind === "link" && l.id === selected.id);

  function patchNode(partial: Partial<Node>) {
    if (!currentNode) return;
    onChange({
      ...topo,
      nodes: topo.nodes.map((n) => (n.id === currentNode.id ? { ...n, ...partial } : n)),
    });
  }

  function patchLink(partial: Partial<Link>) {
    if (!currentLink) return;
    const next = { ...currentLink, ...partial };
    if (next.transport === "ix_replacement_wss" || next.transport === "cf_mesh") {
      next.standby = true;
    }
    onChange({ ...topo, links: topo.links.map((l) => (l.id === next.id ? next : l)) });
  }

  return (
    <div className="layout">
      <div>
        <div className="toolbar">
          {(["gateway", "relay", "ix", "hub", "exit"] as Role[]).map((role) => (
            <Button key={role} onClick={() => addNode(role)}>
              添加{roleLabel[role]}
            </Button>
          ))}
          <Button onClick={commitPositions}>记录位置</Button>
        </div>
        <div className="canvas-wrap">
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onConnect={onConnect}
            onNodeDragStop={(_, node) => {
              onChange({
                ...topo,
                nodes: topo.nodes.map((n) =>
                  n.id === node.id ? { ...n, x: node.position.x, y: node.position.y } : n,
                ),
              });
            }}
            onNodeClick={(_, n) => onSelect({ kind: "node", id: n.id })}
            onEdgeClick={(_, e) => onSelect({ kind: "link", id: e.id })}
            onPaneClick={() => onSelect(null)}
            fitView
          >
            <Background color="#243140" gap={18} />
            <MiniMap pannable zoomable maskColor="rgba(8,12,16,0.7)" />
            <Controls />
          </ReactFlow>
        </div>
      </div>
      <aside className="side">
        {!currentNode && !currentLink && (
          <>
            <h3>拓扑</h3>
            <p>从左到右拉线：家宽 → 阿里云 → IX → 香港枢纽 → 出口。IX 替换 WSS 和 Mesh 会自动标成待命。</p>
            <p>境外默认出口是香港池里 IX 绑定的那一台。家宽出口单独给 Netflix / Disney+。</p>
          </>
        )}
        {currentNode && (
          <>
            <h3>{currentNode.name}</h3>
            <Form layout="vertical" size="small">
              <Form.Item label="名称">
                <Input value={currentNode.name} onChange={(e) => patchNode({ name: e.target.value })} />
              </Form.Item>
              <Form.Item label="角色">
                <Select
                  value={currentNode.role}
                  options={(Object.keys(roleLabel) as Role[]).map((r) => ({ value: r, label: roleLabel[r] }))}
                  onChange={(role) => patchNode({ role })}
                />
              </Form.Item>
              <Form.Item label="公网 IPv4（文档地址，NAT 拨出留空）">
                <Input
                  value={currentNode.endpoint_v4 || ""}
                  onChange={(e) => patchNode({ endpoint_v4: e.target.value })}
                />
              </Form.Item>
              <Form.Item label="出口池">
                <Input value={currentNode.pool || ""} onChange={(e) => patchNode({ pool: e.target.value })} />
              </Form.Item>
              <Form.Item label="SSH 主机（不写入示例密钥）">
                <Input value={currentNode.ssh_host || ""} onChange={(e) => patchNode({ ssh_host: e.target.value })} />
              </Form.Item>
              <Form.Item label="家宽">
                <Switch checked={currentNode.residential} onChange={(residential) => patchNode({ residential })} />
              </Form.Item>
              <Form.Item label="NAT 拨出">
                <Switch checked={currentNode.nat_dial_out} onChange={(nat_dial_out) => patchNode({ nat_dial_out })} />
              </Form.Item>
              <Form.Item label="IX 绑定">
                <Switch checked={currentNode.ix_bound} onChange={(ix_bound) => patchNode({ ix_bound })} />
              </Form.Item>
              <Form.Item label="egress v4 / v6">
                <Switch checked={currentNode.egress_v4} onChange={(egress_v4) => patchNode({ egress_v4 })} />
                <Switch checked={currentNode.egress_v6} onChange={(egress_v6) => patchNode({ egress_v6 })} />
              </Form.Item>
              <Form.Item label="path v4 / v6">
                <Switch checked={currentNode.path_v4} onChange={(path_v4) => patchNode({ path_v4 })} />
                <Switch checked={currentNode.path_v6} onChange={(path_v6) => patchNode({ path_v6 })} />
              </Form.Item>
              <Button danger onClick={() => onChange({ ...topo, nodes: topo.nodes.filter((n) => n.id !== currentNode.id), links: topo.links.filter((l) => l.from !== currentNode.id && l.to !== currentNode.id) })}>
                删除节点
              </Button>
            </Form>
          </>
        )}
        {currentLink && (
          <>
            <h3>{currentLink.name || currentLink.id}</h3>
            <Form layout="vertical" size="small">
              <Form.Item label="传输">
                <Select
                  value={currentLink.transport}
                  options={(Object.keys(transportLabel) as Transport[]).map((t) => ({ value: t, label: transportLabel[t] }))}
                  onChange={(transport) => patchLink({ transport })}
                />
              </Form.Item>
              <Form.Item label="启用">
                <Switch checked={currentLink.enabled} onChange={(enabled) => patchLink({ enabled })} />
              </Form.Item>
              <Form.Item label="待命（不进默认路由）">
                <Switch checked={currentLink.standby} onChange={(standby) => patchLink({ standby })} />
              </Form.Item>
              <Form.Item label="MTU">
                <InputNumber value={currentLink.mtu} onChange={(mtu) => patchLink({ mtu: mtu ?? 0 })} />
              </Form.Item>
              <Form.Item label="WSS MTU">
                <InputNumber value={currentLink.wss_mtu} onChange={(wss_mtu) => patchLink({ wss_mtu: wss_mtu ?? 0 })} />
              </Form.Item>
              <Form.Item label="Keepalive（秒，0 表示拒绝 NAT 拨出）">
                <InputNumber value={currentLink.keepalive} onChange={(keepalive) => patchLink({ keepalive: keepalive ?? 0 })} />
              </Form.Item>
              <Button danger onClick={() => onChange({ ...topo, links: topo.links.filter((l) => l.id !== currentLink.id) })}>
                删除链路
              </Button>
            </Form>
          </>
        )}
      </aside>
    </div>
  );
}
