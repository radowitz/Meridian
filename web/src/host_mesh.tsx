// Host-level Cloudflare Mesh detection (POST /api/mesh/detect): a tag for the
// servers and topology pages and the detail table of the Mesh page. Long
// explanations stay behind the help button; conflicts and failures show.

import { Button, Space, Typography } from "antd";
import { useState } from "react";
import * as api from "./api";
import type { HostMeshDetection } from "./types";
import { DataTable, Help, Mono, StatusTag, TimeText, useApi } from "./ui";

const MODE: Record<string, string> = { connector: "connector", mesh: "Mesh", warp: "WARP 客户端", proxy: "代理模式", unknown: "未知" };
const ACCOUNT: Record<string, string> = { matched: "账户一致", mismatch: "账户不一致", unknown: "账户未知" };
const OPTION: Record<string, string> = { host_connector: "主机级 Linux 节点（cloudflare-warp connector）" };
const ORIGIN: Record<string, string> = { existing_host: "主机已有（沿用）", panel_host: "面板安装", panel_sidecar: "旧版 sidecar（只能撤回）" };

/** One-word state of a detection. */
export function HostMeshTag({ d }: { d: HostMeshDetection | undefined }) {
  if (!d) return <StatusTag kind="neutral">Mesh 未检测</StatusTag>;
  if (d.state === "detect_failed") return <StatusTag kind="attention">Mesh 检测失败</StatusTag>;
  if (d.state === "no_node") return <StatusTag kind="neutral">无 Mesh 节点</StatusTag>;
  if (!d.coexist.ok) return <StatusTag kind="failed">已有 Mesh · 冲突</StatusTag>;
  if (d.reusable && d.origin === "panel_host") return <StatusTag kind="ok">Mesh · 面板安装</StatusTag>;
  if (d.reusable) return <StatusTag kind="ok">已有 Mesh · 可沿用</StatusTag>;
  return <StatusTag kind="attention">已有 Mesh · {d.account !== "matched" ? ACCOUNT[d.account] : "缺地址"}</StatusTag>;
}

function Detail({ d }: { d: HostMeshDetection }) {
  if (d.state === "detect_failed") return <Typography.Text type="danger">{d.reasons.join("；")}</Typography.Text>;
  const blocking = d.coexist.conflicts ?? [];
  return (
    <Space direction="vertical" size={2}>
      {d.state === "existing_node" ? (
        <span>
          {MODE[d.mode] ?? d.mode} · {d.mesh_addr ? <Mono>{`${d.mesh_addr} ${d.iface ?? ""}`}</Mono> : "无 Mesh 地址"} · {ACCOUNT[d.account]}
          {d.account_reason ? <Typography.Text type="secondary">（{d.account_reason}）</Typography.Text> : null}
        </span>
      ) : (
        <span>{d.reasons[0]}</span>
      )}
      {blocking.length > 0 ? <Typography.Text type="danger">阻断：{blocking.join("；")}</Typography.Text> : null}
      {d.install ? (
        d.install.recommended ? (
          <span>需安装：{OPTION[d.install.recommended] ?? d.install.recommended}（部署前由你确认）</span>
        ) : (
          <Typography.Text type="danger">不能安装：{d.install.options.flatMap((o) => o.blockers ?? []).join("；")}</Typography.Text>
        )
      ) : null}
    </Space>
  );
}

/** Detection results for the plan nodes, with a detect button. */
export function HostMeshTable({
  nodes,
  detections,
  busy,
  onDetect,
}: {
  nodes: { id: string; name?: string }[];
  detections: Record<string, HostMeshDetection>;
  busy: boolean;
  onDetect: () => void;
}) {
  return (
    <div data-testid="host-mesh">
      <Space wrap align="center">
        <Typography.Title level={3} style={{ margin: 0 }}>
          主机上已有的 Mesh
        </Typography.Title>
        <Help title="说明">
          经已确认指纹的 SSH 运行固定只读命令，读 warp-svc、模式、账户、100.96.0.0/12 地址和策略路由。沿用的节点面板不改注册、不重装、撤回时不动。
        </Help>
        <Button size="small" loading={busy} onClick={onDetect}>
          检测主机 Mesh
        </Button>
      </Space>
      <DataTable
        size="small"
        rowKey="id"
        pageSize={50}
        dataSource={nodes}
        columns={[
          { title: "节点", kind: "flex", width: 140, render: (_, n) => n.name || n.id },
          { title: "状态", kind: "flex", width: 160, render: (_, n) => <HostMeshTag d={detections[n.id]} /> },
          { title: "详情", kind: "flex", width: 280, render: (_, n) => (detections[n.id] ? <Detail d={detections[n.id]} /> : "—") },
          {
            title: "来源",
            kind: "flex",
            width: 110,
            render: (_, n) => {
              const d = detections[n.id];
              return !d ? "—" : ORIGIN[d.origin] ?? "—";
            },
          },
          { title: "检测时间", kind: "flex", width: 120, render: (_, n) => <TimeText value={detections[n.id]?.checked_at} /> },
        ]}
      />
    </div>
  );
}

/** Detection state of one topology node, with a per-node detect button. */
export function NodeHostMesh({ nodeId }: { nodeId: string }) {
  const st = useApi(() => api.getMesh(), [nodeId]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const d = st.data?.host_mesh?.[nodeId];
  return (
    <span className="inline-status wrap" data-testid="node-host-mesh">
      <HostMeshTag d={d} />
      {d && d.state !== "no_node" ? <Typography.Text type={d.coexist.ok && d.state !== "detect_failed" ? "secondary" : "danger"} className="cell-small">{d.state === "detect_failed" || !d.coexist.ok ? d.reasons.join("；") : d.mesh_addr ?? ""}</Typography.Text> : null}
      <Button
        size="small"
        type="link"
        loading={busy}
        onClick={async () => {
          setBusy(true);
          setErr(null);
          try {
            await api.meshDetect(nodeId);
          } catch (e) {
            setErr((e as Error).message);
          } finally {
            setBusy(false);
            await st.reload();
          }
        }}
      >
        检测 Mesh
      </Button>
      {err ? <Typography.Text type="danger">{err}</Typography.Text> : null}
    </span>
  );
}

/** The full install plan of every host that gets the connector: what the
 * operator confirms before the deploy. Blockers stay visible. */
export function InstallPlans({ nodes, detections }: { nodes: string[]; detections: Record<string, HostMeshDetection> }) {
  if (nodes.length === 0) return null;
  return (
    <div data-testid="mesh-install-plans">
      <Space wrap align="center">
        <Typography.Title level={3} style={{ margin: 0 }}>
          将安装的主机级节点
        </Typography.Title>
        <Help title="安装内容">
          只装 Cloudflare 官方 cloudflare-warp，注册为 connector，不接管默认路由；节点令牌只在安装时注入、主机上 0600、用完即删。撤回只移除面板创建的部分。
        </Help>
      </Space>
      <DataTable
        size="small"
        rowKey="id"
        pageSize={50}
        dataSource={nodes.map((id) => ({ id }))}
        columns={[
          { title: "节点", kind: "flex", width: 110, render: (_, n) => n.id },
          {
            title: "安装内容",
            kind: "flex",
            width: 320,
            render: (_, n) => {
              const o = detections[n.id]?.install?.options?.[0];
              if (!o) return <Typography.Text type="danger">没有检测结果：先检测这台主机</Typography.Text>;
              return (
                <Space direction="vertical" size={0}>
                  <span>
                    源 <Mono>{o.repo ?? "—"}</Mono>
                  </span>
                  <span>
                    签名公钥指纹 {o.key_fingerprint ? <Mono>{o.key_fingerprint}</Mono> : <Typography.Text type="danger">未配置</Typography.Text>}
                  </span>
                  <span>
                    包 {(o.packages ?? []).join("、")} · 服务 {(o.services ?? []).join("、")}
                  </span>
                  <span>
                    内存约 {o.mem_estimate_mb ?? "—"} MB（估计）
                    {o.mem_note ? <Help title="估计依据">{o.mem_note}</Help> : null}
                  </span>
                  {(o.blockers ?? []).length ? <Typography.Text type="danger">阻断：{(o.blockers ?? []).join("；")}</Typography.Text> : null}
                </Space>
              );
            },
          },
          {
            title: "主机条件",
            kind: "flex",
            width: 160,
            render: (_, n) => {
              const d = detections[n.id];
              if (!d) return "—";
              return (
                <span>
                  {d.os ?? "?"} {d.codename ?? ""} · {d.arch ?? "?"} · 源{d.repo_reach === "ok" ? "可达" : d.repo_reach === "unreachable" ? "不可达" : "未知"} · 可用内存 {d.mem_avail_mb < 0 ? "未知" : `${d.mem_avail_mb} MB`}
                </span>
              );
            },
          },
        ]}
      />
    </div>
  );
}
