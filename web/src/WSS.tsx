// WSS carriers: the panel-generated random path per link and self-signed
// certificate per listener, and their two-sided rotation. Only public data
// is shown (fingerprint, validity, "已设置", stages); the path and the
// private key never reach the browser. Changes take effect only through
// the existing installs (gateway install / remote provision), in the order
// the panel lists.

import { Alert, App as AntApp, Button, Space, Tag, Typography } from "antd";
import type { ReactNode } from "react";
import * as api from "./api";
import type { WSSListenerView, WSSPartyView, WSSView } from "./types";
import { ApiErrorAlert, DataTable, DataView, Facts, Mono, Section, StatusTag, TimeText, useAction, useApi, useConfirmDanger, type ApiState } from "./ui";

export function stageLabel(n: number, uncertain?: boolean): string {
  if (uncertain) return "不确定";
  switch (n) {
    case -1:
      return "未安装";
    case 0:
      return "阶段 0（当前凭据）";
    case 1:
      return "阶段 1（接受/信任新旧两套）";
    case 2:
      return "阶段 2（切到新路径/新证书）";
    case 3:
      return "阶段 3（只用新凭据）";
    default:
      return String(n);
  }
}

const REASON: Record<string, string> = {
  manual_path: "手动重新生成路径",
  manual_cert: "手动重新生成证书",
  expiry: "到期前自动轮换",
  migration: "从旧版固定路径迁移",
};

function stateTag(l: WSSListenerView): ReactNode {
  if (l.warnings.some((w) => w.level === "error")) return <StatusTag kind="failed">需要立即处理</StatusTag>;
  if (l.rotating) return <StatusTag kind="running">{REASON[l.rotation_reason ?? ""] ?? "轮换中"}</StatusTag>;
  if (l.inconsistent) return <StatusTag kind="attention">两端不一致</StatusTag>;
  return <StatusTag kind="unverified">已生成（实机未验证）</StatusTag>;
}

/** The WSS card of the deploy page. */
export function WSSPanel({ nodeName }: { nodeName: (id: string) => string }) {
  const wss = useApi(() => api.getWSS(), []);
  return (
    <Section title="WSS 承载：路径与证书" id="wss">
      <WSSPanelBody state={wss} nodeName={nodeName} />
    </Section>
  );
}

function WSSPanelBody({ state, nodeName }: { state: ApiState<WSSView>; nodeName: (id: string) => string }) {
  return (
    <DataView state={state} rows={3}>
      {(v) => (
        <>
          <Typography.Paragraph type="secondary" style={{ marginBottom: 8 }}>
            每条 WSS 链路的升级路径由面板随机生成（只显示“已设置”），每个 WSS 监听使用面板生成的自签证书（有效期 {v.validity_days} 天，到期前 {v.rotate_before}{" "}
            天自动开始轮换）。不使用 ACME，也不需要域名。{v.verification}
          </Typography.Paragraph>
          <Alert type="info" showIcon style={{ marginBottom: 12 }} message="轮换顺序与中断" description={`${v.order}${v.interruption}`} />
          {v.listeners.length === 0 ? (
            <Typography.Text type="secondary">拓扑里没有 WSS 链路。</Typography.Text>
          ) : (
            v.listeners.map((l) => <ListenerCard key={l.node_id} l={l} nodeName={nodeName} onChanged={() => void state.reload()} />)
          )}
        </>
      )}
    </DataView>
  );
}

function ListenerCard({ l, nodeName, onChanged }: { l: WSSListenerView; nodeName: (id: string) => string; onChanged: () => void }) {
  const act = useAction();
  const confirm = useConfirmDanger();
  const { message } = AntApp.useApp();
  const regenCert = () =>
    confirm({
      title: `重新生成 ${nodeName(l.node_id)} 的 WSS 证书？`,
      consequence:
        "面板生成新的自签证书和私钥；旧证书继续有效，直到两端按「下一步」依次重新下发（服务端与客户端交替）。每次下发时这一端的 wstunnel 重启，这条 WSS 承载中断几秒。",
      okText: "重新生成",
      danger: false,
      onOk: async () => {
        const r = await act.run(() => api.wssRegenerateCert(l.node_id), "cert");
        if (r) {
          void message.success(r.committed ? "两端都还没装过，已直接换成新证书" : "已生成新证书：按「下一步」下发两端");
          onChanged();
        }
      },
    });
  const regenPath = (linkId: string) =>
    confirm({
      title: `重新生成链路 ${linkId} 的 WSS 路径？`,
      consequence: "面板生成新的随机路径；服务端先同时接受新旧路径，客户端切换后再去掉旧路径。两端都要重新下发，切换时这条 WSS 承载中断几秒。",
      okText: "重新生成",
      danger: false,
      onOk: async () => {
        const r = await act.run(() => api.wssRegeneratePath(linkId), "path-" + linkId);
        if (r) {
          void message.success(r.committed ? "两端都还没装过，已直接换成新路径" : "已生成新路径：按「下一步」下发两端");
          onChanged();
        }
      },
    });
  const cancel = () =>
    confirm({
      title: "取消这次轮换？",
      consequence: "只在两端都还没装上新凭据时可以取消；新生成的路径和证书会被丢弃。",
      okText: "取消轮换",
      onOk: async () => {
        if (await act.run(() => api.wssCancel(l.node_id), "cancel")) onChanged();
      },
    });
  const partyName = (p: WSSPartyView) => (p.role === "server" ? `服务端（${nodeName(p.node_id)}）` : `客户端 ${p.link_id}（${nodeName(p.node_id)}）`);
  return (
    <div className="wss-listener" data-testid={`wss-listener-${l.node_id}`} style={{ border: "1px solid var(--m-border)", borderRadius: 8, padding: 12, marginBottom: 12, minWidth: 0 }}>
      <Space wrap style={{ marginBottom: 8 }}>
        <Typography.Text strong>{nodeName(l.node_id)}</Typography.Text>
        {stateTag(l)}
        {l.legacy ? <Tag color="orange">旧版迁移中</Tag> : null}
      </Space>
      {act.error ? <ApiErrorAlert error={act.error} onClose={act.clear} /> : null}
      {l.warnings.map((w, i) => (
        <Alert key={i} type={w.level === "error" ? "error" : "warning"} showIcon style={{ marginBottom: 8 }} message={w.message} />
      ))}
      <Facts
        items={[
          ["校验名称（SNI）", <Mono key="n">{l.server_name}</Mono>],
          ["证书指纹 SHA-256", <Mono key="f" copy>{l.cert.fingerprint_sha256}</Mono>],
          ["生成时间", <TimeText key="g" value={l.cert.created_at} />],
          ["到期时间", <span key="e">{new Date(l.cert.not_after).toLocaleString()}（剩 {l.cert.days_left} 天）</span>],
          ...(l.pending_cert
            ? ([
                ["新证书指纹", <Mono key="pf" copy>{l.pending_cert.fingerprint_sha256}</Mono>],
                ["新证书到期", <span key="pe">{new Date(l.pending_cert.not_after).toLocaleString()}</span>],
              ] as [ReactNode, ReactNode][])
            : []),
          ...(l.rotating ? ([["轮换开始", <TimeText key="rs" value={l.rotation_started} />]] as [ReactNode, ReactNode][]) : []),
        ]}
      />
      <DataTable
        size="small"
        rowKey="link_id"
        pageSize={50}
        dataSource={l.links}
        style={{ marginTop: 8 }}
        data-testid={`wss-links-${l.node_id}`}
        columns={[
          { title: "链路", dataIndex: "link_id", kind: "ellipsis", width: 160, mono: true },
          { title: "拨号端", dataIndex: "dialer_id", kind: "ellipsis", width: 150, render: (v: string) => nodeName(v) },
          {
            title: "路径",
            kind: "flex",
            width: 220,
            render: (_: unknown, k) => (
              <Space size={4} wrap>
                {k.path_set ? <Tag color="green">已设置</Tag> : <Tag>未生成</Tag>}
                <TimeText value={k.path_created_at} />
                {k.pending_path_created_at ? <Tag color="blue">新路径待切换</Tag> : null}
                {k.legacy_path_accepted ? <Tag color="orange">旧固定路径仍被接受</Tag> : null}
              </Space>
            ),
          },
          {
            title: "操作",
            kind: "actions",
            width: 128,
            render: (_: unknown, k) => (
              <Button size="small" onClick={() => regenPath(k.link_id)} loading={act.busy === "path-" + k.link_id} disabled={l.legacy || !!k.pending_path_created_at}>
                重新生成路径
              </Button>
            ),
          },
        ]}
      />
      <DataTable
        size="small"
        rowKey="party"
        pageSize={50}
        dataSource={l.parties}
        style={{ marginTop: 8 }}
        data-testid={`wss-parties-${l.node_id}`}
        columns={[
          { title: "一端", kind: "flex", width: 180, render: (_: unknown, p) => partyName(p) },
          { title: "已安装", kind: "flex", width: 180, render: (_: unknown, p) => stageLabel(p.installed_stage, p.uncertain) },
          { title: "下次下发", kind: "flex", width: 180, render: (_: unknown, p) => (l.rotating && p.involved ? stageLabel(p.target_stage) : "—") },
        ]}
      />
      {l.next_steps.length > 0 ? (
        <Alert
          type="warning"
          showIcon
          style={{ marginTop: 8 }}
          data-testid={`wss-next-${l.node_id}`}
          message="下一步"
          description={
            <ol style={{ margin: 0, paddingLeft: 18 }}>
              {l.next_steps.map((s) => (
                <li key={s.party}>
                  {s.node_id === "gw" ? "安装到本机（网关）" : `下发节点 ${nodeName(s.node_id)}`}：{s.party === "server" ? "服务端" : `客户端 ${s.party.replace("client:", "")}`}，从{stageLabel(s.from)}到{stageLabel(s.to)}
                </li>
              ))}
              <li>每下发一端后回到这里看下一步；两端都到阶段 3 后轮换自动完成。</li>
            </ol>
          }
        />
      ) : null}
      {l.results.length > 0 ? (
        <Typography.Paragraph type="secondary" style={{ marginTop: 8, marginBottom: 0, fontSize: 12 }}>
          上次结果：{(() => {
            const r = l.results[l.results.length - 1];
            return `${nodeName(r.node_id)} ${r.party} ${r.ok ? "成功" : "失败"}${r.stage >= 0 ? `（${stageLabel(r.stage)}）` : ""}${r.message ? "：" + r.message : ""}`;
          })()}
        </Typography.Paragraph>
      ) : null}
      <Space style={{ marginTop: 8 }} wrap>
        <Button onClick={regenCert} loading={act.busy === "cert"} disabled={l.rotating}>
          重新生成证书
        </Button>
        {l.rotating && !l.legacy ? (
          <Button onClick={cancel} loading={act.busy === "cancel"}>
            取消轮换
          </Button>
        ) : null}
      </Space>
    </div>
  );
}

/** Compact status of one WSS link for the topology link editor. */
export function WSSLinkStatus({ linkId }: { linkId: string }) {
  const wss = useApi(() => api.getWSS(), [linkId]);
  return (
    <DataView state={wss} rows={1}>
      {(v) => {
        const l = v.listeners.find((x) => x.links.some((k) => k.link_id === linkId));
        const k = l?.links.find((x) => x.link_id === linkId);
        if (!l || !k) {
          return (
            <Typography.Text type="secondary" data-testid="wss-link-status">
              保存后由面板生成随机路径和自签证书。
            </Typography.Text>
          );
        }
        return (
          <div data-testid="wss-link-status">
            <Facts
              items={[
                ["WSS 路径", <span key="p">{k.path_set ? "已设置（面板随机生成，不显示）" : "未生成"}</span>],
                ["监听证书指纹", <Mono key="f">{l.cert.fingerprint_sha256}</Mono>],
                ["证书到期", <span key="e">剩 {l.cert.days_left} 天</span>],
                ["状态", <span key="s">{stateTag(l)}</span>],
              ]}
            />
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              在「部署」页的「WSS 承载」里重新生成路径或证书并按顺序下发两端。
            </Typography.Text>
          </div>
        );
      }}
    </DataView>
  );
}
