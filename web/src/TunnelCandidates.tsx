// Tunnel management address candidates of a server (GET
// /api/servers/{id}/tunnel-candidates): derived on the panel from the
// topology and the allocation — which tunnel and peer each address lives
// on, whether it depends on the main path or the backup hub, and why the
// other addresses cannot be reached from the gateway. Nothing is contacted
// to derive them. The connection test of a candidate (before saving) uses
// the pinned host key and the server's credential and counts against the
// same rate limits; the panel never switches the channel by itself.

import { Button, Radio, Space, Typography } from "antd";
import { useState } from "react";
import * as api from "./api";
import type { ConnectionTest, MgmtCandidate, MgmtDepends, TunnelCandidates, TunnelPathNote } from "./types";
import {
  ApiErrorAlert,
  DataView,
  Mono,
  RateLimitNote,
  StatusTag,
  noteRateLimited,
  useAction,
  useApi,
  useServerCooldown,
  Note,
} from "./ui";

export const DEPENDS_TEXT: Record<MgmtDepends, string> = {
  own_link: "网关自己到它的隧道",
  any: "随网关当前的承载路径",
  main: "依赖主链路",
  backup_hub: "依赖备用枢纽",
  fallback: "依赖直连枢纽的 WSS 备路",
  mixed: "只在部分承载状态下可用",
};

function linkText(c: MgmtCandidate) {
  return `链路 ${c.link_name || c.link_id}（${c.iface}${c.mode === "wss" ? "，WSS" : ""}${c.standby ? "，备用" : ""}）· 对端 ${c.peer_name || c.peer_id}`;
}

function CandidateRow({ c, carrying }: { c: MgmtCandidate; carrying: TunnelCandidates["carrying"] }) {
  const works = (c.works ?? []).map((w) => w.state);
  const now = carrying.known && carrying.state ? works.includes(carrying.state) : undefined;
  return (
    <div className="tunnel-candidate" data-testid={`tunnel-candidate-${c.address}`} data-status={c.status}>
      <Space size={4} wrap>
        <Mono>{c.address}</Mono>
        <span className="muted">{c.family === "ipv6" ? "IPv6" : "IPv4"}</span>
        {c.status === "usable" ? (
          <StatusTag kind="ok">{DEPENDS_TEXT[c.depends ?? "any"]}</StatusTag>
        ) : c.status === "unknown" ? (
          <StatusTag kind="attention">无法判断</StatusTag>
        ) : (
          <StatusTag kind="failed">从网关到不了</StatusTag>
        )}
        {c.status === "usable" && now === false ? <StatusTag kind="attention">当前承载状态下不通</StatusTag> : null}
      </Space>
      <Typography.Text type="secondary" style={{ display: "block", fontSize: 12 }}>
        {linkText(c)}
      </Typography.Text>
      {c.status !== "usable" && c.reason ? (
        <Typography.Text
          type="secondary"
          style={{ display: "block", fontSize: 12, overflowWrap: "anywhere" }}
          data-testid={`tunnel-candidate-reason-${c.address}`}
        >
          原因：{c.reason}
        </Typography.Text>
      ) : null}
    </div>
  );
}

/** The candidate list, the carrying state, the manual-entry note and the test. */
export function CandidateList({ data, address, onPick }: { data: TunnelCandidates; address: string; onPick: (address: string) => void }) {
  const all = data.nodes.flatMap((n) => n.candidates);
  const usable = all.filter((c) => c.status === "usable");
  const other = all.filter((c) => c.status !== "usable");
  const derived = all.some((c) => c.address === address.trim());
  const notes = data.nodes.flatMap((n) => n.notes);
  if (data.nodes.length === 0) {
    return (
      <Note testId="tunnel-candidates-none">
        {data.message ?? "没有可以推导的隧道地址"}
      </Note>
    );
  }
  return (
    <div data-testid="tunnel-candidates">
      <Typography.Text type="secondary" style={{ display: "block", fontSize: 12 }} data-testid="tunnel-carrying">
        {data.carrying.known ? `网关当前经「${data.carrying.label}」承载。` : `${data.carrying.message ?? "读不到网关当前的承载路径"}。`}
      </Typography.Text>
      {usable.length > 0 ? (
        <Radio.Group value={derived ? address.trim() : undefined} onChange={(e) => onPick(e.target.value as string)} style={{ display: "block", marginTop: 8 }}>
          <Space direction="vertical" size={6} style={{ width: "100%" }}>
            {usable.map((c) => (
              <Radio key={c.address} value={c.address} data-testid={`tunnel-pick-${c.address}`}>
                <CandidateRow c={c} carrying={data.carrying} />
              </Radio>
            ))}
          </Space>
        </Radio.Group>
      ) : (
        <Typography.Paragraph type="warning" style={{ marginTop: 8 }} data-testid="tunnel-candidates-no-usable">
          按配置推导，这台服务器没有从网关两个方向都走得通的隧道地址。
        </Typography.Paragraph>
      )}
      {other.length > 0 ? (
        <div style={{ marginTop: 8 }} data-testid="tunnel-candidates-unusable">
          <Typography.Text strong style={{ fontSize: 12 }}>
            不能选的地址（{other.length}）
          </Typography.Text>
          <Space direction="vertical" size={6} style={{ width: "100%", marginTop: 4 }}>
            {other.map((c) => (
              <Radio key={c.address} value={c.address} disabled checked={false}>
                <CandidateRow c={c} carrying={data.carrying} />
              </Radio>
            ))}
          </Space>
        </div>
      ) : null}
      {address.trim() && !derived ? (
        <Typography.Paragraph type="warning" style={{ marginTop: 8 }} data-testid="tunnel-manual-note">
          手工填写的地址 {address.trim()} 不在推导的候选里：未经推导，面板不知道它经哪条路径、依赖主链路还是备用枢纽。保存前先测试连接。
        </Typography.Paragraph>
      ) : null}
      <Note>{"「可以选」是什么意思"}{" "}
        从拓扑和地址分配推导：网关到这个地址有经自己隧道的路由，沿途每一跳的路由和 WireGuard AllowedIPs
        让请求过去，回程也能按同样的检查回到网关用的源地址。它说明配置上两个方向都走得通，不说明隧道此刻在握手、服务器的 sshd
        和防火墙接受这个来源——那要靠下面的连接测试。
        {notes.length > 0 ? (
          <ul className="plain-list">
            {notes.map((n) => (
              <li key={n}>{n}</li>
            ))}
          </ul>
        ) : null}
      </Note>
    </div>
  );
}

/** The test result of a candidate (not recorded on the server). */
export function CandidateTestResult({ test, note, cooldown }: { test: ConnectionTest; note?: TunnelPathNote; cooldown: number }) {
  if (test.ok) {
    return (
      <div data-testid="tunnel-test-result" data-ok="true">
        <StatusTag kind="ok">连接成功</StatusTag>
        <Note inline>经这个地址登录并运行了只读测试命令；结果没有记录到服务器上，保存通道后再在服务器详情里测试一次。</Note>
      </div>
    );
  }
  return (
    <div data-testid="tunnel-test-result" data-ok="false">
      <StatusTag kind="failed">连接失败</StatusTag>
      <Typography.Text style={{ display: "block", overflowWrap: "anywhere" }}>{test.error}</Typography.Text>
      {test.code === "ssh_rate_limited" ? <RateLimitNote seconds={cooldown} /> : null}
      {note?.text ? (
        <Typography.Text type="secondary" style={{ display: "block", fontSize: 12 }} data-testid="tunnel-test-path-note">
          {note.text}
        </Typography.Text>
      ) : null}
    </div>
  );
}

/**
 * The picker in the server form: the candidates of a saved server (a new one
 * has no node yet), the pick fills the address field, and the connection
 * test before saving.
 */
export function TunnelCandidatePicker({
  serverId,
  address,
  port,
  onPick,
}: {
  serverId?: string;
  address: string;
  port?: number;
  onPick: (address: string) => void;
}) {
  const state = useApi(() => (serverId ? api.getTunnelCandidates(serverId) : Promise.resolve(null)), [serverId]);
  const act = useAction();
  const cooldown = useServerCooldown(serverId ?? "");
  const [result, setResult] = useState<{ test: ConnectionTest; note?: TunnelPathNote; address: string } | null>(null);
  if (!serverId) {
    return (
      <Note testId="tunnel-candidates-new">
        保存这台服务器并在拓扑里把它关联到节点后，这里会列出从拓扑推导的隧道地址候选。现在可以手工填写（未经推导）。
      </Note>
    );
  }
  const test = () =>
    act.run(async () => {
      setResult(null);
      const r = await api.testTunnelCandidate(serverId, address.trim(), port);
      if (r.test.code === "ssh_rate_limited") noteRateLimited(serverId, r.test.retry_after ?? 60);
      setResult({ test: r.test, note: r.path_note, address: address.trim() });
    }, "test");
  return (
    <div style={{ marginBottom: 16 }} data-testid="tunnel-picker">
      <Typography.Text strong>地址候选</Typography.Text>
      <DataView state={state} rows={2}>
        {(d) => (d ? <CandidateList data={d} address={address} onPick={onPick} /> : null)}
      </DataView>
      <Space wrap style={{ marginTop: 8 }}>
        <Button onClick={() => void test()} loading={act.busy === "test"} disabled={!address.trim() || cooldown > 0} data-testid="tunnel-test">
          {cooldown > 0 ? `${cooldown} 秒后可测试` : "保存前测试连接"}
        </Button>
        <Note inline>用固定的主机指纹和这台服务器的凭据，经上面填的地址登录一次，计入同样的限速；不会保存，也不会自动改走别的通道。</Note>
      </Space>
      {act.error ? (
        <div style={{ marginTop: 8 }}>
          <ApiErrorAlert error={act.error} onClose={act.clear} />
          {act.error.code === "host_key_untrusted" ? (
            <Note inline>主机指纹还没有固定：先按原有流程获取并核对指纹（可以先保存这个通道，再在服务器详情里「发现指纹」并确认），然后再测试。</Note>
          ) : null}
        </div>
      ) : null}
      {result && result.address === address.trim() ? (
        <div style={{ marginTop: 8 }}>
          <CandidateTestResult test={result.test} note={result.note} cooldown={cooldown} />
        </div>
      ) : null}
    </div>
  );
}
