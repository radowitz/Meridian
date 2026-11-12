import { useCallback, useEffect, useState } from "react";
import { Alert, Button, Checkbox, Descriptions, Input, Select, Space, Tag } from "antd";
import * as api from "./api";

// Panel-driven Cloudflare Mesh deployment. A published run means "the
// Cloudflare routes are published"; it never means Mesh is usable. The data
// plane stays 未验证 until Linux forwarding evidence is archived.

const stageLabel: Record<string, string> = {
  plan: "计划与地址校验",
  preflight: "远端预检",
  cf_node: "Cloudflare 节点",
  sidecar: "部署 sidecar",
  health: "健康检查",
  routes: "发布路由",
  activate: "枢纽重新封装",
};

const stateLabel: Record<string, { text: string; color: string }> = {
  running: { text: "进行中（或被中断）", color: "blue" },
  published: { text: "路由已发布 · 数据面未验证", color: "gold" },
  failed: { text: "失败，已撤回本次创建的资源", color: "default" },
  compensating: { text: "撤回中（或被中断）", color: "orange" },
  compensation_failed: { text: "补偿未完成", color: "red" },
  withdrawn: { text: "已撤回", color: "default" },
};

function stageTag(status: string) {
  switch (status) {
    case "done":
      return <Tag color="green">完成</Tag>;
    case "failed":
      return <Tag color="red">失败</Tag>;
    case "running":
      return <Tag color="blue">进行中</Tag>;
    case "skipped":
      return <Tag>未执行</Tag>;
    default:
      return <Tag>等待</Tag>;
  }
}

const busyStates = ["running", "published", "compensating", "compensation_failed"];

export default function MeshDeploy() {
  const [status, setStatus] = useState<api.MeshStatus | null>(null);
  const [accountId, setAccountId] = useState("");
  const [apiToken, setApiToken] = useState("");
  const [sshKey, setSshKey] = useState("");
  const [trust, setTrust] = useState(false);
  const [hosts, setHosts] = useState<Record<string, string>>({});
  const [failAfter, setFailAfter] = useState<string | undefined>(undefined);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");
  const [compErrs, setCompErrs] = useState<string[]>([]);

  const refresh = useCallback(async () => {
    try {
      setStatus(await api.getMesh());
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  async function run(fn: () => Promise<void>) {
    setBusy(true);
    setErr("");
    setMsg("");
    setCompErrs([]);
    try {
      await fn();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
      const body = (e as { body?: api.MeshRunResult } | undefined)?.body;
      setCompErrs(body?.compensation_errors ?? []);
    } finally {
      setBusy(false);
      await refresh();
    }
  }

  function runBody(): api.MeshRunBody {
    const nodes: api.MeshRunBody["nodes"] = {};
    for (const [id, host] of Object.entries(hosts)) {
      if (host.trim()) nodes[id] = { ssh_host: host.trim() };
    }
    return { private_key_pem: sshKey, trust_new_host: trust, nodes, fail_after: failAfter };
  }

  const plan = status?.plan;
  const journal = status?.journal ?? null;
  const issues = plan?.issues ?? [];
  const journalBusy = !!journal && busyStates.includes(journal.state);
  const creds = status?.credentials;
  const a = plan?.addressing;

  return (
    <div style={{ marginTop: 22 }}>
      <h3>Cloudflare Mesh 部署</h3>
      <Alert
        type="warning"
        showIcon
        style={{ marginBottom: 12 }}
        message="Mesh 数据面：未验证"
        description={
          status?.dataplane_note ??
          "路由发布成功不等于 Mesh 可用。需要在隔离的 Linux 主机上运行 deploy/verify-mesh-veth.sh 并存档，再做真实转发与人工签收。"
        }
      />
      <p>
        顺序：计划并校验两端 IPv4 / IPv6 地址、下一跳与接口作用域 → 远端预检（冲突、已有 Mesh 状态、旧的
        default dev mmesh 脚本）→ 创建 Cloudflare 节点（sidecar 入网需要它的令牌）→ 部署 sidecar 并封装 →
        健康检查（两个下一跳可达、只解析下一跳、warp-cli 已连接、Cloudflare 节点 healthy）→ 才发布路由 →
        枢纽重新封装。任一步失败即停止，撤回本次发布的路由、节点和 sidecar，并把受管文件恢复原样；补偿失败会单独列出，可重复撤回。
      </p>

      <Descriptions size="small" column={1} bordered style={{ marginBottom: 12 }}>
        <Descriptions.Item label="Cloudflare 凭据">
          {creds ? (
            <>
              账户 {creds.account_id}，API token {creds.token_set ? <Tag color="green">已保存（不回显）</Tag> : <Tag>未保存</Tag>}
            </>
          ) : (
            <Tag>未保存</Tag>
          )}
          {status?.credentials_error && <Alert type="error" message={status.credentials_error} />}
        </Descriptions.Item>
        {a && (
          <Descriptions.Item label="veth 地址与下一跳">
            <div>
              IPv4：主机 {a.host_v4}/{a.link_v4.split("/")[1]} dev {a.host_iface} ↔ sidecar {a.sidecar_v4} dev {a.sidecar_iface}；出口表
              default via {a.sidecar_v4} dev {a.host_iface}
            </div>
            <div>
              IPv6：主机 {a.host_v6}/{a.v6_bits} ↔ sidecar {a.sidecar_v6}/{a.v6_bits}（链路本地）；出口表 default via {a.sidecar_v6} dev{" "}
              {a.host_iface}
            </div>
            <div>
              固定 MAC {a.host_mac} / {a.sidecar_mac}，两端永久邻居；sidecar 回程 {(plan?.return_v4 ?? []).join(" ")} via {a.host_v4}，
              {(plan?.return_v6 ?? []).join(" ")} via {a.host_v6}
            </div>
          </Descriptions.Item>
        )}
        <Descriptions.Item label="待发布路由">
          {(plan?.routes ?? []).length === 0
            ? "无（在拓扑里给 Mesh 边填写 mesh_routes）"
            : (plan?.routes ?? []).map((r) => (
                <div key={r.link_id + r.network}>
                  {r.network} → {r.exit_id}（{r.link_id}）
                </div>
              ))}
        </Descriptions.Item>
      </Descriptions>

      {status?.plan_error && <Alert type="error" style={{ marginBottom: 8 }} message={status.plan_error} />}
      {issues.map((i) => (
        <Alert key={i.code + i.message} type="error" style={{ marginBottom: 6 }} message={`${i.code}：${i.message}`} />
      ))}

      <Space wrap style={{ marginBottom: 12 }}>
        <Input
          style={{ width: 300 }}
          placeholder="Cloudflare account id（32 位十六进制）"
          value={accountId}
          onChange={(e) => setAccountId(e.target.value)}
        />
        <Input.Password
          style={{ width: 300 }}
          placeholder="API token（只写，不会回显）"
          autoComplete="off"
          value={apiToken}
          onChange={(e) => setApiToken(e.target.value)}
        />
        <Button
          disabled={busy || !accountId || !apiToken}
          onClick={() =>
            run(async () => {
              await api.putMeshCredentials(accountId, apiToken);
              setApiToken("");
              setMsg("凭据已保存（0600），面板不会再返回 token。");
            })
          }
        >
          保存凭据
        </Button>
        {creds && (
          <Button
            danger
            disabled={busy || journalBusy}
            onClick={() =>
              run(async () => {
                await api.deleteMeshCredentials();
                setMsg("凭据已删除。");
              })
            }
          >
            删除凭据
          </Button>
        )}
      </Space>
      <p style={{ marginBottom: 4 }}>
        最小权限（账户级）：Cloudflare One Connectors Write（创建 / 查询 / 删除 Mesh 节点、读取节点令牌）与 Cloudflare One Networks
        Write（发布 / 撤回路由）。
      </p>

      {(plan?.nodes ?? []).map((n) => (
        <Space key={n.id} style={{ display: "flex", marginBottom: 6 }}>
          <span style={{ width: 160, display: "inline-block" }}>
            {n.name}（{n.role}）
          </span>
          <Input
            style={{ width: 280 }}
            placeholder={n.ssh_host || "SSH 主机"}
            value={hosts[n.id] ?? ""}
            onChange={(e) => setHosts({ ...hosts, [n.id]: e.target.value })}
          />
        </Space>
      ))}
      <Input.TextArea
        style={{ marginTop: 6, fontFamily: "monospace" }}
        rows={4}
        placeholder="SSH 私钥（只用于本次请求，不保存；撤回 / 重试时需要再次提供）"
        value={sshKey}
        onChange={(e) => setSshKey(e.target.value)}
      />
      <Space wrap style={{ marginTop: 8 }}>
        <Checkbox checked={trust} onChange={(e) => setTrust(e.target.checked)}>
          信任首次见到的主机指纹
        </Checkbox>
        {status?.fault_injection && (
          <Select
            allowClear
            style={{ width: 240 }}
            placeholder="故障注入（演练补偿）"
            value={failAfter}
            onChange={(v) => setFailAfter(v)}
            options={(status.stages ?? []).map((s) => ({ value: s, label: `在「${stageLabel[s] ?? s}」后失败` }))}
          />
        )}
        <Button
          type="primary"
          danger
          loading={busy}
          disabled={busy || !creds || issues.length > 0 || journalBusy || !sshKey}
          onClick={() =>
            run(async () => {
              await api.meshDeploy(runBody());
              setMsg("Cloudflare 路由已发布。Mesh 数据面仍是未验证：这不是「Mesh 可用」。");
            })
          }
        >
          部署 Mesh
        </Button>
        <Button
          danger
          loading={busy}
          disabled={busy || !journalBusy || !sshKey}
          onClick={() =>
            run(async () => {
              await api.meshWithdraw({ private_key_pem: sshKey });
              setMsg("已撤回本次部署创建的路由、节点和 sidecar，受管文件已恢复。");
            })
          }
        >
          {journal?.state === "published" ? "撤回部署" : "撤回 / 重试补偿"}
        </Button>
      </Space>

      {msg && <Alert style={{ marginTop: 12 }} type="success" message={msg} />}
      {err && <Alert style={{ marginTop: 12 }} type="error" message={err} />}
      {compErrs.length > 0 && (
        <Alert
          style={{ marginTop: 8 }}
          type="error"
          message="补偿失败：以下资源没有撤回，部署记录已保留，修复后点「撤回 / 重试补偿」"
          description={
            <ul>
              {compErrs.map((c) => (
                <li key={c}>{c}</li>
              ))}
            </ul>
          }
        />
      )}

      {journal && (
        <div style={{ marginTop: 12 }}>
          <p>
            运行 {journal.run_id}：
            <Tag color={stateLabel[journal.state]?.color ?? "default"}>{stateLabel[journal.state]?.text ?? journal.state}</Tag>
            <Tag color="orange">数据面 未验证</Tag>
            {journal.fail_after && <Tag color="purple">故障注入：{journal.fail_after}</Tag>}
          </p>
          {journal.error && <Alert type="error" style={{ marginBottom: 8 }} message={journal.error} />}
          {journalBusy && journal.account_id && creds?.account_id && creds.account_id !== journal.account_id && (
            <Alert
              type="error"
              style={{ marginBottom: 8 }}
              message={`保存的凭据属于账户 ${creds.account_id}，但这次部署绑定账户 ${journal.account_id}。撤回只在原账户进行：请先保存原账户的凭据。`}
            />
          )}
          <Descriptions size="small" column={1} bordered style={{ marginBottom: 8 }}>
            <Descriptions.Item label="Cloudflare 账户（部署时绑定）">
              {journal.account_id ?? "（记录里没有）"}
              {journalBusy && "：撤回完成前不能切换账户，同一账户可以更换 API token"}
            </Descriptions.Item>
            <Descriptions.Item label="主机（部署时固定）">
              {(journal.hosts ?? []).length === 0
                ? "无"
                : (journal.hosts ?? []).map((h) => (
                    <div key={h.node_id}>
                      {h.node_id}：{h.ssh_user}@{h.ssh_host}:{h.ssh_port} {h.host_key ? <code>{h.host_key}</code> : <Tag>指纹未取得</Tag>}
                    </div>
                  ))}
              {journalBusy && <div>撤回只连接这些地址并要求同一主机指纹；拓扑里的地址修改或删除节点不影响撤回，只需再次提供 SSH 私钥。</div>}
            </Descriptions.Item>
          </Descriptions>
          {(journal.compensation_errors ?? []).length > 0 && (
            <Alert
              type="error"
              style={{ marginBottom: 8 }}
              message="补偿未完成"
              description={(journal.compensation_errors ?? []).join("\n")}
            />
          )}
          <pre className="diff">
            {journal.stages
              .map((s) => `${(stageLabel[s.name] ?? s.name).padEnd(10)} ${s.status}${s.error ? `\n    ${s.error}` : ""}${(s.detail ?? []).map((d) => `\n    ${d}`).join("")}`)
              .join("\n")}
          </pre>
          <div>
            {journal.stages.map((s) => (
              <span key={s.name} style={{ marginRight: 8 }}>
                {stageLabel[s.name] ?? s.name} {stageTag(s.status)}
              </span>
            ))}
          </div>
          <pre className="diff">
            {[
              ...(journal.routes ?? []).map((r) => `路由 ${r.network} → ${r.exit_id} ${r.cf_id ?? "(id 未知)"} ${r.state}${r.error ? ` ✗ ${r.error}` : ""}`),
              ...(journal.remotes ?? []).map((r) => `主机 ${r.node_id} sidecar ${r.state}${r.error ? ` ✗ ${r.error}` : ""}`),
              ...(journal.nodes ?? []).map((n) => `Cloudflare 节点 ${n.name} ${n.cf_id ?? "(id 未知)"} ${n.state}${n.error ? ` ✗ ${n.error}` : ""}`),
            ].join("\n") || "本次运行没有创建外部资源"}
          </pre>
        </div>
      )}
    </div>
  );
}
