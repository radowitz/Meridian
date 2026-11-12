import { useCallback, useEffect, useState } from "react";
import { Alert, Button, Checkbox, Descriptions, Select, Space, Tag } from "antd";
import type { Topology } from "./types";
import * as api from "./api";
import MeshDeploy from "./MeshDeploy";

function hostReportOf(e: unknown): api.HostReport | undefined {
  const body = (e as { body?: { host?: api.HostReport } } | undefined)?.body;
  return body?.host ?? undefined;
}

function diffSummary(r: api.HostReport) {
  return Object.entries(r.diff)
    .filter(([, v]) => Array.isArray(v) && v.length > 0)
    .map(([k, v]) => `${k}: ${(v as (string | number)[]).join(", ")}`)
    .join("\n");
}

export default function DeployPanel({ topo }: { topo: Topology }) {
  const [diff, setDiff] = useState("");
  const [script, setScript] = useState("");
  const [nodeId, setNodeId] = useState("ali");
  const [installOk, setInstallOk] = useState(false);
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");
  const [host, setHost] = useState<api.HostStatus | null>(null);
  const [report, setReport] = useState<api.HostReport | null>(null);

  const refreshHost = useCallback(async () => {
    try {
      setHost(await api.hostStatus());
    } catch {
      setHost(null);
    }
  }, []);

  useEffect(() => {
    void refreshHost();
  }, [refreshHost]);

  async function run(fn: () => Promise<void>) {
    setErr("");
    setMsg("");
    setReport(null);
    try {
      await fn();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
      setReport(hostReportOf(e) ?? null);
    } finally {
      await refreshHost();
    }
  }

  const installed = host?.installed ?? null;
  const pending = host?.pending ?? null;

  return (
    <div className="panel">
      <h3>差分、下发、回滚</h3>
      <p>
        下发顺序是：NAT 拨出出口 → 其他出口 → 香港枢纽 → 阿里云 → 家宽网关。
        默认只把渲染结果写到网关的数据目录。勾选确认后才会安装到本机：写入 Meridian 自己的文件，
        再经宿主上的 meridian-host 执行 daemon-reload、启动 meridian.service 与相关服务并做健康检查。
        任一步失败即停止，并把宿主和数据目录一起补偿回安装前的状态。
      </p>
      <Descriptions size="small" column={1} bordered style={{ marginBottom: 12 }}>
        <Descriptions.Item label="宿主执行通道">
          {host === null ? (
            <Tag>未知</Tag>
          ) : host.agent.ok ? (
            <Tag color="green">可用</Tag>
          ) : (
            <>
              <Tag color="red">不可用</Tag> {host.agent.error}
            </>
          )}
        </Descriptions.Item>
        <Descriptions.Item label="本机已安装">
          {installed
            ? `清单版本 ${installed.version}，${installed.files} 个文件；接口 ${installed.interfaces.join(" ") || "无"}；服务 ${installed.units.join(" ") || "无"}`
            : "未安装"}
        </Descriptions.Item>
      </Descriptions>
      {pending && (
        <Alert
          style={{ marginBottom: 12 }}
          type="error"
          message={`有未完成的宿主事务 ${pending.id}（${pending.kind}，阶段 ${pending.phase}）。在恢复之前不会接受新的安装或回滚。`}
          description={pending.error}
          action={
            <Button danger onClick={() => run(async () => {
              const res = await api.recoverHost();
              setReport(res.host ?? null);
              setMsg("已恢复到事务之前的状态（或完成了已生效的提交）。");
            })}>
              恢复
            </Button>
          }
        />
      )}
      <Space wrap>
        <Button onClick={() => run(async () => setDiff((await api.diff(topo)).diff))}>查看差分</Button>
        <Button onClick={() => run(async () => setDiff((await api.apply(true, false)).diff))}>演练</Button>
        <Button type="primary" onClick={() => run(async () => {
          const res = await api.apply(false, false);
          setDiff(res.diff);
          setMsg(`已写入数据目录，共 ${res.wrote?.length ?? 0} 个文件。`);
        })}>
          写入数据目录
        </Button>
        {!installed && (
          <Button onClick={() => run(async () => {
            await api.rollback("snapshot");
            setMsg("本机未安装 Meridian：已回滚数据目录快照。");
          })}>
            回滚数据目录
          </Button>
        )}
      </Space>
      <div style={{ marginTop: 12 }}>
        <Checkbox checked={installOk} onChange={(e) => setInstallOk(e.target.checked)}>
          我确认这台机器是 192.168.100.88，不会改动 ROS 192.168.100.1 和现有 mihomo
        </Checkbox>
        <Space style={{ marginLeft: 8 }} wrap>
          <Button
            danger
            disabled={!installOk || !!pending}
            onClick={() => run(async () => {
              const res = await api.apply(false, true);
              setDiff(res.diff);
              setReport(res.host ?? null);
              setMsg("已安装并激活网关，健康检查通过。远程节点仍要用装机脚本推送。");
            })}
          >
            安装到本机
          </Button>
          {installed && (
            <Button
              danger
              disabled={!installOk || !!pending}
              onClick={() => run(async () => {
                const res = await api.rollback("runtime");
                setReport(res.host ?? null);
                setMsg("已回滚：宿主网络与数据目录一起恢复到上一份，新配置引入的文件、接口和服务已移除。");
              })}
            >
              回滚（含宿主网络）
            </Button>
          )}
        </Space>
      </div>
      <h3 style={{ marginTop: 22 }}>SSH 装机演练</h3>
      <Space>
        <Select
          style={{ width: 220 }}
          value={nodeId}
          onChange={setNodeId}
          options={topo.nodes.filter((n) => n.managed).map((n) => ({ value: n.id, label: n.name }))}
        />
        <Button onClick={() => run(async () => setScript((await api.provision(nodeId)).script))}>
          生成脚本（不连接）
        </Button>
      </Space>
      {msg && <Alert style={{ marginTop: 12 }} type="success" message={msg} />}
      {err && <Alert style={{ marginTop: 12 }} type="error" message={err} />}
      {report && (
        <div style={{ marginTop: 12 }}>
          <p>
            宿主事务 {report.transaction}：版本 {report.from_version} → {report.to_version}，
            {report.committed ? "已提交" : report.compensated ? "已补偿回事务前状态" : "未完成"}
          </p>
          {report.warnings?.map((w) => (
            <Alert key={w} style={{ marginBottom: 8 }} type="warning" message={w} />
          ))}
          {diffSummary(report) && <pre className="diff">{diffSummary(report)}</pre>}
          {report.steps && report.steps.length > 0 && (
            <pre className="diff">
              {report.steps
                .map((s) => `${s.ok ? (s.skipped ? "skip" : " ok ") : "FAIL"}  ${s.name}${s.detail ? `\n      ${s.detail}` : ""}`)
                .join("\n")}
            </pre>
          )}
        </div>
      )}
      {script && <pre className="diff">{script}</pre>}
      {diff && <pre className="diff">{diff}</pre>}
      <MeshDeploy />
    </div>
  );
}
