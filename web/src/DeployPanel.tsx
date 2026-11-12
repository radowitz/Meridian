import { useState } from "react";
import { Alert, Button, Checkbox, Select, Space } from "antd";
import type { Topology } from "./types";
import * as api from "./api";

export default function DeployPanel({ topo }: { topo: Topology }) {
  const [diff, setDiff] = useState("");
  const [script, setScript] = useState("");
  const [nodeId, setNodeId] = useState("ali");
  const [installOk, setInstallOk] = useState(false);
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");

  async function run(fn: () => Promise<void>) {
    setErr("");
    setMsg("");
    try {
      await fn();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  }

  return (
    <div className="panel">
      <h3>差分、下发、回滚</h3>
      <p>
        下发顺序是：NAT 拨出出口 → 其他出口 → 香港枢纽 → 阿里云 → 家宽网关。
        默认只把渲染结果写到网关的数据目录。勾选确认后才会安装到本机 /etc，并且只替换 Meridian 自己的文件，不会 flush 整张 nftables。
      </p>
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
        <Button onClick={() => run(async () => { await api.rollback(); setMsg("已回滚到上一份。"); })}>回滚</Button>
      </Space>
      <div style={{ marginTop: 12 }}>
        <Checkbox checked={installOk} onChange={(e) => setInstallOk(e.target.checked)}>
          我确认这台机器是 192.168.100.88，不会改动 ROS 192.168.100.1 和现有 mihomo
        </Checkbox>
        <Button
          danger
          disabled={!installOk}
          style={{ marginLeft: 8 }}
          onClick={() => run(async () => {
            const res = await api.apply(false, true);
            setDiff(res.diff);
            setMsg("已安装网关文件到本机对应路径。远程节点仍要用装机脚本推送。");
          })}
        >
          安装到本机
        </Button>
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
      {script && <pre className="diff">{script}</pre>}
      {diff && <pre className="diff">{diff}</pre>}
    </div>
  );
}
