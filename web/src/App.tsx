import { useEffect, useState } from "react";
import { Alert, Button, Input, Space, Tabs } from "antd";
import { getToken, setToken } from "./api";
import type { Issue, Topology } from "./types";
import * as api from "./api";
import TopologyEditor from "./TopologyEditor";
import RulesPanel from "./RulesPanel";
import PoolsPanel from "./PoolsPanel";
import UnlockPanel from "./UnlockPanel";
import LeakPanel from "./LeakPanel";
import DeployPanel from "./DeployPanel";

export default function App() {
  const [topo, setTopo] = useState<Topology | null>(null);
  const [issues, setIssues] = useState<Issue[]>([]);
  const [selected, setSelected] = useState<{ kind: "node" | "link"; id: string } | null>(null);
  const [err, setErr] = useState("");
  const [paths, setPaths] = useState("");
  const [token, setTokenValue] = useState(getToken);

  useEffect(() => {
    api.getTopology().then(setTopo).catch((e) => setErr(String(e)));
  }, []);

  async function onValidate() {
    if (!topo) return;
    setErr("");
    try {
      const res = await api.validate(topo);
      setIssues(res.issues || []);
      setPaths((res.paths || []).map((p) => `${p.exit_id}: ${p.nodes.join(" → ")}  MTU ${p.mtu}`).join("\n"));
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  }

  async function onSave(draft: boolean) {
    if (!topo) return;
    setErr("");
    try {
      const res = await api.putTopology({ ...topo, settings: { ...topo.settings, draft } }, draft);
      setTopo(res.topology);
      setIssues(res.issues || []);
    } catch (e) {
      const extra = e as Error & { issues?: Issue[] };
      setIssues(extra.issues || []);
      setErr(e instanceof Error ? e.message : String(e));
    }
  }

  function reload() {
    setErr("");
    api.getTopology().then(setTopo).catch((e) => setErr(e instanceof Error ? e.message : String(e)));
  }

  if (!topo) {
    return (
      <div className="shell">
        {err ? <Alert type="error" showIcon message={err} style={{ marginBottom: 12 }} /> : "正在读取拓扑…"}
        <Input.Password
          style={{ width: 280 }}
          placeholder="面板口令（/var/lib/meridian/panel.token）"
          value={token}
          onChange={(e) => {
            setTokenValue(e.target.value);
            setToken(e.target.value);
          }}
          onPressEnter={reload}
        />
      </div>
    );
  }

  const errors = issues.filter((i) => i.severity === "error");

  return (
    <div className="shell">
      <header className="mast">
        <div>
          <h1><span>Meridian</span> 控制面板</h1>
          <p>
            家宽网关 192.168.100.88。境外流量必须经过阿里云 → 深港 IX → 香港枢纽。
            示例里的地址是文档前缀，下发前要换成你自己的端点。私钥不会出现在这个页面上。
          </p>
        </div>
        <Space>
          <Input.Password
            style={{ width: 220 }}
            placeholder="面板口令"
            value={token}
            onChange={(e) => {
              setTokenValue(e.target.value);
              setToken(e.target.value);
            }}
          />
          <Button onClick={onValidate}>校验路径</Button>
          <Button onClick={() => onSave(true)}>保存草稿</Button>
          <Button type="primary" disabled={errors.length > 0} onClick={() => onSave(false)}>
            保存
          </Button>
        </Space>
      </header>
      {err && <Alert type="error" showIcon message={err} style={{ marginBottom: 12 }} />}
      <Tabs
        items={[
          {
            key: "topo",
            label: "拓扑",
            children: (
              <>
                <TopologyEditor topo={topo} selected={selected} onSelect={setSelected} onChange={setTopo} />
                {paths && <pre className="diff">{paths}</pre>}
                <div className="issues">
                  {issues.map((iss, i) => (
                    <div key={i} className={`issue ${iss.severity}`}>{iss.message}</div>
                  ))}
                </div>
              </>
            ),
          },
          {
            key: "rules",
            label: "规则",
            children: <RulesPanel topo={topo} onChange={setTopo} />,
          },
          {
            key: "pools",
            label: "出口池",
            children: <PoolsPanel topo={topo} onChange={setTopo} />,
          },
          {
            key: "unlock",
            label: "解锁",
            children: <UnlockPanel />,
          },
          {
            key: "leak",
            label: "防泄露",
            children: <LeakPanel topo={topo} onChange={setTopo} />,
          },
          {
            key: "deploy",
            label: "下发",
            children: <DeployPanel topo={topo} />,
          },
        ]}
      />
    </div>
  );
}
