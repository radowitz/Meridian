import { Alert, Button, Table, Tag } from "antd";
import { useEffect, useState } from "react";
import { getUnlock, runUnlock, type UnlockView } from "./api";

export default function UnlockPanel() {
  const [view, setView] = useState<UnlockView | null>(null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  function load() {
    getUnlock().then(setView).catch((e) => setErr(e instanceof Error ? e.message : String(e)));
  }
  useEffect(load, []);

  async function onRun() {
    setBusy(true);
    setErr("");
    try {
      await runUnlock();
      load();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  const rows = (view?.services || []).map((s) => {
    const st = view?.states?.[s.rule_id];
    return {
      ...s,
      active: s.pin ? s.preferred : st?.active || view?.decisions?.[s.rule_id] || s.preferred,
      fails: st?.sched_fails || 0,
      demoted: !!st?.demoted,
      unavailable: !!st?.unavailable,
    };
  });

  return (
    <div>
      <p>
        每 {view ? Math.round(view.interval_sec / 3600) : 6} 小时测一次。AI 留在美国池，Netflix / Disney+ 留在香港家宽，台湾服务留在 TW。连续两次定时失败才改到同池备选；手动测一次或健康变化补测都不计数。切回首选要等首选恢复，并且距离备选和首选都成功后再过 30 分钟。钉死的手动规则只告警，不改路。
      </p>
      {view?.pending_apply && (
        <Alert type="warning" showIcon style={{ marginBottom: 12 }} message="解锁结果已经改变自动规则的出口。到「下发」页应用之后，数据面才会换成新的下一跳。" />
      )}
      <p>
        下次定时：{view?.next_run ? new Date(view.next_run).toLocaleString() : "—"}{" "}
        <Button size="small" loading={busy} onClick={onRun}>立即测试</Button>
      </p>
      {err && <Alert type="info" showIcon style={{ marginBottom: 12 }} message={err} />}
      <Table
        size="small"
        pagination={false}
        rowKey="rule_id"
        dataSource={rows}
        columns={[
          { title: "服务", dataIndex: "name" },
          { title: "池", dataIndex: "pool", width: 140 },
          { title: "首选", dataIndex: "preferred", width: 120 },
          { title: "当前", dataIndex: "active", width: 120 },
          {
            title: "状态",
            render: (_, r) => (
              <>
                {r.pin ? <Tag>钉死</Tag> : <Tag color="blue">自动</Tag>}
                {r.demoted ? <Tag color="orange">滞回中</Tag> : null}
                {r.unavailable ? <Tag color="red">池内都不可用</Tag> : null}
                {!r.pin && r.fails > 0 ? <Tag>{r.fails} 次定时失败</Tag> : null}
              </>
            ),
          },
        ]}
      />
      <h3 style={{ marginTop: 24 }}>历史</h3>
      <Table
        size="small"
        pagination={{ pageSize: 8 }}
        rowKey={(_, i) => String(i)}
        dataSource={[...(view?.history || [])].reverse()}
        columns={[
          { title: "时间", dataIndex: "at", width: 200, render: (v: string) => (v ? new Date(v).toLocaleString() : "") },
          { title: "来源", dataIndex: "kind", width: 110 },
          { title: "服务", dataIndex: "service", width: 140 },
          { title: "出口", dataIndex: "exit_id", width: 120 },
          { title: "结果", dataIndex: "ok", width: 80, render: (v: boolean) => (v ? "通过" : "失败") },
          { title: "说明", dataIndex: "note" },
        ]}
      />
    </div>
  );
}
