import { Alert, Button, Checkbox, Collapse, Select, Space, Table, Tag } from "antd";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  cancelUnlockJob,
  getUnlock,
  getUnlockJobs,
  runUnlock,
  type ProbeCategory,
  type ProbeJob,
  type ProbeJobItem,
  type ProbeJobsView,
  type UnlockView,
} from "./api";

const rejectedLabel: Record<string, string> = {
  stale: "超过有效期",
  future: "时间在未来",
  out_of_order: "比已收到的结果旧",
  duplicate: "重复报告",
  superseded: "该出口已有更新的一轮",
};

const kindLabel: Record<string, string> = {
  scheduled: "定时",
  manual: "手动",
  health: "健康变化",
  inconclusive: "无平台结论",
};

const categoryTag: Record<ProbeCategory, { text: string; color: string }> = {
  network_ok: { text: "网络可达（非平台判定）", color: "blue" },
  unlocked: { text: "平台明确解锁", color: "green" },
  not_unlocked: { text: "平台明确未解锁", color: "red" },
  failed: { text: "探测失败", color: "orange" },
  unknown: { text: "未知（应答无法识别）", color: "default" },
};

const jobStateTag: Record<string, { text: string; color: string }> = {
  running: { text: "进行中", color: "blue" },
  done: { text: "完成", color: "green" },
  cancelled: { text: "已取消", color: "default" },
  timeout: { text: "整轮超时", color: "orange" },
  interrupted: { text: "被中断", color: "orange" },
};

const notIngested: Record<string, string> = {
  no_verdict: "该地址族没有平台结论；同一轮另一地址族的结论已入库",
  cancelled: "已取消，未入库",
  not_sent: "未发出，未入库",
  interrupted: "面板中断，未入库",
  save_failed: "保存失败，未入库",
};

function ingestText(v?: string) {
  if (!v) return "";
  if (v === "accepted") return "已入库";
  if (v === "accepted:inconclusive") return "已入库（无平台结论：不计失败次数，但会打断首选的恢复计时）";
  const [k, ...rest] = v.split(":");
  const r = rest.join(":");
  if (k === "rejected") return "未采纳：" + (rejectedLabel[r] || r);
  if (k === "note") return r;
  if (k === "not_ingested") return notIngested[r] || "未入库：" + r;
  return v;
}

function time(v?: string) {
  return v ? new Date(v).toLocaleTimeString() : "";
}

export default function UnlockPanel() {
  const [view, setView] = useState<UnlockView | null>(null);
  const [jobs, setJobs] = useState<ProbeJobsView | null>(null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const [selServices, setSelServices] = useState<string[]>([]);
  const [selExits, setSelExits] = useState<string[]>([]);
  const [selFamilies, setSelFamilies] = useState<("ipv4" | "ipv6")[]>([]);
  const [shownJob, setShownJob] = useState<string>("");
  const wasRunning = useRef(false);

  const load = useCallback(() => {
    getUnlock()
      .then(setView)
      .catch((e) => setErr(e instanceof Error ? e.message : String(e)));
  }, []);
  const loadJobs = useCallback(() => {
    getUnlockJobs()
      .then((j) => {
        setJobs(j);
        // When a run ends, refresh the states it may have changed.
        if (wasRunning.current && !j.running) load();
        wasRunning.current = !!j.running;
      })
      .catch((e) => setErr(e instanceof Error ? e.message : String(e)));
  }, [load]);
  useEffect(() => {
    load();
    loadJobs();
  }, [load, loadJobs]);
  useEffect(() => {
    if (!jobs?.running) return;
    const t = setInterval(loadJobs, 2000);
    return () => clearInterval(t);
  }, [jobs?.running, loadJobs]);

  async function onRun() {
    setBusy(true);
    setErr("");
    try {
      const r = await runUnlock({
        services: selServices.length ? selServices : undefined,
        exits: selExits.length ? selExits : undefined,
        families: selFamilies.length ? selFamilies : undefined,
      });
      setShownJob(r.job.id);
      wasRunning.current = true;
      loadJobs();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function onCancel() {
    if (!jobs?.running) return;
    try {
      await cancelUnlockJob(jobs.running);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
    loadJobs();
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

  const catalog = jobs?.catalog || [];
  const probeable = useMemo(() => {
    const ids = new Set(catalog.map((c) => c.service));
    return (view?.services || []).filter((s) => ids.has(s.rule_id));
  }, [catalog, view]);
  const exitOptions = useMemo(() => {
    const set = new Set<string>();
    probeable.forEach((s) => s.members.forEach((m) => set.add(m)));
    return [...set].sort().map((id) => ({ value: id, label: id }));
  }, [probeable]);

  const job: ProbeJob | undefined = useMemo(() => {
    const list = jobs?.jobs || [];
    return list.find((j) => j.id === shownJob) || list.find((j) => j.id === jobs?.running) || list[0];
  }, [jobs, shownJob]);

  const running = !!jobs?.running;

  return (
    <div>
      <p>
        每 {view ? Math.round(view.interval_sec / 3600) : 6} 小时测一次。AI 留在美国池，Netflix / Disney+ 留在香港家宽，台湾服务留在 TW。连续两次定时失败才改到同池备选；手动测一次或健康变化补测都不计数。切回首选要求首选当前健康（最新一次结果是成功，且 30 分钟内收到），并且从最后一次失败之后的第一次成功起连续成功满 30 分钟；首选任何一次失败都会把这段计时清零。时间按面板时钟算。迟到的、过期（超过 1 小时）的或重复的报告只记录，不改状态。钉死的手动规则只告警，不改路。
      </p>
      {view?.pending_apply && (
        <Alert type="warning" showIcon style={{ marginBottom: 12 }} message="解锁结果已经改变自动规则的出口。到「下发」页应用之后，数据面才会换成新的下一跳。" />
      )}
      <p>下次定时（面板经宿主探测）：{view?.next_run ? new Date(view.next_run).toLocaleString() : "—"}</p>
      {err && <Alert type="info" showIcon closable onClose={() => setErr("")} style={{ marginBottom: 12 }} message={err} />}
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

      <h3 style={{ marginTop: 24 }}>面板探测</h3>
      {jobs && !jobs.available && (
        <Alert
          type="warning"
          showIcon
          style={{ marginBottom: 12 }}
          message="面板没有宿主探测能力：meridian-host 未运行或未挂载。面板不会编造结果；出口上的 regioncheck 报告仍可经 /api/unlock/report 送达。"
        />
      )}
      <p style={{ color: "#666" }}>
        探测在网关的 meridian-host 里执行：只用下面这些固定目标，带上所选出口的 fwmark 和中转地址，按所选地址族（IPv4 / IPv6）强制建连，先用出口检查确认实际公网地址和地区属于该出口，再访问平台，结束时再确认一次。出口确认不了就记为「探测失败」，不会回落到默认出口或另一个地址族，也不会当成平台结论。不接受任何 Cookie、账号或令牌。留空表示：全部有适配器的自动规则 × 各自池成员 × 出口支持的地址族。
      </p>
      <Space wrap style={{ marginBottom: 12 }}>
        <Select
          mode="multiple"
          allowClear
          style={{ minWidth: 260 }}
          placeholder="服务（留空 = 全部可探测的自动规则）"
          value={selServices}
          onChange={setSelServices}
          options={probeable.map((s) => ({ value: s.rule_id, label: s.name + (s.pin ? "（钉死，只记录）" : "") }))}
        />
        <Select
          mode="multiple"
          allowClear
          style={{ minWidth: 220 }}
          placeholder="出口（留空 = 各服务的池成员）"
          value={selExits}
          onChange={setSelExits}
          options={exitOptions}
        />
        <Checkbox.Group
          value={selFamilies}
          onChange={(v) => setSelFamilies(v as ("ipv4" | "ipv6")[])}
          options={[
            { label: "IPv4", value: "ipv4" },
            { label: "IPv6", value: "ipv6" },
          ]}
        />
        <Button type="primary" loading={busy} disabled={running || (jobs ? !jobs.available : false)} onClick={onRun}>
          立即测试
        </Button>
        <Button danger disabled={!running} onClick={onCancel}>
          取消
        </Button>
        {(jobs?.jobs?.length || 0) > 0 && (
          <Select
            style={{ minWidth: 300 }}
            value={job?.id}
            onChange={setShownJob}
            options={(jobs?.jobs || []).map((j) => ({
              value: j.id,
              label: `${new Date(j.created_at).toLocaleString()} · ${kindLabel[j.kind] || j.kind} · ${jobStateTag[j.state]?.text || j.state}`,
            }))}
          />
        )}
      </Space>
      {job && (
        <>
          <p>
            <Tag color={jobStateTag[job.state]?.color}>{jobStateTag[job.state]?.text || job.state}</Tag>
            <Tag>{kindLabel[job.kind] || job.kind}</Tag>
            开始 {new Date(job.created_at).toLocaleString()}
            {job.finished_at ? ` · 结束 ${new Date(job.finished_at).toLocaleString()}` : ""}
            {job.error ? ` · ${job.error}` : ""}
          </p>
          <Table<ProbeJobItem>
            size="small"
            pagination={{ pageSize: 20 }}
            rowKey={(r) => `${r.service}|${r.exit_id}|${r.family}`}
            dataSource={job.items}
            scroll={{ x: 1200 }}
            columns={[
              { title: "服务", dataIndex: "service_name", width: 140, render: (v: string, r) => v || r.service },
              { title: "出口", dataIndex: "exit_id", width: 120, render: (v: string, r) => (r.exit_region ? `${v}（${r.exit_region.toUpperCase()}）` : v) },
              { title: "地址族", dataIndex: "family", width: 70, render: (v: string) => (v === "ipv6" ? "IPv6" : "IPv4") },
              { title: "开始", dataIndex: "started_at", width: 90, render: time },
              { title: "完成", dataIndex: "finished_at", width: 90, render: time },
              {
                title: "结果",
                width: 170,
                render: (_, r) =>
                  r.state === "queued" ? (
                    <Tag>等待</Tag>
                  ) : r.state === "running" ? (
                    <Tag color="blue">进行中</Tag>
                  ) : r.category ? (
                    <Tag color={categoryTag[r.category]?.color}>{categoryTag[r.category]?.text || r.category}</Tag>
                  ) : null,
              },
              { title: "平台地区", dataIndex: "region", width: 80, render: (v?: string) => (v ? v.toUpperCase() : "") },
              { title: "证据", dataIndex: "evidence", width: 260 },
              { title: "出口确认", dataIndex: "egress", width: 240 },
              { title: "错误", dataIndex: "error", width: 200 },
              { title: "入库", dataIndex: "ingest", width: 200, render: (v?: string) => ingestText(v) },
            ]}
          />
        </>
      )}
      {catalog.length > 0 && (
        <Collapse
          style={{ marginTop: 12 }}
          items={[
            {
              key: "basis",
              label: "各服务的判定依据（平台随时可能改页面，结论需要人工复核，见验收清单）",
              children: (
                <ul style={{ margin: 0 }}>
                  {catalog.map((c) => (
                    <li key={c.service}>
                      <b>{c.name}</b>
                      {c.reachability ? <Tag style={{ marginLeft: 6 }}>只做到达性</Tag> : null}：{c.basis}
                    </li>
                  ))}
                  <li>其余服务（巴哈姆特、KKTV、LINE TV、Hami、Abema、MyTV SUPER）没有面板适配器，仍由出口上的 regioncheck 报告。</li>
                </ul>
              ),
            },
          ]}
        />
      )}

      <h3 style={{ marginTop: 24 }}>历史</h3>
      <Table
        size="small"
        pagination={{ pageSize: 8 }}
        rowKey={(_, i) => String(i)}
        dataSource={[...(view?.history || [])].reverse()}
        columns={[
          { title: "时间", dataIndex: "at", width: 200, render: (v: string) => (v ? new Date(v).toLocaleString() : "") },
          { title: "来源", dataIndex: "kind", width: 110, render: (v: string) => kindLabel[v] || v },
          { title: "服务", dataIndex: "service", width: 140 },
          { title: "出口", dataIndex: "exit_id", width: 120 },
          { title: "地址族", dataIndex: "family", width: 90, render: (v?: string) => v || "" },
          {
            title: "结果",
            width: 110,
            render: (_, h) => (h.kind === "inconclusive" ? "无结论" : h.ok ? "通过" : "失败"),
          },
          {
            title: "说明",
            render: (_, h) => (
              <>
                {h.rejected ? <Tag color="default">未采纳：{rejectedLabel[h.rejected] || h.rejected}</Tag> : null}
                {h.note}
              </>
            ),
          },
        ]}
      />
    </div>
  );
}
