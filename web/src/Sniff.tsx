// 按域名嗅探: the gateway's name-sniffing TCP forwarder. The setting (saved
// into the topology, effective at the next gateway install), what it
// decides by name and what stays address-only, and the forwarder's health
// and recent decisions read from the gateway through the host agent. Names
// appear in the recent decisions only when recording is on; they live in
// the forwarder's memory, never on disk.

import { Alert, Button, Checkbox, Input, Space, Switch, Table, Tag, Typography } from "antd";
import { useEffect, useState } from "react";
import * as api from "./api";
import type { SniffRecord, SniffSettings, SniffView } from "./types";
import { ApiErrorAlert, Section, StatusTag, TABLE_SCROLL, TimeText, useApi } from "./ui";

/** Plain words for the forwarder's "no name" reasons (internal/sniff). */
export const SNIFF_WHY: Record<string, string> = {
  no_sni: "没有 SNI",
  bad_sni: "SNI 不是域名",
  ech: "ECH（按地址）",
  ech_outer: "ECH，按明文名字",
  ech_public: "ECH 公共名（按地址）",
  malformed: "格式错误",
  oversized: "首包过长",
  other: "不是 TLS / HTTP",
  http2: "HTTP/2 明文前言",
  no_host: "没有 Host",
  ip_host: "Host 是地址",
  timeout: "客户端数据不够（超时）",
  no_data: "客户端没有先发数据",
  eof: "客户端提前关闭",
  skipped_port: "端口不嗅探",
  read_failed: "读取失败",
};

const RESULT: Record<string, string> = {
  ok: "已转发",
  rejected: "拒绝规则",
  resolve_failed: "目标解析失败（不回落）",
  dial_failed: "连接失败",
  unknown_mark: "地址分类标记未知（失败关闭）",
  unknown_target: "目标未知",
  orig_dst_failed: "读不到原目的地址",
  client_closed: "客户端关闭",
  loop: "环路",
  bad_destination: "目的地址无效",
  upstream_write_failed: "上游写入失败",
};

/** Overview tile body: running state in one line. */
export function SniffSummary({ v }: { v: SniffView }) {
  if (!v.setting.enabled) {
    return v.runtime.present ? <StatusTag kind="attention">已关闭，网关上仍在运行</StatusTag> : <Typography.Text type="secondary">未开启：全部按目的地址分类</Typography.Text>;
  }
  const h = v.runtime.health;
  if (!v.runtime.available) return <StatusTag kind="unverified">{v.runtime.message ?? "读不到状态"}</StatusTag>;
  if (!v.runtime.present || !h) return <StatusTag kind="failed">没有运行：被接管的连接会失败</StatusTag>;
  const c = h.counters ?? {};
  const byName = c.decided_by_name ?? 0;
  const byAddr = Object.entries(c)
    .filter(([k]) => k.startsWith("decided_by_address_"))
    .reduce((n, [, x]) => n + x, 0);
  return (
    <Space size={4} wrap>
      {h.ready ? <StatusTag kind="ok">运行中</StatusTag> : <StatusTag kind="failed">未就绪</StatusTag>}
      {h.last_reload_error ? <StatusTag kind="attention" title={h.last_reload_error}>上次重载失败</StatusTag> : null}
      <Typography.Text type="secondary" style={{ fontSize: 12 }}>
        按名字 {byName} · 按地址 {byAddr} · 当前连接 {h.active}
      </Typography.Text>
    </Space>
  );
}

function SettingForm({ v, onSaved }: { v: SniffView; onSaved: () => void }) {
  const cur = v.setting;
  const [enabled, setEnabled] = useState(cur.enabled);
  const [ports, setPorts] = useState(cur.ports.join(", "));
  const [ech, setEch] = useState(cur.ech_public_names.join(", "));
  const [record, setRecord] = useState(cur.record_names);
  const [error, setError] = useState<api.ApiError | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    setEnabled(cur.enabled);
    setPorts(cur.ports.join(", "));
    setEch(cur.ech_public_names.join(", "));
    setRecord(cur.record_names);
  }, [cur.enabled, cur.ports, cur.ech_public_names, cur.record_names]);
  const save = async () => {
    setError(null);
    const list = (s: string) =>
      s
        .split(/[,，\s]+/)
        .map((x) => x.trim())
        .filter(Boolean);
    const body: SniffSettings = { enabled, ports: list(ports).map(Number), ech_public_names: list(ech), record_names: record };
    setBusy(true);
    try {
      await api.putSniff(body);
      onSaved();
    } catch (e) {
      setError(e instanceof api.ApiError ? e : new api.ApiError(0, {}));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Space direction="vertical" style={{ width: "100%" }}>
      <Space wrap>
        <Switch checked={enabled} onChange={setEnabled} aria-label="开启按域名嗅探" />
        <Typography.Text>开启按域名嗅探（下次安装到网关时生效）</Typography.Text>
      </Space>
      <Space wrap>
        <Typography.Text>接管的 TCP 端口</Typography.Text>
        <Input value={ports} onChange={(e) => setPorts(e.target.value)} aria-label="嗅探端口" style={{ width: 200 }} />
        <Typography.Text>ECH 公共名（按地址判断）</Typography.Text>
        <Input value={ech} onChange={(e) => setEch(e.target.value)} aria-label="ECH 公共名" style={{ width: 240 }} />
      </Space>
      <Checkbox checked={record} onChange={(e) => setRecord(e.target.checked)}>
        在近期决策里记录域名（只在网关内存里，不写磁盘、不进日志；域名属于敏感信息，默认不记录）
      </Checkbox>
      <Button type="primary" onClick={() => void save()} loading={busy}>
        保存设置
      </Button>
      {error ? <ApiErrorAlert error={error} /> : null}
    </Space>
  );
}

/** Rules page section: setting, coverage, health and recent decisions. */
export function SniffSection() {
  const st = useApi(() => api.getSniff(), []);
  const v = st.data;
  const recent: SniffRecord[] = v?.runtime.recent?.connections ?? [];
  const names = v?.runtime.recent?.record_names ?? false;
  return (
    <Section title="按域名嗅探（TCP）">
      {st.error ? <ApiErrorAlert error={st.error} /> : null}
      {v ? (
        <Space direction="vertical" style={{ width: "100%" }}>
          <Typography.Paragraph type="secondary" style={{ fontSize: 12, marginBottom: 0 }}>
            开启后，局域网和远程接入设备新建的、发往接管端口的 TCP 连接交给网关上的转发服务：它读 TLS 的 SNI 或 HTTP 的 Host，按这张有序规则表从上到下匹配，
            用目标自己的解析器重新解析后经该目标的隧道连出。读不到名字的连接按目的地址分类的结果走，与关闭时相同。转发服务停止或崩溃时，被接管的连接直接失败，不会绕过。
          </Typography.Paragraph>
          <SettingForm v={v} onSaved={() => void st.reload()} />
          <div data-testid="sniff-coverage">
            <Typography.Text strong>按名字判断</Typography.Text>
            {v.coverage.by_name.map((x) => (
              <div key={x} style={{ fontSize: 12 }}>· {x}</div>
            ))}
            <Typography.Text strong>仍按目的地址判断</Typography.Text>
            {v.coverage.address_only.map((x) => (
              <div key={x} style={{ fontSize: 12 }}>· {x}</div>
            ))}
            <Typography.Text strong>代价与已知误差</Typography.Text>
            {v.coverage.costs.map((x) => (
              <div key={x} style={{ fontSize: 12 }}>· {x}</div>
            ))}
          </div>
          <Space wrap data-testid="sniff-runtime">
            <Typography.Text strong>网关上的状态</Typography.Text>
            <SniffSummary v={v} />
            {v.runtime.health ? (
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                规则 {v.runtime.health.rules} 条 · 第 {v.runtime.health.generation} 代 · 载入于 <TimeText value={v.runtime.health.loaded_at} />
              </Typography.Text>
            ) : null}
          </Space>
          {v.runtime.code && v.setting.enabled ? <Alert type="warning" showIcon message={v.runtime.message} /> : null}
          {v.runtime.health?.last_reload_error ? <Alert type="warning" showIcon message={"上次重载失败，仍用旧规则：" + v.runtime.health.last_reload_error} /> : null}
          {recent.length > 0 ? (
            <Table<SniffRecord>
              size="small"
              rowKey={(r) => r.start + r.source + (r.dest ?? "")}
              dataSource={recent}
              pagination={{ pageSize: 20 }}
              scroll={TABLE_SCROLL}
              columns={[
                { title: "时间", render: (_, r) => <TimeText value={r.start} /> },
                { title: "来源", dataIndex: "source" },
                { title: "原目的地址", dataIndex: "dest" },
                {
                  title: "判断依据",
                  render: (_, r) =>
                    r.sniffed ? (
                      <Space size={2}>
                        <Tag color="blue">按名字</Tag>
                        {names && r.name ? <Typography.Text code>{r.name}</Typography.Text> : null}
                        {r.why === "ech_outer" ? <Tag>ECH 明文名</Tag> : null}
                      </Space>
                    ) : (
                      <Space size={2}>
                        <Tag>按地址</Tag>
                        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                          {SNIFF_WHY[r.why ?? ""] ?? r.why}
                        </Typography.Text>
                      </Space>
                    ),
                },
                { title: "规则", render: (_, r) => (r.rule_id ? r.rule_id : r.rule_index < 0 ? "名单 / 默认组" : "") },
                { title: "目标", dataIndex: "target" },
                {
                  title: "结果",
                  render: (_, r) =>
                    r.result === "ok" ? <StatusTag kind="ok">{RESULT.ok}</StatusTag> : <StatusTag kind="attention">{RESULT[r.result] ?? r.result}</StatusTag>,
                },
              ]}
            />
          ) : v.runtime.present ? (
            <Typography.Text type="secondary">还没有近期决策。</Typography.Text>
          ) : null}
        </Space>
      ) : null}
    </Section>
  );
}
