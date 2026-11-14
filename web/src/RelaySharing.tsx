// 国内中继同时分担: what the gateway measured and decided (its upstream
// record, read through meridian-host), and the settings of the policy.
// Measured values come only from the gateway and carry their time; the
// probe traffic cost is the panel's estimate from the settings and is
// labelled so.

import { Alert, Checkbox, Divider, Form, InputNumber, Select, Space, Tag, Tooltip, Typography } from "antd";
import type { ReactNode } from "react";
import type { PathGrade, PathMeasured, PathQuality, RelayOverride, RelayStatus, Sharing, SharingRelay, Topology } from "./types";
import { PATH_QUALITY_DEFAULTS, probeCostBytes } from "./types";
import { DataTable, EllipsisText, Explain, KV, StatusTag, TimeText, bytes, type StatusKind } from "./ui";

export const RELAY_STATUS: Record<RelayStatus, { kind: StatusKind; label: string; help: string }> = {
  active: { kind: "ok", label: "分担中", help: "按质量权重接收新连接" },
  reduced: { kind: "attention", label: "已降权", help: "持续轻度劣化：新连接的份额被压低" },
  standby: { kind: "attention", label: "暂停分配", help: "持续轻度劣化且有更好的中继：不再分配新连接，已有连接保留" },
  evicted: { kind: "failed", label: "已剔除", help: "低于可用下限或不通：不再分配新连接，继续探测" },
  recovering: { kind: "running", label: "逐步加回", help: "恢复良好并保持了足够时间：从小份额起逐步加回" },
  disabled: { kind: "neutral", label: "手动停用", help: "手动覆盖：不分配新连接" },
  unknown: { kind: "unverified", label: "未知", help: "网关还没有报告" },
};

export const GRADE: Record<PathGrade, { kind: StatusKind; label: string }> = {
  good: { kind: "ok", label: "良好" },
  mild: { kind: "attention", label: "轻度劣化" },
  poor: { kind: "failed", label: "低于下限" },
  down: { kind: "failed", label: "不通" },
  none: { kind: "unverified", label: "未测量" },
};

export const REASON: Record<string, string> = {
  down: "完全不通（含经它到主枢纽不通）",
  poor_loss: "丢包高于可用下限",
  poor_rtt: "时延高于可用下限",
  no_throughput: "吞吐探测不达标（小包通、没有速率）",
  no_delivery: "TCP 发出去收不到回包（有业务时）",
  mild_loss: "丢包轻度升高",
  mild_rtt: "时延轻度升高",
  rtt_inflation: "有负载时时延膨胀",
  low_delivery: "单位权重的下行量远低于其他中继",
  relapse: "加回过程中再次变差",
  recovered: "已恢复",
  manual: "手动覆盖",
};

function rate(bps: number) {
  return `${bytes(bps)}/s`;
}

function Measured({ m }: { m?: PathMeasured }) {
  if (!m || !m.at) return <Typography.Text type="secondary">未测量</Typography.Text>;
  const v = (x: number | undefined, unit: string, digits = 0) => (x === undefined ? "—" : `${x.toFixed(digits)}${unit}`);
  return (
    <Tooltip title={`本轮：时延 ${v(m.last_rtt_ms, " ms", 1)}，丢包 ${v(m.last_loss_pct, "%", 0)}；左侧为多轮平滑值`}>
      <span data-testid="measured">
        {v(m.rtt_ms, " ms")} · 丢包 {v(m.loss_pct, "%", 1)}{" "}
        <Typography.Text type="secondary">
          （网关测量，<TimeText value={m.at} />）
        </Typography.Text>
      </span>
    </Tooltip>
  );
}

/** "45 ms · 0.0%" for compact rows; the smoothed and last values with the time on hover. */
function MeasuredShort({ m }: { m?: PathMeasured }) {
  if (!m || !m.at) return <Typography.Text type="secondary">未测量</Typography.Text>;
  const v = (x: number | undefined, unit: string, digits = 0) => (x === undefined ? "—" : `${x.toFixed(digits)}${unit}`);
  return (
    <Tooltip
      title={
        <span>
          时延 {v(m.rtt_ms, " ms")} · 丢包 {v(m.loss_pct, "%", 1)}（多轮平滑，网关测量，<TimeText value={m.at} />）；本轮：时延 {v(m.last_rtt_ms, " ms", 1)}，丢包 {v(m.last_loss_pct, "%", 0)}
        </span>
      }
    >
      <span data-testid="measured" className="nowrap" tabIndex={0}>
        {v(m.rtt_ms, " ms")} · {v(m.loss_pct, "%", 1)}
      </span>
    </Tooltip>
  );
}

function ProbeCell({ r }: { r: SharingRelay }) {
  const p = r.probe;
  if (!p || !p.at) return <Typography.Text type="secondary">{p && p.bytes_today ? `今日 ${bytes(p.bytes_today)}` : "未探测"}</Typography.Text>;
  return (
    <span data-testid={`probe-${r.id}`}>
      {p.ok === false ? <Tag color="error">不达标</Tag> : p.ok ? <Tag color="success">达标</Tag> : null}
      {p.kbps !== undefined ? `${(p.kbps / 1000).toFixed(1)} Mbit/s` : "—"}
      {p.loss_pct !== undefined ? ` · 丢 ${p.loss_pct.toFixed(0)}%` : ""}{" "}
      <Typography.Text type="secondary">
        <TimeText value={p.at} /> · 今日 {bytes(p.bytes_today)}
      </Typography.Text>
    </span>
  );
}

/** The relays as the gateway recorded them, the backup path, and the costs. */
export function RelaySharingView({ s, compact }: { s: Sharing; compact?: boolean }) {
  const total = s.relays.reduce((n, r) => n + r.weight, 0);
  const head: ReactNode[] = [];
  if (!s.known) {
    head.push(
      <Alert
        key="unknown"
        type="warning"
        showIcon
        message="网关的中继状态未知"
        description={s.message || s.code}
        style={{ marginBottom: 8 }}
        data-testid="sharing-unknown"
      />,
    );
  }
  if (s.controller === "shell") {
    head.push(
      <Alert key="fb" type="warning" showIcon style={{ marginBottom: 8 }} message="应急规则在运行" description="网关上的控制程序不可用：可达的中继平均分担，只按通断剔除，不做质量测量。" data-testid="sharing-fallback" />,
    );
  }
  if (s.alert && s.alert !== "on_backup") {
    head.push(<Alert key="alert" type="error" showIcon style={{ marginBottom: 8 }} message={s.alert_text || s.alert} data-testid="sharing-alert" />);
  }
  const share = (r: SharingRelay) => (s.path === "backup" ? "0%（备用枢纽承载）" : total > 0 ? `${((r.weight / 10) | 0).toString()}%` : "—");
  const facts = (
    <div className="kv-list">
      <KV label="承载">
        <span data-testid="sharing-path">
          {s.path === "backup" ? (
            <Tag color="orange">备用枢纽 {s.backup?.name ?? ""}</Tag>
          ) : s.path === "main" ? (
            <Tag color="blue">主链路（多中继分担）</Tag>
          ) : (
            <Typography.Text type="secondary">未知</Typography.Text>
          )}
        </span>
      </KV>
      <KV label="上次切换枢纽">
        <TimeText value={s.switched} empty="从未" />
      </KV>
      {s.beat ? (
        <KV label="记录于">
          <TimeText value={s.beat} />
        </KV>
      ) : null}
      {s.backup ? (
        <KV label="备用枢纽">
          <span data-testid="sharing-backup" className="inline-status">
            <span className="sr-only">备用枢纽 </span>
            <EllipsisText text={`${s.backup.name}（WG over WSS，${s.backup.iface}）`} />
            <StatusTag kind={GRADE[s.backup.grade]?.kind ?? "unverified"}>{GRADE[s.backup.grade]?.label ?? s.backup.grade}</StatusTag>
            {compact ? <MeasuredShort m={s.backup.measured} /> : <Measured m={s.backup.measured} />}
          </span>
        </KV>
      ) : null}
    </div>
  );
  if (compact) {
    // In a tile: one compact row per relay; details on hover and on the exits page.
    return (
      <div data-testid="relay-sharing">
        {head}
        {facts}
        <ul className="relay-rows" aria-label="中继">
          {s.relays.map((r) => {
            const st = RELAY_STATUS[r.status] ?? RELAY_STATUS.unknown;
            const g = GRADE[r.grade] ?? { kind: "unverified" as StatusKind, label: r.grade };
            const tip = [
              r.name,
              r.iface ? `接口 ${r.iface}` : "",
              `${st.label}：${st.help}`,
              r.reason && r.status !== "active" ? REASON[r.reason] ?? r.reason : "",
              `质量（网关测量）：${g.label}`,
              r.drain ? "已有连接正被清理" : "",
            ]
              .filter(Boolean)
              .join("\n");
            return (
              <li key={r.id} className="relay-row">
                <Tooltip title={<span style={{ whiteSpace: "pre-line" }}>{tip}</span>}>
                  <span className="relay-row-name" tabIndex={0}>
                    {r.name}
                    {s.designated === r.id ? <Tag className="tag-inline">指定</Tag> : null}
                  </span>
                </Tooltip>
                <span data-testid={`relay-status-${r.id}`}>
                  <StatusTag kind={st.kind} title={st.help}>
                    {st.label}
                  </StatusTag>
                </span>
                <span className="relay-row-share" data-testid={`relay-weight-${r.id}`}>
                  {s.path === "backup" ? (
                    <Tooltip title="0%（备用枢纽承载）">
                      <span>
                        0%<span className="sr-only">（备用枢纽承载）</span>
                      </span>
                    </Tooltip>
                  ) : (
                    share(r)
                  )}
                </span>
                <span className="relay-row-q">
                  <MeasuredShort m={r.measured} />
                </span>
                {r.drain ? (
                  <span className="sr-only" data-testid={`relay-drain-${r.id}`}>
                    已有连接正被清理
                  </span>
                ) : null}
              </li>
            );
          })}
        </ul>
      </div>
    );
  }
  return (
    <div data-testid="relay-sharing">
      {head}
      {facts}
      <DataTable<SharingRelay>
        size="small"
        rowKey="id"
        dataSource={s.relays}
        columns={[
          {
            title: "中继",
            kind: "flex",
            width: 150,
            render: (_, r) => (
              <div className="cell-stack">
                <span>
                  {r.name} {s.designated === r.id ? <Tag title="本机自己的组解析等无中继标记的流量走它">指定</Tag> : null}
                </span>
                {r.iface ? <Typography.Text type="secondary" className="mono">{r.iface}</Typography.Text> : null}
              </div>
            ),
          },
          {
            title: "状态",
            kind: "flex",
            width: 150,
            render: (_, r) => {
              const st = RELAY_STATUS[r.status] ?? RELAY_STATUS.unknown;
              return (
                <div className="cell-stack">
                  <span data-testid={`relay-status-${r.id}`}>
                    <StatusTag kind={st.kind} title={st.help}>
                      {st.label}
                    </StatusTag>
                  </span>
                  {r.reason && r.status !== "active" ? (
                    <Typography.Text type="secondary" className="cell-small">
                      {REASON[r.reason] ?? r.reason}，<TimeText value={r.status_since} />
                    </Typography.Text>
                  ) : null}
                  {r.drain ? (
                    <Typography.Text type="danger" className="cell-small" data-testid={`relay-drain-${r.id}`}>
                      已有连接正被清理
                    </Typography.Text>
                  ) : null}
                </div>
              );
            },
          },
          {
            title: "新连接份额",
            kind: "flex",
            width: 100,
            render: (_, r) => <span data-testid={`relay-weight-${r.id}`}>{share(r)}</span>,
          },
          {
            title: "质量（网关测量）",
            kind: "flex",
            width: 180,
            render: (_, r) => (
              <div className="cell-stack">
                <StatusTag kind={GRADE[r.grade]?.kind ?? "unverified"}>{GRADE[r.grade]?.label ?? r.grade}</StatusTag>
                <Measured m={r.measured} />
              </div>
            ),
          },
          {
            title: "流量",
            kind: "flex",
            width: 170,
            render: (_: unknown, r: SharingRelay) => (
              <Typography.Text className="cell-small">
                ↓ {rate(r.traffic.rx_bps)} ↑ {rate(r.traffic.tx_bps)}
                <br />
                <Typography.Text type="secondary">
                  累计 ↓ {bytes(r.traffic.rx_bytes)} ↑ {bytes(r.traffic.tx_bytes)} · 新连接 {r.traffic.new_conns}
                </Typography.Text>
              </Typography.Text>
            ),
          },
          { title: "吞吐探测", kind: "flex", width: 170, render: (_: unknown, r: SharingRelay) => <ProbeCell r={r} /> },
        ]}
      />
      <div style={{ marginTop: 8 }}>
        <Explain
          summary={
            <span data-testid="sharing-impact">断连影响：{s.eviction_impact}</span>
          }
        />
        <Explain
          summary={
            <span data-testid="sharing-probe-cost">
              {s.probe_cost.enabled ? (
                <>
                  吞吐探测会消耗中继的计费流量（面板估算）：每次约 {bytes(s.probe_cost.bytes_per_probe)}（上下行合计），每台中继每天最多 {s.probe_cost.max_probes_per_day} 次、约 {bytes(s.probe_cost.max_bytes_per_day)}（预算 {bytes(s.probe_cost.daily_budget_bytes)}）。{s.probe_cost.trigger}
                </>
              ) : (
                "吞吐探测已关闭：没有探测流量；“小包通、没有速率”只能靠被动信号（有业务时 TCP 收不到回包、负载下时延膨胀等）发现。"
              )}
            </span>
          }
        />
      </div>
    </div>
  );
}

// ------------------------------------------------------------- settings ---

type NumKey = keyof typeof PATH_QUALITY_DEFAULTS;

const FIELDS: { key: NumKey; label: string; unit: string; min: number; max: number; help?: string }[] = [
  { key: "mild_loss_permille", label: "轻度劣化：丢包", unit: "‰", min: 1, max: 999 },
  { key: "mild_rtt_ms", label: "轻度劣化：时延", unit: "ms", min: 10, max: 5000 },
  { key: "poor_loss_permille", label: "可用下限：丢包", unit: "‰", min: 1, max: 1000 },
  { key: "poor_rtt_ms", label: "可用下限：时延", unit: "ms", min: 10, max: 10000 },
  { key: "reduce_after_sec", label: "轻度劣化多久降权", unit: "秒", min: 5, max: 3600 },
  { key: "standby_after_sec", label: "轻度劣化多久停止分配", unit: "秒", min: 5, max: 3600 },
  { key: "evict_after_sec", label: "低于下限多久剔除", unit: "秒", min: 5, max: 3600 },
  { key: "down_after_sec", label: "完全不通多久剔除", unit: "秒", min: 5, max: 600 },
  { key: "recover_after_sec", label: "良好多久开始加回", unit: "秒", min: 10, max: 7200 },
  { key: "ramp_step_sec", label: "加回每步（25%→50%→100%）", unit: "秒", min: 5, max: 600 },
  { key: "backup_after_sec", label: "全部剔除多久改走备用枢纽", unit: "秒", min: 5, max: 3600 },
  { key: "return_after_sec", label: "主链路良好多久切回", unit: "秒", min: 10, max: 7200 },
  { key: "min_dwell_sec", label: "两次切换枢纽最短间隔", unit: "秒", min: 10, max: 7200 },
  { key: "switch_advantage_pct", label: "按质量切换所需优势", unit: "%", min: 5, max: 200 },
];

const PROBE_FIELDS: { key: NumKey; label: string; unit: string; min: number; max: number }[] = [
  { key: "probe_bytes", label: "每次探测大小（单向）", unit: "字节", min: 16384, max: 16777216 },
  { key: "probe_rate_kbps", label: "探测速率", unit: "kbit/s", min: 100, max: 1000000 },
  { key: "probe_min_interval_sec", label: "同一中继最短间隔", unit: "秒", min: 60, max: 86400 },
  { key: "probe_daily_budget_mb", label: "每台中继每天预算", unit: "MB", min: 1, max: 10240 },
  { key: "probe_floor_kbps", label: "吞吐下限", unit: "kbit/s", min: 32, max: 1000000 },
  { key: "probe_loss_permille", label: "探测丢包上限", unit: "‰", min: 10, max: 990 },
];

/** Relays the gateway shares across (role relay with an enabled, non-standby link from the gateway). */
export function sharingRelays(t: Topology) {
  const gw = t.nodes.find((n) => n.role === "gateway")?.id;
  const linked = new Set<string>();
  for (const l of t.links) {
    if (!l.enabled || l.standby || !["direct_wg", "wg_over_wss", "udp_wss_failover"].includes(l.transport)) continue;
    if (l.from === gw) linked.add(l.to);
    if (l.to === gw) linked.add(l.from);
  }
  return t.nodes.filter((n) => n.role === "relay" && linked.has(n.id)).sort((a, b) => (a.id < b.id ? -1 : 1));
}

/** The relay-sharing settings inside the gateway settings drawer. */
export function PathQualitySettings({ topo, onChange }: { topo: Topology; onChange: (pq: PathQuality | undefined) => void }) {
  const pq: PathQuality = topo.settings.path_quality ?? {};
  const relays = sharingRelays(topo);
  const set = (p: Partial<PathQuality>) => {
    const next: PathQuality = { ...pq, ...p };
    for (const k of Object.keys(next) as (keyof PathQuality)[]) {
      const v = next[k];
      if (v === undefined || v === null || v === 0 || v === false || (Array.isArray(v) && v.length === 0)) delete next[k];
    }
    onChange(Object.keys(next).length ? next : undefined);
  };
  const num = (f: { key: NumKey; label: string; unit: string; min: number; max: number }) => (
    <Form.Item key={f.key} label={`${f.label}（${f.unit}）`} style={{ marginBottom: 8 }}>
      <InputNumber
        aria-label={f.label}
        min={f.min}
        max={f.max}
        placeholder={`默认 ${PATH_QUALITY_DEFAULTS[f.key]}`}
        value={pq[f.key] || null}
        onChange={(v) => set({ [f.key]: typeof v === "number" ? v : undefined } as Partial<PathQuality>)}
        style={{ width: "100%" }}
      />
    </Form.Item>
  );
  const eff = (k: NumKey) => pq[k] || PATH_QUALITY_DEFAULTS[k];
  const per = probeCostBytes(eff("probe_bytes"));
  const budget = eff("probe_daily_budget_mb") * 1024 * 1024;
  const perDay = Math.min(Math.floor(86400 / eff("probe_min_interval_sec")), Math.floor(budget / per));
  const overrides = pq.overrides ?? [];
  const ov = (id: string) => overrides.find((o) => o.relay === id);
  const setOv = (id: string, o: RelayOverride | null) => {
    const rest = overrides.filter((x) => x.relay !== id);
    set({ overrides: o ? [...rest, o] : rest });
  };
  return (
    <div data-testid="path-quality-settings">
      <Typography.Paragraph type="secondary" className="cell-small">
        {relays.length >= 2
          ? `网关连着 ${relays.length} 台中继：新连接按测得的质量自动加权分担（同一连接始终走同一台中继），所有中继持续低于可用下限时才改走备用枢纽。留空即默认值；修改要安装到网关后才生效。`
          : "只有一台中继时不做分担，这些设置不生效（保存也不会影响现有安装）。"}
      </Typography.Paragraph>
      {FIELDS.map(num)}
      <Form.Item style={{ marginBottom: 8 }}>
        <Checkbox checked={!!pq.keep_connections_on_evict} onChange={(e) => set({ keep_connections_on_evict: e.target.checked })}>
          剔除时保留已有连接（默认关闭：剔除时重置该中继上的 TCP 连接，让应用在健康的中继上重连）
        </Checkbox>
      </Form.Item>
      <Divider orientation="left" plain style={{ margin: "8px 0" }}>
        吞吐探测（消耗中继计费流量）
      </Divider>
      <Form.Item style={{ marginBottom: 8 }}>
        <Checkbox checked={!pq.probe_off} onChange={(e) => set({ probe_off: !e.target.checked })} aria-label="启用吞吐探测">
          启用（只在有业务且被动信号可疑时触发）
        </Checkbox>
      </Form.Item>
      {PROBE_FIELDS.map(num)}
      <Typography.Paragraph type="secondary" style={{ fontSize: 12 }} data-testid="probe-cost-estimate">
        {pq.probe_off
          ? "已关闭：不产生探测流量。"
          : `估算：每次约 ${bytes(per)}（上下行合计，含包头），每台中继每天最多 ${perDay} 次、约 ${bytes(perDay * per)}。`}
      </Typography.Paragraph>
      {relays.length >= 2 ? (
        <>
          <Divider orientation="left" plain style={{ margin: "8px 0" }}>
            手动覆盖（默认全自动）
          </Divider>
          {relays.map((r) => {
            const o = ov(r.id);
            const mode = o?.disabled ? "disabled" : o?.weight ? "fixed" : "auto";
            return (
              <Form.Item key={r.id} label={r.name || r.id} style={{ marginBottom: 8 }}>
                <Space>
                  <Select
                    aria-label={`覆盖 ${r.id}`}
                    value={mode}
                    style={{ width: 120 }}
                    onChange={(m: string) => setOv(r.id, m === "auto" ? null : m === "disabled" ? { relay: r.id, disabled: true } : { relay: r.id, weight: o?.weight || 50 })}
                    options={[
                      { value: "auto", label: "自动" },
                      { value: "disabled", label: "停用" },
                      { value: "fixed", label: "固定权重" },
                    ]}
                  />
                  {mode === "fixed" ? (
                    <InputNumber aria-label={`权重 ${r.id}`} min={1} max={100} value={o?.weight} onChange={(v) => setOv(r.id, { relay: r.id, weight: typeof v === "number" ? v : 50 })} />
                  ) : null}
                </Space>
              </Form.Item>
            );
          })}
        </>
      ) : null}
    </div>
  );
}
