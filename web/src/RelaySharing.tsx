import { LatencyBadge } from "./LatencyBadge";
import {
  Help,
  Note,
} from "./ui";
// 国内中继同时分担: what the gateway measured and decided (its upstream
// record, read through meridian-host), and the settings of the policy.
// Measured values come only from the gateway and carry their time; the
// probe traffic cost is the panel's estimate from the settings and is
// labelled so.

import { Alert, Checkbox, Divider, Form, InputNumber, Select, Space, Tooltip, Typography } from "antd";
import type { ReactNode } from "react";
import type { PathGrade, PathMeasured, PathQuality, RelayOverride, RelaySpeed, RelayStatus, Sharing, SharingRelay, Topology } from "./types";
import { PATH_QUALITY_DEFAULTS, probeCostBytes } from "./types";
import { DataTable, EllipsisText, KV, StatusTag, TimeText, bytes, formatRelative, type StatusKind } from "./ui";

export const RELAY_STATUS: Record<RelayStatus, { kind: StatusKind; label: string; help: string }> = {
  active: { kind: "ok", label: "分担中", help: "按质量权重接收新连接" },
  reduced: { kind: "attention", label: "已降权", help: "新连接的份额被压低" },
  standby: { kind: "attention", label: "暂停分配", help: "不再分配新连接，已有连接保留" },
  evicted: { kind: "failed", label: "已剔除", help: "不通或测速判定限速：不再分配新连接，继续测速" },
  recovering: { kind: "running", label: "逐步加回", help: "测速恢复：从小份额起逐步加回" },
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
  qos_throttled: "测速连续两次低于限速阈值",
  qos_recovered: "测速回到恢复阈值以上",
  retained_best: "全部低于下限，保留最好的一台独占承载（不切备线）",
  recovered: "已恢复",
  manual: "手动覆盖",
};

/** One line per relay: "186 Mbit/s · 12 分钟前"; only a throttled relay is colored. */
export function SpeedLine({ sp, testId }: { sp?: RelaySpeed; testId?: string }) {
  if (!sp || sp.qos === "off") return <Typography.Text type="secondary" data-testid={testId}>{sp ? "测速关闭" : "未测速"}</Typography.Text>;
  const mbps = sp.mbps !== undefined ? `${Math.round(sp.mbps)} Mbit/s` : "";
  const ago = sp.at ? formatRelative(new Date(sp.at)) : "";
  const tip = `基准 ${Math.round(sp.baseline_mbps)} Mbit/s（${sp.baseline_src === "p90" ? "近期 P90" : "标称"}）· 限速 < ${Math.round(sp.threshold_mbps)} · 恢复 ≥ ${Math.round(sp.recover_mbps)}`;
  return (
    <Tooltip title={tip}>
      <span className="nowrap" data-testid={testId} tabIndex={0}>
        {sp.qos === "throttled" ? (
          <StatusTag kind="failed">限速 {mbps || "—"}</StatusTag>
        ) : mbps ? (
          mbps
        ) : (
          <Typography.Text type="secondary">未测速</Typography.Text>
        )}
        {ago ? <Typography.Text type="secondary"> · {ago}</Typography.Text> : null}
      </span>
    </Tooltip>
  );
}

function rate(bps: number) {
  return `${bytes(bps)}/s`;
}

function Measured({ m }: { m?: PathMeasured }) {
  if (!m || !m.at) return <Typography.Text type="secondary">未测量</Typography.Text>;
  const v = (x: number | undefined, unit: string, digits = 0) => (x === undefined ? "—" : `${x.toFixed(digits)}${unit}`);
  return (
    <Tooltip title={`本轮：时延 ${v(m.last_rtt_ms, " ms", 1)}，丢包 ${v(m.last_loss_pct, "%", 0)}；左侧为多轮平滑值`}>
      <span data-testid="measured">
        <LatencyBadge ms={m.rtt_ms} /> · 丢包 {v(m.loss_pct, "%", 1)}{" "}
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
        <LatencyBadge ms={m.rtt_ms} /> · {v(m.loss_pct, "%", 1)}
      </span>
    </Tooltip>
  );
}

function ProbeCell({ r }: { r: SharingRelay }) {
  const p = r.probe;
  if (!p || !p.at) return <Typography.Text type="secondary">{p && p.bytes_today ? `今日 ${bytes(p.bytes_today)}` : "未探测"}</Typography.Text>;
  const speed = `${p.kbps !== undefined ? `${(p.kbps / 1000).toFixed(1)} Mbit/s` : "—"}${p.loss_pct !== undefined ? ` · 丢 ${p.loss_pct.toFixed(0)}%` : ""}`;
  // Two lines: verdict + speed, then when and today's bytes.
  return (
    <span data-testid={`probe-${r.id}`} className="cell-stack">
      <span className="cell-line" title={speed}>
        {p.ok === false ? <StatusTag kind="failed">不达标</StatusTag> : p.ok ? <span className="muted">达标</span> : null}
        {speed}
      </span>
      <Typography.Text type="secondary" className="cell-line">
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
  if (s.alert && s.alert !== "on_backup" && s.alert !== "on_backup_returning") {
    head.push(<Alert key="alert" type="error" showIcon style={{ marginBottom: 8 }} message={s.alert_text || s.alert} data-testid="sharing-alert" />);
  }
  const grouped = !!s.backup_group;
  const share = (r: SharingRelay) =>
    s.path === "backup" && !grouped ? "0%（备用枢纽承载）" : total > 0 ? `${((r.weight / 10) | 0).toString()}%` : "—";
  const groupName = (r: SharingRelay) => (r.group === "backup" ? `备用组 · ${s.backup_group?.name ?? ""}` : "主组");
  const facts = (
    <div className="kv-list">
      <KV label="承载">
        <span data-testid="sharing-path">
          {s.path === "backup" ? (
            <StatusTag kind="attention">
              {grouped ? `备用组 · ${s.backup_group?.name ?? ""}` : `备用枢纽 ${s.backup?.name ?? ""}`}
            </StatusTag>
          ) : s.path === "main" ? (
            <span className="muted">{grouped ? "主组" : "主链路（多中继分担）"}</span>
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
            const tip = [
              r.name,
              r.iface ? `接口 ${r.iface}` : "",
              `${st.label}：${st.help}`,
              r.reason && r.status !== "active" ? REASON[r.reason] ?? r.reason : "",
              r.drain ? "已有连接正被清理" : "",
            ]
              .filter(Boolean)
              .join("\n");
            return (
              <li key={r.id} className="relay-row">
                <Tooltip title={<span style={{ whiteSpace: "pre-line" }}>{tip}</span>}>
                  <span className="relay-row-name" tabIndex={0}>
                    {r.name}
                    {grouped ? <span className="muted"> · {r.group === "backup" ? "备用组" : "主组"}</span> : null}
                    {s.designated === r.id ? <span className="muted">· 指定</span> : null}
                  </span>
                </Tooltip>
                <span data-testid={`relay-status-${r.id}`}>
                  <StatusTag kind={st.kind} title={st.help}>
                    {st.label}
                  </StatusTag>
                </span>
                <span className="relay-row-share" data-testid={`relay-weight-${r.id}`}>
                  {s.path === "backup" && !grouped ? (
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
                  <SpeedLine sp={r.speed} testId={`relay-speed-${r.id}`} />
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
      {/* Fixed layout: the declared widths (940 px) are what the browser uses, and the
          one-line cells are cut inside them instead of widening the table (974 px at 1280). */}
      <DataTable<SharingRelay>
        size="small"
        rowKey="id"
        dataSource={s.relays}
        tableLayout="fixed"
        columns={[
          {
            title: "中继",
            kind: "flex",
            width: 150,
            render: (_, r) => (
              <div className="cell-stack">
                <span className="inline-status">
                  <EllipsisText text={r.name} />
                  {s.designated === r.id ? <span className="muted" title="本机自己的组解析等无中继标记的流量走它">· 指定</span> : null}
                </span>
                {r.iface ? <EllipsisText className="muted" mono text={r.iface} /> : null}
              </div>
            ),
          },
          ...(grouped
            ? [
                {
                  title: "组",
                  kind: "fixed" as const,
                  width: 110,
                  render: (_: unknown, r: SharingRelay) => (
                    <span data-testid={`relay-group-${r.id}`} className="cell-line">
                      <EllipsisText text={groupName(r)} />
                    </span>
                  ),
                },
              ]
            : []),
          {
            title: "状态",
            kind: "flex",
            width: 170,
            render: (_, r) => {
              const st = RELAY_STATUS[r.status] ?? RELAY_STATUS.unknown;
              // At most two lines: the tag (and a short "清理中" tag), then the reason with its time on one cut line.
              const why = r.reason && r.status !== "active" ? REASON[r.reason] ?? r.reason : "";
              const since = r.status_since && !r.status_since.startsWith("0001-") ? formatRelative(new Date(r.status_since)) : "";
              return (
                <div className="cell-stack">
                  <span className="inline-status">
                    <span data-testid={`relay-status-${r.id}`}>
                      <StatusTag kind={st.kind} title={st.help}>
                        {st.label}
                      </StatusTag>
                    </span>
                    {r.drain ? (
                      <Tooltip title="已有连接正被清理">
                        <StatusTag kind="failed" data-testid={`relay-drain-${r.id}`}>
                          清理中<span className="sr-only">：已有连接正被清理</span>
                        </StatusTag>
                      </Tooltip>
                    ) : null}
                  </span>
                  {why ? <EllipsisText className="cell-small muted" text={since ? `${why}，${since}` : why} /> : null}
                </div>
              );
            },
          },
          {
            title: "新连接份额",
            kind: "fixed",
            width: 100,
            render: (_, r) => (
              <span data-testid={`relay-weight-${r.id}`} className="cell-line">
                <EllipsisText text={share(r)} />
              </span>
            ),
          },
          {
            title: "测速",
            kind: "flex",
            width: 180,
            render: (_, r) => (
              <div className="cell-stack">
                <SpeedLine sp={r.speed} testId={`relay-speed-${r.id}`} />
                <span className="cell-line cell-small muted">
                  <MeasuredShort m={r.measured} />
                </span>
              </div>
            ),
          },
          {
            title: "流量",
            kind: "flex",
            width: 170,
            render: (_: unknown, r: SharingRelay) => (
              <span className="cell-stack cell-small">
                <span className="cell-line">
                  ↓ {rate(r.traffic.rx_bps)} ↑ {rate(r.traffic.tx_bps)}
                </span>
                <EllipsisText className="muted" text={`累计 ↓ ${bytes(r.traffic.rx_bytes)} ↑ ${bytes(r.traffic.tx_bytes)} · 新连接 ${r.traffic.new_conns}`} />
              </span>
            ),
          },
          { title: "吞吐探测", kind: "flex", width: 170, render: (_: unknown, r: SharingRelay) => <ProbeCell r={r} /> },
        ]}
      />
      <Note title="中继分担的代价">
        <div>
            <span data-testid="sharing-impact">断连影响：{s.eviction_impact}</span>
        </div>
        <div>
            <span data-testid="sharing-probe-cost">
              {s.probe_cost.enabled ? (
                <>
                  吞吐探测会消耗中继的计费流量（面板估算）：每次约 {bytes(s.probe_cost.bytes_per_probe)}（上下行合计），每台中继每天最多 {s.probe_cost.max_probes_per_day} 次、约 {bytes(s.probe_cost.max_bytes_per_day)}（预算 {bytes(s.probe_cost.daily_budget_bytes)}）。{s.probe_cost.trigger}
                </>
              ) : (
                "吞吐探测已关闭：没有探测流量；“小包通、没有速率”只能靠被动信号（有业务时 TCP 收不到回包、负载下时延膨胀等）发现。"
              )}
            </span>
        </div>
        {s.speed_test_cost ? (
          <div>
            <span data-testid="sharing-speed-cost">{speedCostText(s.speed_test_cost)}</span>
          </div>
        ) : null}
      </Note>
    </div>
  );
}

function speedCostText(c: NonNullable<Sharing["speed_test_cost"]>) {
  return c.enabled ? `测速约 ${bytes(c.bytes_per_day)}/天/中继（${c.tests_per_day} 次 × ${bytes(c.bytes_per_test)}，估算）` : "测速已关闭";
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

const SPEED_FIELDS: { key: NumKey; label: string; unit: string; min: number; max: number }[] = [
  { key: "speed_test_interval_sec", label: "测速间隔", unit: "秒", min: 300, max: 86400 },
  { key: "qos_throttle_pct", label: "限速阈值（基准的）", unit: "%", min: 5, max: 90 },
  { key: "qos_recover_pct", label: "恢复阈值（基准的）", unit: "%", min: 10, max: 100 },
  { key: "qos_baseline_days", label: "基准窗口", unit: "天", min: 1, max: 30 },
  { key: "nominal_mbps", label: "标称带宽", unit: "Mbit/s", min: 1, max: 100000 },
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
  // An override that is only a nominal bandwidth keeps the relay automatic.
  const setOv = (id: string, o: RelayOverride | null) => {
    const rest = overrides.filter((x) => x.relay !== id);
    const nominal = ov(id)?.nominal_mbps;
    const next: RelayOverride | null = o ? { ...o, ...(nominal && o.nominal_mbps === undefined ? { nominal_mbps: nominal } : {}) } : nominal ? { relay: id, nominal_mbps: nominal } : null;
    set({ overrides: next ? [...rest, next] : rest });
  };
  const setNominal = (id: string, v: number | undefined) => {
    const rest = overrides.filter((x) => x.relay !== id);
    const { nominal_mbps: _, ...cur } = ov(id) ?? { relay: id };
    const next: RelayOverride = v ? { ...cur, relay: id, nominal_mbps: v } : { ...cur, relay: id };
    const empty = !next.disabled && !next.weight && !next.nominal_mbps;
    set({ overrides: empty ? rest : [...rest, next] });
  };
  const sizeMB = pq.speed_test_mb || PATH_QUALITY_DEFAULTS.speed_test_mb;
  const speedPerDay = Math.floor(86400 / eff("speed_test_interval_sec")) * sizeMB * 1024 * 1024;
  return (
    <div data-testid="path-quality-settings">
      <Help title="链路质量设置说明">
        {relays.length >= 2
          ? `网关连着 ${relays.length} 台中继：新连接等权分担（同一连接始终走同一台中继）；定时测速低于基准的限速阈值两次即暂停分配，回到恢复阈值再加回；时延和丢包只显示。留空即默认值；修改要安装到网关后才生效。`
          : "只有一台中继时不做分担；有 Mesh 腿时，共用的质量阈值与冷却设置仍对枢纽的双腿选择生效。"}
      </Help>
      {topo.links.some((l) => l.enabled && l.transport === "cf_mesh") ? <>
        <Note>同出口双腿使用下方「可用下限」丢包 / 时延、切换优势、主链路良好多久切回与最短切换间隔。完全无响应一轮即切换；双断黑洞。修改须重新下发枢纽。</Note>
        <Form.Item label="Mesh 双腿采样窗口（每轮 5 个探测包，默认 6 轮）">
          <InputNumber aria-label="Mesh 双腿采样窗口" min={1} max={60} value={pq.mesh_window_samples ?? null} placeholder="默认 6" onChange={(v) => set({ mesh_window_samples: typeof v === "number" ? v : undefined })} />
        </Form.Item>
      </> : null}
      {FIELDS.map(num)}
      <Form.Item style={{ marginBottom: 8 }}>
        <Checkbox checked={!!pq.keep_connections_on_evict} onChange={(e) => set({ keep_connections_on_evict: e.target.checked })}>
          剔除时保留已有连接
        </Checkbox>
        <Note inline>默认关闭：剔除时重置该中继上的 TCP 连接，让应用在健康的中继上重连。</Note>
      </Form.Item>
      <Divider orientation="left" plain style={{ margin: "8px 0" }}>
        测速（消耗中继计费流量）
      </Divider>
      <Form.Item style={{ marginBottom: 8 }}>
        <Checkbox checked={!pq.speed_test_off} onChange={(e) => set({ speed_test_off: !e.target.checked })} aria-label="启用测速">
          启用
        </Checkbox>
      </Form.Item>
      {!pq.speed_test_off ? (
        <>
          <Form.Item label="每次测速大小（MB）" style={{ marginBottom: 8 }}>
            <Select
              aria-label="每次测速大小"
              value={pq.speed_test_mb || null}
              placeholder={`默认 ${PATH_QUALITY_DEFAULTS.speed_test_mb}`}
              allowClear
              onChange={(v: number | undefined) => set({ speed_test_mb: v })}
              options={[5, 10, 20, 50].map((n) => ({ value: n, label: `${n} MB` }))}
              style={{ width: "100%" }}
            />
          </Form.Item>
          {SPEED_FIELDS.map(num)}
        </>
      ) : null}
      <Note testId="speed-cost-estimate">{pq.speed_test_off ? "测速已关闭" : `约 ${bytes(speedPerDay)}/天/中继（估算）`}</Note>
      {(pq.qos_throttle_pct || PATH_QUALITY_DEFAULTS.qos_throttle_pct) >= (pq.qos_recover_pct || PATH_QUALITY_DEFAULTS.qos_recover_pct) ? (
        <Typography.Text type="danger" data-testid="qos-pct-invalid">限速阈值须低于恢复阈值</Typography.Text>
      ) : null}
      <Divider orientation="left" plain style={{ margin: "8px 0" }}>
        吞吐探测（消耗中继计费流量）
      </Divider>
      <Form.Item style={{ marginBottom: 8 }}>
        <Checkbox checked={!pq.probe_off} onChange={(e) => set({ probe_off: !e.target.checked })} aria-label="启用吞吐探测">
          启用（被动信号可疑时触发）
        </Checkbox>
      </Form.Item>
      {PROBE_FIELDS.map(num)}
      <Note testId="probe-cost-estimate">
        {pq.probe_off
          ? "已关闭：不产生探测流量。"
          : `估算：每次约 ${bytes(per)}（上下行合计，含包头），每台中继每天最多 ${perDay} 次、约 ${bytes(perDay * per)}。`}
      </Note>
      {relays.length >= 1 ? (
        <>
          <Divider orientation="left" plain style={{ margin: "8px 0" }}>
            {relays.length >= 2 ? "手动覆盖（默认全自动）" : "标称带宽"}
          </Divider>
          {relays.map((r) => {
            const o = ov(r.id);
            const mode = o?.disabled ? "disabled" : o?.weight ? "fixed" : "auto";
            return (
              <Form.Item key={r.id} label={r.name || r.id} style={{ marginBottom: 8 }}>
                <Space wrap>
                  {relays.length >= 2 ? <Select
                    aria-label={`覆盖 ${r.id}`}
                    value={mode}
                    style={{ width: 120 }}
                    onChange={(m: string) => setOv(r.id, m === "auto" ? null : m === "disabled" ? { relay: r.id, disabled: true } : { relay: r.id, weight: o?.weight || 50 })}
                    options={[
                      { value: "auto", label: "自动" },
                      { value: "disabled", label: "停用" },
                      { value: "fixed", label: "固定权重" },
                    ]}
                  /> : null}
                  {mode === "fixed" ? (
                    <InputNumber aria-label={`权重 ${r.id}`} min={1} max={100} value={o?.weight} onChange={(v) => setOv(r.id, { relay: r.id, weight: typeof v === "number" ? v : 50 })} />
                  ) : null}
                  <InputNumber
                    aria-label={`标称带宽 ${r.id}`}
                    min={1}
                    max={100000}
                    addonAfter="Mbit/s"
                    placeholder={`默认 ${eff("nominal_mbps")}`}
                    value={o?.nominal_mbps ?? null}
                    onChange={(v) => setNominal(r.id, typeof v === "number" ? v : undefined)}
                    style={{ width: 170 }}
                  />
                </Space>
              </Form.Item>
            );
          })}
        </>
      ) : null}
    </div>
  );
}
