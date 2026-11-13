// 解锁: streaming and AI services on each exit. The catalog says what each
// adapter can tell (a platform verdict, a region, or only reachability);
// probes run on the gateway through the host agent; results are a matrix
// service × exit × family where a reachability result never looks like an
// unlock. Every adapter is built from public methods and synthetic samples,
// not validated against the real platforms, and the page says so up front.

import { InfoCircleOutlined, PlayCircleOutlined, StopOutlined } from "@ant-design/icons";
import {
  Alert,
  App as AntApp,
  Button,
  Checkbox,
  Drawer,
  Popover,
  Progress,
  Radio,
  Select,
  Space,
  Table,
  Tag,
  Tooltip,
  Typography,
} from "antd";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import * as api from "./api";
import { href, useStatus } from "./state";
import type { ProbeCatalogEntry, ProbeCategory, ProbeGrade, ProbeJob, ProbeResultRow, ProbeSelection } from "./types";
import {
  TABLE_SCROLL,
  ApiErrorAlert,
  DataView,
  EmptyState,
  Facts,
  Link,
  Mono,
  Page,
  Section,
  StatusTag,
  TimeText,
  useAction,
  useApi,
} from "./ui";

// ------------------------------------------------------------ vocabulary ---

/** Result categories. Deliberately not the panel status colours: these are platform answers. */
export const CATEGORY: Record<ProbeCategory, { label: string; cls: string; desc: string }> = {
  unlocked: { label: "解锁", cls: "cat-unlocked", desc: "平台的应答里有可用的信号" },
  not_unlocked: { label: "未解锁", cls: "cat-not-unlocked", desc: "平台的应答里有不可用的信号" },
  network_ok: { label: "仅可达", cls: "cat-reach", desc: "连得上平台，但这个检测方法给不出解锁结论" },
  unknown: { label: "未知", cls: "cat-unknown", desc: "平台应答无法识别（验证页、登录页、改版……）" },
  failed: { label: "探测失败", cls: "cat-failed", desc: "没有完成：出口确认不了、超时或网络错误" },
  not_applicable: { label: "不适用 · 仅 IPv4", cls: "cat-na", desc: "这个服务的检测方法只支持 IPv4，IPv6 没有探测，也不入库" },
};

/**
 * The category to show. Items stored before the API had not_applicable
 * carry category "unknown" with signal family_not_supported: nothing was
 * probed, so they are not applicable, not unknown.
 */
export function shownCategory(r: { category?: ProbeCategory; signal?: string }): ProbeCategory | undefined {
  if (r.signal === "family_not_supported" && (r.category === "unknown" || r.category === "not_applicable")) return "not_applicable";
  return r.category;
}
function shownGrade(r: { category?: ProbeCategory; signal?: string; grade?: ProbeGrade }): ProbeGrade | undefined {
  return shownCategory(r) === "not_applicable" ? "not_applicable" : r.grade;
}

const GRADE: Record<ProbeGrade, string> = {
  platform_signal: "平台信号",
  reachability_only: "只有可达性",
  unknown_response: "应答无法识别",
  error: "错误",
  not_applicable: "没有探测",
};

const CAPABILITY: Record<string, { label: string; color: string; desc: string }> = {
  region_verdict: { label: "判定 + 地区", color: "green", desc: "能给出解锁结论和平台认定的地区" },
  verdict: { label: "判定", color: "blue", desc: "能给出解锁结论，不给地区" },
  reachability: { label: "仅可达", color: "default", desc: "只能判断连不连得上，给不出解锁结论" },
  unsupported: { label: "不支持面板探测", color: "default", desc: "没有可在面板执行的检测方法" },
};

const SIGNAL: Record<string, string> = {
  region_match: "平台地区与出口一致",
  region_mismatch: "平台地区与出口不一致",
  available_marker: "页面有可用标记",
  no_negative_marker: "没有不可用标记",
  blocked_marker: "页面有不可用标记",
  reachable: "能连上",
  anti_bot_challenge: "遇到人机验证",
  login_required: "要求登录",
  consent_page: "同意条款页",
  rate_limited: "被限速",
  server_error: "平台服务器错误",
  redirect_unlisted: "跳转到未知地址",
  unexpected_response: "意外的应答",
  egress_changed: "探测中出口地址变了",
  family_not_supported: "检测方法不支持这个地址族",
};

const REJECTED: Record<string, string> = {
  stale: "超过有效期",
  future: "时间在未来",
  out_of_order: "比已收到的结果旧",
  duplicate: "重复报告",
  superseded: "该出口已有更新的一轮",
};

const HISTORY_KIND: Record<string, string> = { scheduled: "定时", manual: "手动", health: "健康变化补测", inconclusive: "无平台结论" };

const JOB_STATE: Record<string, { kind: "running" | "ok" | "neutral" | "attention"; label: string }> = {
  running: { kind: "running", label: "进行中" },
  done: { kind: "ok", label: "已完成" },
  cancelled: { kind: "neutral", label: "已取消" },
  timeout: { kind: "attention", label: "整轮超时" },
  interrupted: { kind: "attention", label: "被中断" },
};

const NOT_INGESTED: Record<string, string> = {
  no_verdict: "这个地址族没有平台结论；同一轮另一个地址族的结论已入库",
  cancelled: "已取消，未入库",
  not_sent: "没有发出，未入库",
  interrupted: "面板中断，未入库",
  save_failed: "保存失败，未入库",
  family_not_supported: "检测方法不支持这个地址族，未入库",
};

export function ingestText(v?: string) {
  if (!v) return "—";
  if (v === "accepted") return "已入库：计入这个服务的切换判断";
  if (v === "accepted:inconclusive") return "已入库但不是结论：不计失败次数，会打断首选的恢复计时";
  const [k, ...rest] = v.split(":");
  const r = rest.join(":");
  if (k === "rejected") return `未采纳：${REJECTED[r] ?? r}`;
  if (k === "note") return r;
  if (k === "not_ingested") return NOT_INGESTED[r] ?? `未入库：${r}`;
  return v;
}

export function CategoryChip({ cat, grade, small }: { cat?: ProbeCategory; grade?: ProbeGrade; small?: boolean }) {
  if (!cat) return <span className="cat-chip cat-none">—</span>;
  const c = CATEGORY[cat];
  return (
    <span className={`cat-chip ${c.cls}${small ? " small" : ""}`} data-category={cat} title={`${c.label}：${c.desc}${grade ? `（证据：${GRADE[grade]}）` : ""}`}>
      {c.label}
      {grade && grade !== "platform_signal" && cat !== "network_ok" && cat !== "failed" && cat !== "not_applicable" ? <span className="cat-grade">{GRADE[grade]}</span> : null}
    </span>
  );
}

// --------------------------------------------------------------- catalog ---

function CatalogInfo({ c }: { c: ProbeCatalogEntry }) {
  return (
    <div className="catalog-info">
      <Typography.Paragraph>{c.basis}</Typography.Paragraph>
      {c.combine ? (
        <Typography.Paragraph>
          <Typography.Text type="secondary">结论怎么合成：</Typography.Text>
          {c.combine}
        </Typography.Paragraph>
      ) : null}
      {c.limits ? (
        <Typography.Paragraph>
          <Typography.Text type="secondary">局限：</Typography.Text>
          {c.limits}
        </Typography.Paragraph>
      ) : null}
      {c.requests && c.requests.length > 0 ? (
        <div style={{ marginBottom: 8 }}>
          <Typography.Text type="secondary">请求：</Typography.Text>
          <ul className="ref-list">
            {c.requests.map((r) => (
              <li key={r} className="mono-small">
                {r}
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      {c.sources && c.sources.length > 0 ? (
        <div>
          <Typography.Text type="secondary">依据的公开方法：</Typography.Text>
          <ul className="ref-list">
            {c.sources.map((s) => (
              <li key={s.url}>
                {s.name} <span className="mono-small muted">{s.url}</span> <span className="muted">（核对于 {s.checked}）</span>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  );
}

function CatalogTable({ catalog }: { catalog: ProbeCatalogEntry[] }) {
  return (
    <Table<ProbeCatalogEntry>
      rowKey="service"
      size="small"
      pagination={false}
      dataSource={catalog}
      scroll={TABLE_SCROLL}
      columns={[
        {
          title: "服务",
          className: "cell-name",
          render: (_, c) => (
            <Space size={4}>
              <Typography.Text strong>{c.name}</Typography.Text>
              <Popover title={c.name} content={<CatalogInfo c={c} />} trigger="click" overlayStyle={{ maxWidth: 520 }}>
                <Button type="text" size="small" icon={<InfoCircleOutlined />} aria-label={`${c.name} 的依据与局限`} />
              </Popover>
            </Space>
          ),
        },
        {
          title: "能告诉你什么",
          className: "nowrap",
          render: (_, c) => {
            const cap = CAPABILITY[c.capability ?? (c.reachability ? "reachability" : "verdict")];
            return (
              <Tooltip title={cap.desc}>
                <Tag color={cap.color}>{cap.label}</Tag>
              </Tooltip>
            );
          },
        },
        {
          title: "检测的平台",
          render: (_, c) =>
            (c.platforms ?? []).map((p) => (
              <Tooltip key={p.name} title={p.note || (p.checked ? (p.primary ? "主平台：决定结论" : "附带检查，只作参考") : "不检查")}>
                <Tag color={p.checked ? (p.primary ? "processing" : "default") : undefined} style={!p.checked ? { textDecoration: "line-through", opacity: 0.6 } : undefined}>
                  {p.name}
                </Tag>
              </Tooltip>
            )),
        },
        {
          title: "地址族",
          className: "nowrap",
          render: (_, c) => (c.ipv4_only ? <Tag>只有 IPv4</Tag> : <Typography.Text type="secondary">IPv4 / IPv6</Typography.Text>),
        },
        {
          title: "规则",
          className: "nowrap",
          render: (_, c) =>
            c.enabled ? (
              <Space size={4}>
                <Link to={href("exits", c.group)}>{c.group}</Link>
                {c.group_mode === "manual" ? (
                  <Tooltip title="组是手动模式：结果只记录，不改出口">
                    <Tag>手动组</Tag>
                  </Tooltip>
                ) : null}
              </Space>
            ) : (
              <Typography.Text type="secondary">没有启用的规则</Typography.Text>
            ),
        },
      ]}
    />
  );
}

// --------------------------------------------------------- probe launcher ---

type TargetMode = "default" | "groups" | "exits";

function Launcher({
  catalog,
  available,
  running,
  groups,
  exits,
  onStarted,
}: {
  catalog: ProbeCatalogEntry[];
  available: boolean;
  running: string;
  groups: { id: string; name: string; members: string[] }[];
  exits: { id: string; name: string }[];
  onStarted: (job: ProbeJob) => void;
}) {
  const probeable = catalog.filter((c) => c.probeable !== false && c.capability !== "unsupported");
  const runnable = probeable.filter((c) => c.enabled);
  const autoDefault = runnable.filter((c) => c.group_mode !== "manual").map((c) => c.service);
  const [services, setServices] = useState<string[]>(autoDefault);
  const [target, setTarget] = useState<TargetMode>("default");
  const [selGroups, setSelGroups] = useState<string[]>([]);
  const [selExits, setSelExits] = useState<string[]>([]);
  const [families, setFamilies] = useState<("ipv4" | "ipv6")[]>([]);
  const act = useAction();
  const { refresh } = useStatus();
  const touched = useRef(false);

  useEffect(() => {
    if (!touched.current) setServices(autoDefault);
  }, [autoDefault.join()]); // eslint-disable-line react-hooks/exhaustive-deps

  const start = () =>
    act.run(async () => {
      const sel: ProbeSelection = {};
      if (services.length !== autoDefault.length || services.some((s) => !autoDefault.includes(s))) sel.services = services;
      if (target === "groups" && selGroups.length) sel.groups = selGroups;
      if (target === "exits" && selExits.length) sel.exits = selExits;
      if (families.length) sel.families = families;
      const r = await api.runUnlock(sel);
      onStarted(r.job);
      refresh();
    }, "run");

  const count = useMemo(() => {
    if (target === "groups") return new Set(groups.filter((g) => selGroups.includes(g.id)).flatMap((g) => g.members)).size;
    if (target === "exits") return selExits.length;
    return null;
  }, [target, selGroups, selExits, groups]);

  return (
    <div className="launcher" data-testid="probe-launcher">
      {!available ? (
        <Alert
          type="warning"
          showIcon
          style={{ marginBottom: 12 }}
          message="面板现在不能探测"
          description="探测在网关上的 meridian-host 里执行，它没有运行或面板连不上它。面板不会编造结果；下面是以前的记录。"
        />
      ) : null}
      <div className="launcher-row">
        <Typography.Text strong>服务</Typography.Text>
        <Space size={4} wrap>
          <Button size="small" type="link" onClick={() => ((touched.current = true), setServices(runnable.map((c) => c.service)))}>
            全选
          </Button>
          <Button size="small" type="link" onClick={() => ((touched.current = true), setServices([]))}>
            清空
          </Button>
        </Space>
      </div>
      <Checkbox.Group
        value={services}
        onChange={(v) => {
          touched.current = true;
          setServices(v as string[]);
        }}
        className="service-checks"
      >
        {catalog.map((c) => {
          const disabled = !runnable.includes(c);
          const why = c.capability === "unsupported" || c.probeable === false ? "没有面板探测方法" : !c.enabled ? "没有启用的规则" : c.group_mode === "manual" ? "手动组：只记录" : "";
          return (
            <Checkbox key={c.service} value={c.service} disabled={disabled}>
              {c.name}
              {why ? <span className="muted" style={{ fontSize: 12 }}>（{why}）</span> : null}
            </Checkbox>
          );
        })}
      </Checkbox.Group>
      <div className="launcher-row" style={{ marginTop: 12 }}>
        <Typography.Text strong>出口</Typography.Text>
      </div>
      <Radio.Group value={target} onChange={(e) => setTarget(e.target.value)} optionType="button">
        <Radio.Button value="default">各服务自己的组成员</Radio.Button>
        <Radio.Button value="groups">按地区组</Radio.Button>
        <Radio.Button value="exits">指定出口</Radio.Button>
      </Radio.Group>
      {target === "groups" ? (
        <Select
          mode="multiple"
          style={{ display: "block", marginTop: 8, maxWidth: 560 }}
          placeholder="选择地区组（组里的全部成员都会被探测）"
          value={selGroups}
          onChange={setSelGroups}
          options={groups.map((g) => ({ value: g.id, label: `${g.name}（${g.members.length} 个出口）` }))}
          aria-label="按地区组"
        />
      ) : target === "exits" ? (
        <Select
          mode="multiple"
          style={{ display: "block", marginTop: 8, maxWidth: 560 }}
          placeholder="选择出口"
          value={selExits}
          onChange={setSelExits}
          optionFilterProp="label"
          options={exits.map((e) => ({ value: e.id, label: `${e.name}（${e.id}）` }))}
          aria-label="指定出口"
        />
      ) : null}
      <div className="launcher-row" style={{ marginTop: 12 }}>
        <Typography.Text strong>地址族</Typography.Text>
        <Checkbox.Group value={families} onChange={(v) => setFamilies(v as ("ipv4" | "ipv6")[])} options={[{ label: "IPv4", value: "ipv4" }, { label: "IPv6", value: "ipv6" }]} />
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
          都不选：按每个出口支持的地址族
        </Typography.Text>
      </div>
      <Space style={{ marginTop: 12 }} wrap>
        <Button
          type="primary"
          icon={<PlayCircleOutlined />}
          loading={act.busy === "run"}
          disabled={!available || !!running || services.length === 0 || (target === "groups" && selGroups.length === 0) || (target === "exits" && selExits.length === 0)}
          onClick={() => void start()}
        >
          开始探测
        </Button>
        <Typography.Text type="secondary">
          {services.length} 个服务
          {count !== null ? ` × ${count} 个出口` : ""}。每项先确认实际出口地址属于该出口，确认不了就记为探测失败，不会回落到别的出口。
        </Typography.Text>
      </Space>
      {running ? <Typography.Paragraph type="secondary" style={{ marginTop: 8 }}>已有一轮探测在进行，结束后才能开始新的。</Typography.Paragraph> : null}
      <ApiErrorAlert
        error={act.error}
        onClose={act.clear}
        style={{ marginTop: 12 }}
      >
        {act.error?.status === 409 ? <div>同一时间只能有一轮探测；等它结束或取消它。</div> : act.error?.status === 503 ? <div>宿主执行通道不可用，探测无法进行。</div> : null}
      </ApiErrorAlert>
    </div>
  );
}

// --------------------------------------------------------------- results ---

interface ExitCol {
  id: string;
  name: string;
  group: { id: string; name: string } | null;
  /** The hub reported this member in use for its group. */
  active: boolean;
  /** Only the panel's model says so (面板推算). */
  modelActive: boolean;
  families: string[];
}

function ResultDetail({ row }: { row: ProbeResultRow }) {
  const cat = shownCategory(row);
  const grade = shownGrade(row);
  return (
    <div data-testid="result-detail">
      <Space size={6} wrap style={{ marginBottom: 12 }}>
        <CategoryChip cat={cat} grade={grade} />
        <Tag>{row.family === "ipv6" ? "IPv6" : "IPv4"}</Tag>
        {row.is_active ? <Tag color="success">这个出口正在承载该服务</Tag> : null}
      </Space>
      {row.category === "network_ok" ? (
        <Alert type="info" showIcon style={{ marginBottom: 12 }} message="「仅可达」不是解锁：只说明连得上平台，这个检测方法给不出解锁结论。" />
      ) : null}
      {cat === "not_applicable" ? (
        <Alert
          type="info"
          showIcon
          style={{ marginBottom: 12 }}
          data-testid="not-applicable-notice"
          message="不适用：这一项没有探测"
          description="这个服务的公开检测方法只支持 IPv4，所以没有经这个出口发出 IPv6 请求。这不是失败，也不是未知；不入库，不影响这个服务在组内选哪个出口。要看 IPv4 的结果，点同一格里的 v4。"
        />
      ) : null}
      <Facts
        items={[
          ["服务", row.service_name || row.service],
          ["出口", <span key="e">{row.exit_name || row.exit_id} <span className="mono-small muted">{row.exit_id}</span></span>],
          ["结论", `${cat ? CATEGORY[cat].label : "—"}${cat ? ` — ${CATEGORY[cat].desc}` : ""}`],
          ["证据等级", grade ? GRADE[grade] : "—"],
          ["信号", row.signal ? `${SIGNAL[row.signal] ?? row.signal}（${row.signal}）` : "—"],
          ["平台认定的地区", row.region ? row.region.toUpperCase() : "—"],
          ["证据", row.evidence || "—"],
          ["HTTP 状态", row.status ? String(row.status) : "—"],
          ["出口确认", row.egress || "—"],
          ["实际出口地址", row.egress_ip ? <Mono key="ip">{row.egress_ip}</Mono> : "—"],
          ["确认依据", row.egress_basis || "—"],
          ["错误", row.error || "—"],
          ["入库", ingestText(row.ingest)],
          ["时间", <TimeText key="t" value={row.finished_at || row.started_at} />],
          ["校验状态", row.validation === "synthetic_only" ? <StatusTag key="v" kind="unverified">检测方法未在真实平台验证</StatusTag> : row.validation || "—"],
        ]}
      />
      {row.parts && row.parts.length > 0 ? (
        <>
          <Typography.Title level={5} style={{ marginTop: 16 }}>
            分项检查（仅供参考，主平台决定结论）
          </Typography.Title>
          <Table
            size="small"
            rowKey="platform"
            pagination={false}
            dataSource={row.parts}
            scroll={TABLE_SCROLL}
            columns={[
              { title: "平台", className: "cell-name", render: (_, p) => <span>{p.platform}{p.primary ? <Tag style={{ marginLeft: 4 }}>主</Tag> : null}</span> },
              { title: "结论", render: (_, p) => <CategoryChip cat={p.category} grade={p.grade} small /> },
              { title: "信号", render: (_, p) => (p.signal ? SIGNAL[p.signal] ?? p.signal : "—") },
              { title: "地区", render: (_, p) => p.region?.toUpperCase() || "—" },
              { title: "证据", width: 220, className: "cell-text", render: (_, p) => p.evidence || p.error || "—" },
            ]}
          />
        </>
      ) : null}
    </div>
  );
}

function ResultsMatrix({ rows, catalog, onOpen }: { rows: ProbeResultRow[]; catalog: ProbeCatalogEntry[]; onOpen: (r: ProbeResultRow) => void }) {
  const cols = useMemo(() => {
    const m = new Map<string, ExitCol>();
    for (const r of rows) {
      const c = m.get(r.exit_id) ?? {
        id: r.exit_id,
        name: r.exit_name || r.exit_id,
        group: r.exit_groups[0] ? { id: r.exit_groups[0].id, name: r.exit_groups[0].name } : null,
        active: r.exit_groups.some((g) => g.actual_active === r.exit_id),
        modelActive: r.exit_groups.some((g) => g.model_active === r.exit_id),
        families: [],
      };
      if (!c.families.includes(r.family)) c.families.push(r.family);
      m.set(r.exit_id, c);
    }
    return [...m.values()].sort((a, b) => (a.group?.name ?? "~").localeCompare(b.group?.name ?? "~") || a.id.localeCompare(b.id));
  }, [rows]);
  const services = useMemo(() => {
    const ids = [...new Set(rows.map((r) => r.service))];
    const order = new Map(catalog.map((c, i) => [c.service, i]));
    return ids.sort((a, b) => (order.get(a) ?? 99) - (order.get(b) ?? 99));
  }, [rows, catalog]);
  const cell = useMemo(() => new Map(rows.map((r) => [`${r.service}|${r.exit_id}|${r.family}`, r])), [rows]);
  const groups = useMemo(() => {
    const out: { id: string; name: string; cols: ExitCol[] }[] = [];
    for (const c of cols) {
      const key = c.group?.id ?? "";
      const last = out[out.length - 1];
      if (last && last.id === key) last.cols.push(c);
      else out.push({ id: key, name: c.group?.name ?? "不在组里", cols: [c] });
    }
    return out;
  }, [cols]);
  const svcName = (id: string) => catalog.find((c) => c.service === id)?.name ?? rows.find((r) => r.service === id)?.service_name ?? id;

  return (
    <div className="matrix-wrap">
      <table className="matrix" data-testid="unlock-matrix">
        <thead>
          <tr>
            <th rowSpan={2} className="matrix-corner">
              服务 \ 出口
            </th>
            {groups.map((g) => (
              <th key={g.id || "none"} colSpan={g.cols.length} className="matrix-group">
                {g.id ? <Link to={href("exits", g.id)}>{g.name}</Link> : g.name}
              </th>
            ))}
          </tr>
          <tr>
            {cols.map((c) => (
              <th key={c.id} className="matrix-exit">
                <Tooltip
                  title={c.active ? "枢纽报告这个组当前使用它" : c.modelActive ? "面板推算这个组在用它（未经枢纽确认）" : undefined}
                >
                  <span>
                    {c.name}
                    {c.active ? (
                      <span className="active-dot" aria-label="枢纽报告组当前使用" />
                    ) : c.modelActive ? (
                      <span className="active-dot model" aria-label="面板推算组在用" />
                    ) : null}
                  </span>
                </Tooltip>
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {services.map((s) => (
            <tr key={s}>
              <th className="matrix-service">{svcName(s)}</th>
              {cols.map((c) => (
                <td key={c.id}>
                  <div className="matrix-cell">
                    {c.families.map((f) => {
                      const r = cell.get(`${s}|${c.id}|${f}`);
                      if (!r) return null;
                      return (
                        <button
                          key={f}
                          type="button"
                          className="matrix-btn"
                          onClick={() => onOpen(r)}
                          data-testid={`cell-${s}-${c.id}-${f}`}
                          aria-label={`${svcName(s)} · ${c.name} · ${f === "ipv6" ? "IPv6" : "IPv4"}：${shownCategory(r) ? CATEGORY[shownCategory(r)!].label : r.state}`}
                        >
                          <span className="fam">{f === "ipv6" ? "v6" : "v4"}</span>
                          {r.state === "queued" || r.state === "running" ? (
                            <span className="cat-chip cat-none">{r.state === "running" ? "探测中" : "排队"}</span>
                          ) : (
                            <CategoryChip cat={shownCategory(r)} grade={shownGrade(r)} small />
                          )}
                          {r.is_active ? <span className="active-dot" aria-hidden /> : null}
                        </button>
                      );
                    })}
                  </div>
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ------------------------------------------------------------------ page ---

export default function UnlockPage() {
  const catalog = useApi(() => api.getUnlockCatalog(), []);
  const jobs = useApi(() => api.getUnlockJobs(), []);
  const results = useApi(() => api.getUnlockResults(), []);
  const view = useApi(() => api.getUnlock(), []);
  const groups = useApi(() => api.listGroups(), []);
  const { refresh, status } = useStatus();
  const { message } = AntApp.useApp();
  const cancelAct = useAction();
  const [job, setJob] = useState<ProbeJob | null>(null);
  const [open, setOpen] = useState<ProbeResultRow | null>(null);
  const [fGroup, setFGroup] = useState<string>();
  const [fExit, setFExit] = useState<string>();
  const [fService, setFService] = useState<string>();
  const [fFamily, setFFamily] = useState<string>();

  const running = jobs.data?.running || (job?.state === "running" ? job.id : "");
  // The catalog says a probe runtime is configured; the status says the agent answers now.
  const available = (catalog.data?.available ?? jobs.data?.available ?? false) && (status ? status.probe_available : true);

  useEffect(() => {
    if (!jobs.data) return;
    const cur = jobs.data.jobs.find((j) => j.id === jobs.data!.running) ?? jobs.data.jobs[0] ?? null;
    // A job we just started may not be in the list yet: keep it until polling says otherwise.
    setJob((old) => (old && old.state === "running" && (!cur || old.id !== cur.id) ? old : cur));
  }, [jobs.data]);

  const reloadAll = useCallback(() => {
    void results.reload();
    void view.reload();
    void jobs.reload();
    refresh();
  }, [results, view, jobs, refresh]);

  // Poll the running job (light endpoint) and the results it fills in.
  useEffect(() => {
    if (!job || job.state !== "running") return;
    const t = window.setInterval(async () => {
      try {
        const r = await api.getUnlockJob(job.id);
        setJob(r.job);
        void results.reload();
        if (!r.running || r.job.state !== "running") {
          reloadAll();
          message.info("这一轮探测结束了");
        }
      } catch {
        /* keep the last state */
      }
    }, 2000);
    return () => window.clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [job?.id, job?.state]);

  const rows = useMemo(() => {
    const all = results.data?.results ?? [];
    return all.filter(
      (r) =>
        (!fService || r.service === fService) &&
        (!fExit || r.exit_id === fExit) &&
        (!fFamily || r.family === fFamily) &&
        (!fGroup || r.group === fGroup || r.exit_groups.some((g) => g.id === fGroup)),
    );
  }, [results.data, fService, fExit, fFamily, fGroup]);

  const exitOptions = useMemo(() => {
    const m = new Map<string, string>();
    for (const r of results.data?.results ?? []) m.set(r.exit_id, r.exit_name || r.exit_id);
    for (const g of groups.data?.groups ?? []) for (const ms of g.member_status) m.set(ms.id, ms.name || ms.id);
    return [...m.entries()].map(([id, name]) => ({ id, name }));
  }, [results.data, groups.data]);

  const progress = useMemo(() => {
    if (!job) return null;
    const total = job.items.length;
    const done = job.items.filter((i) => i.state === "done" || i.state === "skipped").length;
    const by: Partial<Record<ProbeCategory, number>> = {};
    for (const i of job.items) {
      const c = shownCategory(i);
      if (c && (i.state === "done" || i.state === "skipped")) by[c] = (by[c] ?? 0) + 1;
    }
    return { total, done, by };
  }, [job]);

  const validationText = catalog.data?.validation_text || results.data?.validation_text || jobs.data?.validation_text;

  const stateRows = useMemo(() => {
    const v = view.data;
    if (!v) return [];
    return v.services.map((s) => {
      const st = v.states?.[s.rule_id];
      return { ...s, st, active: s.pin ? s.preferred : st?.active || v.decisions?.[s.rule_id] || s.preferred };
    });
  }, [view.data]);
  const nm = (id?: string) => (id ? exitOptions.find((e) => e.id === id)?.name ?? id : "—");

  return (
    <Page
      title="解锁"
      description="流媒体和 AI 服务在各个出口上能不能用。探测在网关上执行，结果会影响自动规则在组内选哪个成员。"
      extra={
        running ? (
          <Button
            danger
            icon={<StopOutlined />}
            loading={cancelAct.busy === "cancel"}
            onClick={() =>
              cancelAct.run(async () => {
                await api.cancelUnlockJob(running);
                reloadAll();
              }, "cancel")
            }
          >
            取消探测
          </Button>
        ) : null
      }
    >
      <Alert
        type="warning"
        showIcon
        style={{ marginBottom: 16 }}
        data-testid="validation-notice"
        message="检测方法未在真实平台上验证"
        description={
          <span>
            {validationText || "检测规则依据公开检测方法与合成样本编写，尚未在真实平台上验证。"}
            平台随时可能改页面；任何结论都需要你在真实设备上复核。
          </span>
        }
      />
      <ApiErrorAlert error={cancelAct.error} onClose={cancelAct.clear} />
      <Section title="发起探测">
        <DataView state={catalog} rows={4}>
          {(c) => (
            <Launcher
              catalog={c.catalog}
              available={available}
              running={running}
              groups={(groups.data?.groups ?? []).map((g) => ({ id: g.id, name: g.name, members: g.members }))}
              exits={exitOptions}
              onStarted={(j) => {
                setJob(j);
                message.success("探测已开始");
                void jobs.reload();
              }}
            />
          )}
        </DataView>
        {job && progress ? (
          <div className="job-progress" data-testid="job-progress">
            <Space size={8} wrap>
              <StatusTag kind={JOB_STATE[job.state]?.kind ?? "neutral"}>{JOB_STATE[job.state]?.label ?? job.state}</StatusTag>
              <Typography.Text type="secondary">{job.kind === "scheduled" ? "定时" : "手动"}</Typography.Text>
              <Typography.Text type="secondary">
                开始 <TimeText value={job.created_at} />
              </Typography.Text>
              {job.error ? <Typography.Text type="danger">{job.error}</Typography.Text> : null}
            </Space>
            <Progress percent={progress.total ? Math.round((progress.done / progress.total) * 100) : 0} status={job.state === "running" ? "active" : "normal"} format={() => `${progress.done}/${progress.total}`} />
            <Space size={6} wrap>
              {(Object.keys(CATEGORY) as ProbeCategory[]).map((k) =>
                progress.by[k] ? (
                  <span key={k}>
                    <CategoryChip cat={k} small /> {progress.by[k]}
                  </span>
                ) : null,
              )}
            </Space>
          </div>
        ) : null}
      </Section>

      <Section
        title="结果"
        extra={
          <Space wrap>
            <Select allowClear placeholder="地区组" style={{ width: 150 }} value={fGroup} onChange={setFGroup} options={(groups.data?.groups ?? []).map((g) => ({ value: g.id, label: g.name }))} aria-label="按地区组筛选" />
            <Select allowClear placeholder="出口" style={{ width: 150 }} value={fExit} onChange={setFExit} options={exitOptions.map((e) => ({ value: e.id, label: e.name }))} aria-label="按出口筛选" />
            <Select allowClear placeholder="服务" style={{ width: 160 }} value={fService} onChange={setFService} options={(catalog.data?.catalog ?? []).map((c) => ({ value: c.service, label: c.name }))} aria-label="按服务筛选" />
            <Select allowClear placeholder="地址族" style={{ width: 100 }} value={fFamily} onChange={setFFamily} options={[{ value: "ipv4", label: "IPv4" }, { value: "ipv6", label: "IPv6" }]} aria-label="按地址族筛选" />
          </Space>
        }
      >
        <div className="cat-legend">
          {(Object.keys(CATEGORY) as ProbeCategory[]).map((k) => (
            <span key={k}>
              <CategoryChip cat={k} small /> <span className="muted">{CATEGORY[k].desc}</span>
            </span>
          ))}
          <span>
            <span className="active-dot" /> <span className="muted">组当前使用 / 服务当前所在的出口</span>
          </span>
        </div>
        <DataView state={results} rows={5}>
          {() =>
            rows.length === 0 ? (
              <EmptyState
                title={(results.data?.results.length ?? 0) === 0 ? "还没有探测结果" : "没有符合筛选条件的结果"}
                description={(results.data?.results.length ?? 0) === 0 ? "在上面选择服务和出口，开始一轮探测。" : "换一个筛选条件。"}
              />
            ) : (
              <ResultsMatrix rows={rows} catalog={catalog.data?.catalog ?? []} onOpen={setOpen} />
            )
          }
        </DataView>
      </Section>

      <Section title="各服务现在在哪个出口">
        <DataView state={view} rows={4}>
          {(v) => (
            <>
              {v.pending_apply ? (
                <Alert
                  type="info"
                  showIcon
                  style={{ marginBottom: 12 }}
                  message="解锁结果已经改变了自动规则的出口，还没有安装到网关"
                  action={<Link to={href("deploy")}>去部署</Link>}
                />
              ) : null}
              <Typography.Paragraph type="secondary">
                每 {Math.round(v.interval_sec / 3600)} 小时定时探测一次，下次 <TimeText value={v.next_run} />。连续两次定时失败才改用同组的下一个成员；手动探测和健康变化补测不计数。
                首选恢复后要连续成功满 30 分钟才切回，中间任何一次失败都会重新计时。手动组只记录，不改出口。
              </Typography.Paragraph>
              <Table
                rowKey="rule_id"
                size="small"
                pagination={false}
                dataSource={stateRows}
                scroll={TABLE_SCROLL}
                columns={[
                  { title: "服务", dataIndex: "name", className: "cell-name" },
                  { title: "地区组", className: "nowrap", render: (_, r) => <Link to={href("exits", r.pool)}>{r.pool}</Link> },
                  { title: "首选", className: "nowrap", render: (_, r) => nm(r.preferred) },
                  { title: "现在承载", className: "nowrap", render: (_, r) => <Typography.Text strong={r.active !== r.preferred}>{nm(r.active)}</Typography.Text> },
                  {
                    title: "状态",
                    render: (_, r) => (
                      <Space size={4} wrap>
                        {r.pin ? <Tag>手动组：只记录</Tag> : null}
                        {r.st?.demoted ? <StatusTag kind="attention">已降级到备选</StatusTag> : null}
                        {r.st?.unavailable ? <StatusTag kind="failed">组内都不可用</StatusTag> : null}
                        {!r.pin && (r.st?.sched_fails ?? 0) > 0 ? <Tag>{r.st!.sched_fails} 次定时失败</Tag> : null}
                        {r.st?.demoted && r.st.preferred_ok_at ? (
                          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                            首选连续成功始于 <TimeText value={r.st.preferred_ok_at} />
                          </Typography.Text>
                        ) : null}
                        {!r.pin && !r.st?.demoted && !r.st?.unavailable && !(r.st?.sched_fails ?? 0) ? <Typography.Text type="secondary">—</Typography.Text> : null}
                      </Space>
                    ),
                  },
                ]}
              />
            </>
          )}
        </DataView>
      </Section>

      <Section title="历史">
        <DataView state={view} rows={3}>
          {(v) => (
            <Table
              size="small"
              rowKey={(_, i) => String(i)}
              pagination={{ pageSize: 10, hideOnSinglePage: true }}
              dataSource={[...(v.history ?? [])].reverse()}
              scroll={TABLE_SCROLL}
              columns={[
                { title: "时间", className: "nowrap", render: (_, h) => <TimeText value={h.at} /> },
                { title: "来源", className: "nowrap", render: (_, h) => HISTORY_KIND[h.kind] ?? h.kind },
                { title: "服务", dataIndex: "service", className: "cell-name" },
                { title: "出口", className: "nowrap", render: (_, h) => nm(h.exit_id) },
                { title: "地址族", className: "nowrap", render: (_, h) => (h.family === "ipv6" ? "IPv6" : h.family === "ipv4" ? "IPv4" : "—") },
                {
                  title: "结果",
                  className: "nowrap",
                  render: (_, h) => (h.kind === "inconclusive" ? <Tag>无结论</Tag> : h.ok ? <Tag color="green">可用</Tag> : <Tag color="red">不可用</Tag>),
                },
                {
                  title: "说明",
                  width: 260,
                  className: "cell-text",
                  render: (_, h) => (
                    <>
                      {h.rejected ? <Tag>未采纳：{REJECTED[h.rejected] ?? h.rejected}</Tag> : null}
                      {h.note}
                    </>
                  ),
                },
              ]}
            />
          )}
        </DataView>
      </Section>

      <Section title={`平台目录（${catalog.data?.catalog.length ?? 0} 个服务）`}>
        <DataView state={catalog} rows={4}>
          {(c) => (
            <>
              <Typography.Paragraph type="secondary">
                每个服务的检测方法能告诉你什么：「判定」类给出解锁结论；「仅可达」类只能说明连得上。点 <InfoCircleOutlined /> 看依据、局限和来源。
                {c.ingest_rule ? ` 入库规则：${c.ingest_rule}` : ""}
              </Typography.Paragraph>
              <CatalogTable catalog={c.catalog} />
            </>
          )}
        </DataView>
      </Section>

      <Drawer open={!!open} onClose={() => setOpen(null)} width={560} title={open ? `${open.service_name || open.service} · ${open.exit_name || open.exit_id}` : ""} destroyOnHidden>
        {open ? <ResultDetail row={open} /> : null}
      </Drawer>
    </Page>
  );
}
