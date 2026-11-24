import {
  Help,
  Note,
  StatusTag,
} from "./ui";
// 连接日志 (#/conn-log): the name-sniffing forwarder's bounded journal on
// the gateway (24 h, 50000 records, 32 MiB; root-only), read on demand
// through the host agent: a device list with per-device summaries, a
// device's filterable, paged records, the connections still being relayed
// ("正在转发", in no count), the operator's device labels (panel data), the
// confirmed "clear", and the report of an unclean stop. What the journal
// does not cover (UDP/QUIC, other ports, sniffing off, DNS queries) and how
// names are handled are stated next to it; the switch of name recording
// stays on the sniff card (分流规则 → 按域名嗅探), this page links to it.
//
// Empty states are explicit: sniffing not enabled, the forwarder not
// installed or not running, a gateway without the journal, and no data yet.
//
// Cross-link with the DNS query journal (log_common.tsx): a record links to
// the queries of the same device around its start, and the page shows the
// connections around a query when it is opened with ?device=&at=[&mac=].

import { Alert, App as AntApp, Button, Input, Select, Skeleton, Space, Tag, Typography } from "antd";
import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import * as api from "./api";
import { LogEmpty, LogIntro, LogPager, LogStats, LogToolbar, RelatedPanel, ageText, relatedHref, relatedOf, sinceHours } from "./log_common";
import { JOURNAL_CLASS, NAME_ERROR, NEUTRAL_CLASSES, ResultCell, SNIFF_END, SNIFF_MARK, SNIFF_WHY, durationText, reasonText, targetText } from "./Sniff";
import { href, useRouter, useTopologyDocIfLoaded } from "./state";
import type {
  SniffDeviceLabel,
  SniffDeviceSummary,
  SniffJournalQuery,
  SniffJournalRecord,
  SniffJournalScope,
  SniffJournalStats,
  SniffJournalView,
  SniffRecord,
  SniffView,
} from "./types";
import { ApiErrorAlert, DataTable, EllipsisText, Facts, Link, LinkButton, Mono, Page, SearchInput, Section, TimeText, bytes, useApi, useConfirmDanger, type DataColumn, type FactItem } from "./ui";

/** Where the switch of name recording is (the sniff card on the rules page). */
const SNIFF_SETTINGS = `${href("rules")}?section=sniff`;

/** The unavailable / not-running states of the journal reads, in one line. */
function journalProblem(v: SniffJournalView): string | null {
  if (v.available) return null;
  switch (v.code) {
    case "no_socket":
      return "嗅探服务没有运行，读不到网关上的连接日志。";
    case "no_journal":
      return "网关上的嗅探服务没有连接日志（旧版本或日志目录无法打开）：安装当前版本后才有。";
    default:
      return v.message || "读不到网关上的连接日志。";
  }
}

/** What the journal covers and does not, where it lives, and what is recorded about names. */
function JournalScope({ scope, names, pending }: { scope: SniffJournalScope; names: boolean; pending: boolean }) {
  return (
    <div data-testid="sniff-journal-scope" className="sniff-coverage">
      <div className="sniff-coverage-col">
        <Typography.Text strong>记录什么</Typography.Text>
        <ul className="plain-list">
          {(scope.covered ?? []).map((x) => (
            <li key={x}>{x}</li>
          ))}
        </ul>
      </div>
      <div className="sniff-coverage-col" data-testid="sniff-journal-legend">
        <Typography.Text strong>结果怎么算</Typography.Text>
        <ul className="plain-list">
          {(scope.results ?? []).map((x) => (
            <li key={x}>{x}</li>
          ))}
        </ul>
      </div>
      <div className="sniff-coverage-col">
        <Typography.Text strong>什么时候记录</Typography.Text>
        <ul className="plain-list">
          {(scope.lifecycle ?? []).map((x) => (
            <li key={x}>{x}</li>
          ))}
        </ul>
      </div>
      <div className="sniff-coverage-col">
        <Typography.Text strong>名字</Typography.Text>
        <ul className="plain-list">
          {(names ? scope.names_on : scope.names_off).map((x) => (
            <li key={x}>{x}</li>
          ))}
          {pending ? <li>名字记录的设置已经修改，下次安装到网关后才生效。</li> : null}
        </ul>
      </div>
      <div className="sniff-coverage-col">
        <Typography.Text strong>不在日志里</Typography.Text>
        <ul className="plain-list">
          {scope.not_covered.map((x) => (
            <li key={x}>{x}</li>
          ))}
        </ul>
      </div>
      <div className="sniff-coverage-col">
        <Typography.Text strong>保存在哪里、保留多久</Typography.Text>
        <ul className="plain-list">
          {scope.storage.map((x) => (
            <li key={x}>{x}</li>
          ))}
        </ul>
      </div>
    </div>
  );
}

/** Failures of a device (the forwarder's count; an older forwarder's summary: every class that is a failure). */
function failures(d: SniffDeviceSummary): number {
  if (typeof d.failed === "number") return d.failed;
  return Object.entries(d.by_class ?? {})
    .filter(([k]) => k !== "ok" && !NEUTRAL_CLASSES.has(k))
    .reduce((n, [, x]) => n + x, 0);
}

/** targetText with the topology's group and exit names (ids only when the topology is not loaded). */
const TargetTextCtx = createContext<(t?: string) => string>((t) => targetText(t));
const useTargetText = () => useContext(TargetTextCtx);

function topTargets(m: Record<string, number> | null | undefined, n: number, tt: (t?: string) => string): string {
  return Object.entries(m ?? {})
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, n)
    .map(([k, c]) => `${tt(k)} ${c}`)
    .join(" · ");
}

interface DeviceRow extends SniffDeviceSummary {
  label?: string;
}

/** The device list: one row per LAN address with its summary and label. */
function DeviceList({ rows, onOpen }: { rows: DeviceRow[]; onOpen: (d: string) => void }) {
  const tt = useTargetText();
  return (
    <DataTable<DeviceRow>
      size="small"
      rowKey={(r) => r.device}
      dataSource={rows}
      pageSize={20}
      secondary={(r) => (
        <Facts
          items={[
            ["首次 / 最近", <span key="t"><TimeText value={r.first_seen} /> / <TimeText value={r.last_seen} /></span>],
            ["主要去向", topTargets(r.by_target, 8, tt) || "—"],
          ]}
        />
      )}
      columns={[
        {
          title: "设备",
          kind: "flex",
          width: 220,
          card: "title",
          render: (_, r) => (
            <span className="inline-status">
              {r.label ? <Typography.Text strong>{r.label}</Typography.Text> : null}
              <EllipsisText mono text={r.device} />
              {r.mac ? <Typography.Text type="secondary" style={{ fontSize: 12 }}>{r.mac}</Typography.Text> : null}
            </span>
          ),
        },
        { title: "最近", kind: "fixed", width: 100, render: (_, r) => <TimeText value={r.last_seen} /> },
        {
          title: "连接",
          kind: "fixed",
          width: 90,
          render: (_, r) => (
            <span>
              {r.total}
              {r.active ? (
                <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                  {" "}
                  +{r.active} 转发中
                </Typography.Text>
              ) : null}
            </span>
          ),
        },
        {
          title: "失败",
          kind: "fixed",
          width: 70,
          render: (_, r) => (failures(r) > 0 ? <Typography.Text type="warning">{failures(r)}</Typography.Text> : 0),
        },
        {
          title: "",
          kind: "actions",
          width: 90,
          render: (_, r) => (
            <Button size="small" onClick={() => onOpen(r.device)} aria-label={`查看 ${r.label ?? r.device} 的连接`}>
              查看
            </Button>
          ),
        },
      ]}
    />
  );
}

const RANGES: { value: string; label: string; hours: number }[] = [
  { value: "all", label: "全部（最近 24 小时）", hours: 0 },
  { value: "1h", label: "最近 1 小时", hours: 1 },
  { value: "6h", label: "最近 6 小时", hours: 6 },
];

/** How the record was decided, in one cell: by name (with the name when recorded) or by address and why. */
function decidedBy(r: SniffRecord, names: boolean) {
  const name = names ? (r.name ? <EllipsisText className="sniff-name" mono text={r.name} /> : null) : <Typography.Text type="secondary">未记录名字</Typography.Text>;
  if (r.sniffed)
    return (
      <span className="inline-status sniff-why">
        <span>按名字</span>
        {name}
        {r.why === "ech_outer" ? <span className="muted">ECH 明文名</span> : null}
      </span>
    );
  return (
    <Space size={2} wrap>
      <span className="muted">按地址</span>
      <Typography.Text type="secondary" style={{ fontSize: 12 }}>
        {SNIFF_WHY[r.why ?? ""] ?? r.why ?? "—"}
      </Typography.Text>
      {names && r.name ? <EllipsisText className="sniff-name" mono text={r.name} /> : null}
    </Space>
  );
}

/** The link from a connection to the queries the same device made around its start. */
function QueriesLink({ r }: { r: SniffRecord }) {
  return (
    <span data-testid="conn-related-link">
      <Link to={relatedHref("dns-log", { device: r.source, at: r.start, mac: r.mac })}>查看这台设备在这条连接前后的解析记录</Link>{" "}
      <Typography.Text type="secondary" style={{ fontSize: 12 }}>
        {r.mac ? "按地址和 MAC 在解析日志里查找（有界时间窗）" : "这条连接没有 MAC：只能按地址和时间查找，不能确认是同一台设备"}
      </Typography.Text>
    </span>
  );
}

function recordDetails(r: SniffRecord, tt: (t?: string) => string): FactItem[] {
  const items: FactItem[] = [
    ["来源", <Mono key="s">{r.mac ? `${r.source}（${r.mac}）` : r.source}</Mono>],
    [r.result === "dial_failed" ? "最后尝试的地址" : "实际连接", r.upstream ? <Mono key="u">{r.upstream}</Mono> : "—"],
    ["协议 / 规则", `${r.proto || "—"} · ${r.rule_id ? r.rule_id : r.rule_index < 0 ? "名单 / 默认组" : "—"}`],
    ["判断耗时", `${r.decide_ms ?? "—"} 毫秒`],
    [r.result === "active" ? "已持续" : "时长", durationText(r.duration_ms)],
    ["字节（发 / 收）", r.bytes_up || r.bytes_down ? `${bytes(r.bytes_up ?? 0)} / ${bytes(r.bytes_down ?? 0)}` : "0 / 0"],
    ["规则代", String(r.generation ?? "—")],
  ];
  if (r.end) items.push(["结束方式", SNIFF_END[r.end] ?? r.end]);
  if (r.reason) items.push(["失败原因", <Mono key="r">{reasonText(r.reason)}</Mono>]);
  if (r.error) items.push(["解析 / 标记原因", <Mono key="e">{r.error}</Mono>]);
  if (r.name_rule)
    items.push([
      "名字的判断",
      `${r.name_rule.rule_id ?? (r.name_rule.rule_index < 0 ? "名单 / 默认组" : "")} → ${tt(r.name_rule.target)}（${NAME_ERROR[r.name_rule.error ?? ""] ?? r.name_rule.error ?? ""}，未采用，已按地址处理）`,
    ]);
  if (r.mark_status)
    items.push([
      "套接字标记",
      <Mono key="m">{`${SNIFF_MARK[r.mark_status] ?? r.mark_status}${r.raw_mark ? ` ${r.raw_mark}` : ""}${r.view === "own_address_view" ? "；已拒绝，规则和目标栏是转发服务自己的地址判断（未采用）" : ""}`}</Mono>,
    ]);
  if (r.source && r.start) items.push(["解析日志", <QueriesLink key="q" r={r} />, "stacked"]);
  return items;
}

/** The columns of a table of finished connections (a device's page, and the connections around a query). */
function recordColumns(names: boolean, tt: (t?: string) => string): DataColumn<SniffJournalRecord>[] {
  return [
    { title: "开始", kind: "fixed", width: 90, render: (_, r) => <TimeText value={r.start} /> },
    { title: "目的地址", kind: "ellipsis", width: 140, mono: true, card: "title", dataIndex: "dest" },
    { title: "判断依据", kind: "flex", width: 190, render: (_, r) => decidedBy(r, names) },
    { title: "去向", kind: "ellipsis", width: 120, render: (_, r) => tt(r.target) },
    { title: "结果", kind: "flex", width: 170, render: (_, r) => <ResultCell r={r} /> },
  ];
}

/** The connections around a query: each row shows the MAC it carries, or that it matched by address only. */
function RelatedConnections({ records, names }: { records: SniffJournalRecord[]; names: boolean }) {
  const tt = useTargetText();
  const [start, dest, decided, target, result] = recordColumns(names, tt);
  return (
    <DataTable<SniffJournalRecord>
      size="small"
      rowKey={(r) => String(r.id)}
      dataSource={records}
      pageSize={50}
      secondary={(r) => <Facts items={recordDetails(r, tt)} />}
      columns={[
        start,
        dest,
        { title: "MAC", kind: "fixed", width: 150, render: (_, r) => (r.mac ? <Mono>{r.mac}</Mono> : <StatusTag kind="attention">无 MAC · 仅按地址</StatusTag>) },
        decided,
        target,
        result,
      ]}
    />
  );
}

function UncleanStop({ stats }: { stats?: SniffJournalStats }) {
  const previous = stats?.unclean_stop;
  if (!previous) return null;
  return <Alert type="warning" showIcon data-testid="sniff-journal-unclean" message={<span>
    嗅探服务上一次没有正常退出（被强行终止、崩溃或断电；最后确认运行于 <TimeText value={previous.last_alive} />
    ）：当时仍打开的{previous.active >= 0 ? ` ${previous.active} 条` : ""}连接没有记录。清空日志后不再提示。
  </span>} />;
}

/** One device: its label, summary, and filterable, paged records. */
function DeviceDetail({
  device,
  summary,
  label,
  hostname,
  names: initialNames,
  onBack,
  onLabel,
  refreshKey,
}: {
  device: string;
  summary?: SniffDeviceSummary;
  label?: string;
  hostname?: string;
  names: boolean;
  onBack: () => void;
  onLabel: () => void;
  refreshKey?: number;
}) {
  const tt = useTargetText();
  const [target, setTarget] = useState("");
  const [result, setResult] = useState("");
  const [range, setRange] = useState("all");
  const [search, setSearch] = useState("");
  const [source, setSource] = useState("");
  const [live, setLive] = useState(true);
  const [cursors, setCursors] = useState<number[]>([]);
  const before = cursors.length > 0 ? cursors[cursors.length - 1] : 0;
  const query: SniffJournalQuery = useMemo(() => {
    const h = RANGES.find((x) => x.value === range)?.hours ?? 0;
    return {
      device: device || source || undefined,
      target: target || undefined,
      result: result || undefined,
      from: sinceHours(h),
      text: search.trim() || undefined,
      before: before || undefined,
      limit: 50,
      page_only: true,
    };
  }, [device, source, target, result, range, search, before]);
  const st = useApi(async () => {
    const hours = RANGES.find(x => x.value === range)?.hours ?? 0;
    const requestQuery = live && !before ? { ...query, from: sinceHours(hours) } : query;
    try {
      return await api.getSniffJournal(requestQuery);
    } catch (error) {
      if (!(error instanceof api.ApiError) || error.status !== 400) throw error;
      const { page_only: _, ...legacy } = requestQuery;
      return api.getSniffJournal(legacy);
    }
  }, [JSON.stringify(query), refreshKey]);
  const liveOnPage = live && !before;
  const [liveStatus, setLiveStatus] = useState<"connecting" | "ready" | "retrying">("connecting");
  useEffect(() => {
    if (!liveOnPage) return;
    let session: AbortController | undefined;
    const start = () => {
      session?.abort();
      if (document.hidden) {
        setLiveStatus("connecting");
        return;
      }
      session = new AbortController();
      const { signal } = session;
      setLiveStatus("connecting");
      async function follow() {
        let revision = "";
        while (!signal.aborted) {
          try {
            const update = await api.waitForSniffJournalChange(revision, signal);
            if (signal.aborted) return;
            if (!update.revision) throw new Error("Missing journal revision");
            setLiveStatus("ready");
            if (update.revision === revision) continue;
            revision = update.revision;
            await st.reload(true);
          } catch {
            if (signal.aborted) return;
            setLiveStatus("retrying");
            revision = "";
          }
          // Bound page reads when many connections change in a burst.
          await new Promise(resolve => window.setTimeout(resolve, revision ? 1000 : 2000));
        }
      }
      void follow();
    };
    start();
    document.addEventListener("visibilitychange", start);
    return () => {
      session?.abort();
      document.removeEventListener("visibilitychange", start);
    };
  }, [liveOnPage, st.reload]);
  const liveButton = <Button size="small" aria-pressed={live} onClick={() => setLive(on => !on)}>
    {!live ? "开启实时刷新" : !liveOnPage ? "实时刷新已暂停" : liveStatus === "retrying" ? "实时刷新重连中 · 暂停" :
      liveStatus === "connecting" ? "实时刷新连接中 · 暂停" : "暂停实时刷新"}
  </Button>;
  const page = st.data?.page;
  const names = page?.record_names ?? initialNames;
  const records = page?.records ?? [];
  const resetPaging = () => setCursors([]);
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(label ?? "");
  const [labelErr, setLabelErr] = useState<api.ApiError | null>(null);
  useEffect(() => setDraft(label ?? ""), [label]);
  const saveLabel = async (remove: boolean) => {
    setLabelErr(null);
    try {
      if (remove) await api.deleteSniffDeviceLabel(device);
      else await api.putSniffDeviceLabel(device, draft.trim());
      onLabel();
      setEditing(false);
    } catch (e) {
      setLabelErr(e instanceof api.ApiError ? e : new api.ApiError(0, {}));
    }
  };
  const problem = st.data ? journalProblem(st.data) : null;
  const needsStatus = !device && st.data?.code === "no_socket";
  const runtime = useApi(() => needsStatus ? api.getSniff() : Promise.resolve(undefined), [needsStatus]);
  const labels = new Map((st.data?.labels ?? []).map(item => [item.address, item.label]));
  const displayName = (address: string) => labels.get(address) || st.data?.device_names?.[address];
  const deviceName = label || st.data?.device_names?.[device] || hostname;
  if (st.data && !device && (!st.data.available || (page?.stats.records === 0 && !page.active?.length))) {
    return <>
      <NamesLine names={names} setting={st.data.record_names} known={!!page} />
      {needsStatus && runtime.loading ? <Skeleton active /> : <JournalEmpty v={st.data} sniff={runtime.data} />}
      <Space><Button size="small" onClick={() => void st.reload()}>刷新</Button>{liveButton}</Space>
    </>;
  }
  function sourceColumn<R extends SniffRecord>(): DataColumn<R> {
    return {
      title: "来源", kind: "ellipsis", width: 126,
      render: (_, row) => <Button type="link" size="small" onClick={() => { setSource(row.source); resetPaging(); }}
        aria-label={`筛选来源 ${row.source}`} title={row.source} style={{ paddingInline: 0, maxWidth: "100%" }}><EllipsisText text={displayName(row.source) || row.source} /></Button>,
    };
  }
  return (
    <Space direction="vertical" style={{ width: "100%" }} data-testid="sniff-device" className="sniff-device">
      {!device && st.data ? <NamesLine names={names} setting={st.data.record_names} known={!!page} /> : null}
      {!device ? <UncleanStop stats={page?.stats} /> : null}
      {device ? <div className="log-device-head">
        <Button size="small" onClick={onBack}>
          ← 全部设备
        </Button>
        <Typography.Text strong>{deviceName || device}</Typography.Text>
        {deviceName ? <Mono>{device}</Mono> : null}
        {summary?.mac ? <Typography.Text type="secondary">MAC {summary.mac}</Typography.Text> : null}
        <Button size="small" type="text" aria-expanded={editing} onClick={() => setEditing(!editing)}>
          {label ? "改备注" : "加备注"}
        </Button>
      </div> : null}
      {editing ? (
        <Space wrap>
          <Input
            value={draft}
            maxLength={64}
            onChange={(e) => setDraft(e.target.value)}
            placeholder="备注名（只保存在面板里，与解析日志共用）"
            aria-label="设备备注名"
            className="input-w200"
          />
          <Button size="small" type="primary" onClick={() => void saveLabel(false)} disabled={!draft.trim() || draft.trim() === label}>
            保存备注
          </Button>
          {label ? (
            <Button size="small" onClick={() => void saveLabel(true)}>
              删除备注
            </Button>
          ) : null}
        </Space>
      ) : null}
      {labelErr ? <ApiErrorAlert error={labelErr} /> : null}
      {summary ? (
        <details className="log-details" data-testid="sniff-device-summary">
          <summary>
            {summary.total} 条连接 · 失败 {failures(summary)}
            {summary.active ? ` · 正在转发 ${summary.active}` : ""} · {bytes(summary.bytes_up ?? 0)} / {bytes(summary.bytes_down ?? 0)}
          </summary>
          <Facts
            items={[
              ["首次 / 最近", <span key="t"><TimeText value={summary.first_seen} /> / <TimeText value={summary.last_seen} /></span>],
              ["连接", `${summary.total}（按名字 ${summary.by_name} · 按地址 ${summary.by_address}${summary.name_unresolved ? ` · 名字解析不到 ${summary.name_unresolved}` : ""}）`],
              [
                "结果",
                <Space key="c" size={4} wrap>
                  {Object.entries(summary.by_class ?? {}).map(([k, n]) => (
                    <Tag key={k} color={k === "ok" || NEUTRAL_CLASSES.has(k) ? undefined : "orange"}>
                      {JOURNAL_CLASS[k] ?? k} {n}
                    </Tag>
                  ))}
                </Space>,
              ],
              ...(Object.keys(summary.by_end ?? {}).length > 0
                ? ([
                    [
                      "转发结束方式",
                      Object.entries(summary.by_end ?? {})
                        .sort((a, b) => b[1] - a[1])
                        .map(([k, n]) => `${SNIFF_END[k] ?? k} ${n}`)
                        .join(" · "),
                    ],
                  ] as FactItem[])
                : []),
              ["去向", topTargets(summary.by_target, 8, tt) + (summary.other_targets ? ` · 其它 ${summary.other_targets}` : "")],
            ]}
          />
        </details>
      ) : null}
      {source ? <Space wrap><Typography.Text strong>来源 {displayName(source) ? `${displayName(source)}（${source}）` : source}</Typography.Text><Button size="small" onClick={() => { setSource(""); resetPaging(); }}>清除来源筛选</Button></Space> : null}
      <LogToolbar
        testId="sniff-journal-filters"
        onRefresh={() => void st.reload()}
        stats={liveButton}
        filters={
          <>
            <Select
              aria-label="去向"
              value={target}
              onChange={(v) => {
                setTarget(v);
                resetPaging();
              }}
              className="input-w200"
              options={[{ value: "", label: "全部去向" }, ...Object.keys(summary?.by_target ?? {}).sort().map((k) => ({ value: k, label: tt(k) }))]}
            />
            <Select
              aria-label="结果"
              value={result}
              onChange={(v) => {
                setResult(v);
                resetPaging();
              }}
              className="input-w200"
              options={[{ value: "", label: "全部结果" }, ...Object.entries(JOURNAL_CLASS).map(([value, label]) => ({ value, label }))]}
            />
            <Select
              aria-label="时间"
              value={range}
              onChange={(v) => {
                setRange(v);
                resetPaging();
              }}
              className="input-w200"
              options={RANGES.map(({ value, label }) => ({ value, label }))}
            />
            <SearchInput
              aria-label="按名字搜索"
              value={names ? search : ""}
              disabled={!names}
              placeholder={names ? "名字包含…" : "未记录名字"}
              onSearch={t => {
                setSearch(t);
                setCursors([]);
              }}
              className="input-w200"
            />
          </>
        }
      />
      {st.error ? <ApiErrorAlert error={st.error} /> : null}
      {problem ? (
        <Typography.Text type="warning" data-testid="sniff-device-problem">
          {problem}
        </Typography.Text>
      ) : null}
      <LiveConnections
        initial={page?.active ?? []}
        initialMatched={page?.active_matched}
        device={device || source}
        names={names}
        showSource={!device}
        source={sourceColumn<SniffRecord>()}
        paused={!liveOnPage}
      />
      <DataTable<SniffJournalRecord>
        size="small"
        rowKey={(r) => String(r.id)}
        dataSource={records}
        pageSize={50}
        pagination={false}
        locale={{ emptyText: page ? (page.matched === 0 && (!page.page_only || before === 0) ? "没有符合筛选条件的连接：放宽去向、结果或时间范围" : "这一页没有记录") : "读取中…" }}
        secondary={(r) => <Facts items={recordDetails(r, tt)} />}
        columns={device ? recordColumns(names, tt) : [sourceColumn<SniffJournalRecord>(), ...recordColumns(names, tt)]}
      />
      <LogPager
        cursors={cursors}
        setCursors={setCursors}
        next={st.loading ? undefined : page?.next_before}
        noun="记录"
        matched={
          st.loading ? <span role="status">正在读取连接…</span> : page ? (
            <span data-testid="sniff-journal-matched">
              {page.page_only ? `本页 ${records.length} 条` : `共 ${page.matched} 条已结束的连接符合`}{cursors.length > 0 ? `（第 ${cursors.length + 1} 页）` : ""}
            </span>
          ) : null
        }
      />
    </Space>
  );
}

/** Why there is nothing to list, as an explicit state with the way to get data. */
function JournalEmpty({ v, sniff }: { v: SniffJournalView; sniff: SniffView | undefined }) {
  const deploy = <LinkButton to={href("deploy")}>去部署页安装</LinkButton>;
  if (v.available)
    return (
      <LogEmpty id="conn-log" state="no-data" title="日志里还没有连接">
        嗅探服务在运行，但还没有一条连接结束：设备经网关访问接管端口（默认 80、443）的 TCP 连接，在结束时各记一条；仍在转发的连接结束后才写入。
      </LogEmpty>
    );
  if (sniff && !sniff.setting.enabled && !sniff.runtime.present)
    return (
      <LogEmpty
        id="conn-log"
        state="not-enabled"
        title="按域名嗅探没有开启，所以没有连接日志"
        action={
          <Space wrap>
            <LinkButton to={SNIFF_SETTINGS} type="primary">
              去开启按域名嗅探
            </LinkButton>
            {deploy}
          </Space>
        }
      >
        先开启「按域名嗅探」并安装到网关。
      </LogEmpty>
    );
  if (v.code === "no_journal")
    return (
      <LogEmpty id="conn-log" state="no-journal" title="网关上的嗅探服务没有连接日志（旧版本或日志目录无法打开）" action={deploy}>
        把当前版本安装到网关（部署页：预检 → 确认 → 安装）之后才有连接日志。
      </LogEmpty>
    );
  if (v.code === "no_socket" || (sniff?.setting.enabled && sniff.runtime.available && !sniff.runtime.present))
    return (
      <LogEmpty id="conn-log" state="not-installed" title="嗅探服务没有在网关上运行，读不到连接日志" action={deploy}>
        按域名嗅探已经保存为开启，但网关上没有运行中的嗅探服务：要么还没有安装到网关（部署页：预检 → 确认 → 安装），要么服务停止了——停止期间的连接不会被记录。
      </LogEmpty>
    );
  return (
    <LogEmpty id="conn-log" state="unreadable" title="读不到网关上的连接日志">
      {v.message || "宿主执行通道没有回答。"} 日志在网关本机，面板只能经宿主代理读取；通道恢复后刷新。
    </LogEmpty>
  );
}

/** One line: is the gateway recording names now, a pending change, and where the switch is. */
function NamesLine({ names, setting, known }: { names: boolean; setting: boolean; known: boolean }) {
  const pending = known && names !== setting;
  return (
    <div data-testid="conn-log-names" className="log-names">
      名字记录：
      {known ? (
        names ? (
          <StatusTag kind="attention">网关上已开启</StatusTag>
        ) : (
          <span className="status-text">网关上未开启</span>
        )
      ) : (
        <span className="status-text">{setting ? "已保存为开启（网关上的状态读不到）" : "已保存为关闭（网关上的状态读不到）"}</span>
      )}
      {pending ? <Typography.Text type="warning">设置已改为{setting ? "开启" : "关闭"}，下次安装到网关后才生效。</Typography.Text> : null}{" "}
      <Link to={SNIFF_SETTINGS}>去修改名字记录的设置</Link>
      <Note inline>
        {known && names ? "每条记录还保存嗅探读到的名字（TLS 的 SNI、HTTP 的 Host）。" : "默认不记录名字：记录里只有地址、端口、去向和结果，名字属于敏感信息。"}
        开关在分流规则页的「按域名嗅探」里，保存后经预检、确认、安装生效。
      </Note>
    </div>
  );
}

export default function ConnectionLogsPage() {
  const { route, navigate } = useRouter();
  const related = relatedOf(route.query);
  const linked = related ? "" : (route.query.get("device") ?? "");
  const { message } = AntApp.useApp();
  const [view, setView] = useState<"recent" | "devices">(linked || related || route.query.get("view") === "devices" ? "devices" : "recent");
  const st = useApi(() => view === "devices" ? api.getSniffDevices() : Promise.resolve(undefined), [view]);
  const [refreshKey, setRefreshKey] = useState(0);
  const [disconnecting, setDisconnecting] = useState(false);
  const [disconnectError, setDisconnectError] = useState<api.ApiError | null>(null);
  const unavailable = st.data != null && !st.data.available;
  const sniff = useApi(() => unavailable ? api.getSniff() : Promise.resolve(undefined), [unavailable]);
  const [device, setDevice] = useState<string | null>(linked || null);
  useEffect(() => {
    if (linked) { setView("devices"); setDevice(linked); }
  }, [linked]);
  const [clearErr, setClearErr] = useState<api.ApiError | null>(null);
  const confirm = useConfirmDanger();
  const topo = useTopologyDocIfLoaded()?.topo;
  const tt = useMemo(() => {
    const groups = new Map((topo?.region_groups ?? []).map((g) => [g.id, g.name]));
    const exits = new Map((topo?.nodes ?? []).map((n) => [n.id, n.name]));
    return (t?: string) => targetText(t, (kind, id) => (kind === "group" ? groups : exits).get(id));
  }, [topo]);
  const v = st.data;
  const sum = v?.summary;
  const names = sum?.record_names ?? false;
  const labels = new Map((v?.labels ?? []).map((l: SniffDeviceLabel) => [l.address, l.label]));
  const rows: DeviceRow[] = (sum?.devices ?? []).map((d) => ({ ...d, label: labels.get(d.device) || v?.device_names?.[d.device] }));
  const stats = sum?.stats;
  const clear = () =>
    confirm({
      title: "清空设备连接日志",
      consequence: `立即删除网关上全部 ${stats?.records ?? ""} 条连接记录（所有设备${names ? "，包括记录下的名字" : ""}），不能恢复；之后的新连接照常记录。设备备注名保留在面板里。`,
      okText: "清空",
      onOk: async () => {
        setClearErr(null);
        try {
          await api.clearSniffJournal();
          message.success("连接日志已清空");
          setDevice(null);
          await st.reload();
        } catch (e) {
          setClearErr(e instanceof api.ApiError ? e : new api.ApiError(0, {}));
        }
      },
    });
  const disconnect = () => confirm({
    title: "断开所有连接？",
    consequence: "立即关闭网关嗅探服务当前正在转发的 TCP 连接。历史日志保留，设备可以重新连接。",
    okText: "断开所有连接",
    onOk: async () => {
      setDisconnectError(null);
      setDisconnecting(true);
      try {
        const result = await api.disconnectSniffConnections();
        message.success(`已断开 ${result.disconnected} 条连接`);
        setRefreshKey(key => key + 1);
        if (view === "devices") void st.reload();
      } catch (error) {
        setDisconnectError(error instanceof api.ApiError ? error : new api.ApiError(0, {}));
      } finally {
        setDisconnecting(false);
      }
    },
  });
  const keep: ReactNode = stats
    ? `最近 ${ageText(stats.max_age_s)}、最多 ${stats.max_records} 条、不超过 ${bytes(stats.max_bytes)}，先到的上限生效，超出时删最旧的。`
    : "最近 24 小时、最多 50000 条、不超过 32 MiB，先到的上限生效，超出时删最旧的。";
  return (
    <Page title="连接日志" extra={<Button danger loading={disconnecting} onClick={disconnect}>断开所有连接</Button>}>
      <TargetTextCtx.Provider value={tt}>
      <div data-testid="sniff-journal" className="sniff-journal">
        <Help title="记录范围与保存说明">
          <LogIntro
            id="conn-log"
            records="网关上的嗅探转发服务经手的每一条 TCP 连接（发往接管端口，默认 80、443），在连接结束时记一条：时间、设备地址（能取到时带 MAC）、目的地址、去向、结果和字节数。"
            excludes="UDP（含 QUIC）、其它端口、嗅探关闭期间的流量和 DNS 查询（后者见「解析日志」）；连接里的名字（SNI / Host）默认不保存，只有明确打开名字记录才保存；内容本身从不记录。"
            keep={keep}
            where="只在网关本机的 /var/lib/meridian-sniff，不进入拓扑、快照、导出或面板自己的日志。"
            who="网关上的 root 和嗅探服务；面板只经宿主代理的固定只读请求读取，持有面板口令的人能在这一页看到。"
          />
        </Help>
        {v ? (
          <Help title="记录范围与保存">
            <JournalScope scope={v.scope} names={names} pending={!!sum && sum.record_names !== v.record_names} />
          </Help>
        ) : null}
        {related ? (
          <Section title="来自解析日志的跳转">
            <RelatedPanel<SniffJournalRecord>
              id="conn-log"
              query={related}
              load={api.getDNSLogRelated}
              what="连接"
              source="解析记录"
              onClose={() => navigate(href("conn-log"))}
            >
              {(rv) => <RelatedConnections records={rv.records ?? []} names={rv.record_names ?? false} />}
            </RelatedPanel>
          </Section>
        ) : null}
        <Space wrap style={{ marginBottom: 12 }}>
          <Button type={view === "recent" ? "primary" : "default"} aria-pressed={view === "recent"} onClick={() => setView("recent")}>最近连接</Button>
          <Button type={view === "devices" ? "primary" : "default"} aria-pressed={view === "devices"} onClick={() => setView("devices")}>按设备查看</Button>
        </Space>
        {disconnectError ? <ApiErrorAlert error={disconnectError} /> : null}
        {view === "recent" ? (
          <Section title="全部设备的连接">
            <DeviceDetail device="" names={false} onBack={() => setView("devices")} onLabel={() => {}} refreshKey={refreshKey} />
          </Section>
        ) : <Section
          title={device ? "连接记录" : "设备"}
          extra={
            <LogToolbar
              stats={stats ? <LogStats count={stats.records} used={stats.bytes} max={stats.max_bytes} oldest={stats.oldest} extra={[stats.dropped > 0 && `写不过来丢弃 ${stats.dropped} 条`]} /> : null}
              onRefresh={() => void st.reload()}
              onClear={clear}
              clearLabel="清空日志"
              clearDisabled={!v?.available}
            />
          }
        >
          <Space direction="vertical" style={{ width: "100%" }}>
            {v ? <NamesLine names={names} setting={v.record_names} known={!!sum} /> : null}
            {st.error ? <ApiErrorAlert error={st.error} onRetry={() => void st.reload()} /> : null}
            {clearErr ? <ApiErrorAlert error={clearErr} /> : null}
            <UncleanStop stats={stats} />
            {sum?.truncated ? <Note inline>设备太多，只列出最近出现的 {rows.length} 个。</Note> : null}
            {!v ? (
              st.error ? null : (
                <Skeleton active paragraph={{ rows: 4 }} />
              )
            ) : device ? (
              <DeviceDetail
                key={device}
                refreshKey={refreshKey}
                device={device}
                summary={sum?.devices?.find((d) => d.device === device)}
                label={labels.get(device)}
                hostname={v.device_names?.[device]}
                names={names}
                onBack={() => {
                  setDevice(null);
                  if (linked) navigate(href("conn-log"));
                }}
                onLabel={() => void st.reload()}
              />
            ) : v.available && rows.length > 0 ? (
              <DeviceList rows={rows} onOpen={setDevice} />
            ) : !v.available && !sniff.data && !sniff.error ? (
              // Which empty state applies depends on whether sniffing is enabled: wait for that answer.
              <Skeleton active paragraph={{ rows: 2 }} />
            ) : (
              <JournalEmpty v={v} sniff={sniff.data} />
            )}
          </Space>
        </Section>}
      </div>
      </TargetTextCtx.Provider>
    </Page>
  );
}

/** Bytes per second as text (metacubexd style). */
function rate(n: number) {
  return `${bytes(Math.max(0, Math.round(n)))}/s`;
}

type LiveRow = SniffRecord & { up_rate: number; down_rate: number };
type LiveSort = "down_rate" | "up_rate" | "bytes_down" | "bytes_up" | "start";
const LIVE_SORTS: { value: LiveSort; label: string }[] = [
  { value: "down_rate", label: "按下载速度" },
  { value: "up_rate", label: "按上传速度" },
  { value: "bytes_down", label: "按下载总量" },
  { value: "bytes_up", label: "按上传总量" },
  { value: "start", label: "按开始时间" },
];

/**
 * The connections being relayed, refreshed every second while the page is
 * visible: each row's upload and download speed is the change of its byte
 * counters since the previous read (keyed by the forwarder's conn number).
 */
function LiveConnections({ initial, initialMatched, device, names, showSource, source, paused }: {
  /** Follows the page's live switch (one pause for the whole page). */
  paused: boolean;
  initial: SniffRecord[];
  initialMatched?: number;
  device: string;
  names: boolean;
  showSource: boolean;
  source: DataColumn<SniffRecord>;
}) {
  const tt = useTargetText();
  const [rows, setRows] = useState<LiveRow[]>(() => initial.map(r => ({ ...r, up_rate: 0, down_rate: 0 })));
  const [matched, setMatched] = useState(initialMatched ?? initial.length);
  const [sort, setSort] = useState<LiveSort>("down_rate");
  useEffect(() => {
    setRows(initial.map(r => ({ ...r, up_rate: 0, down_rate: 0 })));
    setMatched(initialMatched ?? initial.length);
  }, [device]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => {
    if (paused) return;
    let prev = new Map<string, { up: number; down: number; at: number }>();
    let stopped = false;
    let timer = 0;
    const key = (r: SniffRecord) => `${r.conn ?? ""}|${r.start}|${r.source}`;
    const tick = async () => {
      if (!document.hidden) {
        try {
          const v = await api.getSniffJournal({ device: device || undefined, limit: 1, page_only: true });
          if (stopped) return;
          const at = performance.now();
          const next = new Map<string, { up: number; down: number; at: number }>();
          const list = (v.page?.active ?? []).map(r => {
            const k = key(r);
            const up = r.bytes_up ?? 0, down = r.bytes_down ?? 0;
            const p = prev.get(k);
            next.set(k, { up, down, at });
            const dt = p ? (at - p.at) / 1000 : 0;
            return { ...r, up_rate: p && dt > 0 ? (up - p.up) / dt : 0, down_rate: p && dt > 0 ? (down - p.down) / dt : 0 };
          });
          prev = next;
          setRows(list);
          setMatched(v.page?.active_matched ?? list.length);
        } catch {
          // keep the last rows; the next tick retries
        }
      }
      if (!stopped) timer = window.setTimeout(tick, 1000);
    };
    void tick();
    return () => {
      stopped = true;
      window.clearTimeout(timer);
    };
  }, [paused, device]);
  const sorted = useMemo(() => {
    const out = [...rows];
    out.sort((a, b) => sort === "start" ? b.start.localeCompare(a.start) : (Number(b[sort] ?? 0) - Number(a[sort] ?? 0)));
    return out;
  }, [rows, sort]);
  if (rows.length === 0) return null;
  const upRate = rows.reduce((n, r) => n + r.up_rate, 0);
  const downRate = rows.reduce((n, r) => n + r.down_rate, 0);
  return (
    <div data-testid="sniff-journal-active">
      <Space wrap style={{ marginBottom: 8 }}>
        <Typography.Text strong>
          正在转发 {matched}
          {matched > rows.length ? `（列出最新的 ${rows.length} 条）` : ""}
        </Typography.Text>
        <Typography.Text data-testid="sniff-live-rate">↑ {rate(upRate)} · ↓ {rate(downRate)}</Typography.Text>
        <Select size="small" aria-label="活动连接排序" value={sort} onChange={setSort} options={LIVE_SORTS} className="input-w200" />
        {paused ? <Typography.Text type="secondary">实时刷新已暂停</Typography.Text> : null}
      </Space>
      <DataTable<LiveRow>
        size="small"
        rowKey={(r) => `a${r.conn ?? r.start + r.dest}`}
        dataSource={sorted}
        pageSize={50}
        pagination={false}
        secondary={(r) => <Facts items={[["判断依据", decidedBy(r, names)], ...recordDetails(r, tt)]} />}
        columns={[
          ...(showSource ? [source as unknown as DataColumn<LiveRow>] : []),
          { title: "主机", kind: "flex", width: 220, card: "title", render: (_, r) => <EllipsisText text={(names && r.name) || r.dest} /> },
          { title: "去向", kind: "ellipsis", width: 120, render: (_, r) => tt(r.target) },
          { title: "↑ 速度", kind: "fixed", width: 96, render: (_, r) => <Mono>{rate(r.up_rate)}</Mono> },
          { title: "↓ 速度", kind: "fixed", width: 96, render: (_, r) => <Mono>{rate(r.down_rate)}</Mono> },
          { title: "↑ 总量", kind: "fixed", width: 88, render: (_, r) => bytes(r.bytes_up ?? 0) },
          { title: "↓ 总量", kind: "fixed", width: 88, render: (_, r) => bytes(r.bytes_down ?? 0) },
          { title: "已持续", kind: "fixed", width: 84, render: (_, r) => durationText(r.duration_ms) },
        ]}
      />
    </div>
  );
}
