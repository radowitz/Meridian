import {
  Help,
  Note,
  StatusTag,
} from "./ui";
import { MeshLegQuality } from "./MeshLegQuality";
// 链路日志 (#/link-log): state changes of the gateway's paths and links
// (internal/api/link_journal.go), recorded by a collector on the gateway
// that is part of every gateway install.
//
// On top the state now: which path carries, every object that is abnormal
// (for how long, on what evidence), objects whose state is unknown (not
// read for longer than the gap threshold) and objects that are flapping.
// Then the scope: what is observed, from which source and how strong the
// evidence is, and what is NOT in scope (e.g. the external-exit health
// check on the carrying node). Then the timeline with filters (object,
// class, time range), cursor paging and the confirmed "clear".
//
// Events are rendered as what they are:
//   - a collection gap (class "collector", from "unknown") is "nothing was
//     collected from … to …", never a state of a link;
//   - a duration whose start is not known (the state was there at the first
//     reading, or it ended inside a gap) is "at least N";
//   - a change found after a gap says that its time inside the gap is not
//     known;
//   - a merged record (changes > 1) is "changed N times between … and …",
//     never one continuous outage.
//
// When the collector is not installed yet (after an upgrade the gateway has
// a pending install) or not running, the page says so and how to get it.

import { App as AntApp, Button, Select, Skeleton, Space, Tag, Typography } from "antd";
import { useMemo, useState } from "react";
import * as api from "./api";
import { LogEmpty, LogIntro, LogPager, LogStats, LogToolbar, ScopeLists, absTime, ageText, sinceHours, spanText } from "./log_common";
import { href, useTopologyDoc } from "./state";
import type { LinkLogEvent, LinkLogKind, LinkLogObjectState, LinkLogQuery, LinkLogSource, LinkLogStats, LinkLogSummary, LinkLogView } from "./types";
import { ApiErrorAlert, DataTable, Facts, LinkButton, Mono, Page, Section, TimeText, bytes, useApi, useConfirmDanger, type FactItem } from "./ui";

/** Class names when the API's source inventory does not name one. */
const CLASS_LABEL: Record<string, string> = {
  path: "承载路径",
  relay: "中继分担",
  tunnel: "隧道握手",
  wss: "WSS 伴随承载",
  external_exit: "外部出口",
  sniff_target: "嗅探自检目标",
  collector: "采集本身",
};

/** How strong a source's evidence is. */
export const STRENGTH: Record<string, { label: string; color?: string }> = {
  direct: { label: "直接读到", color: "blue" },
  probe: { label: "网关自己的探测" },
  indirect: { label: "间接推断", color: "orange" },
};


interface Words {
  kinds: LinkLogKind[];
  sources: LinkLogSource[];
}

function classLabel(c: string, w: Words): string {
  return CLASS_LABEL[c] ?? w.sources.find((s) => s.class === c)?.class_label ?? c;
}

/** A state in words, with its level. A state of an open kind that is not listed is a topology name. */
function stateOf(kind: string, state: string, w: Words): { label: string; level: string } {
  const s = w.kinds.find((k) => k.kind === kind)?.states.find((x) => x.state === state);
  return s ? { label: s.label, level: s.level } : { label: state || "—", level: "info" };
}

/**
 * A state in words, coloured by its level. Text, not a tag: the labels are
 * phrases ("客户端在运行，但里面的隧道握手超时") and must wrap inside a cell or
 * a phone card, which a tag never does.
 */
function StateText({ kind, state, w }: { kind: string; state: string; w: Words }) {
  const s = stateOf(kind, state, w);
  return (
    <span className={`link-state link-state-${s.level}`} data-level={s.level} title={s.label !== state ? state : undefined}>
      {s.label}
    </span>
  );
}

function strengthOf(source: string | undefined, cls: string, w: Words) {
  const row = w.sources.find((s) => s.source === source && s.class === cls) ?? w.sources.find((s) => s.class === cls);
  return row ? STRENGTH[row.strength] ?? { label: row.strength } : null;
}

function objectName(o: { label?: string; kind: string; id: string }): string {
  return o.label || `${o.kind} ${o.id}`;
}

/** How long an object has been in its state: "at least" when the start is not known. */
function sinceText(o: LinkLogObjectState): string {
  return o.since_open ? `至少 ${spanText(o.for_s)}（开始的时间不确定：第一次读到或空窗之后就已如此）` : `已持续 ${spanText(o.for_s)}`;
}

function ObjectFacts({ o, w }: { o: LinkLogObjectState; w: Words }) {
  const st = strengthOf(o.source, o.class, w);
  const items: FactItem[] = [
    ["状态", <StateText key="s" kind={o.kind} state={o.state} w={w} />],
    ["持续", `${sinceText(o)}，自 ${absTime(o.since)} 起读到`],
  ];
  if (o.evidence || o.reason) items.push(["依据", `${o.evidence ?? ""}${o.reason ? `${o.evidence ? "；" : ""}原因代码 ${o.reason}` : ""}`, "stacked"]);
  if (st) items.push(["依据的强弱", <Tag key="t" color={st.color}>{st.label}</Tag>]);
  return <Facts items={items} />;
}

// --------------------------------------------------------------- current ---

function Current({ summary, w, gapAfterS, unobserved = [] }: { summary: LinkLogSummary; w: Words; gapAfterS: number; unobserved?: string[] }) {
  const { carrying, health } = summary;
  // A target removed from the active rules keeps its history in the ledger,
  // but is no longer a current measurement. Do not present that old reading
  // as an unknown current fault; the scope section explains the exclusion.
  const ignored = new Set(unobserved);
  const include = (o: LinkLogObjectState) => !ignored.has(`${o.kind}|${o.id}`);
  const abnormal = summary.abnormal.filter(include);
  const unknown = summary.unknown.filter(include);
  const flapping = summary.flapping.filter(include);
  const inactive = summary.unknown.length - unknown.length;
  return (
    <div data-testid="link-log-current" className="link-current">
      <Note inline>读取于 {absTime(summary.at)}
        {summary.last_pass ? `；采集服务上一次采集于 ${absTime(summary.last_pass)}` : ""}；共 {summary.objects} 个被观测的对象。</Note>
      <div data-testid="link-log-carrying" className="link-block">
        <Typography.Text strong>承载路径（网关的境外流量现在走哪条路）</Typography.Text>
        {carrying ? (
          carrying.stale ? (
            <Typography.Paragraph type="warning" style={{ marginBottom: 0 }}>
              现在未知：超过 {gapAfterS} 秒没有读到承载路径。最后读到的是「{stateOf(carrying.kind, carrying.state, w).label}」（{absTime(carrying.last_seen)}）。
            </Typography.Paragraph>
          ) : (
            <ObjectFacts o={carrying} w={w} />
          )
        ) : (
          <Note>
            还没有读到承载路径。
          </Note>
        )}
        {health && !health.stale ? (
          <div data-testid="link-log-health">
            <Typography.Text type="secondary">故障切换服务上一轮的探测结论：</Typography.Text> <StateText kind={health.kind} state={health.state} w={w} />{" "}
            <Typography.Text type="secondary">
              {sinceText(health)}
              {health.evidence ? `；${health.evidence}` : ""}
            </Typography.Text>
          </div>
        ) : null}
      </div>
      <div data-testid="link-log-abnormal" className="link-block">
        <Typography.Text strong>现在处于异常状态的对象（{abnormal.length}）</Typography.Text>
        {abnormal.length === 0 ? (
          <>
            <div className="state-line">现在没有处于异常状态的对象</div>
            <Note title="异常状态">这只说明网关读到的这些对象；网关读不到的见「说明」里的「不在记录范围内」。</Note>
          </>
        ) : (
          <DataTable<LinkLogObjectState>
            size="small"
            rowKey={(o) => `${o.kind}|${o.id}`}
            dataSource={abnormal}
            pageSize={20}
            columns={[
              {
                title: "对象",
                kind: "flex",
                width: 240,
                card: "title",
                render: (_, o) => (
                  <span className="inline-status wrap">
                    <span>{objectName(o)}</span>
                    <span className="muted">{classLabel(o.class, w)}</span>
                  </span>
                ),
              },
              { title: "状态", kind: "flex", width: 200, render: (_, o) => <StateText kind={o.kind} state={o.state} w={w} /> },
              { title: "持续", kind: "flex", width: 170, render: (_, o) => <span data-testid="link-object-for">{sinceText(o)}</span> },
              {
                title: "依据",
                kind: "flex",
                width: 260,
                render: (_, o) => {
                  const st = strengthOf(o.source, o.class, w);
                  return (
                    <span>
                      {st ? <Tag color={st.color}>{st.label}</Tag> : null}
                      {o.evidence || o.reason || "—"}
                    </span>
                  );
                },
              },
            ]}
          />
        )}
      </div>
      {inactive > 0 ? <div data-testid="link-log-inactive-targets"><Typography.Text type="secondary">{inactive} 个历史自检目标已不在当前规则检查范围内，不代表隧道故障；见下方「未观测的对象」。</Typography.Text></div> : null}
      {unknown.length > 0 ? (
        <div data-testid="link-log-unknown" className="link-block">
          <Typography.Text strong>状态未知的对象（{unknown.length}）</Typography.Text>
          <Note inline>超过 {gapAfterS} 秒没有读到：现在的状态不知道，下面只是最后一次读到的。</Note>
          <ul className="plain-list">
            {unknown.map((o) => (
              <li key={`${o.kind}|${o.id}`}>
                {objectName(o)}：<StatusTag kind="attention">现在未知</StatusTag>最后读到「{stateOf(o.kind, o.state, w).label}」，在 {absTime(o.last_seen)}
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      {flapping.length > 0 ? (
        <div data-testid="link-log-flapping" className="link-block">
          <Typography.Text strong>正在抖动的对象（{flapping.length}）</Typography.Text>
          <Note inline>短时间内反复变化，后面的变化被合并成一条记录；这不是一次连续的中断。</Note>
          <ul className="plain-list">
            {flapping.map((o) => (
              <li key={`${o.kind}|${o.id}`}>
                {objectName(o)}：从 {absTime(o.flapping?.first_at)} 到 {absTime(o.flapping?.last_at)} 已变化 {o.flapping?.changes} 次，仍在合并计数；最后读到「{stateOf(o.kind, o.state, w).label}」
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  );
}

// ----------------------------------------------------------------- scope ---

function Scope({ v }: { v: LinkLogView }) {
  const sc = v.scope;
  return (
    <div data-testid="link-log-scope">
      {sc.mode_note ? <Note>{sc.mode_note}</Note> : null}
      {sc.sources.length > 0 ? (
        <DataTable<LinkLogSource>
          size="small"
          rowKey={(s) => `${s.class}|${s.source}|${s.class_label}`}
          dataSource={sc.sources}
          pagination={false}
          secondary={(s) => (
            <Facts
              items={[
                ["怎么读到", s.how, "stacked"],
                ["多久读一次", s.cadence],
              ]}
            />
          )}
          columns={[
            { title: "观测的对象", kind: "flex", width: 150, card: "title", render: (_, s) => s.class_label },
            { title: "记录什么变化", kind: "flex", width: 240, render: (_, s) => s.events },
            {
              title: "依据的强弱",
              kind: "fixed",
              width: 130,
              render: (_, s) => <Tag color={STRENGTH[s.strength]?.color}>{STRENGTH[s.strength]?.label ?? s.strength}</Tag>,
            },
            { title: "能说明什么、不能说明什么", kind: "flex", width: 300, render: (_, s) => s.evidence },
          ]}
        />
      ) : null}
      <div data-testid="link-log-not-in-scope" className="link-block">
        <Typography.Text strong>不在记录范围内</Typography.Text>
        {sc.not_in_scope.length > 0 ? (
          <ul className="plain-list">
            {sc.not_in_scope.map((x) => (
              <li key={x.what}>
                <Typography.Text strong>{x.what}</Typography.Text>：{x.why}
                {x.instead ? `。最接近的记录：${x.instead}` : ""}
              </li>
            ))}
          </ul>
        ) : (
          <Note>
            没有读到范围说明。
          </Note>
        )}
      </div>
      {sc.externals.length > 0 ? (
        <div data-testid="link-log-externals" className="link-block">
          <Typography.Text strong>外部出口</Typography.Text>
          <ul className="plain-list">
            {sc.externals.map((x) => (
              <li key={x.id}>
                {x.id}
                {x.carrier ? `（由 ${x.carrier} 承载）` : ""}：{x.observed ? <span className="muted">有网关自己的检查</span> : <StatusTag kind="attention">网关没有检查，不记录</StatusTag>}
                {x.note}
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      {sc.unobserved.length > 0 ? (
        <div data-testid="link-log-unobserved" className="link-block">
          <Typography.Text strong>列出但不读取的对象</Typography.Text>
          <ul className="plain-list">
            {sc.unobserved.map((o) => (
              <li key={`${o.kind}|${o.id}`}>
                {o.label}：{o.note || "不读取"}
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      <ScopeLists
        lists={[
          ["记录的是什么", sc.notes.records],
          ["保存在哪里、保留多久", sc.notes.storage],
          ["基线、空窗、抖动", sc.notes.rules],
          ["怎么安装", sc.notes.install],
        ]}
      />
    </div>
  );
}

// -------------------------------------------------------------- timeline ---

/** What kind of record an event is, for its rendering. */
export function eventShape(e: LinkLogEvent): "gap" | "config" | "merged" | "after_gap" | "change" {
  if (e.class === "collector" && e.kind === "collector") return "gap";
  if (e.class === "collector" && e.kind === "config") return "config";
  if ((e.changes ?? 0) > 1) return "merged";
  if (e.after_gap) return "after_gap";
  return "change";
}

function EventChange({ e, w }: { e: LinkLogEvent; w: Words }) {
  const shape = eventShape(e);
  if (shape === "gap")
    return (
      <span data-testid="link-event" data-shape="gap">
        <StatusTag kind="attention">采集空窗</StatusTag>
        {e.after_gap ? `${absTime(e.after_gap.from)} 到 ${absTime(e.after_gap.to)}` : "一段时间"}
        {e.prev_for_s !== undefined ? `（${spanText(e.prev_for_s)}）` : ""}没有采集：这段时间里各对象的状态未知，发生过的变化没有记录。
      </span>
    );
  if (shape === "config")
    return (
      <span data-testid="link-event" data-shape="config">
        <span className="muted">对象清单更新</span>
        采集范围随网关安装更新（{e.from || "—"} → {e.to || "—"}）
      </span>
    );
  const arrow = (
    <>
      <StateText kind={e.kind} state={e.from} w={w} /> → <StateText kind={e.kind} state={e.to} w={w} />{" "}
    </>
  );
  if (shape === "merged")
    return (
      <span data-testid="link-event" data-shape="merged">
        <StatusTag kind="attention">变化了 {e.changes} 次</StatusTag>
        {e.open ? <span className="muted">仍在合并计数</span> : null}
        {arrow}
        <Note inline>第一次在 {absTime(e.at)}，最后一次在 {absTime(e.last_at)}；左边是第一次变化之前的状态，右边是最后一次之后的状态。这是反复变化，不是一次连续的中断。</Note>
      </span>
    );
  return (
    <span data-testid="link-event" data-shape={shape}>
      {arrow}
      {e.after_gap ? (
        <Typography.Text type="secondary">
          <StatusTag kind="attention">空窗后才发现</StatusTag>
          变化发生在 {absTime(e.after_gap.from)} 到 {absTime(e.after_gap.to)} 之间（那段时间没有读到这个对象），具体时间不确定；左边的时间是发现它的时间。
        </Typography.Text>
      ) : null}
    </span>
  );
}

/** How long the previous state was observed; "at least" when its real length is longer or unknown. */
export function prevText(e: LinkLogEvent): string {
  const shape = eventShape(e);
  if (shape === "gap" || shape === "config") return "—";
  if (e.prev_for_s === undefined || e.prev_for_s === null) return e.prev_open ? "不确定" : "—";
  if (!e.prev_open) return spanText(e.prev_for_s);
  return e.after_gap ? `至少 ${spanText(e.prev_for_s)}（之后进入空窗，实际更长或不确定）` : `至少 ${spanText(e.prev_for_s)}（第一次读到时就已是这个状态）`;
}

function eventDetails(e: LinkLogEvent, w: Words): FactItem[] {
  const st = strengthOf(e.source, e.class, w);
  const items: FactItem[] = [
    ["记录时间", absTime(e.at)],
    ["对象", `${objectName(e)}（${classLabel(e.class, w)}）`],
  ];
  if (e.evidence) items.push(["依据", e.evidence, "stacked"]);
  if (e.reason) items.push(["原因代码", <Mono key="r">{e.reason}</Mono>]);
  if (st) items.push(["依据的强弱", <Tag key="t" color={st.color}>{st.label}</Tag>]);
  if (e.source_at) items.push(["来源自己记的时间", absTime(e.source_at)]);
  if ((e.changes ?? 0) > 1) items.push(["合并", `${e.changes} 次变化，${absTime(e.at)} 到 ${absTime(e.last_at)}${e.open ? "；仍在计数，还没有写入日志" : ""}`]);
  return items;
}

const RANGES: { value: string; label: string; hours: number }[] = [
  { value: "all", label: "全部（保留期内）", hours: 0 },
  { value: "1h", label: "最近 1 小时", hours: 1 },
  { value: "24h", label: "最近 24 小时", hours: 24 },
  { value: "7d", label: "最近 7 天", hours: 168 },
];

function StatsLine({ s }: { s: LinkLogStats }) {
  return (
    <LogStats
      testId="link-log-stats"
      count={s.events}
      unit="条事件"
      used={s.disk_bytes}
      max={s.budget.total}
      oldest={s.oldest}
      extra={[
        s.baseline_at && `基线建立于 ${absTime(s.baseline_at)}`,
        s.merged > 0 && `合并掉 ${s.merged} 次变化`,
        s.dropped_budget > 0 && `因每小时写入上限丢弃 ${s.dropped_budget} 条`,
        s.write_errors > 0 && `写入出错 ${s.write_errors} 次`,
      ]}
    />
  );
}

function Journal({ v, w }: { v: LinkLogView; w: Words }) {
  const { message } = AntApp.useApp();
  const cur = useApi(() => api.getLinkLogCurrent(), []);
  const [object, setObject] = useState("");
  const [cls, setCls] = useState("");
  const [range, setRange] = useState("all");
  const [cursors, setCursors] = useState<string[]>([]);
  const [clearErr, setClearErr] = useState<api.ApiError | null>(null);
  const confirm = useConfirmDanger();
  const before = cursors.length > 0 ? cursors[cursors.length - 1] : "";
  const objects = v.objects ?? [];
  const query: LinkLogQuery = useMemo(() => {
    const o = object === "" ? undefined : objects[Number(object)];
    const h = RANGES.find((x) => x.value === range)?.hours ?? 0;
    return {
      class: o ? undefined : cls || undefined,
      kind: o?.kind,
      id: o?.id,
      from: sinceHours(h),
      before: before || undefined,
      limit: 50,
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [object, cls, range, before, objects.length]);
  const ev = useApi(() => api.getLinkLogEvents(query), [JSON.stringify(query)]);
  const reset = () => setCursors([]);
  const page = ev.data?.page;
  const events = page?.events ?? [];
  const stats = page?.stats;
  const filtered = !!(object || cls || range !== "all");
  const classes = useMemo(() => {
    const seen = new Set<string>();
    const out: { value: string; label: string }[] = [];
    for (const c of [...w.kinds.map((k) => k.class), ...Object.keys(CLASS_LABEL)]) {
      if (seen.has(c)) continue;
      seen.add(c);
      out.push({ value: c, label: classLabel(c, w) });
    }
    return out;
  }, [w]);
  const clear = () =>
    confirm({
      title: "清空链路日志",
      consequence: `立即删除网关上全部 ${stats?.events ?? ""} 条事件和已记下的各对象状态，不能恢复。之后的第一次采集重新建立基线：当前各状态的持续时间从那时重新算起，显示为「至少」。`,
      okText: "清空",
      onOk: async () => {
        setClearErr(null);
        try {
          await api.clearLinkLog();
          message.success("链路日志已清空");
          reset();
          await Promise.all([cur.reload(), ev.reload()]);
        } catch (e) {
          setClearErr(e instanceof api.ApiError ? e : new api.ApiError(0, {}));
        }
      },
    });
  return (
    <>
      <Section
        title="当前状态"
        extra={
          <Button size="small" onClick={() => void cur.reload()}>
            刷新
          </Button>
        }
      >
        {cur.error ? <ApiErrorAlert error={cur.error} onRetry={() => void cur.reload()} /> : null}
        {!cur.data ? (
          cur.error ? null : (
            <Skeleton active paragraph={{ rows: 3 }} />
          )
        ) : cur.data.available && cur.data.summary ? (
          <Current summary={cur.data.summary} w={w} gapAfterS={v.timing.gap_after_s} unobserved={v.scope.unobserved.filter(o => o.class === "sniff_target" || o.class === "external_exit").map(o => `${o.kind}|${o.id}`)} />
        ) : (
          <LogEmpty id="link-log-current" state={cur.data.code ?? "unavailable"} title="读不到当前状态">
            {cur.data.message || "采集服务没有回答。"}
          </LogEmpty>
        )}
      </Section>
      <Section title="事件时间线">
        <Space direction="vertical" style={{ width: "100%" }} data-testid="link-log-events">
          <LogToolbar
            testId="link-log-filters"
            filters={<>
            <Select
              aria-label="对象"
              value={object}
              onChange={(x) => {
                setObject(x);
                reset();
              }}
              className="input-w260"
              options={[{ value: "", label: "全部对象" }, ...objects.map((o, i) => ({ value: String(i), label: o.observed ? o.label : `${o.label}（不读取）` }))]}
            />
            <Select
              aria-label="类别"
              value={object ? "" : cls}
              disabled={!!object}
              onChange={(x) => {
                setCls(x);
                reset();
              }}
              className="input-w200"
              options={[{ value: "", label: object ? "已选定对象" : "全部类别" }, ...classes]}
            />
            <Select
              aria-label="时间"
              value={range}
              onChange={(x) => {
                setRange(x);
                reset();
              }}
              className="input-w200"
              options={RANGES.map(({ value, label }) => ({ value, label }))}
            />
          </>}
            stats={stats ? <StatsLine s={stats} /> : null}
            onRefresh={() => void ev.reload()}
            onClear={clear}
            clearDisabled={!ev.data?.available}
          />
          {ev.error ? <ApiErrorAlert error={ev.error} onRetry={() => void ev.reload()} /> : null}
          {clearErr ? <ApiErrorAlert error={clearErr} /> : null}
          {!ev.data ? (
            ev.error ? null : (
              <Skeleton active paragraph={{ rows: 4 }} />
            )
          ) : !ev.data.available ? (
            <LogEmpty id="link-log" state={ev.data.code === "not_running" ? "not-running" : "unreadable"} title="读不到事件">
              {ev.data.message || "采集服务没有回答。"}
            </LogEmpty>
          ) : events.length === 0 ? (
            <LogEmpty id="link-log" state={filtered || cursors.length > 0 ? "no-match" : "no-events"} title={filtered ? "没有符合筛选条件的事件" : "还没有状态变化事件"}>
              {filtered
                ? "放宽对象、类别或时间范围。"
                : "采集服务在运行。它第一次读到每个对象时只记下状态（基线），不产生事件；之后状态发生变化才各记一条。现在的状态见上面的「当前状态」。"}
            </LogEmpty>
          ) : (
            <>
              {(page?.open_merged ?? 0) > 0 ? (
                <Note inline>其中 {page?.open_merged} 条是仍在合并计数的抖动记录，次数还会增加。</Note>
              ) : null}
              <DataTable<LinkLogEvent>
                size="small"
                rowKey={(e) => (e.seq ? String(e.seq) : `open|${e.kind}|${e.id}|${e.at}`)}
                dataSource={events}
                pageSize={100}
                pagination={false}
                secondary={(e) => <Facts items={eventDetails(e, w)} />}
                columns={[
                  { title: "时间", kind: "fixed", width: 110, render: (_, e) => <TimeText value={e.at} /> },
                  {
                    title: "对象",
                    kind: "flex",
                    width: 240,
                    card: "title",
                    render: (_, e) => (
                      <span className="inline-status wrap">
                        <span>{objectName(e)}</span>
                        <span className="muted">{classLabel(e.class, w)}</span>
                      </span>
                    ),
                  },
                  { title: "变化", kind: "flex", width: 300, render: (_, e) => <EventChange e={e} w={w} /> },
                  { title: "之前的状态持续了", kind: "flex", width: 170, render: (_, e) => <span data-testid="link-event-prev">{prevText(e)}</span> },
                ]}
              />
            </>
          )}
          <LogPager cursors={cursors} setCursors={setCursors} next={page?.next_before} noun="事件" />
        </Space>
      </Section>
    </>
  );
}

/** The collector is not there to ask: which state this is, and how to get it. */
function NotCollecting({ v }: { v: LinkLogView }) {
  const rt = v.runtime;
  const deploy = (
    <LinkButton to={href("deploy")} type="primary">
      去部署页安装
    </LinkButton>
  );
  if (rt.code === "not_installed" || (rt.available && !rt.present && v.pending === "install"))
    return (
      <LogEmpty id="link-log" state="not-installed" title="链路日志的采集服务还没有安装到网关" action={deploy}>
        采集服务是网关安装内容的一部分，没有单独的开关。升级到带链路日志的版本之后，网关会显示有待安装的变更：到部署页对网关预检 → 确认差异 → 安装，采集服务随之启动，之后的状态变化才有记录（安装之前发生的不会补记）。
      </LogEmpty>
    );
  if (rt.code === "not_running" || (rt.available && !rt.present))
    return (
      <LogEmpty id="link-log" state="not-running" title="采集服务已安装，但没有运行" action={<LinkButton to={href("deploy")}>去部署页</LinkButton>}>
        {rt.message || "状态变化没有被记录；转发和故障切换不受影响。"} 重新安装网关（部署页）会再次启动它；它停止的这段时间在时间线上是一段采集空窗。
      </LogEmpty>
    );
  if (rt.code === "agent_old")
    return (
      <LogEmpty id="link-log" state="agent-old" title="网关宿主机上的程序比面板旧，还没有链路日志" action={deploy}>
        {rt.message} 先在网关上重新运行 deploy/debian/install.sh 升级宿主程序，再到部署页对网关预检 → 确认 → 安装。
      </LogEmpty>
    );
  return (
    <LogEmpty id="link-log" state="unreadable" title="读不到网关上的链路日志">
      {rt.message || "宿主执行通道没有回答。"} 日志在网关本机，面板只能经宿主代理读取；通道恢复后刷新。
    </LogEmpty>
  );
}

export default function LinkLogsPage() {
  const meshDoc = useTopologyDoc();
  const view = useApi(() => api.getLinkLog(), []);
  const v = view.data;
  const w: Words = useMemo(() => ({ kinds: v?.scope.kinds ?? [], sources: v?.scope.sources ?? [] }), [v]);
  const b = v?.bounds;
  return (
    <Page title="链路日志">
      <MeshLegQuality topo={meshDoc.topo} history />
      <div className="log-page">
        <Help title="记录范围与保存说明">
          <LogIntro
            id="link-log"
            records="状态的变化，不是周期采样：承载路径的切换、中继在分担里被剔除和恢复、每条隧道握手超时和恢复、WSS 伴随承载的连接与断开、网关对外部出口和嗅探自检目标的检查由通变不通及恢复——每条有时间、对象、从什么状态到什么状态、依据和之前的状态持续了多久。"
            excludes="任何流量内容（没有设备地址、域名或连接）；只在远端节点上才看得到的状态也不记录，例如承载节点上的外部出口健康检查、枢纽上地区组的成员切换（见「说明」里的「不在记录范围内」）。"
            keep={
              b
                ? `最近 ${ageText(b.max_age_s)}、最多 ${b.max_events} 条、合计不超过 ${bytes(b.disk_bytes)}，先到的上限生效，超出时删最旧的。`
                : "最近 30 天、最多 20000 条，并有磁盘字节上限，先到的上限生效，超出时删最旧的。"
            }
            where="只在网关本机的 /var/lib/meridian-linklog，不进入拓扑、快照、导出或诊断信息。"
            who="只有网关上的 root；面板只经宿主代理的固定只读请求读取，持有面板口令的人能在这一页看到。没有开关：采集服务随网关安装启动。"
          />
        </Help>
        {v ? (
          <Help title="观测范围">
            <Scope v={v} />
          </Help>
        ) : null}
        {view.error ? <ApiErrorAlert error={view.error} onRetry={() => void view.reload()} /> : null}
        {!v ? (
          view.error ? null : (
            <Skeleton active paragraph={{ rows: 6 }} />
          )
        ) : (
          <>
            {v.runtime.available && v.runtime.present ? (
              <Journal v={v} w={w} />
            ) : (
              <Section
                title="当前状态与事件"
                extra={
                  <Button size="small" onClick={() => void view.reload()} loading={view.loading}>
                    重新读取
                  </Button>
                }
              >
                <NotCollecting v={v} />
              </Section>
            )}
          </>
        )}
      </div>
    </Page>
  );
}
