// What the three log pages (连接日志, 解析日志, 链路日志) share: the opening
// sentences every log page starts with, the explicit empty state, the lists
// of scope text, time-range presets, and the cross-link between the DNS
// query journal and the connection journal.
//
// Cross-linking. A record of one journal links to the other journal's page
// with the device's address, the record's time and, when the record has
// one, its MAC (`#/conn-log?device=…&at=…&mac=…`; a hash fragment, never
// sent to the server). The target page asks the related endpoint, which
// answers the records of that address inside a bounded window and says what
// the match rests on (`identity`): only "mac" is shown as the same device;
// "partial" and "address" say that the device could not be confirmed. No
// name is ever part of a link.

import { EllipsisOutlined } from "@ant-design/icons";
import { Button, Dropdown, Select, Space, Tag, Typography } from "antd";
import { useState, type ReactNode } from "react";
import "./layout_b.css";
import { href } from "./state";
import type { LogRelatedQuery, LogRelatedView } from "./types";
import { ApiErrorAlert, EmptyState, Mono, TimeText, bytes, formatAbsolute, useApi } from "./ui";

/** A length of time in plain words, from seconds: 45 秒, 3 分 5 秒, 2 小时 4 分, 3 天 2 小时. */
export function spanText(seconds: number | undefined | null): string {
  if (seconds === undefined || seconds === null || seconds < 0) return "—";
  const s = Math.round(seconds);
  if (s < 60) return `${s} 秒`;
  if (s < 3600) return `${Math.floor(s / 60)} 分 ${s % 60} 秒`;
  if (s < 86400) return `${Math.floor(s / 3600)} 小时 ${Math.floor((s % 3600) / 60)} 分`;
  return `${Math.floor(s / 86400)} 天 ${Math.floor((s % 86400) / 3600)} 小时`;
}

/** A retention in plain words, from seconds: 24 小时, 30 天. */
export function ageText(seconds: number): string {
  if (seconds % 86400 === 0 && seconds >= 2 * 86400) return `${seconds / 86400} 天`;
  if (seconds % 3600 === 0) return `${seconds / 3600} 小时`;
  return spanText(seconds);
}

/** RFC 3339 (seconds) of `hours` ago, or undefined for 0 (no lower bound). */
export function sinceHours(hours: number): string | undefined {
  return hours ? new Date(Date.now() - hours * 3600_000).toISOString().replace(/\.\d{3}Z$/, "Z") : undefined;
}

/** An absolute local time for texts ("2026-11-14 08:00:00"); the value as given when it is not a time. */
export function absTime(value: string | undefined | null): string {
  if (!value) return "—";
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? value : formatAbsolute(d);
}

/**
 * The two sentences a log page starts with: what it records and what it
 * does not; how long it is kept, where, and who can read it.
 */
export function LogIntro({ id, records, excludes, keep, where, who }: { id: string; records: ReactNode; excludes: ReactNode; keep: ReactNode; where: ReactNode; who: ReactNode }) {
  return (
    <div className="log-intro" data-testid={`${id}-intro`}>
      <p>
        <Typography.Text strong>记录：</Typography.Text>
        {records}
        <Typography.Text strong> 不记录：</Typography.Text>
        {excludes}
      </p>
      <p>
        <Typography.Text strong>保留：</Typography.Text>
        {keep}
        <Typography.Text strong> 存放：</Typography.Text>
        {where}
        <Typography.Text strong> 谁能看：</Typography.Text>
        {who}
      </p>
    </div>
  );
}

// ------------------------------------------------- the shared log layout ---

/**
 * The one control row every log table uses: filters on the left; on the
 * right the size line, 刷新 and a "…" menu holding the rare, destructive
 * 清空 (one visible action per section).
 */
export function LogToolbar({
  testId,
  filters,
  stats,
  onRefresh,
  onClear,
  clearLabel = "清空",
  clearDisabled,
}: {
  testId?: string;
  filters?: ReactNode;
  stats?: ReactNode;
  onRefresh?: () => void;
  onClear?: () => void;
  clearLabel?: string;
  clearDisabled?: boolean;
}) {
  return (
    <div className="log-toolbar">
      {filters ? (
        <Space wrap data-testid={testId} className="log-toolbar-filters">
          {filters}
        </Space>
      ) : (
        <span />
      )}
      <Space wrap size={6} className="log-toolbar-side">
        {stats}
        {onRefresh ? (
          <Button size="small" onClick={onRefresh}>
            刷新
          </Button>
        ) : null}
        {onClear ? (
          <Dropdown trigger={["click"]} menu={{ items: [{ key: "clear", label: clearLabel, danger: true, disabled: clearDisabled }], onClick: () => onClear() }}>
            <Button size="small" type="text" icon={<EllipsisOutlined />} aria-label="日志的更多操作" />
          </Dropdown>
        ) : null}
      </Space>
    </div>
  );
}

/** How much a journal holds, in one muted line: count · size / budget · oldest · extras. */
export function LogStats({ count, unit = "条", used, max, oldest, extra, testId }: { count: number; unit?: string; used: number; max: number; oldest?: string | null; extra?: (string | false | null | undefined)[]; testId?: string }) {
  return (
    <Typography.Text type="secondary" className="log-stats" data-testid={testId}>
      {count} {unit} · {bytes(used)} / {bytes(max)}
      {oldest ? (
        <>
          {" "}
          · 最早 <TimeText value={oldest} />
        </>
      ) : null}
      {(extra ?? []).filter(Boolean).map((x) => ` · ${x}`)}
    </Typography.Text>
  );
}

/** Cursor paging under a log table: the match line on the left, 较新 / 更早 on the right. */
export function LogPager<C>({ cursors, setCursors, next, noun, matched }: { cursors: C[]; setCursors: (c: C[]) => void; next?: C | null; noun: string; matched?: ReactNode }) {
  return (
    <div className="log-pager">
      <span>{matched}</span>
      <Space>
        <Button size="small" disabled={cursors.length === 0} onClick={() => setCursors(cursors.slice(0, -1))}>
          较新的{noun}
        </Button>
        <Button size="small" disabled={!next} onClick={() => next && setCursors([...cursors, next])}>
          更早的{noun}
        </Button>
      </Space>
    </div>
  );
}

/** The explicit empty state of a log page (never a blank page): which state it is, why, and how to get data. */
export function LogEmpty({ id, state, title, children, action }: { id: string; state: string; title: ReactNode; children?: ReactNode; action?: ReactNode }) {
  return (
    <div data-testid={`${id}-empty`} data-state={state} className="log-empty">
      <EmptyState title={title} description={children} action={action} />
    </div>
  );
}

/** Lists of scope text side by side (one column when narrow). */
export function ScopeLists({ testId, lists }: { testId?: string; lists: [string, readonly string[] | null | undefined, ReactNode?][] }) {
  return (
    <div data-testid={testId} className="sniff-coverage">
      {lists
        .filter(([, items, extra]) => (items ?? []).length > 0 || extra)
        .map(([title, items, extra]) => (
          <div key={title} className="sniff-coverage-col">
            <Typography.Text strong>{title}</Typography.Text>
            <ul className="plain-list">
              {(items ?? []).map((x) => (
                <li key={x}>{x}</li>
              ))}
            </ul>
            {extra}
          </div>
        ))}
    </div>
  );
}

// ---------------------------------------------------------- cross-linking ---

/** The link from a record to the other journal's records of the same device around its time. */
export function relatedHref(page: "conn-log" | "dns-log", q: { device: string; at: string; mac?: string }): string {
  const p = new URLSearchParams({ device: q.device, at: q.at });
  if (q.mac) p.set("mac", q.mac);
  return `${href(page)}?${p.toString()}`;
}

/** The related lookup a page was opened with, or null. */
export function relatedOf(query: URLSearchParams): LogRelatedQuery | null {
  const device = query.get("device") ?? "";
  const at = query.get("at") ?? "";
  if (!device || !at) return null;
  return { device, at, mac: query.get("mac") || undefined };
}

const WINDOWS = [60, 120, 300, 600];

/**
 * What a related lookup rests on, in words. Only "mac" (every listed record
 * carries the asked MAC) is called the same device; anything else says that
 * the device could not be confirmed and why.
 */
export function relatedIdentity<R>(v: LogRelatedView<R>, what: string): { same: boolean; tag: string; text: string } {
  const mac = v.mac ?? "";
  if (v.identity === "mac")
    return { same: true, tag: "地址 + MAC", text: `按设备身份关联：地址 ${v.device}，并且列出的每条${what}都带同一个 MAC ${mac}。` };
  if (v.identity === "partial")
    return {
      same: false,
      tag: "部分仅按地址",
      text: `列出的 ${v.listed} 条${what}里有 ${v.no_mac} 条没有 MAC：这些只是地址 ${v.device} 在这段时间里的${what}，不能确认来自同一台设备（表里标为「仅按地址」）；其余的带同一个 MAC ${mac}。`,
    };
  const why = !mac
    ? "发起跳转的那条记录没有 MAC（邻居表里没有，或是本来就没有 MAC 的远程接入设备）"
    : v.listed === 0
      ? "时间窗里没有可比对的记录"
      : `列出的${what}都没有 MAC，无从比对`;
  return {
    same: false,
    tag: "仅按地址",
    text: `仅按地址 ${v.device} 和时间窗关联，不能确认是同一台设备：${why}。同一个地址在这段时间里可能被另一台设备用过。`,
  };
}

/**
 * The other journal's records around a record: asks the related endpoint
 * with a bounded window (the choices never exceed `maxWindow`), says what
 * the match rests on, what was left out, and renders the records with
 * `children`.
 */
export function RelatedPanel<R>({
  id,
  query,
  load,
  what,
  source,
  maxWindow = 600,
  defaultWindow = 120,
  onClose,
  children,
}: {
  id: string;
  query: LogRelatedQuery;
  load: (q: LogRelatedQuery) => Promise<LogRelatedView<R>>;
  /** What is listed: 连接 / 查询. */
  what: string;
  /** Where the link came from: 解析记录 / 连接记录. */
  source: string;
  maxWindow?: number;
  defaultWindow?: number;
  onClose: () => void;
  children: (v: LogRelatedView<R>) => ReactNode;
}) {
  const choices = WINDOWS.filter((w) => w <= maxWindow);
  const [win, setWin] = useState(choices.includes(defaultWindow) ? defaultWindow : choices[Math.min(1, choices.length - 1)] ?? 120);
  const st = useApi(() => load({ ...query, window: win }), [query.device, query.at, query.mac, win]);
  const v = st.data;
  const idn = v ? relatedIdentity(v, what) : null;
  return (
    <div data-testid={`${id}-related`} className="log-related" data-identity={v?.identity}>
      <Space wrap>
        <Typography.Text strong data-testid={`${id}-related-title`}>
          {idn?.same ? `同一设备相近时间的${what}` : `同一地址相近时间的${what}${idn ? "（未确认是同一台设备）" : ""}`}
        </Typography.Text>
        {idn ? <Tag color={idn.same ? "blue" : "orange"}>{idn.tag}</Tag> : null}
        <Select
          aria-label="时间窗"
          size="small"
          value={win}
          onChange={setWin}
          className="input-w200"
          options={choices.map((w) => ({ value: w, label: `前后各 ${w >= 60 ? `${w / 60} 分钟` : `${w} 秒`}` }))}
        />
        <Button size="small" onClick={() => void st.reload()}>
          刷新
        </Button>
        <Button size="small" onClick={onClose}>
          关闭
        </Button>
      </Space>
      <div className="log-related-basis">
        <Typography.Text type="secondary">
          来自一条{source}：设备地址 <Mono>{query.device}</Mono>
          {query.mac ? (
            <>
              ，MAC <Mono>{query.mac}</Mono>
            </>
          ) : (
            "，没有 MAC"
          )}
          ，时间 {absTime(query.at)}
          {v?.from ? `；查找范围 ${absTime(v.from)} 到 ${absTime(v.to)}（前后各 ${v.window_s} 秒，最多 ${maxWindow} 秒）` : ""}。
        </Typography.Text>
      </div>
      {st.error ? <ApiErrorAlert error={st.error} onRetry={() => void st.reload()} /> : null}
      {v && idn ? (
        <>
          <div data-testid={`${id}-related-identity`} className={idn.same ? "log-related-identity" : "log-related-identity unconfirmed"}>
            {idn.text}
            {v.other_mac > 0 ? ` 另有 ${v.other_mac} 条同一地址、但 MAC 不同的${what}没有列出：这个地址在时间窗里被另一台设备用过。` : ""}
            {v.more ? ` 时间窗里的${what}比列出的多：只列出最新的 ${v.listed} 条，缩小时间窗可以看全。` : ""}
          </div>
          {!v.available ? (
            <LogEmpty id={`${id}-related`} state={v.code ?? "unavailable"} title={`读不到另一份日志里的${what}`}>
              {v.message || "没有回答"}
            </LogEmpty>
          ) : (v.records ?? []).length === 0 ? (
            <LogEmpty id={`${id}-related`} state="none" title={`这个时间窗里没有这个地址的${what}`}>
              可以换一个更大的时间窗（最多前后各 {maxWindow / 60} 分钟）；没有记录也可能是因为那份日志当时没有开启，或这次访问不在它的记录范围内。
            </LogEmpty>
          ) : (
            children(v)
          )}
        </>
      ) : null}
    </div>
  );
}

/** A record's time with the absolute time next to it (for detail rows). */
export function WhenText({ value }: { value: string | undefined | null }) {
  return (
    <span>
      <TimeText value={value} /> <Typography.Text type="secondary">{absTime(value)}</Typography.Text>
    </span>
  );
}
