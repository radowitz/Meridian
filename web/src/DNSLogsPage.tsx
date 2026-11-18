import {
  Help,
  Note,
} from "./ui";
// 解析日志 (#/dns-log): the gateway resolver's query journal
// (internal/api/dns_journal.go). Off by default: its content is the names
// devices ask for.
//
// The switch is explicit and gated:
//   - the capability gate first: when this gateway's resolver was not
//     verified for the audit log, the page says why and what to do, and
//     offers no way to turn the journal on;
//   - turning it on needs an acknowledgement (what is recorded, for how
//     long, where) and only saves the setting: it takes effect with the next
//     gateway install (preflight → confirm → install on the deploy page);
//   - turning it off says that the records on the gateway are deleted after
//     the install succeeded, and are kept (and still written) until then.
//
// With the journal installed: a per-device summary, the records with
// filters (device, time range, name text, result class, resolver group) and
// cursor paging, the confirmed "clear", and the scope text (what is not
// recorded; why "name does not exist" and "upstream failed" can only be told
// apart by the elapsed time).
//
// A clear is only shown as done when the gateway says everything went. One
// that left something (a file that could not be deleted or emptied) keeps a
// warning on the page — what is still there, in counts, why, and a retry —
// and what is left stays listed. The warning also comes from the gateway's
// own state, so it is still there after a reload or after the reader on the
// gateway restarted, until a clear completes or nothing is left. A record links to the connections of the same
// device around its time, and the page shows the queries around a
// connection when opened with ?device=&at=[&mac=] (log_common.tsx).

import { Alert, Button, Checkbox, Input, Select, Skeleton, Space, Tag, Typography } from "antd";
import { useEffect, useMemo, useState, type ReactNode } from "react";
import * as api from "./api";
import { LogEmpty, LogIntro, LogPager, LogStats, LogToolbar, RelatedPanel, ScopeLists, WhenText, ageText, relatedHref, relatedOf, sinceHours } from "./log_common";
import { href, useRouter, useStatus } from "./state";
import type { DNSLogClearError, DNSLogClearResidual, DNSLogDeviceSummary, DNSLogGroup, DNSLogJournalView, DNSLogQuery, DNSLogRecord, DNSLogView } from "./types";
import { ApiErrorAlert, DataTable, EllipsisText, Facts, Link, LinkButton, Mono, Page, Section, StatusTag, TimeText, bytes, useAction, useApi, useConfirmDanger, type DataColumn, type FactItem } from "./ui";

/** The result classes in plain words (the audit line has no response code). */
export const DNS_RESULT: Record<string, { label: string; color?: string; hint: string }> = {
  answered: { label: "有应答", color: "green", hint: "应答里至少有一个地址" },
  no_answer: { label: "无应答", hint: "没有地址，很快返回：名字不存在、没有所问类型的记录或上游很快拒绝，日志里分不开" },
  no_answer_slow: { label: "无应答且慢", color: "orange", hint: "没有地址，而且慢：多半是上游失败或超时，也可能是很慢的「不存在」" },
};

function resultTag(r: string) {
  const d = DNS_RESULT[r];
  return (
    <Tag color={d?.color} title={d?.hint}>
      {d?.label ?? r}
    </Tag>
  );
}

interface Ctx {
  groups: DNSLogGroup[];
  qtypes: Record<string, string>;
  labels: Map<string, string>;
}

function groupText(g: string | undefined, groups: DNSLogGroup[]): string {
  if (!g) return "未知";
  return groups.find((x) => x.group === g)?.label ?? g;
}

function qtypeText(n: number, qtypes: Record<string, string>): string {
  return qtypes[String(n)] ?? `类型 ${n}`;
}

/** The link from a query to the connections the same device made around it. */
function ConnectionsLink({ r }: { r: DNSLogRecord }) {
  return (
    <span data-testid="dns-related-link">
      <Link to={relatedHref("conn-log", { device: r.client, at: r.time, mac: r.mac })}>查看这台设备在这次查询前后的连接记录</Link>{" "}
      <Typography.Text type="secondary" style={{ fontSize: 12 }}>
        {r.mac ? "按地址和 MAC 在连接日志里查找（有界时间窗）" : "这条记录没有 MAC：只能按地址和时间查找，不能确认是同一台设备"}
      </Typography.Text>
    </span>
  );
}

function recordDetails(r: DNSLogRecord, ctx: Ctx): FactItem[] {
  return [
    [
      "时间",
      <span key="t">
        <WhenText value={r.time} />
        {r.time_approx ? "（这一行的时区无法确定：这是读到它的时间，可能比实际查询晚）" : ""}
      </span>,
    ],
    ["设备地址", <Mono key="c">{r.client}</Mono>],
    ["MAC", r.mac ? <Mono key="m">{r.mac}</Mono> : "未知（读到这一行时邻居表里没有它，或是本来就没有 MAC 的远程接入设备）"],
    ["应答", `${r.answers} 个地址${r.answers_other ? `，另有 ${r.answers_other} 项不是地址` : ""}（地址本身不保存）`],
    [
      "解析组",
      !r.group
        ? "未知：这一行没有写明"
        : ctx.groups.some((g) => g.group === r.group)
          ? `${groupText(r.group, ctx.groups)}（解析器记为 ${r.group}）`
          : `${r.group}（解析器记下的组名；现在的拓扑里没有这个组，可能是旧拓扑下的记录）`,
    ],
    ["结果说明", `${DNS_RESULT[r.result]?.hint ?? r.result}；耗时 ${r.elapsed_ms} 毫秒`],
    ["连接日志", <ConnectionsLink key="l" r={r} />, "stacked"],
  ];
}

/** The columns of a table of queries; `mac`: show each row's MAC (the related panel) instead of the device. */
function recordColumns(ctx: Ctx, mac: boolean): DataColumn<DNSLogRecord>[] {
  return [
    { title: "时间", kind: "fixed", width: 100, render: (_, r) => <TimeText value={r.time} /> },
    mac
      ? { title: "MAC", kind: "fixed", width: 160, render: (_, r) => (r.mac ? <Mono>{r.mac}</Mono> : <StatusTag kind="attention">无 MAC · 仅按地址</StatusTag>) }
      : {
          title: "设备",
          kind: "flex",
          width: 160,
          render: (_, r) => (
            <span className="inline-status wrap">
              {ctx.labels.get(r.client) ? <Typography.Text strong>{ctx.labels.get(r.client)}</Typography.Text> : null}
              <EllipsisText mono text={r.client} />
            </span>
          ),
        },
    { title: "名字", kind: "flex", width: 220, card: "title", render: (_, r) => <EllipsisText mono text={r.name} /> },
    { title: "类型", kind: "fixed", width: 90, render: (_, r) => qtypeText(r.qtype, ctx.qtypes) },
    { title: "结果", kind: "fixed", width: 120, render: (_, r) => resultTag(r.result) },
  ];
}

function QueryTable({ records, ctx, mac, empty }: { records: DNSLogRecord[]; ctx: Ctx; mac?: boolean; empty?: ReactNode }) {
  return (
    <DataTable<DNSLogRecord>
      size="small"
      rowKey={(r) => String(r.id)}
      dataSource={records}
      pageSize={100}
      pagination={false}
      locale={empty ? { emptyText: empty } : undefined}
      secondary={(r) => <Facts items={recordDetails(r, ctx)} />}
      columns={recordColumns(ctx, !!mac)}
    />
  );
}

// ------------------------------------------------------------- the switch ---

const VERIFIED_BY: Record<string, string> = { builtin: "随这个版本的面板核对", host_record: "在这台网关上核对" };

/** Why the journal cannot be turned on, and what to do. Never a way around it. */
function Unavailable({ v, onRecheck, busy }: { v: DNSLogView; onRecheck: () => void; busy: boolean }) {
  const c = v.capability;
  return (
    <div data-testid="dns-log-unavailable" className="log-gate">
      <Space wrap>
        <StatusTag kind="neutral">不可用</StatusTag>
        <Typography.Text strong>{v.setting.enabled ? "这台网关的解析器现在不满足解析日志的条件" : "这台网关现在不能打开解析日志"}</Typography.Text>
        <Button size="small" onClick={onRecheck} loading={busy}>
          重新检查
        </Button>
      </Space>
      <Facts
        stacked
        items={[
          ["原因", c.reason || "没有说明"],
          ["处理办法", c.action || "没有可在面板里完成的处理办法；条件满足后这里会变为可以打开"],
        ]}
      />
      <Note inline>解析日志只在核对过审计日志行为的解析器上提供（写日志不能拖慢或卡住解析）。条件不满足时没有绕过的办法：{v.setting.enabled ? "带着打开的解析日志做网关预检会被阻断，可以先关闭它。" : "开关保持关闭，保存和安装也会被拒绝。"}</Note>
    </div>
  );
}

function SwitchSection({ v, onView, reload, loading }: { v: DNSLogView; onView: (v: DNSLogView) => void; reload: () => void; loading: boolean }) {
  const act = useAction();
  const confirm = useConfirmDanger();
  const { markApplyRequired } = useStatus();
  const [asking, setAsking] = useState(false);
  const [ack, setAck] = useState(false);
  const on = v.setting.enabled;
  const inst = v.installed;
  const cap = v.capability;
  const rt = v.runtime;
  const b = v.bounds;
  const limits = `最多保留 ${ageText(b.max_age_s)}、${b.max_records} 条、磁盘上不超过 ${bytes(b.disk_bytes)}`;
  const put = (enabled: boolean) =>
    act.run(
      async () => {
        const nv = await api.putDNSLog(enabled);
        setAsking(false);
        setAck(false);
        onView(nv);
        markApplyRequired();
      },
      enabled ? "enable" : "disable",
      () => reload(),
    );
  const disable = () =>
    confirm({
      title: "关闭解析日志",
      consequence: (
        <div data-testid="dns-log-disable-confirm">
          {inst.known && !inst.enabled
            ? "解析日志只是保存为打开、还没有安装到网关：关闭只是撤销这次设置，网关上什么都不变，也没有记录需要删除。"
            : "关闭只是把设置保存到拓扑，要到部署页对网关预检 → 确认 → 安装之后才生效（安装会重启一次网关解析器）。安装成功之后，网关停止记录并删除已有的全部解析记录；在那之前——包括取消预检、安装失败——仍在记录，记录也都保留。要现在就删除已有的记录，用这一页的「清空」。"}
        </div>
      ),
      okText: inst.known && !inst.enabled ? "撤销打开" : "保存：下次网关安装时关闭",
      danger: false,
      onOk: () => put(false),
    });
  return (
    <Section title="开关与状态">
      <div data-testid="dns-log-switch" data-setting={on ? "on" : "off"} data-installed={inst.known ? (inst.enabled ? "on" : "off") : "unknown"}>
        {v.pending === "enable" ? (
          <Alert
            type="info"
            showIcon
            style={{ marginBottom: 12 }}
            data-testid="dns-log-pending"
            message="已保存为打开，还没有生效"
            description={<Note>{"保存只写入了拓扑，网关上什么都没变，现在没有任何记录。到部署页对网关做预检（差异里能看到解析器配置增加审计日志、新增解析日志服务）→ 确认 → 安装之后才开始记录；安装会重启一次网关解析器，解析中断约一两秒。"}</Note>}
            action={
              <LinkButton to={href("deploy")} size="small" type="primary">
                去部署页
              </LinkButton>
            }
          />
        ) : v.pending === "disable" ? (
          <Alert
            type="warning"
            showIcon
            style={{ marginBottom: 12 }}
            data-testid="dns-log-pending"
            message="已保存为关闭，还没有生效：网关上现在仍在记录"
            description="到部署页对网关预检 → 确认 → 安装。安装成功之后，网关停止记录并删除已有的全部解析记录；取消预检或安装失败时继续记录、记录保留。要现在就删除已有的记录，用下面的「清空」。"
            action={
              <LinkButton to={href("deploy")} size="small" type="primary">
                去部署页
              </LinkButton>
            }
          />
        ) : null}
        <Facts
          items={[
            ["保存的设置", on ? "打开" : "关闭（默认）"],
            [
              "网关上",
              !inst.known ? (
                <StatusTag kind="unverified">读不到安装记录，无法判断是否已安装</StatusTag>
              ) : inst.enabled ? (
                rt.available && !rt.present ? (
                  <StatusTag kind="attention">已安装，但解析日志服务没有运行</StatusTag>
                ) : rt.available ? (
                  <span>已安装，解析日志服务在运行</span>
                ) : (
                  <span>已安装（运行状态读不到）</span>
                )
              ) : (
                <span>没有安装：现在不记录任何查询</span>
              ),
            ],
            ...(cap.available
              ? ([
                  [
                    "解析器",
                    `可以打开：SmartDNS ${cap.version ?? "版本未知"}，审计日志的行为已核对${cap.verified_on ? `（${cap.verified_on}，${VERIFIED_BY[cap.verified_by ?? ""] ?? cap.verified_by ?? ""}）` : ""}`,
                  ],
                ] as FactItem[])
              : []),
            ...(rt.available && (rt.data_bytes > 0 || inst.enabled) ? ([["网关上的数据", `${rt.data_files} 个文件，${bytes(rt.data_bytes)}`]] as FactItem[]) : []),
          ]}
        />
        {rt.message && (rt.code === "not_running" || rt.code === "unverified_running" || rt.code === "leftover" || rt.code === "read_failed") ? (
          <Typography.Paragraph type="warning" data-testid="dns-log-runtime" style={{ marginBottom: 8 }}>
            {rt.message}
          </Typography.Paragraph>
        ) : null}
        {!cap.available ? <Unavailable v={v} onRecheck={reload} busy={loading} /> : null}
        {act.error ? <ApiErrorAlert error={act.error} onClose={act.clear} /> : null}
        {asking && !on && cap.available ? (
          <div data-testid="dns-log-enable-confirm" className="log-confirm" data-prose-exempt>
            <Typography.Text strong>打开之前请确认</Typography.Text>
            <Typography.Paragraph style={{ marginBottom: 4 }}>
              打开后，网关会在本机保存每台设备查询过的名字（{limits}）。名字属于敏感信息：只有网关上的 root 能读，面板经宿主代理的固定只读请求查询，不进入拓扑、快照、导出或面板自己的日志。
            </Typography.Paragraph>
            <ScopeLists
              lists={[
                ["记录什么", v.scope.covered],
                ["保存在哪里、保留多久", v.scope.storage],
                ["打开和关闭", v.scope.switch],
              ]}
            />
            <Checkbox checked={ack} onChange={(e) => setAck(e.target.checked)}>
              我已了解：打开后网关会保存每台设备查询的名字
            </Checkbox>
            <Space wrap style={{ marginTop: 8 }}>
              <Button type="primary" disabled={!ack} loading={act.busy === "enable"} onClick={() => void put(true)}>
                保存：下次网关安装时打开
              </Button>
              <Button
                onClick={() => {
                  setAsking(false);
                  setAck(false);
                }}
              >
                取消
              </Button>
            </Space>
          </div>
        ) : null}
        <Space wrap style={{ marginTop: 8 }}>
          {on ? (
            <Button onClick={disable} loading={act.busy === "disable"}>
              关闭解析日志…
            </Button>
          ) : cap.available && !asking ? (
            <Button type="primary" onClick={() => setAsking(true)}>
              打开解析日志…
            </Button>
          ) : null}
        </Space>
      </div>
    </Section>
  );
}

// ---------------------------------------------------------------- the data ---

const RANGES: { value: string; label: string; hours: number }[] = [
  { value: "all", label: "全部（保留期内）", hours: 0 },
  { value: "1h", label: "最近 1 小时", hours: 1 },
  { value: "6h", label: "最近 6 小时", hours: 6 },
];

function topOf(m: Record<string, number> | null | undefined, label: (k: string) => string, n = 3): string {
  return Object.entries(m ?? {})
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, n)
    .map(([k, c]) => `${label(k)} ${c}`)
    .join(" · ");
}

interface DeviceRow extends DNSLogDeviceSummary {
  label?: string;
}

function noAnswer(d: DNSLogDeviceSummary): { all: number; slow: number } {
  const slow = d.by_result?.no_answer_slow ?? 0;
  return { all: (d.by_result?.no_answer ?? 0) + slow, slow };
}

function DeviceSummary({ rows, groups, onOpen }: { rows: DeviceRow[]; groups: DNSLogGroup[]; onOpen: (d: string) => void }) {
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
            [
              "MAC",
              (r.macs ?? []).length > 1
                ? `这个地址出现过 ${(r.macs ?? []).length} 个 MAC（${(r.macs ?? []).join("、")}）：它被不止一台设备用过，这一行是它们的合计`
                : r.mac || "未知",
            ],
            ...(r.no_mac ? ([["没有 MAC 的记录", String(r.no_mac)]] as FactItem[]) : []),
            ["结果", Object.entries(r.by_result ?? {}).map(([k, n]) => `${DNS_RESULT[k]?.label ?? k} ${n}`).join(" · ") || "—"],
            ["解析组", topOf(r.by_group, (k) => groupText(k, groups), 8) + (r.other_groups ? ` · 其它 ${r.other_groups}` : "")],
            ["不同的名字", `${r.distinct_names}${r.names_truncated ? "+" : ""}`],
            [
              "问得最多的名字",
              (r.top_names ?? []).length > 0 ? (
                <span key="n" className="mono-small">
                  {(r.top_names ?? []).map((n) => `${n.name} ×${n.count}`).join("　")}
                  {r.names_truncated ? "（不同的名字太多，只统计了一部分）" : ""}
                </span>
              ) : (
                "—"
              ),
              "stacked",
            ],
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
            <span className="inline-status wrap">
              {r.label ? <Typography.Text strong>{r.label}</Typography.Text> : null}
              <EllipsisText mono text={r.device} />
              {(r.macs ?? []).length > 1 ? (
                <StatusTag kind="attention">{(r.macs ?? []).length} 个 MAC</StatusTag>
              ) : r.mac ? (
                <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                  {r.mac}
                </Typography.Text>
              ) : null}
            </span>
          ),
        },
        { title: "最近", kind: "fixed", width: 100, render: (_, r) => <TimeText value={r.last_seen} /> },
        { title: "查询", kind: "fixed", width: 80, render: (_, r) => r.total },
        {
          // Counts can be five digits each: a wrapping column, not a nowrap one.
          title: "无应答",
          kind: "flex",
          width: 110,
          render: (_, r) => {
            const n = noAnswer(r);
            return n.all > 0 ? `${n.all}${n.slow ? `（慢 ${n.slow}）` : ""}` : 0;
          },
        },
        {
          title: "",
          kind: "actions",
          width: 90,
          render: (_, r) => (
            <Button size="small" onClick={() => onOpen(r.device)} aria-label={`查看 ${r.label ?? r.device} 的查询`}>
              查看
            </Button>
          ),
        },
      ]}
    />
  );
}

function JournalEmpty({ j }: { j: DNSLogJournalView }) {
  if (j.available)
    return (
      <LogEmpty id="dns-log" state="no-data" title="还没有解析记录">
        解析日志已安装，但还没有读到一条查询：设备向网关的解析器查询名字后出现在这里。被解析器的规则直接回答的名字、设备自己的加密 DNS 不会出现（见「说明」）。
      </LogEmpty>
    );
  if (j.code === "no_socket")
    return (
      <LogEmpty id="dns-log" state="not-running" title="解析日志服务没有运行，读不到记录" action={<LinkButton to={href("deploy")}>去部署页</LinkButton>}>
        {j.message || "网关上没有运行中的解析日志服务。"} 解析不受影响，只是这段时间的查询没有被记录；它随网关安装启动。
      </LogEmpty>
    );
  return (
    <LogEmpty id="dns-log" state="unreadable" title="读不到网关上的解析日志">
      {j.message || "宿主执行通道没有回答。"} 日志在网关本机，面板只能经宿主代理读取；通道恢复后刷新。
    </LogEmpty>
  );
}

function DataSections({ v, clearTick, askClear }: { v: DNSLogView; clearTick: number; askClear: AskClear }) {
  // clearTick changes after every clear attempt: both lists are read again,
  // so what a clear could not delete stays on the page.
  const devs = useApi(() => api.getDNSLogDevices(), [clearTick]);
  const [device, setDevice] = useState("");
  const [result, setResult] = useState("");
  const [group, setGroup] = useState("");
  const [range, setRange] = useState("all");
  const [text, setText] = useState("");
  const [cursors, setCursors] = useState<number[]>([]);
  const before = cursors.length > 0 ? cursors[cursors.length - 1] : 0;
  const query: DNSLogQuery = useMemo(() => {
    const h = RANGES.find((x) => x.value === range)?.hours ?? 0;
    return {
      device: device || undefined,
      result: result || undefined,
      group: group || undefined,
      from: sinceHours(h),
      text: text.trim() || undefined,
      before: before || undefined,
      limit: 50,
    };
  }, [device, result, group, range, text, before]);
  const recs = useApi(() => api.getDNSLogJournal(query), [JSON.stringify(query), clearTick]);
  useEffect(() => setCursors([]), [clearTick]);
  const j = devs.data;
  const sum = j?.summary;
  const stats = sum?.stats ?? recs.data?.page?.stats;
  const groups = j?.groups ?? v.groups ?? [];
  const labels = useMemo(() => new Map((j?.labels ?? recs.data?.labels ?? []).map((l) => [l.address, l.label])), [j?.labels, recs.data?.labels]);
  const ctx: Ctx = { groups, qtypes: v.qtypes ?? {}, labels };
  const rows: DeviceRow[] = (sum?.devices ?? []).map((d) => ({ ...d, label: labels.get(d.device) }));
  const page = recs.data?.page;
  const reset = () => setCursors([]);
  const slow = (v.bounds.slow_empty_ms / 1000).toString();
  const clear = () =>
    askClear(
      "清空解析日志",
      `立即删除网关上全部 ${stats?.records ?? ""} 条解析记录，连同轮转副本和解析器审计文件的内容，不能恢复。${v.setting.enabled ? "解析日志保持打开，之后的查询照常记录。" : ""}设备备注名保留在面板里。`,
    );
  const filtered = !!(device || result || group || text.trim() || range !== "all");
  return (
    <>
      <Section
        title="按设备汇总"
        extra={
          <LogToolbar
            stats={stats ? <LogStats count={stats.records} used={stats.bytes} max={stats.max_bytes} oldest={stats.oldest} extra={[stats.dropped > 0 && `写不过来丢弃 ${stats.dropped} 条`]} /> : null}
            onRefresh={() => {
              void devs.reload();
              void recs.reload();
            }}
            onClear={clear}
            clearDisabled={!j?.available}
          />
        }
      >
        <Space direction="vertical" style={{ width: "100%" }} data-testid="dns-log-devices">
          {devs.error ? <ApiErrorAlert error={devs.error} onRetry={() => void devs.reload()} /> : null}
          {sum?.truncated ? <Note inline>设备太多，只列出最近出现的 {rows.length} 个。</Note> : null}
          {!j ? (
            devs.error ? null : (
              <Skeleton active paragraph={{ rows: 3 }} />
            )
          ) : j.available && rows.length > 0 ? (
            <DeviceSummary
              rows={rows}
              groups={groups}
              onOpen={(d) => {
                setDevice(d);
                reset();
              }}
            />
          ) : (
            <JournalEmpty j={j} />
          )}
        </Space>
      </Section>
      {j?.available ? (
        <Section title="查询记录">
          <Space direction="vertical" style={{ width: "100%" }} data-testid="dns-log-records">
            <LogToolbar
              testId="dns-log-filters"
              filters={
                <>
              <Select
                aria-label="设备"
                value={device}
                onChange={(x) => {
                  setDevice(x);
                  reset();
                }}
                className="input-w240"
                options={[
                  { value: "", label: "全部设备" },
                  ...rows.map((d) => ({ value: d.device, label: d.label ? `${d.label}（${d.device}）` : d.device })),
                  ...(device && !rows.some((d) => d.device === device) ? [{ value: device, label: device }] : []),
                ]}
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
              <Input
                aria-label="按名字搜索"
                value={text}
                maxLength={64}
                placeholder="名字包含…"
                onChange={(e) => {
                  setText(e.target.value);
                  reset();
                }}
                className="input-w200"
              />
              <Select
                aria-label="结果"
                value={result}
                onChange={(x) => {
                  setResult(x);
                  reset();
                }}
                className="input-w240"
                options={[
                  { value: "", label: "全部结果" },
                  { value: "answered", label: "有应答" },
                  { value: "no_answer", label: `无应答（${slow} 秒内返回）` },
                  { value: "no_answer_slow", label: "无应答且慢（多半是失败或超时）" },
                  { value: "no_answer_any", label: "全部无应答" },
                ]}
              />
              <Select
                aria-label="解析组"
                value={group}
                onChange={(x) => {
                  setGroup(x);
                  reset();
                }}
                className="input-w200"
                options={[{ value: "", label: "全部解析组" }, ...groups.map((g) => ({ value: g.group, label: g.label }))]}
              />
                </>
              }
            />
            <Note inline>审计行里没有应答码：「名字不存在」和「上游失败」只能按耗时分成「无应答」和「无应答且慢」（{slow} 秒为界），不是确定的结论。</Note>
            {recs.error ? <ApiErrorAlert error={recs.error} onRetry={() => void recs.reload()} /> : null}
            {recs.data && !recs.data.available ? (
              <Typography.Text type="warning" data-testid="dns-log-records-problem">
                {recs.data.message || "读不到查询记录。"}
              </Typography.Text>
            ) : null}
            <QueryTable
              records={page?.records ?? []}
              ctx={ctx}
              empty={page ? (filtered ? "没有符合筛选条件的查询：放宽设备、时间、名字、结果或解析组" : "还没有查询记录") : "读取中…"}
            />
            <LogPager
              cursors={cursors}
              setCursors={setCursors}
              next={page?.next_before}
              noun="记录"
              matched={
                page ? (
                  <span data-testid="dns-log-matched">
                    共 {page.matched} 条查询符合{cursors.length > 0 ? `（第 ${cursors.length + 1} 页）` : ""}
                  </span>
                ) : null
              }
            />
          </Space>
        </Section>
      ) : null}
    </>
  );
}

/** Nothing is collected: say which state this is and how to get data. */
function NotCollecting({ v, onClear }: { v: DNSLogView; onClear: () => void }) {
  const leftover = v.runtime.available && v.runtime.data_bytes > 0;
  const clear = leftover ? (
    <Button danger onClick={onClear}>
      清空网关上留下的数据
    </Button>
  ) : undefined;
  if (v.setting.enabled)
    return (
      <LogEmpty
        id="dns-log"
        state="not-installed"
        title="解析日志已保存为打开，但还没有安装到网关"
        action={
          <LinkButton to={href("deploy")} type="primary">
            去部署页安装
          </LinkButton>
        }
      >
        安装后才开始记录。
      </LogEmpty>
    );
  if (!v.capability.available)
    return (
      <LogEmpty id="dns-log" state="unavailable" title="解析日志没有开启，这台网关现在也不能打开" action={clear}>
        原因和处理办法见上面的「开关与状态」。条件满足之前没有任何查询被记录。
      </LogEmpty>
    );
  return (
    <LogEmpty id="dns-log" state="not-enabled" title="解析日志没有开启" action={clear}>
      默认关闭：日志的内容就是设备查询的名字，所以必须由你明确打开。在上面的「开关与状态」里打开并确认，再到部署页对网关预检 → 确认 → 安装，之后设备的查询才会记在这里。
    </LogEmpty>
  );
}

/** Opens the confirmation of a clear (title, consequence) and runs it. */
type AskClear = (title: string, consequence: string) => void;

/** What a clear left on the gateway and why. */
interface ClearLeft {
  residual: DNSLogClearResidual;
  errors: DNSLogClearError[];
  /** The clear asked from this page was not complete, but the gateway's state no longer reports anything left. */
  gone?: boolean;
}

const CLEAR_PART: Record<string, string> = { journal: "结构化日志", raw: "审计目录" };
const CLEAR_CAUSE: Record<string, string> = { permission: "权限不足", read_only: "文件系统只读", busy: "文件被占用", no_space: "空间或配额不足", io: "磁盘读写错误" };

/** One failure of a clear in plain words (counts and fixed words; the gateway sends no path). */
export function clearErrorText(e: DNSLogClearError): string {
  const what = e.op === "readdir" ? "目录读取失败" : e.op === "lstat" ? `${e.count} 个文件的状态读取失败` : e.op === "truncate" ? "审计文件截断失败" : e.op === "write" ? "清除标记写入失败" : `${e.count} 个文件删除失败`;
  return `${CLEAR_PART[e.part] ?? "解析日志"}${what}（${CLEAR_CAUSE[e.cause] ?? "文件系统错误"}）`;
}

/** What is still on the gateway, in counts. */
export function clearResidualText(r: DNSLogClearResidual): string[] {
  const out: string[] = [];
  if (r.segments > 0 || r.records > 0 || r.bytes > 0) out.push(`结构化日志 ${r.segments} 个分段、${r.records} 条记录（${bytes(r.bytes)}）`);
  if (r.raw_files > 0 || r.raw_bytes > 0) out.push(`审计目录 ${r.raw_files} 个文件（${bytes(r.raw_bytes)}）`);
  if (r.unknown) out.push("有目录或文件读不到，留下的可能比数到的多");
  return out;
}

/**
 * The clear did not remove everything: what is left, why, and the retry.
 * Never collapsed and never replaced by a success: it stays until a clear
 * completes or the gateway reports nothing left.
 */
function ClearResidualAlert({ left, failed, onRetry }: { left: ClearLeft; failed?: string; onRetry: () => void }) {
  const parts = clearResidualText(left.residual);
  return (
    <Alert
      type="warning"
      showIcon
      role="alert"
      data-testid="dns-log-clear-residual"
      message="解析日志没有全部清除"
      description={
        <Space direction="vertical" size={4}>
          {left.gone ? (
            <span data-testid="dns-log-clear-left">上一次清空没有确认全部完成；网关现在没有报告残留。再清空一次可以确认。</span>
          ) : (
            <span data-testid="dns-log-clear-left">
              {parts.length > 0 ? `网关上还留着：${parts.join("；")}。` : "网关没有确认全部清除。"}
              留下的结构化记录没有被删除，仍然会出现在下面的记录里。
            </span>
          )}
          {left.errors.length > 0 ? <span data-testid="dns-log-clear-why">原因：{left.errors.map(clearErrorText).join("；")}。</span> : null}
          {failed ? <span data-testid="dns-log-clear-failed">最近一次清空没有执行：{failed}</span> : null}
          <Button danger size="small" onClick={onRetry}>
            重试清空
          </Button>
        </Space>
      }
    />
  );
}

export default function DNSLogsPage() {
  const { route, navigate } = useRouter();
  const related = relatedOf(route.query);
  const view = useApi(() => api.getDNSLog(), []);
  const confirm = useConfirmDanger();
  const [clearErr, setClearErr] = useState<api.ApiError | null>(null);
  // lastLeft: what the last clear asked from this page left (null: it
  // completed, or none was asked). clearTick: bumped after every attempt.
  const [lastLeft, setLastLeft] = useState<ClearLeft | null>(null);
  const [clearTick, setClearTick] = useState(0);
  const v = view.data;
  const b = v?.bounds;
  const collecting = v ? v.installed.enabled || !v.installed.known || v.runtime.present : false;
  const runClear = async () => {
    setClearErr(null);
    try {
      await api.clearDNSLog();
      setLastLeft(null);
    } catch (e) {
      const left = api.dnsClearLeft(e);
      if (left) setLastLeft(left);
      else setClearErr(e instanceof api.ApiError ? e : new api.ApiError(0, {}));
    }
    // Whatever happened, read the gateway again: the page shows what is
    // there now, not what the clear was meant to do.
    setClearTick((n) => n + 1);
    await view.reload();
  };
  const askClear: AskClear = (title, consequence) => confirm({ title, consequence, okText: "清空", onOk: runClear });
  const clearLeftover = () => askClear("清空解析日志留下的数据", "立即删除网关上解析日志留下的全部记录、轮转副本和审计文件的内容，不能恢复。");
  // The residue to show. The gateway's own state comes first (it survives a
  // reload and a restart of the reader); what the last clear answered adds
  // the reasons, and stands alone when no reader runs to report a state.
  // An incomplete clear asked from this page is never dropped silently:
  // when the gateway no longer reports anything left, the warning says so
  // and stays until a clear completes.
  const serverLeft = v?.runtime.clear_residual ?? null;
  const stillThere = !v || !v.runtime.available || (v.runtime.present ? !!serverLeft : v.runtime.data_bytes > 0);
  const left: ClearLeft | null = lastLeft ? { residual: serverLeft ?? lastLeft.residual, errors: lastLeft.errors, gone: !stillThere } : serverLeft ? { residual: serverLeft, errors: [] } : null;
  const retryClear = () => askClear("重试清空解析日志", "再次删除网关上的全部解析记录、轮转副本和解析器审计文件的内容，不能恢复。上一次没有删掉的数据会再删一次。");
  return (
    <Page title="解析日志">
      <div className="log-page">
        <Help title="记录范围与保存说明">
          <LogIntro
            id="dns-log"
            records="网关上的 SmartDNS 应答的每一次查询：时间、发起查询的设备地址（能取到时带 MAC）、查询的名字和类型、有没有应答、由哪个解析组应答、耗时和应答里的地址条数。"
            excludes="被网关解析器的规则直接回答的名字（例如屏蔽的 DoH 域名）、各出口节点上的查询、不经过网关解析器的查询（设备自己的加密 DNS）；应答的具体地址和应答码也不保存，所以「名字不存在」和「上游失败」只能按耗时区分。"
            keep={
              b
                ? `最近 ${ageText(b.max_age_s)}、最多 ${b.max_records} 条、磁盘上不超过 ${bytes(b.disk_bytes)}，先到的上限生效；关闭并安装成功后全部删除。`
                : "最近 24 小时、最多 50000 条，并有磁盘字节上限，先到的上限生效；关闭并安装成功后全部删除。"
            }
            where="只在网关本机的 /var/lib/meridian-dnslog，不进入拓扑、快照、导出、诊断信息或面板自己的日志。"
            who="只有网关上的 root；面板只经宿主代理的固定只读请求读取，持有面板口令的人能在这一页看到。必须明确打开才会记录。"
          />
        </Help>
        {v ? (
          <Help title="记录范围与保存">
            <ScopeLists
              testId="dns-log-scope"
              lists={[
                ["记录什么", v.scope.covered],
                ["不在日志里", v.scope.not_covered],
                ["结果怎么分", v.scope.results],
                ["保存在哪里、保留多久", v.scope.storage],
                ["打开和关闭", v.scope.switch],
                ["设备身份与关联", v.scope.identity],
              ]}
            />
          </Help>
        ) : null}
        {related ? (
          <Section title="来自连接日志的跳转">
            <RelatedPanel<DNSLogRecord>
              id="dns-log"
              query={related}
              load={api.getSniffJournalRelated}
              what="查询"
              source="连接记录"
              maxWindow={b?.related_window_max_s || 600}
              defaultWindow={b?.related_window_default_s || 120}
              onClose={() => navigate(href("dns-log"))}
            >
              {(rv) => <QueryTable records={rv.records ?? []} ctx={{ groups: v?.groups ?? [], qtypes: v?.qtypes ?? {}, labels: new Map() }} mac />}
            </RelatedPanel>
          </Section>
        ) : null}
        {view.error ? <ApiErrorAlert error={view.error} onRetry={() => void view.reload()} /> : null}
        {clearErr && !left ? <ApiErrorAlert error={clearErr} onClose={() => setClearErr(null)} /> : null}
        {left ? <ClearResidualAlert left={left} failed={clearErr?.message} onRetry={retryClear} /> : null}
        {!v ? (
          view.error ? null : (
            <Skeleton active paragraph={{ rows: 6 }} />
          )
        ) : (
          <>
            <SwitchSection v={v} onView={(nv) => view.setData(nv)} reload={() => void view.reload()} loading={view.loading} />
            {collecting ? (
              <DataSections v={v} clearTick={clearTick} askClear={askClear} />
            ) : (
              <Section title="查询记录">
                <NotCollecting v={v} onClear={clearLeftover} />
              </Section>
            )}
          </>
        )}
      </div>
    </Page>
  );
}
