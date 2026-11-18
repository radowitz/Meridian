// 按域名嗅探: the gateway's name-sniffing TCP forwarder. The setting (saved
// into the topology, effective at the next gateway install), what it
// decides by name and what stays address-only, and the forwarder's health
// and recent decisions read from the gateway through the host agent. Names
// appear only when recording is on.
//
// 设备连接日志: the forwarder's bounded journal on the gateway has its own
// page (ConnectionLogsPage, #/conn-log); this card links to it and keeps the
// switch of name recording (with what turning it on or off does). The words
// both share (results, how a connection ended, reasons, targets) are here.
//
// One final record per connection, written when it ends (ResultCell: the
// result, how it ended and why).
//
// "Running" is not "usable": the card shows the unit's state and, apart
// from it, whether the forwarder's paths work — its last self-check of the
// installed rules (each target's resolver reached through the target's own
// mark and tunnel), per-target recent failures, the sniff_denied counter
// (and whether it grows) and sniff_wg_outer, and a plain message when
// failures concentrate on the tunnel targets while direct works.

import { Alert, Button, Checkbox, Input, Space, Switch, Typography } from "antd";
import { useEffect, useState } from "react";
import * as api from "./api";
import { href, useOptionalRouter } from "./state";
import type { SniffDiagnosis, SniffRecord, SniffSettings, SniffTargetDiag, SniffView } from "./types";
import {
  ApiErrorAlert,
  DataTable,
  EllipsisText,
  Facts,
  KV,
  Link,
  LinkButton,
  Mono,
  SafetyNotice,
  Section,
  StatusReason,
  StatusTag,
  TimeText,
  bytes,
  useApi,
  useConfirmDanger,
  type FactItem,
  type StatusKind,
  Note,
} from "./ui";

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
  name_unresolved: "名字解析不到，按地址",
};

/** The accepted socket's mark as the forwarder read it (internal/sniff MarkOK …). */
export const SNIFF_MARK: Record<string, string> = {
  ok: "带接管位",
  without_bit: "缺接管位",
  read_failed: "读取失败",
  unknown_target: "不在目标表里",
};

/** Why a name gave no address (ConnRecord.name_rule.error). */
export const NAME_ERROR: Record<string, string> = {
  nxdomain: "名字不存在",
  no_address: "没有可用地址",
  resolver_failed: "解析器全部失败",
  timeout: "超过解析时限",
};

/** Plain words for a connection's result (internal/sniff; one final record per connection). */
export const RESULT: Record<string, string> = {
  ok: "成功",
  no_response: "连上后无回应",
  relay_failed: "连上后被重置 / 出错",
  shutdown: "服务停止时中断",
  active: "正在转发",
  rejected: "拒绝规则",
  resolve_failed: "目标没有解析器（失败关闭）",
  dial_failed: "连接失败",
  unknown_mark: "分类标记不在目标表里（失败关闭）",
  mark_missing: "分类标记无法确认（失败关闭）",
  unknown_target: "目标未知",
  orig_dst_failed: "读不到原目的地址",
  client_closed: "客户端关闭",
  loop: "环路",
  bad_destination: "目的地址无效",
  upstream_write_failed: "上游写入失败（旧记录）",
};

/** How a relayed connection ended (ConnRecord.end). */
export const SNIFF_END: Record<string, string> = {
  client_closed: "客户端关闭",
  upstream_closed: "上游关闭",
  client_reset: "客户端重置",
  upstream_reset: "上游重置",
  client_error: "客户端读写出错",
  upstream_error: "上游读写出错",
  idle_timeout: "空闲超时",
  shutdown: "服务停止",
};

/** The bounded failure class (ConnRecord.reason): a dial's error class, or a relay's read_/write_ class. */
const ERR_CLASS: Record<string, string> = {
  timeout: "超时",
  refused: "被拒绝",
  unreachable: "网络不可达",
  no_route: "没有路由",
  reset: "被重置",
  af_unavailable: "地址族不可用",
  denied: "被本机拒绝",
  other: "其它错误",
};

/** A reason in plain words: "超时", "读：被重置", "写入停滞". */
export function reasonText(r?: string): string {
  if (!r) return "";
  if (r === "write_stalled") return "写入停滞";
  const m = /^(read|write)_(.+)$/.exec(r);
  if (m) return `${m[1] === "read" ? "读" : "写"}：${ERR_CLASS[m[2]] ?? m[2]}`;
  return ERR_CLASS[r] ?? r;
}

/** Duration in plain words: 850 毫秒, 12 秒, 3 分 5 秒, 2 小时 4 分. */
export function durationText(ms?: number): string {
  if (ms === undefined || ms === null) return "—";
  if (ms < 1000) return `${ms} 毫秒`;
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s} 秒`;
  if (s < 3600) return `${Math.floor(s / 60)} 分 ${s % 60} 秒`;
  return `${Math.floor(s / 3600)} 小时 ${Math.floor((s % 3600) / 60)} 分`;
}

/** Classes that count as failures (internal/sniff IsFailureClass). */
const FAILURE_RESULTS = new Set(["no_response", "relay_failed", "shutdown", "resolve_failed", "dial_failed", "unknown_mark", "mark_missing", "unknown_target", "orig_dst_failed", "loop", "bad_destination", "upstream_write_failed"]);

/** One cell: the result, and for a relayed connection how it ended and why. */
export function ResultCell({ r }: { r: SniffRecord }) {
  const end = r.end ? SNIFF_END[r.end] ?? r.end : "";
  const why = [end, reasonText(r.reason)].filter(Boolean).join("，");
  if (r.result === "ok" && !r.end)
    return (
      <span className="inline-status" data-testid="sniff-result">
        <StatusTag kind="unverified">结束情况未知</StatusTag>
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
          旧版本记录：连上时就记了
        </Typography.Text>
      </span>
    );
  const label = r.result === "ok" && r.why === "name_unresolved" ? "成功（按地址）" : RESULT[r.result] ?? r.result;
  return (
    <span className="inline-status" data-testid="sniff-result">
      {r.result === "ok" ? (
        <StatusTag kind="ok">{label}</StatusTag>
      ) : r.result === "active" ? (
        <StatusTag kind="running">{label}</StatusTag>
      ) : FAILURE_RESULTS.has(r.result) ? (
        <Typography.Text type="warning">{label}</Typography.Text>
      ) : (
        <Typography.Text type="secondary">{label}</Typography.Text>
      )}
      {why ? (
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
          {why}
        </Typography.Text>
      ) : null}
    </span>
  );
}

/** The paths' state as a tag kind and label (sniff_diag.go). */
export const SNIFF_PATHS: Record<string, { kind: StatusKind; label: string }> = {
  usable: { kind: "ok", label: "路径可用" },
  degraded: { kind: "attention", label: "部分目标不通" },
  failing: { kind: "failed", label: "路径不通" },
  unchecked: { kind: "unverified", label: "路径未自检" },
};

/** Plain words for the self-check's probe outcomes (internal/sniff/selfcheck.go). */
export const SNIFF_OUTCOME: Record<string, string> = {
  answer: "有回答",
  nxdomain: "NXDOMAIN（路径可用）",
  rcode: "错误码（路径可用）",
  connected: "TCP 已建立",
  timeout: "超时",
  send_refused: "发送被本机拒绝",
  refused: "被对端拒绝",
  unreachable: "不可达",
  malformed: "回答不符",
  error: "出错",
  not_run: "未来得及检查",
};

const TRIGGER: Record<string, string> = {
  start: "启动时",
  reload: "重新载入后",
  request: "按请求",
  periodic: "定时",
};

/** What turning name recording on records, for how long, where, and how to clear it (the save confirmation). */
export const NAMES_ON_TEXT =
  "开启后，嗅探服务把读到的名字（TLS 的 SNI、HTTP 的 Host，带 ECH 时是明文的外层名）和目的地址一起写进网关上的设备连接日志：只在网关本机（/var/lib/meridian-sniff，只有 root 和嗅探服务能读），保留最近 24 小时、最多 50000 条，不进入拓扑、快照、导出或任何日志；面板的「清空日志」随时删除全部记录。保存后经预检—确认—安装生效。";
/** What turning it off does to the names already recorded (the save confirmation). */
export const NAMES_OFF_TEXT =
  "关闭后，安装时嗅探服务重启，删除设备连接日志里已有的全部名字（改写日志文件，其余字段保留）；此后的记录不再保存任何名字。在安装之前，已记录的名字仍在网关上，可以用「清空日志」立即删除。保存后经预检—确认—安装生效。";

/** Plain words for the journal's result classes (internal/sniff RecordClass). */
export const JOURNAL_CLASS: Record<string, string> = {
  ok: "成功",
  rejected: "被规则拒绝",
  resolve_failed: "解析失败",
  dial_failed: "连接失败",
  relay_failed: "连上后被重置 / 出错",
  no_response: "连上后无回应",
  client_closed: "客户端关闭",
  mark: "分类标记问题",
  shutdown: "服务停止时中断",
  ended_unknown: "结束情况未知（旧记录）",
  other: "其它失败",
  failed: "全部失败",
  name_unresolved: "名字解析不到（已按地址）",
};

/** Classes that are neither success nor failure (the device list's colours). */
export const NEUTRAL_CLASSES = new Set(["rejected", "client_closed", "ended_unknown"]);

/** A target name in plain words: direct / group / exit / reject. */
export function targetText(t?: string): string {
  if (!t) return "—";
  if (t === "direct") return "直连";
  if (t === "reject") return "拒绝";
  if (t.startsWith("group:")) return `地区组 ${t.slice(6)}`;
  if (t.startsWith("exit:")) return `出口 ${t.slice(5)}`;
  return t;
}

/** Overview tile body: running state in one line. */
export function SniffSummary({ v }: { v: SniffView }) {
  if (!v.setting.enabled) {
    return v.runtime.present ? (
      <StatusTag kind="attention">已关闭，网关上仍在运行</StatusTag>
    ) : (
      <Typography.Text type="secondary">未开启：全部按目的地址分类</Typography.Text>
    );
  }
  const h = v.runtime.health;
  if (!v.runtime.available) return <StatusTag kind="unverified">{v.runtime.message ?? "读不到状态"}</StatusTag>;
  if (!v.runtime.present || !h) return <StatusTag kind="failed">没有运行：被接管的连接会失败</StatusTag>;
  const c = h.counters ?? {};
  const byName = c.decided_by_name ?? 0;
  const byAddr = Object.entries(c)
    .filter(([k]) => k.startsWith("decided_by_address_"))
    .reduce((n, [, x]) => n + x, 0);
  const paths = SNIFF_PATHS[v.runtime.diagnosis?.paths ?? "unchecked"] ?? SNIFF_PATHS.unchecked;
  return (
    <Space size={4} wrap>
      {h.ready ? <StatusTag kind="ok">运行中</StatusTag> : <StatusTag kind="failed">未就绪</StatusTag>}
      <StatusTag kind={paths.kind} title={v.runtime.diagnosis?.message}>
        {paths.label}
      </StatusTag>
      {h.last_reload_error ? (
        <StatusTag kind="attention" title={h.last_reload_error}>
          上次重载失败
        </StatusTag>
      ) : null}
      <Typography.Text type="secondary" style={{ fontSize: 12 }}>
        按名字 {byName} · 按地址 {byAddr} · 当前连接 {h.active}
        {h.relaying !== undefined ? `（转发中 ${h.relaying}）` : ""}
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
  const confirm = useConfirmDanger();
  const save = async () => {
    setError(null);
    const list = (s: string) =>
      s
        .split(/[,，\s]+/)
        .map((x) => x.trim())
        .filter(Boolean);
    const body: SniffSettings = {
      enabled,
      ports: list(ports).map(Number),
      ech_public_names: list(ech),
      record_names: record,
    };
    const put = async () => {
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
    if (record === cur.record_names) return put();
    // Turning name recording on or off: say exactly what happens, then save (it takes effect with the next install).
    confirm({
      title: record ? "开启名字记录" : "关闭名字记录",
      consequence: <div data-testid="sniff-names-confirm">{record ? NAMES_ON_TEXT : NAMES_OFF_TEXT}</div>,
      okText: record ? "保存并在下次安装时开启" : "保存并在下次安装时关闭",
      danger: record,
      onOk: put,
    });
  };
  return (
    <Space direction="vertical" style={{ width: "100%" }}>
      <Space wrap>
        <Switch checked={enabled} onChange={setEnabled} aria-label="开启按域名嗅探" />
        <Typography.Text>开启按域名嗅探（下次安装到网关时生效）</Typography.Text>
      </Space>
      <Space wrap>
        <Typography.Text>接管的 TCP 端口</Typography.Text>
        <Input value={ports} onChange={(e) => setPorts(e.target.value)} aria-label="嗅探端口" className="input-w200" />
        <Typography.Text>ECH 公共名（按地址判断）</Typography.Text>
        <Input value={ech} onChange={(e) => setEch(e.target.value)} aria-label="ECH 公共名" className="input-w240" />
      </Space>
      <Checkbox checked={record} onChange={(e) => setRecord(e.target.checked)}>
        记录嗅探读到的名字
      </Checkbox>
      <Note inline>只存在网关本机、保留 24 小时、可随时清空；名字属于敏感信息，默认不记录。保存后经预检、确认、安装生效。</Note>
      <Button type="primary" onClick={() => void save()} loading={busy}>
        保存设置
      </Button>
      {error ? <ApiErrorAlert error={error} /> : null}
    </Space>
  );
}

function targetCheck(t: SniffTargetDiag) {
  switch (t.check) {
    case "ok":
      return <StatusReason kind="ok" label="可达" />;
    case "failed":
      return <StatusReason kind="failed" label="不通" reason={t.check_reason} />;
    case "unchecked":
      return <StatusReason kind="neutral" label="未检查" reason={t.check_reason} />;
  }
  return <StatusReason kind="unverified" label="无当前自检" />;
}

/** The one primary alert of the runtime part: the read problem, else the paths, else a failed reload. */
function primaryAlert(v: SniffView): { type: "error" | "warning" | "info"; text: string } | null {
  const d = v.runtime.diagnosis;
  if (v.runtime.code && v.setting.enabled) return { type: "warning", text: v.runtime.message ?? "" };
  if (d?.message && d.paths !== "usable")
    return {
      type: d.paths === "failing" ? "error" : d.paths === "degraded" ? "warning" : "info",
      text: d.message,
    };
  if (v.runtime.health?.last_reload_error)
    return {
      type: "warning",
      text: "上次重载失败，仍用旧规则：" + v.runtime.health.last_reload_error,
    };
  return null;
}

/** The forwarder's paths: last self-check, counters, per-target failures. */
export function SniffPaths({ d, onCheck, busy }: { d: SniffDiagnosis; onCheck?: () => void; busy?: boolean }) {
  const sc = d.self_check;
  const p = SNIFF_PATHS[d.paths] ?? SNIFF_PATHS.unchecked;
  const minutes = Math.round((d.window_s || 900) / 60);
  const denied = d.denied;
  return (
    <div data-testid="sniff-paths" className="sniff-paths">
      <Space wrap>
        <Typography.Text strong>路径自检</Typography.Text>
        <StatusTag kind={p.kind}>{p.label}</StatusTag>
        {onCheck ? (
          <Button size="small" onClick={onCheck} loading={busy}>
            立即自检
          </Button>
        ) : null}
      </Space>
      <Note>{"“运行中”只说明服务进程在；自检由转发服务自己、以它真实的身份和出站限制，向每个目标的解析器问一个固定问题（根域 NS，不涉及任何网站），默认目标再经它的隧道建一次 TCP 连接。"}{" "}
        任何格式正确的回答（包括 NXDOMAIN 和错误码）都说明这个目标的路径当时是通的：查询带着目标的标记出去，经过出站限制、隧道（含 WireGuard
        外层包），回答回来了；超时、本机拒绝发送、不可达都不算。 自检只证明当时各目标的解析器可达、默认目标的隧道能建 TCP
        连接，不证明某个网站能打开。安装时默认目标自检不通过会回到上一版本；其它目标不通只记为告警。
      </Note>
      <div className="kv-list">
        <KV label="最近自检">
          {sc ? (
            <span>
              <TimeText value={sc.finished_at} /> · {TRIGGER[sc.trigger] ?? sc.trigger} · 第 {sc.generation} 代规则 · {sc.duration_ms} 毫秒
              {d.current ? null : <span className="muted">不属于当前安装的规则</span>}
            </span>
          ) : (
            "还没有"
          )}
        </KV>
        <KV label="默认目标">
          {d.verdict ? (
            <StatusReason
              kind={d.verdict.code === "ok" ? "ok" : d.verdict.code === "default_failed" ? "failed" : "unverified"}
              label={d.verdict.default || sc?.default || "—"}
              reason={d.verdict.code === "ok" ? null : d.verdict.reason}
            />
          ) : (
            "—"
          )}
        </KV>
        <KV label="出站拦截 sniff_denied">
          {denied?.present ? (
            <span data-testid="sniff-denied">
              {denied.packets} 个包
              {denied.delta === undefined ? (
                <Typography.Text type="secondary">（增长未知：还没有更早的读数）</Typography.Text>
              ) : denied.growing ? (
                <StatusTag kind="failed">
                  {denied.since_s} 秒内 +{denied.delta}，在增长
                </StatusTag>
              ) : (
                <Typography.Text type="secondary">（{denied.since_s} 秒内没有增长）</Typography.Text>
              )}
            </span>
          ) : (
            <StatusTag kind="unverified">读不到</StatusTag>
          )}
        </KV>
        <KV label="WireGuard 外层包 sniff_wg_outer">
          {d.wg_outer?.present ? `${d.wg_outer.packets} 个包已放行` : <StatusTag kind="failed">计数器不存在：规则缺少外层包放行</StatusTag>}
        </KV>
      </div>
      {(d.targets ?? []).length > 0 ? (
        <DataTable<SniffTargetDiag>
          size="small"
          rowKey={(r) => r.target}
          dataSource={d.targets ?? []}
          pageSize={20}
          secondary={(r) =>
            r.last_failure_at ? (
              <Facts
                items={[
                  ["最近一次失败", <TimeText key="t" value={r.last_failure_at} />],
                  ["原因", r.last_failure ?? "—"],
                ]}
              />
            ) : null
          }
          columns={[
            {
              title: "目标",
              kind: "ellipsis",
              width: 150,
              render: (_, r) => (
                <span className="inline-status">
                  <EllipsisText mono text={r.target} />
                  {r.default ? <span className="muted">默认</span> : null}
                </span>
              ),
            },
            {
              title: "自检",
              kind: "flex",
              width: 190,
              render: (_, r) => targetCheck(r),
            },
            {
              title: `${minutes} 分钟内解析失败`,
              kind: "fixed",
              width: 110,
              render: (_, r) => r.recent_resolve_failed,
            },
            {
              title: "连接失败",
              kind: "fixed",
              width: 80,
              render: (_, r) => r.recent_dial_failed,
            },
            {
              title: "连上后失败",
              kind: "fixed",
              width: 90,
              render: (_, r) => r.recent_relay_failed ?? 0,
            },
            {
              title: "成功",
              kind: "fixed",
              width: 70,
              render: (_, r) => r.recent_ok,
            },
          ]}
        />
      ) : null}
    </div>
  );
}

/** Rules page section: setting, coverage, health and recent decisions. */
export function SniffSection() {
  const st = useApi(() => api.getSniff(), []);
  const [checking, setChecking] = useState(false);
  const [checkError, setCheckError] = useState<api.ApiError | null>(null);
  const router = useOptionalRouter();
  const wanted = router?.route.query.get("section") === "sniff";
  const v = st.data;
  // `#/rules?section=sniff` (the connection log page's link to the switch of name recording) scrolls here.
  useEffect(() => {
    if (!wanted || !v) return;
    const t = window.setTimeout(() => document.getElementById("sniff")?.scrollIntoView?.({ behavior: "smooth" }), 200);
    return () => window.clearTimeout(t);
  }, [wanted, !!v]);
  const runCheck = async () => {
    setCheckError(null);
    setChecking(true);
    try {
      await api.postSniffSelfCheck();
      await st.reload();
    } catch (e) {
      setCheckError(e instanceof api.ApiError ? e : new api.ApiError(0, {}));
    } finally {
      setChecking(false);
    }
  };
  const alert = v ? primaryAlert(v) : null;
  const recent: SniffRecord[] = v?.runtime.recent?.connections ?? [];
  const names = v?.runtime.recent?.record_names ?? false;
  return (
    <Section title="按域名嗅探（TCP）" id="sniff">
      {st.error ? <ApiErrorAlert error={st.error} /> : null}
      {v ? (
        <Space direction="vertical" style={{ width: "100%" }}>
          <Note>{"开启后，发往接管端口的 TCP 连接按 TLS 的 SNI 或 HTTP 的 Host 在这张有序规则表里匹配。"}{" "}
            局域网和远程接入设备新建的、发往接管端口的 TCP 连接交给网关上的转发服务：它读 TLS 的 SNI 或 HTTP 的 Host，按这张有序规则表从上到下匹配，
            用目标自己的解析器重新解析后经该目标的隧道连出。读不到名字的连接按目的地址分类的结果走，与关闭时相同。
          </Note>
          <Note testId="sniff-dns-link">
            出口的解析器是出口上的 SmartDNS，上游在 <Link to={href("dns")}>解析设置</Link> 里改。
          </Note>
          <SafetyNotice kind="failclosed">转发服务停止或崩溃时，被接管的连接直接失败，不会绕过。</SafetyNotice>
          <SettingForm v={v} onSaved={() => void st.reload()} />
          <div data-testid="sniff-coverage" className="sniff-coverage">
            {(
              [
                ["按名字判断", v.coverage.by_name],
                ["仍按目的地址判断", v.coverage.address_only],
                ["代价与已知误差", v.coverage.costs],
              ] as const
            ).map(([title, list]) => (
              <div key={title} className="sniff-coverage-col">
                <Typography.Text strong>{title}</Typography.Text>
                <ul className="plain-list">
                  {list.map((x) => (
                    <li key={x}>{x}</li>
                  ))}
                </ul>
              </div>
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
          {checkError ? (
            <ApiErrorAlert error={checkError} />
          ) : alert ? (
            <Alert type={alert.type} showIcon message={alert.text} data-testid="sniff-alert" />
          ) : null}
          {v.runtime.diagnosis ? <SniffPaths d={v.runtime.diagnosis} onCheck={() => void runCheck()} busy={checking} /> : null}
          {recent.length > 0 ? (
            <DataTable<SniffRecord>
              size="small"
              rowKey={(r) => r.start + r.source + (r.dest ?? "")}
              dataSource={recent}
              pageSize={20}
              secondary={(r) => (
                <Facts
                  items={[
                    ["来源", <Mono key="s">{r.source}</Mono>],
                    ["判断耗时", `${r.decide_ms ?? "—"} 毫秒`],
                    ["时长", durationText(r.duration_ms)],
                    ["字节（发 / 收）", r.bytes_up || r.bytes_down ? `${bytes(r.bytes_up ?? 0)} / ${bytes(r.bytes_down ?? 0)}` : "—"],
                    ["规则代", String(r.generation ?? "—")],
                    ...(r.name_rule
                      ? ([
                          [
                            "名字的判断",
                            `${r.name_rule.rule_id ?? (r.name_rule.rule_index < 0 ? "名单 / 默认组" : "")} → ${r.name_rule.target ?? ""}（${NAME_ERROR[r.name_rule.error ?? ""] ?? r.name_rule.error ?? ""}，未采用）`,
                          ],
                        ] as FactItem[])
                      : []),
                    ...(r.mark_status
                      ? ([
                          [
                            "套接字标记",
                            <Mono key="m">{`${SNIFF_MARK[r.mark_status] ?? r.mark_status}${r.raw_mark ? ` ${r.raw_mark}` : ""}${r.view === "own_address_view" ? "；已拒绝，规则和目标栏是转发服务自己的地址判断（未采用）" : ""}`}</Mono>,
                          ],
                        ] as FactItem[])
                      : []),
                  ]}
                />
              )}
              columns={[
                {
                  title: "时间",
                  kind: "fixed",
                  width: 100,
                  render: (_, r) => <TimeText value={r.start} />,
                },
                {
                  title: "原目的地址",
                  kind: "ellipsis",
                  width: 150,
                  mono: true,
                  dataIndex: "dest",
                },
                {
                  title: "判断依据",
                  kind: "flex",
                  width: 190,
                  render: (_, r) =>
                    r.sniffed ? (
                      // One line: tag + the name cut with "…" (full text on hover / focus); wraps only inside a phone card.
                      <span className="inline-status sniff-why">
                        <span>按名字</span>
                        {names ? (
                          r.name ? (
                            <EllipsisText className="sniff-name" mono text={r.name} />
                          ) : null
                        ) : (
                          <Typography.Text type="secondary">未记录名字</Typography.Text>
                        )}
                        {r.why === "ech_outer" ? <span className="muted">ECH 明文名</span> : null}
                      </span>
                    ) : (
                      <Space size={2} wrap>
                        <span className="muted">按地址</span>
                        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                          {SNIFF_WHY[r.why ?? ""] ?? r.why}
                        </Typography.Text>
                      </Space>
                    ),
                },
                {
                  title: "规则",
                  kind: "ellipsis",
                  width: 130,
                  render: (_, r) => (r.rule_id ? r.rule_id : r.rule_index < 0 ? "名单 / 默认组" : ""),
                },
                {
                  title: "目标",
                  kind: "ellipsis",
                  width: 130,
                  dataIndex: "target",
                },
                {
                  title: "结果",
                  kind: "flex",
                  width: 170,
                  render: (_, r) => <ResultCell r={r} />,
                },
              ]}
            />
          ) : v.runtime.present ? (
            <Typography.Text type="secondary">还没有结束的连接。</Typography.Text>
          ) : null}
          {(v.runtime.recent?.active_total ?? 0) > 0 ? (
            <Typography.Text type="secondary" style={{ fontSize: 12 }} data-testid="sniff-recent-active">
              另有 {v.runtime.recent?.active_total} 条连接正在转发，结束后才出现在上表和日志里（设备连接日志里按设备列出）。
            </Typography.Text>
          ) : null}
          <Space wrap data-testid="sniff-journal-entry">
            <LinkButton to={href("conn-log")}>查看设备连接日志</LinkButton>
            <Note inline>网关上按设备保存的嗅探连接记录（最近 24 小时），在「连接日志」页按需读取；名字是否记录由上面的选项决定。</Note>
          </Space>
        </Space>
      ) : null}
    </Section>
  );
}
