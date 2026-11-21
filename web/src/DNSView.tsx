// 解析设置 (#/dns): who answers which names, which upstream, which transport
// and from which line the query leaves (compiled plan, GET /api/dns), the
// generated SmartDNS configs (read-only, account values never part of them)
// planned vs installed by digest, the forwarder's per-resolver measurements
// and the fixed exit resolver check. Everything not measured on a host is
// labelled 未验证. The exits' upstream is edited here and takes effect only
// through the deploy page's preflight → install.
//
// The page opens with what the saved setting means right now: without an
// encrypted upstream, every exit asks the built-in public resolvers in
// clear text, and a prominent「设置加密上游」opens the global form. The form
// says in place that the addresses are the operator's to enter, that the
// account identifier is saved apart and masked, and that the certificate
// host name carries the {account} placeholder, with one invented example.

import "./layout_b.css";
import { DNSLocal } from "./DNSLocal";
import { Alert, App as AntApp, Button, Input, InputNumber, Radio, Select, Space, Typography } from "antd";
import { useEffect, useRef, useState, type HTMLAttributes } from "react";
import * as api from "./api";
import type { ApiError } from "./api";
import { href } from "./state";
import type { DNSAccountView, DNSCheckResult, DNSConfigState, DNSExitRow, DNSPathRow, DNSResolverStatus, DNSView, ExitDNSUpstream } from "./types";
import {
  ApiErrorAlert,
  DataTable,
  DataView,
  Facts,
  Fold,
  Help,
  IssueList,
  Link,
  Mono,
  Page,
  Section,
  StatusTag,
  TimeText,
  useAction,
  useApi,
  type DataColumn,
  type FactItem,
  type StatusKind,
  Note,
} from "./ui";

export const TRANSPORT: Record<string, string> = { plain: "明文", dot: "DoT", doh: "DoH", tunnel: "隧道内明文" };

const SCOPE: Record<DNSPathRow["scope"], string> = {
  clients: "客户端",
  domestic: "国内",
  unlisted: "未列名单",
  group: "地区组",
  exit: "出口",
  external_exit: "外部出口",
  reject: "拒绝与广告",
  doh_block: "公共 DoH",
  gateway: "本机",
};

const OUTCOME: Record<string, string> = {
  answer: "有回答",
  nxdomain: "NXDOMAIN（有回答）",
  rcode: "错误码（有回答）",
  timeout: "超时",
  slow: "回答慢（TCP 可达）",
  send_refused: "发送被本机拒绝",
  refused: "被拒绝",
  unreachable: "不可达",
  malformed: "回答不符",
  error: "出错",
  not_run: "未来得及检查",
  not_allowed: "没有发出",
};

const INSTALLED: Record<DNSConfigState["installed"], { kind: StatusKind; label: string }> = {
  same: { kind: "ok", label: "主机上已安装，与计划一致" },
  differs: { kind: "pending", label: "与主机上已安装的不同" },
  not_installed: { kind: "pending", label: "主机上还没有安装" },
  unknown: { kind: "unverified", label: "未知" },
};

const SOURCE: Record<string, string> = { global: "全局设置", own: "本出口单独设置", builtin: "本出口保持内置", default: "未设置（内置）" };

function UpstreamTags({ row }: { row: DNSPathRow }) {
  if (!row.upstreams?.length) return <Typography.Text type="secondary">—</Typography.Text>;
  return (
    <Space direction="vertical" size={2}>
      {row.upstreams.map((u, i) => (
        <Space key={i} size={4} wrap>
          <Typography.Text>{TRANSPORT[u.transport] ?? u.transport}</Typography.Text>
          <Mono>{u.address}</Mono>
          {u.verify ? <Typography.Text type="secondary">{u.verify}</Typography.Text> : null}
        </Space>
      ))}
    </Space>
  );
}

function pathFacts(row: DNSPathRow): FactItem[] {
  const items: FactItem[] = [
    ["应答方", row.answered_by],
    ["上游与传输", <UpstreamTags key="u" row={row} />],
    ["从哪条线路发出", row.egress],
  ];
  // A switch's label is a sentence: its row is stacked (label above the value), so the label wraps instead of widening the label column.
  for (const s of row.switches ?? []) items.push([s.label, s.value || "—", "stacked"]);
  if ((row.notes ?? []).length) items.push(["说明", (row.notes ?? []).join("；")]);
  return items;
}

/** The transports of a plan row in one short phrase ("DoT · 明文"); "—" when nobody upstream is asked. */
function transportsOf(row: DNSPathRow): string {
  const t = [...new Set((row.upstreams ?? []).map((u) => TRANSPORT[u.transport] ?? u.transport))];
  return t.length ? t.join(" · ") : "—";
}

/**
 * One row of the resolution plan: scope, names, who answers and how, on one
 * line; the upstreams, the line it leaves from and the switches on expand.
 * Native <details>: keyboard and phone width for free, content stays in the DOM.
 */
function PathRow({ row }: { row: DNSPathRow }) {
  return (
    <details className="dns-path dns-plan-row" data-testid={`dns-path-${row.scope}${row.id ? `-${row.id}` : ""}`}>
      <summary className="dns-plan-line">
        <span className="dns-plan-name">
          <span className="dns-plan-scope">{SCOPE[row.scope] ?? row.scope}</span>
          {row.label}
        </span>
        <span className="dns-plan-by">{row.answered_by}</span>
        <span className="dns-plan-t">{transportsOf(row)}</span>
      </summary>
      <div className="dns-plan-more">
        <Facts items={pathFacts(row)} />
      </div>
    </details>
  );
}

function CheckResult({ c }: { c?: DNSCheckResult }) {
  if (!c) return <StatusTag kind="unverified">未检查</StatusTag>;
  const ok = c.outcome === "answer" || c.outcome === "nxdomain";
  return (
    <span data-testid={`dns-check-${c.exit_id}`}>
      <StatusTag kind={ok ? "ok" : "failed"}>{`实测：${OUTCOME[c.outcome] ?? c.outcome}${c.rcode ? ` ${c.rcode}` : ""}`}</StatusTag>
      <Typography.Text type="secondary">
        {c.qtype} {c.name} · {c.duration_ms} 毫秒 · <TimeText value={c.checked_at} />
        {c.error ? ` · ${c.error}` : ""}
      </Typography.Text>
    </span>
  );
}

function ConfigRow({ c }: { c: DNSConfigState }) {
  const [text, setText] = useState<string | null>(null);
  const act = useAction();
  const st = INSTALLED[c.installed] ?? INSTALLED.unknown;
  return (
    <div className="dns-row" data-testid={`dns-config-${c.node}`}>
      <Space size={6} wrap>
        <Typography.Text strong>{c.node_name || c.node}</Typography.Text>
        <Mono>{c.path}</Mono>
        {c.installed === "same" ? <span className="state-word">{st.label}</span> : <StatusTag kind={st.kind}>{st.label}</StatusTag>}
        {c.restricted ? <Typography.Text type="secondary">含账户标识（不显示）</Typography.Text> : null}
        <Button size="small" loading={act.busy === "load"} onClick={() => (text === null ? act.run(async () => setText((await api.getDNSConfig(c.node)).text), "load") : setText(null))}>
          {text === null ? "查看原文" : "收起"}
        </Button>
      </Space>
      <div>
        <Typography.Text type="secondary">
          计划摘要 <Mono>{c.planned_sha256.slice(0, 12)}</Mono>
          {c.detail ? ` · ${c.detail}` : ""}
        </Typography.Text>
      </div>
      {act.error ? <ApiErrorAlert error={act.error} onClose={act.clear} /> : null}
      {text !== null ? (
        <pre className="mono-small" style={{ maxHeight: 360, overflow: "auto", whiteSpace: "pre-wrap" }} aria-label={`${c.node} 的 SmartDNS 配置`}>
          {text}
        </pre>
      ) : null}
    </div>
  );
}

function ResolverRow({ r }: { r: DNSResolverStatus }) {
  const p = r.probe;
  return (
    <div className="dns-row" data-testid="dns-resolver">
      <Space size={6} wrap>
        <code className="mono-small">{r.target}</code>
        <Mono>{p.server}</Mono>
        <StatusTag kind={p.reached ? "ok" : "failed"}>{`实测：${OUTCOME[p.outcome] ?? p.outcome}`}</StatusTag>
        <Typography.Text type="secondary">
          {TRANSPORT[p.transport === "udp" ? "plain" : p.transport ?? "plain"] ?? "明文"} · {p.duration_ms} 毫秒
          {p.timeout_ms ? `（最多等 ${p.timeout_ms} 毫秒）` : ""}
        </Typography.Text>
        {p.known_silent ? <span className="status-text" title="查询时排在最后，不再串行等待">已知不应答</span> : null}
      </Space>
      {r.health ? (
        <div>
          <Typography.Text type="secondary">
            应答 {r.health.answered} 次、失败 {r.health.failed} 次（连续 {r.health.consecutive_failures}）
            {r.health.last_answer_at ? (
              <>
                {" "}· 最近一次应答 <TimeText value={r.health.last_answer_at} />
              </>
            ) : (
              " · 本次运行中从未应答"
            )}
          </Typography.Text>
        </div>
      ) : null}
    </div>
  );
}

const EMPTY: ExitDNSUpstream = { protocol: "dot", addresses: [], tls_host_name: "" };

type Proto = "dot" | "doh";

/** The body a form sends for an encrypted upstream: the same normalisation for the global setting and an exit's own. */
export function upstreamBody(proto: Proto, u: ExitDNSUpstream): ExitDNSUpstream {
  return {
    protocol: proto,
    addresses: u.addresses ?? [],
    tls_host_name: u.tls_host_name ?? "",
    port: u.port || undefined,
    path: proto === "doh" ? u.path ?? "" : undefined,
    account_credential: u.account_credential || undefined,
  };
}

/** A masked one-line summary of an upstream ("{account}" shown as the mask; the value is never part of it). */
export function upstreamSummary(u: ExitDNSUpstream | null | undefined, masked: string): string {
  if (!u || u.protocol === "builtin") return "内置公共解析器（明文 53）";
  const host = (u.tls_host_name ?? "").replace("{account}", masked);
  const port = u.port || (u.protocol === "doh" ? 443 : 853);
  const addrs = (u.addresses ?? []).map((a) => (a.includes(":") ? `[${a}]:${port}` : `${a}:${port}`)).join("、");
  if (u.protocol === "doh") return `DoH https://${host}${(u.path ?? "").replace("{account}", masked)}（连接 ${addrs}，证书校验 ${host}）`;
  return `DoT ${addrs}（证书校验 ${host}）`;
}

/**
 * The fields of an encrypted upstream (addresses, TLS host name, DoH path,
 * port, account-identifier credential with an inline write-once create):
 * shared by the global form and every exit's own setting, so both send the
 * same shape and are checked by the same server validation.
 */
function UpstreamFields({
  proto,
  u,
  setU,
  accounts,
  reloadAccounts,
  masked,
}: {
  proto: Proto;
  u: ExitDNSUpstream;
  setU: (u: ExitDNSUpstream) => void;
  accounts: DNSAccountView[];
  reloadAccounts: () => Promise<unknown> | void;
  /** How a saved account identifier is shown everywhere (never its value). */
  masked: string;
}) {
  const act = useAction();
  const [creating, setCreating] = useState(false);
  const [name, setName] = useState("");
  const [value, setValue] = useState("");
  // The typed text is kept as typed (a trailing separator is not eaten); the addresses are parsed from it.
  const [addrText, setAddrText] = useState((u.addresses ?? []).join(", "));
  return (
    <>
      <Help title="上游填写方法"><UpstreamHelp proto={proto} masked={masked} /></Help>
      <Input
        aria-label="上游地址"
        placeholder="上游 IP 地址，最多两个，用逗号分隔（出口直接连接，不先解析名字）"
        value={addrText}
        onChange={(e) => {
          setAddrText(e.target.value);
          setU({ ...u, addresses: e.target.value.split(/[,\s]+/).filter(Boolean) });
        }}
      />
      <Input
        aria-label="TLS 主机名"
        placeholder="证书上的主机名，账户标签写成 {account}，例如 {account}.dns.example.net"
        value={u.tls_host_name ?? ""}
        onChange={(e) => setU({ ...u, tls_host_name: e.target.value.trim() })}
      />
      {proto === "doh" ? (
        <Input aria-label="DoH 路径" placeholder="URL 路径，例如 /dns-query 或 /{account}" value={u.path ?? ""} onChange={(e) => setU({ ...u, path: e.target.value.trim() })} />
      ) : null}
      <InputNumber aria-label="端口" placeholder={proto === "doh" ? "443" : "853"} min={1} max={65535} value={u.port || null} onChange={(v) => setU({ ...u, port: v ?? undefined })} />
      <Space wrap style={{ maxWidth: "100%" }}>
        <Select
          aria-label="账户标识"
          allowClear
          placeholder="账户标识凭据（主机名或路径里用了 {account} 时必选）"
          value={u.account_credential || undefined}
          style={{ width: 360, maxWidth: "100%" }}
          onChange={(v) => setU({ ...u, account_credential: v ?? "" })}
          options={accounts.map((a) => ({ value: a.id, label: a.version ? `${a.name}（版本 ${a.version}）` : a.name }))}
        />
        <Button size="small" onClick={() => setCreating(!creating)} aria-expanded={creating}>
          {creating ? "取消新建" : "新建账户标识"}
        </Button>
      </Space>
      {creating ? (
        <Space wrap data-testid="dns-account-create" style={{ maxWidth: "100%" }}>
          <Input aria-label="新账户标识名称" placeholder="名称" value={name} onChange={(e) => setName(e.target.value)} style={{ width: 160, maxWidth: "100%" }} />
          <Input.Password
            aria-label="新账户标识的值"
            placeholder="账户标识（只写，保存后不再显示）"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            style={{ width: 260, maxWidth: "100%" }}
            autoComplete="off"
          />
          <Button
            disabled={!name || !value}
            loading={act.busy === "create"}
            onClick={() =>
              act.run(async () => {
                const r = await api.createDNSAccount({ name, account: value });
                setValue("");
                setName("");
                setCreating(false);
                await reloadAccounts();
                setU({ ...u, account_credential: r.account.id });
              }, "create")
            }
          >
            保存并选用
          </Button>
        </Space>
      ) : null}
      {act.error ? <ApiErrorAlert error={act.error} onClose={act.clear} /> : null}
    </>
  );
}

/**
 * What to enter, said where it is entered: the addresses are the operator's
 * own, the account identifier is saved apart and masked, the certificate
 * host name carries the {account} placeholder. The example is an invented
 * provider (example.* names, documentation addresses): no real service.
 */
function UpstreamHelp({ proto, masked }: { proto: Proto; masked: string }) {
  return (
    <div className="dns-help" data-testid="dns-upstream-help">
      <ul className="plain-list">
        <li>
          <Typography.Text strong>上游地址要自己填。</Typography.Text>
          填你的加密解析服务给的 IP 地址（最多两个）。出口直接连这些地址，不会先去解析服务商的域名；面板不内置任何服务商的地址。
        </li>
        <li>
          <Typography.Text strong>账户标识单独保存，并且打码。</Typography.Text>
          服务商分给你账户的那一段（常在专属域名或路径里）不写进这些输入框：在下面「新建账户标识」里保存一次，之后页面、配置预览、差异和日志里都只显示「{masked}」，值只在安装时写到出口上。
        </li>
        <li>
          <Typography.Text strong>证书主机名用占位符。</Typography.Text>
          TLS 主机名{proto === "doh" ? "和 DoH 路径" : ""}里属于账户的那一段写成 <Mono>{"{account}"}</Mono>，安装时换成保存的值；出口按这个主机名校验证书，没有跳过校验的选项。
        </li>
      </ul>
      <div data-testid="dns-upstream-example" className="dns-help-example">
        <Typography.Text type="secondary">
          示例（虚构的服务商，只说明格式）：服务商给的专属域名是「你的账户.dns.example.net」、地址是 198.51.100.53 和 2001:db8::53 时——上游地址填 <Mono>198.51.100.53, 2001:db8::53</Mono>，TLS 主机名填{" "}
          <Mono>{"{account}.dns.example.net"}</Mono>
          {proto === "doh" ? (
            <>
              ，DoH 路径填 <Mono>/dns-query</Mono>（账户写在路径里的服务商：主机名填 <Mono>dns.example.net</Mono>，路径填 <Mono>{"/{account}"}</Mono>）
            </>
          ) : null}
          ，账户标识选刚保存的那一个。
        </Typography.Text>
      </div>
    </div>
  );
}

/** A refused save: the error and the validation issues about the upstream (the same for the global form and an exit's). */
function SaveError({ error, onClose }: { error: ApiError | null; onClose: () => void }) {
  if (!error) return null;
  const issues = (error.issues ?? []).filter((i) => i.field === "exit_dns" || i.code === "exit_dns_invalid");
  return (
    <div data-testid="dns-save-error">
      <ApiErrorAlert error={error} onClose={onClose} />
      <IssueList issues={issues} />
    </div>
  );
}

export interface SavedUpstream {
  changed: string[];
  note: string;
}

function UpstreamForm({
  view,
  accounts,
  reloadAccounts,
  onSaved,
  setup = 0,
}: {
  view: DNSView;
  accounts: DNSAccountView[];
  reloadAccounts: () => void;
  onSaved: (r: SavedUpstream) => void;
  /** Counts the「设置加密上游」requests: each one opens the encrypted fields and brings the form into view. */
  setup?: number;
}) {
  const { message } = AntApp.useApp();
  const act = useAction();
  const g = view.global_upstream;
  const [mode, setMode] = useState<"builtin" | Proto>(g ? (g.protocol as Proto) : "builtin");
  const [u, setU] = useState<ExitDNSUpstream>(g ?? EMPTY);
  const box = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!setup) return;
    setMode((m) => (m === "builtin" ? "dot" : m));
    const t = window.setTimeout(() => {
      box.current?.scrollIntoView?.({ behavior: "smooth", block: "start" });
      box.current?.querySelector<HTMLInputElement>('input[aria-label="上游地址"]')?.focus();
    }, 0);
    return () => window.clearTimeout(t);
  }, [setup]);
  // Only "global" is sent: every exit's own override is kept.
  const save = (global: ExitDNSUpstream | null) =>
    act.run(async () => {
      const r = await api.putDNSUpstream({ global });
      message.success(r.note);
      onSaved({ changed: r.changed_exits ?? [], note: r.note });
    }, "save");
  return (
    <div data-testid="dns-upstream-form" ref={box} className="dns-global-form">
      <Typography.Text strong>全局设置（各出口默认沿用）</Typography.Text>
      <Space direction="vertical" style={{ width: "100%" }}>
        <Select
          aria-label="出口解析上游"
          value={mode}
          style={{ width: 280, maxWidth: "100%" }}
          onChange={(m) => setMode(m)}
          options={[
            { value: "builtin", label: "内置公共解析器（明文，默认）" },
            { value: "dot", label: "DoT（加密，证书主机名校验）" },
            { value: "doh", label: "DoH（加密，证书主机名校验）" },
          ]}
        />
        {mode !== "builtin" ? <UpstreamFields proto={mode} u={u} setU={setU} accounts={accounts} reloadAccounts={reloadAccounts} masked={view.masked} /> : null}
        <Space wrap>
          <Button type="primary" loading={act.busy === "save"} onClick={() => void save(mode === "builtin" ? null : upstreamBody(mode, u))}>
            保存到拓扑
          </Button>
          <Note inline>保存后要在部署页对各出口预检、确认并安装才生效；没有「跳过证书校验」的选项，配置的上游不应答时出口的解析失败，不回落到内置解析器。</Note>
        </Space>
      </Space>
      <SaveError error={act.error} onClose={act.clear} />
    </div>
  );
}

type ExitMode = "inherit" | "builtin" | "custom";

export const EXIT_MODE: Record<ExitMode, string> = { inherit: "沿用全局设置", builtin: "使用内置解析器", custom: "单独设置" };

function modeOf(e: DNSExitRow): ExitMode {
  return e.source === "own" ? "custom" : e.source === "builtin" ? "builtin" : "inherit";
}

/**
 * One exit's own setting. Saves only this exit: the body is
 * {exits: {<id>: null | {protocol:"builtin"} | upstream}} without "global",
 * so the global setting and every other exit's override are kept
 * (PUT /api/dns/upstream changes only what the body names).
 */
function ExitEditor({
  exit,
  view,
  accounts,
  reloadAccounts,
  onSaved,
  onClose,
}: {
  exit: DNSExitRow;
  view: DNSView;
  accounts: DNSAccountView[];
  reloadAccounts: () => void;
  onSaved: (r: SavedUpstream) => void;
  onClose: () => void;
}) {
  const { message } = AntApp.useApp();
  const act = useAction();
  const g = view.global_upstream;
  const own = exit.source === "own" && exit.upstream && exit.upstream.protocol !== "builtin" ? exit.upstream : null;
  const start = own ?? (g && g.protocol !== "builtin" ? g : null);
  const [mode, setMode] = useState<ExitMode>(modeOf(exit));
  const [proto, setProto] = useState<Proto>((start?.protocol as Proto) ?? "dot");
  const [u, setU] = useState<ExitDNSUpstream>(start ?? EMPTY);
  const name = exit.name || exit.id;
  const body = (): ExitDNSUpstream | null => (mode === "inherit" ? null : mode === "builtin" ? { protocol: "builtin" } : upstreamBody(proto, u));
  return (
    <div className="dns-exit-editor" data-testid={`dns-exit-editor-${exit.id}`} style={{ border: "1px solid var(--ant-color-border, #d9d9d9)", borderRadius: 8, padding: 12, marginTop: 12, maxWidth: "100%" }}>
      <Space direction="vertical" style={{ width: "100%" }}>
        <Typography.Text strong>{`出口 ${name} 的解析上游`}</Typography.Text>
        <Radio.Group aria-label={`出口 ${name} 的解析上游来源`} value={mode} onChange={(e) => setMode(e.target.value as ExitMode)}>
          <Space wrap>
            {(Object.keys(EXIT_MODE) as ExitMode[]).map((m) => (
              <Radio key={m} value={m}>
                {EXIT_MODE[m]}
              </Radio>
            ))}
          </Space>
        </Radio.Group>
        {mode === "inherit" ? (
          <Typography.Text type="secondary" data-testid="dns-exit-mode-note">{`跟随全局：${g ? upstreamSummary(g, view.masked) : "内置公共解析器（明文 53）"}`}</Typography.Text>
        ) : mode === "builtin" ? (
          <Typography.Text type="secondary" data-testid="dns-exit-mode-note">不跟随全局，用内置公共解析器明文查询</Typography.Text>
        ) : (
          <>
            <Select
              aria-label="协议"
              value={proto}
              style={{ width: 280, maxWidth: "100%" }}
              onChange={(p) => setProto(p)}
              options={[
                { value: "dot", label: "DoT（加密，证书主机名校验）" },
                { value: "doh", label: "DoH（加密，证书主机名校验）" },
              ]}
            />
            <UpstreamFields proto={proto} u={u} setU={setU} accounts={accounts} reloadAccounts={reloadAccounts} masked={view.masked} />
          </>
        )}
        <Space wrap>
          <Button
            type="primary"
            loading={act.busy === "save"}
            onClick={() =>
              act.run(async () => {
                const r = await api.putDNSUpstream({ exits: { [exit.id]: body() } });
                message.success(r.note);
                onSaved({ changed: r.changed_exits ?? [], note: r.note });
              }, "save")
            }
          >
            保存这个出口
          </Button>
          <Button onClick={onClose}>关闭设置</Button>
        </Space>
        <Note inline>只保存这个出口：全局设置和其它出口的设置不变。保存不触发安装，要在部署页预检、确认并安装后才生效。</Note>
      </Space>
      <SaveError error={act.error} onClose={act.clear} />
    </div>
  );
}

/** One row of the per-exit table: a managed exit, or a node the setting does not apply to. */
interface ExitLine {
  key: string;
  id: string;
  name: string;
  exit?: DNSExitRow;
  config?: DNSConfigState;
  /** Why the setting does not apply (gateway, external SOCKS exit). */
  na?: string;
}


function exitLines(v: DNSView): ExitLine[] {
  const cfg = (id: string) => v.configs.find((c) => c.node === id);
  const out: ExitLine[] = v.exits.map((e) => ({ key: e.id, id: e.id, name: e.name || e.id, exit: e, config: cfg(e.id) }));
  for (const c of v.configs.filter((c) => c.role === "gateway")) {
    out.push({ key: c.node, id: c.node, name: c.node_name || c.node, config: c, na: "网关不是出口：它把境外名字经隧道交给各出口的解析器，自己不向出口的上游查询" });
  }
  for (const p of v.paths.filter((p) => p.scope === "external_exit" && p.id)) {
    const carrier = (p.nodes ?? [])[1];
    out.push({
      key: p.id!,
      id: p.id!,
      name: p.id!,
      na: `外部 SOCKS 出口：名字经它的代理问固定的公共解析器${carrier ? `（承载出口 ${carrier} 上的 SmartDNS）` : ""}，出口解析上游的设置不作用于它`,
    });
  }
  return out;
}

function InstallState({ c }: { c?: DNSConfigState }) {
  if (!c) return <Typography.Text type="secondary">—</Typography.Text>;
  const st = INSTALLED[c.installed] ?? INSTALLED.unknown;
  const av = c.account_version ?? 0;
  const iv = c.installed_account_version ?? 0;
  return (
    <Space direction="vertical" size={2} data-testid={`dns-exit-install-${c.node}`}>
      {c.installed === "same" ? (
        <span className="state-word">计划与已安装一致</span>
      ) : (
        <StatusTag kind={st.kind}>{c.installed === "unknown" ? "已安装：未知" : c.installed === "not_installed" ? "还没有安装" : "待下发：与已安装的不同"}</StatusTag>
      )}
      {av > 0 || iv > 0 ? (
        <Typography.Text type={av !== iv ? "warning" : "secondary"} data-testid={`dns-exit-version-${c.node}`}>
          {`账户标识版本：计划 ${av || "无"} · 已安装 ${iv || "无记录"}${av !== iv ? "（不同：重新预检并安装后生效）" : ""}`}
        </Typography.Text>
      ) : null}
    </Space>
  );
}

function ExitTable({
  v,
  editing,
  setEditing,
  reload,
  onError,
}: {
  v: DNSView;
  editing: string | null;
  setEditing: (id: string | null) => void;
  reload: () => void;
  onError: (error: ApiError | null) => void;
}) {
  const act = useAction();
  useEffect(() => { onError(act.error); }, [act.error, onError]);
  const columns: DataColumn<ExitLine>[] = [
    {
      // The exit's name is its identity and may be long: a flex column, so it wraps inside its cell (never cut, never over the next column).
      title: "出口",
      key: "name",
      kind: "flex",
      width: 160,
      card: "title",
      render: (_, r) => (
        <div className="dns-exit-name" data-testid={`dns-exit-name-${r.id}`}>
          <Typography.Text strong>{r.name}</Typography.Text>
          {r.name !== r.id ? <Mono>{r.id}</Mono> : null}
        </div>
      ),
    },
    {
      title: "生效的上游",
      key: "upstream",
      width: 220,
      render: (_, r) =>
        r.exit ? (
          <Space size={4} wrap>
            <Typography.Text>{r.exit.description}</Typography.Text>
            <Typography.Text type="secondary">{`${TRANSPORT[r.exit.transport] ?? r.exit.transport} · 来源：${SOURCE[r.exit.source] ?? r.exit.source}`}</Typography.Text>
          </Space>
        ) : (
          <Space direction="vertical" size={2} data-testid={`dns-exit-na-${r.id}`}>
            <StatusTag kind="neutral">不可设置</StatusTag>
            <Typography.Text type="secondary">{r.na}</Typography.Text>
          </Space>
        ),
    },
    { title: "计划与已安装", key: "installed", width: 180, render: (_, r) => (r.exit ? <InstallState c={r.config} /> : <Typography.Text type="secondary">—</Typography.Text>) },
    {
      title: "解析检查",
      key: "check",
      width: 160,
      render: (_, r) => {
        if (!r.exit) return <Typography.Text type="secondary">—</Typography.Text>;
        if (!r.exit.checkable) return <Typography.Text type="secondary">不能检查：没有隧道解析器（只经 Mesh）</Typography.Text>;
        return <CheckResult c={v.checks.find((x) => x.exit_id === r.id)} />;
      },
    },
    {
      title: "操作",
      key: "actions",
      kind: "actions",
      width: 180,
      render: (_, r) =>
        r.exit ? (
          <Space size={4} wrap>
            <Button
              size="small"
              disabled={!v.check_available || !r.exit.checkable}
              title={!v.check_available ? "面板现在没有宿主代理，不能检查" : !r.exit.checkable ? "没有隧道解析器" : undefined}
              loading={act.busy === `check:${r.id}`}
              onClick={() => act.run(async () => (await api.postDNSCheck(r.id), void reload()), `check:${r.id}`)}
            >
              解析检查
            </Button>
            <Button size="small" type={editing === r.id ? "primary" : "default"} aria-label={`设置 ${r.name} 的解析上游`} onClick={() => setEditing(editing === r.id ? null : r.id)}>
              设置
            </Button>
          </Space>
        ) : null,
    },
  ];
  return (
    <>
      <DataTable<ExitLine>
        data-testid="dns-exit-table"
        rowKey="key"
        columns={columns}
        dataSource={exitLines(v)}
        pagination={false}
        onRow={(r) => ({ "data-testid": `dns-exit-${r.id}` }) as HTMLAttributes<HTMLElement>}
      />
    </>
  );
}

/** After a save: which exits now need preflight → install (the save installed nothing). */
function PendingNote({ saved, v, onClose }: { saved: SavedUpstream; v: DNSView; onClose: () => void }) {
  const names = saved.changed.map((id) => {
    const e = v.exits.find((x) => x.id === id);
    return e?.name && e.name !== id ? `${e.name}（${id}）` : id;
  });
  return (
    <Alert
      type={names.length ? "warning" : "info"}
      showIcon
      closable
      onClose={onClose}
      style={{ marginBottom: 12 }}
      data-testid="dns-pending"
      message={names.length ? `已保存到拓扑，生效的上游有变化、待下发的出口：${names.join("、")}` : "已保存到拓扑：没有出口的生效上游发生变化"}
      description={names.length ? "保存没有安装任何东西：到部署页对这些出口预检、确认差异并安装后才生效；在那之前它们仍按已安装的配置解析。" : saved.note}
    />
  );
}

function Accounts({ accounts, reload }: { accounts: DNSAccountView[]; reload: () => void }) {
  const act = useAction();
  const [name, setName] = useState("");
  const [value, setValue] = useState("");
  return (
    <div data-testid="dns-accounts">
      {accounts.map((a) => (
        <div key={a.id} className="dns-row" data-testid={`dns-account-${a.id}`}>
          <Space size={6} wrap>
            <Typography.Text strong>{a.name}</Typography.Text>
            <span className="status-text">值已保存，不再显示</span>
            {a.used_by.length ? <Typography.Text type="secondary">用于：{a.used_by.map((r) => r.name || r.id).join("、")}</Typography.Text> : null}
            <Button size="small" danger disabled={a.used_by.length > 0} loading={act.busy === `del:${a.id}`} onClick={() => act.run(async () => (await api.deleteDNSAccount(a.id), reload()), `del:${a.id}`)}>
              删除
            </Button>
          </Space>
        </div>
      ))}
      <Space wrap>
        <Input aria-label="账户标识名称" placeholder="名称" value={name} onChange={(e) => setName(e.target.value)} style={{ width: 160, maxWidth: "100%" }} />
        <Input.Password aria-label="账户标识的值" placeholder="账户标识（只写，保存后不再显示）" value={value} onChange={(e) => setValue(e.target.value)} style={{ width: 260, maxWidth: "100%" }} autoComplete="off" />
        <Button
          disabled={!name || !value}
          loading={act.busy === "create"}
          onClick={() =>
            act.run(async () => {
              await api.createDNSAccount({ name, account: value });
              setValue("");
              setName("");
              reload();
            }, "create")
          }
        >
          添加账户标识
        </Button>
      </Space>
      {act.error ? <ApiErrorAlert error={act.error} onClose={act.clear} /> : null}
    </div>
  );
}

/**
 * What the saved setting means for names that go through the tunnels: asked
 * in clear text of the built-in public resolvers, or of the operator's
 * encrypted upstream. It is the saved (planned) setting; exits whose
 * installed config differs are counted, and the table below says which.
 */
export function upstreamState(v: Pick<DNSView, "exits" | "configs">): { state: "none" | "partial" | "all" | "no_exits"; plain: DNSExitRow[]; encrypted: DNSExitRow[]; notInstalled: number } {
  const plain = v.exits.filter((e) => e.transport === "plain");
  const encrypted = v.exits.filter((e) => e.transport !== "plain");
  const notInstalled = v.exits.filter((e) => {
    const c = v.configs.find((x) => x.node === e.id);
    return !!c && c.installed !== "same";
  }).length;
  const state = v.exits.length === 0 ? "no_exits" : encrypted.length === 0 ? "none" : plain.length === 0 ? "all" : "partial";
  return { state, plain, encrypted, notInstalled };
}

const exitNames = (list: DNSExitRow[]) => list.map((e) => e.name || e.id).join("、");

function UpstreamStatus({ v, onSetup }: { v: DNSView; onSetup: () => void }) {
  const st = upstreamState(v);
  const pending =
    st.notInstalled > 0 ? (
      <div>
        {st.notInstalled} 个出口尚未安装这份设置，<Link to={href("deploy")}>部署页</Link> 安装前仍按旧配置解析。
      </div>
    ) : null;
  const setup = (
    <Button type="primary" onClick={onSetup} data-testid="dns-setup-encrypted">
      设置加密上游
    </Button>
  );
  if (st.state === "all")
    return (
      <div data-testid="dns-upstream-status" data-state="all" className="dns-status">
        <span className="status-text">已设置加密上游</span>
        {st.encrypted.length} 个受管出口
        <Note inline>走隧道的名字由各出口向你设置的加密上游（DoT / DoH）查询；上游不应答时解析失败，不回落到内置解析器。</Note>
        {pending}
      </div>
    );
  if (st.state === "no_exits")
    return (
      <div data-testid="dns-upstream-status" data-state="no_exits" className="dns-status">
        <span className="status-text">还没有受管出口</span>
        <Note inline>{v.global_upstream && v.global_upstream.protocol !== "builtin" ? "全局设置已填加密上游，新加入的出口默认沿用。" : "没有设置加密上游时，出口向内置公共解析器明文查询。"}</Note>
      </div>
    );
  return (
    <>
    <Alert
      type="warning"
      showIcon
      style={{ marginBottom: 16 }}
      data-testid="dns-upstream-status"
      data-state={st.state}
      message={
        st.state === "none"
          ? "还没有设置加密上游：境外名字现在由各出口向内置公共解析器明文查询"
          : `${st.encrypted.length} 个出口使用加密上游，${st.plain.length} 个仍向内置公共解析器明文查询：${exitNames(st.plain)}`
      }
      description={pending || undefined}
      action={setup}
    />
    <Note title="加密上游" testId="dns-upstream-why">没有加密上游的出口从自己的线路用明文（53 端口）问内置公共解析器，出口所在网络能看到查询的名字。在下面「全局设置」里填你的 DoT / DoH 服务。</Note>
    </>
  );
}

/** The resolution view: the body of the 解析设置 page. */
export function DNSConfigView() {
  const view = useApi(() => api.getDNS(), []);
  const accounts = useApi(() => api.listDNSAccounts(), []);
  const [editing, setEditing] = useState<string | null>(null);
  const [saved, setSaved] = useState<SavedUpstream | null>(null);
  const [setup, setSetup] = useState(0);
  const [checkError, setCheckError] = useState<ApiError | null>(null);
  const accts = accounts.data?.accounts ?? [];
  const onSaved = (r: SavedUpstream) => {
    setSaved(r);
    void view.reload();
    void accounts.reload();
  };
  return (
    <DataView state={view} rows={4}>
      {(v) => (
        <div className="dns-page">
          <UpstreamStatus v={v} onSetup={() => setSetup((n) => n + 1)} />
          <DNSLocal />
          <Section title="境外解析上游（例如 NextDNS）">
            <ol className="dns-flow" aria-label="境外名字解析路径" data-testid="dns-overseas-path">
              {["设备", "网关 SmartDNS", "隧道", "出口 SmartDNS", "境外解析上游"].map((step) => <li key={step}>{step}</li>)}
            </ol>
            <Help title="说明" testId="dns-overseas-help">
              境外名字不由网关直接问公共解析器：经隧道送到实际出口，再从出口自己的上联查询，让 CDN 调度与出口一致，境外查询不在国内明文出现。NextDNS 是出口 SmartDNS 可选的 DoT / DoH 上游；默认上游为明文 1.1.1.1 / 8.8.8.8。
            </Help>
            {saved ? <PendingNote saved={saved} v={v} onClose={() => setSaved(null)} /> : null}
            <UpstreamForm view={v} accounts={accts} reloadAccounts={() => void accounts.reload()} onSaved={onSaved} setup={setup} />
            <details className="dns-overrides">
              <summary>按出口覆盖与解析检查</summary>
            <ExitTable v={v} editing={editing} setEditing={setEditing} reload={() => void view.reload()} onError={setCheckError} />
            </details>
            {checkError ? <ApiErrorAlert error={checkError} onClose={() => setCheckError(null)} /> : null}
            {(() => {
              const e = v.exits.find((x) => x.id === editing);
              return e ? (
                <ExitEditor
                  key={`${e.id}:${e.source}:${JSON.stringify(e.upstream ?? null)}`}
                  exit={e}
                  view={v}
                  accounts={accts}
                  reloadAccounts={() => accounts.reload()}
                  onSaved={onSaved}
                  onClose={() => setEditing(null)}
                />
              ) : null;
            })()}
            <Help title="解析检查能说明什么">
              「解析检查」由网关经隧道向该出口的解析器问固定名字 {v.check_name}（A），与网关 SmartDNS 转发的路径相同；出口再从自己的线路问它的上游。它证明出口解析器经隧道有回答；回答可能来自出口的缓存，也看不出是哪个上游回答的——配置了加密上游时出口没有别的上游，没有缓存时有回答即说明配置的上游回答了。检查问的是主机上已安装的配置，不是刚保存、还没下发的设置。
            </Help>
            {!v.check_available ? <Typography.Text type="warning">面板现在没有宿主代理，不能检查。</Typography.Text> : null}
          </Section>
          <Fold title="解析路径（编译结果）" summary={`${v.paths.length} 条`}>
            <div className="dns-plan" data-testid="dns-plan">
              <div className="dns-plan-line dns-plan-head" aria-hidden="true">
                <span>名字</span>
                <span>应答方</span>
                <span>传输</span>
              </div>
              {v.paths.map((p, i) => (
                <PathRow key={`${p.scope}:${p.id ?? i}`} row={p} />
              ))}
            </div>
          </Fold>
          <Fold title="账户标识" summary={accts.length ? `${accts.length} 个` : "没有"}>
            <Accounts accounts={accts} reload={() => void accounts.reload()} />
          </Fold>
          <Fold
            title="生成的 SmartDNS 配置"
            summary={(() => {
              const n = v.configs.filter((c) => c.installed !== "same").length;
              return n ? <Typography.Text type="warning">{`${n} 台与已安装的不同`}</Typography.Text> : `${v.configs.length} 台，与已安装一致`;
            })()}
          >
            {v.configs.map((c) => (
              <ConfigRow key={c.node} c={c} />
            ))}
          </Fold>
          <Fold
            title="嗅探转发服务的逐解析器结果"
            summary={v.forwarder.available ? `${v.forwarder.resolvers.length} 个解析器` : "未验证"}
          >
            {v.forwarder.available ? (
              <>
                <Note>
                  实测于 <TimeText value={v.forwarder.checked_at} />（转发服务的自检，明文 53；多个解析器并行竞速，不应答的会被降级）。
                </Note>
                {v.forwarder.resolvers.map((r, i) => (
                  <ResolverRow key={i} r={r} />
                ))}
              </>
            ) : (
              <StatusTag kind="unverified">{`未验证：${v.forwarder.message ?? "没有测量"}`}</StatusTag>
            )}
          </Fold>
        </div>
      )}
    </DataView>
  );
}

/** 解析设置: the page of the navigation entry (#/dns). */
export default function DNSSettingsPage() {
  return (
    <Page title="解析设置">
      <DNSConfigView />
    </Page>
  );
}
